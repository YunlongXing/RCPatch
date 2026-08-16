#!/usr/bin/env python3
"""Second-pass LLM validation for RCPatch patch verdict confidence buckets.

The first-pass evaluators already compare RCPatch-generated patches against
official/reference patches. This script performs an independent second-pass
audit for selected first-pass verdicts, typically ``bugrc_patch_better`` and
``semantically_equivalent``, then reports confidence-bucket distributions.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import logging
import os
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterable, Optional


DEFAULT_MODEL = os.getenv("RCPATCH_LLM_VALIDATION_MODEL", os.getenv("BUGRC_LLM_VALIDATION_MODEL", "gpt-4.1-mini"))
DEFAULT_VERDICTS = ("bugrc_patch_better", "semantically_equivalent")
CONFIDENCE_BUCKETS = (
    (">=0.99", 0.99, 1.0000001),
    ("0.90-0.99", 0.90, 0.99),
    ("0.85-0.90", 0.85, 0.90),
    ("0.80-0.85", 0.80, 0.85),
    ("0.70-0.80", 0.70, 0.80),
    ("<0.70", -0.0000001, 0.70),
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-jsonl", action="append", default=[], type=Path, help="Evaluation results JSONL.")
    parser.add_argument("--input-json", action="append", default=[], type=Path, help="Evaluation records JSON array.")
    parser.add_argument("--dataset", action="append", default=[], help="Dataset name for the corresponding input.")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--meta-dir", type=Path, help="Optional ARVO metadata directory.")
    parser.add_argument("--patch-dir", type=Path, help="Optional ARVO official patch directory.")
    parser.add_argument("--include-verdict", action="append", default=[], help="First-pass verdict to revalidate.")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--base-url", default=os.getenv("RCPATCH_LLM_BASE_URL", os.getenv("BUGRC_LLM_BASE_URL", "https://api.openai.com/v1")))
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--max-retries", type=int, default=5)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--log-level", default="INFO")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level.upper()), format="%(asctime)s %(levelname)s %(message)s")
    api_key = os.getenv("RCPATCH_OPENAI_API_KEY") or os.getenv("BUGRC_OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not api_key:
        logging.error("RCPATCH_OPENAI_API_KEY, BUGRC_OPENAI_API_KEY, or OPENAI_API_KEY must be set")
        return 2

    args.output_dir.mkdir(parents=True, exist_ok=True)
    cache_dir = args.output_dir / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    results_path = args.output_dir / "second_pass_judgments.jsonl"
    summary_path = args.output_dir / "second_pass_summary.json"

    include_verdicts = tuple(args.include_verdict or DEFAULT_VERDICTS)
    records = load_all_inputs(args.input_jsonl, args.input_json, args.dataset)
    candidates = select_candidates(records, include_verdicts=include_verdicts)
    if args.limit is not None:
        candidates = candidates[: args.limit]
    done = set() if args.force else load_done_keys(results_path)
    pending = [case for case in candidates if case_key(case) not in done]
    logging.info("Candidates=%d pending=%d done=%d verdicts=%s", len(candidates), len(pending), len(done), include_verdicts)

    write_lock = threading.Lock()
    completed = 0

    def run_one(case: dict[str, Any]) -> dict[str, Any]:
        started = time.time()
        try:
            prompt_payload = build_prompt_payload(case, meta_dir=args.meta_dir, patch_dir=args.patch_dir)
            judge = judge_case(
                prompt_payload=prompt_payload,
                model=args.model,
                base_url=args.base_url,
                api_key=api_key,
                cache_dir=cache_dir,
                max_retries=args.max_retries,
            )
            return {
                "key": case_key(case),
                "dataset": case.get("_dataset"),
                "local_id": case.get("local_id"),
                "project": case.get("project") or case.get("target"),
                "input_verdict": first_pass_verdict(case),
                "input_confidence": first_pass_confidence(case),
                "generated_is_pseudo": generated_patch_payload(case).get("is_pseudo_patch"),
                "status": "completed",
                "judge": judge,
                "elapsed_seconds": round(time.time() - started, 3),
            }
        except Exception as exc:  # noqa: BLE001 - batch validation should keep going.
            logging.exception("Failed to validate %s", case_key(case))
            return {
                "key": case_key(case),
                "dataset": case.get("_dataset"),
                "local_id": case.get("local_id"),
                "project": case.get("project") or case.get("target"),
                "input_verdict": first_pass_verdict(case),
                "input_confidence": first_pass_confidence(case),
                "status": "failed",
                "error": f"{type(exc).__name__}: {exc}",
                "elapsed_seconds": round(time.time() - started, 3),
            }

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        future_to_case = {executor.submit(run_one, case): case for case in pending}
        for future in concurrent.futures.as_completed(future_to_case):
            row = future.result()
            with write_lock:
                append_jsonl(results_path, row)
                completed += 1
                if completed % 10 == 0 or completed == len(pending):
                    write_summary(results_path, summary_path, expected_count=len(candidates))
                    logging.info("Progress %d/%d", completed, len(pending))

    write_summary(results_path, summary_path, expected_count=len(candidates))
    logging.info("Wrote %s", summary_path)
    return 0


def load_all_inputs(jsonl_paths: list[Path], json_paths: list[Path], dataset_names: list[str]) -> list[dict[str, Any]]:
    paths: list[tuple[str, Path]] = [("jsonl", path.expanduser().resolve()) for path in jsonl_paths]
    paths.extend(("json", path.expanduser().resolve()) for path in json_paths)
    records: list[dict[str, Any]] = []
    for index, (kind, path) in enumerate(paths):
        dataset = dataset_names[index] if index < len(dataset_names) else infer_dataset(path)
        if kind == "jsonl":
            loaded = load_jsonl(path)
        else:
            payload = json.loads(path.read_text(encoding="utf-8"))
            loaded = payload.get("records", payload) if isinstance(payload, dict) else payload
            if not isinstance(loaded, list):
                raise ValueError(f"{path} must contain a list or records list")
        for record in loaded:
            if isinstance(record, dict):
                copied = dict(record)
                copied["_dataset"] = dataset
                records.append(copied)
    return records


def infer_dataset(path: Path) -> str:
    lowered = path.as_posix().lower()
    if "magma" in lowered:
        return "magma"
    if "arvo" in lowered:
        return "arvo"
    return path.parent.name


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


def select_candidates(records: list[dict[str, Any]], *, include_verdicts: tuple[str, ...]) -> list[dict[str, Any]]:
    selected = [
        record
        for record in records
        if record.get("status") == "completed" and first_pass_verdict(record) in include_verdicts
    ]
    selected.sort(
        key=lambda item: (
            str(item.get("_dataset") or ""),
            first_pass_verdict(item),
            -first_pass_confidence(item),
            str(item.get("project") or item.get("target") or ""),
            str(item.get("local_id") or ""),
        )
    )
    return selected


def first_pass_verdict(record: dict[str, Any]) -> str:
    return str(((record.get("patch_comparison") or {}).get("llm") or {}).get("verdict") or "")


def first_pass_confidence(record: dict[str, Any]) -> float:
    try:
        return max(0.0, min(float(((record.get("patch_comparison") or {}).get("llm") or {}).get("confidence") or 0.0), 1.0))
    except (TypeError, ValueError):
        return 0.0


def generated_patch_payload(record: dict[str, Any]) -> dict[str, Any]:
    payload = (record.get("generated_patch") or {}).get("payload") or {}
    return payload if isinstance(payload, dict) else {}


def case_key(record: dict[str, Any]) -> str:
    return f"{record.get('_dataset') or 'unknown'}:{record.get('local_id') or record.get('bug_id')}"


def build_prompt_payload(record: dict[str, Any], *, meta_dir: Optional[Path], patch_dir: Optional[Path]) -> dict[str, Any]:
    local_id = str(record.get("local_id") or record.get("bug_id") or "")
    dataset = str(record.get("_dataset") or "")
    comparison = ((record.get("patch_comparison") or {}).get("llm") or {})
    bugrc = record.get("bugrc") or {}
    generated = generated_patch_payload(record)
    reference_patch = read_reference_patch(record, dataset=dataset, local_id=local_id, patch_dir=patch_dir)
    report_excerpt = read_report_excerpt(record, dataset=dataset, local_id=local_id, meta_dir=meta_dir)
    return {
        "task": "second_pass_patch_verdict_validation",
        "dataset": dataset,
        "case_id": local_id,
        "project": record.get("project") or record.get("target"),
        "repo_url": record.get("repo_url"),
        "fix_commit_or_base_ref": record.get("fix_commit") or record.get("base_ref"),
        "crash_type": record.get("crash_type"),
        "sanitizer": record.get("sanitizer"),
        "severity": record.get("severity"),
        "crash_state": compact(record.get("crash_state") or record.get("canary_conditions") or [], 1800),
        "report_excerpt": truncate(report_excerpt, 4500),
        "first_pass_comparison": {
            "verdict": comparison.get("verdict"),
            "confidence": comparison.get("confidence"),
            "correct_patch": comparison.get("correct_patch"),
            "semantic_similarity": comparison.get("semantic_similarity"),
            "bugrc_patch_cuts_bug": comparison.get("bugrc_patch_cuts_bug"),
            "reference_patch_cuts_bug": comparison.get("official_patch_cuts_bug", comparison.get("magma_reference_cuts_bug")),
            "bugrc_blocks_root_cause_path": comparison.get("bugrc_blocks_root_cause_path"),
            "reference_blocks_root_cause_path": comparison.get("official_blocks_root_cause_path", comparison.get("magma_blocks_root_cause_path")),
            "root_cause_to_trigger_chain": compact(comparison.get("root_cause_to_trigger_chain"), 2400),
            "bugrc_cut_point": comparison.get("bugrc_cut_point"),
            "reference_cut_point": comparison.get("official_cut_point", comparison.get("magma_cut_point")),
            "reference_limitation": comparison.get("official_patch_limitation", comparison.get("magma_reference_limitation")),
            "patch_proof_strength": comparison.get("patch_proof_strength"),
            "reasoning": truncate(str(comparison.get("reasoning") or ""), 2600),
        },
        "bugrc_evidence": {
            "trigger": compact(rcpatch.get("trigger"), 1800),
            "top_candidates": compact((rcpatch.get("candidates") or [])[:5], 6500),
            "top_chains": compact((rcpatch.get("chains") or [])[:3], 7000),
            "patch_suggestions": compact((rcpatch.get("patch_suggestions") or [])[:3], 3500),
        },
        "bugrc_generated_patch": {
            "root_cause_location": generated.get("root_cause_location"),
            "root_cause_summary": truncate(str(generated.get("root_cause_summary") or ""), 1400),
            "vulnerability_path": compact(generated.get("vulnerability_path"), 2200),
            "cut_point": truncate(str(generated.get("cut_point") or ""), 1200),
            "why_patch_blocks_path": truncate(str(generated.get("why_patch_blocks_path") or ""), 1800),
            "patch_rationale": truncate(str(generated.get("patch_rationale") or ""), 1800),
            "resource_balance_plan": truncate(str(generated.get("resource_balance_plan") or ""), 1200),
            "risk_notes": compact(generated.get("risk_notes"), 1200),
            "is_pseudo_patch": generated.get("is_pseudo_patch"),
            "unified_diff_excerpt": truncate(str(generated.get("unified_diff") or ""), 8000),
        },
        "reference_patch": {
            "path": record.get("official_patch_path") or record.get("magma_patch_path"),
            "diff_excerpt": truncate(reference_patch, 8000),
        },
    }


def read_report_excerpt(record: dict[str, Any], *, dataset: str, local_id: str, meta_dir: Optional[Path]) -> str:
    if dataset == "arvo" and meta_dir is not None:
        meta_path = meta_dir.expanduser().resolve() / f"{local_id}.json"
        meta = read_json(meta_path)
        chunks: list[str] = []
        for comment in (meta.get("report") or {}).get("comments", []) or []:
            content = comment.get("content") if isinstance(comment, dict) else None
            if content:
                chunks.append(str(content))
        if chunks:
            return "\n\n".join(chunks)
    initial = (record.get("llm_initial_root_cause") or {}).get("payload") or {}
    return json.dumps(initial, ensure_ascii=False)


def read_reference_patch(record: dict[str, Any], *, dataset: str, local_id: str, patch_dir: Optional[Path]) -> str:
    if dataset == "arvo" and patch_dir is not None:
        return read_text(patch_dir.expanduser().resolve() / f"{local_id}.diff")
    for key in ("official_patch_path", "magma_patch_path"):
        value = record.get(key)
        if value:
            text = read_text(Path(str(value)))
            if text:
                return text
    return ""


def judge_case(
    *,
    prompt_payload: dict[str, Any],
    model: str,
    base_url: str,
    api_key: str,
    cache_dir: Path,
    max_retries: int,
) -> dict[str, Any]:
    prompt_text = json.dumps(prompt_payload, ensure_ascii=False, sort_keys=True)
    cache_key = hashlib.sha256(f"{model}\npatch_verdict_bins_v1\n{prompt_text}".encode("utf-8")).hexdigest()
    cache_path = cache_dir / f"{cache_key}.json"
    if cache_path.exists():
        cached = json.loads(cache_path.read_text(encoding="utf-8"))
        cached["cached"] = True
        return cached

    messages = [
        {
            "role": "system",
            "content": (
                "You are a strict second-pass judge for a vulnerability repair paper. "
                "Use only the supplied evidence. Do not invent build, test, reproducer, or source facts. "
                "Your task is to independently validate whether the first-pass patch verdict is reliable."
            ),
        },
        {
            "role": "user",
            "content": (
                "Re-evaluate the RCPatch patch and the reference patch.\n\n"
                "Return JSON exactly in this shape:\n"
                "{\n"
                '  "validated_verdict": "confirmed_bugrc_better" | "confirmed_equivalent" | "reference_better" | "both_plausible_or_unclear" | "both_incomplete" | "not_enough_evidence",\n'
                '  "confidence": 0.0,\n'
                '  "bugrc_patch_cuts_bug": true,\n'
                '  "reference_patch_cuts_bug": true,\n'
                '  "bugrc_blocks_root_cause_path": true,\n'
                '  "reference_blocks_root_cause_path": true,\n'
                '  "root_cause_alignment": "strong" | "moderate" | "weak" | "unclear",\n'
                '  "resource_state_safety": "safe" | "likely_safe" | "uncertain" | "unsafe",\n'
                '  "main_uncertainties": ["..."],\n'
                '  "reasoning": "..."\n'
                "}\n\n"
                "Confidence calibration:\n"
                "- Use >=0.99 only when the supplied evidence overwhelmingly supports the validated verdict and leaves no meaningful semantic uncertainty.\n"
                "- Use 0.90-0.99 for strong evidence with minor missing context.\n"
                "- Use 0.85-0.90 for plausible but incomplete evidence.\n"
                "- Use 0.80-0.85 for weak-to-moderate evidence.\n"
                "- Use 0.70-0.80 when the verdict is possible but uncertain.\n"
                "- Use <0.70 when evidence is contradictory, pseudo-patch-like, missing, or not enough for a paper claim.\n\n"
                "Verdict rules:\n"
                "- confirmed_bugrc_better: RCPatch's concrete patch more directly cuts the root-cause-to-trigger path than the reference patch.\n"
                "- confirmed_equivalent: both patches plausibly cut the same vulnerability path with similar semantic coverage.\n"
                "- reference_better: the reference patch is more complete or safer.\n"
                "- both_plausible_or_unclear: both may work but evidence cannot rank them.\n"
                "- both_incomplete: neither patch clearly cuts the root-cause path.\n"
                "- not_enough_evidence: insufficient concrete evidence.\n\n"
                f"Evidence JSON:\n{prompt_text}"
            ),
        },
    ]
    body = {
        "model": model,
        "messages": messages,
        "temperature": 0,
        "response_format": {"type": "json_object"},
    }
    response = post_chat_completion(base_url=base_url, api_key=api_key, body=body, max_retries=max_retries)
    parsed = json.loads(response["choices"][0]["message"]["content"])
    normalized = normalize_judgment(parsed)
    normalized["model"] = model
    normalized["cached"] = False
    cache_path.write_text(json.dumps(normalized, indent=2, ensure_ascii=False), encoding="utf-8")
    return normalized


def post_chat_completion(*, base_url: str, api_key: str, body: dict[str, Any], max_retries: int) -> dict[str, Any]:
    url = f"{base_url.rstrip('/')}/chat/completions"
    payload = json.dumps(body).encode("utf-8")
    last_error: Optional[BaseException] = None
    for attempt in range(max_retries + 1):
        request = urllib.request.Request(
            url,
            data=payload,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code not in {408, 409, 429, 500, 502, 503, 504}:
                detail = exc.read().decode("utf-8", errors="replace")
                raise RuntimeError(f"LLM HTTP {exc.code}: {detail[:1000]}") from exc
        except urllib.error.URLError as exc:
            last_error = exc
        time.sleep(min(60.0, 2.0**attempt))
    raise RuntimeError(f"LLM request failed after retries: {last_error}") from last_error


def normalize_judgment(raw: dict[str, Any]) -> dict[str, Any]:
    verdict = str(raw.get("validated_verdict") or "not_enough_evidence")
    allowed_verdicts = {
        "confirmed_bugrc_better",
        "confirmed_equivalent",
        "reference_better",
        "both_plausible_or_unclear",
        "both_incomplete",
        "not_enough_evidence",
    }
    if verdict not in allowed_verdicts:
        verdict = "not_enough_evidence"
    try:
        confidence = max(0.0, min(float(raw.get("confidence") or 0.0), 1.0))
    except (TypeError, ValueError):
        confidence = 0.0
    root_cause_alignment = str(raw.get("root_cause_alignment") or "unclear")
    if root_cause_alignment not in {"strong", "moderate", "weak", "unclear"}:
        root_cause_alignment = "unclear"
    resource_state_safety = str(raw.get("resource_state_safety") or "uncertain")
    if resource_state_safety not in {"safe", "likely_safe", "uncertain", "unsafe"}:
        resource_state_safety = "uncertain"
    return {
        "validated_verdict": verdict,
        "confidence": confidence,
        "confidence_bucket": confidence_bucket(confidence),
        "bugrc_patch_cuts_bug": bool(raw.get("bugrc_patch_cuts_bug")),
        "reference_patch_cuts_bug": bool(raw.get("reference_patch_cuts_bug")),
        "bugrc_blocks_root_cause_path": bool(raw.get("bugrc_blocks_root_cause_path")),
        "reference_blocks_root_cause_path": bool(raw.get("reference_blocks_root_cause_path")),
        "root_cause_alignment": root_cause_alignment,
        "resource_state_safety": resource_state_safety,
        "main_uncertainties": string_list(raw.get("main_uncertainties")),
        "reasoning": str(raw.get("reasoning") or ""),
    }


def confidence_bucket(confidence: float) -> str:
    for label, lower, upper in CONFIDENCE_BUCKETS:
        if lower <= confidence < upper:
            return label
    return "<0.70"


def write_summary(results_path: Path, summary_path: Path, *, expected_count: int) -> None:
    raw_rows = load_jsonl(results_path) if results_path.exists() else []
    rows = dedupe_rows(raw_rows)
    status_distribution: dict[str, int] = {}
    by_dataset: dict[str, dict[str, Any]] = {}
    by_input_verdict: dict[str, dict[str, Any]] = {}
    by_bucket: dict[str, dict[str, Any]] = {}
    cross: dict[str, dict[str, dict[str, int]]] = {}
    validated_distribution: dict[str, int] = {}
    for row in rows:
        status = str(row.get("status"))
        status_distribution[status] = status_distribution.get(status, 0) + 1
        if status != "completed":
            continue
        dataset = str(row.get("dataset") or "unknown")
        input_verdict = str(row.get("input_verdict") or "")
        judge = row.get("judge") or {}
        bucket = str(judge.get("confidence_bucket") or confidence_bucket(float(judge.get("confidence") or 0.0)))
        validated = str(judge.get("validated_verdict") or "")
        validated_distribution[validated] = validated_distribution.get(validated, 0) + 1
        update_group(by_dataset, dataset, bucket, validated)
        update_group(by_input_verdict, input_verdict, bucket, validated)
        update_group(by_bucket, bucket, bucket, validated)
        cross.setdefault(input_verdict, {}).setdefault(bucket, {})
        cross[input_verdict][bucket][validated] = cross[input_verdict][bucket].get(validated, 0) + 1
    summary = {
        "expected_count": expected_count,
        "raw_record_count": len(raw_rows),
        "record_count": len(rows),
        "completed_count": status_distribution.get("completed", 0),
        "status_distribution": status_distribution,
        "validated_verdict_distribution": validated_distribution,
        "by_dataset": by_dataset,
        "by_input_verdict": by_input_verdict,
        "by_confidence_bucket": {label: by_bucket.get(label, {"count": 0, "validated_verdicts": {}}) for label, *_ in CONFIDENCE_BUCKETS},
        "input_verdict_by_bucket": {
            verdict: {label: buckets.get(label, {}) for label, *_ in CONFIDENCE_BUCKETS}
            for verdict, buckets in cross.items()
        },
    }
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")


def dedupe_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep one row per case key, preferring completed retry results."""

    by_key: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(rows):
        key = str(row.get("key") or f"row:{index}")
        previous = by_key.get(key)
        if previous is None or row_quality(row) >= row_quality(previous):
            by_key[key] = row
    return list(by_key.values())


def row_quality(row: dict[str, Any]) -> tuple[int, float]:
    quality = 0
    if row.get("status") == "completed":
        quality += 100
    judge = row.get("judge") or {}
    if judge.get("validated_verdict"):
        quality += 10
    try:
        confidence = float(judge.get("confidence") or 0.0)
    except (TypeError, ValueError):
        confidence = 0.0
    return quality, confidence


def update_group(group: dict[str, dict[str, Any]], key: str, bucket: str, validated: str) -> None:
    item = group.setdefault(key, {"count": 0, "buckets": {}, "validated_verdicts": {}})
    item["count"] += 1
    item["buckets"][bucket] = item["buckets"].get(bucket, 0) + 1
    item["validated_verdicts"][validated] = item["validated_verdicts"].get(validated, 0) + 1


def load_done_keys(path: Path) -> set[str]:
    done: set[str] = set()
    if not path.exists():
        return done
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get("status") == "completed" and row.get("key"):
            done.add(str(row["key"]))
    return done


def append_jsonl(path: Path, row: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def compact(value: object, max_chars: int) -> object:
    text = json.dumps(value, ensure_ascii=False)
    if len(text) <= max_chars:
        return value
    return text[:max_chars] + "...[truncated]"


def truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "...[truncated]"


def string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


if __name__ == "__main__":
    raise SystemExit(main())
