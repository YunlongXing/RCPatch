#!/usr/bin/env python3
"""LLM second-pass judge for high-quality ARVO RCPatch-better candidates."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


DEFAULT_MODEL = os.getenv("RCPATCH_LLM_VALIDATION_MODEL", os.getenv("BUGRC_LLM_VALIDATION_MODEL", "gpt-4.1-mini"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suspicious-json", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--base-url", default=os.getenv("RCPATCH_LLM_BASE_URL", os.getenv("BUGRC_LLM_BASE_URL", "https://api.openai.com/v1")))
    parser.add_argument("--min-input-confidence", type=float, default=0.95)
    parser.add_argument("--accept-threshold", type=float, default=0.99)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--sleep-seconds", type=float, default=0.0)
    parser.add_argument("--max-retries", type=int, default=5)
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
    results_path = args.output_dir / "llm_judgments.jsonl"
    accepted_path = args.output_dir / "llm_judgments.accepted_099.json"
    summary_path = args.output_dir / "llm_judgments.summary.json"
    cache_dir = args.output_dir / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)

    records = json.loads(args.suspicious_json.read_text(encoding="utf-8"))
    candidates = strict_candidates(records, args.min_input_confidence)
    if args.limit is not None:
        candidates = candidates[: args.limit]
    done = load_done_ids(results_path)
    logging.info("Strict candidates=%d already_done=%d", len(candidates), len(done))

    for index, case in enumerate(candidates):
        local_id = str(case.get("local_id"))
        if local_id in done:
            continue
        logging.info("[%d/%d] judging %s %s", index + 1, len(candidates), local_id, case.get("project"))
        started = time.time()
        try:
            prompt_payload = build_prompt_payload(case)
            judgment = judge_case(
                prompt_payload=prompt_payload,
                model=args.model,
                base_url=args.base_url,
                api_key=api_key,
                cache_dir=cache_dir,
                max_retries=args.max_retries,
            )
            row = {
                "local_id": local_id,
                "project": case.get("project"),
                "crash_type": case.get("crash_type"),
                "input_confidence": input_confidence(case),
                "trigger": case.get("trigger"),
                "judge": judgment,
                "status": "completed",
                "elapsed_seconds": round(time.time() - started, 3),
            }
        except Exception as exc:  # noqa: BLE001 - keep batch running and record failure.
            logging.exception("Failed to judge %s", local_id)
            row = {
                "local_id": local_id,
                "project": case.get("project"),
                "crash_type": case.get("crash_type"),
                "input_confidence": input_confidence(case),
                "status": "failed",
                "error": f"{type(exc).__name__}: {exc}",
                "elapsed_seconds": round(time.time() - started, 3),
            }
        append_jsonl(results_path, row)
        write_outputs(results_path, accepted_path, summary_path, args.accept_threshold)
        if args.sleep_seconds > 0:
            time.sleep(args.sleep_seconds)

    write_outputs(results_path, accepted_path, summary_path, args.accept_threshold)
    return 0


def strict_candidates(records: list[dict[str, Any]], min_confidence: float) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for case in records:
        comparison = case.get("comparison") or {}
        generated_patch = case.get("generated_patch") or {}
        chains = case.get("bugrc_chains") or []
        if comparison.get("verdict") != "bugrc_patch_better":
            continue
        if input_confidence(case) < min_confidence:
            continue
        if comparison.get("official_patch_cuts_bug") is not False:
            continue
        if comparison.get("bugrc_patch_cuts_bug") is not True:
            continue
        if generated_patch.get("is_pseudo_patch") is not False:
            continue
        if not chains:
            continue
        selected.append(case)
    selected.sort(
        key=lambda item: (
            -input_confidence(item),
            -len(item.get("bugrc_chains") or []),
            str(item.get("project") or ""),
            str(item.get("local_id") or ""),
        )
    )
    return selected


def build_prompt_payload(case: dict[str, Any]) -> dict[str, Any]:
    comparison = case.get("comparison") or {}
    generated_patch = case.get("generated_patch") or {}
    chains = case.get("bugrc_chains") or []
    return {
        "task": "second_pass_static_semantic_judge",
        "case_id": case.get("local_id"),
        "project": case.get("project"),
        "crash_type": case.get("crash_type"),
        "sanitizer": case.get("sanitizer"),
        "severity": case.get("severity"),
        "trigger": compact(case.get("trigger"), 2500),
        "report_excerpt": truncate(str(case.get("report_excerpt") or ""), 4000),
        "bugrc_initial_comparison": {
            "verdict": comparison.get("verdict"),
            "confidence": comparison.get("confidence"),
            "official_patch_cuts_bug": comparison.get("official_patch_cuts_bug"),
            "bugrc_patch_cuts_bug": comparison.get("bugrc_patch_cuts_bug"),
            "reasoning": truncate(str(comparison.get("reasoning") or ""), 2500),
            "resource_balance_assessment": truncate(str(comparison.get("resource_balance_assessment") or ""), 1600),
        },
        "bugrc_causality_chains": compact(chains[:2], 5000),
        "bugrc_generated_patch": {
            "rationale": truncate(str(generated_patch.get("patch_rationale") or ""), 1800),
            "risk_notes": truncate(str(generated_patch.get("risk_notes") or ""), 1200),
            "unified_diff_excerpt": truncate(str(generated_patch.get("unified_diff") or ""), 6000),
        },
        "official_patch": {
            "path": case.get("official_patch_path"),
            "subject": truncate(str(case.get("official_patch_subject") or ""), 1000),
            "files": compact(case.get("official_patch_files"), 1200),
            "diff_excerpt": truncate(str(case.get("official_patch") or ""), 6000),
        },
    }


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
    cache_key = hashlib.sha256(f"{model}\n{prompt_text}".encode("utf-8")).hexdigest()
    cache_path = cache_dir / f"{cache_key}.json"
    if cache_path.exists():
        cached = json.loads(cache_path.read_text(encoding="utf-8"))
        cached["cached"] = True
        return cached

    messages = [
        {
            "role": "system",
            "content": (
                "You are a strict static-analysis judge for root-cause patch quality. "
                "You must evaluate only the supplied evidence. Do not assume reproducer results. "
                "Give confidence >= 0.99 only when the evidence is overwhelming: the official patch is clearly unrelated "
                "or fails to address the trigger/root cause, and the RCPatch patch directly blocks the root cause described "
                "by the trigger and causality chain with low semantic risk. If there is any meaningful uncertainty, use "
                "0.95 or lower. Return JSON only."
            ),
        },
        {
            "role": "user",
            "content": (
                "Judge whether this case should be retained as an ultra-high-confidence example where RCPatch's generated "
                "patch is semantically better than the official patch, without using compiler or reproducer evidence.\n\n"
                "Return a JSON object with exactly these keys:\n"
                "{\n"
                '  "label": "ultra_high_confidence_bugrc_better" | "probable_bugrc_better" | "not_enough_evidence" | "official_or_both_plausible",\n'
                '  "confidence": number between 0 and 1,\n'
                '  "official_patch_assessment": string,\n'
                '  "bugrc_patch_assessment": string,\n'
                '  "root_cause_alignment": string,\n'
                '  "main_uncertainties": [strings],\n'
                '  "reasoning": string\n'
                "}\n\n"
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
    content = response["choices"][0]["message"]["content"]
    parsed = json.loads(content)
    normalized = normalize_judgment(parsed)
    normalized["model"] = model
    normalized["cached"] = False
    cache_path.write_text(json.dumps(normalized, indent=2, ensure_ascii=False), encoding="utf-8")
    return normalized


def post_chat_completion(*, base_url: str, api_key: str, body: dict[str, Any], max_retries: int) -> dict[str, Any]:
    url = f"{base_url.rstrip('/')}/chat/completions"
    payload = json.dumps(body).encode("utf-8")
    last_error: Exception | None = None
    for attempt in range(max_retries + 1):
        request = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
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
        sleep_for = min(60.0, 2.0**attempt)
        time.sleep(sleep_for)
    raise RuntimeError(f"LLM request failed after retries: {last_error}") from last_error


def normalize_judgment(raw: dict[str, Any]) -> dict[str, Any]:
    confidence = raw.get("confidence")
    try:
        confidence_value = max(0.0, min(1.0, float(confidence)))
    except (TypeError, ValueError):
        confidence_value = 0.0
    label = str(raw.get("label") or "not_enough_evidence")
    allowed = {
        "ultra_high_confidence_bugrc_better",
        "probable_bugrc_better",
        "not_enough_evidence",
        "official_or_both_plausible",
    }
    if label not in allowed:
        label = "not_enough_evidence"
    return {
        "label": label,
        "confidence": confidence_value,
        "official_patch_assessment": str(raw.get("official_patch_assessment") or ""),
        "bugrc_patch_assessment": str(raw.get("bugrc_patch_assessment") or ""),
        "root_cause_alignment": str(raw.get("root_cause_alignment") or ""),
        "main_uncertainties": [str(item) for item in (raw.get("main_uncertainties") or [])][:8],
        "reasoning": str(raw.get("reasoning") or ""),
    }


def write_outputs(results_path: Path, accepted_path: Path, summary_path: Path, threshold: float) -> None:
    rows = read_jsonl(results_path)
    accepted = [
        row
        for row in rows
        if row.get("status") == "completed"
        and (row.get("judge") or {}).get("label") == "ultra_high_confidence_bugrc_better"
        and float((row.get("judge") or {}).get("confidence") or 0.0) >= threshold
    ]
    summary = {
        "record_count": len(rows),
        "completed": sum(1 for row in rows if row.get("status") == "completed"),
        "failed": sum(1 for row in rows if row.get("status") == "failed"),
        "accepted_threshold": threshold,
        "accepted_count": len(accepted),
        "label_distribution": count_nested(rows, ("judge", "label")),
        "confidence_distribution": count_confidence(rows),
        "accepted_projects": count_field(accepted, "project"),
        "accepted_crash_types": count_field(accepted, "crash_type"),
    }
    accepted_path.write_text(json.dumps({"count": len(accepted), "records": accepted}, indent=2, ensure_ascii=False), encoding="utf-8")
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")


def append_jsonl(path: Path, item: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(item, ensure_ascii=False) + "\n")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]


def load_done_ids(path: Path) -> set[str]:
    return {str(row.get("local_id")) for row in read_jsonl(path) if row.get("local_id") is not None}


def input_confidence(case: dict[str, Any]) -> float:
    value = (case.get("comparison") or {}).get("confidence")
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def compact(value: Any, max_chars: int) -> str:
    """Return a safely truncated JSON representation for prompt context."""
    return truncate(json.dumps(value, ensure_ascii=False, default=str), max_chars)


def truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 120] + "\n...[truncated]...\n" + text[-100:]


def count_nested(rows: list[dict[str, Any]], path: tuple[str, ...]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value: Any = row
        for key in path:
            value = value.get(key) if isinstance(value, dict) else None
        counts[str(value)] = counts.get(str(value), 0) + 1
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def count_confidence(rows: list[dict[str, Any]]) -> dict[str, int]:
    buckets = {"<0.9": 0, "0.9-0.95": 0, "0.95-0.99": 0, ">=0.99": 0}
    for row in rows:
        value = float((row.get("judge") or {}).get("confidence") or 0.0)
        if value >= 0.99:
            buckets[">=0.99"] += 1
        elif value >= 0.95:
            buckets["0.95-0.99"] += 1
        elif value >= 0.9:
            buckets["0.9-0.95"] += 1
        else:
            buckets["<0.9"] += 1
    return buckets


def count_field(rows: list[dict[str, Any]], field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        key = str(row.get(field))
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


if __name__ == "__main__":
    raise SystemExit(main())
