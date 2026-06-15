#!/usr/bin/env python3
"""Run patch-generation ablations from existing BugRC benchmark results.

This script reuses already-computed BugRC evidence and worktrees so expensive
source parsing does not need to be repeated for prompt-only ablations.
Prior-related ablations should still be run with the original benchmark
evaluators because priors affect candidate ranking before patch generation.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Optional


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
VENDOR_ROOT = PROJECT_ROOT / ".vendor"
SCRIPTS_ROOT = PROJECT_ROOT / "scripts"
if SRC_ROOT.exists():
    sys.path.insert(0, str(SRC_ROOT))
try:
    import pydantic  # noqa: F401
except ImportError:
    pydantic = None  # type: ignore[assignment]
if pydantic is None and VENDOR_ROOT.exists():
    sys.path.insert(0, str(VENDOR_ROOT))
if SCRIPTS_ROOT.exists():
    sys.path.insert(0, str(SCRIPTS_ROOT))

from arvo_meta_bugrc_eval import (  # noqa: E402
    DEFAULT_MODEL,
    build_patch_comparison_prompt,
    build_patch_generation_prompt,
    call_json_llm,
    collect_source_snippets,
    extract_report_text,
    shorten,
    with_llm_meta,
)
from magma_bugrc_eval import build_magma_patch_comparison_prompt  # noqa: E402


VARIANTS = ("full", "without_causality_chain", "llm_only_root_cause", "trigger_site_baseline")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True, choices=("arvo", "magma"))
    parser.add_argument("--results-jsonl", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--variant", required=True, choices=VARIANTS)
    parser.add_argument("--case-list-file", type=Path, help="Optional JSON/TXT case list.")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--api-base-url", default=os.getenv("BUGRC_LLM_BASE_URL", "https://api.openai.com/v1"))
    parser.add_argument("--llm-timeout", type=int, default=60)
    parser.add_argument("--max-snippet-chars", type=int, default=14000)
    parser.add_argument("--sleep-seconds", type=float, default=0.0)
    parser.add_argument("--force", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    output_dir = args.output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    results_path = output_dir / f"results.{args.variant}.jsonl"
    summary_path = output_dir / f"summary.{args.variant}.json"
    cache_dir = output_dir / "llm_cache"
    cache_dir.mkdir(exist_ok=True)

    records = load_jsonl(args.results_jsonl.expanduser().resolve())
    case_ids = load_case_ids(args.case_list_file) if args.case_list_file else None
    selected = select_records(records, case_ids=case_ids)
    if args.limit is not None:
        selected = selected[: args.limit]
    done = set() if args.force else load_done_ids(results_path)
    write_json(
        output_dir / f"manifest.{args.variant}.json",
        {
            "dataset": args.dataset,
            "variant": args.variant,
            "input_results": args.results_jsonl.expanduser().resolve().as_posix(),
            "case_count": len(selected),
            "cases": [record_id(record) for record in selected],
        },
    )

    for index, record in enumerate(selected, start=1):
        rid = record_id(record)
        if rid in done:
            print(f"[{index}/{len(selected)}] {rid}: already done", flush=True)
            continue
        print(f"[{index}/{len(selected)}] {rid}: {args.variant}", flush=True)
        started = time.time()
        try:
            if args.variant == "full":
                row = full_variant_row(record, dataset=args.dataset)
            else:
                row = run_prompt_ablation(record, args=args, cache_dir=cache_dir)
            row["elapsed_seconds"] = round(time.time() - started, 3)
        except Exception as exc:  # noqa: BLE001 - batch runner should keep going.
            row = {
                "local_id": rid,
                "bug_id": record.get("bug_id"),
                "project": record.get("project"),
                "target": record.get("target"),
                "dataset": args.dataset,
                "variant": args.variant,
                "status": "failed",
                "error": f"{type(exc).__name__}: {exc}",
                "elapsed_seconds": round(time.time() - started, 3),
            }
        append_jsonl(results_path, row)
        write_summary(results_path, summary_path, dataset=args.dataset, variant=args.variant)
        if args.sleep_seconds > 0:
            time.sleep(args.sleep_seconds)

    write_summary(results_path, summary_path, dataset=args.dataset, variant=args.variant)
    print(f"Results: {results_path}")
    print(f"Summary: {summary_path}")
    return 0


def run_prompt_ablation(record: dict[str, Any], *, args: argparse.Namespace, cache_dir: Path) -> dict[str, Any]:
    dataset = str(args.dataset)
    variant = str(args.variant)
    meta, report_text = build_meta_and_report(record, dataset=dataset)
    initial_root_cause = ((record.get("llm_initial_root_cause") or {}).get("payload") or {})
    bugrc_payload = ablated_bugrc_payload(record.get("bugrc") or {}, variant=variant)
    snippets = collect_ablation_snippets(
        record,
        bugrc_payload=bugrc_payload,
        max_chars=int(args.max_snippet_chars),
        trigger_only=variant in {"llm_only_root_cause", "trigger_site_baseline"},
    )
    if variant == "without_causality_chain":
        prompt = build_patch_generation_prompt(meta, report_text, initial_root_cause, bugrc_payload, snippets)
    elif variant == "llm_only_root_cause":
        prompt = build_llm_only_patch_prompt(meta, report_text, initial_root_cause, bugrc_payload, snippets)
    elif variant == "trigger_site_baseline":
        prompt = build_trigger_site_patch_prompt(meta, report_text, initial_root_cause, bugrc_payload, snippets)
    else:
        raise ValueError(f"unsupported prompt ablation variant: {variant}")

    generated_patch = call_json_llm(
        cache_dir=cache_dir,
        api_base_url=args.api_base_url,
        model=args.model,
        timeout=args.llm_timeout,
        task=f"{dataset}_{variant}_generate_patch",
        prompt=prompt,
    )
    reference_patch = read_reference_patch(record)
    comparison_prompt = build_comparison_prompt(
        dataset=dataset,
        record=record,
        meta=meta,
        report_text=report_text,
        bugrc_payload=bugrc_payload,
        generated_patch=generated_patch.payload,
        reference_patch=reference_patch,
    )
    comparison = call_json_llm(
        cache_dir=cache_dir,
        api_base_url=args.api_base_url,
        model=args.model,
        timeout=args.llm_timeout,
        task=f"{dataset}_{variant}_compare_patch",
        prompt=comparison_prompt,
    )
    return {
        "local_id": record_id(record),
        "bug_id": record.get("bug_id"),
        "project": record.get("project"),
        "target": record.get("target"),
        "dataset": dataset,
        "variant": variant,
        "status": "completed",
        "source_status": record.get("status"),
        "generated_patch": with_llm_meta(generated_patch),
        "patch_comparison": {"status": "semantic_judged", "exact_match": False, "llm": comparison.payload},
    }


def full_variant_row(record: dict[str, Any], *, dataset: str) -> dict[str, Any]:
    return {
        "local_id": record_id(record),
        "bug_id": record.get("bug_id"),
        "project": record.get("project"),
        "target": record.get("target"),
        "dataset": dataset,
        "variant": "full",
        "status": record.get("status"),
        "source_status": record.get("status"),
        "generated_patch": record.get("generated_patch"),
        "patch_comparison": record.get("patch_comparison"),
    }


def ablated_bugrc_payload(payload: dict[str, Any], *, variant: str) -> dict[str, Any]:
    trigger = payload.get("trigger")
    if variant == "without_causality_chain":
        return {
            "trigger": trigger,
            "parsed_files": payload.get("parsed_files"),
            "parsed_functions": payload.get("parsed_functions"),
            "slice_node_count": payload.get("slice_node_count"),
            "slice_edge_count": payload.get("slice_edge_count"),
            "candidates": payload.get("candidates", [])[:5],
            "chains": [],
            "patch_suggestions": [],
            "approximations": payload.get("approximations", []),
            "diagnostics": payload.get("diagnostics", []),
        }
    if variant in {"llm_only_root_cause", "trigger_site_baseline"}:
        return {
            "trigger": trigger,
            "candidates": [],
            "chains": [],
            "patch_suggestions": [],
            "approximations": ["Ablation: BugRC candidates, chains, and patch suggestions hidden from patch generation."],
        }
    return payload


def collect_ablation_snippets(
    record: dict[str, Any],
    *,
    bugrc_payload: dict[str, Any],
    max_chars: int,
    trigger_only: bool,
) -> list[dict[str, Any]]:
    repo_path = record.get("pre_fix_worktree")
    if not repo_path:
        return []
    payload = bugrc_payload
    if trigger_only:
        payload = {"trigger": bugrc_payload.get("trigger"), "candidates": []}
    return collect_source_snippets(Path(str(repo_path)), payload, max_chars=max_chars)


def build_llm_only_patch_prompt(
    meta: dict[str, Any],
    report_text: str,
    initial_root_cause: dict[str, Any],
    bugrc_payload: dict[str, Any],
    snippets: list[dict[str, Any]],
) -> str:
    return f"""Generate a vulnerability-blocking source patch using only the bug report, the initial LLM root-cause hypothesis, the trigger location, and nearby source snippets.

This is an ablation baseline. Do not use BugRC root-cause candidates, dependency edges, causality chains, or patch suggestions.

Patch requirements:
- Return a unified diff relative to the pre-fix repository.
- Try to block the root-cause-to-trigger path inferred from the report.
- Preserve resource balance and avoid unrelated behavior changes.
- If exact code is insufficient, return the smallest plausible patch and mark "is_pseudo_patch": true.

Return JSON with:
{{
  "root_cause_location": {{"file": "...", "function": "...", "line": 0}},
  "root_cause_summary": "...",
  "vulnerability_path": ["root cause step", "propagation step", "trigger step"],
  "cut_point": "...",
  "why_patch_blocks_path": "...",
  "patch_rationale": "...",
  "unified_diff": "...",
  "is_pseudo_patch": false,
  "resource_balance_plan": "...",
  "risk_notes": ["..."],
  "proof_obligations": ["..."],
  "confidence": 0.0
}}

Bug metadata:
project={meta.get('project')}
sanitizer={meta.get('sanitizer')}
crash_type={meta.get('crash_type')}

Initial LLM root cause:
{json.dumps(initial_root_cause, ensure_ascii=False)[:6000]}

Trigger:
{json.dumps(bugrc_payload.get('trigger'), ensure_ascii=False)[:3000]}

Source snippets:
{json.dumps(snippets, ensure_ascii=False)[:16000]}

Bug report:
{shorten(report_text, 8000)}
"""


def build_trigger_site_patch_prompt(
    meta: dict[str, Any],
    report_text: str,
    initial_root_cause: dict[str, Any],
    bugrc_payload: dict[str, Any],
    snippets: list[dict[str, Any]],
) -> str:
    return f"""Generate a trigger-site-only baseline patch for this vulnerability.

This is an ablation baseline. You may use only the trigger location and nearby source snippets. Do not use upstream BugRC root-cause candidates, dependency edges, causality chains, or patch suggestions.

Patch requirements:
- Patch at or immediately before the trigger site.
- Prefer a local guard, bounds check, null check, or early return that prevents the observed failing operation.
- Preserve resource balance on any new return path.
- Do not claim to repair upstream root cause unless the trigger site is also the root cause.
- If exact code is insufficient, mark "is_pseudo_patch": true.

Return JSON with:
{{
  "root_cause_location": {{"file": "...", "function": "...", "line": 0}},
  "root_cause_summary": "...",
  "vulnerability_path": ["trigger-local failure path"],
  "cut_point": "trigger-site",
  "why_patch_blocks_path": "...",
  "patch_rationale": "...",
  "unified_diff": "...",
  "is_pseudo_patch": false,
  "resource_balance_plan": "...",
  "risk_notes": ["..."],
  "proof_obligations": ["..."],
  "confidence": 0.0
}}

Bug metadata:
project={meta.get('project')}
sanitizer={meta.get('sanitizer')}
crash_type={meta.get('crash_type')}

Initial LLM root-cause hint, for context only:
{json.dumps(initial_root_cause, ensure_ascii=False)[:4000]}

Trigger:
{json.dumps(bugrc_payload.get('trigger'), ensure_ascii=False)[:3000]}

Source snippets:
{json.dumps(snippets, ensure_ascii=False)[:16000]}

Bug report:
{shorten(report_text, 6000)}
"""


def build_comparison_prompt(
    *,
    dataset: str,
    record: dict[str, Any],
    meta: dict[str, Any],
    report_text: str,
    bugrc_payload: dict[str, Any],
    generated_patch: dict[str, Any],
    reference_patch: str,
) -> str:
    if dataset == "arvo":
        return build_patch_comparison_prompt(meta, report_text, bugrc_payload, generated_patch, reference_patch)
    case = SimpleNamespace(
        target=record.get("target"),
        bug_id=record.get("bug_id") or record_id(record),
        touched_files=tuple(record.get("touched_files") or []),
        affected_functions=tuple(record.get("affected_functions") or []),
        canary_conditions=tuple(record.get("canary_conditions") or []),
    )
    return build_magma_patch_comparison_prompt(
        case=case,
        report_text=report_text,
        bugrc_payload=bugrc_payload,
        generated_patch=generated_patch,
        magma_reference_patch=reference_patch,
    )


def build_meta_and_report(record: dict[str, Any], *, dataset: str) -> tuple[dict[str, Any], str]:
    if dataset == "arvo":
        meta = read_json(Path(str(record.get("meta_path") or "")))
        if not meta:
            meta = {
                "project": record.get("project"),
                "sanitizer": record.get("sanitizer"),
                "crash_type": record.get("crash_type"),
                "severity": record.get("severity"),
            }
        return meta, extract_report_text(meta) or str(record.get("crash_type") or "")
    meta = {
        "project": record.get("target"),
        "sanitizer": "Magma canary",
        "crash_type": record.get("crash_type") or "Magma canary violation",
        "severity": "ground_truth_bug",
    }
    report_text = "\n".join(
        [
            f"Magma target: {record.get('target')}",
            f"Magma bug id: {record.get('bug_id') or record_id(record)}",
            f"Touched files: {', '.join(record.get('touched_files') or []) or 'unknown'}",
            f"Affected functions: {', '.join(record.get('affected_functions') or []) or 'unknown'}",
            f"Canary conditions: {'; '.join(record.get('canary_conditions') or []) or 'not available'}",
        ]
    )
    return meta, report_text


def read_reference_patch(record: dict[str, Any]) -> str:
    for key in ("official_patch_path", "magma_patch_path"):
        value = record.get(key)
        if value:
            path = Path(str(value))
            if path.exists():
                return path.read_text(encoding="utf-8", errors="replace")
    return ""


def select_records(records: list[dict[str, Any]], *, case_ids: Optional[set[str]]) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for record in records:
        if record.get("status") != "completed":
            continue
        rid = record_id(record)
        if case_ids and rid not in case_ids and str(record.get("bug_id") or "") not in case_ids:
            continue
        selected.append(record)
    return selected


def load_case_ids(path: Optional[Path]) -> set[str]:
    if path is None:
        return set()
    text = path.expanduser().resolve().read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        payload = json.loads(text)
        raw_items = payload.get("cases", payload) if isinstance(payload, dict) else payload
        ids: set[str] = set()
        for item in raw_items:
            if isinstance(item, dict):
                value = item.get("local_id") or item.get("bug_id") or item.get("id")
                if value:
                    ids.add(str(value))
            else:
                ids.add(str(item))
        return ids
    return {line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")}


def write_summary(results_path: Path, summary_path: Path, *, dataset: str, variant: str) -> None:
    rows = load_jsonl(results_path)
    statuses: dict[str, int] = {}
    verdicts: dict[str, int] = {}
    claims: dict[str, int] = {}
    pseudo: dict[str, int] = {}
    confidence_bins = {">=0.95": 0, "0.90-0.95": 0, "0.80-0.90": 0, "<0.80": 0}
    for row in rows:
        statuses[str(row.get("status"))] = statuses.get(str(row.get("status")), 0) + 1
        generated = (row.get("generated_patch") or {}).get("payload") or {}
        if generated:
            key = str(generated.get("is_pseudo_patch"))
            pseudo[key] = pseudo.get(key, 0) + 1
        llm = ((row.get("patch_comparison") or {}).get("llm") or {})
        verdict = llm.get("verdict")
        claim = llm.get("paper_claim")
        if verdict:
            verdicts[str(verdict)] = verdicts.get(str(verdict), 0) + 1
        if claim:
            claims[str(claim)] = claims.get(str(claim), 0) + 1
        confidence = safe_float(llm.get("confidence"))
        if confidence >= 0.95:
            confidence_bins[">=0.95"] += 1
        elif confidence >= 0.90:
            confidence_bins["0.90-0.95"] += 1
        elif confidence >= 0.80:
            confidence_bins["0.80-0.90"] += 1
        elif llm:
            confidence_bins["<0.80"] += 1
    success_count = success_metric(dataset=dataset, claims=claims, verdicts=verdicts)
    write_json(
        summary_path,
        {
            "dataset": dataset,
            "variant": variant,
            "record_count": len(rows),
            "success_count": success_count,
            "success_rate": round(success_count / len(rows), 4) if rows else 0.0,
            "status_distribution": statuses,
            "semantic_verdict_distribution": verdicts,
            "paper_claim_distribution": claims,
            "generated_patch_is_pseudo_distribution": pseudo,
            "confidence_bins": confidence_bins,
            "updated_at_epoch": time.time(),
        },
    )


def success_metric(*, dataset: str, claims: dict[str, int], verdicts: dict[str, int]) -> int:
    if dataset == "magma":
        return claims.get("bugrc_matches_ground_truth", 0) + claims.get("bugrc_blocks_better_than_magma_reference", 0)
    return claims.get("official_incomplete_bugrc_blocks", 0) or verdicts.get("bugrc_patch_better", 0)


def safe_float(value: object) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def record_id(record: dict[str, Any]) -> str:
    return str(record.get("local_id") or record.get("bug_id") or record.get("id") or "")


def load_done_ids(path: Path) -> set[str]:
    return {record_id(record) for record in load_jsonl(path) if record.get("status") == "completed"}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
