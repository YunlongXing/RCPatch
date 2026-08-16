#!/usr/bin/env python3
"""Select ARVO cases that are most useful for dynamic patch validation.

The selector consumes the strict high-confidence RCPatch-better set and emits a
targets JSON compatible with ``scripts/validate_arvo_patch_targets.py``.
Unlike pure confidence-based selection, it favors cases where dynamic evidence
would be most valuable for a paper claim: feature-disable/revert reference
patches, available OSS-Fuzz reproducer metadata, non-pseudo RCPatch patches, and
projects that have not repeatedly failed to build in previous validation runs.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


FUZZ_TARGET_RE = re.compile(r"^Fuzz target(?: binary)?:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
TESTCASE_RE = re.compile(r"https://oss-fuzz\.com/download\?testcase_id=\d+")
SOURCE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inc"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strict-json", required=True, type=Path)
    parser.add_argument("--full-results-json", required=True, type=Path)
    parser.add_argument("--meta-dir", required=True, type=Path)
    parser.add_argument("--patch-dir", required=True, type=Path)
    parser.add_argument("--output-json", required=True, type=Path)
    parser.add_argument("--oss-fuzz-dir", type=Path)
    parser.add_argument("--oss-fuzz-projects-file", type=Path)
    parser.add_argument("--validation-results-jsonl", type=Path, action="append", default=[])
    parser.add_argument("--include-project", action="append", default=[])
    parser.add_argument("--exclude-project", action="append", default=[])
    parser.add_argument("--exclude-results-jsonl", type=Path, action="append", default=[])
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--per-project-limit", type=int, default=4)
    parser.add_argument("--min-confidence", type=float, default=0.99)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    strict_payload = read_json(args.strict_json.expanduser().resolve())
    strict_records = strict_payload.get("records", strict_payload)
    full_records = read_json(args.full_results_json.expanduser().resolve())
    full_by_id = {str(record.get("local_id")): record for record in full_records}
    known_projects = load_known_oss_fuzz_projects(args)
    validation_history = load_validation_history(args.validation_results_jsonl)
    excluded_ids = load_excluded_ids(args.exclude_results_jsonl)
    include_projects = {str(item) for item in args.include_project}
    exclude_projects = {str(item) for item in args.exclude_project}

    selected: list[dict[str, Any]] = []
    for strict in strict_records:
        confidence = safe_float((strict.get("judge") or {}).get("confidence"))
        if confidence < args.min_confidence:
            continue
        local_id = str(strict.get("local_id") or "")
        if local_id in excluded_ids:
            continue
        full = full_by_id.get(local_id)
        if not full:
            continue
        generated_payload = (full.get("generated_patch") or {}).get("payload") or {}
        if generated_payload.get("is_pseudo_patch") is not False:
            continue
        meta = read_json(args.meta_dir.expanduser().resolve() / f"{local_id}.json")
        report_text = first_report_comment(meta)
        project = str(full.get("project") or strict.get("project") or "")
        if include_projects and project not in include_projects:
            continue
        if project in exclude_projects:
            continue
        patch_path = args.patch_dir.expanduser().resolve() / f"{local_id}.diff"
        diff_text = patch_path.read_text(encoding="utf-8", errors="replace") if patch_path.exists() else ""
        category = classify_reference_patch(
            assessment=str((strict.get("judge") or {}).get("official_patch_assessment") or ""),
            diff_text=diff_text,
        )
        target = {
            "local_id": local_id,
            "project": project,
            "repo_url": full.get("repo_url"),
            "fix_commit": full.get("fix_commit"),
            "sanitizer": full.get("sanitizer"),
            "oss_fuzz_sanitizer": sanitizer_for_oss_fuzz(str(full.get("sanitizer") or "")),
            "crash_type": full.get("crash_type"),
            "severity": full.get("severity"),
            "confidence": confidence,
            "trigger": strict.get("trigger") or ((full.get("bugrc") or {}).get("trigger")),
            "fuzzer_name": extract_fuzzer_name(report_text),
            "testcase_url": extract_testcase_url(report_text),
            "has_oss_fuzz_project": project in known_projects if known_projects else True,
            "official_patch_path": patch_path.as_posix(),
            "generated_patch_diff": str(generated_payload.get("unified_diff") or ""),
            "reference_patch_category": category,
            "selection_notes": [],
        }
        score, notes = selection_score(target, validation_history=validation_history)
        target["selection_score"] = round(score, 4)
        target["selection_notes"] = notes
        selected.append(target)

    selected.sort(key=lambda item: (-item["selection_score"], item["project"], item["local_id"]))
    selected = diversify(selected, limit=args.limit, per_project_limit=args.per_project_limit)
    payload = {
        "schema_version": "rcpatch.arvo_dynamic_validation_targets.v1",
        "strict_source": args.strict_json.expanduser().resolve().as_posix(),
        "full_results_source": args.full_results_json.expanduser().resolve().as_posix(),
        "limit": args.limit,
        "per_project_limit": args.per_project_limit,
        "count": len(selected),
        "category_distribution": dict(Counter(item["reference_patch_category"] for item in selected).most_common()),
        "project_distribution": dict(Counter(item["project"] for item in selected).most_common()),
        "targets": selected,
    }
    args.output_json.expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
    args.output_json.expanduser().resolve().write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"targets={len(selected)} output={args.output_json.expanduser().resolve()}")
    return 0


def read_json(path: Path) -> Any:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


def load_known_oss_fuzz_projects(args: argparse.Namespace) -> set[str]:
    if args.oss_fuzz_projects_file:
        path = args.oss_fuzz_projects_file.expanduser().resolve()
        if path.exists():
            payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            if isinstance(payload, list):
                return {str(item) for item in payload}
            return {str(item) for item in payload.get("projects", [])}
    if args.oss_fuzz_dir:
        projects_dir = args.oss_fuzz_dir.expanduser().resolve() / "projects"
        if projects_dir.exists():
            return {path.name for path in projects_dir.iterdir() if path.is_dir()}
    return set()


def load_validation_history(paths: list[Path]) -> dict[str, dict[str, Any]]:
    by_project: dict[str, Counter[str]] = defaultdict(Counter)
    for raw_path in paths:
        path = raw_path.expanduser().resolve()
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            project = str(row.get("project") or "")
            verdict = str((row.get("conclusion") or {}).get("verdict") or "unknown")
            by_project[project][verdict] += 1
    return {
        project: {
            "counts": dict(counter),
            "total": sum(counter.values()),
            "base_build_failed": counter.get("base_build_failed", 0),
            "positive_dynamic": counter.get("validated_official_incomplete_bugrc_fixes", 0)
            + counter.get("both_fix_reproducer", 0),
        }
        for project, counter in by_project.items()
    }


def load_excluded_ids(paths: list[Path]) -> set[str]:
    excluded: set[str] = set()
    for raw_path in paths:
        path = raw_path.expanduser().resolve()
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            local_id = row.get("local_id")
            if local_id is not None:
                excluded.add(str(local_id))
    return excluded


def first_report_comment(meta: dict[str, Any]) -> str:
    for comment in ((meta.get("report") or {}).get("comments") or []):
        content = str(comment.get("content") or "").strip()
        if content:
            return content
    return ""


def extract_fuzzer_name(report_text: str) -> str | None:
    match = FUZZ_TARGET_RE.search(report_text)
    return match.group(1) if match else None


def extract_testcase_url(report_text: str) -> str | None:
    match = TESTCASE_RE.search(report_text)
    return match.group(0) if match else None


def sanitizer_for_oss_fuzz(name: str) -> str:
    lowered = name.lower()
    if lowered == "asan":
        return "address"
    if lowered == "msan":
        return "memory"
    if lowered == "ubsan":
        return "undefined"
    return "address"


def classify_reference_patch(*, assessment: str, diff_text: str) -> str:
    text = f"{assessment}\n{diff_text[:5000]}".lower()
    source_files = [
        line.split()[2].removeprefix("a/")
        for line in diff_text.splitlines()
        if line.startswith("diff --git ") and len(line.split()) >= 4
    ]
    source_files = [file for file in source_files if Path(file).suffix in SOURCE_EXTENSIONS]
    if re.search(r"\b(revert|disable|disabled|remove support|removed support|turn off|turns off)\b", text):
        return "feature_disable_or_revert"
    if re.search(r"\b(fuzzer|fuzz target|testcase|test case|sanitizer|suppress|suppression|build flag)\b", text):
        return "test_fuzzer_or_suppression"
    if not source_files:
        return "non_source_or_metadata_only"
    if "unrelated" in text or "different file" in text or "does not address" in text:
        return "unrelated_or_mismapped_reference"
    if len(source_files) > 20:
        return "large_broad_patch"
    return "source_patch_needs_manual_review"


def selection_score(target: dict[str, Any], *, validation_history: dict[str, dict[str, Any]]) -> tuple[float, list[str]]:
    score = safe_float(target.get("confidence")) * 10.0
    notes: list[str] = []
    category = str(target.get("reference_patch_category") or "")
    category_weights = {
        "feature_disable_or_revert": 6.0,
        "test_fuzzer_or_suppression": 3.0,
        "source_patch_needs_manual_review": 2.5,
        "large_broad_patch": 2.0,
        "non_source_or_metadata_only": 1.0,
        "unrelated_or_mismapped_reference": 0.5,
    }
    score += category_weights.get(category, 0.0)
    notes.append(f"category={category}")
    if target.get("has_oss_fuzz_project"):
        score += 2.0
        notes.append("oss-fuzz project available")
    if target.get("fuzzer_name"):
        score += 2.0
        notes.append("fuzzer name available")
    if target.get("testcase_url"):
        score += 2.0
        notes.append("testcase url available")
    history = validation_history.get(str(target.get("project") or ""))
    if history:
        total = max(1, int(history.get("total") or 0))
        base_fail_rate = safe_float(history.get("base_build_failed")) / total
        if int(history.get("positive_dynamic") or 0) > 0:
            score += 3.0
            notes.append("project has prior positive dynamic validation")
        if base_fail_rate >= 0.7:
            score -= 4.0
            notes.append(f"penalized prior base-build failure rate={base_fail_rate:.2f}")
    return score, notes


def diversify(items: list[dict[str, Any]], *, limit: int, per_project_limit: int) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    by_project: Counter[str] = Counter()
    for item in items:
        project = str(item.get("project") or "")
        if by_project[project] >= per_project_limit:
            continue
        selected.append(item)
        by_project[project] += 1
        if len(selected) >= limit:
            break
    return selected


def safe_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


if __name__ == "__main__":
    raise SystemExit(main())
