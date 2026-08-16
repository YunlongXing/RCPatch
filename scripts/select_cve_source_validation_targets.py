#!/usr/bin/env python3
"""Select high-value semantic CVEs for source-based RCPatch validation.

This is the bridge between:
1. LLM/text-only CVE semantic pattern mining
2. Source-based RCPatch validation for precise root-cause locations

It reads the semantic dataset, chooses high-confidence/high-value CVEs, then
streams the original collection result to produce a much smaller collection JSON
that can be fed to `resume_cve_bootstrap_filtered.py`.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Optional


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
VENDOR_ROOT = PROJECT_ROOT / ".vendor"

if SRC_ROOT.exists():
    sys.path.insert(0, str(SRC_ROOT))
if VENDOR_ROOT.exists():
    sys.path.insert(0, str(VENDOR_ROOT))

from rcpatch.models import CollectedCVERecord  # noqa: E402


DEFAULT_HIGH_VALUE_PATTERNS = {
    "use_after_free_via_dangling_pointer",
    "double_free_or_invalid_free",
    "integer_overflow_to_memory_error",
    "incorrect_length_or_bounds_calculation",
    "missing_bounds_check_before_write",
    "missing_bounds_check_before_read",
    "missing_null_check",
    "type_confusion_state_mismatch",
    "missing_validation_allows_invalid_state",
}

DEFAULT_HIGH_VALUE_BUG_CLASSES = {
    "buffer_overflow",
    "out_of_bounds_read",
    "integer_overflow",
    "use_after_free",
    "double_free",
    "null_dereference",
    "type_confusion",
    "input_validation",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Select high-confidence/high-value semantic CVEs and emit a small collection JSON "
            "for source-based RCPatch validation."
        )
    )
    parser.add_argument("--semantic-dataset", required=True, help="Path to cve_semantic_root_cause_dataset.json.")
    parser.add_argument("--collection-json", required=True, help="Path to bootstrap_collection_result.json.")
    parser.add_argument("--output-dir", required=True, help="Directory for selected validation inputs.")
    parser.add_argument("--min-confidence", type=float, default=0.65, help="Minimum semantic confidence.")
    parser.add_argument("--max-cves", type=int, default=500, help="Maximum selected CVEs.")
    parser.add_argument("--max-per-pattern", type=int, default=100, help="Maximum CVEs selected for each pattern.")
    parser.add_argument(
        "--high-value-only",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Keep only default high-value memory/root-cause patterns and bug classes.",
    )
    parser.add_argument(
        "--include-pattern",
        action="append",
        default=[],
        help="Additional pattern name to include. May be repeated.",
    )
    parser.add_argument(
        "--include-bug-class",
        action="append",
        default=[],
        help="Additional bug class to include. May be repeated.",
    )
    parser.add_argument("--require-repo-url", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--require-fix-commit", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument(
        "--prefer-llm",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Prefer LLM-sourced records when confidence ties.",
    )
    parser.add_argument(
        "--validation-output-dir",
        default=None,
        help="Output directory to use in the generated source-validation command.",
    )
    parser.add_argument(
        "--repos-root",
        default=None,
        help="Repository cache root to use in the generated source-validation command.",
    )
    parser.add_argument(
        "--project-root",
        default=Path.cwd().as_posix(),
        help="Project root used in the generated command script.",
    )
    parser.add_argument(
        "--log-path",
        default=None,
        help="Log path used in the generated source-validation command.",
    )
    parser.add_argument("--validation-max-repos", type=int, default=500)
    parser.add_argument("--git-timeout-seconds", type=int, default=600)
    parser.add_argument("--max-source-files", type=int, default=3000)
    parser.add_argument("--max-source-bytes", type=int, default=64 * 1024 * 1024)
    parser.add_argument("--progress-log-every", type=int, default=25)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    semantic_records = load_semantic_records(Path(args.semantic_dataset).expanduser().resolve())
    selected_annotations = select_annotations(semantic_records, args=args)
    selected_ids = {annotation["cve_id"] for annotation in selected_annotations}
    selected_collection_records = [
        record
        for record in iter_collection_records(Path(args.collection_json).expanduser().resolve())
        if record.cve_id in selected_ids
    ]

    collection_by_cve = {record.cve_id: record for record in selected_collection_records}
    matched_annotations = [annotation for annotation in selected_annotations if annotation["cve_id"] in collection_by_cve]

    targets_path = output_dir / "source_validation_targets.json"
    collection_path = output_dir / "source_validation_collection.json"
    command_path = output_dir / "run_source_validation.sh"

    write_json(
        targets_path,
        {
            "schema_version": "rcpatch.cve_source_validation_targets.v1",
            "metadata": {
                "semantic_dataset": str(Path(args.semantic_dataset).expanduser().resolve()),
                "collection_json": str(Path(args.collection_json).expanduser().resolve()),
                "selected_count": len(matched_annotations),
                "requested_count": len(selected_annotations),
                "missing_from_collection_count": len(selected_annotations) - len(matched_annotations),
                "min_confidence": args.min_confidence,
                "max_cves": args.max_cves,
                "max_per_pattern": args.max_per_pattern,
                "pattern_distribution": dict(Counter(item["pattern"] for item in matched_annotations).most_common()),
                "bug_class_distribution": dict(Counter(item["bug_class"] for item in matched_annotations).most_common()),
            },
            "targets": matched_annotations,
        },
    )
    write_json(
        collection_path,
        {
            "record_count": len(selected_collection_records),
            "records": [collection_by_cve[annotation["cve_id"]].to_dict() for annotation in matched_annotations],
        },
    )
    command_path.write_text(build_validation_command(collection_path, args=args), encoding="utf-8")
    command_path.chmod(0o755)

    print(f"Targets: {targets_path}")
    print(f"Selected collection: {collection_path}")
    print(f"Validation command: {command_path}")
    print(f"Selected CVEs: {len(matched_annotations)}")
    return 0


def load_semantic_records(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    records = data.get("records")
    if not isinstance(records, list):
        raise ValueError(f"{path} does not contain a records array")
    return [record for record in records if isinstance(record, dict)]


def select_annotations(records: list[dict[str, Any]], *, args: argparse.Namespace) -> list[dict[str, Any]]:
    allowed_patterns = {normalize_token(value) for value in DEFAULT_HIGH_VALUE_PATTERNS}
    allowed_patterns.update(normalize_token(value) for value in args.include_pattern)
    allowed_bug_classes = {normalize_token(value) for value in DEFAULT_HIGH_VALUE_BUG_CLASSES}
    allowed_bug_classes.update(normalize_token(value) for value in args.include_bug_class)

    per_pattern: defaultdict[str, int] = defaultdict(int)
    candidates: list[dict[str, Any]] = []
    for record in records:
        confidence = safe_float(record.get("confidence"))
        if confidence < args.min_confidence:
            continue
        pattern = normalize_token(record.get("pattern"))
        bug_class = normalize_token(record.get("bug_class"))
        if args.high_value_only and pattern not in allowed_patterns and bug_class not in allowed_bug_classes:
            continue
        if args.require_repo_url and not record.get("repo_url"):
            continue
        if args.require_fix_commit and not any(reference.get("commit_sha") for reference in record.get("references", [])):
            continue
        if per_pattern[pattern] >= args.max_per_pattern:
            continue
        per_pattern[pattern] += 1
        candidates.append(record)

    candidates.sort(key=lambda item: selection_key(item, prefer_llm=bool(args.prefer_llm)))
    selected: list[dict[str, Any]] = []
    for rank, record in enumerate(candidates[: max(0, args.max_cves)], start=1):
        selected.append(
            {
                "rank": rank,
                "cve_id": record["cve_id"],
                "project": record.get("project"),
                "repo_url": record.get("repo_url"),
                "cwe": record.get("cwe"),
                "bug_class": normalize_token(record.get("bug_class")),
                "root_cause_type": normalize_token(record.get("root_cause_type")),
                "pattern": normalize_token(record.get("pattern")),
                "confidence": safe_float(record.get("confidence")),
                "source": record.get("source"),
                "needs_code_validation": True,
                "explanation": record.get("explanation"),
                "evidence_from_text": record.get("evidence_from_text", []),
            }
        )
    return selected


def selection_key(item: dict[str, Any], *, prefer_llm: bool) -> tuple[float, float, str]:
    source_bonus = -1.0 if prefer_llm and item.get("source") == "llm" else 0.0
    return (-safe_float(item.get("confidence")), source_bonus, str(item.get("cve_id", "")))


def iter_collection_records(path: Path) -> Iterable[CollectedCVERecord]:
    in_records = False
    in_object = False
    depth = 0
    buffer: list[str] = []
    in_string = False
    escape = False
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not in_records:
                if '"records"' in line and "[" in line:
                    in_records = True
                continue
            stripped = line.strip()
            if not in_object:
                if stripped.startswith("]"):
                    break
                if not stripped.startswith("{"):
                    continue
                in_object = True
                buffer = [line]
                depth, in_string, escape = update_json_depth(line, 0, False, False)
            else:
                buffer.append(line)
                depth, in_string, escape = update_json_depth(line, depth, in_string, escape)
            if in_object and depth == 0:
                text = "".join(buffer).strip()
                if text.endswith(","):
                    text = text[:-1]
                yield CollectedCVERecord.from_dict(json.loads(text))
                in_object = False
                buffer = []
                in_string = False
                escape = False


def update_json_depth(line: str, depth: int, in_string: bool, escape: bool) -> tuple[int, bool, bool]:
    for char in line:
        if escape:
            escape = False
            continue
        if char == "\\" and in_string:
            escape = True
            continue
        if char == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
    return depth, in_string, escape


def build_validation_command(collection_path: Path, *, args: argparse.Namespace) -> str:
    project_root = Path(args.project_root)
    validation_output_dir = args.validation_output_dir or str(Path(args.output_dir).expanduser().resolve() / "source_validation")
    repos_root = args.repos_root or str(Path(args.output_dir).expanduser().resolve() / "repos")
    log_path = args.log_path or str(Path(args.output_dir).expanduser().resolve() / "source_validation.log")
    command = [
        str(project_root / ".venv" / "bin" / "python"),
        str(project_root / "scripts" / "resume_cve_bootstrap_filtered.py"),
        "--collection-json",
        str(collection_path),
        "--output-dir",
        validation_output_dir,
        "--repos-root",
        repos_root,
        "--parser-backend",
        "regex",
        "--max-repos",
        str(args.validation_max_repos),
        "--git-timeout-seconds",
        str(args.git_timeout_seconds),
        "--max-source-files",
        str(args.max_source_files),
        "--max-source-bytes",
        str(args.max_source_bytes),
        "--progress-log-every",
        str(args.progress_log_every),
    ]
    return (
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f"mkdir -p {shlex.quote(str(Path(log_path).parent))}\n"
        f"nohup {' '.join(shlex.quote(part) for part in command)} > {shlex.quote(log_path)} 2>&1 &\n"
        "echo \"Started source validation PID=$!\"\n"
        f"echo \"Log: {log_path}\"\n"
    )


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def safe_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def normalize_token(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("_")
    return text or "unknown"


if __name__ == "__main__":
    raise SystemExit(main())
