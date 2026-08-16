#!/usr/bin/env python3
"""Build a CVE root-cause pattern library from an existing dataset JSON.

This is a lightweight adapter around RCPatch's ``RootCausePatternMiner``. It is
useful after LLM-guided merge stages, where the dataset has additional
traceability fields that are not part of the strict model schema.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Optional


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
VENDOR_ROOT = PROJECT_ROOT / ".vendor"
if SRC_ROOT.exists():
    sys.path.insert(0, str(SRC_ROOT))
if VENDOR_ROOT.exists():
    sys.path.insert(0, str(VENDOR_ROOT))

from rcpatch.cve_mining import RootCausePatternMiner  # noqa: E402
from rcpatch.models import (  # noqa: E402
    CVERootCauseAnnotation,
    CVERootCauseDataset,
    CVERootCauseDatasetRecord,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True, help="Input cve_root_cause_dataset*.json.")
    parser.add_argument("--output", required=True, help="Output cve_pattern_library*.json.")
    parser.add_argument("--summary-output", help="Optional summary JSON path.")
    parser.add_argument("--min-support", type=int, default=1)
    parser.add_argument("--max-examples", type=int, default=3)
    parser.add_argument("--max-templates", type=int, default=3)
    parser.add_argument(
        "--drop-none-patterns",
        action="store_true",
        help="Skip annotations whose type/pattern is none, unknown, or empty.",
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.0,
        help="Skip annotations below this confidence before pattern mining.",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    dataset_path = Path(args.dataset).expanduser().resolve()
    output_path = Path(args.output).expanduser().resolve()
    summary_path = Path(args.summary_output).expanduser().resolve() if args.summary_output else output_path.with_suffix(".summary.json")

    raw_dataset = read_json(dataset_path)
    dataset, adapter_summary = adapt_dataset(
        raw_dataset,
        drop_none_patterns=bool(args.drop_none_patterns),
        min_confidence=float(args.min_confidence),
    )
    miner = RootCausePatternMiner(
        min_support=args.min_support,
        max_examples=args.max_examples,
        max_templates=args.max_templates,
    )
    pattern_library = miner.mine(dataset, min_support=args.min_support)
    pattern_payload = pattern_library.to_dict()
    summary = build_summary(
        dataset_path=dataset_path,
        output_path=output_path,
        raw_dataset=raw_dataset,
        adapted_dataset=dataset,
        pattern_payload=pattern_payload,
        adapter_summary=adapter_summary,
        args=args,
    )
    pattern_payload["metadata"] = {
        **pattern_payload.get("metadata", {}),
        "schema_version": "rcpatch.cve_pattern_library.v3",
        "source_dataset": dataset_path.as_posix(),
        "source_dataset_schema": raw_dataset.get("metadata", {}).get("schema_version"),
        "source_dataset_record_count": len(raw_dataset.get("records", []) or []),
        "adapted_record_count": len(dataset.records),
        "adapted_annotation_count": adapter_summary["adapted_annotation_count"],
        "skipped_annotation_count": adapter_summary["skipped_annotation_count"],
        "min_confidence": float(args.min_confidence),
        "drop_none_patterns": bool(args.drop_none_patterns),
    }
    write_json(output_path, pattern_payload)
    write_json(summary_path, summary)

    print(f"Input records: {len(raw_dataset.get('records', []) or [])}")
    print(f"Adapted records: {len(dataset.records)}")
    print(f"Adapted annotations: {adapter_summary['adapted_annotation_count']}")
    print(f"Skipped annotations: {adapter_summary['skipped_annotation_count']}")
    print(f"Patterns: {len(pattern_payload.get('patterns', []) or [])}")
    print(f"Pattern library: {output_path}")
    print(f"Summary: {summary_path}")
    return 0


def adapt_dataset(
    raw_dataset: dict[str, Any],
    *,
    drop_none_patterns: bool,
    min_confidence: float,
) -> tuple[CVERootCauseDataset, dict[str, Any]]:
    records: list[CVERootCauseDatasetRecord] = []
    skipped_reasons: Counter[str] = Counter()
    adapted_annotations = 0
    source_records = raw_dataset.get("records", []) or []
    for raw_record in source_records:
        if not isinstance(raw_record, dict):
            skipped_reasons["invalid_record"] += 1
            continue
        annotations = []
        for raw_cause in raw_record.get("root_causes", []) or []:
            if not isinstance(raw_cause, dict):
                skipped_reasons["invalid_annotation"] += 1
                continue
            normalized = normalize_annotation(raw_cause)
            if normalized is None:
                skipped_reasons["invalid_annotation"] += 1
                continue
            confidence = float(normalized.get("confidence") or 0.0)
            if confidence < min_confidence:
                skipped_reasons["below_min_confidence"] += 1
                continue
            category = str(normalized.get("pattern") or normalized.get("type") or "").strip().lower()
            if drop_none_patterns and category in {"", "none", "unknown"}:
                skipped_reasons["none_or_unknown_pattern"] += 1
                continue
            try:
                annotations.append(CVERootCauseAnnotation.from_dict(normalized))
                adapted_annotations += 1
            except Exception:
                skipped_reasons["model_validation_failed"] += 1
        if not annotations:
            skipped_reasons["record_without_annotations"] += 1
            continue
        try:
            records.append(
                CVERootCauseDatasetRecord.from_dict(
                    {
                        "cve_id": str(raw_record.get("cve_id") or ""),
                        "project": raw_record.get("project"),
                        "repo_url": raw_record.get("repo_url"),
                        "root_causes": [item.to_dict() for item in annotations],
                        "diagnostics": list(raw_record.get("diagnostics") or []),
                        "metadata": dict(raw_record.get("metadata") or {}),
                    }
                )
            )
        except Exception:
            skipped_reasons["record_model_validation_failed"] += 1
    metadata = dict(raw_dataset.get("metadata") or {})
    metadata.update(
        {
            "adapted_for_pattern_mining": True,
            "source_record_count": len(source_records),
            "adapted_record_count": len(records),
            "adapted_annotation_count": adapted_annotations,
        }
    )
    return (
        CVERootCauseDataset(records=records, metadata=metadata),
        {
            "source_record_count": len(source_records),
            "adapted_record_count": len(records),
            "adapted_annotation_count": adapted_annotations,
            "skipped_annotation_count": sum(skipped_reasons.values()),
            "skipped_reasons": dict(sorted(skipped_reasons.items())),
        },
    )


def normalize_annotation(raw_cause: dict[str, Any]) -> Optional[dict[str, Any]]:
    location = raw_cause.get("location")
    if not isinstance(location, dict):
        return None
    code_snippet = str(raw_cause.get("code_snippet") or location.get("snippet") or "").strip()
    if not code_snippet:
        code_snippet = f"{location.get('file')}:{location.get('line')}"
    cause_type = str(raw_cause.get("type") or raw_cause.get("pattern") or "unknown").strip() or "unknown"
    explanation = str(raw_cause.get("explanation") or "").strip()
    if not explanation:
        explanation = "Pattern-mining annotation imported from merged CVE root-cause dataset."
    confidence = raw_cause.get("confidence")
    try:
        confidence_value = max(0.0, min(1.0, float(confidence)))
    except (TypeError, ValueError):
        confidence_value = 0.0
    patch_relation = str(raw_cause.get("patch_relation") or "unknown").strip() or "unknown"
    return {
        "rank": safe_positive_int(raw_cause.get("rank")),
        "location": {
            "file": str(location.get("file") or "").strip(),
            "line": safe_positive_int(location.get("line")) or 1,
            "column": safe_positive_int(location.get("column")),
            "end_line": safe_positive_int(location.get("end_line")),
            "end_column": safe_positive_int(location.get("end_column")),
            "function": optional_text(location.get("function")),
            "snippet": optional_text(location.get("snippet")),
            "metadata": dict(location.get("metadata") or {}),
        },
        "code_snippet": code_snippet,
        "type": cause_type,
        "classification": raw_cause.get("classification") or "root_cause_candidate",
        "pattern": optional_text(raw_cause.get("pattern")),
        "explanation": explanation,
        "confidence": confidence_value,
        "patch_relation": patch_relation,
        "candidate_rank": safe_positive_int(raw_cause.get("candidate_rank")),
        "candidate_origin": optional_text(raw_cause.get("candidate_origin")),
        "metadata": dict(raw_cause.get("metadata") or {}),
    }


def build_summary(
    *,
    dataset_path: Path,
    output_path: Path,
    raw_dataset: dict[str, Any],
    adapted_dataset: CVERootCauseDataset,
    pattern_payload: dict[str, Any],
    adapter_summary: dict[str, Any],
    args: argparse.Namespace,
) -> dict[str, Any]:
    patterns = pattern_payload.get("patterns", []) or []
    category_counts = Counter(str(pattern.get("category") or "unknown") for pattern in patterns)
    operation_counts = Counter(str(pattern.get("operation_type") or "unknown") for pattern in patterns)
    support_counts = [int(pattern.get("support_count") or 0) for pattern in patterns]
    top_patterns = [
        {
            "pattern_id": pattern.get("pattern_id"),
            "name": pattern.get("name"),
            "category": pattern.get("category"),
            "operation_type": pattern.get("operation_type"),
            "support_count": pattern.get("support_count"),
            "average_confidence": (pattern.get("metadata") or {}).get("average_confidence"),
        }
        for pattern in sorted(patterns, key=lambda item: int(item.get("support_count") or 0), reverse=True)[:25]
    ]
    return {
        "schema_version": "rcpatch.cve_pattern_library_build_summary.v3",
        "source_dataset": dataset_path.as_posix(),
        "source_dataset_schema": raw_dataset.get("metadata", {}).get("schema_version"),
        "output": output_path.as_posix(),
        "min_support": int(args.min_support),
        "max_examples": int(args.max_examples),
        "max_templates": int(args.max_templates),
        "min_confidence": float(args.min_confidence),
        "drop_none_patterns": bool(args.drop_none_patterns),
        "source_record_count": len(raw_dataset.get("records", []) or []),
        "adapted_record_count": len(adapted_dataset.records),
        "adapted_annotation_count": adapter_summary["adapted_annotation_count"],
        "skipped_annotation_count": adapter_summary["skipped_annotation_count"],
        "skipped_reasons": adapter_summary["skipped_reasons"],
        "pattern_count": len(patterns),
        "category_distribution": dict(sorted(category_counts.items(), key=lambda item: (-item[1], item[0]))),
        "operation_distribution": dict(sorted(operation_counts.items(), key=lambda item: (-item[1], item[0]))),
        "support": {
            "min": min(support_counts) if support_counts else 0,
            "max": max(support_counts) if support_counts else 0,
            "total": sum(support_counts),
        },
        "top_patterns": top_patterns,
    }


def optional_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def safe_positive_int(value: Any) -> Optional[int]:
    try:
        if value is None:
            return None
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 1 else None


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"Expected JSON object in {path}")
    return payload


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    tmp.replace(path)


if __name__ == "__main__":
    raise SystemExit(main())
