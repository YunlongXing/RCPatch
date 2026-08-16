#!/usr/bin/env python3
"""Build a remaining-target refinement plan by excluding already processed CVEs.

The main refinement planner emits a full ordered plan plus a selected target
subset. This utility keeps the full plan intact and creates a new target file
for CVEs that have not yet been source-refined, so long-running batches can be
continued without overwriting earlier results.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any, Optional


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-json", required=True, help="partial_records_refinement_plan.json containing all records.")
    parser.add_argument(
        "--exclude-jsonl",
        action="append",
        default=[],
        help="JSONL files containing processed records with a cve_id field. May be repeated.",
    )
    parser.add_argument(
        "--exclude-json",
        action="append",
        default=[],
        help="JSON files containing processed records under records/targets/items or a single cve_id. May be repeated.",
    )
    parser.add_argument("--output-dir", required=True, help="Directory for the remaining target plan.")
    parser.add_argument("--max-targets", type=int, default=None, help="Optional cap for staged runs.")
    parser.add_argument("--label", default="remaining", help="Batch label stored in metadata.")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    plan_path = Path(args.plan_json).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    payload = read_json(plan_path)
    records = list(payload.get("records", []))
    excluded = load_excluded_cve_ids(args.exclude_jsonl, args.exclude_json)
    remaining = [item for item in records if str(item.get("cve_id") or "") not in excluded]
    if args.max_targets is not None:
        remaining = remaining[: max(0, args.max_targets)]

    summary = build_summary(
        source_payload=payload,
        records=records,
        remaining=remaining,
        excluded=excluded,
        label=args.label,
    )
    target_payload = {"metadata": summary, "targets": remaining}
    plan_payload = {"metadata": summary, "records": remaining}

    write_json(output_dir / "partial_records_refinement_plan.remaining.json", plan_payload)
    write_json(output_dir / "partial_records_refinement_targets.remaining.json", target_payload)
    write_jsonl(output_dir / "partial_records_refinement_plan.remaining.jsonl", remaining)
    write_csv(output_dir / "partial_records_refinement_plan.remaining.csv", remaining)
    write_markdown(output_dir / "partial_records_refinement_summary.remaining.md", summary, remaining)

    print(f"Source records: {len(records)}")
    print(f"Excluded CVEs: {len(excluded)}")
    print(f"Remaining targets: {len(remaining)}")
    print(f"Output dir: {output_dir}")
    print(f"Targets: {output_dir / 'partial_records_refinement_targets.remaining.json'}")
    return 0


def build_summary(
    *,
    source_payload: dict[str, Any],
    records: list[dict[str, Any]],
    remaining: list[dict[str, Any]],
    excluded: set[str],
    label: str,
) -> dict[str, Any]:
    return {
        "schema_version": "rcpatch.remaining_refinement_targets.v1",
        "label": label,
        "source_metadata": source_payload.get("metadata", {}),
        "source_record_count": len(records),
        "excluded_cve_count": len(excluded),
        "remaining_target_count": len(remaining),
        "priority_distribution": count_nested(remaining, ("refinement", "priority")),
        "action_distribution": count_nested(remaining, ("refinement", "primary_action")),
        "pattern_distribution": count_list_field(remaining, "patterns"),
        "top_priority_score": remaining[0].get("refinement", {}).get("priority_score") if remaining else None,
        "bottom_priority_score": remaining[-1].get("refinement", {}).get("priority_score") if remaining else None,
    }


def load_excluded_cve_ids(jsonl_paths: list[str], json_paths: list[str]) -> set[str]:
    excluded: set[str] = set()
    for raw_path in jsonl_paths:
        path = Path(raw_path).expanduser().resolve()
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                collect_cve_ids(item, excluded)
    for raw_path in json_paths:
        path = Path(raw_path).expanduser().resolve()
        if not path.exists():
            continue
        collect_cve_ids(read_json(path), excluded)
    return excluded


def collect_cve_ids(value: Any, output: set[str]) -> None:
    if isinstance(value, dict):
        cve_id = value.get("cve_id")
        if cve_id:
            output.add(str(cve_id))
        for key in ("records", "targets", "items", "root_causes"):
            nested = value.get(key)
            if isinstance(nested, list):
                for item in nested:
                    collect_cve_ids(item, output)
    elif isinstance(value, list):
        for item in value:
            collect_cve_ids(item, output)


def count_nested(records: list[dict[str, Any]], path: tuple[str, ...]) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for record in records:
        value: Any = record
        for key in path:
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(key)
        counter[str(value or "unknown")] += 1
    return dict(sorted(counter.items(), key=lambda item: (-item[1], item[0])))


def count_list_field(records: list[dict[str, Any]], field: str) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for record in records:
        values = record.get(field)
        if isinstance(values, list):
            for value in values:
                counter[str(value or "unknown")] += 1
    return dict(sorted(counter.items(), key=lambda item: (-item[1], item[0]))[:50])


def write_csv(path: Path, records: list[dict[str, Any]]) -> None:
    fields = [
        "cve_id",
        "project",
        "repo_url",
        "priority",
        "priority_score",
        "primary_action",
        "llm_confidence",
        "cve_bug_class",
        "patterns",
        "patch_relations",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for record in records:
            refinement = record.get("refinement", {})
            validation = record.get("llm_validation", {})
            writer.writerow(
                {
                    "cve_id": record.get("cve_id"),
                    "project": record.get("project"),
                    "repo_url": record.get("repo_url"),
                    "priority": refinement.get("priority"),
                    "priority_score": refinement.get("priority_score"),
                    "primary_action": refinement.get("primary_action"),
                    "llm_confidence": validation.get("confidence"),
                    "cve_bug_class": validation.get("cve_bug_class"),
                    "patterns": ";".join(str(item) for item in record.get("patterns", []) or []),
                    "patch_relations": ";".join(str(item) for item in record.get("patch_relations", []) or []),
                }
            )


def write_markdown(path: Path, summary: dict[str, Any], records: list[dict[str, Any]]) -> None:
    lines = [
        "# Remaining LLM-Guided Refinement Targets",
        "",
        f"- Source records: {summary['source_record_count']}",
        f"- Excluded CVEs: {summary['excluded_cve_count']}",
        f"- Remaining targets: {summary['remaining_target_count']}",
        f"- Top priority score: {summary['top_priority_score']}",
        f"- Bottom priority score: {summary['bottom_priority_score']}",
        "",
        "## Action Distribution",
    ]
    for key, value in summary["action_distribution"].items():
        lines.append(f"- {key}: {value}")
    lines.extend(["", "## First 20 Targets"])
    for record in records[:20]:
        refinement = record.get("refinement", {})
        lines.append(
            f"- {record.get('cve_id')}: {refinement.get('primary_action')} "
            f"score={refinement.get('priority_score')} project={record.get('project')}"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"Expected JSON object in {path}")
    return payload


def write_json(path: Path, payload: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    tmp.replace(path)


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True))
            handle.write("\n")


if __name__ == "__main__":
    raise SystemExit(main())
