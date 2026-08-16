#!/usr/bin/env python3
"""Build RCPatch ranker calibration and project priors from curated ARVO results."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", action="append", required=True, help="ARVO result JSON or JSONL file.")
    parser.add_argument("--output-dir", required=True, help="Directory for generated prior JSON files.")
    parser.add_argument("--min-project-support", type=int, default=2)
    args = parser.parse_args(argv)

    records = []
    for raw_path in args.input:
        records.extend(load_records(Path(raw_path).expanduser().resolve()))

    project_patterns: dict[str, Counter[str]] = defaultdict(Counter)
    project_ops: dict[str, Counter[str]] = defaultdict(Counter)
    global_patterns: Counter[str] = Counter()
    global_features: Counter[str] = Counter()

    for record in records:
        project = str(record.get("project") or "unknown").strip()
        pattern = infer_pattern(record)
        operation = infer_operation(record)
        if pattern:
            project_patterns[project][pattern] += 1
            global_patterns[pattern] += 1
        if operation:
            project_ops[project][operation] += 1
        for feature in infer_feature_boosts(record):
            global_features[feature] += 1

    project_prior = {"projects": {}}
    for project in sorted(project_patterns):
        support = sum(project_patterns[project].values())
        if support < args.min_project_support:
            continue
        project_prior["projects"][project] = {
            "patterns": normalize_counter(project_patterns[project]),
            "operation_types": normalize_counter(project_ops[project]),
            "metadata": {"support_count": support},
        }

    ranker_calibration = {
        "metadata": {
            "source": "ARVO curated RCPatch-better cases",
            "record_count": len(records),
            "purpose": "Weakly calibrate ranking toward patterns repeatedly accepted by strict semantic review.",
        },
        "pattern_boosts": {
            pattern: round(min(count / max(len(records), 1), 0.08), 4)
            for pattern, count in global_patterns.items()
        },
        "feature_boosts": {
            feature: round(min(count / max(len(records), 1), 0.06), 4)
            for feature, count in global_features.items()
        },
        "contribution_weights": {
            "project_prior": 0.10,
            "cve_pattern_prior": 0.14,
        },
        "penalty_weights": {
            "trigger_symptom": 0.36,
            "pure_use_site": 0.22,
        },
        "root_cause_threshold": 0.58,
        "symptom_threshold": 0.20,
    }

    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    write_json(output_dir / "arvo_project_prior.json", project_prior)
    write_json(output_dir / "arvo_ranker_calibration.json", ranker_calibration)
    write_json(
        output_dir / "arvo_prior_summary.json",
        {
            "record_count": len(records),
            "project_count": len(project_prior["projects"]),
            "global_patterns": dict(global_patterns.most_common()),
            "global_features": dict(global_features.most_common()),
        },
    )
    print(output_dir)
    print(f"records={len(records)} projects={len(project_prior['projects'])}")
    return 0


def load_records(path: Path) -> list[dict[str, Any]]:
    if path.suffix == ".jsonl":
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict) and isinstance(payload.get("records"), list):
        return [item for item in payload["records"] if isinstance(item, dict)]
    return []


def infer_pattern(record: dict[str, Any]) -> str:
    candidates = ((record.get("bugrc") or {}).get("candidates") or [])
    for candidate in candidates:
        features = candidate.get("features") or {}
        pattern = str(features.get("matched_bug_pattern") or "")
        if pattern and pattern not in {"none", "unknown"}:
            return pattern

    text = " ".join(
        str(item or "")
        for item in [
            record.get("crash_type"),
            (((record.get("generated_patch") or {}).get("payload") or {}).get("patch_rationale")),
            (((record.get("llm_initial_root_cause") or {}).get("payload") or {}).get("likely_bug_pattern")),
        ]
    ).lower()
    if any(token in text for token in ("uninitialized", "initialize", "initialization")):
        return "invalid_initialization"
    if any(token in text for token in ("size", "length", "index", "bounds", "overflow")):
        return "incorrect_size_computation"
    if any(token in text for token in ("free", "use-after-free", "lifetime", "double-free")):
        return "ownership_or_lifetime_operation"
    if any(token in text for token in ("null", "guard", "check", "validation")):
        return "validation_or_guard_issue"
    return "invalid_state_update"


def infer_operation(record: dict[str, Any]) -> str:
    pattern = infer_pattern(record)
    if pattern == "invalid_initialization":
        return "initialization"
    if pattern == "incorrect_size_computation":
        return "length_calculation"
    if pattern == "ownership_or_lifetime_operation":
        return "lifetime_management"
    if pattern == "validation_or_guard_issue":
        return "guard_check"
    return "state_update"


def infer_feature_boosts(record: dict[str, Any]) -> Iterable[str]:
    pattern = infer_pattern(record)
    if pattern == "incorrect_size_computation":
        yield "has_integer_influence"
        yield "defines_value_used_later"
    elif pattern == "ownership_or_lifetime_operation":
        yield "has_memory_context"
        yield "changes_object_state"
    elif pattern == "validation_or_guard_issue":
        yield "affects_control_flow"
    elif pattern == "invalid_initialization":
        yield "defines_value_used_later"


def normalize_counter(counter: Counter[str]) -> dict[str, float]:
    total = sum(counter.values()) or 1
    return {key: round(value / total, 4) for key, value in counter.items()}


def write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
