#!/usr/bin/env python3
"""Build a refinement plan from LLM-validated RCPatch CVE outputs.

This script does not call an LLM. It consumes the LLM validation JSONL files and
turns "partially_correct" judgments into concrete follow-up actions for source
analysis. The goal is to use LLM feedback as navigation, not as ground truth.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Optional


DEFAULT_TARGET_LABEL = "partially_correct"
HIGH_VALUE_BUG_CLASSES = {
    "buffer_overflow",
    "heap_buffer_overflow",
    "stack_buffer_overflow",
    "out_of_bounds_read",
    "out_of_bounds_write",
    "use_after_free",
    "double_free",
    "null_dereference",
    "integer_overflow",
    "integer_underflow",
    "memory_corruption",
    "type_confusion",
}

LOCATION_WEAK_TERMS = (
    "location",
    "outside patched",
    "unrelated file",
    "not clearly",
    "does not clearly",
    "weak",
    "mismatch",
    "patch",
)
PATTERN_WEAK_TERMS = (
    "overbroad",
    "too broad",
    "generic",
    "pattern",
    "vulnerability class",
    "incorrect size",
    "wrong",
)
SYMPTOM_TERMS = (
    "symptom",
    "downstream",
    "use site",
    "crash",
    "visible",
    "consumed",
)
CONTEXT_TERMS = (
    "caller",
    "callee",
    "interprocedural",
    "data flow",
    "control flow",
    "state",
    "lifetime",
    "ownership",
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True, help="LLM annotated or original dataset JSON.")
    parser.add_argument("--record-validations", required=True, help="llm_record_validations.jsonl.")
    parser.add_argument("--pattern-validations", help="Optional llm_pattern_validations.jsonl.")
    parser.add_argument("--collection-json", help="Optional CVE collection JSON for descriptions/CWE metadata.")
    parser.add_argument("--output-dir", required=True, help="Directory for refinement plan outputs.")
    parser.add_argument("--target-label", default=DEFAULT_TARGET_LABEL, help="LLM record label to organize.")
    parser.add_argument("--top-k-targets", type=int, default=300, help="Number of highest-priority targets to emit.")
    parser.add_argument("--max-description-chars", type=int, default=900)
    parser.add_argument("--max-reasoning-chars", type=int, default=1200)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    dataset = read_json(Path(args.dataset).expanduser().resolve())
    records_by_cve = {
        str(record.get("cve_id")): record
        for record in dataset.get("records", [])
        if isinstance(record, dict) and record.get("cve_id")
    }
    validations = load_jsonl_by_key(Path(args.record_validations).expanduser().resolve(), "cve_id")
    pattern_validations = (
        load_pattern_validation_index(Path(args.pattern_validations).expanduser().resolve())
        if args.pattern_validations
        else {}
    )

    target_items = [
        item
        for item in validations.values()
        if normalize_token(item.get("validation", {}).get("label")) == normalize_token(args.target_label)
    ]
    target_cve_ids = {str(item.get("cve_id")) for item in target_items if item.get("cve_id")}
    cve_metadata = (
        load_collection_metadata(
            Path(args.collection_json).expanduser().resolve(),
            target_cve_ids,
            max_description_chars=args.max_description_chars,
        )
        if args.collection_json
        else {}
    )

    plans = []
    for item in sorted(target_items, key=lambda value: str(value.get("cve_id", ""))):
        cve_id = str(item.get("cve_id", ""))
        record = records_by_cve.get(cve_id, {})
        metadata = cve_metadata.get(cve_id, {})
        plan = build_refinement_plan(
            record=record,
            validation_item=item,
            cve_metadata=metadata,
            pattern_validations=pattern_validations,
            max_reasoning_chars=args.max_reasoning_chars,
        )
        plans.append(plan)

    plans.sort(key=lambda item: (-item["refinement"]["priority_score"], item["cve_id"]))
    targets = plans[: max(0, args.top_k_targets)]
    summary = build_summary(plans, targets, target_label=args.target_label)

    write_json(output_dir / "partial_records_refinement_plan.json", {"metadata": summary, "records": plans})
    write_jsonl(output_dir / "partial_records_refinement_plan.jsonl", plans)
    write_csv(output_dir / "partial_records_refinement_plan.csv", plans)
    write_json(output_dir / "partial_records_refinement_targets.json", {"metadata": summary, "targets": targets})
    write_markdown(output_dir / "partial_records_refinement_summary.md", summary, targets)

    print(f"Partial records: {len(plans)}")
    print(f"High-priority targets: {summary['priority_distribution'].get('high', 0)}")
    print(f"Output dir: {output_dir}")
    print(f"Plan: {output_dir / 'partial_records_refinement_plan.json'}")
    print(f"Targets: {output_dir / 'partial_records_refinement_targets.json'}")
    return 0


def build_refinement_plan(
    *,
    record: dict[str, Any],
    validation_item: dict[str, Any],
    cve_metadata: dict[str, Any],
    pattern_validations: dict[str, dict[str, Any]],
    max_reasoning_chars: int,
) -> dict[str, Any]:
    validation = validation_item.get("validation", {})
    cve_id = str(validation_item.get("cve_id") or record.get("cve_id") or "")
    root_causes = list(record.get("root_causes", []) or [])
    candidate_assessments = list(validation.get("candidate_assessments", []) or [])
    reasoning = str(validation.get("reasoning") or "")
    issues = [str(item) for item in validation.get("issues", []) or []]
    text_blob = " ".join([reasoning, " ".join(issues)]).lower()
    cve_bug_class = normalize_token(validation.get("cve_bug_class"))
    pattern_assessment = normalize_token(validation.get("root_cause_pattern_assessment"))

    candidate_index = candidate_assessment_index(candidate_assessments)
    candidate_actions = []
    for cause in root_causes:
        rank = cause.get("rank") or cause.get("candidate_rank")
        assessment = candidate_index.get(str(rank), {})
        candidate_actions.append(
            classify_candidate_action(
                cause=cause,
                assessment=assessment,
                text_blob=text_blob,
                pattern_validation=lookup_pattern_validation(cause, pattern_validations),
            )
        )

    action = choose_refinement_action(
        validation=validation,
        root_causes=root_causes,
        candidate_actions=candidate_actions,
        text_blob=text_blob,
        cve_bug_class=cve_bug_class,
        pattern_assessment=pattern_assessment,
    )
    priority_score = compute_priority_score(
        validation=validation,
        action=action,
        cve_bug_class=cve_bug_class,
        candidate_actions=candidate_actions,
        text_blob=text_blob,
    )
    priority = priority_bucket(priority_score)
    start_locations = select_start_locations(root_causes, candidate_actions)
    demote_ranks = [
        item["rank"]
        for item in candidate_actions
        if item["candidate_refinement"] in {"demote_symptom_or_noise", "replace_candidate"}
    ]
    promote_ranks = [
        item["rank"]
        for item in candidate_actions
        if item["candidate_refinement"] in {"retain_candidate", "promote_for_recheck"}
    ]

    return {
        "schema_version": "rcpatch.llm_guided_refinement_plan.v1",
        "cve_id": cve_id,
        "project": record.get("project") or cve_metadata.get("project"),
        "repo_url": record.get("repo_url") or cve_metadata.get("repo_url"),
        "cwe": cve_metadata.get("cwe"),
        "description": cve_metadata.get("description"),
        "llm_validation": {
            "label": normalize_token(validation.get("label")),
            "confidence": safe_float(validation.get("confidence")),
            "recommended_action": normalize_token(validation.get("recommended_action")),
            "cve_bug_class": cve_bug_class,
            "root_cause_pattern_assessment": pattern_assessment,
            "reasoning": truncate_text(reasoning, max_reasoning_chars),
            "issues": issues,
        },
        "refinement": {
            "primary_action": action,
            "priority": priority,
            "priority_score": priority_score,
            "start_locations": start_locations,
            "promote_candidate_ranks": promote_ranks,
            "demote_candidate_ranks": demote_ranks,
            "suggested_query_terms": suggested_query_terms(validation, root_causes),
            "instructions": refinement_instructions(action),
        },
        "candidate_actions": candidate_actions,
        "root_cause_count": len(root_causes),
        "patch_relations": sorted({str(cause.get("patch_relation") or "unknown") for cause in root_causes}),
        "patterns": sorted({str(cause.get("pattern") or cause.get("type") or "unknown") for cause in root_causes}),
    }


def classify_candidate_action(
    *,
    cause: dict[str, Any],
    assessment: dict[str, Any],
    text_blob: str,
    pattern_validation: Optional[dict[str, Any]],
) -> dict[str, Any]:
    assessment_label = normalize_token(assessment.get("label"))
    patch_relation = normalize_token(cause.get("patch_relation"))
    cause_pattern = normalize_token(cause.get("pattern") or cause.get("type"))
    pattern_label = normalize_token((pattern_validation or {}).get("validation", {}).get("label"))
    pattern_action = normalize_token((pattern_validation or {}).get("validation", {}).get("recommended_action"))

    if assessment_label == "correct":
        candidate_refinement = "retain_candidate"
    elif assessment_label == "partially_correct":
        candidate_refinement = "promote_for_recheck"
    elif assessment_label in {"likely_incorrect", "uncertain"}:
        candidate_refinement = "replace_candidate"
    elif patch_relation in {"patch_anchor_overlap", "patched_statement", "same_function_as_patch"}:
        candidate_refinement = "promote_for_recheck"
    elif patch_relation == "outside_patched_files" and contains_any(text_blob, LOCATION_WEAK_TERMS):
        candidate_refinement = "demote_symptom_or_noise"
    else:
        candidate_refinement = "recheck_with_more_context"

    if pattern_label in {"weak_or_noisy", "likely_incorrect"} or pattern_action == "drop":
        pattern_refinement = "avoid_or_split_pattern"
    elif pattern_label == "valid_but_broad" or pattern_action in {"manual_review", "merge"}:
        pattern_refinement = "specialize_pattern"
    elif cause_pattern in {"none", "unknown", "incorrect_size_computation"} and contains_any(text_blob, PATTERN_WEAK_TERMS):
        pattern_refinement = "specialize_pattern"
    else:
        pattern_refinement = "keep_pattern_signal"

    return {
        "rank": cause.get("rank") or cause.get("candidate_rank"),
        "location": cause.get("location"),
        "code_snippet": cause.get("code_snippet") or (cause.get("location", {}) or {}).get("snippet"),
        "candidate_type": cause.get("type"),
        "pattern": cause.get("pattern"),
        "patch_relation": cause.get("patch_relation"),
        "bugrc_confidence": cause.get("confidence"),
        "llm_candidate_label": assessment_label or "missing",
        "llm_candidate_confidence": safe_float(assessment.get("confidence")),
        "llm_candidate_reasoning": truncate_text(str(assessment.get("reasoning") or ""), 500),
        "candidate_refinement": candidate_refinement,
        "pattern_refinement": pattern_refinement,
    }


def choose_refinement_action(
    *,
    validation: dict[str, Any],
    root_causes: list[dict[str, Any]],
    candidate_actions: list[dict[str, Any]],
    text_blob: str,
    cve_bug_class: str,
    pattern_assessment: str,
) -> str:
    recommended_action = normalize_token(validation.get("recommended_action"))
    all_patch_relations = {normalize_token(cause.get("patch_relation")) for cause in root_causes}
    candidate_refinements = {item["candidate_refinement"] for item in candidate_actions}
    pattern_refinements = {item["pattern_refinement"] for item in candidate_actions}

    if recommended_action == "manual_review" and safe_float(validation.get("confidence")) < 0.55:
        return "manual_review_due_to_weak_evidence"
    if "replace_candidate" in candidate_refinements or contains_any(text_blob, SYMPTOM_TERMS):
        return "demote_symptoms_and_search_upstream"
    if "outside_patched_files" in all_patch_relations and contains_any(text_blob, LOCATION_WEAK_TERMS):
        return "rerun_slice_from_patch_context"
    if pattern_assessment in {"overbroad", "wrong", "insufficient_evidence"} or "specialize_pattern" in pattern_refinements:
        return "specialize_root_cause_pattern"
    if contains_any(text_blob, CONTEXT_TERMS):
        return "expand_interprocedural_context"
    if recommended_action == "keep_with_lower_confidence":
        return "retain_but_lower_confidence"
    if cve_bug_class in HIGH_VALUE_BUG_CLASSES:
        return "rerun_slice_from_patch_context"
    return "manual_review"


def compute_priority_score(
    *,
    validation: dict[str, Any],
    action: str,
    cve_bug_class: str,
    candidate_actions: list[dict[str, Any]],
    text_blob: str,
) -> float:
    score = safe_float(validation.get("confidence")) * 45.0
    if cve_bug_class in HIGH_VALUE_BUG_CLASSES:
        score += 18.0
    if action in {
        "rerun_slice_from_patch_context",
        "demote_symptoms_and_search_upstream",
        "specialize_root_cause_pattern",
    }:
        score += 20.0
    if any(item["candidate_refinement"] in {"retain_candidate", "promote_for_recheck"} for item in candidate_actions):
        score += 10.0
    if any(item["candidate_refinement"] == "replace_candidate" for item in candidate_actions):
        score += 8.0
    if contains_any(text_blob, ("vague", "insufficient", "too vague", "not enough")):
        score -= 15.0
    return round(max(0.0, min(100.0, score)), 2)


def priority_bucket(score: float) -> str:
    if score >= 75:
        return "high"
    if score >= 50:
        return "medium"
    return "low"


def select_start_locations(
    root_causes: list[dict[str, Any]],
    candidate_actions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    preferred_relations = {"patched_statement", "patch_anchor_overlap", "same_function_as_patch", "same_file_as_patch"}
    action_by_rank = {str(item["rank"]): item for item in candidate_actions}
    locations = []
    for cause in root_causes:
        rank = cause.get("rank") or cause.get("candidate_rank")
        action = action_by_rank.get(str(rank), {})
        patch_relation = str(cause.get("patch_relation") or "")
        if patch_relation not in preferred_relations and action.get("candidate_refinement") == "demote_symptom_or_noise":
            continue
        location = cause.get("location") or {}
        locations.append(
            {
                "rank": rank,
                "file": location.get("file"),
                "line": location.get("line"),
                "function": location.get("function"),
                "patch_relation": cause.get("patch_relation"),
                "reason": action.get("candidate_refinement", "recheck"),
            }
        )
    if locations:
        return locations[:5]
    for cause in root_causes[:5]:
        location = cause.get("location") or {}
        locations.append(
            {
                "rank": cause.get("rank") or cause.get("candidate_rank"),
                "file": location.get("file"),
                "line": location.get("line"),
                "function": location.get("function"),
                "patch_relation": cause.get("patch_relation"),
                "reason": "fallback_existing_candidate",
            }
        )
    return locations


def suggested_query_terms(validation: dict[str, Any], root_causes: list[dict[str, Any]]) -> list[str]:
    terms = {
        normalize_token(validation.get("cve_bug_class")),
        normalize_token(validation.get("root_cause_pattern_assessment")),
    }
    for cause in root_causes:
        for key in ("type", "pattern", "patch_relation"):
            terms.add(normalize_token(cause.get(key)))
    for issue in validation.get("issues", []) or []:
        for token in re.findall(r"[A-Za-z][A-Za-z0-9_]{3,}", str(issue)):
            terms.add(normalize_token(token))
    return sorted(term for term in terms if term not in {"unknown", "none"})[:16]


def refinement_instructions(action: str) -> list[str]:
    mapping = {
        "rerun_slice_from_patch_context": [
            "Use patch hunks and changed functions as anchors instead of the old top-ranked candidate.",
            "Run backward slicing from patched statements and nearby guard/computation edits.",
            "Prefer same-function and same-file definitions before accepting outside-file candidates.",
        ],
        "demote_symptoms_and_search_upstream": [
            "Lower scores for candidates that the LLM judged as likely symptom/noise.",
            "Continue slicing upstream through definitions, guards, size computations, ownership updates, and call arguments.",
            "Require a concrete invariant violation before labeling the new candidate as root cause.",
        ],
        "specialize_root_cause_pattern": [
            "Map broad RCPatch patterns to a CVE-specific subtype from the LLM bug-class hint.",
            "Separate size-calculation, bounds-check, lifetime, state-transition, and validation failures.",
            "Do not keep generic 'none' or overly broad pattern labels unless code evidence is strong.",
        ],
        "expand_interprocedural_context": [
            "Expand through callers, callee returns, global state, heap aliases, and ownership transfers.",
            "Use the LLM reasoning only to choose expansion direction, not as proof.",
        ],
        "retain_but_lower_confidence": [
            "Keep the current candidate as weak supervision.",
            "Reduce confidence until code/patch evidence confirms the exact root-cause statement.",
        ],
        "manual_review_due_to_weak_evidence": [
            "Queue for human review or external advisory lookup.",
            "Avoid generating a new ground-truth root cause from weak CVE text alone.",
        ],
        "manual_review": [
            "Review manually before using as training ground truth.",
            "Use current evidence only as a candidate prior.",
        ],
    }
    return mapping.get(action, mapping["manual_review"])


def candidate_assessment_index(candidate_assessments: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    index = {}
    for item in candidate_assessments:
        rank = item.get("rank")
        if rank is not None:
            index[str(rank)] = item
    return index


def lookup_pattern_validation(
    cause: dict[str, Any],
    pattern_validations: dict[str, dict[str, Any]],
) -> Optional[dict[str, Any]]:
    candidates = [
        normalize_token(cause.get("pattern")),
        normalize_token(cause.get("type")),
        normalize_token(cause.get("metadata", {}).get("matched_bug_pattern") if isinstance(cause.get("metadata"), dict) else None),
    ]
    for key in candidates:
        if key in pattern_validations:
            return pattern_validations[key]
    return None


def load_pattern_validation_index(path: Path) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for item in load_jsonl(path):
        keys = {
            normalize_token(item.get("pattern_id")),
            normalize_token(item.get("name")),
            normalize_token(item.get("category")),
            normalize_token(item.get("input_summary", {}).get("category") if isinstance(item.get("input_summary"), dict) else None),
        }
        for key in keys:
            if key and key not in {"unknown", "none"}:
                index.setdefault(key, item)
    return index


def build_summary(plans: list[dict[str, Any]], targets: list[dict[str, Any]], *, target_label: str = DEFAULT_TARGET_LABEL) -> dict[str, Any]:
    return {
        "schema_version": "rcpatch.llm_guided_refinement_plan.v1",
        "target_label": target_label,
        "partial_record_count": len(plans),
        "target_count": len(targets),
        "priority_distribution": dict(Counter(item["refinement"]["priority"] for item in plans).most_common()),
        "action_distribution": dict(Counter(item["refinement"]["primary_action"] for item in plans).most_common()),
        "bug_class_distribution": dict(Counter(item["llm_validation"]["cve_bug_class"] for item in plans).most_common(25)),
        "pattern_assessment_distribution": dict(
            Counter(item["llm_validation"]["root_cause_pattern_assessment"] for item in plans).most_common(25)
        ),
        "top_target_cve_ids": [item["cve_id"] for item in targets[:50]],
    }


def write_markdown(path: Path, summary: dict[str, Any], targets: list[dict[str, Any]]) -> None:
    lines = [
        "# LLM-Guided Refinement Summary",
        "",
        f"Partial records: {summary['partial_record_count']}",
        f"Selected targets: {summary['target_count']}",
        "",
        "## Priority Distribution",
        "",
    ]
    for key, value in summary["priority_distribution"].items():
        lines.append(f"- {key}: {value}")
    lines.extend(["", "## Action Distribution", ""])
    for key, value in summary["action_distribution"].items():
        lines.append(f"- {key}: {value}")
    lines.extend(["", "## Top Targets", ""])
    for item in targets[:30]:
        lines.append(
            "- "
            f"{item['cve_id']} | {item['refinement']['priority']} "
            f"({item['refinement']['priority_score']}) | "
            f"{item['refinement']['primary_action']} | "
            f"{item['llm_validation']['cve_bug_class']}"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_csv(path: Path, plans: list[dict[str, Any]]) -> None:
    fields = [
        "cve_id",
        "priority",
        "priority_score",
        "primary_action",
        "cve_bug_class",
        "pattern_assessment",
        "llm_confidence",
        "recommended_action",
        "root_cause_count",
        "patterns",
        "patch_relations",
        "repo_url",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for item in plans:
            writer.writerow(
                {
                    "cve_id": item["cve_id"],
                    "priority": item["refinement"]["priority"],
                    "priority_score": item["refinement"]["priority_score"],
                    "primary_action": item["refinement"]["primary_action"],
                    "cve_bug_class": item["llm_validation"]["cve_bug_class"],
                    "pattern_assessment": item["llm_validation"]["root_cause_pattern_assessment"],
                    "llm_confidence": item["llm_validation"]["confidence"],
                    "recommended_action": item["llm_validation"]["recommended_action"],
                    "root_cause_count": item["root_cause_count"],
                    "patterns": ";".join(item["patterns"]),
                    "patch_relations": ";".join(item["patch_relations"]),
                    "repo_url": item.get("repo_url"),
                }
            )


def load_jsonl_by_key(path: Path, key_field: str) -> dict[str, dict[str, Any]]:
    result = {}
    for item in load_jsonl(path):
        key = item.get(key_field)
        if key:
            result[str(key)] = item
    return result


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    items = []
    if not path.exists():
        return items
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                items.append(item)
    return items


def load_collection_metadata(path: Path, cve_ids: set[str], *, max_description_chars: int) -> dict[str, dict[str, Any]]:
    metadata: dict[str, dict[str, Any]] = {}
    for record in iter_collection_records(path):
        cve_id = str(record.get("cve_id", ""))
        if cve_id not in cve_ids:
            continue
        metadata[cve_id] = {
            "description": truncate_text(str(record.get("description") or ""), max_description_chars),
            "cwe": record.get("cwe"),
            "project": record.get("project"),
            "repo_url": record.get("repo_url"),
            "fix_commits": record.get("fix_commits", [])[:5] if isinstance(record.get("fix_commits"), list) else [],
        }
        if len(metadata) >= len(cve_ids):
            break
    return metadata


def iter_collection_records(path: Path) -> Iterable[dict[str, Any]]:
    in_records = False
    in_object = False
    depth = 0
    buffer: list[str] = []
    in_string = False
    escape = False
    with path.open("r", encoding="utf-8", errors="replace") as handle:
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
                try:
                    item = json.loads(text)
                except json.JSONDecodeError:
                    item = {}
                if isinstance(item, dict):
                    yield item
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


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False), encoding="utf-8")


def write_jsonl(path: Path, items: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for item in items:
            handle.write(json.dumps(item, sort_keys=True, ensure_ascii=False) + "\n")


def contains_any(text: str, terms: Iterable[str]) -> bool:
    return any(term in text for term in terms)


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


def truncate_text(text: str, limit: int) -> str:
    cleaned = text.strip()
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: max(0, limit - 3)].rstrip() + "..."


if __name__ == "__main__":
    raise SystemExit(main())
