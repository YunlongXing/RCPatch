#!/usr/bin/env python3
"""Second-pass LLM validation and v2 merge for refined CVE root-cause records.

This script validates source-refined records produced by
``run_llm_guided_source_refinement.py``. The LLM is used only as an
evidence-bounded judge: it may accept, down-rank, or reject RCPatch's existing
refined candidates, but it must not invent new locations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import time
from collections import Counter
from pathlib import Path
from typing import Any, Optional
from urllib import error as urllib_error
from urllib import request as urllib_request


SCHEMA_VERSION = "rcpatch.refined_secondary_llm_validation.v1"
V2_DATASET_SCHEMA = "rcpatch.cve_root_cause_dataset.v2"
PROMPT_VERSION = "bugrc-refined-record-secondary-validation-v1"

DEFAULT_MODEL = os.getenv("RCPATCH_LLM_VALIDATION_MODEL", os.getenv("BUGRC_LLM_VALIDATION_MODEL", "gpt-4.1-mini"))
DEFAULT_BASE_URL = os.getenv("RCPATCH_LLM_BASE_URL", os.getenv("BUGRC_LLM_BASE_URL", "https://api.openai.com/v1"))

VERDICTS = {"accept", "accept_with_lower_confidence", "manual_review", "reject"}
QUALITY_LABELS = {
    "strong_improvement",
    "plausible_improvement",
    "plausible_but_broad",
    "no_clear_improvement",
    "likely_wrong",
}
MERGE_RECOMMENDATIONS = {"replace_original", "append_as_alternative", "do_not_merge"}
CANDIDATE_LABELS = {"root_cause", "plausible_root_cause", "propagation", "symptom_or_noise", "uncertain"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refined-dataset", required=True, help="Path to refined_dataset.json.")
    parser.add_argument("--base-dataset", required=True, help="Base LLM-filtered dataset to merge into.")
    parser.add_argument("--output-dir", required=True, help="Directory for validation and v2 outputs.")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="OpenAI-compatible model name.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="OpenAI-compatible API base URL.")
    parser.add_argument("--timeout-seconds", type=float, default=60.0)
    parser.add_argument("--max-retries", type=int, default=6)
    parser.add_argument("--sleep-seconds", type=float, default=0.12)
    parser.add_argument("--checkpoint-every", type=int, default=20)
    parser.add_argument("--max-records", type=int, default=None, help="Optional smoke-test cap.")
    parser.add_argument("--min-merge-confidence", type=float, default=0.65)
    parser.add_argument(
        "--output-dataset-name",
        default="cve_root_cause_dataset.v2.json",
        help="Merged dataset file name written under output-dir.",
    )
    parser.add_argument(
        "--merged-schema-version",
        default=V2_DATASET_SCHEMA,
        help="Schema version recorded in the merged dataset metadata.",
    )
    parser.add_argument(
        "--merge-source-label",
        default="llm_guided_source_refinement",
        help="Traceability label stored on records replaced/appended by this merge.",
    )
    parser.add_argument("--force", action="store_true", help="Ignore existing validation JSONL.")
    parser.add_argument("--dry-run", action="store_true", help="Build outputs without provider calls.")
    parser.add_argument("--log-level", default="INFO", choices=("DEBUG", "INFO", "WARNING", "ERROR"))
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
    logger = logging.getLogger("rcpatch.secondary_refined_validation")

    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    cache_dir = output_dir / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)

    api_key = os.getenv("RCPATCH_OPENAI_API_KEY") or os.getenv("BUGRC_OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not api_key and not args.dry_run:
        logger.error("RCPATCH_OPENAI_API_KEY, BUGRC_OPENAI_API_KEY, or OPENAI_API_KEY must be set")
        return 2

    refined_dataset = read_json(Path(args.refined_dataset).expanduser().resolve())
    base_dataset = read_json(Path(args.base_dataset).expanduser().resolve())
    refined_records = list(refined_dataset.get("records", []))
    if args.max_records is not None:
        refined_records = refined_records[: max(0, args.max_records)]

    provider = OpenAIJSONClient(
        api_key=api_key or "",
        model=args.model,
        base_url=args.base_url,
        timeout_seconds=args.timeout_seconds,
        max_retries=args.max_retries,
        sleep_seconds=args.sleep_seconds,
        cache_dir=cache_dir,
        dry_run=bool(args.dry_run),
    )

    validations_path = output_dir / "secondary_refined_validations.jsonl"
    completed = {} if args.force else load_existing_jsonl(validations_path, key_field="cve_id")
    status_path = output_dir / "secondary_validation_status.json"
    write_status(status_path, state="running", total_records=len(refined_records), completed=len(completed))

    live_calls = 0
    for index, record in enumerate(refined_records, start=1):
        cve_id = str(record.get("cve_id") or "")
        if not cve_id or cve_id in completed:
            continue
        payload = build_prompt_payload(record)
        result = provider.complete_json(
            task="refined_cve_root_cause_secondary_validation",
            prompt_version=PROMPT_VERSION,
            system_prompt=system_prompt(),
            user_payload=payload,
            max_tokens=1000,
        )
        validation = normalize_validation(result.payload, min_merge_confidence=args.min_merge_confidence)
        item = {
            "schema_version": SCHEMA_VERSION,
            "item_kind": "refined_root_cause_record",
            "cve_id": cve_id,
            "record_index": index,
            "model": args.model,
            "cached": result.cached,
            "provider_metadata": result.metadata,
            "validation": validation,
            "input_summary": input_summary(record),
        }
        append_jsonl(validations_path, item)
        completed[cve_id] = item
        live_calls += 0 if result.cached else 1
        if index % args.checkpoint_every == 0 or live_calls % args.checkpoint_every == 0:
            logger.info("Secondary validation progress: %d/%d", len(completed), len(refined_records))
            write_outputs(
                output_dir,
                base_dataset,
                refined_dataset,
                completed,
                args.min_merge_confidence,
                output_dataset_name=args.output_dataset_name,
                merged_schema_version=args.merged_schema_version,
                merge_source_label=args.merge_source_label,
            )
            write_status(
                status_path,
                state="running",
                total_records=len(refined_records),
                completed=len(completed),
                live_calls=live_calls,
            )

    write_outputs(
        output_dir,
        base_dataset,
        refined_dataset,
        completed,
        args.min_merge_confidence,
        output_dataset_name=args.output_dataset_name,
        merged_schema_version=args.merged_schema_version,
        merge_source_label=args.merge_source_label,
    )
    write_status(
        status_path,
        state="finished",
        total_records=len(refined_records),
        completed=len(completed),
        live_calls=live_calls,
    )
    logger.info("Secondary validation complete: %d/%d", len(completed), len(refined_records))
    return 0


class LLMCallResult:
    def __init__(self, *, payload: dict[str, Any], cached: bool, metadata: dict[str, Any]) -> None:
        self.payload = payload
        self.cached = cached
        self.metadata = metadata


class OpenAIJSONClient:
    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        base_url: str,
        timeout_seconds: float,
        max_retries: int,
        sleep_seconds: float,
        cache_dir: Path,
        dry_run: bool,
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.sleep_seconds = sleep_seconds
        self.cache_dir = cache_dir
        self.dry_run = dry_run

    def complete_json(
        self,
        *,
        task: str,
        prompt_version: str,
        system_prompt: str,
        user_payload: dict[str, Any],
        max_tokens: int,
    ) -> LLMCallResult:
        cache_key = stable_hash(
            {
                "task": task,
                "prompt_version": prompt_version,
                "model": self.model,
                "system_prompt": system_prompt,
                "user_payload": user_payload,
            }
        )
        cache_path = self.cache_dir / f"{cache_key}.json"
        if cache_path.exists():
            return LLMCallResult(payload=read_json(cache_path), cached=True, metadata={"cache_key": cache_key})
        if self.dry_run:
            payload = dry_run_payload()
            write_json(cache_path, payload)
            return LLMCallResult(payload=payload, cached=False, metadata={"cache_key": cache_key, "dry_run": True})

        body = {
            "model": self.model,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False, sort_keys=True)},
            ],
        }
        request = urllib_request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        last_error: Optional[BaseException] = None
        for attempt in range(self.max_retries + 1):
            try:
                with urllib_request.urlopen(request, timeout=self.timeout_seconds) as response:
                    response_payload = json.loads(response.read().decode("utf-8"))
                text = response_payload["choices"][0]["message"]["content"]
                payload = parse_json_object(text)
                write_json(cache_path, payload)
                if self.sleep_seconds > 0:
                    time.sleep(self.sleep_seconds)
                return LLMCallResult(
                    payload=payload,
                    cached=False,
                    metadata={
                        "cache_key": cache_key,
                        "usage": response_payload.get("usage", {}),
                        "finish_reason": response_payload.get("choices", [{}])[0].get("finish_reason"),
                    },
                )
            except (urllib_error.HTTPError, urllib_error.URLError, TimeoutError, json.JSONDecodeError, KeyError) as exc:
                last_error = exc
                if attempt >= self.max_retries:
                    break
                time.sleep(min(45.0, 2.0**attempt))
        raise RuntimeError(f"LLM request failed after retries: {last_error}")


def system_prompt() -> str:
    return (
        "You are validating refined CVE root-cause candidates for RCPatch. "
        "Use only the CVE description, patch metadata, prior LLM guidance, old candidate actions, "
        "and refined source candidates provided by the user. Do not invent new files, functions, "
        "line numbers, or root causes. Judge whether the refined candidates should be merged into "
        "the dataset as better root-cause annotations. Prefer concrete upstream state, bounds, "
        "validation, lifetime, or size-computation causes over crash-site symptoms. Return only JSON "
        "with keys: verdict, quality_label, confidence, best_candidate_ranks, candidate_assessments, "
        "merge_recommendation, reasoning, issues. verdict must be one of accept, "
        "accept_with_lower_confidence, manual_review, reject. quality_label must be one of "
        "strong_improvement, plausible_improvement, plausible_but_broad, no_clear_improvement, "
        "likely_wrong. merge_recommendation must be one of replace_original, append_as_alternative, "
        "do_not_merge. candidate_assessments must contain objects with rank, label, confidence, "
        "reasoning, where label is one of root_cause, plausible_root_cause, propagation, "
        "symptom_or_noise, uncertain."
    )


def build_prompt_payload(record: dict[str, Any]) -> dict[str, Any]:
    refined = [compact_refined_candidate(item) for item in (record.get("refined_root_causes") or [])[:5]]
    old_actions = [compact_old_action(item) for item in (record.get("old_candidate_actions") or [])[:5]]
    return {
        "prompt_version": PROMPT_VERSION,
        "task": "secondary_validate_refined_root_cause_record",
        "cve_id": record.get("cve_id"),
        "project": record.get("project"),
        "repo_url": record.get("repo_url"),
        "cve_description": truncate_text(str(record.get("description") or ""), 1600),
        "prior_llm_guidance": compact_mapping(record.get("llm_guidance") or {}, max_chars=1800),
        "refinement_plan": compact_mapping(record.get("refinement_plan") or {}, max_chars=1800),
        "patch": compact_mapping(record.get("patch") or {}, max_chars=1400),
        "old_candidate_actions": old_actions,
        "refined_candidates": refined,
        "decision_policy": {
            "accept": "Use when at least one refined candidate is a well-supported root cause aligned with the CVE and patch/source evidence.",
            "accept_with_lower_confidence": "Use when refined candidates are plausible and better than old candidates but still broad or partly patch-anchor-like.",
            "manual_review": "Use when evidence is mixed, overly broad, or candidate ranks include both plausible and suspicious items.",
            "reject": "Use when refined candidates remain unrelated symptoms/noise or contradict the CVE.",
        },
    }


def compact_refined_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    location = candidate.get("location") or {}
    return {
        "rank": candidate.get("rank"),
        "location": {
            "file": location.get("file"),
            "function": location.get("function"),
            "line": location.get("line"),
            "snippet": truncate_text(str(location.get("snippet") or ""), 260),
        },
        "code_snippet": truncate_text(str(candidate.get("code_snippet") or ""), 500),
        "pattern": candidate.get("pattern") or candidate.get("type"),
        "classification": candidate.get("classification"),
        "source_score": candidate.get("source_score"),
        "refined_score": candidate.get("refined_score"),
        "patch_relation": candidate.get("patch_relation"),
        "candidate_origin": candidate.get("candidate_origin"),
        "explanation": truncate_text(str(candidate.get("explanation") or ""), 500),
        "guidance_reasons": list(candidate.get("guidance_reasons") or [])[:5],
        "features": compact_mapping(candidate.get("features") or {}, max_chars=900),
    }


def compact_old_action(action: dict[str, Any]) -> dict[str, Any]:
    location = action.get("location") or {}
    return {
        "rank": action.get("rank"),
        "candidate_refinement": action.get("candidate_refinement"),
        "llm_candidate_label": action.get("llm_candidate_label"),
        "llm_candidate_confidence": action.get("llm_candidate_confidence"),
        "patch_relation": action.get("patch_relation"),
        "pattern": action.get("pattern") or action.get("candidate_type"),
        "location": {
            "file": location.get("file"),
            "function": location.get("function"),
            "line": location.get("line"),
            "snippet": truncate_text(str(location.get("snippet") or action.get("code_snippet") or ""), 260),
        },
        "reasoning": truncate_text(str(action.get("llm_candidate_reasoning") or ""), 500),
    }


def normalize_validation(payload: dict[str, Any], *, min_merge_confidence: float) -> dict[str, Any]:
    verdict = normalize_choice(payload.get("verdict"), VERDICTS, "manual_review")
    quality_label = normalize_choice(payload.get("quality_label"), QUALITY_LABELS, "no_clear_improvement")
    merge_recommendation = normalize_choice(payload.get("merge_recommendation"), MERGE_RECOMMENDATIONS, "do_not_merge")
    confidence = clamp_confidence(payload.get("confidence"))
    assessments = []
    for item in payload.get("candidate_assessments") or []:
        if not isinstance(item, dict):
            continue
        rank = safe_int(item.get("rank"))
        if rank is None:
            continue
        assessments.append(
            {
                "rank": rank,
                "label": normalize_choice(item.get("label"), CANDIDATE_LABELS, "uncertain"),
                "confidence": clamp_confidence(item.get("confidence")),
                "reasoning": truncate_text(str(item.get("reasoning") or ""), 500),
            }
        )
    best_ranks = []
    for rank in payload.get("best_candidate_ranks") or []:
        value = safe_int(rank)
        if value is not None and value not in best_ranks:
            best_ranks.append(value)
    if not best_ranks:
        best_ranks = [
            item["rank"]
            for item in assessments
            if item["label"] in {"root_cause", "plausible_root_cause"} and item["confidence"] >= 0.55
        ][:3]
    passed = (
        verdict in {"accept", "accept_with_lower_confidence"}
        and merge_recommendation != "do_not_merge"
        and confidence >= min_merge_confidence
        and bool(best_ranks)
    )
    return {
        "verdict": verdict,
        "quality_label": quality_label,
        "confidence": confidence,
        "best_candidate_ranks": best_ranks[:5],
        "candidate_assessments": assessments[:8],
        "merge_recommendation": merge_recommendation,
        "reasoning": truncate_text(str(payload.get("reasoning") or ""), 1000),
        "issues": normalize_string_list(payload.get("issues")),
        "passed_for_v2_merge": passed,
        "raw_payload": payload,
    }


def write_outputs(
    output_dir: Path,
    base_dataset: dict[str, Any],
    refined_dataset: dict[str, Any],
    validations: dict[str, dict[str, Any]],
    min_merge_confidence: float,
    *,
    output_dataset_name: str,
    merged_schema_version: str,
    merge_source_label: str,
) -> None:
    refined_records = list(refined_dataset.get("records", []))
    by_cve = {str(record.get("cve_id")): record for record in refined_records if record.get("cve_id")}
    annotated = []
    passed = []
    for record in refined_records:
        cve_id = str(record.get("cve_id") or "")
        cloned = dict(record)
        validation_item = validations.get(cve_id)
        if validation_item is not None:
            cloned["secondary_llm_validation"] = validation_item["validation"]
            if validation_item["validation"].get("passed_for_v2_merge"):
                passed.append(cloned)
        annotated.append(cloned)

    base_records = list(base_dataset.get("records", []))
    replaced = 0
    appended = 0
    passed_ids = {str(record.get("cve_id")) for record in passed}
    merged_records = []
    for record in base_records:
        cve_id = str(record.get("cve_id") or "")
        if cve_id in passed_ids:
            merged_records.append(
                convert_refined_to_v2_record(
                    by_cve[cve_id],
                    validations[cve_id]["validation"],
                    original_record=record,
                    merged_schema_version=merged_schema_version,
                    merge_source_label=merge_source_label,
                )
            )
            replaced += 1
        else:
            merged_records.append(record)
    base_ids = {str(record.get("cve_id") or "") for record in base_records}
    for cve_id in sorted(passed_ids - base_ids):
        merged_records.append(
            convert_refined_to_v2_record(
                by_cve[cve_id],
                validations[cve_id]["validation"],
                original_record=None,
                merged_schema_version=merged_schema_version,
                merge_source_label=merge_source_label,
            )
        )
        appended += 1

    summary = build_summary(validations, base_dataset, refined_dataset, replaced=replaced, appended=appended, min_merge_confidence=min_merge_confidence)
    metadata = dict(base_dataset.get("metadata", {}))
    metadata.update(
        {
            "schema_version": merged_schema_version,
            "record_count": len(merged_records),
            "base_record_count": len(base_records),
            "secondary_validation_schema": SCHEMA_VERSION,
            "secondary_validated_refined_records": len(validations),
            "secondary_passed_refined_records": summary["passed_for_v2_merge_count"],
            "secondary_replaced_records": replaced,
            "secondary_appended_records": appended,
            "min_merge_confidence": min_merge_confidence,
        }
    )
    v2_dataset = {"metadata": metadata, "records": merged_records}

    write_json(output_dir / "refined_records.secondary_llm_annotated.json", {"metadata": summary, "records": annotated})
    write_json(output_dir / "refined_records.secondary_llm_passed.json", {"metadata": summary, "records": passed})
    write_json(output_dir / output_dataset_name, v2_dataset)
    write_json(output_dir / "secondary_llm_validation_summary.json", summary)


def convert_refined_to_v2_record(
    record: dict[str, Any],
    validation: dict[str, Any],
    *,
    original_record: Optional[dict[str, Any]],
    merged_schema_version: str,
    merge_source_label: str,
) -> dict[str, Any]:
    allowed_ranks = set(validation.get("best_candidate_ranks") or [])
    assessments = {item["rank"]: item for item in validation.get("candidate_assessments", [])}
    refined_causes = []
    for cause in record.get("refined_root_causes") or []:
        rank = safe_int(cause.get("rank"))
        assessment = assessments.get(rank or -1)
        if allowed_ranks and rank not in allowed_ranks:
            continue
        if assessment and assessment.get("label") not in {"root_cause", "plausible_root_cause"}:
            continue
        refined_causes.append(convert_refined_cause(cause, validation, assessment=assessment))
    if not refined_causes and record.get("refined_root_causes"):
        refined_causes = [convert_refined_cause(record["refined_root_causes"][0], validation, assessment=assessments.get(1))]

    for index, cause in enumerate(refined_causes, start=1):
        cause["rank"] = index
        cause["candidate_rank"] = index

    metadata = {
        "candidate_count": record.get("mining", {}).get("raw_candidate_count"),
        "retained_root_causes": len(refined_causes),
        "threshold": None,
        "used_patch_context": True,
        "used_semantic_alignment": True,
        "source_refinement": "llm_guided_secondary_validated",
        "replaces_original_record": original_record is not None,
        "original_root_cause_count": len((original_record or {}).get("root_causes", []) or []),
        "secondary_llm_confidence": validation.get("confidence"),
        "secondary_llm_verdict": validation.get("verdict"),
        "secondary_quality_label": validation.get("quality_label"),
    }
    return {
        "cve_id": record.get("cve_id"),
        "project": record.get("project"),
        "repo_url": record.get("repo_url"),
        "diagnostics": list(record.get("mining", {}).get("diagnostics") or []),
        "metadata": metadata,
        "llm_validation": record.get("llm_guidance"),
        "secondary_llm_validation": validation,
        "refinement_plan": record.get("refinement_plan"),
        "patch": record.get("patch"),
        "root_causes": refined_causes,
        "v2_merge": {
            "source": merge_source_label,
            "schema_version": merged_schema_version,
            "merge_reason": validation.get("reasoning"),
        },
    }


def convert_refined_cause(
    cause: dict[str, Any],
    validation: dict[str, Any],
    *,
    assessment: Optional[dict[str, Any]],
) -> dict[str, Any]:
    confidence_parts = [
        safe_float(cause.get("refined_score")),
        safe_float(cause.get("source_score")),
        safe_float(validation.get("confidence")),
    ]
    if assessment is not None:
        confidence_parts.append(safe_float(assessment.get("confidence")))
    confidence_values = [value for value in confidence_parts if value is not None]
    confidence = sum(confidence_values) / len(confidence_values) if confidence_values else 0.0
    metadata = dict(cause.get("features") or {})
    metadata.update(
        {
            "heuristic_label": cause.get("classification"),
            "heuristic_score": cause.get("source_score"),
            "matched_bug_pattern": cause.get("pattern") or cause.get("type"),
            "secondary_llm_label": assessment.get("label") if assessment else None,
            "secondary_llm_confidence": assessment.get("confidence") if assessment else None,
            "secondary_llm_reasoning": assessment.get("reasoning") if assessment else None,
            "refined_score": cause.get("refined_score"),
            "guidance_bonus": cause.get("guidance_bonus"),
            "guidance_penalty": cause.get("guidance_penalty"),
            "guidance_reasons": cause.get("guidance_reasons"),
        }
    )
    return {
        "candidate_origin": cause.get("candidate_origin"),
        "candidate_rank": cause.get("rank"),
        "classification": cause.get("classification") or "root_cause_candidate",
        "code_snippet": cause.get("code_snippet") or (cause.get("location") or {}).get("snippet"),
        "confidence": round(max(0.0, min(1.0, confidence)), 6),
        "explanation": cause.get("explanation"),
        "location": cause.get("location"),
        "metadata": metadata,
        "patch_relation": cause.get("patch_relation"),
        "pattern": cause.get("pattern") or cause.get("type"),
        "rank": cause.get("rank"),
        "type": cause.get("type") or cause.get("pattern"),
    }


def build_summary(
    validations: dict[str, dict[str, Any]],
    base_dataset: dict[str, Any],
    refined_dataset: dict[str, Any],
    *,
    replaced: int,
    appended: int,
    min_merge_confidence: float,
) -> dict[str, Any]:
    validation_values = [item["validation"] for item in validations.values()]
    verdicts = Counter(item.get("verdict") for item in validation_values)
    quality = Counter(item.get("quality_label") for item in validation_values)
    merge_recommendations = Counter(item.get("merge_recommendation") for item in validation_values)
    passed_count = sum(1 for item in validation_values if item.get("passed_for_v2_merge"))
    candidate_labels = Counter()
    for item in validation_values:
        for assessment in item.get("candidate_assessments", []) or []:
            candidate_labels[assessment.get("label")] += 1
    merged_record_count = len(base_dataset.get("records", []) or []) - replaced + replaced + appended
    return {
        "schema_version": SCHEMA_VERSION,
        "prompt_version": PROMPT_VERSION,
        "base_record_count": len(base_dataset.get("records", []) or []),
        "refined_record_count": len(refined_dataset.get("records", []) or []),
        "validated_refined_record_count": len(validations),
        "passed_for_v2_merge_count": passed_count,
        "replaced_record_count": replaced,
        "appended_record_count": appended,
        "merged_record_count": merged_record_count,
        "v2_record_count": merged_record_count,
        "min_merge_confidence": min_merge_confidence,
        "verdict_distribution": dict(sorted(verdicts.items())),
        "quality_distribution": dict(sorted(quality.items())),
        "merge_recommendation_distribution": dict(sorted(merge_recommendations.items())),
        "candidate_label_distribution": dict(sorted(candidate_labels.items())),
    }


def input_summary(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve_id": record.get("cve_id"),
        "project": record.get("project"),
        "refined_candidate_count": len(record.get("refined_root_causes") or []),
        "old_candidate_action_count": len(record.get("old_candidate_actions") or []),
        "refinement_action": (record.get("refinement_plan") or {}).get("primary_action"),
        "patterns": sorted({str(item.get("pattern") or item.get("type")) for item in record.get("refined_root_causes") or []}),
        "patch_relations": sorted({str(item.get("patch_relation")) for item in record.get("refined_root_causes") or []}),
    }


def dry_run_payload() -> dict[str, Any]:
    return {
        "verdict": "manual_review",
        "quality_label": "plausible_but_broad",
        "confidence": 0.5,
        "best_candidate_ranks": [1],
        "candidate_assessments": [{"rank": 1, "label": "uncertain", "confidence": 0.5, "reasoning": "Dry run."}],
        "merge_recommendation": "do_not_merge",
        "reasoning": "Dry run.",
        "issues": [],
    }


def parse_json_object(text: str) -> dict[str, Any]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end < start:
            raise
        payload = json.loads(text[start : end + 1])
    if not isinstance(payload, dict):
        raise ValueError("LLM response was not a JSON object")
    return payload


def normalize_choice(value: Any, allowed: set[str], default: str) -> str:
    text = normalize_token(value)
    return text if text in allowed else default


def normalize_token(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = text.replace("-", "_").replace(" ", "_")
    return "_".join(part for part in text.split("_") if part)


def normalize_string_list(value: Any, *, max_items: int = 12) -> list[str]:
    if not isinstance(value, list):
        return []
    return [truncate_text(str(item), 300) for item in value[:max_items] if item is not None]


def clamp_confidence(value: Any) -> float:
    number = safe_float(value)
    if number is None:
        return 0.0
    return max(0.0, min(1.0, number))


def safe_float(value: Any) -> Optional[float]:
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def safe_int(value: Any) -> Optional[int]:
    try:
        if value is None:
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def truncate_text(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def compact_mapping(value: dict[str, Any], *, max_chars: int) -> Any:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    if len(text) <= max_chars:
        return value
    return {"truncated_json": truncate_text(text, max_chars)}


def stable_hash(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


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


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        handle.write("\n")


def load_existing_jsonl(path: Path, *, key_field: str) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    if not path.exists():
        return records
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            item = json.loads(line)
            key = str(item.get(key_field) or "")
            if key:
                records[key] = item
    return records


def write_status(path: Path, **payload: Any) -> None:
    payload["updated_at_epoch"] = time.time()
    write_json(path, payload)


if __name__ == "__main__":
    raise SystemExit(main())
