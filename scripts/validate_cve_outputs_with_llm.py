#!/usr/bin/env python3
"""Validate mined CVE root-cause datasets and pattern libraries with an LLM.

The validator is intentionally evidence-bounded: it asks the model to judge
RCPatch's existing records against CVE descriptions and compact code evidence,
not to invent new root causes. Results are checkpointed as JSONL so a long run
can be resumed without repeating completed calls.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Optional
from urllib import error as urllib_error
from urllib import request as urllib_request


SCHEMA_VERSION = "rcpatch.llm_validation.v1"
RECORD_PROMPT_VERSION = "bugrc-record-validation-v1"
PATTERN_PROMPT_VERSION = "bugrc-pattern-validation-v1"

DEFAULT_MODEL = os.getenv("RCPATCH_LLM_VALIDATION_MODEL", os.getenv("BUGRC_LLM_VALIDATION_MODEL", "gpt-4.1-mini"))
DEFAULT_BASE_URL = os.getenv("RCPATCH_LLM_BASE_URL", os.getenv("BUGRC_LLM_BASE_URL", "https://api.openai.com/v1"))

RECORD_LABELS = {"correct", "partially_correct", "uncertain", "likely_incorrect"}
PATTERN_LABELS = {"valid_pattern", "valid_but_broad", "merge_or_deduplicate", "weak_or_noisy", "likely_incorrect"}
RECORD_ACTIONS = {"keep", "keep_with_lower_confidence", "manual_review", "drop"}
PATTERN_ACTIONS = {"keep", "merge", "manual_review", "drop"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True, help="Path to cve_root_cause_dataset.json.")
    parser.add_argument("--patterns", required=True, help="Path to cve_pattern_library.json.")
    parser.add_argument("--collection-json", required=True, help="Full or filtered CVE collection JSON for descriptions.")
    parser.add_argument("--output-dir", required=True, help="Directory for validation outputs.")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="OpenAI-compatible model name.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="OpenAI-compatible API base URL.")
    parser.add_argument("--timeout-seconds", type=float, default=60.0, help="Per-request timeout.")
    parser.add_argument("--max-retries", type=int, default=6, help="Retry count for transient provider failures.")
    parser.add_argument("--sleep-seconds", type=float, default=0.15, help="Delay between live provider calls.")
    parser.add_argument("--checkpoint-every", type=int, default=25, help="Rewrite summary after this many new calls.")
    parser.add_argument("--max-records", type=int, default=None, help="Optional cap for smoke tests.")
    parser.add_argument("--max-patterns", type=int, default=None, help="Optional cap for smoke tests.")
    parser.add_argument(
        "--mode",
        choices=("all", "records", "patterns"),
        default="all",
        help="Which item type to validate.",
    )
    parser.add_argument("--force", action="store_true", help="Ignore existing validation JSONL and re-query.")
    parser.add_argument("--dry-run", action="store_true", help="Build prompts and summaries without provider calls.")
    parser.add_argument("--log-level", default="INFO", choices=("DEBUG", "INFO", "WARNING", "ERROR"))
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
    logger = logging.getLogger("rcpatch.llm_validation")

    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    cache_dir = output_dir / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)

    api_key = os.getenv("RCPATCH_OPENAI_API_KEY") or os.getenv("BUGRC_OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not api_key and not args.dry_run:
        logger.error("RCPATCH_OPENAI_API_KEY, BUGRC_OPENAI_API_KEY, or OPENAI_API_KEY must be set")
        return 2

    dataset = read_json(Path(args.dataset).expanduser().resolve())
    pattern_library = read_json(Path(args.patterns).expanduser().resolve())
    records = list(dataset.get("records", []))
    patterns = list(pattern_library.get("patterns", []))
    if args.max_records is not None:
        records = records[: max(0, args.max_records)]
    if args.max_patterns is not None:
        patterns = patterns[: max(0, args.max_patterns)]

    needed_cve_ids = collect_needed_cve_ids(records, patterns)
    logger.info("Loading descriptions for %d CVE IDs", len(needed_cve_ids))
    cve_metadata = load_cve_metadata(Path(args.collection_json).expanduser().resolve(), needed_cve_ids)
    logger.info("Loaded metadata for %d CVEs", len(cve_metadata))

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

    record_output = output_dir / "llm_record_validations.jsonl"
    pattern_output = output_dir / "llm_pattern_validations.jsonl"
    completed_records = {} if args.force else load_existing_jsonl(record_output, key_field="cve_id")
    completed_patterns = {} if args.force else load_existing_jsonl(pattern_output, key_field="pattern_key")

    new_calls = 0
    status_path = output_dir / "llm_validation_status.json"
    write_status(
        status_path,
        state="running",
        model=args.model,
        mode=args.mode,
        total_records=len(records),
        total_patterns=len(patterns),
        completed_records=len(completed_records),
        completed_patterns=len(completed_patterns),
    )

    if args.mode in {"all", "records"}:
        for index, record in enumerate(records, start=1):
            cve_id = str(record.get("cve_id", ""))
            if not cve_id:
                continue
            if cve_id in completed_records:
                continue
            metadata = cve_metadata.get(cve_id, {})
            prompt = build_record_prompt(record, metadata)
            result = provider.complete_json(
                task="cve_root_cause_record_validation",
                prompt_version=RECORD_PROMPT_VERSION,
                system_prompt=record_system_prompt(),
                user_payload=prompt,
                max_tokens=900,
            )
            validation = normalize_record_validation(result.payload)
            item = {
                "schema_version": SCHEMA_VERSION,
                "item_kind": "root_cause_record",
                "cve_id": cve_id,
                "record_index": index,
                "model": args.model,
                "cached": result.cached,
                "provider_metadata": result.metadata,
                "validation": validation,
                "input_summary": compact_record_summary(record, metadata),
            }
            append_jsonl(record_output, item)
            completed_records[cve_id] = item
            new_calls += 0 if result.cached else 1
            if index % args.checkpoint_every == 0 or new_calls % args.checkpoint_every == 0:
                logger.info("Record validation progress: %d/%d", len(completed_records), len(records))
                write_outputs(output_dir, dataset, pattern_library, completed_records, completed_patterns)
                write_status(
                    status_path,
                    state="running",
                    model=args.model,
                    mode=args.mode,
                    total_records=len(records),
                    total_patterns=len(patterns),
                    completed_records=len(completed_records),
                    completed_patterns=len(completed_patterns),
                    live_calls=new_calls,
                )

    if args.mode in {"all", "patterns"}:
        for index, pattern in enumerate(patterns, start=1):
            pattern_key = pattern_identity(pattern, index)
            if pattern_key in completed_patterns:
                continue
            prompt = build_pattern_prompt(pattern, cve_metadata)
            result = provider.complete_json(
                task="cve_root_cause_pattern_validation",
                prompt_version=PATTERN_PROMPT_VERSION,
                system_prompt=pattern_system_prompt(),
                user_payload=prompt,
                max_tokens=950,
            )
            validation = normalize_pattern_validation(result.payload)
            item = {
                "schema_version": SCHEMA_VERSION,
                "item_kind": "root_cause_pattern",
                "pattern_key": pattern_key,
                "pattern_index": index,
                "pattern_id": pattern.get("pattern_id"),
                "name": pattern.get("name"),
                "category": pattern.get("category"),
                "support_count": pattern.get("support_count"),
                "model": args.model,
                "cached": result.cached,
                "provider_metadata": result.metadata,
                "validation": validation,
                "input_summary": compact_pattern_summary(pattern),
            }
            append_jsonl(pattern_output, item)
            completed_patterns[pattern_key] = item
            new_calls += 0 if result.cached else 1
            if index % args.checkpoint_every == 0 or new_calls % args.checkpoint_every == 0:
                logger.info("Pattern validation progress: %d/%d", len(completed_patterns), len(patterns))
                write_outputs(output_dir, dataset, pattern_library, completed_records, completed_patterns)
                write_status(
                    status_path,
                    state="running",
                    model=args.model,
                    mode=args.mode,
                    total_records=len(records),
                    total_patterns=len(patterns),
                    completed_records=len(completed_records),
                    completed_patterns=len(completed_patterns),
                    live_calls=new_calls,
                )

    write_outputs(output_dir, dataset, pattern_library, completed_records, completed_patterns)
    write_status(
        status_path,
        state="finished",
        model=args.model,
        mode=args.mode,
        total_records=len(records),
        total_patterns=len(patterns),
        completed_records=len(completed_records),
        completed_patterns=len(completed_patterns),
        live_calls=new_calls,
    )
    logger.info("LLM validation complete: records=%d patterns=%d", len(completed_records), len(completed_patterns))
    return 0


class LLMCallResult:
    def __init__(self, *, payload: dict[str, Any], cached: bool, metadata: dict[str, Any]) -> None:
        self.payload = payload
        self.cached = cached
        self.metadata = metadata


class OpenAIJSONClient:
    """Small resumable JSON-mode client for long-running validation jobs."""

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
        request_payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(user_payload, indent=2, sort_keys=True, ensure_ascii=False)},
            ],
            "temperature": 0,
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"},
        }
        cache_key = stable_hash(
            {
                "task": task,
                "prompt_version": prompt_version,
                "base_url": self.base_url,
                "payload": request_payload,
            }
        )
        cache_path = self.cache_dir / f"{cache_key}.json"
        if cache_path.exists():
            cached = read_json(cache_path)
            return LLMCallResult(payload=dict(cached["payload"]), cached=True, metadata=cached.get("metadata", {}))

        if self.dry_run:
            payload = {
                "label": "uncertain",
                "confidence": 0.0,
                "reasoning": "dry-run placeholder; no provider call was made",
                "issues": ["dry_run"],
                "recommended_action": "manual_review",
            }
            return LLMCallResult(payload=payload, cached=False, metadata={"dry_run": True})

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        request = urllib_request.Request(
            url=f"{self.base_url}/chat/completions",
            data=json.dumps(request_payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )

        last_error = ""
        for attempt in range(self.max_retries + 1):
            try:
                with urllib_request.urlopen(request, timeout=self.timeout_seconds) as response:
                    raw = json.loads(response.read().decode("utf-8"))
                text = extract_message_text(raw)
                payload = parse_json_object(text)
                cache_payload = {
                    "payload": payload,
                    "metadata": {
                        "task": task,
                        "prompt_version": prompt_version,
                        "model": self.model,
                        "raw_usage": raw.get("usage"),
                    },
                    "raw_response": raw,
                }
                write_json(cache_path, cache_payload)
                if self.sleep_seconds > 0:
                    time.sleep(self.sleep_seconds)
                return LLMCallResult(payload=payload, cached=False, metadata=cache_payload["metadata"])
            except urllib_error.HTTPError as exc:
                body = exc.read().decode("utf-8", errors="replace")
                last_error = f"HTTP {exc.code}: {body[:800]}"
                if exc.code not in {408, 409, 429, 500, 502, 503, 504}:
                    break
            except (urllib_error.URLError, TimeoutError, OSError, ValueError) as exc:
                last_error = str(exc)

            sleep_for = min(90.0, (2**attempt) + 0.25)
            logging.getLogger("rcpatch.llm_validation").warning(
                "LLM call failed for %s attempt %d/%d: %s; sleeping %.1fs",
                task,
                attempt + 1,
                self.max_retries + 1,
                last_error,
                sleep_for,
            )
            time.sleep(sleep_for)

        raise RuntimeError(f"LLM call failed for {task}: {last_error}")


def record_system_prompt() -> str:
    return (
        "You are validating RCPatch's mined CVE root-cause records.\n"
        "Use only the provided CVE description/CWE/reference metadata and RCPatch code evidence. "
        "You may use general software-security knowledge about vulnerability classes, but do not browse and do not invent code facts.\n"
        "Judge whether the proposed root-cause record is semantically consistent with the CVE description and likely vulnerability class.\n"
        "Return JSON only."
    )


def pattern_system_prompt() -> str:
    return (
        "You are validating RCPatch's mined root-cause pattern library.\n"
        "Use only the provided pattern metadata, representative snippets, and CVE descriptions. "
        "You may use general software-security knowledge, but do not invent new examples or external facts.\n"
        "Judge whether the pattern is coherent, useful, and supported by the representative CVEs.\n"
        "Return JSON only."
    )


def build_record_prompt(record: dict[str, Any], metadata: dict[str, Any]) -> dict[str, Any]:
    root_causes = [
        {
            "rank": cause.get("rank"),
            "candidate_rank": cause.get("candidate_rank"),
            "classification": cause.get("classification"),
            "type": cause.get("type"),
            "pattern": cause.get("pattern"),
            "confidence": cause.get("confidence"),
            "patch_relation": cause.get("patch_relation"),
            "location": cause.get("location"),
            "code_snippet": truncate_text(str(cause.get("code_snippet") or cause.get("location", {}).get("snippet") or ""), 500),
            "explanation": truncate_text(str(cause.get("explanation") or ""), 500),
        }
        for cause in record.get("root_causes", [])[:5]
    ]
    return {
        "task": "validate_one_bugrc_root_cause_record",
        "cve": cve_prompt_metadata(record.get("cve_id"), metadata),
        "bugrc_record": {
            "project": record.get("project"),
            "repo_url": record.get("repo_url"),
            "metadata": record.get("metadata", {}),
            "diagnostics": record.get("diagnostics", [])[:5],
            "root_causes": root_causes,
        },
        "instructions": {
            "allowed_labels": sorted(RECORD_LABELS),
            "allowed_recommended_actions": sorted(RECORD_ACTIONS),
            "label_meanings": {
                "correct": "The CVE description strongly supports the proposed vulnerability class and at least one proposed root-cause candidate.",
                "partially_correct": "The broad vulnerability class or one candidate is plausible, but location/pattern precision is weak or mixed.",
                "uncertain": "The CVE text is too vague or evidence too thin to verify correctness.",
                "likely_incorrect": "The proposed root cause/pattern conflicts with the CVE description or appears to be a symptom/noise.",
            },
            "requirements": [
                "Assess the record as a whole and each provided root_cause candidate.",
                "Do not require exact source-code proof if only CVE text is available; lower confidence instead.",
                "Penalize candidates outside patched files only when the explanation/code does not plausibly connect to the CVE.",
                "Prefer manual_review over drop for vague CVE descriptions.",
            ],
        },
        "output_format": {
            "label": "correct | partially_correct | uncertain | likely_incorrect",
            "confidence": 0.0,
            "cve_bug_class": "short normalized vulnerability class inferred from the CVE text",
            "root_cause_pattern_assessment": "matches | overbroad | wrong | insufficient_evidence",
            "candidate_assessments": [
                {
                    "rank": 1,
                    "label": "correct | partially_correct | uncertain | likely_incorrect",
                    "confidence": 0.0,
                    "reasoning": "short candidate-specific judgment",
                }
            ],
            "reasoning": "short evidence-grounded explanation",
            "issues": ["short issue strings, or []"],
            "recommended_action": "keep | keep_with_lower_confidence | manual_review | drop",
        },
    }


def build_pattern_prompt(pattern: dict[str, Any], cve_metadata: dict[str, dict[str, Any]]) -> dict[str, Any]:
    examples = []
    for example in list(pattern.get("examples", []) or [])[:8]:
        cve_id = str(example.get("cve_id", ""))
        examples.append(
            {
                "cve_id": cve_id,
                "cve_description": truncate_text(str(cve_metadata.get(cve_id, {}).get("description") or ""), 900),
                "cwe": cve_metadata.get(cve_id, {}).get("cwe"),
                "code_snippet": truncate_text(str(example.get("code_snippet") or ""), 350),
                "abstract_template": truncate_text(str(example.get("abstract_template") or ""), 250),
                "confidence": example.get("confidence"),
                "patch_relation": example.get("patch_relation"),
                "location": example.get("location"),
            }
        )
    cve_ids = list(pattern.get("cve_ids", []) or [])
    return {
        "task": "validate_one_bugrc_root_cause_pattern",
        "pattern": {
            "pattern_id": pattern.get("pattern_id"),
            "name": pattern.get("name"),
            "category": pattern.get("category"),
            "operation_type": pattern.get("operation_type"),
            "support_count": pattern.get("support_count"),
            "cve_count": len(cve_ids),
            "sample_cve_ids": cve_ids[:25],
            "templates": list(pattern.get("templates", []) or [])[:8],
            "feature_rules": pattern.get("feature_rules", [])[:8] if isinstance(pattern.get("feature_rules"), list) else pattern.get("feature_rules"),
            "graph_pattern": truncate_text(json.dumps(pattern.get("graph_pattern", {}), sort_keys=True, ensure_ascii=False), 1200),
            "metadata": pattern.get("metadata", {}),
            "representative_examples": examples,
        },
        "instructions": {
            "allowed_labels": sorted(PATTERN_LABELS),
            "allowed_recommended_actions": sorted(PATTERN_ACTIONS),
            "label_meanings": {
                "valid_pattern": "The pattern is coherent, useful, and examples support it.",
                "valid_but_broad": "The pattern is generally useful but too broad or mixed.",
                "merge_or_deduplicate": "The pattern overlaps heavily with another likely pattern or is a duplicate slice.",
                "weak_or_noisy": "Support examples are inconsistent or too vague.",
                "likely_incorrect": "The pattern label is contradicted by representative examples.",
            },
            "requirements": [
                "Base support on representative CVE descriptions and snippets only.",
                "Do not invent external CVE facts.",
                "Lower confidence when examples lack descriptions or code evidence.",
            ],
        },
        "output_format": {
            "label": "valid_pattern | valid_but_broad | merge_or_deduplicate | weak_or_noisy | likely_incorrect",
            "confidence": 0.0,
            "semantic_pattern_name": "concise normalized name",
            "reasoning": "short evidence-grounded explanation",
            "supported_example_cves": ["CVE-..."],
            "questionable_example_cves": ["CVE-..."],
            "issues": ["short issue strings, or []"],
            "recommended_action": "keep | merge | manual_review | drop",
        },
    }


def cve_prompt_metadata(cve_id: Any, metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve_id": str(cve_id or ""),
        "description": truncate_text(str(metadata.get("description") or ""), 1500),
        "cwe": metadata.get("cwe"),
        "project": metadata.get("project"),
        "repo_url": metadata.get("repo_url"),
        "references": metadata.get("references", [])[:8],
        "fix_commits": metadata.get("fix_commits", [])[:5],
    }


def collect_needed_cve_ids(records: list[dict[str, Any]], patterns: list[dict[str, Any]]) -> set[str]:
    ids = {str(record.get("cve_id", "")) for record in records if record.get("cve_id")}
    for pattern in patterns:
        for cve_id in list(pattern.get("cve_ids", []) or [])[:40]:
            if cve_id:
                ids.add(str(cve_id))
        for example in pattern.get("examples", []) or []:
            cve_id = example.get("cve_id")
            if cve_id:
                ids.add(str(cve_id))
    return ids


def load_cve_metadata(path: Path, needed_ids: set[str]) -> dict[str, dict[str, Any]]:
    data = read_json(path)
    records = data.get("records", [])
    result: dict[str, dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        cve_id = str(record.get("cve_id", ""))
        if cve_id not in needed_ids:
            continue
        result[cve_id] = {
            "description": record.get("description"),
            "cwe": record.get("cwe"),
            "project": record.get("project"),
            "repo_url": record.get("repo_url"),
            "references": compact_references(record.get("references", [])),
            "fix_commits": record.get("fix_commits", [])[:5] if isinstance(record.get("fix_commits"), list) else [],
        }
    return result


def compact_references(references: Any) -> list[dict[str, Any]]:
    compact: list[dict[str, Any]] = []
    if not isinstance(references, list):
        return compact
    for reference in references[:12]:
        if not isinstance(reference, dict):
            continue
        compact.append(
            {
                "url": reference.get("url"),
                "tags": reference.get("tags", [])[:5] if isinstance(reference.get("tags"), list) else [],
                "commit_sha": reference.get("commit_sha"),
            }
        )
    return compact


def normalize_record_validation(payload: dict[str, Any]) -> dict[str, Any]:
    label = normalize_choice(payload.get("label"), RECORD_LABELS, "uncertain")
    action = normalize_choice(payload.get("recommended_action"), RECORD_ACTIONS, "manual_review")
    candidates = payload.get("candidate_assessments", [])
    if not isinstance(candidates, list):
        candidates = []
    normalized_candidates = []
    for item in candidates[:8]:
        if not isinstance(item, dict):
            continue
        normalized_candidates.append(
            {
                "rank": item.get("rank"),
                "label": normalize_choice(item.get("label"), RECORD_LABELS, "uncertain"),
                "confidence": clamp_confidence(item.get("confidence")),
                "reasoning": truncate_text(str(item.get("reasoning") or ""), 600),
            }
        )
    return {
        "label": label,
        "confidence": clamp_confidence(payload.get("confidence")),
        "cve_bug_class": normalize_token(payload.get("cve_bug_class")),
        "root_cause_pattern_assessment": normalize_token(payload.get("root_cause_pattern_assessment")),
        "candidate_assessments": normalized_candidates,
        "reasoning": truncate_text(str(payload.get("reasoning") or ""), 1000),
        "issues": normalize_string_list(payload.get("issues")),
        "recommended_action": action,
        "raw_payload": payload,
    }


def normalize_pattern_validation(payload: dict[str, Any]) -> dict[str, Any]:
    label = normalize_choice(payload.get("label"), PATTERN_LABELS, "weak_or_noisy")
    action = normalize_choice(payload.get("recommended_action"), PATTERN_ACTIONS, "manual_review")
    return {
        "label": label,
        "confidence": clamp_confidence(payload.get("confidence")),
        "semantic_pattern_name": normalize_token(payload.get("semantic_pattern_name")),
        "reasoning": truncate_text(str(payload.get("reasoning") or ""), 1000),
        "supported_example_cves": normalize_string_list(payload.get("supported_example_cves"), max_items=20),
        "questionable_example_cves": normalize_string_list(payload.get("questionable_example_cves"), max_items=20),
        "issues": normalize_string_list(payload.get("issues")),
        "recommended_action": action,
        "raw_payload": payload,
    }


def write_outputs(
    output_dir: Path,
    dataset: dict[str, Any],
    pattern_library: dict[str, Any],
    record_validations: dict[str, dict[str, Any]],
    pattern_validations: dict[str, dict[str, Any]],
) -> None:
    summary = build_summary(record_validations, pattern_validations)
    write_json(output_dir / "llm_validation_summary.json", summary)
    write_json(
        output_dir / "cve_root_cause_dataset.llm_annotated.json",
        annotate_dataset(dataset, record_validations, keep_only=False),
    )
    write_json(
        output_dir / "cve_root_cause_dataset.llm_filtered.json",
        annotate_dataset(dataset, record_validations, keep_only=True),
    )
    write_json(
        output_dir / "cve_pattern_library.llm_annotated.json",
        annotate_patterns(pattern_library, pattern_validations, keep_only=False),
    )
    write_json(
        output_dir / "cve_pattern_library.llm_filtered.json",
        annotate_patterns(pattern_library, pattern_validations, keep_only=True),
    )


def build_summary(
    record_validations: dict[str, dict[str, Any]],
    pattern_validations: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    record_labels = Counter(item["validation"]["label"] for item in record_validations.values())
    record_actions = Counter(item["validation"]["recommended_action"] for item in record_validations.values())
    pattern_labels = Counter(item["validation"]["label"] for item in pattern_validations.values())
    pattern_actions = Counter(item["validation"]["recommended_action"] for item in pattern_validations.values())
    return {
        "schema_version": SCHEMA_VERSION,
        "record_validation_count": len(record_validations),
        "pattern_validation_count": len(pattern_validations),
        "record_labels": dict(sorted(record_labels.items())),
        "record_actions": dict(sorted(record_actions.items())),
        "pattern_labels": dict(sorted(pattern_labels.items())),
        "pattern_actions": dict(sorted(pattern_actions.items())),
        "record_keep_count": sum(
            1
            for item in record_validations.values()
            if item["validation"]["recommended_action"] in {"keep", "keep_with_lower_confidence"}
        ),
        "pattern_keep_count": sum(
            1
            for item in pattern_validations.values()
            if item["validation"]["recommended_action"] == "keep"
        ),
    }


def annotate_dataset(
    dataset: dict[str, Any],
    validations: dict[str, dict[str, Any]],
    *,
    keep_only: bool,
) -> dict[str, Any]:
    records = []
    for record in dataset.get("records", []):
        cve_id = str(record.get("cve_id", ""))
        validation = validations.get(cve_id)
        if keep_only and (
            validation is None
            or validation["validation"]["recommended_action"] not in {"keep", "keep_with_lower_confidence"}
        ):
            continue
        cloned = dict(record)
        if validation is not None:
            cloned["llm_validation"] = validation["validation"]
        records.append(cloned)
    metadata = dict(dataset.get("metadata", {}))
    metadata.update(
        {
            "llm_validation_schema": SCHEMA_VERSION,
            "llm_filtered": keep_only,
            "record_count": len(records),
            "source_record_count": len(dataset.get("records", [])),
        }
    )
    return {"metadata": metadata, "records": records}


def annotate_patterns(
    pattern_library: dict[str, Any],
    validations: dict[str, dict[str, Any]],
    *,
    keep_only: bool,
) -> dict[str, Any]:
    patterns = []
    for index, pattern in enumerate(pattern_library.get("patterns", []), start=1):
        key = pattern_identity(pattern, index)
        validation = validations.get(key)
        if keep_only and (validation is None or validation["validation"]["recommended_action"] != "keep"):
            continue
        cloned = dict(pattern)
        if validation is not None:
            cloned["llm_validation"] = validation["validation"]
        patterns.append(cloned)
    metadata = dict(pattern_library.get("metadata", {}))
    metadata.update(
        {
            "llm_validation_schema": SCHEMA_VERSION,
            "llm_filtered": keep_only,
            "pattern_count": len(patterns),
            "source_pattern_count": len(pattern_library.get("patterns", [])),
        }
    )
    return {"metadata": metadata, "patterns": patterns}


def compact_record_summary(record: dict[str, Any], metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve_id": record.get("cve_id"),
        "description_present": bool(metadata.get("description")),
        "root_cause_count": len(record.get("root_causes", []) or []),
        "root_cause_types": sorted({str(cause.get("type")) for cause in record.get("root_causes", []) or []}),
        "patch_relations": sorted({str(cause.get("patch_relation")) for cause in record.get("root_causes", []) or []}),
    }


def compact_pattern_summary(pattern: dict[str, Any]) -> dict[str, Any]:
    return {
        "pattern_id": pattern.get("pattern_id"),
        "name": pattern.get("name"),
        "category": pattern.get("category"),
        "support_count": pattern.get("support_count"),
        "example_count": len(pattern.get("examples", []) or []),
        "cve_count": len(pattern.get("cve_ids", []) or []),
    }


def pattern_identity(pattern: dict[str, Any], index: int) -> str:
    explicit = pattern.get("pattern_id")
    if explicit:
        return str(explicit)
    payload = {
        "index": index,
        "name": pattern.get("name"),
        "category": pattern.get("category"),
        "templates": list(pattern.get("templates", []) or [])[:3],
        "examples": [
            {
                "cve_id": example.get("cve_id"),
                "code_snippet": example.get("code_snippet"),
            }
            for example in list(pattern.get("examples", []) or [])[:3]
        ],
    }
    return f"pattern_{index:04d}_{stable_hash(payload)[:12]}"


def write_status(path: Path, **payload: Any) -> None:
    payload["updated_at_epoch"] = time.time()
    write_json(path, payload)


def load_existing_jsonl(path: Path, *, key_field: str) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    result: dict[str, dict[str, Any]] = {}
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            key = item.get(key_field)
            if key:
                result[str(key)] = item
    return result


def append_jsonl(path: Path, item: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(item, sort_keys=True, ensure_ascii=False) + "\n")
        handle.flush()


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def extract_message_text(raw: dict[str, Any]) -> str:
    choices = raw.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ValueError("provider response missing choices")
    message = choices[0].get("message", {})
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
        if parts:
            return "\n".join(parts)
    raise ValueError("provider response missing message content")


def parse_json_object(text: str) -> dict[str, Any]:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?", "", cleaned).strip()
        cleaned = re.sub(r"```$", "", cleaned).strip()
    candidates = [cleaned]
    extracted = extract_first_json_object(cleaned)
    if extracted and extracted != cleaned:
        candidates.append(extracted)
    for candidate in candidates:
        try:
            payload = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload
    raise ValueError("response did not contain a JSON object")


def extract_first_json_object(text: str) -> Optional[str]:
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_string = False
    escape = False
    for offset, character in enumerate(text[start:], start=start):
        if escape:
            escape = False
            continue
        if character == "\\":
            escape = True
            continue
        if character == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return text[start : offset + 1]
    return None


def normalize_choice(value: Any, allowed: set[str], default: str) -> str:
    normalized = normalize_token(value)
    return normalized if normalized in allowed else default


def normalize_token(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("_")
    return text or "unknown"


def normalize_string_list(value: Any, *, max_items: int = 12) -> list[str]:
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value[:max_items]:
        text = str(item).strip()
        if text:
            result.append(truncate_text(text, 180))
    return result


def clamp_confidence(value: Any) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.0


def truncate_text(text: str, limit: int) -> str:
    cleaned = text.strip()
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: max(0, limit - 3)].rstrip() + "..."


def stable_hash(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
