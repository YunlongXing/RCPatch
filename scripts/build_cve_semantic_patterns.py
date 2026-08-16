#!/usr/bin/env python3
"""Build a lightweight CVE semantic root-cause dataset and pattern prior library.

This script intentionally does not clone repositories, inspect patches, or build
source-level slices. It uses CVE text/CWE/reference metadata as weak semantic
evidence and optionally asks an OpenAI-compatible LLM to classify each existing
CVE record into a reusable root-cause hypothesis and pattern.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
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

from rcpatch.llm import FileLLMCache, LLMClient, LLMRequest, OpenAICompatibleProvider  # noqa: E402
from rcpatch.logging_utils import configure_logging, get_logger  # noqa: E402
from rcpatch.models import CollectedCVERecord, Language  # noqa: E402


SCHEMA_VERSION_DATASET = "rcpatch.cve_semantic_root_cause_dataset.v1"
SCHEMA_VERSION_PATTERNS = "rcpatch.cve_pattern_prior_library.v1"
PROMPT_VERSION = "cve-semantic-pattern-v1"

MEMORY_CWES = {
    "CWE-119",
    "CWE-120",
    "CWE-121",
    "CWE-122",
    "CWE-124",
    "CWE-125",
    "CWE-126",
    "CWE-127",
    "CWE-129",
    "CWE-131",
    "CWE-190",
    "CWE-191",
    "CWE-369",
    "CWE-415",
    "CWE-416",
    "CWE-476",
    "CWE-787",
    "CWE-788",
    "CWE-805",
    "CWE-843",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Create a semantic CVE root-cause dataset and pattern prior library from "
            "bootstrap_collection_result.json without cloning repositories."
        )
    )
    parser.add_argument("--collection-json", required=True, help="Path to bootstrap_collection_result.json.")
    parser.add_argument("--output-dir", required=True, help="Directory for semantic dataset and pattern outputs.")
    parser.add_argument("--max-records", type=int, default=None, help="Optional cap after text/CWE filtering.")
    parser.add_argument("--start-after-cve", help="Skip records until after this CVE ID, useful for manual resume.")
    parser.add_argument(
        "--only-cpp-relevant",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Keep only records that look relevant to C/C++ or memory-safety style root causes.",
    )
    parser.add_argument("--min-confidence", type=float, default=0.45, help="Drop semantic annotations below this confidence.")
    parser.add_argument("--pattern-min-support", type=int, default=2, help="Minimum examples for a pattern to be emitted.")
    parser.add_argument("--checkpoint-every", type=int, default=100, help="Write output files every N processed records.")
    parser.add_argument("--sleep-seconds", type=float, default=0.0, help="Optional delay between LLM calls.")
    parser.add_argument(
        "--llm",
        dest="enable_llm",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Use an OpenAI-compatible LLM when RCPATCH_OPENAI_API_KEY, BUGRC_OPENAI_API_KEY, or OPENAI_API_KEY is configured.",
    )
    parser.add_argument("--require-llm", action="store_true", help="Fail if --llm is enabled but no provider is available.")
    parser.add_argument("--llm-model", default=os.getenv("RCPATCH_LLM_MODEL", os.getenv("BUGRC_LLM_MODEL", "gpt-4.1-mini")), help="OpenAI-compatible model.")
    parser.add_argument("--llm-base-url", default="https://api.openai.com/v1", help="OpenAI-compatible base URL.")
    parser.add_argument("--llm-cache-dir", help="Directory for LLM response cache.")
    parser.add_argument("--llm-timeout-seconds", type=float, default=45.0, help="Per-request LLM timeout.")
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        help="Logging verbosity.",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(getattr(logging, str(args.log_level).upper(), logging.INFO))
    logger = get_logger(__name__)

    collection_path = Path(args.collection_json).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    dataset_path = output_dir / "cve_semantic_root_cause_dataset.json"
    pattern_path = output_dir / "cve_pattern_prior_library.json"

    llm_client = build_llm_client(args, logger)
    if args.enable_llm and args.require_llm and (llm_client is None or not llm_client.is_available()):
        logger.error("--require-llm was set, but no OpenAI-compatible provider is available")
        return 1

    annotations: list[dict[str, Any]] = []
    stats = {
        "input_records_seen": 0,
        "skipped_before_start": 0,
        "filtered_not_cpp_relevant": 0,
        "below_min_confidence": 0,
        "llm_annotations": 0,
        "heuristic_annotations": 0,
    }
    started = args.start_after_cve is None
    processed = 0

    try:
        for record in iter_collection_records(collection_path):
            stats["input_records_seen"] += 1
            if not started:
                if record.cve_id == args.start_after_cve:
                    started = True
                stats["skipped_before_start"] += 1
                continue
            if args.only_cpp_relevant and not looks_cpp_relevant(record):
                stats["filtered_not_cpp_relevant"] += 1
                continue

            annotation = classify_record(record, llm_client=llm_client if args.enable_llm else None)
            if annotation["confidence"] < args.min_confidence:
                stats["below_min_confidence"] += 1
                continue

            annotations.append(annotation)
            processed += 1
            if annotation["source"] == "llm":
                stats["llm_annotations"] += 1
            else:
                stats["heuristic_annotations"] += 1

            if processed % max(1, args.checkpoint_every) == 0:
                write_outputs(dataset_path, pattern_path, annotations, args=args, stats=stats, final=False)
                logger.info("Checkpointed %d semantic annotations", processed)
            if args.max_records is not None and processed >= args.max_records:
                break
            if args.sleep_seconds > 0:
                time.sleep(args.sleep_seconds)
    except KeyboardInterrupt:
        logger.warning("Interrupted; writing partial semantic outputs with %d annotations", len(annotations))
        write_outputs(dataset_path, pattern_path, annotations, args=args, stats=stats, final=False)
        return 130

    write_outputs(dataset_path, pattern_path, annotations, args=args, stats=stats, final=True)
    print(f"Semantic dataset: {dataset_path}")
    print(f"Pattern prior library: {pattern_path}")
    print(f"Annotations: {len(annotations)}")
    return 0


def build_llm_client(args: argparse.Namespace, logger: logging.Logger) -> Optional[LLMClient]:
    """Build an optional OpenAI-compatible client."""

    if not args.enable_llm:
        return None
    provider = OpenAICompatibleProvider(
        model=args.llm_model,
        base_url=args.llm_base_url,
        timeout_seconds=args.llm_timeout_seconds,
    )
    client = LLMClient(
        provider=provider,
        cache=FileLLMCache(cache_dir=args.llm_cache_dir) if args.llm_cache_dir else FileLLMCache(),
    )
    if not client.is_available():
        logger.warning("LLM requested but no API key/model is available; falling back to heuristics")
    return client


def iter_collection_records(path: Path) -> Iterable[CollectedCVERecord]:
    """Stream records from a pretty-printed bootstrap collection result.

    The bootstrap output can be multiple gigabytes, so this avoids loading the
    whole JSON document into memory. It expects the standard RCPatch layout:
    {"record_count": ..., "records": [ ... ]}.
    """

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
    """Track JSON object nesting while ignoring braces inside strings."""

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


def looks_cpp_relevant(record: CollectedCVERecord) -> bool:
    """Heuristic relevance gate for C/C++ and memory-safety style CVEs."""

    if record.language in {Language.C, Language.CPP, Language.C_CPP}:
        return True
    cwes = {cwe.upper() for cwe in record.cwes if cwe}
    if cwes.intersection(MEMORY_CWES):
        return True
    text = f"{record.description} {record.project} {record.repo_url or ''}".lower()
    hints = (
        " c ",
        "c++",
        "cpp",
        "buffer overflow",
        "out-of-bounds",
        "out of bounds",
        "heap overflow",
        "stack overflow",
        "use-after-free",
        "use after free",
        "null pointer",
        "integer overflow",
        "memory corruption",
        "segmentation fault",
        "malloc",
        "free(",
        "memcpy",
        "strcpy",
    )
    padded = f" {text} "
    return any(hint in padded for hint in hints)


def classify_record(record: CollectedCVERecord, *, llm_client: Optional[LLMClient]) -> dict[str, Any]:
    """Classify one CVE through LLM interpretation or deterministic fallback."""

    heuristic = heuristic_classification(record)
    if llm_client is None or not llm_client.is_available():
        return build_annotation(record, heuristic, source="heuristic")

    response = llm_client.complete(build_llm_request(record, heuristic))
    if response is None:
        return build_annotation(record, heuristic, source="heuristic")

    parsed = parse_llm_json(response.text)
    if parsed is None:
        return build_annotation(record, heuristic, source="heuristic", extra={"llm_parse_failed": True})

    normalized = normalize_decision(parsed, fallback=heuristic)
    return build_annotation(
        record,
        normalized,
        source="llm",
        extra={"llm_provider": response.provider, "llm_model": response.model, "llm_cached": response.cached},
    )


def build_llm_request(record: CollectedCVERecord, heuristic: dict[str, Any]) -> LLMRequest:
    """Build a deterministic semantic prompt for one CVE."""

    references = [
        {
            "url": reference.url,
            "type": reference.reference_type.value,
            "tags": reference.tags[:5],
        }
        for reference in record.references[:8]
    ]
    user_payload = {
        "cve_id": record.cve_id,
        "project": record.project,
        "repo_url": record.repo_url,
        "cwe": record.cwe,
        "cwes": record.cwes[:8],
        "description": truncate_text(record.description, 2400),
        "references": references,
        "heuristic_prior": {
            "bug_class": heuristic["bug_class"],
            "root_cause_type": heuristic["root_cause_type"],
            "pattern": heuristic["pattern"],
        },
    }
    system_prompt = (
        "You classify CVE descriptions into semantic root-cause hypotheses for RCPatch. "
        "Use only the provided CVE text, CWE, project, and reference metadata. "
        "Do not invent source files, functions, line numbers, patches, or candidates. "
        "Return only valid JSON."
    )
    user_prompt = (
        "Classify this CVE into a reusable root-cause pattern. The result is a hypothesis "
        "that still needs code validation.\n\n"
        f"{json.dumps(user_payload, ensure_ascii=False, indent=2)}\n\n"
        "Return JSON with exactly these keys:\n"
        "{\n"
        '  "bug_class": "buffer_overflow|out_of_bounds_read|integer_overflow|use_after_free|null_dereference|double_free|type_confusion|input_validation|other",\n'
        '  "root_cause_type": "short snake_case root cause type",\n'
        '  "pattern": "short snake_case reusable pattern name",\n'
        '  "reasoning": "one concise explanation grounded in the CVE text",\n'
        '  "evidence_from_text": ["short phrases from the CVE text/CWE that support the classification"],\n'
        '  "confidence": 0.0\n'
        "}"
    )
    return LLMRequest(
        task="cve_semantic_root_cause_pattern",
        prompt_version=PROMPT_VERSION,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_schema={
            "type": "object",
            "required": ["bug_class", "root_cause_type", "pattern", "reasoning", "evidence_from_text", "confidence"],
        },
        temperature=0.0,
        max_output_tokens=500,
        metadata={"cve_id": record.cve_id},
    )


def heuristic_classification(record: CollectedCVERecord) -> dict[str, Any]:
    """Text/CWE-only fallback classification with explicit low-to-medium confidence."""

    text = f"{record.description} {' '.join(record.cwes)}".lower()
    cwes = {cwe.upper() for cwe in record.cwes if cwe}

    if "CWE-416" in cwes or "use-after-free" in text or "use after free" in text:
        return decision("use_after_free", "memory_lifetime_misuse", "use_after_free_via_dangling_pointer", text, 0.72)
    if "CWE-415" in cwes or "double free" in text:
        return decision("double_free", "ownership_lifetime_error", "double_free_or_invalid_free", text, 0.7)
    if "CWE-476" in cwes or "null pointer" in text or "null dereference" in text:
        return decision("null_dereference", "missing_null_check", "missing_null_check", text, 0.68)
    if "CWE-843" in cwes or "type confusion" in text:
        return decision("type_confusion", "incorrect_type_state_transition", "type_confusion_state_mismatch", text, 0.66)
    if "CWE-190" in cwes or "integer overflow" in text or "integer wrap" in text:
        bug_class = "integer_overflow"
        pattern = "integer_overflow_to_memory_error" if any(token in text for token in ("buffer", "out-of-bounds", "out of bounds", "memory")) else "integer_overflow"
        return decision(bug_class, "incorrect_integer_computation", pattern, text, 0.68)
    if any(cwe in cwes for cwe in ("CWE-787", "CWE-120", "CWE-121", "CWE-122", "CWE-788")) or "buffer overflow" in text or "heap overflow" in text or "stack overflow" in text:
        if any(token in text for token in ("length", "size", "bound", "index", "off-by-one", "off by one")):
            return decision("buffer_overflow", "incorrect_bounds_or_size_calculation", "incorrect_length_or_bounds_calculation", text, 0.7)
        return decision("buffer_overflow", "missing_bounds_check", "missing_bounds_check_before_write", text, 0.64)
    if any(cwe in cwes for cwe in ("CWE-125", "CWE-126", "CWE-127")) or "out-of-bounds read" in text or "out of bounds read" in text:
        return decision("out_of_bounds_read", "missing_bounds_check", "missing_bounds_check_before_read", text, 0.64)
    if "CWE-20" in cwes or "improper input validation" in text or "does not validate" in text or "insufficient validation" in text:
        return decision("input_validation", "missing_input_validation", "missing_validation_allows_invalid_state", text, 0.58)
    if "CWE-369" in cwes or "divide by zero" in text or "division by zero" in text:
        return decision("other", "missing_zero_check", "missing_arithmetic_guard", text, 0.55)
    return decision("other", "unknown_from_description", "unknown_semantic_pattern", text, 0.35)


def decision(bug_class: str, root_cause_type: str, pattern: str, text: str, confidence: float) -> dict[str, Any]:
    return {
        "bug_class": bug_class,
        "root_cause_type": root_cause_type,
        "pattern": pattern,
        "reasoning": heuristic_reasoning(bug_class, root_cause_type, pattern),
        "evidence_from_text": evidence_phrases(text),
        "confidence": confidence,
    }


def heuristic_reasoning(bug_class: str, root_cause_type: str, pattern: str) -> str:
    return (
        f"The CVE text/CWE indicates {bug_class}; RCPatch treats the likely semantic root cause as "
        f"{root_cause_type}, represented by pattern {pattern}. This is a text-only hypothesis."
    )


def evidence_phrases(text: str) -> list[str]:
    tokens = [
        "buffer overflow",
        "out-of-bounds",
        "out of bounds",
        "use-after-free",
        "use after free",
        "null pointer",
        "integer overflow",
        "improper input validation",
        "heap overflow",
        "stack overflow",
        "type confusion",
        "double free",
        "divide by zero",
    ]
    return [token for token in tokens if token in text][:5]


def parse_llm_json(text: str) -> Optional[dict[str, Any]]:
    """Parse a JSON object from an LLM response."""

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return None
        try:
            payload = json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return None
    return payload if isinstance(payload, dict) else None


def normalize_decision(payload: dict[str, Any], *, fallback: dict[str, Any]) -> dict[str, Any]:
    """Normalize LLM fields and keep deterministic fallback values for omissions."""

    confidence = payload.get("confidence", fallback["confidence"])
    try:
        normalized_confidence = max(0.0, min(1.0, float(confidence)))
    except (TypeError, ValueError):
        normalized_confidence = fallback["confidence"]
    evidence = payload.get("evidence_from_text", fallback["evidence_from_text"])
    if isinstance(evidence, str):
        evidence = [evidence]
    if not isinstance(evidence, list):
        evidence = fallback["evidence_from_text"]
    return {
        "bug_class": normalize_token(payload.get("bug_class") or fallback["bug_class"]),
        "root_cause_type": normalize_token(payload.get("root_cause_type") or fallback["root_cause_type"]),
        "pattern": normalize_token(payload.get("pattern") or fallback["pattern"]),
        "reasoning": str(payload.get("reasoning") or fallback["reasoning"]).strip(),
        "evidence_from_text": [str(item).strip() for item in evidence if str(item).strip()][:6],
        "confidence": normalized_confidence,
    }


def build_annotation(
    record: CollectedCVERecord,
    decision_payload: dict[str, Any],
    *,
    source: str,
    extra: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Convert a semantic decision into the lightweight dataset row."""

    references = [
        {
            "url": reference.url,
            "type": reference.reference_type.value,
            "repo_url": reference.repo_url,
            "commit_sha": reference.commit_sha,
        }
        for reference in record.references[:10]
    ]
    return {
        "cve_id": record.cve_id,
        "project": record.project,
        "repo_url": record.repo_url,
        "cwe": record.cwe,
        "cwes": record.cwes,
        "language": record.language.value,
        "description": record.description,
        "classification": "semantic_root_cause_hypothesis",
        "bug_class": decision_payload["bug_class"],
        "root_cause_type": decision_payload["root_cause_type"],
        "pattern": decision_payload["pattern"],
        "explanation": decision_payload["reasoning"],
        "evidence_from_text": decision_payload["evidence_from_text"],
        "confidence": round(float(decision_payload["confidence"]), 4),
        "needs_code_validation": True,
        "source": source,
        "references": references,
        "metadata": extra or {},
    }


def write_outputs(
    dataset_path: Path,
    pattern_path: Path,
    annotations: list[dict[str, Any]],
    *,
    args: argparse.Namespace,
    stats: dict[str, Any],
    final: bool,
) -> None:
    """Write dataset and pattern library atomically enough for checkpoint use."""

    dataset = {
        "schema_version": SCHEMA_VERSION_DATASET,
        "metadata": {
            "generated_at": utc_now(),
            "final": final,
            "source_collection": str(Path(args.collection_json).expanduser().resolve()),
            "record_count": len(annotations),
            "only_cpp_relevant": bool(args.only_cpp_relevant),
            "min_confidence": args.min_confidence,
            "llm_enabled": bool(args.enable_llm),
            "llm_model": args.llm_model if args.enable_llm else None,
            "stats": stats,
            "limitations": [
                "Text-only semantic hypotheses; no source checkout, patch alignment, slicing, or line-level validation.",
                "Root-cause locations are intentionally omitted because they require code evidence.",
                "Use this as a RCPatch ranking prior or triage dataset, not as ground-truth source annotations.",
            ],
        },
        "records": annotations,
    }
    pattern_library = build_pattern_library(annotations, min_support=args.pattern_min_support)
    atomic_write_json(dataset_path, dataset)
    atomic_write_json(pattern_path, pattern_library)


def build_pattern_library(annotations: list[dict[str, Any]], *, min_support: int) -> dict[str, Any]:
    """Aggregate semantic annotations into reusable pattern priors."""

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for annotation in annotations:
        grouped[annotation["pattern"]].append(annotation)

    patterns: list[dict[str, Any]] = []
    for pattern_name, items in sorted(grouped.items(), key=lambda pair: (-len(pair[1]), pair[0])):
        if len(items) < min_support:
            continue
        confidence_values = [float(item["confidence"]) for item in items]
        bug_classes = Counter(item["bug_class"] for item in items)
        root_types = Counter(item["root_cause_type"] for item in items)
        cwes = Counter(cwe for item in items for cwe in item.get("cwes", []) if cwe)
        examples = [
            {
                "cve_id": item["cve_id"],
                "project": item["project"],
                "bug_class": item["bug_class"],
                "root_cause_type": item["root_cause_type"],
                "confidence": item["confidence"],
                "explanation": truncate_text(item["explanation"], 320),
                "needs_code_validation": True,
            }
            for item in sorted(items, key=lambda row: (-float(row["confidence"]), row["cve_id"]))[:8]
        ]
        patterns.append(
            {
                "pattern_id": pattern_name,
                "name": pattern_name.replace("_", " "),
                "category": most_common_key(bug_classes),
                "root_cause_type": most_common_key(root_types),
                "support_count": len(items),
                "confidence_avg": round(sum(confidence_values) / len(confidence_values), 4),
                "confidence_min": round(min(confidence_values), 4),
                "confidence_max": round(max(confidence_values), 4),
                "cve_ids": sorted(item["cve_id"] for item in items),
                "bug_class_distribution": dict(bug_classes.most_common()),
                "root_cause_distribution": dict(root_types.most_common()),
                "cwe_distribution": dict(cwes.most_common(12)),
                "feature_rules": [
                    {"feature": "semantic_pattern", "operator": "equals", "value": pattern_name},
                    {"feature": "needs_code_validation", "operator": "equals", "value": "true"},
                ],
                "examples": examples,
                "metadata": {
                    "source": "cve_description_semantic_prior",
                    "precision_level": "semantic_only",
                },
            }
        )

    return {
        "schema_version": SCHEMA_VERSION_PATTERNS,
        "metadata": {
            "generated_at": utc_now(),
            "pattern_count": len(patterns),
            "annotation_count": len(annotations),
            "min_support": min_support,
            "limitations": [
                "Patterns are mined from CVE text semantics and require source-level RCPatch validation before use as evidence.",
            ],
        },
        "patterns": patterns,
    }


def most_common_key(counter: Counter[str]) -> str:
    return counter.most_common(1)[0][0] if counter else "unknown"


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    """Write JSON through a sibling temp file so readers never see a partial file."""

    temp_path = path.with_name(f".{path.name}.tmp")
    temp_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    temp_path.replace(path)


def normalize_token(value: Any) -> str:
    text = str(value).strip().lower()
    text = re.sub(r"[^a-z0-9]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("_")
    return text or "unknown"


def truncate_text(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


if __name__ == "__main__":
    raise SystemExit(main())
