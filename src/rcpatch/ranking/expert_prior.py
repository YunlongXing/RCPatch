"""Expert-curated RCA priors for candidate ranking.

This module supports small, high-quality RCA corpora such as Google Project
Zero's 0-day root-cause analyses. The prior is deliberately weak supervision:
it can only boost candidates already recovered from source evidence.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

from rcpatch.errors import ModelSerializationError
from rcpatch.ranking.cve_feature_map import describe_pattern_category


@dataclass(frozen=True)
class ExpertRCAMatch:
    """Best expert-RCA match for one candidate statement."""

    score: float
    category: str
    operation_type: str
    confidence: float
    record_ids: tuple[str, ...]
    source: str
    matched_terms: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class _ExpertRCAEntry:
    record_id: str
    source: str
    category_tags: tuple[str, ...]
    operation_types: tuple[str, ...]
    confidence: float
    search_text: str


class ExpertRCAPrior:
    """Lookup table for expert-curated root-cause analyses.

    The expected JSON shape is intentionally flexible:

    ``{"records": [{...}]}``, ``{"rcas": [{...}]}``, ``{"patterns": [{...}]}``,
    or a top-level list are accepted. Each record may contain fields such as
    ``bug_class``, ``root_cause_summary``, ``patch_analysis``, ``exploit_flow``,
    ``variant_analysis``, ``structural_improvements``, ``pattern_tags``, and
    ``operation_types``.
    """

    def __init__(self, entries: Iterable[_ExpertRCAEntry]) -> None:
        self.entries = tuple(entries)
        self.max_records = max(len(self.entries), 1)

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        *,
        min_confidence: float = 0.0,
    ) -> "ExpertRCAPrior":
        """Load an expert RCA prior JSON file."""

        input_path = Path(path).expanduser().resolve()
        try:
            payload = json.loads(input_path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ModelSerializationError(f"Failed to read expert RCA prior {input_path}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ModelSerializationError(f"Invalid expert RCA prior JSON {input_path}: {exc}") from exc

        entries: list[_ExpertRCAEntry] = []
        for raw_record in _iter_records(payload):
            if not isinstance(raw_record, dict):
                continue
            confidence = _safe_float(raw_record.get("confidence"), default=0.85)
            if confidence < min_confidence:
                continue
            category_tags = _extract_category_tags(raw_record)
            operation_types = _extract_operation_types(raw_record)
            search_text = _build_search_text(raw_record)
            record_id = _record_id(raw_record)
            if not record_id or (not category_tags and not operation_types and not search_text):
                continue
            entries.append(
                _ExpertRCAEntry(
                    record_id=record_id,
                    source=str(raw_record.get("source") or raw_record.get("dataset") or "expert_rca").strip(),
                    category_tags=category_tags,
                    operation_types=operation_types,
                    confidence=max(0.0, min(confidence, 1.0)),
                    search_text=search_text,
                )
            )
        return cls(entries)

    def match(
        self,
        *,
        category: str,
        operation_type: str,
        text_lower: str,
        bug_type: Optional[str] = None,
    ) -> Optional[ExpertRCAMatch]:
        """Return the strongest expert-prior match for extracted features."""

        if not self.entries:
            return None
        normalized_category = _normalize_pattern_category(category)
        normalized_operation = _normalize_operation_type(operation_type)
        bug_type_tokens = set(_tokenize(str(bug_type or "")))
        text_tokens = set(_tokenize(text_lower))

        best_entry: Optional[_ExpertRCAEntry] = None
        best_score = 0.0
        best_terms: tuple[str, ...] = ()
        for entry in self.entries:
            category_match = bool(normalized_category and normalized_category in entry.category_tags)
            operation_match = bool(normalized_operation and normalized_operation in entry.operation_types)
            text_score, matched_terms = _text_overlap_score(text_tokens | bug_type_tokens, entry.search_text)
            if not category_match and not operation_match and text_score <= 0.0:
                continue

            score = 0.0
            if category_match:
                score += 0.42
            if operation_match:
                score += 0.24
            score += 0.22 * text_score
            score += 0.10 * entry.confidence
            score += 0.02 * (math.log1p(len(entry.category_tags) + len(entry.operation_types)) / math.log1p(10))
            if score > best_score:
                best_entry = entry
                best_score = score
                best_terms = matched_terms

        if best_entry is None or best_score <= 0.0:
            return None

        matched_category = normalized_category if normalized_category in best_entry.category_tags else (
            best_entry.category_tags[0] if best_entry.category_tags else "unknown"
        )
        matched_operation = normalized_operation if normalized_operation in best_entry.operation_types else (
            best_entry.operation_types[0] if best_entry.operation_types else "unknown"
        )
        sibling_ids = tuple(
            entry.record_id
            for entry in self.entries
            if matched_category in entry.category_tags or matched_operation in entry.operation_types
        )[:5]
        reason = (
            "Expert RCA prior matches an existing candidate's root-cause semantics. "
            f"{describe_pattern_category(matched_category)}"
        )
        return ExpertRCAMatch(
            score=round(min(best_score, 1.0), 4),
            category=matched_category,
            operation_type=matched_operation,
            confidence=round(best_entry.confidence, 4),
            record_ids=sibling_ids or (best_entry.record_id,),
            source=best_entry.source,
            matched_terms=best_terms,
            reason=reason,
        )


def _iter_records(payload: Any) -> Iterable[Any]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("records", "rcas", "entries", "patterns", "root_cause_analyses"):
            records = payload.get(key)
            if isinstance(records, list):
                return records
    raise ModelSerializationError("Expected expert RCA prior to contain a list of records")


def _extract_category_tags(raw_record: dict[str, Any]) -> tuple[str, ...]:
    raw_values: list[Any] = []
    for key in ("pattern_tags", "root_cause_patterns", "categories", "bug_classes", "bug_class", "pattern", "category"):
        value = raw_record.get(key)
        if isinstance(value, list):
            raw_values.extend(value)
        elif value:
            raw_values.append(value)

    tags = {_normalize_pattern_category(str(value)) for value in raw_values}
    text = _build_search_text(raw_record)
    tags.update(_infer_categories_from_text(text))
    return tuple(sorted(tag for tag in tags if tag and tag != "unknown"))


def _extract_operation_types(raw_record: dict[str, Any]) -> tuple[str, ...]:
    raw_values: list[Any] = []
    for key in ("operation_types", "operation_type", "operations"):
        value = raw_record.get(key)
        if isinstance(value, list):
            raw_values.extend(value)
        elif value:
            raw_values.append(value)

    operations = {_normalize_operation_type(str(value)) for value in raw_values}
    operations.update(_infer_operations_from_text(_build_search_text(raw_record)))
    return tuple(sorted(operation for operation in operations if operation and operation != "unknown"))


def _build_search_text(raw_record: dict[str, Any]) -> str:
    fields = (
        "title",
        "product",
        "cve_id",
        "bug_class",
        "vulnerability_details",
        "root_cause_summary",
        "patch_analysis",
        "bug_introducing_change",
        "exploit_flow",
        "variant_analysis",
        "structural_improvements",
        "notes",
    )
    parts: list[str] = []
    for field in fields:
        value = raw_record.get(field)
        if isinstance(value, list):
            parts.extend(str(item) for item in value)
        elif value:
            parts.append(str(value))
    for field in ("pattern_tags", "operation_types"):
        value = raw_record.get(field)
        if isinstance(value, list):
            parts.extend(str(item) for item in value)
    return " ".join(parts).lower()


def _record_id(raw_record: dict[str, Any]) -> str:
    for key in ("record_id", "id", "cve_id", "bug_id", "title", "url"):
        value = str(raw_record.get(key) or "").strip()
        if value:
            return value
    return ""


def _normalize_pattern_category(value: str) -> str:
    token = _normalize_token(value)
    if not token or token in {"none", "unknown"}:
        return token
    if any(item in token for item in ("use_after_free", "uaf", "double_free", "dangling", "lifetime", "ownership")):
        return "ownership_or_lifetime_operation"
    if any(item in token for item in ("integer", "overflow", "underflow", "bounds", "length", "size", "index", "oob")):
        return "incorrect_size_computation"
    if any(item in token for item in ("missing_check", "validation", "guard", "null_check", "bounds_check", "sanit")):
        return "validation_or_guard_issue"
    if any(item in token for item in ("uninit", "initialization", "initialisation")):
        return "invalid_initialization"
    if any(item in token for item in ("state", "logic", "type_confusion", "confusion", "race", "invariant")):
        return "invalid_state_update"
    if "contract" in token and any(item in token for item in ("buffer", "size", "length")):
        return "buffer_size_contract_mismatch"
    return token


def _normalize_operation_type(value: str) -> str:
    token = _normalize_token(value)
    if not token or token in {"none", "unknown"}:
        return token
    if any(item in token for item in ("length", "size", "integer", "bounds", "index", "overflow", "underflow")):
        return "length_calculation"
    if any(item in token for item in ("guard", "check", "validation", "condition", "branch")):
        return "guard_condition"
    if any(item in token for item in ("alloc", "free", "delete", "lifetime", "ownership", "uaf")):
        return "ownership_transfer"
    if any(item in token for item in ("init", "zero", "uninit")):
        return "initialization"
    if any(item in token for item in ("state", "field", "type", "logic")):
        return "state_update"
    return token


def _infer_categories_from_text(text: str) -> set[str]:
    categories: set[str] = set()
    for phrase, category in (
        ("use-after-free", "ownership_or_lifetime_operation"),
        ("use after free", "ownership_or_lifetime_operation"),
        ("double free", "ownership_or_lifetime_operation"),
        ("dangling pointer", "ownership_or_lifetime_operation"),
        ("integer overflow", "incorrect_size_computation"),
        ("integer underflow", "incorrect_size_computation"),
        ("out-of-bounds", "incorrect_size_computation"),
        ("out of bounds", "incorrect_size_computation"),
        ("bounds check", "validation_or_guard_issue"),
        ("missing check", "validation_or_guard_issue"),
        ("null check", "validation_or_guard_issue"),
        ("uninitialized", "invalid_initialization"),
        ("type confusion", "invalid_state_update"),
        ("state inconsistency", "invalid_state_update"),
    ):
        if phrase in text:
            categories.add(category)
    return categories


def _infer_operations_from_text(text: str) -> set[str]:
    operations: set[str] = set()
    if any(phrase in text for phrase in ("length", "size", "bounds", "index", "integer overflow", "out-of-bounds")):
        operations.add("length_calculation")
    if any(phrase in text for phrase in ("check", "guard", "validate", "validation", "condition")):
        operations.add("guard_condition")
    if any(phrase in text for phrase in ("free", "delete", "allocation", "lifetime", "ownership", "use-after-free")):
        operations.add("ownership_transfer")
    if any(phrase in text for phrase in ("initialize", "initialise", "zero", "uninitialized")):
        operations.add("initialization")
    if any(phrase in text for phrase in ("state", "field", "type confusion", "invariant")):
        operations.add("state_update")
    return operations


def _text_overlap_score(candidate_tokens: set[str], search_text: str) -> tuple[float, tuple[str, ...]]:
    if not candidate_tokens or not search_text:
        return 0.0, ()
    rca_tokens = set(_tokenize(search_text))
    if not rca_tokens:
        return 0.0, ()
    overlap = sorted(candidate_tokens & rca_tokens)
    if not overlap:
        return 0.0, ()
    return min(len(overlap) / min(len(candidate_tokens), 8), 1.0), tuple(overlap[:8])


def _tokenize(value: str) -> list[str]:
    return [token for token in re.split(r"[^a-zA-Z0-9_]+", value.lower()) if len(token) > 2]


def _normalize_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")


def _safe_float(value: Any, *, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default
