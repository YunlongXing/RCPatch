"""Historical CVE pattern priors used to guide candidate ranking."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

from rcpatch.errors import ModelSerializationError
from rcpatch.ranking.cve_feature_map import describe_pattern_category, infer_cve_operation_type


@dataclass(frozen=True)
class CVEPatternMatch:
    """Best historical pattern match for one candidate statement."""

    score: float
    category: str
    operation_type: str
    support_count: int
    average_confidence: float
    pattern_ids: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class _PatternEntry:
    pattern_id: str
    category: str
    operation_type: str
    support_count: int
    average_confidence: float
    templates: tuple[str, ...]


class CVEPatternPrior:
    """Lookup table built from a mined CVE root-cause pattern library.

    The prior is intentionally weak supervision: it only boosts candidates that
    already have source-derived evidence. It never invents candidates or
    overrides the backward slice.
    """

    def __init__(self, patterns: Iterable[_PatternEntry]) -> None:
        self.patterns = tuple(patterns)
        self.max_support = max((pattern.support_count for pattern in self.patterns), default=1)

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        *,
        min_support: int = 1,
        min_confidence: float = 0.0,
    ) -> "CVEPatternPrior":
        """Load a mined pattern library JSON file."""

        input_path = Path(path).expanduser().resolve()
        try:
            payload = json.loads(input_path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ModelSerializationError(f"Failed to read CVE pattern library {input_path}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ModelSerializationError(f"Invalid CVE pattern library JSON {input_path}: {exc}") from exc
        if not isinstance(payload, dict):
            raise ModelSerializationError(f"Expected CVE pattern library object in {input_path}")

        entries: list[_PatternEntry] = []
        for raw_pattern in payload.get("patterns", []) or []:
            if not isinstance(raw_pattern, dict):
                continue
            support_count = _safe_int(raw_pattern.get("support_count"), default=0)
            metadata = raw_pattern.get("metadata") if isinstance(raw_pattern.get("metadata"), dict) else {}
            average_confidence = _safe_float(metadata.get("average_confidence"), default=0.0)
            if support_count < min_support or average_confidence < min_confidence:
                continue
            category = _normalize_token(raw_pattern.get("category"))
            operation_type = _normalize_token(raw_pattern.get("operation_type"))
            pattern_id = str(raw_pattern.get("pattern_id") or "").strip()
            if not category or not operation_type or not pattern_id:
                continue
            templates = tuple(
                str(item.get("template") or "").strip().lower()
                for item in raw_pattern.get("templates", []) or []
                if isinstance(item, dict) and str(item.get("template") or "").strip()
            )
            entries.append(
                _PatternEntry(
                    pattern_id=pattern_id,
                    category=category,
                    operation_type=operation_type,
                    support_count=support_count,
                    average_confidence=average_confidence,
                    templates=templates,
                )
            )
        return cls(entries)

    def match(
        self,
        *,
        category: str,
        text_lower: str,
        affects_control_flow: bool,
        has_integer_influence: bool,
        has_memory_context: bool,
        changes_object_state: bool,
    ) -> Optional[CVEPatternMatch]:
        """Return the strongest pattern-library match for extracted features."""

        normalized_category = _normalize_token(category)
        if not self.patterns or normalized_category in {"", "none", "unknown"}:
            return None

        operation_type = infer_operation_type(
            text_lower=text_lower,
            affects_control_flow=affects_control_flow,
            has_integer_influence=has_integer_influence,
            has_memory_context=has_memory_context,
            changes_object_state=changes_object_state,
        )

        best_entry: Optional[_PatternEntry] = None
        best_score = 0.0
        best_reason = ""
        for entry in self.patterns:
            category_match = entry.category == normalized_category
            operation_match = entry.operation_type == operation_type
            if not category_match and not operation_match:
                continue

            support_score = math.log1p(entry.support_count) / math.log1p(max(self.max_support, 1))
            confidence_score = max(0.0, min(entry.average_confidence, 1.0))
            template_score = _template_overlap_score(text_lower, entry.templates)
            score = 0.0
            if category_match:
                score += 0.45
            if operation_match:
                score += 0.25
            score += 0.18 * support_score
            score += 0.10 * confidence_score
            score += 0.02 * template_score

            if score > best_score:
                best_entry = entry
                best_score = score
                if category_match and operation_match:
                    best_reason = (
                        "Historical CVE pattern matches both root-cause category and operation type. "
                        f"{describe_pattern_category(entry.category)}"
                    )
                elif category_match:
                    best_reason = (
                        "Historical CVE pattern matches the root-cause category. "
                        f"{describe_pattern_category(entry.category)}"
                    )
                else:
                    best_reason = "Historical CVE pattern matches the inferred operation type."

        if best_entry is None or best_score <= 0.0:
            return None

        sibling_ids = tuple(
            entry.pattern_id
            for entry in self.patterns
            if entry.category == best_entry.category and entry.operation_type == best_entry.operation_type
        )[:5]
        return CVEPatternMatch(
            score=round(min(best_score, 1.0), 4),
            category=best_entry.category,
            operation_type=best_entry.operation_type,
            support_count=best_entry.support_count,
            average_confidence=round(best_entry.average_confidence, 4),
            pattern_ids=sibling_ids,
            reason=best_reason,
        )


def infer_operation_type(
    *,
    text_lower: str,
    affects_control_flow: bool,
    has_integer_influence: bool,
    has_memory_context: bool,
    changes_object_state: bool,
) -> str:
    """Infer the coarse operation vocabulary used by mined CVE patterns."""
    return infer_cve_operation_type(
        text_lower=text_lower,
        affects_control_flow=affects_control_flow,
        has_integer_influence=has_integer_influence,
        has_memory_context=has_memory_context,
        changes_object_state=changes_object_state,
    )


def _template_overlap_score(text_lower: str, templates: tuple[str, ...]) -> float:
    if not templates:
        return 0.0
    text_tokens = set(_tokenize(text_lower))
    if not text_tokens:
        return 0.0
    best = 0.0
    for template in templates:
        template_tokens = set(_tokenize(template))
        if not template_tokens:
            continue
        best = max(best, len(text_tokens & template_tokens) / len(template_tokens))
    return min(best, 1.0)


def _tokenize(value: str) -> list[str]:
    return [token for token in value.replace("_", " ").split() if len(token) > 2]


def _normalize_token(value: Any) -> str:
    return str(value or "").strip().lower()


def _safe_int(value: Any, *, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value: Any, *, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default
