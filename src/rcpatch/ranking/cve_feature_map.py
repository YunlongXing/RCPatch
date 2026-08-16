"""Explicit feature vocabulary for mined CVE pattern priors."""

from __future__ import annotations

from dataclasses import dataclass


SIZE_HINT_TOKENS = ("len", "length", "size", "count", "index", "idx", "offset", "bound", "capacity")
COPY_TOKENS = ("memcpy", "memmove", "strcpy", "strncpy", "memset", "copy")
LIFETIME_TOKENS = ("malloc", "calloc", "realloc", "free", "delete", "new")
NULL_TOKENS = ("null", "nullptr")


@dataclass(frozen=True)
class CVEPatternFeatureRule:
    """Human-readable mapping from a pattern category to ranking features."""

    category: str
    description: str
    positive_features: tuple[str, ...]
    operation_types: tuple[str, ...]


CVE_PATTERN_FEATURE_RULES: tuple[CVEPatternFeatureRule, ...] = (
    CVEPatternFeatureRule(
        category="incorrect_size_computation",
        description="Length, size, index, or capacity computation contributes to memory misuse.",
        positive_features=("has_integer_influence", "defines_value_used_later", "has_memory_context"),
        operation_types=("length_calculation", "size_to_copy"),
    ),
    CVEPatternFeatureRule(
        category="validation_or_guard_issue",
        description="Missing, wrong, or misplaced validation changes reachability of unsafe behavior.",
        positive_features=("affects_control_flow", "runtime_support_score"),
        operation_types=("guard_check", "null_check"),
    ),
    CVEPatternFeatureRule(
        category="ownership_or_lifetime_operation",
        description="Allocation, deallocation, ownership transfer, or alias lifetime contributes to invalid access.",
        positive_features=("has_memory_context", "changes_object_state"),
        operation_types=("lifetime_management", "state_update"),
    ),
    CVEPatternFeatureRule(
        category="invalid_state_update",
        description="Object or global state is updated inconsistently before the trigger.",
        positive_features=("changes_object_state", "defines_value_used_later"),
        operation_types=("state_update",),
    ),
    CVEPatternFeatureRule(
        category="invalid_initialization",
        description="Initialization or copy operation seeds an invalid value used later.",
        positive_features=("defines_value_used_later", "has_memory_context"),
        operation_types=("initialization", "size_to_copy"),
    ),
    CVEPatternFeatureRule(
        category="buffer_size_contract_mismatch",
        description="A public or internal API reports one size but writes a larger object later.",
        positive_features=("writes_through_output_parameter", "has_integer_influence", "defines_value_used_later"),
        operation_types=("length_calculation", "size_to_copy"),
    ),
)


def infer_cve_operation_type(
    *,
    text_lower: str,
    affects_control_flow: bool,
    has_integer_influence: bool,
    has_memory_context: bool,
    changes_object_state: bool,
) -> str:
    """Infer the coarse operation vocabulary used by mined CVE patterns."""

    has_size_hint = any(token in text_lower for token in SIZE_HINT_TOKENS)
    has_copy = any(token in text_lower for token in COPY_TOKENS)
    has_lifetime = has_memory_context or any(token in text_lower for token in LIFETIME_TOKENS)
    if affects_control_flow and any(token in text_lower for token in NULL_TOKENS):
        return "null_check"
    if has_copy and has_size_hint:
        return "size_to_copy"
    if has_integer_influence and has_size_hint:
        return "length_calculation"
    if has_lifetime:
        return "lifetime_management"
    if affects_control_flow:
        return "guard_check"
    if changes_object_state:
        return "state_update"
    if has_copy:
        return "initialization"
    return "unknown"


def describe_pattern_category(category: str) -> str:
    """Return a compact description for a mined pattern category."""

    normalized = category.strip().lower()
    for rule in CVE_PATTERN_FEATURE_RULES:
        if rule.category == normalized:
            return rule.description
    return "No explicit CVE pattern feature rule is registered for this category."
