"""Stable enumerations used across RCPatch models."""

from __future__ import annotations

from enum import Enum


class Language(str, Enum):
    """Supported implementation language families."""

    C_CPP = "c_cpp"
    C = "c"
    CPP = "cpp"
    UNKNOWN = "unknown"


class AdvisorySourceKind(str, Enum):
    """Supported upstream advisory data sources for CVE collection."""

    CVE_LIST_V5 = "cve_list_v5"
    NVD_JSON_FEED = "nvd_json_feed"
    GITHUB_SECURITY_ADVISORY = "github_security_advisory"
    PROJECT_ADVISORY = "project_advisory"


class RepositoryProvider(str, Enum):
    """Repository hosting providers recognized by collection heuristics."""

    GITHUB = "github"
    GITLAB = "gitlab"
    OTHER = "other"
    UNKNOWN = "unknown"


class ReferenceType(str, Enum):
    """Normalized reference categories extracted from advisory URLs."""

    COMMIT = "commit"
    PULL_REQUEST = "pull_request"
    ISSUE = "issue"
    ADVISORY = "advisory"
    PATCH = "patch"
    COMPARE = "compare"
    RELEASE = "release"
    REPOSITORY = "repository"
    OTHER = "other"


class CVEPatchType(str, Enum):
    """Heuristic categories for CVE fixing patches."""

    DIRECT_FIX = "direct_fix"
    ADDED_CHECK = "added_check"
    BOUNDS_FIX = "bounds_fix"
    REFACTOR = "refactor"
    CLEANUP = "cleanup"
    UNKNOWN = "unknown"


class BugType(str, Enum):
    """Initial prioritized bug classes."""

    NULL_DEREFERENCE = "null_dereference"
    BUFFER_OVERFLOW = "buffer_overflow"
    INTEGER_OVERFLOW_TO_MEMORY_ERROR = "integer_overflow_to_memory_error"
    USE_AFTER_FREE = "use_after_free"
    UNKNOWN = "unknown"


class TriggerType(str, Enum):
    """Ways a trigger point may be identified."""

    USER_PROVIDED = "user_provided"
    ASAN_REPORT = "asan_report"
    UBSAN_REPORT = "ubsan_report"
    TSAN_REPORT = "tsan_report"
    ASSERT_FAILURE = "assert_failure"
    CRASH_LINE = "crash_line"
    FIRST_FAILING_OPERATION = "first_failing_operation"
    EXCEPTION_THROW_SITE = "exception_throw_site"
    STACK_TRACE = "stack_trace"


class EvidenceKind(str, Enum):
    """Types of supporting evidence attached to findings and reports."""

    SANITIZER_REPORT = "sanitizer_report"
    STACK_TRACE = "stack_trace"
    RUNTIME_LOG = "runtime_log"
    PATCH_DIFF = "patch_diff"
    COMMIT_MESSAGE = "commit_message"
    ISSUE_TEXT = "issue_text"
    REGRESSION_TEST = "regression_test"
    CORE_DUMP = "core_dump"
    EXECUTION_TRACE = "execution_trace"
    USER_HINT = "user_hint"


class CandidateLabel(str, Enum):
    """Classification used when ranking likely locations."""

    SYMPTOM = "symptom"
    PROPAGATION = "propagation"
    ROOT_CAUSE_CANDIDATE = "root_cause_candidate"


class PropagationRelation(str, Enum):
    """Allowed causality chain edge kinds."""

    DATA_FLOW = "data_flow"
    CONTROL_FLOW = "control_flow"
    CALL_ARGUMENT = "call_argument"
    RETURN_VALUE = "return_value"
    STATE_UPDATE = "state_update"
    HEAP_ALIAS_PROPAGATION = "heap_alias_propagation"
    OWNERSHIP_TRANSFER = "ownership_transfer"
    ALLOCATION = "allocation"
    FREE = "free"
    PATCH_HINT = "patch_hint"


class PatchIntent(str, Enum):
    """Optional interpretation of what a patch is doing."""

    DIRECT_FIX = "direct_fix"
    DEFENSIVE_GUARD = "defensive_guard"
    COMPENSATING_CHECK = "compensating_check"
    CLEANUP = "cleanup"
    REFACTOR = "refactor"
    UNKNOWN = "unknown"


class ParserBackend(str, Enum):
    """Preferred source-analysis backend."""

    TREE_SITTER = "tree_sitter"
    CLANG_AST = "clang_ast"
    CTAGS = "ctags"
    REGEX = "regex"


class StatementKind(str, Enum):
    """Approximate source statement categories used by the lightweight abstraction layer."""

    ASSIGNMENT = "assignment"
    CONDITION = "condition"
    RETURN = "return"
    FUNCTION_CALL = "function_call"
    MEMORY_OPERATION = "memory_operation"
    DECLARATION = "declaration"
    UNKNOWN = "unknown"


class MemoryOperationKind(str, Enum):
    """Categories for memory-related operations."""

    ALLOCATION = "allocation"
    DEALLOCATION = "deallocation"
    COPY = "copy"
    SET = "set"
    COMPARE = "compare"
    REALLOCATION = "reallocation"
    UNKNOWN = "unknown"


class DiagnosticLevel(str, Enum):
    """Severity levels for parser diagnostics."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class DependencyRelation(str, Enum):
    """Dependency edge categories used by backward slicing."""

    TRIGGER = "trigger"
    DATA_DEPENDENCE = "data_dependence"
    CONTROL_DEPENDENCE = "control_dependence"
    CALL_ARGUMENT = "call_argument"
    RETURN_VALUE = "return_value"
    GLOBAL_STATE = "global_state"
    HEAP_OBJECT = "heap_object"
    ALLOCATION_SITE = "allocation_site"
    DEALLOCATION_SITE = "deallocation_site"
    INITIALIZATION_SITE = "initialization_site"
    INTEGER_INFLUENCE = "integer_influence"
    STATE_UPDATE = "state_update"
    CALLER_CONTEXT = "caller_context"
