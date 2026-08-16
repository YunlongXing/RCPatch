"""Core data models and intermediate representations for RCPatch."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from collections.abc import Mapping

from pydantic import Field, field_validator, model_validator

from rcpatch.models.base import RCPatchModel
from rcpatch.models.enums import (
    BugType,
    CandidateLabel,
    EvidenceKind,
    Language,
    ParserBackend,
    PatchIntent,
    PropagationRelation,
    TriggerType,
)


def _validate_non_empty_optional(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    if not value.strip():
        raise ValueError("value must not be empty when provided")
    return value


def _normalize_blank_optional(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    if not value.strip():
        return None
    return value


class ConfidenceScore(RCPatchModel):
    """Confidence metadata for uncertain inferences."""

    value: float = Field(ge=0.0, le=1.0, description="Normalized confidence score between 0.0 and 1.0.")
    rationale: Optional[str] = Field(default=None, description="Short explanation of what drives the score.")
    method: Optional[str] = Field(default=None, description="Name of the scoring or calibration method.")
    components: dict[str, float] = Field(
        default_factory=dict,
        description="Optional feature-level contribution map used to explain confidence.",
    )
    metadata: dict[str, Any] = Field(default_factory=dict, description="Loose extension space for future metadata.")

    @field_validator("rationale", "method")
    @classmethod
    def _check_optional_text(cls, value: Optional[str]) -> Optional[str]:
        return _validate_non_empty_optional(value)


class EvidenceReference(RCPatchModel):
    """Pointer to supporting evidence from a runtime or patch artifact."""

    kind: EvidenceKind
    path: Optional[str] = Field(default=None, description="Filesystem path or logical identifier for the evidence.")
    line: Optional[int] = Field(default=None, ge=1, description="1-based line number in the evidence artifact.")
    column: Optional[int] = Field(default=None, ge=1, description="1-based column number in the evidence artifact.")
    excerpt: Optional[str] = Field(default=None, description="Short excerpt from the evidence.")
    description: Optional[str] = Field(default=None, description="Human-readable explanation of why this evidence matters.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Extension bag for tool-specific evidence fields.")

    @field_validator("path", "excerpt", "description")
    @classmethod
    def _validate_text_fields(cls, value: Optional[str]) -> Optional[str]:
        return _validate_non_empty_optional(value)


class LLMJudgment(RCPatchModel):
    """Optional LLM-assisted interpretation attached to candidates, chains, or patches."""

    task: str = Field(min_length=1, description="Semantic task performed by the LLM, such as patch_intent.")
    provider: Optional[str] = Field(default=None, description="LLM provider name.")
    model: Optional[str] = Field(default=None, description="Model identifier.")
    verdict: str = Field(min_length=1, description="Short semantic judgment or label produced by the LLM.")
    rationale: Optional[str] = Field(default=None, description="Short explanation of the judgment.")
    confidence: Optional[ConfidenceScore] = Field(default=None, description="Optional confidence attached to the judgment.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Extension space for prompts, tokens, or tags.")

    @field_validator("provider", "model", "rationale")
    @classmethod
    def _validate_optional_text(cls, value: Optional[str]) -> Optional[str]:
        return _validate_non_empty_optional(value)


class SourceLocation(RCPatchModel):
    """A normalized source-code location within the analyzed repository."""

    file: str = Field(min_length=1, description="Repository-relative or absolute source file path.")
    line: int = Field(ge=1, description="1-based source line number.")
    column: Optional[int] = Field(default=None, ge=1, description="1-based source column number.")
    end_line: Optional[int] = Field(default=None, ge=1, description="Optional end line for ranges or multi-token spans.")
    end_column: Optional[int] = Field(default=None, ge=1, description="Optional end column for ranges or multi-token spans.")
    function: Optional[str] = Field(default=None, description="Enclosing function or method name.")
    snippet: Optional[str] = Field(default=None, description="Optional source snippet for display or debugging.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Extension space for symbol ids or AST node ids.")

    @field_validator("function", "snippet")
    @classmethod
    def _validate_optional_text(cls, value: Optional[str]) -> Optional[str]:
        return _validate_non_empty_optional(value)

    @model_validator(mode="after")
    def _validate_range(self) -> "SourceLocation":
        if self.end_line is not None and self.end_line < self.line:
            raise ValueError("end_line must be greater than or equal to line")
        if self.end_line == self.line and self.column is not None and self.end_column is not None:
            if self.end_column < self.column:
                raise ValueError("end_column must be greater than or equal to column when the range is on one line")
        return self


class TriggerPoint(RCPatchModel):
    """Normalized location where the bug first becomes observable."""

    location: SourceLocation
    type: TriggerType = Field(description="How the trigger point was identified.")
    failing_operation: Optional[str] = Field(default=None, description="Observed failing operation, such as memcpy or dereference.")
    bug_type_hint: Optional[BugType] = Field(default=None, description="Optional bug-class hint derived from evidence.")
    evidence: list[EvidenceReference] = Field(default_factory=list, description="Evidence supporting this trigger selection.")
    confidence: Optional[ConfidenceScore] = Field(default=None, description="Confidence in the normalized trigger selection.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Extension space for trigger-specific annotations.")

    @model_validator(mode="before")
    @classmethod
    def _coerce_legacy_location_shape(cls, data: Any) -> Any:
        if not isinstance(data, Mapping):
            return data
        if "location" in data:
            return data

        legacy_keys = {"file", "line", "column", "end_line", "end_column", "function", "snippet", "metadata"}
        location_payload = {key: data[key] for key in legacy_keys if key in data}
        if "file" not in location_payload or "line" not in location_payload:
            return data

        normalized = dict(data)
        normalized["location"] = location_payload
        for key in legacy_keys:
            normalized.pop(key, None)
        return normalized

    @field_validator("failing_operation")
    @classmethod
    def _validate_failing_operation(cls, value: Optional[str]) -> Optional[str]:
        return _validate_non_empty_optional(value)


class StackFrame(RCPatchModel):
    """A runtime stack frame extracted from crash or sanitizer evidence."""

    index: int = Field(ge=0, description="0-based frame index, where 0 is the top-most observed frame.")
    function: Optional[str] = Field(default=None, description="Resolved function name.")
    location: Optional[SourceLocation] = Field(default=None, description="Mapped source location if symbolized.")
    module: Optional[str] = Field(default=None, description="Binary or shared library containing the frame.")
    instruction: Optional[str] = Field(default=None, description="Instruction address or symbolized instruction text.")
    is_inlined: bool = Field(default=False, description="Whether the frame is known to be from an inline expansion.")
    notes: Optional[str] = Field(default=None, description="Optional parser notes about ambiguity or symbolization quality.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Extension space for debugger-specific fields.")

    @field_validator("function", "module", "instruction", "notes")
    @classmethod
    def _validate_optional_text(cls, value: Optional[str]) -> Optional[str]:
        return _validate_non_empty_optional(value)

    @model_validator(mode="after")
    def _require_minimal_identity(self) -> "StackFrame":
        if self.function is None and self.location is None and self.module is None and self.instruction is None:
            raise ValueError("a stack frame must include at least one identifying field")
        return self


class RuntimeEvidence(RCPatchModel):
    """Dynamic artifacts and normalized runtime evidence for a bug."""

    sanitizer_report_path: Optional[str] = Field(default=None, description="Path to an ASan, UBSan, or similar report.")
    stack_trace_path: Optional[str] = Field(default=None, description="Path to a stack trace artifact.")
    runtime_log_path: Optional[str] = Field(default=None, description="Path to a runtime log or captured stderr/stdout.")
    core_path: Optional[str] = Field(default=None, description="Path to a core dump or related metadata.")
    execution_trace_path: Optional[str] = Field(default=None, description="Path to an extracted execution trace.")
    poc_path: Optional[str] = Field(default=None, description="Path to the PoC input that reproduces the bug.")
    failure_summary: Optional[str] = Field(default=None, description="Normalized summary of the observed failure.")
    failing_access: Optional[str] = Field(default=None, description="Normalized access category such as read, write, or free.")
    trigger_frame_index: Optional[int] = Field(default=None, ge=0, description="Stack frame index most closely associated with the trigger.")
    stack_frames: list[StackFrame] = Field(default_factory=list, description="Symbolized and normalized stack frames.")
    evidence: list[EvidenceReference] = Field(default_factory=list, description="Evidence references parsed from runtime artifacts.")
    confidence: Optional[ConfidenceScore] = Field(default=None, description="Confidence in runtime evidence normalization.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Extension space for parser-specific runtime fields.")

    @field_validator(
        "sanitizer_report_path",
        "stack_trace_path",
        "runtime_log_path",
        "core_path",
        "execution_trace_path",
        "poc_path",
        "failure_summary",
        "failing_access",
    )
    @classmethod
    def _validate_optional_text(cls, value: Optional[str]) -> Optional[str]:
        return _validate_non_empty_optional(value)

    @model_validator(mode="after")
    def _validate_trigger_frame_index(self) -> "RuntimeEvidence":
        if self.trigger_frame_index is not None and self.stack_frames:
            if self.trigger_frame_index >= len(self.stack_frames):
                raise ValueError("trigger_frame_index is out of range for the provided stack_frames")
        return self


class PatchEvidence(RCPatchModel):
    """Optional patch and issue context used as weak supervision."""

    fix_commit: Optional[str] = Field(default=None, description="Commit identifier for a known fix.")
    diff_path: Optional[str] = Field(default=None, description="Path to a patch diff or exported commit.")
    commit_message: Optional[str] = Field(default=None, description="Commit message text if available.")
    commit_message_path: Optional[str] = Field(default=None, description="Path to a commit message file.")
    issue_text: Optional[str] = Field(default=None, description="Issue or CVE text if available inline.")
    issue_text_path: Optional[str] = Field(default=None, description="Path to issue or CVE text.")
    regression_test_path: Optional[str] = Field(default=None, description="Path to a regression test associated with the fix.")
    patch_intent: Optional[PatchIntent] = Field(default=None, description="Optional semantic interpretation of the patch intent.")
    changed_locations: list[SourceLocation] = Field(default_factory=list, description="Source locations touched by the known patch.")
    llm_judgments: list[LLMJudgment] = Field(default_factory=list, description="Optional semantic judgments attached to the patch.")
    confidence: Optional[ConfidenceScore] = Field(default=None, description="Confidence in patch parsing or intent classification.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Extension space for patch-specific metadata.")

    @field_validator(
        "fix_commit",
        "diff_path",
        "commit_message_path",
        "issue_text",
        "issue_text_path",
        "regression_test_path",
    )
    @classmethod
    def _validate_optional_text(cls, value: Optional[str]) -> Optional[str]:
        return _validate_non_empty_optional(value)

    @field_validator("commit_message")
    @classmethod
    def _normalize_commit_message(cls, value: Optional[str]) -> Optional[str]:
        return _normalize_blank_optional(value)


class RootCauseCandidate(RCPatchModel):
    """Ranked location that may represent symptom, propagation, or root cause."""

    rank: Optional[int] = Field(default=None, ge=1, description="1-based ranking position after candidate scoring.")
    location: SourceLocation
    label: CandidateLabel = Field(description="Classification label for the candidate location.")
    score: float = Field(ge=0.0, le=1.0, description="Normalized ranking score.")
    explanation: str = Field(min_length=1, description="Short explanation of why the location matters.")
    features: dict[str, Any] = Field(default_factory=dict, description="Extracted scoring features and derived attributes.")
    evidence: list[EvidenceReference] = Field(default_factory=list, description="Evidence supporting the candidate.")
    bug_type_hint: Optional[BugType] = Field(default=None, description="Optional bug-type guess attached to the candidate.")
    confidence: Optional[ConfidenceScore] = Field(default=None, description="Confidence in the candidate label and score.")
    llm_judgments: list[LLMJudgment] = Field(default_factory=list, description="Optional semantic judgments about the candidate.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Extension space for ranker-specific metadata.")


class PropagationStep(RCPatchModel):
    """One step in a root-cause-to-trigger causality chain."""

    location: SourceLocation
    relation: PropagationRelation = Field(description="Kind of propagation relation represented by the step.")
    entity: Optional[str] = Field(default=None, description="Variable, object, field, or conceptual state being propagated.")
    explanation: str = Field(min_length=1, description="Concise explanation of the propagation step.")
    evidence: list[EvidenceReference] = Field(default_factory=list, description="Evidence tied to this specific step.")
    confidence: Optional[ConfidenceScore] = Field(default=None, description="Confidence in the propagation step.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Extension space for graph or slice metadata.")

    @field_validator("entity")
    @classmethod
    def _validate_entity(cls, value: Optional[str]) -> Optional[str]:
        return _validate_non_empty_optional(value)


class CausalityChain(RCPatchModel):
    """Ordered propagation chain connecting a candidate root cause to the trigger."""

    rank: Optional[int] = Field(default=None, ge=1, description="1-based ranking position for the chain.")
    root_cause_rank: Optional[int] = Field(
        default=None,
        ge=1,
        description="Rank of the linked root cause candidate if ranking has already been assigned.",
    )
    steps: list[PropagationStep] = Field(default_factory=list, description="Ordered propagation steps from source to trigger.")
    summary: str = Field(min_length=1, description="High-level summary of the entire chain.")
    score: float = Field(ge=0.0, le=1.0, description="Normalized chain ranking score.")
    confidence: Optional[ConfidenceScore] = Field(default=None, description="Confidence in the reconstructed chain.")
    llm_judgments: list[LLMJudgment] = Field(default_factory=list, description="Optional semantic refinement of the chain.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Extension space for path-search metadata.")

    @model_validator(mode="after")
    def _require_steps(self) -> "CausalityChain":
        if not self.steps:
            raise ValueError("a causality chain must contain at least one propagation step")
        return self


class BuildConfig(RCPatchModel):
    """Build instructions and compile database hints for the target repository."""

    build_dir: Optional[str] = Field(default=None, description="Directory where the project is configured or built.")
    build_cmd: Optional[str] = Field(default=None, description="Command used to build the target.")
    compile_commands_path: Optional[str] = Field(default=None, description="Path to compile_commands.json if available.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Extension space for build-system metadata.")

    @field_validator("build_dir", "build_cmd", "compile_commands_path")
    @classmethod
    def _validate_optional_text(cls, value: Optional[str]) -> Optional[str]:
        return _validate_non_empty_optional(value)


class RunConfig(RCPatchModel):
    """Run instructions used to reproduce or analyze the bug."""

    cmd: Optional[str] = Field(default=None, description="Command used to run the buggy target.")
    poc_path: Optional[str] = Field(default=None, description="Path to the proof-of-concept input.")
    env: dict[str, str] = Field(default_factory=dict, description="Environment variables needed for reproduction.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Extension space for runner-specific metadata.")

    @field_validator("cmd", "poc_path")
    @classmethod
    def _validate_optional_text(cls, value: Optional[str]) -> Optional[str]:
        return _validate_non_empty_optional(value)


class AnalysisConfig(RCPatchModel):
    """Configuration that controls RCPatch analysis behavior."""

    enable_patch_analysis: bool = Field(default=True, description="Whether patch-derived weak supervision should be enabled.")
    enable_llm: bool = Field(default=False, description="Whether optional LLM-based semantic refinement is allowed.")
    top_k_candidates: int = Field(default=5, ge=1, description="Maximum number of candidates returned to the user.")
    max_chain_paths: int = Field(default=5, ge=1, description="Maximum number of causality chains returned to the user.")
    parser_backend: ParserBackend = Field(
        default=ParserBackend.TREE_SITTER,
        description="Preferred source-analysis backend for parsing C/C++ code.",
    )
    bug_type_hint: Optional[BugType] = Field(default=None, description="Optional bug-type hint that narrows analysis heuristics.")
    max_backward_depth: int = Field(default=12, ge=1, description="Bound on backward traversal depth during slicing.")
    max_interprocedural_hops: int = Field(default=8, ge=0, description="Bound on interprocedural expansion depth.")
    confidence_threshold: float = Field(
        default=0.15,
        ge=0.0,
        le=1.0,
        description="Minimum confidence threshold used to suppress extremely weak outputs.",
    )
    feature_flags: dict[str, bool] = Field(
        default_factory=dict,
        description="Extension space for experimental toggles without changing the core schema.",
    )
    enable_cve_pattern_prior: bool = Field(
        default=False,
        description="Whether mined historical CVE root-cause patterns should weakly boost candidate ranking.",
    )
    cve_pattern_library_path: Optional[str] = Field(
        default=None,
        description="Path to a mined CVE pattern library JSON file, for example cve_pattern_library.v4.clean.json.",
    )
    cve_pattern_min_support: int = Field(
        default=1,
        ge=1,
        description="Minimum historical support required for a CVE pattern to influence ranking.",
    )
    cve_pattern_min_confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Minimum average historical confidence required for a CVE pattern to influence ranking.",
    )
    cve_pattern_prior_weight: float = Field(
        default=0.12,
        ge=0.0,
        le=0.5,
        description="Maximum additive score contribution from the CVE pattern prior.",
    )
    ranker_calibration_path: Optional[str] = Field(
        default=None,
        description="Optional JSON file with ranker weight/threshold calibration learned from curated cases.",
    )
    enable_project_prior: bool = Field(
        default=False,
        description="Whether project-specific historical priors should weakly influence ranking.",
    )
    project_prior_path: Optional[str] = Field(
        default=None,
        description="Optional JSON file mapping project names to preferred bug patterns or operation types.",
    )
    project_prior_weight: float = Field(
        default=0.08,
        ge=0.0,
        le=0.3,
        description="Maximum additive score contribution from project-specific priors.",
    )
    enable_expert_rca_prior: bool = Field(
        default=False,
        description="Whether expert-curated RCA priors should weakly influence ranking.",
    )
    expert_rca_prior_path: Optional[str] = Field(
        default=None,
        description="Optional JSON file containing expert-curated RCA records, such as Project Zero-style RCAs.",
    )
    expert_rca_prior_min_confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Minimum confidence required for expert RCA records to influence ranking.",
    )
    expert_rca_prior_weight: float = Field(
        default=0.06,
        ge=0.0,
        le=0.25,
        description="Maximum additive score contribution from expert-curated RCA priors.",
    )
    metadata: dict[str, Any] = Field(default_factory=dict, description="Extension space for run-level configuration metadata.")


class BugReport(RCPatchModel):
    """Top-level normalized input describing a buggy program and its evidence."""

    bug_id: str = Field(min_length=1, description="Stable identifier for the bug under analysis.")
    repo_path: str = Field(min_length=1, description="Path to the source repository containing the buggy program.")
    language: Language = Field(default=Language.C_CPP, description="Target source language family.")
    title: Optional[str] = Field(default=None, description="Optional short title for the bug report.")
    summary: Optional[str] = Field(default=None, description="Optional textual summary of the bug.")
    build: Optional[BuildConfig] = Field(default=None, description="Build configuration for the target repository.")
    run: Optional[RunConfig] = Field(default=None, description="Run configuration or reproduction command.")
    trigger_point: TriggerPoint = Field(description="Known trigger point where the bug becomes observable.")
    runtime_evidence: Optional[RuntimeEvidence] = Field(default=None, description="Optional parsed runtime evidence bundle.")
    patch_evidence: Optional[PatchEvidence] = Field(default=None, description="Optional patch and issue evidence bundle.")
    analysis_config: AnalysisConfig = Field(
        default_factory=AnalysisConfig,
        alias="config",
        description="Analysis-time configuration controlling RCPatch behavior.",
    )
    issue_text: Optional[str] = Field(default=None, description="Optional inline issue or CVE text.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Extension space for ingestion or provenance metadata.")

    @field_validator("title", "summary", "issue_text")
    @classmethod
    def _validate_optional_text(cls, value: Optional[str]) -> Optional[str]:
        return _validate_non_empty_optional(value)


class AnalysisResult(RCPatchModel):
    """Top-level structured output of a RCPatch analysis run."""

    bug_id: str = Field(min_length=1, description="Stable identifier for the bug under analysis.")
    trigger_point: TriggerPoint
    root_cause_candidates: list[RootCauseCandidate] = Field(
        default_factory=list,
        description="Ranked root cause, propagation, or symptom candidates.",
    )
    chains: list[CausalityChain] = Field(default_factory=list, description="Ranked causality chains tied to the trigger point.")
    analysis_config: Optional[AnalysisConfig] = Field(
        default=None,
        alias="config",
        description="Configuration used when producing this result.",
    )
    runtime_evidence: Optional[RuntimeEvidence] = Field(default=None, description="Runtime evidence used during the run.")
    patch_evidence: Optional[PatchEvidence] = Field(default=None, description="Patch evidence used during the run.")
    summary: Optional[str] = Field(default=None, description="Human-readable summary of the most likely explanation.")
    limitations: list[str] = Field(default_factory=list, description="Explicit limitations or approximation notes.")
    llm_judgments: list[LLMJudgment] = Field(default_factory=list, description="Optional run-level LLM judgments.")
    confidence: Optional[ConfidenceScore] = Field(default=None, description="Overall confidence for the analysis result.")
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when the result object was generated.",
    )
    metadata: dict[str, Any] = Field(default_factory=dict, description="Extension space for exporter or pipeline metadata.")

    @field_validator("summary")
    @classmethod
    def _validate_summary(cls, value: Optional[str]) -> Optional[str]:
        return _validate_non_empty_optional(value)

    @model_validator(mode="after")
    def _validate_rank_consistency(self) -> "AnalysisResult":
        candidate_ranks = [candidate.rank for candidate in self.root_cause_candidates if candidate.rank is not None]
        if len(candidate_ranks) != len(set(candidate_ranks)):
            raise ValueError("root_cause_candidates contains duplicate rank values")

        chain_ranks = [chain.rank for chain in self.chains if chain.rank is not None]
        if len(chain_ranks) != len(set(chain_ranks)):
            raise ValueError("chains contains duplicate rank values")

        known_candidate_ranks = set(candidate_ranks)
        for chain in self.chains:
            if chain.root_cause_rank is not None and known_candidate_ranks and chain.root_cause_rank not in known_candidate_ranks:
                raise ValueError(
                    "chain root_cause_rank must reference a rank present in root_cause_candidates when candidate ranks exist"
                )
        return self


SourceLocation.model_config["json_schema_extra"] = {
    "example": {
        "file": "src/parser.c",
        "line": 145,
        "column": 9,
        "function": "parse_header",
        "snippet": "len = read_u16(input);",
    }
}

TriggerPoint.model_config["json_schema_extra"] = {
    "example": {
        "location": {
            "file": "src/foo.c",
            "line": 312,
            "column": 9,
            "function": "process_input",
        },
        "type": "asan_report",
        "failing_operation": "memcpy",
        "bug_type_hint": "buffer_overflow",
    }
}

StackFrame.model_config["json_schema_extra"] = {
    "example": {
        "index": 0,
        "function": "process_input",
        "location": {
            "file": "src/foo.c",
            "line": 312,
            "column": 9,
            "function": "process_input",
        },
        "module": "target_program",
    }
}

RuntimeEvidence.model_config["json_schema_extra"] = {
    "example": {
        "sanitizer_report_path": "/tmp/asan.txt",
        "stack_trace_path": "/tmp/stack.txt",
        "poc_path": "/tmp/poc.bin",
        "failure_summary": "heap-buffer-overflow in memcpy",
        "failing_access": "write",
        "trigger_frame_index": 0,
        "stack_frames": [
            {
                "index": 0,
                "function": "process_input",
                "location": {
                    "file": "src/foo.c",
                    "line": 312,
                    "column": 9,
                    "function": "process_input",
                },
            }
        ],
    }
}

PatchEvidence.model_config["json_schema_extra"] = {
    "example": {
        "fix_commit": "abc123",
        "diff_path": "/tmp/fix.diff",
        "issue_text_path": "/tmp/issue.txt",
        "patch_intent": "direct_fix",
        "changed_locations": [
            {
                "file": "src/parser.c",
                "line": 145,
                "function": "parse_header",
            }
        ],
    }
}

RootCauseCandidate.model_config["json_schema_extra"] = {
    "example": {
        "rank": 1,
        "location": {
            "file": "src/parser.c",
            "line": 145,
            "function": "parse_header",
        },
        "label": "root_cause_candidate",
        "score": 0.91,
        "explanation": "This statement computes a length field later used as a memcpy size.",
        "features": {
            "defines_tainted_size": True,
            "distance_to_trigger": 6,
            "matched_bug_pattern": "incorrect_length_computation",
        },
    }
}

PropagationStep.model_config["json_schema_extra"] = {
    "example": {
        "location": {
            "file": "src/core.c",
            "line": 218,
            "function": "handle_msg",
        },
        "relation": "call_argument",
        "entity": "len",
        "explanation": "The faulty length is passed into the downstream handler.",
    }
}

CausalityChain.model_config["json_schema_extra"] = {
    "example": {
        "rank": 1,
        "root_cause_rank": 1,
        "score": 0.88,
        "steps": [
            {
                "location": {
                    "file": "src/parser.c",
                    "line": 145,
                    "function": "parse_header",
                },
                "relation": "state_update",
                "entity": "len",
                "explanation": "An incorrect length is computed from unvalidated input.",
            },
            {
                "location": {
                    "file": "src/foo.c",
                    "line": 312,
                    "function": "process_input",
                },
                "relation": "data_flow",
                "entity": "memcpy_size",
                "explanation": "The same length is used as memcpy size at the trigger point.",
            },
        ],
        "summary": "Incorrect length computation reaches memcpy and causes overflow.",
    }
}

BugReport.model_config["json_schema_extra"] = {
    "example": {
        "bug_id": "example_bug_001",
        "repo_path": "/path/to/repo",
        "language": "c_cpp",
        "build": {
            "build_dir": "/path/to/build",
            "build_cmd": "cmake .. && make -j",
        },
        "run": {
            "cmd": "./target_program poc_input",
            "poc_path": "/path/to/poc",
        },
        "trigger_point": {
            "location": {
                "file": "src/foo.c",
                "function": "process_input",
                "line": 312,
                "column": 9,
            },
            "type": "asan_report",
            "failing_operation": "memcpy",
        },
        "runtime_evidence": {
            "sanitizer_report_path": "/path/to/asan.txt",
            "stack_trace_path": "/path/to/stack.txt",
        },
        "patch_evidence": {
            "fix_commit": "abc123",
            "diff_path": "/path/to/fix.diff",
            "issue_text_path": "/path/to/issue.txt",
        },
        "config": {
            "enable_patch_analysis": True,
            "enable_llm": True,
            "top_k_candidates": 5,
            "max_chain_paths": 5,
        },
    }
}

AnalysisResult.model_config["json_schema_extra"] = {
    "example": {
        "bug_id": "example_bug_001",
        "trigger_point": {
            "location": {
                "file": "src/foo.c",
                "function": "process_input",
                "line": 312,
            },
            "type": "asan_report",
        },
        "root_cause_candidates": [
            {
                "rank": 1,
                "location": {
                    "file": "src/parser.c",
                    "function": "parse_header",
                    "line": 145,
                },
                "label": "root_cause_candidate",
                "score": 0.91,
                "explanation": "This statement computes a length field later used by memcpy size at the trigger point.",
                "features": {
                    "defines_tainted_size": True,
                    "affects_control": False,
                    "distance_to_trigger": 6,
                    "matched_bug_pattern": "incorrect_length_computation",
                    "supported_by_patch": True,
                },
            }
        ],
        "chains": [
            {
                "rank": 1,
                "root_cause_rank": 1,
                "score": 0.89,
                "steps": [
                    {
                        "location": {
                            "file": "src/parser.c",
                            "function": "parse_header",
                            "line": 145,
                        },
                        "relation": "state_update",
                        "entity": "len",
                        "explanation": "An incorrect length is computed from unvalidated input.",
                    },
                    {
                        "location": {
                            "file": "src/foo.c",
                            "function": "process_input",
                            "line": 312,
                        },
                        "relation": "data_flow",
                        "entity": "memcpy_size",
                        "explanation": "The same length is used as memcpy size, causing overflow.",
                    },
                ],
                "summary": "Incorrect length computation in parse_header reaches the memcpy size at the trigger point.",
            }
        ],
        "limitations": [
            "Interprocedural alias tracking is approximate.",
        ],
    }
}

for _model in (
    SourceLocation,
    TriggerPoint,
    StackFrame,
    RuntimeEvidence,
    PatchEvidence,
    RootCauseCandidate,
    PropagationStep,
    CausalityChain,
    BugReport,
    AnalysisResult,
):
    _model.model_rebuild(force=True)
