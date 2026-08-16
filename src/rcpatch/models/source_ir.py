"""Source parsing models and parser-agnostic program abstraction IR."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import Field, field_validator, model_validator

from rcpatch.models.base import RCPatchModel
from rcpatch.models.core import ConfidenceScore, SourceLocation
from rcpatch.models.enums import DiagnosticLevel, Language, MemoryOperationKind, ParserBackend, StatementKind


def _clean_optional_text(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    stripped = value.strip()
    if not stripped:
        raise ValueError("value must not be empty when provided")
    return stripped


class ParseDiagnostic(RCPatchModel):
    """Diagnostic emitted during source scanning or parsing."""

    level: DiagnosticLevel = Field(description="Diagnostic severity.")
    backend: ParserBackend = Field(description="Backend that emitted the diagnostic.")
    message: str = Field(min_length=1, description="Diagnostic message.")
    file: Optional[str] = Field(default=None, description="Repository-relative file path if applicable.")
    line: Optional[int] = Field(default=None, ge=1, description="1-based line number if applicable.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Extension space for parser-specific context.")


class SourceParameter(RCPatchModel):
    """Function parameter approximation extracted from a signature."""

    position: int = Field(ge=0, description="0-based parameter position.")
    name: Optional[str] = Field(default=None, description="Parameter name when one could be identified.")
    raw_declaration: str = Field(min_length=1, description="Original parameter declaration text.")
    type_hint: Optional[str] = Field(default=None, description="Approximate type text for the parameter.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Extension space for parser-specific details.")

    @field_validator("name", "type_hint")
    @classmethod
    def _normalize_optional_text(cls, value: Optional[str]) -> Optional[str]:
        return _clean_optional_text(value)


class MemoryOperation(RCPatchModel):
    """Memory-related operation found in source code."""

    kind: MemoryOperationKind = Field(description="Category of memory-related operation.")
    function_name: str = Field(min_length=1, description="Function or operator name, such as malloc or free.")
    location: SourceLocation
    target: Optional[str] = Field(default=None, description="Best-effort target variable or object.")
    size_expression: Optional[str] = Field(default=None, description="Best-effort size expression if one was found.")
    confidence: Optional[ConfidenceScore] = Field(default=None, description="Confidence in the operation classification.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Extension space for extra parser data.")

    @field_validator("target", "size_expression")
    @classmethod
    def _normalize_optional_text(cls, value: Optional[str]) -> Optional[str]:
        return _clean_optional_text(value)


class StatementInfo(RCPatchModel):
    """Approximate statement abstraction used by later analysis passes."""

    statement_id: str = Field(min_length=1, description="Stable identifier for the statement within the parsed program.")
    location: SourceLocation
    text: str = Field(min_length=1, description="Best-effort statement text.")
    statement_types: list[StatementKind] = Field(default_factory=list, description="Detected categories for the statement.")
    defined_variables: list[str] = Field(default_factory=list, description="Variables defined or updated by the statement.")
    referenced_variables: list[str] = Field(default_factory=list, description="Variables referenced by the statement.")
    call_names: list[str] = Field(default_factory=list, description="Function or method names called from the statement.")
    memory_operations: list[MemoryOperation] = Field(default_factory=list, description="Memory-related operations observed in the statement.")
    condition_expression: Optional[str] = Field(default=None, description="Condition text if the statement is a control predicate.")
    return_expression: Optional[str] = Field(default=None, description="Returned expression text if this is a return statement.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Extension space for statement-level attributes.")

    @field_validator("condition_expression", "return_expression")
    @classmethod
    def _normalize_optional_text(cls, value: Optional[str]) -> Optional[str]:
        return _clean_optional_text(value)


class CallSite(RCPatchModel):
    """A function call observed inside a function body."""

    caller_function_id: str = Field(min_length=1, description="Stable identifier of the caller function.")
    caller_name: str = Field(min_length=1, description="Caller function name.")
    callee_name: str = Field(min_length=1, description="Callee function or method name.")
    location: SourceLocation
    argument_expressions: list[str] = Field(default_factory=list, description="Best-effort argument text list.")
    resolved_target: Optional[str] = Field(default=None, description="Resolved function id when the callee matches a known in-repo function.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Extension space for call-site level details.")

    @property
    def is_resolved(self) -> bool:
        """Whether the call site resolved to a known in-repo target."""
        return self.resolved_target is not None

    @field_validator("resolved_target")
    @classmethod
    def _normalize_optional_text(cls, value: Optional[str]) -> Optional[str]:
        return _clean_optional_text(value)


class FunctionDefinition(RCPatchModel):
    """Parser-agnostic function abstraction."""

    function_id: str = Field(min_length=1, description="Stable function identifier, typically path:name:start_line.")
    name: str = Field(min_length=1, description="Function or method name.")
    qualified_name: Optional[str] = Field(default=None, description="Qualified name when available.")
    location: SourceLocation
    end_line: int = Field(ge=1, description="Best-effort end line for the function body.")
    return_type: Optional[str] = Field(default=None, description="Approximate return type or constructor marker.")
    parameters: list[SourceParameter] = Field(default_factory=list, description="Approximate parameter list.")
    statements: list[StatementInfo] = Field(default_factory=list, description="Lightweight statement abstractions from the function body.")
    call_sites: list[CallSite] = Field(default_factory=list, description="Function calls observed in the body.")
    memory_operations: list[MemoryOperation] = Field(default_factory=list, description="Memory-related operations observed in the body.")
    local_variables: list[str] = Field(default_factory=list, description="Approximate set of local variables mentioned in the function.")
    approximations: list[str] = Field(default_factory=list, description="Explicit notes about heuristic extraction quality.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Extension space for backend-specific context.")

    @field_validator("qualified_name", "return_type")
    @classmethod
    def _normalize_optional_text_fields(cls, value: Optional[str]) -> Optional[str]:
        return _clean_optional_text(value)

    @model_validator(mode="after")
    def _validate_location_range(self) -> "FunctionDefinition":
        if self.end_line < self.location.line:
            raise ValueError("function end_line must be greater than or equal to the start line")
        return self


class SourceFile(RCPatchModel):
    """Source file abstraction consumed by later analyses."""

    path: str = Field(min_length=1, description="Repository-relative source file path.")
    language: Language = Field(description="Detected source language for the file.")
    includes: list[str] = Field(default_factory=list, description="Header includes referenced by the file.")
    functions: list[FunctionDefinition] = Field(default_factory=list, description="Functions found in the file.")
    diagnostics: list[ParseDiagnostic] = Field(default_factory=list, description="Per-file diagnostics from the parser backend.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Extension space for backend-specific file metadata.")


class CallRelationship(RCPatchModel):
    """Approximate call-graph edge between two functions."""

    caller_function_id: str = Field(min_length=1, description="Stable identifier of the caller function.")
    caller_name: str = Field(min_length=1, description="Caller function name.")
    callee_name: str = Field(min_length=1, description="Callee function name.")
    location: SourceLocation
    resolved_target: Optional[str] = Field(default=None, description="Resolved callee function id when known.")
    confidence: Optional[ConfidenceScore] = Field(default=None, description="Confidence in the call relationship.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Extension space for relationship annotations.")

    @property
    def is_resolved(self) -> bool:
        """Whether the call relationship resolves to a known in-repo target."""
        return self.resolved_target is not None

    @field_validator("resolved_target")
    @classmethod
    def _normalize_optional_text(cls, value: Optional[str]) -> Optional[str]:
        return _clean_optional_text(value)


class ProgramAbstraction(RCPatchModel):
    """Parser-independent source abstraction for an analyzed repository."""

    repo_path: str = Field(min_length=1, description="Absolute repository path used to build the abstraction.")
    backend: ParserBackend = Field(description="Parser backend used to build this abstraction.")
    files: list[SourceFile] = Field(default_factory=list, description="Parsed source files.")
    functions: list[FunctionDefinition] = Field(default_factory=list, description="Flattened list of parsed functions.")
    call_relationships: list[CallRelationship] = Field(default_factory=list, description="Approximate call relationships.")
    diagnostics: list[ParseDiagnostic] = Field(default_factory=list, description="Repository-wide parser diagnostics.")
    approximations: list[str] = Field(default_factory=list, description="Repository-wide approximation notes.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Extension space for indexing and backend metadata.")

    @model_validator(mode="after")
    def _validate_unique_function_ids(self) -> "ProgramAbstraction":
        function_ids = [function.function_id for function in self.functions]
        if len(function_ids) != len(set(function_ids)):
            raise ValueError("ProgramAbstraction contains duplicate function ids")
        return self
