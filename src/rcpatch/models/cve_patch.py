"""Structured patch models used by CVE-to-fix mapping."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import Field, field_validator

from rcpatch.models.base import RCPatchModel
from rcpatch.models.enums import CVEPatchType, PatchIntent


class FixCommitCandidate(RCPatchModel):
    """A fix-commit candidate inferred from references or repository search."""

    commit_sha: str
    commit_url: Optional[str] = None
    summary: Optional[str] = None
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    matched_by: list[str] = Field(default_factory=list)
    evidence_urls: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class StructuredPatchHunk(RCPatchModel):
    """A normalized diff hunk with both old-side and new-side code preserved."""

    hunk_index: int = Field(ge=0)
    old_start: int = Field(ge=0)
    old_count: int = Field(ge=0)
    new_start: int = Field(ge=0)
    new_count: int = Field(ge=0)
    header: str = ""
    function: Optional[str] = None
    before: str = ""
    after: str = ""
    added_statements: list[str] = Field(default_factory=list)
    removed_statements: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class StructuredPatchFile(RCPatchModel):
    """A file-level structured patch representation."""

    file: str
    old_path: Optional[str] = None
    new_path: Optional[str] = None
    changed_functions: list[str] = Field(default_factory=list)
    before: str = ""
    after: str = ""
    hunks: list[StructuredPatchHunk] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CVEPatchExtraction(RCPatchModel):
    """Structured patch output for a single CVE record."""

    cve_id: str
    repo_url: Optional[str] = None
    repo_path: Optional[str] = None
    resolved_fix_commit: Optional[FixCommitCandidate] = None
    fix_commit_candidates: list[FixCommitCandidate] = Field(default_factory=list)
    patch_type: CVEPatchType = CVEPatchType.UNKNOWN
    patch_intent: Optional[PatchIntent] = None
    modified_files: list[str] = Field(default_factory=list)
    patches: list[StructuredPatchFile] = Field(default_factory=list)
    commit_message: Optional[str] = None
    diagnostics: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("commit_message")
    @classmethod
    def _normalize_commit_message(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        if not value.strip():
            return None
        return value
