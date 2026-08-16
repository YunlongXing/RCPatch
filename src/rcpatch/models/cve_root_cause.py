"""CVE-oriented root-cause mining models."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import Field

from rcpatch.models.base import RCPatchModel
from rcpatch.models.core import RootCauseCandidate, SourceLocation
from rcpatch.models.slice_ir import BackwardSlice


class CVEPatchAnchor(RCPatchModel):
    """A pre-patch source anchor derived from a fixing patch hunk."""

    anchor_id: str = Field(min_length=1)
    location: SourceLocation
    file: str = Field(min_length=1)
    anchor_kind: str = Field(min_length=1)
    hunk_index: int = Field(ge=0)
    statement_id: Optional[str] = None
    function_id: Optional[str] = None
    changed_function: Optional[str] = None
    anchor_text: Optional[str] = None
    before: str = ""
    after: str = ""
    removed_statements: list[str] = Field(default_factory=list)
    added_statements: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CVERootCauseMiningResult(RCPatchModel):
    """Candidate root-cause mining output for a single CVE."""

    cve_id: str = Field(min_length=1)
    repo_path: str = Field(min_length=1)
    anchors: list[CVEPatchAnchor] = Field(default_factory=list)
    slices: list[BackwardSlice] = Field(default_factory=list)
    candidates: list[RootCauseCandidate] = Field(default_factory=list)
    diagnostics: list[str] = Field(default_factory=list)
    approximations: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
