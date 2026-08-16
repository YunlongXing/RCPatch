"""Dataset-oriented models for curated CVE root-cause annotations."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import Field

from rcpatch.models.base import RCPatchModel
from rcpatch.models.core import SourceLocation
from rcpatch.models.enums import CandidateLabel


class CVERootCauseAnnotation(RCPatchModel):
    """One curated root-cause annotation derived from a historical CVE."""

    rank: Optional[int] = Field(default=None, ge=1)
    location: SourceLocation
    code_snippet: str = Field(min_length=1)
    type: str = Field(min_length=1)
    classification: CandidateLabel
    pattern: Optional[str] = None
    explanation: str = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    patch_relation: str = Field(min_length=1)
    candidate_rank: Optional[int] = Field(default=None, ge=1)
    candidate_origin: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CVERootCauseDatasetRecord(RCPatchModel):
    """Dataset record for one CVE after high-confidence filtering."""

    cve_id: str = Field(min_length=1)
    project: Optional[str] = None
    repo_url: Optional[str] = None
    root_causes: list[CVERootCauseAnnotation] = Field(default_factory=list)
    diagnostics: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CVERootCauseDataset(RCPatchModel):
    """A curated dataset bundle of CVE-to-root-cause mappings."""

    records: list[CVERootCauseDatasetRecord] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
