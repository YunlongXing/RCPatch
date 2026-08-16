"""Semantic-alignment models for CVE candidate interpretation."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import Field

from rcpatch.models.base import RCPatchModel
from rcpatch.models.core import LLMJudgment, SourceLocation
from rcpatch.models.enums import CandidateLabel


class CVECandidateSemanticAlignment(RCPatchModel):
    """LLM-based semantic interpretation of one existing CVE candidate."""

    candidate_rank: Optional[int] = Field(default=None, ge=1)
    location: SourceLocation
    heuristic_label: CandidateLabel
    label: CandidateLabel
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str = Field(min_length=1)
    candidate_origin: Optional[str] = None
    llm_judgment: Optional[LLMJudgment] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CVESemanticAlignmentResult(RCPatchModel):
    """Semantic-alignment output for a mined CVE candidate set."""

    cve_id: str = Field(min_length=1)
    alignments: list[CVECandidateSemanticAlignment] = Field(default_factory=list)
    diagnostics: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
