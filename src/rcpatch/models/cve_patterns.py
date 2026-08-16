"""Pattern-mining models for reusable CVE root-cause templates."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import Field

from rcpatch.models.base import RCPatchModel
from rcpatch.models.core import SourceLocation


class RootCausePatternTemplate(RCPatchModel):
    """An abstract code template extracted from one or more root causes."""

    template: str = Field(min_length=1)
    support_count: int = Field(ge=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RootCausePatternGraph(RCPatchModel):
    """An abstract graph/data-flow signature for a root-cause pattern."""

    signature: str = Field(min_length=1)
    entry_relations: list[str] = Field(default_factory=list)
    path_relations: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RootCausePatternRule(RCPatchModel):
    """A reusable feature rule derived from a pattern cluster."""

    feature: str = Field(min_length=1)
    operator: str = Field(default="equals", min_length=1)
    value: str = Field(min_length=1)
    support: float = Field(ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RootCausePatternExample(RCPatchModel):
    """One supporting example for a mined root-cause pattern."""

    cve_id: str = Field(min_length=1)
    location: SourceLocation
    code_snippet: str = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    abstract_template: str = Field(min_length=1)
    patch_relation: str = Field(min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RootCausePattern(RCPatchModel):
    """A reusable root-cause pattern mined from historical CVEs."""

    pattern_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    category: str = Field(min_length=1)
    operation_type: str = Field(min_length=1)
    support_count: int = Field(ge=1)
    cve_ids: list[str] = Field(default_factory=list)
    templates: list[RootCausePatternTemplate] = Field(default_factory=list)
    graph_pattern: RootCausePatternGraph
    feature_rules: list[RootCausePatternRule] = Field(default_factory=list)
    examples: list[RootCausePatternExample] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RootCausePatternLibrary(RCPatchModel):
    """Library of reusable root-cause patterns."""

    patterns: list[RootCausePattern] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
