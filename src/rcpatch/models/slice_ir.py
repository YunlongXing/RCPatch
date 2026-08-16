"""Backward-slice IR for trigger-guided analysis."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import Field, field_validator, model_validator

from rcpatch.models.base import RCPatchModel
from rcpatch.models.core import ConfidenceScore, SourceLocation, TriggerPoint
from rcpatch.models.enums import DependencyRelation, StatementKind


def _normalize_optional_text(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    stripped = value.strip()
    if not stripped:
        raise ValueError("value must not be empty when provided")
    return stripped


class SliceNode(RCPatchModel):
    """Statement-level node in a backward slice graph."""

    node_id: str = Field(min_length=1, description="Stable slice node identifier.")
    statement_id: str = Field(min_length=1, description="Identifier of the underlying statement.")
    function_id: str = Field(min_length=1, description="Stable identifier of the enclosing function.")
    function_name: str = Field(min_length=1, description="Short name of the enclosing function.")
    location: SourceLocation
    text: str = Field(min_length=1, description="Statement text.")
    statement_types: list[StatementKind] = Field(default_factory=list, description="Categories attached to the statement.")
    tracked_entities: list[str] = Field(default_factory=list, description="Variables, objects, or expressions that make the node relevant.")
    is_trigger: bool = Field(default=False, description="Whether this node is the normalized trigger statement.")
    confidence: Optional[ConfidenceScore] = Field(default=None, description="Confidence attached to the node.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Extension space for slice-specific annotations.")


class DependencyEdge(RCPatchModel):
    """Directed dependency edge between slice nodes."""

    source_node_id: str = Field(min_length=1, description="Upstream source node id.")
    target_node_id: str = Field(min_length=1, description="Downstream target node id.")
    relation: DependencyRelation = Field(description="Kind of dependency or propagation relation.")
    entity: Optional[str] = Field(default=None, description="Entity responsible for the dependency when one is known.")
    explanation: Optional[str] = Field(default=None, description="Short explanation of why the edge exists.")
    approximated: bool = Field(default=True, description="Whether the edge was recovered heuristically.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Extension space for edge-specific metadata.")

    @field_validator("entity", "explanation")
    @classmethod
    def _clean_text(cls, value: Optional[str]) -> Optional[str]:
        return _normalize_optional_text(value)


class BackwardSlice(RCPatchModel):
    """Structured backward slice rooted at a trigger point."""

    trigger: TriggerPoint
    trigger_node_id: Optional[str] = Field(default=None, description="Slice node id corresponding to the trigger statement.")
    nodes: list[SliceNode] = Field(default_factory=list, description="Candidate statements connected to the trigger.")
    edges: list[DependencyEdge] = Field(default_factory=list, description="Dependency edges between candidate statements.")
    approximations: list[str] = Field(default_factory=list, description="Explicit notes about approximation quality.")
    diagnostics: list[str] = Field(default_factory=list, description="Slice-time diagnostics and fallback notes.")
    confidence: Optional[ConfidenceScore] = Field(default=None, description="Overall confidence in the extracted slice.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Extension space for slicer-specific metadata.")

    @model_validator(mode="after")
    def _validate_trigger_node(self) -> "BackwardSlice":
        if self.trigger_node_id is None:
            return self
        node_ids = {node.node_id for node in self.nodes}
        if self.trigger_node_id not in node_ids:
            raise ValueError("trigger_node_id must reference a node present in nodes")
        return self
