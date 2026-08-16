"""Utilities for exporting JSON schemas for RCPatch data models."""

from __future__ import annotations

import json
from typing import Any

from rcpatch.models.core import (
    AnalysisConfig,
    AnalysisResult,
    BugReport,
    CausalityChain,
    PatchEvidence,
    PropagationStep,
    RootCauseCandidate,
    RuntimeEvidence,
    SourceLocation,
    StackFrame,
    TriggerPoint,
)
from rcpatch.models.cve import CVECollectionResult, CollectedCVERecord, AdvisoryReference, CVEAffectedVersion
from rcpatch.models.cve_dataset import CVERootCauseAnnotation, CVERootCauseDataset, CVERootCauseDatasetRecord
from rcpatch.models.cve_patterns import (
    RootCausePattern,
    RootCausePatternExample,
    RootCausePatternGraph,
    RootCausePatternLibrary,
    RootCausePatternRule,
    RootCausePatternTemplate,
)
from rcpatch.models.cve_patch import CVEPatchExtraction, FixCommitCandidate, StructuredPatchFile, StructuredPatchHunk
from rcpatch.models.cve_root_cause import CVEPatchAnchor, CVERootCauseMiningResult
from rcpatch.models.cve_semantic import CVECandidateSemanticAlignment, CVESemanticAlignmentResult
from rcpatch.models.source_ir import ProgramAbstraction, SourceFile, FunctionDefinition, StatementInfo
from rcpatch.models.slice_ir import BackwardSlice, DependencyEdge, SliceNode

MODEL_REGISTRY = {
    "SourceLocation": SourceLocation,
    "TriggerPoint": TriggerPoint,
    "StackFrame": StackFrame,
    "RuntimeEvidence": RuntimeEvidence,
    "PatchEvidence": PatchEvidence,
    "RootCauseCandidate": RootCauseCandidate,
    "PropagationStep": PropagationStep,
    "CausalityChain": CausalityChain,
    "AnalysisConfig": AnalysisConfig,
    "BugReport": BugReport,
    "AnalysisResult": AnalysisResult,
    "SourceFile": SourceFile,
    "FunctionDefinition": FunctionDefinition,
    "StatementInfo": StatementInfo,
    "ProgramAbstraction": ProgramAbstraction,
    "SliceNode": SliceNode,
    "DependencyEdge": DependencyEdge,
    "BackwardSlice": BackwardSlice,
    "CVEAffectedVersion": CVEAffectedVersion,
    "AdvisoryReference": AdvisoryReference,
    "CollectedCVERecord": CollectedCVERecord,
    "CVECollectionResult": CVECollectionResult,
    "CVERootCauseAnnotation": CVERootCauseAnnotation,
    "CVERootCauseDataset": CVERootCauseDataset,
    "CVERootCauseDatasetRecord": CVERootCauseDatasetRecord,
    "FixCommitCandidate": FixCommitCandidate,
    "RootCausePatternTemplate": RootCausePatternTemplate,
    "RootCausePatternGraph": RootCausePatternGraph,
    "RootCausePatternRule": RootCausePatternRule,
    "RootCausePatternExample": RootCausePatternExample,
    "RootCausePattern": RootCausePattern,
    "RootCausePatternLibrary": RootCausePatternLibrary,
    "StructuredPatchHunk": StructuredPatchHunk,
    "StructuredPatchFile": StructuredPatchFile,
    "CVEPatchExtraction": CVEPatchExtraction,
    "CVEPatchAnchor": CVEPatchAnchor,
    "CVERootCauseMiningResult": CVERootCauseMiningResult,
    "CVECandidateSemanticAlignment": CVECandidateSemanticAlignment,
    "CVESemanticAlignmentResult": CVESemanticAlignmentResult,
}


def generate_schema_bundle() -> dict[str, Any]:
    """Return JSON Schema documents for the main RCPatch models."""
    return {name: model.json_schema() for name, model in MODEL_REGISTRY.items()}


def schema_bundle_json(indent: int = 2) -> str:
    """Serialize the schema bundle as JSON."""
    return json.dumps(generate_schema_bundle(), indent=indent, sort_keys=True)


if __name__ == "__main__":
    print(schema_bundle_json())
