"""Patch-aware analysis exports."""

from rcpatch.patch_analysis.analyzer import PatchAwareAnalyzer
from rcpatch.patch_analysis.classifier import PatchIntentClassifier
from rcpatch.patch_analysis.models import (
    MappedPatchLocation,
    ParsedPatch,
    PatchAwareAnalysisResult,
    PatchHunk,
    PatchLine,
    PatchedFile,
)
from rcpatch.patch_analysis.parser import UnifiedDiffParser

__all__ = [
    "MappedPatchLocation",
    "ParsedPatch",
    "PatchAwareAnalysisResult",
    "PatchAwareAnalyzer",
    "PatchHunk",
    "PatchIntentClassifier",
    "PatchLine",
    "PatchedFile",
    "UnifiedDiffParser",
]
