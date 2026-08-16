"""Protocol-style interfaces for major RCPatch pipeline stages."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Optional, Protocol

from rcpatch.models import (
    BackwardSlice,
    BugReport,
    CausalityChain,
    LLMJudgment,
    PatchEvidence,
    PatchIntent,
    ProgramAbstraction,
    RootCauseCandidate,
    TriggerPoint,
)
from rcpatch.patch_analysis import PatchAwareAnalysisResult
from rcpatch.source import ProgramIndex


class BugSpecLoader(Protocol):
    """Interface for loading and normalizing bug specifications."""

    def load_from_file(self, spec_path: str | Path) -> BugReport:
        """Load a bug report from a JSON file."""

    def load_from_dict(
        self,
        payload: Mapping[str, Any],
        *,
        spec_path: Optional[str | Path] = None,
    ) -> BugReport:
        """Load a bug report from an already-parsed mapping."""


class RepositoryParser(Protocol):
    """Interface for source parsing and index construction."""

    def parse_repository(
        self,
        repo_root: str | Path,
        *,
        preferred_backend: Any,
        source_files: Optional[list[str]] = None,
    ) -> ProgramAbstraction:
        """Build a parser-agnostic program abstraction for a repository."""

    def build_index(self, program: ProgramAbstraction) -> ProgramIndex:
        """Construct a queryable index from a program abstraction."""


class SliceExtractor(Protocol):
    """Interface for trigger-guided backward slicing."""

    def slice_from_trigger(self, program_index: ProgramIndex, trigger: TriggerPoint) -> BackwardSlice:
        """Return a backward slice rooted at the normalized trigger."""


class CandidateRanker(Protocol):
    """Interface for candidate extraction and ranking."""

    def extract_candidates(
        self,
        bug_report: BugReport,
        backward_slice: BackwardSlice,
        *,
        top_k: Optional[int] = None,
    ) -> list[RootCauseCandidate]:
        """Return ranked root-cause candidates."""


class ChainBuilder(Protocol):
    """Interface for causality-chain construction."""

    def construct_chains(
        self,
        bug_report: BugReport,
        candidates: list[RootCauseCandidate],
        backward_slice: BackwardSlice,
        *,
        max_chains: Optional[int] = None,
    ) -> list[CausalityChain]:
        """Return ranked causality chains."""


class PatchRefiner(Protocol):
    """Interface for optional patch-aware refinement."""

    def analyze(
        self,
        bug_report: BugReport,
        *,
        program_index: Optional[ProgramIndex] = None,
        candidates: tuple[RootCauseCandidate, ...] | list[RootCauseCandidate] = (),
        chains: tuple[CausalityChain, ...] | list[CausalityChain] = (),
    ) -> PatchAwareAnalysisResult:
        """Return patch-aware candidate and chain refinements."""


class SemanticInterpreter(Protocol):
    """Interface for optional LLM-assisted semantic interpretation."""

    def disambiguate_candidate_label(
        self,
        *,
        trigger_point: TriggerPoint,
        candidate: RootCauseCandidate,
        candidate_source_code: str,
        surrounding_function_code: str,
        dependency_summary: str,
        patch_diff: Optional[str] = None,
        heuristic_label: Optional[Any] = None,
    ) -> LLMJudgment:
        """Interpret whether a candidate is a root cause, propagation, or symptom."""

    def infer_patch_intent(
        self,
        *,
        patch_evidence: PatchEvidence,
        diff_text: str,
        commit_message: Optional[str] = None,
        issue_description: Optional[str] = None,
        heuristic_intent: Optional[PatchIntent] = None,
    ) -> LLMJudgment:
        """Interpret patch intent using already extracted evidence."""
