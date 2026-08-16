"""Internal models for patch-aware analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Optional

from rcpatch.models import CausalityChain, PatchEvidence, RootCauseCandidate, SourceLocation

PatchLineKind = Literal["context", "add", "del"]


@dataclass(frozen=True)
class PatchLine:
    """One line within a unified-diff hunk."""

    kind: PatchLineKind
    text: str
    old_lineno: Optional[int]
    new_lineno: Optional[int]

    @property
    def is_changed(self) -> bool:
        """Whether the line was added or removed."""
        return self.kind in {"add", "del"}


@dataclass(frozen=True)
class PatchHunk:
    """A parsed diff hunk."""

    old_start: int
    old_count: int
    new_start: int
    new_count: int
    header: str
    lines: tuple[PatchLine, ...]


@dataclass(frozen=True)
class PatchedFile:
    """A file-level diff entry."""

    old_path: str
    new_path: str
    hunks: tuple[PatchHunk, ...]

    @property
    def path(self) -> str:
        """Best-effort path to use for source correlation."""
        return self.old_path or self.new_path


@dataclass(frozen=True)
class ParsedPatch:
    """Parsed representation of a unified diff."""

    files: tuple[PatchedFile, ...]
    raw_text: str
    diagnostics: tuple[str, ...] = ()


@dataclass(frozen=True)
class MappedPatchLocation:
    """Patch location mapped back to source coordinates."""

    location: SourceLocation
    patch_side: Literal["old", "new"]
    change_kind: PatchLineKind
    line_text: str
    hunk_header: str


@dataclass(frozen=True)
class PatchAwareAnalysisResult:
    """Patch-aware refinement outputs."""

    patch_evidence: Optional[PatchEvidence]
    candidates: tuple[RootCauseCandidate, ...]
    chains: tuple[CausalityChain, ...]
    diagnostics: tuple[str, ...] = ()
    mapped_locations: tuple[MappedPatchLocation, ...] = field(default_factory=tuple)
