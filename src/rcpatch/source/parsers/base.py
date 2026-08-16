"""Parser backend abstractions for the source parsing layer."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from rcpatch.models import DiagnosticLevel, ParseDiagnostic, ParserBackend, ProgramAbstraction


class SourceParserBackend(ABC):
    """Abstract parser backend returning the shared RCPatch program IR."""

    backend_name: ParserBackend

    @classmethod
    @abstractmethod
    def is_available(cls) -> bool:
        """Whether the backend can be used in the current environment."""

    @abstractmethod
    def parse_project(self, repo_root: Path, source_files: list[str]) -> ProgramAbstraction:
        """Parse a repository into the shared program abstraction."""

    @classmethod
    def unavailable_reason(cls) -> Optional[str]:
        """Why the backend is unavailable, if known."""
        return None

    @classmethod
    def unavailable_diagnostic(cls) -> ParseDiagnostic:
        """Build a generic diagnostic when the backend is unavailable."""
        reason = cls.unavailable_reason() or f"{cls.backend_name.value} backend is unavailable"
        return ParseDiagnostic(
            level=DiagnosticLevel.WARNING,
            backend=cls.backend_name,
            message=reason,
        )
