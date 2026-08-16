"""Optional tree-sitter backend hook with graceful fallback when unavailable."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from rcpatch.models import ParserBackend, ProgramAbstraction
from rcpatch.source.parsers.base import SourceParserBackend


class TreeSitterSourceParserBackend(SourceParserBackend):
    """Optional backend slot for tree-sitter integration."""

    backend_name = ParserBackend.TREE_SITTER

    @classmethod
    def is_available(cls) -> bool:
        try:
            import tree_sitter  # noqa: F401
        except ImportError:
            return False
        return False

    @classmethod
    def unavailable_reason(cls) -> Optional[str]:
        return "tree-sitter backend is not configured in this environment; falling back to regex heuristics."

    def parse_project(self, repo_root: Path, source_files: list[str]) -> ProgramAbstraction:
        raise RuntimeError("tree-sitter backend is unavailable in this environment")
