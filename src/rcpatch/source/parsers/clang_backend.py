"""Optional clang AST backend hook with explicit fallback diagnostics."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Optional

from rcpatch.models import ParserBackend, ProgramAbstraction
from rcpatch.source.parsers.base import SourceParserBackend


class ClangASTSourceParserBackend(SourceParserBackend):
    """Reserved backend for compile-database-aware clang AST extraction.

    RCPatch keeps this backend registered so experiments can request
    ``--parser-backend clang_ast`` and receive an explicit diagnostic rather
    than silently falling through to unrelated behavior. Until the full clang
    extractor is wired into the shared IR, the parser service falls back to the
    regex backend after recording why clang was not used.
    """

    backend_name = ParserBackend.CLANG_AST

    @classmethod
    def is_available(cls) -> bool:
        return False

    @classmethod
    def unavailable_reason(cls) -> Optional[str]:
        if shutil.which("clang") is None and shutil.which("clang++") is None:
            return "clang/clang++ was not found in PATH; falling back to regex heuristics."
        return (
            "clang AST backend hook exists but is not yet wired to the shared IR; "
            "falling back to regex heuristics."
        )

    def parse_project(self, repo_root: Path, source_files: list[str]) -> ProgramAbstraction:
        raise RuntimeError("clang AST backend is unavailable in this environment")
