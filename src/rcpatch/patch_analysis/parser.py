"""Unified-diff parsing utilities for patch-aware analysis."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from rcpatch.logging_utils import get_logger
from rcpatch.patch_analysis.models import ParsedPatch, PatchHunk, PatchLine, PatchedFile

HUNK_HEADER_RE = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? \+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@(?P<header>.*)$"
)


class UnifiedDiffParser:
    """Parse unified diff text into structured hunks and changed lines."""

    def __init__(self) -> None:
        self.logger = get_logger(__name__)

    def parse_file(self, diff_path: str) -> ParsedPatch:
        """Parse a unified diff from disk."""
        path = Path(diff_path).expanduser()
        raw_text = path.read_text(encoding="utf-8", errors="replace")
        return self.parse_text(raw_text)

    def parse_text(self, raw_text: str) -> ParsedPatch:
        """Parse unified diff text."""
        lines = raw_text.splitlines()
        files: list[PatchedFile] = []
        diagnostics: list[str] = []

        current_old_path = ""
        current_new_path = ""
        current_hunks: list[PatchHunk] = []
        current_lines: list[PatchLine] = []
        current_hunk_meta: Optional[tuple[int, int, int, int, str]] = None
        old_lineno = 0
        new_lineno = 0

        def finalize_hunk() -> None:
            nonlocal current_lines, current_hunk_meta, current_hunks
            if current_hunk_meta is None:
                return
            old_start, old_count, new_start, new_count, header = current_hunk_meta
            current_hunks.append(
                PatchHunk(
                    old_start=old_start,
                    old_count=old_count,
                    new_start=new_start,
                    new_count=new_count,
                    header=header.strip(),
                    lines=tuple(current_lines),
                )
            )
            current_lines = []
            current_hunk_meta = None

        def finalize_file() -> None:
            nonlocal current_old_path, current_new_path, current_hunks
            finalize_hunk()
            if not current_old_path and not current_new_path:
                current_hunks = []
                return
            files.append(
                PatchedFile(
                    old_path=current_old_path,
                    new_path=current_new_path,
                    hunks=tuple(current_hunks),
                )
            )
            current_old_path = ""
            current_new_path = ""
            current_hunks = []

        for raw_line in lines:
            if raw_line.startswith("diff --git "):
                finalize_file()
                continue
            if raw_line.startswith("--- "):
                current_old_path = _normalize_patch_path(raw_line[4:].strip())
                continue
            if raw_line.startswith("+++ "):
                current_new_path = _normalize_patch_path(raw_line[4:].strip())
                continue

            header_match = HUNK_HEADER_RE.match(raw_line)
            if header_match:
                finalize_hunk()
                old_start = int(header_match.group("old_start"))
                old_count = int(header_match.group("old_count") or "1")
                new_start = int(header_match.group("new_start"))
                new_count = int(header_match.group("new_count") or "1")
                old_lineno = old_start
                new_lineno = new_start
                current_hunk_meta = (old_start, old_count, new_start, new_count, header_match.group("header"))
                continue

            if current_hunk_meta is None:
                continue
            if raw_line.startswith("\\ No newline at end of file"):
                diagnostics.append("Encountered missing newline marker in diff.")
                continue

            prefix = raw_line[:1]
            text = raw_line[1:] if raw_line else ""
            if prefix == " ":
                current_lines.append(PatchLine(kind="context", text=text, old_lineno=old_lineno, new_lineno=new_lineno))
                old_lineno += 1
                new_lineno += 1
            elif prefix == "-":
                current_lines.append(PatchLine(kind="del", text=text, old_lineno=old_lineno, new_lineno=None))
                old_lineno += 1
            elif prefix == "+":
                current_lines.append(PatchLine(kind="add", text=text, old_lineno=None, new_lineno=new_lineno))
                new_lineno += 1
            else:
                diagnostics.append(f"Unrecognized diff line prefix {prefix!r}; preserving as context.")
                current_lines.append(PatchLine(kind="context", text=raw_line, old_lineno=old_lineno, new_lineno=new_lineno))
                old_lineno += 1
                new_lineno += 1

        finalize_file()
        return ParsedPatch(files=tuple(files), raw_text=raw_text, diagnostics=tuple(diagnostics))


def _normalize_patch_path(raw_path: str) -> str:
    path = raw_path.strip()
    if path in {"/dev/null", "dev/null"}:
        return ""
    if path.startswith("a/") or path.startswith("b/"):
        return path[2:]
    return path
