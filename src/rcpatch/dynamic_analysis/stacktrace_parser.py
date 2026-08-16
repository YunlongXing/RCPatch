"""Generic stack-trace parsing for C/C++ runtime evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from rcpatch.ingestion.path_utils import SourcePathResolver
from rcpatch.logging_utils import get_logger
from rcpatch.models import EvidenceKind, EvidenceReference, SourceLocation, StackFrame

_ASAN_FRAME_RE = re.compile(
    r"^\s*#(?P<index>\d+)\s+0x[0-9A-Fa-f]+\s+in\s+(?P<function>.+?)\s+"
    r"(?P<file>.+?):(?P<line>\d+)(?::(?P<column>\d+))?(?:\s.*)?$"
)
_GDB_FRAME_RE = re.compile(
    r"^\s*#(?P<index>\d+)\s+(?P<function>.+?)\s+at\s+(?P<file>.+?):(?P<line>\d+)(?::(?P<column>\d+))?\s*$"
)
_PAREN_FRAME_RE = re.compile(
    r"^\s*(?:frame\s+#)?(?P<index>\d+)?:?\s*at\s+(?P<function>.+?)\s+\((?P<file>.+?):(?P<line>\d+)(?::(?P<column>\d+))?\)\s*$"
)
_MODULE_ONLY_RE = re.compile(
    r"^\s*#(?P<index>\d+)\s+0x(?P<address>[0-9A-Fa-f]+)\s+in\s+(?P<function>.+?)\s+\((?P<module>.+?)\+0x[0-9A-Fa-f]+\)\s*$"
)


@dataclass
class ParsedStackTrace:
    """Structured representation of a parsed stack trace."""

    frames: list[StackFrame] = field(default_factory=list)
    evidence: list[EvidenceReference] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class StackTraceParser:
    """Parse stack traces from ASan-like and debugger-style formats."""

    def __init__(self) -> None:
        self.logger = get_logger(__name__)

    def parse(
        self,
        text: str,
        *,
        resolver: Optional[SourcePathResolver] = None,
        evidence_path: Optional[str] = None,
        evidence_kind: EvidenceKind = EvidenceKind.STACK_TRACE,
    ) -> ParsedStackTrace:
        frames: list[StackFrame] = []
        evidence_refs: list[EvidenceReference] = []
        notes: list[str] = []

        for line_number, raw_line in enumerate(text.splitlines(), start=1):
            line = raw_line.rstrip()
            if not line:
                continue

            frame = self._parse_frame_line(
                line,
                resolver=resolver,
                line_number=line_number,
                evidence_path=evidence_path,
                evidence_kind=evidence_kind,
            )
            if frame is None:
                continue

            frames.append(frame)
            evidence_refs.append(
                EvidenceReference(
                    kind=evidence_kind,
                    path=evidence_path,
                    line=line_number,
                    excerpt=line,
                    description="Parsed stack frame",
                )
            )

        if not frames:
            notes.append("No recognizable stack frames were parsed.")
            self.logger.debug("No stack frames parsed from evidence at %s", evidence_path)

        return ParsedStackTrace(frames=frames, evidence=evidence_refs, notes=notes)

    def _parse_frame_line(
        self,
        line: str,
        *,
        resolver: Optional[SourcePathResolver],
        line_number: int,
        evidence_path: Optional[str],
        evidence_kind: EvidenceKind,
    ) -> Optional[StackFrame]:
        for pattern in (_ASAN_FRAME_RE, _GDB_FRAME_RE, _PAREN_FRAME_RE, _MODULE_ONLY_RE):
            match = pattern.match(line)
            if match is None:
                continue
            return self._build_frame(
                match=match,
                resolver=resolver,
                line_number=line_number,
                evidence_path=evidence_path,
                evidence_kind=evidence_kind,
            )
        return None

    def _build_frame(
        self,
        *,
        match: re.Match[str],
        resolver: Optional[SourcePathResolver],
        line_number: int,
        evidence_path: Optional[str],
        evidence_kind: EvidenceKind,
    ) -> StackFrame:
        groups = match.groupdict()
        index = int(groups.get("index") or 0)
        function = self._clean_function(groups.get("function"))
        module = groups.get("module")
        instruction = groups.get("address")

        location: Optional[SourceLocation] = None
        raw_file = groups.get("file")
        raw_line = groups.get("line")
        raw_column = groups.get("column")
        if raw_file and raw_line:
            normalized_file = resolver.normalize_source_path(raw_file) if resolver is not None else raw_file
            location = SourceLocation(
                file=normalized_file or raw_file,
                line=int(raw_line),
                column=int(raw_column) if raw_column is not None else None,
                function=function,
                metadata={
                    "evidence_kind": evidence_kind.value,
                    "evidence_path": evidence_path,
                    "evidence_line": line_number,
                },
            )

        return StackFrame(
            index=index,
            function=function,
            location=location,
            module=module,
            instruction=instruction,
            metadata={
                "parsed_from_line": line_number,
            },
        )

    @staticmethod
    def _clean_function(raw_function: Optional[str]) -> Optional[str]:
        if raw_function is None:
            return None
        cleaned = raw_function.strip()
        if not cleaned:
            return None
        if cleaned.endswith(")"):
            return cleaned
        return cleaned
