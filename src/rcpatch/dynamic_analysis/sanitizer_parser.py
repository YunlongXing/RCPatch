"""Parsers for ASan-like sanitizer reports."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from rcpatch.dynamic_analysis.stacktrace_parser import StackTraceParser
from rcpatch.ingestion.path_utils import SourcePathResolver
from rcpatch.logging_utils import get_logger
from rcpatch.models import BugType, EvidenceKind, EvidenceReference, SourceLocation

_ERROR_RE = re.compile(
    r"ERROR:\s+(?P<sanitizer>[A-Za-z]+Sanitizer):\s+(?P<error_type>[A-Za-z0-9_\-]+)",
    re.IGNORECASE,
)
_SUMMARY_RE = re.compile(
    r"SUMMARY:\s+(?P<sanitizer>[A-Za-z]+Sanitizer):\s+(?P<error_type>[A-Za-z0-9_\-]+)"
    r"(?:\s+(?P<file>.+?):(?P<line>\d+)(?::(?P<column>\d+))?\s+in\s+(?P<function>.+))?$",
    re.IGNORECASE,
)
_ACCESS_RE = re.compile(r"\b(?P<access>READ|WRITE)\s+of\s+size\s+\d+", re.IGNORECASE)
_FREE_RE = re.compile(r"\b(free|freed by thread|attempting free)\b", re.IGNORECASE)


@dataclass
class SanitizerParseResult:
    """Structured sanitizer parsing output."""

    failure_summary: Optional[str] = None
    failing_access: Optional[str] = None
    stack_frames: list[Any] = field(default_factory=list)
    evidence: list[EvidenceReference] = field(default_factory=list)
    trigger_frame_index: Optional[int] = None
    trigger_location: Optional[SourceLocation] = None
    bug_type_hint: Optional[BugType] = None
    metadata: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


class AsanLikeSanitizerParser:
    """Parse common AddressSanitizer-style reports into structured runtime evidence."""

    def __init__(self, stacktrace_parser: Optional[StackTraceParser] = None) -> None:
        self.stacktrace_parser = stacktrace_parser or StackTraceParser()
        self.logger = get_logger(__name__)

    def parse(
        self,
        text: str,
        *,
        resolver: Optional[SourcePathResolver] = None,
        evidence_path: Optional[str] = None,
    ) -> SanitizerParseResult:
        result = SanitizerParseResult()
        parsed_stack = self.stacktrace_parser.parse(
            text,
            resolver=resolver,
            evidence_path=evidence_path,
            evidence_kind=EvidenceKind.SANITIZER_REPORT,
        )
        result.stack_frames = parsed_stack.frames
        result.evidence.extend(parsed_stack.evidence)
        result.notes.extend(parsed_stack.notes)

        for line_number, raw_line in enumerate(text.splitlines(), start=1):
            line = raw_line.strip()
            if not line:
                continue

            error_match = _ERROR_RE.search(line)
            if error_match is not None and result.failure_summary is None:
                sanitizer = error_match.group("sanitizer")
                error_type = error_match.group("error_type")
                result.failure_summary = f"{sanitizer}: {error_type}"
                result.metadata["sanitizer"] = sanitizer
                result.metadata["error_type"] = error_type
                result.bug_type_hint = _map_bug_type(error_type)
                result.evidence.append(
                    EvidenceReference(
                        kind=EvidenceKind.SANITIZER_REPORT,
                        path=evidence_path,
                        line=line_number,
                        excerpt=raw_line.rstrip(),
                        description="Parsed sanitizer error header",
                    )
                )

            summary_match = _SUMMARY_RE.search(line)
            if summary_match is not None:
                sanitizer = summary_match.group("sanitizer")
                error_type = summary_match.group("error_type")
                result.failure_summary = f"{sanitizer}: {error_type}"
                result.metadata["sanitizer"] = sanitizer
                result.metadata["error_type"] = error_type
                result.bug_type_hint = _map_bug_type(error_type)
                result.evidence.append(
                    EvidenceReference(
                        kind=EvidenceKind.SANITIZER_REPORT,
                        path=evidence_path,
                        line=line_number,
                        excerpt=raw_line.rstrip(),
                        description="Parsed sanitizer summary line",
                    )
                )
                if summary_match.group("file") and summary_match.group("line"):
                    normalized_file = (
                        resolver.normalize_source_path(summary_match.group("file")) if resolver is not None else summary_match.group("file")
                    )
                    result.trigger_location = SourceLocation(
                        file=normalized_file or summary_match.group("file"),
                        line=int(summary_match.group("line")),
                        column=int(summary_match.group("column")) if summary_match.group("column") else None,
                        function=summary_match.group("function"),
                        metadata={
                            "source": "sanitizer_summary",
                            "evidence_path": evidence_path,
                            "evidence_line": line_number,
                        },
                    )

            access_match = _ACCESS_RE.search(line)
            if access_match is not None:
                result.failing_access = access_match.group("access").lower()

            if result.failing_access is None and _FREE_RE.search(line):
                result.failing_access = "free"

        result.trigger_frame_index = self._find_trigger_frame_index(result)
        if result.trigger_location is None and result.trigger_frame_index is not None:
            trigger_frame = result.stack_frames[result.trigger_frame_index]
            result.trigger_location = trigger_frame.location

        if result.failure_summary is None:
            result.notes.append("No sanitizer summary or error header was parsed.")
            self.logger.debug("No sanitizer summary parsed from evidence at %s", evidence_path)

        return result

    @staticmethod
    def _find_trigger_frame_index(result: SanitizerParseResult) -> Optional[int]:
        if not result.stack_frames:
            return None
        if result.trigger_location is None:
            return 0

        for frame in result.stack_frames:
            if frame.location is None:
                continue
            if (
                frame.location.file == result.trigger_location.file
                and frame.location.line == result.trigger_location.line
            ):
                return frame.index
        return 0


def _map_bug_type(error_type: Optional[str]) -> Optional[BugType]:
    if error_type is None:
        return None

    lowered = error_type.lower()
    if "use-after-free" in lowered:
        return BugType.USE_AFTER_FREE
    if "buffer-overflow" in lowered or "out-of-bounds" in lowered:
        return BugType.BUFFER_OVERFLOW
    if "null" in lowered:
        return BugType.NULL_DEREFERENCE
    if "integer" in lowered or "overflow" in lowered:
        return BugType.INTEGER_OVERFLOW_TO_MEMORY_ERROR
    return None
