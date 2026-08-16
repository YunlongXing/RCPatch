"""Regex-and-heuristic fallback backend for lightweight source abstraction."""

from __future__ import annotations

import re
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from rcpatch.logging_utils import get_logger
from rcpatch.models import (
    CallRelationship,
    CallSite,
    DiagnosticLevel,
    FunctionDefinition,
    Language,
    ParseDiagnostic,
    ParserBackend,
    ProgramAbstraction,
    SourceFile,
    SourceLocation,
    StatementInfo,
)
from rcpatch.source.parsers.base import SourceParserBackend
from rcpatch.source.parsers.heuristics import (
    detect_condition_expression,
    detect_language,
    detect_return_expression,
    detect_statement_types,
    extract_call_argument_metadata,
    extract_call_names,
    extract_declared_variables,
    extract_defined_variables,
    extract_includes,
    extract_memory_operations,
    extract_referenced_variables,
    extract_structural_accesses,
    make_statement_location,
    parse_parameters,
    strip_comments_preserve_layout,
)

FUNCTION_SIGNATURE_RE = re.compile(
    r"""
    ^\s*
    (?P<ret>.*?)?
    (?P<name>[A-Za-z_~][A-Za-z0-9_:]*)\s*
    \(
        (?P<params>.*)
    \)\s*
    (?:const\b\s*)?
    (?:noexcept\b\s*)?
    (?:->\s*[^{;]+)?
    \s*$
    """,
    re.DOTALL | re.VERBOSE,
)

CONTROL_KEYWORDS = {"if", "for", "while", "switch", "catch"}
NON_FUNCTION_PREFIXES = ("typedef", "enum", "struct", "union", "namespace")
MAX_SIGNATURE_LINES = 12


@dataclass(frozen=True)
class FunctionCandidate:
    """Intermediate top-level function candidate extracted from a source file."""

    start_index: int
    open_brace_index: int
    name: str
    return_type: Optional[str]
    params: str
    signature_text: str


class RegexSourceParserBackend(SourceParserBackend):
    """Pure-Python fallback parser using brace matching and regex heuristics."""

    backend_name = ParserBackend.REGEX

    def __init__(self) -> None:
        self.logger = get_logger(__name__)

    @classmethod
    def is_available(cls) -> bool:
        return True

    def parse_project(self, repo_root: Path, source_files: list[str]) -> ProgramAbstraction:
        parsed_files: list[SourceFile] = []
        diagnostics: list[ParseDiagnostic] = []
        functions: list[FunctionDefinition] = []

        for relative_path in source_files:
            source_file = self._parse_file(repo_root, relative_path)
            parsed_files.append(source_file)
            diagnostics.extend(source_file.diagnostics)
            functions.extend(source_file.functions)

        call_relationships = self._build_call_relationships(functions)
        approximations = [
            "Regex backend uses heuristic function discovery and statement extraction.",
            "Control-flow and declaration parsing are approximate and line-oriented.",
        ]

        return ProgramAbstraction(
            repo_path=repo_root.as_posix(),
            backend=self.backend_name,
            files=parsed_files,
            functions=functions,
            call_relationships=call_relationships,
            diagnostics=diagnostics,
            approximations=approximations,
            metadata={
                "parsed_file_count": len(parsed_files),
            },
        )

    def _parse_file(self, repo_root: Path, relative_path: str) -> SourceFile:
        absolute_path = repo_root / relative_path
        source_text = absolute_path.read_text(encoding="utf-8", errors="replace")
        cleaned_text = strip_comments_preserve_layout(source_text)

        diagnostics: list[ParseDiagnostic] = []
        functions: list[FunctionDefinition] = []
        seen_function_ids: dict[str, int] = {}

        for candidate in self._iter_function_candidates(cleaned_text):
            name = candidate.name
            open_brace_index = candidate.open_brace_index
            close_brace_index = self._find_matching_brace(cleaned_text, open_brace_index)
            if close_brace_index is None:
                diagnostics.append(
                    ParseDiagnostic(
                        level=DiagnosticLevel.WARNING,
                        backend=self.backend_name,
                        file=relative_path,
                        line=cleaned_text.count("\n", 0, candidate.start_index) + 1,
                        message=f"Could not find matching closing brace for function {name}.",
                    )
                )
                continue

            function = self._build_function(
                relative_path=relative_path,
                source_text=source_text,
                cleaned_text=cleaned_text,
                candidate=candidate,
                open_brace_index=open_brace_index,
                close_brace_index=close_brace_index,
                function_id=self._allocate_function_id(
                    relative_path=relative_path,
                    candidate=candidate,
                    cleaned_text=cleaned_text,
                    open_brace_index=open_brace_index,
                    seen_function_ids=seen_function_ids,
                ),
            )
            functions.append(function)

        if not functions:
            diagnostics.append(
                ParseDiagnostic(
                    level=DiagnosticLevel.INFO,
                    backend=self.backend_name,
                    file=relative_path,
                    message="No function definitions were recognized in this file.",
                )
            )

        return SourceFile(
            path=relative_path,
            language=detect_language(relative_path),
            includes=extract_includes(cleaned_text),
            functions=functions,
            diagnostics=diagnostics,
            metadata={
                "absolute_path": absolute_path.as_posix(),
                "function_count": len(functions),
            },
        )

    def _build_function(
        self,
        *,
        relative_path: str,
        source_text: str,
        cleaned_text: str,
        candidate: FunctionCandidate,
        open_brace_index: int,
        close_brace_index: int,
        function_id: str,
    ) -> FunctionDefinition:
        name = candidate.name
        qualified_name = name if "::" in name else None
        short_name = name.split("::")[-1]
        start_line = cleaned_text.count("\n", 0, candidate.start_index) + 1
        open_brace_line = cleaned_text.count("\n", 0, open_brace_index) + 1
        end_line = cleaned_text.count("\n", 0, close_brace_index) + 1
        signature_text = candidate.signature_text
        return_type = candidate.return_type
        parameters = parse_parameters(candidate.params)

        function_location = SourceLocation(
            file=relative_path,
            line=start_line,
            function=short_name,
            snippet=signature_text,
        )

        body_text = source_text[open_brace_index + 1 : close_brace_index]
        body_lines = body_text.splitlines()
        statements: list[StatementInfo] = []
        call_sites: list[CallSite] = []
        memory_operations = []
        local_variables: list[str] = []
        current_depth = 0

        for offset, raw_line in enumerate(body_lines):
            statement_line = open_brace_line + offset
            stripped_line = raw_line.strip()
            if not stripped_line:
                continue

            leading_closes = len(stripped_line) - len(stripped_line.lstrip("}"))
            effective_depth = max(current_depth - leading_closes, 0)

            open_count = stripped_line.count("{")
            close_count = stripped_line.count("}")
            next_depth = max(effective_depth + open_count - close_count, 0)
            if stripped_line in {"{", "}"}:
                current_depth = next_depth
                continue

            column = raw_line.find(stripped_line) + 1 if stripped_line in raw_line else 1
            location = make_statement_location(
                file_path=relative_path,
                line=statement_line,
                column=column,
                function_name=short_name,
                snippet=stripped_line,
            )

            call_names = extract_call_names(stripped_line)
            defined_variables = extract_defined_variables(stripped_line)
            declared_variables = extract_declared_variables(stripped_line)
            local_variables.extend(declared_variables)
            if defined_variables:
                local_variables.extend(defined_variables)
            memory_ops = extract_memory_operations(stripped_line, location=location, call_names=call_names)
            statement_types = detect_statement_types(stripped_line, call_names=call_names, memory_operations=memory_ops)
            condition_expression = detect_condition_expression(stripped_line)
            return_expression = detect_return_expression(stripped_line)
            excluded_identifiers = set(call_names + defined_variables + declared_variables)
            referenced_variables = extract_referenced_variables(stripped_line, excluded=excluded_identifiers)
            structural_accesses = extract_structural_accesses(stripped_line)
            call_argument_metadata = extract_call_argument_metadata(stripped_line, call_names)

            statement = StatementInfo(
                statement_id=f"{function_id}:{statement_line}",
                location=location,
                text=stripped_line,
                statement_types=statement_types,
                defined_variables=defined_variables + declared_variables,
                referenced_variables=referenced_variables,
                call_names=call_names,
                memory_operations=memory_ops,
                condition_expression=condition_expression,
                return_expression=return_expression,
                metadata={
                    "block_depth": effective_depth,
                    **structural_accesses,
                    **call_argument_metadata,
                },
            )
            statements.append(statement)
            memory_operations.extend(memory_ops)

            for call_name in call_names:
                call_sites.append(
                    CallSite(
                        caller_function_id=function_id,
                        caller_name=short_name,
                        callee_name=call_name.split("::")[-1],
                        location=location,
                    )
                )
            current_depth = next_depth

        return FunctionDefinition(
            function_id=function_id,
            name=short_name,
            qualified_name=qualified_name,
            location=function_location,
            end_line=end_line,
            return_type=return_type,
            parameters=parameters,
            statements=statements,
            call_sites=call_sites,
            memory_operations=memory_operations,
            local_variables=_deduplicate(local_variables),
            approximations=[
                "Function boundaries are detected with regex and brace matching.",
                "Statements are extracted line-by-line and may merge multiple operations on one line.",
            ],
            metadata={
                "signature_text": signature_text,
            },
        )

    def _allocate_function_id(
        self,
        *,
        relative_path: str,
        candidate: FunctionCandidate,
        cleaned_text: str,
        open_brace_index: int,
        seen_function_ids: dict[str, int],
    ) -> str:
        short_name = candidate.name.split("::")[-1]
        start_line = cleaned_text.count("\n", 0, candidate.start_index) + 1
        base_id = f"{relative_path}:{short_name}:{start_line}:{open_brace_index}"
        occurrence = seen_function_ids.get(base_id, 0)
        seen_function_ids[base_id] = occurrence + 1
        if occurrence == 0:
            return base_id
        return f"{base_id}#{occurrence + 1}"

    def _build_call_relationships(self, functions: list[FunctionDefinition]) -> list[CallRelationship]:
        functions_by_name: dict[str, list[FunctionDefinition]] = {}
        for function in functions:
            functions_by_name.setdefault(function.name, []).append(function)

        relationships: list[CallRelationship] = []
        for function in functions:
            for call_site in function.call_sites:
                candidate_targets = functions_by_name.get(call_site.callee_name, [])
                resolved_target = candidate_targets[0].function_id if len(candidate_targets) == 1 else None
                relationships.append(
                    CallRelationship(
                        caller_function_id=function.function_id,
                        caller_name=function.name,
                        callee_name=call_site.callee_name,
                        location=call_site.location,
                        resolved_target=resolved_target,
                        metadata={
                            "candidate_targets": [candidate.function_id for candidate in candidate_targets],
                            "resolved_by": "name_match" if resolved_target is not None else "heuristic",
                        },
                    )
                )
        return relationships

    @staticmethod
    def _find_matching_brace(text: str, open_brace_index: int) -> Optional[int]:
        depth = 0
        for index in range(open_brace_index, len(text)):
            current = text[index]
            if current == "{":
                depth += 1
            elif current == "}":
                depth -= 1
                if depth == 0:
                    return index
        return None

    def _iter_function_candidates(self, cleaned_text: str) -> list[FunctionCandidate]:
        line_starts = self._line_starts(cleaned_text)
        candidates: list[FunctionCandidate] = []
        depth = 0

        for index, current in enumerate(cleaned_text):
            if current == "{":
                if depth == 0:
                    candidate = self._candidate_from_open_brace(cleaned_text, line_starts, index)
                    if candidate is not None:
                        candidates.append(candidate)
                depth += 1
            elif current == "}":
                depth = max(depth - 1, 0)

        return candidates

    def _candidate_from_open_brace(
        self,
        cleaned_text: str,
        line_starts: list[int],
        open_brace_index: int,
    ) -> Optional[FunctionCandidate]:
        line_number = max(bisect_right(line_starts, open_brace_index) - 1, 0)
        lines = cleaned_text.splitlines()

        signature_line_indexes: list[int] = []
        for current_line in range(line_number, max(line_number - MAX_SIGNATURE_LINES, -1), -1):
            raw_line = lines[current_line]
            prefix = raw_line[: open_brace_index - line_starts[current_line]] if current_line == line_number else raw_line
            stripped = prefix.strip()

            if not stripped:
                if signature_line_indexes:
                    break
                continue

            if stripped.startswith("#"):
                break
            if stripped.endswith(";") or stripped.endswith("}") or stripped == "{":
                break

            signature_line_indexes.append(current_line)
            if "(" in stripped:
                break

        if not signature_line_indexes:
            return None

        signature_line_indexes.reverse()
        start_line = signature_line_indexes[0]
        signature_parts: list[str] = []
        for current_line in signature_line_indexes:
            raw_line = lines[current_line]
            if current_line == line_number:
                raw_line = raw_line[: open_brace_index - line_starts[current_line]]
            signature_parts.append(raw_line.rstrip())

        signature_text = "\n".join(part for part in signature_parts if part.strip()).strip()
        if not self._looks_like_function_signature(signature_text):
            return None

        match = FUNCTION_SIGNATURE_RE.match(signature_text)
        if match is None:
            return None

        name = match.group("name")
        short_name = name.split("::")[-1]
        return_type = (match.group("ret") or "").strip() or None
        params = match.group("params") or ""

        if short_name in CONTROL_KEYWORDS:
            return None
        if return_type is None and short_name.isupper():
            return None

        return FunctionCandidate(
            start_index=line_starts[start_line],
            open_brace_index=open_brace_index,
            name=name,
            return_type=return_type,
            params=params,
            signature_text=signature_text,
        )

    @staticmethod
    def _line_starts(text: str) -> list[int]:
        starts = [0]
        for index, current in enumerate(text):
            if current == "\n" and index + 1 < len(text):
                starts.append(index + 1)
        return starts

    @staticmethod
    def _looks_like_function_signature(signature_text: str) -> bool:
        if "(" not in signature_text or ")" not in signature_text:
            return False

        normalized = " ".join(signature_text.split())
        if not normalized:
            return False
        if normalized.startswith(NON_FUNCTION_PREFIXES):
            return False
        if "=" in normalized.split("(", 1)[0]:
            return False
        return True


def _deduplicate(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result
