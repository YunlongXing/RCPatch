"""High-level source parsing service and parser-agnostic query helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Optional, Tuple, Union

from rcpatch.logging_utils import get_logger
from rcpatch.models import (
    CallRelationship,
    DiagnosticLevel,
    FunctionDefinition,
    ParseDiagnostic,
    ParserBackend,
    ProgramAbstraction,
    SourceFile,
    SourceLocation,
    StatementInfo,
)
from rcpatch.source.parsers.base import SourceParserBackend
from rcpatch.source.parsers import (
    ClangASTSourceParserBackend,
    CtagsSourceParserBackend,
    RegexSourceParserBackend,
    TreeSitterSourceParserBackend,
)
from rcpatch.source.scanner import RepoFileScanner

BACKEND_REGISTRY = {
    ParserBackend.TREE_SITTER: TreeSitterSourceParserBackend,
    ParserBackend.CLANG_AST: ClangASTSourceParserBackend,
    ParserBackend.CTAGS: CtagsSourceParserBackend,
    ParserBackend.REGEX: RegexSourceParserBackend,
}


class SourceProjectParser:
    """Parse a repository into a lightweight parser-agnostic program abstraction."""

    def __init__(self, *, file_scanner: Optional[RepoFileScanner] = None) -> None:
        self.file_scanner = file_scanner or RepoFileScanner()
        self.logger = get_logger(__name__)

    def parse_repository(
        self,
        repo_root: Union[str, Path],
        *,
        preferred_backend: ParserBackend = ParserBackend.TREE_SITTER,
        source_files: Optional[Iterable[str]] = None,
    ) -> ProgramAbstraction:
        root = Path(repo_root).expanduser().resolve()
        selected_backend, diagnostics, approximations = self._select_backend(preferred_backend)
        file_list = sorted(source_files) if source_files is not None else self.file_scanner.scan(root)
        self.logger.info(
            "Parsing %d source files under %s with %s backend",
            len(file_list),
            root,
            selected_backend.backend_name.value,
        )

        program = selected_backend.parse_project(root, file_list)
        merged_diagnostics = diagnostics + program.diagnostics
        merged_approximations = approximations + program.approximations

        return program.model_copy(
            update={
                "diagnostics": merged_diagnostics,
                "approximations": merged_approximations,
            }
        )

    def build_index(self, program: ProgramAbstraction) -> "ProgramIndex":
        """Build query indexes for a parsed program abstraction."""
        return ProgramIndex(program=program)

    def _select_backend(
        self,
        preferred_backend: ParserBackend,
    ) -> Tuple[SourceParserBackend, list[ParseDiagnostic], list[str]]:
        diagnostics: list[ParseDiagnostic] = []
        approximations: list[str] = []

        for backend_name in self._backend_order(preferred_backend):
            backend_class = BACKEND_REGISTRY.get(backend_name)
            if backend_class is None:
                diagnostics.append(
                    ParseDiagnostic(
                        level=DiagnosticLevel.WARNING,
                        backend=preferred_backend,
                        message=f"Requested backend {backend_name.value} is not registered; falling back.",
                    )
                )
                continue

            if backend_class.is_available():
                if backend_name != preferred_backend:
                    diagnostics.append(
                        ParseDiagnostic(
                            level=DiagnosticLevel.INFO,
                            backend=backend_name,
                            message=f"Using fallback backend {backend_name.value}.",
                        )
                    )
                return backend_class(), diagnostics, approximations

            diagnostics.append(backend_class.unavailable_diagnostic())
            approximations.append(backend_class.unavailable_reason() or f"{backend_name.value} backend unavailable.")

        return RegexSourceParserBackend(), diagnostics, approximations

    @staticmethod
    def _backend_order(preferred_backend: ParserBackend) -> list[ParserBackend]:
        order = [preferred_backend]
        for backend in (ParserBackend.TREE_SITTER, ParserBackend.CLANG_AST, ParserBackend.CTAGS, ParserBackend.REGEX):
            if backend not in order:
                order.append(backend)
        return order


@dataclass
class ProgramIndex:
    """Convenient query facade over the parser-agnostic program abstraction."""

    program: ProgramAbstraction
    files_by_path: Dict[str, SourceFile] = field(init=False)
    functions_by_id: Dict[str, FunctionDefinition] = field(init=False)
    functions_by_name: Dict[str, list[FunctionDefinition]] = field(init=False)
    functions_by_file: Dict[str, list[FunctionDefinition]] = field(init=False)
    callers_by_target: Dict[str, list[str]] = field(init=False)
    call_relationships_by_target: Dict[str, list[CallRelationship]] = field(init=False)
    statements_by_id: Dict[str, StatementInfo] = field(init=False)
    statements_by_function_id: Dict[str, list[StatementInfo]] = field(init=False)
    statement_to_function_id: Dict[str, str] = field(init=False)

    def __post_init__(self) -> None:
        self.files_by_path = {source_file.path: source_file for source_file in self.program.files}
        self.functions_by_id = {function.function_id: function for function in self.program.functions}
        self.functions_by_name = {}
        self.functions_by_file = {}
        self.callers_by_target = {}
        self.call_relationships_by_target = {}
        self.statements_by_id = {}
        self.statements_by_function_id = {}
        self.statement_to_function_id = {}

        for function in self.program.functions:
            self.functions_by_name.setdefault(function.name, []).append(function)
            self.functions_by_file.setdefault(function.location.file, []).append(function)
            ordered_statements = sorted(function.statements, key=lambda statement: (statement.location.line, statement.location.column or 0))
            self.statements_by_function_id[function.function_id] = ordered_statements
            for statement in ordered_statements:
                self.statements_by_id[statement.statement_id] = statement
                self.statement_to_function_id[statement.statement_id] = function.function_id

        for relationship in self.program.call_relationships:
            if relationship.resolved_target is None:
                continue
            self.callers_by_target.setdefault(relationship.resolved_target, []).append(relationship.caller_function_id)
            self.call_relationships_by_target.setdefault(relationship.resolved_target, []).append(relationship)

    def get_file(self, path: str) -> Optional[SourceFile]:
        """Return a source file by repository-relative path."""
        return self.files_by_path.get(path)

    def get_function(self, function_id: str) -> Optional[FunctionDefinition]:
        """Return a function by its stable id."""
        return self.functions_by_id.get(function_id)

    def get_statement(self, statement_id: str) -> Optional[StatementInfo]:
        """Return a statement by its stable id."""
        return self.statements_by_id.get(statement_id)

    def find_functions(self, name: str) -> list[FunctionDefinition]:
        """Return functions whose short name matches the provided name."""
        return list(self.functions_by_name.get(name, []))

    def statements_in_function(self, function_id: str) -> list[StatementInfo]:
        """Return statements for a function in source order."""
        return list(self.statements_by_function_id.get(function_id, []))

    def function_for_statement(self, statement_id: str) -> Optional[FunctionDefinition]:
        """Return the enclosing function for a statement id."""
        function_id = self.statement_to_function_id.get(statement_id)
        if function_id is None:
            return None
        return self.get_function(function_id)

    def find_enclosing_function(self, location: SourceLocation) -> Optional[FunctionDefinition]:
        """Find the best enclosing function for a source location."""
        candidates = self.functions_by_file.get(location.file, [])
        if location.function:
            named_candidates = [function for function in candidates if function.name == location.function]
            if named_candidates:
                candidates = named_candidates

        exact_range_matches = [
            function
            for function in candidates
            if function.location.line <= location.line <= function.end_line
        ]
        if exact_range_matches:
            return min(exact_range_matches, key=lambda function: (function.end_line - function.location.line, function.location.line))

        if candidates:
            return min(candidates, key=lambda function: abs(function.location.line - location.line))
        return None

    def find_nearest_statement(
        self,
        location: SourceLocation,
        *,
        max_line_distance: int = 5,
    ) -> Optional[StatementInfo]:
        """Find the nearest statement to a source location."""
        function = self.find_enclosing_function(location)
        candidate_statements: list[StatementInfo]
        if function is not None:
            candidate_statements = self.statements_in_function(function.function_id)
        else:
            candidate_statements = [
                statement
                for statement in self.statements_by_id.values()
                if statement.location.file == location.file
            ]

        exact_line_matches = [statement for statement in candidate_statements if statement.location.line == location.line]
        if exact_line_matches:
            if location.column is not None:
                return min(
                    exact_line_matches,
                    key=lambda statement: abs((statement.location.column or location.column) - location.column),
                )
            return exact_line_matches[0]

        line_matches = [
            statement
            for statement in candidate_statements
            if abs(statement.location.line - location.line) <= max_line_distance
        ]
        if line_matches:
            return min(
                line_matches,
                key=lambda statement: (abs(statement.location.line - location.line), statement.location.line),
            )
        return None

    def callees_of(self, function_id: str) -> list[str]:
        """Return resolved or unresolved callee names for a function."""
        function = self.get_function(function_id)
        if function is None:
            return []
        return [call_site.resolved_target or call_site.callee_name for call_site in function.call_sites]

    def callers_of(self, function_id: str) -> list[str]:
        """Return stable caller ids for a resolved function target."""
        return list(self.callers_by_target.get(function_id, []))

    def call_relationships_to(self, function_id: str) -> list[CallRelationship]:
        """Return resolved call relationships targeting a function."""
        return list(self.call_relationships_by_target.get(function_id, []))
