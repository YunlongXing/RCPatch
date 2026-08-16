"""Utilities for extracting source snippets and locating trigger statements."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from rcpatch.logging_utils import get_logger
from rcpatch.models import FunctionDefinition, SourceLocation, StatementInfo, TriggerPoint
from rcpatch.source import ProgramIndex


class SourceContextExtractor:
    """Utility facade for source lookup and context extraction during slicing."""

    def __init__(self, program_index: ProgramIndex) -> None:
        self.program_index = program_index
        self.repo_root = Path(program_index.program.repo_path)
        self.logger = get_logger(__name__)

    def find_enclosing_function(self, location: SourceLocation) -> Optional[FunctionDefinition]:
        """Find the best enclosing function for a location."""
        return self.program_index.find_enclosing_function(location)

    def find_trigger_statement(self, trigger: TriggerPoint) -> Optional[StatementInfo]:
        """Find the statement that best matches the normalized trigger location."""
        exact_statement = self.program_index.find_nearest_statement(trigger.location, max_line_distance=0)
        if exact_statement is not None and self._statement_matches_trigger(exact_statement, trigger):
            return exact_statement

        function = self.find_enclosing_function(trigger.location)
        if function is not None and trigger.failing_operation:
            statements = self.program_index.statements_in_function(function.function_id)
            matching_candidates = [
                statement
                for statement in statements
                if self._statement_matches_trigger(statement, trigger)
            ]
            if matching_candidates:
                return min(
                    matching_candidates,
                    key=lambda statement: abs(statement.location.line - trigger.location.line),
                )

        return exact_statement or self.program_index.find_nearest_statement(trigger.location)

    def get_statement_text(self, statement: StatementInfo) -> str:
        """Return statement text, falling back to direct file lookup when needed."""
        if statement.text:
            return statement.text
        return self.read_line(statement.location)

    def read_line(self, location: SourceLocation) -> str:
        """Read the source line at a given location."""
        absolute_path = self.repo_root / location.file
        try:
            lines = absolute_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            self.logger.debug("Failed to read source line from %s", absolute_path)
            return ""

        if 1 <= location.line <= len(lines):
            return lines[location.line - 1].rstrip()
        return ""

    def get_context(self, location: SourceLocation, *, before: int = 2, after: int = 2) -> list[tuple[int, str]]:
        """Return a small source window around a location."""
        absolute_path = self.repo_root / location.file
        try:
            lines = absolute_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            self.logger.debug("Failed to read context from %s", absolute_path)
            return []

        start = max(location.line - before, 1)
        end = min(location.line + after, len(lines))
        return [(line_number, lines[line_number - 1].rstrip()) for line_number in range(start, end + 1)]

    @staticmethod
    def _statement_matches_trigger(statement: StatementInfo, trigger: TriggerPoint) -> bool:
        if trigger.failing_operation is None:
            return statement.location.line == trigger.location.line
        failing_operation = trigger.failing_operation.strip()
        if not failing_operation:
            return statement.location.line == trigger.location.line
        if failing_operation in statement.call_names:
            return True
        if failing_operation in statement.text:
            return True
        for operation in statement.memory_operations:
            if operation.function_name == failing_operation:
                return True
        return False
