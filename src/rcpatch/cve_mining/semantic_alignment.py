"""LLM-based semantic alignment between CVE text and existing code-level candidates."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from rcpatch.llm import SemanticDisambiguator
from rcpatch.logging_utils import get_logger
from rcpatch.models import (
    CVECandidateSemanticAlignment,
    CVEPatchExtraction,
    CVESemanticAlignmentResult,
    CVERootCauseMiningResult,
    CandidateLabel,
    CollectedCVERecord,
    DependencyEdge,
    ParserBackend,
    RootCauseCandidate,
    SliceNode,
)
from rcpatch.source import ProgramIndex, SourceProjectParser
from rcpatch.slicing import SourceContextExtractor

_MAX_FUNCTION_CONTEXT_LINES = 40
_MAX_EDGE_SUMMARY_LINES = 5
_MAX_PATCH_HUNKS = 2
_MAX_PATCH_STATEMENTS_PER_HUNK = 6


class CVESemanticAligner:
    """Classify existing CVE candidates using CVE text plus extracted code evidence."""

    def __init__(
        self,
        *,
        parser: Optional[SourceProjectParser] = None,
        semantic_disambiguator: Optional[SemanticDisambiguator] = None,
    ) -> None:
        self.parser = parser or SourceProjectParser()
        self.semantic_disambiguator = semantic_disambiguator or SemanticDisambiguator()
        self.logger = get_logger(__name__)

    def align_candidates(
        self,
        record: CollectedCVERecord,
        mining_result: CVERootCauseMiningResult,
        *,
        patch_extraction: Optional[CVEPatchExtraction] = None,
        repo_path: Optional[str] = None,
        parser_backend: ParserBackend = ParserBackend.REGEX,
        top_k: Optional[int] = None,
    ) -> CVESemanticAlignmentResult:
        """Run semantic alignment for existing mined candidates only."""
        selected_candidates = self._select_candidates(mining_result.candidates, top_k=top_k)
        diagnostics = list(mining_result.diagnostics)

        if not selected_candidates:
            diagnostics.append("No mined candidates were available for CVE semantic alignment.")
            return CVESemanticAlignmentResult(
                cve_id=record.cve_id,
                alignments=[],
                diagnostics=diagnostics,
                metadata={
                    "parser_backend": parser_backend.value,
                    "candidate_count": 0,
                    "used_patch_context": bool(patch_extraction and patch_extraction.patches),
                },
            )

        repo_root = Path(repo_path or mining_result.repo_path).expanduser().resolve()
        source_files = sorted(self._relevant_source_files(selected_candidates, mining_result, patch_extraction))
        program = self.parser.parse_repository(
            repo_root,
            preferred_backend=parser_backend,
            source_files=source_files or None,
        )
        program_index = self.parser.build_index(program)
        context_extractor = SourceContextExtractor(program_index)

        alignments: list[CVECandidateSemanticAlignment] = []
        for candidate in selected_candidates:
            candidate_source_code = self._candidate_source_code(candidate, context_extractor, program_index)
            surrounding_function_code = self._surrounding_function_code(candidate, context_extractor, program_index)
            dependency_summary = self._dependency_summary(candidate, mining_result)
            patch_diff = self._patch_context_for_candidate(candidate, patch_extraction)

            judgment = self.semantic_disambiguator.align_cve_candidate(
                cve_id=record.cve_id,
                cve_description=record.description,
                candidate=candidate,
                candidate_source_code=candidate_source_code,
                surrounding_function_code=surrounding_function_code,
                dependency_summary=dependency_summary,
                patch_diff=patch_diff,
                heuristic_label=candidate.label,
            )
            alignments.append(
                CVECandidateSemanticAlignment(
                    candidate_rank=candidate.rank,
                    location=candidate.location,
                    heuristic_label=candidate.label,
                    label=CandidateLabel(judgment.verdict),
                    confidence=judgment.confidence.value if judgment.confidence is not None else candidate.score,
                    reasoning=judgment.rationale or candidate.explanation,
                    candidate_origin=_string_feature(candidate.features, "candidate_origin"),
                    llm_judgment=judgment,
                    metadata={
                        "candidate_score": candidate.score,
                        "parser_backend": parser_backend.value,
                        "matched_bug_pattern": _string_feature(candidate.features, "matched_bug_pattern"),
                        "used_patch_context": bool(patch_diff),
                    },
                )
            )

        diagnostics.extend(program.approximations)
        diagnostics.extend(
            diagnostic.message
            for diagnostic in program.diagnostics
            if diagnostic.message not in diagnostics
        )
        return CVESemanticAlignmentResult(
            cve_id=record.cve_id,
            alignments=alignments,
            diagnostics=diagnostics,
            metadata={
                "parser_backend": program.backend.value,
                "parsed_file_count": len(program.files),
                "candidate_count": len(selected_candidates),
                "used_patch_context": bool(patch_extraction and patch_extraction.patches),
                "repo_path": repo_root.as_posix(),
            },
        )

    @staticmethod
    def _select_candidates(
        candidates: list[RootCauseCandidate],
        *,
        top_k: Optional[int],
    ) -> list[RootCauseCandidate]:
        ranked = sorted(
            candidates,
            key=lambda candidate: (
                candidate.rank if candidate.rank is not None else 10**9,
                -candidate.score,
                candidate.location.file,
                candidate.location.line,
            ),
        )
        return ranked[:top_k] if top_k is not None else ranked

    @staticmethod
    def _relevant_source_files(
        candidates: list[RootCauseCandidate],
        mining_result: CVERootCauseMiningResult,
        patch_extraction: Optional[CVEPatchExtraction],
    ) -> set[str]:
        files = {candidate.location.file for candidate in candidates}
        files.update(anchor.file for anchor in mining_result.anchors)
        if patch_extraction is not None:
            files.update(patch_extraction.modified_files)
        return {file_path for file_path in files if file_path}

    def _candidate_source_code(
        self,
        candidate: RootCauseCandidate,
        context_extractor: SourceContextExtractor,
        program_index: ProgramIndex,
    ) -> str:
        statement = self._locate_statement(candidate, program_index)
        if statement is not None:
            return context_extractor.get_statement_text(statement)
        line = context_extractor.read_line(candidate.location)
        return line or candidate.location.snippet or ""

    def _surrounding_function_code(
        self,
        candidate: RootCauseCandidate,
        context_extractor: SourceContextExtractor,
        program_index: ProgramIndex,
    ) -> str:
        statement = self._locate_statement(candidate, program_index)
        function = None
        if statement is not None:
            function = program_index.function_for_statement(statement.statement_id)
        if function is None:
            function = context_extractor.find_enclosing_function(candidate.location)
        if function is None:
            context = context_extractor.get_context(candidate.location, before=4, after=4)
            return "\n".join(f"{line_no}: {line}" for line_no, line in context)

        absolute_path = Path(program_index.program.repo_path) / function.location.file
        try:
            lines = absolute_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            self.logger.debug("Failed to read function context from %s", absolute_path)
            context = context_extractor.get_context(candidate.location, before=4, after=4)
            return "\n".join(f"{line_no}: {line}" for line_no, line in context)

        start = function.location.line
        end = function.end_line
        if end - start + 1 > _MAX_FUNCTION_CONTEXT_LINES:
            half_window = _MAX_FUNCTION_CONTEXT_LINES // 2
            start = max(function.location.line, candidate.location.line - half_window)
            end = min(function.end_line, start + _MAX_FUNCTION_CONTEXT_LINES - 1)

        return "\n".join(
            f"{line_no}: {lines[line_no - 1].rstrip()}"
            for line_no in range(start, min(end, len(lines)) + 1)
        )

    def _dependency_summary(
        self,
        candidate: RootCauseCandidate,
        mining_result: CVERootCauseMiningResult,
    ) -> str:
        summary_lines = [
            f"Heuristic label: {candidate.label.value}.",
            f"Heuristic explanation: {candidate.explanation}",
        ]
        if candidate.rank is not None:
            summary_lines.append(f"Candidate rank: {candidate.rank}.")
        tracked_entities = candidate.features.get("tracked_entities")
        if isinstance(tracked_entities, list) and tracked_entities:
            summary_lines.append(f"Tracked entities: {', '.join(str(entity) for entity in tracked_entities[:5])}.")
        matched_bug_pattern = _string_feature(candidate.features, "matched_bug_pattern")
        if matched_bug_pattern:
            summary_lines.append(f"Matched bug pattern: {matched_bug_pattern}.")
        candidate_origin = _string_feature(candidate.features, "candidate_origin")
        if candidate_origin:
            summary_lines.append(f"Candidate origin: {candidate_origin}.")
        if candidate.features.get("defines_value_later_fixed"):
            summary_lines.append("The candidate defines a value later corrected or validated by the patch.")
        if candidate.features.get("missing_check_replaced_by_patch"):
            summary_lines.append("The patch appears to replace or compensate for a missing check near this candidate.")
        if candidate.features.get("incorrect_computation_replaced_by_patch"):
            summary_lines.append("The patch appears to replace an incorrect computation downstream of this candidate.")

        edge_summaries = self._edge_summaries_for_candidate(candidate, mining_result)
        summary_lines.extend(edge_summaries)
        return "\n".join(summary_lines)

    def _edge_summaries_for_candidate(
        self,
        candidate: RootCauseCandidate,
        mining_result: CVERootCauseMiningResult,
    ) -> list[str]:
        lines: list[str] = []
        for slice_result in mining_result.slices:
            matched_nodes = self._matching_slice_nodes(candidate, slice_result.nodes)
            if not matched_nodes:
                continue
            node_ids = {node.node_id for node in matched_nodes}
            related_edges = [
                edge
                for edge in slice_result.edges
                if edge.source_node_id in node_ids or edge.target_node_id in node_ids
            ]
            node_lookup = {node.node_id: node for node in slice_result.nodes}
            for edge in related_edges:
                lines.append(self._render_edge_summary(edge, node_lookup))
                if len(lines) >= _MAX_EDGE_SUMMARY_LINES:
                    return lines
        return lines

    @staticmethod
    def _matching_slice_nodes(
        candidate: RootCauseCandidate,
        nodes: list[SliceNode],
    ) -> list[SliceNode]:
        statement_id = candidate.metadata.get("statement_id")
        if isinstance(statement_id, str):
            matches = [node for node in nodes if node.statement_id == statement_id]
            if matches:
                return matches
        return [
            node
            for node in nodes
            if node.location.file == candidate.location.file and node.location.line == candidate.location.line
        ]

    @staticmethod
    def _render_edge_summary(
        edge: DependencyEdge,
        node_lookup: dict[str, SliceNode],
    ) -> str:
        source_node = node_lookup.get(edge.source_node_id)
        target_node = node_lookup.get(edge.target_node_id)
        source_label = _format_node_label(source_node)
        target_label = _format_node_label(target_node)
        entity_text = f" via {edge.entity}" if edge.entity else ""
        explanation_text = f" ({edge.explanation})" if edge.explanation else ""
        return (
            f"Dependency: {source_label} -> {target_label} "
            f"[{edge.relation.value}{entity_text}]{explanation_text}."
        )

    def _patch_context_for_candidate(
        self,
        candidate: RootCauseCandidate,
        patch_extraction: Optional[CVEPatchExtraction],
    ) -> Optional[str]:
        if patch_extraction is None or not patch_extraction.patches:
            return None

        patch_files = [
            patch_file
            for patch_file in patch_extraction.patches
            if patch_file.file == candidate.location.file
        ]
        if not patch_files:
            patch_files = patch_extraction.patches[:1]

        rendered_chunks: list[str] = []
        for patch_file in patch_files[:1]:
            rendered_chunks.append(f"--- a/{patch_file.old_path or patch_file.file}")
            rendered_chunks.append(f"+++ b/{patch_file.new_path or patch_file.file}")
            hunks = self._select_patch_hunks_for_candidate(candidate, patch_file.hunks)
            for hunk in hunks[:_MAX_PATCH_HUNKS]:
                header = f"@@ -{hunk.old_start},{hunk.old_count} +{hunk.new_start},{hunk.new_count} @@"
                if hunk.function:
                    header += f" {hunk.function}"
                rendered_chunks.append(header)
                for statement in hunk.removed_statements[:_MAX_PATCH_STATEMENTS_PER_HUNK]:
                    rendered_chunks.append(f"-{statement}")
                for statement in hunk.added_statements[:_MAX_PATCH_STATEMENTS_PER_HUNK]:
                    rendered_chunks.append(f"+{statement}")
        return "\n".join(rendered_chunks) if rendered_chunks else None

    @staticmethod
    def _select_patch_hunks_for_candidate(candidate: RootCauseCandidate, hunks: list[object]) -> list[object]:
        function_name = candidate.location.function
        matching_hunks = [
            hunk
            for hunk in hunks
            if function_name and getattr(hunk, "function", None) == function_name
        ]
        if matching_hunks:
            return matching_hunks
        return list(hunks)

    @staticmethod
    def _locate_statement(
        candidate: RootCauseCandidate,
        program_index: ProgramIndex,
    ) -> Optional[object]:
        statement_id = candidate.metadata.get("statement_id")
        if isinstance(statement_id, str):
            statement = program_index.get_statement(statement_id)
            if statement is not None:
                return statement
        return program_index.find_nearest_statement(candidate.location, max_line_distance=1)


def _format_node_label(node: Optional[SliceNode]) -> str:
    if node is None:
        return "unknown"
    return f"{node.location.file}:{node.location.line}"


def _string_feature(features: dict[str, object], key: str) -> Optional[str]:
    value = features.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None
