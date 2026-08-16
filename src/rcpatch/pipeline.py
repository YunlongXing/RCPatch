"""End-to-end orchestration and artifact export helpers for RCPatch."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional

from rcpatch.chains import CausalityChainConstructor, ChainTextFormatter
from rcpatch.config import load_bug_spec_payload
from rcpatch.errors import RCPatchError, ModelSerializationError
from rcpatch.ingestion import BugIngestionService
from rcpatch.interfaces import (
    BugSpecLoader,
    CandidateRanker,
    ChainBuilder,
    PatchRefiner,
    RepositoryParser,
    SemanticInterpreter,
    SliceExtractor,
)
from rcpatch.llm import SemanticDisambiguator, load_patch_diff_text
from rcpatch.logging_utils import get_logger
from rcpatch.manifest import build_run_manifest
from rcpatch.models import (
    AnalysisResult,
    BackwardSlice,
    BugReport,
    CausalityChain,
    ConfidenceScore,
    LLMJudgment,
    PatchIntent,
    ProgramAbstraction,
    RootCauseCandidate,
    SourceLocation,
)
from rcpatch.patch_analysis import PatchAwareAnalysisResult, PatchAwareAnalyzer
from rcpatch.ranking import RootCauseCandidateExtractor
from rcpatch.reporting import render_html_report
from rcpatch.source import ProgramIndex, SourceProjectParser
from rcpatch.slicing import HybridBackwardSlicer


@dataclass
class PipelineArtifacts:
    """Container for intermediate and final pipeline outputs."""

    bug_report: BugReport
    program: Optional[ProgramAbstraction] = None
    program_index: Optional[ProgramIndex] = None
    backward_slice: Optional[BackwardSlice] = None
    candidates: list[RootCauseCandidate] = field(default_factory=list)
    chains: list[CausalityChain] = field(default_factory=list)
    analysis_result: Optional[AnalysisResult] = None
    patch_analysis_result: Optional[PatchAwareAnalysisResult] = None
    llm_judgments: list[LLMJudgment] = field(default_factory=list)


class RCPatchPipeline:
    """Coordinate ingestion, parsing, slicing, ranking, and explanation."""

    def __init__(
        self,
        *,
        ingestion_service: Optional[BugSpecLoader] = None,
        source_parser: Optional[RepositoryParser] = None,
        slicer: Optional[SliceExtractor] = None,
        candidate_extractor: Optional[CandidateRanker] = None,
        chain_constructor: Optional[ChainBuilder] = None,
        patch_analyzer: Optional[PatchRefiner] = None,
        semantic_disambiguator: Optional[SemanticInterpreter] = None,
        chain_formatter: Optional[ChainTextFormatter] = None,
    ) -> None:
        self.ingestion_service = ingestion_service or BugIngestionService()
        self.source_parser = source_parser or SourceProjectParser()
        self.slicer = slicer or HybridBackwardSlicer()
        self.candidate_extractor = candidate_extractor or RootCauseCandidateExtractor()
        self.chain_constructor = chain_constructor or CausalityChainConstructor()
        self.patch_analyzer = patch_analyzer or PatchAwareAnalyzer()
        self.semantic_disambiguator = semantic_disambiguator
        self.chain_formatter = chain_formatter or ChainTextFormatter()
        self.logger = get_logger(__name__)

    def ingest(
        self,
        spec_path: str | Path,
        *,
        config_path: Optional[str | Path] = None,
        config_overrides: Optional[Mapping[str, Any]] = None,
    ) -> BugReport:
        """Load a bug spec, merge config overrides, and normalize it."""
        spec_file = Path(spec_path).expanduser().resolve()
        self.logger.info("Ingesting bug specification from %s", spec_file)
        payload = load_bug_spec_payload(spec_file, config_path=config_path, config_overrides=config_overrides)
        bug_report = self.ingestion_service.load_from_dict(payload, spec_path=spec_file)
        self.logger.info(
            "Loaded bug report %s for repository %s",
            bug_report.bug_id,
            bug_report.repo_path,
        )
        return bug_report

    def run_ranking(
        self,
        spec_path: str | Path,
        *,
        config_path: Optional[str | Path] = None,
        config_overrides: Optional[Mapping[str, Any]] = None,
    ) -> PipelineArtifacts:
        """Run ingestion, source parsing, slicing, and candidate ranking."""
        bug_report = self.ingest(spec_path, config_path=config_path, config_overrides=config_overrides)
        self.logger.info(
            "Parsing repository for %s with %s backend",
            bug_report.bug_id,
            bug_report.analysis_config.parser_backend.value,
        )
        program = self.source_parser.parse_repository(
            bug_report.repo_path,
            preferred_backend=bug_report.analysis_config.parser_backend,
        )
        program_index = self.source_parser.build_index(program)
        self.logger.info(
            "Parsed repository into %d files and %d functions",
            len(program.files),
            len(program.functions),
        )
        slicer = self.slicer
        if isinstance(slicer, HybridBackwardSlicer):
            slicer.max_interprocedural_hops = bug_report.analysis_config.max_interprocedural_hops
        backward_slice = slicer.slice_from_trigger(program_index, bug_report.trigger_point)
        self.logger.info(
            "Extracted backward slice with %d nodes and %d edges",
            len(backward_slice.nodes),
            len(backward_slice.edges),
        )
        candidates = self.candidate_extractor.extract_candidates(
            bug_report,
            backward_slice,
            top_k=bug_report.analysis_config.top_k_candidates,
        )
        self.logger.info("Ranked %d candidate locations", len(candidates))
        return PipelineArtifacts(
            bug_report=bug_report,
            program=program,
            program_index=program_index,
            backward_slice=backward_slice,
            candidates=candidates,
        )

    def run_analysis(
        self,
        spec_path: str | Path,
        *,
        config_path: Optional[str | Path] = None,
        config_overrides: Optional[Mapping[str, Any]] = None,
    ) -> PipelineArtifacts:
        """Run the full RCPatch pipeline and produce an AnalysisResult."""
        artifacts = self.run_ranking(
            spec_path,
            config_path=config_path,
            config_overrides=config_overrides,
        )
        if artifacts.backward_slice is None:
            raise RCPatchError("Cannot construct chains without a backward slice.")

        self.logger.info("Constructing causality chains for %s", artifacts.bug_report.bug_id)
        chains = self.chain_constructor.construct_chains(
            artifacts.bug_report,
            artifacts.candidates,
            artifacts.backward_slice,
            max_chains=artifacts.bug_report.analysis_config.max_chain_paths,
        )
        artifacts.chains = chains
        self.logger.info("Constructed %d causality chains", len(chains))

        if (
            artifacts.bug_report.analysis_config.enable_patch_analysis
            and artifacts.bug_report.patch_evidence is not None
        ):
            self.logger.info("Applying patch-aware refinement for %s", artifacts.bug_report.bug_id)
            patch_result = self.patch_analyzer.analyze(
                artifacts.bug_report,
                program_index=artifacts.program_index,
                candidates=artifacts.candidates,
                chains=artifacts.chains,
            )
            artifacts.patch_analysis_result = patch_result
            artifacts.candidates = list(patch_result.candidates)
            artifacts.chains = list(patch_result.chains)
            if patch_result.patch_evidence is not None:
                artifacts.bug_report = artifacts.bug_report.model_copy(
                    update={"patch_evidence": patch_result.patch_evidence}
                )
            self.logger.info(
                "Patch-aware refinement updated %d candidates and %d chains",
                len(artifacts.candidates),
                len(artifacts.chains),
            )

        if artifacts.bug_report.analysis_config.enable_llm:
            self.logger.info("Applying optional semantic disambiguation for %s", artifacts.bug_report.bug_id)
            artifacts = self._apply_llm_disambiguation(artifacts)

        artifacts.analysis_result = self._build_analysis_result(artifacts)
        self.logger.info("Completed analysis for %s", artifacts.bug_report.bug_id)
        return artifacts

    def format_result_summary(
        self,
        result: AnalysisResult,
        *,
        max_candidates: int = 3,
        max_chains: int = 2,
    ) -> str:
        """Render a concise terminal-friendly summary for an analysis result."""
        lines = [f"RCPatch analysis for {result.bug_id}"]
        trigger = result.trigger_point
        trigger_text = f"Trigger: {trigger.location.file}:{trigger.location.line}"
        if trigger.location.function:
            trigger_text += f" in {trigger.location.function}"
        trigger_text += f" [{trigger.type.value}]"
        if trigger.failing_operation:
            trigger_text += f" op={trigger.failing_operation}"
        lines.append(trigger_text)

        if result.summary:
            lines.append(f"Summary: {result.summary}")

        if result.root_cause_candidates:
            lines.append("")
            lines.append("Top candidates:")
            for candidate in result.root_cause_candidates[:max_candidates]:
                label = candidate.label.value
                candidate_line = (
                    f"  #{candidate.rank or '?'} {candidate.location.file}:{candidate.location.line}"
                    f" ({label}, score={candidate.score:.2f})"
                )
                if candidate.location.function:
                    candidate_line += f" in {candidate.location.function}"
                lines.append(candidate_line)
                lines.append(f"    {candidate.explanation}")

        if result.chains:
            lines.append("")
            lines.append("Top chains:")
            chain_text = self.chain_formatter.format_chains(result.chains[:max_chains])
            lines.extend(f"  {line}" if line else "" for line in chain_text.splitlines())

        if result.patch_evidence and result.patch_evidence.patch_intent is not None:
            lines.append("")
            lines.append(f"Patch intent: {result.patch_evidence.patch_intent.value}")

        if result.limitations:
            lines.append("")
            lines.append("Limitations:")
            for limitation in result.limitations[:5]:
                lines.append(f"  - {limitation}")

        return "\n".join(lines)

    def _apply_llm_disambiguation(self, artifacts: PipelineArtifacts) -> PipelineArtifacts:
        disambiguator = self.semantic_disambiguator or SemanticDisambiguator()
        if artifacts.program_index is None:
            return artifacts

        chain_by_rank = {
            chain.root_cause_rank: chain
            for chain in artifacts.chains
            if chain.root_cause_rank is not None
        }
        patch_diff = None
        if artifacts.bug_report.patch_evidence is not None:
            patch_diff = load_patch_diff_text(artifacts.bug_report.patch_evidence)

        updated_candidates: list[RootCauseCandidate] = []
        llm_judgments = list(artifacts.llm_judgments)
        semantic_limit = min(max(artifacts.bug_report.analysis_config.top_k_candidates, 1), 3)

        for candidate in artifacts.candidates:
            if candidate.rank is None or candidate.rank > semantic_limit:
                updated_candidates.append(candidate)
                continue

            candidate_source = self._extract_candidate_source(candidate, artifacts.program_index)
            function_source = self._extract_function_source(candidate.location, artifacts.program_index, artifacts.bug_report.repo_path)
            dependency_summary = chain_by_rank.get(candidate.rank).summary if candidate.rank in chain_by_rank else candidate.explanation
            judgment = disambiguator.disambiguate_candidate_label(
                trigger_point=artifacts.bug_report.trigger_point,
                candidate=candidate,
                candidate_source_code=candidate_source,
                surrounding_function_code=function_source,
                dependency_summary=dependency_summary,
                patch_diff=patch_diff,
                heuristic_label=candidate.label,
            )
            llm_judgments.append(judgment)
            updated_candidates.append(
                candidate.model_copy(
                    update={
                        "llm_judgments": list(candidate.llm_judgments) + [judgment],
                        "metadata": {**candidate.metadata, "semantic_verdict": judgment.verdict},
                    }
                )
            )

        updated_bug_report = artifacts.bug_report
        if updated_bug_report.patch_evidence is not None and patch_diff:
            patch_judgment = disambiguator.infer_patch_intent(
                patch_evidence=updated_bug_report.patch_evidence,
                diff_text=patch_diff,
                commit_message=updated_bug_report.patch_evidence.commit_message,
                issue_description=updated_bug_report.patch_evidence.issue_text or updated_bug_report.issue_text,
                heuristic_intent=updated_bug_report.patch_evidence.patch_intent,
            )
            llm_judgments.append(patch_judgment)
            new_patch_intent = updated_bug_report.patch_evidence.patch_intent
            if new_patch_intent in {None, PatchIntent.UNKNOWN}:
                try:
                    new_patch_intent = PatchIntent(patch_judgment.verdict)
                except ValueError:
                    new_patch_intent = updated_bug_report.patch_evidence.patch_intent
            updated_bug_report = updated_bug_report.model_copy(
                update={
                    "patch_evidence": updated_bug_report.patch_evidence.model_copy(
                        update={
                            "llm_judgments": list(updated_bug_report.patch_evidence.llm_judgments) + [patch_judgment],
                            "patch_intent": new_patch_intent,
                        }
                    )
                }
            )

        artifacts.bug_report = updated_bug_report
        artifacts.candidates = updated_candidates
        artifacts.llm_judgments = llm_judgments
        return artifacts

    def _build_analysis_result(self, artifacts: PipelineArtifacts) -> AnalysisResult:
        limitations = self._collect_limitations(artifacts)
        summary = self._build_summary(artifacts)
        confidence = self._build_overall_confidence(artifacts)
        metadata = {
            "parser_backend": artifacts.program.backend.value if artifacts.program is not None else None,
            "program_file_count": len(artifacts.program.files) if artifacts.program is not None else 0,
            "program_function_count": len(artifacts.program.functions) if artifacts.program is not None else 0,
            "slice_node_count": len(artifacts.backward_slice.nodes) if artifacts.backward_slice is not None else 0,
            "slice_edge_count": len(artifacts.backward_slice.edges) if artifacts.backward_slice is not None else 0,
            "patch_diagnostics": list(artifacts.patch_analysis_result.diagnostics)
            if artifacts.patch_analysis_result is not None
            else [],
        }

        return AnalysisResult(
            bug_id=artifacts.bug_report.bug_id,
            trigger_point=artifacts.bug_report.trigger_point,
            root_cause_candidates=artifacts.candidates,
            chains=artifacts.chains,
            config=artifacts.bug_report.analysis_config,
            runtime_evidence=artifacts.bug_report.runtime_evidence,
            patch_evidence=artifacts.bug_report.patch_evidence,
            summary=summary,
            limitations=limitations,
            llm_judgments=artifacts.llm_judgments,
            confidence=confidence,
            metadata=metadata,
        )

    def _build_summary(self, artifacts: PipelineArtifacts) -> Optional[str]:
        if artifacts.chains:
            top_chain = artifacts.chains[0]
            if artifacts.candidates:
                top_candidate = artifacts.candidates[0]
                return (
                    f"Top candidate #{top_candidate.rank or 1} at "
                    f"{top_candidate.location.file}:{top_candidate.location.line} "
                    f"flows to the trigger through chain #{top_chain.rank or 1}: {top_chain.summary}"
                )
            return top_chain.summary

        if artifacts.candidates:
            top_candidate = artifacts.candidates[0]
            return (
                f"Top candidate #{top_candidate.rank or 1} is "
                f"{top_candidate.location.file}:{top_candidate.location.line} "
                f"({top_candidate.label.value}): {top_candidate.explanation}"
            )
        return None

    def _build_overall_confidence(self, artifacts: PipelineArtifacts) -> ConfidenceScore:
        candidate_score = artifacts.candidates[0].score if artifacts.candidates else 0.0
        chain_score = artifacts.chains[0].score if artifacts.chains else 0.0
        runtime_bonus = 0.1 if artifacts.bug_report.runtime_evidence and artifacts.bug_report.runtime_evidence.stack_frames else 0.0
        patch_bonus = 0.05 if artifacts.bug_report.patch_evidence and artifacts.bug_report.patch_evidence.changed_locations else 0.0
        llm_bonus = 0.03 if artifacts.llm_judgments else 0.0
        components = {
            "top_candidate": 0.55 * candidate_score,
            "top_chain": 0.25 * chain_score,
            "runtime_bonus": runtime_bonus,
            "patch_bonus": patch_bonus,
            "llm_bonus": llm_bonus,
        }
        score = max(0.0, min(sum(components.values()), 1.0))
        return ConfidenceScore(
            value=score,
            rationale="Overall confidence combines the strongest candidate, best chain, and supporting evidence coverage.",
            method="analysis_rollup_v1",
            components=components,
        )

    def _collect_limitations(self, artifacts: PipelineArtifacts) -> list[str]:
        limitations: list[str] = []
        if artifacts.program is not None:
            limitations.extend(artifacts.program.approximations)
            limitations.extend(
                diagnostic.message for diagnostic in artifacts.program.diagnostics[:5]
            )
        if artifacts.backward_slice is not None:
            limitations.extend(artifacts.backward_slice.approximations)
            limitations.extend(artifacts.backward_slice.diagnostics)
        if artifacts.patch_analysis_result is not None:
            limitations.extend(artifacts.patch_analysis_result.diagnostics)
        seen: set[str] = set()
        ordered: list[str] = []
        for limitation in limitations:
            normalized = limitation.strip()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            ordered.append(normalized)
        return ordered

    def _extract_candidate_source(self, candidate: RootCauseCandidate, program_index: ProgramIndex) -> str:
        statement_id = candidate.metadata.get("statement_id")
        if isinstance(statement_id, str):
            statement = program_index.get_statement(statement_id)
            if statement is not None:
                return statement.text
        statement = program_index.find_nearest_statement(candidate.location)
        return statement.text if statement is not None else (candidate.location.snippet or candidate.explanation)

    def _extract_function_source(
        self,
        location: SourceLocation,
        program_index: ProgramIndex,
        repo_path: str,
    ) -> str:
        function = program_index.find_enclosing_function(location)
        if function is None:
            return location.snippet or ""

        source_path = Path(repo_path) / function.location.file
        try:
            lines = source_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return "\n".join(statement.text for statement in function.statements)

        start_index = max(function.location.line - 1, 0)
        end_index = min(function.end_line, len(lines))
        if start_index >= end_index:
            return "\n".join(statement.text for statement in function.statements)
        return "\n".join(lines[start_index:end_index]).strip()


class PipelineOutputManager:
    """Manage output directories and JSON/text artifact export."""

    def __init__(self, *, default_root: Optional[str | Path] = None) -> None:
        self.default_root = Path(default_root).expanduser().resolve() if default_root is not None else Path.cwd() / "rcpatch_output"
        self.logger = get_logger(__name__)

    def resolve_output_dir(
        self,
        *,
        bug_id: str,
        command_name: str,
        requested_dir: Optional[str | Path] = None,
        ) -> Path:
        """Create and return the output directory for a command."""
        if requested_dir is not None:
            output_dir = Path(requested_dir).expanduser().resolve()
        else:
            output_dir = (self.default_root / command_name / bug_id).resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        self.logger.info("Using output directory %s", output_dir)
        return output_dir

    def export_ingest(self, output_dir: str | Path, bug_report: BugReport) -> dict[str, Path]:
        """Export a normalized bug report."""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        exported = {
            "normalized_bug_report": bug_report.to_json_file(output_path / "normalized_bug_report.json"),
        }
        exported["run_manifest"] = build_run_manifest(
            bug_report=bug_report,
            command="ingest",
            artifact_paths=exported,
        ).to_json_file(output_path / "run_manifest.json")
        return exported

    def export_ranking(
        self,
        output_dir: str | Path,
        artifacts: PipelineArtifacts,
        *,
        command_name: str = "rank",
    ) -> dict[str, Path]:
        """Export ranking-stage artifacts."""
        output_path = Path(output_dir)
        exported = self.export_ingest(output_path, artifacts.bug_report)
        if artifacts.backward_slice is not None:
            exported["backward_slice"] = artifacts.backward_slice.to_json_file(output_path / "backward_slice.json")
        exported["ranked_candidates"] = self.write_json(
            output_path / "ranked_candidates.json",
            [candidate.to_dict() for candidate in artifacts.candidates],
        )
        exported["run_manifest"] = build_run_manifest(
            bug_report=artifacts.bug_report,
            command=command_name,
            artifact_paths=exported,
            program=artifacts.program,
            backward_slice=artifacts.backward_slice,
            candidates=artifacts.candidates,
            chains=artifacts.chains,
            analysis_result=artifacts.analysis_result,
        ).to_json_file(output_path / "run_manifest.json")
        return exported

    def export_analysis(
        self,
        output_dir: str | Path,
        artifacts: PipelineArtifacts,
        *,
        include_program: bool = False,
        summary_text: Optional[str] = None,
        command_name: str = "analyze",
    ) -> dict[str, Path]:
        """Export end-to-end analysis artifacts."""
        output_path = Path(output_dir)
        exported = self.export_ranking(output_path, artifacts, command_name=command_name)
        exported["causality_chains"] = self.write_json(
            output_path / "causality_chains.json",
            [chain.to_dict() for chain in artifacts.chains],
        )
        if artifacts.analysis_result is not None:
            exported["analysis_result"] = artifacts.analysis_result.to_json_file(output_path / "analysis_result.json")
            exported["analysis_report_html"] = self.write_text(
                output_path / "analysis_report.html",
                render_html_report(
                    artifacts.analysis_result,
                    repo_path=artifacts.bug_report.repo_path,
                    artifacts={name: path.as_posix() for name, path in exported.items()},
                ),
            )
        if include_program and artifacts.program is not None:
            exported["program_abstraction"] = artifacts.program.to_json_file(output_path / "program_abstraction.json")
        if summary_text:
            exported["summary_text"] = self.write_text(output_path / "analysis_summary.txt", summary_text)
        exported["run_manifest"] = build_run_manifest(
            bug_report=artifacts.bug_report,
            command=command_name,
            artifact_paths=exported,
            program=artifacts.program,
            backward_slice=artifacts.backward_slice,
            candidates=artifacts.candidates,
            chains=artifacts.chains,
            analysis_result=artifacts.analysis_result,
        ).to_json_file(output_path / "run_manifest.json")
        return exported

    def write_json(self, path: str | Path, payload: Any) -> Path:
        """Write a JSON-compatible payload to disk."""
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            output_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        except (OSError, TypeError) as exc:
            raise ModelSerializationError(f"Failed to write JSON artifact {output_path}: {exc}") from exc
        return output_path

    def write_text(self, path: str | Path, content: str) -> Path:
        """Write a UTF-8 text artifact to disk."""
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            output_path.write_text(content, encoding="utf-8")
        except OSError as exc:
            raise ModelSerializationError(f"Failed to write text artifact {output_path}: {exc}") from exc
        return output_path


# Backward-compatible public name retained for older BugRC-based imports.
BugRCPipeline = RCPatchPipeline
