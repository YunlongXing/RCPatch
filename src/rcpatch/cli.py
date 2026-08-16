"""Argparse-based command-line interface for RCPatch."""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Optional

from rcpatch.config import build_analysis_config_overrides
from rcpatch.errors import RCPatchError
from rcpatch.llm import FileLLMCache, LLMClient, OpenAICompatibleProvider, SemanticDisambiguator
from rcpatch.logging_utils import configure_logging, get_logger
from rcpatch.models import AnalysisResult, BugReport, ParserBackend, RootCauseCandidate
from rcpatch.patch_generation import PatchSuggestionGenerator
from rcpatch.pipeline import RCPatchPipeline, PipelineOutputManager
from rcpatch.validation import PatchValidationHarness, ValidationCommand

EXAMPLE_COMMANDS = """Examples:
  rcpatch ingest bug.json --output-dir out/ingest
  rcpatch analyze bug.json --parser-backend regex --patch-aware --output-dir out/analyze
  rcpatch analyze bug.json --cve-pattern-library pattern_library_v4/cve_pattern_library.v4.clean.json --output-dir out/analyze
  rcpatch analyze bug.json --ranker-calibration arvo_ranker_calibration.json --project-prior project_prior.json --output-dir out/analyze
  rcpatch rank bug.json --config analysis_overrides.json --top-k 3 --output-dir out/rank
  rcpatch explain bug.json --output-dir out/explain
  rcpatch explain --result-json out/analyze/analysis_result.json
  rcpatch export bug.json --llm --llm-model gpt-4.1-mini --output-dir out/export
  rcpatch suggest-patch bug.json --output-dir out/patches
  rcpatch validate-patch --repo /path/to/repo --patch fix.diff --build-cmd "make -j2" --output-dir out/validate
"""


def build_parser() -> argparse.ArgumentParser:
    """Create the top-level CLI parser."""
    parser = argparse.ArgumentParser(
        prog="rcpatch",
        description="RCPatch: root-cause-guided patch generation for C/C++ vulnerabilities",
        epilog=EXAMPLE_COMMANDS,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        help="Logging level for terminal output.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    ingest_parser = subparsers.add_parser("ingest", help="Load and normalize a bug specification.")
    _add_spec_arguments(ingest_parser)
    ingest_parser.set_defaults(handler=_handle_ingest)

    analyze_parser = subparsers.add_parser("analyze", help="Run the full RCPatch analysis pipeline.")
    _add_spec_arguments(analyze_parser)
    _add_analysis_arguments(analyze_parser, include_llm=True)
    analyze_parser.set_defaults(handler=_handle_analyze)

    rank_parser = subparsers.add_parser("rank", help="Run parsing, slicing, and candidate ranking.")
    _add_spec_arguments(rank_parser)
    _add_analysis_arguments(rank_parser, include_llm=False)
    rank_parser.set_defaults(handler=_handle_rank)

    explain_parser = subparsers.add_parser("explain", help="Print a readable explanation of an analysis result.")
    _add_spec_arguments(explain_parser, require_spec=False)
    explain_parser.add_argument(
        "--result-json",
        dest="result_json",
        help="Optional existing analysis_result.json to explain without rerunning the pipeline.",
    )
    _add_analysis_arguments(explain_parser, include_llm=True)
    explain_parser.set_defaults(handler=_handle_explain)

    export_parser = subparsers.add_parser("export", help="Run the full pipeline and export all JSON artifacts.")
    _add_spec_arguments(export_parser)
    _add_analysis_arguments(export_parser, include_llm=True)
    export_parser.set_defaults(handler=_handle_export)

    patch_parser = subparsers.add_parser("suggest-patch", help="Generate conservative patch suggestions from RCPatch analysis.")
    _add_spec_arguments(patch_parser, require_spec=False)
    patch_parser.add_argument("--result-json", help="Existing analysis_result.json to avoid rerunning analysis.")
    patch_parser.add_argument("--repo", help="Repository path required when using --result-json outside a bug spec.")
    _add_analysis_arguments(patch_parser, include_llm=True)
    patch_parser.set_defaults(handler=_handle_suggest_patch)

    validate_parser = subparsers.add_parser("validate-patch", help="Validate a patch with build/reproducer commands.")
    validate_parser.add_argument("--repo", required=True, help="Repository root to validate.")
    validate_parser.add_argument("--patch", help="Patch file to apply in a temporary copy before validation.")
    validate_parser.add_argument("--build-cmd", help="Optional build command.")
    validate_parser.add_argument("--reproduce-cmd", help="Optional reproducer command.")
    validate_parser.add_argument(
        "--validation-cmd",
        action="append",
        default=[],
        help="Additional validation command. Use NAME=COMMAND or just COMMAND.",
    )
    validate_parser.add_argument("--timeout", type=int, default=30, help="Per-command timeout in seconds.")
    validate_parser.add_argument(
        "--existing-tree",
        action="store_true",
        help="Run commands directly in --repo instead of applying --patch in a temporary copy.",
    )
    validate_parser.add_argument(
        "--keep-worktree",
        action="store_true",
        help="Keep the temporary validation copy for debugging.",
    )
    validate_parser.add_argument("--output-dir", help="Directory where validation JSON should be written.")
    validate_parser.set_defaults(handler=_handle_validate_patch)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(getattr(logging, str(args.log_level).upper(), logging.INFO))
    logger = get_logger(__name__)

    try:
        return int(args.handler(args))
    except RCPatchError as exc:
        logger.error("%s", exc)
        return 1
    except Exception as exc:  # pragma: no cover - defensive logging path
        if logger.isEnabledFor(logging.DEBUG):
            logger.exception("Unhandled RCPatch CLI failure: %s", exc)
        else:
            logger.error("Unhandled RCPatch CLI failure: %s", exc)
        return 1


def _handle_ingest(args: argparse.Namespace) -> int:
    pipeline = RCPatchPipeline()
    output_manager = PipelineOutputManager()
    bug_report = pipeline.ingest(
        args.spec,
        config_path=args.config_path,
        config_overrides=_config_overrides_from_args(args, include_llm=False),
    )
    output_dir = output_manager.resolve_output_dir(
        bug_id=bug_report.bug_id,
        command_name="ingest",
        requested_dir=args.output_dir,
    )
    exported = output_manager.export_ingest(output_dir, bug_report)
    print(f"Normalized bug report written to {exported['normalized_bug_report']}")
    print(_format_trigger_summary(bug_report))
    return 0


def _handle_rank(args: argparse.Namespace) -> int:
    pipeline = RCPatchPipeline()
    output_manager = PipelineOutputManager()
    artifacts = pipeline.run_ranking(
        args.spec,
        config_path=args.config_path,
        config_overrides=_config_overrides_from_args(args, include_llm=False),
    )
    output_dir = output_manager.resolve_output_dir(
        bug_id=artifacts.bug_report.bug_id,
        command_name="rank",
        requested_dir=args.output_dir,
    )
    exported = output_manager.export_ranking(output_dir, artifacts)
    print(f"Ranked candidates written to {exported['ranked_candidates']}")
    print(_format_candidate_summary(artifacts.candidates))
    return 0


def _handle_analyze(args: argparse.Namespace) -> int:
    pipeline = _build_pipeline(args)
    output_manager = PipelineOutputManager()
    artifacts = pipeline.run_analysis(
        args.spec,
        config_path=args.config_path,
        config_overrides=_config_overrides_from_args(args, include_llm=True),
    )
    summary_text = pipeline.format_result_summary(artifacts.analysis_result)
    output_dir = output_manager.resolve_output_dir(
        bug_id=artifacts.bug_report.bug_id,
        command_name="analyze",
        requested_dir=args.output_dir,
    )
    exported = output_manager.export_analysis(output_dir, artifacts, summary_text=summary_text, command_name="analyze")
    print(summary_text)
    print("")
    print(f"Analysis result written to {exported['analysis_result']}")
    return 0


def _handle_explain(args: argparse.Namespace) -> int:
    pipeline = _build_pipeline(args)
    if args.result_json:
        result = AnalysisResult.from_json_file(args.result_json)
        summary_text = pipeline.format_result_summary(result)
        output_dir = None
        if args.output_dir:
            output_manager = PipelineOutputManager()
            output_dir = output_manager.resolve_output_dir(
                bug_id=result.bug_id,
                command_name="explain",
                requested_dir=args.output_dir,
            )
            output_manager.write_text(output_dir / "analysis_summary.txt", summary_text)
    else:
        if not args.spec:
            raise RCPatchError("explain requires either a bug spec path or --result-json")
        artifacts = pipeline.run_analysis(
            args.spec,
            config_path=args.config_path,
            config_overrides=_config_overrides_from_args(args, include_llm=True),
        )
        result = artifacts.analysis_result
        summary_text = pipeline.format_result_summary(result)
        output_manager = PipelineOutputManager()
        output_dir = output_manager.resolve_output_dir(
            bug_id=artifacts.bug_report.bug_id,
            command_name="explain",
            requested_dir=args.output_dir,
        )
        output_manager.export_analysis(output_dir, artifacts, summary_text=summary_text, command_name="explain")

    print(summary_text)
    return 0


def _handle_export(args: argparse.Namespace) -> int:
    pipeline = _build_pipeline(args)
    output_manager = PipelineOutputManager()
    artifacts = pipeline.run_analysis(
        args.spec,
        config_path=args.config_path,
        config_overrides=_config_overrides_from_args(args, include_llm=True),
    )
    summary_text = pipeline.format_result_summary(artifacts.analysis_result)
    output_dir = output_manager.resolve_output_dir(
        bug_id=artifacts.bug_report.bug_id,
        command_name="export",
        requested_dir=args.output_dir,
    )
    exported = output_manager.export_analysis(
        output_dir,
        artifacts,
        include_program=True,
        summary_text=summary_text,
        command_name="export",
    )
    print(summary_text)
    print("")
    print(f"Exported {len(exported)} artifacts to {output_dir}")
    return 0


def _handle_suggest_patch(args: argparse.Namespace) -> int:
    pipeline = _build_pipeline(args)
    repo_path = getattr(args, "repo", None)
    if args.result_json:
        result = AnalysisResult.from_json_file(args.result_json)
        if not repo_path:
            raise RCPatchError("suggest-patch with --result-json requires --repo so source context can be read")
        bug_id = result.bug_id
    else:
        if not args.spec:
            raise RCPatchError("suggest-patch requires either a bug spec path or --result-json")
        artifacts = pipeline.run_analysis(
            args.spec,
            config_path=args.config_path,
            config_overrides=_config_overrides_from_args(args, include_llm=True),
        )
        result = artifacts.analysis_result
        repo_path = artifacts.bug_report.repo_path
        bug_id = artifacts.bug_report.bug_id

    suggestions = PatchSuggestionGenerator().generate(result, repo_path=str(repo_path))
    output_manager = PipelineOutputManager()
    output_dir = output_manager.resolve_output_dir(
        bug_id=bug_id,
        command_name="suggest-patch",
        requested_dir=args.output_dir,
    )
    output_path = output_manager.write_json(
        output_dir / "patch_suggestions.json",
        [suggestion.to_dict() for suggestion in suggestions],
    )
    for suggestion in suggestions:
        if suggestion.unified_diff:
            output_manager.write_text(output_dir / f"{suggestion.patch_id}.diff", suggestion.unified_diff)
    print(f"Patch suggestions written to {output_path}")
    for suggestion in suggestions:
        marker = "pseudo" if suggestion.is_pseudo_patch else "apply-ready"
        print(f"  {suggestion.patch_id}: {suggestion.strategy} [{marker}]")
    return 0


def _handle_validate_patch(args: argparse.Namespace) -> int:
    commands = _validation_commands_from_args(args)
    if not commands:
        raise RCPatchError("validate-patch requires at least one --build-cmd, --reproduce-cmd, or --validation-cmd")
    if not args.existing_tree and not args.patch:
        raise RCPatchError("validate-patch requires --patch unless --existing-tree is used")

    harness = PatchValidationHarness()
    if args.existing_tree:
        result = harness.validate_existing_tree(args.repo, commands=commands)
    else:
        result = harness.validate_patch_in_copy(
            args.repo,
            args.patch,
            commands=commands,
            keep_worktree=bool(args.keep_worktree),
        )

    output_manager = PipelineOutputManager()
    output_dir = output_manager.resolve_output_dir(
        bug_id="patch_validation",
        command_name="validate-patch",
        requested_dir=args.output_dir,
    )
    result_path = output_manager.write_json(output_dir / "patch_validation_result.json", result.to_dict())

    status = "PASSED" if result.passed else "FAILED"
    print(f"Patch validation {status}: {result_path}")
    for step in result.steps:
        step_status = "ok" if step.succeeded else "failed"
        if step.timed_out:
            step_status = "timeout"
        print(f"  {step.name}: {step_status} ({step.duration_seconds:.3f}s)")
    if result.diagnostics:
        print("Diagnostics:")
        for diagnostic in result.diagnostics:
            print(f"  - {diagnostic}")
    return 0 if result.passed else 2


def _add_spec_arguments(parser: argparse.ArgumentParser, *, require_spec: bool = True) -> None:
    kwargs = {"help": "Path to the bug JSON specification."}
    if not require_spec:
        kwargs["nargs"] = "?"
    parser.add_argument("spec", **kwargs)
    parser.add_argument(
        "--config",
        dest="config_path",
        help="Optional JSON config overlay. Supports either {\"config\": {...}} or direct AnalysisConfig fields.",
    )
    parser.add_argument(
        "--output-dir",
        help="Directory where RCPatch should write JSON and text artifacts.",
    )


def _add_analysis_arguments(parser: argparse.ArgumentParser, *, include_llm: bool) -> None:
    parser.add_argument(
        "--parser-backend",
        choices=tuple(backend.value for backend in ParserBackend),
        help="Preferred source parser backend.",
    )
    parser.add_argument(
        "--top-k",
        type=int,
        help="Maximum number of ranked candidates to keep.",
    )
    parser.add_argument(
        "--max-chains",
        type=int,
        help="Maximum number of causality chains to keep.",
    )
    parser.add_argument(
        "--patch-aware",
        dest="enable_patch_analysis",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable or disable patch-aware weak supervision.",
    )
    parser.add_argument(
        "--cve-pattern-library",
        dest="cve_pattern_library_path",
        help="Path to a mined CVE pattern library JSON used as weak ranking prior.",
    )
    parser.add_argument(
        "--cve-pattern-prior",
        dest="enable_cve_pattern_prior",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable or disable historical CVE pattern ranking prior.",
    )
    parser.add_argument(
        "--cve-pattern-min-support",
        type=int,
        help="Minimum support count required for a mined CVE pattern to affect ranking.",
    )
    parser.add_argument(
        "--cve-pattern-min-confidence",
        type=float,
        help="Minimum average confidence required for a mined CVE pattern to affect ranking.",
    )
    parser.add_argument(
        "--cve-pattern-weight",
        dest="cve_pattern_prior_weight",
        type=float,
        help="Maximum additive candidate-score contribution from the CVE pattern prior.",
    )
    parser.add_argument(
        "--ranker-calibration",
        dest="ranker_calibration_path",
        help="Optional JSON calibration file for candidate scoring weights, thresholds, and boosts.",
    )
    parser.add_argument(
        "--project-prior",
        dest="project_prior_path",
        help="Optional JSON file with project-specific historical pattern priors.",
    )
    parser.add_argument(
        "--enable-project-prior",
        dest="enable_project_prior",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable or disable project-specific ranking priors.",
    )
    parser.add_argument(
        "--project-prior-weight",
        dest="project_prior_weight",
        type=float,
        help="Maximum additive score contribution from the project prior.",
    )
    parser.add_argument(
        "--expert-rca-prior",
        dest="expert_rca_prior_path",
        help="Optional JSON file with expert-curated RCA priors, such as Project Zero-style RCAs.",
    )
    parser.add_argument(
        "--enable-expert-rca-prior",
        dest="enable_expert_rca_prior",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable or disable expert-curated RCA ranking priors.",
    )
    parser.add_argument(
        "--expert-rca-min-confidence",
        dest="expert_rca_prior_min_confidence",
        type=float,
        help="Minimum confidence required for expert RCA records to affect ranking.",
    )
    parser.add_argument(
        "--expert-rca-weight",
        dest="expert_rca_prior_weight",
        type=float,
        help="Maximum additive score contribution from the expert RCA prior.",
    )
    if include_llm:
        parser.add_argument(
            "--llm",
            dest="enable_llm",
            action=argparse.BooleanOptionalAction,
            default=None,
            help="Enable or disable optional LLM-based semantic disambiguation.",
        )
        parser.add_argument(
            "--llm-model",
            help="OpenAI-compatible model name used when --llm is enabled.",
        )
        parser.add_argument(
            "--llm-base-url",
            default="https://api.openai.com/v1",
            help="Base URL for an OpenAI-compatible API endpoint.",
        )
        parser.add_argument(
            "--llm-cache-dir",
            help="Directory used for prompt/response caching when LLM mode is enabled.",
        )


def _build_pipeline(args: argparse.Namespace) -> RCPatchPipeline:
    disambiguator = None
    if hasattr(args, "llm_base_url"):
        provider = OpenAICompatibleProvider(
            model=getattr(args, "llm_model", None) or "",
            base_url=getattr(args, "llm_base_url", "https://api.openai.com/v1"),
        )
        llm_client = LLMClient(
            provider=provider,
            cache=FileLLMCache(cache_dir=getattr(args, "llm_cache_dir", None))
            if getattr(args, "llm_cache_dir", None)
            else FileLLMCache(),
        )
        disambiguator = SemanticDisambiguator(llm_client=llm_client)
    return RCPatchPipeline(semantic_disambiguator=disambiguator)


def _config_overrides_from_args(args: argparse.Namespace, *, include_llm: bool) -> dict[str, object]:
    cve_pattern_library_path = getattr(args, "cve_pattern_library_path", None)
    enable_cve_pattern_prior = getattr(args, "enable_cve_pattern_prior", None)
    if enable_cve_pattern_prior is None and cve_pattern_library_path:
        enable_cve_pattern_prior = True
    project_prior_path = getattr(args, "project_prior_path", None)
    enable_project_prior = getattr(args, "enable_project_prior", None)
    if enable_project_prior is None and project_prior_path:
        enable_project_prior = True
    expert_rca_prior_path = getattr(args, "expert_rca_prior_path", None)
    enable_expert_rca_prior = getattr(args, "enable_expert_rca_prior", None)
    if enable_expert_rca_prior is None and expert_rca_prior_path:
        enable_expert_rca_prior = True
    return build_analysis_config_overrides(
        parser_backend=getattr(args, "parser_backend", None),
        top_k_candidates=getattr(args, "top_k", None),
        max_chain_paths=getattr(args, "max_chains", None),
        enable_patch_analysis=(
            bool(args.enable_patch_analysis)
            if getattr(args, "enable_patch_analysis", None) is not None
            else None
        ),
        enable_llm=(
            bool(args.enable_llm)
            if include_llm and getattr(args, "enable_llm", None) is not None
            else None
        ),
        enable_cve_pattern_prior=enable_cve_pattern_prior,
        cve_pattern_library_path=cve_pattern_library_path,
        cve_pattern_min_support=getattr(args, "cve_pattern_min_support", None),
        cve_pattern_min_confidence=getattr(args, "cve_pattern_min_confidence", None),
        cve_pattern_prior_weight=getattr(args, "cve_pattern_prior_weight", None),
        ranker_calibration_path=getattr(args, "ranker_calibration_path", None),
        enable_project_prior=enable_project_prior,
        project_prior_path=project_prior_path,
        project_prior_weight=getattr(args, "project_prior_weight", None),
        enable_expert_rca_prior=enable_expert_rca_prior,
        expert_rca_prior_path=expert_rca_prior_path,
        expert_rca_prior_min_confidence=getattr(args, "expert_rca_prior_min_confidence", None),
        expert_rca_prior_weight=getattr(args, "expert_rca_prior_weight", None),
    )


def _format_trigger_summary(bug_report: BugReport) -> str:
    trigger = bug_report.trigger_point
    summary = f"Trigger normalized to {trigger.location.file}:{trigger.location.line}"
    if trigger.location.function:
        summary += f" in {trigger.location.function}"
    summary += f" [{trigger.type.value}]"
    return summary


def _format_candidate_summary(candidates: list[RootCauseCandidate]) -> str:
    if not candidates:
        return "No root cause candidates were produced."
    lines = ["Top candidates:"]
    for candidate in candidates[:3]:
        lines.append(
            f"  #{candidate.rank or '?'} {candidate.location.file}:{candidate.location.line} "
            f"({candidate.label.value}, score={candidate.score:.2f})"
        )
    return "\n".join(lines)


def _validation_commands_from_args(args: argparse.Namespace) -> list[ValidationCommand]:
    commands: list[ValidationCommand] = []
    timeout = int(getattr(args, "timeout", 30) or 30)
    if getattr(args, "build_cmd", None):
        commands.append(ValidationCommand(name="build", command=args.build_cmd, timeout_seconds=timeout))
    if getattr(args, "reproduce_cmd", None):
        commands.append(ValidationCommand(name="reproduce", command=args.reproduce_cmd, timeout_seconds=timeout))
    for index, raw_command in enumerate(getattr(args, "validation_cmd", []) or [], start=1):
        if "=" in raw_command:
            name, command = raw_command.split("=", 1)
            name = name.strip() or f"validation_{index}"
            command = command.strip()
        else:
            name = f"validation_{index}"
            command = raw_command.strip()
        if command:
            commands.append(ValidationCommand(name=name, command=command, timeout_seconds=timeout))
    return commands


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
