#!/usr/bin/env python3
"""Run RCPatch for a bug spec or summarize an existing result into a concise report."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Optional


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
VENDOR_ROOT = PROJECT_ROOT / ".vendor"

if SRC_ROOT.exists():
    sys.path.insert(0, str(SRC_ROOT))
if VENDOR_ROOT.exists():
    sys.path.insert(0, str(VENDOR_ROOT))

from rcpatch.config import build_analysis_config_overrides, load_json_object  # noqa: E402
from rcpatch.errors import RCPatchError, ModelSerializationError  # noqa: E402
from rcpatch.llm import FileLLMCache, LLMClient, OpenAICompatibleProvider, SemanticDisambiguator  # noqa: E402
from rcpatch.logging_utils import configure_logging, get_logger  # noqa: E402
from rcpatch.models import AnalysisResult, BugReport, ParserBackend  # noqa: E402
from rcpatch.pipeline import RCPatchPipeline, PipelineOutputManager  # noqa: E402
from rcpatch.reporting import build_concise_report, collect_standard_artifacts, render_concise_report  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI parser for the generic report helper."""
    parser = argparse.ArgumentParser(
        description="Run RCPatch for a case or summarize an existing analysis_result.json into a concise report.",
    )
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--spec", help="Path to a bug JSON specification to analyze and summarize.")
    source_group.add_argument(
        "--result-json",
        help="Path to an existing analysis_result.json to summarize without rerunning RCPatch.",
    )
    parser.add_argument(
        "--config",
        dest="config_path",
        help="Optional JSON config overlay used when --spec is provided.",
    )
    parser.add_argument(
        "--output-dir",
        help="Directory where RCPatch artifacts and the concise report should be written.",
    )
    parser.add_argument(
        "--repo-path",
        help="Optional repo path override used in the concise report, mainly for --result-json mode.",
    )
    parser.add_argument(
        "--parser-backend",
        choices=tuple(backend.value for backend in ParserBackend),
        help="Preferred source parser backend when --spec is provided.",
    )
    parser.add_argument(
        "--top-k",
        type=int,
        help="Maximum number of ranked candidates to keep when --spec is provided.",
    )
    parser.add_argument(
        "--max-chains",
        type=int,
        help="Maximum number of causality chains to keep when --spec is provided.",
    )
    parser.add_argument(
        "--patch-aware",
        dest="enable_patch_analysis",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable or disable patch-aware weak supervision when --spec is provided.",
    )
    parser.add_argument(
        "--llm",
        dest="enable_llm",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable or disable optional LLM-based semantic disambiguation when --spec is provided.",
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
    parser.add_argument(
        "--report-candidates",
        type=int,
        default=3,
        help="Number of top candidates to keep in the concise report.",
    )
    parser.add_argument(
        "--report-chains",
        type=int,
        default=3,
        help="Number of top chains to keep in the concise report.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        help="Logging level for terminal output.",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(getattr(logging, str(args.log_level).upper(), logging.INFO))
    logger = get_logger(__name__)

    try:
        if args.spec:
            return _handle_spec_mode(args)
        return _handle_result_mode(args)
    except RCPatchError as exc:
        logger.error("%s", exc)
        return 1
    except Exception as exc:  # pragma: no cover - defensive logging path
        if logger.isEnabledFor(logging.DEBUG):
            logger.exception("Unhandled RCPatch report_case failure: %s", exc)
        else:
            logger.error("Unhandled RCPatch report_case failure: %s", exc)
        return 1


def _handle_spec_mode(args: argparse.Namespace) -> int:
    spec_path = Path(args.spec).expanduser().resolve()
    pipeline = _build_pipeline(args)
    output_manager = PipelineOutputManager()
    artifacts = pipeline.run_analysis(
        spec_path,
        config_path=args.config_path,
        config_overrides=_config_overrides_from_args(args),
    )
    if artifacts.analysis_result is None:
        raise RCPatchError("RCPatch did not produce an analysis result.")

    summary_text = pipeline.format_result_summary(artifacts.analysis_result)
    output_dir = output_manager.resolve_output_dir(
        bug_id=artifacts.bug_report.bug_id,
        command_name="report",
        requested_dir=args.output_dir,
    )
    exported = output_manager.export_analysis(output_dir, artifacts, summary_text=summary_text)
    report = build_concise_report(
        artifacts.analysis_result,
        report_candidates=args.report_candidates,
        report_chains=args.report_chains,
        repo_path=args.repo_path or artifacts.bug_report.repo_path,
        artifacts={name: path.as_posix() for name, path in exported.items()},
    )
    return _write_and_print_report(output_dir=output_dir, report=report)


def _handle_result_mode(args: argparse.Namespace) -> int:
    result_path = Path(args.result_json).expanduser().resolve()
    result = AnalysisResult.from_json_file(result_path)
    output_dir = Path(args.output_dir).expanduser().resolve() if args.output_dir else result_path.parent
    output_dir.mkdir(parents=True, exist_ok=True)

    repo_path = args.repo_path or _infer_repo_path_from_neighbors(result_path)
    report = build_concise_report(
        result,
        report_candidates=args.report_candidates,
        report_chains=args.report_chains,
        repo_path=repo_path,
        artifacts=collect_standard_artifacts(result_path.parent),
    )
    return _write_and_print_report(output_dir=output_dir, report=report)


def _build_pipeline(args: argparse.Namespace) -> RCPatchPipeline:
    disambiguator = None
    if bool(args.enable_llm):
        provider = OpenAICompatibleProvider(
            model=args.llm_model or "",
            base_url=args.llm_base_url,
        )
        llm_client = LLMClient(
            provider=provider,
            cache=FileLLMCache(cache_dir=args.llm_cache_dir) if args.llm_cache_dir else FileLLMCache(),
        )
        disambiguator = SemanticDisambiguator(llm_client=llm_client)
    return RCPatchPipeline(semantic_disambiguator=disambiguator)


def _config_overrides_from_args(args: argparse.Namespace) -> dict[str, object]:
    return build_analysis_config_overrides(
        parser_backend=args.parser_backend,
        top_k_candidates=args.top_k,
        max_chain_paths=args.max_chains,
        enable_patch_analysis=bool(args.enable_patch_analysis) if args.enable_patch_analysis is not None else None,
        enable_llm=bool(args.enable_llm) if args.enable_llm is not None else None,
    )


def _infer_repo_path_from_neighbors(result_path: Path) -> Optional[str]:
    normalized_bug_report = result_path.parent / "normalized_bug_report.json"
    if not normalized_bug_report.exists():
        return None
    try:
        bug_report = BugReport.from_json_file(normalized_bug_report)
    except (ModelSerializationError, RCPatchError, ValueError):
        payload = load_json_object(normalized_bug_report, description="normalized bug report")
        repo_path = payload.get("repo_path")
        return repo_path if isinstance(repo_path, str) and repo_path else None
    return bug_report.repo_path


def _write_and_print_report(*, output_dir: Path, report: dict[str, object]) -> int:
    output_manager = PipelineOutputManager()
    report_text = render_concise_report(report)
    report_json_path = output_manager.write_json(output_dir / "concise_report.json", report)
    report_text_path = output_manager.write_text(output_dir / "concise_report.txt", f"{report_text}\n")

    print(report_text)
    print("")
    print(f"Concise JSON report: {report_json_path}")
    print(f"Concise text report: {report_text_path}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
