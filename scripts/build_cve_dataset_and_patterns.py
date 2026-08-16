#!/usr/bin/env python3
"""Build a CVE root-cause dataset and pattern library from advisory sources."""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Optional


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
VENDOR_ROOT = PROJECT_ROOT / ".vendor"

if SRC_ROOT.exists():
    sys.path.insert(0, str(SRC_ROOT))
if VENDOR_ROOT.exists():
    sys.path.insert(0, str(VENDOR_ROOT))

from rcpatch.cve_mining import (  # noqa: E402
    CVECollectionService,
    CVEDatasetBuildCase,
    CVERootCauseDatasetBuilder,
    CVERootCauseMiner,
    CVEPatchExtractor,
    CVESemanticAligner,
    CollectionSource,
    RootCausePatternMiner,
)
from rcpatch.errors import RCPatchError, ModelSerializationError  # noqa: E402
from rcpatch.llm import FileLLMCache, LLMClient, OpenAICompatibleProvider, SemanticDisambiguator  # noqa: E402
from rcpatch.logging_utils import configure_logging, get_logger  # noqa: E402
from rcpatch.models import (  # noqa: E402
    AdvisorySourceKind,
    CVEPatchExtraction,
    CVERootCauseMiningResult,
    CVESemanticAlignmentResult,
    ParserBackend,
)


C_CPP_SOURCE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".c++",
    ".cp",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".ipp",
    ".inl",
}


class PerRecordTimeoutError(TimeoutError):
    """Raised when one CVE exceeds the configured per-record time budget."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run the CVE collection -> patch extraction -> root-cause mining -> optional semantic alignment "
            "-> dataset -> pattern mining pipeline."
        ),
    )
    parser.add_argument(
        "--manifest",
        required=True,
        help="Path to a JSON manifest describing advisory sources, local repo paths, and optional language hints.",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory where intermediate artifacts, dataset, and pattern library will be written.",
    )
    parser.add_argument(
        "--parser-backend",
        choices=tuple(backend.value for backend in ParserBackend),
        default=ParserBackend.REGEX.value,
        help="Preferred source parser backend for CVE root-cause mining.",
    )
    parser.add_argument(
        "--mine-top-k",
        type=int,
        default=12,
        help="Top-K candidates to keep during patch-anchored root-cause mining.",
    )
    parser.add_argument(
        "--semantic-top-k",
        type=int,
        default=5,
        help="How many ranked candidates to send to semantic alignment per CVE.",
    )
    parser.add_argument(
        "--dataset-top-k",
        type=int,
        default=3,
        help="How many high-confidence root causes to retain per CVE in the dataset.",
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.7,
        help="Minimum confidence required for a root cause to enter the dataset.",
    )
    parser.add_argument(
        "--pattern-min-support",
        type=int,
        default=1,
        help="Minimum number of supporting annotations required for a mined pattern.",
    )
    parser.add_argument(
        "--max-fix-candidates",
        type=int,
        default=5,
        help="Maximum number of fix-commit candidates to consider per CVE.",
    )
    parser.add_argument(
        "--max-source-files",
        type=int,
        default=3000,
        help="Skip source-based mining for worktrees with more than this many C/C++ source files. Use 0 to disable.",
    )
    parser.add_argument(
        "--max-source-bytes",
        type=int,
        default=64 * 1024 * 1024,
        help="Skip source-based mining for worktrees with more than this many C/C++ source bytes. Use 0 to disable.",
    )
    parser.add_argument(
        "--progress-log-every",
        type=int,
        default=25,
        help="Emit an explicit progress log every N CVEs during source-based dataset building.",
    )
    parser.add_argument(
        "--per-record-timeout-seconds",
        type=int,
        default=900,
        help=(
            "Maximum wall-clock seconds allowed for a single CVE before it is skipped. "
            "Use 0 to disable. This keeps one pathological repository from stalling a corpus run."
        ),
    )
    parser.add_argument(
        "--llm",
        dest="enable_llm",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Enable optional LLM-based CVE semantic alignment.",
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
        "--keep-empty",
        dest="drop_empty",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Keep CVE records with no retained root causes in the dataset output.",
    )
    parser.add_argument(
        "--disk-saver",
        dest="disk_saver",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="After a successful build, remove stage JSON artifacts and keep only the final dataset/pattern outputs.",
    )
    parser.add_argument(
        "--keep-stage-artifacts",
        dest="keep_stage_artifacts",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Preserve collection/patch/mining/alignment JSON artifacts even in disk-saver mode.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        help="Logging verbosity.",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(getattr(logging, str(args.log_level).upper(), logging.INFO))
    logger = get_logger(__name__)

    try:
        manifest_path = Path(args.manifest).expanduser().resolve()
        output_dir = Path(args.output_dir).expanduser().resolve()
        output_dir.mkdir(parents=True, exist_ok=True)

        manifest = _load_manifest(manifest_path)
        sources = _parse_sources(manifest, manifest_path.parent)
        repo_paths = _normalize_path_map(manifest.get("repo_paths"), manifest_path.parent)
        repo_paths_by_cve = _normalize_path_map(manifest.get("repo_paths_by_cve"), manifest_path.parent)
        language_hints = _normalize_string_map(manifest.get("language_hints"))
        keep_unknown_language = bool(manifest.get("keep_unknown_language", False))

        collector = CVECollectionService(
            language_hints=language_hints,
            keep_unknown_language=keep_unknown_language,
        )
        collection_result = collector.collect(sources)
        collection_result_path = output_dir / "cve_collection_result.json"
        patch_extractions_path = output_dir / "cve_patch_extractions.json"
        mining_results_path = output_dir / "cve_root_cause_mining_results.json"
        semantic_alignments_path = output_dir / "cve_semantic_alignments.json"
        dataset_path = output_dir / "cve_root_cause_dataset.json"
        pattern_library_path = output_dir / "cve_pattern_library.json"
        _write_model_json(collection_result_path, collection_result.to_dict())

        patch_extractor = CVEPatchExtractor()
        miner = CVERootCauseMiner()
        semantic_aligner = _build_semantic_aligner(args) if args.enable_llm else None
        dataset_builder = CVERootCauseDatasetBuilder(
            min_confidence=args.min_confidence,
            top_k=args.dataset_top_k,
        )
        pattern_miner = RootCausePatternMiner(min_support=args.pattern_min_support)

        patch_extractions = []
        mining_results = []
        semantic_alignments = []
        dataset_cases: list[CVEDatasetBuildCase] = []
        mining_results_by_cve: dict[str, CVERootCauseMiningResult] = {}
        repo_budget_cache: dict[str, dict[str, Any]] = {}
        total_records = len(collection_result.records)

        for index, record in enumerate(collection_result.records, start=1):
            if index == 1 or index == total_records or (
                args.progress_log_every > 0 and index % args.progress_log_every == 0
            ):
                logger.info("Processing CVE %d/%d: %s", index, total_records, record.cve_id)
            repo_path = _lookup_repo_path(record.cve_id, record.repo_url, record.project, repo_paths_by_cve, repo_paths)
            patch_extraction: Optional[CVEPatchExtraction] = None
            semantic_alignment = None
            try:
                with _per_record_timeout(args.per_record_timeout_seconds, cve_id=record.cve_id):
                    patch_extraction = patch_extractor.extract_for_record(
                        record,
                        repo_path=repo_path,
                        max_candidates=args.max_fix_candidates,
                    )
                    patch_extractions.append(patch_extraction)

                    mining_result = _mine_record(
                        record=record,
                        patch_extraction=patch_extraction,
                        repo_path=repo_path,
                        miner=miner,
                        parser_backend=ParserBackend(args.parser_backend),
                        top_k=args.mine_top_k,
                        max_source_files=args.max_source_files,
                        max_source_bytes=args.max_source_bytes,
                        repo_budget_cache=repo_budget_cache,
                    )
                    mining_results.append(mining_result)
                    mining_results_by_cve[record.cve_id] = mining_result

                    if semantic_aligner is not None and repo_path and mining_result.candidates:
                        semantic_alignment = semantic_aligner.align_candidates(
                            record,
                            mining_result,
                            patch_extraction=patch_extraction,
                            repo_path=repo_path,
                            parser_backend=ParserBackend(args.parser_backend),
                            top_k=args.semantic_top_k,
                        )
                        semantic_alignments.append(semantic_alignment)
            except PerRecordTimeoutError as exc:
                logger.warning(
                    "Skipping %s after per-record timeout of %d seconds",
                    record.cve_id,
                    args.per_record_timeout_seconds,
                )
                if patch_extraction is None:
                    patch_extraction = CVEPatchExtraction(
                        cve_id=record.cve_id,
                        repo_url=record.repo_url,
                        repo_path=repo_path,
                        diagnostics=[str(exc)],
                        metadata={"skipped": True, "timeout": True},
                    )
                    patch_extractions.append(patch_extraction)
                mining_result = CVERootCauseMiningResult(
                    cve_id=record.cve_id,
                    repo_path=repo_path or PROJECT_ROOT.as_posix(),
                    diagnostics=[str(exc)],
                    metadata={
                        "parser_backend": ParserBackend(args.parser_backend).value,
                        "skipped": True,
                        "timeout": True,
                        "timeout_seconds": args.per_record_timeout_seconds,
                    },
                )
                mining_results.append(mining_result)
                mining_results_by_cve[record.cve_id] = mining_result
            except Exception as exc:
                logger.warning("Skipping %s after per-record failure: %s", record.cve_id, exc)
                if patch_extraction is None:
                    patch_extraction = CVEPatchExtraction(
                        cve_id=record.cve_id,
                        repo_url=record.repo_url,
                        repo_path=repo_path,
                        diagnostics=[f"Per-record failure before patch extraction completed: {exc}"],
                        metadata={"skipped": True, "exception": type(exc).__name__},
                    )
                    patch_extractions.append(patch_extraction)
                mining_result = CVERootCauseMiningResult(
                    cve_id=record.cve_id,
                    repo_path=repo_path or PROJECT_ROOT.as_posix(),
                    diagnostics=[f"Per-record failure: {exc}"],
                    metadata={
                        "parser_backend": ParserBackend(args.parser_backend).value,
                        "skipped": True,
                        "exception": type(exc).__name__,
                    },
                )
                mining_results.append(mining_result)
                mining_results_by_cve[record.cve_id] = mining_result

            dataset_cases.append(
                CVEDatasetBuildCase(
                    record=record,
                    mining_result=mining_result,
                    patch_extraction=patch_extraction,
                    semantic_alignment=semantic_alignment,
                    repo_path=repo_path,
                )
            )

        dataset = dataset_builder.build_dataset(
            dataset_cases,
            drop_empty=not bool(args.drop_empty),
        )
        pattern_library = pattern_miner.mine(
            dataset,
            mining_results_by_cve=mining_results_by_cve,
            min_support=args.pattern_min_support,
        )

        _write_json(patch_extractions_path, [item.to_dict() for item in patch_extractions])
        _write_json(mining_results_path, [item.to_dict() for item in mining_results])
        _write_json(semantic_alignments_path, [item.to_dict() for item in semantic_alignments])
        _write_model_json(dataset_path, dataset.to_dict())
        _write_model_json(pattern_library_path, pattern_library.to_dict())

        if args.disk_saver and not args.keep_stage_artifacts:
            cleanup_stage_artifacts(
                collect_builder_stage_artifacts(
                    collection_result_path=collection_result_path,
                    patch_extractions_path=patch_extractions_path,
                    mining_results_path=mining_results_path,
                    semantic_alignments_path=semantic_alignments_path,
                ),
                logger=logger,
            )

        logger.info("Collected %d CVE records", len(collection_result.records))
        logger.info("Built dataset with %d retained CVE records", len(dataset.records))
        logger.info("Mined %d reusable root-cause patterns", len(pattern_library.patterns))

        if args.keep_stage_artifacts or not args.disk_saver:
            print(f"Collection result: {collection_result_path}")
            print(f"Patch extractions: {patch_extractions_path}")
            print(f"Mining results: {mining_results_path}")
            print(f"Semantic alignments: {semantic_alignments_path}")
        print(f"Dataset: {dataset_path}")
        print(f"Pattern library: {pattern_library_path}")
        return 0
    except RCPatchError as exc:
        logger.error("%s", exc)
        return 1
    except Exception as exc:  # pragma: no cover - defensive path
        if logger.isEnabledFor(logging.DEBUG):
            logger.exception("Unhandled CVE dataset/pattern build failure: %s", exc)
        else:
            logger.error("Unhandled CVE dataset/pattern build failure: %s", exc)
        return 1


@contextmanager
def _per_record_timeout(seconds: int, *, cve_id: str) -> Any:
    """Bound one CVE's wall-clock runtime on POSIX systems."""

    if seconds <= 0 or not hasattr(signal, "SIGALRM"):
        yield
        return

    def _raise_timeout(signum: int, frame: Any) -> None:
        raise PerRecordTimeoutError(f"Timed out while processing {cve_id} after {seconds} seconds")

    previous_handler = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, _raise_timeout)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous_handler)


def _load_manifest(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except OSError as exc:
        raise ModelSerializationError(f"Failed to read manifest {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ModelSerializationError(f"Invalid JSON in manifest {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ModelSerializationError("Manifest must be a JSON object")
    return payload


def _parse_sources(payload: dict[str, Any], base_dir: Path) -> list[CollectionSource]:
    raw_sources = payload.get("sources")
    if not isinstance(raw_sources, list) or not raw_sources:
        raise ModelSerializationError("Manifest must include a non-empty 'sources' array")

    sources: list[CollectionSource] = []
    for item in raw_sources:
        if not isinstance(item, dict):
            raise ModelSerializationError("Each source entry must be an object")
        source_kind_value = item.get("source_kind")
        if not isinstance(source_kind_value, str):
            raise ModelSerializationError("Each source entry must include string field 'source_kind'")
        locator = item.get("locator")
        if isinstance(locator, str) and not locator.startswith(("http://", "https://")):
            locator = str((base_dir / locator).expanduser().resolve())
        sources.append(
            CollectionSource(
                source_kind=AdvisorySourceKind(source_kind_value),
                locator=locator,
                payload=item.get("payload"),
                metadata=dict(item.get("metadata", {})) if isinstance(item.get("metadata"), dict) else {},
            )
        )
    return sources


def _normalize_path_map(raw_map: Any, base_dir: Path) -> dict[str, str]:
    if not isinstance(raw_map, dict):
        return {}
    normalized: dict[str, str] = {}
    for key, value in raw_map.items():
        if not isinstance(key, str) or not isinstance(value, str):
            continue
        normalized[key] = str((base_dir / value).expanduser().resolve()) if not Path(value).is_absolute() else str(Path(value).expanduser().resolve())
    return normalized


def _normalize_string_map(raw_map: Any) -> dict[str, str]:
    if not isinstance(raw_map, dict):
        return {}
    return {
        str(key): str(value)
        for key, value in raw_map.items()
        if isinstance(key, str) and isinstance(value, str)
    }


def _lookup_repo_path(
    cve_id: Optional[str],
    repo_url: Optional[str],
    project: Optional[str],
    repo_paths_by_cve: dict[str, str],
    repo_paths: dict[str, str],
) -> Optional[str]:
    if cve_id and cve_id in repo_paths_by_cve:
        return repo_paths_by_cve[cve_id]
    if repo_url and repo_url in repo_paths:
        return repo_paths[repo_url]
    if project and project in repo_paths:
        return repo_paths[project]
    return None


def _mine_record(
    *,
    record: Any,
    patch_extraction: Any,
    repo_path: Optional[str],
    miner: CVERootCauseMiner,
    parser_backend: ParserBackend,
    top_k: int,
    max_source_files: int,
    max_source_bytes: int,
    repo_budget_cache: dict[str, dict[str, Any]],
) -> CVERootCauseMiningResult:
    diagnostics: list[str] = []
    metadata: dict[str, Any] = {
        "parser_backend": parser_backend.value,
    }
    if not repo_path:
        diagnostics.append("No local vulnerable repository path was provided for this CVE; skipping root-cause mining.")
    if not patch_extraction.patches:
        diagnostics.append("No structured patch hunks were available for this CVE; skipping root-cause mining.")
    repo_budget = _evaluate_repo_budget(
        repo_path,
        max_source_files=max_source_files,
        max_source_bytes=max_source_bytes,
        cache=repo_budget_cache,
    )
    metadata.update(repo_budget)
    if repo_budget.get("skip_reason"):
        diagnostics.append(str(repo_budget["skip_reason"]))
    if diagnostics:
        return CVERootCauseMiningResult(
            cve_id=record.cve_id,
            repo_path=repo_path or PROJECT_ROOT.as_posix(),
            diagnostics=diagnostics,
            metadata={**metadata, "skipped": True},
        )

    return miner.mine_for_record(
        record,
        patch_extraction,
        pre_patch_repo_path=repo_path,
        parser_backend=parser_backend,
        top_k=top_k,
    )


def _evaluate_repo_budget(
    repo_path: Optional[str],
    *,
    max_source_files: int,
    max_source_bytes: int,
    cache: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    if not repo_path:
        return {}
    cached = cache.get(repo_path)
    if cached is not None:
        return dict(cached)

    repo_root = Path(repo_path)
    source_file_count = 0
    source_bytes = 0
    limit_files = max_source_files if max_source_files > 0 else None
    limit_bytes = max_source_bytes if max_source_bytes > 0 else None
    skip_reason: Optional[str] = None

    for root, dirs, files in os.walk(repo_root):
        if ".git" in dirs:
            dirs.remove(".git")
        for file_name in files:
            if Path(file_name).suffix.lower() not in C_CPP_SOURCE_EXTENSIONS:
                continue
            file_path = Path(root) / file_name
            try:
                file_size = file_path.stat().st_size
            except OSError:
                continue
            source_file_count += 1
            source_bytes += file_size
            if limit_files is not None and source_file_count > limit_files:
                skip_reason = (
                    f"Skipping root-cause mining because the worktree is too large "
                    f"({source_file_count} source files exceeds limit {limit_files})."
                )
                break
            if limit_bytes is not None and source_bytes > limit_bytes:
                skip_reason = (
                    f"Skipping root-cause mining because the worktree is too large "
                    f"({source_bytes} source bytes exceeds limit {limit_bytes})."
                )
                break
        if skip_reason is not None:
            break

    budget = {
        "source_file_count": source_file_count,
        "source_bytes": source_bytes,
    }
    if skip_reason is not None:
        budget["skip_reason"] = skip_reason
    cache[repo_path] = dict(budget)
    return budget


def _build_semantic_aligner(args: argparse.Namespace) -> Optional[CVESemanticAligner]:
    provider = OpenAICompatibleProvider(
        model=args.llm_model or "",
        base_url=args.llm_base_url,
    )
    llm_client = LLMClient(
        provider=provider,
        cache=FileLLMCache(cache_dir=args.llm_cache_dir) if args.llm_cache_dir else FileLLMCache(),
    )
    return CVESemanticAligner(
        semantic_disambiguator=SemanticDisambiguator(llm_client=llm_client)
    )


def _write_model_json(path: Path, payload: dict[str, Any]) -> None:
    _write_json(path, payload)


def collect_builder_stage_artifacts(
    *,
    collection_result_path: Path,
    patch_extractions_path: Path,
    mining_results_path: Path,
    semantic_alignments_path: Path,
) -> list[Path]:
    """List the stage artifacts that may be removed once final outputs exist."""

    return [
        path
        for path in (
            collection_result_path,
            patch_extractions_path,
            mining_results_path,
            semantic_alignments_path,
        )
        if path.exists()
    ]


def cleanup_stage_artifacts(paths: list[Path], *, logger: logging.Logger) -> None:
    """Delete stage artifacts best-effort after a successful dataset/pattern build."""

    for path in paths:
        try:
            path.unlink()
            logger.info("Disk-saver cleanup removed %s", path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            logger.warning("Disk-saver cleanup could not remove %s: %s", path, exc)


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
