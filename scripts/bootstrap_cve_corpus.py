#!/usr/bin/env python3
"""Bootstrap the full CVE -> manifest -> local source -> dataset/pattern pipeline."""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import selectors
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
VENDOR_ROOT = PROJECT_ROOT / ".vendor"

if SRC_ROOT.exists():
    sys.path.insert(0, str(SRC_ROOT))
if VENDOR_ROOT.exists():
    sys.path.insert(0, str(VENDOR_ROOT))

from rcpatch.cve_mining import CVECollectionService, CVEPatchExtractor, CollectionSource  # noqa: E402
from rcpatch.errors import RCPatchError, ModelSerializationError  # noqa: E402
from rcpatch.logging_utils import configure_logging, get_logger  # noqa: E402
from rcpatch.models import AdvisoryReference, AdvisorySourceKind, CollectedCVERecord, Language  # noqa: E402


CVELIST_V5_REPO_URL = "https://github.com/CVEProject/cvelistV5.git"
NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GHSA_API_URL = "https://api.github.com/advisories"
DEFAULT_USER_AGENT = "RCPatch-CVE-Bootstrap/1.0"
_NEXT_LINK_RE = re.compile(r'<([^>]+)>;\s*rel="next"')
CPP_EXTENSIONS = {
    ".c",
    ".cc",
    ".cp",
    ".cpp",
    ".cxx",
    ".c++",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".ipp",
    ".inl",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Collect CVE records from the official CVEProject cvelistV5 repository, merge them with optional GHSA "
            "metadata, clone local repositories, prepare per-CVE pre-patch worktrees, and invoke the RCPatch "
            "CVE dataset/pattern build script."
        ),
    )
    parser.add_argument("--output-dir", required=True, help="Workspace directory for caches, clones, and outputs.")
    parser.add_argument(
        "--include-ghsa",
        dest="include_ghsa",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Also download GitHub global security advisories to enrich repo/fix metadata.",
    )
    parser.add_argument("--github-token", help="GitHub token for GHSA collection. Falls back to GITHUB_TOKEN.")
    parser.add_argument("--ghsa-max-pages", type=int, default=None, help="Optional page cap for GHSA downloads.")
    parser.add_argument(
        "--cvelist-repo-url",
        default=CVELIST_V5_REPO_URL,
        help="Git URL for the official cvelistV5 repository.",
    )
    parser.add_argument(
        "--cvelist-ref",
        default="main",
        help="Branch or ref to check out from the cvelistV5 repository.",
    )
    parser.add_argument(
        "--nvd-results-per-page",
        type=int,
        default=2000,
        help="Legacy NVD API page size. Retained only for the fallback NVD downloader helper.",
    )
    parser.add_argument(
        "--nvd-max-records",
        type=int,
        default=None,
        help="Optional cap when using the legacy NVD downloader helper; not used by cvelistV5 collection.",
    )
    parser.add_argument("--max-cves", type=int, default=None, help="Optional cap for CVEs processed after normalization.")
    parser.add_argument("--max-repos", type=int, default=None, help="Optional cap for cloned repositories.")
    parser.add_argument(
        "--refresh",
        dest="refresh",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Refresh downloaded feeds, repository clones, and worktrees instead of reusing existing artifacts.",
    )
    parser.add_argument(
        "--clone-filter",
        default="blob:none",
        help="Git clone --filter value used for repository bootstrap. Use an empty string to disable filtering.",
    )
    parser.add_argument(
        "--git-timeout-seconds",
        type=int,
        default=600,
        help="Maximum seconds allowed for each git command before the repository is skipped.",
    )
    parser.add_argument(
        "--skip-build",
        dest="skip_build",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Only prepare caches/repos/manifest without invoking the dataset/pattern builder.",
    )
    parser.add_argument(
        "--disk-saver",
        dest="disk_saver",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="After a successful full build, delete bulky repos/worktrees/intermediate caches to save disk space.",
    )
    parser.add_argument(
        "--keep-collection-json",
        dest="keep_collection_json",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Keep bootstrap_collection_result.json even in disk-saver mode.",
    )
    parser.add_argument(
        "--parser-backend",
        default="regex",
        help="Parser backend passed through to build_cve_dataset_and_patterns.py.",
    )
    parser.add_argument("--mine-top-k", type=int, default=12, help="Pass-through mining top-k for the downstream builder.")
    parser.add_argument(
        "--semantic-top-k",
        type=int,
        default=5,
        help="Pass-through semantic alignment top-k for the downstream builder.",
    )
    parser.add_argument(
        "--dataset-top-k",
        type=int,
        default=3,
        help="Pass-through dataset top-k for the downstream builder.",
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.7,
        help="Pass-through minimum confidence for the downstream builder.",
    )
    parser.add_argument(
        "--pattern-min-support",
        type=int,
        default=1,
        help="Pass-through pattern support threshold for the downstream builder.",
    )
    parser.add_argument(
        "--max-fix-candidates",
        type=int,
        default=5,
        help="Pass-through fix-commit candidate cap for patch resolution.",
    )
    parser.add_argument(
        "--max-source-files",
        type=int,
        default=3000,
        help="Pass-through maximum C/C++ source file count allowed for source-based mining. Use 0 to disable.",
    )
    parser.add_argument(
        "--max-source-bytes",
        type=int,
        default=64 * 1024 * 1024,
        help="Pass-through maximum C/C++ source bytes allowed for source-based mining. Use 0 to disable.",
    )
    parser.add_argument(
        "--progress-log-every",
        type=int,
        default=25,
        help="Pass-through CVE progress logging interval for the downstream builder.",
    )
    parser.add_argument(
        "--per-record-timeout-seconds",
        type=int,
        default=900,
        help="Pass-through per-CVE timeout for the downstream builder. Use 0 to disable.",
    )
    parser.add_argument(
        "--llm",
        dest="enable_llm",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Enable Prompt 4 semantic alignment in the downstream build script.",
    )
    parser.add_argument("--llm-model", help="Model name for LLM semantic alignment.")
    parser.add_argument("--llm-base-url", default="https://api.openai.com/v1", help="OpenAI-compatible base URL.")
    parser.add_argument("--llm-cache-dir", help="Optional cache directory for LLM prompt/response caching.")
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
        output_dir = Path(args.output_dir).expanduser().resolve()
        cache_dir = output_dir / "cache"
        repos_dir = output_dir / "repos"
        worktrees_dir = output_dir / "worktrees"
        pipeline_dir = output_dir / "pipeline-output"
        for path in (output_dir, cache_dir, repos_dir, worktrees_dir, pipeline_dir):
            path.mkdir(parents=True, exist_ok=True)

        cvelist_root = cache_dir / "cvelistV5"
        ghsa_path = cache_dir / "github_advisories.json"
        advisory_path = cache_dir / "normalized_cve_advisories.json"
        manifest_path = output_dir / "generated_cve_manifest.json"
        bootstrap_summary_path = output_dir / "bootstrap_summary.json"
        precollection_path = output_dir / "bootstrap_collection_result.json"
        bootstrap_patches_path = output_dir / "bootstrap_patch_resolutions.json"

        github_token = args.github_token or os.environ.get("GITHUB_TOKEN")

        ensure_cvelist_checkout(
            repo_url=args.cvelist_repo_url,
            repo_root=cvelist_root,
            git_ref=args.cvelist_ref,
            refresh=bool(args.refresh),
            git_timeout_seconds=args.git_timeout_seconds,
            logger=logger,
        )
        if args.include_ghsa:
            download_github_advisories(
                output_path=ghsa_path,
                github_token=github_token,
                refresh=bool(args.refresh),
                max_pages=args.ghsa_max_pages,
                logger=logger,
            )

        normalized_records = build_normalized_advisory_records(
            cvelist_path=cvelist_root,
            ghsa_path=ghsa_path if args.include_ghsa else None,
            max_cves=args.max_cves,
        )
        if args.keep_collection_json:
            precollection_payload = {
                "records": [record.to_dict() for record in normalized_records],
                "record_count": len(normalized_records),
            }
            write_json(precollection_path, precollection_payload)

            repo_clone_map = clone_repositories(
                normalized_records,
                repos_root=repos_dir,
                max_repos=args.max_repos,
                refresh=bool(args.refresh),
                clone_filter=args.clone_filter,
                git_timeout_seconds=args.git_timeout_seconds,
                logger=logger,
            )
        language_hints = infer_language_hints(repo_clone_map, logger=logger)

        patch_extractor = CVEPatchExtractor()
        repo_paths, repo_paths_by_cve, bootstrap_patch_resolutions = prepare_repo_mappings(
            records=normalized_records,
            repo_clone_map=repo_clone_map,
            language_hints=language_hints,
            worktrees_root=worktrees_dir,
            patch_extractor=patch_extractor,
            max_fix_candidates=args.max_fix_candidates,
            refresh=bool(args.refresh),
            logger=logger,
        )

        advisory_payload = {"records": [serialize_record_for_project_advisory(record, language_hints) for record in normalized_records]}
        write_json(advisory_path, advisory_payload)
        write_json(bootstrap_patches_path, bootstrap_patch_resolutions)

        manifest_payload = {
            "sources": [
                {
                    "source_kind": "project_advisory",
                    "locator": relativize_for_manifest(advisory_path, manifest_path.parent),
                }
            ],
            "repo_paths": {
                key: relativize_for_manifest(Path(value), manifest_path.parent)
                for key, value in sorted(repo_paths.items())
            },
            "repo_paths_by_cve": {
                key: relativize_for_manifest(Path(value), manifest_path.parent)
                for key, value in sorted(repo_paths_by_cve.items())
            },
            "language_hints": language_hints,
            "keep_unknown_language": False,
        }
        write_json(manifest_path, manifest_payload)

        bootstrap_summary = {
            "raw_sources": {
                "cvelist_path": cvelist_root.as_posix(),
                "ghsa_path": ghsa_path.as_posix() if args.include_ghsa else None,
            },
            "normalized_record_count": len(normalized_records),
            "cloned_repo_count": len(repo_clone_map),
            "cve_specific_worktree_count": len(repo_paths_by_cve),
            "manifest_path": manifest_path.as_posix(),
            "pipeline_output_dir": pipeline_dir.as_posix(),
        }
        write_json(bootstrap_summary_path, bootstrap_summary)

        if not args.skip_build:
            run_dataset_pattern_builder(
                manifest_path=manifest_path,
                output_dir=pipeline_dir,
                args=args,
                logger=logger,
            )
            if args.disk_saver:
                cleanup_paths(
                    collect_post_build_cleanup_paths(
                        output_dir=output_dir,
                        repos_root=repos_dir,
                        worktrees_root=worktrees_dir,
                        extra_paths=[
                            cvelist_root,
                            ghsa_path if args.include_ghsa else None,
                            advisory_path,
                            manifest_path,
                            bootstrap_patches_path,
                            precollection_path if not args.keep_collection_json else None,
                        ],
                        cleanup_external_paths=False,
                    ),
                    logger=logger,
                )

        print(f"CVE list repo cache: {cvelist_root}")
        if args.include_ghsa:
            print(f"Raw GHSA cache: {ghsa_path}")
        print(f"Normalized advisories: {advisory_path}")
        print(f"Generated manifest: {manifest_path}")
        print(f"Bootstrap patch resolutions: {bootstrap_patches_path}")
        print(f"Bootstrap summary: {bootstrap_summary_path}")
        if not args.skip_build:
            print(f"Pipeline output: {pipeline_dir}")
        return 0
    except RCPatchError as exc:
        logger.error("%s", exc)
        return 1
    except Exception as exc:  # pragma: no cover - defensive path
        if logger.isEnabledFor(logging.DEBUG):
            logger.exception("Unhandled CVE bootstrap failure: %s", exc)
        else:
            logger.error("Unhandled CVE bootstrap failure: %s", exc)
        return 1


def build_normalized_advisory_records(
    *,
    cvelist_path: Path,
    ghsa_path: Optional[Path],
    max_cves: Optional[int],
) -> list[CollectedCVERecord]:
    """Normalize raw feeds and merge overlapping CVE records into one advisory list."""

    records_by_cve: dict[str, list[CollectedCVERecord]] = {}
    for source in (
        CollectionSource(source_kind=AdvisorySourceKind.CVE_LIST_V5, locator=cvelist_path.as_posix()),
        CollectionSource(source_kind=AdvisorySourceKind.GITHUB_SECURITY_ADVISORY, locator=ghsa_path.as_posix())
        if ghsa_path is not None
        else None,
    ):
        if source is None:
            continue
        collection = CVECollectionService(keep_unknown_language=True).collect([source])
        for record in collection.records:
            records_by_cve.setdefault(record.cve_id, []).append(record)

    merged = [merge_cve_records(group) for _cve_id, group in sorted(records_by_cve.items())]
    if max_cves is not None:
        merged = merged[: max(0, max_cves)]
    return merged


def merge_cve_records(records: list[CollectedCVERecord]) -> CollectedCVERecord:
    """Merge NVD/GHSA variants of the same CVE into one normalized advisory record."""

    if not records:
        raise ModelSerializationError("Cannot merge an empty CVE record group")
    if len(records) == 1:
        return records[0]

    descriptions = [record.description.strip() for record in records if record.description.strip()]
    project = choose_best_value([record.project for record in records if record.project != "unknown_project"]) or records[0].project
    repo_url = choose_best_value([record.repo_url for record in records if record.repo_url])
    language = next((record.language for record in records if record.language != Language.UNKNOWN), Language.UNKNOWN)
    references = dedupe_references(reference for record in records for reference in record.references)
    fix_commits = []
    seen_fix_commits: set[str] = set()
    for record in records:
        for commit_sha in record.fix_commits:
            normalized_sha = commit_sha.lower()
            if normalized_sha in seen_fix_commits:
                continue
            seen_fix_commits.add(normalized_sha)
            fix_commits.append(normalized_sha)
    cwes = dedupe_strings(cwe for record in records for cwe in record.cwes)
    aliases = dedupe_strings(alias for record in records for alias in record.aliases)
    affected_versions = dedupe_affected_versions(version for record in records for version in record.affected_versions)
    traceability = records[0].traceability.model_copy(
        update={
            "notes": dedupe_strings(
                note
                for record in records
                for note in record.traceability.notes
            ),
            "repo_reference_urls": dedupe_strings(
                url
                for record in records
                for url in record.traceability.repo_reference_urls
            ),
            "fix_commit_reference_urls": dedupe_strings(
                url
                for record in records
                for url in record.traceability.fix_commit_reference_urls
            ),
            "affected_version_sources": dedupe_strings(
                value
                for record in records
                for value in record.traceability.affected_version_sources
            ),
            "metadata": {
                "merged_source_kinds": dedupe_strings(
                    record.traceability.source_kind.value for record in records
                ),
                "source_record_count": len(records),
            },
        }
    )
    merged = records[0].model_copy(
        update={
            "aliases": aliases,
            "project": project,
            "repo_url": repo_url,
            "description": max(descriptions, key=len) if descriptions else records[0].description,
            "cwe": cwes[0] if cwes else None,
            "cwes": cwes,
            "language": language,
            "affected_versions": affected_versions,
            "references": references,
            "fix_commits": fix_commits,
            "traceability": traceability,
            "metadata": {
                "merged_source_records": len(records),
                "merged_from": dedupe_strings(
                    record.traceability.source_kind.value for record in records
                ),
            },
        }
    )
    return merged


def clone_repositories(
    records: list[CollectedCVERecord],
    *,
    repos_root: Path,
    max_repos: Optional[int],
    refresh: bool,
    clone_filter: str,
    git_timeout_seconds: int,
    logger: logging.Logger,
) -> dict[str, str]:
    """Clone/update repositories inferred from CVE records."""

    repo_urls = dedupe_strings(record.repo_url for record in records if record.repo_url)
    if max_repos is not None:
        repo_urls = repo_urls[: max(0, max_repos)]

    repo_clone_map: dict[str, str] = {}
    for repo_url in repo_urls:
        repo_root = repo_local_path(repos_root, repo_url)
        try:
            ensure_repo_checkout(
                repo_url=repo_url,
                repo_root=repo_root,
                refresh=refresh,
                clone_filter=clone_filter,
                git_timeout_seconds=git_timeout_seconds,
            )
            repo_clone_map[repo_url] = repo_root.as_posix()
        except RuntimeError as exc:
            logger.warning("Skipping repository %s: %s", repo_url, exc)
    return repo_clone_map


def infer_language_hints(repo_clone_map: dict[str, str], *, logger: logging.Logger) -> dict[str, str]:
    """Infer C/C++ relevance after cloning repositories locally."""

    hints: dict[str, str] = {}
    for repo_url, repo_path in sorted(repo_clone_map.items()):
        language = detect_repository_language(Path(repo_path))
        if language == "c_cpp":
            hints[repo_url] = language
            logger.debug("Detected C/C++ repository: %s", repo_url)
        else:
            logger.debug("Repository did not look C/C++-centric: %s", repo_url)
    return hints


def prepare_repo_mappings(
    *,
    records: list[CollectedCVERecord],
    repo_clone_map: dict[str, str],
    language_hints: dict[str, str],
    worktrees_root: Path,
    patch_extractor: CVEPatchExtractor,
    max_fix_candidates: int,
    refresh: bool,
    logger: logging.Logger,
) -> tuple[dict[str, str], dict[str, str], list[dict[str, Any]]]:
    """Prepare repo-url/project mappings plus per-CVE vulnerable worktrees."""

    repo_paths: dict[str, str] = {}
    repo_paths_by_cve: dict[str, str] = {}
    bootstrap_patch_resolutions: list[dict[str, Any]] = []

    for record in records:
        if not record.repo_url:
            continue
        repo_path = repo_clone_map.get(record.repo_url)
        if repo_path is None:
            continue
        repo_paths[record.repo_url] = repo_path
        if record.project and record.project != "unknown_project":
            repo_paths.setdefault(record.project, repo_path)
        if language_hints.get(record.repo_url) != "c_cpp":
            continue

        patch_extraction = patch_extractor.extract_for_record(
            record,
            repo_path=repo_path,
            max_candidates=max_fix_candidates,
        )
        bootstrap_patch_resolutions.append(patch_extraction.to_dict())
        resolved_fix = patch_extraction.resolved_fix_commit
        if resolved_fix is None:
            logger.debug("No resolved fix commit for %s; leaving repo at shared clone path", record.cve_id)
            continue
        try:
            worktree_path = ensure_pre_patch_worktree(
                repo_root=Path(repo_path),
                worktrees_root=worktrees_root,
                cve_id=record.cve_id,
                commit_sha=resolved_fix.commit_sha,
                refresh=refresh,
            )
        except RuntimeError as exc:
            logger.warning("Failed to prepare pre-patch worktree for %s: %s", record.cve_id, exc)
            continue
        repo_paths_by_cve[record.cve_id] = worktree_path.as_posix()

    return repo_paths, repo_paths_by_cve, bootstrap_patch_resolutions


def serialize_record_for_project_advisory(record: CollectedCVERecord, language_hints: dict[str, str]) -> dict[str, Any]:
    """Serialize a merged normalized record into the project_advisory JSON shape."""

    language = language_hints.get(record.repo_url or "", record.language.value if record.language != Language.UNKNOWN else None)
    return {
        "cve_id": record.cve_id,
        "aliases": list(record.aliases),
        "project": record.project,
        "repo_url": record.repo_url,
        "language": language,
        "description": record.description,
        "cwes": list(record.cwes),
        "references": [reference.to_dict() for reference in record.references],
        "affected_versions": [item.to_dict() for item in record.affected_versions],
        "metadata": {
            "fix_commits": list(record.fix_commits),
            "traceability": record.traceability.to_dict(),
            "normalized_by": "bootstrap_cve_corpus",
        },
    }


def ensure_cvelist_checkout(
    *,
    repo_url: str,
    repo_root: Path,
    git_ref: str,
    refresh: bool,
    git_timeout_seconds: int,
    logger: logging.Logger,
) -> None:
    """Clone or refresh the official cvelistV5 checkout used for CVE collection."""

    if (repo_root / ".git").exists():
        if refresh:
            run_git(
                ["fetch", "--progress", "--depth", "1", "--filter=blob:none", "origin", git_ref],
                cwd=repo_root,
                timeout_seconds=git_timeout_seconds,
            )
            run_git(["checkout", "--force", "FETCH_HEAD"], cwd=repo_root)
            run_git(["sparse-checkout", "set", "cves"], cwd=repo_root)
        else:
            logger.info("Reusing existing cvelistV5 checkout: %s", repo_root)
        return

    if repo_root.exists():
        shutil.rmtree(repo_root)
    repo_root.parent.mkdir(parents=True, exist_ok=True)
    run_git(
        ["clone", "--progress", "--depth", "1", "--filter=blob:none", "--sparse", "--branch", git_ref, repo_url, repo_root.as_posix()],
        cwd=PROJECT_ROOT,
        timeout_seconds=git_timeout_seconds,
    )
    run_git(["sparse-checkout", "set", "cves"], cwd=repo_root)


def download_nvd_cves(
    *,
    output_path: Path,
    api_key: Optional[str],
    refresh: bool,
    max_records: Optional[int],
    results_per_page: int,
    logger: logging.Logger,
) -> None:
    """Download CVEs from the NVD 2.0 API into one local JSON file."""

    headers = {"User-Agent": DEFAULT_USER_AGENT}
    if api_key:
        headers["apiKey"] = api_key

    all_items: list[dict[str, Any]] = []
    start_index = 0
    total_results: Optional[int] = None
    if output_path.exists() and not refresh:
        cached_items, cached_total, cached_partial = load_nvd_snapshot(output_path)
        if max_records is not None:
            cached_items = cached_items[: max(0, max_records)]
        if cached_items and cached_partial:
            all_items = list(cached_items)
            start_index = len(all_items)
            total_results = cached_total
            logger.info(
                "Resuming partial NVD cache %s at startIndex=%d (%d cached items)",
                output_path,
                start_index,
                len(all_items),
            )
        elif output_path.exists():
            logger.info("Reusing existing NVD cache: %s", output_path)
            return

    page_count = 0
    try:
        while True:
            params = {
                "startIndex": start_index,
                "resultsPerPage": results_per_page,
            }
            payload = fetch_json(NVD_CVE_API_URL, headers=headers, params=params)
            if not isinstance(payload, dict):
                raise ModelSerializationError("NVD API returned a non-object payload")
            vulnerabilities = payload.get("vulnerabilities")
            if not isinstance(vulnerabilities, list):
                raise ModelSerializationError("NVD API payload missing vulnerabilities array")
            all_items.extend(vulnerabilities)
            page_count += 1
            if total_results is None:
                raw_total = payload.get("totalResults")
                total_results = int(raw_total) if isinstance(raw_total, int) else len(vulnerabilities)
            logger.info(
                "Downloaded NVD page %d (%d items, %d/%s total)",
                page_count,
                len(vulnerabilities),
                len(all_items),
                total_results,
            )

            if max_records is not None and len(all_items) >= max_records:
                all_items = all_items[:max_records]
                persist_nvd_snapshot(output_path, all_items=all_items, total_results=total_results, partial=False)
                break

            persist_nvd_snapshot(output_path, all_items=all_items, total_results=total_results, partial=True)
            if not vulnerabilities or (total_results is not None and len(all_items) >= total_results):
                persist_nvd_snapshot(output_path, all_items=all_items, total_results=total_results, partial=False)
                break

            start_index = len(all_items)
            if not api_key:
                time.sleep(1.2)
    except ModelSerializationError:
        if all_items:
            persist_nvd_snapshot(output_path, all_items=all_items, total_results=total_results, partial=True)
            logger.warning(
                "Saved a partial NVD snapshot to %s with %d items; rerun the command to resume from startIndex=%d.",
                output_path,
                len(all_items),
                len(all_items),
            )
        raise


def download_github_advisories(
    *,
    output_path: Path,
    github_token: Optional[str],
    refresh: bool,
    max_pages: Optional[int],
    logger: logging.Logger,
) -> None:
    """Download GitHub global security advisories into one local JSON file."""

    if output_path.exists() and not refresh:
        logger.info("Reusing existing GHSA cache: %s", output_path)
        return

    headers = {
        "User-Agent": DEFAULT_USER_AGENT,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
    }
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    all_items: list[dict[str, Any]] = []
    after_cursor: Optional[str] = None
    page = 0
    truncated = False
    diagnostics: list[str] = []
    while True:
        try:
            payload, response_headers = fetch_json_with_headers(
                GHSA_API_URL,
                headers=headers,
                params={"per_page": 100, "after": after_cursor},
            )
        except ModelSerializationError as exc:
            if is_rate_limit_error(exc):
                truncated = True
                diagnostics.append(str(exc))
                logger.warning(
                    "GitHub advisory download hit a rate limit after %d pages and %d advisories; "
                    "keeping the partial GHSA snapshot and continuing. Configure GITHUB_TOKEN "
                    "or rerun with --no-include-ghsa for a full uninterrupted run.",
                    page,
                    len(all_items),
                )
                break
            raise
        if not isinstance(payload, list):
            raise ModelSerializationError("GitHub advisories API returned a non-list payload")
        if not payload:
            break
        page += 1
        all_items.extend(item for item in payload if isinstance(item, dict))
        logger.info("Downloaded GHSA page %d (%d advisories)", page, len(payload))
        if max_pages is not None and page >= max_pages:
            break
        after_cursor = extract_next_cursor(response_headers.get("Link"))
        if after_cursor is None:
            break
        if not github_token:
            time.sleep(1.0)

    write_json(
        output_path,
        {
            "format": "github_global_security_advisories_snapshot",
            "downloaded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "partial": truncated,
            "diagnostics": diagnostics,
            "items": all_items,
        },
    )


def load_nvd_snapshot(path: Path) -> tuple[list[dict[str, Any]], Optional[int], bool]:
    """Load an existing NVD snapshot, including whether it is partial."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ModelSerializationError(f"Failed to read cached NVD snapshot from {path}: {exc}") from exc
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise ModelSerializationError(f"Cached NVD snapshot {path} is missing a vulnerabilities array")
    total_results = payload.get("totalResults")
    normalized_total = int(total_results) if isinstance(total_results, int) else None
    partial = bool(payload.get("partial"))
    return [item for item in vulnerabilities if isinstance(item, dict)], normalized_total, partial


def persist_nvd_snapshot(
    path: Path,
    *,
    all_items: list[dict[str, Any]],
    total_results: Optional[int],
    partial: bool,
) -> None:
    """Persist the current NVD download state so interrupted runs can resume later."""

    write_json(
        path,
        {
            "format": "nvd_api_2.0_snapshot",
            "downloaded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "totalResults": total_results if total_results is not None else len(all_items),
            "partial": partial,
            "resumeStartIndex": len(all_items),
            "vulnerabilities": all_items,
        },
    )


def fetch_json(url: str, *, headers: dict[str, str], params: Optional[dict[str, Any]] = None) -> Any:
    """Fetch and decode a JSON payload with small retry/backoff handling."""

    payload, _headers = fetch_json_with_headers(url, headers=headers, params=params)
    return payload


def fetch_json_with_headers(
    url: str,
    *,
    headers: dict[str, str],
    params: Optional[dict[str, Any]] = None,
) -> tuple[Any, dict[str, str]]:
    """Fetch a JSON payload and return both the decoded body and response headers."""

    full_url = url
    if params:
        query = urllib_parse.urlencode({key: value for key, value in params.items() if value is not None})
        full_url = f"{url}?{query}"
    request = urllib_request.Request(full_url, headers=headers)
    last_error: Optional[Exception] = None
    for attempt in range(3):
        try:
            with urllib_request.urlopen(request, timeout=120) as response:
                raw = response.read()
                response_headers = dict(response.headers.items())
            return json.loads(raw.decode("utf-8")), response_headers
        except (urllib_error.HTTPError, urllib_error.URLError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            last_error = exc
            if isinstance(exc, urllib_error.HTTPError) and exc.code not in {403, 429, 500, 502, 503, 504}:
                break
            time.sleep(1.5 * (attempt + 1))
    raise ModelSerializationError(build_fetch_error_message(full_url, last_error))


def build_fetch_error_message(full_url: str, error: Optional[Exception]) -> str:
    """Render a more actionable fetch error message for API calls."""

    if isinstance(error, urllib_error.HTTPError):
        parts = [f"Failed to fetch JSON from {full_url}: HTTP Error {error.code}: {error.reason}"]
        remaining = error.headers.get("X-RateLimit-Remaining") if error.headers else None
        reset_at = parse_rate_limit_reset(error.headers.get("X-RateLimit-Reset") if error.headers else None)
        retry_after = error.headers.get("Retry-After") if error.headers else None
        body_snippet = read_http_error_body(error)
        if remaining is not None:
            parts.append(f"remaining={remaining}")
        if retry_after is not None:
            parts.append(f"retry_after={retry_after}s")
        if reset_at is not None:
            parts.append(f"rate_limit_reset_at={reset_at}")
        if body_snippet:
            parts.append(f"body={body_snippet}")
        return " | ".join(parts)
    return f"Failed to fetch JSON from {full_url}: {error}"


def read_http_error_body(error: urllib_error.HTTPError) -> Optional[str]:
    """Extract a short body snippet from an HTTP error when available."""

    try:
        raw = error.read()
    except Exception:  # pragma: no cover - defensive path
        return None
    if not raw:
        return None
    try:
        text = raw.decode("utf-8", errors="replace").strip()
    except Exception:  # pragma: no cover - defensive path
        return None
    if not text:
        return None
    return text[:200]


def parse_rate_limit_reset(raw_value: Optional[str]) -> Optional[str]:
    """Convert a rate-limit reset epoch into an ISO timestamp when possible."""

    if raw_value is None:
        return None
    try:
        epoch = int(raw_value)
    except (TypeError, ValueError):
        return raw_value
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def is_rate_limit_error(error: Exception) -> bool:
    """Return whether an exception looks like an API rate-limit failure."""

    message = str(error).lower()
    return "rate limit" in message or "ratelimit" in message


def extract_next_cursor(link_header: Optional[str]) -> Optional[str]:
    """Extract the next-page cursor from a GitHub Link header when present."""

    if not link_header:
        return None
    match = _NEXT_LINK_RE.search(link_header)
    if match is None:
        return None
    query = urllib_parse.urlparse(match.group(1)).query
    values = urllib_parse.parse_qs(query)
    cursor_values = values.get("after")
    if not cursor_values:
        return None
    return cursor_values[0]


def ensure_repo_checkout(
    *,
    repo_url: str,
    repo_root: Path,
    refresh: bool,
    clone_filter: str,
    git_timeout_seconds: int,
) -> None:
    """Clone or update a repository checkout used for patch search and worktree creation."""

    if (repo_root / ".git").exists():
        if refresh:
            run_git(["fetch", "--progress", "--all", "--tags", "--prune"], cwd=repo_root, timeout_seconds=git_timeout_seconds)
        return

    if repo_root.exists():
        shutil.rmtree(repo_root)
    repo_root.parent.mkdir(parents=True, exist_ok=True)
    command = ["clone", "--progress"]
    if clone_filter:
        command.extend(["--filter", clone_filter])
    command.extend([repo_url, repo_root.as_posix()])
    run_git(command, cwd=PROJECT_ROOT, timeout_seconds=git_timeout_seconds)


def ensure_pre_patch_worktree(
    *,
    repo_root: Path,
    worktrees_root: Path,
    cve_id: str,
    commit_sha: str,
    refresh: bool,
) -> Path:
    """Create or reuse a detached worktree at the parent of a fix commit."""

    parent_sha = resolve_git_revision(repo_root, f"{commit_sha}^")
    repo_leaf = repo_root.name or "repo"
    worktree_path = worktrees_root / cve_id / repo_leaf

    if worktree_path.exists() and not refresh:
        try:
            head_sha = resolve_git_revision(worktree_path, "HEAD")
            if head_sha == parent_sha:
                return worktree_path
        except RuntimeError:
            pass

    if worktree_path.exists():
        try:
            run_git(["worktree", "remove", "--force", worktree_path.as_posix()], cwd=repo_root)
        except RuntimeError:
            shutil.rmtree(worktree_path, ignore_errors=True)
    run_git(["worktree", "prune"], cwd=repo_root)
    worktree_path.parent.mkdir(parents=True, exist_ok=True)
    run_git(["worktree", "add", "--force", "--detach", worktree_path.as_posix(), parent_sha], cwd=repo_root)
    return worktree_path


def detect_repository_language(repo_root: Path) -> str:
    """Approximate whether a cloned repository is C/C++ by scanning file extensions."""

    visited_files = 0
    for path in repo_root.rglob("*"):
        if ".git" in path.parts or not path.is_file():
            continue
        visited_files += 1
        if path.suffix.lower() in CPP_EXTENSIONS:
            return "c_cpp"
        if visited_files >= 50000:
            break
    return "unknown"


def repo_local_path(repos_root: Path, repo_url: str) -> Path:
    """Map a repository URL to a stable local clone path."""

    parsed = urllib_parse.urlparse(repo_url)
    host = parsed.netloc or "unknown-host"
    path_parts = [part for part in parsed.path.split("/") if part]
    if not path_parts:
        path_parts = ["unknown-repo"]
    leaf = path_parts[-1]
    if leaf.endswith(".git"):
        path_parts[-1] = leaf[:-4]
    return repos_root.joinpath(host, *path_parts)


def run_dataset_pattern_builder(
    *,
    manifest_path: Path,
    output_dir: Path,
    args: argparse.Namespace,
    logger: logging.Logger,
) -> None:
    """Invoke the existing Prompt 0-6 builder with the generated manifest."""

    command = [
        sys.executable,
        (PROJECT_ROOT / "scripts" / "build_cve_dataset_and_patterns.py").as_posix(),
        "--manifest",
        manifest_path.as_posix(),
        "--output-dir",
        output_dir.as_posix(),
        "--parser-backend",
        str(args.parser_backend),
        "--mine-top-k",
        str(args.mine_top_k),
        "--semantic-top-k",
        str(args.semantic_top_k),
        "--dataset-top-k",
        str(args.dataset_top_k),
        "--min-confidence",
        str(args.min_confidence),
        "--pattern-min-support",
        str(args.pattern_min_support),
        "--max-fix-candidates",
        str(args.max_fix_candidates),
        "--max-source-files",
        str(args.max_source_files),
        "--max-source-bytes",
        str(args.max_source_bytes),
        "--progress-log-every",
        str(args.progress_log_every),
        "--per-record-timeout-seconds",
        str(getattr(args, "per_record_timeout_seconds", 900)),
    ]
    if hasattr(args, "disk_saver") and not bool(args.disk_saver):
        command.append("--no-disk-saver")
    if args.enable_llm:
        command.extend(["--llm", "--llm-model", args.llm_model or "", "--llm-base-url", args.llm_base_url])
        if args.llm_cache_dir:
            command.extend(["--llm-cache-dir", args.llm_cache_dir])

    logger.info("Running dataset/pattern builder: %s", " ".join(command))
    completed = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"build_cve_dataset_and_patterns.py failed with exit code {completed.returncode}")


def collect_post_build_cleanup_paths(
    *,
    output_dir: Path,
    repos_root: Path,
    worktrees_root: Path,
    extra_paths: Iterable[Optional[Path]],
    cleanup_external_paths: bool,
) -> list[Path]:
    """Collect bulky paths that can be removed after successful result generation."""

    candidates: list[Path] = []
    for path in (repos_root, worktrees_root, *extra_paths):
        if path is None:
            continue
        resolved = path.expanduser().resolve()
        if not resolved.exists():
            continue
        if cleanup_external_paths or is_path_within(resolved, output_dir):
            candidates.append(resolved)
    unique: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        unique.append(candidate)
    return unique


def cleanup_paths(paths: Iterable[Path], *, logger: logging.Logger) -> None:
    """Remove a list of files/directories best-effort after successful processing."""

    for path in paths:
        if not path.exists():
            continue
        try:
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
            logger.info("Disk-saver cleanup removed %s", path)
        except OSError as exc:
            logger.warning("Disk-saver cleanup could not remove %s: %s", path, exc)


def is_path_within(path: Path, root: Path) -> bool:
    """Return whether a path lives under the given root directory."""

    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def run_git(args: list[str], *, cwd: Path, timeout_seconds: Optional[int] = None) -> str:
    """Run a git command and return stdout, with optional idle timeout for network-heavy commands.

    When `timeout_seconds` is set, the command is terminated only if it produces no stdout/stderr
    activity for that many seconds. This better matches long-running git operations that continue
    to emit progress.
    """

    command = ["git", *args]
    if not timeout_seconds or timeout_seconds <= 0:
        completed = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            stderr = completed.stderr.strip() or completed.stdout.strip() or "unknown git error"
            raise RuntimeError(stderr)
        return completed.stdout.strip()

    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        bufsize=0,
    )
    selector = selectors.DefaultSelector()
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    if process.stdout is not None:
        selector.register(process.stdout, selectors.EVENT_READ)
    if process.stderr is not None:
        selector.register(process.stderr, selectors.EVENT_READ)

    try:
        while selector.get_map():
            events = selector.select(timeout_seconds)
            if not events:
                process.kill()
                raise RuntimeError(f"{' '.join(command)} timed out after {timeout_seconds}s of inactivity")
            for key, _mask in events:
                chunk = os.read(key.fileobj.fileno(), 4096)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if process.stdout is not None and key.fileobj is process.stdout:
                    stdout_chunks.append(chunk)
                else:
                    stderr_chunks.append(chunk)
        returncode = process.wait()
    finally:
        selector.close()

    stdout_text = b"".join(stdout_chunks).decode("utf-8", errors="replace")
    stderr_text = b"".join(stderr_chunks).decode("utf-8", errors="replace")
    if returncode != 0:
        stderr = stderr_text.strip() or stdout_text.strip() or "unknown git error"
        raise RuntimeError(stderr)
    return stdout_text.strip()


def resolve_git_revision(repo_root: Path, revision: str) -> str:
    """Resolve a revision expression to a full commit SHA."""

    return run_git(["rev-parse", "--verify", f"{revision}^{{commit}}"], cwd=repo_root)


def choose_best_value(values: Iterable[Optional[str]]) -> Optional[str]:
    """Choose the most common non-empty value, breaking ties by length."""

    counts: dict[str, int] = {}
    for value in values:
        if not value:
            continue
        counts[value] = counts.get(value, 0) + 1
    if not counts:
        return None
    return max(counts.items(), key=lambda item: (item[1], len(item[0]), item[0]))[0]


def dedupe_strings(values: Iterable[Optional[str]]) -> list[str]:
    """Deduplicate strings while preserving their first-seen order."""

    results: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value is None:
            continue
        stripped = value.strip()
        if not stripped or stripped in seen:
            continue
        seen.add(stripped)
        results.append(stripped)
    return results


def dedupe_references(values: Iterable[AdvisoryReference]) -> list[AdvisoryReference]:
    """Deduplicate advisory references by URL while keeping the richer variant."""

    by_url: dict[str, AdvisoryReference] = {}
    for reference in values:
        previous = by_url.get(reference.url)
        if previous is None:
            by_url[reference.url] = reference
            continue
        previous_score = int(bool(previous.commit_sha)) + int(bool(previous.repo_url)) + len(previous.tags)
        current_score = int(bool(reference.commit_sha)) + int(bool(reference.repo_url)) + len(reference.tags)
        if current_score > previous_score:
            by_url[reference.url] = reference
    return list(by_url.values())


def dedupe_affected_versions(values: Iterable[Any]) -> list[Any]:
    """Deduplicate affected-version entries using their serialized shape."""

    results: list[Any] = []
    seen: set[str] = set()
    for value in values:
        serialized = json.dumps(value.to_dict(), sort_keys=True)
        if serialized in seen:
            continue
        seen.add(serialized)
        results.append(value)
    return results


def relativize_for_manifest(path: Path, manifest_dir: Path) -> str:
    """Prefer manifest-relative paths for generated artifacts when possible."""

    try:
        return path.resolve().relative_to(manifest_dir.resolve()).as_posix()
    except ValueError:
        return os.path.relpath(path.resolve(), manifest_dir.resolve())


def write_json(path: Path, payload: Any) -> None:
    """Write formatted JSON to disk."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
