#!/usr/bin/env python3
"""Resume the CVE bootstrap pipeline from an existing normalized collection result."""

from __future__ import annotations

import argparse
import importlib.util
import json
import logging
import sys
from collections import Counter
from pathlib import Path
from typing import Iterable, Optional
from urllib.parse import urlparse


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
VENDOR_ROOT = PROJECT_ROOT / ".vendor"

if SRC_ROOT.exists():
    sys.path.insert(0, str(SRC_ROOT))
if VENDOR_ROOT.exists():
    sys.path.insert(0, str(VENDOR_ROOT))

from rcpatch.cve_mining import CVEPatchExtractor  # noqa: E402
from rcpatch.errors import RCPatchError, ModelSerializationError, ModelValidationError  # noqa: E402
from rcpatch.logging_utils import configure_logging, get_logger  # noqa: E402
from rcpatch.models import CollectedCVERecord  # noqa: E402


BOOTSTRAP_SCRIPT = PROJECT_ROOT / "scripts" / "bootstrap_cve_corpus.py"
BOOTSTRAP_SPEC = importlib.util.spec_from_file_location("bootstrap_cve_corpus", BOOTSTRAP_SCRIPT)
if BOOTSTRAP_SPEC is None or BOOTSTRAP_SPEC.loader is None:  # pragma: no cover - defensive import path
    raise RuntimeError(f"Unable to load bootstrap helpers from {BOOTSTRAP_SCRIPT}")
BOOTSTRAP = importlib.util.module_from_spec(BOOTSTRAP_SPEC)
BOOTSTRAP_SPEC.loader.exec_module(BOOTSTRAP)


DEFAULT_ALLOWED_HOSTS = (
    "github.com",
    "gitlab.com",
    "gist.github.com",
)
DEFAULT_DENY_HOSTS = (
    "exchange.xforce.ibmcloud.com",
    "www.exploit-db.com",
    "www.securityfocus.com",
    "www.zerodayinitiative.com",
    "wpscan.com",
    "www.vulncheck.com",
    "www.securitytracker.com",
    "talosintelligence.com",
    "www.talosintelligence.com",
    "packetstormsecurity.com",
    "security.netapp.com",
    "secunia.com",
    "security-tracker.debian.org",
    "lists.apache.org",
    "lists.opensuse.org",
    "bugs.launchpad.net",
    "discuss.hashicorp.com",
    "discuss.elastic.co",
    "www.oracle.com",
)
DENY_PATH_TOKENS = (
    "advisories",
    "advisory",
    "bulletins",
    "bulletin",
    "exploits",
    "exploit",
    "vulnerabilities",
    "vulnerability",
    "security",
    "alert",
    "alerts",
    "slowloris",
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Resume CVE bootstrap from an existing bootstrap_collection_result.json, but filter out "
            "non-repository URLs before cloning and building the dataset/pattern library."
        )
    )
    parser.add_argument(
        "--collection-json",
        required=True,
        help="Path to an existing bootstrap_collection_result.json file.",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory for filtered manifest, summaries, worktrees, and pipeline output.",
    )
    parser.add_argument(
        "--repos-root",
        help="Optional repository cache root to reuse existing clones. Defaults to <output-dir>/repos.",
    )
    parser.add_argument(
        "--worktrees-root",
        help="Optional worktree root. Defaults to <output-dir>/worktrees.",
    )
    parser.add_argument(
        "--allowed-host",
        dest="allowed_hosts",
        action="append",
        default=None,
        help="Additional allowed repository host. Repeatable. Defaults to github.com, gitlab.com, gist.github.com.",
    )
    parser.add_argument(
        "--deny-host",
        dest="deny_hosts",
        action="append",
        default=None,
        help="Additional denied host to skip before cloning. Repeatable.",
    )
    parser.add_argument(
        "--require-fix-commit",
        dest="require_fix_commit",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Keep only CVEs that already have at least one inferred fix commit.",
    )
    parser.add_argument(
        "--max-records",
        type=int,
        default=None,
        help="Optional cap after filtering, before cloning.",
    )
    parser.add_argument(
        "--max-repos",
        type=int,
        default=None,
        help="Optional cap on unique repositories cloned in this resumed run.",
    )
    parser.add_argument(
        "--refresh",
        dest="refresh",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Refresh repositories/worktrees instead of reusing what already exists.",
    )
    parser.add_argument(
        "--clone-filter",
        default="blob:none",
        help="Git clone --filter value used when a repository is not already cached.",
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
        help="Only produce filtered advisories/manifest/repo mappings without invoking dataset/pattern build.",
    )
    parser.add_argument(
        "--disk-saver",
        dest="disk_saver",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="After a successful full build, remove bulky repos/worktrees/intermediate files and keep the final outputs.",
    )
    parser.add_argument(
        "--cleanup-external-repos",
        dest="cleanup_external_repos",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Also delete repos/worktrees that live outside --output-dir after a successful build.",
    )
    parser.add_argument(
        "--dry-run",
        dest="dry_run",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Only compute and print filter stats without cloning or building.",
    )
    parser.add_argument("--parser-backend", default="regex", help="Pass-through parser backend for the downstream builder.")
    parser.add_argument("--mine-top-k", type=int, default=12, help="Pass-through mining top-k.")
    parser.add_argument("--semantic-top-k", type=int, default=5, help="Pass-through semantic alignment top-k.")
    parser.add_argument("--dataset-top-k", type=int, default=3, help="Pass-through dataset top-k.")
    parser.add_argument("--min-confidence", type=float, default=0.7, help="Pass-through min confidence.")
    parser.add_argument("--pattern-min-support", type=int, default=1, help="Pass-through pattern minimum support.")
    parser.add_argument("--max-fix-candidates", type=int, default=5, help="Pass-through patch resolution top-k.")
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
    parser.add_argument("--llm-model", help="Pass-through LLM model name.")
    parser.add_argument("--llm-base-url", default="https://api.openai.com/v1", help="Pass-through LLM base URL.")
    parser.add_argument("--llm-cache-dir", help="Pass-through LLM cache directory.")
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
        collection_path = Path(args.collection_json).expanduser().resolve()
        output_dir = Path(args.output_dir).expanduser().resolve()
        repos_root = Path(args.repos_root).expanduser().resolve() if args.repos_root else output_dir / "repos"
        worktrees_root = Path(args.worktrees_root).expanduser().resolve() if args.worktrees_root else output_dir / "worktrees"
        pipeline_dir = output_dir / "pipeline-output"
        for path in (output_dir, repos_root, worktrees_root, pipeline_dir):
            path.mkdir(parents=True, exist_ok=True)

        records = load_collection_records(collection_path)
        filtered_records, filter_stats = filter_records(
            records,
            allowed_hosts=tuple(args.allowed_hosts or DEFAULT_ALLOWED_HOSTS),
            deny_hosts=tuple(args.deny_hosts or DEFAULT_DENY_HOSTS),
            require_fix_commit=bool(args.require_fix_commit),
            max_records=args.max_records,
        )

        stats_payload = {
            "source_collection": collection_path.as_posix(),
            "input_record_count": len(records),
            "retained_record_count": len(filtered_records),
            **filter_stats,
        }
        BOOTSTRAP.write_json(output_dir / "filtered_resume_stats.json", stats_payload)

        logger.info(
            "Filtered %d records down to %d records and %d unique repository URLs",
            len(records),
            len(filtered_records),
            len({record.repo_url for record in filtered_records if record.repo_url}),
        )

        if args.dry_run:
            print(f"Filtered stats: {output_dir / 'filtered_resume_stats.json'}")
            return 0

        repo_clone_map = BOOTSTRAP.clone_repositories(
            filtered_records,
            repos_root=repos_root,
            max_repos=args.max_repos,
            refresh=bool(args.refresh),
            clone_filter=args.clone_filter,
            git_timeout_seconds=args.git_timeout_seconds,
            logger=logger,
        )
        language_hints = BOOTSTRAP.infer_language_hints(repo_clone_map, logger=logger)

        patch_extractor = CVEPatchExtractor()
        repo_paths, repo_paths_by_cve, patch_resolutions = BOOTSTRAP.prepare_repo_mappings(
            records=filtered_records,
            repo_clone_map=repo_clone_map,
            language_hints=language_hints,
            worktrees_root=worktrees_root,
            patch_extractor=patch_extractor,
            max_fix_candidates=args.max_fix_candidates,
            refresh=bool(args.refresh),
            logger=logger,
        )

        advisory_payload = {
            "records": [
                BOOTSTRAP.serialize_record_for_project_advisory(record, language_hints)
                for record in filtered_records
            ]
        }
        advisory_path = output_dir / "filtered_normalized_cve_advisories.json"
        manifest_path = output_dir / "filtered_generated_cve_manifest.json"
        patch_path = output_dir / "filtered_patch_resolutions.json"
        summary_path = output_dir / "filtered_resume_summary.json"

        BOOTSTRAP.write_json(advisory_path, advisory_payload)
        BOOTSTRAP.write_json(patch_path, patch_resolutions)
        BOOTSTRAP.write_json(
            manifest_path,
            {
                "sources": [
                    {
                        "source_kind": "project_advisory",
                        "locator": BOOTSTRAP.relativize_for_manifest(advisory_path, manifest_path.parent),
                    }
                ],
                "repo_paths": {
                    key: BOOTSTRAP.relativize_for_manifest(Path(value), manifest_path.parent)
                    for key, value in sorted(repo_paths.items())
                },
                "repo_paths_by_cve": {
                    key: BOOTSTRAP.relativize_for_manifest(Path(value), manifest_path.parent)
                    for key, value in sorted(repo_paths_by_cve.items())
                },
                "language_hints": language_hints,
                "keep_unknown_language": False,
            },
        )

        BOOTSTRAP.write_json(
            summary_path,
            {
                **stats_payload,
                "cloned_repo_count": len(repo_clone_map),
                "cve_specific_worktree_count": len(repo_paths_by_cve),
                "manifest_path": manifest_path.as_posix(),
                "pipeline_output_dir": pipeline_dir.as_posix(),
            },
        )

        if not args.skip_build:
            BOOTSTRAP.run_dataset_pattern_builder(
                manifest_path=manifest_path,
                output_dir=pipeline_dir,
                args=args,
                logger=logger,
            )
            if args.disk_saver:
                BOOTSTRAP.cleanup_paths(
                    collect_resume_cleanup_paths(
                        output_dir=output_dir,
                        repos_root=repos_root,
                        worktrees_root=worktrees_root,
                        advisory_path=advisory_path,
                        manifest_path=manifest_path,
                        patch_path=patch_path,
                        cleanup_external_repos=bool(args.cleanup_external_repos),
                    ),
                    logger=logger,
                )

        print(f"Filtered stats: {output_dir / 'filtered_resume_stats.json'}")
        print(f"Filtered advisories: {advisory_path}")
        print(f"Filtered manifest: {manifest_path}")
        print(f"Filtered patch resolutions: {patch_path}")
        print(f"Filtered summary: {summary_path}")
        if not args.skip_build:
            print(f"Pipeline output: {pipeline_dir}")
        return 0
    except (RCPatchError, ModelSerializationError, ModelValidationError) as exc:
        logger.error("%s", exc)
        return 1
    except Exception as exc:  # pragma: no cover - defensive path
        if logger.isEnabledFor(logging.DEBUG):
            logger.exception("Unhandled filtered resume failure: %s", exc)
        else:
            logger.error("Unhandled filtered resume failure: %s", exc)
        return 1


def load_collection_records(path: Path) -> list[CollectedCVERecord]:
    """Load normalized CVE records from a previous bootstrap collection result."""

    try:
        raw_payload = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ModelSerializationError(f"Failed to read collection JSON from {path}: {exc}") from exc
    try:
        data = json.loads(raw_payload)
    except json.JSONDecodeError as exc:
        raise ModelSerializationError(f"Invalid JSON in collection result {path}: {exc}") from exc
    records = data.get("records")
    if not isinstance(records, list):
        raise ModelSerializationError("Collection result must contain a 'records' array")
    results: list[CollectedCVERecord] = []
    for item in records:
        if not isinstance(item, dict):
            continue
        results.append(CollectedCVERecord.from_dict(item))
    return results


def filter_records(
    records: Iterable[CollectedCVERecord],
    *,
    allowed_hosts: tuple[str, ...],
    deny_hosts: tuple[str, ...],
    require_fix_commit: bool,
    max_records: Optional[int],
) -> tuple[list[CollectedCVERecord], dict[str, object]]:
    """Filter normalized CVE records down to likely cloneable source-code repositories."""

    retained: list[CollectedCVERecord] = []
    reasons = Counter()
    host_counts = Counter()

    for record in records:
        decision = classify_record(
            record,
            allowed_hosts=allowed_hosts,
            deny_hosts=deny_hosts,
            require_fix_commit=require_fix_commit,
        )
        if decision != "keep":
            reasons[decision] += 1
            continue
        retained.append(record)
        if record.repo_url:
            host_counts[urlparse(record.repo_url).netloc.lower()] += 1
        if max_records is not None and len(retained) >= max_records:
            break

    stats = {
        "drop_reasons": dict(sorted(reasons.items())),
        "unique_repo_urls": len({record.repo_url for record in retained if record.repo_url}),
        "records_with_fix_commits": sum(1 for record in retained if record.fix_commits),
        "top_hosts": [[host, count] for host, count in host_counts.most_common(20)],
        "allowed_hosts": list(allowed_hosts),
        "deny_hosts": list(deny_hosts),
    }
    return retained, stats


def classify_record(
    record: CollectedCVERecord,
    *,
    allowed_hosts: tuple[str, ...],
    deny_hosts: tuple[str, ...],
    require_fix_commit: bool,
) -> str:
    """Classify whether a normalized CVE record should remain in the resumed pipeline."""

    if not record.repo_url:
        return "missing_repo_url"
    if require_fix_commit and not record.fix_commits:
        return "missing_fix_commit"

    parsed = urlparse(record.repo_url)
    host = parsed.netloc.lower()
    path = parsed.path.lower()
    if any(host == denied or host.endswith(f".{denied}") for denied in deny_hosts):
        return "denied_host"
    if not any(host == allowed or host.endswith(f".{allowed}") for allowed in allowed_hosts):
        return "host_not_allowed"
    if any(token in path for token in DENY_PATH_TOKENS):
        return "denied_path_token"
    return "keep"


def collect_resume_cleanup_paths(
    *,
    output_dir: Path,
    repos_root: Path,
    worktrees_root: Path,
    advisory_path: Path,
    manifest_path: Path,
    patch_path: Path,
    cleanup_external_repos: bool,
) -> list[Path]:
    """Collect resume-stage artifacts that can be removed after final outputs are built."""

    return BOOTSTRAP.collect_post_build_cleanup_paths(
        output_dir=output_dir,
        repos_root=repos_root,
        worktrees_root=worktrees_root,
        extra_paths=[advisory_path, manifest_path, patch_path],
        cleanup_external_paths=cleanup_external_repos,
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
