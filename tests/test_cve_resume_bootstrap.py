"""Regression tests for the filtered CVE bootstrap resume script."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

from rcpatch.models import (
    AdvisoryReference,
    AdvisorySourceKind,
    CVETraceability,
    CollectedCVERecord,
    Language,
    ReferenceType,
    RepositoryProvider,
)


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "resume_cve_bootstrap_filtered.py"
SPEC = importlib.util.spec_from_file_location("resume_cve_bootstrap_filtered", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - defensive import path
    raise RuntimeError(f"Unable to load resume script module from {SCRIPT_PATH}")
RESUME = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RESUME)


def make_record(
    *,
    cve_id: str,
    repo_url: str | None,
    fix_commits: list[str] | None = None,
) -> CollectedCVERecord:
    """Build a minimal normalized record for filter tests."""

    return CollectedCVERecord(
        cve_id=cve_id,
        aliases=[],
        project="demo",
        repo_url=repo_url,
        repo_provider=RepositoryProvider.GITHUB if repo_url and "github.com" in repo_url else RepositoryProvider.OTHER,
        description="demo",
        cwe="CWE-787",
        cwes=["CWE-787"],
        language=Language.UNKNOWN,
        affected_versions=[],
        references=[
            AdvisoryReference(
                url=(repo_url or "https://example.com/advisory"),
                source="test",
                reference_type=ReferenceType.REPOSITORY,
                repo_url=repo_url,
                provider=RepositoryProvider.GITHUB if repo_url and "github.com" in repo_url else RepositoryProvider.OTHER,
            )
        ],
        fix_commits=list(fix_commits or []),
        traceability=CVETraceability(source_kind=AdvisorySourceKind.PROJECT_ADVISORY),
    )


class CVEResumeBootstrapTests(unittest.TestCase):
    def test_classify_record_keeps_github_record_with_fix_commit(self) -> None:
        record = make_record(
            cve_id="CVE-2024-4000",
            repo_url="https://github.com/example/libfoo",
            fix_commits=["0123456789abcdef0123456789abcdef01234567"],
        )

        decision = RESUME.classify_record(
            record,
            allowed_hosts=("github.com", "gitlab.com", "gist.github.com"),
            deny_hosts=tuple(),
            require_fix_commit=True,
        )

        self.assertEqual(decision, "keep")

    def test_classify_record_rejects_non_repo_advisory_host(self) -> None:
        record = make_record(
            cve_id="CVE-2024-4001",
            repo_url="https://www.exploit-db.com/exploits/5794",
            fix_commits=["0123456789abcdef0123456789abcdef01234567"],
        )

        decision = RESUME.classify_record(
            record,
            allowed_hosts=("github.com", "gitlab.com", "gist.github.com"),
            deny_hosts=("www.exploit-db.com",),
            require_fix_commit=True,
        )

        self.assertEqual(decision, "denied_host")

    def test_filter_records_requires_fix_commit_by_default(self) -> None:
        kept, stats = RESUME.filter_records(
            [
                make_record(
                    cve_id="CVE-2024-4002",
                    repo_url="https://github.com/example/keepme",
                    fix_commits=["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
                ),
                make_record(
                    cve_id="CVE-2024-4003",
                    repo_url="https://github.com/example/dropme",
                    fix_commits=[],
                ),
            ],
            allowed_hosts=("github.com", "gitlab.com", "gist.github.com"),
            deny_hosts=tuple(),
            require_fix_commit=True,
            max_records=None,
        )

        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0].cve_id, "CVE-2024-4002")
        self.assertEqual(stats["drop_reasons"]["missing_fix_commit"], 1)

    def test_collect_resume_cleanup_paths_keeps_external_repo_cache_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "resume-out"
            repos_root = Path(temp_dir) / "shared-repos"
            worktrees_root = Path(temp_dir) / "shared-worktrees"
            advisory_path = output_dir / "filtered_advisories.json"
            manifest_path = output_dir / "filtered_manifest.json"
            patch_path = output_dir / "patches.json"
            output_dir.mkdir(parents=True)
            repos_root.mkdir()
            worktrees_root.mkdir()
            for path in (advisory_path, manifest_path, patch_path):
                path.write_text("{}", encoding="utf-8")

            cleanup_paths = RESUME.collect_resume_cleanup_paths(
                output_dir=output_dir,
                repos_root=repos_root,
                worktrees_root=worktrees_root,
                advisory_path=advisory_path,
                manifest_path=manifest_path,
                patch_path=patch_path,
                cleanup_external_repos=False,
            )

            self.assertEqual(
                {path.as_posix() for path in cleanup_paths},
                {advisory_path.resolve().as_posix(), manifest_path.resolve().as_posix(), patch_path.resolve().as_posix()},
            )


if __name__ == "__main__":
    unittest.main()
