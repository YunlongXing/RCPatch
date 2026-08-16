"""Regression tests for the CVE bootstrap script helpers."""

from __future__ import annotations

import importlib.util
import json
import logging
import tempfile
import unittest
from unittest import mock
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


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "bootstrap_cve_corpus.py"
SPEC = importlib.util.spec_from_file_location("bootstrap_cve_corpus", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - defensive import path
    raise RuntimeError(f"Unable to load bootstrap script module from {SCRIPT_PATH}")
BOOTSTRAP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BOOTSTRAP)


def make_record(
    *,
    cve_id: str,
    description: str,
    repo_url: str | None = None,
    project: str = "unknown_project",
    language: Language = Language.UNKNOWN,
    reference_url: str = "https://example.com/advisory",
) -> CollectedCVERecord:
    """Construct a minimal normalized CVE record for merge tests."""

    return CollectedCVERecord(
        cve_id=cve_id,
        aliases=[],
        project=project,
        repo_url=repo_url,
        repo_provider=RepositoryProvider.GITHUB if repo_url else RepositoryProvider.UNKNOWN,
        description=description,
        cwe="CWE-787",
        cwes=["CWE-787"],
        language=language,
        references=[
            AdvisoryReference(
                url=reference_url,
                source="test",
                reference_type=ReferenceType.COMMIT if "/commit/" in reference_url else ReferenceType.OTHER,
                repo_url=repo_url,
                provider=RepositoryProvider.GITHUB if repo_url else RepositoryProvider.UNKNOWN,
            )
        ],
        fix_commits=[],
        traceability=CVETraceability(source_kind=AdvisorySourceKind.PROJECT_ADVISORY),
    )


class CVEBootstrapTests(unittest.TestCase):
    def test_build_normalized_advisory_records_supports_cvelist_v5_checkout(self) -> None:
        payload = {
            "dataType": "CVE_RECORD",
            "dataVersion": "5.1",
            "cveMetadata": {
                "cveId": "CVE-2024-7777",
                "state": "PUBLISHED",
            },
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en", "value": "Overflow in a C library."}],
                    "problemTypes": [{"descriptions": [{"cweId": "CWE-787", "lang": "en"}]}],
                    "references": [
                        {"url": "https://github.com/example/cvelib/commit/0123456789abcdef0123456789abcdef01234567"}
                    ],
                    "affected": [
                        {
                            "vendor": "Example",
                            "product": "cvelib",
                            "versions": [{"version": "1.0.0", "lessThan": "1.0.2", "status": "affected"}],
                        }
                    ],
                }
            },
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            cves_root = Path(temp_dir) / "cves" / "2024" / "7xxx"
            cves_root.mkdir(parents=True)
            (cves_root / "CVE-2024-7777.json").write_text(json.dumps(payload), encoding="utf-8")

            records = BOOTSTRAP.build_normalized_advisory_records(
                cvelist_path=Path(temp_dir),
                ghsa_path=None,
                max_cves=None,
            )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].cve_id, "CVE-2024-7777")
        self.assertEqual(records[0].project, "cvelib")

    def test_merge_cve_records_prefers_richer_repo_metadata(self) -> None:
        nvd_like = make_record(
            cve_id="CVE-2024-9991",
            description="Short description.",
            reference_url="https://nvd.nist.gov/vuln/detail/CVE-2024-9991",
        )
        ghsa_like = make_record(
            cve_id="CVE-2024-9991",
            description="Longer description with repository context and actionable patch metadata.",
            repo_url="https://github.com/example/libfoo",
            project="libfoo",
            language=Language.C_CPP,
            reference_url="https://github.com/example/libfoo/commit/0123456789abcdef0123456789abcdef01234567",
        )

        merged = BOOTSTRAP.merge_cve_records([nvd_like, ghsa_like])

        self.assertEqual(merged.repo_url, "https://github.com/example/libfoo")
        self.assertEqual(merged.project, "libfoo")
        self.assertEqual(merged.language, Language.C_CPP)
        self.assertIn("repository context", merged.description)
        self.assertEqual(len(merged.references), 2)

    def test_detect_repository_language_flags_c_cpp_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir)
            (repo_root / "src").mkdir()
            (repo_root / "src" / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
            (repo_root / "README.md").write_text("# example\n", encoding="utf-8")

            self.assertEqual(BOOTSTRAP.detect_repository_language(repo_root), "c_cpp")

    def test_extract_next_cursor_parses_github_link_header(self) -> None:
        link_header = '<https://api.github.com/advisories?after=Y3Vyc29yOnYyOpHOUH8B7A%3D%3D&per_page=100>; rel="next"'
        self.assertEqual(BOOTSTRAP.extract_next_cursor(link_header), "Y3Vyc29yOnYyOpHOUH8B7A==")

    def test_download_github_advisories_keeps_partial_snapshot_on_rate_limit(self) -> None:
        responses = [
            (
                [{"ghsa_id": "GHSA-1111-2222-3333", "cve_id": "CVE-2024-9999"}],
                {"Link": '<https://api.github.com/advisories?after=cursor123&per_page=100>; rel="next"'},
            ),
            BOOTSTRAP.ModelSerializationError(
                "Failed to fetch JSON from https://api.github.com/advisories: HTTP Error 403: rate limit exceeded"
            ),
        ]

        def fake_fetch(*_args, **_kwargs):
            next_value = responses.pop(0)
            if isinstance(next_value, Exception):
                raise next_value
            return next_value

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "ghsa.json"
            with mock.patch.object(BOOTSTRAP, "fetch_json_with_headers", side_effect=fake_fetch):
                BOOTSTRAP.download_github_advisories(
                    output_path=output_path,
                    github_token=None,
                    refresh=True,
                    max_pages=None,
                    logger=logging.getLogger("test"),
                )

            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertTrue(payload["partial"])
            self.assertEqual(len(payload["items"]), 1)
            self.assertTrue(payload["diagnostics"])

    def test_download_nvd_cves_persists_partial_snapshot_on_timeout(self) -> None:
        responses = [
            {
                "totalResults": 3,
                "vulnerabilities": [
                    {"cve": {"id": "CVE-2024-0001"}},
                    {"cve": {"id": "CVE-2024-0002"}},
                ],
            },
            BOOTSTRAP.ModelSerializationError("The read operation timed out"),
        ]

        def fake_fetch(*_args, **_kwargs):
            next_value = responses.pop(0)
            if isinstance(next_value, Exception):
                raise next_value
            return next_value

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "nvd.json"
            with mock.patch.object(BOOTSTRAP, "fetch_json", side_effect=fake_fetch):
                with self.assertRaises(BOOTSTRAP.ModelSerializationError):
                    BOOTSTRAP.download_nvd_cves(
                        output_path=output_path,
                        api_key="token",
                        refresh=True,
                        max_records=None,
                        results_per_page=2000,
                        logger=logging.getLogger("test"),
                    )

            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertTrue(payload["partial"])
            self.assertEqual(payload["resumeStartIndex"], 2)
            self.assertEqual(len(payload["vulnerabilities"]), 2)

    def test_download_nvd_cves_resumes_from_partial_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "nvd.json"
            BOOTSTRAP.write_json(
                output_path,
                {
                    "format": "nvd_api_2.0_snapshot",
                    "downloaded_at": "2026-04-22T00:00:00Z",
                    "totalResults": 3,
                    "partial": True,
                    "resumeStartIndex": 2,
                    "vulnerabilities": [
                        {"cve": {"id": "CVE-2024-0001"}},
                        {"cve": {"id": "CVE-2024-0002"}},
                    ],
                },
            )

            seen_start_indices: list[int] = []

            def fake_fetch(*_args, **kwargs):
                params = kwargs.get("params", {})
                seen_start_indices.append(int(params.get("startIndex", -1)))
                return {
                    "totalResults": 3,
                    "vulnerabilities": [{"cve": {"id": "CVE-2024-0003"}}],
                }

            with mock.patch.object(BOOTSTRAP, "fetch_json", side_effect=fake_fetch):
                BOOTSTRAP.download_nvd_cves(
                    output_path=output_path,
                    api_key="token",
                    refresh=False,
                    max_records=None,
                    results_per_page=2000,
                    logger=logging.getLogger("test"),
                )

            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(seen_start_indices, [2])
            self.assertFalse(payload["partial"])
            self.assertEqual(len(payload["vulnerabilities"]), 3)

    def test_collect_post_build_cleanup_paths_skips_external_paths_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "out"
            repos_root = output_dir / "repos"
            worktrees_root = output_dir / "worktrees"
            advisory_path = output_dir / "normalized.json"
            external_cache = Path(temp_dir) / "external-cache.json"
            for path in (repos_root, worktrees_root):
                path.mkdir(parents=True)
            advisory_path.write_text("{}", encoding="utf-8")
            external_cache.write_text("{}", encoding="utf-8")

            cleanup_paths = BOOTSTRAP.collect_post_build_cleanup_paths(
                output_dir=output_dir,
                repos_root=repos_root,
                worktrees_root=worktrees_root,
                extra_paths=[advisory_path, external_cache],
                cleanup_external_paths=False,
            )

            self.assertEqual(
                {path.as_posix() for path in cleanup_paths},
                {repos_root.resolve().as_posix(), worktrees_root.resolve().as_posix(), advisory_path.resolve().as_posix()},
            )


if __name__ == "__main__":
    unittest.main()
