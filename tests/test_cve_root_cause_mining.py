"""Tests for CVE candidate root-cause mining around patch anchors."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from rcpatch.cve_mining import CVERootCauseMiner, CVEPatchExtractor
from rcpatch.models import (
    AdvisoryReference,
    AdvisorySourceKind,
    CVEAffectedVersion,
    CVEPatchExtraction,
    CVETraceability,
    CollectedCVERecord,
    Language,
    ParserBackend,
    ReferenceType,
    RepositoryProvider,
)


def _git(repo_root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=True,
    )
    return completed.stdout.strip()


@unittest.skipUnless(shutil.which("git"), "git is required for CVE root-cause mining tests")
class CVERootCauseMiningTests(unittest.TestCase):
    def test_miner_keeps_patch_locations_and_upstream_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir) / "repo"
            repo_root.mkdir()
            _git(repo_root, "init")
            _git(repo_root, "config", "user.name", "RCPatch")
            _git(repo_root, "config", "user.email", "bugrc@example.com")

            src_dir = repo_root / "src"
            src_dir.mkdir()
            source_path = src_dir / "sample.c"
            source_path.write_text(
                "#include <string.h>\n"
                "int compute_size(int len) {\n"
                "    int size = len + 8;\n"
                "    return size;\n"
                "}\n\n"
                "void copy_data(char *dst, const char *src, int len, int cap) {\n"
                "    int actual = compute_size(len);\n"
                "    memcpy(dst, src, actual);\n"
                "}\n",
                encoding="utf-8",
            )
            _git(repo_root, "add", ".")
            _git(repo_root, "commit", "-m", "initial vulnerable version")
            vulnerable_commit = _git(repo_root, "rev-parse", "HEAD")

            source_path.write_text(
                "#include <string.h>\n"
                "int compute_size(int len) {\n"
                "    int size = len + 8;\n"
                "    return size;\n"
                "}\n\n"
                "void copy_data(char *dst, const char *src, int len, int cap) {\n"
                "    int actual = compute_size(len);\n"
                "    if (actual > cap) {\n"
                "        actual = cap;\n"
                "    }\n"
                "    memcpy(dst, src, actual);\n"
                "}\n",
                encoding="utf-8",
            )
            _git(repo_root, "add", ".")
            _git(repo_root, "commit", "-m", "CVE-2024-4000 add bounds check in copy_data")
            fix_commit = _git(repo_root, "rev-parse", "HEAD")

            record = CollectedCVERecord(
                cve_id="CVE-2024-4000",
                project="sample",
                repo_url="https://github.com/example/sample",
                repo_provider=RepositoryProvider.GITHUB,
                description="A buffer overflow occurs because an incorrect size reaches memcpy and the fix adds a guard.",
                language=Language.C,
                affected_versions=[CVEAffectedVersion(package="sample", vulnerable_version_range="< 1.0.1")],
                references=[
                    AdvisoryReference(
                        url=f"https://github.com/example/sample/commit/{fix_commit}",
                        source="advisory",
                        reference_type=ReferenceType.COMMIT,
                        repo_url="https://github.com/example/sample",
                        provider=RepositoryProvider.GITHUB,
                        commit_sha=fix_commit,
                    )
                ],
                fix_commits=[fix_commit],
                traceability=CVETraceability(source_kind=AdvisorySourceKind.PROJECT_ADVISORY),
            )

            patch_extraction = CVEPatchExtractor().extract_for_record(record, repo_path=repo_root.as_posix())
            _git(repo_root, "checkout", vulnerable_commit)

            result = CVERootCauseMiner().mine_for_record(
                record,
                patch_extraction,
                pre_patch_repo_path=repo_root.as_posix(),
                parser_backend=ParserBackend.REGEX,
                top_k=8,
            )

        self.assertTrue(result.anchors)
        self.assertTrue(any(anchor.anchor_kind == "insertion_site" for anchor in result.anchors))
        self.assertTrue(any(anchor.location.function == "copy_data" for anchor in result.anchors))
        self.assertTrue(result.slices)
        self.assertTrue(result.candidates)
        self.assertTrue(
            any(
                candidate.features.get("patch_anchor_overlap")
                and candidate.features.get("candidate_origin") == "patch_location"
                for candidate in result.candidates
            )
        )
        self.assertTrue(
            any(
                candidate.location.function == "compute_size"
                and candidate.features.get("candidate_origin") == "upstream_candidate"
                and (
                    candidate.features.get("incorrect_computation_replaced_by_patch")
                    or candidate.features.get("defines_value_later_fixed")
                )
                for candidate in result.candidates
            )
        )

    def test_miner_skips_cve_when_source_parsing_fails(self) -> None:
        record = CollectedCVERecord(
            cve_id="CVE-2024-4999",
            project="broken",
            repo_url="https://github.com/example/broken",
            repo_provider=RepositoryProvider.GITHUB,
            description="Parsing this repository fails.",
            language=Language.C,
            traceability=CVETraceability(source_kind=AdvisorySourceKind.PROJECT_ADVISORY),
        )
        patch_extraction = CVEPatchExtraction(cve_id="CVE-2024-4999")
        miner = CVERootCauseMiner()

        with mock.patch.object(miner.parser, "parse_repository", side_effect=ValueError("duplicate function ids")):
            result = miner.mine_for_record(
                record,
                patch_extraction,
                pre_patch_repo_path="/tmp/nonexistent-repo",
                parser_backend=ParserBackend.REGEX,
                top_k=8,
            )

        self.assertEqual(result.cve_id, "CVE-2024-4999")
        self.assertFalse(result.anchors)
        self.assertFalse(result.slices)
        self.assertFalse(result.candidates)
        self.assertTrue(any("Source parsing failed" in diagnostic for diagnostic in result.diagnostics))
        self.assertTrue(result.metadata.get("skipped"))
        self.assertEqual(result.metadata.get("skip_reason"), "source_parse_failure")


if __name__ == "__main__":
    unittest.main()
