"""Tests for CVE patch extraction and fix-commit resolution."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from rcpatch.cve_mining import CVEPatchExtractor
from rcpatch.models import (
    AdvisoryReference,
    AdvisorySourceKind,
    CVEAffectedVersion,
    CVEPatchExtraction,
    CVEPatchType,
    CVETraceability,
    CollectedCVERecord,
    Language,
    PatchEvidence,
    PatchIntent,
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


@unittest.skipUnless(shutil.which("git"), "git is required for CVE patch extraction tests")
class CVEPatchExtractionTests(unittest.TestCase):
    def test_extracts_structured_patch_from_direct_commit_reference(self) -> None:
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
                "void copy_data(char *dst, const char *src, int len, int cap) {\n"
                "    memcpy(dst, src, len);\n"
                "}\n",
                encoding="utf-8",
            )
            _git(repo_root, "add", ".")
            _git(repo_root, "commit", "-m", "initial vulnerable version")

            source_path.write_text(
                "#include <string.h>\n"
                "void copy_data(char *dst, const char *src, int len, int cap) {\n"
                "    if (len > cap) {\n"
                "        len = cap;\n"
                "    }\n"
                "    memcpy(dst, src, len);\n"
                "}\n",
                encoding="utf-8",
            )
            _git(repo_root, "add", ".")
            _git(repo_root, "commit", "-m", "CVE-2024-3000 fix bounds check in copy_data")
            fix_commit = _git(repo_root, "rev-parse", "HEAD")

            record = CollectedCVERecord(
                cve_id="CVE-2024-3000",
                project="sample",
                repo_url="https://github.com/example/sample",
                repo_provider=RepositoryProvider.GITHUB,
                description="A buffer overflow occurs when len exceeds the destination capacity.",
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

            result = CVEPatchExtractor().extract_for_record(record, repo_path=repo_root.as_posix())

        self.assertIsNotNone(result.resolved_fix_commit)
        self.assertEqual(result.resolved_fix_commit.commit_sha, fix_commit)
        self.assertEqual(result.patch_type, CVEPatchType.BOUNDS_FIX)
        self.assertEqual(result.patch_intent, PatchIntent.DIRECT_FIX)
        self.assertEqual(result.modified_files, ["src/sample.c"])
        self.assertEqual(result.patches[0].changed_functions, ["copy_data"])
        self.assertIn("memcpy(dst, src, len);", result.patches[0].before)
        self.assertIn("if (len > cap)", result.patches[0].after)
        self.assertTrue(result.patches[0].hunks[0].added_statements)

    def test_searches_git_history_when_fix_commit_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir) / "repo"
            repo_root.mkdir()
            _git(repo_root, "init")
            _git(repo_root, "config", "user.name", "RCPatch")
            _git(repo_root, "config", "user.email", "bugrc@example.com")

            src_dir = repo_root / "src"
            src_dir.mkdir()
            source_path = src_dir / "demo.c"
            source_path.write_text(
                "int parse_size(int len) {\n"
                "    return len + 8;\n"
                "}\n",
                encoding="utf-8",
            )
            _git(repo_root, "add", ".")
            _git(repo_root, "commit", "-m", "initial version")

            source_path.write_text(
                "int parse_size(int len) {\n"
                "    if (len < 0) {\n"
                "        return 0;\n"
                "    }\n"
                "    return len;\n"
                "}\n",
                encoding="utf-8",
            )
            _git(repo_root, "add", ".")
            _git(repo_root, "commit", "-m", "Fix CVE-2024-3001 from issue #42")
            fix_commit = _git(repo_root, "rev-parse", "HEAD")

            record = CollectedCVERecord(
                cve_id="CVE-2024-3001",
                project="demo",
                repo_url="https://github.com/example/demo",
                repo_provider=RepositoryProvider.GITHUB,
                description="Negative lengths can lead to incorrect size handling.",
                language=Language.C,
                references=[
                    AdvisoryReference(
                        url="https://github.com/example/demo/issues/42",
                        source="advisory",
                        reference_type=ReferenceType.ISSUE,
                        repo_url="https://github.com/example/demo",
                        provider=RepositoryProvider.GITHUB,
                        issue_id="42",
                    )
                ],
                traceability=CVETraceability(source_kind=AdvisorySourceKind.NVD_JSON_FEED),
            )

            result = CVEPatchExtractor().extract_for_record(record, repo_path=repo_root.as_posix())

        self.assertIsNotNone(result.resolved_fix_commit)
        self.assertEqual(result.resolved_fix_commit.commit_sha, fix_commit)
        self.assertIn("cve_id_search", result.resolved_fix_commit.matched_by)
        self.assertEqual(result.patch_type, CVEPatchType.ADDED_CHECK)
        self.assertTrue(any(candidate.commit_sha == fix_commit for candidate in result.fix_commit_candidates))

    def test_git_output_with_invalid_utf8_is_decoded_lossily(self) -> None:
        extractor = CVEPatchExtractor()
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir)
            completed = subprocess.CompletedProcess(
                args=["git", "log"],
                returncode=0,
                stdout=b"subject:\x9cbad-bytes\n",
                stderr=b"",
            )
            with mock.patch("subprocess.run", return_value=completed):
                result = extractor._run_git(repo_root, ["log", "-1", "--format=%s", "deadbeef"], allow_failure=False)

        self.assertIn("subject:", result)
        self.assertIn("bad-bytes", result)

    def test_missing_commit_is_negative_cached(self) -> None:
        extractor = CVEPatchExtractor()
        repo_root = Path("/tmp/fake-repo")
        commit_sha = "deadbeef"

        with mock.patch.object(extractor, "_has_commit", return_value=False) as has_commit:
            with mock.patch.object(extractor, "_run_git", return_value=None) as run_git:
                first = extractor._ensure_commit_available(repo_root, commit_sha)
                second = extractor._ensure_commit_available(repo_root, commit_sha)

        self.assertFalse(first)
        self.assertFalse(second)
        self.assertEqual(has_commit.call_count, 4)
        self.assertEqual(run_git.call_count, 3)

    def test_blank_commit_message_is_normalized_to_none(self) -> None:
        extraction = CVEPatchExtraction(cve_id="CVE-2024-9999", commit_message="   ")
        evidence = PatchEvidence(commit_message="   ")

        self.assertIsNone(extraction.commit_message)
        self.assertIsNone(evidence.commit_message)


if __name__ == "__main__":
    unittest.main()
