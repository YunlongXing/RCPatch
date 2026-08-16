"""Tests for bug ingestion, runtime parsing, and trigger normalization."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rcpatch.dynamic_analysis import AsanLikeSanitizerParser, StackTraceParser
from rcpatch.ingestion import BugIngestionService, SourcePathResolver
from rcpatch.models import BugType


ASAN_REPORT = """\
==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020000000f0 at pc 0x000000401234 bp 0x7ffee sp 0x7ffdd
WRITE of size 16 at 0x6020000000f0 thread T0
    #0 0x401234 in process_input /tmp/project/src/foo.c:312:9
    #1 0x401111 in handle_msg /tmp/project/src/core.c:218:5
SUMMARY: AddressSanitizer: heap-buffer-overflow /tmp/project/src/foo.c:312:9 in process_input
"""

GDB_STACK_TRACE = """\
#0 process_input at /tmp/project/src/foo.c:312:9
#1 handle_msg at /tmp/project/src/core.c:218:5
"""


class SourcePathResolverTests(unittest.TestCase):
    def test_resolves_absolute_relative_and_suffix_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir) / "repo"
            (repo_root / "src").mkdir(parents=True)
            source_file = repo_root / "src" / "foo.c"
            source_file.write_text("int main(void) { return 0; }\n", encoding="utf-8")

            resolver = SourcePathResolver(repo_root)

            self.assertEqual(resolver.normalize_source_path("src/foo.c"), "src/foo.c")
            self.assertEqual(resolver.normalize_source_path(source_file.as_posix()), "src/foo.c")
            self.assertEqual(resolver.normalize_source_path("/different/root/src/foo.c"), "src/foo.c")


class ParserTests(unittest.TestCase):
    def test_asan_parser_extracts_summary_frames_and_bug_hint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir) / "project"
            (repo_root / "src").mkdir(parents=True)
            (repo_root / "src" / "foo.c").write_text("void process_input(void) {}\n", encoding="utf-8")
            (repo_root / "src" / "core.c").write_text("void handle_msg(void) {}\n", encoding="utf-8")

            resolver = SourcePathResolver(repo_root)
            parser = AsanLikeSanitizerParser()
            result = parser.parse(
                ASAN_REPORT.replace("/tmp/project", repo_root.as_posix()),
                resolver=resolver,
                evidence_path=(repo_root / "asan.txt").as_posix(),
            )

            self.assertEqual(result.failure_summary, "AddressSanitizer: heap-buffer-overflow")
            self.assertEqual(result.failing_access, "write")
            self.assertEqual(result.trigger_frame_index, 0)
            self.assertEqual(result.bug_type_hint, BugType.BUFFER_OVERFLOW)
            self.assertEqual(result.stack_frames[0].location.file, "src/foo.c")
            self.assertEqual(result.stack_frames[0].function, "process_input")

    def test_stacktrace_parser_handles_gdb_like_format(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir) / "project"
            (repo_root / "src").mkdir(parents=True)
            (repo_root / "src" / "foo.c").write_text("void process_input(void) {}\n", encoding="utf-8")
            (repo_root / "src" / "core.c").write_text("void handle_msg(void) {}\n", encoding="utf-8")

            resolver = SourcePathResolver(repo_root)
            parser = StackTraceParser()
            parsed = parser.parse(GDB_STACK_TRACE.replace("/tmp/project", repo_root.as_posix()), resolver=resolver)

            self.assertEqual(len(parsed.frames), 2)
            self.assertEqual(parsed.frames[0].location.file, "src/foo.c")
            self.assertEqual(parsed.frames[1].function, "handle_msg")


class IngestionServiceTests(unittest.TestCase):
    def test_ingestion_service_returns_normalized_bug_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            repo_root = workspace / "repo"
            build_root = repo_root / "build"
            spec_root = workspace / "specs"
            evidence_root = workspace / "evidence"

            (repo_root / "src").mkdir(parents=True)
            build_root.mkdir(parents=True)
            spec_root.mkdir(parents=True)
            evidence_root.mkdir(parents=True)

            (repo_root / "src" / "foo.c").write_text("void process_input(void) {}\n", encoding="utf-8")
            (repo_root / "src" / "core.c").write_text("void handle_msg(void) {}\n", encoding="utf-8")
            compile_commands = build_root / "compile_commands.json"
            compile_commands.write_text("[]\n", encoding="utf-8")

            asan_path = evidence_root / "asan.txt"
            asan_path.write_text(ASAN_REPORT.replace("/tmp/project", repo_root.as_posix()), encoding="utf-8")
            stack_path = evidence_root / "stack.txt"
            stack_path.write_text(GDB_STACK_TRACE.replace("/tmp/project", repo_root.as_posix()), encoding="utf-8")
            poc_path = evidence_root / "poc.bin"
            poc_path.write_bytes(b"AAAA")
            diff_path = evidence_root / "fix.diff"
            diff_path.write_text("--- a/src/foo.c\n+++ b/src/foo.c\n", encoding="utf-8")
            issue_path = evidence_root / "issue.txt"
            issue_path.write_text("Bug description\n", encoding="utf-8")

            spec_payload = {
                "bug_id": "ingestion_001",
                "repo_path": "../repo",
                "build": {
                    "build_dir": "../repo/build",
                    "build_cmd": "cmake .. && make -j",
                    "compile_commands_path": "../repo/build/compile_commands.json",
                },
                "run": {
                    "cmd": "./foo poc.bin",
                    "poc_path": "../evidence/poc.bin",
                },
                "trigger_point": {
                    "file": str(repo_root / "src" / "foo.c"),
                    "line": 312,
                    "type": "asan_report",
                },
                "runtime_evidence": {
                    "sanitizer_report_path": "../evidence/asan.txt",
                    "stack_trace_path": "../evidence/stack.txt",
                },
                "patch_evidence": {
                    "diff_path": "../evidence/fix.diff",
                    "issue_text_path": "../evidence/issue.txt",
                },
                "config": {
                    "enable_patch_analysis": True,
                    "enable_llm": False,
                    "top_k_candidates": 5,
                    "max_chain_paths": 5,
                },
            }

            spec_path = spec_root / "bug.json"
            spec_path.write_text(json.dumps(spec_payload, indent=2), encoding="utf-8")

            service = BugIngestionService()
            bug_report = service.load_from_file(spec_path)

            self.assertEqual(bug_report.repo_path, repo_root.resolve().as_posix())
            self.assertEqual(bug_report.trigger_point.location.file, "src/foo.c")
            self.assertEqual(bug_report.trigger_point.location.function, "process_input")
            self.assertEqual(bug_report.runtime_evidence.stack_frames[0].location.file, "src/foo.c")
            self.assertEqual(bug_report.runtime_evidence.failure_summary, "AddressSanitizer: heap-buffer-overflow")
            self.assertEqual(bug_report.patch_evidence.diff_path, diff_path.resolve().as_posix())
            self.assertEqual(bug_report.build.compile_commands_path, compile_commands.resolve().as_posix())
            self.assertIn("linked_source_locations", bug_report.runtime_evidence.metadata)


if __name__ == "__main__":
    unittest.main()
