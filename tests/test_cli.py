"""Tests for the RCPatch CLI integration layer."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from rcpatch.cli import main
from rcpatch.models import AnalysisResult, BugReport

SAMPLE_SOURCE = """\
#include <stdlib.h>
#include <string.h>

int compute_size(int n) {
    int len = n + 4;
    return len;
}

char *make_buffer(int input) {
    int len = compute_size(input);
    char *buf = (char *)malloc(len);
    if (buf == NULL) {
        return NULL;
    }
    memset(buf, 0, len);
    return buf;
}

void do_work(int input) {
    char *ptr = make_buffer(input);
    if (ptr != NULL) {
        memcpy(ptr, "AAAA", input);
    }
}
"""


class CLITests(unittest.TestCase):
    def test_ingest_command_writes_normalized_bug_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            spec_path = _write_sample_spec(workspace)
            output_dir = workspace / "out" / "ingest"

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = main(["ingest", spec_path.as_posix(), "--output-dir", output_dir.as_posix()])

            self.assertEqual(exit_code, 0)
            normalized_path = output_dir / "normalized_bug_report.json"
            self.assertTrue(normalized_path.exists())
            normalized = BugReport.from_json_file(normalized_path)
            self.assertEqual(normalized.trigger_point.location.file, "src/sample.c")
            self.assertIn("Trigger normalized to", stdout.getvalue())

    def test_analyze_command_applies_config_file_and_exports_results(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            spec_path = _write_sample_spec(workspace)
            config_path = workspace / "analysis_overrides.json"
            config_path.write_text(
                json.dumps(
                    {
                        "top_k_candidates": 1,
                        "max_chain_paths": 1,
                        "parser_backend": "regex",
                        "enable_patch_analysis": False,
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            output_dir = workspace / "out" / "analyze"

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = main(
                    [
                        "analyze",
                        spec_path.as_posix(),
                        "--config",
                        config_path.as_posix(),
                        "--output-dir",
                        output_dir.as_posix(),
                    ]
                )

            self.assertEqual(exit_code, 0)
            result_path = output_dir / "analysis_result.json"
            self.assertTrue(result_path.exists())
            self.assertTrue((output_dir / "ranked_candidates.json").exists())
            self.assertTrue((output_dir / "causality_chains.json").exists())
            self.assertTrue((output_dir / "analysis_summary.txt").exists())

            result = AnalysisResult.from_json_file(result_path)
            self.assertEqual(result.analysis_config.top_k_candidates, 1)
            self.assertLessEqual(len(result.root_cause_candidates), 1)
            self.assertLessEqual(len(result.chains), 1)
            self.assertIn("RCPatch analysis for cli_sample", stdout.getvalue())

    def test_explain_command_supports_existing_analysis_result(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            spec_path = _write_sample_spec(workspace)
            output_dir = workspace / "out" / "analysis"

            analyze_stdout = io.StringIO()
            with redirect_stdout(analyze_stdout):
                analyze_exit = main(
                    [
                        "analyze",
                        spec_path.as_posix(),
                        "--parser-backend",
                        "regex",
                        "--output-dir",
                        output_dir.as_posix(),
                    ]
                )
            self.assertEqual(analyze_exit, 0)

            explain_stdout = io.StringIO()
            with redirect_stdout(explain_stdout):
                explain_exit = main(
                    [
                        "explain",
                        "--result-json",
                        (output_dir / "analysis_result.json").as_posix(),
                    ]
                )

            self.assertEqual(explain_exit, 0)
            self.assertIn("Top candidates:", explain_stdout.getvalue())
            self.assertIn("Top chains:", explain_stdout.getvalue())


def _write_sample_spec(workspace: Path) -> Path:
    repo_root = workspace / "repo"
    src_root = repo_root / "src"
    src_root.mkdir(parents=True)
    (src_root / "sample.c").write_text(SAMPLE_SOURCE, encoding="utf-8")

    spec_path = workspace / "bug.json"
    spec_path.write_text(
        json.dumps(
            {
                "bug_id": "cli_sample",
                "repo_path": repo_root.as_posix(),
                "trigger_point": {
                    "file": "src/sample.c",
                    "line": 22,
                    "function": "do_work",
                    "type": "crash_line",
                    "failing_operation": "memcpy",
                },
                "runtime_evidence": {
                    "stack_frames": [
                        {
                            "index": 0,
                            "function": "do_work",
                            "location": {
                                "file": "src/sample.c",
                                "line": 22,
                                "function": "do_work",
                            },
                        }
                    ]
                },
                "config": {
                    "top_k_candidates": 5,
                    "max_chain_paths": 3,
                    "parser_backend": "regex",
                    "enable_patch_analysis": False,
                    "enable_llm": False,
                    "confidence_threshold": 0.05,
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return spec_path


if __name__ == "__main__":
    unittest.main()
