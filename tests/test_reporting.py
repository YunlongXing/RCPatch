"""Tests for concise reporting helpers and the generic report_case script."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from rcpatch.pipeline import RCPatchPipeline, PipelineOutputManager
from rcpatch.reporting import build_concise_report, render_html_report

SCRIPTS_ROOT = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from report_case import main as report_case_main  # noqa: E402


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


class ReportingTests(unittest.TestCase):
    def test_build_concise_report_extracts_top_candidate_and_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            spec_path = _write_sample_spec(workspace)
            pipeline = RCPatchPipeline()
            artifacts = pipeline.run_analysis(spec_path)
            result = artifacts.analysis_result

            self.assertIsNotNone(result)
            assert result is not None
            report = build_concise_report(
                result,
                report_candidates=2,
                report_chains=1,
                repo_path=artifacts.bug_report.repo_path,
            )

            self.assertEqual(report["bug_id"], "report_sample")
            self.assertEqual(report["trigger"]["file"], "src/sample.c")
            self.assertIsNotNone(report["top_candidate"])
            self.assertIsNotNone(report["top_chain"])

    def test_report_case_can_run_from_bug_spec(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            spec_path = _write_sample_spec(workspace)
            report_dir = workspace / "out" / "report"

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = report_case_main(
                    [
                        "--spec",
                        spec_path.as_posix(),
                        "--output-dir",
                        report_dir.as_posix(),
                    ]
                )

            self.assertEqual(exit_code, 0)
            self.assertTrue((report_dir / "analysis_result.json").exists())
            self.assertTrue((report_dir / "concise_report.json").exists())
            self.assertTrue((report_dir / "concise_report.txt").exists())
            self.assertIn("Top candidate:", stdout.getvalue())

    def test_report_case_supports_existing_analysis_result(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            spec_path = _write_sample_spec(workspace)
            pipeline = RCPatchPipeline()
            artifacts = pipeline.run_analysis(spec_path)
            output_dir = workspace / "out" / "analysis"
            output_dir.mkdir(parents=True, exist_ok=True)
            output_manager = PipelineOutputManager()
            output_manager.export_analysis(output_dir, artifacts, summary_text=pipeline.format_result_summary(artifacts.analysis_result))

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = report_case_main(
                    [
                        "--result-json",
                        (output_dir / "analysis_result.json").as_posix(),
                        "--output-dir",
                        (workspace / "out" / "report").as_posix(),
                    ]
                )

            self.assertEqual(exit_code, 0)
            report_dir = workspace / "out" / "report"
            self.assertTrue((report_dir / "concise_report.json").exists())
            self.assertTrue((report_dir / "concise_report.txt").exists())
            self.assertIn("RCPatch concise report for report_sample", stdout.getvalue())

    def test_export_analysis_writes_html_report_and_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            spec_path = _write_sample_spec(workspace)
            pipeline = RCPatchPipeline()
            artifacts = pipeline.run_analysis(spec_path)
            output_dir = workspace / "out" / "analysis"
            output_manager = PipelineOutputManager()
            exported = output_manager.export_analysis(
                output_dir,
                artifacts,
                summary_text=pipeline.format_result_summary(artifacts.analysis_result),
            )

            self.assertIn("analysis_report_html", exported)
            self.assertIn("run_manifest", exported)
            html = (output_dir / "analysis_report.html").read_text(encoding="utf-8")
            manifest = json.loads((output_dir / "run_manifest.json").read_text(encoding="utf-8"))

            self.assertIn("RCPatch Evidence Report", html)
            self.assertEqual(manifest["bug_id"], "report_sample")
            self.assertEqual(manifest["metrics"]["candidate_count"], len(artifacts.candidates))

    def test_render_html_report_escapes_content(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            spec_path = _write_sample_spec(workspace)
            pipeline = RCPatchPipeline()
            artifacts = pipeline.run_analysis(spec_path)
            assert artifacts.analysis_result is not None

            html = render_html_report(
                artifacts.analysis_result.model_copy(update={"summary": "<unsafe>"}),
                repo_path=artifacts.bug_report.repo_path,
            )

            self.assertIn("&lt;unsafe&gt;", html)
            self.assertNotIn("<unsafe>", html)


def _write_sample_spec(workspace: Path) -> Path:
    repo_root = workspace / "repo"
    src_root = repo_root / "src"
    src_root.mkdir(parents=True)
    (src_root / "sample.c").write_text(SAMPLE_SOURCE, encoding="utf-8")

    spec_path = workspace / "bug.json"
    spec_path.write_text(
        json.dumps(
            {
                "bug_id": "report_sample",
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
