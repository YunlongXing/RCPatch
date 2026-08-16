"""Smoke tests for the RCPatch data model layer."""

from __future__ import annotations

import json
import unittest

from rcpatch.errors import ModelValidationError
from rcpatch.models import AnalysisResult, BugReport, SourceLocation
from rcpatch.models.schema_registry import generate_schema_bundle


BUG_REPORT_EXAMPLE = {
    "bug_id": "example_bug_001",
    "repo_path": "/tmp/repo",
    "language": "c_cpp",
    "trigger_point": {
        "location": {
            "file": "src/foo.c",
            "line": 312,
            "column": 9,
            "function": "process_input",
        },
        "type": "asan_report",
        "failing_operation": "memcpy",
    },
    "config": {
        "enable_patch_analysis": True,
        "enable_llm": False,
        "top_k_candidates": 3,
        "max_chain_paths": 2,
    },
}


ANALYSIS_RESULT_EXAMPLE = {
    "bug_id": "example_bug_001",
    "trigger_point": {
        "location": {
            "file": "src/foo.c",
            "line": 312,
            "column": 9,
            "function": "process_input",
        },
        "type": "asan_report",
    },
    "root_cause_candidates": [
        {
            "rank": 1,
            "location": {"file": "src/parser.c", "line": 145, "function": "parse_header"},
            "label": "root_cause_candidate",
            "score": 0.91,
            "explanation": "Incorrect size computation later reaches memcpy.",
        }
    ],
    "chains": [
        {
            "rank": 1,
            "root_cause_rank": 1,
            "score": 0.88,
            "steps": [
                {
                    "location": {"file": "src/parser.c", "line": 145, "function": "parse_header"},
                    "relation": "state_update",
                    "entity": "len",
                    "explanation": "Incorrect length is computed here.",
                }
            ],
            "summary": "Incorrect length computation propagates to the trigger.",
        }
    ],
}


class ModelTests(unittest.TestCase):
    def test_source_location_validation(self) -> None:
        with self.assertRaises(ModelValidationError):
            SourceLocation.from_dict({"file": "src/foo.c", "line": 0})

    def test_bug_report_roundtrip(self) -> None:
        report = BugReport.from_dict(BUG_REPORT_EXAMPLE)
        payload = json.loads(report.to_json())
        self.assertEqual(payload["bug_id"], BUG_REPORT_EXAMPLE["bug_id"])
        self.assertEqual(payload["config"]["top_k_candidates"], 3)

    def test_analysis_result_rank_validation(self) -> None:
        AnalysisResult.from_dict(ANALYSIS_RESULT_EXAMPLE)

    def test_schema_bundle_contains_top_level_models(self) -> None:
        schema_bundle = generate_schema_bundle()
        self.assertIn("BugReport", schema_bundle)
        self.assertIn("AnalysisResult", schema_bundle)


if __name__ == "__main__":
    unittest.main()
