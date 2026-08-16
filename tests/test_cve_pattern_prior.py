"""Tests for CVE pattern-library ranking priors."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rcpatch.models import AnalysisConfig, BugReport, BugType, ParserBackend, SourceLocation, TriggerPoint, TriggerType
from rcpatch.ranking import CVEPatternPrior, RootCauseCandidateExtractor
from rcpatch.source import SourceProjectParser
from rcpatch.slicing import HybridBackwardSlicer


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
    memset(buf, 0, len);
    return buf;
}

void copy_data(int input) {
    char *dst = make_buffer(input);
    memcpy(dst, "AAAA", input);
}
"""


def _write_pattern_library(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "patterns": [
                    {
                        "pattern_id": "incorrect_size_computation:length_calculation:1",
                        "name": "incorrect size computation",
                        "category": "incorrect_size_computation",
                        "operation_type": "length_calculation",
                        "support_count": 500,
                        "templates": [{"template": "int len = n + CONST;", "support_count": 10}],
                        "metadata": {"average_confidence": 0.92},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )


class CVEPatternPriorTests(unittest.TestCase):
    def test_prior_loads_and_matches_category_and_operation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            library_path = Path(temp_dir) / "patterns.json"
            _write_pattern_library(library_path)

            prior = CVEPatternPrior.from_file(library_path)
            match = prior.match(
                category="incorrect_size_computation",
                text_lower="int len = n + 4;",
                affects_control_flow=False,
                has_integer_influence=True,
                has_memory_context=False,
                changes_object_state=True,
            )

            self.assertIsNotNone(match)
            assert match is not None
            self.assertGreater(match.score, 0.8)
            self.assertEqual(match.operation_type, "length_calculation")
            self.assertEqual(match.support_count, 500)

    def test_candidate_extraction_adds_cve_pattern_prior_features(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            repo_root = workspace / "repo"
            src_root = repo_root / "src"
            src_root.mkdir(parents=True)
            (src_root / "sample.c").write_text(SAMPLE_SOURCE, encoding="utf-8")
            library_path = workspace / "patterns.json"
            _write_pattern_library(library_path)

            parser = SourceProjectParser()
            program = parser.parse_repository(repo_root, preferred_backend=ParserBackend.REGEX)
            index = parser.build_index(program)
            trigger = TriggerPoint(
                location=SourceLocation(file="src/sample.c", line=16, function="copy_data"),
                type=TriggerType.CRASH_LINE,
                failing_operation="memcpy",
                bug_type_hint=BugType.BUFFER_OVERFLOW,
            )
            bug_report = BugReport(
                bug_id="cve-prior-sample",
                repo_path=repo_root.as_posix(),
                trigger_point=trigger,
                config=AnalysisConfig(
                    parser_backend=ParserBackend.REGEX,
                    top_k_candidates=5,
                    confidence_threshold=0.0,
                    bug_type_hint=BugType.BUFFER_OVERFLOW,
                    enable_cve_pattern_prior=True,
                    cve_pattern_library_path=library_path.as_posix(),
                ),
            )

            backward_slice = HybridBackwardSlicer(max_interprocedural_hops=2).slice_from_trigger(index, trigger)
            candidates = RootCauseCandidateExtractor().extract_candidates(bug_report, backward_slice)
            matched = [
                candidate
                for candidate in candidates
                if candidate.features.get("matched_bug_pattern") == "incorrect_size_computation"
            ]

            self.assertTrue(matched)
            self.assertGreater(float(matched[0].features["cve_pattern_prior_score"]), 0.0)
            self.assertGreater(matched[0].confidence.components.get("cve_pattern_prior", 0.0), 0.0)


if __name__ == "__main__":
    unittest.main()
