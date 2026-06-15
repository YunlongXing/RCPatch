"""Tests for expert-curated RCA ranking priors."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from bugrc.models import AnalysisConfig, BugReport, BugType, ParserBackend, SourceLocation, TriggerPoint, TriggerType
from bugrc.ranking import ExpertRCAPrior, RootCauseCandidateExtractor
from bugrc.source import SourceProjectParser
from bugrc.slicing import HybridBackwardSlicer


SAMPLE_SOURCE = """\
#include <stdlib.h>
#include <string.h>

int compute_size(int n) {
    int len = n + 4;
    return len;
}

void copy_data(int input) {
    int len = compute_size(input);
    char *dst = (char *)malloc(len);
    memcpy(dst, "AAAA", input);
}
"""


def _write_expert_prior(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "metadata": {"schema_version": "bugrc.expert_rca_prior.v1"},
                "records": [
                    {
                        "record_id": "p0-style-size-overflow",
                        "source": "google_project_zero_rca",
                        "bug_class": "Integer overflow leading to out-of-bounds access",
                        "root_cause_summary": "A length calculation trusts attacker-controlled size and allocates too small a buffer.",
                        "patch_analysis": "The fix adds bounds validation before copying into the destination buffer.",
                        "exploit_flow": "The computed length propagates to allocation and then to memcpy.",
                        "pattern_tags": ["incorrect_size_computation", "bounds_validation"],
                        "operation_types": ["length_calculation"],
                        "confidence": 0.95,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


class ExpertRCAPriorTests(unittest.TestCase):
    def test_prior_loads_and_matches_project_zero_style_record(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            prior_path = Path(temp_dir) / "expert_rca_prior.json"
            _write_expert_prior(prior_path)

            prior = ExpertRCAPrior.from_file(prior_path)
            match = prior.match(
                category="incorrect_size_computation",
                operation_type="length_calculation",
                text_lower="int len = n + 4;",
                bug_type=BugType.BUFFER_OVERFLOW.value,
            )

            self.assertIsNotNone(match)
            assert match is not None
            self.assertGreater(match.score, 0.7)
            self.assertEqual(match.category, "incorrect_size_computation")
            self.assertEqual(match.operation_type, "length_calculation")
            self.assertIn("p0-style-size-overflow", match.record_ids)

    def test_candidate_extraction_adds_expert_prior_features(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            repo_root = workspace / "repo"
            src_root = repo_root / "src"
            src_root.mkdir(parents=True)
            (src_root / "sample.c").write_text(SAMPLE_SOURCE, encoding="utf-8")
            prior_path = workspace / "expert_rca_prior.json"
            _write_expert_prior(prior_path)

            parser = SourceProjectParser()
            program = parser.parse_repository(repo_root, preferred_backend=ParserBackend.REGEX)
            index = parser.build_index(program)
            trigger = TriggerPoint(
                location=SourceLocation(file="src/sample.c", line=12, function="copy_data"),
                type=TriggerType.CRASH_LINE,
                failing_operation="memcpy",
                bug_type_hint=BugType.BUFFER_OVERFLOW,
            )
            report = BugReport(
                bug_id="expert-prior-sample",
                repo_path=repo_root.as_posix(),
                trigger_point=trigger,
                config=AnalysisConfig(
                    parser_backend=ParserBackend.REGEX,
                    top_k_candidates=5,
                    confidence_threshold=0.0,
                    bug_type_hint=BugType.BUFFER_OVERFLOW,
                    enable_expert_rca_prior=True,
                    expert_rca_prior_path=prior_path.as_posix(),
                ),
            )

            backward_slice = HybridBackwardSlicer(max_interprocedural_hops=2).slice_from_trigger(index, trigger)
            candidates = RootCauseCandidateExtractor().extract_candidates(report, backward_slice)
            matched = [
                candidate
                for candidate in candidates
                if float(candidate.features.get("expert_rca_prior_score", 0.0)) > 0.0
            ]

            self.assertTrue(matched)
            self.assertTrue(all(candidate.features.get("expert_rca_prior_enabled") for candidate in matched))
            self.assertGreater(matched[0].confidence.components.get("expert_rca_prior", 0.0), 0.0)


if __name__ == "__main__":
    unittest.main()
