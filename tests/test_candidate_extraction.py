"""Tests for root-cause candidate extraction."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from rcpatch.models import (
    AnalysisConfig,
    BugReport,
    BugType,
    CandidateLabel,
    ParserBackend,
    RuntimeEvidence,
    SourceLocation,
    StackFrame,
    TriggerPoint,
    TriggerType,
)
from rcpatch.ranking import RootCauseCandidateExtractor
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


class CandidateExtractionTests(unittest.TestCase):
    def test_root_cause_candidate_extractor_prefers_upstream_state_origin(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir) / "repo"
            src_root = repo_root / "src"
            src_root.mkdir(parents=True)
            (src_root / "sample.c").write_text(SAMPLE_SOURCE, encoding="utf-8")

            parser = SourceProjectParser()
            program = parser.parse_repository(repo_root, preferred_backend=ParserBackend.REGEX)
            index = parser.build_index(program)

            trigger = TriggerPoint(
                location=SourceLocation(file="src/sample.c", line=20, function="do_work"),
                type=TriggerType.CRASH_LINE,
                failing_operation="memcpy",
                bug_type_hint=BugType.BUFFER_OVERFLOW,
            )
            bug_report = BugReport(
                bug_id="bugrc-phase5-sample",
                repo_path=repo_root.as_posix(),
                trigger_point=trigger,
                runtime_evidence=RuntimeEvidence(
                    stack_trace_path="artifacts/stack.txt",
                    stack_frames=[
                        StackFrame(
                            index=0,
                            function="do_work",
                            location=SourceLocation(file="src/sample.c", line=22, function="do_work"),
                        )
                    ],
                ),
                config=AnalysisConfig(
                    top_k_candidates=10,
                    confidence_threshold=0.05,
                    bug_type_hint=BugType.BUFFER_OVERFLOW,
                ),
            )

            backward_slice = HybridBackwardSlicer(max_interprocedural_hops=3).slice_from_trigger(index, trigger)
            candidates = RootCauseCandidateExtractor().extract_candidates(bug_report, backward_slice)

            self.assertEqual(len(candidates), 10)
            self.assertEqual([candidate.rank for candidate in candidates], [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])

            top_candidate = candidates[0]
            self.assertEqual(top_candidate.location.file, "src/sample.c")
            self.assertEqual(top_candidate.location.line, 5)
            self.assertEqual(top_candidate.label, CandidateLabel.ROOT_CAUSE_CANDIDATE)
            self.assertEqual(top_candidate.features["matched_bug_pattern"], "incorrect_size_computation")
            self.assertTrue(top_candidate.features["defines_value_used_later"])
            self.assertGreater(top_candidate.score, 0.7)

            trigger_candidate = next(candidate for candidate in candidates if candidate.location.line == 22)
            self.assertEqual(trigger_candidate.label, CandidateLabel.SYMPTOM)
            self.assertTrue(trigger_candidate.features["is_trigger_node"])
            self.assertGreater(trigger_candidate.features["runtime_support_score"], 0.7)

            self.assertTrue(any(candidate.label == CandidateLabel.PROPAGATION for candidate in candidates))


if __name__ == "__main__":
    unittest.main()
