"""Tests for patch-aware analysis."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from rcpatch.chains import CausalityChainConstructor
from rcpatch.models import (
    AnalysisConfig,
    BugReport,
    BugType,
    EvidenceKind,
    ParserBackend,
    PatchEvidence,
    PatchIntent,
    RuntimeEvidence,
    SourceLocation,
    StackFrame,
    TriggerPoint,
    TriggerType,
)
from rcpatch.patch_analysis import PatchAwareAnalyzer
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

SAMPLE_DIFF = """\
diff --git a/src/sample.c b/src/sample.c
index 1111111..2222222 100644
--- a/src/sample.c
+++ b/src/sample.c
@@ -4,4 +4,4 @@ int compute_size(int n) {
-    int len = n + 4;
+    int len = n;
     return len;
 }
"""


class PatchAwareAnalysisTests(unittest.TestCase):
    def test_patch_aware_analyzer_uses_diff_as_weak_supervision(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir) / "repo"
            src_root = repo_root / "src"
            src_root.mkdir(parents=True)
            (src_root / "sample.c").write_text(SAMPLE_SOURCE, encoding="utf-8")

            diff_path = Path(temp_dir) / "fix.diff"
            diff_path.write_text(SAMPLE_DIFF, encoding="utf-8")

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
                bug_id="bugrc-phase7-sample",
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
                patch_evidence=PatchEvidence(
                    diff_path=diff_path.as_posix(),
                    commit_message="fix incorrect length calculation causing overflow",
                    issue_text="Buffer overflow is caused by a bad size computation in compute_size.",
                ),
                config=AnalysisConfig(
                    top_k_candidates=10,
                    max_chain_paths=5,
                    confidence_threshold=0.05,
                    bug_type_hint=BugType.BUFFER_OVERFLOW,
                    enable_patch_analysis=True,
                ),
            )

            backward_slice = HybridBackwardSlicer(max_interprocedural_hops=3).slice_from_trigger(index, trigger)
            candidates = RootCauseCandidateExtractor().extract_candidates(bug_report, backward_slice)
            chains = CausalityChainConstructor().construct_chains(bug_report, candidates, backward_slice)

            original_top_score = candidates[0].score
            patch_result = PatchAwareAnalyzer().analyze(
                bug_report,
                program_index=index,
                candidates=candidates,
                chains=chains,
            )

            self.assertIsNotNone(patch_result.patch_evidence)
            self.assertEqual(patch_result.patch_evidence.patch_intent, PatchIntent.DIRECT_FIX)
            self.assertTrue(any(location.location.line == 5 for location in patch_result.mapped_locations))
            self.assertTrue(any(location.location.function == "compute_size" for location in patch_result.mapped_locations))

            top_candidate = patch_result.candidates[0]
            self.assertEqual(top_candidate.location.line, 5)
            self.assertTrue(top_candidate.features["supported_by_patch"])
            self.assertTrue(top_candidate.features["patch_exact_overlap"])
            self.assertEqual(top_candidate.features["patch_intent"], PatchIntent.DIRECT_FIX.value)
            self.assertGreater(top_candidate.score, original_top_score)
            self.assertTrue(any(evidence.kind == EvidenceKind.PATCH_DIFF for evidence in top_candidate.evidence))

            self.assertTrue(patch_result.chains)
            top_chain = patch_result.chains[0]
            self.assertTrue(top_chain.metadata["patch_supported"])
            self.assertEqual(top_chain.metadata["patch_intent"], PatchIntent.DIRECT_FIX.value)
            self.assertTrue(any(evidence.kind == EvidenceKind.PATCH_DIFF for evidence in top_chain.steps[0].evidence))


if __name__ == "__main__":
    unittest.main()
