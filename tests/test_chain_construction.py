"""Tests for causality-chain construction and formatting."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from rcpatch.chains import CausalityChainConstructor, ChainTextFormatter
from rcpatch.models import (
    AnalysisConfig,
    BackwardSlice,
    BugReport,
    BugType,
    CandidateLabel,
    ParserBackend,
    PropagationRelation,
    RuntimeEvidence,
    RootCauseCandidate,
    SourceLocation,
    SliceNode,
    StackFrame,
    StatementKind,
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


class ChainConstructionTests(unittest.TestCase):
    def test_causality_chain_constructor_builds_ranked_interprocedural_paths(self) -> None:
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
                bug_id="bugrc-phase6-sample",
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
                    max_chain_paths=5,
                    confidence_threshold=0.05,
                    bug_type_hint=BugType.BUFFER_OVERFLOW,
                ),
            )

            backward_slice = HybridBackwardSlicer(max_interprocedural_hops=3).slice_from_trigger(index, trigger)
            candidates = RootCauseCandidateExtractor().extract_candidates(bug_report, backward_slice)
            self.assertEqual(candidates[0].label, CandidateLabel.ROOT_CAUSE_CANDIDATE)

            chains = CausalityChainConstructor().construct_chains(bug_report, candidates, backward_slice)
            self.assertGreaterEqual(len(chains), 2)
            self.assertEqual([chain.rank for chain in chains], list(range(1, len(chains) + 1)))

            top_chain = chains[0]
            self.assertEqual(top_chain.root_cause_rank, 1)
            self.assertEqual(top_chain.steps[0].location.line, 5)
            self.assertEqual(top_chain.steps[-1].location.line, 22)
            self.assertIn(PropagationRelation.RETURN_VALUE, {step.relation for step in top_chain.steps})
            self.assertGreater(top_chain.score, 0.6)
            self.assertIn("memcpy", top_chain.summary)

            rendered = ChainTextFormatter().format_chain(top_chain)
            self.assertIn("Chain 1", rendered)
            self.assertIn("Summary:", rendered)
            self.assertIn("memcpy", rendered)

    def test_constructor_keeps_single_step_trigger_chain_when_only_symptom_is_available(self) -> None:
        trigger = TriggerPoint(
            location=SourceLocation(file="src/sample.c", line=10, function="crash"),
            type=TriggerType.CRASH_LINE,
            failing_operation="memcpy",
        )
        bug_report = BugReport(
            bug_id="single-step",
            repo_path="/tmp/repo",
            trigger_point=trigger,
            config=AnalysisConfig(max_chain_paths=3),
        )
        node = SliceNode(
            node_id="n1",
            statement_id="s1",
            function_id="f1",
            function_name="crash",
            location=trigger.location,
            text="memcpy(dst, src, len);",
            statement_types=[StatementKind.FUNCTION_CALL],
            tracked_entities=["len"],
            is_trigger=True,
        )
        candidate = RootCauseCandidate(
            rank=1,
            location=trigger.location,
            label=CandidateLabel.SYMPTOM,
            score=0.0,
            explanation="Only the trigger statement is available.",
            metadata={"statement_id": "n1"},
        )
        backward_slice = BackwardSlice(trigger=trigger, trigger_node_id="n1", nodes=[node], edges=[])

        chains = CausalityChainConstructor().construct_chains(bug_report, [candidate], backward_slice)

        self.assertEqual(len(chains), 1)
        self.assertEqual(len(chains[0].steps), 1)
        self.assertTrue(chains[0].metadata["fallback_chain"])
        self.assertEqual(chains[0].steps[0].relation, PropagationRelation.DATA_FLOW)

    def test_constructor_adds_direct_fallback_edge_for_disconnected_candidate(self) -> None:
        trigger = TriggerPoint(
            location=SourceLocation(file="src/sample.c", line=20, function="crash"),
            type=TriggerType.CRASH_LINE,
            failing_operation="memcpy",
        )
        bug_report = BugReport(
            bug_id="direct-fallback",
            repo_path="/tmp/repo",
            trigger_point=trigger,
            config=AnalysisConfig(max_chain_paths=3),
        )
        root_node = SliceNode(
            node_id="n1",
            statement_id="s1",
            function_id="f1",
            function_name="setup",
            location=SourceLocation(file="src/sample.c", line=8, function="setup"),
            text="len = user_len;",
            statement_types=[StatementKind.ASSIGNMENT],
            tracked_entities=["len"],
        )
        trigger_node = SliceNode(
            node_id="n2",
            statement_id="s2",
            function_id="f2",
            function_name="crash",
            location=trigger.location,
            text="memcpy(dst, src, len);",
            statement_types=[StatementKind.FUNCTION_CALL],
            tracked_entities=["len"],
            is_trigger=True,
        )
        candidate = RootCauseCandidate(
            rank=1,
            location=root_node.location,
            label=CandidateLabel.ROOT_CAUSE_CANDIDATE,
            score=0.7,
            explanation="Length is introduced from user input.",
            features={"has_integer_influence": True},
            metadata={"statement_id": "n1"},
        )
        backward_slice = BackwardSlice(trigger=trigger, trigger_node_id="n2", nodes=[root_node, trigger_node], edges=[])

        chains = CausalityChainConstructor().construct_chains(bug_report, [candidate], backward_slice)

        self.assertEqual(len(chains), 1)
        self.assertEqual([step.location.line for step in chains[0].steps], [8, 20])
        self.assertTrue(chains[0].metadata["fallback_chain"])
        self.assertEqual(chains[0].steps[0].relation, PropagationRelation.DATA_FLOW)


if __name__ == "__main__":
    unittest.main()
