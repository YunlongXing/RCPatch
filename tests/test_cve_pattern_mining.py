"""Tests for reusable root-cause pattern mining."""

from __future__ import annotations

import unittest

from rcpatch.cve_mining import RootCausePatternMiner
from rcpatch.models import (
    BackwardSlice,
    CVERootCauseAnnotation,
    CVERootCauseDataset,
    CVERootCauseDatasetRecord,
    CVERootCauseMiningResult,
    DependencyEdge,
    DependencyRelation,
    SliceNode,
    SourceLocation,
    TriggerPoint,
    TriggerType,
)


class RootCausePatternMinerTests(unittest.TestCase):
    def test_pattern_miner_clusters_size_patterns(self) -> None:
        miner = RootCausePatternMiner(min_support=2)
        library = miner.mine(self._dataset(), mining_results_by_cve=self._mining_results())

        self.assertEqual(len(library.patterns), 1)
        pattern = library.patterns[0]
        self.assertEqual(pattern.category, "incorrect_size_computation")
        self.assertEqual(pattern.support_count, 2)
        self.assertEqual(pattern.operation_type, "length_calculation")
        self.assertEqual(pattern.graph_pattern.signature, "data_dependence -> call_argument")
        self.assertIn("<size_var>", pattern.templates[0].template)
        self.assertIn("patch_relation", [rule.feature for rule in pattern.feature_rules])

    def test_pattern_miner_emits_multiple_patterns_with_low_support_threshold(self) -> None:
        miner = RootCausePatternMiner(min_support=1)
        library = miner.mine(self._dataset(), mining_results_by_cve=self._mining_results())

        self.assertEqual(len(library.patterns), 2)
        categories = {pattern.category for pattern in library.patterns}
        self.assertIn("incorrect_size_computation", categories)
        self.assertIn("ownership_or_lifetime_operation", categories)

        lifetime_pattern = next(
            pattern for pattern in library.patterns if pattern.category == "ownership_or_lifetime_operation"
        )
        self.assertEqual(lifetime_pattern.operation_type, "lifetime_management")
        self.assertIn("<free_op>", lifetime_pattern.templates[0].template)

    @staticmethod
    def _dataset() -> CVERootCauseDataset:
        return CVERootCauseDataset(
            records=[
                CVERootCauseDatasetRecord(
                    cve_id="CVE-2026-1001",
                    project="demo-one",
                    root_causes=[
                        CVERootCauseAnnotation(
                            rank=1,
                            location=SourceLocation(file="src/a.c", line=10, function="parse"),
                            code_snippet="10: int payload_len = input[0] + 8;",
                            type="incorrect_size_computation",
                            classification="root_cause_candidate",
                            pattern="incorrect_size_computation",
                            explanation="This length is too large and later reaches memcpy.",
                            confidence=0.93,
                            patch_relation="patched_statement",
                            candidate_rank=1,
                            candidate_origin="upstream_slice",
                        )
                    ],
                ),
                CVERootCauseDatasetRecord(
                    cve_id="CVE-2026-1002",
                    project="demo-two",
                    root_causes=[
                        CVERootCauseAnnotation(
                            rank=1,
                            location=SourceLocation(file="src/b.c", line=21, function="decode"),
                            code_snippet="21: size_t msg_len = header_len + 4;",
                            type="incorrect_size_computation",
                            classification="root_cause_candidate",
                            pattern="incorrect_size_computation",
                            explanation="This computed message size is propagated into a copy length.",
                            confidence=0.88,
                            patch_relation="patched_statement",
                            candidate_rank=1,
                            candidate_origin="upstream_slice",
                        )
                    ],
                ),
                CVERootCauseDatasetRecord(
                    cve_id="CVE-2026-1003",
                    project="demo-three",
                    root_causes=[
                        CVERootCauseAnnotation(
                            rank=1,
                            location=SourceLocation(file="src/c.c", line=42, function="release_ctx"),
                            code_snippet="42: free(buf);",
                            type="ownership_or_lifetime_operation",
                            classification="root_cause_candidate",
                            pattern="ownership_or_lifetime_operation",
                            explanation="The buffer is freed while aliases still remain.",
                            confidence=0.85,
                            patch_relation="same_function_as_patch",
                            candidate_rank=1,
                            candidate_origin="upstream_slice",
                        )
                    ],
                ),
            ]
        )

    @staticmethod
    def _mining_results() -> dict[str, CVERootCauseMiningResult]:
        return {
            "CVE-2026-1001": CVERootCauseMiningResult(
                cve_id="CVE-2026-1001",
                repo_path="/tmp/demo-one",
                slices=[
                    BackwardSlice(
                        trigger=TriggerPoint(
                            location=SourceLocation(file="src/a.c", line=30, function="copy_payload"),
                            type=TriggerType.CRASH_LINE,
                            failing_operation="memcpy",
                        ),
                        trigger_node_id="n3",
                        nodes=[
                            SliceNode(
                                node_id="n1",
                                statement_id="s1",
                                function_id="f1",
                                function_name="parse",
                                location=SourceLocation(file="src/a.c", line=10, function="parse"),
                                text="int payload_len = input[0] + 8;",
                            ),
                            SliceNode(
                                node_id="n2",
                                statement_id="s2",
                                function_id="f2",
                                function_name="handle",
                                location=SourceLocation(file="src/a.c", line=20, function="handle"),
                                text="copy(dst, payload_len);",
                            ),
                            SliceNode(
                                node_id="n3",
                                statement_id="s3",
                                function_id="f3",
                                function_name="copy_payload",
                                location=SourceLocation(file="src/a.c", line=30, function="copy_payload"),
                                text="memcpy(dst, src, payload_len);",
                                is_trigger=True,
                            ),
                        ],
                        edges=[
                            DependencyEdge(source_node_id="n1", target_node_id="n2", relation=DependencyRelation.DATA_DEPENDENCE),
                            DependencyEdge(source_node_id="n2", target_node_id="n3", relation=DependencyRelation.CALL_ARGUMENT),
                        ],
                    )
                ],
            ),
            "CVE-2026-1002": CVERootCauseMiningResult(
                cve_id="CVE-2026-1002",
                repo_path="/tmp/demo-two",
                slices=[
                    BackwardSlice(
                        trigger=TriggerPoint(
                            location=SourceLocation(file="src/b.c", line=40, function="copy_msg"),
                            type=TriggerType.CRASH_LINE,
                            failing_operation="memcpy",
                        ),
                        trigger_node_id="m3",
                        nodes=[
                            SliceNode(
                                node_id="m1",
                                statement_id="t1",
                                function_id="g1",
                                function_name="decode",
                                location=SourceLocation(file="src/b.c", line=21, function="decode"),
                                text="size_t msg_len = header_len + 4;",
                            ),
                            SliceNode(
                                node_id="m2",
                                statement_id="t2",
                                function_id="g2",
                                function_name="dispatch",
                                location=SourceLocation(file="src/b.c", line=32, function="dispatch"),
                                text="forward(msg_len);",
                            ),
                            SliceNode(
                                node_id="m3",
                                statement_id="t3",
                                function_id="g3",
                                function_name="copy_msg",
                                location=SourceLocation(file="src/b.c", line=40, function="copy_msg"),
                                text="memcpy(dst, src, msg_len);",
                                is_trigger=True,
                            ),
                        ],
                        edges=[
                            DependencyEdge(source_node_id="m1", target_node_id="m2", relation=DependencyRelation.DATA_DEPENDENCE),
                            DependencyEdge(source_node_id="m2", target_node_id="m3", relation=DependencyRelation.CALL_ARGUMENT),
                        ],
                    )
                ],
            ),
            "CVE-2026-1003": CVERootCauseMiningResult(
                cve_id="CVE-2026-1003",
                repo_path="/tmp/demo-three",
                slices=[
                    BackwardSlice(
                        trigger=TriggerPoint(
                            location=SourceLocation(file="src/c.c", line=60, function="reuse"),
                            type=TriggerType.CRASH_LINE,
                            failing_operation="read",
                        ),
                        trigger_node_id="u2",
                        nodes=[
                            SliceNode(
                                node_id="u1",
                                statement_id="r1",
                                function_id="h1",
                                function_name="release_ctx",
                                location=SourceLocation(file="src/c.c", line=42, function="release_ctx"),
                                text="free(buf);",
                            ),
                            SliceNode(
                                node_id="u2",
                                statement_id="r2",
                                function_id="h2",
                                function_name="reuse",
                                location=SourceLocation(file="src/c.c", line=60, function="reuse"),
                                text="return buf[0];",
                                is_trigger=True,
                            ),
                        ],
                        edges=[
                            DependencyEdge(source_node_id="u1", target_node_id="u2", relation=DependencyRelation.DEALLOCATION_SITE),
                        ],
                    )
                ],
            ),
        }


if __name__ == "__main__":
    unittest.main()
