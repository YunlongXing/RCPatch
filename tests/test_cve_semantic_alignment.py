"""Tests for CVE-aware semantic alignment."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from rcpatch.cve_mining import CVESemanticAligner
from rcpatch.llm import (
    LLMClient,
    SemanticDisambiguator,
    StaticLLMProvider,
    CVECandidateAlignmentInput,
    build_cve_candidate_alignment_prompt,
)
from rcpatch.models import (
    AdvisorySourceKind,
    CandidateLabel,
    CollectedCVERecord,
    CVEPatchExtraction,
    CVEPatchType,
    CVETraceability,
    CVERootCauseMiningResult,
    DependencyEdge,
    DependencyRelation,
    Language,
    ParserBackend,
    RootCauseCandidate,
    SliceNode,
    SourceLocation,
    StructuredPatchFile,
    StructuredPatchHunk,
    TriggerPoint,
    TriggerType,
    BackwardSlice,
    RepositoryProvider,
)


class CVESemanticAlignmentTests(unittest.TestCase):
    def test_cve_alignment_prompt_contains_required_sections(self) -> None:
        candidate = RootCauseCandidate(
            rank=1,
            location=SourceLocation(file="src/parser.c", line=12, function="parse_size"),
            label=CandidateLabel.PROPAGATION,
            score=0.72,
            explanation="Heuristic upstream size computation candidate.",
            features={"candidate_origin": "upstream_slice", "tracked_entities": ["payload_len"]},
        )
        prompt = build_cve_candidate_alignment_prompt(
            CVECandidateAlignmentInput(
                cve_id="CVE-2026-1111",
                cve_description="A size miscalculation can overflow the destination buffer.",
                candidate=candidate,
                candidate_source_code="int payload_len = input[0] + 8;",
                surrounding_function_code="int parse_size(const unsigned char *input) {\n    int payload_len = input[0] + 8;\n    return payload_len;\n}",
                dependency_summary="payload_len flows into memcpy size at the patched call site.",
                patch_diff="@@ -2 +2 @@\n-int payload_len = input[0] + 8;\n+int payload_len = input[0];",
            )
        )

        self.assertEqual(prompt.task, "cve_candidate_semantic_alignment")
        self.assertIn("cve_id", prompt.user_prompt)
        self.assertIn("description", prompt.user_prompt)
        self.assertIn("candidate_source_code", prompt.user_prompt)
        self.assertIn("surrounding_function_code", prompt.user_prompt)
        self.assertIn("dependency_summary", prompt.user_prompt)
        self.assertIn("patch_diff", prompt.user_prompt)

    def test_cve_semantic_aligner_returns_structured_alignment(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = self._build_repo(Path(temp_dir))
            aligner = CVESemanticAligner(
                semantic_disambiguator=SemanticDisambiguator(
                    llm_client=LLMClient(
                        provider=StaticLLMProvider(
                            response_text=(
                                '{"label":"root_cause","reasoning":"The CVE describes an incorrect payload length '
                                'calculation, and this statement computes the oversized length later used by memcpy.",'
                                '"confidence":0.89}'
                            )
                        )
                    )
                )
            )

            result = aligner.align_candidates(
                self._record(),
                self._mining_result(repo_root),
                patch_extraction=self._patch_extraction(),
                repo_path=repo_root.as_posix(),
                parser_backend=ParserBackend.REGEX,
                top_k=1,
            )

            self.assertEqual(result.cve_id, "CVE-2026-1111")
            self.assertEqual(len(result.alignments), 1)
            alignment = result.alignments[0]
            self.assertEqual(alignment.label, CandidateLabel.ROOT_CAUSE_CANDIDATE)
            self.assertEqual(alignment.heuristic_label, CandidateLabel.PROPAGATION)
            self.assertGreater(alignment.confidence, 0.6)
            self.assertIn("incorrect payload length", alignment.reasoning)
            self.assertIsNotNone(alignment.llm_judgment)
            self.assertEqual(alignment.llm_judgment.task, "cve_candidate_semantic_alignment")
            self.assertEqual(alignment.candidate_origin, "upstream_slice")

    def test_cve_semantic_aligner_falls_back_to_heuristics(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = self._build_repo(Path(temp_dir))
            aligner = CVESemanticAligner(
                semantic_disambiguator=SemanticDisambiguator(
                    llm_client=LLMClient(provider=StaticLLMProvider(response_text="", available=False))
                )
            )

            result = aligner.align_candidates(
                self._record(),
                self._mining_result(repo_root),
                patch_extraction=self._patch_extraction(),
                repo_path=repo_root.as_posix(),
                parser_backend=ParserBackend.REGEX,
                top_k=1,
            )

            alignment = result.alignments[0]
            self.assertEqual(alignment.label, CandidateLabel.PROPAGATION)
            self.assertIsNotNone(alignment.llm_judgment)
            self.assertEqual(alignment.llm_judgment.provider, "fallback")
            self.assertTrue(alignment.llm_judgment.metadata["fallback"])

    @staticmethod
    def _build_repo(root: Path) -> Path:
        source_dir = root / "src"
        source_dir.mkdir(parents=True, exist_ok=True)
        (source_dir / "parser.c").write_text(
            "\n".join(
                [
                    "int parse_size(const unsigned char *input) {",
                    "    int payload_len = input[0] + 8;",
                    "    return payload_len;",
                    "}",
                    "",
                    "int copy_payload(char *dst, const unsigned char *input) {",
                    "    int payload_len = parse_size(input);",
                    "    memcpy(dst, input + 1, payload_len);",
                    "    return payload_len;",
                    "}",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        return root

    @staticmethod
    def _record() -> CollectedCVERecord:
        return CollectedCVERecord(
            cve_id="CVE-2026-1111",
            project="demo-parser",
            repo_url="https://github.com/example/demo-parser",
            repo_provider=RepositoryProvider.GITHUB,
            description="A crafted packet can trigger a buffer overflow because payload length is calculated too large before memcpy.",
            language=Language.C_CPP,
            traceability=CVETraceability(
                source_kind=AdvisorySourceKind.PROJECT_ADVISORY,
                source_locator="https://example.com/advisories/CVE-2026-1111",
            ),
        )

    @staticmethod
    def _patch_extraction() -> CVEPatchExtraction:
        return CVEPatchExtraction(
            cve_id="CVE-2026-1111",
            repo_url="https://github.com/example/demo-parser",
            patch_type=CVEPatchType.BOUNDS_FIX,
            modified_files=["src/parser.c"],
            patches=[
                StructuredPatchFile(
                    file="src/parser.c",
                    changed_functions=["parse_size"],
                    hunks=[
                        StructuredPatchHunk(
                            hunk_index=0,
                            old_start=2,
                            old_count=1,
                            new_start=2,
                            new_count=1,
                            function="parse_size",
                            before="    int payload_len = input[0] + 8;",
                            after="    int payload_len = input[0];",
                            removed_statements=["int payload_len = input[0] + 8;"],
                            added_statements=["int payload_len = input[0];"],
                        )
                    ],
                )
            ],
        )

    @staticmethod
    def _mining_result(repo_root: Path) -> CVERootCauseMiningResult:
        candidate = RootCauseCandidate(
            rank=1,
            location=SourceLocation(file="src/parser.c", line=2, function="parse_size"),
            label=CandidateLabel.PROPAGATION,
            score=0.74,
            explanation="This computes the payload length later consumed by memcpy.",
            features={
                "candidate_origin": "upstream_slice",
                "tracked_entities": ["payload_len"],
                "matched_bug_pattern": "incorrect_size_computation",
                "defines_value_later_fixed": True,
                "incorrect_computation_replaced_by_patch": True,
            },
        )
        trigger = TriggerPoint(
            location=SourceLocation(file="src/parser.c", line=8, function="copy_payload"),
            type=TriggerType.CRASH_LINE,
            failing_operation="memcpy",
        )
        slice_result = BackwardSlice(
            trigger=trigger,
            trigger_node_id="node-trigger",
            nodes=[
                SliceNode(
                    node_id="node-root",
                    statement_id="stmt-root",
                    function_id="fn-parse",
                    function_name="parse_size",
                    location=SourceLocation(file="src/parser.c", line=2, function="parse_size"),
                    text="int payload_len = input[0] + 8;",
                    tracked_entities=["payload_len"],
                ),
                SliceNode(
                    node_id="node-trigger",
                    statement_id="stmt-trigger",
                    function_id="fn-copy",
                    function_name="copy_payload",
                    location=SourceLocation(file="src/parser.c", line=8, function="copy_payload"),
                    text="memcpy(dst, input + 1, payload_len);",
                    tracked_entities=["payload_len"],
                    is_trigger=True,
                ),
            ],
            edges=[
                DependencyEdge(
                    source_node_id="node-root",
                    target_node_id="node-trigger",
                    relation=DependencyRelation.DATA_DEPENDENCE,
                    entity="payload_len",
                    explanation="payload_len returned by parse_size becomes memcpy size",
                    approximated=True,
                )
            ],
        )
        return CVERootCauseMiningResult(
            cve_id="CVE-2026-1111",
            repo_path=repo_root.as_posix(),
            slices=[slice_result],
            candidates=[candidate],
        )


if __name__ == "__main__":
    unittest.main()
