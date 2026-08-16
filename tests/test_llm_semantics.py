"""Tests for LLM-assisted semantic disambiguation helpers."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from rcpatch.llm import (
    CandidateDisambiguationInput,
    FileLLMCache,
    LLMClient,
    LLMResponseParser,
    SemanticDisambiguator,
    StaticLLMProvider,
    build_candidate_label_prompt,
)
from rcpatch.models import CandidateLabel, RootCauseCandidate, SourceLocation, TriggerPoint, TriggerType


class LLMSemanticsTests(unittest.TestCase):
    def test_candidate_label_prompt_contains_required_evidence_sections(self) -> None:
        trigger = TriggerPoint(
            location=SourceLocation(file="src/foo.c", line=42, function="run"),
            type=TriggerType.CRASH_LINE,
            failing_operation="memcpy",
        )
        candidate = RootCauseCandidate(
            location=SourceLocation(file="src/bar.c", line=12, function="compute"),
            label=CandidateLabel.PROPAGATION,
            score=0.61,
            explanation="Heuristic candidate.",
            features={"distance_to_trigger": 3, "tracked_entities": ["len"]},
        )
        prompt = build_candidate_label_prompt(
            CandidateDisambiguationInput(
                trigger_point=trigger,
                candidate=candidate,
                candidate_source_code="int len = n + 4;",
                surrounding_function_code="int compute(int n) {\n    int len = n + 4;\n    return len;\n}",
                dependency_summary="len flows into memcpy size via compute -> run.",
                patch_diff="@@ -1 +1 @@\n-int len = n + 4;\n+int len = n;",
            )
        )

        self.assertEqual(prompt.task, "candidate_label_disambiguation")
        self.assertIn("trigger_point", prompt.user_prompt)
        self.assertIn("candidate_source_code", prompt.user_prompt)
        self.assertIn("surrounding_function_code", prompt.user_prompt)
        self.assertIn("dependency_summary", prompt.user_prompt)
        self.assertIn("patch_diff", prompt.user_prompt)
        self.assertIn("allowed_labels", prompt.user_prompt)

    def test_parser_handles_json_code_fences_and_label_mapping(self) -> None:
        parser = LLMResponseParser()
        decision = parser.parse_candidate_label(
            """```json
            {"label":"root_cause","reasoning":"This introduces the wrong length.","confidence":0.84}
            ```"""
        )
        self.assertEqual(decision.verdict, CandidateLabel.ROOT_CAUSE_CANDIDATE.value)
        self.assertEqual(decision.raw_label, "root_cause")
        self.assertAlmostEqual(decision.confidence, 0.84, places=2)

    def test_semantic_disambiguator_uses_cache_and_fallback(self) -> None:
        trigger = TriggerPoint(
            location=SourceLocation(file="src/foo.c", line=42, function="run"),
            type=TriggerType.CRASH_LINE,
            failing_operation="memcpy",
        )
        candidate = RootCauseCandidate(
            location=SourceLocation(file="src/bar.c", line=12, function="compute"),
            label=CandidateLabel.PROPAGATION,
            score=0.61,
            explanation="Heuristic candidate.",
            features={"distance_to_trigger": 3, "tracked_entities": ["len"]},
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            provider = StaticLLMProvider(
                response_text='{"label":"root_cause","reasoning":"This computes a bad size.","confidence":0.91}'
            )
            llm_client = LLMClient(provider=provider, cache=FileLLMCache(cache_dir=temp_dir))
            disambiguator = SemanticDisambiguator(llm_client=llm_client)

            judgment_one = disambiguator.disambiguate_candidate_label(
                trigger_point=trigger,
                candidate=candidate,
                candidate_source_code="int len = n + 4;",
                surrounding_function_code="int compute(int n) { int len = n + 4; return len; }",
                dependency_summary="len influences memcpy size at the trigger.",
            )
            judgment_two = disambiguator.disambiguate_candidate_label(
                trigger_point=trigger,
                candidate=candidate,
                candidate_source_code="int len = n + 4;",
                surrounding_function_code="int compute(int n) { int len = n + 4; return len; }",
                dependency_summary="len influences memcpy size at the trigger.",
            )

            self.assertEqual(provider.calls, 1)
            self.assertEqual(judgment_one.verdict, CandidateLabel.ROOT_CAUSE_CANDIDATE.value)
            self.assertGreater(judgment_one.confidence.value, 0.5)
            self.assertEqual(judgment_two.verdict, CandidateLabel.ROOT_CAUSE_CANDIDATE.value)

            unavailable_disambiguator = SemanticDisambiguator(
                llm_client=LLMClient(provider=StaticLLMProvider(response_text="", available=False), cache=FileLLMCache(cache_dir=Path(temp_dir) / "fallback"))
            )
            fallback = unavailable_disambiguator.disambiguate_candidate_label(
                trigger_point=trigger,
                candidate=candidate,
                candidate_source_code="int len = n + 4;",
                surrounding_function_code="int compute(int n) { int len = n + 4; return len; }",
                dependency_summary="len influences memcpy size at the trigger.",
            )
            self.assertEqual(fallback.provider, "fallback")
            self.assertEqual(fallback.verdict, CandidateLabel.PROPAGATION.value)
            self.assertTrue(fallback.metadata["fallback"])


if __name__ == "__main__":
    unittest.main()
