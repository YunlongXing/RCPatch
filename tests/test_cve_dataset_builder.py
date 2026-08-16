"""Tests for CVE root-cause dataset construction."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from rcpatch.cve_mining import CVEDatasetBuildCase, CVERootCauseDatasetBuilder
from rcpatch.models import (
    AdvisorySourceKind,
    CandidateLabel,
    CollectedCVERecord,
    CVECandidateSemanticAlignment,
    CVEPatchExtraction,
    CVEPatchType,
    CVERootCauseMiningResult,
    CVESemanticAlignmentResult,
    CVETraceability,
    Language,
    RepositoryProvider,
    RootCauseCandidate,
    SourceLocation,
    StructuredPatchFile,
    StructuredPatchHunk,
)


class CVERootCauseDatasetBuilderTests(unittest.TestCase):
    def test_build_record_keeps_high_confidence_root_cause(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = self._build_repo(Path(temp_dir))
            builder = CVERootCauseDatasetBuilder(min_confidence=0.7, top_k=2)

            dataset_record = builder.build_record(
                self._record(),
                self._mining_result(repo_root),
                patch_extraction=self._patch_extraction(),
                semantic_alignment=self._semantic_alignment(),
                repo_path=repo_root.as_posix(),
            )

            self.assertEqual(dataset_record.cve_id, "CVE-2026-1111")
            self.assertEqual(len(dataset_record.root_causes), 1)
            annotation = dataset_record.root_causes[0]
            self.assertEqual(annotation.classification, CandidateLabel.ROOT_CAUSE_CANDIDATE)
            self.assertEqual(annotation.pattern, "incorrect_size_computation")
            self.assertEqual(annotation.patch_relation, "patched_statement")
            self.assertGreaterEqual(annotation.confidence, 0.8)
            self.assertIn("payload_len", annotation.code_snippet)
            self.assertIn("oversized payload length", annotation.explanation)

    def test_build_dataset_drops_low_confidence_records(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = self._build_repo(Path(temp_dir))
            builder = CVERootCauseDatasetBuilder(min_confidence=0.8, top_k=1)
            good_case = CVEDatasetBuildCase(
                record=self._record(),
                mining_result=self._mining_result(repo_root),
                patch_extraction=self._patch_extraction(),
                semantic_alignment=self._semantic_alignment(),
                repo_path=repo_root.as_posix(),
            )
            weak_case = CVEDatasetBuildCase(
                record=self._record(cve_id="CVE-2026-2222"),
                mining_result=self._mining_result(repo_root, cve_id="CVE-2026-2222", score=0.55),
                patch_extraction=self._patch_extraction(cve_id="CVE-2026-2222"),
                semantic_alignment=self._semantic_alignment(cve_id="CVE-2026-2222", confidence=0.42),
                repo_path=repo_root.as_posix(),
            )

            dataset = builder.build_dataset([good_case, weak_case], drop_empty=True)

            self.assertEqual(len(dataset.records), 1)
            self.assertEqual(dataset.records[0].cve_id, "CVE-2026-1111")
            self.assertEqual(dataset.metadata["discarded_records"], 1)

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
    def _record(cve_id: str = "CVE-2026-1111") -> CollectedCVERecord:
        return CollectedCVERecord(
            cve_id=cve_id,
            project="demo-parser",
            repo_url="https://github.com/example/demo-parser",
            repo_provider=RepositoryProvider.GITHUB,
            description="A crafted packet can trigger a buffer overflow because payload length is calculated too large before memcpy.",
            language=Language.C_CPP,
            traceability=CVETraceability(
                source_kind=AdvisorySourceKind.PROJECT_ADVISORY,
                source_locator=f"https://example.com/advisories/{cve_id}",
            ),
        )

    @staticmethod
    def _patch_extraction(cve_id: str = "CVE-2026-1111") -> CVEPatchExtraction:
        return CVEPatchExtraction(
            cve_id=cve_id,
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
    def _mining_result(repo_root: Path, cve_id: str = "CVE-2026-1111", score: float = 0.74) -> CVERootCauseMiningResult:
        return CVERootCauseMiningResult(
            cve_id=cve_id,
            repo_path=repo_root.as_posix(),
            candidates=[
                RootCauseCandidate(
                    rank=1,
                    location=SourceLocation(file="src/parser.c", line=2, function="parse_size"),
                    label=CandidateLabel.ROOT_CAUSE_CANDIDATE,
                    score=score,
                    explanation="This computes the payload length later consumed by memcpy.",
                    features={
                        "candidate_origin": "upstream_slice",
                        "matched_bug_pattern": "incorrect_size_computation",
                    },
                ),
                RootCauseCandidate(
                    rank=2,
                    location=SourceLocation(file="src/parser.c", line=8, function="copy_payload"),
                    label=CandidateLabel.PROPAGATION,
                    score=0.63,
                    explanation="This memcpy uses the propagated payload length.",
                    features={"candidate_origin": "trigger_neighborhood"},
                ),
            ],
        )

    @staticmethod
    def _semantic_alignment(
        cve_id: str = "CVE-2026-1111",
        confidence: float = 0.91,
    ) -> CVESemanticAlignmentResult:
        return CVESemanticAlignmentResult(
            cve_id=cve_id,
            alignments=[
                CVECandidateSemanticAlignment(
                    candidate_rank=1,
                    location=SourceLocation(file="src/parser.c", line=2, function="parse_size"),
                    heuristic_label=CandidateLabel.ROOT_CAUSE_CANDIDATE,
                    label=CandidateLabel.ROOT_CAUSE_CANDIDATE,
                    confidence=confidence,
                    reasoning="The CVE text describes an oversized payload length, and this statement computes that invalid length before memcpy.",
                    candidate_origin="upstream_slice",
                ),
                CVECandidateSemanticAlignment(
                    candidate_rank=2,
                    location=SourceLocation(file="src/parser.c", line=8, function="copy_payload"),
                    heuristic_label=CandidateLabel.PROPAGATION,
                    label=CandidateLabel.PROPAGATION,
                    confidence=0.67,
                    reasoning="This is where the oversized length is consumed, not where it originates.",
                    candidate_origin="trigger_neighborhood",
                ),
            ],
        )


if __name__ == "__main__":
    unittest.main()
