"""Dataset construction for high-confidence CVE root-cause annotations."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from rcpatch.logging_utils import get_logger
from rcpatch.models import (
    CVECandidateSemanticAlignment,
    CVEPatchExtraction,
    CVERootCauseAnnotation,
    CVERootCauseDataset,
    CVERootCauseDatasetRecord,
    CVERootCauseMiningResult,
    CVESemanticAlignmentResult,
    CandidateLabel,
    CollectedCVERecord,
    RootCauseCandidate,
    SourceLocation,
)

_DEFAULT_MIN_CONFIDENCE = 0.7
_DEFAULT_TOP_K = 3
_SNIPPET_CONTEXT = 1


@dataclass(frozen=True)
class CVEDatasetBuildCase:
    """One fully analyzed CVE case ready for dataset curation."""

    record: CollectedCVERecord
    mining_result: CVERootCauseMiningResult
    patch_extraction: Optional[CVEPatchExtraction] = None
    semantic_alignment: Optional[CVESemanticAlignmentResult] = None
    repo_path: Optional[str] = None


class CVERootCauseDatasetBuilder:
    """Curate a CVE-to-root-cause dataset from mining and semantic-alignment outputs."""

    def __init__(
        self,
        *,
        min_confidence: float = _DEFAULT_MIN_CONFIDENCE,
        top_k: int = _DEFAULT_TOP_K,
        snippet_context: int = _SNIPPET_CONTEXT,
    ) -> None:
        self.min_confidence = max(0.0, min(min_confidence, 1.0))
        self.top_k = max(1, top_k)
        self.snippet_context = max(0, snippet_context)
        self.logger = get_logger(__name__)

    def build_record(
        self,
        record: CollectedCVERecord,
        mining_result: CVERootCauseMiningResult,
        *,
        patch_extraction: Optional[CVEPatchExtraction] = None,
        semantic_alignment: Optional[CVESemanticAlignmentResult] = None,
        repo_path: Optional[str] = None,
        min_confidence: Optional[float] = None,
        top_k: Optional[int] = None,
    ) -> CVERootCauseDatasetRecord:
        """Build one filtered dataset record for a CVE."""

        threshold = self.min_confidence if min_confidence is None else max(0.0, min(min_confidence, 1.0))
        max_roots = self.top_k if top_k is None else max(1, top_k)
        diagnostics = list(mining_result.diagnostics)
        alignment_map = self._alignment_index(semantic_alignment)
        repo_root = Path(repo_path or mining_result.repo_path).expanduser().resolve()

        selected: list[CVERootCauseAnnotation] = []
        skipped_low_confidence = 0
        skipped_non_root = 0
        for candidate in self._ranked_candidates(mining_result.candidates):
            alignment = alignment_map.get(self._candidate_key(candidate))
            final_label = alignment.label if alignment is not None else candidate.label
            final_confidence = self._candidate_confidence(candidate, alignment)
            if final_label != CandidateLabel.ROOT_CAUSE_CANDIDATE:
                skipped_non_root += 1
                continue
            if final_confidence < threshold:
                skipped_low_confidence += 1
                continue

            annotation = CVERootCauseAnnotation(
                rank=len(selected) + 1,
                location=candidate.location,
                code_snippet=self._code_snippet(candidate.location, repo_root),
                type=self._derive_type(candidate, alignment),
                classification=final_label,
                pattern=self._pattern(candidate),
                explanation=self._explanation(candidate, alignment),
                confidence=final_confidence,
                patch_relation=self._patch_relation(candidate, mining_result, patch_extraction),
                candidate_rank=candidate.rank,
                candidate_origin=self._string_feature(candidate.features, "candidate_origin"),
                metadata={
                    "heuristic_label": candidate.label.value,
                    "heuristic_score": candidate.score,
                    "semantic_label": alignment.label.value if alignment is not None else None,
                    "semantic_confidence": alignment.confidence if alignment is not None else None,
                    "matched_bug_pattern": self._pattern(candidate),
                },
            )
            selected.append(annotation)
            if len(selected) >= max_roots:
                break

        if not selected:
            diagnostics.append("No high-confidence root-cause candidates survived dataset filtering.")
        if skipped_non_root:
            diagnostics.append(f"Filtered out {skipped_non_root} non-root-cause candidates.")
        if skipped_low_confidence:
            diagnostics.append(f"Filtered out {skipped_low_confidence} low-confidence candidates below {threshold:.2f}.")

        return CVERootCauseDatasetRecord(
            cve_id=record.cve_id,
            project=record.project,
            repo_url=record.repo_url,
            root_causes=selected,
            diagnostics=diagnostics,
            metadata={
                "threshold": threshold,
                "retained_root_causes": len(selected),
                "candidate_count": len(mining_result.candidates),
                "used_semantic_alignment": semantic_alignment is not None,
                "used_patch_context": patch_extraction is not None,
            },
        )

    def build_dataset(
        self,
        cases: Iterable[CVEDatasetBuildCase],
        *,
        min_confidence: Optional[float] = None,
        top_k: Optional[int] = None,
        drop_empty: bool = True,
    ) -> CVERootCauseDataset:
        """Build a dataset bundle across many analyzed CVEs."""

        records: list[CVERootCauseDatasetRecord] = []
        discarded_records = 0
        for case in cases:
            record = self.build_record(
                case.record,
                case.mining_result,
                patch_extraction=case.patch_extraction,
                semantic_alignment=case.semantic_alignment,
                repo_path=case.repo_path,
                min_confidence=min_confidence,
                top_k=top_k,
            )
            if drop_empty and not record.root_causes:
                discarded_records += 1
                continue
            records.append(record)

        return CVERootCauseDataset(
            records=records,
            metadata={
                "record_count": len(records),
                "discarded_records": discarded_records,
                "min_confidence": self.min_confidence if min_confidence is None else min_confidence,
                "top_k": self.top_k if top_k is None else top_k,
                "drop_empty": drop_empty,
            },
        )

    @staticmethod
    def _ranked_candidates(candidates: list[RootCauseCandidate]) -> list[RootCauseCandidate]:
        return sorted(
            candidates,
            key=lambda candidate: (
                candidate.rank if candidate.rank is not None else 10**9,
                -candidate.score,
                candidate.location.file,
                candidate.location.line,
            ),
        )

    @staticmethod
    def _alignment_index(
        semantic_alignment: Optional[CVESemanticAlignmentResult],
    ) -> dict[tuple[str, int, Optional[str], Optional[int]], CVECandidateSemanticAlignment]:
        if semantic_alignment is None:
            return {}
        return {
            (
                alignment.location.file,
                alignment.location.line,
                alignment.location.function,
                alignment.candidate_rank,
            ): alignment
            for alignment in semantic_alignment.alignments
        }

    @staticmethod
    def _candidate_key(candidate: RootCauseCandidate) -> tuple[str, int, Optional[str], Optional[int]]:
        return (
            candidate.location.file,
            candidate.location.line,
            candidate.location.function,
            candidate.rank,
        )

    @staticmethod
    def _candidate_confidence(
        candidate: RootCauseCandidate,
        alignment: Optional[CVECandidateSemanticAlignment],
    ) -> float:
        if alignment is not None:
            return alignment.confidence
        if candidate.confidence is not None:
            return candidate.confidence.value
        return candidate.score

    def _code_snippet(self, location: SourceLocation, repo_root: Path) -> str:
        if location.snippet:
            return location.snippet
        source_path = repo_root / location.file
        try:
            lines = source_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            self.logger.debug("Failed to read snippet from %s", source_path)
            return f"{location.file}:{location.line}"
        start = max(1, location.line - self.snippet_context)
        end = min(len(lines), location.line + self.snippet_context)
        return "\n".join(
            f"{line_no}: {lines[line_no - 1].rstrip()}"
            for line_no in range(start, end + 1)
        )

    @staticmethod
    def _derive_type(
        candidate: RootCauseCandidate,
        alignment: Optional[CVECandidateSemanticAlignment],
    ) -> str:
        pattern = CVERootCauseDatasetBuilder._pattern(candidate)
        if pattern:
            return pattern
        if candidate.bug_type_hint is not None:
            return candidate.bug_type_hint.value
        origin = CVERootCauseDatasetBuilder._string_feature(candidate.features, "candidate_origin")
        if origin:
            return origin
        if alignment is not None:
            return alignment.label.value
        return candidate.label.value

    @staticmethod
    def _pattern(candidate: RootCauseCandidate) -> Optional[str]:
        value = candidate.features.get("matched_bug_pattern")
        if isinstance(value, str) and value.strip():
            return value.strip()
        return None

    @staticmethod
    def _explanation(
        candidate: RootCauseCandidate,
        alignment: Optional[CVECandidateSemanticAlignment],
    ) -> str:
        if alignment is not None and alignment.reasoning.strip():
            return alignment.reasoning.strip()
        return candidate.explanation

    @staticmethod
    def _patch_relation(
        candidate: RootCauseCandidate,
        mining_result: CVERootCauseMiningResult,
        patch_extraction: Optional[CVEPatchExtraction],
    ) -> str:
        if candidate.features.get("patch_anchor_overlap"):
            return "patch_anchor_overlap"

        for anchor in mining_result.anchors:
            if anchor.location.file == candidate.location.file and anchor.location.line == candidate.location.line:
                return "patch_anchor"

        if patch_extraction is None:
            return "unknown"

        for patch_file in patch_extraction.patches:
            if patch_file.file != candidate.location.file:
                continue
            for hunk in patch_file.hunks:
                old_end = hunk.old_start + max(hunk.old_count, 1) - 1
                if hunk.old_start <= candidate.location.line <= old_end:
                    return "patched_statement"
            if candidate.location.function and candidate.location.function in patch_file.changed_functions:
                return "same_function_as_patch"
            return "same_file_as_patch"

        origin = CVERootCauseDatasetBuilder._string_feature(candidate.features, "candidate_origin")
        if origin == "upstream_slice":
            return "upstream_of_patch"
        return "outside_patched_files"

    @staticmethod
    def _string_feature(features: dict[str, object], key: str) -> Optional[str]:
        value = features.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
        return None
