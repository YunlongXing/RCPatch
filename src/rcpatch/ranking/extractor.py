"""Root-cause candidate extraction entry point."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from rcpatch.logging_utils import get_logger
from rcpatch.models import BugReport, CandidateLabel, ConfidenceScore, RootCauseCandidate
from rcpatch.models.slice_ir import BackwardSlice
from rcpatch.ranking.features import CandidateFeatureExtractor
from rcpatch.ranking.calibration import RankerCalibration
from rcpatch.ranking.scorer import CandidateScorer


@dataclass(frozen=True)
class _ScoredObservation:
    candidate: RootCauseCandidate
    score_components: dict[str, float]


class RootCauseCandidateExtractor:
    """Extract and rank root-cause candidates from a backward slice."""

    def __init__(
        self,
        *,
        feature_extractor: Optional[CandidateFeatureExtractor] = None,
        scorer: Optional[CandidateScorer] = None,
    ) -> None:
        self.feature_extractor = feature_extractor or CandidateFeatureExtractor()
        self.scorer = scorer or CandidateScorer()
        self.logger = get_logger(__name__)

    def extract_candidates(
        self,
        bug_report: BugReport,
        backward_slice: BackwardSlice,
        *,
        top_k: Optional[int] = None,
    ) -> list[RootCauseCandidate]:
        """Extract, score, and rank candidate root-cause locations."""
        if not backward_slice.nodes:
            self.logger.info("Backward slice for %s contained no nodes; returning no candidates", bug_report.bug_id)
            return []

        observations = self.feature_extractor.extract(bug_report, backward_slice)
        scorer = self._scorer_for_report(bug_report)
        scored = [self._score_observation(observation, scorer=scorer) for observation in observations]
        scored = self._ensure_root_cause_candidate(scored)
        ranked = sorted(
            scored,
            key=lambda item: (
                self._label_priority(item.candidate.label),
                item.candidate.score,
                item.candidate.location.line,
            ),
            reverse=True,
        )

        selected_count = top_k or bug_report.analysis_config.top_k_candidates
        threshold = bug_report.analysis_config.confidence_threshold
        selected = [item for item in ranked if item.candidate.score >= threshold][:selected_count]
        if len(selected) < min(selected_count, len(ranked)):
            for item in ranked:
                if item in selected:
                    continue
                selected.append(item)
                if len(selected) >= selected_count:
                    break

        return [
            item.candidate.model_copy(update={"rank": index})
            for index, item in enumerate(selected, start=1)
        ]

    def _score_observation(self, observation: object, *, scorer: CandidateScorer) -> _ScoredObservation:
        from rcpatch.ranking.features import CandidateObservation

        if not isinstance(observation, CandidateObservation):
            raise TypeError("expected CandidateObservation")

        score, components, label = scorer.score(
            features=observation.features,
            initial_label=observation.label,
        )
        candidate = RootCauseCandidate(
            location=observation.node.location,
            label=label,
            score=score,
            explanation=observation.explanation,
            features=observation.features,
            evidence=observation.evidence,
            confidence=ConfidenceScore(
                value=score,
                rationale=f"Weighted heuristic score for {label.value}.",
                method="heuristic_candidate_ranker_v1",
                components=components,
            ),
            metadata={
                "statement_id": observation.node.statement_id,
                "function_id": observation.node.function_id,
                "function_name": observation.node.function_name,
                "is_trigger_node": observation.node.is_trigger,
            },
        )
        return _ScoredObservation(candidate=candidate, score_components=components)

    def _scorer_for_report(self, bug_report: BugReport) -> CandidateScorer:
        calibration_path = bug_report.analysis_config.ranker_calibration_path
        if not calibration_path:
            return self.scorer
        path = Path(calibration_path).expanduser()
        if not path.is_absolute():
            path = Path(bug_report.repo_path).expanduser().resolve() / path
        try:
            calibration = RankerCalibration.from_file(path)
        except Exception as exc:
            self.logger.warning("Could not load ranker calibration from %s: %s", path, exc)
            return self.scorer
        return CandidateScorer(
            contribution_weights=self.scorer.contribution_weights,
            penalty_weights=self.scorer.penalty_weights,
            calibration=calibration,
        )

    def _ensure_root_cause_candidate(self, scored: list[_ScoredObservation]) -> list[_ScoredObservation]:
        if any(item.candidate.label == CandidateLabel.ROOT_CAUSE_CANDIDATE for item in scored):
            return scored

        promotable = [
            item
            for item in scored
            if not item.candidate.metadata.get("is_trigger_node")
        ]
        if not promotable:
            return scored

        best = max(promotable, key=lambda item: item.candidate.score)
        promoted_candidate = best.candidate.model_copy(
            update={
                "label": CandidateLabel.ROOT_CAUSE_CANDIDATE,
                "explanation": "No strong root-cause label crossed the threshold, so the strongest upstream state-introducing site was promoted.",
            }
        )
        updated: list[_ScoredObservation] = []
        for item in scored:
            if item is best:
                updated.append(_ScoredObservation(candidate=promoted_candidate, score_components=item.score_components))
            else:
                updated.append(item)
        return updated

    @staticmethod
    def _label_priority(label: CandidateLabel) -> int:
        if label == CandidateLabel.ROOT_CAUSE_CANDIDATE:
            return 3
        if label == CandidateLabel.PROPAGATION:
            return 2
        return 1
