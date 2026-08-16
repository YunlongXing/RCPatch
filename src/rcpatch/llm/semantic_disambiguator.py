"""Optional LLM-assisted semantic disambiguation on top of extracted evidence."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from rcpatch.errors import LLMResponseParseError
from rcpatch.llm.calibration import LLMConfidenceCalibrator
from rcpatch.llm.llm_client import LLMClient, LLMRequest
from rcpatch.llm.parser import LLMResponseParser
from rcpatch.llm.prompts import (
    CVECandidateAlignmentInput,
    CandidateDisambiguationInput,
    build_candidate_label_prompt,
    build_cve_candidate_alignment_prompt,
    build_patch_intent_prompt,
)
from rcpatch.logging_utils import get_logger
from rcpatch.models import (
    CandidateLabel,
    LLMJudgment,
    PatchEvidence,
    PatchIntent,
    RootCauseCandidate,
    TriggerPoint,
)


class SemanticDisambiguator:
    """LLM-assisted interpretation service that never replaces raw evidence extraction."""

    def __init__(
        self,
        *,
        llm_client: Optional[LLMClient] = None,
        parser: Optional[LLMResponseParser] = None,
        calibrator: Optional[LLMConfidenceCalibrator] = None,
    ) -> None:
        self.llm_client = llm_client or LLMClient()
        self.parser = parser or LLMResponseParser()
        self.calibrator = calibrator or LLMConfidenceCalibrator()
        self.logger = get_logger(__name__)

    def disambiguate_candidate_label(
        self,
        *,
        trigger_point: TriggerPoint,
        candidate: RootCauseCandidate,
        candidate_source_code: str,
        surrounding_function_code: str,
        dependency_summary: str,
        patch_diff: Optional[str] = None,
        heuristic_label: Optional[CandidateLabel] = None,
    ) -> LLMJudgment:
        """Interpret whether a candidate is a root cause, propagation step, or symptom."""
        prompt_bundle = build_candidate_label_prompt(
            CandidateDisambiguationInput(
                trigger_point=trigger_point,
                candidate=candidate,
                candidate_source_code=candidate_source_code,
                surrounding_function_code=surrounding_function_code,
                dependency_summary=dependency_summary,
                patch_diff=patch_diff,
                heuristic_label=heuristic_label,
            )
        )
        llm_request = LLMRequest(
            task=prompt_bundle.task,
            prompt_version=prompt_bundle.version,
            system_prompt=prompt_bundle.system_prompt,
            user_prompt=prompt_bundle.user_prompt,
            response_schema=prompt_bundle.response_schema,
            temperature=0.0,
            max_output_tokens=400,
            metadata={
                "candidate_location": candidate.location.model_dump(mode="json"),
                "heuristic_label": (heuristic_label or candidate.label).value,
            },
        )
        response = self.llm_client.complete(llm_request)
        evidence_density = _evidence_density(dependency_summary)

        if response is None:
            return self._fallback_candidate_judgment(
                candidate=candidate,
                heuristic_label=heuristic_label or candidate.label,
                dependency_summary=dependency_summary,
                patch_diff=patch_diff,
            )

        try:
            parsed = self.parser.parse_candidate_label(response.text)
            confidence = self.calibrator.calibrate(
                task=prompt_bundle.task,
                raw_confidence=parsed.confidence,
                reasoning=parsed.reasoning,
                evidence_density=evidence_density,
                used_patch=bool(patch_diff),
                fallback_used=False,
                parse_succeeded=True,
            )
            return LLMJudgment(
                task=prompt_bundle.task,
                provider=response.provider,
                model=response.model,
                verdict=parsed.verdict,
                rationale=parsed.reasoning,
                confidence=confidence,
                metadata={
                    "raw_label": parsed.raw_label,
                    "prompt_version": prompt_bundle.version,
                    "cached": response.cached,
                    "response_schema": prompt_bundle.response_schema,
                },
            )
        except LLMResponseParseError as exc:
            self.logger.warning("Failed to parse candidate semantic response: %s", exc)
            return self._fallback_candidate_judgment(
                candidate=candidate,
                heuristic_label=heuristic_label or candidate.label,
                dependency_summary=dependency_summary,
                patch_diff=patch_diff,
                parse_error=str(exc),
            )

    def infer_patch_intent(
        self,
        *,
        patch_evidence: PatchEvidence,
        diff_text: str,
        commit_message: Optional[str] = None,
        issue_description: Optional[str] = None,
        heuristic_intent: Optional[PatchIntent] = None,
    ) -> LLMJudgment:
        """Interpret patch intent from a diff and surrounding text."""
        prompt_bundle = build_patch_intent_prompt(
            diff_text=diff_text,
            commit_message=commit_message or patch_evidence.commit_message,
            issue_description=issue_description or patch_evidence.issue_text,
        )
        llm_request = LLMRequest(
            task=prompt_bundle.task,
            prompt_version=prompt_bundle.version,
            system_prompt=prompt_bundle.system_prompt,
            user_prompt=prompt_bundle.user_prompt,
            response_schema=prompt_bundle.response_schema,
            temperature=0.0,
            max_output_tokens=300,
            metadata={"diff_path": patch_evidence.diff_path},
        )
        response = self.llm_client.complete(llm_request)
        evidence_density = min(len(diff_text.splitlines()) / 40.0, 1.0)
        if response is None:
            return self._fallback_patch_intent_judgment(
                heuristic_intent=heuristic_intent or patch_evidence.patch_intent or PatchIntent.UNKNOWN,
            )

        try:
            parsed = self.parser.parse_patch_intent(response.text)
            confidence = self.calibrator.calibrate(
                task=prompt_bundle.task,
                raw_confidence=parsed.confidence,
                reasoning=parsed.reasoning,
                evidence_density=evidence_density,
                used_patch=True,
                fallback_used=False,
                parse_succeeded=True,
            )
            return LLMJudgment(
                task=prompt_bundle.task,
                provider=response.provider,
                model=response.model,
                verdict=parsed.verdict,
                rationale=parsed.reasoning,
                confidence=confidence,
                metadata={
                    "raw_label": parsed.raw_label,
                    "prompt_version": prompt_bundle.version,
                    "cached": response.cached,
                },
            )
        except LLMResponseParseError as exc:
            self.logger.warning("Failed to parse patch intent response: %s", exc)
            return self._fallback_patch_intent_judgment(
                heuristic_intent=heuristic_intent or patch_evidence.patch_intent or PatchIntent.UNKNOWN,
                parse_error=str(exc),
            )

    def align_cve_candidate(
        self,
        *,
        cve_id: str,
        cve_description: str,
        candidate: RootCauseCandidate,
        candidate_source_code: str,
        surrounding_function_code: str,
        dependency_summary: str,
        patch_diff: Optional[str] = None,
        heuristic_label: Optional[CandidateLabel] = None,
    ) -> LLMJudgment:
        """Interpret one existing CVE candidate using CVE text plus code evidence."""
        prompt_bundle = build_cve_candidate_alignment_prompt(
            CVECandidateAlignmentInput(
                cve_id=cve_id,
                cve_description=cve_description,
                candidate=candidate,
                candidate_source_code=candidate_source_code,
                surrounding_function_code=surrounding_function_code,
                dependency_summary=dependency_summary,
                patch_diff=patch_diff,
                heuristic_label=heuristic_label,
            )
        )
        llm_request = LLMRequest(
            task=prompt_bundle.task,
            prompt_version=prompt_bundle.version,
            system_prompt=prompt_bundle.system_prompt,
            user_prompt=prompt_bundle.user_prompt,
            response_schema=prompt_bundle.response_schema,
            temperature=0.0,
            max_output_tokens=450,
            metadata={
                "cve_id": cve_id,
                "candidate_location": candidate.location.model_dump(mode="json"),
                "heuristic_label": (heuristic_label or candidate.label).value,
            },
        )
        response = self.llm_client.complete(llm_request)
        evidence_density = _evidence_density(dependency_summary)

        if response is None:
            return self._fallback_candidate_judgment(
                candidate=candidate,
                heuristic_label=heuristic_label or candidate.label,
                dependency_summary=dependency_summary,
                patch_diff=patch_diff,
                task_name=prompt_bundle.task,
                extra_metadata={"cve_id": cve_id},
            )

        try:
            parsed = self.parser.parse_candidate_label(response.text)
            confidence = self.calibrator.calibrate(
                task=prompt_bundle.task,
                raw_confidence=parsed.confidence,
                reasoning=parsed.reasoning,
                evidence_density=evidence_density,
                used_patch=bool(patch_diff),
                fallback_used=False,
                parse_succeeded=True,
            )
            return LLMJudgment(
                task=prompt_bundle.task,
                provider=response.provider,
                model=response.model,
                verdict=parsed.verdict,
                rationale=parsed.reasoning,
                confidence=confidence,
                metadata={
                    "cve_id": cve_id,
                    "raw_label": parsed.raw_label,
                    "prompt_version": prompt_bundle.version,
                    "cached": response.cached,
                    "response_schema": prompt_bundle.response_schema,
                },
            )
        except LLMResponseParseError as exc:
            self.logger.warning("Failed to parse CVE semantic alignment response: %s", exc)
            return self._fallback_candidate_judgment(
                candidate=candidate,
                heuristic_label=heuristic_label or candidate.label,
                dependency_summary=dependency_summary,
                patch_diff=patch_diff,
                parse_error=str(exc),
                task_name=prompt_bundle.task,
                extra_metadata={"cve_id": cve_id},
            )

    def _fallback_candidate_judgment(
        self,
        *,
        candidate: RootCauseCandidate,
        heuristic_label: CandidateLabel,
        dependency_summary: str,
        patch_diff: Optional[str],
        parse_error: Optional[str] = None,
        task_name: str = "candidate_label_disambiguation",
        extra_metadata: Optional[dict[str, object]] = None,
    ) -> LLMJudgment:
        reasoning = "LLM unavailable or unparsable; retained heuristic label because semantic interpretation could not be refreshed."
        if parse_error:
            reasoning += f" Parse error: {parse_error}."
        confidence = self.calibrator.calibrate(
            task=task_name,
            raw_confidence=None,
            reasoning=reasoning,
            evidence_density=_evidence_density(dependency_summary),
            used_patch=bool(patch_diff),
            fallback_used=True,
            parse_succeeded=False,
        )
        metadata: dict[str, object] = {
            "fallback": True,
            "candidate_location": candidate.location.model_dump(mode="json"),
        }
        if extra_metadata:
            metadata.update(extra_metadata)
        return LLMJudgment(
            task=task_name,
            provider="fallback",
            model="heuristic",
            verdict=heuristic_label.value,
            rationale=reasoning,
            confidence=confidence,
            metadata=metadata,
        )

    def _fallback_patch_intent_judgment(
        self,
        *,
        heuristic_intent: PatchIntent,
        parse_error: Optional[str] = None,
    ) -> LLMJudgment:
        reasoning = "LLM unavailable or unparsable; retained heuristic patch intent classification."
        if parse_error:
            reasoning += f" Parse error: {parse_error}."
        confidence = self.calibrator.calibrate(
            task="patch_intent_disambiguation",
            raw_confidence=None,
            reasoning=reasoning,
            evidence_density=0.5,
            used_patch=True,
            fallback_used=True,
            parse_succeeded=False,
        )
        return LLMJudgment(
            task="patch_intent_disambiguation",
            provider="fallback",
            model="heuristic",
            verdict=heuristic_intent.value,
            rationale=reasoning,
            confidence=confidence,
            metadata={"fallback": True},
        )


def load_patch_diff_text(patch_evidence: PatchEvidence) -> Optional[str]:
    """Load inline or file-backed patch diff text."""
    metadata_text = patch_evidence.metadata.get("diff_text")
    if isinstance(metadata_text, str) and metadata_text.strip():
        return metadata_text
    if patch_evidence.diff_path:
        diff_path = Path(patch_evidence.diff_path).expanduser()
        if diff_path.exists():
            return diff_path.read_text(encoding="utf-8", errors="replace")
    return None


def _evidence_density(dependency_summary: str) -> float:
    lines = [line for line in dependency_summary.splitlines() if line.strip()]
    return min(len(lines) / 8.0, 1.0)
