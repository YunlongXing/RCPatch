"""Confidence calibration for LLM-assisted judgments."""

from __future__ import annotations

from typing import Optional

from rcpatch.models import ConfidenceScore


class LLMConfidenceCalibrator:
    """Calibrate raw model confidence into a bounded RCPatch confidence score."""

    def calibrate(
        self,
        *,
        task: str,
        raw_confidence: Optional[float],
        reasoning: str,
        evidence_density: float,
        used_patch: bool,
        fallback_used: bool,
        parse_succeeded: bool,
    ) -> ConfidenceScore:
        """Return a calibrated confidence score with feature contributions."""
        base = 0.45 if raw_confidence is None else max(0.0, min(float(raw_confidence), 1.0))
        contributions = {
            "model_confidence": 0.55 * base,
            "reasoning_quality": 0.15 * _reasoning_quality(reasoning),
            "evidence_density": 0.15 * max(0.0, min(evidence_density, 1.0)),
            "patch_context": 0.05 if used_patch else 0.0,
            "parse_success": 0.1 if parse_succeeded else -0.15,
            "fallback_penalty": -0.35 if fallback_used else 0.0,
        }
        calibrated = max(0.0, min(sum(contributions.values()), 1.0))
        rationale = (
            f"Calibrated {task} confidence from raw model certainty, reasoning quality, available evidence, "
            f"and fallback status."
        )
        return ConfidenceScore(
            value=calibrated,
            rationale=rationale,
            method="llm_confidence_calibration_v1",
            components=contributions,
        )


def _reasoning_quality(reasoning: str) -> float:
    stripped = reasoning.strip()
    if len(stripped) < 25:
        return 0.25
    if len(stripped) < 80:
        return 0.55
    return 0.85
