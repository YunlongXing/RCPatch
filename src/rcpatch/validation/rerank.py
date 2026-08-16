"""Validation-driven reranking for generated patch suggestions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from rcpatch.patch_generation import PatchSuggestion
from rcpatch.validation.harness import PatchValidationResult


@dataclass(frozen=True)
class ValidationRerankedPatch:
    """Patch suggestion paired with a validation-derived score."""

    suggestion: PatchSuggestion
    validation: PatchValidationResult | None
    score: float
    reason: str


class ValidationDrivenReranker:
    """Rank patch suggestions using apply/build/reproducer validation results."""

    def rerank(
        self,
        suggestions: Iterable[PatchSuggestion],
        validations: dict[str, PatchValidationResult],
    ) -> list[ValidationRerankedPatch]:
        """Return suggestions sorted by validation strength."""

        ranked: list[ValidationRerankedPatch] = []
        for suggestion in suggestions:
            validation = validations.get(suggestion.patch_id)
            score, reason = self._score(suggestion, validation)
            ranked.append(
                ValidationRerankedPatch(
                    suggestion=suggestion,
                    validation=validation,
                    score=score,
                    reason=reason,
                )
            )
        return sorted(ranked, key=lambda item: item.score, reverse=True)

    def _score(self, suggestion: PatchSuggestion, validation: PatchValidationResult | None) -> tuple[float, str]:
        if validation is None:
            base = 0.35 if not suggestion.is_pseudo_patch else 0.2
            return base, "No validation result was available; ranking falls back to patch concreteness."
        if validation.passed:
            return 1.0, "Patch applies and all requested validation commands passed."
        if validation.patch_applied and any(step.succeeded for step in validation.steps):
            return 0.55, "Patch applies and at least one validation step succeeded, but the run did not fully pass."
        if validation.patch_applied:
            return 0.35, "Patch applies but validation commands failed."
        return 0.05, "Patch did not apply cleanly."
