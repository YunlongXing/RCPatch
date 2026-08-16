"""Parsers for structured LLM responses."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional

from rcpatch.errors import LLMResponseParseError
from rcpatch.models import CandidateLabel, PatchIntent


@dataclass(frozen=True)
class ParsedLLMDecision:
    """Parsed, normalized semantic LLM decision."""

    verdict: str
    reasoning: str
    confidence: float
    raw_label: str
    raw_payload: dict[str, object]


class LLMResponseParser:
    """Extract normalized judgments from JSON-only LLM outputs."""

    def parse_candidate_label(self, response_text: str) -> ParsedLLMDecision:
        """Parse candidate label JSON into an internal verdict."""
        payload = self._parse_json_payload(response_text)
        raw_label = _normalize_label(str(payload.get("label", "")))
        mapped_label = {
            "root_cause": CandidateLabel.ROOT_CAUSE_CANDIDATE.value,
            "propagation": CandidateLabel.PROPAGATION.value,
            "symptom": CandidateLabel.SYMPTOM.value,
        }.get(raw_label)
        if mapped_label is None:
            raise LLMResponseParseError(f"Unsupported candidate label {raw_label!r}")
        reasoning = _extract_reasoning(payload)
        confidence = _extract_confidence(payload)
        return ParsedLLMDecision(
            verdict=mapped_label,
            reasoning=reasoning,
            confidence=confidence,
            raw_label=raw_label,
            raw_payload=payload,
        )

    def parse_patch_intent(self, response_text: str) -> ParsedLLMDecision:
        """Parse patch intent JSON into an internal verdict."""
        payload = self._parse_json_payload(response_text)
        raw_label = _normalize_label(str(payload.get("label", "")))
        normalized = raw_label.replace(" ", "_")
        if normalized not in {intent.value for intent in PatchIntent}:
            raise LLMResponseParseError(f"Unsupported patch intent label {raw_label!r}")
        reasoning = _extract_reasoning(payload)
        confidence = _extract_confidence(payload)
        return ParsedLLMDecision(
            verdict=normalized,
            reasoning=reasoning,
            confidence=confidence,
            raw_label=raw_label,
            raw_payload=payload,
        )

    def _parse_json_payload(self, response_text: str) -> dict[str, object]:
        cleaned = response_text.strip()
        if cleaned.startswith("```"):
            cleaned = _strip_code_fence(cleaned)

        candidates = [cleaned]
        extracted = _extract_first_json_object(cleaned)
        if extracted is not None and extracted != cleaned:
            candidates.append(extracted)

        for candidate in candidates:
            try:
                payload = json.loads(candidate)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                return payload
        raise LLMResponseParseError("LLM response did not contain a parseable JSON object")


def _extract_reasoning(payload: dict[str, object]) -> str:
    value = payload.get("reasoning")
    if not isinstance(value, str) or not value.strip():
        raise LLMResponseParseError("LLM response is missing a non-empty reasoning field")
    return value.strip()


def _extract_confidence(payload: dict[str, object]) -> float:
    raw_confidence = payload.get("confidence")
    if isinstance(raw_confidence, (int, float)):
        return max(0.0, min(float(raw_confidence), 1.0))
    raise LLMResponseParseError("LLM response is missing a numeric confidence field")


def _normalize_label(label: str) -> str:
    return label.strip().lower().replace("-", "_")


def _strip_code_fence(text: str) -> str:
    stripped = text.strip()
    if not stripped.startswith("```"):
        return stripped
    lines = stripped.splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()


def _extract_first_json_object(text: str) -> Optional[str]:
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_string = False
    escape = False
    for index, character in enumerate(text[start:], start=start):
        if escape:
            escape = False
            continue
        if character == "\\":
            escape = True
            continue
        if character == "\"":
            in_string = not in_string
            continue
        if in_string:
            continue
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    return None
