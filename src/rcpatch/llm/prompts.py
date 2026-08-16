"""Structured prompt templates for RCPatch semantic disambiguation."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

from rcpatch.models import CandidateLabel, RootCauseCandidate, TriggerPoint


@dataclass(frozen=True)
class PromptBundle:
    """Structured prompt bundle ready for an LLM request."""

    task: str
    version: str
    system_prompt: str
    user_prompt: str
    response_schema: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class CandidateDisambiguationInput:
    """All evidence needed for semantic candidate disambiguation."""

    trigger_point: TriggerPoint
    candidate: RootCauseCandidate
    candidate_source_code: str
    surrounding_function_code: str
    dependency_summary: str
    patch_diff: Optional[str] = None
    heuristic_label: Optional[CandidateLabel] = None


@dataclass(frozen=True)
class CVECandidateAlignmentInput:
    """All evidence needed for CVE-to-code semantic alignment."""

    cve_id: str
    cve_description: str
    candidate: RootCauseCandidate
    candidate_source_code: str
    surrounding_function_code: str
    dependency_summary: str
    patch_diff: Optional[str] = None
    heuristic_label: Optional[CandidateLabel] = None


def build_candidate_label_prompt(prompt_input: CandidateDisambiguationInput) -> PromptBundle:
    """Build a deterministic prompt for candidate label disambiguation."""
    system_prompt = (
        "You are RCPatch's semantic disambiguation assistant.\n"
        "Use only the provided evidence.\n"
        "Do not invent CFG edges, runtime facts, or patch semantics that are not explicitly present.\n"
        "Your job is only to interpret already-extracted evidence and decide whether the candidate is a root cause, "
        "a propagation step, or a symptom.\n"
        "Return JSON only with the exact schema requested."
    )
    payload = {
        "trigger_point": {
            "file": prompt_input.trigger_point.location.file,
            "line": prompt_input.trigger_point.location.line,
            "function": prompt_input.trigger_point.location.function,
            "type": prompt_input.trigger_point.type.value,
            "failing_operation": prompt_input.trigger_point.failing_operation,
        },
        "candidate": {
            "location": {
                "file": prompt_input.candidate.location.file,
                "line": prompt_input.candidate.location.line,
                "function": prompt_input.candidate.location.function,
            },
            "heuristic_label": (
                prompt_input.heuristic_label.value
                if prompt_input.heuristic_label is not None
                else prompt_input.candidate.label.value
            ),
            "heuristic_score": prompt_input.candidate.score,
            "heuristic_explanation": prompt_input.candidate.explanation,
            "features": prompt_input.candidate.features,
        },
        "candidate_source_code": prompt_input.candidate_source_code,
        "surrounding_function_code": prompt_input.surrounding_function_code,
        "dependency_summary": prompt_input.dependency_summary,
        "patch_diff": prompt_input.patch_diff,
        "instructions": {
            "allowed_labels": ["root_cause", "propagation", "symptom"],
            "confidence_range": [0.0, 1.0],
            "rules": [
                "Prefer root_cause only when the statement likely introduces invalid state or violates an invariant.",
                "Use propagation when the statement mainly forwards, transforms, or carries already-invalid state.",
                "Use symptom when the statement is mostly where the failure becomes observable.",
                "If evidence is mixed, preserve ambiguity in reasoning and lower confidence.",
            ],
        },
        "output_format": {
            "label": "root_cause | propagation | symptom",
            "reasoning": "short evidence-grounded explanation",
            "confidence": 0.0,
        },
    }
    user_prompt = json.dumps(payload, indent=2, sort_keys=True, default=str)
    response_schema = {
        "type": "object",
        "required": ["label", "reasoning", "confidence"],
        "properties": {
            "label": {"type": "string", "enum": ["root_cause", "propagation", "symptom"]},
            "reasoning": {"type": "string"},
            "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        },
        "additionalProperties": False,
    }
    return PromptBundle(
        task="candidate_label_disambiguation",
        version="candidate_label_v1",
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_schema=response_schema,
    )


def build_cve_candidate_alignment_prompt(prompt_input: CVECandidateAlignmentInput) -> PromptBundle:
    """Build a deterministic prompt for aligning a CVE description with one existing candidate."""
    system_prompt = (
        "You are RCPatch's CVE semantic alignment assistant.\n"
        "Use only the provided evidence.\n"
        "Do not invent candidates, control-flow edges, data-flow facts, or patch semantics beyond what is shown.\n"
        "Your job is only to classify the provided candidate as root cause, propagation, or symptom, and explain "
        "how it relates to the CVE description.\n"
        "Return JSON only with the exact schema requested."
    )
    payload = {
        "cve": {
            "cve_id": prompt_input.cve_id,
            "description": prompt_input.cve_description,
        },
        "candidate": {
            "location": {
                "file": prompt_input.candidate.location.file,
                "line": prompt_input.candidate.location.line,
                "function": prompt_input.candidate.location.function,
            },
            "heuristic_label": (
                prompt_input.heuristic_label.value
                if prompt_input.heuristic_label is not None
                else prompt_input.candidate.label.value
            ),
            "heuristic_score": prompt_input.candidate.score,
            "heuristic_explanation": prompt_input.candidate.explanation,
            "features": prompt_input.candidate.features,
        },
        "candidate_source_code": prompt_input.candidate_source_code,
        "surrounding_function_code": prompt_input.surrounding_function_code,
        "dependency_summary": prompt_input.dependency_summary,
        "patch_diff": prompt_input.patch_diff,
        "instructions": {
            "allowed_labels": ["root_cause", "propagation", "symptom"],
            "confidence_range": [0.0, 1.0],
            "rules": [
                "Do not create new candidates or claim facts not present in the evidence.",
                "Use root_cause only when the candidate likely introduces invalid state or violates an invariant that matches the CVE description.",
                "Use propagation when the candidate mainly carries or transforms already-invalid state toward the patched location or failure.",
                "Use symptom when the candidate is mainly where the bug becomes visible or consumed.",
                "If the CVE text aligns weakly with the code evidence, lower confidence and say so explicitly.",
            ],
        },
        "output_format": {
            "label": "root_cause | propagation | symptom",
            "reasoning": "short evidence-grounded explanation that ties the candidate back to the CVE description",
            "confidence": 0.0,
        },
    }
    response_schema = {
        "type": "object",
        "required": ["label", "reasoning", "confidence"],
        "properties": {
            "label": {"type": "string", "enum": ["root_cause", "propagation", "symptom"]},
            "reasoning": {"type": "string"},
            "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        },
        "additionalProperties": False,
    }
    return PromptBundle(
        task="cve_candidate_semantic_alignment",
        version="cve_candidate_alignment_v1",
        system_prompt=system_prompt,
        user_prompt=json.dumps(payload, indent=2, sort_keys=True, default=str),
        response_schema=response_schema,
    )


def build_patch_intent_prompt(
    *,
    diff_text: str,
    commit_message: Optional[str] = None,
    issue_description: Optional[str] = None,
) -> PromptBundle:
    """Build a deterministic prompt for semantic patch-intent interpretation."""
    system_prompt = (
        "You are RCPatch's patch-intent interpreter.\n"
        "Use only the provided diff and text context.\n"
        "Do not assume the patch edits the exact root cause.\n"
        "Return JSON only."
    )
    payload = {
        "commit_message": commit_message,
        "issue_description": issue_description,
        "patch_diff": diff_text,
        "instructions": {
            "allowed_labels": ["direct_fix", "compensating_check", "defensive_guard", "cleanup", "refactor", "unknown"],
        },
        "output_format": {
            "label": "direct_fix | compensating_check | defensive_guard | cleanup | refactor | unknown",
            "reasoning": "short evidence-grounded explanation",
            "confidence": 0.0,
        },
    }
    response_schema = {
        "type": "object",
        "required": ["label", "reasoning", "confidence"],
        "properties": {
            "label": {
                "type": "string",
                "enum": ["direct_fix", "compensating_check", "defensive_guard", "cleanup", "refactor", "unknown"],
            },
            "reasoning": {"type": "string"},
            "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        },
        "additionalProperties": False,
    }
    return PromptBundle(
        task="patch_intent_disambiguation",
        version="patch_intent_v1",
        system_prompt=system_prompt,
        user_prompt=json.dumps(payload, indent=2, sort_keys=True, default=str),
        response_schema=response_schema,
    )
