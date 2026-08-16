"""LLM-assisted semantic disambiguation exports."""

from rcpatch.llm.calibration import LLMConfidenceCalibrator
from rcpatch.llm.llm_client import (
    FileLLMCache,
    LLMClient,
    LLMProvider,
    LLMRequest,
    LLMResponse,
    OpenAICompatibleProvider,
    StaticLLMProvider,
)
from rcpatch.llm.parser import LLMResponseParser, ParsedLLMDecision
from rcpatch.llm.prompts import (
    CVECandidateAlignmentInput,
    CandidateDisambiguationInput,
    PromptBundle,
    build_candidate_label_prompt,
    build_cve_candidate_alignment_prompt,
    build_patch_intent_prompt,
)
from rcpatch.llm.semantic_disambiguator import SemanticDisambiguator, load_patch_diff_text

__all__ = [
    "CandidateDisambiguationInput",
    "CVECandidateAlignmentInput",
    "FileLLMCache",
    "LLMClient",
    "LLMConfidenceCalibrator",
    "LLMProvider",
    "LLMRequest",
    "LLMResponse",
    "LLMResponseParser",
    "OpenAICompatibleProvider",
    "ParsedLLMDecision",
    "PromptBundle",
    "SemanticDisambiguator",
    "StaticLLMProvider",
    "build_candidate_label_prompt",
    "build_cve_candidate_alignment_prompt",
    "build_patch_intent_prompt",
    "load_patch_diff_text",
]
