"""Shared RCPatch exceptions."""

from __future__ import annotations

from typing import Any


class RCPatchError(Exception):
    """Base exception for RCPatch errors."""


class ModelSerializationError(RCPatchError):
    """Raised when JSON serialization or deserialization fails."""


class ModelValidationError(RCPatchError):
    """Raised when a model fails validation."""

    def __init__(self, model_name: str, details: Any) -> None:
        self.model_name = model_name
        self.details = details
        super().__init__(f"Validation failed for {model_name}: {details}")


class LLMError(RCPatchError):
    """Base exception for LLM-related failures."""


class LLMProviderError(LLMError):
    """Raised when an LLM provider request fails."""


class LLMResponseParseError(LLMError):
    """Raised when an LLM response cannot be parsed into the expected structure."""


# Backward-compatible public names retained for older BugRC-based scripts.
BugRCError = RCPatchError
