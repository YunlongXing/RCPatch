"""Provider abstraction, caching, and OpenAI-compatible LLM client support."""

from __future__ import annotations

import hashlib
import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib import error as urllib_error
from urllib import request as urllib_request

from rcpatch.errors import LLMProviderError
from rcpatch.logging_utils import get_logger


@dataclass(frozen=True)
class LLMRequest:
    """Structured LLM request used for deterministic prompting and caching."""

    task: str
    prompt_version: str
    system_prompt: str
    user_prompt: str
    response_schema: dict[str, Any]
    temperature: float = 0.0
    max_output_tokens: int = 512
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class LLMResponse:
    """Normalized LLM response returned by a provider."""

    text: str
    provider: str
    model: str
    cached: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
    raw_response: Optional[dict[str, Any]] = None


class LLMProvider(ABC):
    """Abstract provider interface for pluggable LLM backends."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """User-facing provider name."""

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Configured model identifier."""

    @abstractmethod
    def is_available(self) -> bool:
        """Whether this provider is configured and ready to serve requests."""

    @abstractmethod
    def complete(self, llm_request: LLMRequest) -> LLMResponse:
        """Execute a completion request."""


class FileLLMCache:
    """Small JSON-file cache keyed by hashed request fingerprints."""

    def __init__(self, cache_dir: Optional[str] = None) -> None:
        default_cache_dir = Path(".rcpatch_llm_cache")
        self.cache_dir = Path(cache_dir).expanduser() if cache_dir else default_cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.logger = get_logger(__name__)

    def make_key(self, provider: LLMProvider, llm_request: LLMRequest) -> str:
        """Build a stable cache key for a provider/request pair."""
        fingerprint_payload = {
            "provider": provider.provider_name,
            "model": provider.model_name,
            "task": llm_request.task,
            "prompt_version": llm_request.prompt_version,
            "system_prompt": llm_request.system_prompt,
            "user_prompt": llm_request.user_prompt,
            "response_schema": llm_request.response_schema,
            "temperature": llm_request.temperature,
            "max_output_tokens": llm_request.max_output_tokens,
            "metadata": llm_request.metadata,
        }
        fingerprint = json.dumps(fingerprint_payload, sort_keys=True, ensure_ascii=True, default=str)
        return hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()

    def get(self, cache_key: str) -> Optional[LLMResponse]:
        """Return a cached response if present."""
        cache_path = self.cache_dir / f"{cache_key}.json"
        if not cache_path.exists():
            return None
        payload = json.loads(cache_path.read_text(encoding="utf-8"))
        return LLMResponse(
            text=payload["text"],
            provider=payload["provider"],
            model=payload["model"],
            cached=True,
            metadata=payload.get("metadata", {}),
            raw_response=payload.get("raw_response"),
        )

    def set(self, cache_key: str, response: LLMResponse) -> None:
        """Persist a response under a cache key."""
        cache_path = self.cache_dir / f"{cache_key}.json"
        payload = {
            "text": response.text,
            "provider": response.provider,
            "model": response.model,
            "metadata": response.metadata,
            "raw_response": response.raw_response,
        }
        cache_path.write_text(json.dumps(payload, sort_keys=True, indent=2), encoding="utf-8")


class LLMClient:
    """Thin orchestration layer that adds caching and graceful fallback."""

    def __init__(
        self,
        provider: Optional[LLMProvider] = None,
        *,
        cache: Optional[FileLLMCache] = None,
    ) -> None:
        self.provider = provider
        self.cache = cache or FileLLMCache()
        self.logger = get_logger(__name__)

    def is_available(self) -> bool:
        """Whether a provider is configured and available."""
        return self.provider is not None and self.provider.is_available()

    def complete(self, llm_request: LLMRequest) -> Optional[LLMResponse]:
        """Return a cached or live response, or None if unavailable."""
        if self.provider is None or not self.provider.is_available():
            self.logger.info("LLM provider unavailable for task %s", llm_request.task)
            return None

        cache_key = self.cache.make_key(self.provider, llm_request)
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached

        try:
            response = self.provider.complete(llm_request)
        except LLMProviderError:
            return None

        self.cache.set(cache_key, response)
        return response


class OpenAICompatibleProvider(LLMProvider):
    """OpenAI-compatible provider that calls a `/chat/completions` endpoint."""

    def __init__(
        self,
        *,
        model: str,
        api_key: Optional[str] = None,
        base_url: str = "https://api.openai.com/v1",
        timeout_seconds: float = 30.0,
        organization: Optional[str] = None,
        extra_headers: Optional[dict[str, str]] = None,
    ) -> None:
        self._model = model
        self.api_key = (
            api_key
            or os.getenv("RCPATCH_OPENAI_API_KEY")
            or os.getenv("BUGRC_OPENAI_API_KEY")
            or os.getenv("OPENAI_API_KEY")
        )
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.organization = organization
        self.extra_headers = dict(extra_headers or {})
        self.logger = get_logger(__name__)

    @property
    def provider_name(self) -> str:
        return "openai_compatible"

    @property
    def model_name(self) -> str:
        return self._model

    def is_available(self) -> bool:
        return bool(self.api_key and self._model)

    def complete(self, llm_request: LLMRequest) -> LLMResponse:
        if not self.is_available():
            raise LLMProviderError("OpenAI-compatible provider is missing an API key or model name")

        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": llm_request.system_prompt},
                {"role": "user", "content": llm_request.user_prompt},
            ],
            "temperature": llm_request.temperature,
            "max_tokens": llm_request.max_output_tokens,
            "response_format": {"type": "json_object"},
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        if self.organization:
            headers["OpenAI-Organization"] = self.organization
        headers.update(self.extra_headers)

        request = urllib_request.Request(
            url=f"{self.base_url}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib_request.urlopen(request, timeout=self.timeout_seconds) as response:
                raw_payload = json.loads(response.read().decode("utf-8"))
        except urllib_error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise LLMProviderError(f"HTTP {exc.code} from LLM provider: {body}") from exc
        except urllib_error.URLError as exc:
            raise LLMProviderError(f"Network error contacting LLM provider: {exc.reason}") from exc
        except OSError as exc:
            raise LLMProviderError(f"Failed to contact LLM provider: {exc}") from exc

        text = _extract_openai_message_text(raw_payload)
        return LLMResponse(
            text=text,
            provider=self.provider_name,
            model=self._model,
            cached=False,
            metadata={"task": llm_request.task, "prompt_version": llm_request.prompt_version},
            raw_response=raw_payload,
        )


class StaticLLMProvider(LLMProvider):
    """Testing-oriented provider that returns a fixed payload."""

    def __init__(self, *, response_text: str, model: str = "static-model", provider_name: str = "static", available: bool = True) -> None:
        self.response_text = response_text
        self._model = model
        self._provider_name = provider_name
        self.available = available
        self.calls = 0

    @property
    def provider_name(self) -> str:
        return self._provider_name

    @property
    def model_name(self) -> str:
        return self._model

    def is_available(self) -> bool:
        return self.available

    def complete(self, llm_request: LLMRequest) -> LLMResponse:
        self.calls += 1
        return LLMResponse(
            text=self.response_text,
            provider=self.provider_name,
            model=self.model_name,
            metadata={"task": llm_request.task, "prompt_version": llm_request.prompt_version},
        )


def _extract_openai_message_text(raw_payload: dict[str, Any]) -> str:
    choices = raw_payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise LLMProviderError("LLM provider response did not contain any choices")

    first_choice = choices[0]
    message = first_choice.get("message", {})
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
        if parts:
            return "".join(parts)
    raise LLMProviderError("LLM provider response did not contain a usable message content payload")
