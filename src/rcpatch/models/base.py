"""Base helpers for validated RCPatch models."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, TypeVar, Union

from pydantic import BaseModel, ConfigDict, ValidationError

from rcpatch.errors import ModelSerializationError, ModelValidationError

ModelT = TypeVar("ModelT", bound="RCPatchModel")


class RCPatchModel(BaseModel):
    """Base model with strict validation and JSON round-tripping helpers."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        validate_assignment=True,
        str_strip_whitespace=True,
        use_attribute_docstrings=True,
    )

    def to_dict(self, *, exclude_none: bool = True) -> dict[str, Any]:
        """Serialize the model to a JSON-compatible dictionary."""
        return self.model_dump(mode="json", exclude_none=exclude_none, by_alias=True)

    def to_json(self, *, indent: int = 2, exclude_none: bool = True) -> str:
        """Serialize the model to a formatted JSON string."""
        try:
            return json.dumps(self.to_dict(exclude_none=exclude_none), indent=indent, sort_keys=True)
        except TypeError as exc:
            raise ModelSerializationError(f"Failed to serialize {self.__class__.__name__}: {exc}") from exc

    def to_json_file(self, path: Union[str, Path], *, indent: int = 2, exclude_none: bool = True) -> Path:
        """Write the model as JSON to disk."""
        output_path = Path(path)
        try:
            output_path.write_text(self.to_json(indent=indent, exclude_none=exclude_none), encoding="utf-8")
        except OSError as exc:
            raise ModelSerializationError(
                f"Failed to write {self.__class__.__name__} JSON to {output_path}: {exc}"
            ) from exc
        return output_path

    @classmethod
    def from_dict(cls: type[ModelT], payload: Mapping[str, Any]) -> ModelT:
        """Build a model from a Python mapping with validation."""
        try:
            return cls.model_validate(payload)
        except ValidationError as exc:
            raise ModelValidationError(cls.__name__, exc.errors()) from exc

    @classmethod
    def from_json(cls: type[ModelT], raw_json: str) -> ModelT:
        """Build a model from a JSON string with validation."""
        try:
            payload = json.loads(raw_json)
        except json.JSONDecodeError as exc:
            raise ModelSerializationError(f"Invalid JSON for {cls.__name__}: {exc}") from exc
        if not isinstance(payload, Mapping):
            raise ModelSerializationError(
                f"Expected a JSON object for {cls.__name__}, received {type(payload).__name__}"
            )
        return cls.from_dict(payload)

    @classmethod
    def from_json_file(cls: type[ModelT], path: Union[str, Path]) -> ModelT:
        """Build a model from a JSON file with validation."""
        input_path = Path(path)
        try:
            raw_json = input_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ModelSerializationError(f"Failed to read JSON for {cls.__name__} from {input_path}: {exc}") from exc
        return cls.from_json(raw_json)

    @classmethod
    def json_schema(cls) -> dict[str, Any]:
        """Return the JSON schema for the model."""
        return cls.model_json_schema(by_alias=True)


# Backward-compatible public name retained for older BugRC-based imports.
BugRCModel = RCPatchModel
