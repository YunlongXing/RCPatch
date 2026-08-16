"""Data-driven calibration helpers for RCPatch's heuristic ranker."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rcpatch.errors import ModelSerializationError


@dataclass(frozen=True)
class RankerCalibration:
    """Optional ranker adjustments learned from curated ARVO/CVE cases."""

    contribution_weights: dict[str, float] = field(default_factory=dict)
    penalty_weights: dict[str, float] = field(default_factory=dict)
    pattern_boosts: dict[str, float] = field(default_factory=dict)
    feature_boosts: dict[str, float] = field(default_factory=dict)
    root_cause_threshold: float | None = None
    symptom_threshold: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_file(cls, path: str | Path) -> "RankerCalibration":
        """Load calibration JSON from disk."""

        input_path = Path(path).expanduser().resolve()
        try:
            payload = json.loads(input_path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ModelSerializationError(f"Failed to read ranker calibration {input_path}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ModelSerializationError(f"Invalid ranker calibration JSON {input_path}: {exc}") from exc
        if not isinstance(payload, dict):
            raise ModelSerializationError(f"Expected ranker calibration object in {input_path}")
        return cls(
            contribution_weights=_float_map(payload.get("contribution_weights")),
            penalty_weights=_float_map(payload.get("penalty_weights")),
            pattern_boosts=_float_map(payload.get("pattern_boosts")),
            feature_boosts=_float_map(payload.get("feature_boosts")),
            root_cause_threshold=_optional_float(payload.get("root_cause_threshold")),
            symptom_threshold=_optional_float(payload.get("symptom_threshold")),
            metadata=payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {},
        )


def _float_map(value: object) -> dict[str, float]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, float] = {}
    for key, raw_value in value.items():
        try:
            result[str(key)] = float(raw_value)
        except (TypeError, ValueError):
            continue
    return result


def _optional_float(value: object) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
