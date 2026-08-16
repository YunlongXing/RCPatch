"""Configuration helpers for RCPatch CLI and pipeline orchestration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Optional

from rcpatch.errors import ModelSerializationError
from rcpatch.models import AnalysisConfig

ANALYSIS_CONFIG_FIELDS = frozenset(AnalysisConfig.model_fields)


def load_bug_spec_payload(
    spec_path: str | Path,
    *,
    config_path: Optional[str | Path] = None,
    config_overrides: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    """Load a bug specification and merge optional config overlays.

    Merge order is intentionally explicit:
    1. base bug specification
    2. config overlay file
    3. CLI/runtime overrides

    Later layers win so command-line flags can override both the spec and the
    external config file without mutating either source.
    """

    spec_payload = load_json_object(spec_path, description="bug specification")
    if config_path is not None:
        config_payload = normalize_config_overlay(
            load_json_object(config_path, description="analysis config")
        )
        spec_payload = deep_merge_dicts(spec_payload, config_payload)
    if config_overrides:
        spec_payload = deep_merge_dicts(spec_payload, {"config": dict(config_overrides)})
    return spec_payload


def build_analysis_config_overrides(
    *,
    parser_backend: Optional[str] = None,
    top_k_candidates: Optional[int] = None,
    max_chain_paths: Optional[int] = None,
    enable_patch_analysis: Optional[bool] = None,
    enable_llm: Optional[bool] = None,
    enable_cve_pattern_prior: Optional[bool] = None,
    cve_pattern_library_path: Optional[str] = None,
    cve_pattern_min_support: Optional[int] = None,
    cve_pattern_min_confidence: Optional[float] = None,
    cve_pattern_prior_weight: Optional[float] = None,
    ranker_calibration_path: Optional[str] = None,
    enable_project_prior: Optional[bool] = None,
    project_prior_path: Optional[str] = None,
    project_prior_weight: Optional[float] = None,
    enable_expert_rca_prior: Optional[bool] = None,
    expert_rca_prior_path: Optional[str] = None,
    expert_rca_prior_min_confidence: Optional[float] = None,
    expert_rca_prior_weight: Optional[float] = None,
) -> dict[str, object]:
    """Build a compact config-override payload from runtime flags."""

    overrides: dict[str, object] = {}
    if parser_backend:
        overrides["parser_backend"] = parser_backend
    if top_k_candidates is not None:
        overrides["top_k_candidates"] = top_k_candidates
    if max_chain_paths is not None:
        overrides["max_chain_paths"] = max_chain_paths
    if enable_patch_analysis is not None:
        overrides["enable_patch_analysis"] = enable_patch_analysis
    if enable_llm is not None:
        overrides["enable_llm"] = enable_llm
    if enable_cve_pattern_prior is not None:
        overrides["enable_cve_pattern_prior"] = enable_cve_pattern_prior
    if cve_pattern_library_path:
        overrides["cve_pattern_library_path"] = cve_pattern_library_path
    if cve_pattern_min_support is not None:
        overrides["cve_pattern_min_support"] = cve_pattern_min_support
    if cve_pattern_min_confidence is not None:
        overrides["cve_pattern_min_confidence"] = cve_pattern_min_confidence
    if cve_pattern_prior_weight is not None:
        overrides["cve_pattern_prior_weight"] = cve_pattern_prior_weight
    if ranker_calibration_path:
        overrides["ranker_calibration_path"] = ranker_calibration_path
    if enable_project_prior is not None:
        overrides["enable_project_prior"] = enable_project_prior
    if project_prior_path:
        overrides["project_prior_path"] = project_prior_path
    if project_prior_weight is not None:
        overrides["project_prior_weight"] = project_prior_weight
    if enable_expert_rca_prior is not None:
        overrides["enable_expert_rca_prior"] = enable_expert_rca_prior
    if expert_rca_prior_path:
        overrides["expert_rca_prior_path"] = expert_rca_prior_path
    if expert_rca_prior_min_confidence is not None:
        overrides["expert_rca_prior_min_confidence"] = expert_rca_prior_min_confidence
    if expert_rca_prior_weight is not None:
        overrides["expert_rca_prior_weight"] = expert_rca_prior_weight
    return overrides


def load_json_object(path: str | Path, *, description: str) -> dict[str, Any]:
    """Load a JSON object from disk with uniform error handling."""

    input_path = Path(path).expanduser().resolve()
    try:
        payload = json.loads(input_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ModelSerializationError(f"Failed to read {description} {input_path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ModelSerializationError(f"Invalid JSON in {description} {input_path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ModelSerializationError(
            f"Expected a JSON object in {description} {input_path}, received {type(payload).__name__}"
        )
    return payload


def normalize_config_overlay(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize overlay payloads into the canonical ``{\"config\": ...}`` form.

    The CLI accepts both a nested shape and a flat file containing only
    ``AnalysisConfig`` fields so experiments can keep small override files.
    """

    overlay = dict(payload)
    if "analysis_config" in overlay and "config" not in overlay:
        value = overlay.pop("analysis_config")
        if isinstance(value, Mapping):
            overlay["config"] = dict(value)

    if "config" in overlay and isinstance(overlay["config"], Mapping):
        return dict(overlay)

    direct_config = {
        key: overlay.pop(key)
        for key in list(overlay.keys())
        if key in ANALYSIS_CONFIG_FIELDS
    }
    if direct_config:
        overlay["config"] = direct_config
    return overlay


def deep_merge_dicts(base: Mapping[str, Any], overlay: Mapping[str, Any]) -> dict[str, Any]:
    """Recursively merge mapping-like payloads without mutating inputs."""

    merged = dict(base)
    for key, value in overlay.items():
        existing = merged.get(key)
        if isinstance(existing, Mapping) and isinstance(value, Mapping):
            merged[key] = deep_merge_dicts(existing, value)
        else:
            merged[key] = value
    return merged
