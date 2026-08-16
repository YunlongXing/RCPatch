"""Scoring logic for root-cause candidates."""

from __future__ import annotations

from typing import Any

from rcpatch.models import CandidateLabel
from rcpatch.ranking.calibration import RankerCalibration


class CandidateScorer:
    """Score and re-label candidate observations using explicit heuristics.

    These weights are intentionally hand-tuned research heuristics, not learned
    parameters. Keeping them centralized makes the tradeoffs easy to inspect,
    document, and change as the prototype evolves.
    """

    DEFAULT_CONTRIBUTION_WEIGHTS = {
        "distance": 0.18,
        "module_proximity": 0.14,
        "defines_value": 0.18,
        "state_change": 0.16,
        "integer_influence": 0.14,
        "control": 0.08,
        "bug_pattern": 0.18,
        "runtime_support": 0.10,
        "fanout": 0.08,
        "origin": 0.07,
        "contract_mismatch": 0.14,
        "cve_pattern_prior": 0.12,
        "project_prior": 0.08,
        "expert_rca_prior": 0.06,
    }
    DEFAULT_PENALTY_WEIGHTS = {
        "trigger_symptom": 0.32,
        "pure_use_site": 0.18,
        "return_only": 0.18,
        "call_forwarding": 0.16,
    }
    ROOT_CAUSE_THRESHOLD = 0.60
    SYMPTOM_THRESHOLD = 0.18

    def __init__(
        self,
        *,
        contribution_weights: dict[str, float] | None = None,
        penalty_weights: dict[str, float] | None = None,
        calibration: RankerCalibration | None = None,
    ) -> None:
        calibration = calibration or RankerCalibration()
        self.contribution_weights = {
            **self.DEFAULT_CONTRIBUTION_WEIGHTS,
            **(contribution_weights or {}),
            **calibration.contribution_weights,
        }
        self.penalty_weights = {
            **self.DEFAULT_PENALTY_WEIGHTS,
            **(penalty_weights or {}),
            **calibration.penalty_weights,
        }
        self.pattern_boosts = dict(calibration.pattern_boosts)
        self.feature_boosts = dict(calibration.feature_boosts)
        self.root_cause_threshold = calibration.root_cause_threshold or self.ROOT_CAUSE_THRESHOLD
        self.symptom_threshold = calibration.symptom_threshold or self.SYMPTOM_THRESHOLD

    def score(self, *, features: dict[str, Any], initial_label: CandidateLabel) -> tuple[float, dict[str, float], CandidateLabel]:
        """Return a normalized score, contribution map, and final label."""
        contributions = {
            "distance": self.contribution_weights["distance"] * float(features["distance_score"]),
            "module_proximity": self.contribution_weights["module_proximity"] * float(features["module_proximity_score"]),
            "defines_value": self.contribution_weights["defines_value"] if bool(features["defines_value_used_later"]) else 0.0,
            "state_change": self.contribution_weights["state_change"] if bool(features["changes_object_state"]) else 0.0,
            "integer_influence": self.contribution_weights["integer_influence"] if bool(features["has_integer_influence"]) else 0.0,
            "control": self.contribution_weights["control"] if bool(features["affects_control_flow"]) else 0.0,
            "bug_pattern": self.contribution_weights["bug_pattern"] * float(features["bug_pattern_score"]),
            "runtime_support": self.contribution_weights["runtime_support"] * float(features["runtime_support_score"]),
            "fanout": self.contribution_weights["fanout"] * min(float(features["outgoing_edge_count"]) / 3.0, 1.0),
            "origin": self.contribution_weights["origin"] * float(features["state_origin_score"]),
            "contract_mismatch": (
                self.contribution_weights["contract_mismatch"]
                if str(features["matched_bug_pattern"]) == "buffer_size_contract_mismatch"
                else 0.0
            ),
            "cve_pattern_prior": max(
                0.0,
                min(float(features.get("cve_pattern_prior_weight", self.contribution_weights["cve_pattern_prior"])), 0.5),
            )
            * float(features.get("cve_pattern_prior_score", 0.0)),
            "project_prior": max(
                0.0,
                min(float(features.get("project_prior_weight", self.contribution_weights["project_prior"])), 0.3),
            )
            * float(features.get("project_prior_score", 0.0)),
            "expert_rca_prior": max(
                0.0,
                min(float(features.get("expert_rca_prior_weight", self.contribution_weights["expert_rca_prior"])), 0.25),
            )
            * float(features.get("expert_rca_prior_score", 0.0)),
        }
        calibrated_feature_boost = self._calibrated_feature_boost(features)
        calibrated_pattern_boost = self.pattern_boosts.get(str(features.get("matched_bug_pattern") or "").lower(), 0.0)
        if calibrated_feature_boost:
            contributions["calibrated_features"] = calibrated_feature_boost
        if calibrated_pattern_boost:
            contributions["calibrated_pattern"] = calibrated_pattern_boost
        penalties = {
            "trigger_symptom": self.penalty_weights["trigger_symptom"] if bool(features["is_trigger_node"]) else 0.0,
            "pure_use_site": self.penalty_weights["pure_use_site"] if bool(features["pure_use_site"]) else 0.0,
            "return_only": self.penalty_weights["return_only"] if bool(features["is_return_statement"]) and not bool(features["changes_object_state"]) else 0.0,
            "call_forwarding": self.penalty_weights["call_forwarding"] if bool(features["is_call_forwarding_statement"]) else 0.0,
        }

        raw_score = sum(contributions.values()) - sum(penalties.values())
        score = max(0.0, min(raw_score, 1.0))
        component_map = {**contributions, **{f"penalty_{name}": -value for name, value in penalties.items() if value}}

        label = initial_label
        # These decision boundaries encode the core ranking policy:
        # observable failure sites are symptoms, pure forwarding sites are
        # propagation, and stronger upstream state-introducing sites are roots.
        if bool(features["is_trigger_node"]) or score < self.symptom_threshold:
            label = CandidateLabel.SYMPTOM
        elif bool(features["is_return_statement"]) or bool(features["is_call_forwarding_statement"]):
            label = CandidateLabel.PROPAGATION
        elif score >= self.root_cause_threshold and (
            float(features["bug_pattern_score"]) >= 0.6
            or float(features.get("cve_pattern_prior_score", 0.0)) >= 0.65
            or float(features.get("expert_rca_prior_score", 0.0)) >= 0.7
            or bool(features["has_integer_influence"])
            or bool(features["has_memory_context"])
            or bool(features["affects_control_flow"])
        ) and (
            bool(features["defines_value_used_later"])
            or bool(features["changes_object_state"])
        ):
            label = CandidateLabel.ROOT_CAUSE_CANDIDATE
        else:
            label = CandidateLabel.PROPAGATION

        return score, component_map, label

    def _calibrated_feature_boost(self, features: dict[str, Any]) -> float:
        boost = 0.0
        for feature_name, weight in self.feature_boosts.items():
            value = features.get(feature_name)
            if isinstance(value, bool) and value:
                boost += weight
            elif isinstance(value, (int, float)) and float(value) > 0:
                boost += weight * min(float(value), 1.0)
        return max(0.0, min(boost, 0.25))
