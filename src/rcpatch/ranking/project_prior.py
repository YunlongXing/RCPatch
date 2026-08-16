"""Project-specific historical priors for RCPatch candidate ranking."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from rcpatch.errors import ModelSerializationError


@dataclass(frozen=True)
class ProjectPriorMatch:
    """Best project prior match for a candidate."""

    score: float
    project: str
    reason: str
    matched_key: str


@dataclass(frozen=True)
class _ProjectRule:
    patterns: dict[str, float] = field(default_factory=dict)
    operation_types: dict[str, float] = field(default_factory=dict)
    bug_types: dict[str, float] = field(default_factory=dict)


class ProjectPrior:
    """Lightweight lookup table for project-specific bug patterns."""

    def __init__(self, rules: dict[str, _ProjectRule]) -> None:
        self.rules = {key.lower(): value for key, value in rules.items()}

    @classmethod
    def from_file(cls, path: str | Path) -> "ProjectPrior":
        """Load a project-prior JSON file.

        Expected shape:
        ``{"projects": {"curl": {"patterns": {"validation_or_guard_issue": 0.8}}}}``.
        """

        input_path = Path(path).expanduser().resolve()
        try:
            payload = json.loads(input_path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ModelSerializationError(f"Failed to read project prior {input_path}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ModelSerializationError(f"Invalid project prior JSON {input_path}: {exc}") from exc
        if not isinstance(payload, dict):
            raise ModelSerializationError(f"Expected project prior object in {input_path}")

        raw_projects = payload.get("projects", payload)
        rules: dict[str, _ProjectRule] = {}
        if isinstance(raw_projects, dict):
            for project, raw_rule in raw_projects.items():
                if not isinstance(raw_rule, dict):
                    continue
                rules[str(project)] = _ProjectRule(
                    patterns=_float_map(raw_rule.get("patterns")),
                    operation_types=_float_map(raw_rule.get("operation_types")),
                    bug_types=_float_map(raw_rule.get("bug_types")),
                )
        return cls(rules)

    def match(
        self,
        *,
        project: str,
        matched_pattern: str,
        operation_type: Optional[str],
        bug_type: Optional[str],
    ) -> Optional[ProjectPriorMatch]:
        """Return a bounded project-specific score for extracted features."""

        normalized_project = project.lower()
        rule = self.rules.get(normalized_project)
        if rule is None:
            return None

        candidates: list[tuple[float, str, str]] = []
        pattern = matched_pattern.lower()
        if pattern and pattern in rule.patterns:
            candidates.append((rule.patterns[pattern], pattern, "Project history favors this root-cause pattern."))
        if operation_type and operation_type.lower() in rule.operation_types:
            key = operation_type.lower()
            candidates.append((rule.operation_types[key], key, "Project history favors this operation type."))
        if bug_type and bug_type.lower() in rule.bug_types:
            key = bug_type.lower()
            candidates.append((rule.bug_types[key], key, "Project history favors this bug type."))
        if not candidates:
            return None
        score, key, reason = max(candidates, key=lambda item: item[0])
        return ProjectPriorMatch(
            score=max(0.0, min(score, 1.0)),
            project=project,
            reason=reason,
            matched_key=key,
        )


def infer_project_name(repo_path: str, metadata: dict[str, Any]) -> str:
    """Choose a stable project key from metadata or repository path."""

    for key in ("project", "project_name", "package", "repo_name"):
        value = metadata.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return Path(repo_path).name


def _float_map(value: object) -> dict[str, float]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, float] = {}
    for key, raw_value in value.items():
        try:
            result[str(key).lower()] = float(raw_value)
        except (TypeError, ValueError):
            continue
    return result
