"""Conservative patch-suggestion helpers for RCPatch analysis results."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from pydantic import Field

from rcpatch.models import AnalysisResult, CandidateLabel, RootCauseCandidate
from rcpatch.models.base import RCPatchModel


class PatchSuggestion(RCPatchModel):
    """A machine-readable patch suggestion with explicit safety notes."""

    patch_id: str = Field(min_length=1, description="Stable patch suggestion id.")
    strategy: str = Field(min_length=1, description="Patch strategy name.")
    candidate_rank: Optional[int] = Field(default=None, description="Linked root-cause candidate rank.")
    unified_diff: str = Field(default="", description="Best-effort unified diff. May be empty for pseudo patches.")
    rationale: str = Field(min_length=1, description="Why this patch could cut the bug path.")
    risk_notes: list[str] = Field(default_factory=list, description="Known risks and required human checks.")
    is_pseudo_patch: bool = Field(default=True, description="Whether the patch is a design suggestion instead of ready-to-apply diff.")
    metadata: dict[str, object] = Field(default_factory=dict, description="Extension space for generators.")


@dataclass
class PatchSuggestionGenerator:
    """Generate conservative repair ideas from RCPatch candidates and chains."""

    context_lines: int = 2

    def generate(self, result: AnalysisResult, *, repo_path: str) -> list[PatchSuggestion]:
        """Return ranked patch suggestions for an analysis result."""

        suggestions: list[PatchSuggestion] = []
        root_candidates = [
            candidate
            for candidate in result.root_cause_candidates
            if candidate.label == CandidateLabel.ROOT_CAUSE_CANDIDATE
        ] or list(result.root_cause_candidates[:1])
        for index, candidate in enumerate(root_candidates[:3], start=1):
            suggestion = self._suggest_for_candidate(result, repo_path=repo_path, candidate=candidate, ordinal=index)
            if suggestion is not None:
                suggestions.append(suggestion)
        return suggestions

    def _suggest_for_candidate(
        self,
        result: AnalysisResult,
        *,
        repo_path: str,
        candidate: RootCauseCandidate,
        ordinal: int,
    ) -> Optional[PatchSuggestion]:
        pattern = str(candidate.features.get("matched_bug_pattern") or "")
        if pattern in {"incorrect_size_computation", "buffer_size_contract_mismatch"}:
            return self._size_contract_patch(result, repo_path=repo_path, candidate=candidate, ordinal=ordinal)
        if pattern in {"validation_or_guard_issue", "none"}:
            return self._guard_patch(result, repo_path=repo_path, candidate=candidate, ordinal=ordinal)
        if pattern in {"ownership_or_lifetime_operation", "invalid_initialization", "invalid_state_update"}:
            return self._state_repair_patch(result, repo_path=repo_path, candidate=candidate, ordinal=ordinal)
        return self._guard_patch(result, repo_path=repo_path, candidate=candidate, ordinal=ordinal)

    def _guard_patch(
        self,
        result: AnalysisResult,
        *,
        repo_path: str,
        candidate: RootCauseCandidate,
        ordinal: int,
    ) -> PatchSuggestion:
        trigger = result.trigger_point.location
        entity = _preferred_entity(candidate.features.get("tracked_entities"))
        condition = f"{entity} == NULL" if entity else "/* invalid state */"
        guard = f"if ({condition}) {{\\n    return;\\n}}"
        diff = self._insert_before_line(
            repo_path=repo_path,
            relative_file=trigger.file,
            line=trigger.line,
            inserted_lines=[guard],
        )
        is_pseudo = "return;" in guard
        return PatchSuggestion(
            patch_id=f"guard-{ordinal}",
            strategy="defensive_guard",
            candidate_rank=candidate.rank,
            unified_diff=diff,
            rationale="Add a guard before the trigger to stop the unsafe execution path when the relevant state is invalid.",
            risk_notes=[
                "Confirm the enclosing function can safely return at this point.",
                "If resources or locks were acquired before the trigger, release or restore them before returning.",
                "Prefer repairing the upstream invalid state if a precise correction is known.",
            ],
            is_pseudo_patch=is_pseudo,
            metadata={"guard_condition": condition},
        )

    def _size_contract_patch(
        self,
        result: AnalysisResult,
        *,
        repo_path: str,
        candidate: RootCauseCandidate,
        ordinal: int,
    ) -> PatchSuggestion:
        trigger = result.trigger_point.location
        entity = _preferred_entity(candidate.features.get("tracked_entities")) or "size"
        inserted = [
            f"if ({entity} < 0) {{",
            "    return;",
            "}",
            f"/* Ensure reported and written sizes agree before using {entity}. */",
        ]
        diff = self._insert_before_line(
            repo_path=repo_path,
            relative_file=trigger.file,
            line=trigger.line,
            inserted_lines=inserted,
        )
        return PatchSuggestion(
            patch_id=f"size-contract-{ordinal}",
            strategy="size_contract_repair",
            candidate_rank=candidate.rank,
            unified_diff=diff,
            rationale="Repair or guard the size/index contract before it reaches the memory operation at the trigger.",
            risk_notes=[
                "Replace the placeholder guard with the project's canonical size type and error return.",
                "Check both size-query and write paths for two-call APIs.",
                "Preserve buffer ownership and do not silently truncate attacker-controlled data unless documented.",
            ],
            is_pseudo_patch=True,
            metadata={"size_entity": entity},
        )

    def _state_repair_patch(
        self,
        result: AnalysisResult,
        *,
        repo_path: str,
        candidate: RootCauseCandidate,
        ordinal: int,
    ) -> PatchSuggestion:
        location = candidate.location
        entity = _preferred_entity(candidate.features.get("tracked_entities")) or "state"
        inserted = [
            f"/* Repair {entity} here, or route failure through existing cleanup before propagation. */",
        ]
        diff = self._insert_before_line(
            repo_path=repo_path,
            relative_file=location.file,
            line=location.line,
            inserted_lines=inserted,
        )
        return PatchSuggestion(
            patch_id=f"state-repair-{ordinal}",
            strategy="state_repair_or_cleanup",
            candidate_rank=candidate.rank,
            unified_diff=diff,
            rationale="The root-cause candidate updates lifetime, ownership, initialization, or object state before the trigger.",
            risk_notes=[
                "Use the project's existing cleanup path rather than adding a new early return when resources are live.",
                "Restore globals and object fields consistently on all error paths.",
                "Validate alias ownership before freeing or transferring pointers.",
            ],
            is_pseudo_patch=True,
            metadata={"state_entity": entity},
        )

    def _insert_before_line(
        self,
        *,
        repo_path: str,
        relative_file: str,
        line: int,
        inserted_lines: list[str],
    ) -> str:
        source_path = Path(repo_path) / relative_file
        try:
            lines = source_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return ""
        if line < 1 or line > len(lines):
            return ""

        start = max(line - self.context_lines - 1, 0)
        end = min(line + self.context_lines - 1, len(lines))
        before = lines[start : line - 1]
        after = lines[line - 1 : end]
        old_count = max(end - start, 1)
        new_count = old_count + len(inserted_lines)
        hunk = [
            f"--- a/{relative_file}",
            f"+++ b/{relative_file}",
            f"@@ -{start + 1},{old_count} +{start + 1},{new_count} @@",
        ]
        hunk.extend(f" {item}" for item in before)
        hunk.extend(f"+{item}" for item in inserted_lines)
        hunk.extend(f" {item}" for item in after)
        return "\n".join(hunk) + "\n"


def _preferred_entity(raw_entities: object) -> Optional[str]:
    if not isinstance(raw_entities, list):
        return None
    for entity in raw_entities:
        if isinstance(entity, str) and entity and entity not in {"NULL", "nullptr"}:
            return entity
    return None
