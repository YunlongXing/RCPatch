"""Heuristic patch-intent classification."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Optional

from rcpatch.logging_utils import get_logger
from rcpatch.models import PatchIntent
from rcpatch.patch_analysis.models import ParsedPatch

CONDITION_RE = re.compile(r"^\s*(if|assert|while)\b")
EARLY_EXIT_RE = re.compile(r"\b(return|goto|break|continue)\b")
ASSIGNMENT_RE = re.compile(r"(?<![=!<>])=(?!=)")
ARITHMETIC_RE = re.compile(r"(<<|>>|\+\+|--|\+=|-=|\*=|/=|%=|[+\-/%])")
REFactor_TOKENS = ("refactor", "cleanup", "rename", "style", "format", "whitespace")
FIX_TOKENS = ("fix", "overflow", "underflow", "length", "size", "bound", "oob", "root cause", "incorrect")
GUARD_TOKENS = ("check", "guard", "validate", "null", "nullptr", "bounds", "range")


class PatchIntentClassifier:
    """Classify the likely purpose of an official fix patch."""

    def __init__(self) -> None:
        self.logger = get_logger(__name__)

    def classify(
        self,
        parsed_patch: ParsedPatch,
        *,
        commit_message: Optional[str] = None,
        issue_text: Optional[str] = None,
    ) -> tuple[PatchIntent, dict[str, float]]:
        """Return the most likely patch intent and raw heuristic scores."""
        scores: dict[PatchIntent, float] = defaultdict(float)
        commit_lower = (commit_message or "").lower()
        issue_lower = (issue_text or "").lower()
        message_text = " ".join(part for part in (commit_lower, issue_lower) if part)

        added_lines = [line.text.strip() for patched_file in parsed_patch.files for hunk in patched_file.hunks for line in hunk.lines if line.kind == "add"]
        removed_lines = [line.text.strip() for patched_file in parsed_patch.files for hunk in patched_file.hunks for line in hunk.lines if line.kind == "del"]

        added_checks = sum(1 for line in added_lines if CONDITION_RE.search(line))
        early_exit_additions = sum(1 for line in added_lines if EARLY_EXIT_RE.search(line))
        semantic_assignments = sum(1 for line in added_lines + removed_lines if ASSIGNMENT_RE.search(line) or ARITHMETIC_RE.search(line))
        semantic_memory_edits = sum(1 for line in added_lines + removed_lines if any(token in line for token in ("malloc", "free", "memcpy", "memmove", "memset")))

        if semantic_assignments or semantic_memory_edits:
            scores[PatchIntent.DIRECT_FIX] += 0.6
        if any(token in message_text for token in FIX_TOKENS):
            scores[PatchIntent.DIRECT_FIX] += 0.25

        if added_checks:
            scores[PatchIntent.DEFENSIVE_GUARD] += 0.55
            if any(token in message_text for token in GUARD_TOKENS):
                scores[PatchIntent.DEFENSIVE_GUARD] += 0.15

        if added_checks and early_exit_additions:
            scores[PatchIntent.COMPENSATING_CHECK] += 0.55
        if early_exit_additions and any(token in message_text for token in ("avoid", "prevent", "fallback", "graceful")):
            scores[PatchIntent.COMPENSATING_CHECK] += 0.15

        if any(token in message_text for token in REFactor_TOKENS):
            scores[PatchIntent.CLEANUP] += 0.65
            scores[PatchIntent.REFACTOR] += 0.65
        if not semantic_assignments and not semantic_memory_edits and not added_checks and parsed_patch.files:
            scores[PatchIntent.CLEANUP] += 0.2

        if scores[PatchIntent.DIRECT_FIX] >= 0.6 and scores[PatchIntent.COMPENSATING_CHECK] < 0.6:
            scores[PatchIntent.DEFENSIVE_GUARD] *= 0.75
            scores[PatchIntent.CLEANUP] *= 0.5
            scores[PatchIntent.REFACTOR] *= 0.5

        if not scores:
            return PatchIntent.UNKNOWN, {}

        intent = max(scores.items(), key=lambda item: item[1])[0]
        if scores[intent] < 0.4:
            return PatchIntent.UNKNOWN, dict(scores)
        return intent, dict(scores)
