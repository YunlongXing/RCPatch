"""Interfaces for backward slicing."""

from __future__ import annotations

from abc import ABC, abstractmethod

from rcpatch.models import BackwardSlice, TriggerPoint
from rcpatch.source import ProgramIndex


class BackwardSlicer(ABC):
    """Interface implemented by backward slicing strategies."""

    @abstractmethod
    def slice_from_trigger(self, program_index: ProgramIndex, trigger: TriggerPoint) -> BackwardSlice:
        """Build a backward slice rooted at the provided trigger point."""
