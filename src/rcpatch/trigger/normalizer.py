"""Trigger-point normalization logic."""

from __future__ import annotations

from typing import Optional

from rcpatch.logging_utils import get_logger
from rcpatch.models import BugType, EvidenceReference, RuntimeEvidence, SourceLocation, TriggerPoint


class TriggerNormalizer:
    """Merge explicit trigger information with parsed runtime evidence."""

    def __init__(self) -> None:
        self.logger = get_logger(__name__)

    def normalize(
        self,
        explicit_trigger: TriggerPoint,
        runtime_evidence: Optional[RuntimeEvidence] = None,
    ) -> TriggerPoint:
        canonical_location = explicit_trigger.location
        merged_evidence: list[EvidenceReference] = list(explicit_trigger.evidence)
        bug_type_hint = explicit_trigger.bug_type_hint
        confidence = explicit_trigger.confidence
        metadata = dict(explicit_trigger.metadata)

        if runtime_evidence is None:
            return explicit_trigger

        runtime_trigger_location = self._select_runtime_trigger_location(runtime_evidence)
        if runtime_trigger_location is not None:
            canonical_location = self._merge_locations(canonical_location, runtime_trigger_location)
            metadata.setdefault("runtime_trigger_source", runtime_trigger_location.metadata.get("source", "stack_frame"))

        merged_evidence.extend(self._select_runtime_evidence(runtime_evidence))
        if bug_type_hint is None:
            bug_type_hint = self._bug_type_from_runtime(runtime_evidence)

        if confidence is None:
            confidence = runtime_evidence.confidence

        return explicit_trigger.model_copy(
            update={
                "location": canonical_location,
                "bug_type_hint": bug_type_hint,
                "evidence": merged_evidence,
                "confidence": confidence,
                "metadata": metadata,
            }
        )

    def _select_runtime_trigger_location(self, runtime_evidence: RuntimeEvidence) -> Optional[SourceLocation]:
        if runtime_evidence.trigger_frame_index is not None and runtime_evidence.stack_frames:
            for frame in runtime_evidence.stack_frames:
                if frame.index == runtime_evidence.trigger_frame_index and frame.location is not None:
                    return frame.location

        for frame in runtime_evidence.stack_frames:
            if frame.location is not None:
                return frame.location
        return None

    def _select_runtime_evidence(self, runtime_evidence: RuntimeEvidence) -> list[EvidenceReference]:
        selected: list[EvidenceReference] = []
        for evidence in runtime_evidence.evidence:
            description = (evidence.description or "").lower()
            if "summary" in description or "frame" in description or "error header" in description:
                selected.append(evidence)
        return selected

    @staticmethod
    def _bug_type_from_runtime(runtime_evidence: RuntimeEvidence) -> Optional[BugType]:
        raw_hint = runtime_evidence.metadata.get("bug_type_hint")
        if isinstance(raw_hint, str):
            try:
                return BugType(raw_hint)
            except ValueError:
                return None
        if isinstance(raw_hint, BugType):
            return raw_hint
        return None

    @staticmethod
    def _merge_locations(explicit_location: SourceLocation, runtime_location: SourceLocation) -> SourceLocation:
        function = explicit_location.function or runtime_location.function
        column = explicit_location.column if explicit_location.column is not None else runtime_location.column
        metadata = dict(runtime_location.metadata)
        metadata.update(explicit_location.metadata)

        return explicit_location.model_copy(
            update={
                "file": explicit_location.file or runtime_location.file,
                "line": explicit_location.line or runtime_location.line,
                "column": column,
                "function": function,
                "metadata": metadata,
            }
        )
