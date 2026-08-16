"""Bug-spec ingestion and trigger normalization pipeline."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional, Union

from rcpatch.dynamic_analysis import AsanLikeSanitizerParser, StackTraceParser
from rcpatch.errors import RCPatchError, ModelSerializationError
from rcpatch.ingestion.path_utils import SourcePathResolver
from rcpatch.logging_utils import get_logger
from rcpatch.models import (
    BugReport,
    EvidenceReference,
    RuntimeEvidence,
    TriggerPoint,
)
from rcpatch.trigger import TriggerNormalizer


@dataclass
class InlineEvidencePayload:
    """Inline text extracted from a bug-spec payload before model validation."""

    sanitizer_report_text: Optional[str] = None
    stack_trace_text: Optional[str] = None
    runtime_log_text: Optional[str] = None


class BugIngestionService:
    """Load a bug specification JSON file and return a normalized BugReport."""

    def __init__(
        self,
        *,
        sanitizer_parser: Optional[AsanLikeSanitizerParser] = None,
        stacktrace_parser: Optional[StackTraceParser] = None,
        trigger_normalizer: Optional[TriggerNormalizer] = None,
    ) -> None:
        self.stacktrace_parser = stacktrace_parser or StackTraceParser()
        self.sanitizer_parser = sanitizer_parser or AsanLikeSanitizerParser(self.stacktrace_parser)
        self.trigger_normalizer = trigger_normalizer or TriggerNormalizer()
        self.logger = get_logger(__name__)

    def load_from_file(self, spec_path: Union[str, Path]) -> BugReport:
        """Load, validate, and normalize a bug specification JSON file."""
        input_path = Path(spec_path).expanduser().resolve()
        self.logger.info("Loading bug specification from %s", input_path)
        try:
            raw_payload = json.loads(input_path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ModelSerializationError(f"Failed to read bug specification {input_path}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ModelSerializationError(f"Invalid JSON in bug specification {input_path}: {exc}") from exc

        if not isinstance(raw_payload, Mapping):
            raise ModelSerializationError(
                f"Expected top-level JSON object in bug specification, received {type(raw_payload).__name__}"
            )

        return self.load_from_dict(raw_payload, spec_path=input_path)

    def load_from_dict(
        self,
        payload: Mapping[str, Any],
        *,
        spec_path: Optional[Union[str, Path]] = None,
    ) -> BugReport:
        """Load, validate, and normalize a bug specification mapping."""
        spec_directory = (
            Path(spec_path).expanduser().resolve().parent if spec_path is not None else Path.cwd().resolve()
        )
        normalized_payload = deepcopy(dict(payload))
        inline_evidence = self._extract_inline_evidence(normalized_payload)
        normalized_payload = self._preprocess_payload(normalized_payload)
        repo_root = self._resolve_repo_root(normalized_payload, spec_directory)
        resolver = SourcePathResolver(repo_root)

        self._normalize_filesystem_paths(normalized_payload, resolver=resolver, spec_directory=spec_directory)
        initial_report = BugReport.from_dict(normalized_payload)
        runtime_evidence = self._build_runtime_evidence(
            initial_report.runtime_evidence,
            inline_evidence=inline_evidence,
            resolver=resolver,
        )
        trigger_point = self._normalize_trigger(
            initial_report.trigger_point,
            runtime_evidence=runtime_evidence,
            resolver=resolver,
        )

        metadata = dict(initial_report.metadata)
        metadata.setdefault("ingestion", {})
        metadata["ingestion"].update(
            {
                "normalized_from": str(spec_path) if spec_path is not None else "<mapping>",
                "repo_root": resolver.repo_root.as_posix(),
            }
        )

        return initial_report.model_copy(
            update={
                "repo_path": resolver.repo_root.as_posix(),
                "runtime_evidence": runtime_evidence,
                "trigger_point": trigger_point,
                "metadata": metadata,
            }
        )

    def _extract_inline_evidence(self, payload: dict[str, Any]) -> InlineEvidencePayload:
        runtime_payload = payload.get("runtime_evidence")
        if not isinstance(runtime_payload, dict):
            runtime_payload = {}
            payload["runtime_evidence"] = runtime_payload

        inline = InlineEvidencePayload(
            sanitizer_report_text=self._pop_non_empty_string(runtime_payload, "sanitizer_report"),
            stack_trace_text=self._pop_non_empty_string(runtime_payload, "stack_trace"),
            runtime_log_text=self._pop_non_empty_string(runtime_payload, "runtime_log"),
        )

        if inline.sanitizer_report_text is None:
            inline.sanitizer_report_text = self._pop_non_empty_string(payload, "sanitizer_report")
        if inline.stack_trace_text is None:
            inline.stack_trace_text = self._pop_non_empty_string(payload, "stack_trace")

        return inline

    def _preprocess_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        if "config" not in payload and "analysis_config" in payload:
            payload["config"] = payload.pop("analysis_config")

        build_payload = payload.get("build")
        if not isinstance(build_payload, dict):
            build_payload = {}
            if any(key in payload for key in ("build_cmd", "build_dir", "compile_commands_path")):
                payload["build"] = build_payload
        for key in ("build_cmd", "build_dir", "compile_commands_path"):
            if key in payload:
                build_payload[key] = payload.pop(key)

        run_payload = payload.get("run")
        if not isinstance(run_payload, dict):
            run_payload = {}
            if any(key in payload for key in ("run_cmd", "cmd", "poc_path", "env")):
                payload["run"] = run_payload
        if "run_cmd" in payload:
            run_payload["cmd"] = payload.pop("run_cmd")
        if "cmd" in payload and "cmd" not in run_payload:
            run_payload["cmd"] = payload.pop("cmd")
        if "poc_path" in payload and "poc_path" not in run_payload:
            run_payload["poc_path"] = payload.pop("poc_path")
        if "env" in payload and "env" not in run_payload:
            run_payload["env"] = payload.pop("env")

        runtime_payload = payload.get("runtime_evidence")
        if not isinstance(runtime_payload, dict):
            runtime_payload = {}
            payload["runtime_evidence"] = runtime_payload
        for key in (
            "sanitizer_report_path",
            "stack_trace_path",
            "runtime_log_path",
            "core_path",
            "execution_trace_path",
        ):
            if key in payload and key not in runtime_payload:
                runtime_payload[key] = payload.pop(key)

        patch_payload = payload.get("patch_evidence")
        if not isinstance(patch_payload, dict):
            patch_payload = {}
            if any(key in payload for key in ("fix_commit", "diff_path", "issue_text", "issue_text_path")):
                payload["patch_evidence"] = patch_payload
        for key in (
            "fix_commit",
            "diff_path",
            "issue_text",
            "issue_text_path",
            "commit_message",
            "commit_message_path",
            "regression_test_path",
        ):
            if key in payload and key not in patch_payload:
                patch_payload[key] = payload.pop(key)

        trigger_payload = payload.get("trigger_point")
        if isinstance(trigger_payload, dict) and "location" not in trigger_payload:
            location_payload = {}
            for key in ("file", "line", "column", "end_line", "end_column", "function", "snippet", "metadata"):
                if key in trigger_payload:
                    location_payload[key] = trigger_payload.pop(key)
            if location_payload:
                trigger_payload["location"] = location_payload

        return payload

    def _resolve_repo_root(self, payload: Mapping[str, Any], spec_directory: Path) -> Path:
        repo_path = payload.get("repo_path")
        if not isinstance(repo_path, str) or not repo_path.strip():
            raise RCPatchError("bug specification must include a non-empty repo_path")

        path = Path(repo_path).expanduser()
        if not path.is_absolute():
            path = (spec_directory / path).resolve()
        else:
            path = path.resolve()

        if not path.exists():
            raise RCPatchError(f"Repository path does not exist: {path}")
        if not path.is_dir():
            raise RCPatchError(f"Repository path is not a directory: {path}")
        return path

    def _normalize_filesystem_paths(
        self,
        payload: dict[str, Any],
        *,
        resolver: SourcePathResolver,
        spec_directory: Path,
    ) -> None:
        payload["repo_path"] = resolver.repo_root.as_posix()

        build_payload = payload.get("build")
        if isinstance(build_payload, dict):
            for key, require_dir in (("build_dir", True), ("compile_commands_path", False)):
                if isinstance(build_payload.get(key), str):
                    build_payload[key] = resolver.resolve_artifact_path(
                        build_payload[key],
                        base_dir=spec_directory,
                        must_exist=True,
                        require_dir=require_dir,
                    )

        run_payload = payload.get("run")
        if isinstance(run_payload, dict) and isinstance(run_payload.get("poc_path"), str):
            run_payload["poc_path"] = resolver.resolve_artifact_path(
                run_payload["poc_path"],
                base_dir=spec_directory,
                must_exist=True,
            )

        runtime_payload = payload.get("runtime_evidence")
        if isinstance(runtime_payload, dict):
            for key in (
                "sanitizer_report_path",
                "stack_trace_path",
                "runtime_log_path",
                "core_path",
                "execution_trace_path",
                "poc_path",
            ):
                if isinstance(runtime_payload.get(key), str):
                    runtime_payload[key] = resolver.resolve_artifact_path(
                        runtime_payload[key],
                        base_dir=spec_directory,
                        must_exist=True,
                    )

        patch_payload = payload.get("patch_evidence")
        if isinstance(patch_payload, dict):
            for key in ("diff_path", "commit_message_path", "issue_text_path", "regression_test_path"):
                if isinstance(patch_payload.get(key), str):
                    patch_payload[key] = resolver.resolve_artifact_path(
                        patch_payload[key],
                        base_dir=spec_directory,
                        must_exist=True,
                    )
            if isinstance(patch_payload.get("changed_locations"), list):
                patch_payload["changed_locations"] = [
                    self._normalize_location_payload(location_payload, resolver=resolver)
                    for location_payload in patch_payload["changed_locations"]
                    if isinstance(location_payload, Mapping)
                ]

        trigger_payload = payload.get("trigger_point")
        if isinstance(trigger_payload, dict) and isinstance(trigger_payload.get("location"), Mapping):
            trigger_payload["location"] = self._normalize_location_payload(trigger_payload["location"], resolver=resolver)

    def _build_runtime_evidence(
        self,
        runtime_evidence: Optional[RuntimeEvidence],
        *,
        inline_evidence: InlineEvidencePayload,
        resolver: SourcePathResolver,
    ) -> Optional[RuntimeEvidence]:
        if runtime_evidence is None and not any(
            (inline_evidence.sanitizer_report_text, inline_evidence.stack_trace_text, inline_evidence.runtime_log_text)
        ):
            return None

        base_runtime = runtime_evidence or RuntimeEvidence()
        parsed_evidence_refs: list[EvidenceReference] = list(base_runtime.evidence)
        stack_frames = list(base_runtime.stack_frames)
        failure_summary = base_runtime.failure_summary
        failing_access = base_runtime.failing_access
        trigger_frame_index = base_runtime.trigger_frame_index
        metadata = dict(base_runtime.metadata)

        sanitizer_text = inline_evidence.sanitizer_report_text
        if sanitizer_text is None and base_runtime.sanitizer_report_path is not None:
            sanitizer_text = Path(base_runtime.sanitizer_report_path).read_text(encoding="utf-8")
        if sanitizer_text:
            sanitizer_result = self.sanitizer_parser.parse(
                sanitizer_text,
                resolver=resolver,
                evidence_path=base_runtime.sanitizer_report_path,
            )
            stack_frames = self._deduplicate_stack_frames(stack_frames + sanitizer_result.stack_frames)
            parsed_evidence_refs.extend(sanitizer_result.evidence)
            failure_summary = sanitizer_result.failure_summary or failure_summary
            failing_access = sanitizer_result.failing_access or failing_access
            trigger_frame_index = (
                sanitizer_result.trigger_frame_index
                if sanitizer_result.trigger_frame_index is not None
                else trigger_frame_index
            )
            metadata.update(sanitizer_result.metadata)
            if sanitizer_result.bug_type_hint is not None:
                metadata["bug_type_hint"] = sanitizer_result.bug_type_hint.value
            if sanitizer_result.notes:
                metadata["sanitizer_notes"] = sanitizer_result.notes

        stack_trace_text = inline_evidence.stack_trace_text
        if stack_trace_text is None and base_runtime.stack_trace_path is not None:
            stack_trace_text = Path(base_runtime.stack_trace_path).read_text(encoding="utf-8")
        if stack_trace_text:
            stack_result = self.stacktrace_parser.parse(
                stack_trace_text,
                resolver=resolver,
                evidence_path=base_runtime.stack_trace_path,
            )
            stack_frames = self._deduplicate_stack_frames(stack_frames + stack_result.frames)
            parsed_evidence_refs.extend(stack_result.evidence)
            if "stacktrace_notes" not in metadata and stack_result.notes:
                metadata["stacktrace_notes"] = stack_result.notes

        linked_locations = [
            frame.location.to_dict()
            for frame in stack_frames
            if frame.location is not None
        ]
        if linked_locations:
            metadata["linked_source_locations"] = linked_locations

        return base_runtime.model_copy(
            update={
                "stack_frames": stack_frames,
                "evidence": parsed_evidence_refs,
                "failure_summary": failure_summary,
                "failing_access": failing_access,
                "trigger_frame_index": trigger_frame_index,
                "metadata": metadata,
            }
        )

    def _normalize_trigger(
        self,
        trigger_point: TriggerPoint,
        *,
        runtime_evidence: Optional[RuntimeEvidence],
        resolver: SourcePathResolver,
    ) -> TriggerPoint:
        normalized_location = trigger_point.location.model_copy(
            update={
                "file": resolver.normalize_source_path(trigger_point.location.file) or trigger_point.location.file,
            }
        )
        normalized_trigger = trigger_point.model_copy(update={"location": normalized_location})
        return self.trigger_normalizer.normalize(normalized_trigger, runtime_evidence=runtime_evidence)

    def _normalize_location_payload(
        self,
        payload: Mapping[str, Any],
        *,
        resolver: SourcePathResolver,
    ) -> dict[str, Any]:
        normalized = dict(payload)
        file_value = normalized.get("file")
        if isinstance(file_value, str):
            normalized["file"] = resolver.normalize_source_path(file_value) or file_value
        return normalized

    @staticmethod
    def _pop_non_empty_string(payload: Mapping[str, Any], key: str) -> Optional[str]:
        if not isinstance(payload, dict):
            return None
        value = payload.pop(key, None)
        if isinstance(value, str) and value.strip():
            return value
        return None

    @staticmethod
    def _deduplicate_stack_frames(stack_frames: list[Any]) -> list[Any]:
        deduplicated: list[Any] = []
        seen: set[tuple[Any, ...]] = set()
        for frame in stack_frames:
            key = (
                frame.index,
                frame.function,
                frame.location.file if frame.location is not None else None,
                frame.location.line if frame.location is not None else None,
                frame.location.column if frame.location is not None else None,
                frame.module,
                frame.instruction,
            )
            if key in seen:
                continue
            seen.add(key)
            deduplicated.append(frame)
        return deduplicated
