"""Run-manifest helpers for reproducible RCPatch experiments."""

from __future__ import annotations

import hashlib
import platform
import sys
from datetime import datetime, timezone
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Any, Mapping, Optional

from pydantic import Field

from rcpatch.models.base import RCPatchModel


class FileFingerprint(RCPatchModel):
    """Stable fingerprint for an input or output file."""

    path: str = Field(min_length=1, description="Absolute or user-facing file path.")
    sha256: Optional[str] = Field(default=None, description="SHA-256 digest when the file could be read.")
    size_bytes: Optional[int] = Field(default=None, ge=0, description="File size in bytes when available.")
    exists: bool = Field(default=True, description="Whether the file existed when the manifest was built.")
    error: Optional[str] = Field(default=None, description="Read or stat error if fingerprinting failed.")


class RunManifest(RCPatchModel):
    """Reproducibility metadata emitted with every RCPatch output bundle."""

    bug_id: str = Field(min_length=1, description="Bug identifier analyzed in this run.")
    command: str = Field(min_length=1, description="RCPatch command or pipeline stage that produced the bundle.")
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when this manifest was generated.",
    )
    bugrc_version: str = Field(
        min_length=1,
        description="Installed RCPatch package version or local marker. Field name is retained for compatibility.",
    )
    python_version: str = Field(min_length=1, description="Python interpreter version.")
    platform: str = Field(min_length=1, description="Operating-system and machine summary.")
    repo_path: str = Field(min_length=1, description="Repository root analyzed by RCPatch.")
    parser_backend: Optional[str] = Field(default=None, description="Source parser backend used for the run.")
    analysis_config: dict[str, Any] = Field(default_factory=dict, description="Effective AnalysisConfig payload.")
    inputs: dict[str, FileFingerprint] = Field(default_factory=dict, description="Fingerprints for important inputs.")
    outputs: dict[str, FileFingerprint] = Field(default_factory=dict, description="Fingerprints for exported artifacts.")
    metrics: dict[str, Any] = Field(default_factory=dict, description="Small run-level counts useful for experiments.")
    notes: list[str] = Field(default_factory=list, description="Explicit caveats for interpreting the run.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Extension space for callers.")


def build_run_manifest(
    *,
    bug_report: Any,
    command: str,
    artifact_paths: Optional[Mapping[str, Path]] = None,
    program: Optional[Any] = None,
    backward_slice: Optional[Any] = None,
    candidates: Optional[list[Any]] = None,
    chains: Optional[list[Any]] = None,
    analysis_result: Optional[Any] = None,
    metadata: Optional[Mapping[str, Any]] = None,
) -> RunManifest:
    """Build a reproducibility manifest from pipeline artifacts.

    The manifest intentionally records weak-supervision inputs such as CVE
    pattern libraries by fingerprint. This makes large RCPatch experiments easier
    to audit when the pattern library evolves over time.
    """

    config = bug_report.analysis_config
    ingestion_meta = {}
    if isinstance(getattr(bug_report, "metadata", None), Mapping):
        maybe_ingestion = bug_report.metadata.get("ingestion")
        if isinstance(maybe_ingestion, Mapping):
            ingestion_meta = dict(maybe_ingestion)

    inputs: dict[str, FileFingerprint] = {}
    spec_path = ingestion_meta.get("normalized_from")
    if isinstance(spec_path, str) and spec_path and spec_path != "<mapping>":
        inputs["bug_spec"] = fingerprint_file(spec_path)

    cve_library_path = getattr(config, "cve_pattern_library_path", None)
    if isinstance(cve_library_path, str) and cve_library_path:
        inputs["cve_pattern_library"] = fingerprint_file(_resolve_input_path(cve_library_path, bug_report.repo_path))

    expert_rca_prior_path = getattr(config, "expert_rca_prior_path", None)
    if isinstance(expert_rca_prior_path, str) and expert_rca_prior_path:
        inputs["expert_rca_prior"] = fingerprint_file(_resolve_input_path(expert_rca_prior_path, bug_report.repo_path))

    patch_evidence = getattr(bug_report, "patch_evidence", None)
    if patch_evidence is not None and getattr(patch_evidence, "diff_path", None):
        inputs["patch_diff"] = fingerprint_file(getattr(patch_evidence, "diff_path"))

    runtime_evidence = getattr(bug_report, "runtime_evidence", None)
    if runtime_evidence is not None:
        for name in ("sanitizer_report_path", "stack_trace_path", "runtime_log_path", "poc_path"):
            value = getattr(runtime_evidence, name, None)
            if isinstance(value, str) and value:
                inputs[name] = fingerprint_file(value)

    outputs = {
        name: fingerprint_file(path)
        for name, path in dict(artifact_paths or {}).items()
        if name != "run_manifest"
    }

    metrics = {
        "program_file_count": len(getattr(program, "files", []) or []),
        "program_function_count": len(getattr(program, "functions", []) or []),
        "slice_node_count": len(getattr(backward_slice, "nodes", []) or []),
        "slice_edge_count": len(getattr(backward_slice, "edges", []) or []),
        "candidate_count": len(candidates or []),
        "chain_count": len(chains or []),
        "has_analysis_result": analysis_result is not None,
        "cve_pattern_prior_enabled": bool(getattr(config, "enable_cve_pattern_prior", False)),
        "expert_rca_prior_enabled": bool(getattr(config, "enable_expert_rca_prior", False)),
        "patch_analysis_enabled": bool(getattr(config, "enable_patch_analysis", False)),
        "llm_enabled": bool(getattr(config, "enable_llm", False)),
    }

    notes: list[str] = []
    if program is not None:
        notes.extend(str(item) for item in getattr(program, "approximations", [])[:5])
    if backward_slice is not None:
        notes.extend(str(item) for item in getattr(backward_slice, "approximations", [])[:5])

    return RunManifest(
        bug_id=bug_report.bug_id,
        command=command,
        bugrc_version=_bugrc_version(),
        python_version=sys.version.split()[0],
        platform=platform.platform(),
        repo_path=bug_report.repo_path,
        parser_backend=getattr(config.parser_backend, "value", str(config.parser_backend)),
        analysis_config=config.to_dict(),
        inputs=inputs,
        outputs=outputs,
        metrics=metrics,
        notes=_dedupe(notes),
        metadata=dict(metadata or {}),
    )


def fingerprint_file(path: str | Path) -> FileFingerprint:
    """Return a SHA-256 fingerprint for a file without failing the caller."""

    file_path = Path(path).expanduser()
    try:
        resolved_path = file_path.resolve()
    except OSError:
        resolved_path = file_path

    if not resolved_path.exists():
        return FileFingerprint(path=resolved_path.as_posix(), exists=False)
    if not resolved_path.is_file():
        return FileFingerprint(
            path=resolved_path.as_posix(),
            exists=True,
            error="path is not a regular file",
        )

    digest = hashlib.sha256()
    size = 0
    try:
        with resolved_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                size += len(chunk)
                digest.update(chunk)
    except OSError as exc:
        return FileFingerprint(
            path=resolved_path.as_posix(),
            exists=True,
            error=str(exc),
        )
    return FileFingerprint(path=resolved_path.as_posix(), sha256=digest.hexdigest(), size_bytes=size)


def _resolve_input_path(path: str, repo_path: str) -> Path:
    candidate = Path(path).expanduser()
    if candidate.is_absolute():
        return candidate
    cwd_candidate = (Path.cwd() / candidate).resolve()
    if cwd_candidate.exists():
        return cwd_candidate
    return Path(repo_path).expanduser().resolve() / candidate


def _bugrc_version() -> str:
    try:
        return importlib_metadata.version("rcpatch")
    except importlib_metadata.PackageNotFoundError:
        try:
            return importlib_metadata.version("bugrc")
        except importlib_metadata.PackageNotFoundError:
            return "0.1.0-local"


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        normalized = item.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)
    return result
