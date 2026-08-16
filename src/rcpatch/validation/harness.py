"""Unit-testable patch validation harness for RCPatch experiments."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Iterable, Optional

from pydantic import Field

from rcpatch.logging_utils import get_logger
from rcpatch.models.base import RCPatchModel


class ValidationCommand(RCPatchModel):
    """A shell command used during build or reproducer validation."""

    name: str = Field(min_length=1, description="Stable step name such as build or reproduce.")
    command: str = Field(min_length=1, description="Command to execute.")
    cwd: Optional[str] = Field(default=None, description="Optional working directory relative to the validation repo.")
    timeout_seconds: int = Field(default=30, ge=1, description="Per-command timeout.")


class ValidationStepResult(RCPatchModel):
    """Observed result for one validation command."""

    name: str = Field(min_length=1, description="Step name.")
    command: str = Field(min_length=1, description="Executed command.")
    cwd: str = Field(min_length=1, description="Absolute working directory.")
    exit_code: Optional[int] = Field(default=None, description="Process return code, absent on timeout.")
    duration_seconds: float = Field(ge=0.0, description="Wall-clock duration.")
    timed_out: bool = Field(default=False, description="Whether the command timed out.")
    succeeded: bool = Field(default=False, description="Whether the command completed successfully.")
    stdout_tail: str = Field(default="", description="Tail of stdout for diagnostics.")
    stderr_tail: str = Field(default="", description="Tail of stderr for diagnostics.")


class PatchValidationResult(RCPatchModel):
    """Machine-readable result of patch validation."""

    repo_path: str = Field(min_length=1, description="Original repository path.")
    validation_root: str = Field(min_length=1, description="Repository copy or tree where validation ran.")
    patch_path: Optional[str] = Field(default=None, description="Patch file applied for validation.")
    patch_applied: bool = Field(default=False, description="Whether the patch was applied before command execution.")
    passed: bool = Field(default=False, description="Whether every requested step succeeded.")
    steps: list[ValidationStepResult] = Field(default_factory=list, description="Executed validation steps.")
    diagnostics: list[str] = Field(default_factory=list, description="Non-fatal validation diagnostics.")
    metadata: dict[str, object] = Field(default_factory=dict, description="Extension space for experiment runners.")


class PatchValidationHarness:
    """Run build/reproducer commands with timeouts, optionally after applying a patch.

    The harness defaults to validating in a temporary copy so RCPatch experiments
    do not mutate a developer's checkout. Large-scale evaluations can instead
    call ``validate_existing_tree`` when an external runner already manages
    clean worktrees.
    """

    def __init__(self, *, output_tail_chars: int = 4000) -> None:
        self.output_tail_chars = output_tail_chars
        self.logger = get_logger(__name__)

    def validate_existing_tree(
        self,
        repo_path: str | Path,
        *,
        commands: Iterable[ValidationCommand],
    ) -> PatchValidationResult:
        """Run validation commands directly in an existing repository tree."""

        root = Path(repo_path).expanduser().resolve()
        steps = [self._run_command(root, command) for command in commands]
        return PatchValidationResult(
            repo_path=root.as_posix(),
            validation_root=root.as_posix(),
            passed=all(step.succeeded for step in steps),
            steps=steps,
            metadata={"mode": "existing_tree"},
        )

    def validate_patch_in_copy(
        self,
        repo_path: str | Path,
        patch_path: str | Path,
        *,
        commands: Iterable[ValidationCommand],
        keep_worktree: bool = False,
    ) -> PatchValidationResult:
        """Apply a patch in a temporary copy and run validation commands."""

        source_root = Path(repo_path).expanduser().resolve()
        patch_file = Path(patch_path).expanduser().resolve()
        temp_root = Path(tempfile.mkdtemp(prefix="bugrc-patch-validation-"))
        validation_root = temp_root / source_root.name
        diagnostics: list[str] = []
        steps: list[ValidationStepResult] = []
        patch_applied = False

        try:
            shutil.copytree(source_root, validation_root, ignore=_copy_ignore)
            check_step = self._run_command(
                validation_root,
                ValidationCommand(
                    name="patch_check",
                    command=f"git apply --check {shlex_quote(patch_file.as_posix())}",
                ),
            )
            steps.append(check_step)
            if not check_step.succeeded:
                diagnostics.append("patch did not apply cleanly")
                return PatchValidationResult(
                    repo_path=source_root.as_posix(),
                    validation_root=validation_root.as_posix(),
                    patch_path=patch_file.as_posix(),
                    patch_applied=False,
                    passed=False,
                    steps=steps,
                    diagnostics=diagnostics,
                    metadata={"mode": "temporary_copy", "kept_worktree": keep_worktree},
                )

            apply_step = self._run_command(
                validation_root,
                ValidationCommand(
                    name="patch_apply",
                    command=f"git apply {shlex_quote(patch_file.as_posix())}",
                ),
            )
            steps.append(apply_step)
            patch_applied = apply_step.succeeded
            if not apply_step.succeeded:
                diagnostics.append("patch check succeeded but patch application failed")
            else:
                for command in commands:
                    step = self._run_command(validation_root, command)
                    steps.append(step)
                    if not step.succeeded:
                        diagnostics.append(f"validation step failed: {command.name}")
                        break

            return PatchValidationResult(
                repo_path=source_root.as_posix(),
                validation_root=validation_root.as_posix(),
                patch_path=patch_file.as_posix(),
                patch_applied=patch_applied,
                passed=patch_applied and all(step.succeeded for step in steps),
                steps=steps,
                diagnostics=diagnostics,
                metadata={"mode": "temporary_copy", "kept_worktree": keep_worktree},
            )
        finally:
            if not keep_worktree:
                shutil.rmtree(temp_root, ignore_errors=True)

    def _run_command(self, repo_root: Path, command: ValidationCommand) -> ValidationStepResult:
        cwd = (repo_root / command.cwd).resolve() if command.cwd else repo_root
        start = time.monotonic()
        self.logger.info("Running validation step %s in %s", command.name, cwd)
        try:
            completed = subprocess.run(
                command.command,
                cwd=cwd,
                shell=True,
                text=True,
                capture_output=True,
                timeout=command.timeout_seconds,
                check=False,
            )
            duration = time.monotonic() - start
            return ValidationStepResult(
                name=command.name,
                command=command.command,
                cwd=cwd.as_posix(),
                exit_code=completed.returncode,
                duration_seconds=round(duration, 3),
                timed_out=False,
                succeeded=completed.returncode == 0,
                stdout_tail=_tail(completed.stdout, self.output_tail_chars),
                stderr_tail=_tail(completed.stderr, self.output_tail_chars),
            )
        except subprocess.TimeoutExpired as exc:
            duration = time.monotonic() - start
            stdout = exc.stdout if isinstance(exc.stdout, str) else ""
            stderr = exc.stderr if isinstance(exc.stderr, str) else ""
            return ValidationStepResult(
                name=command.name,
                command=command.command,
                cwd=cwd.as_posix(),
                duration_seconds=round(duration, 3),
                timed_out=True,
                succeeded=False,
                stdout_tail=_tail(stdout, self.output_tail_chars),
                stderr_tail=_tail(stderr, self.output_tail_chars),
            )


def _copy_ignore(directory: str, names: list[str]) -> set[str]:
    ignored = {".git", ".cache", ".pytest_cache", "__pycache__"}
    return {name for name in names if name in ignored}


def _tail(value: str, max_chars: int) -> str:
    if len(value) <= max_chars:
        return value
    return value[-max_chars:]


def shlex_quote(value: str) -> str:
    """Small local quote helper to avoid command injection in patch paths."""

    return "'" + value.replace("'", "'\"'\"'") + "'"
