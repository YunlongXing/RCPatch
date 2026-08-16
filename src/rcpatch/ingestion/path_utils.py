"""Filesystem and source-path normalization helpers for RCPatch."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Iterable, Optional, Sequence, Union

from rcpatch.errors import RCPatchError
from rcpatch.logging_utils import get_logger

SOURCE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
}


class SourcePathResolver:
    """Resolve source and artifact paths relative to the target repository."""

    def __init__(self, repo_root: Union[str, Path], *, source_extensions: Optional[Iterable[str]] = None) -> None:
        self.repo_root = Path(repo_root).expanduser().resolve()
        if not self.repo_root.exists():
            raise RCPatchError(f"Repository path does not exist: {self.repo_root}")
        if not self.repo_root.is_dir():
            raise RCPatchError(f"Repository path is not a directory: {self.repo_root}")

        self._source_extensions = {extension.lower() for extension in (source_extensions or SOURCE_EXTENSIONS)}
        self._suffix_index: Optional[dict[tuple[str, ...], list[str]]] = None
        self.logger = get_logger(__name__)

    def resolve_artifact_path(
        self,
        raw_path: Optional[str],
        *,
        base_dir: Optional[Union[str, Path]] = None,
        must_exist: bool = False,
        require_dir: bool = False,
    ) -> Optional[str]:
        """Resolve an arbitrary artifact path to an absolute normalized path."""
        if raw_path is None:
            return None

        base_directory = Path(base_dir).expanduser().resolve() if base_dir is not None else self.repo_root
        candidates = self._artifact_candidates(raw_path, base_directory)
        for candidate in candidates:
            if candidate.exists():
                if require_dir and not candidate.is_dir():
                    raise RCPatchError(f"Expected directory path but found file: {candidate}")
                if not require_dir and candidate.is_dir():
                    raise RCPatchError(f"Expected file path but found directory: {candidate}")
                return candidate.resolve().as_posix()

        fallback = candidates[0].resolve().as_posix()
        if must_exist:
            raise RCPatchError(f"Referenced path does not exist: {raw_path} (resolved candidate: {fallback})")
        return fallback

    def normalize_source_path(
        self,
        raw_path: Optional[str],
        *,
        base_dir: Optional[Union[str, Path]] = None,
    ) -> Optional[str]:
        """Normalize a source path to a repository-relative path when possible."""
        if raw_path is None:
            return None

        base_directory = Path(base_dir).expanduser().resolve() if base_dir is not None else self.repo_root
        for candidate in self._artifact_candidates(raw_path, base_directory):
            normalized = self._to_repo_relative(candidate)
            if normalized is not None:
                return normalized

        suffix_match = self._find_suffix_match(Path(raw_path))
        if suffix_match is not None:
            return suffix_match

        stripped = raw_path.strip()
        if not stripped:
            return None
        return Path(stripped).as_posix()

    def _artifact_candidates(self, raw_path: str, base_dir: Path) -> list[Path]:
        path = Path(raw_path).expanduser()
        candidates: list[Path] = []
        if path.is_absolute():
            candidates.append(path)
        else:
            candidates.append((base_dir / path).resolve())
            if base_dir != self.repo_root:
                candidates.append((self.repo_root / path).resolve())
        return self._unique_paths(candidates)

    def _to_repo_relative(self, candidate: Path) -> Optional[str]:
        try:
            resolved = candidate.resolve()
        except OSError:
            resolved = candidate

        try:
            return resolved.relative_to(self.repo_root).as_posix()
        except ValueError:
            return None

    def _find_suffix_match(self, raw_path: Path) -> Optional[str]:
        path_parts = tuple(part for part in raw_path.parts if part not in ("", ".", ".."))
        if not path_parts:
            return None

        suffix_index = self._get_suffix_index()
        max_width = min(4, len(path_parts))
        for width in range(max_width, 0, -1):
            key = tuple(path_parts[-width:])
            matches = suffix_index.get(key, [])
            if len(matches) == 1:
                return matches[0]
        return None

    def _get_suffix_index(self) -> dict[tuple[str, ...], list[str]]:
        if self._suffix_index is not None:
            return self._suffix_index

        suffix_index: dict[tuple[str, ...], list[str]] = defaultdict(list)
        for file_path in self.repo_root.rglob("*"):
            if not file_path.is_file():
                continue
            if file_path.suffix.lower() not in self._source_extensions:
                continue

            relative_parts = file_path.relative_to(self.repo_root).parts
            for width in range(1, min(4, len(relative_parts)) + 1):
                suffix_index[tuple(relative_parts[-width:])].append(Path(*relative_parts).as_posix())

        self._suffix_index = dict(suffix_index)
        return self._suffix_index

    @staticmethod
    def _unique_paths(paths: Sequence[Path]) -> list[Path]:
        seen: set[str] = set()
        unique: list[Path] = []
        for path in paths:
            key = path.as_posix()
            if key in seen:
                continue
            seen.add(key)
            unique.append(path)
        return unique
