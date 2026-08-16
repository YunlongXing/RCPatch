"""Repository scanning helpers for source parsing."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Optional, Union

from rcpatch.logging_utils import get_logger

DEFAULT_SOURCE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
}

DEFAULT_IGNORED_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    ".cache",
    ".idea",
    ".vscode",
    "build",
    "cmake-build-debug",
    "cmake-build-release",
    "out",
    "dist",
    "node_modules",
    "__pycache__",
}


class RepoFileScanner:
    """Find C and C++ source files under a repository root."""

    def __init__(
        self,
        *,
        source_extensions: Optional[Iterable[str]] = None,
        ignored_directories: Optional[Iterable[str]] = None,
    ) -> None:
        self.source_extensions = {extension.lower() for extension in (source_extensions or DEFAULT_SOURCE_EXTENSIONS)}
        self.ignored_directories = set(ignored_directories or DEFAULT_IGNORED_DIRECTORIES)
        self.logger = get_logger(__name__)

    def scan(self, repo_root: Union[str, Path]) -> list[str]:
        """Return repository-relative source file paths."""
        root = Path(repo_root).expanduser().resolve()
        source_files: list[str] = []

        for file_path in root.rglob("*"):
            if not file_path.is_file():
                continue
            if any(part in self.ignored_directories for part in file_path.relative_to(root).parts[:-1]):
                continue
            if file_path.suffix.lower() not in self.source_extensions:
                continue
            source_files.append(file_path.relative_to(root).as_posix())

        source_files.sort()
        self.logger.debug("Scanned %d source files under %s", len(source_files), root)
        return source_files
