"""Patch resolution and structured extraction for CVE records."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Iterable, Optional

from rcpatch.cve_mining.collection import CVECollectionService
from rcpatch.cve_mining.sources import CollectionSource
from rcpatch.logging_utils import get_logger
from rcpatch.models.cve import CollectedCVERecord
from rcpatch.models.cve_patch import (
    CVEPatchExtraction,
    FixCommitCandidate,
    StructuredPatchFile,
    StructuredPatchHunk,
)
from rcpatch.models.enums import CVEPatchType, PatchIntent, ReferenceType
from rcpatch.patch_analysis import PatchIntentClassifier, UnifiedDiffParser
from rcpatch.patch_analysis.models import ParsedPatch, PatchHunk

_FUNCTION_HEADER_RE = re.compile(r"([A-Za-z_~][A-Za-z0-9_:~]*)\s*\(")
_TOKEN_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_BOUNDS_TOKENS = ("bound", "bounds", "length", "size", "offset", "capacity", "index", "overflow", "oob")
_CHECK_TOKENS = ("if", "assert", "validate", "check", "guard", "null", "nullptr", "return")
_REFACTOR_TOKENS = ("refactor", "rename", "restructure", "cleanup", "style", "format")
_MEMORY_TOKENS = ("memcpy", "memmove", "memset", "malloc", "calloc", "realloc", "free", "delete", "new")
_KEYWORD_TOKENS = ("overflow", "underflow", "bounds", "length", "size", "oob", "uaf", "null", "check")
_CONTROL_KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "catch"}


class CVEPatchExtractor:
    """Resolve fix commits and extract structured patches for CVEs.

    This module keeps patch extraction separate from root-cause identification:
    patches are supervision evidence, not direct root-cause labels.
    """

    def __init__(
        self,
        *,
        diff_parser: Optional[UnifiedDiffParser] = None,
        intent_classifier: Optional[PatchIntentClassifier] = None,
    ) -> None:
        self.diff_parser = diff_parser or UnifiedDiffParser()
        self.intent_classifier = intent_classifier or PatchIntentClassifier()
        self.logger = get_logger(__name__)
        self._commit_availability_cache: dict[tuple[str, str], bool] = {}

    def extract_for_record(
        self,
        record: CollectedCVERecord,
        *,
        repo_path: Optional[str] = None,
        max_candidates: int = 5,
    ) -> CVEPatchExtraction:
        """Resolve a CVE's fix commit and return a structured patch view."""

        repo_root = Path(repo_path).expanduser().resolve() if repo_path else None
        diagnostics: list[str] = []
        candidates = self._resolve_fix_commit_candidates(record, repo_root=repo_root, max_candidates=max_candidates)
        resolved = candidates[0] if candidates else None

        if resolved is None:
            diagnostics.append("No fix commit candidate could be resolved for this CVE record.")
            return CVEPatchExtraction(
                cve_id=record.cve_id,
                repo_url=record.repo_url,
                repo_path=repo_root.as_posix() if repo_root else None,
                fix_commit_candidates=candidates,
                diagnostics=diagnostics,
                metadata={"traceability": record.traceability.to_dict()},
            )

        commit_message = None
        parsed_patch = None
        if repo_root is not None:
            commit_message = self._git_show_commit_message(repo_root, resolved.commit_sha)
            parsed_patch = self._git_show_patch(repo_root, resolved.commit_sha)
        else:
            diff_text = self._diff_text_from_references(record, resolved.commit_sha)
            if diff_text:
                parsed_patch = self.diff_parser.parse_text(diff_text)
            else:
                diagnostics.append("No local repository was provided, so only reference-derived commit metadata is available.")

        if parsed_patch is None:
            return CVEPatchExtraction(
                cve_id=record.cve_id,
                repo_url=record.repo_url,
                repo_path=repo_root.as_posix() if repo_root else None,
                resolved_fix_commit=resolved,
                fix_commit_candidates=candidates,
                commit_message=commit_message,
                diagnostics=diagnostics,
                metadata={"traceability": record.traceability.to_dict()},
            )

        patch_intent, _intent_scores = self.intent_classifier.classify(
            parsed_patch,
            commit_message=commit_message,
            issue_text=record.description,
        )
        patch_type = self._classify_patch_type(
            parsed_patch,
            commit_message=commit_message,
            record=record,
            patch_intent=patch_intent,
        )
        structured_files = self._build_structured_files(parsed_patch)

        diagnostics.extend(parsed_patch.diagnostics)
        if not structured_files:
            diagnostics.append("Patch diff was resolved, but no modified files were extracted.")

        return CVEPatchExtraction(
            cve_id=record.cve_id,
            repo_url=record.repo_url,
            repo_path=repo_root.as_posix() if repo_root else None,
            resolved_fix_commit=resolved,
            fix_commit_candidates=candidates,
            patch_type=patch_type,
            patch_intent=patch_intent if patch_intent != PatchIntent.UNKNOWN else None,
            modified_files=[item.file for item in structured_files],
            patches=structured_files,
            commit_message=commit_message,
            diagnostics=diagnostics,
            metadata={
                "traceability": record.traceability.to_dict(),
                "reference_count": len(record.references),
            },
        )

    def extract_from_sources(
        self,
        sources: Iterable[CollectionSource],
        *,
        repo_paths: Optional[dict[str, str]] = None,
        language_hints: Optional[dict[str, str]] = None,
        max_candidates: int = 5,
    ) -> list[CVEPatchExtraction]:
        """Collect CVEs from sources and extract patches for all retained records."""

        collector = CVECollectionService(language_hints=language_hints or {})
        collection_result = collector.collect(sources)
        repo_path_map = dict(repo_paths or {})
        return [
            self.extract_for_record(
                record,
                repo_path=repo_path_map.get(record.repo_url or "") or repo_path_map.get(record.project),
                max_candidates=max_candidates,
            )
            for record in collection_result.records
        ]

    def _resolve_fix_commit_candidates(
        self,
        record: CollectedCVERecord,
        *,
        repo_root: Optional[Path],
        max_candidates: int,
    ) -> list[FixCommitCandidate]:
        candidates: dict[str, FixCommitCandidate] = {}

        for reference in record.references:
            if reference.commit_sha:
                summary = self._git_show_subject(repo_root, reference.commit_sha) if repo_root is not None else None
                self._upsert_candidate(
                    candidates,
                    commit_sha=reference.commit_sha,
                    commit_url=reference.url,
                    summary=summary,
                    score=1.0 if reference.reference_type == ReferenceType.COMMIT else 0.8,
                    matched_by=["reference_commit"],
                    evidence_urls=[reference.url],
                )

        for commit_sha in record.fix_commits:
            summary = self._git_show_subject(repo_root, commit_sha) if repo_root is not None else None
            self._upsert_candidate(
                candidates,
                commit_sha=commit_sha,
                commit_url=self._commit_url_from_repo(record.repo_url, commit_sha),
                summary=summary,
                score=0.95,
                matched_by=["normalized_fix_commit"],
                evidence_urls=[],
            )

        if (not candidates) and repo_root is not None and self._git_available(repo_root):
            for commit_sha, summary, reason, score in self._search_git_history(record, repo_root):
                self._upsert_candidate(
                    candidates,
                    commit_sha=commit_sha,
                    commit_url=self._commit_url_from_repo(record.repo_url, commit_sha),
                    summary=summary,
                    score=score,
                    matched_by=[reason],
                    evidence_urls=[],
                )

        ranked = sorted(
            candidates.values(),
            key=lambda candidate: (candidate.score, candidate.commit_sha),
            reverse=True,
        )
        return ranked[:max_candidates]

    def _search_git_history(
        self,
        record: CollectedCVERecord,
        repo_root: Path,
    ) -> list[tuple[str, str, str, float]]:
        results: list[tuple[str, str, str, float]] = []
        seen: set[str] = set()

        search_terms = [(record.cve_id, "cve_id_search", 0.9)]
        search_terms.extend((alias, "alias_search", 0.75) for alias in record.aliases)

        for reference in record.references:
            if reference.issue_id:
                if reference.provider.value == "github":
                    search_terms.append((f"#{reference.issue_id}", "issue_reference_search", 0.65))
                else:
                    search_terms.append((reference.issue_id, "issue_reference_search", 0.55))
            if reference.pull_request:
                prefix = "#" if reference.provider.value == "github" else "!"
                search_terms.append((f"{prefix}{reference.pull_request}", "pull_request_search", 0.6))

        for keyword in self._description_keywords(record.description):
            search_terms.append((keyword, "keyword_search", 0.25))

        for term, reason, score in search_terms:
            if not term:
                continue
            for commit_sha, summary in self._git_log_grep(repo_root, term):
                if commit_sha in seen:
                    continue
                seen.add(commit_sha)
                results.append((commit_sha, summary, reason, score))

        return results

    def _build_structured_files(self, parsed_patch: ParsedPatch) -> list[StructuredPatchFile]:
        structured_files: list[StructuredPatchFile] = []
        for patched_file in parsed_patch.files:
            hunks = [
                self._build_structured_hunk(hunk_index=index, hunk=hunk)
                for index, hunk in enumerate(patched_file.hunks)
            ]
            changed_functions = sorted({hunk.function for hunk in hunks if hunk.function})
            structured_files.append(
                StructuredPatchFile(
                    file=patched_file.path,
                    old_path=patched_file.old_path or None,
                    new_path=patched_file.new_path or None,
                    changed_functions=changed_functions,
                    before="\n\n".join(filter(None, [hunk.before for hunk in hunks])),
                    after="\n\n".join(filter(None, [hunk.after for hunk in hunks])),
                    hunks=hunks,
                    metadata={"hunk_count": len(hunks)},
                )
            )
        return structured_files

    def _build_structured_hunk(self, *, hunk_index: int, hunk: PatchHunk) -> StructuredPatchHunk:
        function_name = self._function_name_from_hunk_header(hunk.header)
        before_lines: list[str] = []
        after_lines: list[str] = []
        added_statements: list[str] = []
        removed_statements: list[str] = []

        for line in hunk.lines:
            if line.kind in {"context", "del"}:
                before_lines.append(line.text)
            if line.kind in {"context", "add"}:
                after_lines.append(line.text)
            if line.kind == "add" and self._looks_like_statement(line.text):
                added_statements.append(line.text.strip())
            if line.kind == "del" and self._looks_like_statement(line.text):
                removed_statements.append(line.text.strip())

        if function_name is None:
            function_name = self._function_name_from_snippet(after_lines) or self._function_name_from_snippet(before_lines)

        return StructuredPatchHunk(
            hunk_index=hunk_index,
            old_start=hunk.old_start,
            old_count=hunk.old_count,
            new_start=hunk.new_start,
            new_count=hunk.new_count,
            header=hunk.header.strip(),
            function=function_name,
            before="\n".join(before_lines).strip(),
            after="\n".join(after_lines).strip(),
            added_statements=added_statements,
            removed_statements=removed_statements,
        )

    def _classify_patch_type(
        self,
        parsed_patch: ParsedPatch,
        *,
        commit_message: Optional[str],
        record: CollectedCVERecord,
        patch_intent: PatchIntent,
    ) -> CVEPatchType:
        message = (commit_message or "").lower()
        description = record.description.lower()
        added_lines = [line.text.strip() for file in parsed_patch.files for hunk in file.hunks for line in hunk.lines if line.kind == "add"]
        removed_lines = [line.text.strip() for file in parsed_patch.files for hunk in file.hunks for line in hunk.lines if line.kind == "del"]
        all_changed = added_lines + removed_lines
        has_added_check = any(re.search(r"\bif\s*\(", line) for line in added_lines)
        has_bounds_context = any(any(token in line.lower() for token in _BOUNDS_TOKENS) for line in all_changed) or any(
            token in message for token in _BOUNDS_TOKENS
        )
        description_has_bounds = any(token in description for token in _BOUNDS_TOKENS)

        if any(token in message for token in _REFACTOR_TOKENS):
            if any(token in message for token in ("refactor", "rename", "restructure")):
                return CVEPatchType.REFACTOR
            return CVEPatchType.CLEANUP

        bounds_score = 0
        added_check_score = 0
        direct_fix_score = 0

        if has_bounds_context:
            bounds_score += 2
        if any(any(token in line.lower() for token in _MEMORY_TOKENS) for line in all_changed):
            bounds_score += 1
            direct_fix_score += 1
        if has_added_check:
            added_check_score += 2
        if any(any(token in line.lower() for token in _CHECK_TOKENS) for line in added_lines):
            added_check_score += 1
        if any(
            re.search(r"(?<![=!<>])=(?!=)", line) or any(op in line for op in ("+", "-", "*", "/", "%", "<<", ">>"))
            for line in all_changed
        ):
            direct_fix_score += 2
        if any(token in message for token in ("fix", "overflow", "underflow", "invalid")):
            direct_fix_score += 1
        if description_has_bounds and any(any(token in line.lower() for token in _MEMORY_TOKENS) for line in all_changed):
            bounds_score += 1

        if patch_intent in {PatchIntent.DEFENSIVE_GUARD, PatchIntent.COMPENSATING_CHECK}:
            added_check_score += 2
        elif patch_intent == PatchIntent.DIRECT_FIX:
            direct_fix_score += 1

        if has_added_check and has_bounds_context:
            return CVEPatchType.BOUNDS_FIX
        if has_added_check:
            return CVEPatchType.ADDED_CHECK
        if bounds_score >= max(added_check_score, direct_fix_score) and bounds_score >= 2:
            return CVEPatchType.BOUNDS_FIX
        if added_check_score >= max(bounds_score, direct_fix_score) and added_check_score >= 2:
            return CVEPatchType.ADDED_CHECK
        if direct_fix_score >= 2:
            return CVEPatchType.DIRECT_FIX
        if patch_intent == PatchIntent.CLEANUP:
            return CVEPatchType.CLEANUP
        if patch_intent == PatchIntent.REFACTOR:
            return CVEPatchType.REFACTOR
        return CVEPatchType.UNKNOWN

    def _git_show_patch(self, repo_root: Path, commit_sha: str) -> Optional[ParsedPatch]:
        if not self._ensure_commit_available(repo_root, commit_sha):
            return None
        raw_diff = self._run_git(
            repo_root,
            ["show", "--format=medium", "--no-ext-diff", "--unified=3", commit_sha],
            allow_failure=True,
        )
        if raw_diff is None or "diff --git " not in raw_diff:
            return None
        return self.diff_parser.parse_text(raw_diff)

    def _git_show_commit_message(self, repo_root: Path, commit_sha: str) -> Optional[str]:
        if not self._ensure_commit_available(repo_root, commit_sha):
            return None
        message = self._run_git(repo_root, ["log", "-1", "--format=%B", commit_sha], allow_failure=True)
        if message is None:
            return None
        normalized = message.strip()
        return normalized or None

    def _git_show_subject(self, repo_root: Optional[Path], commit_sha: str) -> Optional[str]:
        if repo_root is None:
            return None
        if not self._ensure_commit_available(repo_root, commit_sha):
            return None
        return self._run_git(repo_root, ["log", "-1", "--format=%s", commit_sha], allow_failure=True)

    def _git_log_grep(self, repo_root: Path, term: str) -> list[tuple[str, str]]:
        raw = self._run_git(
            repo_root,
            ["log", "--all", "--regexp-ignore-case", f"--grep={term}", "--format=%H%x00%s"],
            allow_failure=True,
        )
        if not raw:
            return []
        results: list[tuple[str, str]] = []
        for line in raw.splitlines():
            if "\x00" not in line:
                continue
            commit_sha, summary = line.split("\x00", 1)
            results.append((commit_sha.strip(), summary.strip()))
        return results

    @staticmethod
    def _git_available(repo_root: Path) -> bool:
        return shutil.which("git") is not None and (repo_root / ".git").exists()

    def _ensure_commit_available(self, repo_root: Path, commit_sha: str) -> bool:
        key = (repo_root.as_posix(), commit_sha)
        cached = self._commit_availability_cache.get(key)
        if cached is not None:
            return cached

        if self._has_commit(repo_root, commit_sha):
            self._commit_availability_cache[key] = True
            return True

        fetch_attempts = [
            ["fetch", "--progress", "origin", commit_sha],
            ["fetch", "--progress", "--all", "--tags", "--prune", "--deepen=1000"],
            ["fetch", "--progress", "--all", "--tags", "--prune", "--unshallow"],
        ]
        for args in fetch_attempts:
            self._run_git(repo_root, args, allow_failure=True, log_failure=False)
            if self._has_commit(repo_root, commit_sha):
                self._commit_availability_cache[key] = True
                return True

        self._commit_availability_cache[key] = False
        self.logger.warning("Commit %s is unavailable in %s after fallback fetch attempts", commit_sha, repo_root)
        return False

    def _has_commit(self, repo_root: Path, commit_sha: str) -> bool:
        return self._run_git(
            repo_root,
            ["rev-parse", "--verify", f"{commit_sha}^{{commit}}"],
            allow_failure=True,
            log_failure=False,
        ) is not None

    def _run_git(
        self,
        repo_root: Path,
        args: list[str],
        *,
        allow_failure: bool,
        log_failure: bool = True,
        timeout_seconds: int = 30,
    ) -> Optional[str]:
        if shutil.which("git") is None:
            return None
        try:
            completed = subprocess.run(
                ["git", *args],
                cwd=repo_root,
                capture_output=True,
                text=False,
                check=False,
                timeout=timeout_seconds if timeout_seconds > 0 else None,
            )
        except subprocess.TimeoutExpired:
            if log_failure:
                self.logger.warning(
                    "git %s timed out in %s after %ss",
                    " ".join(args),
                    repo_root,
                    timeout_seconds,
                )
            if allow_failure:
                return None
            raise RuntimeError(f"git {' '.join(args)} timed out after {timeout_seconds}s")
        stdout = completed.stdout.decode("utf-8", errors="replace").strip()
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        if completed.returncode != 0:
            if log_failure:
                self.logger.warning("git %s failed in %s: %s", " ".join(args), repo_root, stderr)
            if allow_failure:
                return None
            raise RuntimeError(f"git {' '.join(args)} failed: {stderr}")
        return stdout

    @staticmethod
    def _description_keywords(description: str) -> list[str]:
        seen: set[str] = set()
        results: list[str] = []
        for token in _TOKEN_RE.findall(description.lower()):
            if token in _KEYWORD_TOKENS and token not in seen:
                seen.add(token)
                results.append(token)
        return results

    @staticmethod
    def _commit_url_from_repo(repo_url: Optional[str], commit_sha: str) -> Optional[str]:
        if not repo_url:
            return None
        if "gitlab.com" in repo_url:
            return f"{repo_url.rstrip('/')}/-/commit/{commit_sha}"
        if "github.com" in repo_url:
            return f"{repo_url.rstrip('/')}/commit/{commit_sha}"
        return None

    @staticmethod
    def _diff_text_from_references(record: CollectedCVERecord, commit_sha: str) -> Optional[str]:
        for reference in record.references:
            if reference.commit_sha == commit_sha and isinstance(reference.metadata.get("diff_text"), str):
                return str(reference.metadata["diff_text"])
        return None

    @staticmethod
    def _function_name_from_hunk_header(header: str) -> Optional[str]:
        if not header:
            return None
        matches = _FUNCTION_HEADER_RE.findall(header)
        if matches:
            candidate = matches[-1].split("::")[-1]
            if candidate not in _CONTROL_KEYWORDS:
                return candidate
        tokens = _TOKEN_RE.findall(header)
        if not tokens:
            return None
        candidate = tokens[-1]
        return candidate if candidate not in _CONTROL_KEYWORDS else None

    @staticmethod
    def _function_name_from_snippet(lines: Iterable[str]) -> Optional[str]:
        for line in lines:
            stripped = line.strip()
            if "(" not in stripped or stripped.startswith(tuple(sorted(_CONTROL_KEYWORDS))):
                continue
            matches = _FUNCTION_HEADER_RE.findall(stripped)
            if not matches:
                continue
            candidate = matches[-1].split("::")[-1]
            if candidate not in _CONTROL_KEYWORDS:
                return candidate
        return None

    @staticmethod
    def _looks_like_statement(text: str) -> bool:
        stripped = text.strip()
        return bool(stripped and stripped not in {"{", "}"} and not stripped.startswith("//"))

    @staticmethod
    def _upsert_candidate(
        candidates: dict[str, FixCommitCandidate],
        *,
        commit_sha: str,
        commit_url: Optional[str],
        summary: Optional[str],
        score: float,
        matched_by: list[str],
        evidence_urls: list[str],
    ) -> None:
        existing = candidates.get(commit_sha)
        if existing is None:
            candidates[commit_sha] = FixCommitCandidate(
                commit_sha=commit_sha,
                commit_url=commit_url,
                summary=summary,
                score=score,
                matched_by=matched_by,
                evidence_urls=evidence_urls,
            )
            return
        candidates[commit_sha] = existing.model_copy(
            update={
                "commit_url": existing.commit_url or commit_url,
                "summary": existing.summary or summary,
                "score": max(existing.score, score),
                "matched_by": sorted({*existing.matched_by, *matched_by}),
                "evidence_urls": sorted({*existing.evidence_urls, *evidence_urls}),
            }
        )
