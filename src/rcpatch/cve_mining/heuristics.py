"""Heuristics for normalizing repositories, references, and CVE metadata."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Mapping, Optional
from urllib.parse import urlparse

from rcpatch.models import AdvisoryReference, Language
from rcpatch.models.cve import CVEAffectedVersion
from rcpatch.models.enums import ReferenceType, RepositoryProvider

_SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{7,40}$")
_GITHUB_COMMIT = re.compile(r"^/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{7,40})/?$")
_GITHUB_PULL = re.compile(r"^/([^/]+)/([^/]+)/pull/([0-9]+)(?:/.*)?$")
_GITHUB_ISSUE = re.compile(r"^/([^/]+)/([^/]+)/(issues|discussions)/([0-9]+)(?:/.*)?$")
_GITHUB_COMPARE = re.compile(r"^/([^/]+)/([^/]+)/compare/([^/]+)$")
_GITHUB_RELEASE = re.compile(r"^/([^/]+)/([^/]+)/releases/tag/(.+)$")
_GITHUB_ADVISORY = re.compile(r"^/([^/]+)/([^/]+)/security/advisories/([^/]+)$")
_GITLAB_COMMIT = re.compile(r"^/([^/]+(?:/[^/]+)+)/-/commit/([0-9a-fA-F]{7,40})/?$")
_GITLAB_MERGE_REQUEST = re.compile(r"^/([^/]+(?:/[^/]+)+)/-/merge_requests/([0-9]+)(?:/.*)?$")
_GITLAB_ISSUE = re.compile(r"^/([^/]+(?:/[^/]+)+)/-/issues/([0-9]+)(?:/.*)?$")
_REFERENCE_SCHEME_FIXUPS: tuple[tuple[str, str], ...] = (
    ("ttps://", "https://"),
    ("tps://", "https://"),
    ("tp://", "http://"),
    ("hxxps://", "https://"),
    ("hxxp://", "http://"),
)


@dataclass(frozen=True)
class ParsedReferenceURL:
    """Structured interpretation of a security-advisory reference URL."""

    reference_type: ReferenceType
    provider: RepositoryProvider
    repo_url: Optional[str] = None
    commit_sha: Optional[str] = None
    pull_request: Optional[str] = None
    issue_id: Optional[str] = None


def detect_repository_provider(url: str) -> RepositoryProvider:
    """Return the repository provider inferred from a URL."""

    hostname = urlparse(url).netloc.lower()
    if hostname.endswith("github.com"):
        return RepositoryProvider.GITHUB
    if hostname.endswith("gitlab.com"):
        return RepositoryProvider.GITLAB
    if hostname:
        return RepositoryProvider.OTHER
    return RepositoryProvider.UNKNOWN


def normalize_repo_url(url: str) -> Optional[str]:
    """Normalize a GitHub/GitLab project URL to its repository root."""

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return None
    parts = [part for part in parsed.path.split("/") if part]
    provider = detect_repository_provider(url)
    if provider == RepositoryProvider.GITHUB and len(parts) >= 2:
        return f"{parsed.scheme}://{parsed.netloc}/{parts[0]}/{_strip_git_suffix(parts[1])}"
    if provider == RepositoryProvider.GITLAB and len(parts) >= 2:
        if "-" in parts:
            repo_parts = parts[: parts.index("-")]
        else:
            repo_parts = parts
        if len(repo_parts) >= 2:
            repo_parts[-1] = _strip_git_suffix(repo_parts[-1])
            return f"{parsed.scheme}://{parsed.netloc}/{'/'.join(repo_parts)}"
    if len(parts) >= 2:
        return f"{parsed.scheme}://{parsed.netloc}/{parts[0]}/{_strip_git_suffix(parts[1])}"
    return None


def parse_reference_url(url: str) -> ParsedReferenceURL:
    """Infer reference semantics from common GitHub/GitLab advisory URLs."""

    parsed = urlparse(url)
    path = parsed.path.rstrip("/")
    provider = detect_repository_provider(url)

    if provider == RepositoryProvider.GITHUB:
        commit_match = _GITHUB_COMMIT.match(path)
        if commit_match:
            owner, repo, sha = commit_match.groups()
            return ParsedReferenceURL(
                reference_type=ReferenceType.COMMIT,
                provider=provider,
                repo_url=f"{parsed.scheme}://{parsed.netloc}/{owner}/{repo}",
                commit_sha=sha.lower(),
            )
        pull_match = _GITHUB_PULL.match(path)
        if pull_match:
            owner, repo, pull_request = pull_match.groups()
            return ParsedReferenceURL(
                reference_type=ReferenceType.PULL_REQUEST,
                provider=provider,
                repo_url=f"{parsed.scheme}://{parsed.netloc}/{owner}/{repo}",
                pull_request=pull_request,
            )
        issue_match = _GITHUB_ISSUE.match(path)
        if issue_match:
            owner, repo, _category, issue_id = issue_match.groups()
            return ParsedReferenceURL(
                reference_type=ReferenceType.ISSUE,
                provider=provider,
                repo_url=f"{parsed.scheme}://{parsed.netloc}/{owner}/{repo}",
                issue_id=issue_id,
            )
        compare_match = _GITHUB_COMPARE.match(path)
        if compare_match:
            owner, repo, revision_range = compare_match.groups()
            commit_sha = _extract_compare_rhs_sha(revision_range)
            return ParsedReferenceURL(
                reference_type=ReferenceType.COMPARE,
                provider=provider,
                repo_url=f"{parsed.scheme}://{parsed.netloc}/{owner}/{repo}",
                commit_sha=commit_sha,
            )
        release_match = _GITHUB_RELEASE.match(path)
        if release_match:
            owner, repo, _tag = release_match.groups()
            return ParsedReferenceURL(
                reference_type=ReferenceType.RELEASE,
                provider=provider,
                repo_url=f"{parsed.scheme}://{parsed.netloc}/{owner}/{repo}",
            )
        advisory_match = _GITHUB_ADVISORY.match(path)
        if advisory_match:
            owner, repo, _advisory_id = advisory_match.groups()
            return ParsedReferenceURL(
                reference_type=ReferenceType.ADVISORY,
                provider=provider,
                repo_url=f"{parsed.scheme}://{parsed.netloc}/{owner}/{repo}",
            )

    if provider == RepositoryProvider.GITLAB:
        commit_match = _GITLAB_COMMIT.match(path)
        if commit_match:
            repo_path, sha = commit_match.groups()
            return ParsedReferenceURL(
                reference_type=ReferenceType.COMMIT,
                provider=provider,
                repo_url=f"{parsed.scheme}://{parsed.netloc}/{repo_path}",
                commit_sha=sha.lower(),
            )
        mr_match = _GITLAB_MERGE_REQUEST.match(path)
        if mr_match:
            repo_path, pull_request = mr_match.groups()
            return ParsedReferenceURL(
                reference_type=ReferenceType.PULL_REQUEST,
                provider=provider,
                repo_url=f"{parsed.scheme}://{parsed.netloc}/{repo_path}",
                pull_request=pull_request,
            )
        issue_match = _GITLAB_ISSUE.match(path)
        if issue_match:
            repo_path, issue_id = issue_match.groups()
            return ParsedReferenceURL(
                reference_type=ReferenceType.ISSUE,
                provider=provider,
                repo_url=f"{parsed.scheme}://{parsed.netloc}/{repo_path}",
                issue_id=issue_id,
            )

    repo_url = normalize_repo_url(url)
    reference_type = ReferenceType.REPOSITORY if repo_url is not None else ReferenceType.OTHER
    return ParsedReferenceURL(reference_type=reference_type, provider=provider, repo_url=repo_url)


def normalize_reference(
    url: str,
    *,
    source: Optional[str] = None,
    tags: Optional[Iterable[str]] = None,
    metadata: Optional[Mapping[str, object]] = None,
) -> AdvisoryReference:
    """Build a normalized ``AdvisoryReference`` from a raw URL-like reference."""

    normalized_url = normalize_reference_url(url)
    parsed = parse_reference_url(normalized_url)
    return AdvisoryReference(
        url=normalized_url,
        source=source,
        tags=list(tags or []),
        reference_type=parsed.reference_type,
        repo_url=parsed.repo_url,
        provider=parsed.provider,
        commit_sha=parsed.commit_sha,
        pull_request=parsed.pull_request,
        issue_id=parsed.issue_id,
        metadata=dict(metadata or {}),
    )


def normalize_reference_url(url: str) -> str:
    """Repair common advisory URL typos before reference parsing/validation."""

    candidate = url.strip()
    lowered = candidate.lower()
    for malformed_prefix, fixed_prefix in _REFERENCE_SCHEME_FIXUPS:
        if lowered.startswith(malformed_prefix):
            return fixed_prefix + candidate[len(malformed_prefix) :]
    if lowered.startswith("www."):
        return f"https://{candidate}"
    return candidate


def infer_repo_url(
    references: Iterable[AdvisoryReference],
    *,
    explicit_repo_url: Optional[str] = None,
) -> tuple[Optional[str], RepositoryProvider, list[str]]:
    """Pick the best repository URL for a CVE and record supporting evidence URLs."""

    if explicit_repo_url:
        provider = detect_repository_provider(explicit_repo_url)
        return normalize_repo_url(explicit_repo_url) or explicit_repo_url, provider, [explicit_repo_url]

    repo_votes: dict[str, int] = {}
    repo_evidence: dict[str, list[str]] = {}
    for reference in references:
        if reference.repo_url is None:
            continue
        repo_votes[reference.repo_url] = repo_votes.get(reference.repo_url, 0) + _reference_vote(reference.reference_type)
        repo_evidence.setdefault(reference.repo_url, []).append(reference.url)

    if not repo_votes:
        return None, RepositoryProvider.UNKNOWN, []

    repo_url = max(repo_votes.items(), key=lambda item: (item[1], item[0]))[0]
    return repo_url, detect_repository_provider(repo_url), repo_evidence.get(repo_url, [])


def infer_fix_commits(references: Iterable[AdvisoryReference]) -> tuple[list[str], list[str]]:
    """Return unique commit SHAs and the URLs that supported them."""

    commits: list[str] = []
    evidence_urls: list[str] = []
    seen: set[str] = set()
    for reference in references:
        if not reference.commit_sha:
            continue
        sha = reference.commit_sha.lower()
        if sha in seen:
            continue
        seen.add(sha)
        commits.append(sha)
        evidence_urls.append(reference.url)
    return commits, evidence_urls


def infer_project_name(
    *,
    explicit_project: Optional[str],
    repo_url: Optional[str],
    affected_versions: Iterable[CVEAffectedVersion],
) -> str:
    """Choose a stable project identifier with transparent fallback rules."""

    if explicit_project:
        return explicit_project
    if repo_url:
        parts = [part for part in urlparse(repo_url).path.split("/") if part]
        if parts:
            return parts[-1]
    for item in affected_versions:
        if item.product:
            return item.product
        if item.package:
            return item.package
    return "unknown_project"


def infer_language(
    *,
    explicit_language: Optional[str],
    repo_url: Optional[str],
    project: str,
    references: Iterable[AdvisoryReference],
    language_hints: Mapping[str, str | Language],
) -> Language:
    """Infer whether a record should be treated as C/C++ relevant."""

    if explicit_language:
        return _coerce_language(explicit_language)

    for key in filter(None, [repo_url, project]):
        if key in language_hints:
            return _coerce_language(language_hints[key])

    for reference in references:
        if reference.url in language_hints:
            return _coerce_language(language_hints[reference.url])

    return Language.UNKNOWN


def extract_cpe_version_range(criteria: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Extract vendor, product, and version from a CPE 2.3 URI when present."""

    parts = criteria.split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return None, None, None
    vendor = _normalize_cpe_component(parts[3])
    product = _normalize_cpe_component(parts[4])
    version = _normalize_cpe_component(parts[5])
    return vendor, product, version


def _coerce_language(value: str | Language) -> Language:
    if isinstance(value, Language):
        return value
    normalized = str(value).strip().lower()
    if normalized in {"c", "c89", "c99", "c11"}:
        return Language.C
    if normalized in {"c++", "cpp", "cxx"}:
        return Language.CPP
    if normalized in {"c_cpp", "c/c++", "c-cpp"}:
        return Language.C_CPP
    return Language.UNKNOWN


def _reference_vote(reference_type: ReferenceType) -> int:
    if reference_type == ReferenceType.COMMIT:
        return 4
    if reference_type in {ReferenceType.PULL_REQUEST, ReferenceType.COMPARE, ReferenceType.ADVISORY}:
        return 3
    if reference_type in {ReferenceType.ISSUE, ReferenceType.RELEASE}:
        return 2
    return 1


def _extract_compare_rhs_sha(revision_range: str) -> Optional[str]:
    if "..." not in revision_range:
        return None
    _lhs, rhs = revision_range.split("...", 1)
    rhs = rhs.split("?", 1)[0]
    if _SHA_PATTERN.match(rhs):
        return rhs.lower()
    return None


def _normalize_cpe_component(value: str) -> Optional[str]:
    if value in {"*", "-"}:
        return None
    return value


def _strip_git_suffix(value: str) -> str:
    return value[:-4] if value.endswith(".git") else value
