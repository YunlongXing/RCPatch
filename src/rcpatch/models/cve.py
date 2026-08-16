"""Data models for CVE collection and normalization."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import Field, field_validator, model_validator

from rcpatch.models.base import RCPatchModel
from rcpatch.models.enums import AdvisorySourceKind, Language, ReferenceType, RepositoryProvider


class CVEAffectedVersion(RCPatchModel):
    """Affected-version metadata normalized across advisory sources."""

    package: Optional[str] = None
    vendor: Optional[str] = None
    product: Optional[str] = None
    ecosystem: Optional[str] = None
    vulnerable_version_range: Optional[str] = None
    first_patched_version: Optional[str] = None
    version_start_including: Optional[str] = None
    version_start_excluding: Optional[str] = None
    version_end_including: Optional[str] = None
    version_end_excluding: Optional[str] = None
    cpe_uri: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AdvisoryReference(RCPatchModel):
    """A traceable, normalized reference associated with a CVE."""

    url: str
    source: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    reference_type: ReferenceType = ReferenceType.OTHER
    repo_url: Optional[str] = None
    provider: RepositoryProvider = RepositoryProvider.UNKNOWN
    commit_sha: Optional[str] = None
    pull_request: Optional[str] = None
    issue_id: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        """Ensure references always carry absolute URLs from supported schemes."""
        lowered = value.lower()
        if not lowered.startswith(("http://", "https://", "ftp://", "ftps://")):
            raise ValueError("reference url must start with http://, https://, ftp://, or ftps://")
        return value


class CVETraceability(RCPatchModel):
    """Links a normalized record back to the evidence used to construct it."""

    source_kind: AdvisorySourceKind
    source_locator: Optional[str] = None
    repo_reference_urls: list[str] = Field(default_factory=list)
    fix_commit_reference_urls: list[str] = Field(default_factory=list)
    affected_version_sources: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CollectedCVERecord(RCPatchModel):
    """Normalized CVE metadata ready for downstream mining."""

    cve_id: str
    aliases: list[str] = Field(default_factory=list)
    project: str
    repo_url: Optional[str] = None
    repo_provider: RepositoryProvider = RepositoryProvider.UNKNOWN
    description: str
    cwe: Optional[str] = None
    cwes: list[str] = Field(default_factory=list)
    language: Language = Language.UNKNOWN
    affected_versions: list[CVEAffectedVersion] = Field(default_factory=list)
    references: list[AdvisoryReference] = Field(default_factory=list)
    fix_commits: list[str] = Field(default_factory=list)
    traceability: CVETraceability
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("cve_id")
    @classmethod
    def validate_cve_id(cls, value: str) -> str:
        """Reject malformed identifiers early so traceability stays consistent."""
        normalized = value.upper()
        if not normalized.startswith("CVE-"):
            raise ValueError("cve_id must start with CVE-")
        return normalized

    @model_validator(mode="after")
    def ensure_primary_cwe(self) -> "CollectedCVERecord":
        """Populate the primary CWE field from the complete CWE list when omitted."""
        if self.cwe is None and self.cwes:
            self.cwe = self.cwes[0]
        return self


class DiscardedCVERecord(RCPatchModel):
    """Traceable representation of a CVE that was filtered out."""

    cve_id: str
    source_kind: AdvisorySourceKind
    reason: str
    project: Optional[str] = None
    repo_url: Optional[str] = None
    description: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CVECollectionResult(RCPatchModel):
    """Result bundle returned by the CVE collection module."""

    records: list[CollectedCVERecord] = Field(default_factory=list)
    discarded: list[DiscardedCVERecord] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
