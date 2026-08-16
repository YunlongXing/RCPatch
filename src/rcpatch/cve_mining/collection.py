"""High-level CVE collection and filtering service."""

from __future__ import annotations

import logging
from typing import Any, Iterable, Mapping, Optional

from rcpatch.cve_mining.heuristics import (
    infer_fix_commits,
    infer_language,
    infer_project_name,
    infer_repo_url,
    normalize_reference,
)
from rcpatch.cve_mining.sources import CollectionSource, RawCVERecord, get_source_adapter
from rcpatch.models import AdvisoryReference, AdvisorySourceKind, Language, ReferenceType
from rcpatch.models.cve import CVECollectionResult, CVEAffectedVersion, CVETraceability, CollectedCVERecord, DiscardedCVERecord

logger = logging.getLogger(__name__)


class CVECollectionService:
    """Collect, filter, and normalize CVEs from heterogeneous advisory sources."""

    def __init__(
        self,
        *,
        language_hints: Optional[Mapping[str, str]] = None,
        keep_unknown_language: bool = False,
    ) -> None:
        self.language_hints = dict(language_hints or {})
        self.keep_unknown_language = keep_unknown_language

    def collect(self, sources: Iterable[CollectionSource]) -> CVECollectionResult:
        """Collect and normalize all CVEs from the given source list."""

        records: list[CollectedCVERecord] = []
        discarded: list[DiscardedCVERecord] = []
        source_count = 0
        for source in sources:
            source_count += 1
            adapter = get_source_adapter(source.source_kind)
            payload = adapter.load_payload(source)
            raw_records = adapter.extract_records(payload, source)
            logger.info("Collected %d raw CVE records from %s", len(raw_records), source.source_kind.value)
            for raw_record in raw_records:
                normalized = self._normalize_record(raw_record, source)
                if isinstance(normalized, CollectedCVERecord):
                    records.append(normalized)
                else:
                    discarded.append(normalized)

        return CVECollectionResult(
            records=records,
            discarded=discarded,
            metadata={
                "source_count": source_count,
                "record_count": len(records),
                "discarded_count": len(discarded),
                "kept_languages": sorted({record.language.value for record in records}),
            },
        )

    def _normalize_record(
        self,
        raw_record: RawCVERecord,
        source: CollectionSource,
    ) -> CollectedCVERecord | DiscardedCVERecord:
        references = self._normalize_references(raw_record)
        affected_versions = self._normalize_affected_versions(raw_record)
        repo_url, repo_provider, repo_evidence = infer_repo_url(
            references,
            explicit_repo_url=_optional_string(raw_record.get("repo_url")),
        )
        project = infer_project_name(
            explicit_project=_optional_string(raw_record.get("project")),
            repo_url=repo_url,
            affected_versions=affected_versions,
        )
        language = infer_language(
            explicit_language=_optional_string(raw_record.get("language")),
            repo_url=repo_url,
            project=project,
            references=references,
            language_hints=self.language_hints,
        )
        if language not in {Language.C, Language.CPP, Language.C_CPP} and not self.keep_unknown_language:
            return DiscardedCVERecord(
                cve_id=str(raw_record.get("cve_id", "UNKNOWN")),
                source_kind=source.source_kind,
                reason="language_not_c_cpp",
                project=project,
                repo_url=repo_url,
                description=_optional_string(raw_record.get("description")),
                metadata={
                    "language": language.value,
                    "repo_evidence_urls": repo_evidence,
                },
            )

        fix_commits, fix_commit_evidence = infer_fix_commits(references)
        cwes = [value for value in raw_record.get("cwes", []) if isinstance(value, str)]
        return CollectedCVERecord(
            cve_id=str(raw_record["cve_id"]),
            aliases=[alias for alias in raw_record.get("aliases", []) if isinstance(alias, str)],
            project=project,
            repo_url=repo_url,
            repo_provider=repo_provider,
            description=_optional_string(raw_record.get("description")) or "",
            cwe=cwes[0] if cwes else None,
            cwes=cwes,
            language=language,
            affected_versions=affected_versions,
            references=references,
            fix_commits=fix_commits,
            traceability=CVETraceability(
                source_kind=source.source_kind,
                source_locator=source.locator,
                repo_reference_urls=repo_evidence,
                fix_commit_reference_urls=fix_commit_evidence,
                affected_version_sources=_affected_version_sources(affected_versions),
                notes=self._build_traceability_notes(
                    repo_url=repo_url,
                    language=language,
                    fix_commits=fix_commits,
                    references=references,
                ),
                metadata=dict(source.metadata),
            ),
            metadata=dict(raw_record.get("metadata", {})) if isinstance(raw_record.get("metadata"), Mapping) else {},
        )

    def _normalize_references(self, raw_record: RawCVERecord) -> list[AdvisoryReference]:
        results: list[AdvisoryReference] = []
        for reference in raw_record.get("references", []):
            try:
                if isinstance(reference, AdvisoryReference):
                    results.append(reference)
                elif isinstance(reference, str):
                    results.append(normalize_reference(reference))
                elif isinstance(reference, Mapping) and isinstance(reference.get("url"), str):
                    results.append(
                        normalize_reference(
                            reference["url"],
                            source=_optional_string(reference.get("source")),
                            tags=[tag for tag in reference.get("tags", []) if isinstance(tag, str)],
                            metadata=dict(reference.get("metadata", {})) if isinstance(reference.get("metadata"), Mapping) else {},
                        )
                    )
            except ValueError as exc:
                logger.debug(
                    "Skipping malformed advisory reference for %s: %s (%s)",
                    raw_record.get("cve_id", "UNKNOWN"),
                    reference,
                    exc,
                )
        return results

    def _normalize_affected_versions(self, raw_record: RawCVERecord) -> list[CVEAffectedVersion]:
        results: list[CVEAffectedVersion] = []
        for item in raw_record.get("affected_versions", []):
            if isinstance(item, CVEAffectedVersion):
                results.append(item)
            elif isinstance(item, Mapping):
                results.append(CVEAffectedVersion.from_dict(dict(item)))
        return results

    def _build_traceability_notes(
        self,
        *,
        repo_url: Optional[str],
        language: Language,
        fix_commits: list[str],
        references: list[AdvisoryReference],
    ) -> list[str]:
        notes: list[str] = []
        if repo_url is None:
            notes.append("Repository URL could not be inferred from advisory references.")
        if language == Language.UNKNOWN:
            notes.append("Language remains unknown; record was retained only because keep_unknown_language=True.")
        if not fix_commits:
            if any(reference.reference_type in {ReferenceType.PULL_REQUEST, ReferenceType.COMPARE} for reference in references):
                notes.append("No direct fix commit URL found; PR/compare references were preserved for later resolution.")
            else:
                notes.append("No fix commit could be inferred from advisory references.")
        return notes


def _affected_version_sources(affected_versions: Iterable[CVEAffectedVersion]) -> list[str]:
    sources: list[str] = []
    for item in affected_versions:
        if item.cpe_uri:
            sources.append(item.cpe_uri)
        elif item.vulnerable_version_range:
            sources.append(item.vulnerable_version_range)
    return sources


def _optional_string(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value.strip() else None
