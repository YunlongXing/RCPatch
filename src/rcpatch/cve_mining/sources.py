"""Source adapters for CVE collection inputs."""

from __future__ import annotations

import gzip
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional
from urllib import error as urllib_error
from urllib import request as urllib_request

from rcpatch.errors import ModelSerializationError
from rcpatch.models.cve import CVEAffectedVersion
from rcpatch.models.enums import AdvisorySourceKind


@dataclass(frozen=True)
class CollectionSource:
    """A CVE collection input backed by an in-memory payload or external locator."""

    source_kind: AdvisorySourceKind
    locator: Optional[str] = None
    payload: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)


class RawCVERecord(dict[str, Any]):
    """Thin wrapper used internally before final normalization."""


class CVESourceAdapter:
    """Protocol-like base class for advisory source adapters."""

    source_kind: AdvisorySourceKind

    def load_payload(self, source: CollectionSource) -> Any:
        """Load the source payload from disk, the network, or memory."""

        if source.payload is not None:
            return source.payload
        if source.locator is None:
            raise ModelSerializationError(f"{self.source_kind.value} source requires a payload or locator")
        if source.locator.startswith("http://") or source.locator.startswith("https://"):
            return _load_json_from_url(source.locator)
        return _load_json_from_path(Path(source.locator))

    def extract_records(self, payload: Any, source: CollectionSource) -> list[RawCVERecord]:
        """Convert a source payload into raw normalized records."""

        raise NotImplementedError


class CVEListV5Adapter(CVESourceAdapter):
    """Adapter for the official CVEProject cvelistV5 repository or exported CVE JSON 5 files."""

    source_kind = AdvisorySourceKind.CVE_LIST_V5

    def load_payload(self, source: CollectionSource) -> Any:
        if source.payload is not None:
            return source.payload
        if source.locator is None:
            raise ModelSerializationError("cve_list_v5 source requires a payload or locator")
        locator = Path(source.locator)
        if locator.is_dir():
            root = locator / "cves" if (locator / "cves").is_dir() else locator
            return sorted(path for path in root.rglob("*.json") if _is_cvelist_record_path(path))
        return _load_json_from_path(locator)

    def extract_records(self, payload: Any, source: CollectionSource) -> list[RawCVERecord]:
        raw_items: list[tuple[Mapping[str, Any], Optional[str]]] = []
        if isinstance(payload, Mapping):
            raw_items = [(payload, source.locator)]
        elif isinstance(payload, list):
            for item in payload:
                if isinstance(item, Path):
                    raw_items.append((_load_json_from_path(item), item.as_posix()))
                elif isinstance(item, str):
                    item_path = Path(item)
                    raw_items.append((_load_json_from_path(item_path), item_path.as_posix()))
                elif isinstance(item, Mapping):
                    raw_items.append((item, source.locator))
        else:
            raise ModelSerializationError("cve_list_v5 payload must be a JSON object, a list of objects, or a directory of JSON files")

        records: list[RawCVERecord] = []
        for item, item_locator in raw_items:
            cve_id = _extract_cvelist_cve_id(item)
            containers = _extract_cvelist_containers(item)
            descriptions = _extract_cvelist_descriptions(containers)
            cwes = _extract_cvelist_cwes(containers)
            references = _extract_cvelist_references(containers)
            affected_versions = _extract_cvelist_affected_versions(containers)
            vendor = next((entry.get("vendor") for entry in affected_versions if isinstance(entry, Mapping) and entry.get("vendor")), None)
            product = next((entry.get("product") for entry in affected_versions if isinstance(entry, Mapping) and entry.get("product")), None)
            cve_metadata = item.get("cveMetadata") if isinstance(item.get("cveMetadata"), Mapping) else {}
            records.append(
                RawCVERecord(
                    cve_id=cve_id,
                    aliases=[],
                    description=descriptions.get("en") or next(iter(descriptions.values()), ""),
                    cwes=cwes,
                    references=references,
                    affected_versions=affected_versions,
                    project=product,
                    vendor=vendor,
                    repo_url=None,
                    language=source.metadata.get("language"),
                    metadata={
                        "source_schema": "cve_list_v5",
                        "data_version": item.get("dataVersion"),
                        "cve_state": cve_metadata.get("state"),
                        "assigner_short_name": cve_metadata.get("assignerShortName"),
                        "date_published": cve_metadata.get("datePublished"),
                        "date_updated": cve_metadata.get("dateUpdated"),
                        "source_locator": item_locator,
                    },
                )
            )
        return records


class NVDJSONFeedAdapter(CVESourceAdapter):
    """Adapter for NVD JSON feed exports and API-like payloads."""

    source_kind = AdvisorySourceKind.NVD_JSON_FEED

    def extract_records(self, payload: Any, source: CollectionSource) -> list[RawCVERecord]:
        if not isinstance(payload, Mapping):
            raise ModelSerializationError("NVD payload must be a JSON object")

        raw_items: Iterable[Any]
        if "vulnerabilities" in payload and isinstance(payload["vulnerabilities"], list):
            raw_items = payload["vulnerabilities"]
        elif "CVE_Items" in payload and isinstance(payload["CVE_Items"], list):
            raw_items = payload["CVE_Items"]
        else:
            raise ModelSerializationError("Unsupported NVD payload shape")

        records: list[RawCVERecord] = []
        for item in raw_items:
            cve = item.get("cve") if isinstance(item, Mapping) else None
            if not isinstance(cve, Mapping) and isinstance(item, Mapping):
                cve = item
            if not isinstance(cve, Mapping):
                continue

            descriptions = _extract_nvd_descriptions(cve)
            cwes = _extract_nvd_cwes(cve)
            references = _extract_nvd_references(cve)
            affected_versions = _extract_nvd_affected_versions(item if isinstance(item, Mapping) else cve)
            vendor = next((entry.vendor for entry in affected_versions if entry.vendor), None)
            product = next((entry.product for entry in affected_versions if entry.product), None)
            records.append(
                RawCVERecord(
                    cve_id=_extract_nvd_cve_id(cve),
                    aliases=[],
                    description=descriptions.get("en") or next(iter(descriptions.values()), ""),
                    cwes=cwes,
                    references=references,
                    affected_versions=affected_versions,
                    project=product,
                    vendor=vendor,
                    repo_url=None,
                    language=source.metadata.get("language"),
                    metadata={
                        "source_schema": "nvd",
                        "description_languages": sorted(descriptions),
                        "source_locator": source.locator,
                    },
                )
            )
        return records


class GitHubSecurityAdvisoryAdapter(CVESourceAdapter):
    """Adapter for GitHub global security advisory REST payloads."""

    source_kind = AdvisorySourceKind.GITHUB_SECURITY_ADVISORY

    def extract_records(self, payload: Any, source: CollectionSource) -> list[RawCVERecord]:
        raw_items: Iterable[Any]
        if isinstance(payload, list):
            raw_items = payload
        elif isinstance(payload, Mapping):
            if "items" in payload and isinstance(payload["items"], list):
                raw_items = payload["items"]
            else:
                raw_items = [payload]
        else:
            raise ModelSerializationError("GitHub advisory payload must be a JSON object or array")

        records: list[RawCVERecord] = []
        for item in raw_items:
            if not isinstance(item, Mapping):
                continue
            identifiers = item.get("identifiers")
            cve_id = item.get("cve_id") or _extract_identifier(identifiers, "CVE")
            if not cve_id:
                continue

            ghsa_id = item.get("ghsa_id") or _extract_identifier(identifiers, "GHSA")
            source_code_location = item.get("source_code_location")
            references = _extract_github_references(item)
            affected_versions = _extract_github_affected_versions(item)
            project = _project_from_source_code_location(source_code_location) or _project_from_vulnerabilities(
                affected_versions
            )
            records.append(
                RawCVERecord(
                    cve_id=cve_id,
                    aliases=[ghsa_id] if ghsa_id else [],
                    description=(item.get("description") or item.get("summary") or "").strip(),
                    cwes=_extract_github_cwes(item),
                    references=references,
                    affected_versions=affected_versions,
                    project=project,
                    repo_url=source_code_location,
                    language=source.metadata.get("language"),
                    metadata={
                        "source_schema": "github_security_advisory",
                        "severity": item.get("severity"),
                        "published_at": item.get("published_at"),
                        "updated_at": item.get("updated_at"),
                        "source_locator": source.locator,
                    },
                )
            )
        return records


class ProjectAdvisoryAdapter(CVESourceAdapter):
    """Adapter for project-specific advisories in a normalized local JSON shape."""

    source_kind = AdvisorySourceKind.PROJECT_ADVISORY

    def extract_records(self, payload: Any, source: CollectionSource) -> list[RawCVERecord]:
        raw_items: Iterable[Any]
        if isinstance(payload, list):
            raw_items = payload
        elif isinstance(payload, Mapping):
            if "records" in payload and isinstance(payload["records"], list):
                raw_items = payload["records"]
            else:
                raw_items = [payload]
        else:
            raise ModelSerializationError("Project advisory payload must be a JSON object or array")

        records: list[RawCVERecord] = []
        for item in raw_items:
            if not isinstance(item, Mapping):
                continue
            cve_id = item.get("cve_id")
            if not isinstance(cve_id, str):
                continue
            references = _extract_project_references(item)
            affected_versions = _extract_project_affected_versions(item)
            records.append(
                RawCVERecord(
                    cve_id=cve_id,
                    aliases=[alias for alias in item.get("aliases", []) if isinstance(alias, str)],
                    description=(item.get("description") or "").strip(),
                    cwes=_coerce_string_list(item.get("cwes")),
                    references=references,
                    affected_versions=affected_versions,
                    project=item.get("project"),
                    repo_url=item.get("repo_url"),
                    language=item.get("language") or source.metadata.get("language"),
                    metadata={
                        "source_schema": "project_advisory",
                        "source_locator": source.locator,
                        "raw_metadata": dict(item.get("metadata", {})) if isinstance(item.get("metadata"), Mapping) else {},
                    },
                )
            )
        return records


def get_source_adapter(source_kind: AdvisorySourceKind) -> CVESourceAdapter:
    """Return the source adapter matching the requested advisory kind."""

    if source_kind == AdvisorySourceKind.CVE_LIST_V5:
        return CVEListV5Adapter()
    if source_kind == AdvisorySourceKind.NVD_JSON_FEED:
        return NVDJSONFeedAdapter()
    if source_kind == AdvisorySourceKind.GITHUB_SECURITY_ADVISORY:
        return GitHubSecurityAdvisoryAdapter()
    if source_kind == AdvisorySourceKind.PROJECT_ADVISORY:
        return ProjectAdvisoryAdapter()
    raise ModelSerializationError(f"Unsupported source kind: {source_kind.value}")


def _load_json_from_path(path: Path) -> Any:
    try:
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8") as handle:
                return json.load(handle)
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ModelSerializationError(f"Failed to read CVE source {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ModelSerializationError(f"Invalid JSON in CVE source {path}: {exc}") from exc


def _load_json_from_url(url: str) -> Any:
    request = urllib_request.Request(url, headers={"User-Agent": "RCPatch/1.0"})
    try:
        with urllib_request.urlopen(request, timeout=30) as response:
            raw_body = response.read()
            if url.endswith(".gz"):
                raw_body = gzip.decompress(raw_body)
    except urllib_error.HTTPError as exc:
        raise ModelSerializationError(f"HTTP error while fetching CVE source {url}: {exc}") from exc
    except urllib_error.URLError as exc:
        raise ModelSerializationError(f"Network error while fetching CVE source {url}: {exc}") from exc
    try:
        return json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ModelSerializationError(f"Invalid JSON returned by CVE source {url}: {exc}") from exc


def _is_cvelist_record_path(path: Path) -> bool:
    """Return whether a path looks like a concrete CVE JSON record in cvelistV5."""

    return path.is_file() and path.suffix == ".json" and path.name.startswith("CVE-")


def _extract_cvelist_cve_id(payload: Mapping[str, Any]) -> str:
    metadata = payload.get("cveMetadata")
    if isinstance(metadata, Mapping) and isinstance(metadata.get("cveId"), str):
        return metadata["cveId"]
    raise ModelSerializationError("cve_list_v5 record missing cveMetadata.cveId")


def _extract_cvelist_containers(payload: Mapping[str, Any]) -> list[tuple[str, Mapping[str, Any]]]:
    containers = payload.get("containers")
    if not isinstance(containers, Mapping):
        return []
    results: list[tuple[str, Mapping[str, Any]]] = []
    cna = containers.get("cna")
    if isinstance(cna, Mapping):
        results.append(("cna", cna))
    adp = containers.get("adp")
    if isinstance(adp, list):
        for index, item in enumerate(adp):
            if not isinstance(item, Mapping):
                continue
            provider_metadata = item.get("providerMetadata")
            provider = provider_metadata.get("shortName") if isinstance(provider_metadata, Mapping) else None
            label = f"adp:{provider}" if isinstance(provider, str) and provider else f"adp:{index}"
            results.append((label, item))
    return results


def _extract_cvelist_descriptions(containers: list[tuple[str, Mapping[str, Any]]]) -> dict[str, str]:
    descriptions: dict[str, str] = {}
    for _label, container in containers:
        raw_descriptions = container.get("descriptions")
        if not isinstance(raw_descriptions, list):
            continue
        for item in raw_descriptions:
            if not isinstance(item, Mapping):
                continue
            lang = item.get("lang")
            value = item.get("value")
            if isinstance(lang, str) and isinstance(value, str) and value.strip() and lang not in descriptions:
                descriptions[lang] = value.strip()
    return descriptions


def _extract_cvelist_cwes(containers: list[tuple[str, Mapping[str, Any]]]) -> list[str]:
    cwes: list[str] = []
    for _label, container in containers:
        problem_types = container.get("problemTypes")
        if not isinstance(problem_types, list):
            continue
        for problem_type in problem_types:
            if not isinstance(problem_type, Mapping):
                continue
            descriptions = problem_type.get("descriptions")
            if not isinstance(descriptions, list):
                continue
            for entry in descriptions:
                if not isinstance(entry, Mapping):
                    continue
                cwe_id = entry.get("cweId")
                description = entry.get("description")
                value = cwe_id if isinstance(cwe_id, str) and cwe_id else description
                if isinstance(value, str) and value not in cwes:
                    cwes.append(value)
    return cwes


def _extract_cvelist_references(containers: list[tuple[str, Mapping[str, Any]]]) -> list[dict[str, Any]]:
    references: list[dict[str, Any]] = []
    for label, container in containers:
        raw_references = container.get("references")
        provider_metadata = container.get("providerMetadata")
        provider_name = provider_metadata.get("shortName") if isinstance(provider_metadata, Mapping) else None
        source_name = provider_name if isinstance(provider_name, str) and provider_name else label
        if not isinstance(raw_references, list):
            continue
        for entry in raw_references:
            if not isinstance(entry, Mapping):
                continue
            url = entry.get("url")
            if not isinstance(url, str):
                continue
            references.append(
                {
                    "url": url,
                    "source": source_name,
                    "tags": [tag for tag in entry.get("tags", []) if isinstance(tag, str)],
                    "metadata": {
                        "container": label,
                    },
                }
            )
    return references


def _extract_cvelist_affected_versions(containers: list[tuple[str, Mapping[str, Any]]]) -> list[dict[str, Any]]:
    affected_versions: list[dict[str, Any]] = []
    for label, container in containers:
        raw_affected = container.get("affected")
        if not isinstance(raw_affected, list):
            continue
        for affected in raw_affected:
            if not isinstance(affected, Mapping):
                continue
            vendor = affected.get("vendor")
            product = affected.get("product")
            package_name = affected.get("packageName")
            default_status = affected.get("defaultStatus")
            platforms = [value for value in affected.get("platforms", []) if isinstance(value, str)]
            cpes = [value for value in affected.get("cpes", []) if isinstance(value, str)]
            collection_url = affected.get("collectionURL")
            versions = affected.get("versions")
            if isinstance(versions, list) and versions:
                for version in versions:
                    if not isinstance(version, Mapping):
                        continue
                    affected_versions.append(
                        {
                            "package": package_name if isinstance(package_name, str) else product,
                            "vendor": vendor if isinstance(vendor, str) else None,
                            "product": product if isinstance(product, str) else None,
                            "version_start_including": version.get("version") if isinstance(version.get("version"), str) else None,
                            "version_end_including": version.get("lessThanOrEqual") if isinstance(version.get("lessThanOrEqual"), str) else None,
                            "version_end_excluding": version.get("lessThan") if isinstance(version.get("lessThan"), str) else None,
                            "first_patched_version": version.get("changes", [{}])[0].get("at") if isinstance(version.get("changes"), list) and version.get("changes") else None,
                            "metadata": {
                                "status": version.get("status"),
                                "version_type": version.get("versionType"),
                                "default_status": default_status,
                                "platforms": platforms,
                                "container": label,
                                "collection_url": collection_url,
                            },
                            "cpe_uri": cpes[0] if cpes else None,
                        }
                    )
            else:
                affected_versions.append(
                    {
                        "package": package_name if isinstance(package_name, str) else product,
                        "vendor": vendor if isinstance(vendor, str) else None,
                        "product": product if isinstance(product, str) else None,
                        "metadata": {
                            "default_status": default_status,
                            "platforms": platforms,
                            "container": label,
                            "collection_url": collection_url,
                        },
                        "cpe_uri": cpes[0] if cpes else None,
                    }
                )
    return affected_versions


def _extract_nvd_cve_id(cve: Mapping[str, Any]) -> str:
    if isinstance(cve.get("id"), str):
        return cve["id"]
    metadata = cve.get("CVE_data_meta")
    if isinstance(metadata, Mapping) and isinstance(metadata.get("ID"), str):
        return metadata["ID"]
    raise ModelSerializationError("NVD record missing CVE identifier")


def _extract_nvd_descriptions(cve: Mapping[str, Any]) -> dict[str, str]:
    descriptions = cve.get("descriptions")
    if isinstance(descriptions, list):
        result = {
            entry.get("lang", ""): entry.get("value", "").strip()
            for entry in descriptions
            if isinstance(entry, Mapping) and isinstance(entry.get("value"), str)
        }
        if result:
            return result
    description_block = cve.get("description")
    if isinstance(description_block, Mapping) and isinstance(description_block.get("description_data"), list):
        return {
            entry.get("lang", ""): entry.get("value", "").strip()
            for entry in description_block["description_data"]
            if isinstance(entry, Mapping) and isinstance(entry.get("value"), str)
        }
    return {}


def _extract_nvd_cwes(cve: Mapping[str, Any]) -> list[str]:
    weaknesses = cve.get("weaknesses")
    collected: list[str] = []
    if isinstance(weaknesses, list):
        for weakness in weaknesses:
            if not isinstance(weakness, Mapping):
                continue
            descriptions = weakness.get("description")
            if not isinstance(descriptions, list):
                continue
            for entry in descriptions:
                value = entry.get("value") if isinstance(entry, Mapping) else None
                if isinstance(value, str) and value not in collected:
                    collected.append(value)
        if collected:
            return collected
    problemtype = cve.get("problemtype")
    if isinstance(problemtype, Mapping):
        problem_entries = problemtype.get("problemtype_data")
        if isinstance(problem_entries, list):
            for problem in problem_entries:
                descriptions = problem.get("description") if isinstance(problem, Mapping) else None
                if not isinstance(descriptions, list):
                    continue
                for entry in descriptions:
                    value = entry.get("value") if isinstance(entry, Mapping) else None
                    if isinstance(value, str) and value not in collected:
                        collected.append(value)
    return collected


def _extract_nvd_references(cve: Mapping[str, Any]) -> list[dict[str, Any]]:
    references = cve.get("references")
    normalized: list[dict[str, Any]] = []
    if isinstance(references, list):
        for reference in references:
            if not isinstance(reference, Mapping):
                continue
            url = reference.get("url")
            if isinstance(url, str):
                normalized.append(
                    {
                        "url": url,
                        "source": reference.get("source"),
                        "tags": [tag for tag in reference.get("tags", []) if isinstance(tag, str)],
                    }
                )
        if normalized:
            return normalized
    ref_block = cve.get("references")
    if isinstance(ref_block, Mapping):
        ref_entries = ref_block.get("reference_data")
        if isinstance(ref_entries, list):
            for reference in ref_entries:
                if not isinstance(reference, Mapping):
                    continue
                url = reference.get("url")
                if isinstance(url, str):
                    normalized.append(
                        {
                            "url": url,
                            "source": reference.get("refsource"),
                            "tags": [tag for tag in reference.get("tags", []) if isinstance(tag, str)],
                        }
                    )
    return normalized


def _extract_nvd_affected_versions(item: Mapping[str, Any]) -> list[CVEAffectedVersion]:
    results: list[CVEAffectedVersion] = []
    configurations = item.get("configurations")
    if isinstance(configurations, list):
        for config in configurations:
            if not isinstance(config, Mapping):
                continue
            nodes = config.get("nodes")
            if isinstance(nodes, list):
                results.extend(_extract_cpe_matches(nodes))
        return results
    if isinstance(configurations, Mapping):
        nodes = configurations.get("nodes")
        if isinstance(nodes, list):
            results.extend(_extract_cpe_matches(nodes))
    return results


def _extract_cpe_matches(nodes: Iterable[Any]) -> list[CVEAffectedVersion]:
    results: list[CVEAffectedVersion] = []
    for node in nodes:
        if not isinstance(node, Mapping):
            continue
        cpe_matches = node.get("cpeMatch") or node.get("cpe_match")
        if isinstance(cpe_matches, list):
            for match in cpe_matches:
                if not isinstance(match, Mapping):
                    continue
                criteria = match.get("criteria") or match.get("cpe23Uri")
                if not isinstance(criteria, str):
                    continue
                vendor, product, version = _extract_vendor_product_version(criteria)
                results.append(
                    CVEAffectedVersion(
                        vendor=vendor,
                        product=product,
                        vulnerable_version_range=version,
                        version_start_including=_optional_str(match.get("versionStartIncluding")),
                        version_start_excluding=_optional_str(match.get("versionStartExcluding")),
                        version_end_including=_optional_str(match.get("versionEndIncluding")),
                        version_end_excluding=_optional_str(match.get("versionEndExcluding")),
                        cpe_uri=criteria,
                    )
                )
        children = node.get("children")
        if isinstance(children, list):
            results.extend(_extract_cpe_matches(children))
    return results


def _extract_github_references(item: Mapping[str, Any]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for url in item.get("references", []):
        if isinstance(url, str):
            results.append({"url": url, "source": "github", "tags": []})
    if isinstance(item.get("url"), str):
        results.append({"url": item["url"], "source": "github", "tags": ["advisory"]})
    return results


def _extract_github_affected_versions(item: Mapping[str, Any]) -> list[CVEAffectedVersion]:
    vulnerabilities = item.get("vulnerabilities")
    results: list[CVEAffectedVersion] = []
    if not isinstance(vulnerabilities, list):
        return results
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, Mapping):
            continue
        package = vulnerability.get("package")
        package_name = None
        ecosystem = None
        if isinstance(package, Mapping):
            package_name = _optional_str(package.get("name"))
            ecosystem = _optional_str(package.get("ecosystem"))
        results.append(
            CVEAffectedVersion(
                package=package_name,
                ecosystem=ecosystem,
                vulnerable_version_range=_optional_str(vulnerability.get("vulnerable_version_range")),
                first_patched_version=_first_patched_version(vulnerability.get("first_patched_version")),
            )
        )
    return results


def _extract_github_cwes(item: Mapping[str, Any]) -> list[str]:
    cwes = item.get("cwes")
    if not isinstance(cwes, list):
        return []
    results: list[str] = []
    for entry in cwes:
        if isinstance(entry, Mapping):
            value = entry.get("cwe_id") or entry.get("name")
            if isinstance(value, str):
                results.append(value)
    return results


def _extract_project_references(item: Mapping[str, Any]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for reference in item.get("references", []):
        if isinstance(reference, str):
            results.append({"url": reference, "source": "project_advisory", "tags": []})
        elif isinstance(reference, Mapping) and isinstance(reference.get("url"), str):
            results.append(
                {
                    "url": reference["url"],
                    "source": reference.get("source"),
                    "tags": [tag for tag in reference.get("tags", []) if isinstance(tag, str)],
                }
            )
    return results


def _extract_project_affected_versions(item: Mapping[str, Any]) -> list[CVEAffectedVersion]:
    affected_versions = item.get("affected_versions")
    if not isinstance(affected_versions, list):
        return []
    results: list[CVEAffectedVersion] = []
    for entry in affected_versions:
        if isinstance(entry, Mapping):
            results.append(CVEAffectedVersion.from_dict(dict(entry)))
    return results


def _extract_identifier(identifiers: Any, prefix: str) -> Optional[str]:
    if not isinstance(identifiers, list):
        return None
    for identifier in identifiers:
        if not isinstance(identifier, Mapping):
            continue
        identifier_type = identifier.get("type")
        value = identifier.get("value")
        if isinstance(identifier_type, str) and isinstance(value, str) and identifier_type.upper() == prefix.upper():
            return value
    return None


def _project_from_source_code_location(source_code_location: Any) -> Optional[str]:
    if not isinstance(source_code_location, str):
        return None
    parts = [part for part in source_code_location.rstrip("/").split("/") if part]
    return parts[-1] if parts else None


def _project_from_vulnerabilities(affected_versions: Iterable[CVEAffectedVersion]) -> Optional[str]:
    for item in affected_versions:
        if item.package:
            return item.package
    return None


def _extract_vendor_product_version(criteria: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
    parts = criteria.split(":")
    if len(parts) < 6:
        return None, None, None
    vendor = None if parts[3] in {"*", "-"} else parts[3]
    product = None if parts[4] in {"*", "-"} else parts[4]
    version = None if parts[5] in {"*", "-"} else parts[5]
    return vendor, product, version


def _first_patched_version(value: Any) -> Optional[str]:
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        identifier = value.get("identifier")
        return identifier if isinstance(identifier, str) else None
    return None


def _coerce_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _optional_str(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value else None
