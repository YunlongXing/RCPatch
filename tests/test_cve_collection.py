"""Tests for the CVE collection and normalization module."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rcpatch.cve_mining import CVECollectionService, CollectionSource
from rcpatch.models import AdvisorySourceKind, Language, ReferenceType
from rcpatch.models.schema_registry import generate_schema_bundle


class CVECollectionTests(unittest.TestCase):
    def test_cvelist_v5_directory_collection_extracts_cna_and_adp_data(self) -> None:
        payload = {
            "dataType": "CVE_RECORD",
            "dataVersion": "5.1",
            "cveMetadata": {
                "cveId": "CVE-2024-4000",
                "state": "PUBLISHED",
                "assignerShortName": "ExampleCNA",
                "datePublished": "2024-04-01T00:00:00Z",
                "dateUpdated": "2024-04-02T00:00:00Z",
            },
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en", "value": "Heap overflow in a C parser."}],
                    "problemTypes": [
                        {
                            "descriptions": [
                                {
                                    "cweId": "CWE-122",
                                    "description": "Heap-based Buffer Overflow",
                                    "lang": "en",
                                }
                            ]
                        }
                    ],
                    "references": [
                        {
                            "url": "https://github.com/example/libfoo/commit/0123456789abcdef0123456789abcdef01234567",
                            "tags": ["patch"],
                        }
                    ],
                    "affected": [
                        {
                            "vendor": "Example",
                            "product": "libfoo",
                            "versions": [
                                {
                                    "version": "1.0.0",
                                    "lessThan": "1.2.4",
                                    "status": "affected",
                                    "versionType": "semver",
                                }
                            ],
                        }
                    ],
                    "providerMetadata": {"shortName": "ExampleCNA"},
                },
                "adp": [
                    {
                        "references": [
                            {
                                "url": "https://github.com/example/libfoo/security/advisories/GHSA-xxxx-yyyy-zzzz",
                                "tags": ["x_transferred"],
                            }
                        ],
                        "providerMetadata": {"shortName": "CVE"},
                    }
                ],
            },
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            cves_root = Path(temp_dir) / "cves" / "2024" / "4xxx"
            cves_root.mkdir(parents=True)
            (cves_root / "CVE-2024-4000.json").write_text(json.dumps(payload), encoding="utf-8")

            service = CVECollectionService(language_hints={"https://github.com/example/libfoo": "c_cpp"})
            result = service.collect(
                [
                    CollectionSource(
                        source_kind=AdvisorySourceKind.CVE_LIST_V5,
                        locator=str(Path(temp_dir)),
                    )
                ]
            )

        self.assertEqual(len(result.records), 1)
        record = result.records[0]
        self.assertEqual(record.cve_id, "CVE-2024-4000")
        self.assertEqual(record.project, "libfoo")
        self.assertEqual(record.repo_url, "https://github.com/example/libfoo")
        self.assertEqual(record.cwe, "CWE-122")
        self.assertEqual(record.language, Language.C_CPP)
        self.assertEqual(record.fix_commits, ["0123456789abcdef0123456789abcdef01234567"])
        self.assertEqual(len(record.references), 2)
        self.assertTrue(any(reference.source == "CVE" for reference in record.references))

    def test_nvd_feed_collection_and_filtering(self) -> None:
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-0001",
                        "descriptions": [{"lang": "en", "value": "Heap overflow in a C parser."}],
                        "weaknesses": [
                            {
                                "description": [
                                    {"lang": "en", "value": "CWE-122"},
                                ]
                            }
                        ],
                        "references": [
                            {
                                "url": "https://github.com/example/libfoo/commit/0123456789abcdef0123456789abcdef01234567",
                                "source": "MISC",
                                "tags": ["Patch"],
                            },
                            {
                                "url": "https://github.com/example/libfoo/pull/88",
                                "source": "MISC",
                                "tags": ["Patch"],
                            },
                        ],
                    },
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "criteria": "cpe:2.3:a:example:libfoo:*:*:*:*:*:*:*:*",
                                            "versionStartIncluding": "1.0.0",
                                            "versionEndExcluding": "1.2.4",
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                },
                {
                    "cve": {
                        "id": "CVE-2024-0002",
                        "descriptions": [{"lang": "en", "value": "Bug in a Java service."}],
                        "references": [
                            {
                                "url": "https://github.com/example/service/commit/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                                "source": "MISC",
                            }
                        ],
                    }
                },
            ]
        }
        service = CVECollectionService(
            language_hints={
                "https://github.com/example/libfoo": "c_cpp",
                "https://github.com/example/service": "unknown",
            }
        )
        result = service.collect(
            [
                CollectionSource(
                    source_kind=AdvisorySourceKind.NVD_JSON_FEED,
                    payload=payload,
                )
            ]
        )

        self.assertEqual(len(result.records), 1)
        self.assertEqual(len(result.discarded), 1)
        record = result.records[0]
        self.assertEqual(record.cve_id, "CVE-2024-0001")
        self.assertEqual(record.project, "libfoo")
        self.assertEqual(record.repo_url, "https://github.com/example/libfoo")
        self.assertEqual(record.cwe, "CWE-122")
        self.assertEqual(record.language, Language.C_CPP)
        self.assertEqual(
            record.fix_commits,
            ["0123456789abcdef0123456789abcdef01234567"],
        )
        self.assertEqual(record.references[0].reference_type, ReferenceType.COMMIT)
        self.assertTrue(record.traceability.fix_commit_reference_urls)
        self.assertEqual(result.discarded[0].reason, "language_not_c_cpp")

    def test_github_advisory_collection_preserves_traceability(self) -> None:
        payload = {
            "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
            "cve_id": "CVE-2024-1000",
            "summary": "Incorrect bounds validation in a decoder",
            "description": "A C++ decoder trusts the advertised length.",
            "references": [
                "https://github.com/example/decoder/commit/abcdefabcdefabcdefabcdefabcdefabcdefabcd",
                "https://github.com/example/decoder/security/advisories/GHSA-xxxx-yyyy-zzzz",
            ],
            "source_code_location": "https://github.com/example/decoder",
            "cwes": [{"cwe_id": "CWE-787"}],
            "vulnerabilities": [
                {
                    "package": {"ecosystem": "COMPOSER", "name": "example/decoder"},
                    "vulnerable_version_range": "< 2.0.1",
                    "first_patched_version": {"identifier": "2.0.1"},
                }
            ],
        }
        service = CVECollectionService(language_hints={"https://github.com/example/decoder": "cpp"})
        result = service.collect(
            [
                CollectionSource(
                    source_kind=AdvisorySourceKind.GITHUB_SECURITY_ADVISORY,
                    payload=payload,
                )
            ]
        )

        self.assertEqual(len(result.records), 1)
        record = result.records[0]
        self.assertEqual(record.aliases, ["GHSA-xxxx-yyyy-zzzz"])
        self.assertEqual(record.repo_url, "https://github.com/example/decoder")
        self.assertEqual(record.fix_commits, ["abcdefabcdefabcdefabcdefabcdefabcdefabcd"])
        self.assertEqual(record.affected_versions[0].first_patched_version, "2.0.1")
        self.assertIn("https://github.com/example/decoder", record.traceability.repo_reference_urls)

    def test_project_advisory_file_input_and_schema_bundle(self) -> None:
        payload = {
            "records": [
                {
                    "cve_id": "CVE-2024-2000",
                    "project": "minihttpd",
                    "repo_url": "https://gitlab.com/example/minihttpd",
                    "language": "c",
                    "description": "A bounds check is missing before memcpy.",
                    "cwes": ["CWE-120"],
                    "references": [
                        {
                            "url": "https://gitlab.com/example/minihttpd/-/commit/1234567890abcdef1234567890abcdef12345678",
                            "source": "project",
                            "tags": ["patch"],
                        }
                    ],
                    "affected_versions": [
                        {
                            "package": "minihttpd",
                            "vulnerable_version_range": "< 1.3.0",
                            "first_patched_version": "1.3.0",
                        }
                    ],
                }
            ]
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            advisory_path = Path(temp_dir) / "advisory.json"
            advisory_path.write_text(json.dumps(payload), encoding="utf-8")
            service = CVECollectionService()
            result = service.collect(
                [
                    CollectionSource(
                        source_kind=AdvisorySourceKind.PROJECT_ADVISORY,
                        locator=str(advisory_path),
                    )
                ]
            )

        self.assertEqual(len(result.records), 1)
        record = result.records[0]
        self.assertEqual(record.language, Language.C)
        self.assertEqual(record.references[0].reference_type, ReferenceType.COMMIT)
        self.assertEqual(record.fix_commits, ["1234567890abcdef1234567890abcdef12345678"])
        self.assertIn("CVECollectionResult", generate_schema_bundle())

    def test_nvd_collection_accepts_ftp_references(self) -> None:
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-3000",
                        "descriptions": [{"lang": "en", "value": "Advisory with FTP reference."}],
                        "references": [
                            {
                                "url": "ftp://ftp.freebsd.org/pub/FreeBSD/CERT/advisories/FreeBSD-SA-24:01.asc",
                                "source": "MISC",
                            },
                            {
                                "url": "https://github.com/example/libftp/commit/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                                "source": "MISC",
                                "tags": ["Patch"],
                            },
                        ],
                    }
                }
            ]
        }
        service = CVECollectionService(language_hints={"https://github.com/example/libftp": "c_cpp"})
        result = service.collect(
            [
                CollectionSource(
                    source_kind=AdvisorySourceKind.NVD_JSON_FEED,
                    payload=payload,
                )
            ]
        )

        self.assertEqual(len(result.records), 1)
        record = result.records[0]
        self.assertEqual(record.references[0].url, "ftp://ftp.freebsd.org/pub/FreeBSD/CERT/advisories/FreeBSD-SA-24:01.asc")
        self.assertEqual(record.references[1].reference_type, ReferenceType.COMMIT)

    def test_nvd_collection_repairs_common_reference_scheme_typos(self) -> None:
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-3001",
                        "descriptions": [{"lang": "en", "value": "Advisory with malformed scheme."}],
                        "references": [
                            {
                                "url": "ttps://www.cloudflare.com/learning/ddos/ddos-attack-tools/slowloris/",
                                "source": "MISC",
                            },
                            {
                                "url": "https://github.com/example/libslow/commit/cccccccccccccccccccccccccccccccccccccccc",
                                "source": "MISC",
                            },
                        ],
                    }
                }
            ]
        }
        service = CVECollectionService(language_hints={"https://github.com/example/libslow": "c_cpp"})
        result = service.collect(
            [
                CollectionSource(
                    source_kind=AdvisorySourceKind.NVD_JSON_FEED,
                    payload=payload,
                )
            ]
        )

        self.assertEqual(len(result.records), 1)
        record = result.records[0]
        self.assertEqual(
            record.references[0].url,
            "https://www.cloudflare.com/learning/ddos/ddos-attack-tools/slowloris/",
        )
        self.assertEqual(record.references[1].reference_type, ReferenceType.COMMIT)

    def test_nvd_collection_skips_unrepairable_reference_without_failing_record(self) -> None:
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-3002",
                        "descriptions": [{"lang": "en", "value": "Advisory with one bad reference."}],
                        "references": [
                            {
                                "url": "notaurl",
                                "source": "MISC",
                            },
                            {
                                "url": "https://github.com/example/libskip/commit/dddddddddddddddddddddddddddddddddddddddd",
                                "source": "MISC",
                            },
                        ],
                    }
                }
            ]
        }
        service = CVECollectionService(language_hints={"https://github.com/example/libskip": "c_cpp"})
        result = service.collect(
            [
                CollectionSource(
                    source_kind=AdvisorySourceKind.NVD_JSON_FEED,
                    payload=payload,
                )
            ]
        )

        self.assertEqual(len(result.records), 1)
        record = result.records[0]
        self.assertEqual(len(record.references), 1)
        self.assertEqual(record.references[0].reference_type, ReferenceType.COMMIT)


if __name__ == "__main__":
    unittest.main()
