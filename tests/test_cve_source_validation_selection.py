"""Tests for selecting semantic CVEs for source-based validation."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from rcpatch.models import AdvisoryReference, AdvisorySourceKind, CVETraceability, CollectedCVERecord, ReferenceType


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "select_cve_source_validation_targets.py"
SPEC = importlib.util.spec_from_file_location("select_cve_source_validation_targets", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - defensive import path
    raise RuntimeError(f"Unable to load selection script from {SCRIPT_PATH}")
SELECT_SCRIPT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SELECT_SCRIPT)


class CVESourceValidationSelectionTests(unittest.TestCase):
    def test_selects_high_confidence_targets_and_collection_subset(self) -> None:
        semantic_dataset = {
            "records": [
                semantic_record("CVE-2024-0001", 0.9, "use_after_free_via_dangling_pointer"),
                semantic_record("CVE-2024-0002", 0.4, "missing_bounds_check_before_write"),
                semantic_record("CVE-2024-0003", 0.8, "unknown_semantic_pattern", bug_class="other"),
            ]
        }
        collection_records = [
            collection_record("CVE-2024-0001"),
            collection_record("CVE-2024-0002"),
            collection_record("CVE-2024-0003"),
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            semantic_path = root / "semantic.json"
            collection_path = root / "collection.json"
            out_dir = root / "out"
            semantic_path.write_text(json.dumps(semantic_dataset), encoding="utf-8")
            collection_path.write_text(
                json.dumps({"record_count": len(collection_records), "records": [item.to_dict() for item in collection_records]}, indent=2),
                encoding="utf-8",
            )

            exit_code = SELECT_SCRIPT.main(
                [
                    "--semantic-dataset",
                    semantic_path.as_posix(),
                    "--collection-json",
                    collection_path.as_posix(),
                    "--output-dir",
                    out_dir.as_posix(),
                    "--min-confidence",
                    "0.65",
                    "--max-cves",
                    "10",
                ]
            )

            self.assertEqual(exit_code, 0)
            targets = json.loads((out_dir / "source_validation_targets.json").read_text(encoding="utf-8"))
            selected_collection = json.loads((out_dir / "source_validation_collection.json").read_text(encoding="utf-8"))
            command = (out_dir / "run_source_validation.sh").read_text(encoding="utf-8")

        self.assertEqual(targets["metadata"]["selected_count"], 1)
        self.assertEqual(targets["targets"][0]["cve_id"], "CVE-2024-0001")
        self.assertEqual(selected_collection["record_count"], 1)
        self.assertEqual(selected_collection["records"][0]["cve_id"], "CVE-2024-0001")
        self.assertIn("resume_cve_bootstrap_filtered.py", command)


def semantic_record(cve_id: str, confidence: float, pattern: str, *, bug_class: str = "use_after_free") -> dict[str, object]:
    return {
        "cve_id": cve_id,
        "project": "libexample",
        "repo_url": "https://github.com/example/libexample",
        "cwe": "CWE-416",
        "bug_class": bug_class,
        "root_cause_type": "memory_lifetime_misuse",
        "pattern": pattern,
        "confidence": confidence,
        "source": "heuristic",
        "explanation": "semantic hypothesis",
        "evidence_from_text": ["use-after-free"],
        "references": [{"commit_sha": "0123456789abcdef0123456789abcdef01234567"}],
    }


def collection_record(cve_id: str) -> CollectedCVERecord:
    return CollectedCVERecord(
        cve_id=cve_id,
        project="libexample",
        repo_url="https://github.com/example/libexample",
        description="A use-after-free in a C library.",
        cwe="CWE-416",
        cwes=["CWE-416"],
        references=[
            AdvisoryReference(
                url="https://github.com/example/libexample/commit/0123456789abcdef0123456789abcdef01234567",
                reference_type=ReferenceType.COMMIT,
                repo_url="https://github.com/example/libexample",
                commit_sha="0123456789abcdef0123456789abcdef01234567",
            )
        ],
        fix_commits=["0123456789abcdef0123456789abcdef01234567"],
        traceability=CVETraceability(source_kind=AdvisorySourceKind.CVE_LIST_V5),
    )


if __name__ == "__main__":
    unittest.main()
