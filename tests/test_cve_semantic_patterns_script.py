"""Tests for the lightweight CVE semantic pattern builder script."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from rcpatch.models import AdvisoryReference, AdvisorySourceKind, CVETraceability, CollectedCVERecord, Language, ReferenceType


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "build_cve_semantic_patterns.py"
SPEC = importlib.util.spec_from_file_location("build_cve_semantic_patterns", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - defensive import path
    raise RuntimeError(f"Unable to load semantic pattern script from {SCRIPT_PATH}")
SEMANTIC_SCRIPT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SEMANTIC_SCRIPT)


class CVESemanticPatternScriptTests(unittest.TestCase):
    def test_builds_semantic_dataset_and_pattern_library_without_llm(self) -> None:
        records = [
            make_record(
                cve_id="CVE-2024-1000",
                cwe="CWE-416",
                description="A use-after-free in a C parser may lead to memory corruption.",
            ),
            make_record(
                cve_id="CVE-2024-1001",
                cwe="CWE-787",
                description="A heap-based buffer overflow occurs because a length field is not checked.",
            ),
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            collection_path = temp_path / "collection.json"
            output_dir = temp_path / "out"
            collection_path.write_text(
                json.dumps({"record_count": len(records), "records": [record.to_dict() for record in records]}, indent=2),
                encoding="utf-8",
            )

            exit_code = SEMANTIC_SCRIPT.main(
                [
                    "--collection-json",
                    collection_path.as_posix(),
                    "--output-dir",
                    output_dir.as_posix(),
                    "--min-confidence",
                    "0.1",
                    "--pattern-min-support",
                    "1",
                ]
            )

            self.assertEqual(exit_code, 0)
            dataset = json.loads((output_dir / "cve_semantic_root_cause_dataset.json").read_text(encoding="utf-8"))
            patterns = json.loads((output_dir / "cve_pattern_prior_library.json").read_text(encoding="utf-8"))

        self.assertEqual(dataset["schema_version"], SEMANTIC_SCRIPT.SCHEMA_VERSION_DATASET)
        self.assertEqual(len(dataset["records"]), 2)
        self.assertTrue(all(record["needs_code_validation"] for record in dataset["records"]))
        self.assertEqual({record["source"] for record in dataset["records"]}, {"heuristic"})
        self.assertGreaterEqual(len(patterns["patterns"]), 2)

    def test_llm_json_parser_accepts_wrapped_json(self) -> None:
        parsed = SEMANTIC_SCRIPT.parse_llm_json(
            'Result:\n{"bug_class": "buffer_overflow", "root_cause_type": "missing_bounds_check", '
            '"pattern": "missing_bounds_check_before_write", "reasoning": "x", '
            '"evidence_from_text": ["buffer overflow"], "confidence": 0.8}'
        )

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["pattern"], "missing_bounds_check_before_write")


def make_record(*, cve_id: str, cwe: str, description: str) -> CollectedCVERecord:
    return CollectedCVERecord(
        cve_id=cve_id,
        aliases=[],
        project="libexample",
        repo_url="https://github.com/example/libexample",
        description=description,
        cwe=cwe,
        cwes=[cwe],
        language=Language.UNKNOWN,
        references=[
            AdvisoryReference(
                url="https://github.com/example/libexample/commit/0123456789abcdef0123456789abcdef01234567",
                reference_type=ReferenceType.COMMIT,
                repo_url="https://github.com/example/libexample",
            )
        ],
        fix_commits=["0123456789abcdef0123456789abcdef01234567"],
        traceability=CVETraceability(source_kind=AdvisorySourceKind.CVE_LIST_V5),
    )


if __name__ == "__main__":
    unittest.main()
