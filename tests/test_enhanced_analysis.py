"""Tests for enhanced RCPatch analysis priors, slicing, and patch suggestions."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rcpatch.cli import main as bugrc_cli_main
from rcpatch.models import AnalysisConfig, BugReport, BugType, ParserBackend, SourceLocation, TriggerPoint, TriggerType
from rcpatch.patch_generation import PatchSuggestionGenerator
from rcpatch.ranking import RootCauseCandidateExtractor
from rcpatch.source import SourceProjectParser
from rcpatch.slicing import HybridBackwardSlicer


SOURCE = """\
#include <string.h>
#define MAX_COPY 64

struct Box {
    char *buf;
};

void copy_box(struct Box *box, int idx, int len) {
    char *alias = box->buf;
    alias[idx] = 'A';
    memcpy(alias, "BBBB", len < MAX_COPY ? len : MAX_COPY);
}
"""


class EnhancedAnalysisTests(unittest.TestCase):
    def test_parser_records_field_index_and_alias_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = _write_repo(Path(temp_dir))
            parser = SourceProjectParser()
            program = parser.parse_repository(repo, preferred_backend=ParserBackend.REGEX)
            statements = [statement for function in program.functions for statement in function.statements]
            alias_statement = next(statement for statement in statements if "alias =" in statement.text)
            index_statement = next(statement for statement in statements if "alias[idx]" in statement.text)

            self.assertIn("box->buf", alias_statement.metadata["field_accesses"])
            self.assertIn("box", alias_statement.metadata["field_bases"])
            self.assertIn("box", alias_statement.metadata["alias_sources"])
            self.assertIn("idx", index_statement.metadata["index_variables"])
            call_statement = next(statement for statement in statements if "memcpy" in statement.text)
            self.assertIn("memcpy", call_statement.metadata["call_arguments"])
            self.assertIn("len", call_statement.metadata["call_argument_variables"])
            self.assertIn("MAX_COPY", call_statement.metadata["macro_references"])

    def test_slicer_tracks_alias_and_index_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = _write_repo(Path(temp_dir))
            parser = SourceProjectParser()
            program = parser.parse_repository(repo, preferred_backend=ParserBackend.REGEX)
            index = parser.build_index(program)
            trigger = TriggerPoint(
                location=SourceLocation(file="src/sample.c", line=11, function="copy_box"),
                type=TriggerType.CRASH_LINE,
                failing_operation="memcpy",
                bug_type_hint=BugType.BUFFER_OVERFLOW,
            )
            backward_slice = HybridBackwardSlicer(max_interprocedural_hops=1).slice_from_trigger(index, trigger)
            texts = {node.text for node in backward_slice.nodes}
            relations = {edge.relation.value for edge in backward_slice.edges}

            self.assertIn("char *alias = box->buf;", texts)
            self.assertIn("alias[idx] = 'A';", texts)
            self.assertIn("integer_influence", relations)
            self.assertIn("heap_object", relations)

    def test_project_prior_and_ranker_calibration_affect_candidate_features(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            repo = _write_repo(workspace)
            prior_path = workspace / "project_prior.json"
            prior_path.write_text(
                json.dumps(
                    {
                        "projects": {
                            "demo-project": {
                                "patterns": {"incorrect_size_computation": 1.0},
                                "operation_types": {"length_calculation": 1.0},
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            calibration_path = workspace / "calibration.json"
            calibration_path.write_text(
                json.dumps({"feature_boosts": {"has_integer_influence": 0.05}}),
                encoding="utf-8",
            )

            parser = SourceProjectParser()
            program = parser.parse_repository(repo, preferred_backend=ParserBackend.REGEX)
            index = parser.build_index(program)
            trigger = TriggerPoint(
                location=SourceLocation(file="src/sample.c", line=11, function="copy_box"),
                type=TriggerType.CRASH_LINE,
                failing_operation="memcpy",
                bug_type_hint=BugType.BUFFER_OVERFLOW,
            )
            report = BugReport(
                bug_id="enhanced",
                repo_path=repo.as_posix(),
                trigger_point=trigger,
                metadata={"project": "demo-project"},
                config=AnalysisConfig(
                    parser_backend=ParserBackend.REGEX,
                    bug_type_hint=BugType.BUFFER_OVERFLOW,
                    top_k_candidates=5,
                    confidence_threshold=0.0,
                    enable_project_prior=True,
                    project_prior_path=prior_path.as_posix(),
                    ranker_calibration_path=calibration_path.as_posix(),
                ),
            )
            backward_slice = HybridBackwardSlicer(max_interprocedural_hops=1).slice_from_trigger(index, trigger)
            candidates = RootCauseCandidateExtractor().extract_candidates(report, backward_slice)

            self.assertTrue(any(candidate.features.get("project_prior_score", 0.0) > 0 for candidate in candidates))
            self.assertTrue(any("calibrated_features" in candidate.confidence.components for candidate in candidates))

    def test_patch_suggestion_cli_writes_suggestions(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            repo = _write_repo(workspace)
            spec = workspace / "bug.json"
            spec.write_text(
                json.dumps(
                    {
                        "bug_id": "patch-suggestion",
                        "repo_path": repo.as_posix(),
                        "trigger_point": {
                            "file": "src/sample.c",
                            "line": 11,
                            "function": "copy_box",
                            "type": "crash_line",
                            "failing_operation": "memcpy",
                            "bug_type_hint": "buffer_overflow",
                        },
                        "config": {"parser_backend": "regex", "enable_patch_analysis": False},
                    }
                ),
                encoding="utf-8",
            )
            output_dir = workspace / "out"
            exit_code = bugrc_cli_main(["suggest-patch", spec.as_posix(), "--output-dir", output_dir.as_posix()])

            self.assertEqual(exit_code, 0)
            suggestions = json.loads((output_dir / "patch_suggestions.json").read_text(encoding="utf-8"))
            self.assertTrue(suggestions)


def _write_repo(workspace: Path) -> Path:
    repo = workspace / "repo"
    source_dir = repo / "src"
    source_dir.mkdir(parents=True)
    (source_dir / "sample.c").write_text(SOURCE, encoding="utf-8")
    return repo


if __name__ == "__main__":
    unittest.main()
