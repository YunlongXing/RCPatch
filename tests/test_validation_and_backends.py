"""Tests for validation harness and parser backend fallback behavior."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from rcpatch.cli import main as bugrc_cli_main
from rcpatch.models import ParserBackend
from rcpatch.source import SourceProjectParser
from rcpatch.validation import PatchValidationHarness, ValidationCommand


SAMPLE_SOURCE = """\
int add_one(int value) {
    return value + 1;
}
"""


class ValidationAndBackendTests(unittest.TestCase):
    def test_validate_existing_tree_runs_commands_with_timeout_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            harness = PatchValidationHarness()
            result = harness.validate_existing_tree(
                root,
                commands=[
                    ValidationCommand(
                        name="smoke",
                        command="printf validation-ok",
                        timeout_seconds=5,
                    )
                ],
            )

            self.assertTrue(result.passed)
            self.assertEqual(result.steps[0].stdout_tail, "validation-ok")
            self.assertFalse(result.steps[0].timed_out)

    def test_clang_ast_backend_request_falls_back_with_diagnostic(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "sample.c").write_text(SAMPLE_SOURCE, encoding="utf-8")

            parser = SourceProjectParser()
            program = parser.parse_repository(root, preferred_backend=ParserBackend.CLANG_AST)

            self.assertEqual(program.backend, ParserBackend.REGEX)
            self.assertTrue(any("clang AST backend" in diagnostic.message for diagnostic in program.diagnostics))
            self.assertTrue(program.functions)

    def test_validate_patch_cli_can_run_existing_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output_dir = root / "out"

            exit_code = bugrc_cli_main(
                [
                    "validate-patch",
                    "--repo",
                    root.as_posix(),
                    "--existing-tree",
                    "--validation-cmd",
                    "smoke=printf cli-validation-ok",
                    "--output-dir",
                    output_dir.as_posix(),
                ]
            )

            self.assertEqual(exit_code, 0)
            self.assertTrue((output_dir / "patch_validation_result.json").exists())


if __name__ == "__main__":
    unittest.main()
