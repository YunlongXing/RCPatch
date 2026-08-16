"""Tests for config loading and overlay normalization helpers."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rcpatch.config import build_analysis_config_overrides, load_bug_spec_payload


class ConfigHelpersTests(unittest.TestCase):
    def test_load_bug_spec_payload_merges_spec_overlay_and_cli_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            repo_root = workspace / "repo"
            repo_root.mkdir()

            spec_path = workspace / "bug.json"
            spec_path.write_text(
                json.dumps(
                    {
                        "bug_id": "config_001",
                        "repo_path": repo_root.as_posix(),
                        "trigger_point": {
                            "file": "src/foo.c",
                            "line": 10,
                            "type": "crash_line",
                        },
                        "config": {
                            "top_k_candidates": 5,
                            "max_chain_paths": 5,
                            "enable_patch_analysis": True,
                        },
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            config_path = workspace / "analysis_config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "top_k_candidates": 3,
                        "parser_backend": "regex",
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            payload = load_bug_spec_payload(
                spec_path,
                config_path=config_path,
                config_overrides={"top_k_candidates": 1, "enable_llm": True},
            )

            self.assertEqual(payload["config"]["top_k_candidates"], 1)
            self.assertEqual(payload["config"]["parser_backend"], "regex")
            self.assertEqual(payload["config"]["enable_patch_analysis"], True)
            self.assertEqual(payload["config"]["enable_llm"], True)

    def test_build_analysis_config_overrides_omits_unset_values(self) -> None:
        overrides = build_analysis_config_overrides(
            parser_backend="regex",
            top_k_candidates=2,
            max_chain_paths=None,
            enable_patch_analysis=False,
            enable_llm=None,
        )

        self.assertEqual(
            overrides,
            {
                "parser_backend": "regex",
                "top_k_candidates": 2,
                "enable_patch_analysis": False,
            },
        )


if __name__ == "__main__":
    unittest.main()
