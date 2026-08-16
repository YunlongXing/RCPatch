"""Regression coverage for SM2-style two-phase decrypt sizing bugs."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rcpatch.pipeline import RCPatchPipeline


CRYPTO_C = """\
#include <stddef.h>
#include <string.h>

int plaintext_size(size_t msg_len, size_t *pt_size) {
    size_t overhead = 10 + 32;
    if (msg_len <= overhead) {
        return 0;
    }
    *pt_size = msg_len - overhead;
    return 1;
}

int decrypt(const unsigned char *ciphertext,
            size_t ciphertext_len,
            unsigned char *ptext_buf,
            size_t *ptext_len) {
    unsigned char msg_mask_storage[1024];
    unsigned char *msg_mask = msg_mask_storage;
    size_t i;
    size_t msg_len = ciphertext_len;

    memset(ptext_buf, 0, *ptext_len);

    for (i = 0; i != msg_len; ++i)
        ptext_buf[i] = ciphertext[i] ^ msg_mask[i];

    *ptext_len = msg_len;
    return 1;
}
"""

PMETH_C = """\
#include <stddef.h>

typedef struct {
    void *data;
} Context;

int plaintext_size(size_t msg_len, size_t *pt_size);
int decrypt(const unsigned char *ciphertext,
            size_t ciphertext_len,
            unsigned char *ptext_buf,
            size_t *ptext_len);

int pkey_sm2_init(Context *ctx) {
    ctx->data = 0;
    return 1;
}

int pkey_sm2_cleanup(Context *ctx) {
    ctx->data = 0;
    return 1;
}

int pkey_sm2_decrypt(Context *ctx,
                     unsigned char *out,
                     size_t *outlen,
                     const unsigned char *in,
                     size_t inlen) {
    void *dctx = ctx->data;
    (void)dctx;

    if (out == NULL) {
        if (!plaintext_size(inlen, outlen))
            return -1;
        return 1;
    }

    return decrypt(in, inlen, out, outlen);
}
"""

TEST_CALLER_C = """\
#include <stddef.h>

int decrypt(const unsigned char *ciphertext,
            size_t ciphertext_len,
            unsigned char *ptext_buf,
            size_t *ptext_len);

int regression_test_driver(const unsigned char *ciphertext,
                           size_t ciphertext_len) {
    unsigned char recovered[64];
    size_t recovered_len = sizeof(recovered);
    return decrypt(ciphertext, ciphertext_len, recovered, &recovered_len);
}
"""

NOISE_C = """\
#include <stdint.h>

int unrelated_counter(void) {
    int status = 0;
    uint8_t scratch = 7;
    return status + scratch;
}
"""


class Sm2RegressionTests(unittest.TestCase):
    def test_two_phase_size_query_is_ranked_above_context_init_noise(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir) / "repo"
            crypto_path = repo_root / "src" / "crypto.c"
            pmeth_path = repo_root / "src" / "pmeth.c"
            crypto_path.parent.mkdir(parents=True)
            crypto_path.write_text(CRYPTO_C, encoding="utf-8")
            pmeth_path.write_text(PMETH_C, encoding="utf-8")

            trigger_line = _find_line(CRYPTO_C, "ptext_buf[i] = ciphertext[i] ^ msg_mask[i];")
            spec_path = Path(temp_dir) / "bug.json"
            spec_payload = {
                "bug_id": "sm2_like_two_phase_size_regression",
                "repo_path": str(repo_root),
                "language": "c_cpp",
                "trigger_point": {
                    "location": {
                        "file": "src/crypto.c",
                        "line": trigger_line,
                        "function": "decrypt",
                    },
                    "type": "first_failing_operation",
                    "failing_operation": "ptext_buf[i] = ciphertext[i] ^ msg_mask[i]",
                    "bug_type_hint": "buffer_overflow",
                },
                "config": {
                    "parser_backend": "regex",
                    "top_k_candidates": 10,
                    "max_chain_paths": 5,
                    "enable_patch_analysis": False,
                    "enable_llm": False,
                    "bug_type_hint": "buffer_overflow",
                    "max_interprocedural_hops": 6,
                },
            }
            spec_path.write_text(json.dumps(spec_payload, indent=2), encoding="utf-8")

            pipeline = RCPatchPipeline()
            artifacts = pipeline.run_analysis(spec_path)
            result = artifacts.analysis_result

            self.assertIsNotNone(result)
            assert result is not None
            self.assertTrue(result.root_cause_candidates)

            top_candidate = result.root_cause_candidates[0]
            self.assertEqual(top_candidate.location.function, "plaintext_size")
            self.assertEqual(
                top_candidate.location.line,
                _find_line(CRYPTO_C, "*pt_size = msg_len - overhead;"),
            )
            self.assertNotIn(top_candidate.location.function, {"pkey_sm2_init", "pkey_sm2_cleanup"})

            self.assertTrue(result.chains)
            top_chain = result.chains[0]
            self.assertTrue(any(step.location.function == "plaintext_size" for step in top_chain.steps))
            self.assertEqual(top_chain.steps[-1].location.function, "decrypt")
            self.assertEqual(top_chain.steps[-1].location.line, trigger_line)

    def test_multiple_callers_and_type_noise_do_not_block_size_query_root_cause(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir) / "repo"
            crypto_path = repo_root / "src" / "crypto.c"
            pmeth_path = repo_root / "src" / "pmeth.c"
            test_driver_path = repo_root / "test" / "driver.c"
            noise_path = repo_root / "src" / "noise.c"
            crypto_path.parent.mkdir(parents=True)
            test_driver_path.parent.mkdir(parents=True)

            crypto_path.write_text(CRYPTO_C, encoding="utf-8")
            pmeth_path.write_text(PMETH_C, encoding="utf-8")
            test_driver_path.write_text(TEST_CALLER_C, encoding="utf-8")
            noise_path.write_text(NOISE_C, encoding="utf-8")

            trigger_line = _find_line(CRYPTO_C, "ptext_buf[i] = ciphertext[i] ^ msg_mask[i];")
            spec_path = Path(temp_dir) / "bug.json"
            spec_payload = {
                "bug_id": "sm2_like_full_repo_regression",
                "repo_path": str(repo_root),
                "language": "c_cpp",
                "trigger_point": {
                    "location": {
                        "file": "src/crypto.c",
                        "line": trigger_line,
                        "function": "decrypt",
                    },
                    "type": "first_failing_operation",
                    "failing_operation": "ptext_buf[i] = ciphertext[i] ^ msg_mask[i]",
                    "bug_type_hint": "buffer_overflow",
                },
                "config": {
                    "parser_backend": "regex",
                    "top_k_candidates": 10,
                    "max_chain_paths": 5,
                    "enable_patch_analysis": False,
                    "enable_llm": False,
                    "bug_type_hint": "buffer_overflow",
                    "max_interprocedural_hops": 6,
                },
            }
            spec_path.write_text(json.dumps(spec_payload, indent=2), encoding="utf-8")

            pipeline = RCPatchPipeline()
            artifacts = pipeline.run_analysis(spec_path)
            result = artifacts.analysis_result

            self.assertIsNotNone(result)
            assert result is not None
            self.assertTrue(result.root_cause_candidates)

            top_candidate = result.root_cause_candidates[0]
            self.assertEqual(top_candidate.location.function, "plaintext_size")
            self.assertEqual(
                top_candidate.location.line,
                _find_line(CRYPTO_C, "*pt_size = msg_len - overhead;"),
            )
            self.assertTrue(
                any(step.location.function == "pkey_sm2_decrypt" for step in result.chains[0].steps),
            )
            self.assertFalse(
                any(
                    candidate.location.file == "test/driver.c"
                    for candidate in result.root_cause_candidates[:3]
                )
            )
            self.assertFalse(
                any(
                    candidate.location.file == "src/noise.c"
                    for candidate in result.root_cause_candidates[:3]
                )
            )


def _find_line(source: str, needle: str) -> int:
    for index, line in enumerate(source.splitlines(), start=1):
        if needle in line:
            return index
    raise AssertionError(f"could not find line containing {needle!r}")


if __name__ == "__main__":
    unittest.main()
