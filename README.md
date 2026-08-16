# RCPatch

RCPatch is a research prototype for **root-cause-guided patch generation** in
C/C++ projects. Given a target repository, a vulnerability trigger, and any
available supporting evidence, RCPatch reconstructs a root-cause-to-trigger
causality chain, ranks root-cause candidates, and emits evidence-grounded patch
suggestions and audit artifacts.

This public repository contains the software artifact only: source code, tests,
examples, lightweight priors, and reproduction/evaluation drivers. Large
benchmark corpora, local caches, generated worktrees, and paper-writing
materials are intentionally not included.

## Core Idea

RCPatch is designed around one principle:

> A vulnerability patch should cut the causal path from the vulnerability
> origin to the trigger, not merely suppress the crash-site symptom.

The implementation provides:

- JSON-validated intermediate representations for bug reports, trigger points,
  runtime evidence, backward slices, root-cause candidates, and causality chains.
- C/C++ source abstraction with lightweight parser backends and heuristic
  fallbacks for incomplete projects.
- Trigger-guided backward slicing over variables, sizes, indices, pointers,
  branch guards, returns, globals, and heap-like aliases.
- Root-cause candidate ranking with explicit features and optional CVE-derived
  or project-specific priors.
- Optional OpenAI-compatible LLM interpretation for ambiguous candidate labels
  and patch intent. LLM output is used only to interpret extracted evidence.
- Patch suggestion, patch-aware analysis, JSON/HTML/text reporting, run
  manifests, and timeout-bounded patch validation helpers.

## Results Snapshot

The following numbers summarize the authors' latest evaluation runs. Raw ARVO,
Magma, and CVE corpora are not included in this repository because they are
large and should be obtained from their original sources.

- **ARVO-Meta:** RCPatch completed 3,660 analyses from 4,993 C/C++ bug reports.
  A first-pass semantic comparison identified 2,184 cases where the RCPatch patch
  was preferred over the benchmark reference patch and 69 semantically
  equivalent cases. A second-pass audit confirmed 2,182 RCPatch-preferred cases
  and 69 equivalent cases, with only two ARVO cases rejected or unsupported.
- **Magma:** On all 138 Magma vulnerabilities, RCPatch matched the reference
  repair semantics in 104 cases, produced a stronger source-level repair in 20
  cases, was incomplete or reference-worse in 13 cases, and left one case
  outside the claim taxonomy. RCPatch therefore matched or improved the reference
  repair in 124 of 138 cases, about 90%, under the evaluation taxonomy.
- **Patch materialization:** After refinement, 115 of 138 generated Magma diffs
  were applicable source patches; 113 passed `diff --check`.
- **Compile validation:** Among the 115 materialized Magma patches, 112 had
  buildable unpatched baselines and 95 RCPatch-patched versions compiled after
  compile-guided refinement.
- **Same-testcase behavior evidence:** Seven Magma cases additionally showed
  observed-signature disappearance on the same testcase.
- **Ablation:** Removing the causality chain reduced performance, while a
  trigger-site patch baseline dropped to 65.2% on Magma, supporting the value
  of root-cause-to-trigger reasoning.

These numbers are artifact context, not standalone proof of patch correctness.
RCPatch reports semantic, materialization, and validation evidence separately.
Compact sanitized result files are included under `results/`.

## Repository Layout

```text
src/rcpatch/
  models/           Pydantic data models and JSON contracts
  ingestion/        Bug-spec loading and evidence normalization
  dynamic_analysis/ ASan-like sanitizer and stack trace parsing
  source/           C/C++ source abstraction and parser backends
  slicing/          Trigger-guided backward slicing
  ranking/          Candidate features, scoring, and priors
  chains/           Causality-chain search and formatting
  patch_analysis/   Patch parsing and weak-supervision refinement
  llm/              Optional OpenAI-compatible semantic interpretation
  validation/       Patch/build/reproducer validation harness
  pipeline.py       End-to-end orchestration
  cli.py            rcpatch command-line interface

scripts/            Reproduction, CVE-mining, ARVO, and Magma drivers
examples/           JSON schema-shape inputs and output examples
tests/              Unit tests for core components and scripts
data/               CVE-derived root-cause dataset and pattern library
results/            Sanitized summaries and compressed experiment results
reproduce_openssl_sm2_case/
                    Small SM2-style regression example
```

## Dependencies

Required:

- Python `>=3.9`
- `pydantic>=2.7,<3`
- `git` for patch validation and benchmark helpers

Recommended for development:

- `pytest`

Optional:

- `ctags`, `clang`, or tree-sitter-related tooling for richer source parsing.
  RCPatch falls back to regex/heuristic parsing when these are unavailable.
- An OpenAI-compatible API key for optional LLM-assisted interpretation:
  `RCPATCH_OPENAI_API_KEY`, legacy `BUGRC_OPENAI_API_KEY`, or `OPENAI_API_KEY`.

## Installation

```bash
git clone https://github.com/YunlongXing/RCPatch.git
cd RCPatch
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -e .
python3 -m pip install pytest
```

Run the tests:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

## Basic Usage

RCPatch exposes a `rcpatch` command after installation. The legacy `bugrc`
entry point remains available for older scripts:

```bash
rcpatch ingest examples/bug_report.example.json --output-dir out/ingest
rcpatch rank examples/bug_report.example.json --parser-backend regex --top-k 3 --output-dir out/rank
rcpatch analyze examples/bug_report.example.json --config examples/analysis_config.example.json --output-dir out/analyze
rcpatch explain examples/bug_report.example.json --output-dir out/explain
rcpatch export examples/bug_report.example.json --patch-aware --output-dir out/export
rcpatch suggest-patch examples/bug_report.example.json --output-dir out/patches
rcpatch validate-patch --repo /path/to/repo --patch fix.diff --build-cmd "make -j2" --output-dir out/validate
```

Useful options:

- `--parser-backend`: `tree_sitter`, `clang_ast`, `ctags`, or `regex`.
- `--cve-pattern-library`: use a mined historical CVE pattern library as a weak
  ranking prior.
- `--ranker-calibration`: load benchmark-derived score weights and feature
  boosts.
- `--project-prior`: load project-specific pattern priors mined from curated
  results.
- `--llm/--no-llm`: enable or disable optional semantic interpretation.
- `--llm-model`: OpenAI-compatible model name when LLM mode is enabled.

## Priors

### CVE Pattern Prior

Historical CVE mining outputs can be used directly by the normal RCPatch
pipeline:

```bash
rcpatch analyze examples/bug_report.example.json \
  --parser-backend regex \
  --cve-pattern-library data/cve_pattern_library.v4.clean.json \
  --output-dir out/analyze-with-cve-prior
```

The prior is deliberately weak supervision. It does not create new candidates
and does not replace source, patch, or runtime evidence. It only adds
`cve_pattern_prior_*` features and a bounded score contribution when an existing
candidate matches a pattern mined from historical CVEs.

## Benchmark Drivers

### Magma

```bash
python3 scripts/magma_bugrc_eval.py \
  --magma-root /path/to/magma \
  --output-dir out/magma \
  --dry-run
```

```bash
python3 scripts/magma_bugrc_eval.py \
  --magma-root /path/to/magma \
  --output-dir out/magma-full \
  --ranker-calibration out/arvo-priors/arvo_ranker_calibration.json \
  --project-prior out/arvo-priors/arvo_project_prior.json
```

The runner writes `magma_manifest.json`, `results.jsonl`, and `summary.json`.
It materializes a buggy-only source view so RCPatch cannot inspect the fixed
branch during patch generation; Magma patches are used only during comparison.

### ARVO-Meta

ARVO-Meta is large and is not redistributed here. After obtaining the corpus,
use `scripts/arvo_meta_bugrc_eval.py` with local paths to the report metadata,
reference patches, and repository cache. For example:

```bash
python3 scripts/arvo_meta_bugrc_eval.py \
  --meta-dir /path/to/ARVO-Meta-main/archive_data/meta \
  --patch-dir /path/to/ARVO-Meta-main/archive_data/patches \
  --repos-dir /path/to/arvo/repos \
  --output-dir out/arvo \
  --sample-size 100 \
  --parser-backend regex
```

## Patch Validation

RCPatch includes a lightweight validation harness in `rcpatch.validation`:

```python
from rcpatch.validation import PatchValidationHarness, ValidationCommand

harness = PatchValidationHarness()
result = harness.validate_existing_tree(
    "/path/to/repo",
    commands=[
        ValidationCommand(name="build", command="make -j2", timeout_seconds=30),
        ValidationCommand(name="reproduce", command="./target poc", timeout_seconds=30),
    ],
)
```

`validate_patch_in_copy()` applies a patch inside a temporary repository copy
before running commands. The harness records stdout/stderr tails, timeout
status, per-step duration, and pass/fail state.

## OpenSSL SM2 Regression Example

The `reproduce_openssl_sm2_case/` directory contains a small standalone
SM2-style example derived from the OpenSSL 1.1.1k SM2 decryption buffer-size
bug pattern:

```bash
python3 scripts/run_openssl_sm2_case.py --output-dir out/sm2
python3 scripts/report_openssl_sm2_case.py --output-dir out/sm2-report
```

This example is intentionally small and is meant to exercise the RCPatch pipeline,
not to replace the full OpenSSL build.

## Outputs

Every `ingest`, `rank`, `analyze`, `explain`, and `export` bundle includes:

- `run_manifest.json`: RCPatch version, Python/platform details, effective config,
  input fingerprints, output fingerprints, and stage-level metrics.
- `analysis_result.json`: normalized root-cause candidates, causality chains,
  patch suggestions, and diagnostic metadata.
- `analysis_report.html`: self-contained evidence report for full analysis
  runs.

For concise reports:

```bash
python3 scripts/report_case.py --spec examples/bug_report.example.json --output-dir out/report
python3 scripts/report_case.py --result-json out/analyze/analysis_result.json
```

## Testing

Run all unit tests:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

Run a targeted test:

```bash
PYTHONPATH=src python3 -m unittest tests.test_models
```
