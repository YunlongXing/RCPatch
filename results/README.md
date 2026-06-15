# Experiment Results Bundle

This directory contains compact, sanitized result artifacts for auditing BugRC's
main empirical claims. It intentionally excludes raw benchmark corpora, cloned
source trees, build directories, local caches, remote path maps, and non-software
materials.

## Contents

- `latest_full_run/`
  - Compact latest ARVO/Magma full-run summaries and independent second-pass
    semantic audit summary.
  - ARVO-Meta: 4,993 reports attempted, 3,660 completed analyses, 2,184
    first-pass BugRC-preferred patch judgments, and 69 first-pass equivalent
    judgments. The second-pass audit confirmed 2,182 BugRC-preferred ARVO cases
    and 69 equivalent ARVO cases, with two ARVO cases rejected or unsupported.
  - Magma: 138/138 completed; 114 cases matched reference repair semantics, 14
    produced stronger source-level repairs, 9 were incomplete, and 1 remained
    outside the claim taxonomy. BugRC matched or improved the reference repair
    in 128/138 cases under this taxonomy.

- `magma/`
  - Compact Magma summaries and compressed per-case JSONL result archive.
  - `full_138_summary.json` mirrors the latest compact Magma full-run summary.
  - `full_138_results.jsonl.gz` is a compressed earlier 138-case per-case run
    archive retained for inspection; use `latest_full_run/` for the current
    paper-level compact summary.

- `ablation/`
  - Ablation table for Full BugRC, variants without causality chain,
    CVE/pattern prior, project prior, LLM-only root cause, and trigger-site
    baseline.
  - On Magma, Full BugRC reached 94.9% success under the evaluation taxonomy,
    while the trigger-site baseline reached 65.2%.

- `validation/`
  - Patch materialization, diff-check, compile, and targeted dynamic-validation
    summaries.
  - Refined Magma patch materialization applied 115 of 138 generated patches,
    with 113 passing `diff --check`.
  - In the selected 12-case Magma compile set, all base versions compiled and
    11 BugRC-patched versions compiled.

- `external_baselines/`
  - Small Magma-subset compatibility/effectiveness artifacts for external AVR
    baselines, including VulRepair prediction export and CPR/ExtractFix
    applicability assessment.

- `arvo_high_confidence/`
  - Compressed earlier high-confidence ARVO semantic audit subset.
  - Contains 267 records from a curated provenance-audit subset retained for
    representative case inspection. The latest broad second-pass audit summary
    is under `latest_full_run/`.

- `priors/`
  - ARVO-derived project prior, ranker calibration, and prior summary files.
  - These are optional priors for reproducing enhanced ranking configurations.

- `artifact_manifest.json`
  - File-level SHA-256 hashes and byte sizes for the result bundle.

## Reading Compressed Files

```bash
python3 - <<'PY'
import gzip
import json

with gzip.open("results/magma/full_138_results.jsonl.gz", "rt") as handle:
    first_case = json.loads(handle.readline())

print(first_case.keys())
PY
```

## Notes

The result files preserve the evaluation taxonomy and per-case evidence used by
the artifact, but they are not a replacement for rebuilding benchmarks from
their original sources. Large corpora such as ARVO, Magma, CVE mirrors, and
project source checkouts should be obtained separately and supplied to the
scripts in `scripts/`.
