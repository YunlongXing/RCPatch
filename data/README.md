# CVE-Derived Root-Cause Data

This directory contains the compact CVE-derived artifacts used by RCPatch as
weak priors for root-cause ranking.

## Files

- `cve_pattern_library.v4.clean.json`
  - Reusable root-cause pattern library.
  - Contains 84 patterns mined from validated CVE root-cause annotations.
  - Intended for direct use with `rcpatch analyze --cve-pattern-library`.

- `cve_pattern_library.v4.clean.summary.json`
  - Build summary for the pattern library.
  - Includes pattern counts, category distribution, operation distribution,
    support metadata, and top patterns.

- `cve_root_cause_dataset.v4.json.gz`
  - Compressed CVE root-cause annotation dataset.
  - Contains 2,177 CVE-level records.
  - The uncompressed JSON has schema `bugrc.cve_root_cause_dataset.v4`.
    The legacy schema prefix is retained for compatibility.
  - The current v4 build retains 5,285 root-cause annotations for pattern
    construction after filtering low-quality or unknown-pattern records.

## Scope

The dataset is built from public CVE/advisory metadata, fixing patches, source
analysis, heuristic root-cause mining, and LLM-assisted semantic validation.
It is not a perfect hand-labeled ground truth corpus. RCPatch uses it as weak
supervision: patterns can boost candidates already recovered from the analyzed
program, but they cannot create new source locations or dependency edges.

Current compact counts:

- CVE-level records: 2,177
- Retained root-cause annotations used by the pattern builder: 5,285
- Generalized patterns: 84
- Top categories: validation/guard issues, incorrect size computations,
  invalid state updates, invalid initialization, and ownership/lifetime
  operations.

## Usage

Use the pattern library as a ranking prior:

```bash
rcpatch analyze path/to/bug.json \
  --parser-backend regex \
  --cve-pattern-library data/cve_pattern_library.v4.clean.json \
  --output-dir out/with-cve-prior
```

Inspect the compressed dataset:

```bash
python3 - <<'PY'
import gzip
import json

with gzip.open("data/cve_root_cause_dataset.v4.json.gz", "rt") as handle:
    data = json.load(handle)

print(data["metadata"]["schema_version"])
print(len(data["records"]))
PY
```

## Reproducibility Notes

Large intermediate data, cloned source repositories, raw CVE mirrors, and local
cache directories are intentionally not committed. The scripts in `scripts/`
provide the collection, source-validation, refinement, validation, and pattern
construction pipeline for rebuilding or extending these artifacts from external
CVE and project sources.
