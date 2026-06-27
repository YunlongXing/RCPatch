#!/usr/bin/env bash
set -euo pipefail

# Run the expanded Magma experiments used to strengthen the paper evaluation.
#
# This script is intended to run on the machine that holds the Magma worktrees
# referenced by the BugRC result JSONL files.  The defaults match the historical
# /home/dragon/bugrc-data layout, but every path can be overridden with an
# environment variable.

PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

BUGRC_DATA_ROOT="${BUGRC_DATA_ROOT:-/home/dragon/bugrc-data}"
MAGMA_ROOT="${MAGMA_ROOT:-${BUGRC_DATA_ROOT}/magma/magma}"
TARGET_WORK_DIR="${TARGET_WORK_DIR:-${BUGRC_DATA_ROOT}/magma/target_work}"
MAGMA_RESULTS_JSONL="${MAGMA_RESULTS_JSONL:-${BUGRC_DATA_ROOT}/magma/bugrc_magma_full_138_20260602/results.jsonl}"
MATERIALIZATION_JSONL="${MATERIALIZATION_JSONL:-${BUGRC_DATA_ROOT}/paper_experiments/validation/magma_patch_applicability_refined_full_20260606/validation_results.jsonl}"

RUN_STAMP="${RUN_STAMP:-$(date +%Y%m%d_%H%M%S)}"
PAPER_EXPERIMENTS_ROOT="${PAPER_EXPERIMENTS_ROOT:-${BUGRC_DATA_ROOT}/paper_experiments}"
EXTERNAL_OUTPUT_DIR="${EXTERNAL_OUTPUT_DIR:-${PAPER_EXPERIMENTS_ROOT}/external_baselines_magma_full_138_${RUN_STAMP}}"
COMPILE_OUTPUT_DIR="${COMPILE_OUTPUT_DIR:-${PAPER_EXPERIMENTS_ROOT}/validation/magma_compile_materialized_115_${RUN_STAMP}}"

RUN_EXTERNAL="${RUN_EXTERNAL:-1}"
RUN_COMPILE="${RUN_COMPILE:-1}"
RUN_VULREPAIR="${RUN_VULREPAIR:-1}"
PULL_CPR_DOCKER="${PULL_CPR_DOCKER:-0}"
VULREPAIR_PYTHON="${VULREPAIR_PYTHON:-${BUGRC_DATA_ROOT}/external_baselines_magma_20260603/vulrepair_venv/bin/python}"

mkdir -p "${PAPER_EXPERIMENTS_ROOT}/logs"
LOG_PATH="${LOG_PATH:-${PAPER_EXPERIMENTS_ROOT}/logs/expanded_magma_${RUN_STAMP}.log}"

echo "[BugRC] project root: ${PROJECT_ROOT}" | tee -a "${LOG_PATH}"
echo "[BugRC] output external: ${EXTERNAL_OUTPUT_DIR}" | tee -a "${LOG_PATH}"
echo "[BugRC] output compile: ${COMPILE_OUTPUT_DIR}" | tee -a "${LOG_PATH}"

if [[ "${RUN_EXTERNAL}" == "1" ]]; then
  external_args=(
    "${PROJECT_ROOT}/scripts/run_magma_external_baselines.py"
    --magma-results "${MAGMA_RESULTS_JSONL}"
    --output-dir "${EXTERNAL_OUTPUT_DIR}"
    --all-cases
  )
  if [[ "${RUN_VULREPAIR}" == "1" ]]; then
    external_args+=(--run-vulrepair --python "${VULREPAIR_PYTHON}")
  fi
  if [[ "${PULL_CPR_DOCKER}" == "1" ]]; then
    external_args+=(--pull-cpr-docker)
  fi
  echo "[BugRC] running full-138 external baseline audit" | tee -a "${LOG_PATH}"
  "${PYTHON_BIN}" "${external_args[@]}" 2>&1 | tee -a "${LOG_PATH}"
fi

if [[ "${RUN_COMPILE}" == "1" ]]; then
  echo "[BugRC] running materialized-patch compile validation" | tee -a "${LOG_PATH}"
  "${PYTHON_BIN}" "${PROJECT_ROOT}/scripts/validate_magma_compile_core_cases.py" \
    --magma-root "${MAGMA_ROOT}" \
    --magma-results-jsonl "${MAGMA_RESULTS_JSONL}" \
    --materialization-jsonl "${MATERIALIZATION_JSONL}" \
    --target-work-dir "${TARGET_WORK_DIR}" \
    --output-dir "${COMPILE_OUTPUT_DIR}" \
    --selection-mode materialized \
    --case-timeout "${CASE_TIMEOUT:-3600}" \
    --build-timeout "${BUILD_TIMEOUT:-2400}" \
    --git-timeout "${GIT_TIMEOUT:-180}" \
    2>&1 | tee -a "${LOG_PATH}"
fi

echo "[BugRC] done" | tee -a "${LOG_PATH}"
echo "[BugRC] log: ${LOG_PATH}" | tee -a "${LOG_PATH}"
