#!/usr/bin/env python3
"""Summarize RCPatch ablation outputs into JSON and Markdown tables."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


VARIANT_LABELS = {
    "full": "Full RCPatch",
    "without_causality_chain": "w/o causality chain",
    "without_cve_pattern_prior": "w/o CVE/pattern prior",
    "without_project_prior": "w/o project prior",
    "llm_only_root_cause": "LLM-only root cause",
    "trigger_site_baseline": "Trigger-site baseline",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path, help="Ablation output root.")
    parser.add_argument("--output-json", type=Path, help="Summary JSON path.")
    parser.add_argument("--output-md", type=Path, help="Markdown table path.")
    args = parser.parse_args()

    root = args.root.expanduser().resolve()
    rows = collect_rows(root)
    output_json = args.output_json.expanduser().resolve() if args.output_json else root / "ablation_summary_table.json"
    output_md = args.output_md.expanduser().resolve() if args.output_md else root / "ablation_summary_table.md"
    output_json.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    output_md.write_text(render_markdown(rows), encoding="utf-8")
    print(f"JSON: {output_json}")
    print(f"Markdown: {output_md}")
    return 0


def collect_rows(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for summary_path in sorted(set(root.glob("*/summary.*.json")) | set(root.glob("*/summary.json"))):
        payload = json.loads(summary_path.read_text(encoding="utf-8"))
        dataset, inferred_variant = infer_dataset_variant(summary_path.parent.name)
        dataset = str(payload.get("dataset") or dataset)
        variant = str(payload.get("variant") or summary_path.stem.removeprefix("summary.") or inferred_variant)
        if variant == "summary":
            variant = inferred_variant
        success_count = int(payload.get("success_count") or infer_success_count(dataset=dataset, payload=payload))
        record_count = int(payload.get("record_count") or 0)
        rows.append(
            {
                "dataset": dataset,
                "variant": variant,
                "variant_label": VARIANT_LABELS.get(variant, variant),
                "records": record_count,
                "success": success_count,
                "success_rate": float(payload.get("success_rate") or (success_count / record_count if record_count else 0.0)),
                "completed": int((payload.get("status_distribution") or {}).get("completed", 0)),
                "failed": int((payload.get("status_distribution") or {}).get("failed", 0)),
                "paper_claim_distribution": payload.get("paper_claim_distribution") or {},
                "semantic_verdict_distribution": payload.get("semantic_verdict_distribution") or {},
                "pseudo_distribution": payload.get("generated_patch_is_pseudo_distribution") or {},
                "summary_path": summary_path.as_posix(),
            }
        )
    rows.sort(key=lambda row: (row["dataset"], variant_order(str(row["variant"]))))
    return rows


def infer_dataset_variant(directory_name: str) -> tuple[str, str]:
    for dataset in ("arvo", "magma"):
        prefix = f"{dataset}_"
        if directory_name.startswith(prefix):
            return dataset, directory_name.removeprefix(prefix)
    return directory_name.split("_", 1)[0], directory_name


def infer_success_count(*, dataset: str, payload: dict[str, Any]) -> int:
    claims = payload.get("paper_claim_distribution") or {}
    verdicts = payload.get("semantic_verdict_distribution") or {}
    if dataset == "magma":
        return int(claims.get("bugrc_matches_ground_truth", 0)) + int(
            claims.get("bugrc_blocks_better_than_magma_reference", 0)
        )
    return int(claims.get("official_incomplete_bugrc_blocks", 0)) or int(verdicts.get("bugrc_patch_better", 0))


def variant_order(variant: str) -> int:
    order = {
        "full": 0,
        "without_causality_chain": 1,
        "without_cve_pattern_prior": 2,
        "without_project_prior": 3,
        "llm_only_root_cause": 4,
        "trigger_site_baseline": 5,
    }
    return order.get(variant, 99)


def render_markdown(rows: list[dict[str, Any]]) -> str:
    lines = [
        "| Dataset | Variant | Records | Completed | Success | Success Rate | Failed | Main Claims |",
        "|---|---|---:|---:|---:|---:|---:|---|",
    ]
    for row in rows:
        claims = ", ".join(f"{key}={value}" for key, value in row["paper_claim_distribution"].items()) or "-"
        lines.append(
            "| {dataset} | {variant} | {records} | {completed} | {success} | {rate:.1%} | {failed} | {claims} |".format(
                dataset=row["dataset"],
                variant=row["variant_label"],
                records=row["records"],
                completed=row["completed"],
                success=row["success"],
                rate=row["success_rate"],
                failed=row["failed"],
                claims=claims,
            )
        )
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
