#!/usr/bin/env python3
"""Prepare ARVO full-run manifests for the enhanced RCPatch evaluator."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--meta-dir", required=True, help="Directory containing ARVO-Meta JSON files.")
    parser.add_argument("--output-root", required=True, help="Enhanced ARVO output root.")
    parser.add_argument("--shards", type=int, default=12, help="Number of worker manifests to create.")
    parser.add_argument("--resume-results", action="append", default=[], help="Existing results.jsonl to skip completed ids.")
    args = parser.parse_args()

    meta_dir = Path(args.meta_dir).expanduser().resolve()
    output_root = Path(args.output_root).expanduser().resolve()
    manifest_dir = output_root / "manifests"
    manifest_dir.mkdir(parents=True, exist_ok=True)

    done = load_done_ids([Path(path).expanduser().resolve() for path in args.resume_results])
    meta_files = sorted(meta_dir.glob("*.json"), key=lambda path: int(path.stem) if path.stem.isdigit() else path.stem)
    cases = [
        {"local_id": path.stem, "meta_path": path.as_posix()}
        for path in meta_files
        if path.stem not in done
    ]

    for index in range(args.shards):
        shard_cases = cases[index :: args.shards]
        payload = {
            "source_meta_dir": meta_dir.as_posix(),
            "shard_index": index,
            "shard_count": args.shards,
            "skipped_completed_count": len(done),
            "case_count": len(shard_cases),
            "cases": shard_cases,
        }
        (manifest_dir / f"shard_{index:02d}.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    summary = {
        "meta_count": len(meta_files),
        "skipped_completed_count": len(done),
        "scheduled_count": len(cases),
        "shard_count": args.shards,
    }
    (output_root / "shard_plan.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    for path in sorted(manifest_dir.glob("shard_*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        print(f"{path.name}: {payload['case_count']}")
    return 0


def load_done_ids(paths: list[Path]) -> set[str]:
    done: set[str] = set()
    for path in paths:
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if payload.get("local_id") and payload.get("status") == "completed":
                done.add(str(payload["local_id"]))
    return done


if __name__ == "__main__":
    raise SystemExit(main())
