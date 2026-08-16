#!/usr/bin/env python3
"""Run the OpenSSL SM2 RCPatch case and emit a concise top-results report."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
VENDOR_ROOT = PROJECT_ROOT / ".vendor"

if SRC_ROOT.exists():
    sys.path.insert(0, str(SRC_ROOT))
if VENDOR_ROOT.exists():
    sys.path.insert(0, str(VENDOR_ROOT))

from rcpatch.models import AnalysisResult  # noqa: E402
from rcpatch.reporting import build_concise_report, collect_standard_artifacts, render_concise_report  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the OpenSSL 1.1.1k SM2 case and emit a concise RCPatch report.",
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=PROJECT_ROOT / ".tmp" / "report_openssl_sm2_case",
        help="Fresh working directory for the full RCPatch reproduction and exported report.",
    )
    parser.add_argument(
        "--openssl-root",
        type=Path,
        default=None,
        help="Path to an extracted OpenSSL 1.1.1k source tree.",
    )
    parser.add_argument(
        "--openssl-tarball",
        type=Path,
        default=PROJECT_ROOT / ".tmp" / "openssl-1.1.1k.tar.gz",
        help="Path to the OpenSSL 1.1.1k tarball used if --openssl-root is omitted.",
    )
    parser.add_argument(
        "--top-k",
        type=int,
        default=20,
        help="Number of candidates to ask RCPatch to retain internally.",
    )
    parser.add_argument(
        "--max-chains",
        type=int,
        default=10,
        help="Maximum number of chains to ask RCPatch to export internally.",
    )
    parser.add_argument(
        "--report-candidates",
        type=int,
        default=3,
        help="Number of top candidates to keep in the concise report.",
    )
    parser.add_argument(
        "--report-chains",
        type=int,
        default=3,
        help="Number of top chains to keep in the concise report.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        help="Log level forwarded to the underlying RCPatch reproduction script.",
    )
    parser.add_argument(
        "--preserve-work-dir",
        action="store_true",
        help="Preserve the working directory before rerunning the case.",
    )
    return parser.parse_args()


def _build_run_command(args: argparse.Namespace) -> list[str]:
    command = [
        sys.executable,
        str(PROJECT_ROOT / "scripts" / "run_openssl_sm2_case.py"),
        "--work-dir",
        str(args.work_dir),
        "--repo-mode",
        "full",
        "--top-k",
        str(args.top_k),
        "--max-chains",
        str(args.max_chains),
        "--log-level",
        args.log_level,
    ]
    if args.openssl_root is not None:
        command.extend(["--openssl-root", str(args.openssl_root.expanduser().resolve())])
    else:
        command.extend(["--openssl-tarball", str(args.openssl_tarball.expanduser().resolve())])
    if args.preserve_work_dir:
        command.append("--preserve-work-dir")
    return command


def main() -> int:
    args = parse_args()
    work_dir = args.work_dir.expanduser().resolve()

    run_command = _build_run_command(args)
    subprocess.run(run_command, check=True)

    result_path = work_dir / "bugrc-output" / "analysis_result.json"
    spec_path = work_dir / "openssl_sm2_case.json"
    result = AnalysisResult.from_json_file(result_path)
    spec_payload = json.loads(spec_path.read_text(encoding="utf-8"))
    report = build_concise_report(
        result,
        report_candidates=args.report_candidates,
        report_chains=args.report_chains,
        repo_path=spec_payload.get("repo_path"),
        artifacts=collect_standard_artifacts(work_dir / "bugrc-output"),
    )
    report_json_path = work_dir / "bugrc-output" / "openssl_sm2_concise_report.json"
    report_text_path = work_dir / "bugrc-output" / "openssl_sm2_concise_report.txt"
    report_json_path.write_text(f"{json.dumps(report, indent=2)}\n", encoding="utf-8")
    report_text_path.write_text(f"{render_concise_report(report)}\n", encoding="utf-8")

    print(render_concise_report(report))
    print("")
    print(f"Concise JSON report: {report_json_path}")
    print(f"Concise text report: {report_text_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
