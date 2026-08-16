#!/usr/bin/env python3
"""Run RCPatch on the OpenSSL 1.1.1k SM2 decrypt overflow case.

By default this helper points RCPatch at the full extracted OpenSSL tree and
generates a fresh bug specification from scratch. A subset-copy mode remains
available for debugging parser behavior, but it is opt-in and not used by
default.
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import sys
import tarfile
from pathlib import Path
from typing import Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
VENDOR_ROOT = PROJECT_ROOT / ".vendor"

if SRC_ROOT.exists():
    sys.path.insert(0, str(SRC_ROOT))
if VENDOR_ROOT.exists():
    sys.path.insert(0, str(VENDOR_ROOT))

from rcpatch.pipeline import RCPatchPipeline, PipelineOutputManager  # noqa: E402


REQUIRED_OPENSSL_FILES = (
    "crypto/sm2/sm2_crypt.c",
    "crypto/sm2/sm2_pmeth.c",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Reproduce the OpenSSL 1.1.1k SM2 RCPatch case from scratch.",
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=PROJECT_ROOT / ".tmp" / "reproduce_openssl_sm2_case",
        help="Fresh working directory for extraction, generated spec, and RCPatch outputs.",
    )
    parser.add_argument(
        "--openssl-root",
        type=Path,
        default=None,
        help="Path to an extracted OpenSSL 1.1.1k source tree. If omitted, the script can extract from --openssl-tarball.",
    )
    parser.add_argument(
        "--openssl-tarball",
        type=Path,
        default=PROJECT_ROOT / ".tmp" / "openssl-1.1.1k.tar.gz",
        help="Path to an OpenSSL 1.1.1k source tarball used when --openssl-root is not supplied.",
    )
    parser.add_argument(
        "--repo-mode",
        choices=("full", "subset"),
        default="full",
        help="Analyze the full OpenSSL repo or copy a small subset into a temporary repo.",
    )
    parser.add_argument(
        "--subset-repo",
        type=Path,
        default=None,
        help="Directory where the subset repo should be created when --repo-mode=subset. Defaults under --work-dir.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Directory where RCPatch output artifacts should be written. Defaults under --work-dir.",
    )
    parser.add_argument(
        "--spec-path",
        type=Path,
        default=None,
        help="Path for the generated bug-spec JSON. Defaults under --work-dir.",
    )
    parser.add_argument(
        "--top-k",
        type=int,
        default=20,
        help="Number of ranked candidates to keep in the final analysis result.",
    )
    parser.add_argument(
        "--max-chains",
        type=int,
        default=10,
        help="Maximum number of causality chains to export.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        help="RCPatch log level.",
    )
    parser.add_argument(
        "--preserve-work-dir",
        action="store_true",
        help="Do not delete any pre-existing work directory before reproducing the case.",
    )
    return parser.parse_args()


def ensure_openssl_tree(openssl_root: Path, required_files: Iterable[str]) -> None:
    missing = [relative for relative in required_files if not (openssl_root / relative).exists()]
    if missing:
        missing_text = ", ".join(missing)
        raise SystemExit(
            f"OpenSSL tree {openssl_root} is missing required files: {missing_text}\n"
            "Pass --openssl-root with an extracted OpenSSL 1.1.1k source tree."
        )


def prepare_openssl_root(*, work_dir: Path, openssl_root: Path | None, openssl_tarball: Path) -> Path:
    if openssl_root is not None:
        resolved_root = openssl_root.expanduser().resolve()
        if not resolved_root.exists():
            raise SystemExit(f"Provided --openssl-root does not exist: {resolved_root}")
        return resolved_root

    tarball_path = openssl_tarball.expanduser().resolve()
    if not tarball_path.exists():
        raise SystemExit(
            "No --openssl-root was provided and the default tarball was not found.\n"
            f"Expected tarball at: {tarball_path}"
        )

    extract_root = work_dir / "openssl-src"
    extract_root.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tarball_path, "r:gz") as archive:
        archive.extractall(extract_root)

    extracted_dirs = [path for path in extract_root.iterdir() if path.is_dir()]
    if not extracted_dirs:
        raise SystemExit(f"Failed to extract OpenSSL tarball into {extract_root}")

    candidate_roots = sorted(extracted_dirs, key=lambda path: path.name)
    return candidate_roots[0]


def prepare_subset_repo(
    openssl_root: Path,
    subset_repo: Path,
    required_files: Iterable[str],
    *,
    preserve: bool,
) -> None:
    if subset_repo.exists() and not preserve:
        shutil.rmtree(subset_repo)
    subset_repo.mkdir(parents=True, exist_ok=True)

    for relative in required_files:
        source_path = openssl_root / relative
        target_path = subset_repo / relative
        target_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, target_path)


def write_bug_spec(spec_path: Path, repo_path: Path, *, top_k: int, max_chains: int) -> None:
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "bug_id": "openssl_1_1_1k_sm2_decrypt_line355_user",
        "repo_path": str(repo_path),
        "language": "c_cpp",
        "title": "Potential overflow in OpenSSL sm2_decrypt",
        "summary": (
            "The XOR copy in sm2_decrypt may overflow when msg_len derived from the "
            "ciphertext exceeds the effective plaintext output capacity."
        ),
        "trigger_point": {
            "location": {
                "file": "crypto/sm2/sm2_crypt.c",
                "line": 355,
                "function": "sm2_decrypt",
            },
            "type": "first_failing_operation",
            "failing_operation": "ptext_buf[i] = C2[i] ^ msg_mask[i]",
            "bug_type_hint": "buffer_overflow",
        },
        "config": {
            "enable_patch_analysis": False,
            "enable_llm": False,
            "top_k_candidates": top_k,
            "max_chain_paths": max_chains,
            "parser_backend": "regex",
            "bug_type_hint": "buffer_overflow",
            "max_backward_depth": 12,
            "max_interprocedural_hops": 6,
            "confidence_threshold": 0.05,
        },
    }
    spec_path.write_text(f"{json.dumps(payload, indent=2)}\n", encoding="utf-8")


def find_candidate_by_location(result, relative_file: str, line: int):
    for candidate in result.root_cause_candidates:
        if candidate.location.file == relative_file and candidate.location.line == line:
            return candidate
    return None


def print_candidate(prefix: str, candidate) -> None:
    if candidate is None:
        print(f"{prefix}: not present in the exported top-k result")
        return
    print(
        f"{prefix}: rank={candidate.rank} score={candidate.score:.3f} "
        f"label={candidate.label.value} location={candidate.location.file}:{candidate.location.line}"
    )
    print(f"  {candidate.explanation}")


def main() -> int:
    args = parse_args()

    work_dir = args.work_dir.expanduser().resolve()
    if work_dir.exists() and not args.preserve_work_dir:
        shutil.rmtree(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)

    subset_repo = (
        args.subset_repo.expanduser().resolve() if args.subset_repo else work_dir / "openssl-sm2-subset"
    ).resolve()
    output_dir = (args.output_dir.expanduser().resolve() if args.output_dir else work_dir / "bugrc-output").resolve()
    spec_path = (args.spec_path.expanduser().resolve() if args.spec_path else work_dir / "openssl_sm2_case.json").resolve()
    openssl_root = prepare_openssl_root(
        work_dir=work_dir,
        openssl_root=args.openssl_root,
        openssl_tarball=args.openssl_tarball,
    )

    ensure_openssl_tree(openssl_root, REQUIRED_OPENSSL_FILES)
    analysis_repo = openssl_root
    if args.repo_mode == "subset":
        prepare_subset_repo(openssl_root, subset_repo, REQUIRED_OPENSSL_FILES, preserve=True)
        analysis_repo = subset_repo

    write_bug_spec(spec_path, analysis_repo, top_k=args.top_k, max_chains=args.max_chains)
    output_dir.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )

    pipeline = RCPatchPipeline()
    output_manager = PipelineOutputManager()

    artifacts = pipeline.run_analysis(
        spec_path,
        config_overrides={
            "top_k_candidates": args.top_k,
            "max_chain_paths": args.max_chains,
        },
    )
    summary_text = pipeline.format_result_summary(
        artifacts.analysis_result,
        max_candidates=min(args.top_k, 5),
        max_chains=min(args.max_chains, 3),
    )
    exported = output_manager.export_analysis(output_dir, artifacts, summary_text=summary_text)

    result = artifacts.analysis_result
    if result is None:
        raise SystemExit("RCPatch did not produce an analysis result.")

    print(summary_text)
    print("")
    print("Sanity-check locations:")
    print_candidate(
        "  likely sizing write site",
        find_candidate_by_location(result, "crypto/sm2/sm2_crypt.c", 86),
    )
    print_candidate(
        "  likely sizing formula site",
        find_candidate_by_location(result, "crypto/sm2/sm2_crypt.c", 80),
    )
    print_candidate(
        "  likely caller-side guard site",
        find_candidate_by_location(result, "crypto/sm2/sm2_pmeth.c", 153),
    )
    print_candidate(
        "  trigger symptom",
        find_candidate_by_location(result, "crypto/sm2/sm2_crypt.c", 355),
    )

    print("")
    print(f"Bug spec: {spec_path}")
    print(f"Work dir: {work_dir}")
    print(f"OpenSSL source: {openssl_root}")
    print(f"Repo mode: {args.repo_mode}")
    print(f"Analysis repo: {analysis_repo}")
    if args.repo_mode == "subset":
        print(f"Subset repo: {subset_repo}")
    for name, path in sorted(exported.items()):
        print(f"{name}: {path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
