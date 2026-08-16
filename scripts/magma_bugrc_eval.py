#!/usr/bin/env python3
"""Evaluate RCPatch on Magma as a second real-bug benchmark.

Magma bug patches encode both the vulnerable behavior and the ground-truth
fixed behavior using ``MAGMA_ENABLE_FIXES``. This runner materializes a
buggy-only view before running RCPatch, then compares RCPatch's generated patch
against the Magma ground-truth fix semantics in a separate comparison stage.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
VENDOR_ROOT = PROJECT_ROOT / ".vendor"
SCRIPTS_ROOT = PROJECT_ROOT / "scripts"
if SRC_ROOT.exists():
    sys.path.insert(0, str(SRC_ROOT))
try:
    import pydantic  # noqa: F401
except ImportError:
    pydantic = None  # type: ignore[assignment]
if pydantic is None and VENDOR_ROOT.exists():
    sys.path.insert(0, str(VENDOR_ROOT))
if SCRIPTS_ROOT.exists():
    sys.path.insert(0, str(SCRIPTS_ROOT))

from arvo_meta_bugrc_eval import (  # noqa: E402
    DEFAULT_MODEL,
    LLMResult,
    build_initial_root_cause_prompt,
    build_patch_generation_prompt,
    call_json_llm,
    collect_source_snippets,
    infer_bug_type,
    normalize_diff,
    run,
    shorten,
    with_llm_meta,
)
from rcpatch.chains import CausalityChainConstructor  # noqa: E402
from rcpatch.models import (  # noqa: E402
    AnalysisConfig,
    AnalysisResult,
    BugReport,
    EvidenceReference,
    EvidenceKind,
    ParserBackend,
    SourceLocation,
    TriggerPoint,
    TriggerType,
)
from rcpatch.patch_generation import PatchSuggestionGenerator  # noqa: E402
from rcpatch.ranking import RootCauseCandidateExtractor  # noqa: E402
from rcpatch.source import SourceProjectParser  # noqa: E402
from rcpatch.slicing import HybridBackwardSlicer  # noqa: E402


C_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx", ".ipp", ".inl"}


@dataclass(frozen=True)
class MagmaCase:
    """A normalized Magma bug case discovered from target patches."""

    bug_id: str
    target: str
    patch_path: Path
    setup_patches: tuple[Path, ...]
    repo_url: str
    base_ref: str
    touched_files: tuple[str, ...]
    affected_functions: tuple[str, ...]
    canary_conditions: tuple[str, ...]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run RCPatch on Magma ground-truth bugs.")
    parser.add_argument("--magma-root", required=True, type=Path, help="Path to the official Magma repository checkout.")
    parser.add_argument("--output-dir", required=True, type=Path, help="Directory for Magma RCPatch artifacts.")
    parser.add_argument("--target-work-dir", type=Path, help="Working directory for fetched Magma target repositories.")
    parser.add_argument("--target", action="append", default=[], help="Magma target name to include. May be repeated.")
    parser.add_argument("--case-list-file", type=Path, help="Optional JSON/TXT list of Magma bug IDs to process.")
    parser.add_argument("--sample-size", type=int, default=None, help="Optional random sample size. Default: all cases.")
    parser.add_argument("--seed", type=int, default=20260602)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--api-base-url", default=os.getenv("RCPATCH_LLM_BASE_URL", os.getenv("BUGRC_LLM_BASE_URL", "https://api.openai.com/v1")))
    parser.add_argument("--llm-timeout", type=int, default=45)
    parser.add_argument("--git-timeout", type=int, default=180)
    parser.add_argument("--case-timeout", type=int, default=300)
    parser.add_argument("--max-source-files", type=int, default=700)
    parser.add_argument("--max-snippet-chars", type=int, default=14000)
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--force", action="store_true", help="Reprocess completed cases.")
    parser.add_argument("--dry-run", action="store_true", help="Only write the discovered manifest.")
    parser.add_argument("--cve-pattern-library", help="Optional RCPatch CVE pattern library JSON.")
    parser.add_argument("--ranker-calibration", help="Optional RCPatch ranker calibration JSON.")
    parser.add_argument("--project-prior", help="Optional RCPatch project prior JSON.")
    parser.add_argument("--expert-rca-prior", help="Optional expert RCA prior JSON, e.g., Project Zero RCA patterns.")
    parser.add_argument("--expert-rca-min-confidence", type=float, default=0.0)
    parser.add_argument("--expert-rca-weight", type=float, default=0.06)
    parser.add_argument(
        "--include-bugrc-patch-suggestions",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Include RCPatch's conservative patch suggestions in patch-generation evidence.",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    magma_root = args.magma_root.expanduser().resolve()
    output_dir = args.output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    target_work_dir = (
        args.target_work_dir.expanduser().resolve() if args.target_work_dir else output_dir / "magma_targets"
    )
    target_work_dir.mkdir(parents=True, exist_ok=True)

    cases = discover_magma_cases(magma_root, include_targets=set(args.target or []))
    cases = filter_cases(cases, case_list_file=args.case_list_file, sample_size=args.sample_size, seed=args.seed)
    write_json(output_dir / "magma_manifest.json", {"seed": args.seed, "case_count": len(cases), "cases": [case_to_dict(c) for c in cases]})
    if args.dry_run:
        print(f"Magma manifest: {output_dir / 'magma_manifest.json'}")
        print(f"Cases: {len(cases)}")
        return 0

    done_ids = set() if args.force else load_done_ids(output_dir / "results.jsonl")
    llm_cache_dir = output_dir / "llm_cache"
    llm_cache_dir.mkdir(exist_ok=True)

    for index, case in enumerate(cases, start=1):
        if case.bug_id in done_ids:
            print(f"[{index}/{len(cases)}] {case.bug_id}: already done", flush=True)
            continue
        print(f"[{index}/{len(cases)}] {case.bug_id}: processing {case.target}", flush=True)
        started = time.time()
        try:
            with case_timeout(args.case_timeout):
                row = process_case(
                    case=case,
                    magma_root=magma_root,
                    target_work_dir=target_work_dir,
                    output_dir=output_dir,
                    llm_cache_dir=llm_cache_dir,
                    args=args,
                )
            row["elapsed_seconds"] = round(time.time() - started, 3)
        except Exception as exc:  # noqa: BLE001 - batch runner should keep going.
            row = {
                "local_id": case.bug_id,
                "bug_id": case.bug_id,
                "target": case.target,
                "status": "failed",
                "error": f"{type(exc).__name__}: {exc}",
                "elapsed_seconds": round(time.time() - started, 3),
            }
        append_jsonl(output_dir / "results.jsonl", row)
        write_summary(output_dir / "results.jsonl", output_dir / "summary.json")
        print(f"[{index}/{len(cases)}] {case.bug_id}: {row.get('status')}", flush=True)

    write_summary(output_dir / "results.jsonl", output_dir / "summary.json")
    print(f"Results: {output_dir / 'results.jsonl'}")
    print(f"Summary: {output_dir / 'summary.json'}")
    return 0


def discover_magma_cases(magma_root: Path, *, include_targets: set[str]) -> list[MagmaCase]:
    targets_root = magma_root / "targets"
    if not targets_root.exists():
        raise FileNotFoundError(f"Magma targets directory not found: {targets_root}")
    cases: list[MagmaCase] = []
    for target_dir in sorted(path for path in targets_root.iterdir() if path.is_dir()):
        target = target_dir.name
        if include_targets and target not in include_targets:
            continue
        bug_patch_dir = target_dir / "patches" / "bugs"
        if not bug_patch_dir.exists():
            continue
        repo_url, base_ref = parse_fetch_script(target_dir / "fetch.sh")
        setup_patches = tuple(sorted((target_dir / "patches" / "setup").glob("*.patch")))
        for patch_path in sorted(bug_patch_dir.glob("*.patch")):
            touched_files, affected_functions, canaries = parse_magma_patch(patch_path)
            cases.append(
                MagmaCase(
                    bug_id=patch_path.stem,
                    target=target,
                    patch_path=patch_path,
                    setup_patches=setup_patches,
                    repo_url=repo_url,
                    base_ref=base_ref,
                    touched_files=tuple(touched_files),
                    affected_functions=tuple(affected_functions),
                    canary_conditions=tuple(canaries),
                )
            )
    return cases


def parse_fetch_script(path: Path) -> tuple[str, str]:
    text = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    repo_url = ""
    base_ref = ""
    clone_match = re.search(r"git\s+clone\s+(?:--no-checkout\s+)?(?P<url>\S+)\s+\\?\s*\n?\s*\"\$TARGET/repo\"", text)
    if clone_match:
        repo_url = clone_match.group("url")
    checkout_match = re.search(r"git\s+-C\s+\"\$TARGET/repo\"\s+checkout\s+(?P<ref>[0-9a-fA-F]{7,40})", text)
    if checkout_match:
        base_ref = checkout_match.group("ref")
    tarball_match = re.search(r"curl\s+\"(?P<url>https?://[^\"]+)\"", text)
    if not repo_url and tarball_match:
        repo_url = tarball_match.group("url")
    return repo_url, base_ref


def parse_magma_patch(path: Path) -> tuple[list[str], list[str], list[str]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    touched_files: list[str] = []
    functions: list[str] = []
    canaries: list[str] = []
    for line in text.splitlines():
        if line.startswith("diff --git "):
            parts = line.split()
            if len(parts) >= 4:
                touched_files.append(parts[3].removeprefix("b/"))
        elif line.startswith("+++ b/"):
            touched_files.append(line.removeprefix("+++ b/"))
        elif line.startswith("@@"):
            function = parse_hunk_function(line)
            if function:
                functions.append(function)
        elif "MAGMA_LOG" in line:
            condition = parse_magma_log_condition(line)
            if condition:
                canaries.append(condition)
    return unique(touched_files), unique(functions), unique(canaries)


def parse_hunk_function(line: str) -> Optional[str]:
    match = re.search(r"@@.*@@\s*(?P<context>.*)$", line)
    if not match:
        return None
    context = match.group("context").strip()
    if not context:
        return None
    before_paren = context.split("(", 1)[0].strip()
    token = before_paren.split()[-1] if before_paren.split() else before_paren
    token = token.strip("*&")
    return token or None


def parse_magma_log_condition(line: str) -> Optional[str]:
    match = re.search(r"MAGMA_LOG\s*\([^,]+,\s*(?P<cond>.*)\)\s*;?", line)
    if not match:
        return None
    condition = match.group("cond").strip()
    if condition.endswith(";"):
        condition = condition[:-1].strip()
    return condition


def filter_cases(
    cases: list[MagmaCase],
    *,
    case_list_file: Optional[Path],
    sample_size: Optional[int],
    seed: int,
) -> list[MagmaCase]:
    selected = list(cases)
    if case_list_file:
        requested = load_case_ids(case_list_file)
        selected = [case for case in selected if case.bug_id in requested or f"{case.target}:{case.bug_id}" in requested]
    if sample_size is not None:
        rng = random.Random(seed)
        selected = rng.sample(selected, min(sample_size, len(selected)))
    return selected


def load_case_ids(path: Path) -> set[str]:
    text = path.expanduser().resolve().read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        payload = json.loads(text)
        raw_items = payload.get("cases", payload) if isinstance(payload, dict) else payload
        ids: set[str] = set()
        for item in raw_items:
            if isinstance(item, dict):
                value = item.get("bug_id") or item.get("local_id") or item.get("id")
                target = item.get("target")
                if value:
                    ids.add(str(value))
                    if target:
                        ids.add(f"{target}:{value}")
            else:
                ids.add(str(item))
        return ids
    return {line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")}


def process_case(
    *,
    case: MagmaCase,
    magma_root: Path,
    target_work_dir: Path,
    output_dir: Path,
    llm_cache_dir: Path,
    args: argparse.Namespace,
) -> dict[str, Any]:
    deadline = time.time() + max(args.case_timeout, 1)
    target_base = prepare_target_base(case, magma_root=magma_root, target_work_dir=target_work_dir, timeout=args.git_timeout)
    worktree_path = prepare_case_worktree(case, target_base=target_base, output_dir=output_dir, timeout=args.git_timeout)
    if time.time() > deadline:
        raise TimeoutError("case timeout after Magma worktree preparation")

    report_text = build_magma_report_text(case)
    meta = {
        "project": case.target,
        "sanitizer": "Magma canary",
        "crash_type": infer_magma_crash_type(case),
        "severity": "ground_truth_bug",
    }
    crash_state = list(case.affected_functions or case.canary_conditions or case.touched_files)

    initial_llm = call_json_llm(
        cache_dir=llm_cache_dir,
        api_base_url=args.api_base_url,
        model=args.model,
        timeout=args.llm_timeout,
        task="magma_initial_root_cause",
        prompt=build_initial_root_cause_prompt(meta, report_text, crash_state),
    )

    selected_files = select_source_files(worktree_path, case, max_files=args.max_source_files)
    bugrc_payload = run_magma_bugrc_analysis(
        case=case,
        meta=meta,
        report_text=report_text,
        crash_state=crash_state,
        repo_path=worktree_path,
        selected_files=selected_files,
        top_k=args.top_k,
        cve_pattern_library=args.cve_pattern_library,
        ranker_calibration=args.ranker_calibration,
        project_prior=args.project_prior,
        expert_rca_prior=args.expert_rca_prior,
        expert_rca_min_confidence=args.expert_rca_min_confidence,
        expert_rca_weight=args.expert_rca_weight,
        include_patch_suggestions=args.include_bugrc_patch_suggestions,
    )
    snippets = collect_source_snippets(worktree_path, bugrc_payload, max_chars=args.max_snippet_chars)

    generated_patch = call_json_llm(
        cache_dir=llm_cache_dir,
        api_base_url=args.api_base_url,
        model=args.model,
        timeout=args.llm_timeout,
        task="magma_generate_patch",
        prompt=build_patch_generation_prompt(meta, report_text, initial_llm.payload, bugrc_payload, snippets),
    )

    reference_patch = case.patch_path.read_text(encoding="utf-8", errors="replace")
    generated_diff = str(generated_patch.payload.get("unified_diff") or "")
    exact_match = bool(generated_diff and normalize_diff(generated_diff) == normalize_diff(reference_patch))
    if exact_match:
        comparison: dict[str, Any] = {"status": "exact_match", "exact_match": True}
    else:
        comparison_llm = call_json_llm(
            cache_dir=llm_cache_dir,
            api_base_url=args.api_base_url,
            model=args.model,
            timeout=args.llm_timeout,
            task="magma_compare_patch",
            prompt=build_magma_patch_comparison_prompt(
                case=case,
                report_text=report_text,
                bugrc_payload=bugrc_payload,
                generated_patch=generated_patch.payload,
                magma_reference_patch=reference_patch,
            ),
        )
        comparison = {"status": "semantic_judged", "exact_match": False, "llm": comparison_llm.payload}

    return {
        "local_id": case.bug_id,
        "bug_id": case.bug_id,
        "target": case.target,
        "status": "completed",
        "repo_url": case.repo_url,
        "base_ref": case.base_ref,
        "magma_patch_path": case.patch_path.as_posix(),
        "pre_fix_worktree": worktree_path.as_posix(),
        "touched_files": list(case.touched_files),
        "affected_functions": list(case.affected_functions),
        "canary_conditions": list(case.canary_conditions),
        "crash_state": crash_state,
        "selected_source_files": selected_files,
        "llm_initial_root_cause": with_llm_meta(initial_llm),
        "bugrc": bugrc_payload,
        "source_snippet_count": len(snippets),
        "generated_patch": with_llm_meta(generated_patch),
        "official_patch_path": case.patch_path.as_posix(),
        "patch_comparison": comparison,
    }


def prepare_target_base(case: MagmaCase, *, magma_root: Path, target_work_dir: Path, timeout: int) -> Path:
    target_copy = target_work_dir / "targets" / case.target
    repo_path = target_copy / "repo"
    marker = target_copy / ".bugrc_base_ready"
    if marker.exists() and repo_path.exists():
        return repo_path

    source_target = magma_root / "targets" / case.target
    if not target_copy.exists():
        copy_target_skeleton(source_target, target_copy)

    env = os.environ.copy()
    env["TARGET"] = target_copy.as_posix()
    env["OUT"] = (target_work_dir / "downloads").as_posix()
    Path(env["OUT"]).mkdir(parents=True, exist_ok=True)
    if not repo_path.exists():
        subprocess.run(["bash", "fetch.sh"], cwd=target_copy, env=env, text=True, check=True, timeout=timeout)

    skipped_setup: list[str] = []
    for setup_patch in sorted((target_copy / "patches" / "setup").glob("*.patch")):
        try:
            apply_magma_patch(repo_path, setup_patch, replacement_name=setup_patch.stem, timeout=timeout)
        except subprocess.CalledProcessError:
            # Setup patches often tweak fuzzing/build harnesses. They are useful
            # but not required for RCPatch's source-level root-cause analysis.
            skipped_setup.append(setup_patch.name)
    ensure_git_snapshot(repo_path, timeout=timeout)
    if skipped_setup:
        (target_copy / ".bugrc_skipped_setup_patches").write_text("\n".join(skipped_setup) + "\n", encoding="utf-8")
    marker.write_text("ready\n", encoding="utf-8")
    return repo_path


def copy_target_skeleton(source: Path, destination: Path) -> None:
    def ignore(_dir: str, names: list[str]) -> set[str]:
        return {name for name in names if name in {"repo", "corpus", "build", "logs"}}

    shutil.copytree(source, destination, ignore=ignore)


def apply_magma_patch(repo_path: Path, patch_path: Path, *, replacement_name: str, timeout: int) -> None:
    payload = patch_path.read_text(encoding="utf-8", errors="replace").replace("%MAGMA_BUG%", replacement_name)
    dry_run = subprocess.run(
        ["patch", "--dry-run", "-p1"],
        cwd=repo_path,
        text=True,
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    if dry_run.returncode != 0:
        raise subprocess.CalledProcessError(
            dry_run.returncode,
            ["patch", "--dry-run", "-p1", patch_path.as_posix()],
            output=dry_run.stdout,
            stderr=dry_run.stderr,
        )
    subprocess.run(
        ["patch", "-p1"],
        cwd=repo_path,
        text=True,
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=True,
    )


def ensure_git_snapshot(repo_path: Path, *, timeout: int) -> None:
    if not (repo_path / ".git").exists():
        run(["git", "init"], cwd=repo_path, timeout=timeout)
    run(["git", "config", "user.email", "bugrc@example.invalid"], cwd=repo_path, timeout=timeout, check=False)
    run(["git", "config", "user.name", "RCPatch"], cwd=repo_path, timeout=timeout, check=False)
    run(["git", "add", "-A"], cwd=repo_path, timeout=timeout)
    status = run(["git", "status", "--porcelain"], cwd=repo_path, timeout=timeout)
    if status.stdout.strip():
        run(["git", "commit", "-m", "RCPatch Magma base snapshot"], cwd=repo_path, timeout=timeout)


def prepare_case_worktree(case: MagmaCase, *, target_base: Path, output_dir: Path, timeout: int) -> Path:
    worktree_path = output_dir / "worktrees" / case.bug_id / case.target
    if worktree_path.exists():
        return worktree_path
    worktree_path.parent.mkdir(parents=True, exist_ok=True)
    run(["git", "worktree", "add", "--detach", worktree_path.as_posix(), "HEAD"], cwd=target_base, timeout=timeout)
    touched_files = set(case.touched_files)
    try:
        apply_magma_patch(worktree_path, case.patch_path, replacement_name=case.bug_id, timeout=timeout)
    except subprocess.CalledProcessError:
        for patch_path in sorted(case.patch_path.parent.glob("*.patch")):
            apply_magma_patch(worktree_path, patch_path, replacement_name=patch_path.stem, timeout=timeout)
            touched, _functions, _canaries = parse_magma_patch(patch_path)
            touched_files.update(touched)
    materialize_magma_buggy_files(worktree_path, sorted(touched_files))
    return worktree_path


def materialize_magma_buggy_files(repo_path: Path, touched_files: Iterable[str]) -> None:
    for rel_path in touched_files:
        path = repo_path / rel_path
        if not path.exists() or path.suffix.lower() not in C_EXTENSIONS:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        path.write_text(materialize_magma_buggy_source(text), encoding="utf-8")


def materialize_magma_buggy_source(text: str) -> str:
    """Remove MAGMA fixed branches and keep vulnerable branches."""

    output: list[str] = []
    stack: list[dict[str, Any]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r"#\s*ifdef\s+MAGMA_ENABLE_FIXES\b", stripped):
            stack.append({"kind": "ifdef_fixes", "else": False})
            continue
        if re.match(r"#\s*ifndef\s+MAGMA_ENABLE_FIXES\b", stripped):
            stack.append({"kind": "ifndef_fixes", "else": False})
            continue
        if re.match(r"#\s*else\b", stripped) and stack and stack[-1]["kind"] in {"ifdef_fixes", "ifndef_fixes"}:
            stack[-1]["else"] = True
            continue
        if re.match(r"#\s*endif\b", stripped) and stack and stack[-1]["kind"] in {"ifdef_fixes", "ifndef_fixes"}:
            stack.pop()
            continue
        if should_keep_magma_line(stack):
            output.append(line)
    trailing_newline = "\n" if text.endswith("\n") else ""
    return "\n".join(output) + trailing_newline


def should_keep_magma_line(stack: list[dict[str, Any]]) -> bool:
    for frame in stack:
        if frame["kind"] == "ifdef_fixes" and not frame["else"]:
            return False
        if frame["kind"] == "ifndef_fixes" and frame["else"]:
            return False
    return True


def select_source_files(repo_path: Path, case: MagmaCase, *, max_files: int) -> list[str]:
    selected: list[str] = []
    for rel_path in case.touched_files:
        path = repo_path / rel_path
        if path.exists() and path.suffix.lower() in C_EXTENSIONS:
            selected.append(rel_path)
    terms = [term for term in list(case.affected_functions) + list(case.canary_conditions) if len(term) >= 3]
    all_files = sorted(
        path.relative_to(repo_path).as_posix()
        for path in repo_path.rglob("*")
        if path.is_file() and path.suffix.lower() in C_EXTENSIONS and ".git" not in path.parts
    )
    for rel_path in all_files:
        if len(selected) >= max_files:
            break
        if rel_path in selected:
            continue
        if not terms:
            selected.append(rel_path)
            continue
        try:
            text = (repo_path / rel_path).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if any(term in text for term in terms):
            selected.append(rel_path)
    return selected[:max_files]


def run_magma_bugrc_analysis(
    *,
    case: MagmaCase,
    meta: dict[str, Any],
    report_text: str,
    crash_state: list[str],
    repo_path: Path,
    selected_files: list[str],
    top_k: int,
    cve_pattern_library: Optional[str],
    ranker_calibration: Optional[str],
    project_prior: Optional[str],
    expert_rca_prior: Optional[str],
    expert_rca_min_confidence: float,
    expert_rca_weight: float,
    include_patch_suggestions: bool,
) -> dict[str, Any]:
    parser = SourceProjectParser()
    program = parser.parse_repository(repo_path, preferred_backend=ParserBackend.REGEX, source_files=selected_files)
    index = parser.build_index(program)
    trigger_location = locate_magma_trigger(index, case)
    diagnostics: list[str] = []
    if trigger_location is None:
        if not program.functions:
            raise RuntimeError("could not locate Magma trigger function and parsed source contains no functions")
        fallback = program.functions[0]
        trigger_location = SourceLocation(
            file=fallback.location.file,
            line=fallback.location.line,
            column=fallback.location.column,
            function=fallback.name,
            snippet=fallback.location.snippet,
        )
        diagnostics.append("Magma hunk function was not found; using first parsed function as approximate trigger.")

    trigger = TriggerPoint(
        location=trigger_location,
        type=TriggerType.CRASH_LINE,
        failing_operation=crash_state[0] if crash_state else None,
        bug_type_hint=infer_bug_type(str(meta.get("crash_type") or "")),
        evidence=[
            EvidenceReference(
                kind=EvidenceKind.USER_HINT,
                path=case.patch_path.as_posix(),
                excerpt="; ".join(case.canary_conditions) or None,
                description="Magma canary conditions and patch hunk used as trigger evidence.",
                metadata={"target": case.target, "bug_id": case.bug_id},
            )
        ],
    )
    config = AnalysisConfig(
        parser_backend=ParserBackend.REGEX,
        top_k_candidates=top_k,
        max_chain_paths=top_k,
        confidence_threshold=0.0,
        bug_type_hint=trigger.bug_type_hint,
        enable_cve_pattern_prior=bool(cve_pattern_library),
        cve_pattern_library_path=cve_pattern_library,
        ranker_calibration_path=ranker_calibration,
        enable_project_prior=bool(project_prior),
        project_prior_path=project_prior,
        enable_expert_rca_prior=bool(expert_rca_prior),
        expert_rca_prior_path=expert_rca_prior,
        expert_rca_prior_min_confidence=expert_rca_min_confidence,
        expert_rca_prior_weight=expert_rca_weight,
    )
    bug_report = BugReport(
        bug_id=f"magma-{case.bug_id}",
        repo_path=repo_path.as_posix(),
        title=f"Magma {case.target} {case.bug_id}",
        summary=shorten(report_text, 3000),
        trigger_point=trigger,
        issue_text=shorten(report_text, 12000),
        config=config,
        metadata={"benchmark": "magma", "target": case.target, "bug_id": case.bug_id},
    )
    slicer = HybridBackwardSlicer(max_interprocedural_hops=4)
    backward_slice = slicer.slice_from_trigger(index, trigger)
    candidates = RootCauseCandidateExtractor().extract_candidates(bug_report, backward_slice, top_k=top_k)
    chains = CausalityChainConstructor().construct_chains(bug_report, candidates, backward_slice, max_chains=top_k)
    patch_suggestions: list[dict[str, Any]] = []
    if include_patch_suggestions:
        analysis_result = AnalysisResult(
            bug_id=bug_report.bug_id,
            trigger_point=trigger,
            root_cause_candidates=candidates,
            chains=chains,
            config=config,
            summary="Magma evaluation analysis result for patch-suggestion evidence.",
            limitations=list(program.approximations) + list(backward_slice.approximations),
            metadata={"benchmark": "magma", "target": case.target, "bug_id": case.bug_id},
        )
        patch_suggestions = [
            suggestion.to_dict()
            for suggestion in PatchSuggestionGenerator().generate(analysis_result, repo_path=repo_path.as_posix())
        ]
    return {
        "trigger": trigger.to_dict(),
        "parsed_files": len(program.files),
        "parsed_functions": len(program.functions),
        "slice_node_count": len(backward_slice.nodes),
        "slice_edge_count": len(backward_slice.edges),
        "candidates": [candidate.to_dict() for candidate in candidates],
        "chains": [chain.to_dict() for chain in chains],
        "patch_suggestions": patch_suggestions,
        "approximations": list(program.approximations) + list(backward_slice.approximations),
        "diagnostics": diagnostics + [diagnostic.to_dict() for diagnostic in program.diagnostics] + list(backward_slice.diagnostics),
    }


def locate_magma_trigger(index: Any, case: MagmaCase) -> Optional[SourceLocation]:
    function_names = set(case.affected_functions)
    touched = set(case.touched_files)
    for function in index.program.functions:
        if function.name in function_names or (function.qualified_name and function.qualified_name in function_names):
            return SourceLocation(
                file=function.location.file,
                line=function.location.line,
                column=function.location.column,
                function=function.name,
                snippet=function.location.snippet,
            )
    for function in index.program.functions:
        if function.location.file in touched:
            return SourceLocation(
                file=function.location.file,
                line=function.location.line,
                column=function.location.column,
                function=function.name,
                snippet=function.location.snippet,
            )
    return None


def build_magma_report_text(case: MagmaCase) -> str:
    return "\n".join(
        [
            f"Magma target: {case.target}",
            f"Magma bug id: {case.bug_id}",
            f"Touched files: {', '.join(case.touched_files) or 'unknown'}",
            f"Affected functions: {', '.join(case.affected_functions) or 'unknown'}",
            f"Canary conditions: {'; '.join(case.canary_conditions) or 'not available'}",
            "",
            "This is a Magma ground-truth vulnerability case. The canary condition marks the vulnerable state.",
            "During patch generation, do not use the Magma ground-truth fixed branch; generate a patch from the buggy source, trigger hints, and RCPatch evidence only.",
        ]
    )


def infer_magma_crash_type(case: MagmaCase) -> str:
    haystack = " ".join(list(case.canary_conditions) + list(case.affected_functions) + list(case.touched_files)).lower()
    if any(token in haystack for token in ("len", "size", "nkey", "memcmp", "memcpy", "strcat", "buffer", "row")):
        return "memory safety / bounds violation"
    if any(token in haystack for token in ("null", "ptr", "pointer")):
        return "null pointer or invalid pointer"
    if any(token in haystack for token in ("free", "alloc", "lifetime")):
        return "lifetime or allocation error"
    return "Magma canary violation"


def build_magma_patch_comparison_prompt(
    *,
    case: MagmaCase,
    report_text: str,
    bugrc_payload: dict[str, Any],
    generated_patch: dict[str, Any],
    magma_reference_patch: str,
) -> str:
    return f"""Compare RCPatch's generated patch against the Magma ground-truth fix semantics.

Magma patch interpretation:
- Lines under #ifdef MAGMA_ENABLE_FIXES represent the ground-truth fixed behavior.
- Lines under #else or #ifndef MAGMA_ENABLE_FIXES represent the vulnerable behavior.
- MAGMA_LOG marks the bug canary condition, not a source-level fix.

Evaluation goal:
- Decide whether RCPatch's patch blocks the same root-cause-to-trigger path as the Magma fixed branch.
- Do not require textual equivalence to Magma instrumentation.
- Prefer patches that repair the root cause, not only silence the canary.

Return JSON with:
{{
  "verdict": "exact_match | semantically_equivalent | magma_reference_better | bugrc_patch_better | both_plausible | both_incomplete | unclear",
  "correct_patch": "magma_reference | bugrc | both | neither | unclear",
  "semantic_similarity": 0.0,
  "bugrc_patch_cuts_bug": true,
  "magma_reference_cuts_bug": true,
  "bugrc_blocks_root_cause_path": true,
  "magma_blocks_root_cause_path": true,
  "root_cause_to_trigger_chain": ["..."],
  "bugrc_cut_point": "...",
  "magma_cut_point": "...",
  "magma_reference_limitation": "none | symptom_only | compensating_guard | incomplete_path_coverage | wrong_location | instrumentation_only | unknown",
  "missed_paths_by_bugrc_patch": ["..."],
  "patch_proof_strength": "strong | moderate | weak | not_proven",
  "paper_claim": "bugrc_matches_ground_truth | bugrc_blocks_better_than_magma_reference | bugrc_incomplete | not_enough_evidence",
  "resource_balance_assessment": "...",
  "reasoning": "...",
  "confidence": 0.0
}}

Magma case:
target={case.target}
bug_id={case.bug_id}
touched_files={list(case.touched_files)}
affected_functions={list(case.affected_functions)}
canary_conditions={list(case.canary_conditions)}

Synthetic bug report:
{shorten(report_text, 5000)}

RCPatch trigger/candidates/chains:
{json.dumps({'trigger': bugrc_payload.get('trigger'), 'candidates': bugrc_payload.get('candidates', [])[:5], 'chains': bugrc_payload.get('chains', [])[:3], 'patch_suggestions': bugrc_payload.get('patch_suggestions', [])[:3]}, ensure_ascii=False)[:12000]}

RCPatch generated patch:
{json.dumps(generated_patch, ensure_ascii=False)[:12000]}

Magma reference patch:
{shorten(magma_reference_patch, 18000)}
"""


@contextlib.contextmanager
def case_timeout(timeout_seconds: int) -> Iterable[None]:
    if timeout_seconds <= 0 or not hasattr(signal, "SIGALRM"):
        yield
        return
    previous_handler = signal.getsignal(signal.SIGALRM)

    def _raise_timeout(_signum: int, _frame: object) -> None:
        raise TimeoutError(f"case exceeded {timeout_seconds} seconds")

    signal.signal(signal.SIGALRM, _raise_timeout)
    signal.alarm(timeout_seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous_handler)


def write_summary(results_path: Path, summary_path: Path) -> None:
    records = load_jsonl(results_path)
    statuses: dict[str, int] = {}
    targets: dict[str, int] = {}
    comparison: dict[str, int] = {}
    verdicts: dict[str, int] = {}
    paper_claims: dict[str, int] = {}
    pseudo: dict[str, int] = {}
    for record in records:
        statuses[str(record.get("status"))] = statuses.get(str(record.get("status")), 0) + 1
        targets[str(record.get("target"))] = targets.get(str(record.get("target")), 0) + 1
        generated = (record.get("generated_patch") or {}).get("payload") or {}
        if generated:
            key = str(generated.get("is_pseudo_patch"))
            pseudo[key] = pseudo.get(key, 0) + 1
        comp = record.get("patch_comparison") or {}
        if comp:
            comparison[str(comp.get("status"))] = comparison.get(str(comp.get("status")), 0) + 1
            llm = comp.get("llm") or {}
            verdict = llm.get("verdict")
            claim = llm.get("paper_claim")
            if verdict:
                verdicts[str(verdict)] = verdicts.get(str(verdict), 0) + 1
            if claim:
                paper_claims[str(claim)] = paper_claims.get(str(claim), 0) + 1
    write_json(
        summary_path,
        {
            "record_count": len(records),
            "status_distribution": statuses,
            "target_distribution": targets,
            "patch_comparison_distribution": comparison,
            "semantic_verdict_distribution": verdicts,
            "paper_claim_distribution": paper_claims,
            "generated_patch_is_pseudo_distribution": pseudo,
            "updated_at_epoch": time.time(),
        },
    )


def case_to_dict(case: MagmaCase) -> dict[str, Any]:
    return {
        "bug_id": case.bug_id,
        "target": case.target,
        "patch_path": case.patch_path.as_posix(),
        "setup_patches": [path.as_posix() for path in case.setup_patches],
        "repo_url": case.repo_url,
        "base_ref": case.base_ref,
        "touched_files": list(case.touched_files),
        "affected_functions": list(case.affected_functions),
        "canary_conditions": list(case.canary_conditions),
    }


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not path.exists():
        return records
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def load_done_ids(path: Path) -> set[str]:
    return {str(record.get("local_id") or record.get("bug_id")) for record in load_jsonl(path) if record.get("status") == "completed"}


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


if __name__ == "__main__":
    raise SystemExit(main())
