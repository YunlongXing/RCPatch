#!/usr/bin/env python3
"""Compile-validate materialized RCPatch patches on Magma cases.

The patch-materialization pass proves that RCPatch's generated repair can be
placed into a source tree.  This script adds the next evidence layer by
rebuilding the target before and after the materialized RCPatch patch.  Results
distinguish environment/base-build failures from genuine patch-induced compile
failures.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = PROJECT_ROOT / "scripts"
if SCRIPTS_ROOT.exists():
    sys.path.insert(0, str(SCRIPTS_ROOT))

def load_patch_validator() -> Any:
    path = SCRIPTS_ROOT / "validate_magma_patch_applicability.py"
    spec = importlib.util.spec_from_file_location("validate_magma_patch_applicability", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load patch validator from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


patch_validator = load_patch_validator()


C_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx", ".ipp", ".inl"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--magma-root", required=True, type=Path)
    parser.add_argument("--magma-results-jsonl", required=True, type=Path)
    parser.add_argument("--materialization-jsonl", required=True, type=Path)
    parser.add_argument("--target-work-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--case-timeout", type=int, default=3600)
    parser.add_argument("--build-timeout", type=int, default=2400)
    parser.add_argument("--git-timeout", type=int, default=180)
    parser.add_argument("--max-cases", type=int, default=None)
    parser.add_argument("--case-id", action="append", default=None, help="Restrict validation to one or more local IDs.")
    parser.add_argument(
        "--case-list-file",
        type=Path,
        help="Optional JSON/TXT/JSONL file containing case IDs to validate.",
    )
    parser.add_argument(
        "--selection-mode",
        choices=("better", "materialized", "matches", "all"),
        default="better",
        help=(
            "Case selection policy. 'better' reproduces the original core-claim run; "
            "'materialized' compiles every materialized RCPatch patch; 'matches' compiles "
            "materialized matches/equivalent cases; 'all' includes materialized and "
            "non-materialized cases so patch materialization failures are counted."
        ),
    )
    parser.add_argument(
        "--paper-claim",
        action="append",
        default=None,
        help="Restrict to one or more paper_claim values after applying selection-mode.",
    )
    parser.add_argument(
        "--require-diff-check",
        action="store_true",
        help="Only select materialized patches whose git diff --check returncode is 0.",
    )
    parser.add_argument(
        "--select-only",
        action="store_true",
        help="Write selected_cases.json and exit without building cases.",
    )
    parser.add_argument(
        "--compile-refinement-mode",
        choices=("off", "conservative", "llm", "conservative_then_llm"),
        default="off",
        help="Try conservative compiler-error-guided source edits after a RCPatch patch compile failure.",
    )
    parser.add_argument(
        "--compile-refinement-passes",
        type=int,
        default=1,
        help="Maximum conservative compile-refinement attempts per case.",
    )
    parser.add_argument("--llm-model", default=os.getenv("RCPATCH_LLM_MODEL", os.getenv("BUGRC_LLM_MODEL", "gpt-4.1-mini")))
    parser.add_argument("--llm-base-url", default=os.getenv("RCPATCH_LLM_BASE_URL", os.getenv("BUGRC_LLM_BASE_URL", "https://api.openai.com/v1")))
    parser.add_argument("--llm-timeout", type=int, default=90)
    parser.add_argument(
        "--llm-cache-dir",
        type=Path,
        help="Cache directory for compile-guided LLM refinement calls. Defaults to <output-dir>/llm_compile_refinement_cache.",
    )
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--keep-worktrees", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    results_path = args.output_dir / "compile_results.jsonl"
    selected = select_core_cases(
        magma_results=args.magma_results_jsonl,
        materialization_results=args.materialization_jsonl,
        max_cases=args.max_cases,
        case_ids=collect_case_ids(args),
        selection_mode=args.selection_mode,
        paper_claims=set(args.paper_claim or []),
        require_diff_check=args.require_diff_check,
    )
    write_json(
        args.output_dir / "selected_cases.json",
        {
            "count": len(selected),
            "selection_mode": args.selection_mode,
            "paper_claims": sorted(set(args.paper_claim or [])),
            "require_diff_check": args.require_diff_check,
            "case_list_file": args.case_list_file.as_posix() if args.case_list_file else None,
            "compile_refinement_mode": args.compile_refinement_mode,
            "compile_refinement_passes": args.compile_refinement_passes,
            "llm_model": args.llm_model,
            "cases": selected,
        },
    )
    if args.select_only:
        print(f"Selected {len(selected)} cases")
        print(f"Selection: {args.output_dir / 'selected_cases.json'}")
        return 0
    done = set() if args.force else load_done_ids(results_path)
    cases_by_id = {
        str(row.get("local_id") or row.get("bug_id")): row
        for row in load_jsonl(args.magma_results_jsonl)
        if row.get("status") == "completed"
    }

    for index, selected_case in enumerate(selected, start=1):
        case_id = str(selected_case["local_id"])
        if case_id in done:
            print(f"[{index}/{len(selected)}] {case_id}: already done", flush=True)
            continue
        started = time.time()
        print(f"[{index}/{len(selected)}] {case_id}: compile validating", flush=True)
        try:
            row = validate_case(selected_case, cases_by_id[case_id], args)
            row["status"] = "completed"
        except Exception as exc:  # noqa: BLE001 - keep the batch moving.
            row = {
                "local_id": case_id,
                "target": selected_case.get("target"),
                "status": "failed",
                "error": f"{type(exc).__name__}: {exc}",
            }
        row["elapsed_seconds"] = round(time.time() - started, 3)
        append_jsonl(results_path, row)
        write_summary(results_path, args.output_dir / "compile_summary.json")
        print(f"[{index}/{len(selected)}] {case_id}: {row.get('conclusion')}", flush=True)

    write_summary(results_path, args.output_dir / "compile_summary.json")
    print(f"Results: {results_path}")
    print(f"Summary: {args.output_dir / 'compile_summary.json'}")
    return 0


def select_core_cases(
    *,
    magma_results: Path,
    materialization_results: Path,
    max_cases: int | None,
    case_ids: set[str] | None = None,
    selection_mode: str,
    paper_claims: set[str] | None = None,
    require_diff_check: bool = False,
) -> list[dict[str, Any]]:
    materialization_by_id = {str(row.get("local_id")): row for row in load_jsonl(materialization_results)}
    selected: list[dict[str, Any]] = []
    for row in load_jsonl(magma_results):
        case_id = str(row.get("local_id") or row.get("bug_id"))
        if case_ids and case_id not in case_ids:
            continue
        mat = materialization_by_id.get(case_id)
        if not mat:
            continue
        patch_apply = mat.get("patch_apply") or {}
        paper_claim = str(mat.get("paper_claim") or (((row.get("patch_comparison") or {}).get("llm") or {}).get("paper_claim") or ""))
        if paper_claims and paper_claim not in paper_claims:
            continue
        applied = patch_apply.get("applied") is True
        if require_diff_check and str(patch_apply.get("diff_check_returncode")) != "0":
            continue
        if selection_mode == "better" and paper_claim != "bugrc_blocks_better_than_magma_reference":
            continue
        if selection_mode == "matches" and paper_claim != "bugrc_matches_ground_truth":
            continue
        if selection_mode in {"better", "matches", "materialized"} and not applied:
            continue
        selected.append(
            {
                "local_id": case_id,
                "bug_id": row.get("bug_id"),
                "target": row.get("target"),
                "semantic_verdict": ((row.get("patch_comparison") or {}).get("llm") or {}).get("verdict"),
                "paper_claim": paper_claim,
                "materialized": applied,
                "materialization_method": (mat.get("patch_apply") or {}).get("applied_method"),
                "materialization_reason": (mat.get("patch_apply") or {}).get("reason"),
                "materialization_diff_check_returncode": (mat.get("patch_apply") or {}).get("diff_check_returncode"),
                "materialized_changed_files": (mat.get("patch_apply") or {}).get("changed_files"),
            }
        )
    selected.sort(key=lambda item: (str(item.get("target")), str(item.get("local_id"))))
    return selected[:max_cases] if max_cases is not None else selected


def collect_case_ids(args: argparse.Namespace) -> set[str]:
    case_ids = set(args.case_id or [])
    if not args.case_list_file:
        return case_ids
    if not args.case_list_file.exists():
        raise FileNotFoundError(f"case list file not found: {args.case_list_file}")
    text = args.case_list_file.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return case_ids
    if args.case_list_file.suffix.lower() == ".json":
        payload = json.loads(text)
        if isinstance(payload, list):
            for item in payload:
                if isinstance(item, str):
                    case_ids.add(item)
                elif isinstance(item, dict):
                    case_ids.add(str(item.get("local_id") or item.get("bug_id") or item.get("id")))
        elif isinstance(payload, dict):
            for item in payload.get("cases") or payload.get("case_ids") or []:
                if isinstance(item, str):
                    case_ids.add(item)
                elif isinstance(item, dict):
                    case_ids.add(str(item.get("local_id") or item.get("bug_id") or item.get("id")))
        return {case_id for case_id in case_ids if case_id and case_id != "None"}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            item = json.loads(line)
            case_ids.add(str(item.get("local_id") or item.get("bug_id") or item.get("id")))
        else:
            case_ids.add(line.split()[0])
    return {case_id for case_id in case_ids if case_id and case_id != "None"}


def validate_case(selected: dict[str, Any], case: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    case_id = str(case.get("local_id") or case.get("bug_id"))
    target = str(case.get("target"))
    case_dir = args.output_dir / "cases" / case_id
    if args.force and case_dir.exists():
        shutil.rmtree(case_dir)
    case_dir.mkdir(parents=True, exist_ok=True)

    target_base = args.target_work_dir / "targets" / target / "repo"
    source_worktree, setup_patch_results = prepare_buggy_source_tree(
        case=case,
        target_base=target_base,
        source_target=args.target_work_dir / "targets" / target,
        destination=case_dir / "buggy_source",
        timeout=args.git_timeout,
    )

    base_repo = clone_source_tree(source_worktree, case_dir / "base_repo")
    bugrc_repo = clone_source_tree(source_worktree, case_dir / "bugrc_repo")
    patch_path = case_dir / "bugrc_generated.patch"
    generated = generated_patch_by_id(args.magma_results_jsonl, case_id)
    patch_path.write_text(generated, encoding="utf-8")

    patch_apply = patch_validator.apply_patch(
        bugrc_repo,
        patch_path,
        args.git_timeout,
        allow_fuzzy=True,
        allow_refinement=True,
        refinement_window_lines=120,
    )
    if patch_apply.get("applied"):
        changed_files = run(["git", "diff", "--name-only"], cwd=bugrc_repo, timeout=args.git_timeout, check=False)
        patch_apply["changed_files"] = changed_files.stdout.splitlines()

    base_target = prepare_build_target(args.target_work_dir / "targets" / target, case_dir / "base_target", base_repo)
    bugrc_target = prepare_build_target(args.target_work_dir / "targets" / target, case_dir / "bugrc_target", bugrc_repo)
    base_build = run_target_build(base_target, args.magma_root, case_dir / "base_out", case_dir / "base_shared", args)
    if base_build["returncode"] != 0:
        conclusion = "base_build_failed"
        bugrc_build: dict[str, Any] = {"skipped": True, "reason": "base build failed"}
    elif not patch_apply.get("applied"):
        conclusion = "bugrc_patch_not_materialized"
        bugrc_build = {"skipped": True, "reason": "bugrc patch did not materialize"}
    else:
        bugrc_build = run_target_build(bugrc_target, args.magma_root, case_dir / "bugrc_out", case_dir / "bugrc_shared", args)
        conclusion = "base_and_bugrc_build" if bugrc_build["returncode"] == 0 else "patch_compile_failed"
        compile_refinements: list[dict[str, Any]] = []
        refined_bugrc_build: dict[str, Any] | None = None
        wants_conservative = args.compile_refinement_mode in {"conservative", "conservative_then_llm"}
        wants_llm = args.compile_refinement_mode in {"llm", "conservative_then_llm"}
        if conclusion == "patch_compile_failed" and wants_conservative:
            for pass_index in range(max(0, args.compile_refinement_passes)):
                refinement = refine_compile_failure_conservative(bugrc_repo, bugrc_build if refined_bugrc_build is None else refined_bugrc_build)
                refinement["pass_index"] = pass_index + 1
                compile_refinements.append(refinement)
                if not refinement.get("changed"):
                    break
                refined_target = prepare_build_target(
                    args.target_work_dir / "targets" / target,
                    case_dir / f"bugrc_refined_target_{pass_index + 1}",
                    bugrc_repo,
                )
                refined_bugrc_build = run_target_build(
                    refined_target,
                    args.magma_root,
                    case_dir / f"bugrc_refined_out_{pass_index + 1}",
                    case_dir / f"bugrc_refined_shared_{pass_index + 1}",
                    args,
                )
                if refined_bugrc_build["returncode"] == 0:
                    conclusion = "base_and_bugrc_refined_build"
                    break
        if conclusion == "patch_compile_failed" and wants_llm:
            llm_refinement = refine_compile_failure_with_llm(
                repo_path=bugrc_repo,
                build=refined_bugrc_build if refined_bugrc_build is not None else bugrc_build,
                selected=selected,
                case=case,
                case_dir=case_dir,
                args=args,
            )
            llm_compile_refinements = [llm_refinement]
            if llm_refinement.get("changed"):
                llm_target = prepare_build_target(
                    args.target_work_dir / "targets" / target,
                    case_dir / "bugrc_llm_refined_target",
                    bugrc_repo,
                )
                llm_refined_bugrc_build = run_target_build(
                    llm_target,
                    args.magma_root,
                    case_dir / "bugrc_llm_refined_out",
                    case_dir / "bugrc_llm_refined_shared",
                    args,
                )
                if llm_refined_bugrc_build["returncode"] == 0:
                    conclusion = "base_and_bugrc_llm_refined_build"

    if not args.keep_worktrees:
        cleanup_build_dirs(case_dir)

    return {
        "local_id": case_id,
        "target": target,
        "semantic_verdict": selected.get("semantic_verdict"),
        "paper_claim": selected.get("paper_claim"),
        "materialization_method": selected.get("materialization_method"),
        "setup_patch_results": setup_patch_results,
        "patch_apply": patch_apply,
        "base_build": base_build,
        "bugrc_build": bugrc_build,
        "compile_refinements": locals().get("compile_refinements", []),
        "refined_bugrc_build": locals().get("refined_bugrc_build"),
        "llm_compile_refinements": locals().get("llm_compile_refinements", []),
        "llm_refined_bugrc_build": locals().get("llm_refined_bugrc_build"),
        "conclusion": conclusion,
    }


def refine_compile_failure_conservative(repo_path: Path, build: dict[str, Any]) -> dict[str, Any]:
    """Apply small compiler-error-guided edits that do not change patch intent.

    The refinement is intentionally narrow.  It fixes syntax-level integration
    mistakes that are common after source-grounded patch materialization:
    project-local enum spelling suggested by the compiler, void/non-void return
    mismatches, break/continue inserted outside loops, and simple redeclarations
    of variables that already exist in the enclosing function.  It does not
    invent missing fields, move the patch to another location, or rewrite whole
    functions.
    """

    text = f"{build.get('stderr') or ''}\n{build.get('stdout') or ''}"
    diagnostics = parse_compile_diagnostics(text)
    changes: list[dict[str, Any]] = []
    for diagnostic in diagnostics:
        path = resolve_diagnostic_path(repo_path, diagnostic["path"])
        if path is None or not path.exists() or path.suffix.lower() not in C_EXTENSIONS:
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        line_no = diagnostic["line"]
        if line_no < 1 or line_no > len(lines):
            continue
        original = lines[line_no - 1]
        updated = apply_conservative_line_fix(lines, line_no, diagnostic["message"])
        if updated is None or updated == original:
            continue
        lines[line_no - 1] = updated
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        changes.append(
            {
                "file": path.relative_to(repo_path).as_posix() if path.is_relative_to(repo_path) else path.as_posix(),
                "line": line_no,
                "message": diagnostic["message"][:300],
                "old": original,
                "new": updated,
            }
        )
    diff_check = run(["git", "diff", "--check"], cwd=repo_path, timeout=120, check=False)
    diff_stat = run(["git", "diff", "--stat"], cwd=repo_path, timeout=120, check=False)
    return {
        "changed": bool(changes),
        "changes": changes,
        "diff_check_returncode": diff_check.returncode,
        "diff_check_stdout": diff_check.stdout[-2000:],
        "diff_check_stderr": diff_check.stderr[-2000:],
        "diff_stat": diff_stat.stdout[-4000:],
    }


def refine_compile_failure_with_llm(
    *,
    repo_path: Path,
    build: dict[str, Any],
    selected: dict[str, Any],
    case: dict[str, Any],
    case_dir: Path,
    args: argparse.Namespace,
) -> dict[str, Any]:
    """Ask an LLM for minimal exact replacements that fix compile integration.

    The prompt is deliberately constrained.  The model sees only the current
    compiler errors, the current RCPatch diff, and local source snippets.  It may
    return exact old/new replacements in already-touched files, or decline.
    """

    api_key = os.getenv("RCPATCH_OPENAI_API_KEY") or os.getenv("BUGRC_OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not api_key:
        return {"changed": False, "reason": "missing_openai_api_key"}
    diagnostics = parse_compile_diagnostics(f"{build.get('stderr') or ''}\n{build.get('stdout') or ''}")
    if not diagnostics:
        return {"changed": False, "reason": "no_compile_diagnostics"}
    prompt = build_llm_compile_refinement_prompt(repo_path, build, selected, case, diagnostics)
    cache_dir = args.llm_cache_dir or (args.output_dir / "llm_compile_refinement_cache")
    payload = call_json_llm(
        prompt=prompt,
        model=args.llm_model,
        base_url=args.llm_base_url,
        api_key=api_key,
        timeout=args.llm_timeout,
        cache_dir=cache_dir,
    )
    apply_result = apply_llm_replacement_payload(repo_path, payload, selected)
    diff_check = run(["git", "diff", "--check"], cwd=repo_path, timeout=120, check=False)
    diff_stat = run(["git", "diff", "--stat"], cwd=repo_path, timeout=120, check=False)
    return {
        "changed": bool(apply_result.get("changed")),
        "reason": apply_result.get("reason"),
        "llm_payload": payload,
        "apply_result": apply_result,
        "diff_check_returncode": diff_check.returncode,
        "diff_check_stdout": diff_check.stdout[-2000:],
        "diff_check_stderr": diff_check.stderr[-2000:],
        "diff_stat": diff_stat.stdout[-4000:],
    }


def build_llm_compile_refinement_prompt(
    repo_path: Path,
    build: dict[str, Any],
    selected: dict[str, Any],
    case: dict[str, Any],
    diagnostics: list[dict[str, Any]],
) -> str:
    changed_files = [
        str(path)
        for path in (selected.get("materialized_changed_files") or (build.get("patch_apply") or {}).get("changed_files") or [])
        if str(path)
    ]
    if not changed_files:
        changed_files = run(["git", "diff", "--name-only"], cwd=repo_path, timeout=120, check=False).stdout.splitlines()
    allowed_files = sorted(set(changed_files))
    error_text = extract_error_lines(f"{build.get('stderr') or ''}\n{build.get('stdout') or ''}", limit=80)
    diff_text = run(["git", "diff", "--"] + allowed_files[:6], cwd=repo_path, timeout=120, check=False).stdout
    snippets = collect_llm_source_snippets(repo_path, diagnostics, allowed_files)
    generated_patch = ""
    patch_path = repo_path.parent / "bugrc_generated.patch"
    if patch_path.exists():
        generated_patch = patch_path.read_text(encoding="utf-8", errors="replace")
    request = {
        "case_id": selected.get("local_id") or case.get("local_id") or case.get("bug_id"),
        "target": selected.get("target") or case.get("target"),
        "paper_claim": selected.get("paper_claim"),
        "semantic_verdict": selected.get("semantic_verdict"),
        "allowed_files": allowed_files,
        "compiler_errors": error_text,
        "current_bugrc_diff": truncate_text(diff_text, 16000),
        "source_snippets": snippets,
        "generated_patch": truncate_text(generated_patch, 8000),
    }
    return f"""You are repairing only compile-integration errors in an already generated C/C++ vulnerability patch.

Hard rules:
- Do not change the root-cause location, patch intent, or vulnerability semantics.
- Do not introduce a new repair strategy.
- Edit only files listed in allowed_files.
- Prefer no edit if a safe local compile-only fix is not obvious.
- Return JSON only.
- Each edit must use an exact old string that appears in the current patched source file.
- Keep replacements minimal: usually one line or a short block.

Return schema:
{{
  "should_apply": true or false,
  "confidence": 0.0-1.0,
  "reasoning": "short explanation",
  "edits": [
    {{
      "file": "relative/path/from/repo",
      "old": "exact text currently in that file",
      "new": "replacement text",
      "reason": "why this is only a compile integration fix"
    }}
  ]
}}

Input:
{json.dumps(request, indent=2, ensure_ascii=False)}
"""


def extract_error_lines(text: str, *, limit: int) -> list[str]:
    lines = []
    for line in text.splitlines():
        if re.search(r"error:|undefined reference|not declared|undeclared|no member|redefinition|expected|return-type", line, re.I):
            lines.append(line[:500])
        if len(lines) >= limit:
            break
    return lines


def collect_llm_source_snippets(repo_path: Path, diagnostics: list[dict[str, Any]], allowed_files: list[str]) -> list[dict[str, Any]]:
    snippets: list[dict[str, Any]] = []
    diag_by_file: dict[str, list[int]] = {}
    for diagnostic in diagnostics[:12]:
        path = resolve_diagnostic_path(repo_path, diagnostic["path"])
        if path is None or not path.exists():
            continue
        rel = path.relative_to(repo_path).as_posix() if path.is_relative_to(repo_path) else path.as_posix()
        if allowed_files and rel not in allowed_files and path.name not in {Path(item).name for item in allowed_files}:
            continue
        diag_by_file.setdefault(rel, []).append(int(diagnostic["line"]))
    for rel, lines in diag_by_file.items():
        path = repo_path / rel
        if not path.exists():
            continue
        source_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        windows = []
        for line_no in lines[:4]:
            start = max(1, line_no - 30)
            end = min(len(source_lines), line_no + 30)
            body = "\n".join(f"{idx}: {source_lines[idx-1]}" for idx in range(start, end + 1))
            windows.append({"start_line": start, "end_line": end, "text": truncate_text(body, 10000)})
        snippets.append({"file": rel, "windows": windows})
    return snippets[:6]


def call_json_llm(
    *,
    prompt: str,
    model: str,
    base_url: str,
    api_key: str,
    timeout: int,
    cache_dir: Path,
) -> dict[str, Any]:
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_key = hashlib.sha256(f"compile_refine_v1\n{model}\n{prompt}".encode("utf-8")).hexdigest()
    cache_path = cache_dir / f"{cache_key}.json"
    if cache_path.exists():
        cached = json.loads(cache_path.read_text(encoding="utf-8"))
        cached["cached"] = True
        return cached
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You return strict JSON for conservative compile-error patch refinement."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0,
        "max_tokens": 2500,
        "response_format": {"type": "json_object"},
    }
    request = urllib.request.Request(
        url=f"{base_url.rstrip('/')}/chat/completions",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - user-configured HTTPS API endpoint.
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        error_text = exc.read().decode("utf-8", errors="replace")
        return {"should_apply": False, "error": f"HTTPError {exc.code}: {error_text[-1000:]}"}
    except Exception as exc:  # noqa: BLE001 - keep batch moving.
        return {"should_apply": False, "error": f"{type(exc).__name__}: {exc}"}
    data = json.loads(raw)
    content = ((data.get("choices") or [{}])[0].get("message") or {}).get("content") or "{}"
    payload = parse_json_object(content)
    payload["cached"] = False
    cache_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return payload


def parse_json_object(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?", "", stripped).strip()
        stripped = re.sub(r"```$", "", stripped).strip()
    try:
        payload = json.loads(stripped)
        return payload if isinstance(payload, dict) else {"should_apply": False, "error": "non_object_json"}
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", stripped, re.DOTALL)
        if not match:
            return {"should_apply": False, "error": "json_parse_failed"}
        payload = json.loads(match.group(0))
        return payload if isinstance(payload, dict) else {"should_apply": False, "error": "non_object_json"}


def apply_llm_replacement_payload(repo_path: Path, payload: dict[str, Any], selected: dict[str, Any]) -> dict[str, Any]:
    if not payload.get("should_apply"):
        return {"changed": False, "reason": "llm_declined_or_failed"}
    allowed = {str(path) for path in selected.get("materialized_changed_files") or []}
    allowed_names = {Path(path).name for path in allowed}
    applied: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for index, edit in enumerate(payload.get("edits") or []):
        rel = str(edit.get("file") or "")
        old = str(edit.get("old") or "")
        new = str(edit.get("new") or "")
        if not rel or not old:
            failures.append({"index": index, "reason": "missing_file_or_old"})
            continue
        if allowed and rel not in allowed and Path(rel).name not in allowed_names:
            failures.append({"index": index, "file": rel, "reason": "file_not_allowed"})
            continue
        path = repo_path / rel
        if not path.exists():
            matches = [candidate for candidate in repo_path.rglob(Path(rel).name) if candidate.is_file()]
            path = matches[0] if len(matches) == 1 else path
        if not path.exists() or not path.is_file():
            failures.append({"index": index, "file": rel, "reason": "file_not_found"})
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        replacement = find_llm_replacement(text, old, new)
        if replacement is None:
            failures.append({"index": index, "file": rel, "reason": "old_text_not_found", "old_preview": old[:300]})
            continue
        path.write_text(replacement["text"], encoding="utf-8")
        applied.append(
            {
                "index": index,
                "file": rel,
                "reason": edit.get("reason"),
                "match": replacement["match"],
                "old_preview": replacement["old"][:300],
                "new_preview": replacement["new"][:300],
            }
        )
    return {
        "changed": bool(applied),
        "reason": "applied_llm_replacements" if applied else "no_llm_replacements_applied",
        "applied": applied,
        "failures": failures[:10],
    }


def find_llm_replacement(text: str, old: str, new: str) -> dict[str, str] | None:
    """Find a conservative exact or unique-stripped replacement for an LLM edit.

    LLMs sometimes echo unified-diff markers in the JSON replacement blocks
    even though the checked-out file contains plain source.  We therefore try a
    tiny set of normalized variants, but still require either exact occurrence
    or a single unambiguous whitespace-stripped block match.
    """

    candidates: list[tuple[str, str, str]] = [("exact", old, new)]
    diff_old = strip_diff_context_markers(old)
    diff_new = strip_added_line_markers(new)
    if diff_old != old or diff_new != new:
        candidates.append(("diff_marker_normalized", diff_old, diff_new))

    seen: set[tuple[str, str]] = set()
    for mode, old_candidate, new_candidate in candidates:
        key = (old_candidate, new_candidate)
        if key in seen:
            continue
        seen.add(key)
        if old_candidate in text:
            return {
                "text": text.replace(old_candidate, new_candidate, 1),
                "match": mode,
                "old": old_candidate,
                "new": new_candidate,
            }
        fuzzy = replace_unique_stripped_block(text, old_candidate, new_candidate)
        if fuzzy is not None:
            return {
                "text": fuzzy,
                "match": f"{mode}:unique_stripped_block",
                "old": old_candidate,
                "new": new_candidate,
            }
    return None


def strip_diff_context_markers(block: str) -> str:
    """Remove leading unified-diff markers from an old/source block.

    This is intentionally narrow and line-local. It handles JSON payloads where
    the LLM copied ``+`` inserted lines or context lines with a leading space.
    """

    normalized: list[str] = []
    for line in block.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            normalized.append(line[1:])
        elif line.startswith(" "):
            normalized.append(line[1:])
        else:
            normalized.append(line)
    return "\n".join(normalized)


def strip_added_line_markers(block: str) -> str:
    """Remove accidental leading ``+`` markers from an LLM new/source block."""

    normalized: list[str] = []
    for line in block.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            normalized.append(line[1:])
        else:
            normalized.append(line)
    return "\n".join(normalized)


def replace_unique_stripped_block(text: str, old: str, new: str) -> str | None:
    """Replace a block whose lines match uniquely after trimming indentation.

    This is still conservative: it only accepts a single unambiguous block with
    the same line count as the LLM-provided old text.  It handles harmless
    whitespace drift between the prompt snippet and the checked-out file.
    """

    old_lines = old.splitlines()
    if not old_lines:
        return None
    target = [line.strip() for line in old_lines]
    lines = text.splitlines()
    matches: list[int] = []
    width = len(target)
    for index in range(0, len(lines) - width + 1):
        if [line.strip() for line in lines[index : index + width]] == target:
            matches.append(index)
            if len(matches) > 1:
                return None
    if len(matches) != 1:
        return None
    index = matches[0]
    replacement = new.splitlines()
    updated_lines = lines[:index] + replacement + lines[index + width :]
    return "\n".join(updated_lines) + ("\n" if text.endswith("\n") else "")


def truncate_text(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    half = max(1, limit // 2)
    return text[:half] + "\n...[truncated]...\n" + text[-half:]


def parse_compile_diagnostics(text: str) -> list[dict[str, Any]]:
    diagnostics: list[dict[str, Any]] = []
    pattern = re.compile(r"(?P<path>(?:/[^:\n]+|[A-Za-z0-9_./+-]+)):(?P<line>\d+):(?P<col>\d+):\s*(?:fatal\s+)?error:\s*(?P<message>.*)")
    for line in text.splitlines():
        match = pattern.search(line)
        if not match:
            continue
        diagnostics.append(
            {
                "path": match.group("path"),
                "line": int(match.group("line")),
                "column": int(match.group("col")),
                "message": match.group("message").strip(),
            }
        )
    return diagnostics


def resolve_diagnostic_path(repo_path: Path, raw_path: str) -> Path | None:
    candidates: list[Path] = []
    path = Path(raw_path)
    if path.is_absolute():
        candidates.append(path)
    else:
        candidates.append(repo_path / raw_path)
        # Some build tools prefix diagnostics with a job number, e.g. 1src/foo.c.
        stripped = re.sub(r"^\d+(?=[A-Za-z_./-])", "", raw_path)
        if stripped != raw_path:
            candidates.append(repo_path / stripped)
    for candidate in candidates:
        if candidate.exists():
            return candidate
    suffix = re.sub(r"^\d+(?=[A-Za-z_./-])", "", raw_path)
    matches = list(repo_path.rglob(Path(suffix).name))
    for match in matches:
        if match.as_posix().endswith(suffix):
            return match
    return matches[0] if len(matches) == 1 else None


def apply_conservative_line_fix(lines: list[str], line_no: int, message: str) -> str | None:
    line = lines[line_no - 1]
    stripped = line.strip()
    suggestion = re.search(r"use of undeclared identifier '([^']+)'; did you mean '([^']+)'", message)
    if suggestion:
        old, new = suggestion.groups()
        if re.search(rf"\b{re.escape(old)}\b", line):
            return re.sub(rf"\b{re.escape(old)}\b", new, line)

    if "void function" in message and "should not return a value" in message:
        fixed = re.sub(r"\breturn\s+[^;]+;", "return;", line)
        return fixed if fixed != line else None

    if "non-void function" in message and "should return a value" in message and re.search(r"\breturn\s*;", line):
        return re.sub(r"\breturn\s*;", infer_return_statement(lines, line_no), line)

    if ("'break' statement not in loop" in message or "'continue' statement not in loop" in message) and stripped in {"break;", "continue;"}:
        indent = line[: len(line) - len(line.lstrip())]
        return f"{indent}{infer_return_statement(lines, line_no)}"

    redeclared = re.search(r"redefinition of '([^']+)'", message)
    if redeclared:
        variable = redeclared.group(1)
        if variable_seen_before(lines, line_no, variable):
            fixed = remove_redeclaration(line, variable)
            if fixed != line:
                return fixed
    return None


def variable_seen_before(lines: list[str], line_no: int, variable: str) -> bool:
    start = max(0, line_no - 120)
    before = "\n".join(lines[start : line_no - 1])
    return bool(re.search(rf"\b{re.escape(variable)}\b", before))


def remove_redeclaration(line: str, variable: str) -> str:
    escaped = re.escape(variable)
    patterns = [
        rf"^(\s*)(?:const\s+)?(?:struct\s+\w+\s+)?[A-Za-z_][A-Za-z0-9_:<>]*\s*[*&]?\s+{escaped}\s*=\s*(.+;\s*)$",
        rf"^(\s*)auto\s+{escaped}\s*=\s*(.+;\s*)$",
    ]
    for pattern in patterns:
        match = re.match(pattern, line)
        if match:
            return f"{match.group(1)}{variable} = {match.group(2)}"
    return line


def infer_return_statement(lines: list[str], line_no: int) -> str:
    signature = find_enclosing_function_signature(lines, line_no)
    if not signature:
        return "return 0;"
    signature = re.sub(r"\s+", " ", signature)
    prefix = signature.split("(", 1)[0]
    if re.search(r"\bvoid\b", prefix):
        return "return;"
    if "*" in prefix or re.search(r"\b(xml[A-Za-z0-9_]*Ptr|char\s*\*|GooString\s*\*)", prefix):
        return "return NULL;"
    if re.search(r"\b(bool|GBool)\b", prefix):
        return "return false;"
    return "return 0;"


def find_enclosing_function_signature(lines: list[str], line_no: int) -> str | None:
    start = max(0, line_no - 220)
    for index in range(line_no - 1, start - 1, -1):
        line = lines[index].strip()
        if "{" not in line:
            continue
        candidate_lines = [line]
        for back in range(index - 1, max(start, index - 8), -1):
            prev = lines[back].strip()
            if not prev or prev.startswith("#") or prev.endswith(";") or prev.endswith("}"):
                break
            candidate_lines.insert(0, prev)
            if "(" in prev:
                break
        signature = " ".join(candidate_lines)
        if "(" not in signature or ")" not in signature:
            continue
        if re.search(r"\b(if|for|while|switch|catch)\s*\(", signature):
            continue
        return signature.split("{", 1)[0].strip()
    return None


def prepare_buggy_source_tree(
    case: dict[str, Any],
    target_base: Path,
    source_target: Path,
    destination: Path,
    timeout: int,
) -> tuple[Path, list[dict[str, Any]]]:
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(target_base, destination, ignore=lambda _dir, names: {name for name in names if name == ".git"})
    apply_compile_validation_source_tweaks(destination, source_target.name)
    setup_patch_results = apply_setup_patches_best_effort(destination, source_target, timeout)
    patch_path = Path(str(case.get("magma_patch_path") or case.get("official_patch_path") or ""))
    apply_magma_patch(destination, patch_path, replacement_name=str(case.get("local_id") or case.get("bug_id")), timeout=timeout)
    touched_files = case.get("touched_files") or []
    materialize_magma_buggy_files(destination, touched_files)
    run(["git", "init"], cwd=destination, timeout=timeout)
    run(["git", "config", "user.email", "bugrc@example.invalid"], cwd=destination, timeout=timeout, check=False)
    run(["git", "config", "user.name", "RCPatch"], cwd=destination, timeout=timeout, check=False)
    run(["git", "add", "-A"], cwd=destination, timeout=timeout)
    run(["git", "commit", "-m", "RCPatch Magma buggy source"], cwd=destination, timeout=timeout, check=False)
    return destination, setup_patch_results


def apply_compile_validation_source_tweaks(repo_path: Path, target_name: str) -> None:
    """Apply host-reproducibility source-tree tweaks before validation builds.

    These are not RCPatch repair edits. They only neutralize benchmark setup
    assumptions that are brittle on a modern host, such as downloading Autotools
    helper scripts during validation.
    """
    if target_name == "libtiff":
        patch_libtiff_autogen(repo_path / "autogen.sh")


def patch_libtiff_autogen(path: Path) -> None:
    if not path.exists():
        return
    text = path.read_text(encoding="utf-8", errors="replace")
    marker = "# Get latest config.guess and config.sub from upstream master since"
    if marker not in text or "/usr/share/misc/${file}" in text:
        return
    replacement = """# Use host-provided Autotools helpers during compile validation.
for file in config.guess config.sub
do
    if [ -f "/usr/share/misc/${file}" ]; then
        cp "/usr/share/misc/${file}" "config/${file}"
        chmod a+x "config/${file}"
    fi
done
"""
    text = text[: text.index(marker)] + replacement
    path.write_text(text, encoding="utf-8")


def apply_setup_patches_best_effort(repo_path: Path, source_target: Path, timeout: int) -> list[dict[str, Any]]:
    setup_dir = source_target / "patches" / "setup"
    if not setup_dir.exists():
        return []
    results: list[dict[str, Any]] = []
    for patch_path in sorted(setup_dir.glob("*.patch")):
        result = apply_setup_patch_best_effort(repo_path, patch_path, timeout)
        results.append(result)
    (repo_path / ".bugrc_compile_setup_patches.json").write_text(
        json.dumps(results, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return results


def apply_setup_patch_best_effort(repo_path: Path, patch_path: Path, timeout: int) -> dict[str, Any]:
    payload = patch_path.read_text(encoding="utf-8", errors="replace")
    failures: list[dict[str, Any]] = []
    for strip_level in (1, 0):
        dry_run = run(
            ["patch", "--dry-run", f"-p{strip_level}"],
            cwd=repo_path,
            timeout=timeout,
            check=False,
            input_text=payload,
        )
        if dry_run.returncode == 0:
            applied = run(
                ["patch", f"-p{strip_level}"],
                cwd=repo_path,
                timeout=timeout,
                check=False,
                input_text=payload,
            )
            return {
                "patch": patch_path.as_posix(),
                "status": "applied" if applied.returncode == 0 else "apply_failed_after_dry_run",
                "strip_level": strip_level,
                "stdout_tail": applied.stdout[-1000:],
                "stderr_tail": applied.stderr[-1000:],
            }

        reverse_dry_run = run(
            ["patch", "--dry-run", "-R", f"-p{strip_level}"],
            cwd=repo_path,
            timeout=timeout,
            check=False,
            input_text=payload,
        )
        if reverse_dry_run.returncode == 0:
            return {
                "patch": patch_path.as_posix(),
                "status": "already_applied",
                "strip_level": strip_level,
                "stdout_tail": reverse_dry_run.stdout[-1000:],
                "stderr_tail": reverse_dry_run.stderr[-1000:],
            }

        failures.append(
            {
                "strip_level": strip_level,
                "dry_run_stdout_tail": dry_run.stdout[-1000:],
                "dry_run_stderr_tail": dry_run.stderr[-1000:],
                "reverse_stdout_tail": reverse_dry_run.stdout[-1000:],
                "reverse_stderr_tail": reverse_dry_run.stderr[-1000:],
            }
        )

    return {
        "patch": patch_path.as_posix(),
        "status": "skipped",
        "failures": failures,
    }


def apply_magma_patch(repo_path: Path, patch_path: Path, *, replacement_name: str, timeout: int) -> None:
    payload = patch_path.read_text(encoding="utf-8", errors="replace").replace("%MAGMA_BUG%", replacement_name)
    proc = run(["patch", "-p1"], cwd=repo_path, timeout=timeout, check=False, input_text=payload)
    if proc.returncode != 0:
        raise RuntimeError(f"failed to apply Magma patch {patch_path}: {proc.stderr[-1000:] or proc.stdout[-1000:]}")


def materialize_magma_buggy_files(repo_path: Path, touched_files: list[str]) -> None:
    for rel_path in touched_files:
        path = repo_path / rel_path
        if not path.exists() or path.suffix.lower() not in C_EXTENSIONS:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        path.write_text(materialize_magma_buggy_source(text), encoding="utf-8")


def materialize_magma_buggy_source(text: str) -> str:
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
    return "\n".join(output) + ("\n" if text.endswith("\n") else "")


def should_keep_magma_line(stack: list[dict[str, Any]]) -> bool:
    for frame in stack:
        if frame["kind"] == "ifdef_fixes" and not frame["else"]:
            return False
        if frame["kind"] == "ifndef_fixes" and frame["else"]:
            return False
    return True


def generated_patch_by_id(results_jsonl: Path, case_id: str) -> str:
    for row in load_jsonl(results_jsonl):
        if str(row.get("local_id") or row.get("bug_id")) == case_id:
            return patch_validator.normalize_patch_text(
                str(((row.get("generated_patch") or {}).get("payload") or {}).get("unified_diff") or "")
            )
    raise KeyError(f"Could not find generated patch for {case_id}")


def clone_source_tree(source: Path, destination: Path) -> Path:
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination, ignore=lambda _dir, names: {name for name in names if name == ".git"})
    run(["git", "init"], cwd=destination, timeout=120)
    run(["git", "config", "user.email", "bugrc@example.invalid"], cwd=destination, timeout=120, check=False)
    run(["git", "config", "user.name", "RCPatch"], cwd=destination, timeout=120, check=False)
    run(["git", "add", "-A"], cwd=destination, timeout=120)
    run(["git", "commit", "-m", "RCPatch compile validation source"], cwd=destination, timeout=120, check=False)
    return destination


def prepare_build_target(source_target: Path, destination: Path, repo_path: Path) -> Path:
    if destination.exists():
        shutil.rmtree(destination)

    def ignore(_dir: str, names: list[str]) -> set[str]:
        return {name for name in names if name in {"repo", "work", "corpus", "logs", ".bugrc_base_ready"}}

    shutil.copytree(source_target, destination, ignore=ignore)
    apply_compile_validation_build_tweaks(destination, source_target.name)
    os.symlink(repo_path, destination / "repo")
    return destination


def apply_compile_validation_build_tweaks(target_dir: Path, target_name: str) -> None:
    """Apply reproducibility-only build fixes to copied Magma target scaffolds.

    These edits are intentionally limited to the temporary target wrapper used
    for compile validation. They do not change the vulnerable source tree or
    RCPatch's generated patch; they only make historical Magma targets build in
    the current host environment when optional dependencies are unavailable.
    """
    if target_name == "libtiff":
        patch_libtiff_build(target_dir / "build.sh")
    elif target_name == "libxml2":
        ensure_header_include(target_dir / "src" / "FuzzedDataProvider.h", "#include <limits>")
    elif target_name == "php":
        patch_php_build(target_dir / "build.sh")
    elif target_name == "poppler":
        patch_poppler_build(target_dir / "build.sh")


def patch_libtiff_build(path: Path) -> None:
    if not path.exists():
        return
    text = path.read_text(encoding="utf-8", errors="replace")
    old = './configure --disable-shared --prefix="$WORK"'
    new = './configure --disable-shared --prefix="$WORK" --disable-jbig --disable-libdeflate'
    if old in text and new not in text:
        text = text.replace(old, new)
        path.write_text(text, encoding="utf-8")


def patch_poppler_build(path: Path) -> None:
    if not path.exists():
        return
    text = path.read_text(encoding="utf-8", errors="replace")
    if "-DENABLE_QT6=OFF" not in text:
        text = text.replace("  -DENABLE_QT5=OFF \\\n", "  -DENABLE_QT5=OFF \\\n  -DENABLE_QT6=OFF \\\n")
    if "-DENABLE_LIBOPENJPEG=none" not in text:
        text = text.replace("  -DWITH_Cairo=ON \\\n", "  -DWITH_Cairo=ON \\\n  -DENABLE_LIBOPENJPEG=none \\\n")
    text = text.replace(" -lopenjp2", "")
    text = text.replace(" -llcms2", "")
    path.write_text(text, encoding="utf-8")


def patch_php_build(path: Path) -> None:
    if not path.exists():
        return
    text = path.read_text(encoding="utf-8", errors="replace")
    # PHP-7-era intl code is incompatible with newer system ICU headers. The
    # Magma PHP fuzzers built here do not include an intl fuzzer, and PHP005's
    # RCPatch patch touches ext/iconv, so disabling intl only removes a host
    # compatibility blocker from compile validation.
    text = text.replace("    --enable-intl \\\n", "")
    path.write_text(text, encoding="utf-8")


def ensure_header_include(path: Path, include_line: str) -> None:
    if not path.exists():
        return
    text = path.read_text(encoding="utf-8", errors="replace")
    if include_line in text:
        return
    marker = "#include <initializer_list>"
    if marker in text:
        text = text.replace(marker, f"{include_line}\n{marker}", 1)
    else:
        text = f"{include_line}\n{text}"
    path.write_text(text, encoding="utf-8")


def run_target_build(target_dir: Path, magma_root: Path, out_dir: Path, shared_dir: Path, args: argparse.Namespace) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    shared_dir.mkdir(parents=True, exist_ok=True)
    magma_dir = magma_root / "magma"
    env = os.environ.copy()
    user_tool_dir = Path.home() / "bugrc-tools" / "bin"
    if user_tool_dir.exists():
        env["PATH"] = f"{user_tool_dir}{os.pathsep}{env.get('PATH', '')}"
    env.update(
        {
            "TARGET": target_dir.as_posix(),
            "OUT": out_dir.as_posix(),
            "SHARED": shared_dir.as_posix(),
            "MAGMA": magma_dir.as_posix(),
            "CC": env.get("CC", "clang"),
            "CXX": env.get("CXX", "clang++"),
            "LD": env.get("LD") or shutil.which("ld") or "ld",
            "AR": env.get("AR") or shutil.which("ar") or "ar",
            "RANLIB": env.get("RANLIB") or shutil.which("ranlib") or "ranlib",
        }
    )
    build_flags = f'-include {magma_dir / "src" / "canary.h"} -DMAGMA_ENABLE_CANARIES -g -O0 -fPIC'
    env["CFLAGS"] = f'{env.get("CFLAGS", "")} {build_flags} -fsanitize=fuzzer-no-link'.strip()
    env["CXXFLAGS"] = f'{env.get("CXXFLAGS", "")} {build_flags} -fsanitize=fuzzer-no-link'.strip()
    env["LDFLAGS"] = f'{env.get("LDFLAGS", "")} -L{out_dir} -g -fsanitize=fuzzer-no-link'.strip()

    fuzzer_runtime = ensure_libfuzzer_artifacts(magma_root, out_dir, env, args.build_timeout)
    env["LIBS"] = f'{env.get("LIBS", "")} -l:magma.o -lrt -l:driver.o {fuzzer_runtime} -lstdc++'.strip()

    magma_build = run(["bash", "build.sh"], cwd=magma_dir, timeout=args.build_timeout, check=False, env=env)
    if magma_build.returncode != 0:
        return {
            "returncode": magma_build.returncode,
            "phase": "magma_build",
            "stdout": magma_build.stdout[-12000:],
            "stderr": magma_build.stderr[-12000:],
        }
    target_build = run(["bash", "build.sh"], cwd=target_dir, timeout=args.build_timeout, check=False, env=env)
    artifacts = sorted(path.name for path in out_dir.iterdir()) if out_dir.exists() else []
    return {
        "returncode": target_build.returncode,
        "phase": "target_build",
        "stdout": target_build.stdout[-12000:],
        "stderr": target_build.stderr[-12000:],
        "artifacts": artifacts[:50],
    }


def ensure_libfuzzer_artifacts(magma_root: Path, out_dir: Path, env: dict[str, str], timeout: int) -> str:
    driver_source = magma_root / "fuzzers" / "libfuzzer" / "src" / "driver.cpp"
    driver_obj = out_dir / "driver.o"
    cxx = env.get("CXX", "clang++")
    runtime = run(
        [cxx, "-print-file-name=libclang_rt.fuzzer_no_main-x86_64.a"],
        cwd=magma_root,
        timeout=timeout,
        check=False,
        env=env,
    ).stdout.strip()
    if not runtime or runtime == "libclang_rt.fuzzer_no_main-x86_64.a" or not Path(runtime).exists():
        runtime = run(
            [cxx, "-print-file-name=libclang_rt.fuzzer-x86_64.a"],
            cwd=magma_root,
            timeout=timeout,
            check=False,
            env=env,
        ).stdout.strip()
    compile_driver = run(
        [cxx, "-std=c++11", "-c", driver_source.as_posix(), "-fPIC", "-o", driver_obj.as_posix()],
        cwd=magma_root,
        timeout=timeout,
        check=False,
        env=env,
    )
    if compile_driver.returncode != 0:
        raise RuntimeError(f"failed to compile libFuzzer driver: {compile_driver.stderr[-1000:]}")
    if not runtime or not Path(runtime).exists():
        raise RuntimeError("could not locate clang libFuzzer runtime")
    return runtime


def cleanup_build_dirs(case_dir: Path) -> None:
    for name in ("base_target", "bugrc_target", "base_repo", "bugrc_repo"):
        shutil.rmtree(case_dir / name, ignore_errors=True)
    for pattern in ("bugrc_refined_target_*", "bugrc_refined_out_*", "bugrc_refined_shared_*"):
        for path in case_dir.glob(pattern):
            shutil.rmtree(path, ignore_errors=True)


def write_summary(results_path: Path, summary_path: Path) -> None:
    records = load_jsonl(results_path)
    summary = {
        "record_count": len(records),
        "status_distribution": dict(Counter(row.get("status") for row in records)),
        "target_distribution": dict(Counter(row.get("target") for row in records)),
        "paper_claim_distribution": dict(Counter(row.get("paper_claim") for row in records)),
        "semantic_verdict_distribution": dict(Counter(row.get("semantic_verdict") for row in records)),
        "conclusion_distribution": dict(Counter(row.get("conclusion") for row in records)),
        "compile_refinement_changed_distribution": dict(
            Counter(str(any(refinement.get("changed") for refinement in row.get("compile_refinements") or [])) for row in records)
        ),
        "base_build_returncodes": dict(Counter(str((row.get("base_build") or {}).get("returncode")) for row in records)),
        "bugrc_build_returncodes": dict(Counter(str((row.get("bugrc_build") or {}).get("returncode")) for row in records)),
        "patch_apply_distribution": dict(Counter(str((row.get("patch_apply") or {}).get("applied")) for row in records)),
        "updated_at_epoch": time.time(),
    }
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")


def load_done_ids(path: Path) -> set[str]:
    return {str(row.get("local_id")) for row in load_jsonl(path) if row.get("local_id")}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def append_jsonl(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def run(
    command: list[str],
    *,
    cwd: Path,
    timeout: int,
    check: bool = True,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        input=input_text,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=check,
    )


if __name__ == "__main__":
    raise SystemExit(main())
