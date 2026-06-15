#!/usr/bin/env python3
"""Compile-validate materialized BugRC patches on core Magma claim cases.

The patch-materialization pass proves that BugRC's generated repair can be
placed into a source tree.  This script adds the next evidence layer: for the
Magma cases where BugRC is judged to block the root-cause path better than the
benchmark reference patch, rebuild the target before and after the materialized
BugRC patch.  Results distinguish environment/base-build failures from genuine
patch-induced compile failures.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import time
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
        case_ids=set(args.case_id or []),
    )
    write_json(args.output_dir / "selected_cases.json", {"count": len(selected), "cases": selected})
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
) -> list[dict[str, Any]]:
    materialized = {
        str(row.get("local_id")): row
        for row in load_jsonl(materialization_results)
        if (row.get("patch_apply") or {}).get("applied") is True
        and row.get("paper_claim") == "bugrc_blocks_better_than_magma_reference"
    }
    selected: list[dict[str, Any]] = []
    for row in load_jsonl(magma_results):
        case_id = str(row.get("local_id") or row.get("bug_id"))
        if case_ids and case_id not in case_ids:
            continue
        mat = materialized.get(case_id)
        if not mat:
            continue
        selected.append(
            {
                "local_id": case_id,
                "bug_id": row.get("bug_id"),
                "target": row.get("target"),
                "semantic_verdict": ((row.get("patch_comparison") or {}).get("llm") or {}).get("verdict"),
                "paper_claim": mat.get("paper_claim"),
                "materialization_method": (mat.get("patch_apply") or {}).get("applied_method"),
                "materialization_reason": (mat.get("patch_apply") or {}).get("reason"),
                "materialized_changed_files": (mat.get("patch_apply") or {}).get("changed_files"),
            }
        )
    selected.sort(key=lambda item: (str(item.get("target")), str(item.get("local_id"))))
    return selected[:max_cases] if max_cases is not None else selected


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
        "conclusion": conclusion,
    }


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
    run(["git", "config", "user.name", "BugRC"], cwd=destination, timeout=timeout, check=False)
    run(["git", "add", "-A"], cwd=destination, timeout=timeout)
    run(["git", "commit", "-m", "BugRC Magma buggy source"], cwd=destination, timeout=timeout, check=False)
    return destination, setup_patch_results


def apply_compile_validation_source_tweaks(repo_path: Path, target_name: str) -> None:
    """Apply host-reproducibility source-tree tweaks before validation builds.

    These are not BugRC repair edits. They only neutralize benchmark setup
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
    run(["git", "config", "user.name", "BugRC"], cwd=destination, timeout=120, check=False)
    run(["git", "add", "-A"], cwd=destination, timeout=120)
    run(["git", "commit", "-m", "BugRC compile validation source"], cwd=destination, timeout=120, check=False)
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
    BugRC's generated patch; they only make historical Magma targets build in
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
    # BugRC patch touches ext/iconv, so disabling intl only removes a host
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


def write_summary(results_path: Path, summary_path: Path) -> None:
    records = load_jsonl(results_path)
    summary = {
        "record_count": len(records),
        "status_distribution": dict(Counter(row.get("status") for row in records)),
        "target_distribution": dict(Counter(row.get("target") for row in records)),
        "conclusion_distribution": dict(Counter(row.get("conclusion") for row in records)),
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
