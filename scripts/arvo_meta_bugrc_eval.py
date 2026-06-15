#!/usr/bin/env python3
"""Evaluate BugRC on a random ARVO-Meta sample.

The first two stages intentionally avoid official patch files:
1. use the bug report plus an LLM to produce an initial root-cause hypothesis;
2. run BugRC on the pre-fix source and ask the LLM to generate a patch from the
   report, BugRC candidates, causality chains, and source snippets.

Official patches are read only in the comparison stage.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import textwrap
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional
from urllib.parse import urlparse


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
VENDOR_ROOT = PROJECT_ROOT / ".vendor"
if SRC_ROOT.exists():
    sys.path.insert(0, str(SRC_ROOT))
try:
    import pydantic  # noqa: F401
except ImportError:
    pydantic = None  # type: ignore[assignment]
if pydantic is None and VENDOR_ROOT.exists():
    sys.path.insert(0, str(VENDOR_ROOT))

from bugrc.chains import CausalityChainConstructor  # noqa: E402
from bugrc.models import (  # noqa: E402
    AnalysisConfig,
    AnalysisResult,
    BugReport,
    BugType,
    ParserBackend,
    SourceLocation,
    TriggerPoint,
    TriggerType,
)
from bugrc.patch_generation import PatchSuggestionGenerator  # noqa: E402
from bugrc.ranking import RootCauseCandidateExtractor  # noqa: E402
from bugrc.source import SourceProjectParser  # noqa: E402
from bugrc.slicing import HybridBackwardSlicer  # noqa: E402


C_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx", ".ipp", ".inl"}
DEFAULT_MODEL = "gpt-4.1-mini"
BUG_TYPE_BY_CRASH_TOKEN = (
    ("heap-buffer-overflow", BugType.BUFFER_OVERFLOW),
    ("stack-buffer-overflow", BugType.BUFFER_OVERFLOW),
    ("global-buffer-overflow", BugType.BUFFER_OVERFLOW),
    ("buffer-overflow", BugType.BUFFER_OVERFLOW),
    ("use-after-free", BugType.USE_AFTER_FREE),
    ("null-dereference", BugType.NULL_DEREFERENCE),
    ("null pointer", BugType.NULL_DEREFERENCE),
)


@dataclass(frozen=True)
class LLMResult:
    payload: dict[str, Any]
    cached: bool
    error: Optional[str] = None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a remote ARVO-Meta BugRC evaluation sample.")
    parser.add_argument("--meta-dir", required=True, help="Directory containing ARVO-Meta JSON bug reports.")
    parser.add_argument("--patch-dir", required=True, help="Directory containing official localId.diff files.")
    parser.add_argument("--output-dir", required=True, help="Directory for evaluation artifacts.")
    parser.add_argument("--repos-dir", help="Shared repository cache directory.")
    parser.add_argument("--repo-lock-dir", help="Directory for cross-process git repository locks.")
    parser.add_argument("--worktrees-dir", help="Per-case pre-fix worktree directory.")
    parser.add_argument("--sample-size", type=int, default=100)
    parser.add_argument("--case-list-file", help="Optional JSON/TXT manifest limiting the cases processed by this run.")
    parser.add_argument("--seed", type=int, default=20260509)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--api-base-url", default="https://api.openai.com/v1")
    parser.add_argument("--llm-timeout", type=int, default=30)
    parser.add_argument("--git-timeout", type=int, default=30)
    parser.add_argument("--case-timeout", type=int, default=240)
    parser.add_argument("--max-source-files", type=int, default=600)
    parser.add_argument("--max-snippet-chars", type=int, default=12000)
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--force", action="store_true", help="Reprocess cases already present in results.jsonl.")
    parser.add_argument("--dry-run", action="store_true", help="Only write sample manifest.")
    parser.add_argument("--cve-pattern-library", help="Optional BugRC CVE pattern library JSON.")
    parser.add_argument("--ranker-calibration", help="Optional BugRC ranker calibration JSON.")
    parser.add_argument("--project-prior", help="Optional BugRC project prior JSON.")
    parser.add_argument("--expert-rca-prior", help="Optional expert RCA prior JSON, e.g., Project Zero RCA patterns.")
    parser.add_argument("--expert-rca-min-confidence", type=float, default=0.0)
    parser.add_argument("--expert-rca-weight", type=float, default=0.06)
    parser.add_argument(
        "--include-bugrc-patch-suggestions",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Include BugRC's conservative patch suggestions in the patch-generation evidence.",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    meta_dir = Path(args.meta_dir).expanduser().resolve()
    patch_dir = Path(args.patch_dir).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    repos_dir = Path(args.repos_dir).expanduser().resolve() if args.repos_dir else output_dir / "repos"
    repo_lock_dir = Path(args.repo_lock_dir).expanduser().resolve() if args.repo_lock_dir else repos_dir / ".locks"
    worktrees_dir = Path(args.worktrees_dir).expanduser().resolve() if args.worktrees_dir else output_dir / "worktrees"
    repos_dir.mkdir(parents=True, exist_ok=True)
    repo_lock_dir.mkdir(parents=True, exist_ok=True)
    worktrees_dir.mkdir(parents=True, exist_ok=True)

    sample = load_case_list(Path(args.case_list_file), meta_dir=meta_dir) if args.case_list_file else select_sample(
        meta_dir,
        sample_size=args.sample_size,
        seed=args.seed,
    )
    write_json(output_dir / "sample_manifest.json", {"seed": args.seed, "sample_size": len(sample), "cases": sample})
    if args.dry_run:
        print(f"Sample manifest: {output_dir / 'sample_manifest.json'}")
        return 0

    done_ids = set() if args.force else load_done_ids(output_dir / "results.jsonl")
    llm_cache_dir = output_dir / "llm_cache"
    llm_cache_dir.mkdir(exist_ok=True)

    for index, case in enumerate(sample, start=1):
        local_id = str(case["local_id"])
        if local_id in done_ids:
            print(f"[{index}/{len(sample)}] {local_id}: already done")
            continue
        print(f"[{index}/{len(sample)}] {local_id}: processing", flush=True)
        started = time.time()
        try:
            with case_timeout(args.case_timeout):
                result = process_case(
                    local_id=local_id,
                    meta_path=Path(case["meta_path"]),
                    patch_path=patch_dir / f"{local_id}.diff",
                    repos_dir=repos_dir,
                    repo_lock_dir=repo_lock_dir,
                    worktrees_dir=worktrees_dir,
                    output_dir=output_dir,
                    llm_cache_dir=llm_cache_dir,
                    args=args,
                )
            result["elapsed_seconds"] = round(time.time() - started, 3)
        except Exception as exc:
            result = {
                "local_id": local_id,
                "status": "failed",
                "error": f"{type(exc).__name__}: {exc}",
                "elapsed_seconds": round(time.time() - started, 3),
            }
        append_jsonl(output_dir / "results.jsonl", result)
        write_summary(output_dir / "results.jsonl", output_dir / "summary.json")
        print(f"[{index}/{len(sample)}] {local_id}: {result.get('status')}", flush=True)

    write_summary(output_dir / "results.jsonl", output_dir / "summary.json")
    print(f"Results: {output_dir / 'results.jsonl'}")
    print(f"Summary: {output_dir / 'summary.json'}")
    return 0


@contextlib.contextmanager
def case_timeout(timeout_seconds: int) -> Iterable[None]:
    """Interrupt CPU-bound per-case analysis that subprocess timeouts cannot stop."""

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


def select_sample(meta_dir: Path, *, sample_size: int, seed: int) -> list[dict[str, str]]:
    meta_files = sorted(meta_dir.glob("*.json"), key=lambda path: int(path.stem) if path.stem.isdigit() else path.stem)
    rng = random.Random(seed)
    selected = rng.sample(meta_files, min(sample_size, len(meta_files)))
    return [{"local_id": path.stem, "meta_path": path.as_posix()} for path in selected]


def load_case_list(path: Path, *, meta_dir: Path) -> list[dict[str, str]]:
    """Load a fixed case list from JSON or newline-delimited ids."""
    text = path.expanduser().resolve().read_text(encoding="utf-8")
    cases: list[dict[str, str]] = []
    if path.suffix.lower() == ".json":
        payload = json.loads(text)
        raw_cases = payload.get("cases", payload) if isinstance(payload, dict) else payload
        if not isinstance(raw_cases, list):
            raise ValueError("case list JSON must be a list or an object containing a cases list")
        for item in raw_cases:
            if isinstance(item, dict):
                local_id = str(item.get("local_id") or item.get("id") or "").strip()
                meta_path = item.get("meta_path")
            else:
                local_id = str(item).strip()
                meta_path = None
            if not local_id:
                continue
            path_value = Path(str(meta_path)).expanduser() if meta_path else meta_dir / f"{local_id}.json"
            cases.append({"local_id": local_id, "meta_path": path_value.resolve().as_posix()})
        return cases

    for line in text.splitlines():
        local_id = line.strip()
        if not local_id or local_id.startswith("#"):
            continue
        cases.append({"local_id": local_id, "meta_path": (meta_dir / f"{local_id}.json").resolve().as_posix()})
    return cases


def process_case(
    *,
    local_id: str,
    meta_path: Path,
    patch_path: Path,
    repos_dir: Path,
    repo_lock_dir: Path,
    worktrees_dir: Path,
    output_dir: Path,
    llm_cache_dir: Path,
    args: argparse.Namespace,
) -> dict[str, Any]:
    deadline = time.time() + max(args.case_timeout, 1)
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    report_text = extract_report_text(meta)
    crash_state = extract_crash_state(report_text)
    repo_url = normalize_repo_url(str(meta.get("repo_addr") or ""))
    fix_commit = str(meta.get("fix_commit") or "").strip()
    if not repo_url or not fix_commit:
        return base_result(local_id, meta, status="skipped", reason="missing_repo_or_fix_commit")

    initial_llm = call_json_llm(
        cache_dir=llm_cache_dir,
        api_base_url=args.api_base_url,
        model=args.model,
        timeout=args.llm_timeout,
        task="initial_root_cause",
        prompt=build_initial_root_cause_prompt(meta, report_text, crash_state),
    )
    if time.time() > deadline:
        raise TimeoutError("case timeout after initial LLM call")

    repo_path = ensure_repo(repo_url, repos_dir=repos_dir, lock_dir=repo_lock_dir, timeout=args.git_timeout)
    worktree_path = ensure_prefixed_worktree(
        repo_path=repo_path,
        lock_dir=repo_lock_dir,
        worktrees_dir=worktrees_dir,
        local_id=local_id,
        fix_commit=fix_commit,
        timeout=args.git_timeout,
    )
    if time.time() > deadline:
        raise TimeoutError("case timeout after git preparation")

    selected_files = select_source_files(worktree_path, crash_state, max_files=args.max_source_files)
    bugrc_payload = run_bugrc_analysis(
        local_id=local_id,
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
        task="generate_patch",
        prompt=build_patch_generation_prompt(meta, report_text, initial_llm.payload, bugrc_payload, snippets),
    )

    official_patch = patch_path.read_text(encoding="utf-8", errors="replace") if patch_path.exists() else ""
    generated_diff = str(generated_patch.payload.get("unified_diff") or "")
    exact_match = bool(generated_diff and normalize_diff(generated_diff) == normalize_diff(official_patch))
    comparison: dict[str, Any]
    if not official_patch:
        comparison = {"status": "missing_official_patch", "exact_match": False}
    elif exact_match:
        comparison = {"status": "exact_match", "exact_match": True}
    else:
        comparison_llm = call_json_llm(
            cache_dir=llm_cache_dir,
            api_base_url=args.api_base_url,
            model=args.model,
            timeout=args.llm_timeout,
            task="compare_patch",
            prompt=build_patch_comparison_prompt(meta, report_text, bugrc_payload, generated_patch.payload, official_patch),
        )
        comparison = {"status": "semantic_judged", "exact_match": False, "llm": comparison_llm.payload}

    return {
        **base_result(local_id, meta, status="completed"),
        "meta_path": meta_path.as_posix(),
        "repo_url": repo_url,
        "fix_commit": fix_commit,
        "pre_fix_worktree": worktree_path.as_posix(),
        "crash_state": crash_state,
        "selected_source_files": selected_files,
        "llm_initial_root_cause": with_llm_meta(initial_llm),
        "bugrc": bugrc_payload,
        "source_snippet_count": len(snippets),
        "generated_patch": with_llm_meta(generated_patch),
        "official_patch_path": patch_path.as_posix() if patch_path.exists() else None,
        "patch_comparison": comparison,
    }


def run_bugrc_analysis(
    *,
    local_id: str,
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
    trigger_location = locate_trigger(index, crash_state)
    trigger_diagnostics: list[str] = []
    if trigger_location is None:
        if not program.functions:
            raise RuntimeError("could not locate trigger function and parsed source contains no functions")
        fallback = program.functions[0]
        trigger_location = SourceLocation(
            file=fallback.location.file,
            line=fallback.location.line,
            column=fallback.location.column,
            function=fallback.name,
            snippet=fallback.location.snippet,
        )
        trigger_diagnostics.append(
            "Crash-state function was not found in parsed source; using the first parsed function as an approximate trigger."
        )
    trigger = TriggerPoint(
        location=trigger_location,
        type=TriggerType.CRASH_LINE,
        failing_operation=crash_state[0] if crash_state else None,
        bug_type_hint=infer_bug_type(str(meta.get("crash_type") or "")),
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
        bug_id=f"arvo-{local_id}",
        repo_path=repo_path.as_posix(),
        title=f"ARVO-Meta {local_id} {meta.get('crash_type') or ''}".strip(),
        summary=shorten(report_text, 3000),
        trigger_point=trigger,
        issue_text=shorten(report_text, 12000),
        config=config,
        metadata={"project": meta.get("project"), "local_id": local_id},
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
            summary="ARVO evaluation analysis result for patch-suggestion evidence.",
            limitations=list(program.approximations) + list(backward_slice.approximations),
            metadata={"project": meta.get("project"), "local_id": local_id},
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
        "diagnostics": trigger_diagnostics
        + [diagnostic.to_dict() for diagnostic in program.diagnostics]
        + list(backward_slice.diagnostics),
    }


def locate_trigger(index: Any, crash_state: list[str]) -> Optional[SourceLocation]:
    for frame in crash_state:
        names = function_name_variants(frame)
        for function in index.program.functions:
            qualified = function.qualified_name or function.name
            if function.name in names or qualified in names or any(name and name in qualified for name in names):
                return SourceLocation(
                    file=function.location.file,
                    line=function.location.line,
                    column=function.location.column,
                    function=function.name,
                    snippet=function.location.snippet,
                )
    return None


def select_source_files(repo_path: Path, crash_state: list[str], *, max_files: int) -> list[str]:
    all_files = sorted(
        path.relative_to(repo_path).as_posix()
        for path in repo_path.rglob("*")
        if path.is_file() and path.suffix.lower() in C_EXTENSIONS and ".git" not in path.parts
    )
    if not crash_state:
        return all_files[:max_files]
    terms = [variant for frame in crash_state[:5] for variant in function_name_variants(frame)]
    terms = [term for term in terms if len(term) >= 3]
    matched: list[str] = []
    for rel_path in all_files:
        if len(matched) >= max_files:
            break
        path = repo_path / rel_path
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if any(term in text for term in terms):
            matched.append(rel_path)
    if matched:
        return matched[:max_files]
    return all_files[:max_files]


def collect_source_snippets(repo_path: Path, bugrc_payload: dict[str, Any], *, max_chars: int) -> list[dict[str, Any]]:
    snippets: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    locations = [bugrc_payload.get("trigger", {}).get("location", {})]
    locations.extend(candidate.get("location", {}) for candidate in bugrc_payload.get("candidates", []) or [])
    for location in locations:
        file_name = location.get("file")
        line = int(location.get("line") or 1)
        if not file_name or (file_name, line) in seen:
            continue
        seen.add((file_name, line))
        path = repo_path / file_name
        if not path.exists():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        start = max(line - 25, 1)
        end = min(line + 25, len(lines))
        body = "\n".join(f"{idx}: {lines[idx-1]}" for idx in range(start, end + 1))
        snippets.append({"file": file_name, "line": line, "function": location.get("function"), "snippet": body})
        if len(json.dumps(snippets)) >= max_chars:
            break
    return snippets


def call_json_llm(
    *,
    cache_dir: Path,
    api_base_url: str,
    model: str,
    timeout: int,
    task: str,
    prompt: str,
) -> LLMResult:
    cache_key = hashlib.sha256(f"{model}\n{task}\n{prompt}".encode("utf-8")).hexdigest()
    cache_path = cache_dir / f"{cache_key}.json"
    if cache_path.exists():
        try:
            return LLMResult(payload=json.loads(cache_path.read_text(encoding="utf-8")), cached=True)
        except json.JSONDecodeError:
            cache_path.unlink(missing_ok=True)
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return LLMResult(payload={"error": "OPENAI_API_KEY is not set"}, cached=False, error="missing_api_key")

    request_payload = {
        "model": model,
        "temperature": 0,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": "You are a careful software vulnerability analysis assistant. Return only valid JSON."},
            {"role": "user", "content": prompt},
        ],
    }
    request = urllib.request.Request(
        api_base_url.rstrip("/") + "/chat/completions",
        data=json.dumps(request_payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    last_error: Optional[BaseException] = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = json.loads(response.read().decode("utf-8"))
            content = raw["choices"][0]["message"]["content"]
            parsed = json.loads(content)
            cache_path.write_text(json.dumps(parsed, indent=2, ensure_ascii=False), encoding="utf-8")
            return LLMResult(payload=parsed, cached=False)
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code not in {429, 500, 502, 503, 504} or attempt == 2:
                break
            time.sleep(5 * (attempt + 1))
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = exc
            if attempt == 2:
                break
            time.sleep(3 * (attempt + 1))
        except (KeyError, json.JSONDecodeError, OSError) as exc:
            last_error = exc
            break
    error = last_error or RuntimeError("unknown LLM call failure")
    return LLMResult(payload={"error": f"{type(error).__name__}: {error}"}, cached=False, error=str(error))


def build_initial_root_cause_prompt(meta: dict[str, Any], report_text: str, crash_state: list[str]) -> str:
    return f"""Analyze this OSS-Fuzz style C/C++ bug report without using the official patch.

Return JSON with:
{{
  "root_cause_summary": "...",
  "likely_bug_pattern": "...",
  "likely_root_cause_functions": ["..."],
  "trigger_functions": ["..."],
  "patch_strategy": "...",
  "confidence": 0.0
}}

Metadata:
project={meta.get('project')}
sanitizer={meta.get('sanitizer')}
crash_type={meta.get('crash_type')}
crash_state={crash_state}

Report:
{shorten(report_text, 10000)}
"""


def build_patch_generation_prompt(
    meta: dict[str, Any],
    report_text: str,
    initial_root_cause: dict[str, Any],
    bugrc_payload: dict[str, Any],
    snippets: list[dict[str, Any]],
) -> str:
    slim_bugrc = {
        "trigger": bugrc_payload.get("trigger"),
        "candidates": bugrc_payload.get("candidates", [])[:5],
        "chains": bugrc_payload.get("chains", [])[:3],
        "patch_suggestions": bugrc_payload.get("patch_suggestions", [])[:3],
    }
    return f"""Generate a source patch for this bug using only the bug report, BugRC root-cause candidates, causality chains, and source snippets. Do not use or assume the official patch.

Primary goal:
- Identify the root-cause-to-trigger vulnerability path.
- Patch the earliest safe cut point that blocks that path.
- Make the patch explainable as evidence that the vulnerability path is cut.

Patch requirements:
- Return a unified diff relative to the pre-fix repository.
- Cut the bug at or before the root cause when possible, not merely at the crash symptom.
- Preserve resource balance: allocated memory must still be freed, locks must be released, and reference counts/state must remain balanced.
- If changing global or persistent state, restore it on error paths.
- Avoid changing unrelated behavior not implicated by the bug.
- If exact code is insufficient, produce the smallest plausible patch and mark "is_pseudo_patch": true.
- Prefer a patch that repairs invalid state, size/length calculation, ownership/lifetime, initialization, or missing validation before propagation.
- If the safest patch is a guard, explain why it cuts every relevant path and why it is not only hiding the symptom.

Return JSON with:
{{
  "root_cause_location": {{"file": "...", "function": "...", "line": 0}},
  "root_cause_summary": "...",
  "vulnerability_path": ["root cause step", "propagation step", "trigger step"],
  "cut_point": "...",
  "why_patch_blocks_path": "...",
  "patch_rationale": "...",
  "unified_diff": "...",
  "is_pseudo_patch": false,
  "resource_balance_plan": "...",
  "risk_notes": ["..."],
  "proof_obligations": ["what must be true for this patch to prove the path is blocked"],
  "confidence": 0.0
}}

Bug metadata:
project={meta.get('project')}
sanitizer={meta.get('sanitizer')}
crash_type={meta.get('crash_type')}

Initial LLM root cause:
{json.dumps(initial_root_cause, ensure_ascii=False)[:5000]}

BugRC evidence:
{json.dumps(slim_bugrc, ensure_ascii=False)[:14000]}

Source snippets:
{json.dumps(snippets, ensure_ascii=False)[:16000]}

Bug report:
{shorten(report_text, 6000)}
"""


def build_patch_comparison_prompt(
    meta: dict[str, Any],
    report_text: str,
    bugrc_payload: dict[str, Any],
    generated_patch: dict[str, Any],
    official_patch: str,
) -> str:
    return f"""Compare BugRC's generated patch against the official patch for the same bug.

Evaluation goal:
- Decide whether BugRC's patch better blocks the root-cause-to-trigger vulnerability path.
- Decide whether the official patch fully cuts that same path, only mitigates a symptom, adds a compensating guard, or misses an upstream root cause.
- A claim that BugRC is better requires evidence that BugRC's cut point blocks the vulnerability path and the official patch is incomplete, wrong, too narrow, or does not address the root cause.

Return JSON with:
{{
  "verdict": "exact_match | semantically_equivalent | official_patch_better | bugrc_patch_better | both_plausible | both_incomplete | unclear",
  "correct_patch": "official | bugrc | both | neither | unclear",
  "semantic_similarity": 0.0,
  "bugrc_patch_cuts_bug": true,
  "official_patch_cuts_bug": true,
  "bugrc_blocks_root_cause_path": true,
  "official_blocks_root_cause_path": true,
  "root_cause_to_trigger_chain": ["..."],
  "bugrc_cut_point": "...",
  "official_cut_point": "...",
  "official_patch_limitation": "none | symptom_only | compensating_guard | incomplete_path_coverage | wrong_location | refactor_or_cleanup | unknown",
  "missed_paths_by_official_patch": ["..."],
  "patch_proof_strength": "strong | moderate | weak | not_proven",
  "paper_claim": "official_incomplete_bugrc_blocks | bugrc_better_but_needs_validation | official_and_bugrc_both_cut_path | not_enough_evidence",
  "resource_balance_assessment": "...",
  "reasoning": "...",
  "confidence": 0.0
}}

Use conservative standards:
- Use "official_incomplete_bugrc_blocks" only if the evidence shows a root-cause path that BugRC blocks and the official patch does not fully block.
- If both patches plausibly cut the path, use semantically_equivalent, both_plausible, or official_patch_better.
- If BugRC patch is a pseudo patch, missing a concrete diff, or has resource-balance risk, do not make a strong proof claim.

Bug metadata:
project={meta.get('project')}
sanitizer={meta.get('sanitizer')}
crash_type={meta.get('crash_type')}

Bug report:
{shorten(report_text, 6000)}

BugRC trigger/candidates/chains:
{json.dumps({'trigger': bugrc_payload.get('trigger'), 'candidates': bugrc_payload.get('candidates', [])[:5], 'chains': bugrc_payload.get('chains', [])[:3], 'patch_suggestions': bugrc_payload.get('patch_suggestions', [])[:3]}, ensure_ascii=False)[:12000]}

BugRC generated patch:
{json.dumps(generated_patch, ensure_ascii=False)[:12000]}

Official patch:
{shorten(official_patch, 18000)}
"""


def ensure_repo(repo_url: str, *, repos_dir: Path, lock_dir: Path, timeout: int) -> Path:
    parsed = urlparse(repo_url)
    key_parts = [parsed.netloc or "unknown"] + [part for part in parsed.path.strip("/").split("/") if part]
    if key_parts[-1].endswith(".git"):
        key_parts[-1] = key_parts[-1][:-4]
    repo_path = repos_dir.joinpath(*key_parts)
    with file_lock(lock_dir, lock_name_for_repo(repo_path)):
        if (repo_path / ".git").exists():
            run(["git", "fetch", "--filter=blob:none", "origin"], cwd=repo_path, timeout=timeout, check=False)
            return repo_path
        repo_path.parent.mkdir(parents=True, exist_ok=True)
        run(["git", "clone", "--filter=blob:none", repo_url, repo_path.as_posix()], cwd=repos_dir, timeout=timeout)
        return repo_path


def ensure_prefixed_worktree(
    *,
    repo_path: Path,
    lock_dir: Path,
    worktrees_dir: Path,
    local_id: str,
    fix_commit: str,
    timeout: int,
) -> Path:
    worktree_path = worktrees_dir / local_id / repo_path.name
    if worktree_path.exists():
        return worktree_path
    worktree_path.parent.mkdir(parents=True, exist_ok=True)
    with file_lock(lock_dir, lock_name_for_repo(repo_path)):
        if worktree_path.exists():
            return worktree_path
        run(["git", "fetch", "origin", fix_commit, "--depth", "2"], cwd=repo_path, timeout=timeout, check=False)
        pre_fix_ref = f"{fix_commit}^"
        try:
            run(["git", "rev-parse", "--verify", pre_fix_ref], cwd=repo_path, timeout=timeout)
        except subprocess.CalledProcessError:
            run(["git", "fetch", "origin", fix_commit], cwd=repo_path, timeout=timeout, check=False)
        run(["git", "worktree", "add", "--detach", worktree_path.as_posix(), pre_fix_ref], cwd=repo_path, timeout=timeout)
    return worktree_path


@contextlib.contextmanager
def file_lock(lock_dir: Path, lock_name: str) -> Iterable[None]:
    """Serialize git operations touching the same shared repository cache."""
    lock_dir.mkdir(parents=True, exist_ok=True)
    lock_path = lock_dir / f"{lock_name}.lock"
    with lock_path.open("w", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def lock_name_for_repo(repo_path: Path) -> str:
    return hashlib.sha256(repo_path.as_posix().encode("utf-8")).hexdigest()


def run(command: list[str], *, cwd: Path, timeout: int, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=check,
    )


def extract_report_text(meta: dict[str, Any]) -> str:
    chunks = []
    for comment in (meta.get("report") or {}).get("comments", []) or []:
        content = comment.get("content")
        if content:
            chunks.append(str(content))
    return "\n\n".join(chunks)


def extract_crash_state(report_text: str) -> list[str]:
    match = re.search(r"Crash State:\s*\n(?P<body>.*?)(?:\n\s*\n|Sanitizer:|Recommended Security Severity:)", report_text, re.S | re.I)
    if not match:
        return []
    frames = []
    for line in match.group("body").splitlines():
        value = line.strip()
        if value and not value.startswith("#"):
            frames.append(value)
    return frames[:10]


def function_name_variants(name: str) -> list[str]:
    cleaned = re.sub(r"<.*?>", "", name).strip()
    last = cleaned.split("::")[-1].strip()
    last = re.sub(r"\(.*", "", last).strip()
    variants = [cleaned, last]
    if " " in last:
        variants.append(last.split()[-1])
    return list(dict.fromkeys(value for value in variants if value))


def infer_bug_type(crash_type: str) -> Optional[BugType]:
    lowered = crash_type.lower()
    for token, bug_type in BUG_TYPE_BY_CRASH_TOKEN:
        if token in lowered:
            return bug_type
    return None


def normalize_repo_url(repo_url: str) -> str:
    value = repo_url.strip()
    if value.startswith("git@github.com:"):
        return "https://github.com/" + value.split(":", 1)[1]
    return value


def normalize_diff(diff: str) -> str:
    lines = []
    for line in diff.splitlines():
        if line.startswith(("commit ", "Author:", "Date:", "index ")):
            continue
        if line.startswith(("+++", "---", "diff --git", "@@", "+", "-")):
            lines.append(line.rstrip())
    return "\n".join(lines).strip()


def with_llm_meta(result: LLMResult) -> dict[str, Any]:
    return {"cached": result.cached, "error": result.error, "payload": result.payload}


def base_result(local_id: str, meta: dict[str, Any], *, status: str, reason: Optional[str] = None) -> dict[str, Any]:
    payload = {
        "local_id": local_id,
        "status": status,
        "project": meta.get("project"),
        "sanitizer": meta.get("sanitizer"),
        "crash_type": meta.get("crash_type"),
        "severity": meta.get("severity"),
    }
    if reason:
        payload["reason"] = reason
    return payload


def shorten(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n...[truncated]..."


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def load_done_ids(path: Path) -> set[str]:
    if not path.exists():
        return set()
    done: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if payload.get("status") == "completed" and payload.get("local_id"):
            done.add(str(payload["local_id"]))
    return done


def write_summary(results_path: Path, summary_path: Path) -> None:
    records = []
    if results_path.exists():
        for line in results_path.read_text(encoding="utf-8").splitlines():
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    statuses: dict[str, int] = {}
    comparison: dict[str, int] = {}
    semantic_verdicts: dict[str, int] = {}
    for record in records:
        statuses[str(record.get("status"))] = statuses.get(str(record.get("status")), 0) + 1
        comp = record.get("patch_comparison") or {}
        if comp:
            comparison[str(comp.get("status"))] = comparison.get(str(comp.get("status")), 0) + 1
            verdict = (comp.get("llm") or {}).get("verdict")
            if verdict:
                semantic_verdicts[str(verdict)] = semantic_verdicts.get(str(verdict), 0) + 1
    write_json(
        summary_path,
        {
            "record_count": len(records),
            "status_distribution": statuses,
            "patch_comparison_distribution": comparison,
            "semantic_verdict_distribution": semantic_verdicts,
            "updated_at_epoch": time.time(),
        },
    )


if __name__ == "__main__":
    raise SystemExit(main())
