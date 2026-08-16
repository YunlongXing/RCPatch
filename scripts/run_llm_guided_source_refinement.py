#!/usr/bin/env python3
"""Run source-based refinement for LLM-guided partial CVE records.

The input is the refinement target file produced by
`build_llm_guided_refinement_plan.py`. For each target this driver rebuilds the
pre-patch worktree, re-runs RCPatch's patch-anchored root-cause miner, and applies
the LLM guidance as a reranking signal. The LLM guidance is not treated as
ground truth; every refined candidate still comes from source/patch analysis.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import logging
import shutil
import signal
import sys
import time
from pathlib import Path
from typing import Any, Iterable, Optional


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
VENDOR_ROOT = PROJECT_ROOT / ".vendor"
if SRC_ROOT.exists():
    sys.path.insert(0, str(SRC_ROOT))
if VENDOR_ROOT.exists():
    sys.path.insert(0, str(VENDOR_ROOT))

from rcpatch.cve_mining import CVEPatchExtractor, CVERootCauseMiner  # noqa: E402
from rcpatch.logging_utils import configure_logging, get_logger  # noqa: E402
from rcpatch.models import CandidateLabel, CollectedCVERecord, ParserBackend, RootCauseCandidate  # noqa: E402


BOOTSTRAP_SCRIPT = PROJECT_ROOT / "scripts" / "bootstrap_cve_corpus.py"
BOOTSTRAP_SPEC = importlib.util.spec_from_file_location("bootstrap_cve_corpus", BOOTSTRAP_SCRIPT)
if BOOTSTRAP_SPEC is None or BOOTSTRAP_SPEC.loader is None:
    raise RuntimeError(f"Unable to import bootstrap helpers from {BOOTSTRAP_SCRIPT}")
BOOTSTRAP = importlib.util.module_from_spec(BOOTSTRAP_SPEC)
BOOTSTRAP_SPEC.loader.exec_module(BOOTSTRAP)

HIGH_VALUE_BUG_CLASSES = {
    "buffer_overflow",
    "heap_buffer_overflow",
    "stack_buffer_overflow",
    "out_of_bounds_read",
    "out_of_bounds_write",
    "use_after_free",
    "double_free",
    "null_dereference",
    "integer_overflow",
    "memory_corruption",
    "type_confusion",
}
GENERIC_PATTERNS = {"", "none", "unknown", "incorrect_size_computation"}


class TargetTimeoutError(RuntimeError):
    """Raised when one CVE refinement exceeds the configured wall-clock budget."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", required=True, help="partial_records_refinement_targets.json.")
    parser.add_argument("--collection-json", required=True, help="Full CVE collection JSON.")
    parser.add_argument("--repos-root", required=True, help="Repository cache root.")
    parser.add_argument("--output-dir", required=True, help="Output directory.")
    parser.add_argument("--max-targets", type=int, default=None, help="Optional cap over selected targets.")
    parser.add_argument("--parser-backend", default="regex", choices=[backend.value for backend in ParserBackend])
    parser.add_argument("--top-k", type=int, default=5, help="Refined candidates kept per CVE.")
    parser.add_argument("--mine-top-k", type=int, default=24, help="Raw candidates requested from the miner.")
    parser.add_argument("--min-refined-score", type=float, default=0.45)
    parser.add_argument("--git-timeout-seconds", type=int, default=30)
    parser.add_argument("--target-timeout-seconds", type=int, default=1200)
    parser.add_argument("--clone-filter", default="blob:none")
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--keep-worktrees", action="store_true")
    parser.add_argument("--force", action="store_true", help="Reprocess CVEs already present in refined_records.jsonl.")
    parser.add_argument("--log-level", default="INFO", choices=("DEBUG", "INFO", "WARNING", "ERROR"))
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(getattr(logging, args.log_level))
    logger = get_logger(__name__)

    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    worktrees_root = output_dir / "worktrees"
    worktrees_root.mkdir(parents=True, exist_ok=True)
    repos_root = Path(args.repos_root).expanduser().resolve()

    targets_payload = read_json(Path(args.targets).expanduser().resolve())
    targets = list(targets_payload.get("targets", []))
    if args.max_targets is not None:
        targets = targets[: max(0, args.max_targets)]
    target_cve_ids = [str(item.get("cve_id")) for item in targets if item.get("cve_id")]
    target_by_cve = {str(item.get("cve_id")): item for item in targets if item.get("cve_id")}

    logger.info("Loading %d target CVE records from collection", len(target_cve_ids))
    records_by_cve = load_collection_records(Path(args.collection_json).expanduser().resolve(), set(target_cve_ids))
    logger.info("Loaded %d target CVE records", len(records_by_cve))

    refined_path = output_dir / "refined_records.jsonl"
    failures_path = output_dir / "refinement_failures.jsonl"
    completed = set() if args.force else load_completed_cves(refined_path)

    patch_extractor = CVEPatchExtractor()
    miner = CVERootCauseMiner()
    status_path = output_dir / "refinement_status.json"
    write_status(
        status_path,
        state="running",
        total_targets=len(targets),
        completed=len(completed),
        output_dir=output_dir.as_posix(),
    )

    for index, cve_id in enumerate(target_cve_ids, start=1):
        if cve_id in completed:
            continue
        target = target_by_cve[cve_id]
        record = records_by_cve.get(cve_id)
        if record is None:
            failure = failure_payload(cve_id, "missing_collection_record", "CVE record was not found in collection JSON.")
            append_jsonl(failures_path, failure)
            logger.warning("Skipping %s: missing collection record", cve_id)
            continue

        logger.info("Refining %s (%d/%d)", cve_id, index, len(target_cve_ids))
        started = time.time()
        repo_root: Optional[Path] = None
        worktree_path: Optional[Path] = None
        try:
            with target_timeout(args.target_timeout_seconds, cve_id):
                repo_root = ensure_repo(record, repos_root, args=args)
                patch_extraction = patch_extractor.extract_for_record(record, repo_path=repo_root.as_posix())
                if patch_extraction.resolved_fix_commit is None:
                    raise RuntimeError("No resolved fix commit for refinement target")
                worktree_path = BOOTSTRAP.ensure_pre_patch_worktree(
                    repo_root=repo_root,
                    worktrees_root=worktrees_root,
                    cve_id=cve_id,
                    commit_sha=patch_extraction.resolved_fix_commit.commit_sha,
                    refresh=bool(args.refresh),
                )
                mining_result = miner.mine_for_record(
                    record,
                    patch_extraction,
                    pre_patch_repo_path=worktree_path.as_posix(),
                    parser_backend=ParserBackend(args.parser_backend),
                    top_k=args.mine_top_k,
                )
                refined_record = build_refined_record(
                    record=record,
                    target=target,
                    mining_result=mining_result,
                    patch_extraction=patch_extraction,
                    repo_path=worktree_path,
                    top_k=args.top_k,
                    min_refined_score=args.min_refined_score,
                    elapsed_seconds=time.time() - started,
                )
                append_jsonl(refined_path, refined_record)
                completed.add(cve_id)
                write_outputs(output_dir, refined_path, failures_path, total_targets=len(targets), completed=len(completed))
        except TargetTimeoutError as exc:
            failure = failure_payload(cve_id, "timeout", str(exc), target=target)
            append_jsonl(failures_path, failure)
            logger.warning("Timed out refining %s after %d seconds", cve_id, args.target_timeout_seconds)
        except Exception as exc:
            failure = failure_payload(cve_id, type(exc).__name__, str(exc), target=target)
            append_jsonl(failures_path, failure)
            logger.warning("Failed refining %s: %s", cve_id, exc)
        finally:
            if worktree_path is not None and not args.keep_worktrees:
                cleanup_worktree(repo_root, worktree_path, logger=logger)
            write_status(
                status_path,
                state="running",
                current_cve=cve_id,
                total_targets=len(targets),
                completed=len(completed),
                elapsed_seconds=round(time.time() - started, 2),
            )

    write_outputs(output_dir, refined_path, failures_path, total_targets=len(targets), completed=len(completed))
    write_status(status_path, state="finished", total_targets=len(targets), completed=len(completed))
    logger.info("Refinement complete: %d/%d", len(completed), len(targets))
    return 0


def ensure_repo(record: CollectedCVERecord, repos_root: Path, *, args: argparse.Namespace) -> Path:
    if not record.repo_url:
        raise RuntimeError("target CVE has no repository URL")
    repo_root = BOOTSTRAP.repo_local_path(repos_root, record.repo_url)
    BOOTSTRAP.ensure_repo_checkout(
        repo_url=record.repo_url,
        repo_root=repo_root,
        refresh=bool(args.refresh),
        clone_filter=args.clone_filter,
        git_timeout_seconds=args.git_timeout_seconds,
    )
    return repo_root


def build_refined_record(
    *,
    record: CollectedCVERecord,
    target: dict[str, Any],
    mining_result: Any,
    patch_extraction: Any,
    repo_path: Path,
    top_k: int,
    min_refined_score: float,
    elapsed_seconds: float,
) -> dict[str, Any]:
    scored_candidates = [
        score_candidate(candidate, target)
        for candidate in mining_result.candidates
    ]
    scored_candidates.sort(
        key=lambda item: (
            item["refined_score"],
            item["guidance_bonus"],
            item["source_score"],
            -int(item["candidate"].location.line or 0),
        ),
        reverse=True,
    )

    selected = [
        item
        for item in scored_candidates
        if item["refined_score"] >= min_refined_score
    ][:top_k]
    if not selected:
        selected = scored_candidates[:top_k]

    refined_causes = [
        serialize_refined_candidate(
            item,
            rank=rank,
            repo_path=repo_path,
            target=target,
            patch_extraction=patch_extraction,
        )
        for rank, item in enumerate(selected, start=1)
    ]
    old_actions = list(target.get("candidate_actions", []) or [])
    return {
        "schema_version": "rcpatch.llm_guided_source_refinement.v1",
        "cve_id": record.cve_id,
        "project": record.project,
        "repo_url": record.repo_url,
        "description": record.description,
        "llm_guidance": target.get("llm_validation", {}),
        "refinement_plan": target.get("refinement", {}),
        "old_candidate_actions": old_actions,
        "patch": {
            "resolved_fix_commit": (
                patch_extraction.resolved_fix_commit.commit_sha
                if patch_extraction.resolved_fix_commit is not None
                else None
            ),
            "patch_type": patch_extraction.patch_type.value if patch_extraction.patch_type else None,
            "patch_intent": patch_extraction.patch_intent.value if patch_extraction.patch_intent else None,
            "modified_files": list(patch_extraction.modified_files),
            "diagnostics": list(patch_extraction.diagnostics),
        },
        "mining": {
            "raw_candidate_count": len(mining_result.candidates),
            "anchor_count": len(mining_result.anchors),
            "slice_count": len(mining_result.slices),
            "diagnostics": list(mining_result.diagnostics),
            "approximations": list(mining_result.approximations),
            "metadata": mining_result.metadata,
        },
        "refined_root_causes": refined_causes,
        "metadata": {
            "elapsed_seconds": round(elapsed_seconds, 2),
            "repo_path": repo_path.as_posix(),
            "top_k": top_k,
            "source_analysis_required": True,
            "llm_guidance_is_ground_truth": False,
        },
    }


def score_candidate(candidate: RootCauseCandidate, target: dict[str, Any]) -> dict[str, Any]:
    source_score = candidate.score
    bonus = 0.0
    penalties = 0.0
    reasons: list[str] = []

    action = target.get("refinement", {}).get("primary_action")
    bug_class = normalize_token(target.get("llm_validation", {}).get("cve_bug_class"))
    query_terms = {normalize_token(term) for term in target.get("refinement", {}).get("suggested_query_terms", [])}
    old_action = match_old_candidate_action(candidate, target)
    old_refinement = normalize_token(old_action.get("candidate_refinement") if old_action else None)
    old_pattern_refinement = normalize_token(old_action.get("pattern_refinement") if old_action else None)

    if old_refinement == "retain_candidate":
        bonus += 0.22
        reasons.append("LLM candidate assessment retained this location.")
    elif old_refinement == "promote_for_recheck":
        bonus += 0.14
        reasons.append("LLM candidate assessment marked this location plausible but needing source recheck.")
    elif old_refinement in {"replace_candidate", "demote_symptom_or_noise"}:
        penalties += 0.32
        reasons.append("LLM candidate assessment suggested replacing or demoting the old candidate.")

    if candidate.features.get("patch_anchor_overlap"):
        bonus += 0.08
        reasons.append("Candidate overlaps a patch anchor.")
    if candidate.features.get("same_function_as_patch"):
        bonus += 0.12
        reasons.append("Candidate is in the same function as a patch anchor.")
    elif candidate.features.get("same_file_as_patch"):
        bonus += 0.06
        reasons.append("Candidate is in the same file as a patch anchor.")
    elif action in {"rerun_slice_from_patch_context", "demote_symptoms_and_search_upstream"}:
        penalties += 0.08
        reasons.append("Candidate remains outside patched files under a patch-context refinement action.")

    if candidate.features.get("defines_value_later_fixed"):
        bonus += 0.08
        reasons.append("Candidate defines a value later fixed by the patch.")
    if candidate.features.get("missing_check_replaced_by_patch"):
        bonus += 0.08
        reasons.append("Candidate is tied to a missing check replaced by the patch.")
    if candidate.features.get("incorrect_computation_replaced_by_patch"):
        bonus += 0.07
        reasons.append("Candidate participates in a computation corrected by the patch.")

    pattern = normalize_token(candidate.features.get("matched_bug_pattern") or candidate.bug_type_hint or "")
    snippet = normalize_token(candidate.location.snippet or "")
    if bug_class in HIGH_VALUE_BUG_CLASSES and (bug_class in query_terms or bug_class in snippet or bug_class in pattern):
        bonus += 0.05
        reasons.append("Candidate pattern/snippet aligns with the LLM-inferred vulnerability class.")
    if old_pattern_refinement == "specialize_pattern" and pattern in GENERIC_PATTERNS:
        penalties += 0.05
        reasons.append("Candidate retains a broad pattern that the refinement plan asked to specialize.")

    refined_score = max(0.0, min(1.0, source_score + bonus - penalties))
    return {
        "candidate": candidate,
        "source_score": source_score,
        "guidance_bonus": round(bonus, 4),
        "guidance_penalty": round(penalties, 4),
        "refined_score": round(refined_score, 6),
        "guidance_reasons": reasons,
        "matched_old_candidate_action": old_action,
    }


def serialize_refined_candidate(
    item: dict[str, Any],
    *,
    rank: int,
    repo_path: Path,
    target: dict[str, Any],
    patch_extraction: Any,
) -> dict[str, Any]:
    candidate: RootCauseCandidate = item["candidate"]
    location = candidate.location
    return {
        "rank": rank,
        "location": location.to_dict(),
        "code_snippet": read_snippet(repo_path, location.file, location.line, fallback=location.snippet),
        "classification": CandidateLabel.ROOT_CAUSE_CANDIDATE.value,
        "type": candidate.features.get("matched_bug_pattern") or (candidate.bug_type_hint.value if candidate.bug_type_hint else candidate.label.value),
        "pattern": candidate.features.get("matched_bug_pattern"),
        "source_score": item["source_score"],
        "refined_score": item["refined_score"],
        "guidance_bonus": item["guidance_bonus"],
        "guidance_penalty": item["guidance_penalty"],
        "guidance_reasons": item["guidance_reasons"],
        "explanation": candidate.explanation,
        "patch_relation": patch_relation(candidate),
        "candidate_origin": candidate.features.get("candidate_origin"),
        "candidate_rank": candidate.rank,
        "features": candidate.features,
        "matched_old_candidate_action": item.get("matched_old_candidate_action"),
        "refinement_action": target.get("refinement", {}).get("primary_action"),
        "patch_type": patch_extraction.patch_type.value if patch_extraction.patch_type else None,
    }


def match_old_candidate_action(candidate: RootCauseCandidate, target: dict[str, Any]) -> Optional[dict[str, Any]]:
    for action in target.get("candidate_actions", []) or []:
        location = action.get("location") or {}
        if (
            str(location.get("file")) == candidate.location.file
            and int(location.get("line") or -1) == candidate.location.line
            and (not location.get("function") or location.get("function") == candidate.location.function)
        ):
            return action
    return None


def patch_relation(candidate: RootCauseCandidate) -> str:
    if candidate.features.get("patch_anchor_overlap"):
        return "patch_anchor_overlap"
    if candidate.features.get("same_function_as_patch"):
        return "same_function_as_patch"
    if candidate.features.get("same_file_as_patch"):
        return "same_file_as_patch"
    return "outside_patched_files"


def read_snippet(repo_path: Path, file_path: str, line: int, *, fallback: Optional[str]) -> str:
    if fallback:
        return fallback
    source_path = repo_path / file_path
    try:
        lines = source_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return f"{file_path}:{line}"
    if line < 1 or line > len(lines):
        return f"{file_path}:{line}"
    return lines[line - 1].rstrip()


def write_outputs(output_dir: Path, refined_path: Path, failures_path: Path, *, total_targets: int, completed: int) -> None:
    records = load_jsonl(refined_path)
    failures = load_jsonl(failures_path)
    dataset = {
        "metadata": {
            "schema_version": "rcpatch.llm_guided_source_refinement_dataset.v1",
            "record_count": len(records),
            "total_targets": total_targets,
            "completed_targets": completed,
            "failure_count": len(failures),
            "llm_guidance_is_ground_truth": False,
        },
        "records": records,
    }
    write_json(output_dir / "refined_dataset.json", dataset)
    summary = {
        "schema_version": "rcpatch.llm_guided_source_refinement_summary.v1",
        "total_targets": total_targets,
        "completed_targets": completed,
        "refined_record_count": len(records),
        "failure_count": len(failures),
        "action_distribution": count_nested(records, ("refinement_plan", "primary_action")),
        "selected_pattern_distribution": count_selected_patterns(records),
    }
    write_json(output_dir / "refinement_summary.json", summary)


def count_nested(records: list[dict[str, Any]], path: tuple[str, ...]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        value: Any = record
        for key in path:
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(key)
        text = str(value or "unknown")
        counts[text] = counts.get(text, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def count_selected_patterns(records: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        for cause in record.get("refined_root_causes", []):
            pattern = str(cause.get("pattern") or cause.get("type") or "unknown")
            counts[pattern] = counts.get(pattern, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:50])


def load_collection_records(path: Path, cve_ids: set[str]) -> dict[str, CollectedCVERecord]:
    records = {}
    for item in iter_collection_records(path):
        cve_id = str(item.get("cve_id", ""))
        if cve_id not in cve_ids:
            continue
        records[cve_id] = CollectedCVERecord.from_dict(item)
        if len(records) >= len(cve_ids):
            break
    return records


def iter_collection_records(path: Path) -> Iterable[dict[str, Any]]:
    in_records = False
    in_object = False
    depth = 0
    buffer: list[str] = []
    in_string = False
    escape = False
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not in_records:
                if '"records"' in line and "[" in line:
                    in_records = True
                continue
            stripped = line.strip()
            if not in_object:
                if stripped.startswith("]"):
                    break
                if not stripped.startswith("{"):
                    continue
                in_object = True
                buffer = [line]
                depth, in_string, escape = update_json_depth(line, 0, False, False)
            else:
                buffer.append(line)
                depth, in_string, escape = update_json_depth(line, depth, in_string, escape)
            if in_object and depth == 0:
                text = "".join(buffer).strip()
                if text.endswith(","):
                    text = text[:-1]
                try:
                    payload = json.loads(text)
                except json.JSONDecodeError:
                    payload = {}
                if isinstance(payload, dict):
                    yield payload
                in_object = False
                buffer = []
                in_string = False
                escape = False


def update_json_depth(line: str, depth: int, in_string: bool, escape: bool) -> tuple[int, bool, bool]:
    for char in line:
        if escape:
            escape = False
            continue
        if char == "\\" and in_string:
            escape = True
            continue
        if char == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
    return depth, in_string, escape


def cleanup_worktree(repo_root: Optional[Path], worktree_path: Path, *, logger: logging.Logger) -> None:
    if repo_root is not None and repo_root.exists():
        try:
            BOOTSTRAP.run_git(["worktree", "remove", "--force", worktree_path.as_posix()], cwd=repo_root)
            BOOTSTRAP.run_git(["worktree", "prune"], cwd=repo_root)
            return
        except Exception as exc:
            logger.debug("git worktree cleanup failed for %s: %s", worktree_path, exc)
    shutil.rmtree(worktree_path, ignore_errors=True)


class target_timeout:
    def __init__(self, seconds: int, cve_id: str) -> None:
        self.seconds = seconds
        self.cve_id = cve_id
        self.previous_handler: Any = None

    def __enter__(self) -> None:
        if self.seconds <= 0 or not hasattr(signal, "SIGALRM"):
            return
        self.previous_handler = signal.getsignal(signal.SIGALRM)
        signal.signal(signal.SIGALRM, self._handle_timeout)
        signal.alarm(self.seconds)

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self.seconds <= 0 or not hasattr(signal, "SIGALRM"):
            return
        signal.alarm(0)
        if self.previous_handler is not None:
            signal.signal(signal.SIGALRM, self.previous_handler)

    def _handle_timeout(self, signum: int, frame: object) -> None:
        raise TargetTimeoutError(f"{self.cve_id} exceeded {self.seconds} seconds")


def failure_payload(cve_id: str, reason: str, message: str, *, target: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    return {
        "schema_version": "rcpatch.llm_guided_source_refinement_failure.v1",
        "cve_id": cve_id,
        "reason": reason,
        "message": message,
        "target_action": (target or {}).get("refinement", {}).get("primary_action"),
    }


def load_completed_cves(path: Path) -> set[str]:
    return {str(item.get("cve_id")) for item in load_jsonl(path) if item.get("cve_id")}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    items: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                items.append(item)
    return items


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True, ensure_ascii=False) + "\n")
        handle.flush()


def read_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def write_status(path: Path, **payload: Any) -> None:
    payload["updated_at_epoch"] = time.time()
    write_json(path, payload)


def normalize_token(value: Any) -> str:
    text = str(value or "").strip().lower()
    for attr in ("value",):
        if hasattr(value, attr):
            text = str(getattr(value, attr)).strip().lower()
    return "_".join("".join(ch if ch.isalnum() else "_" for ch in text).split("_")).strip("_") or "unknown"


if __name__ == "__main__":
    raise SystemExit(main())
