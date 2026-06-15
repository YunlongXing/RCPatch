#!/usr/bin/env python3
"""Validate whether BugRC-generated Magma patches materialize on source trees.

This script is intentionally lighter than dynamic reproducer validation.  It
does not build Magma targets; instead it creates a clean detached worktree from
each recorded pre-fix Magma worktree and checks whether BugRC's generated
unified diff can be applied there.  The output is useful as a paper-facing
sanity check: a semantic patch judgment is much stronger when the patch also
materializes against the buggy source revision.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-jsonl", required=True, type=Path, help="Magma BugRC results.jsonl.")
    parser.add_argument("--output-dir", required=True, type=Path, help="Output directory for validation artifacts.")
    parser.add_argument("--max-targets", type=int, default=None, help="Optional maximum number of records to check.")
    parser.add_argument("--start-index", type=int, default=0, help="Start index into completed records.")
    parser.add_argument("--git-timeout", type=int, default=120)
    parser.add_argument("--keep-worktrees", action="store_true", help="Keep temporary validation worktrees for inspection.")
    parser.add_argument("--force", action="store_true", help="Reprocess records already present in validation_results.jsonl.")
    parser.add_argument(
        "--enable-refinement",
        action="store_true",
        help="Try a conservative source-based materialization pass when git/fuzzy apply fail.",
    )
    parser.add_argument(
        "--refinement-window-lines",
        type=int,
        default=120,
        help="Line-window around the generated hunk anchor used by the refinement pass.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    results_path = args.output_dir / "validation_results.jsonl"
    records = [record for record in load_jsonl(args.results_jsonl) if record.get("status") == "completed"]
    end_index = None if args.max_targets is None else args.start_index + args.max_targets
    selected = records[args.start_index : end_index]
    done = set() if args.force else load_done_ids(results_path)

    for absolute_index, record in enumerate(selected, start=args.start_index):
        case_id = str(record.get("local_id") or record.get("bug_id") or absolute_index)
        if case_id in done:
            print(f"[{absolute_index}] {case_id}: already done", flush=True)
            continue
        print(f"[{absolute_index}] {case_id}: checking patch applicability", flush=True)
        started = time.time()
        try:
            result = validate_one(record, args)
            result["status"] = "completed"
        except Exception as exc:  # noqa: BLE001 - batch validation should keep going.
            result = {
                "local_id": case_id,
                "bug_id": record.get("bug_id"),
                "target": record.get("target"),
                "status": "failed",
                "error": f"{type(exc).__name__}: {exc}",
            }
        result["elapsed_seconds"] = round(time.time() - started, 3)
        append_jsonl(results_path, result)
        write_summary(results_path, args.output_dir / "validation_summary.json")
        print(f"[{absolute_index}] {case_id}: {result.get('patch_apply', {}).get('reason') or result.get('status')}", flush=True)

    write_summary(results_path, args.output_dir / "validation_summary.json")
    print(f"Results: {results_path}")
    print(f"Summary: {args.output_dir / 'validation_summary.json'}")
    return 0


def validate_one(record: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    case_id = str(record.get("local_id") or record.get("bug_id"))
    case_dir = args.output_dir / "cases" / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    source_worktree = Path(str(record.get("pre_fix_worktree") or ""))
    generated_diff = normalize_patch_text(
        str(((record.get("generated_patch") or {}).get("payload") or {}).get("unified_diff") or "")
    )
    patch_path = case_dir / "bugrc_generated.patch"
    patch_path.write_text(generated_diff, encoding="utf-8")

    comparison = record.get("patch_comparison") or {}
    llm = comparison.get("llm") or {}
    patch_apply: dict[str, Any]
    temp_worktree = case_dir / "worktree"
    if not source_worktree.exists():
        patch_apply = {"applied": False, "reason": "missing_source_worktree"}
    elif not generated_diff.strip():
        patch_apply = {"applied": False, "reason": "missing_generated_diff"}
    elif not looks_like_unified_diff(generated_diff):
        patch_apply = {"applied": False, "reason": "generated_patch_not_unified_diff"}
    else:
        temp_worktree = prepare_clean_worktree(source_worktree, temp_worktree, args.git_timeout)
        patch_apply = apply_patch(
            temp_worktree,
            patch_path,
            args.git_timeout,
            allow_fuzzy=True,
            allow_refinement=args.enable_refinement,
            refinement_window_lines=args.refinement_window_lines,
        )
        if patch_apply.get("applied"):
            changed_files = run(["git", "diff", "--name-only"], cwd=temp_worktree, timeout=args.git_timeout, check=False)
            diff_stat = run(["git", "diff", "--stat"], cwd=temp_worktree, timeout=args.git_timeout, check=False)
            patch_apply["changed_files"] = changed_files.stdout.splitlines()
            patch_apply["diff_stat"] = diff_stat.stdout[-4000:]

    if not args.keep_worktrees and temp_worktree.exists():
        remove_temp_worktree(source_worktree, temp_worktree, args.git_timeout)

    return {
        "local_id": case_id,
        "bug_id": record.get("bug_id"),
        "target": record.get("target"),
        "magma_patch_path": record.get("magma_patch_path"),
        "pre_fix_worktree": source_worktree.as_posix() if source_worktree else None,
        "semantic_verdict": llm.get("verdict"),
        "paper_claim": llm.get("paper_claim"),
        "semantic_confidence": llm.get("confidence"),
        "generated_patch_is_pseudo": ((record.get("generated_patch") or {}).get("payload") or {}).get("is_pseudo"),
        "generated_patch_length": len(generated_diff),
        "materialization_refinement_enabled": args.enable_refinement,
        "patch_path": patch_path.as_posix(),
        "patch_apply": patch_apply,
    }


def prepare_clean_worktree(source_worktree: Path, temp_worktree: Path, timeout: int) -> Path:
    if temp_worktree.exists():
        remove_temp_worktree(source_worktree, temp_worktree, timeout)
    temp_worktree.parent.mkdir(parents=True, exist_ok=True)
    run(["git", "worktree", "prune"], cwd=source_worktree, timeout=timeout, check=False)
    head = run(["git", "rev-parse", "HEAD"], cwd=source_worktree, timeout=timeout)
    run(
        ["git", "worktree", "add", "--detach", temp_worktree.as_posix(), head.stdout.strip()],
        cwd=source_worktree,
        timeout=timeout,
    )
    return temp_worktree


def remove_temp_worktree(source_worktree: Path, temp_worktree: Path, timeout: int) -> None:
    if temp_worktree.exists():
        run(["git", "worktree", "remove", "--force", temp_worktree.as_posix()], cwd=source_worktree, timeout=timeout, check=False)
    if temp_worktree.exists():
        shutil.rmtree(temp_worktree, ignore_errors=True)
    if source_worktree.exists():
        run(["git", "worktree", "prune"], cwd=source_worktree, timeout=timeout, check=False)


def apply_patch(
    worktree: Path,
    patch_path: Path,
    timeout: int,
    *,
    allow_fuzzy: bool,
    allow_refinement: bool,
    refinement_window_lines: int,
) -> dict[str, Any]:
    check = run(["git", "apply", "--check", patch_path.as_posix()], cwd=worktree, timeout=timeout, check=False)
    if check.returncode == 0:
        applied = run(["git", "apply", patch_path.as_posix()], cwd=worktree, timeout=timeout, check=False)
        return patch_application_payload("git_apply", applied, worktree, patch_path, timeout)

    three_way_check = run(["git", "apply", "--3way", "--check", patch_path.as_posix()], cwd=worktree, timeout=timeout, check=False)
    if three_way_check.returncode == 0:
        applied = run(["git", "apply", "--3way", patch_path.as_posix()], cwd=worktree, timeout=timeout, check=False)
        payload = patch_application_payload("git_apply_3way", applied, worktree, patch_path, timeout)
        payload["raw_git_apply_stderr"] = check.stderr[-4000:]
        return payload

    if allow_fuzzy:
        fuzzy = fuzzy_apply_patch(worktree, patch_path)
        if fuzzy.get("applied"):
            diff_check = run(["git", "diff", "--check"], cwd=worktree, timeout=timeout, check=False)
            fuzzy.update(
                {
                    "patch_path": patch_path.as_posix(),
                    "raw_git_apply_stderr": check.stderr[-4000:],
                    "raw_git_apply_3way_stderr": three_way_check.stderr[-4000:],
                    "diff_check_returncode": diff_check.returncode,
                    "diff_check_stdout": diff_check.stdout[-4000:],
                    "diff_check_stderr": diff_check.stderr[-4000:],
                }
            )
            return fuzzy

    if allow_refinement:
        refined = refine_apply_patch(worktree, patch_path, window_lines=refinement_window_lines)
        if refined.get("applied"):
            diff_check = run(["git", "diff", "--check"], cwd=worktree, timeout=timeout, check=False)
            refined.update(
                {
                    "patch_path": patch_path.as_posix(),
                    "raw_git_apply_stderr": check.stderr[-4000:],
                    "raw_git_apply_3way_stderr": three_way_check.stderr[-4000:],
                    "diff_check_returncode": diff_check.returncode,
                    "diff_check_stdout": diff_check.stdout[-4000:],
                    "diff_check_stderr": diff_check.stderr[-4000:],
                }
            )
            return refined

    return {
        "applied": False,
        "reason": "git_apply_check_failed",
        "patch_path": patch_path.as_posix(),
        "stdout": check.stdout[-4000:],
        "stderr": check.stderr[-4000:],
        "three_way_stdout": three_way_check.stdout[-4000:],
        "three_way_stderr": three_way_check.stderr[-4000:],
    }


def patch_application_payload(
    method: str,
    proc: subprocess.CompletedProcess[str],
    worktree: Path,
    patch_path: Path,
    timeout: int,
) -> dict[str, Any]:
    diff_check = run(["git", "diff", "--check"], cwd=worktree, timeout=timeout, check=False)
    return {
        "applied": proc.returncode == 0,
        "reason": "applied" if proc.returncode == 0 else f"{method}_failed",
        "applied_method": method,
        "patch_path": patch_path.as_posix(),
        "stdout": proc.stdout[-4000:],
        "stderr": proc.stderr[-4000:],
        "diff_check_returncode": diff_check.returncode,
        "diff_check_stdout": diff_check.stdout[-4000:],
        "diff_check_stderr": diff_check.stderr[-4000:],
    }


def fuzzy_apply_patch(worktree: Path, patch_path: Path) -> dict[str, Any]:
    """Apply generated diffs by exact old-block replacement when git apply fails."""
    text = patch_path.read_text(encoding="utf-8", errors="replace")
    file_patches = parse_generated_file_patches(text)
    applied = 0
    failures: list[dict[str, Any]] = []
    for file_patch in file_patches:
        rel_path = str(file_patch["file"])
        path = worktree / rel_path
        if not path.exists():
            failures.append({"file": rel_path, "reason": "file_not_found"})
            continue
        original = path.read_text(encoding="utf-8", errors="replace")
        updated = original
        file_applied = 0
        for hunk in file_patch["hunks"]:
            old_text = "\n".join(hunk["old_lines"])
            new_text = "\n".join(hunk["new_lines"])
            if old_text and not old_text.endswith("\n"):
                old_text += "\n"
            if new_text and not new_text.endswith("\n"):
                new_text += "\n"
            if old_text and old_text in updated:
                updated = updated.replace(old_text, new_text, 1)
                file_applied += 1
                continue
            compact_old = "\n".join(line for line in hunk["old_lines"] if line.strip())
            compact_new = "\n".join(line for line in hunk["new_lines"] if line.strip())
            if compact_old and compact_old in updated:
                updated = updated.replace(compact_old, compact_new, 1)
                file_applied += 1
                continue
            failures.append({"file": rel_path, "reason": "old_block_not_found", "old_preview": old_text[:700]})
        if file_applied:
            path.write_text(updated, encoding="utf-8")
            applied += file_applied
    return {
        "applied": applied > 0 and not failures,
        "reason": "fuzzy_applied" if applied > 0 and not failures else "fuzzy_apply_incomplete",
        "applied_method": "fuzzy_block_replace",
        "applied_hunks": applied,
        "failures": failures[:20],
    }


def refine_apply_patch(worktree: Path, patch_path: Path, *, window_lines: int) -> dict[str, Any]:
    """Materialize malformed generated diffs by inserting extracted guard blocks.

    The LLM-generated Magma diffs often describe a valid security check but
    produce an invalid hunk, for example by truncating the rest of the function.
    This pass deliberately does not try to rewrite whole functions.  It only
    inserts newly introduced validation/control-flow blocks near the generated
    hunk anchor when there is enough local context to place them.
    """
    text = patch_path.read_text(encoding="utf-8", errors="replace")
    file_patches = parse_generated_file_patches(text)
    applied_blocks = 0
    details: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for file_patch in file_patches:
        rel_path = str(file_patch["file"])
        path = worktree / rel_path
        if not path.exists():
            failures.append({"file": rel_path, "reason": "file_not_found"})
            continue
        original_text = path.read_text(encoding="utf-8", errors="replace")
        lines = original_text.splitlines()
        file_applied = 0
        for hunk_index, hunk in enumerate(file_patch["hunks"]):
            block_results = apply_refined_hunk(lines, hunk, window_lines=window_lines)
            for block_result in block_results:
                if block_result["applied"]:
                    file_applied += 1
                    applied_blocks += 1
                    details.append({"file": rel_path, "hunk": hunk_index, **block_result})
                else:
                    failures.append({"file": rel_path, "hunk": hunk_index, **block_result})
        if file_applied:
            path.write_text("\n".join(lines) + ("\n" if original_text.endswith("\n") else ""), encoding="utf-8")
    hard_failures = [failure for failure in failures if failure.get("reason") != "no_refinable_added_blocks"]
    return {
        "applied": applied_blocks > 0 and not hard_failures,
        "reason": "refined_guard_insertion" if applied_blocks > 0 and not hard_failures else "refinement_incomplete",
        "applied_method": "semantic_guard_insertion",
        "applied_blocks": applied_blocks,
        "refinement_details": details[:20],
        "failures": failures[:20],
    }


def apply_refined_hunk(lines: list[str], hunk: dict[str, Any], *, window_lines: int) -> list[dict[str, Any]]:
    added_blocks = extract_refinable_added_blocks(hunk)
    if not added_blocks:
        return [{"applied": False, "reason": "no_refinable_added_blocks"}]
    results: list[dict[str, Any]] = []
    line_offset = 0
    for block in added_blocks:
        placement = place_added_block(
            lines,
            block,
            old_start=max(1, int(hunk.get("old_start") or 1) + line_offset),
            window_lines=window_lines,
        )
        if placement["applied"]:
            line_offset += len(block["lines"])
        results.append(placement)
    return results


def extract_refinable_added_blocks(hunk: dict[str, Any]) -> list[dict[str, Any]]:
    entries: list[tuple[str, str]] = hunk.get("entries") or []
    old_norms = Counter(normalize_source_line(line) for line in hunk.get("old_lines", []) if normalize_source_line(line))
    old_norm_set = set(old_norms)
    blocks: list[dict[str, Any]] = []
    index = 0
    while index < len(entries):
        prefix, _ = entries[index]
        if prefix != "+":
            index += 1
            continue
        start = index
        raw_added: list[str] = []
        while index < len(entries) and entries[index][0] == "+":
            cleaned = clean_generated_added_line(entries[index][1])
            if cleaned is not None:
                raw_added.append(cleaned)
            index += 1
        for candidate in extract_guard_candidates_from_added_run(raw_added, old_norm_set):
            before_context = (
                collect_intra_run_context(raw_added, candidate["start"], old_norm_set, direction=-1)
                or collect_context(entries, start, direction=-1)
            )
            after_context = (
                collect_intra_run_context(raw_added, candidate["end"], old_norm_set, direction=1)
                or collect_context(entries, index, direction=1)
            )
            blocks.append(
                {
                    "lines": candidate["lines"],
                    "before_context": before_context,
                    "after_context": after_context,
                    "entry_index": start + candidate["start"],
                }
            )
    return merge_adjacent_added_blocks(blocks)


def extract_guard_candidates_from_added_run(raw_added: list[str], old_norm_set: set[str]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    index = 0
    while index < len(raw_added):
        line = raw_added[index]
        if not re.search(r"\bif\s*\(", line):
            index += 1
            continue
        if normalize_source_line(line) in old_norm_set:
            index += 1
            continue
        start = guard_candidate_start(raw_added, index, old_norm_set)
        start = expand_start_for_support_variables(raw_added, start, index, old_norm_set)
        end = guard_candidate_end(raw_added, index)
        candidate_lines = trim_unhelpful_edges([line.rstrip() for line in raw_added[start:end]])
        if is_refinable_block(candidate_lines) and has_new_information(candidate_lines, old_norm_set):
            candidates.append({"start": start, "end": end, "lines": candidate_lines})
        index = max(end, index + 1)
    return candidates


def guard_candidate_start(raw_added: list[str], if_index: int, old_norm_set: set[str]) -> int:
    start = if_index
    cursor = if_index - 1
    while cursor >= 0 and if_index - cursor <= 8:
        line = raw_added[cursor].rstrip()
        norm = normalize_source_line(line)
        if not norm:
            start = cursor + 1
            break
        if norm in old_norm_set and not is_comment_line(line):
            break
        if is_comment_line(line) or looks_like_support_statement(line):
            start = cursor
            cursor -= 1
            continue
        break
    return start


def expand_start_for_support_variables(raw_added: list[str], start: int, if_index: int, old_norm_set: set[str]) -> int:
    condition_vars = identifiers_in_line(raw_added[if_index])
    expanded = start
    cursor = start - 1
    while cursor >= 0 and if_index - cursor <= 10:
        line = raw_added[cursor].rstrip()
        norm = normalize_source_line(line)
        if not norm:
            cursor -= 1
            continue
        if norm in old_norm_set:
            break
        if defines_any_identifier(line, condition_vars) or is_comment_line(line):
            expanded = cursor
            cursor -= 1
            continue
        break
    return expanded


def identifiers_in_line(line: str) -> set[str]:
    keywords = {
        "if",
        "NULL",
        "sizeof",
        "return",
        "goto",
        "true",
        "false",
    }
    return {
        token
        for token in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", line)
        if token not in keywords and not token.isupper()
    }


def defines_any_identifier(line: str, identifiers: set[str]) -> bool:
    stripped = line.strip()
    for identifier in identifiers:
        if re.search(rf"\b{re.escape(identifier)}\b\s*=", stripped):
            return True
        if re.search(rf"\b{re.escape(identifier)}\b\s*;", stripped) and looks_like_support_statement(stripped):
            return True
    return False


def guard_candidate_end(raw_added: list[str], if_index: int) -> int:
    brace_balance = 0
    saw_open_brace = False
    saw_control_effect = False
    end = if_index + 1
    for cursor in range(if_index, min(len(raw_added), if_index + 32)):
        line = raw_added[cursor]
        brace_balance += line.count("{") - line.count("}")
        saw_open_brace = saw_open_brace or "{" in line
        saw_control_effect = saw_control_effect or has_control_effect(line)
        end = cursor + 1
        if saw_open_brace and saw_control_effect and brace_balance <= 0 and cursor > if_index:
            break
        if not saw_open_brace and saw_control_effect and line.rstrip().endswith(";"):
            break
        if not saw_open_brace and cursor > if_index + 4:
            break
    return end


def collect_intra_run_context(
    raw_added: list[str],
    index: int,
    old_norm_set: set[str],
    *,
    direction: int,
    limit: int = 3,
) -> list[str]:
    collected: list[str] = []
    cursor = index - 1 if direction < 0 else index
    while 0 <= cursor < len(raw_added) and len(collected) < limit:
        line = raw_added[cursor].rstrip()
        norm = normalize_source_line(line)
        if norm in old_norm_set and not is_comment_line(line) and line.strip() not in {"{", "}"}:
            if direction < 0:
                collected.insert(0, line)
            else:
                collected.append(line)
        elif norm and not is_comment_line(line):
            # Stop at non-original generated code, so anchors stay grounded.
            if collected:
                break
        cursor += direction
    return collected


def has_new_information(lines: list[str], old_norm_set: set[str]) -> bool:
    for line in lines:
        norm = normalize_source_line(line)
        if norm and norm not in old_norm_set:
            return True
    return False


def looks_like_support_statement(line: str) -> bool:
    stripped = line.strip()
    if is_comment_line(line):
        return True
    if stripped in {"{", "}"}:
        return True
    return bool(
        re.search(
            r"^(?:const\s+)?(?:unsigned\s+)?(?:long\s+long|long|int|size_t|png_uint_32|png_alloc_size_t|ssize_t|char|bool|double|float)\b.*[=;]",
            stripped,
        )
        or re.search(r"^[A-Za-z_][A-Za-z0-9_]*(?:->[A-Za-z_][A-Za-z0-9_]*|\.[A-Za-z_][A-Za-z0-9_]*)?\s*=.*;", stripped)
    )


def has_control_effect(line: str) -> bool:
    return bool(
        re.search(
            r"\b(return|goto|break|continue)\b|(?:_error|error|warn|fail|abort|assert|raise)\s*\(",
            line,
            flags=re.IGNORECASE,
        )
    )


def place_added_block(
    lines: list[str],
    block: dict[str, Any],
    *,
    old_start: int,
    window_lines: int,
) -> dict[str, Any]:
    added_lines = [line.rstrip() for line in block["lines"]]
    if block_already_present(lines, added_lines):
        return {"applied": True, "reason": "refined_block_already_present", "inserted_lines": 0}
    before_context = block.get("before_context") or []
    after_context = block.get("after_context") or []
    search_start = max(0, old_start - window_lines - 1)
    search_end = min(len(lines), old_start + window_lines - 1)

    before_index = find_context(lines, before_context, search_start, search_end)
    if before_index is not None:
        insert_at = before_index + len(before_context)
        added_lines = remove_duplicate_local_declarations(lines, added_lines, search_start, search_end)
        insert_at = move_after_required_local_declarations(lines, added_lines, insert_at, search_end)
        lines[insert_at:insert_at] = added_lines
        return {
            "applied": True,
            "reason": "inserted_after_before_context",
            "inserted_lines": len(added_lines),
            "line": insert_at + 1,
            "context": before_context[-2:],
        }

    after_index = find_context(lines, after_context, search_start, search_end)
    if after_index is not None:
        added_lines = remove_duplicate_local_declarations(lines, added_lines, search_start, search_end)
        after_index = move_after_required_local_declarations(lines, added_lines, after_index, search_end)
        lines[after_index:after_index] = added_lines
        return {
            "applied": True,
            "reason": "inserted_before_after_context",
            "inserted_lines": len(added_lines),
            "line": after_index + 1,
            "context": after_context[:2],
        }

    fallback_index = min(max(old_start - 1, 0), len(lines))
    if len(added_lines) <= 12 and has_strong_guard_signal(added_lines):
        added_lines = remove_duplicate_local_declarations(lines, added_lines, search_start, search_end)
        fallback_index = move_after_required_local_declarations(lines, added_lines, fallback_index, search_end)
        lines[fallback_index:fallback_index] = added_lines
        return {
            "applied": True,
            "reason": "inserted_at_hunk_line_fallback",
            "inserted_lines": len(added_lines),
            "line": fallback_index + 1,
        }
    return {
        "applied": False,
        "reason": "no_context_anchor",
        "old_start": old_start,
        "before_context": before_context[-3:],
        "after_context": after_context[:3],
        "preview": "\n".join(added_lines[:8]),
    }


def remove_duplicate_local_declarations(
    existing_lines: list[str],
    added_lines: list[str],
    search_start: int,
    search_end: int,
) -> list[str]:
    existing = declared_identifiers(existing_lines[search_start:search_end])
    sanitized: list[str] = []
    for line in added_lines:
        declared = declared_identifier(line)
        if declared and declared in existing:
            continue
        sanitized.append(line)
    return trim_blank_edges(sanitized)


def move_after_required_local_declarations(
    existing_lines: list[str],
    added_lines: list[str],
    insert_at: int,
    search_end: int,
) -> int:
    used = identifiers_in_line("\n".join(added_lines))
    if not used:
        return insert_at
    latest_declaration = None
    for index in range(insert_at, min(search_end, len(existing_lines))):
        declared = declared_identifier(existing_lines[index])
        if declared and declared in used:
            latest_declaration = index
    if latest_declaration is None:
        return insert_at
    return max(insert_at, latest_declaration + 1)


def declared_identifiers(lines: list[str]) -> set[str]:
    return {identifier for line in lines if (identifier := declared_identifier(line))}


def declared_identifier(line: str) -> str | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if "(" in stripped.split("=", 1)[0] and not re.search(r"\)\s*(?:=|;)", stripped):
        return None
    match = re.match(
        r"^(?:static\s+)?(?:const\s+)?(?:volatile\s+)?"
        r"(?:(?:struct|enum|union)\s+)?[A-Za-z_][A-Za-z0-9_:<>]*"
        r"(?:\s+|\s*[*&]\s*)+"
        r"([A-Za-z_][A-Za-z0-9_]*)"
        r"\s*(?:\[[^\]]*\])?\s*(?:=|;)",
        stripped,
    )
    if not match:
        return None
    return match.group(1)


def trim_blank_edges(lines: list[str]) -> list[str]:
    start = 0
    end = len(lines)
    while start < end and not lines[start].strip():
        start += 1
    while end > start and not lines[end - 1].strip():
        end -= 1
    return lines[start:end]


def collect_context(entries: list[tuple[str, str]], index: int, *, direction: int, limit: int = 3) -> list[str]:
    collected: list[str] = []
    cursor = index - 1 if direction < 0 else index
    while 0 <= cursor < len(entries) and len(collected) < limit:
        prefix, text = entries[cursor]
        if prefix in {" ", "-"}:
            cleaned = clean_generated_added_line(text)
            if cleaned is not None and normalize_source_line(cleaned):
                if direction < 0:
                    collected.insert(0, cleaned.rstrip())
                else:
                    collected.append(cleaned.rstrip())
        cursor += direction
    return collected


def find_context(lines: list[str], context: list[str], start: int, end: int) -> int | None:
    if not context:
        return None
    normalized_context = [normalize_source_line(line) for line in context if normalize_source_line(line)]
    if not normalized_context:
        return None
    normalized_lines = [normalize_source_line(line) for line in lines]
    max_index = min(end, len(lines) - len(normalized_context) + 1)
    for index in range(max(start, 0), max_index):
        if normalized_lines[index : index + len(normalized_context)] == normalized_context:
            return index
    # Generated context is sometimes too ambitious; try the nearest single line.
    preferred = normalized_context[-1]
    for index in range(max(start, 0), min(end, len(lines))):
        if normalized_lines[index] == preferred:
            return index
    return None


def merge_adjacent_added_blocks(blocks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if len(blocks) < 2:
        return blocks
    merged: list[dict[str, Any]] = []
    for block in blocks:
        if (
            merged
            and block["entry_index"] - merged[-1]["entry_index"] <= len(merged[-1]["lines"]) + 4
            and len(merged[-1]["lines"]) + len(block["lines"]) <= 24
        ):
            merged[-1]["lines"].extend(["", *block["lines"]])
            merged[-1]["after_context"] = block.get("after_context") or merged[-1].get("after_context")
        else:
            merged.append(block)
    return merged


def trim_unhelpful_edges(lines: list[str]) -> list[str]:
    trimmed = list(lines)
    while trimmed and not normalize_source_line(trimmed[0]):
        trimmed.pop(0)
    while trimmed and not normalize_source_line(trimmed[-1]):
        trimmed.pop()
    while trimmed and is_pseudo_continuation_line(trimmed[-1]):
        trimmed.pop()
    return trimmed


def clean_generated_added_line(line: str) -> str | None:
    stripped = line.rstrip()
    if is_pseudo_continuation_line(stripped):
        return None
    return stripped


def is_pseudo_continuation_line(line: str) -> bool:
    lowered = line.lower()
    return any(
        phrase in lowered
        for phrase in (
            "existing code continues",
            "rest of existing code",
            "existing function body continues",
            "further processing can continue safely",
            "continue with existing code",
        )
    )


def is_refinable_block(lines: list[str]) -> bool:
    if not lines:
        return False
    code_lines = [line for line in lines if normalize_source_line(line) and not is_comment_line(line)]
    if not code_lines:
        return False
    if len(lines) > 32:
        return False
    return has_strong_guard_signal(lines)


def has_strong_guard_signal(lines: list[str]) -> bool:
    text = "\n".join(lines)
    return bool(
        re.search(r"\bif\s*\(", text)
        and re.search(
            r"\b(return|goto|break|continue)\b|(?:_error|error|warn|fail|abort|assert|raise)\s*\(",
            text,
            flags=re.IGNORECASE,
        )
    )


def block_already_present(lines: list[str], added_lines: list[str]) -> bool:
    normalized_block = [normalize_source_line(line) for line in added_lines if normalize_source_line(line)]
    if not normalized_block:
        return True
    normalized_text = "\n".join(normalize_source_line(line) for line in lines if normalize_source_line(line))
    block_text = "\n".join(normalized_block)
    return block_text in normalized_text


def is_comment_line(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith(("/*", "*", "//")) or stripped.endswith("*/")


def normalize_source_line(line: str) -> str:
    line = line.strip()
    if not line:
        return ""
    return re.sub(r"\s+", " ", line)


def parse_generated_file_patches(text: str) -> list[dict[str, Any]]:
    lines = text.splitlines()
    patches: list[dict[str, Any]] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if not line.startswith("--- "):
            index += 1
            continue
        old_file = normalize_diff_path(line[4:].strip())
        index += 1
        if index >= len(lines) or not lines[index].startswith("+++ "):
            continue
        new_file = normalize_diff_path(lines[index][4:].strip())
        rel_file = new_file or old_file
        index += 1
        hunks: list[dict[str, list[str]]] = []
        current: dict[str, list[str]] | None = None
        while index < len(lines) and not lines[index].startswith("--- "):
            hunk_line = lines[index]
            if hunk_line.startswith("@@"):
                if current and (current["old_lines"] or current["new_lines"]):
                    hunks.append(current)
                current = {"old_lines": [], "new_lines": [], "entries": [], "old_start": parse_hunk_old_start(hunk_line)}
            elif current is not None:
                if hunk_line.startswith("-") and not hunk_line.startswith("---"):
                    current["old_lines"].append(hunk_line[1:])
                    current["entries"].append(("-", hunk_line[1:]))
                elif hunk_line.startswith("+") and not hunk_line.startswith("+++"):
                    current["new_lines"].append(hunk_line[1:])
                    current["entries"].append(("+", hunk_line[1:]))
                elif hunk_line.startswith(" "):
                    current["old_lines"].append(hunk_line[1:])
                    current["new_lines"].append(hunk_line[1:])
                    current["entries"].append((" ", hunk_line[1:]))
            index += 1
        if current and (current["old_lines"] or current["new_lines"]):
            hunks.append(current)
        if rel_file and rel_file != "/dev/null":
            patches.append({"file": rel_file, "hunks": hunks})
    return patches


def parse_hunk_old_start(header: str) -> int:
    match = re.search(r"@@\s+-(\d+)", header)
    return int(match.group(1)) if match else 1


def normalize_diff_path(path: str) -> str:
    path = path.split("\t", 1)[0].strip()
    if path.startswith("a/") or path.startswith("b/"):
        path = path[2:]
    return path


def normalize_patch_text(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()
    return stripped + ("\n" if stripped else "")


def looks_like_unified_diff(text: str) -> bool:
    return "--- " in text and "+++ " in text and "@@" in text


def run(
    command: list[str],
    *,
    cwd: Path,
    timeout: int,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=check,
    )


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
    done: set[str] = set()
    for record in load_jsonl(path):
        if record.get("local_id"):
            done.add(str(record["local_id"]))
    return done


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def write_summary(results_path: Path, summary_path: Path) -> None:
    records = load_jsonl(results_path)
    summary: dict[str, Any] = {
        "record_count": len(records),
        "status_distribution": dict(Counter(record.get("status") for record in records)),
        "target_distribution": dict(Counter(record.get("target") for record in records)),
        "semantic_verdict_distribution": dict(Counter(record.get("semantic_verdict") for record in records)),
        "paper_claim_distribution": dict(Counter(record.get("paper_claim") for record in records)),
        "patch_apply_distribution": dict(Counter(str((record.get("patch_apply") or {}).get("applied")) for record in records)),
        "apply_reason_distribution": dict(Counter((record.get("patch_apply") or {}).get("reason") for record in records)),
        "apply_method_distribution": dict(Counter((record.get("patch_apply") or {}).get("applied_method") for record in records)),
        "diff_check_distribution": dict(Counter(str((record.get("patch_apply") or {}).get("diff_check_returncode")) for record in records)),
        "generated_patch_is_pseudo_distribution": dict(Counter(str(record.get("generated_patch_is_pseudo")) for record in records)),
        "failure_taxonomy_distribution": dict(Counter(failure_taxonomy(record) for record in records if not ((record.get("patch_apply") or {}).get("applied")))),
        "updated_at_epoch": time.time(),
    }
    summary["patch_apply_by_paper_claim"] = nested_counter(records, "paper_claim")
    summary["patch_apply_by_semantic_verdict"] = nested_counter(records, "semantic_verdict")
    summary["applied_examples"] = examples(records, applied=True)
    summary["failed_examples"] = examples(records, applied=False)
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")


def nested_counter(records: list[dict[str, Any]], key: str) -> dict[str, dict[str, int]]:
    grouped: dict[str, Counter[str]] = defaultdict(Counter)
    for record in records:
        group = str(record.get(key))
        applied = str((record.get("patch_apply") or {}).get("applied"))
        grouped[group][applied] += 1
    return {group: dict(counter) for group, counter in sorted(grouped.items())}


def examples(records: list[dict[str, Any]], *, applied: bool, limit: int = 8) -> list[dict[str, Any]]:
    selected = []
    for record in records:
        patch_apply = record.get("patch_apply") or {}
        if patch_apply.get("applied") is not applied:
            continue
        selected.append(
            {
                "local_id": record.get("local_id"),
                "target": record.get("target"),
                "semantic_verdict": record.get("semantic_verdict"),
                "paper_claim": record.get("paper_claim"),
                "reason": patch_apply.get("reason"),
                "method": patch_apply.get("applied_method"),
                "changed_files": patch_apply.get("changed_files"),
            }
        )
        if len(selected) >= limit:
            break
    return selected


def failure_taxonomy(record: dict[str, Any]) -> str:
    patch_apply = record.get("patch_apply") or {}
    text = "\n".join(
        str(patch_apply.get(key) or "")
        for key in ("stderr", "three_way_stderr", "raw_git_apply_stderr", "raw_git_apply_3way_stderr")
    )
    if "corrupt patch" in text or "patch fragment without header" in text or "unrecognized input" in text:
        return "malformed_or_truncated_diff"
    if "patch failed:" in text and "patch does not apply" in text:
        return "context_mismatch"
    if "does not exist in index" in text:
        return "file_not_in_index"
    if "No such file" in text or "No such file or directory" in text:
        return "file_path_missing"
    if "No valid patches" in text:
        return "no_valid_patch"
    if patch_apply.get("reason"):
        return str(patch_apply["reason"])
    return "unknown"


if __name__ == "__main__":
    raise SystemExit(main())
