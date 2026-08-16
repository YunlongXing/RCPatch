#!/usr/bin/env python3
"""Summarize ARVO-Meta cases where the official patch looks suspicious."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from textwrap import shorten
from typing import Any


DEFAULT_SUSPICIOUS_VERDICTS = {
    "bugrc_patch_better",
    "both_incomplete",
    "unclear",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build Markdown/JSON reports for ARVO-Meta cases whose official patch is judged incomplete or suspicious.",
    )
    parser.add_argument("--results-jsonl", required=True, type=Path)
    parser.add_argument("--meta-dir", required=True, type=Path)
    parser.add_argument("--patch-dir", required=True, type=Path)
    parser.add_argument("--output-md", required=True, type=Path)
    parser.add_argument("--output-json", required=True, type=Path)
    parser.add_argument(
        "--suspicious-verdict",
        action="append",
        default=[],
        help="LLM verdict to include. May be repeated. Defaults to bugrc_patch_better, both_incomplete, unclear.",
    )
    parser.add_argument(
        "--include-full-diffs",
        action="store_true",
        help="Embed full official and generated patches instead of compact summaries.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    verdicts = set(args.suspicious_verdict) if args.suspicious_verdict else DEFAULT_SUSPICIOUS_VERDICTS
    records = load_jsonl(args.results_jsonl)
    suspicious = [record for record in records if is_suspicious(record, verdicts)]
    suspicious.sort(key=sort_key)

    cases = [build_case(record, args.meta_dir, args.patch_dir) for record in suspicious]
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_md.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(cases, indent=2, ensure_ascii=False), encoding="utf-8")
    args.output_md.write_text(render_markdown(cases, include_full_diffs=args.include_full_diffs), encoding="utf-8")
    print(f"records={len(records)} suspicious={len(cases)}")
    print(f"markdown={args.output_md}")
    print(f"json={args.output_json}")


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not path.exists():
        return records
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def is_suspicious(record: dict[str, Any], verdicts: set[str]) -> bool:
    if record.get("status") != "completed":
        return False
    comparison = ((record.get("patch_comparison") or {}).get("llm") or {})
    verdict = comparison.get("verdict")
    if verdict in verdicts:
        return True
    return comparison.get("official_patch_cuts_bug") is False


def sort_key(record: dict[str, Any]) -> tuple[int, float, str]:
    comparison = ((record.get("patch_comparison") or {}).get("llm") or {})
    priority = {
        "bugrc_patch_better": 0,
        "both_incomplete": 1,
        "unclear": 2,
    }.get(str(comparison.get("verdict")), 3)
    confidence = comparison.get("confidence")
    if not isinstance(confidence, (int, float)):
        confidence = 0.0
    return (priority, -float(confidence), str(record.get("local_id") or ""))


def build_case(record: dict[str, Any], meta_dir: Path, patch_dir: Path) -> dict[str, Any]:
    local_id = str(record.get("local_id") or "")
    meta = read_json(meta_dir / f"{local_id}.json")
    official_patch_path = patch_dir / f"{local_id}.diff"
    official_patch = read_text(official_patch_path)
    official_subject, official_files = summarize_official_patch(official_patch)
    bugrc = record.get("bugrc") or {}
    generated_patch = ((record.get("generated_patch") or {}).get("payload") or {})
    generated_diff = generated_patch.get("unified_diff") or ""
    comparison = ((record.get("patch_comparison") or {}).get("llm") or {})

    return {
        "local_id": local_id,
        "project": record.get("project"),
        "repo_url": record.get("repo_url"),
        "fix_commit": record.get("fix_commit"),
        "sanitizer": record.get("sanitizer"),
        "crash_type": record.get("crash_type"),
        "severity": record.get("severity"),
        "crash_state": record.get("crash_state") or [],
        "trigger": rcpatch.get("trigger"),
        "llm_initial_root_cause": ((record.get("llm_initial_root_cause") or {}).get("payload") or {}),
        "bugrc_candidates": rcpatch.get("candidates") or [],
        "bugrc_chains": rcpatch.get("chains") or [],
        "generated_patch": generated_patch,
        "generated_patch_files": patch_files_from_unified_diff(generated_diff),
        "official_patch_path": official_patch_path.as_posix(),
        "official_patch_subject": official_subject,
        "official_patch_files": official_files,
        "official_patch": official_patch,
        "comparison": comparison,
        "report_excerpt": first_report_comment(meta),
    }


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def summarize_official_patch(diff_text: str) -> tuple[str, list[str]]:
    subject = ""
    for line in diff_text.splitlines():
        if line.startswith("    ") and line.strip():
            subject = line.strip()
            break
    files = [match.group(2) for match in re.finditer(r"^diff --git a/(.*?) b/(.*?)$", diff_text, re.MULTILINE)]
    return subject, files


def patch_files_from_unified_diff(diff_text: str) -> list[str]:
    files: list[str] = []
    for line in diff_text.splitlines():
        if line.startswith("--- a/"):
            files.append(line.removeprefix("--- a/"))
    return files


def first_report_comment(meta: dict[str, Any]) -> str:
    comments = ((meta.get("report") or {}).get("comments") or [])
    for comment in comments:
        content = str(comment.get("content") or "").strip()
        if content:
            return content
    return ""


def render_markdown(cases: list[dict[str, Any]], *, include_full_diffs: bool) -> str:
    lines: list[str] = [
        "# ARVO-Meta Official Patch Suspicious Cases",
        "",
        "Included cases have verdict `bugrc_patch_better`, `both_incomplete`, `unclear`, or `official_patch_cuts_bug=false`.",
        "",
        "## Summary",
        "",
        "| ID | Project | Verdict | Confidence | Crash | Trigger | Official patch | RCPatch patch | Chain |",
        "|---|---|---|---:|---|---|---|---|---|",
    ]
    for case in cases:
        comparison = case.get("comparison") or {}
        trigger = case.get("trigger") or {}
        official_summary = compact_list(case.get("official_patch_files") or [], case.get("official_patch_subject") or "")
        bugrc_summary = compact_list(case.get("generated_patch_files") or [], patch_rationale(case))
        chains = case.get("bugrc_chains") or []
        chain_summary = f"{len(chains)} chain(s)"
        if chains:
            chain_summary += f", fallback={chains[0].get('metadata', {}).get('fallback_chain')}"
        lines.append(
            f"| {case.get('local_id')} | {case.get('project')} | {comparison.get('verdict')} | "
            f"{comparison.get('confidence')} | {case.get('sanitizer')} / {case.get('crash_type')} | "
            f"{location_text((trigger.get('location') or {}))} | {official_summary} | {bugrc_summary} | {chain_summary} |"
        )

    lines.extend(["", "## Details", ""])
    for case in cases:
        lines.extend(render_case(case, include_full_diffs=include_full_diffs))
    return "\n".join(lines)


def render_case(case: dict[str, Any], *, include_full_diffs: bool) -> list[str]:
    comparison = case.get("comparison") or {}
    trigger = case.get("trigger") or {}
    initial = case.get("llm_initial_root_cause") or {}
    generated = case.get("generated_patch") or {}
    lines = [
        f"## {case.get('local_id')} - {case.get('project')}",
        "",
        f"- Verdict: `{comparison.get('verdict')}`, correct patch: `{comparison.get('correct_patch')}`, confidence: `{comparison.get('confidence')}`",
        f"- Repo: `{case.get('repo_url')}`",
        f"- Fix commit: `{case.get('fix_commit')}`",
        f"- Crash: `{case.get('sanitizer')}` / `{case.get('crash_type')}`; state `{', '.join(case.get('crash_state') or [])}`",
        f"- Trigger: `{location_text((trigger.get('location') or {}))}`, failing operation `{trigger.get('failing_operation')}`",
        f"- Initial root cause: {initial.get('root_cause_summary') or 'N/A'}",
        f"- Likely pattern: {initial.get('likely_bug_pattern') or 'N/A'}",
        f"- Patch strategy: {initial.get('patch_strategy') or 'N/A'}",
        "",
        "### RCPatch Evidence",
        "",
    ]
    candidates = case.get("bugrc_candidates") or []
    if not candidates:
        lines.append("No source-based RCPatch candidate was produced.")
    for candidate in candidates[:5]:
        location = candidate.get("location") or {}
        lines.append(
            f"- Candidate #{candidate.get('rank')} `{candidate.get('label')}` score `{candidate.get('score')}` "
            f"at `{location_text(location)}`: `{location.get('snippet') or ''}`"
        )
        lines.append(f"  Explanation: {candidate.get('explanation') or ''}")
    chains = case.get("bugrc_chains") or []
    if not chains:
        lines.append("- No causality chain was produced.")
    for chain in chains[:3]:
        lines.append(
            f"- Chain #{chain.get('rank')} score `{chain.get('score')}` fallback "
            f"`{chain.get('metadata', {}).get('fallback_chain')}`: {chain.get('summary') or ''}"
        )
        for index, step in enumerate(chain.get("steps") or [], start=1):
            location = step.get("location") or {}
            lines.append(
                f"  Step {index}: `{step.get('relation')}` `{step.get('entity')}` at "
                f"`{location_text(location)}`; {step.get('explanation') or ''}"
            )

    lines.extend(
        [
            "",
            "### Comparison Reasoning",
            "",
            f"- RCPatch cuts bug: `{comparison.get('bugrc_patch_cuts_bug')}`",
            f"- Official cuts bug: `{comparison.get('official_patch_cuts_bug')}`",
            f"- Semantic similarity: `{comparison.get('semantic_similarity')}`",
            f"- Reasoning: {comparison.get('reasoning') or ''}",
            f"- Resource/balance: {comparison.get('resource_balance_assessment') or ''}",
            "",
            "### Patch Summaries",
            "",
            f"- Official subject: {case.get('official_patch_subject') or 'N/A'}",
            f"- Official files: `{', '.join(case.get('official_patch_files') or []) or 'N/A'}`",
            f"- RCPatch files: `{', '.join(case.get('generated_patch_files') or []) or 'N/A'}`",
            f"- RCPatch rationale: {generated.get('patch_rationale') or 'N/A'}",
            "",
        ]
    )
    if include_full_diffs:
        lines.extend(["#### RCPatch Generated Patch", "", fence(generated.get("unified_diff") or "", "diff"), ""])
        lines.extend(["#### Official Patch", "", fence(case.get("official_patch") or "", "diff"), ""])
    return lines


def location_text(location: dict[str, Any]) -> str:
    if not location:
        return "N/A"
    text = str(location.get("file") or "?")
    if location.get("line"):
        text += f":{location.get('line')}"
    if location.get("function"):
        text += f" ({location.get('function')})"
    return text


def compact_list(files: list[str], fallback: str) -> str:
    if files:
        text = ", ".join(files[:3])
        if len(files) > 3:
            text += f", +{len(files) - 3}"
        return f"`{shorten(text, width=90, placeholder='...')}`"
    return shorten(fallback or "N/A", width=90, placeholder="...")


def patch_rationale(case: dict[str, Any]) -> str:
    generated = case.get("generated_patch") or {}
    return str(generated.get("patch_rationale") or "")


def fence(text: str, language: str) -> str:
    safe_text = str(text).replace("```", "`` `")
    return f"```{language}\n{safe_text.rstrip()}\n```"


if __name__ == "__main__":
    main()
