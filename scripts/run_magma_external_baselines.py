#!/usr/bin/env python3
"""Run external AVR baseline checks on Magma cases.

This script intentionally keeps the baseline layer separate from RCPatch's main
pipeline.  It prepares either a representative Magma subset or the full Magma
case set, adapts each case into a function-level input for VulRepair, and
records whether CPR/ExtractFix can be applied with the artifacts available for
each case.

The CPR/ExtractFix path is compatibility-aware: those tools require inputs such
as a crashing input/exploit, KLEE-compatible bitcode, fault locations, and repair
specifications.  Magma bug metadata does not always provide these in the format
expected by those tools, so the script records a per-case applicability verdict
instead of silently treating missing prerequisites as repair failures.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


LOG = logging.getLogger("magma_external_baselines")


@dataclass(frozen=True)
class BaselineCase:
    """A compact representation of a Magma case for external baselines."""

    local_id: str
    target: str
    bug_id: str
    pre_fix_worktree: Path
    magma_patch_path: Path
    touched_files: list[str]
    affected_functions: list[str]
    canary_conditions: list[str]
    bugrc_paper_claim: str | None
    bugrc_semantic_verdict: str | None


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def nested_patch_claim(row: dict[str, Any], key: str) -> str | None:
    comparison = row.get("patch_comparison") or {}
    llm = comparison.get("llm") or {}
    value = llm.get(key)
    return str(value) if value is not None else None


def row_to_case(row: dict[str, Any]) -> BaselineCase:
    return BaselineCase(
        local_id=str(row.get("local_id") or row.get("bug_id")),
        target=str(row.get("target") or ""),
        bug_id=str(row.get("bug_id") or row.get("local_id")),
        pre_fix_worktree=Path(str(row.get("pre_fix_worktree") or "")),
        magma_patch_path=Path(str(row.get("magma_patch_path") or row.get("official_patch_path") or "")),
        touched_files=[str(v) for v in row.get("touched_files") or []],
        affected_functions=[str(v) for v in row.get("affected_functions") or []],
        canary_conditions=[str(v) for v in row.get("canary_conditions") or []],
        bugrc_paper_claim=nested_patch_claim(row, "paper_claim"),
        bugrc_semantic_verdict=nested_patch_claim(row, "verdict"),
    )


def select_subset(rows: list[dict[str, Any]], sample_size: int, per_target: int) -> list[BaselineCase]:
    """Select a target-balanced subset with a mixture of RCPatch outcomes."""

    by_target: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if row.get("status") != "completed":
            continue
        by_target.setdefault(str(row.get("target") or ""), []).append(row)

    selected: list[dict[str, Any]] = []
    preferred_claims = [
        "bugrc_blocks_better_than_magma_reference",
        "bugrc_incomplete",
        "bugrc_matches_ground_truth",
    ]
    for target in sorted(by_target):
        candidates = sorted(by_target[target], key=lambda item: str(item.get("bug_id") or ""))
        bucket: list[dict[str, Any]] = []
        for claim in preferred_claims:
            match = next((row for row in candidates if nested_patch_claim(row, "paper_claim") == claim), None)
            if match is not None and match not in bucket:
                bucket.append(match)
            if len(bucket) >= per_target:
                break
        for row in candidates:
            if len(bucket) >= per_target:
                break
            if row not in bucket:
                bucket.append(row)
        selected.extend(bucket)

    if len(selected) < sample_size:
        used = {(row.get("target"), row.get("bug_id")) for row in selected}
        for row in sorted(rows, key=lambda item: (str(item.get("target") or ""), str(item.get("bug_id") or ""))):
            key = (row.get("target"), row.get("bug_id"))
            if row.get("status") == "completed" and key not in used:
                selected.append(row)
                used.add(key)
            if len(selected) >= sample_size:
                break

    return [row_to_case(row) for row in selected[:sample_size]]


def select_all_completed(rows: list[dict[str, Any]]) -> list[BaselineCase]:
    """Select all completed Magma cases in a stable target/bug order."""

    completed = [row for row in rows if row.get("status") == "completed"]
    completed.sort(key=lambda item: (str(item.get("target") or ""), str(item.get("bug_id") or item.get("local_id") or "")))
    return [row_to_case(row) for row in completed]


def line_start_offsets(text: str) -> list[int]:
    offsets = [0]
    for match in re.finditer(r"\n", text):
        offsets.append(match.end())
    return offsets


def offset_to_line(offsets: list[int], offset: int) -> int:
    lo, hi = 0, len(offsets)
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if offsets[mid] <= offset:
            lo = mid
        else:
            hi = mid
    return lo + 1


def find_matching_brace(text: str, open_index: int) -> int | None:
    depth = 0
    in_string: str | None = None
    escaped = False
    in_line_comment = False
    in_block_comment = False
    i = open_index
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue
        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 2
            else:
                i += 1
            continue
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == in_string:
                in_string = None
            i += 1
            continue
        if ch == "/" and nxt == "/":
            in_line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            in_block_comment = True
            i += 2
            continue
        if ch in {"\"", "'"}:
            in_string = ch
            i += 1
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return None


def normalize_function_name(function_name: str) -> list[str]:
    clean = function_name.strip().rstrip(":")
    parts = [clean]
    if "::" in clean:
        parts.append(clean.split("::")[-1])
    if ":" in clean:
        parts.append(clean.split(":")[-1])
    return [part for part in dict.fromkeys(parts) if part]


def extract_function_from_text(text: str, function_name: str) -> tuple[str, int] | None:
    """Best-effort C/C++ function extraction by name and balanced braces."""

    offsets = line_start_offsets(text)
    for name in normalize_function_name(function_name):
        pattern = re.compile(rf"(?<![A-Za-z0-9_~]){re.escape(name)}\s*\([^;{{}}]*\)\s*(?:const\s*)?(?:noexcept\s*)?(?:override\s*)?\{{", re.MULTILINE)
        for match in pattern.finditer(text):
            open_index = text.find("{", match.start(), match.end())
            if open_index < 0:
                continue
            prefix_start = text.rfind("\n", 0, match.start()) + 1
            # Include multi-line return type / qualifiers when they are directly above.
            scan = prefix_start
            while scan > 0:
                prev_end = scan - 1
                prev_start = text.rfind("\n", 0, prev_end) + 1
                prev_line = text[prev_start:prev_end].strip()
                if not prev_line or prev_line.endswith(";") or prev_line.endswith("}") or prev_line.startswith("#"):
                    break
                if re.search(r"\b(if|for|while|switch|return)\b", prev_line):
                    break
                scan = prev_start
            close_index = find_matching_brace(text, open_index)
            if close_index is None:
                continue
            snippet = text[scan:close_index].strip()
            if len(snippet) > 20:
                return snippet, offset_to_line(offsets, scan)
    return None


def fallback_context(text: str, function_name: str, radius: int = 80) -> tuple[str, int] | None:
    offsets = line_start_offsets(text)
    for name in normalize_function_name(function_name):
        idx = text.find(name)
        if idx >= 0:
            line = offset_to_line(offsets, idx)
            lines = text.splitlines()
            start = max(1, line - radius)
            end = min(len(lines), line + radius)
            return "\n".join(lines[start - 1 : end]), start
    return None


def extract_case_function(case: BaselineCase) -> dict[str, Any]:
    """Extract the first affected function that can be found in touched files."""

    attempts: list[dict[str, str]] = []
    for relpath in case.touched_files:
        source_path = case.pre_fix_worktree / relpath
        if not source_path.exists() or not source_path.is_file():
            attempts.append({"path": relpath, "reason": "missing_source_file"})
            continue
        try:
            text = source_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            attempts.append({"path": relpath, "reason": f"read_error:{exc}"})
            continue
        for function_name in case.affected_functions or [""]:
            extracted = extract_function_from_text(text, function_name)
            if extracted is None:
                extracted = fallback_context(text, function_name)
            if extracted is not None:
                snippet, start_line = extracted
                return {
                    "status": "extracted",
                    "path": relpath,
                    "function": function_name,
                    "start_line": start_line,
                    "source": snippet,
                    "attempts": attempts,
                }
        attempts.append({"path": relpath, "reason": "function_not_found"})
    return {
        "status": "not_extracted",
        "path": case.touched_files[0] if case.touched_files else None,
        "function": case.affected_functions[0] if case.affected_functions else None,
        "start_line": None,
        "source": "",
        "attempts": attempts,
    }


def write_subset_outputs(cases: list[BaselineCase], output_dir: Path) -> list[dict[str, Any]]:
    prepared: list[dict[str, Any]] = []
    for case in cases:
        extracted = extract_case_function(case)
        record = {
            "local_id": case.local_id,
            "target": case.target,
            "bug_id": case.bug_id,
            "pre_fix_worktree": str(case.pre_fix_worktree),
            "magma_patch_path": str(case.magma_patch_path),
            "touched_files": case.touched_files,
            "affected_functions": case.affected_functions,
            "canary_conditions": case.canary_conditions,
            "bugrc_paper_claim": case.bugrc_paper_claim,
            "bugrc_semantic_verdict": case.bugrc_semantic_verdict,
            "vulrepair_input": extracted,
        }
        prepared.append(record)

    (output_dir / "subset_cases.json").write_text(json.dumps(prepared, indent=2), encoding="utf-8")
    with (output_dir / "vulrepair_inputs.jsonl").open("w", encoding="utf-8") as handle:
        for record in prepared:
            source = (record["vulrepair_input"] or {}).get("source") or ""
            if source:
                handle.write(json.dumps({
                    "local_id": record["local_id"],
                    "target": record["target"],
                    "bug_id": record["bug_id"],
                    "function": (record["vulrepair_input"] or {}).get("function"),
                    "path": (record["vulrepair_input"] or {}).get("path"),
                    "source": source,
                }) + "\n")
    with (output_dir / "vulrepair_inputs.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["local_id", "target", "bug_id", "function", "path", "source"])
        writer.writeheader()
        for record in prepared:
            source = (record["vulrepair_input"] or {}).get("source") or ""
            if source:
                writer.writerow({
                    "local_id": record["local_id"],
                    "target": record["target"],
                    "bug_id": record["bug_id"],
                    "function": (record["vulrepair_input"] or {}).get("function"),
                    "path": (record["vulrepair_input"] or {}).get("path"),
                    "source": source,
                })
    return prepared


def run_command(command: list[str], cwd: Path | None = None, timeout_seconds: int = 60) -> tuple[int, str]:
    LOG.info("Running: %s", " ".join(command))
    try:
        proc = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout_seconds,
            check=False,
        )
        return proc.returncode, proc.stdout
    except subprocess.TimeoutExpired as exc:
        return 124, (exc.stdout or "") + f"\nTIMEOUT after {timeout_seconds}s\n"
    except OSError as exc:
        return 127, f"{type(exc).__name__}: {exc}\n"


def write_vulrepair_runner(path: Path) -> None:
    path.write_text(
        '''#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

import torch
from transformers import RobertaTokenizer, T5ForConditionalGeneration


def clean_tokens(tokens: str) -> str:
    tokens = tokens.replace("<pad>", "")
    tokens = tokens.replace("<s>", "")
    tokens = tokens.replace("</s>", "")
    return tokens.strip("\\n").strip()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs-jsonl", required=True)
    parser.add_argument("--output-jsonl", required=True)
    parser.add_argument("--model-name-or-path", default="MickyMike/VulRepair")
    parser.add_argument("--tokenizer-name", default="MickyMike/VulRepair")
    parser.add_argument("--encoder-block-size", type=int, default=512)
    parser.add_argument("--decoder-block-size", type=int, default=256)
    parser.add_argument("--num-beams", type=int, default=5)
    parser.add_argument("--device", default="cuda" if torch.cuda.is_available() else "cpu")
    args = parser.parse_args()

    tokenizer = RobertaTokenizer.from_pretrained(args.tokenizer_name)
    tokenizer.add_tokens(["<S2SV_StartBug>", "<S2SV_EndBug>", "<S2SV_blank>", "<S2SV_ModStart>", "<S2SV_ModEnd>"])
    model = T5ForConditionalGeneration.from_pretrained(args.model_name_or_path)
    model.resize_token_embeddings(len(tokenizer))
    model.to(args.device)
    model.eval()

    input_path = Path(args.inputs_jsonl)
    output_path = Path(args.output_jsonl)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with input_path.open("r", encoding="utf-8") as src, output_path.open("w", encoding="utf-8") as dst:
        for line in src:
            if not line.strip():
                continue
            record = json.loads(line)
            encoded = tokenizer.encode(
                record["source"],
                truncation=True,
                max_length=args.encoder_block_size,
                padding="max_length",
                return_tensors="pt",
            ).to(args.device)
            attention = encoded.ne(tokenizer.pad_token_id).to(args.device)
            with torch.no_grad():
                outputs = model.generate(
                    input_ids=encoded,
                    attention_mask=attention,
                    do_sample=False,
                    num_beams=args.num_beams,
                    num_return_sequences=1,
                    max_length=args.decoder_block_size,
                )
            prediction = clean_tokens(tokenizer.decode(outputs[0].detach().cpu().tolist(), skip_special_tokens=False))
            record["vulrepair_prediction"] = prediction
            record["vulrepair_prediction_nonempty"] = bool(prediction.strip())
            dst.write(json.dumps(record) + "\\n")


if __name__ == "__main__":
    main()
''',
        encoding="utf-8",
    )
    path.chmod(0o755)


def run_vulrepair_if_requested(args: argparse.Namespace, output_dir: Path) -> dict[str, Any]:
    status: dict[str, Any] = {
        "baseline": "VulRepair",
        "status": "not_requested",
        "model": args.vulrepair_model,
        "num_beams": args.vulrepair_num_beams,
    }
    if not args.run_vulrepair:
        return status

    runner = output_dir / "vulrepair_infer.py"
    write_vulrepair_runner(runner)
    import_check, import_output = run_command(
        [args.python, "-c", "import torch, transformers; print(torch.__version__); print(transformers.__version__)"],
        timeout_seconds=30,
    )
    status["dependency_check_output"] = import_output[-4000:]
    if import_check != 0:
        status["status"] = "missing_dependencies"
        status["reason"] = "torch/transformers are not importable in the selected Python environment"
        return status

    command = [
        args.python,
        str(runner),
        "--inputs-jsonl",
        str(output_dir / "vulrepair_inputs.jsonl"),
        "--output-jsonl",
        str(output_dir / "vulrepair_predictions.jsonl"),
        "--model-name-or-path",
        args.vulrepair_model,
        "--tokenizer-name",
        args.vulrepair_tokenizer,
        "--num-beams",
        str(args.vulrepair_num_beams),
        "--encoder-block-size",
        str(args.vulrepair_encoder_block_size),
        "--decoder-block-size",
        str(args.vulrepair_decoder_block_size),
    ]
    start = time.time()
    rc, output = run_command(command, timeout_seconds=args.vulrepair_timeout_seconds)
    status.update({
        "status": "completed" if rc == 0 else "failed",
        "returncode": rc,
        "elapsed_seconds": round(time.time() - start, 3),
        "log_tail": output[-8000:],
        "predictions_path": str(output_dir / "vulrepair_predictions.jsonl"),
    })
    if (output_dir / "vulrepair_predictions.jsonl").exists():
        count = sum(1 for line in (output_dir / "vulrepair_predictions.jsonl").read_text(encoding="utf-8").splitlines() if line.strip())
        status["prediction_count"] = count
    return status


def find_case_reproducer_files(case: BaselineCase) -> list[str]:
    root = case.magma_patch_path.parents[3] if len(case.magma_patch_path.parents) >= 4 else case.magma_patch_path.parent
    matches: list[str] = []
    if root.exists():
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            lower = path.name.lower()
            text = str(path).lower()
            if case.bug_id.lower() in text and any(token in lower or token in text for token in ["pov", "repro", "crash", "seed"]):
                matches.append(str(path))
    return matches[:20]


def assess_cpr_extractfix(cases: list[BaselineCase], output_dir: Path, pull_cpr: bool = False) -> dict[str, Any]:
    docker_path = shutil.which("docker")
    summary: dict[str, Any] = {
        "baseline": "CPR/ExtractFix",
        "docker_available": bool(docker_path),
        "docker_path": docker_path,
        "image": "rshariffdeen/cpr:experiments-cpr",
        "status": "compatibility_assessed",
        "cases": [],
    }
    if docker_path:
        rc, out = run_command(["docker", "image", "inspect", "rshariffdeen/cpr:experiments-cpr"], timeout_seconds=30)
        summary["docker_image_present"] = rc == 0
        summary["docker_image_inspect_tail"] = out[-2000:]
        if pull_cpr and rc != 0:
            pull_rc, pull_out = run_command(["docker", "pull", "rshariffdeen/cpr:experiments-cpr"], timeout_seconds=1800)
            summary["docker_pull_returncode"] = pull_rc
            summary["docker_pull_tail"] = pull_out[-4000:]
            summary["docker_image_present"] = pull_rc == 0

    for case in cases:
        reproducers = find_case_reproducer_files(case)
        has_worktree = case.pre_fix_worktree.exists()
        has_patch = case.magma_patch_path.exists()
        # Magma provides fuzzing targets and bug canaries, but not the CPR/ExtractFix
        # repair specification or KLEE bitcode required by those tools.
        missing = []
        if not reproducers:
            missing.append("tool_specific_crashing_input_or_exploit")
        missing.extend(["klee_compatible_bitcode", "repair_grammar_or_specification", "extractfix_crash_constraint"])
        verdict = "not_applicable_without_custom_harness" if missing else "potentially_applicable"
        summary["cases"].append({
            "local_id": case.local_id,
            "target": case.target,
            "bug_id": case.bug_id,
            "has_pre_fix_worktree": has_worktree,
            "has_magma_patch": has_patch,
            "reproducer_candidates": reproducers,
            "applicability": verdict,
            "missing_requirements": missing,
        })

    counts: dict[str, int] = {}
    for item in summary["cases"]:
        counts[item["applicability"]] = counts.get(item["applicability"], 0) + 1
    summary["applicability_distribution"] = counts
    (output_dir / "cpr_extractfix_applicability.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def write_summary(
    output_dir: Path,
    prepared: list[dict[str, Any]],
    vulrepair: dict[str, Any],
    cpr: dict[str, Any],
    *,
    selection_mode: str,
) -> None:
    extracted = sum(1 for record in prepared if (record.get("vulrepair_input") or {}).get("status") == "extracted")
    extraction_distribution: dict[str, int] = {}
    target_distribution: dict[str, int] = {}
    claim_distribution: dict[str, int] = {}
    for record in prepared:
        extraction_status = str((record.get("vulrepair_input") or {}).get("status") or "unknown")
        extraction_distribution[extraction_status] = extraction_distribution.get(extraction_status, 0) + 1
        target = str(record.get("target") or "unknown")
        target_distribution[target] = target_distribution.get(target, 0) + 1
        claim = str(record.get("bugrc_paper_claim") or "unknown")
        claim_distribution[claim] = claim_distribution.get(claim, 0) + 1
    vulrepair_prediction_quality: dict[str, Any] = {}
    predictions_path = output_dir / "vulrepair_predictions.jsonl"
    if predictions_path.exists():
        predictions = [json.loads(line) for line in predictions_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        nonempty = 0
        s2sv_encoded = 0
        unified_diff_like = 0
        code_like = 0
        for record in predictions:
            prediction = str(record.get("vulrepair_prediction") or "")
            if prediction.strip():
                nonempty += 1
            if "<S2SV_" in prediction:
                s2sv_encoded += 1
            if prediction.startswith("diff --git") or ("--- " in prediction and "+++ " in prediction and "@@" in prediction):
                unified_diff_like += 1
            if re.search(r"\b(if|return|for|while|malloc|free|sizeof)\b", prediction):
                code_like += 1
        vulrepair_prediction_quality = {
            "prediction_count": len(predictions),
            "nonempty_predictions": nonempty,
            "s2sv_encoded_predictions": s2sv_encoded,
            "code_like_predictions": code_like,
            "directly_applicable_unified_diffs": unified_diff_like,
            "direct_project_patch_rate": round(unified_diff_like / len(predictions), 4) if predictions else 0.0,
            "interpretation": (
                "VulRepair completed function-level inference, but its artifact emits S2SV edit-script predictions. "
                "These are not directly applicable project-level patches without the original dataset-specific "
                "de-preprocessing and patch reconstruction step."
            ),
        }
    summary = {
        "selection_mode": selection_mode,
        "case_count": len(prepared),
        "subset_size": len(prepared),
        "target_distribution": target_distribution,
        "bugrc_paper_claim_distribution": claim_distribution,
        "vulrepair_function_inputs": extracted,
        "vulrepair_input_extraction_distribution": extraction_distribution,
        "vulrepair": vulrepair,
        "vulrepair_prediction_quality": vulrepair_prediction_quality,
        "cpr_extractfix": {
            key: value for key, value in cpr.items() if key != "cases"
        },
        "outputs": {
            "subset_cases": str(output_dir / "subset_cases.json"),
            "vulrepair_inputs_jsonl": str(output_dir / "vulrepair_inputs.jsonl"),
            "vulrepair_inputs_csv": str(output_dir / "vulrepair_inputs.csv"),
            "cpr_extractfix_applicability": str(output_dir / "cpr_extractfix_applicability.json"),
        },
    }
    if (output_dir / "vulrepair_predictions.jsonl").exists():
        summary["outputs"]["vulrepair_predictions"] = str(output_dir / "vulrepair_predictions.jsonl")
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    lines = [
        "# Magma External Baseline Run",
        "",
        f"- Selection mode: {selection_mode}",
        f"- Case count: {len(prepared)}",
        f"- VulRepair function-level inputs extracted: {extracted}/{len(prepared)}",
        f"- VulRepair status: {vulrepair.get('status')}",
        f"- VulRepair predictions: {vulrepair_prediction_quality or 'not available'}",
        f"- CPR/ExtractFix status: {cpr.get('status')}",
        f"- CPR/ExtractFix applicability: {cpr.get('applicability_distribution')}",
        "",
        "## Notes",
        "",
        "- VulRepair is evaluated as a function-level neural AVR baseline because its artifact expects localized vulnerable functions.",
        "- CPR/ExtractFix require tool-specific crash inputs, KLEE-compatible bitcode, repair specifications, and crash constraints; cases lacking these are recorded as not applicable rather than failed repairs.",
    ]
    (output_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--magma-results", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--all-cases", action="store_true", help="Use all completed Magma cases instead of a balanced subset.")
    parser.add_argument("--sample-size", type=int, default=18)
    parser.add_argument("--per-target", type=int, default=2)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--run-vulrepair", action="store_true")
    parser.add_argument("--vulrepair-model", default="MickyMike/VulRepair")
    parser.add_argument("--vulrepair-tokenizer", default="MickyMike/VulRepair")
    parser.add_argument("--vulrepair-num-beams", type=int, default=5)
    parser.add_argument("--vulrepair-encoder-block-size", type=int, default=512)
    parser.add_argument("--vulrepair-decoder-block-size", type=int, default=256)
    parser.add_argument("--vulrepair-timeout-seconds", type=int, default=3600)
    parser.add_argument("--pull-cpr-docker", action="store_true")
    parser.add_argument("--log-level", default="INFO")
    return parser.parse_args(list(argv))


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO), format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
    args.output_dir.mkdir(parents=True, exist_ok=True)

    rows = read_jsonl(args.magma_results)
    if args.all_cases:
        cases = select_all_completed(rows)
        selection_mode = "all_completed"
    else:
        cases = select_subset(rows, sample_size=args.sample_size, per_target=args.per_target)
        selection_mode = f"balanced_subset_{args.sample_size}"
    LOG.info("Selected %d cases (%s)", len(cases), selection_mode)
    prepared = write_subset_outputs(cases, args.output_dir)
    vulrepair_status = run_vulrepair_if_requested(args, args.output_dir)
    cpr_status = assess_cpr_extractfix(cases, args.output_dir, pull_cpr=args.pull_cpr_docker)
    write_summary(args.output_dir, prepared, vulrepair_status, cpr_status, selection_mode=selection_mode)
    LOG.info("Wrote summary to %s", args.output_dir / "summary.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
