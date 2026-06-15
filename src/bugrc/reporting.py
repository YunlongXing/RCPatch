"""Helpers for concise human-readable, HTML, and JSON BugRC reports."""

from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any, Mapping, Optional

from bugrc.models import AnalysisResult


def collect_standard_artifacts(output_dir: str | Path) -> dict[str, str]:
    """Collect standard BugRC artifact paths from an output directory."""
    root = Path(output_dir).expanduser().resolve()
    artifact_names = (
        "analysis_result.json",
        "analysis_report.html",
        "run_manifest.json",
        "ranked_candidates.json",
        "causality_chains.json",
        "analysis_summary.txt",
        "normalized_bug_report.json",
        "backward_slice.json",
        "program_abstraction.json",
    )
    artifacts: dict[str, str] = {}
    for filename in artifact_names:
        artifact_path = root / filename
        if artifact_path.exists():
            artifacts[artifact_path.stem] = artifact_path.as_posix()
    return artifacts


def build_concise_report(
    result: AnalysisResult,
    *,
    report_candidates: int = 3,
    report_chains: int = 3,
    repo_path: Optional[str] = None,
    artifacts: Optional[Mapping[str, str]] = None,
) -> dict[str, Any]:
    """Build a compact report payload from a full analysis result."""
    top_candidates = result.root_cause_candidates[: max(report_candidates, 0)]
    top_chains = result.chains[: max(report_chains, 0)]

    return {
        "bug_id": result.bug_id,
        "repo_path": repo_path,
        "trigger": {
            "file": result.trigger_point.location.file,
            "line": result.trigger_point.location.line,
            "function": result.trigger_point.location.function,
            "type": result.trigger_point.type.value,
            "failing_operation": result.trigger_point.failing_operation,
        },
        "top_candidate": _candidate_payload(top_candidates[0]) if top_candidates else None,
        "top_candidates": [_candidate_payload(candidate) for candidate in top_candidates],
        "top_chain": _chain_payload(top_chains[0]) if top_chains else None,
        "top_chains": [_chain_payload(chain) for chain in top_chains],
        "artifacts": dict(artifacts or {}),
    }


def render_concise_report(report: Mapping[str, Any]) -> str:
    """Render a compact terminal-friendly report summary."""
    trigger = report["trigger"]
    function_name = trigger["function"] or "<unknown>"
    lines = [
        f"BugRC concise report for {report['bug_id']}",
        f"Trigger: {trigger['file']}:{trigger['line']} in {function_name} [{trigger['type']}]",
        f"Operation: {trigger['failing_operation']}",
    ]

    repo_path = report.get("repo_path")
    if repo_path:
        lines.append(f"Repository: {repo_path}")
    lines.append("")

    top_candidate = report.get("top_candidate")
    if top_candidate is not None:
        candidate_function = top_candidate["function"] or "<unknown>"
        lines.append("Top candidate:")
        lines.append(
            "  "
            f"#{top_candidate['rank']} {top_candidate['file']}:{top_candidate['line']} "
            f"in {candidate_function} ({top_candidate['label']}, score={top_candidate['score']:.3f})"
        )
        if top_candidate.get("matched_bug_pattern"):
            lines.append(f"  pattern={top_candidate['matched_bug_pattern']}")
        lines.append(f"  {top_candidate['explanation']}")
        lines.append("")

    top_chain = report.get("top_chain")
    if top_chain is not None:
        lines.append("Top chain:")
        lines.append(
            f"  rank={top_chain['rank']} root_cause_rank={top_chain['root_cause_rank']} score={top_chain['score']:.3f}"
        )
        for index, step in enumerate(top_chain["steps"], start=1):
            step_function = step["function"] or "<unknown>"
            lines.append(
                "  "
                f"{index}. {step['file']}:{step['line']} in {step_function} "
                f"[{step['relation']}] entity={step['entity']}"
            )
        lines.append(f"  summary: {top_chain['summary']}")
        lines.append("")

    lines.append("Artifacts:")
    for name, path in sorted(dict(report.get("artifacts", {})).items()):
        lines.append(f"  {name}: {path}")
    return "\n".join(lines)


def render_html_report(
    result: AnalysisResult,
    *,
    repo_path: Optional[str] = None,
    artifacts: Optional[Mapping[str, str]] = None,
    max_candidates: int = 10,
    max_chains: int = 5,
) -> str:
    """Render a self-contained HTML evidence report for a BugRC result."""

    trigger = result.trigger_point
    candidates = result.root_cause_candidates[: max(max_candidates, 0)]
    chains = result.chains[: max(max_chains, 0)]
    artifact_items = sorted(dict(artifacts or {}).items())
    confidence = result.confidence.value if result.confidence is not None else None

    rows = "\n".join(_candidate_row(candidate) for candidate in candidates)
    chain_cards = "\n".join(_chain_card(chain) for chain in chains)
    limitation_items = "\n".join(f"<li>{escape(item)}</li>" for item in result.limitations)
    artifact_rows = "\n".join(
        f"<tr><td>{escape(name)}</td><td><code>{escape(path)}</code></td></tr>"
        for name, path in artifact_items
    )
    repo_html = f"<p><strong>Repository:</strong> <code>{escape(repo_path)}</code></p>" if repo_path else ""
    confidence_html = f"{confidence:.3f}" if confidence is not None else "n/a"

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>BugRC Evidence Report - {escape(result.bug_id)}</title>
  <style>
    :root {{
      --ink: #18212f;
      --muted: #667085;
      --line: #d6dae3;
      --panel: #f8fafc;
      --accent: #0f766e;
      --accent-soft: #ccfbf1;
      --risk: #b42318;
      --warn: #b54708;
      --ok: #067647;
    }}
    body {{
      margin: 0;
      color: var(--ink);
      font-family: Avenir Next, Gill Sans, Segoe UI, sans-serif;
      background:
        radial-gradient(circle at top left, rgba(15, 118, 110, 0.16), transparent 34rem),
        linear-gradient(180deg, #ffffff 0%, #eef5f3 100%);
    }}
    main {{
      max-width: 1180px;
      margin: 0 auto;
      padding: 42px 28px 64px;
    }}
    header, section {{
      background: rgba(255, 255, 255, 0.88);
      border: 1px solid var(--line);
      border-radius: 22px;
      box-shadow: 0 18px 48px rgba(24, 33, 47, 0.08);
      margin-bottom: 22px;
      padding: 24px;
    }}
    h1, h2, h3 {{ margin: 0 0 12px; }}
    h1 {{ font-size: 34px; letter-spacing: -0.03em; }}
    h2 {{ font-size: 21px; }}
    p {{ line-height: 1.55; }}
    code {{
      background: var(--panel);
      border: 1px solid #e4e7ec;
      border-radius: 7px;
      padding: 2px 6px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      overflow: hidden;
      border-radius: 14px;
    }}
    th, td {{
      border-bottom: 1px solid var(--line);
      padding: 10px 12px;
      text-align: left;
      vertical-align: top;
    }}
    th {{
      color: var(--muted);
      font-size: 12px;
      letter-spacing: 0.06em;
      text-transform: uppercase;
    }}
    .pill {{
      display: inline-block;
      border-radius: 999px;
      background: var(--accent-soft);
      color: var(--accent);
      font-weight: 700;
      padding: 3px 9px;
    }}
    .score {{ font-variant-numeric: tabular-nums; font-weight: 700; }}
    .chain {{
      border: 1px solid var(--line);
      border-radius: 16px;
      margin: 14px 0;
      padding: 16px;
      background: var(--panel);
    }}
    .step {{
      border-left: 3px solid var(--accent);
      margin: 10px 0 0;
      padding: 2px 0 2px 12px;
    }}
    .muted {{ color: var(--muted); }}
  </style>
</head>
<body>
<main>
  <header>
    <h1>BugRC Evidence Report</h1>
    <p><strong>Bug:</strong> {escape(result.bug_id)} <span class="pill">confidence {confidence_html}</span></p>
    {repo_html}
    <p><strong>Trigger:</strong> <code>{escape(trigger.location.file)}:{trigger.location.line}</code>
       in {escape(trigger.location.function or "<unknown>")} [{escape(trigger.type.value)}]</p>
    <p><strong>Failing operation:</strong> {escape(trigger.failing_operation or "n/a")}</p>
    <p>{escape(result.summary or "No summary was produced.")}</p>
  </header>
  <section>
    <h2>Ranked Root-Cause Candidates</h2>
    <table>
      <thead>
        <tr><th>Rank</th><th>Location</th><th>Label</th><th>Score</th><th>Pattern</th><th>Explanation</th></tr>
      </thead>
      <tbody>
        {rows or '<tr><td colspan="6" class="muted">No candidates were produced.</td></tr>'}
      </tbody>
    </table>
  </section>
  <section>
    <h2>Causality Chains</h2>
    {chain_cards or '<p class="muted">No causality chains were produced.</p>'}
  </section>
  <section>
    <h2>Limitations</h2>
    <ul>{limitation_items or '<li>No explicit limitations were reported.</li>'}</ul>
  </section>
  <section>
    <h2>Artifacts</h2>
    <table>
      <thead><tr><th>Name</th><th>Path</th></tr></thead>
      <tbody>{artifact_rows or '<tr><td colspan="2" class="muted">No artifact list was provided.</td></tr>'}</tbody>
    </table>
  </section>
</main>
</body>
</html>
"""


def _candidate_payload(candidate: Any) -> dict[str, Any]:
    return {
        "rank": candidate.rank,
        "file": candidate.location.file,
        "line": candidate.location.line,
        "function": candidate.location.function,
        "label": candidate.label.value,
        "score": candidate.score,
        "explanation": candidate.explanation,
        "matched_bug_pattern": candidate.features.get("matched_bug_pattern"),
    }


def _chain_payload(chain: Any) -> dict[str, Any]:
    return {
        "rank": chain.rank,
        "root_cause_rank": chain.root_cause_rank,
        "score": chain.score,
        "summary": chain.summary,
        "steps": [
            {
                "file": step.location.file,
                "line": step.location.line,
                "function": step.location.function,
                "relation": step.relation.value,
                "entity": step.entity,
            }
            for step in chain.steps
        ],
    }


def _candidate_row(candidate: Any) -> str:
    pattern = (
        candidate.features.get("matched_bug_pattern")
        or candidate.features.get("cve_pattern_prior_category")
        or candidate.features.get("expert_rca_prior_category")
        or "none"
    )
    location = f"{candidate.location.file}:{candidate.location.line}"
    if candidate.location.function:
        location += f" in {candidate.location.function}"
    return (
        "<tr>"
        f"<td>#{escape(str(candidate.rank or '?'))}</td>"
        f"<td><code>{escape(location)}</code></td>"
        f"<td>{escape(candidate.label.value)}</td>"
        f"<td class=\"score\">{candidate.score:.3f}</td>"
        f"<td>{escape(str(pattern))}</td>"
        f"<td>{escape(candidate.explanation)}</td>"
        "</tr>"
    )


def _chain_card(chain: Any) -> str:
    steps = "\n".join(
        (
            '<div class="step">'
            f"<strong>{escape(step.relation.value)}</strong> "
            f"<code>{escape(step.location.file)}:{step.location.line}</code> "
            f"in {escape(step.location.function or '<unknown>')} "
            f"<span class=\"muted\">entity={escape(step.entity or 'n/a')}</span>"
            f"<br>{escape(step.explanation)}"
            "</div>"
        )
        for step in chain.steps
    )
    return (
        '<article class="chain">'
        f"<h3>Chain #{escape(str(chain.rank or '?'))} "
        f"<span class=\"muted\">score={chain.score:.3f}, root candidate #{escape(str(chain.root_cause_rank or '?'))}</span></h3>"
        f"<p>{escape(chain.summary)}</p>"
        f"{steps}"
        "</article>"
    )
