"""Patch-aware correlation and weak-supervision refinement."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Optional

from rcpatch.logging_utils import get_logger
from rcpatch.models import (
    BugReport,
    CandidateLabel,
    CausalityChain,
    ConfidenceScore,
    EvidenceKind,
    EvidenceReference,
    PatchEvidence,
    PatchIntent,
    RootCauseCandidate,
    SourceLocation,
)
from rcpatch.patch_analysis.classifier import PatchIntentClassifier
from rcpatch.patch_analysis.models import MappedPatchLocation, ParsedPatch, PatchAwareAnalysisResult, PatchLine
from rcpatch.patch_analysis.parser import UnifiedDiffParser
from rcpatch.source import ProgramIndex

TOKEN_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")


class PatchAwareAnalyzer:
    """Use official fix patches as weak supervision for candidate and chain refinement."""

    def __init__(
        self,
        *,
        parser: Optional[UnifiedDiffParser] = None,
        classifier: Optional[PatchIntentClassifier] = None,
    ) -> None:
        self.parser = parser or UnifiedDiffParser()
        self.classifier = classifier or PatchIntentClassifier()
        self.logger = get_logger(__name__)

    def analyze(
        self,
        bug_report: BugReport,
        *,
        program_index: Optional[ProgramIndex] = None,
        candidates: Iterable[RootCauseCandidate] = (),
        chains: Iterable[CausalityChain] = (),
    ) -> PatchAwareAnalysisResult:
        """Parse patch evidence and apply weak-supervision refinements."""
        patch_evidence = bug_report.patch_evidence
        if patch_evidence is None or not bug_report.analysis_config.enable_patch_analysis:
            return PatchAwareAnalysisResult(
                patch_evidence=patch_evidence,
                candidates=tuple(candidates),
                chains=tuple(chains),
                diagnostics=("Patch-aware analysis disabled or no patch evidence provided.",),
            )

        parsed_patch = self._load_patch(patch_evidence)
        if parsed_patch is None:
            return PatchAwareAnalysisResult(
                patch_evidence=patch_evidence,
                candidates=tuple(candidates),
                chains=tuple(chains),
                diagnostics=("No parseable patch diff was available.",),
            )

        commit_message = self._load_text_artifact(patch_evidence.commit_message, patch_evidence.commit_message_path)
        issue_text = self._load_text_artifact(
            patch_evidence.issue_text or bug_report.issue_text,
            patch_evidence.issue_text_path,
        )
        patch_intent, intent_scores = self.classifier.classify(
            parsed_patch,
            commit_message=commit_message,
            issue_text=issue_text,
        )
        mapped_locations, changed_functions = self._map_patch_locations(parsed_patch, program_index)
        updated_patch_evidence = self._update_patch_evidence(
            patch_evidence=patch_evidence,
            mapped_locations=mapped_locations,
            patch_intent=patch_intent,
            intent_scores=intent_scores,
        )

        updated_candidates = self._refine_candidates(
            candidates=tuple(candidates),
            mapped_locations=mapped_locations,
            changed_functions=changed_functions,
            patch_evidence=updated_patch_evidence,
            patch_intent=patch_intent,
            commit_message=commit_message,
            issue_text=issue_text,
        )
        updated_chains = self._refine_chains(
            chains=tuple(chains),
            original_candidates=tuple(candidates),
            updated_candidates=updated_candidates,
            mapped_locations=mapped_locations,
            changed_functions=changed_functions,
            patch_evidence=updated_patch_evidence,
            patch_intent=patch_intent,
        )

        diagnostics = list(parsed_patch.diagnostics)
        if not mapped_locations:
            diagnostics.append("Patch diff was parsed, but no changed lines could be mapped back to source locations.")

        return PatchAwareAnalysisResult(
            patch_evidence=updated_patch_evidence,
            candidates=tuple(updated_candidates),
            chains=tuple(updated_chains),
            diagnostics=tuple(diagnostics),
            mapped_locations=tuple(mapped_locations),
        )

    def _load_patch(self, patch_evidence: PatchEvidence) -> Optional[ParsedPatch]:
        diff_path = patch_evidence.diff_path
        diff_text = patch_evidence.metadata.get("diff_text")
        if isinstance(diff_text, str) and diff_text.strip():
            return self.parser.parse_text(diff_text)
        if diff_path:
            path = Path(diff_path).expanduser()
            if path.exists():
                return self.parser.parse_file(path.as_posix())
        return None

    @staticmethod
    def _load_text_artifact(inline_text: Optional[str], path_text: Optional[str]) -> Optional[str]:
        if inline_text:
            return inline_text
        if path_text:
            artifact_path = Path(path_text).expanduser()
            if artifact_path.exists():
                return artifact_path.read_text(encoding="utf-8", errors="replace")
        return None

    def _map_patch_locations(
        self,
        parsed_patch: ParsedPatch,
        program_index: Optional[ProgramIndex],
    ) -> tuple[list[MappedPatchLocation], set[str]]:
        mapped_locations: list[MappedPatchLocation] = []
        changed_functions: set[str] = set()

        for patched_file in parsed_patch.files:
            file_path = patched_file.old_path or patched_file.new_path
            for hunk in patched_file.hunks:
                for line in hunk.lines:
                    if not line.is_changed:
                        continue
                    mapped = self._map_patch_line(
                        file_path=file_path,
                        line=line,
                        hunk_header=hunk.header,
                        program_index=program_index,
                    )
                    if mapped is None:
                        continue
                    mapped_locations.append(mapped)
                    if mapped.location.function:
                        changed_functions.add(mapped.location.function)

        unique_locations: list[MappedPatchLocation] = []
        seen: set[tuple[str, int, str, str, str]] = set()
        for item in mapped_locations:
            key = (
                item.location.file,
                item.location.line,
                item.patch_side,
                item.change_kind,
                item.line_text,
            )
            if key in seen:
                continue
            seen.add(key)
            unique_locations.append(item)
        return unique_locations, changed_functions

    def _map_patch_line(
        self,
        *,
        file_path: str,
        line: PatchLine,
        hunk_header: str,
        program_index: Optional[ProgramIndex],
    ) -> Optional[MappedPatchLocation]:
        if not file_path:
            return None

        if line.kind == "del" and line.old_lineno is not None:
            side = "old"
            line_number = line.old_lineno
        elif line.kind == "add" and line.new_lineno is not None:
            side = "new"
            line_number = line.new_lineno
        else:
            return None

        function_name = _function_name_from_hunk_header(hunk_header)
        location = SourceLocation(
            file=file_path,
            line=line_number,
            function=function_name,
            snippet=line.text.strip() or None,
            metadata={"patch_side": side, "change_kind": line.kind, "hunk_header": hunk_header},
        )

        if program_index is not None:
            function = program_index.find_enclosing_function(location)
            statement = program_index.find_nearest_statement(location, max_line_distance=1)
            if statement is not None and statement.location.file == file_path:
                location = statement.location.model_copy(
                    update={
                        "metadata": {
                            **statement.location.metadata,
                            "patch_side": side,
                            "change_kind": line.kind,
                            "hunk_header": hunk_header,
                        }
                    }
                )
            elif function is not None:
                location = location.model_copy(update={"function": function.name})

        return MappedPatchLocation(
            location=location,
            patch_side=side,
            change_kind=line.kind,
            line_text=line.text.strip(),
            hunk_header=hunk_header.strip(),
        )

    def _update_patch_evidence(
        self,
        *,
        patch_evidence: PatchEvidence,
        mapped_locations: list[MappedPatchLocation],
        patch_intent: PatchIntent,
        intent_scores: dict[object, float],
    ) -> PatchEvidence:
        changed_locations = [item.location for item in mapped_locations]
        metadata = {
            **patch_evidence.metadata,
            "intent_scores": {
                (key.value if isinstance(key, PatchIntent) else str(key)): value
                for key, value in intent_scores.items()
            },
            "mapped_location_count": len(mapped_locations),
        }
        return patch_evidence.model_copy(
            update={
                "patch_intent": patch_intent if patch_intent != PatchIntent.UNKNOWN else patch_evidence.patch_intent,
                "changed_locations": changed_locations or patch_evidence.changed_locations,
                "metadata": metadata,
            }
        )

    def _refine_candidates(
        self,
        *,
        candidates: tuple[RootCauseCandidate, ...],
        mapped_locations: list[MappedPatchLocation],
        changed_functions: set[str],
        patch_evidence: PatchEvidence,
        patch_intent: PatchIntent,
        commit_message: Optional[str],
        issue_text: Optional[str],
    ) -> list[RootCauseCandidate]:
        updated: list[RootCauseCandidate] = []
        for candidate in candidates:
            alignment = self._candidate_patch_alignment(
                candidate=candidate,
                mapped_locations=mapped_locations,
                changed_functions=changed_functions,
                patch_evidence=patch_evidence,
                patch_intent=patch_intent,
                commit_message=commit_message,
                issue_text=issue_text,
            )
            patch_boost = min(alignment["patch_alignment_score"] * 0.12, 0.18)
            new_score = min(candidate.score + patch_boost, 1.0)
            new_features = {
                **candidate.features,
                "supported_by_patch": alignment["patch_alignment_score"] >= 0.3,
                **alignment,
            }
            new_evidence = self._dedupe_evidence(candidate.evidence + alignment["evidence"])
            confidence_components = dict(candidate.confidence.components) if candidate.confidence else {}
            confidence_components["patch_alignment"] = float(alignment["patch_alignment_score"])

            explanation = candidate.explanation
            if alignment["patch_alignment_score"] >= 0.45:
                explanation += " Official patch evidence overlaps this location or function."

            updated_candidate = candidate.model_copy(
                update={
                    "score": new_score,
                    "features": new_features,
                    "evidence": new_evidence,
                    "explanation": explanation,
                    "confidence": ConfidenceScore(
                        value=new_score,
                        rationale="Patch-aware refinement keeps patch evidence as a weak supervision feature.",
                        method="heuristic_candidate_ranker_patch_aware_v1",
                        components=confidence_components,
                    ),
                    "metadata": {
                        **candidate.metadata,
                        "patch_intent": patch_intent.value,
                    },
                }
            )
            updated.append(updated_candidate)

        ranked = sorted(
            updated,
            key=lambda candidate: (
                _label_priority(candidate.label),
                candidate.score,
                -candidate.location.line,
            ),
            reverse=True,
        )
        return [
            candidate.model_copy(update={"rank": index})
            for index, candidate in enumerate(ranked, start=1)
        ]

    def _candidate_patch_alignment(
        self,
        *,
        candidate: RootCauseCandidate,
        mapped_locations: list[MappedPatchLocation],
        changed_functions: set[str],
        patch_evidence: PatchEvidence,
        patch_intent: PatchIntent,
        commit_message: Optional[str],
        issue_text: Optional[str],
    ) -> dict[str, object]:
        exact_matches = [
            location
            for location in mapped_locations
            if location.location.file == candidate.location.file and location.location.line == candidate.location.line
        ]
        same_function_matches = [
            location
            for location in mapped_locations
            if location.location.file == candidate.location.file
            and location.location.function
            and candidate.location.function
            and location.location.function == candidate.location.function
        ]
        candidate_tokens = {
            token.lower()
            for token in TOKEN_RE.findall(" ".join(map(str, candidate.features.get("tracked_entities", []))))
        }
        if candidate.location.function:
            candidate_tokens.add(candidate.location.function.lower())
        patch_tokens = {
            token.lower()
            for location in mapped_locations
            for token in TOKEN_RE.findall(location.line_text)
        }
        entity_overlap = sorted(candidate_tokens.intersection(patch_tokens))
        commit_text = " ".join(part for part in (commit_message or "", issue_text or "") if part).lower()
        pattern_name = str(candidate.features.get("matched_bug_pattern", ""))
        pattern_overlap = bool(pattern_name and pattern_name != "none" and any(token in commit_text for token in pattern_name.split("_")))

        score = 0.0
        if exact_matches:
            score += 0.65
        if same_function_matches and not exact_matches:
            score += 0.28
        if candidate.location.function and candidate.location.function in changed_functions:
            score += 0.12
        if entity_overlap:
            score += min(0.08 + (0.03 * len(entity_overlap)), 0.16)
        if pattern_overlap:
            score += 0.08
        if patch_intent == PatchIntent.DIRECT_FIX:
            score += 0.08
        elif patch_intent in {PatchIntent.DEFENSIVE_GUARD, PatchIntent.COMPENSATING_CHECK}:
            score += 0.04
        if candidate.label == CandidateLabel.SYMPTOM:
            score *= 0.5

        evidence = []
        if exact_matches:
            for match in exact_matches:
                evidence.append(
                    EvidenceReference(
                        kind=EvidenceKind.PATCH_DIFF,
                        path=patch_evidence.diff_path,
                        line=match.location.line,
                        excerpt=match.line_text,
                        description="Official patch edits the same source line as this candidate.",
                    )
                )
        elif same_function_matches:
            evidence.append(
                EvidenceReference(
                    kind=EvidenceKind.PATCH_DIFF,
                    excerpt=same_function_matches[0].hunk_header or same_function_matches[0].line_text,
                    description="Official patch edits the same function as this candidate.",
                )
            )
        if pattern_overlap:
            evidence.append(
                EvidenceReference(
                    kind=EvidenceKind.COMMIT_MESSAGE,
                    excerpt=(commit_message or issue_text or "").strip()[:160] or None,
                    description="Patch message or issue text uses terms aligned with this candidate's bug pattern.",
                )
            )

        alignment_kind = "exact_line" if exact_matches else "same_function" if same_function_matches else "entity_overlap" if entity_overlap else "none"
        return {
            "patch_alignment_score": round(min(score, 1.0), 4),
            "patch_alignment_kind": alignment_kind,
            "patch_exact_overlap": bool(exact_matches),
            "patch_same_function": bool(same_function_matches),
            "patch_entity_overlap": entity_overlap,
            "patch_intent": patch_intent.value,
            "evidence": self._dedupe_evidence(evidence),
        }

    def _refine_chains(
        self,
        *,
        chains: tuple[CausalityChain, ...],
        original_candidates: tuple[RootCauseCandidate, ...],
        updated_candidates: list[RootCauseCandidate],
        mapped_locations: list[MappedPatchLocation],
        changed_functions: set[str],
        patch_evidence: PatchEvidence,
        patch_intent: PatchIntent,
    ) -> list[CausalityChain]:
        original_statement_by_rank = {
            candidate.rank: candidate.metadata.get("statement_id")
            for candidate in original_candidates
            if candidate.rank is not None
        }
        updated_candidate_by_statement = {
            candidate.metadata.get("statement_id"): candidate
            for candidate in updated_candidates
            if candidate.metadata.get("statement_id")
        }
        updated_chains: list[CausalityChain] = []

        for chain in chains:
            root_statement_id = original_statement_by_rank.get(chain.root_cause_rank)
            root_candidate = updated_candidate_by_statement.get(root_statement_id)
            patch_alignment_score = float(root_candidate.features.get("patch_alignment_score", 0.0)) if root_candidate else 0.0
            matched_lines: list[int] = []
            updated_steps = []
            step_patch_hits = 0

            for step in chain.steps:
                step_matches = [
                    location
                    for location in mapped_locations
                    if location.location.file == step.location.file and location.location.line == step.location.line
                ]
                same_function = [
                    location
                    for location in mapped_locations
                    if location.location.file == step.location.file
                    and location.location.function
                    and step.location.function
                    and location.location.function == step.location.function
                ]
                if step_matches:
                    step_patch_hits += 1
                    matched_lines.extend(match.location.line for match in step_matches)
                    new_evidence = self._dedupe_evidence(
                        step.evidence
                        + [
                            EvidenceReference(
                                kind=EvidenceKind.PATCH_DIFF,
                                path=patch_evidence.diff_path,
                                line=match.location.line,
                                excerpt=match.line_text,
                                description="This chain step is edited directly by the official patch.",
                            )
                            for match in step_matches
                        ]
                    )
                    updated_steps.append(step.model_copy(update={"evidence": new_evidence}))
                elif same_function:
                    new_evidence = self._dedupe_evidence(
                        step.evidence
                        + [
                            EvidenceReference(
                                kind=EvidenceKind.PATCH_DIFF,
                                path=patch_evidence.diff_path,
                                excerpt=same_function[0].hunk_header or same_function[0].line_text,
                                description="Official patch edits the same function as this chain step.",
                            )
                        ]
                    )
                    updated_steps.append(step.model_copy(update={"evidence": new_evidence}))
                else:
                    updated_steps.append(step)

            chain_boost = min(patch_alignment_score * 0.08, 0.12)
            if step_patch_hits:
                chain_boost += min(0.04 * step_patch_hits, 0.12)
            if patch_intent == PatchIntent.DIRECT_FIX and root_candidate is not None:
                chain_boost += 0.04
            new_score = min(chain.score + chain_boost, 1.0)
            confidence_components = dict(chain.confidence.components) if chain.confidence else {}
            confidence_components["patch_alignment"] = patch_alignment_score
            confidence_components["patch_step_hits"] = float(step_patch_hits)

            updated_chain = chain.model_copy(
                update={
                    "score": new_score,
                    "steps": updated_steps,
                    "root_cause_rank": root_candidate.rank if root_candidate and root_candidate.rank is not None else chain.root_cause_rank,
                    "confidence": ConfidenceScore(
                        value=new_score,
                        rationale="Patch-aware chain ranking gives moderate credit to chains that pass through edited or repaired locations.",
                        method="heuristic_chain_ranker_patch_aware_v1",
                        components=confidence_components,
                    ),
                    "metadata": {
                        **chain.metadata,
                        "patch_alignment_score": round(min(patch_alignment_score + (0.08 * step_patch_hits), 1.0), 4),
                        "patch_supported": bool(step_patch_hits or patch_alignment_score >= 0.3),
                        "patch_intent": patch_intent.value,
                        "matched_patch_lines": sorted(set(matched_lines)),
                        "changed_functions": sorted(changed_functions),
                    },
                }
            )
            updated_chains.append(updated_chain)

        reranked = sorted(updated_chains, key=lambda chain: chain.score, reverse=True)
        return [
            chain.model_copy(update={"rank": index})
            for index, chain in enumerate(reranked, start=1)
        ]

    @staticmethod
    def _dedupe_evidence(evidence: Iterable[EvidenceReference]) -> list[EvidenceReference]:
        seen: set[tuple[object, ...]] = set()
        result: list[EvidenceReference] = []
        for item in evidence:
            key = (item.kind, item.path, item.line, item.column, item.excerpt, item.description)
            if key in seen:
                continue
            seen.add(key)
            result.append(item)
        return result


def _label_priority(label: CandidateLabel) -> int:
    if label == CandidateLabel.ROOT_CAUSE_CANDIDATE:
        return 3
    if label == CandidateLabel.PROPAGATION:
        return 2
    return 1


def _function_name_from_hunk_header(header: str) -> Optional[str]:
    if not header:
        return None
    matches = re.findall(r"([A-Za-z_~][A-Za-z0-9_:~]*)\s*\(", header)
    if matches:
        return matches[-1].split("::")[-1]
    tokens = TOKEN_RE.findall(header)
    if not tokens:
        return None
    return tokens[-1]
