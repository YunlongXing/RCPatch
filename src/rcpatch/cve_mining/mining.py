"""Candidate root-cause mining for historical CVEs."""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Iterable, Optional

from rcpatch.logging_utils import get_logger
from rcpatch.models import (
    AnalysisConfig,
    BugReport,
    BugType,
    CandidateLabel,
    CVEPatchExtraction,
    CVEPatchType,
    CVEPatchAnchor,
    CVERootCauseMiningResult,
    CollectedCVERecord,
    ConfidenceScore,
    DependencyRelation,
    EvidenceKind,
    EvidenceReference,
    ParserBackend,
    PatchEvidence,
    RootCauseCandidate,
    SourceLocation,
    TriggerPoint,
    TriggerType,
)
from rcpatch.ranking import RootCauseCandidateExtractor
from rcpatch.source import ProgramIndex, SourceProjectParser
from rcpatch.slicing import HybridBackwardSlicer

_IDENTIFIER_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_IGNORED_IDENTIFIER_TOKENS = {
    "if",
    "for",
    "while",
    "return",
    "else",
    "switch",
    "case",
    "sizeof",
    "const",
    "int",
    "char",
    "void",
    "long",
    "short",
    "unsigned",
    "signed",
}
_MEMORY_OPERATION_NAMES = ("memcpy", "memmove", "memset", "strcpy", "strncpy", "free", "malloc", "calloc", "realloc")


class CVERootCauseMiner:
    """Mine candidate root causes around patch anchor points in vulnerable code."""

    def __init__(
        self,
        *,
        parser: Optional[SourceProjectParser] = None,
        slicer: Optional[HybridBackwardSlicer] = None,
        candidate_extractor: Optional[RootCauseCandidateExtractor] = None,
    ) -> None:
        self.parser = parser or SourceProjectParser()
        self.slicer = slicer or HybridBackwardSlicer(max_interprocedural_hops=4)
        self.candidate_extractor = candidate_extractor or RootCauseCandidateExtractor()
        self.logger = get_logger(__name__)

    def mine_for_record(
        self,
        record: CollectedCVERecord,
        patch_extraction: CVEPatchExtraction,
        *,
        pre_patch_repo_path: str,
        parser_backend: ParserBackend = ParserBackend.REGEX,
        top_k: int = 12,
    ) -> CVERootCauseMiningResult:
        """Generate patch-adjacent and upstream root-cause candidates for a CVE."""

        repo_root = Path(pre_patch_repo_path).expanduser().resolve()
        diagnostics: list[str] = []
        approximations: list[str] = [
            "Patch anchors are mapped from old-side hunks to nearest pre-patch statements using syntax and line-range heuristics.",
            "Root-cause candidates are mined by reusing RCPatch's trigger-guided backward slicer with patch anchors as synthetic triggers.",
            "Patch locations are preserved as candidates, but they are not assumed to be the true root cause.",
        ]

        try:
            program = self.parser.parse_repository(repo_root, preferred_backend=parser_backend)
            program_index = self.parser.build_index(program)
        except Exception as exc:
            self.logger.warning(
                "Skipping source-based mining for %s because repository parsing failed: %s",
                record.cve_id,
                exc,
            )
            diagnostics.append(f"Source parsing failed for the pre-patch snapshot: {exc}")
            return CVERootCauseMiningResult(
                cve_id=record.cve_id,
                repo_path=repo_root.as_posix(),
                anchors=[],
                slices=[],
                candidates=[],
                diagnostics=diagnostics,
                approximations=approximations,
                metadata={
                    "parser_backend": parser_backend.value,
                    "patch_type": patch_extraction.patch_type.value if patch_extraction.patch_type else None,
                    "skipped": True,
                    "skip_reason": "source_parse_failure",
                },
            )

        anchors, anchor_diagnostics = self._resolve_patch_anchors(program_index, patch_extraction)
        diagnostics.extend(anchor_diagnostics)

        if not anchors:
            diagnostics.append("No patch anchors could be mapped into the pre-patch code snapshot.")
            return CVERootCauseMiningResult(
                cve_id=record.cve_id,
                repo_path=repo_root.as_posix(),
                anchors=[],
                slices=[],
                candidates=[],
                diagnostics=diagnostics,
                approximations=approximations,
                metadata={
                    "parser_backend": parser_backend.value,
                    "patch_type": patch_extraction.patch_type.value if patch_extraction.patch_type else None,
                },
            )

        slices = []
        collected_candidates: list[RootCauseCandidate] = []
        for anchor in anchors:
            trigger = self._build_anchor_trigger(anchor)
            synthetic_report = self._build_synthetic_bug_report(
                record=record,
                patch_extraction=patch_extraction,
                repo_root=repo_root,
                trigger=trigger,
                anchors=anchors,
                parser_backend=parser_backend,
            )
            backward_slice = self.slicer.slice_from_trigger(program_index, trigger)
            slices.append(backward_slice)
            anchor_candidates = self.candidate_extractor.extract_candidates(
                synthetic_report,
                backward_slice,
                top_k=max(len(backward_slice.nodes), 1),
            )
            collected_candidates.extend(
                self._augment_candidates(
                    anchor_candidates,
                    anchor=anchor,
                    patch_extraction=patch_extraction,
                )
            )

        merged_candidates = self._merge_candidates(
            collected_candidates,
            patch_extraction=patch_extraction,
            top_k=top_k,
        )
        return CVERootCauseMiningResult(
            cve_id=record.cve_id,
            repo_path=repo_root.as_posix(),
            anchors=anchors,
            slices=slices,
            candidates=merged_candidates,
            diagnostics=diagnostics,
            approximations=approximations + list(program.approximations),
            metadata={
                "parser_backend": parser_backend.value,
                "patch_type": patch_extraction.patch_type.value if patch_extraction.patch_type else None,
                "anchor_count": len(anchors),
                "slice_count": len(slices),
            },
        )

    def _resolve_patch_anchors(
        self,
        program_index: ProgramIndex,
        patch_extraction: CVEPatchExtraction,
    ) -> tuple[list[CVEPatchAnchor], list[str]]:
        anchors: list[CVEPatchAnchor] = []
        diagnostics: list[str] = []
        seen_keys: set[tuple[str, int, str]] = set()

        for patch_file in patch_extraction.patches:
            if program_index.get_file(patch_file.file) is None:
                diagnostics.append(f"Patched file {patch_file.file} is not present in the pre-patch repository snapshot.")
                continue

            for hunk in patch_file.hunks:
                matched_statements = self._find_anchor_statements(
                    program_index,
                    file_path=patch_file.file,
                    hunk=hunk,
                    changed_functions=patch_file.changed_functions,
                )
                anchor_kind = self._anchor_kind_for_hunk(hunk)
                anchor_text = hunk.removed_statements[0] if hunk.removed_statements else (hunk.added_statements[0] if hunk.added_statements else None)
                if not matched_statements:
                    fallback_location = SourceLocation(
                        file=patch_file.file,
                        line=max(1, hunk.old_start),
                        function=hunk.function or (patch_file.changed_functions[0] if patch_file.changed_functions else None),
                        snippet=anchor_text,
                    )
                    key = (fallback_location.file, fallback_location.line, anchor_kind)
                    if key not in seen_keys:
                        seen_keys.add(key)
                        anchors.append(
                            CVEPatchAnchor(
                                anchor_id=f"{patch_file.file}:{hunk.hunk_index}:{fallback_location.line}:{anchor_kind}",
                                location=fallback_location,
                                file=patch_file.file,
                                anchor_kind=anchor_kind,
                                hunk_index=hunk.hunk_index,
                                changed_function=hunk.function or (patch_file.changed_functions[0] if patch_file.changed_functions else None),
                                anchor_text=anchor_text,
                                before=hunk.before,
                                after=hunk.after,
                                removed_statements=list(hunk.removed_statements),
                                added_statements=list(hunk.added_statements),
                                metadata={"matched_statement": False},
                            )
                        )
                    continue

                for statement in matched_statements:
                    key = (statement.location.file, statement.location.line, anchor_kind)
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    function = program_index.function_for_statement(statement.statement_id)
                    anchors.append(
                        CVEPatchAnchor(
                            anchor_id=f"{patch_file.file}:{hunk.hunk_index}:{statement.location.line}:{anchor_kind}",
                            location=statement.location,
                            file=patch_file.file,
                            anchor_kind=anchor_kind,
                            hunk_index=hunk.hunk_index,
                            statement_id=statement.statement_id,
                            function_id=function.function_id if function else None,
                            changed_function=function.name if function else statement.location.function,
                            anchor_text=statement.text,
                            before=hunk.before,
                            after=hunk.after,
                            removed_statements=list(hunk.removed_statements),
                            added_statements=list(hunk.added_statements),
                            metadata={"matched_statement": True},
                        )
                    )

        return anchors, diagnostics

    def _find_anchor_statements(
        self,
        program_index: ProgramIndex,
        *,
        file_path: str,
        hunk: object,
        changed_functions: list[str],
    ) -> list[object]:
        from rcpatch.models import StatementInfo

        candidate_statements: list[StatementInfo] = []
        preferred_function_names = [name for name in [getattr(hunk, "function", None), *changed_functions] if name]
        trust_function_hint = not (getattr(hunk, "added_statements", []) and not getattr(hunk, "removed_statements", []))
        if trust_function_hint:
            for function_name in preferred_function_names:
                for function in program_index.find_functions(function_name):
                    if function.location.file != file_path:
                        continue
                    candidate_statements.extend(program_index.statements_in_function(function.function_id))

        if not candidate_statements:
            candidate_statements = [
                statement
                for statement in program_index.statements_by_id.values()
                if statement.location.file == file_path
            ]

        range_start = max(1, hunk.old_start - 2)
        range_end = max(range_start, hunk.old_start + max(hunk.old_count, 1) + 2)
        local_statements = [
            statement
            for statement in candidate_statements
            if range_start <= statement.location.line <= range_end
        ]
        removed_signatures = {self._normalize_statement_text(text) for text in hunk.removed_statements}
        if removed_signatures:
            exact_matches = [
                statement
                for statement in local_statements
                if self._normalize_statement_text(statement.text) in removed_signatures
            ]
            if exact_matches:
                return exact_matches
            exact_matches = [
                statement
                for statement in candidate_statements
                if self._normalize_statement_text(statement.text) in removed_signatures
            ]
            if exact_matches:
                return exact_matches

        if getattr(hunk, "added_statements", []):
            added_tokens = {
                token.lower()
                for token in _IDENTIFIER_RE.findall(" ".join(hunk.added_statements))
                if token.lower() not in _IGNORED_IDENTIFIER_TOKENS
            }
            if added_tokens:
                scored_matches = [
                    (self._statement_token_overlap(statement, added_tokens), statement)
                    for statement in local_statements or candidate_statements
                ]
                scored_matches = [
                    (score, statement)
                    for score, statement in scored_matches
                    if score > 0
                ]
                if scored_matches:
                    scored_matches.sort(
                        key=lambda item: (
                            item[0],
                            abs(item[1].location.line - max(1, hunk.old_start + hunk.old_count - 1)),
                            item[1].location.line,
                        ),
                        reverse=True,
                    )
                    return [statement for _score, statement in scored_matches[:2]]

        before_signatures = {
            self._normalize_statement_text(text)
            for text in getattr(hunk, "before", "").splitlines()
            if self._normalize_statement_text(text)
        }
        if before_signatures and not getattr(hunk, "added_statements", []):
            contextual_matches = [
                statement
                for statement in local_statements
                if self._normalize_statement_text(statement.text) in before_signatures
            ]
            if contextual_matches:
                return contextual_matches[:2]

        if local_statements:
            location = SourceLocation(
                file=file_path,
                line=max(1, hunk.old_start),
                function=getattr(hunk, "function", None),
            )
            nearest = program_index.find_nearest_statement(location, max_line_distance=max(hunk.old_count + 2, 3))
            if nearest is not None and nearest.location.file == file_path:
                return [nearest]
        return []

    def _build_anchor_trigger(self, anchor: CVEPatchAnchor) -> TriggerPoint:
        anchor_operation = self._infer_anchor_operation(anchor)
        evidence = [
            EvidenceReference(
                kind=EvidenceKind.PATCH_DIFF,
                path=anchor.file,
                line=anchor.location.line,
                excerpt=anchor.anchor_text,
                description="Patch-derived anchor used as the starting point for backward analysis.",
                metadata={"anchor_kind": anchor.anchor_kind, "hunk_index": anchor.hunk_index},
            )
        ]
        return TriggerPoint(
            location=anchor.location,
            type=TriggerType.USER_PROVIDED,
            failing_operation=anchor_operation,
            evidence=evidence,
        )

    def _build_synthetic_bug_report(
        self,
        *,
        record: CollectedCVERecord,
        patch_extraction: CVEPatchExtraction,
        repo_root: Path,
        trigger: TriggerPoint,
        anchors: list[CVEPatchAnchor],
        parser_backend: ParserBackend,
    ) -> BugReport:
        patch_evidence = PatchEvidence(
            fix_commit=patch_extraction.resolved_fix_commit.commit_sha if patch_extraction.resolved_fix_commit else None,
            commit_message=patch_extraction.commit_message,
            issue_text=record.description,
            patch_intent=patch_extraction.patch_intent,
            changed_locations=[anchor.location for anchor in anchors],
            metadata={
                "cve_patch_type": patch_extraction.patch_type.value if patch_extraction.patch_type else None,
                "resolved_fix_commit": patch_extraction.resolved_fix_commit.commit_sha if patch_extraction.resolved_fix_commit else None,
            },
        )
        return BugReport(
            bug_id=record.cve_id,
            repo_path=repo_root.as_posix(),
            language=record.language,
            title=record.project,
            summary=record.description,
            trigger_point=trigger,
            patch_evidence=patch_evidence,
            issue_text=record.description,
            config=AnalysisConfig(
                enable_patch_analysis=False,
                enable_llm=False,
                top_k_candidates=64,
                max_chain_paths=1,
                parser_backend=parser_backend,
                bug_type_hint=self._infer_bug_type(record),
                max_backward_depth=12,
                max_interprocedural_hops=self.slicer.max_interprocedural_hops,
                confidence_threshold=0.0,
            ),
        )

    def _augment_candidates(
        self,
        candidates: list[RootCauseCandidate],
        *,
        anchor: CVEPatchAnchor,
        patch_extraction: CVEPatchExtraction,
    ) -> list[RootCauseCandidate]:
        anchor_entities = self._anchor_entities(anchor)
        patch_type = patch_extraction.patch_type
        evidence = EvidenceReference(
            kind=EvidenceKind.PATCH_DIFF,
            path=anchor.file,
            line=anchor.location.line,
            excerpt=anchor.anchor_text,
            description="Patch-derived anchor location for CVE root-cause mining.",
            metadata={"anchor_id": anchor.anchor_id},
        )
        augmented: list[RootCauseCandidate] = []
        for candidate in candidates:
            tracked_entities = {
                str(entity).lower()
                for entity in candidate.features.get("tracked_entities", [])
                if isinstance(entity, str)
            }
            exact_patch_overlap = self._same_location(candidate.location, anchor.location)
            same_function = bool(
                anchor.location.function
                and candidate.location.function
                and anchor.location.function == candidate.location.function
            )
            same_file = candidate.location.file == anchor.location.file
            defines_value_later_fixed = bool(candidate.features.get("defines_value_used_later")) and bool(tracked_entities & anchor_entities)
            missing_check_replaced = patch_type in {CVEPatchType.ADDED_CHECK, CVEPatchType.BOUNDS_FIX} and (
                bool(candidate.features.get("affects_control_flow")) or exact_patch_overlap
            )
            incorrect_computation_replaced = patch_type in {CVEPatchType.DIRECT_FIX, CVEPatchType.BOUNDS_FIX} and bool(
                candidate.features.get("has_integer_influence")
            )
            upstream_from_patch = not exact_patch_overlap and (
                candidate.location.file != anchor.location.file or candidate.location.line <= anchor.location.line
            )

            updated_features = dict(candidate.features)
            updated_features.update(
                {
                    "patch_anchor_overlap": exact_patch_overlap,
                    "patch_anchor_kind": anchor.anchor_kind,
                    "same_file_as_patch": same_file,
                    "same_function_as_patch": same_function,
                    "defines_value_later_fixed": defines_value_later_fixed,
                    "missing_check_replaced_by_patch": missing_check_replaced,
                    "incorrect_computation_replaced_by_patch": incorrect_computation_replaced,
                    "upstream_from_patch": upstream_from_patch,
                    "candidate_origin": "patch_location" if exact_patch_overlap else "upstream_candidate",
                    "anchor_ids": [anchor.anchor_id],
                    "patch_type": patch_type.value if patch_type else None,
                }
            )

            updated_evidence = self._dedupe_evidence(candidate.evidence + [evidence])
            explanation_suffix = ""
            if exact_patch_overlap:
                explanation_suffix = " This location is directly modified by the fix and is kept as a patch anchor."
            elif defines_value_later_fixed:
                explanation_suffix = " This upstream statement defines values that later flow into the patched location."
            elif missing_check_replaced:
                explanation_suffix = " This statement is relevant to the missing check or guard introduced by the patch."
            elif incorrect_computation_replaced:
                explanation_suffix = " This statement participates in a computation that the patch likely corrects."

            augmented.append(
                candidate.model_copy(
                    update={
                        "features": updated_features,
                        "evidence": updated_evidence,
                        "explanation": candidate.explanation + explanation_suffix,
                        "metadata": {
                            **candidate.metadata,
                            "anchor_id": anchor.anchor_id,
                            "candidate_origin": "patch_location" if exact_patch_overlap else "upstream_candidate",
                        },
                    }
                )
            )
        return augmented

    def _merge_candidates(
        self,
        candidates: list[RootCauseCandidate],
        *,
        patch_extraction: CVEPatchExtraction,
        top_k: int,
    ) -> list[RootCauseCandidate]:
        merged: dict[tuple[str, int, Optional[str]], RootCauseCandidate] = {}
        for candidate in candidates:
            key = (candidate.location.file, candidate.location.line, candidate.location.function)
            existing = merged.get(key)
            if existing is None:
                merged[key] = candidate
                continue

            merged_anchor_ids = sorted({
                *[str(anchor_id) for anchor_id in existing.features.get("anchor_ids", [])],
                *[str(anchor_id) for anchor_id in candidate.features.get("anchor_ids", [])],
            })
            merged_features = dict(existing.features)
            merged_features.update(candidate.features)
            merged_features["anchor_ids"] = merged_anchor_ids
            merged_features["anchor_count"] = len(merged_anchor_ids)
            merged_features["patch_anchor_overlap"] = bool(existing.features.get("patch_anchor_overlap")) or bool(
                candidate.features.get("patch_anchor_overlap")
            )
            merged_features["candidate_origin"] = (
                "patch_location"
                if merged_features["patch_anchor_overlap"]
                else "upstream_candidate"
            )
            merged_features["defines_value_later_fixed"] = bool(existing.features.get("defines_value_later_fixed")) or bool(
                candidate.features.get("defines_value_later_fixed")
            )
            merged_features["missing_check_replaced_by_patch"] = bool(existing.features.get("missing_check_replaced_by_patch")) or bool(
                candidate.features.get("missing_check_replaced_by_patch")
            )
            merged_features["incorrect_computation_replaced_by_patch"] = bool(
                existing.features.get("incorrect_computation_replaced_by_patch")
            ) or bool(candidate.features.get("incorrect_computation_replaced_by_patch"))

            score = max(existing.score, candidate.score)
            if merged_features["defines_value_later_fixed"]:
                score = min(score + 0.03, 1.0)
            if merged_features["incorrect_computation_replaced_by_patch"]:
                score = min(score + 0.04, 1.0)
            if merged_features["patch_anchor_overlap"]:
                score = min(score + 0.02, 1.0)

            merged_label = self._stronger_label(existing.label, candidate.label)
            merged[key] = existing.model_copy(
                update={
                    "score": score,
                    "label": merged_label,
                    "features": merged_features,
                    "evidence": self._dedupe_evidence(existing.evidence + candidate.evidence),
                    "explanation": existing.explanation if len(existing.explanation) >= len(candidate.explanation) else candidate.explanation,
                    "confidence": ConfidenceScore(
                        value=score,
                        rationale="Merged CVE candidate score across one or more patch anchors.",
                        method="cve_root_cause_miner_v1",
                        components={
                            "base_score": score,
                            "anchor_count": float(len(merged_anchor_ids)),
                        },
                    ),
                }
            )

        ranked = sorted(
            merged.values(),
            key=lambda candidate: (
                self._label_priority(candidate.label),
                candidate.score,
                candidate.features.get("anchor_count", 1),
                -candidate.location.line,
            ),
            reverse=True,
        )
        selected = ranked[:top_k]
        if not any(candidate.features.get("patch_anchor_overlap") for candidate in selected):
            patch_candidates = [candidate for candidate in ranked if candidate.features.get("patch_anchor_overlap")]
            if patch_candidates:
                selected = (selected[:-1] if selected else []) + [patch_candidates[0]]

        return [
            candidate.model_copy(update={"rank": index})
            for index, candidate in enumerate(selected, start=1)
        ]

    @staticmethod
    def _same_location(left: SourceLocation, right: SourceLocation) -> bool:
        return left.file == right.file and left.line == right.line and left.function == right.function

    @staticmethod
    def _dedupe_evidence(evidence: list[EvidenceReference]) -> list[EvidenceReference]:
        deduped: list[EvidenceReference] = []
        seen: set[tuple[object, ...]] = set()
        for item in evidence:
            key = (item.kind.value, item.path, item.line, item.column, item.excerpt, item.description)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)
        return deduped

    @staticmethod
    def _stronger_label(left: CandidateLabel, right: CandidateLabel) -> CandidateLabel:
        priorities = {
            CandidateLabel.SYMPTOM: 1,
            CandidateLabel.PROPAGATION: 2,
            CandidateLabel.ROOT_CAUSE_CANDIDATE: 3,
        }
        return left if priorities[left] >= priorities[right] else right

    @staticmethod
    def _label_priority(label: CandidateLabel) -> int:
        return {
            CandidateLabel.SYMPTOM: 1,
            CandidateLabel.PROPAGATION: 2,
            CandidateLabel.ROOT_CAUSE_CANDIDATE: 3,
        }[label]

    @staticmethod
    def _normalize_statement_text(text: str) -> str:
        normalized = " ".join(text.strip().split())
        return normalized.strip(" ;{}")

    @staticmethod
    def _anchor_kind_for_hunk(hunk: object) -> str:
        if getattr(hunk, "removed_statements", []):
            return "removed_statement"
        if getattr(hunk, "added_statements", []):
            return "insertion_site"
        return "patch_context"

    def _anchor_entities(self, anchor: CVEPatchAnchor) -> set[str]:
        tokens = {
            token.lower()
            for token in _IDENTIFIER_RE.findall(
                " ".join(
                    [
                        anchor.anchor_text or "",
                        anchor.before,
                        anchor.after,
                        " ".join(anchor.removed_statements),
                        " ".join(anchor.added_statements),
                    ]
                )
            )
            if token.lower() not in _IGNORED_IDENTIFIER_TOKENS
        }
        return tokens

    @staticmethod
    def _statement_token_overlap(statement: object, tokens: set[str]) -> int:
        statement_tokens = {
            token.lower()
            for token in _IDENTIFIER_RE.findall(getattr(statement, "text", ""))
            if token.lower() not in _IGNORED_IDENTIFIER_TOKENS
        }
        for field_name in ("defined_variables", "referenced_variables"):
            for token in getattr(statement, field_name, []):
                if isinstance(token, str):
                    normalized = token.lower()
                    if normalized not in _IGNORED_IDENTIFIER_TOKENS:
                        statement_tokens.add(normalized)
        return len(statement_tokens.intersection(tokens))

    def _infer_anchor_operation(self, anchor: CVEPatchAnchor) -> Optional[str]:
        haystacks = [anchor.anchor_text or "", *anchor.removed_statements, *anchor.added_statements, anchor.before, anchor.after]
        for text in haystacks:
            lowered = text.lower()
            for operation_name in _MEMORY_OPERATION_NAMES:
                if operation_name in lowered:
                    return operation_name
        return None

    @staticmethod
    def _infer_bug_type(record: CollectedCVERecord) -> Optional[BugType]:
        description = record.description.lower()
        if any(token in description for token in ("overflow", "out-of-bounds", "oob", "buffer")):
            return BugType.BUFFER_OVERFLOW
        if any(token in description for token in ("use-after-free", "uaf")):
            return BugType.USE_AFTER_FREE
        if "null" in description and "dereference" in description:
            return BugType.NULL_DEREFERENCE
        return None
