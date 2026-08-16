"""Feature extraction for ranked root-cause candidates."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
import re
from typing import DefaultDict, Iterable, Optional

from rcpatch.logging_utils import get_logger
from rcpatch.models import (
    BackwardSlice,
    BugReport,
    BugType,
    CandidateLabel,
    DependencyEdge,
    DependencyRelation,
    EvidenceKind,
    EvidenceReference,
    SliceNode,
    StatementKind,
)
from rcpatch.ranking.cve_prior import CVEPatternPrior, infer_operation_type
from rcpatch.ranking.expert_prior import ExpertRCAPrior
from rcpatch.ranking.project_prior import ProjectPrior, infer_project_name

# Token lists below are deliberately lightweight heuristics. They make the
# ranking rules inspectable and easy to adapt for new bug families, but they do
# not provide compiler-grade semantic precision.
SIZE_HINT_TOKENS = (
    "len",
    "length",
    "size",
    "count",
    "index",
    "idx",
    "offset",
    "bound",
    "capacity",
)
OUTPUT_SIZE_TOKENS = (
    "outlen",
    "pt_size",
    "ptext_len",
    "plaintext_size",
    "ciphertext_len",
)
LIFETIME_TOKENS = ("malloc", "calloc", "realloc", "free", "delete", "new")
COPY_TOKENS = ("memcpy", "memmove", "strcpy", "strncpy", "memset")
GUARD_TOKENS = ("null", "nullptr", "<", ">", "<=", ">=", "==", "!=", "check", "valid")
C_STYLE_CAST_RE = re.compile(r"\(\s*[A-Za-z_][A-Za-z0-9_\s\*]*\s*\)")
INTEGER_BINARY_OP_RE = re.compile(
    r"(?:\b[A-Za-z_][A-Za-z0-9_]*\b|\b\d+\b|\))\s*(<<|>>|[+\-/%*])\s*(?:\b[A-Za-z_][A-Za-z0-9_]*\b|\b\d+\b|\()"
)


@dataclass(frozen=True)
class SliceGraphView:
    """Convenience view over a backward slice graph."""

    nodes_by_id: dict[str, SliceNode]
    outgoing_edges: dict[str, list[DependencyEdge]]
    incoming_edges: dict[str, list[DependencyEdge]]
    distances_to_trigger: dict[str, int]
    max_distance_to_trigger: int


@dataclass(frozen=True)
class CandidateObservation:
    """Feature extraction result for one slice node."""

    node: SliceNode
    label: CandidateLabel
    features: dict[str, object]
    evidence: list[EvidenceReference]
    explanation: str


class CandidateFeatureExtractor:
    """Extract rankable features from a backward slice."""

    def __init__(self) -> None:
        self.logger = get_logger(__name__)
        self._cve_pattern_prior_cache: dict[tuple[str, int, float], Optional[CVEPatternPrior]] = {}
        self._project_prior_cache: dict[str, Optional[ProjectPrior]] = {}
        self._expert_rca_prior_cache: dict[tuple[str, float], Optional[ExpertRCAPrior]] = {}

    def extract(self, bug_report: BugReport, backward_slice: BackwardSlice) -> list[CandidateObservation]:
        """Extract candidate observations from a backward slice."""
        graph = self._build_graph(backward_slice)
        bug_type_hint = bug_report.analysis_config.bug_type_hint or bug_report.trigger_point.bug_type_hint

        cve_pattern_prior = self._load_cve_pattern_prior(bug_report)
        project_prior = self._load_project_prior(bug_report)
        expert_rca_prior = self._load_expert_rca_prior(bug_report)
        observations: list[CandidateObservation] = []
        for node in backward_slice.nodes:
            features, evidence = self._extract_node_features(
                bug_report=bug_report,
                backward_slice=backward_slice,
                graph=graph,
                node=node,
                bug_type_hint=bug_type_hint,
                cve_pattern_prior=cve_pattern_prior,
                project_prior=project_prior,
                expert_rca_prior=expert_rca_prior,
            )
            label = self._classify(features)
            explanation = self._build_explanation(node=node, features=features, label=label)
            observations.append(
                CandidateObservation(
                    node=node,
                    label=label,
                    features=features,
                    evidence=evidence,
                    explanation=explanation,
                )
            )

        return observations

    def _build_graph(self, backward_slice: BackwardSlice) -> SliceGraphView:
        nodes_by_id = {node.node_id: node for node in backward_slice.nodes}
        outgoing_edges: DefaultDict[str, list[DependencyEdge]] = defaultdict(list)
        incoming_edges: DefaultDict[str, list[DependencyEdge]] = defaultdict(list)
        for edge in backward_slice.edges:
            outgoing_edges[edge.source_node_id].append(edge)
            incoming_edges[edge.target_node_id].append(edge)

        distances_to_trigger: dict[str, int] = {}
        trigger_node_id = backward_slice.trigger_node_id
        if trigger_node_id and trigger_node_id in nodes_by_id:
            queue = deque([(trigger_node_id, 0)])
            visited = {trigger_node_id}
            while queue:
                node_id, distance = queue.popleft()
                distances_to_trigger[node_id] = distance
                for edge in incoming_edges.get(node_id, []):
                    if edge.source_node_id in visited:
                        continue
                    visited.add(edge.source_node_id)
                    queue.append((edge.source_node_id, distance + 1))

        max_distance = max(distances_to_trigger.values(), default=0)
        return SliceGraphView(
            nodes_by_id=nodes_by_id,
            outgoing_edges=dict(outgoing_edges),
            incoming_edges=dict(incoming_edges),
            distances_to_trigger=distances_to_trigger,
            max_distance_to_trigger=max(max_distance, 1),
        )

    def _extract_node_features(
        self,
        *,
        bug_report: BugReport,
        backward_slice: BackwardSlice,
        graph: SliceGraphView,
        node: SliceNode,
        bug_type_hint: Optional[BugType],
        cve_pattern_prior: Optional[CVEPatternPrior],
        project_prior: Optional[ProjectPrior],
        expert_rca_prior: Optional[ExpertRCAPrior],
    ) -> tuple[dict[str, object], list[EvidenceReference]]:
        outgoing_edges = graph.outgoing_edges.get(node.node_id, [])
        incoming_edges = graph.incoming_edges.get(node.node_id, [])
        outgoing_relations = {edge.relation for edge in outgoing_edges}
        incoming_relations = {edge.relation for edge in incoming_edges}
        distance_to_trigger = graph.distances_to_trigger.get(node.node_id, graph.max_distance_to_trigger)
        normalized_distance = min(distance_to_trigger / graph.max_distance_to_trigger, 1.0)
        module_proximity_score = self._module_proximity(
            node.location.file,
            bug_report.trigger_point.location.file,
        )

        text_lower = node.text.lower()
        metadata = node.metadata
        statement_types = set(node.statement_types)
        defined_variables = tuple(metadata.get("defined_variables", []))
        referenced_variables = tuple(metadata.get("referenced_variables", []))
        memory_operation_kinds = tuple(metadata.get("memory_operation_kinds", []))
        call_names = tuple(metadata.get("call_names", []))

        defines_value_used_later = bool(outgoing_edges) and any(
            edge.relation
            in {
                DependencyRelation.DATA_DEPENDENCE,
                DependencyRelation.STATE_UPDATE,
                DependencyRelation.RETURN_VALUE,
                DependencyRelation.CALL_ARGUMENT,
                DependencyRelation.INTEGER_INFLUENCE,
                DependencyRelation.ALLOCATION_SITE,
                DependencyRelation.DEALLOCATION_SITE,
                DependencyRelation.INITIALIZATION_SITE,
                DependencyRelation.GLOBAL_STATE,
                DependencyRelation.HEAP_OBJECT,
            }
            for edge in outgoing_edges
        )
        changes_object_state = bool(
            statement_types.intersection({StatementKind.MEMORY_OPERATION})
            or outgoing_relations.intersection(
                {
                    DependencyRelation.STATE_UPDATE,
                    DependencyRelation.ALLOCATION_SITE,
                    DependencyRelation.DEALLOCATION_SITE,
                    DependencyRelation.INITIALIZATION_SITE,
                    DependencyRelation.HEAP_OBJECT,
                }
            )
            or self._looks_like_state_update(node.text)
        )
        affects_control_flow = bool(
            StatementKind.CONDITION in statement_types
            or DependencyRelation.CONTROL_DEPENDENCE in outgoing_relations
        )
        has_integer_influence = bool(
            DependencyRelation.INTEGER_INFLUENCE in outgoing_relations
            or self._looks_like_integer_computation(node.text)
        )
        writes_through_output_parameter = self._writes_through_output_parameter(node.text)
        has_memory_context = bool(memory_operation_kinds or "malloc" in text_lower or "free" in text_lower or "delete" in text_lower)
        is_return_statement = StatementKind.RETURN in statement_types
        is_call_forwarding_statement = bool(
            call_names
            and self._looks_like_state_update(node.text)
            and not is_return_statement
            and not has_integer_influence
            and not affects_control_flow
            and not has_memory_context
        )
        pure_use_site = bool(
            node.is_trigger
            or (
                not defines_value_used_later
                and not changes_object_state
                and not affects_control_flow
                and not defined_variables
                and bool(incoming_edges)
            )
        )
        root_origin_score = 1.0 if not incoming_edges else 0.0

        matched_bug_pattern, bug_pattern_score = self._match_bug_pattern(
            text_lower=text_lower,
            outgoing_relations=outgoing_relations,
            incoming_relations=incoming_relations,
            affects_control_flow=affects_control_flow,
            has_integer_influence=has_integer_influence,
            has_memory_context=has_memory_context,
            bug_type_hint=bug_type_hint,
            tracked_entities=node.tracked_entities,
            referenced_variables=referenced_variables,
            writes_through_output_parameter=writes_through_output_parameter,
        )
        cve_pattern_match = None
        inferred_operation_type = infer_operation_type(
            text_lower=text_lower,
            affects_control_flow=affects_control_flow,
            has_integer_influence=has_integer_influence,
            has_memory_context=has_memory_context,
            changes_object_state=changes_object_state,
        )
        if cve_pattern_prior is not None:
            cve_pattern_match = cve_pattern_prior.match(
                category=matched_bug_pattern,
                text_lower=text_lower,
                affects_control_flow=affects_control_flow,
                has_integer_influence=has_integer_influence,
                has_memory_context=has_memory_context,
                changes_object_state=changes_object_state,
            )
            if cve_pattern_match is not None:
                # Historical CVEs are weak supervision: they increase confidence
                # in an already-detected pattern, but do not replace source facts.
                bug_pattern_score = min(bug_pattern_score + 0.12 * cve_pattern_match.score, 1.0)
                inferred_operation_type = cve_pattern_match.operation_type
        expert_rca_match = None
        if expert_rca_prior is not None:
            expert_rca_match = expert_rca_prior.match(
                category=matched_bug_pattern,
                operation_type=inferred_operation_type,
                text_lower=text_lower,
                bug_type=bug_type_hint.value if bug_type_hint is not None else None,
            )
            if expert_rca_match is not None:
                # Expert RCA corpora are high-quality but small. They can
                # clarify an existing pattern but cannot introduce candidates.
                bug_pattern_score = min(bug_pattern_score + 0.08 * expert_rca_match.score, 1.0)
                if inferred_operation_type in {"", "none", "unknown"}:
                    inferred_operation_type = expert_rca_match.operation_type
        project_prior_match = None
        if project_prior is not None:
            project_name = infer_project_name(bug_report.repo_path, bug_report.metadata)
            project_prior_match = project_prior.match(
                project=project_name,
                matched_pattern=matched_bug_pattern,
                operation_type=inferred_operation_type,
                bug_type=bug_type_hint.value if bug_type_hint is not None else None,
            )
        runtime_support_score, evidence = self._runtime_support(bug_report=bug_report, node=node)

        features: dict[str, object] = {
            "distance_to_trigger": distance_to_trigger,
            "distance_score": round(normalized_distance, 4),
            "module_proximity_score": round(module_proximity_score, 4),
            "defines_value_used_later": defines_value_used_later,
            "changes_object_state": changes_object_state,
            "affects_control_flow": affects_control_flow,
            "matched_bug_pattern": matched_bug_pattern,
            "bug_pattern_score": round(bug_pattern_score, 4),
            "cve_pattern_prior_enabled": cve_pattern_prior is not None,
            "cve_pattern_prior_score": round(cve_pattern_match.score, 4) if cve_pattern_match else 0.0,
            "cve_pattern_prior_weight": bug_report.analysis_config.cve_pattern_prior_weight,
            "cve_pattern_prior_support": cve_pattern_match.support_count if cve_pattern_match else 0,
            "cve_pattern_prior_confidence": cve_pattern_match.average_confidence if cve_pattern_match else 0.0,
            "cve_pattern_prior_category": cve_pattern_match.category if cve_pattern_match else None,
            "cve_pattern_prior_operation": cve_pattern_match.operation_type if cve_pattern_match else None,
            "cve_pattern_prior_ids": list(cve_pattern_match.pattern_ids) if cve_pattern_match else [],
            "cve_pattern_prior_reason": cve_pattern_match.reason if cve_pattern_match else None,
            "project_prior_enabled": project_prior is not None,
            "project_prior_score": round(project_prior_match.score, 4) if project_prior_match else 0.0,
            "project_prior_weight": bug_report.analysis_config.project_prior_weight,
            "project_prior_project": project_prior_match.project if project_prior_match else None,
            "project_prior_key": project_prior_match.matched_key if project_prior_match else None,
            "project_prior_reason": project_prior_match.reason if project_prior_match else None,
            "expert_rca_prior_enabled": expert_rca_prior is not None,
            "expert_rca_prior_score": round(expert_rca_match.score, 4) if expert_rca_match else 0.0,
            "expert_rca_prior_weight": bug_report.analysis_config.expert_rca_prior_weight,
            "expert_rca_prior_confidence": expert_rca_match.confidence if expert_rca_match else 0.0,
            "expert_rca_prior_category": expert_rca_match.category if expert_rca_match else None,
            "expert_rca_prior_operation": expert_rca_match.operation_type if expert_rca_match else None,
            "expert_rca_prior_ids": list(expert_rca_match.record_ids) if expert_rca_match else [],
            "expert_rca_prior_source": expert_rca_match.source if expert_rca_match else None,
            "expert_rca_prior_terms": list(expert_rca_match.matched_terms) if expert_rca_match else [],
            "expert_rca_prior_reason": expert_rca_match.reason if expert_rca_match else None,
            "inferred_operation_type": inferred_operation_type,
            "runtime_support_score": round(runtime_support_score, 4),
            "runtime_support_exact": runtime_support_score >= 0.7,
            "incoming_edge_count": len(incoming_edges),
            "outgoing_edge_count": len(outgoing_edges),
            "is_trigger_node": node.is_trigger,
            "pure_use_site": pure_use_site,
            "has_integer_influence": has_integer_influence,
            "has_memory_context": has_memory_context,
            "writes_through_output_parameter": writes_through_output_parameter,
            "is_return_statement": is_return_statement,
            "is_call_forwarding_statement": is_call_forwarding_statement,
            "state_origin_score": root_origin_score,
            "statement_types": [statement_type.value for statement_type in node.statement_types],
            "tracked_entities": list(node.tracked_entities),
        }
        return features, evidence

    def _classify(self, features: dict[str, object]) -> CandidateLabel:
        is_trigger_node = bool(features["is_trigger_node"])
        pure_use_site = bool(features["pure_use_site"])
        distance_to_trigger = int(features["distance_to_trigger"])
        defines_value_used_later = bool(features["defines_value_used_later"])
        changes_object_state = bool(features["changes_object_state"])
        affects_control_flow = bool(features["affects_control_flow"])
        bug_pattern_score = float(features["bug_pattern_score"])
        cve_pattern_prior_score = float(features.get("cve_pattern_prior_score", 0.0))
        expert_rca_prior_score = float(features.get("expert_rca_prior_score", 0.0))
        is_return_statement = bool(features["is_return_statement"])
        is_call_forwarding_statement = bool(features["is_call_forwarding_statement"])

        if is_trigger_node or (pure_use_site and distance_to_trigger <= 1):
            return CandidateLabel.SYMPTOM
        if is_return_statement or is_call_forwarding_statement:
            return CandidateLabel.PROPAGATION
        if (
            distance_to_trigger >= 1
            and (defines_value_used_later or changes_object_state or affects_control_flow)
            and (bug_pattern_score >= 0.55 or cve_pattern_prior_score >= 0.65 or expert_rca_prior_score >= 0.7)
        ):
            return CandidateLabel.ROOT_CAUSE_CANDIDATE
        if distance_to_trigger >= 2 and (defines_value_used_later or changes_object_state):
            return CandidateLabel.ROOT_CAUSE_CANDIDATE
        return CandidateLabel.PROPAGATION

    def _build_explanation(self, *, node: SliceNode, features: dict[str, object], label: CandidateLabel) -> str:
        pattern = str(features["matched_bug_pattern"])
        entities = ", ".join(node.tracked_entities[:2]) if node.tracked_entities else "relevant state"
        if label == CandidateLabel.ROOT_CAUSE_CANDIDATE:
            if pattern != "none":
                return f"This upstream statement introduces or updates {entities} and matches the {pattern} heuristic."
            return f"This upstream statement likely introduces state that later propagates to the trigger through {entities}."
        if label == CandidateLabel.SYMPTOM:
            return "This location is close to the observable failure and mostly consumes already-propagated state."
        return "This statement participates in propagation toward the trigger but is less likely to be the original state introduction site."

    def _match_bug_pattern(
        self,
        *,
        text_lower: str,
        outgoing_relations: set[DependencyRelation],
        incoming_relations: set[DependencyRelation],
        affects_control_flow: bool,
        has_integer_influence: bool,
        has_memory_context: bool,
        bug_type_hint: Optional[BugType],
        tracked_entities: Iterable[str],
        referenced_variables: Iterable[str],
        writes_through_output_parameter: bool,
    ) -> tuple[str, float]:
        tokens = {token.lower() for token in tracked_entities}
        tokens.update(variable.lower() for variable in referenced_variables)

        has_size_hint = any(hint in text_lower for hint in SIZE_HINT_TOKENS) or any(hint in tokens for hint in SIZE_HINT_TOKENS)
        has_output_size_hint = any(hint in text_lower for hint in OUTPUT_SIZE_TOKENS) or any(hint in tokens for hint in OUTPUT_SIZE_TOKENS)
        if has_integer_influence and has_size_hint and writes_through_output_parameter and bug_type_hint == BugType.BUFFER_OVERFLOW:
            return "buffer_size_contract_mismatch", 1.0

        if affects_control_flow and has_output_size_hint and "plaintext_size" in text_lower and bug_type_hint == BugType.BUFFER_OVERFLOW:
            return "buffer_size_query_or_guard", 0.9

        if has_integer_influence and (has_size_hint or has_output_size_hint or has_memory_context):
            score = 0.9
            if bug_type_hint == BugType.BUFFER_OVERFLOW:
                score += 0.08
            return "incorrect_size_computation", min(score, 1.0)

        if (
            DependencyRelation.INITIALIZATION_SITE in outgoing_relations
            or DependencyRelation.INITIALIZATION_SITE in incoming_relations
            or any(token in text_lower for token in COPY_TOKENS)
        ):
            return "invalid_initialization", 0.55

        if (
            outgoing_relations.intersection(
                {
                    DependencyRelation.ALLOCATION_SITE,
                    DependencyRelation.DEALLOCATION_SITE,
                    DependencyRelation.HEAP_OBJECT,
                }
            )
            or any(token in text_lower for token in LIFETIME_TOKENS)
        ):
            score = 0.82
            if bug_type_hint == BugType.USE_AFTER_FREE:
                score += 0.1
            return "ownership_or_lifetime_operation", min(score, 1.0)

        if affects_control_flow and any(token in text_lower for token in GUARD_TOKENS):
            score = 0.72
            if bug_type_hint in {BugType.NULL_DEREFERENCE, BugType.BUFFER_OVERFLOW}:
                score += 0.05
            return "validation_or_guard_issue", min(score, 1.0)

        if DependencyRelation.STATE_UPDATE in outgoing_relations or self._looks_like_state_update(text_lower):
            return "invalid_state_update", 0.66

        return "none", 0.0

    def _load_cve_pattern_prior(self, bug_report: BugReport) -> Optional[CVEPatternPrior]:
        config = bug_report.analysis_config
        if not config.enable_cve_pattern_prior or not config.cve_pattern_library_path:
            return None

        library_path = _resolve_prior_path(config.cve_pattern_library_path, bug_report.repo_path)
        key = (
            library_path.as_posix(),
            config.cve_pattern_min_support,
            config.cve_pattern_min_confidence,
        )
        if key not in self._cve_pattern_prior_cache:
            try:
                self._cve_pattern_prior_cache[key] = CVEPatternPrior.from_file(
                    library_path,
                    min_support=config.cve_pattern_min_support,
                    min_confidence=config.cve_pattern_min_confidence,
                )
                self.logger.info("Loaded CVE pattern prior from %s", library_path)
            except Exception as exc:
                self.logger.warning("Could not load CVE pattern prior from %s: %s", library_path, exc)
                self._cve_pattern_prior_cache[key] = None
        return self._cve_pattern_prior_cache[key]

    def _load_project_prior(self, bug_report: BugReport) -> Optional[ProjectPrior]:
        config = bug_report.analysis_config
        if not config.enable_project_prior or not config.project_prior_path:
            return None
        prior_path = _resolve_prior_path(config.project_prior_path, bug_report.repo_path)
        key = prior_path.as_posix()
        if key not in self._project_prior_cache:
            try:
                self._project_prior_cache[key] = ProjectPrior.from_file(prior_path)
                self.logger.info("Loaded project prior from %s", prior_path)
            except Exception as exc:
                self.logger.warning("Could not load project prior from %s: %s", prior_path, exc)
                self._project_prior_cache[key] = None
        return self._project_prior_cache[key]

    def _load_expert_rca_prior(self, bug_report: BugReport) -> Optional[ExpertRCAPrior]:
        config = bug_report.analysis_config
        if not config.enable_expert_rca_prior or not config.expert_rca_prior_path:
            return None
        prior_path = _resolve_prior_path(config.expert_rca_prior_path, bug_report.repo_path)
        key = (prior_path.as_posix(), config.expert_rca_prior_min_confidence)
        if key not in self._expert_rca_prior_cache:
            try:
                self._expert_rca_prior_cache[key] = ExpertRCAPrior.from_file(
                    prior_path,
                    min_confidence=config.expert_rca_prior_min_confidence,
                )
                self.logger.info("Loaded expert RCA prior from %s", prior_path)
            except Exception as exc:
                self.logger.warning("Could not load expert RCA prior from %s: %s", prior_path, exc)
                self._expert_rca_prior_cache[key] = None
        return self._expert_rca_prior_cache[key]

    @staticmethod
    def _module_proximity(candidate_file: str, trigger_file: str) -> float:
        if candidate_file == trigger_file:
            return 1.0

        candidate_parts = candidate_file.split("/")
        trigger_parts = trigger_file.split("/")
        shared = 0
        for candidate_part, trigger_part in zip(candidate_parts, trigger_parts):
            if candidate_part != trigger_part:
                break
            shared += 1

        if shared >= max(min(len(candidate_parts), len(trigger_parts)) - 1, 1):
            return 0.9
        if shared >= 2:
            return 0.65
        if shared >= 1:
            return 0.4
        return 0.1

    def _runtime_support(self, *, bug_report: BugReport, node: SliceNode) -> tuple[float, list[EvidenceReference]]:
        evidence: list[EvidenceReference] = []
        score = 0.0

        if bug_report.trigger_point.location.file == node.location.file and bug_report.trigger_point.location.line == node.location.line:
            evidence.extend(self._dedupe_evidence(bug_report.trigger_point.evidence))
            score = max(score, 0.85)

        runtime_evidence = bug_report.runtime_evidence
        if runtime_evidence is None:
            return score, evidence

        exact_stack_match = False
        function_match = False
        for frame in runtime_evidence.stack_frames:
            if frame.location is None:
                continue
            if frame.location.file == node.location.file and frame.location.line == node.location.line:
                exact_stack_match = True
                evidence.append(
                    EvidenceReference(
                        kind=EvidenceKind.STACK_TRACE,
                        path=runtime_evidence.stack_trace_path or runtime_evidence.sanitizer_report_path,
                        line=frame.location.line,
                        excerpt=f"frame #{frame.index}: {frame.function or frame.location.function or 'unknown'}",
                        description="Candidate location appears directly in the normalized runtime stack.",
                    )
                )
            elif frame.location.function and frame.location.function == node.function_name:
                function_match = True

        if exact_stack_match:
            score = max(score, 0.8)
        elif function_match:
            evidence.append(
                EvidenceReference(
                    kind=EvidenceKind.STACK_TRACE,
                    path=runtime_evidence.stack_trace_path or runtime_evidence.sanitizer_report_path,
                    excerpt=f"function {node.function_name}",
                    description="Candidate shares a function with a runtime stack frame.",
                )
            )
            score = max(score, 0.35)

        return score, self._dedupe_evidence(evidence)

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

    @staticmethod
    def _looks_like_integer_computation(text: str) -> bool:
        if not text:
            return False

        expression = text
        if "=" in text:
            expression = text.split("=", 1)[1]
        elif text.strip().startswith("return "):
            expression = text.strip()[len("return ") :]

        expression = C_STYLE_CAST_RE.sub("", expression)
        expression = expression.replace("->", ".")
        expression = re.sub(r"(<=|>=|==|!=|&&|\|\|)", " ", expression)
        return bool(INTEGER_BINARY_OP_RE.search(expression))

    @staticmethod
    def _looks_like_state_update(text: str) -> bool:
        stripped = text.strip()
        if stripped.startswith("return "):
            return False
        if "=" not in stripped:
            return False
        lhs = stripped.split("=", 1)[0].strip()
        return "->" in lhs or "." in lhs or "[" in lhs or lhs.startswith("*")

    @staticmethod
    def _writes_through_output_parameter(text: str) -> bool:
        if "=" not in text:
            return False
        lhs = text.split("=", 1)[0].strip()
        return lhs.startswith("*") or "[" in lhs


def _resolve_prior_path(path: str, repo_path: str) -> Path:
    candidate = Path(path).expanduser()
    if candidate.is_absolute():
        return candidate
    cwd_candidate = (Path.cwd() / candidate).resolve()
    if cwd_candidate.exists():
        return cwd_candidate
    return Path(repo_path).expanduser().resolve() / candidate
