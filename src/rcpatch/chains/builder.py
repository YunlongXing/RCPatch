"""Causality-chain construction over ranked candidates and backward slices."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from rcpatch.chains.search import DependencyPath, DependencyPathSearcher
from rcpatch.logging_utils import get_logger
from rcpatch.models import (
    BackwardSlice,
    BugReport,
    CandidateLabel,
    CausalityChain,
    ConfidenceScore,
    DependencyEdge,
    DependencyRelation,
    EvidenceKind,
    EvidenceReference,
    PropagationRelation,
    PropagationStep,
    RootCauseCandidate,
    SliceNode,
)


@dataclass(frozen=True)
class _BuiltChain:
    chain: CausalityChain


class CausalityChainConstructor:
    """Build ranked root-cause-to-trigger chains from a backward slice."""

    def __init__(
        self,
        *,
        searcher: Optional[DependencyPathSearcher] = None,
        max_paths_per_candidate: int = 3,
    ) -> None:
        self.searcher = searcher or DependencyPathSearcher()
        self.max_paths_per_candidate = max_paths_per_candidate
        self.logger = get_logger(__name__)

    def construct_chains(
        self,
        bug_report: BugReport,
        candidates: list[RootCauseCandidate],
        backward_slice: BackwardSlice,
        *,
        max_chains: Optional[int] = None,
    ) -> list[CausalityChain]:
        """Construct ranked causality chains for the strongest candidate roots."""
        if not backward_slice.trigger_node_id:
            self.logger.info("Backward slice for %s has no trigger node id; returning no chains", bug_report.bug_id)
            return []

        nodes_by_id = {node.node_id: node for node in backward_slice.nodes}
        selected_count = max_chains or bug_report.analysis_config.max_chain_paths
        max_depth = max(bug_report.analysis_config.max_backward_depth, 4)
        candidate_pool = self._select_candidates(candidates, selected_count=selected_count)
        built: list[_BuiltChain] = []
        seen_signatures: set[tuple[str, ...]] = set()

        for candidate in candidate_pool:
            start_node_id = self._resolve_candidate_node_id(candidate, backward_slice)
            if start_node_id is None:
                continue

            if start_node_id == backward_slice.trigger_node_id:
                paths = [DependencyPath(node_ids=(start_node_id,), edges=())]
            else:
                paths = self.searcher.search_paths(
                    backward_slice,
                    start_node_id=start_node_id,
                    trigger_node_id=backward_slice.trigger_node_id,
                    max_paths=min(self.max_paths_per_candidate, selected_count),
                    max_depth=max_depth,
                )
                if not paths:
                    fallback_path = self._build_direct_fallback_path(
                        candidate=candidate,
                        start_node_id=start_node_id,
                        trigger_node_id=backward_slice.trigger_node_id,
                        nodes_by_id=nodes_by_id,
                    )
                    if fallback_path is not None:
                        paths = [fallback_path]

            for path in paths:
                if path.node_ids in seen_signatures:
                    continue
                seen_signatures.add(path.node_ids)
                built.append(
                    _BuiltChain(
                        chain=self._build_chain(
                            bug_report=bug_report,
                            candidate=candidate,
                            path=path,
                            nodes_by_id=nodes_by_id,
                        ),
                    )
                )

        ranked = sorted(
            built,
            key=lambda item: (
                item.chain.score,
                -(item.chain.root_cause_rank or 999),
                -len(item.chain.steps),
            ),
            reverse=True,
        )
        selected = ranked[:selected_count]
        return [
            item.chain.model_copy(update={"rank": index})
            for index, item in enumerate(selected, start=1)
        ]

    def _select_candidates(self, candidates: list[RootCauseCandidate], *, selected_count: int) -> list[RootCauseCandidate]:
        root_candidates = [candidate for candidate in candidates if candidate.label == CandidateLabel.ROOT_CAUSE_CANDIDATE]
        if not root_candidates:
            root_candidates = [candidate for candidate in candidates if candidate.label != CandidateLabel.SYMPTOM]
        fallback_candidates = [candidate for candidate in candidates if candidate.label == CandidateLabel.PROPAGATION]

        ordered = root_candidates + [candidate for candidate in fallback_candidates if candidate not in root_candidates]
        if not ordered:
            ordered = [candidate for candidate in candidates if candidate.label != CandidateLabel.SYMPTOM]
        if not ordered:
            ordered = list(candidates)
        return ordered[: max(selected_count, 3)]

    def _resolve_candidate_node_id(self, candidate: RootCauseCandidate, backward_slice: BackwardSlice) -> Optional[str]:
        statement_id = candidate.metadata.get("statement_id")
        if isinstance(statement_id, str):
            return statement_id

        for node in backward_slice.nodes:
            if (
                node.location.file == candidate.location.file
                and node.location.line == candidate.location.line
                and node.location.function == candidate.location.function
            ):
                return node.node_id
        return None

    def _build_direct_fallback_path(
        self,
        *,
        candidate: RootCauseCandidate,
        start_node_id: str,
        trigger_node_id: str,
        nodes_by_id: dict[str, SliceNode],
    ) -> Optional[DependencyPath]:
        """Create an explicit approximate edge when path search cannot connect useful nodes."""
        start_node = nodes_by_id.get(start_node_id)
        trigger_node = nodes_by_id.get(trigger_node_id)
        if start_node is None or trigger_node is None:
            return None

        edge = DependencyEdge(
            source_node_id=start_node_id,
            target_node_id=trigger_node_id,
            relation=self._fallback_relation(candidate),
            entity=self._first_entity(start_node, trigger_node),
            explanation=(
                "Approximate direct propagation edge: no precise dependency path was recovered, "
                "so the chain preserves the strongest candidate-to-trigger relationship."
            ),
            approximated=True,
            metadata={"fallback": True, "fallback_reason": "no_dependency_path_recovered"},
        )
        return DependencyPath(node_ids=(start_node_id, trigger_node_id), edges=(edge,))

    @staticmethod
    def _fallback_relation(candidate: RootCauseCandidate) -> DependencyRelation:
        features = candidate.features
        if features.get("affects_control_flow"):
            return DependencyRelation.CONTROL_DEPENDENCE
        if features.get("changes_object_state"):
            return DependencyRelation.STATE_UPDATE
        if features.get("has_integer_influence"):
            return DependencyRelation.INTEGER_INFLUENCE
        if features.get("has_memory_context"):
            return DependencyRelation.HEAP_OBJECT
        return DependencyRelation.DATA_DEPENDENCE

    @staticmethod
    def _first_entity(*nodes: SliceNode) -> Optional[str]:
        for node in nodes:
            if node.tracked_entities:
                return node.tracked_entities[0]
        return None

    def _build_chain(
        self,
        *,
        bug_report: BugReport,
        candidate: RootCauseCandidate,
        path: DependencyPath,
        nodes_by_id: dict[str, SliceNode],
    ) -> CausalityChain:
        node_sequence = [nodes_by_id[node_id] for node_id in path.node_ids if node_id in nodes_by_id]
        steps = self._build_steps(
            bug_report=bug_report,
            node_sequence=node_sequence,
            edges=list(path.edges),
        )
        score, components = self._score_chain(candidate=candidate, path=path, steps=steps, bug_report=bug_report)
        summary = self._summarize_chain(
            bug_report=bug_report,
            candidate=candidate,
            steps=steps,
        )

        return CausalityChain(
            root_cause_rank=candidate.rank,
            steps=steps,
            summary=summary,
            score=score,
            confidence=ConfidenceScore(
                value=score,
                rationale="Heuristic path score combining candidate strength, path conciseness, relation richness, and runtime support.",
                method="heuristic_chain_ranker_v1",
                components=components,
            ),
            metadata={
                "path_node_ids": list(path.node_ids),
                "edge_count": len(path.edges),
                "root_candidate_score": candidate.score,
                "root_candidate_label": candidate.label.value,
                "fallback_chain": not path.edges or any(edge.metadata.get("fallback") for edge in path.edges),
            },
        )

    def _build_steps(
        self,
        *,
        bug_report: BugReport,
        node_sequence: list[SliceNode],
        edges: list[DependencyEdge],
    ) -> list[PropagationStep]:
        steps: list[PropagationStep] = []
        for index, node in enumerate(node_sequence):
            if index < len(edges):
                edge = edges[index]
                target_node = node_sequence[index + 1]
                relation = self._map_relation(edge.relation)
                entity = edge.entity
                explanation = self._step_explanation(node=node, edge=edge, target_node=target_node)
                operation_type = self._operation_type(node=node, edge=edge)
                confidence_value = 0.7 if edge.approximated else 0.85
                metadata = {
                    "statement_id": node.statement_id,
                    "function_name": node.function_name,
                    "statement_text": node.text,
                    "operation_type": operation_type,
                    "next_location": target_node.location.model_dump(mode="json"),
                }
            elif not edges:
                relation = PropagationRelation.DATA_FLOW
                entity = self._first_entity(node)
                explanation = self._single_step_explanation(node=node, bug_report=bug_report)
                operation_type = self._operation_type_without_edge(node=node)
                confidence_value = 0.55
                metadata = {
                    "statement_id": node.statement_id,
                    "function_name": node.function_name,
                    "statement_text": node.text,
                    "operation_type": operation_type,
                    "trigger": node.is_trigger,
                    "fallback": True,
                    "fallback_reason": "candidate_is_trigger_or_no_upstream_path",
                }
            else:
                previous_edge = edges[-1]
                relation = self._map_relation(previous_edge.relation)
                entity = previous_edge.entity
                explanation = self._trigger_explanation(node=node, edge=previous_edge, bug_report=bug_report)
                operation_type = self._operation_type(node=node, edge=previous_edge)
                confidence_value = 0.85
                metadata = {
                    "statement_id": node.statement_id,
                    "function_name": node.function_name,
                    "statement_text": node.text,
                    "operation_type": operation_type,
                    "trigger": True,
                }

            steps.append(
                PropagationStep(
                    location=node.location,
                    relation=relation,
                    entity=entity,
                    explanation=explanation,
                    evidence=self._evidence_for_location(bug_report=bug_report, node=node),
                    confidence=ConfidenceScore(
                        value=confidence_value,
                        rationale="Step confidence is higher for runtime-supported or terminal propagation points.",
                        method="heuristic_chain_step_confidence_v1",
                    ),
                    metadata=metadata,
                )
            )
        return steps

    def _score_chain(
        self,
        *,
        candidate: RootCauseCandidate,
        path: DependencyPath,
        steps: list[PropagationStep],
        bug_report: BugReport,
    ) -> tuple[float, dict[str, float]]:
        edge_count = max(len(path.edges), 1)
        distinct_relations = {step.relation for step in steps}
        interprocedural = any(
            step.relation in {PropagationRelation.CALL_ARGUMENT, PropagationRelation.RETURN_VALUE}
            for step in steps
        )
        runtime_supported = any(step.evidence for step in steps)
        approximated_edges = sum(1 for edge in path.edges if edge.approximated)
        approximation_ratio = approximated_edges / edge_count
        label_bonus = {
            CandidateLabel.ROOT_CAUSE_CANDIDATE: 0.08,
            CandidateLabel.PROPAGATION: 0.02,
            CandidateLabel.SYMPTOM: -0.12,
        }.get(candidate.label, 0.0)

        max_depth = max(bug_report.analysis_config.max_backward_depth, edge_count)
        conciseness = 1.0 - min((edge_count - 1) / max_depth, 1.0)
        relation_richness = min(len(distinct_relations) / 4.0, 1.0)

        components = {
            "candidate_score": 0.70 * candidate.score,
            "conciseness": 0.10 * conciseness,
            "relation_richness": 0.07 * relation_richness,
            "interprocedural_bonus": 0.07 if interprocedural else 0.0,
            "runtime_support": 0.08 if runtime_supported else 0.0,
            "label_bonus": label_bonus,
            "approximation_penalty": -0.06 * approximation_ratio,
        }
        raw_score = sum(components.values())
        return max(0.0, min(raw_score, 1.0)), components

    def _summarize_chain(
        self,
        *,
        bug_report: BugReport,
        candidate: RootCauseCandidate,
        steps: list[PropagationStep],
    ) -> str:
        root_step = steps[0]
        trigger_step = steps[-1]
        intermediate_functions = []
        for step in steps[1:-1]:
            function_name = step.location.function
            if function_name and function_name != root_step.location.function and function_name not in intermediate_functions:
                intermediate_functions.append(function_name)
        failing_operation = bug_report.trigger_point.failing_operation or "the trigger point"
        if intermediate_functions:
            intermediate_text = " through " + " -> ".join(intermediate_functions)
        else:
            intermediate_text = ""
        root_clause = candidate.explanation.rstrip(".")
        return (
            f"{root_clause}. It propagates from "
            f"{root_step.location.function or root_step.location.file}:{root_step.location.line}"
            f"{intermediate_text} to {failing_operation} at "
            f"{trigger_step.location.file}:{trigger_step.location.line}."
        )

    def _step_explanation(self, *, node: SliceNode, edge: DependencyEdge, target_node: SliceNode) -> str:
        entity_text = edge.entity or "relevant state"
        if edge.relation == DependencyRelation.RETURN_VALUE:
            return f"The returned {entity_text} flows into {target_node.function_name} at line {target_node.location.line}."
        if edge.relation == DependencyRelation.CALL_ARGUMENT:
            return f"{entity_text} is passed across the call boundary into line {target_node.location.line}."
        if edge.relation == DependencyRelation.CONTROL_DEPENDENCE:
            return f"This guard controls whether line {target_node.location.line} executes."
        if edge.relation == DependencyRelation.STATE_UPDATE:
            return f"This statement updates {entity_text}, which is used at line {target_node.location.line}."
        if edge.relation == DependencyRelation.INTEGER_INFLUENCE:
            return f"The computed {entity_text} influences a later size or index at line {target_node.location.line}."
        if edge.relation == DependencyRelation.ALLOCATION_SITE:
            return f"This allocation determines the later lifetime or bounds of {entity_text} at line {target_node.location.line}."
        if edge.relation == DependencyRelation.DEALLOCATION_SITE:
            return f"This deallocation can invalidate {entity_text} before line {target_node.location.line}."
        if edge.relation == DependencyRelation.INITIALIZATION_SITE:
            return f"This initialization affects the later state of {entity_text} at line {target_node.location.line}."
        if edge.relation == DependencyRelation.HEAP_OBJECT:
            return f"Heap state for {entity_text} aliases into line {target_node.location.line}."
        return f"{entity_text} flows from this statement to line {target_node.location.line}."

    def _trigger_explanation(self, *, node: SliceNode, edge: DependencyEdge, bug_report: BugReport) -> str:
        entity_text = edge.entity or "the propagated state"
        failing_operation = bug_report.trigger_point.failing_operation or "the failing operation"
        return f"At the trigger, {entity_text} reaches {failing_operation} in `{node.text}`."

    def _single_step_explanation(self, *, node: SliceNode, bug_report: BugReport) -> str:
        failing_operation = bug_report.trigger_point.failing_operation or "the failing operation"
        if node.is_trigger:
            return (
                "The best available candidate is the trigger statement itself; "
                f"no upstream dependency path was recovered before {failing_operation}."
            )
        return (
            "This candidate is retained as an approximate one-step chain because no precise "
            f"dependency path to {failing_operation} was recovered."
        )

    def _operation_type(self, *, node: SliceNode, edge: DependencyEdge) -> str:
        if node.statement_types:
            return node.statement_types[0].value
        if edge.relation == DependencyRelation.CALL_ARGUMENT:
            return "call_argument"
        if edge.relation == DependencyRelation.RETURN_VALUE:
            return "return"
        if edge.relation == DependencyRelation.CONTROL_DEPENDENCE:
            return "condition"
        if edge.relation == DependencyRelation.ALLOCATION_SITE:
            return "allocation"
        if edge.relation == DependencyRelation.DEALLOCATION_SITE:
            return "deallocation"
        if edge.relation == DependencyRelation.INITIALIZATION_SITE:
            return "initialization"
        return "statement"

    @staticmethod
    def _operation_type_without_edge(*, node: SliceNode) -> str:
        if node.statement_types:
            return node.statement_types[0].value
        return "statement"

    def _map_relation(self, relation: DependencyRelation) -> PropagationRelation:
        mapping = {
            DependencyRelation.DATA_DEPENDENCE: PropagationRelation.DATA_FLOW,
            DependencyRelation.INTEGER_INFLUENCE: PropagationRelation.DATA_FLOW,
            DependencyRelation.CONTROL_DEPENDENCE: PropagationRelation.CONTROL_FLOW,
            DependencyRelation.CALL_ARGUMENT: PropagationRelation.CALL_ARGUMENT,
            DependencyRelation.RETURN_VALUE: PropagationRelation.RETURN_VALUE,
            DependencyRelation.STATE_UPDATE: PropagationRelation.STATE_UPDATE,
            DependencyRelation.GLOBAL_STATE: PropagationRelation.STATE_UPDATE,
            DependencyRelation.INITIALIZATION_SITE: PropagationRelation.STATE_UPDATE,
            DependencyRelation.HEAP_OBJECT: PropagationRelation.HEAP_ALIAS_PROPAGATION,
            DependencyRelation.ALLOCATION_SITE: PropagationRelation.OWNERSHIP_TRANSFER,
            DependencyRelation.DEALLOCATION_SITE: PropagationRelation.OWNERSHIP_TRANSFER,
            DependencyRelation.CALLER_CONTEXT: PropagationRelation.CONTROL_FLOW,
        }
        return mapping.get(relation, PropagationRelation.DATA_FLOW)

    def _evidence_for_location(self, *, bug_report: BugReport, node: SliceNode) -> list[EvidenceReference]:
        evidence: list[EvidenceReference] = []
        if (
            node.location.file == bug_report.trigger_point.location.file
            and node.location.line == bug_report.trigger_point.location.line
        ):
            evidence.extend(bug_report.trigger_point.evidence)

        runtime_evidence = bug_report.runtime_evidence
        if runtime_evidence is None:
            return evidence

        for frame in runtime_evidence.stack_frames:
            if frame.location is None:
                continue
            if frame.location.file == node.location.file and frame.location.line == node.location.line:
                evidence.append(
                    EvidenceReference(
                        kind=EvidenceKind.STACK_TRACE,
                        path=runtime_evidence.stack_trace_path or runtime_evidence.sanitizer_report_path,
                        line=frame.location.line,
                        excerpt=f"frame #{frame.index}: {frame.function or frame.location.function or node.function_name}",
                        description="Chain step appears directly in runtime evidence.",
                    )
                )
        return self._dedupe_evidence(evidence)

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
