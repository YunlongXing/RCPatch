"""Reusable root-cause pattern mining from curated CVE annotations."""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass
import re
from typing import Iterable, Optional

from rcpatch.logging_utils import get_logger
from rcpatch.models import (
    CVERootCauseAnnotation,
    CVERootCauseDataset,
    CVERootCauseDatasetRecord,
    CVERootCauseMiningResult,
    DependencyEdge,
    RootCausePattern,
    RootCausePatternExample,
    RootCausePatternGraph,
    RootCausePatternLibrary,
    RootCausePatternRule,
    RootCausePatternTemplate,
)

_LINE_PREFIX_RE = re.compile(r"(?m)^\s*\d+:\s*")
_IDENTIFIER_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_INTEGER_RE = re.compile(r"\b(?:0x[0-9A-Fa-f]+|\d+)\b")
_STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"')

_KEYWORDS = {
    "if",
    "else",
    "for",
    "while",
    "return",
    "switch",
    "case",
    "break",
    "continue",
    "const",
    "static",
    "unsigned",
    "signed",
    "int",
    "long",
    "short",
    "char",
    "void",
    "size_t",
    "struct",
    "enum",
    "do",
}
_SIZE_HINT_TOKENS = ("len", "length", "size", "count", "capacity", "offset", "bound", "idx", "index")
_BUFFER_HINT_TOKENS = ("buf", "dst", "src", "ptr", "out", "in", "data", "payload", "msg", "text")
_NULL_TOKENS = ("null", "nullptr")
_COPY_TOKENS = {"memcpy", "memmove", "strcpy", "strncpy"}
_ALLOC_TOKENS = {"malloc", "calloc", "realloc", "new"}
_FREE_TOKENS = {"free", "delete"}


@dataclass(frozen=True)
class _PatternObservation:
    record: CVERootCauseDatasetRecord
    annotation: CVERootCauseAnnotation
    normalized_template: str
    operation_type: str
    graph_signature: RootCausePatternGraph
    category: str


class RootCausePatternMiner:
    """Mine reusable templates, graph patterns, and rules from curated CVE roots."""

    def __init__(self, *, min_support: int = 1, max_examples: int = 3, max_templates: int = 3) -> None:
        self.min_support = max(1, min_support)
        self.max_examples = max(1, max_examples)
        self.max_templates = max(1, max_templates)
        self.logger = get_logger(__name__)

    def mine(
        self,
        dataset: CVERootCauseDataset,
        *,
        mining_results_by_cve: Optional[dict[str, CVERootCauseMiningResult]] = None,
        min_support: Optional[int] = None,
    ) -> RootCausePatternLibrary:
        """Build a reusable pattern library from curated CVE root-cause annotations."""

        support_threshold = self.min_support if min_support is None else max(1, min_support)
        observations = self._collect_observations(dataset, mining_results_by_cve or {})
        clusters: dict[tuple[str, str, str], list[_PatternObservation]] = defaultdict(list)
        for observation in observations:
            key = (observation.category, observation.operation_type, observation.graph_signature.signature)
            clusters[key].append(observation)

        patterns: list[RootCausePattern] = []
        for cluster_index, ((category, operation_type, _graph_signature), cluster_observations) in enumerate(
            sorted(clusters.items(), key=lambda item: (-len(item[1]), item[0]))
        ):
            if len(cluster_observations) < support_threshold:
                continue
            patterns.append(
                self._build_pattern(
                    cluster_index=cluster_index + 1,
                    category=category,
                    operation_type=operation_type,
                    observations=cluster_observations,
                )
            )

        return RootCausePatternLibrary(
            patterns=patterns,
            metadata={
                "input_record_count": len(dataset.records),
                "observation_count": len(observations),
                "pattern_count": len(patterns),
                "min_support": support_threshold,
            },
        )

    def _collect_observations(
        self,
        dataset: CVERootCauseDataset,
        mining_results_by_cve: dict[str, CVERootCauseMiningResult],
    ) -> list[_PatternObservation]:
        observations: list[_PatternObservation] = []
        for record in dataset.records:
            mining_result = mining_results_by_cve.get(record.cve_id)
            for annotation in record.root_causes:
                normalized_template = self._normalize_template(annotation.code_snippet)
                operation_type = self._operation_type(annotation)
                graph_signature = self._graph_pattern(annotation, mining_result)
                category = annotation.pattern or annotation.type or annotation.classification.value
                observations.append(
                    _PatternObservation(
                        record=record,
                        annotation=annotation,
                        normalized_template=normalized_template,
                        operation_type=operation_type,
                        graph_signature=graph_signature,
                        category=category,
                    )
                )
        return observations

    def _build_pattern(
        self,
        *,
        cluster_index: int,
        category: str,
        operation_type: str,
        observations: list[_PatternObservation],
    ) -> RootCausePattern:
        template_counter = Counter(observation.normalized_template for observation in observations)
        templates = [
            RootCausePatternTemplate(
                template=template,
                support_count=count,
                metadata={"category": category, "operation_type": operation_type},
            )
            for template, count in template_counter.most_common(self.max_templates)
        ]

        graph_pattern = self._aggregate_graph_pattern(observations)
        feature_rules = self._feature_rules(observations)
        sorted_examples = sorted(observations, key=lambda item: item.annotation.confidence, reverse=True)
        examples = [
            RootCausePatternExample(
                cve_id=observation.record.cve_id,
                location=observation.annotation.location,
                code_snippet=observation.annotation.code_snippet,
                confidence=observation.annotation.confidence,
                abstract_template=observation.normalized_template,
                patch_relation=observation.annotation.patch_relation,
                metadata={
                    "pattern": observation.annotation.pattern,
                    "type": observation.annotation.type,
                    "classification": observation.annotation.classification.value,
                },
            )
            for observation in sorted_examples[: self.max_examples]
        ]
        support_count = len(observations)
        pattern_name = category.replace("_", " ")
        pattern_id = f"{category}:{operation_type}:{cluster_index}"
        return RootCausePattern(
            pattern_id=pattern_id,
            name=pattern_name,
            category=category,
            operation_type=operation_type,
            support_count=support_count,
            cve_ids=sorted({observation.record.cve_id for observation in observations}),
            templates=templates,
            graph_pattern=graph_pattern,
            feature_rules=feature_rules,
            examples=examples,
            metadata={
                "average_confidence": round(
                    sum(observation.annotation.confidence for observation in observations) / support_count,
                    4,
                ),
                "patch_relations": sorted({observation.annotation.patch_relation for observation in observations}),
            },
        )

    def _aggregate_graph_pattern(self, observations: list[_PatternObservation]) -> RootCausePatternGraph:
        signatures = Counter(observation.graph_signature.signature for observation in observations)
        dominant_signature, _ = signatures.most_common(1)[0]
        dominant = next(
            observation.graph_signature
            for observation in observations
            if observation.graph_signature.signature == dominant_signature
        )
        relation_counter = Counter()
        path_counter = Counter()
        for observation in observations:
            relation_counter.update(observation.graph_signature.entry_relations)
            path_counter.update(observation.graph_signature.path_relations)
        return RootCausePatternGraph(
            signature=dominant_signature,
            entry_relations=[relation for relation, _count in relation_counter.most_common()],
            path_relations=[relation for relation, _count in path_counter.most_common()],
            metadata={
                "support_count": len(observations),
                "dominant_signature_support": signatures[dominant_signature],
            },
        )

    def _feature_rules(self, observations: list[_PatternObservation]) -> list[RootCausePatternRule]:
        support_count = len(observations)
        counters: dict[str, Counter[str]] = {
            "patch_relation": Counter(observation.annotation.patch_relation for observation in observations),
            "candidate_origin": Counter(
                observation.annotation.candidate_origin or "unknown"
                for observation in observations
            ),
            "classification": Counter(observation.annotation.classification.value for observation in observations),
        }
        rules: list[RootCausePatternRule] = []
        for feature, counter in counters.items():
            value, count = counter.most_common(1)[0]
            support = count / support_count
            if support < 0.6:
                continue
            rules.append(
                RootCausePatternRule(
                    feature=feature,
                    value=value,
                    support=round(support, 4),
                )
            )
        return rules

    def _operation_type(self, annotation: CVERootCauseAnnotation) -> str:
        pattern = (annotation.pattern or annotation.type).lower()
        snippet = annotation.code_snippet.lower()
        if "null" in pattern or any(token in snippet for token in _NULL_TOKENS):
            return "null_check"
        if "overflow" in pattern and "integer" in pattern:
            return "integer_overflow"
        if "size" in pattern or "length" in pattern or any(token in snippet for token in _SIZE_HINT_TOKENS):
            if any(token in snippet for token in _COPY_TOKENS):
                return "size_to_copy"
            return "length_calculation"
        if "lifetime" in pattern or "use_after_free" in pattern or any(token in snippet for token in _FREE_TOKENS):
            return "lifetime_management"
        if "initialization" in pattern:
            return "initialization"
        if "guard" in pattern or "check" in pattern:
            return "guard_check"
        return "state_update"

    def _normalize_template(self, snippet: str) -> str:
        stripped = _LINE_PREFIX_RE.sub("", snippet)
        stripped = _STRING_RE.sub("<str>", stripped)
        stripped = _INTEGER_RE.sub("<int>", stripped)
        identifier_map: dict[str, str] = {}
        next_var_index = 1

        def replace_identifier(match: re.Match[str]) -> str:
            nonlocal next_var_index
            identifier = match.group(0)
            lowered = identifier.lower()
            if lowered in _KEYWORDS:
                return identifier
            if lowered in _NULL_TOKENS:
                return "<null>"
            if lowered in _COPY_TOKENS:
                return "<copy_op>"
            if lowered in _ALLOC_TOKENS:
                return "<alloc_op>"
            if lowered in _FREE_TOKENS:
                return "<free_op>"
            if any(token in lowered for token in _SIZE_HINT_TOKENS):
                return "<size_var>"
            if any(token in lowered for token in _BUFFER_HINT_TOKENS):
                return "<buffer_var>"
            if lowered not in identifier_map:
                identifier_map[lowered] = f"<var{next_var_index}>"
                next_var_index += 1
            return identifier_map[lowered]

        normalized = _IDENTIFIER_RE.sub(replace_identifier, stripped)
        normalized = re.sub(r"\s+", " ", normalized).strip()
        return normalized

    def _graph_pattern(
        self,
        annotation: CVERootCauseAnnotation,
        mining_result: Optional[CVERootCauseMiningResult],
    ) -> RootCausePatternGraph:
        if mining_result is None:
            signature = f"{annotation.patch_relation}:{annotation.candidate_origin or 'unknown'}"
            return RootCausePatternGraph(
                signature=signature,
                entry_relations=[],
                path_relations=[],
                metadata={"fallback": True},
            )

        matched_node_ids = self._matching_node_ids(annotation, mining_result)
        if not matched_node_ids:
            signature = f"{annotation.patch_relation}:{annotation.candidate_origin or 'unknown'}"
            return RootCausePatternGraph(
                signature=signature,
                entry_relations=[],
                path_relations=[],
                metadata={"fallback": True, "reason": "candidate location not found in slices"},
            )

        entry_relations: list[str] = []
        path_relations: list[str] = []
        for slice_result in mining_result.slices:
            outgoing = defaultdict(list)
            for edge in slice_result.edges:
                outgoing[edge.source_node_id].append(edge)

            trigger_node_id = slice_result.trigger_node_id
            for node_id in matched_node_ids:
                local_outgoing = outgoing.get(node_id, [])
                entry_relations.extend(edge.relation.value for edge in local_outgoing)
                path_relations.extend(self._path_relations_to_trigger(node_id, trigger_node_id, outgoing))

        if not entry_relations and not path_relations:
            signature = f"{annotation.patch_relation}:{annotation.candidate_origin or 'unknown'}"
            return RootCausePatternGraph(
                signature=signature,
                entry_relations=[],
                path_relations=[],
                metadata={"fallback": True, "reason": "no reachable path relations"},
            )

        unique_entry = list(dict.fromkeys(entry_relations))
        unique_path = list(dict.fromkeys(path_relations or entry_relations))
        signature = " -> ".join(unique_path) if unique_path else "direct_state_origin"
        return RootCausePatternGraph(
            signature=signature,
            entry_relations=unique_entry,
            path_relations=unique_path,
            metadata={"fallback": False},
        )

    @staticmethod
    def _matching_node_ids(
        annotation: CVERootCauseAnnotation,
        mining_result: CVERootCauseMiningResult,
    ) -> set[str]:
        matched: set[str] = set()
        for slice_result in mining_result.slices:
            for node in slice_result.nodes:
                if (
                    node.location.file == annotation.location.file
                    and node.location.line == annotation.location.line
                    and node.location.function == annotation.location.function
                ):
                    matched.add(node.node_id)
        return matched

    @staticmethod
    def _path_relations_to_trigger(
        start_node_id: str,
        trigger_node_id: Optional[str],
        outgoing: dict[str, list[DependencyEdge]],
    ) -> list[str]:
        if trigger_node_id is None:
            return [edge.relation.value for edge in outgoing.get(start_node_id, [])]

        queue = deque([(start_node_id, [])])
        visited = {start_node_id}
        while queue:
            node_id, relations = queue.popleft()
            if node_id == trigger_node_id and relations:
                return relations
            for edge in outgoing.get(node_id, []):
                if edge.target_node_id in visited:
                    continue
                visited.add(edge.target_node_id)
                queue.append((edge.target_node_id, [*relations, edge.relation.value]))
        return [edge.relation.value for edge in outgoing.get(start_node_id, [])]
