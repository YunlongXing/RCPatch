"""Approximate trigger-guided backward slicer built on the shared program abstraction."""

from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import DefaultDict, Dict, Iterable, List, Optional, Set, Tuple

from rcpatch.logging_utils import get_logger
from rcpatch.models import (
    BackwardSlice,
    DependencyEdge,
    DependencyRelation,
    FunctionDefinition,
    MemoryOperationKind,
    SliceNode,
    SourceLocation,
    StatementInfo,
    StatementKind,
    TriggerPoint,
)
from rcpatch.source import ProgramIndex
from rcpatch.slicing.base import BackwardSlicer
from rcpatch.slicing.source_utils import SourceContextExtractor

IDENTIFIER_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
C_STYLE_CAST_RE = re.compile(r"\(\s*[A-Za-z_][A-Za-z0-9_\s\*]*\s*\)")
INTEGER_BINARY_OP_RE = re.compile(
    r"(?:\b[A-Za-z_][A-Za-z0-9_]*\b|\b\d+\b|\))\s*(<<|>>|[+\-/%*])\s*(?:\b[A-Za-z_][A-Za-z0-9_]*\b|\b\d+\b|\()"
)
PRIMITIVE_TYPE_TOKENS = {
    "bool",
    "char",
    "const",
    "double",
    "float",
    "int",
    "long",
    "short",
    "signed",
    "size_t",
    "ssize_t",
    "static",
    "struct",
    "typedef",
    "union",
    "unsigned",
    "void",
    "volatile",
}
NON_PRODUCTION_PATH_PREFIXES = ("test/", "tests/", "fuzz/", "fuzzers/", "example/", "examples/")


@dataclass
class SliceSeed:
    """Work item used during interprocedural expansion."""

    function_id: str
    statement_id: str
    relevant_entities: Set[str]
    hop_count: int


class HybridBackwardSlicer(BackwardSlicer):
    """Simple hybrid backward slicer with intraprocedural and interprocedural expansion."""

    def __init__(
        self,
        *,
        max_interprocedural_hops: int = 3,
        global_search_limit: int = 8,
    ) -> None:
        self.max_interprocedural_hops = max_interprocedural_hops
        self.global_search_limit = global_search_limit
        self.logger = get_logger(__name__)

    def slice_from_trigger(self, program_index: ProgramIndex, trigger: TriggerPoint) -> BackwardSlice:
        context_extractor = SourceContextExtractor(program_index)
        trigger_statement = context_extractor.find_trigger_statement(trigger)
        if trigger_statement is None:
            return BackwardSlice(
                trigger=trigger,
                diagnostics=["Unable to locate a statement corresponding to the trigger point."],
                approximations=[
                    "Slice extraction requires a statement-level match and currently falls back to nearest-line lookup.",
                ],
            )

        trigger_function = program_index.function_for_statement(trigger_statement.statement_id)
        if trigger_function is None:
            return BackwardSlice(
                trigger=trigger,
                diagnostics=["Trigger statement was found, but the enclosing function could not be determined."],
                approximations=["Function ownership resolution is approximate when parser metadata is incomplete."],
            )

        nodes_by_id: Dict[str, SliceNode] = {}
        edges_by_key: Dict[Tuple[str, str, str, str], DependencyEdge] = {}
        diagnostics: List[str] = []
        approximations: List[str] = [
            "Intraprocedural slicing uses statement order plus variable and syntax heuristics instead of full SSA/CFG dependence.",
            "Control dependence is approximated from nearby guarding conditions and block-depth metadata.",
            "Interprocedural expansion uses name-based parameter/return matching and may over-approximate indirect calls or globals.",
        ]

        trigger_node = self._ensure_node(
            nodes_by_id,
            trigger_statement,
            trigger_function,
            tracked_entities=self._extract_seed_entities(trigger_statement),
            is_trigger=True,
        )

        initial_entities = set(trigger_node.tracked_entities)
        pending = deque([SliceSeed(trigger_function.function_id, trigger_statement.statement_id, initial_entities, 0)])
        seen_seeds: Set[Tuple[str, str, Tuple[str, ...], int]] = set()

        while pending:
            seed = pending.popleft()
            seed_key = (seed.function_id, seed.statement_id, tuple(sorted(seed.relevant_entities)), seed.hop_count)
            if seed_key in seen_seeds:
                continue
            seen_seeds.add(seed_key)

            self._slice_within_function(
                program_index,
                seed=seed,
                nodes_by_id=nodes_by_id,
                edges_by_key=edges_by_key,
                pending=pending,
                diagnostics=diagnostics,
            )

        return BackwardSlice(
            trigger=trigger,
            trigger_node_id=trigger_node.node_id,
            nodes=sorted(nodes_by_id.values(), key=lambda node: (node.location.file, node.location.line, node.location.column or 0)),
            edges=sorted(
                edges_by_key.values(),
                key=lambda edge: (
                    nodes_by_id[edge.source_node_id].location.file,
                    nodes_by_id[edge.source_node_id].location.line,
                    nodes_by_id[edge.target_node_id].location.line,
                    edge.relation.value,
                ),
            ),
            diagnostics=diagnostics,
            approximations=approximations,
            metadata={
                "node_count": len(nodes_by_id),
                "edge_count": len(edges_by_key),
                "max_interprocedural_hops": self.max_interprocedural_hops,
            },
        )

    def _slice_within_function(
        self,
        program_index: ProgramIndex,
        *,
        seed: SliceSeed,
        nodes_by_id: Dict[str, SliceNode],
        edges_by_key: Dict[Tuple[str, str, str, str], DependencyEdge],
        pending: deque[SliceSeed],
        diagnostics: List[str],
    ) -> None:
        function = program_index.get_function(seed.function_id)
        target_statement = program_index.get_statement(seed.statement_id)
        if function is None or target_statement is None:
            diagnostics.append(f"Skipping seed {seed.function_id}:{seed.statement_id} because the source statement is unavailable.")
            return

        statements = program_index.statements_in_function(function.function_id)
        statement_positions = {statement.statement_id: index for index, statement in enumerate(statements)}
        if seed.statement_id not in statement_positions:
            diagnostics.append(f"Skipping seed {seed.statement_id} because it is not indexed in function {function.name}.")
            return

        consumer_map: DefaultDict[str, Set[str]] = defaultdict(set)
        selected_statement_ids: Set[str] = {target_statement.statement_id}
        target_node = self._ensure_node(
            nodes_by_id,
            target_statement,
            function,
            tracked_entities=seed.relevant_entities,
            is_trigger=nodes_by_id.get(target_statement.statement_id) is not None and nodes_by_id[target_statement.statement_id].is_trigger,
        )

        for entity in seed.relevant_entities:
            consumer_map[entity].add(target_statement.statement_id)

        for entity in self._extract_upstream_entities(target_statement):
            consumer_map[entity].add(target_statement.statement_id)

        start_index = statement_positions[seed.statement_id]
        for index in range(start_index - 1, -1, -1):
            statement = statements[index]
            statement_entities = set(statement.defined_variables)
            matched_entities = sorted(statement_entities.intersection(consumer_map.keys()))
            memory_matches = self._memory_relations(statement, consumer_map.keys())
            semantic_matches = self._semantic_relations(statement, consumer_map.keys())
            if matched_entities or memory_matches or semantic_matches:
                selected_statement_ids.add(statement.statement_id)
                source_node = self._ensure_node(
                    nodes_by_id,
                    statement,
                    function,
                    tracked_entities=set(matched_entities + list(memory_matches.keys()) + list(semantic_matches.keys())),
                )

                if matched_entities:
                    for entity in matched_entities:
                        relation = self._relation_for_statement(statement, entity)
                        for consumer_id in consumer_map[entity]:
                            self._add_edge(
                                edges_by_key,
                                source_node_id=source_node.node_id,
                                target_node_id=consumer_id,
                                relation=relation,
                                entity=entity,
                                explanation=self._explain_data_edge(statement, entity, relation),
                            )

                for entity, relation in memory_matches.items():
                    for consumer_id in consumer_map[entity]:
                        self._add_edge(
                            edges_by_key,
                            source_node_id=source_node.node_id,
                            target_node_id=consumer_id,
                            relation=relation,
                            entity=entity,
                            explanation=self._explain_memory_edge(statement, entity, relation),
                        )

                for entity, relation in semantic_matches.items():
                    for consumer_id in consumer_map[entity]:
                        self._add_edge(
                            edges_by_key,
                            source_node_id=source_node.node_id,
                            target_node_id=consumer_id,
                            relation=relation,
                            entity=entity,
                            explanation=self._explain_semantic_edge(statement, entity, relation),
                        )

                upstream_entities = self._extract_upstream_entities(statement)
                for entity in upstream_entities:
                    consumer_map[entity].add(statement.statement_id)

                if seed.hop_count < self.max_interprocedural_hops:
                    self._enqueue_return_expansion(
                        program_index,
                        function=function,
                        statement=statement,
                        relevant_entities=set(matched_entities),
                        hop_count=seed.hop_count,
                        pending=pending,
                        nodes_by_id=nodes_by_id,
                        edges_by_key=edges_by_key,
                    )
                    self._enqueue_output_parameter_expansion(
                        program_index,
                        function=function,
                        statement=statement,
                        relevant_entities=set(matched_entities).union(memory_matches.keys()),
                        hop_count=seed.hop_count,
                        pending=pending,
                        nodes_by_id=nodes_by_id,
                        edges_by_key=edges_by_key,
                    )

        self._attach_guard_conditions(
            function=function,
            selected_statement_ids=selected_statement_ids,
            program_index=program_index,
            nodes_by_id=nodes_by_id,
            edges_by_key=edges_by_key,
            consumer_map=consumer_map,
        )

        if seed.hop_count < self.max_interprocedural_hops:
            self._enqueue_parameter_expansion(
                program_index,
                function=function,
                target_statement=target_statement,
                seed=seed,
                pending=pending,
                nodes_by_id=nodes_by_id,
                edges_by_key=edges_by_key,
                consumer_map=consumer_map,
                selected_statement_ids=selected_statement_ids,
            )

        self._attach_global_updates(
            program_index,
            function=function,
            consumer_map=consumer_map,
            nodes_by_id=nodes_by_id,
            edges_by_key=edges_by_key,
            selected_statement_ids=selected_statement_ids,
        )

    def _attach_guard_conditions(
        self,
        *,
        function: FunctionDefinition,
        selected_statement_ids: Set[str],
        program_index: ProgramIndex,
        nodes_by_id: Dict[str, SliceNode],
        edges_by_key: Dict[Tuple[str, str, str, str], DependencyEdge],
        consumer_map: DefaultDict[str, Set[str]],
    ) -> None:
        statements = program_index.statements_in_function(function.function_id)
        selected_statements = [statement for statement in statements if statement.statement_id in selected_statement_ids]
        for statement in statements:
            if StatementKind.CONDITION not in statement.statement_types:
                continue
            condition_depth = int(statement.metadata.get("block_depth", 0))
            guarded_targets = [
                target_statement
                for target_statement in selected_statements
                if target_statement.location.line > statement.location.line
                and int(target_statement.metadata.get("block_depth", 0)) > condition_depth
            ]
            if not guarded_targets:
                continue

            guard_node = self._ensure_node(
                nodes_by_id,
                statement,
                function,
                tracked_entities=set(statement.referenced_variables),
            )
            for target_statement in guarded_targets:
                self._add_edge(
                    edges_by_key,
                    source_node_id=guard_node.node_id,
                    target_node_id=target_statement.statement_id,
                    relation=DependencyRelation.CONTROL_DEPENDENCE,
                    entity=statement.condition_expression,
                    explanation="Condition statement may guard downstream execution.",
                )
            for entity in statement.referenced_variables:
                consumer_map[entity].add(statement.statement_id)

    def _enqueue_parameter_expansion(
        self,
        program_index: ProgramIndex,
        *,
        function: FunctionDefinition,
        target_statement: StatementInfo,
        seed: SliceSeed,
        pending: deque[SliceSeed],
        nodes_by_id: Dict[str, SliceNode],
        edges_by_key: Dict[Tuple[str, str, str, str], DependencyEdge],
        consumer_map: DefaultDict[str, Set[str]],
        selected_statement_ids: Set[str],
    ) -> None:
        parameter_names = {parameter.position: parameter.name for parameter in function.parameters if parameter.name}
        relevant_parameters = {
            position: name
            for position, name in parameter_names.items()
            if name in consumer_map.keys() or name in seed.relevant_entities or name in target_statement.referenced_variables
        }
        if not relevant_parameters:
            return

        caller_relationships = self._select_caller_relationships(
            function=function,
            relationships=program_index.call_relationships_to(function.function_id),
        )
        if not caller_relationships:
            return

        selected_targets = [
            statement
            for statement in program_index.statements_in_function(function.function_id)
            if statement.statement_id in selected_statement_ids
        ]

        for relationship in caller_relationships:
            caller_function = program_index.get_function(relationship.caller_function_id)
            if caller_function is None:
                continue
            argument_texts = _extract_call_arguments(relationship.location.snippet or "", relationship.callee_name)
            caller_statement = program_index.find_nearest_statement(relationship.location, max_line_distance=0)
            if caller_statement is None:
                continue
            caller_node = self._ensure_node(
                nodes_by_id,
                caller_statement,
                caller_function,
                tracked_entities=set(_tokens_from_text(" ".join(argument_texts))),
            )
            for position, parameter_name in relevant_parameters.items():
                if position >= len(argument_texts):
                    continue
                argument_text = argument_texts[position]
                argument_entities = set(_tokens_from_text(argument_text))
                if not argument_entities:
                    continue
                target_statements = [
                    statement
                    for statement in selected_targets
                    if parameter_name in self._extract_upstream_entities(statement)
                    or parameter_name in statement.referenced_variables
                    or parameter_name in statement.defined_variables
                ]
                if not target_statements:
                    target_statements = [target_statement]
                edge_entity = _preferred_argument_entity(argument_text, fallback=parameter_name)
                for parameter_target in target_statements:
                    self._add_edge(
                        edges_by_key,
                        source_node_id=caller_node.node_id,
                        target_node_id=parameter_target.statement_id,
                        relation=DependencyRelation.CALL_ARGUMENT,
                        entity=edge_entity,
                        explanation="Caller argument may define a relevant callee parameter.",
                    )
                pending.append(
                    SliceSeed(
                        function_id=caller_function.function_id,
                        statement_id=caller_statement.statement_id,
                        relevant_entities=argument_entities,
                        hop_count=seed.hop_count + 1,
                    )
                )

    def _enqueue_return_expansion(
        self,
        program_index: ProgramIndex,
        *,
        function: FunctionDefinition,
        statement: StatementInfo,
        relevant_entities: Set[str],
        hop_count: int,
        pending: deque[SliceSeed],
        nodes_by_id: Dict[str, SliceNode],
        edges_by_key: Dict[Tuple[str, str, str, str], DependencyEdge],
    ) -> None:
        if not statement.call_names:
            return
        if not statement.defined_variables:
            return
        defined_entities = set(statement.defined_variables)
        if not defined_entities.intersection(relevant_entities):
            return

        for call_name in statement.call_names:
            candidate_functions = program_index.find_functions(call_name.split("::")[-1])
            if len(candidate_functions) != 1:
                continue
            callee = candidate_functions[0]
            return_statements = [
                callee_statement
                for callee_statement in program_index.statements_in_function(callee.function_id)
                if StatementKind.RETURN in callee_statement.statement_types
            ]
            if not return_statements:
                continue

            caller_node = self._ensure_node(nodes_by_id, statement, function, tracked_entities=defined_entities)
            for return_statement in return_statements:
                upstream_entities = set(return_statement.referenced_variables) or set(_tokens_from_text(return_statement.return_expression or ""))
                return_node = self._ensure_node(
                    nodes_by_id,
                    return_statement,
                    callee,
                    tracked_entities=upstream_entities,
                )
                self._add_edge(
                    edges_by_key,
                    source_node_id=return_node.node_id,
                    target_node_id=caller_node.node_id,
                    relation=DependencyRelation.RETURN_VALUE,
                    entity=call_name,
                    explanation="Return value from callee may define the caller-side state.",
                )
                if upstream_entities:
                    pending.append(
                        SliceSeed(
                            function_id=callee.function_id,
                            statement_id=return_statement.statement_id,
                            relevant_entities=upstream_entities,
                            hop_count=hop_count + 1,
                        )
                    )

    def _attach_global_updates(
        self,
        program_index: ProgramIndex,
        *,
        function: FunctionDefinition,
        consumer_map: DefaultDict[str, Set[str]],
        nodes_by_id: Dict[str, SliceNode],
        edges_by_key: Dict[Tuple[str, str, str, str], DependencyEdge],
        selected_statement_ids: Set[str],
    ) -> None:
        local_names = set(function.local_variables)
        local_names.update(parameter.name for parameter in function.parameters if parameter.name)
        global_candidates = [
            entity
            for entity in consumer_map.keys()
            if entity not in local_names
        ]
        if not global_candidates:
            return

        matches_added = 0
        for entity in global_candidates:
            consumer_statements = [
                program_index.get_statement(statement_id)
                for statement_id in consumer_map[entity]
            ]
            if not self._is_probable_shared_state_entity(entity, consumer_statements):
                continue
            for other_function in program_index.program.functions:
                for statement in program_index.statements_in_function(other_function.function_id):
                    if statement.statement_id in selected_statement_ids:
                        continue
                    if entity not in statement.defined_variables:
                        continue
                    global_node = self._ensure_node(
                        nodes_by_id,
                        statement,
                        other_function,
                        tracked_entities={entity},
                    )
                    for consumer_id in consumer_map[entity]:
                        self._add_edge(
                            edges_by_key,
                            source_node_id=global_node.node_id,
                            target_node_id=consumer_id,
                            relation=DependencyRelation.GLOBAL_STATE,
                            entity=entity,
                            explanation="Global or shared state may influence downstream behavior.",
                        )
                    matches_added += 1
                    if matches_added >= self.global_search_limit:
                        return

    def _enqueue_output_parameter_expansion(
        self,
        program_index: ProgramIndex,
        *,
        function: FunctionDefinition,
        statement: StatementInfo,
        relevant_entities: Set[str],
        hop_count: int,
        pending: deque[SliceSeed],
        nodes_by_id: Dict[str, SliceNode],
        edges_by_key: Dict[Tuple[str, str, str, str], DependencyEdge],
    ) -> None:
        if not statement.call_names or not relevant_entities:
            return

        caller_node = self._ensure_node(
            nodes_by_id,
            statement,
            function,
            tracked_entities=relevant_entities,
        )
        visible_entities = set(statement.referenced_variables).union(statement.defined_variables).union(relevant_entities)

        for call_name in statement.call_names:
            candidate_functions = program_index.find_functions(call_name.split("::")[-1])
            if len(candidate_functions) != 1:
                continue
            callee = candidate_functions[0]
            argument_texts = _extract_call_arguments(statement.location.snippet or statement.text, call_name.split("::")[-1])
            if not argument_texts:
                continue

            for parameter in callee.parameters:
                parameter_name = parameter.name
                if parameter_name is None or parameter.position >= len(argument_texts):
                    continue

                argument_text = argument_texts[parameter.position]
                argument_entities = set(_tokens_from_text(argument_text))
                if not argument_entities.intersection(visible_entities):
                    continue
                if not _parameter_may_be_output(parameter.raw_declaration, argument_text):
                    continue

                target_statements = [
                    callee_statement
                    for callee_statement in program_index.statements_in_function(callee.function_id)
                    if parameter_name in callee_statement.defined_variables
                ]
                if not target_statements:
                    target_statements = [
                        callee_statement
                        for callee_statement in program_index.statements_in_function(callee.function_id)
                        if parameter_name in self._extract_upstream_entities(callee_statement)
                    ]
                if not target_statements:
                    continue

                edge_entity = _preferred_argument_entity(argument_text, fallback=parameter_name)
                for callee_statement in target_statements:
                    upstream_entities = self._extract_upstream_entities(callee_statement) or {parameter_name}
                    callee_node = self._ensure_node(
                        nodes_by_id,
                        callee_statement,
                        callee,
                        tracked_entities=upstream_entities.union({parameter_name}),
                    )
                    self._add_edge(
                        edges_by_key,
                        source_node_id=callee_node.node_id,
                        target_node_id=caller_node.node_id,
                        relation=DependencyRelation.CALL_ARGUMENT,
                        entity=edge_entity,
                        explanation="Callee may update caller-visible state through an output argument.",
                    )
                    pending.append(
                        SliceSeed(
                            function_id=callee.function_id,
                            statement_id=callee_statement.statement_id,
                            relevant_entities=upstream_entities,
                            hop_count=hop_count + 1,
                        )
                    )

    def _memory_relations(self, statement: StatementInfo, relevant_entities: Iterable[str]) -> Dict[str, DependencyRelation]:
        matches: Dict[str, DependencyRelation] = {}
        relevant_set = set(relevant_entities)
        for operation in statement.memory_operations:
            target = operation.target
            if target is None or target not in relevant_set:
                continue
            if operation.kind in (MemoryOperationKind.ALLOCATION, MemoryOperationKind.REALLOCATION):
                matches[target] = DependencyRelation.ALLOCATION_SITE
            elif operation.kind == MemoryOperationKind.DEALLOCATION:
                matches[target] = DependencyRelation.DEALLOCATION_SITE
            elif operation.kind in (MemoryOperationKind.SET, MemoryOperationKind.COPY):
                matches[target] = DependencyRelation.INITIALIZATION_SITE
            else:
                matches[target] = DependencyRelation.HEAP_OBJECT
        return matches

    def _semantic_relations(self, statement: StatementInfo, relevant_entities: Iterable[str]) -> Dict[str, DependencyRelation]:
        """Recover lightweight alias, field, and index dependencies."""

        relevant_set = set(relevant_entities)
        metadata = statement.metadata
        matches: Dict[str, DependencyRelation] = {}

        index_variables = set(metadata.get("index_variables") or [])
        index_bases = set(metadata.get("index_bases") or [])
        for entity in relevant_set.intersection(index_variables):
            matches[entity] = DependencyRelation.INTEGER_INFLUENCE
        for entity in relevant_set.intersection(index_bases):
            matches[entity] = DependencyRelation.INTEGER_INFLUENCE if index_variables else DependencyRelation.HEAP_OBJECT

        structural_entities = set(metadata.get("field_bases") or [])
        structural_entities.update(index_bases)
        structural_entities.update(metadata.get("pointer_dereferences") or [])
        for entity in relevant_set.intersection(structural_entities):
            matches.setdefault(entity, DependencyRelation.HEAP_OBJECT)

        field_names = {
            access.replace("->", ".").split(".")[-1]
            for access in metadata.get("field_accesses") or []
            if "->" in access or "." in access
        }
        for entity in relevant_set.intersection(field_names):
            matches[entity] = DependencyRelation.STATE_UPDATE if _looks_like_mutating_assignment(statement.text) else DependencyRelation.HEAP_OBJECT

        alias_sources = set(metadata.get("alias_sources") or [])
        if relevant_set.intersection(statement.defined_variables) and alias_sources:
            for entity in relevant_set.intersection(statement.defined_variables):
                matches[entity] = DependencyRelation.HEAP_OBJECT

        return matches

    def _extract_seed_entities(self, statement: StatementInfo) -> List[str]:
        entities = set(statement.referenced_variables)
        entities.update(_tokens_from_text(statement.condition_expression or ""))
        entities.update(_tokens_from_text(statement.return_expression or ""))
        for operation in statement.memory_operations:
            if operation.target:
                entities.add(operation.target)
            entities.update(_tokens_from_text(operation.size_expression or ""))
        metadata = statement.metadata
        for key in ("index_variables", "call_argument_variables", "macro_references"):
            entities.update(str(item) for item in metadata.get(key, []) if item)
        return sorted(entities)

    def _extract_upstream_entities(self, statement: StatementInfo) -> Set[str]:
        entities = set(statement.referenced_variables)
        entities.update(_tokens_from_text(statement.condition_expression or ""))
        entities.update(_tokens_from_text(statement.return_expression or ""))
        for operation in statement.memory_operations:
            entities.update(_tokens_from_text(operation.size_expression or ""))
            if operation.target and operation.kind in (MemoryOperationKind.ALLOCATION, MemoryOperationKind.REALLOCATION):
                entities.add(operation.target)
        metadata = statement.metadata
        for key in (
            "field_bases",
            "index_bases",
            "index_variables",
            "alias_sources",
            "pointer_dereferences",
            "call_argument_variables",
            "macro_references",
        ):
            entities.update(str(item) for item in metadata.get(key, []) if item)
        return entities

    def _relation_for_statement(self, statement: StatementInfo, entity: str) -> DependencyRelation:
        if StatementKind.RETURN in statement.statement_types:
            return DependencyRelation.RETURN_VALUE
        if _looks_like_integer_computation(statement.text) and entity in statement.defined_variables:
            return DependencyRelation.INTEGER_INFLUENCE
        if StatementKind.ASSIGNMENT in statement.statement_types and _looks_like_mutating_assignment(statement.text):
            return DependencyRelation.STATE_UPDATE
        return DependencyRelation.DATA_DEPENDENCE

    def _explain_data_edge(self, statement: StatementInfo, entity: str, relation: DependencyRelation) -> str:
        if relation == DependencyRelation.INTEGER_INFLUENCE:
            return f"Integer computation for {entity} may influence a later size, index, or bound."
        if relation == DependencyRelation.STATE_UPDATE:
            return f"Statement updates {entity}, which is used downstream."
        if relation == DependencyRelation.RETURN_VALUE:
            return f"Return statement contributes to the value of {entity}."
        return f"Definition or use of {entity} may flow into a later statement."

    def _explain_memory_edge(self, statement: StatementInfo, entity: str, relation: DependencyRelation) -> str:
        if relation == DependencyRelation.ALLOCATION_SITE:
            return f"Allocation site for {entity} may determine the object's later validity or bounds."
        if relation == DependencyRelation.DEALLOCATION_SITE:
            return f"Deallocation of {entity} may invalidate later accesses."
        if relation == DependencyRelation.INITIALIZATION_SITE:
            return f"Initialization or copy into {entity} may affect later behavior."
        return f"Memory-related operation on {entity} may influence later behavior."

    def _explain_semantic_edge(self, statement: StatementInfo, entity: str, relation: DependencyRelation) -> str:
        if relation == DependencyRelation.INTEGER_INFLUENCE:
            return f"Index or size expression involving {entity} may influence a later memory access."
        if relation == DependencyRelation.STATE_UPDATE:
            return f"Field or object-state update involving {entity} may affect later behavior."
        return f"Pointer, field, index, or alias use of {entity} may connect this statement to downstream state."

    def _ensure_node(
        self,
        nodes_by_id: Dict[str, SliceNode],
        statement: StatementInfo,
        function: FunctionDefinition,
        *,
        tracked_entities: Iterable[str],
        is_trigger: bool = False,
    ) -> SliceNode:
        node = nodes_by_id.get(statement.statement_id)
        if node is None:
            node = SliceNode(
                node_id=statement.statement_id,
                statement_id=statement.statement_id,
                function_id=function.function_id,
                function_name=function.name,
                location=statement.location,
                text=statement.text,
                statement_types=statement.statement_types,
                tracked_entities=sorted(set(tracked_entities)),
                is_trigger=is_trigger,
                metadata={
                    "block_depth": statement.metadata.get("block_depth"),
                    "call_names": list(statement.call_names),
                    "condition_expression": statement.condition_expression,
                    "return_expression": statement.return_expression,
                    "defined_variables": list(statement.defined_variables),
                    "referenced_variables": list(statement.referenced_variables),
                    "memory_operation_kinds": [operation.kind.value for operation in statement.memory_operations],
                    "field_accesses": list(statement.metadata.get("field_accesses") or []),
                    "field_bases": list(statement.metadata.get("field_bases") or []),
                    "index_accesses": list(statement.metadata.get("index_accesses") or []),
                    "index_variables": list(statement.metadata.get("index_variables") or []),
                    "alias_sources": list(statement.metadata.get("alias_sources") or []),
                    "pointer_dereferences": list(statement.metadata.get("pointer_dereferences") or []),
                    "call_arguments": dict(statement.metadata.get("call_arguments") or {}),
                    "call_argument_variables": list(statement.metadata.get("call_argument_variables") or []),
                    "macro_references": list(statement.metadata.get("macro_references") or []),
                },
            )
            nodes_by_id[statement.statement_id] = node
            return node

        merged_entities = set(node.tracked_entities).union(tracked_entities)
        if merged_entities != set(node.tracked_entities) or (is_trigger and not node.is_trigger):
            node = node.model_copy(update={"tracked_entities": sorted(merged_entities), "is_trigger": node.is_trigger or is_trigger})
            nodes_by_id[statement.statement_id] = node
        return node

    def _add_edge(
        self,
        edges_by_key: Dict[Tuple[str, str, str, str], DependencyEdge],
        *,
        source_node_id: str,
        target_node_id: str,
        relation: DependencyRelation,
        entity: Optional[str],
        explanation: str,
    ) -> None:
        entity_key = entity or ""
        key = (source_node_id, target_node_id, relation.value, entity_key)
        if key in edges_by_key:
            return
        edges_by_key[key] = DependencyEdge(
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            relation=relation,
            entity=entity,
            explanation=explanation,
            approximated=True,
        )

    @staticmethod
    def _is_probable_shared_state_entity(
        entity: str,
        consumer_statements: Iterable[Optional[StatementInfo]],
    ) -> bool:
        if not entity or len(entity) < 2:
            return False
        if _looks_like_type_identifier(entity):
            return False

        bare_pattern = re.compile(rf"\b{re.escape(entity)}\b")
        bare_uses = 0
        member_only_uses = 0
        for statement in consumer_statements:
            if statement is None:
                continue
            text = statement.text
            normalized = text.replace(f"->{entity}", " ").replace(f".{entity}", " ")
            if bare_pattern.search(normalized):
                bare_uses += 1
            elif f"->{entity}" in text or f".{entity}" in text:
                member_only_uses += 1

        if bare_uses > 0:
            return True
        if member_only_uses > 0:
            return False
        return True

    def _select_caller_relationships(
        self,
        *,
        function: FunctionDefinition,
        relationships: List,
    ) -> List:
        if not relationships:
            return []
        if len(relationships) == 1:
            return relationships

        non_auxiliary = [
            relationship
            for relationship in relationships
            if not relationship.location.file.startswith(NON_PRODUCTION_PATH_PREFIXES)
        ]
        if non_auxiliary:
            relationships = non_auxiliary

        scored = sorted(
            relationships,
            key=lambda relationship: (
                -_path_similarity(function.location.file, relationship.location.file),
                relationship.location.file,
                relationship.location.line,
            ),
        )
        return scored[: min(3, self.global_search_limit)]


def _tokens_from_text(text: str) -> List[str]:
    if not text:
        return []
    return [
        token
        for token in IDENTIFIER_RE.findall(text)
        if token not in {"if", "for", "while", "switch", "return", "NULL", "nullptr", "sizeof"}
        and not _looks_like_type_identifier(token)
    ]


def _looks_like_integer_computation(text: str) -> bool:
    if not text:
        return False

    expression = text
    if "=" in text:
        expression = text.split("=", 1)[1]
    elif text.strip().startswith("return "):
        expression = text.strip()[len("return ") :]

    expression = _normalize_numeric_expression(expression)
    return bool(INTEGER_BINARY_OP_RE.search(expression))


def _normalize_numeric_expression(expression: str) -> str:
    normalized = C_STYLE_CAST_RE.sub("", expression)
    normalized = normalized.replace("->", ".")
    normalized = re.sub(r"(<=|>=|==|!=|&&|\|\|)", " ", normalized)
    return normalized


def _looks_like_type_identifier(token: str) -> bool:
    if token in PRIMITIVE_TYPE_TOKENS:
        return True
    if re.fullmatch(r"[iu]?int\d+_t", token):
        return True
    if token.endswith("_t"):
        return True
    return False


def _parameter_may_be_output(raw_declaration: str, argument_text: str) -> bool:
    declaration = raw_declaration.strip()
    if "*" in declaration or "[" in declaration:
        return True
    return argument_text.strip().endswith("len") or argument_text.strip().endswith("size")


def _looks_like_mutating_assignment(text: str) -> bool:
    stripped = text.strip()
    if "=" not in stripped or stripped.startswith("return "):
        return False
    lhs = stripped.split("=", 1)[0].strip()
    return "->" in lhs or "." in lhs or "[" in lhs or lhs.startswith("*")


def _extract_call_arguments(statement_text: str, callee_name: str) -> List[str]:
    if not statement_text:
        return []
    pattern = re.compile(re.escape(callee_name) + r"\s*\((?P<args>.*?)\)")
    match = pattern.search(statement_text)
    if match is None:
        return []

    arguments_text = match.group("args")
    return _split_top_level(arguments_text)


def _preferred_argument_entity(argument_text: str, *, fallback: str) -> str:
    tokens = _tokens_from_text(argument_text)
    if len(tokens) == 1:
        return tokens[0]
    return fallback


def _path_similarity(left: str, right: str) -> int:
    left_parts = left.split("/")
    right_parts = right.split("/")
    shared = 0
    for left_part, right_part in zip(left_parts, right_parts):
        if left_part != right_part:
            break
        shared += 1
    return shared


def _split_top_level(text: str) -> List[str]:
    parts: List[str] = []
    current: List[str] = []
    depth_paren = 0
    depth_bracket = 0
    depth_angle = 0
    for character in text:
        if character == "(":
            depth_paren += 1
        elif character == ")":
            depth_paren = max(depth_paren - 1, 0)
        elif character == "[":
            depth_bracket += 1
        elif character == "]":
            depth_bracket = max(depth_bracket - 1, 0)
        elif character == "<":
            depth_angle += 1
        elif character == ">":
            depth_angle = max(depth_angle - 1, 0)

        if character == "," and depth_paren == 0 and depth_bracket == 0 and depth_angle == 0:
            part = "".join(current).strip()
            if part:
                parts.append(part)
            current = []
            continue
        current.append(character)

    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts
