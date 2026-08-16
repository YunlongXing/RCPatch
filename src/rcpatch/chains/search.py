"""Dependency-graph path search for causality-chain construction."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import DefaultDict, Iterable

from rcpatch.logging_utils import get_logger
from rcpatch.models import BackwardSlice, DependencyEdge, DependencyRelation


RELATION_PRIORITY = {
    DependencyRelation.RETURN_VALUE: 0,
    DependencyRelation.CALL_ARGUMENT: 0,
    DependencyRelation.INTEGER_INFLUENCE: 1,
    DependencyRelation.STATE_UPDATE: 1,
    DependencyRelation.DATA_DEPENDENCE: 2,
    DependencyRelation.ALLOCATION_SITE: 2,
    DependencyRelation.INITIALIZATION_SITE: 2,
    DependencyRelation.HEAP_OBJECT: 3,
    DependencyRelation.GLOBAL_STATE: 3,
    DependencyRelation.CONTROL_DEPENDENCE: 4,
    DependencyRelation.CALLER_CONTEXT: 4,
    DependencyRelation.DEALLOCATION_SITE: 4,
    DependencyRelation.TRIGGER: 5,
}


@dataclass(frozen=True)
class DependencyPath:
    """A simple dependency path from a candidate node to the trigger."""

    node_ids: tuple[str, ...]
    edges: tuple[DependencyEdge, ...]


class DependencyPathSearcher:
    """Enumerate concise dependency paths through a backward slice."""

    def __init__(self) -> None:
        self.logger = get_logger(__name__)

    def search_paths(
        self,
        backward_slice: BackwardSlice,
        *,
        start_node_id: str,
        trigger_node_id: str,
        max_paths: int = 3,
        max_depth: int = 10,
    ) -> list[DependencyPath]:
        """Enumerate simple, pruned paths from a candidate node to the trigger."""
        if start_node_id == trigger_node_id:
            return []

        outgoing_edges = self._outgoing_edges(backward_slice.edges)
        distances = self._distance_to_trigger(backward_slice.edges, trigger_node_id)
        if start_node_id not in distances:
            return []

        paths: list[DependencyPath] = []
        seen_signatures: set[tuple[str, ...]] = set()

        def dfs(current_node_id: str, path_edges: list[DependencyEdge], visited: set[str]) -> None:
            if len(paths) >= max_paths:
                return
            if len(path_edges) > max_depth:
                return
            if current_node_id == trigger_node_id:
                node_ids = self._node_sequence(start_node_id=start_node_id, edges=path_edges)
                if node_ids not in seen_signatures:
                    seen_signatures.add(node_ids)
                    paths.append(DependencyPath(node_ids=node_ids, edges=tuple(path_edges)))
                return

            candidate_edges = sorted(
                outgoing_edges.get(current_node_id, []),
                key=lambda edge: (
                    distances.get(edge.target_node_id, max_depth + 1),
                    RELATION_PRIORITY.get(edge.relation, 99),
                    edge.target_node_id,
                ),
            )
            for edge in candidate_edges:
                if edge.target_node_id in visited:
                    continue
                remaining_distance = distances.get(edge.target_node_id)
                if remaining_distance is None:
                    continue
                if len(path_edges) + 1 + remaining_distance > max_depth:
                    continue
                visited.add(edge.target_node_id)
                path_edges.append(edge)
                dfs(edge.target_node_id, path_edges, visited)
                path_edges.pop()
                visited.remove(edge.target_node_id)

        dfs(start_node_id, [], {start_node_id})
        return paths

    @staticmethod
    def _outgoing_edges(edges: Iterable[DependencyEdge]) -> dict[str, list[DependencyEdge]]:
        adjacency: DefaultDict[str, list[DependencyEdge]] = defaultdict(list)
        for edge in edges:
            adjacency[edge.source_node_id].append(edge)
        return dict(adjacency)

    @staticmethod
    def _distance_to_trigger(edges: Iterable[DependencyEdge], trigger_node_id: str) -> dict[str, int]:
        incoming: DefaultDict[str, list[str]] = defaultdict(list)
        for edge in edges:
            incoming[edge.target_node_id].append(edge.source_node_id)

        distances = {trigger_node_id: 0}
        queue = deque([trigger_node_id])
        while queue:
            current = queue.popleft()
            current_distance = distances[current]
            for predecessor in incoming.get(current, []):
                if predecessor in distances:
                    continue
                distances[predecessor] = current_distance + 1
                queue.append(predecessor)
        return distances

    @staticmethod
    def _node_sequence(*, start_node_id: str, edges: list[DependencyEdge]) -> tuple[str, ...]:
        if not edges:
            return (start_node_id,)
        node_ids = [start_node_id]
        node_ids.extend(edge.target_node_id for edge in edges)
        return tuple(node_ids)
