from __future__ import annotations

from collections import deque
from typing import Iterable

from ..models import AnalysisBundle, FunctionMetadata


class GraphStore:
    """Read-only call graph with budgeted caller/callee context expansion."""

    def __init__(self, bundle: AnalysisBundle):
        self.bundle = bundle
        self._callers: dict[str, set[str]] = {key: set() for key in bundle.functions}
        self._callees: dict[str, set[str]] = {key: set() for key in bundle.functions}
        for edge in bundle.edges:
            if edge.caller_id in self._callees and edge.callee_id in self._callers:
                self._callees[edge.caller_id].add(edge.callee_id)
                self._callers[edge.callee_id].add(edge.caller_id)

    def get(self, function_id: str) -> FunctionMetadata:
        return self.bundle.functions[function_id]

    def callers(self, function_id: str) -> list[FunctionMetadata]:
        return self._resolve(self._callers.get(function_id, set()))

    def callees(self, function_id: str) -> list[FunctionMetadata]:
        return self._resolve(self._callees.get(function_id, set()))

    def frontier(self, function_ids: Iterable[str]) -> list[dict[str, object]]:
        """Return source-free caller/callee choices around an explicit context.

        This is deliberately different from :meth:`context_with_trace`.  It
        exposes only enough metadata for an agent to choose its next function;
        it never adds that function's source to the prompt automatically.
        Multiple edges to the same frontier function are retained as compact
        connection records so the model can make a targeted choice without a
        breadth-first source expansion.
        """

        selected = [
            function_id for function_id in function_ids
            if function_id in self.bundle.functions
        ]
        selected_set = set(selected)
        choices: dict[str, dict[str, object]] = {}
        for current in selected:
            current_function = self.get(current)
            neighbours = [
                *(
                    (neighbour, "caller_of")
                    for neighbour in sorted(self._callers.get(current, set()))
                ),
                *(
                    (neighbour, "callee_of")
                    for neighbour in sorted(self._callees.get(current, set()))
                ),
            ]
            for neighbour, relation in neighbours:
                if neighbour in selected_set:
                    continue
                function = self.get(neighbour)
                choice = choices.setdefault(
                    neighbour,
                    {
                        "function_id": neighbour,
                        "name": function.name,
                        "qualified_name": function.qualified_name,
                        "file": function.file,
                        "start_line": function.start_line,
                        "connections": [],
                    },
                )
                connections = choice["connections"]
                assert isinstance(connections, list)
                connections.append(
                    {
                        "relation": relation,
                        "connected_function_id": current,
                        "connected_function_name": current_function.name,
                    }
                )
        return list(choices.values())

    def context(
        self,
        roots: Iterable[str],
        *,
        max_depth: int = 3,
        max_functions: int = 16,
    ) -> list[FunctionMetadata]:
        context, _ = self.context_with_trace(
            roots, max_depth=max_depth, max_functions=max_functions
        )
        return context

    def context_with_trace(
        self,
        roots: Iterable[str],
        *,
        max_depth: int = 3,
        max_functions: int = 16,
    ) -> tuple[list[FunctionMetadata], list[dict[str, object]]]:
        queue: deque[tuple[str, int, str | None, str]] = deque(
            (root, 0, None, "root")
            for root in roots
            if root in self.bundle.functions
        )
        seen: set[str] = set()
        result: list[FunctionMetadata] = []
        walk: list[dict[str, object]] = []
        while queue and len(result) < max_functions:
            current, depth, discovered_from, relation = queue.popleft()
            if current in seen:
                continue
            seen.add(current)
            function = self.get(current)
            result.append(function)
            walk.append(
                {
                    "function_id": current,
                    "name": function.name,
                    "file": function.file,
                    "start_line": function.start_line,
                    "depth": depth,
                    "discovered_from": discovered_from,
                    "relation": relation,
                }
            )
            if depth >= max_depth:
                continue
            # Callers first: provenance and prerequisite state generally live upward.
            queue.extend(
                (neighbour, depth + 1, current, "caller_of")
                for neighbour in sorted(self._callers[current])
                if neighbour not in seen
            )
            queue.extend(
                (neighbour, depth + 1, current, "callee_of")
                for neighbour in sorted(self._callees[current])
                if neighbour not in seen
            )
        return result, walk

    def induced_edges(self, function_ids: Iterable[str]) -> list[dict[str, object]]:
        allowed = set(function_ids)
        return [
            {
                "caller_id": edge.caller_id,
                "caller_name": self.bundle.functions[edge.caller_id].name,
                "callee_id": edge.callee_id,
                "callee_name": self.bundle.functions[edge.callee_id].name,
                "line": edge.line,
                "kind": edge.kind,
                "confidence": edge.confidence,
            }
            for edge in self.bundle.edges
            if edge.caller_id in allowed and edge.callee_id in allowed
        ]

    def shortest_path(self, source: str, target: str, max_depth: int = 8) -> list[str]:
        if source == target:
            return [source]
        queue = deque([(source, [source])])
        seen = {source}
        while queue:
            current, path = queue.popleft()
            if len(path) > max_depth:
                continue
            for next_id in self._callees.get(current, set()):
                if next_id == target:
                    return [*path, next_id]
                if next_id not in seen:
                    seen.add(next_id)
                    queue.append((next_id, [*path, next_id]))
        return []

    def _resolve(self, ids: Iterable[str]) -> list[FunctionMetadata]:
        return sorted(
            (self.bundle.functions[item] for item in ids if item in self.bundle.functions),
            key=lambda function: (function.file, function.start_line, function.name),
        )
