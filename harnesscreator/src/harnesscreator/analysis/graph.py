from __future__ import annotations

import re
from collections import deque
from typing import Iterable

from ..models import AnalysisBundle, CallEdge, FunctionMetadata


def _code_only(source: str) -> str:
    """Mask C/C++ comments and literals without changing line offsets.

    Callback registration is source navigation. A spelling inside a comment
    or example string must not create even a navigational callback edge.
    """
    result = list(source)
    position = 0
    while position < len(source):
        if source.startswith("//", position):
            end = source.find("\n", position)
            end = len(source) if end < 0 else end
        elif source.startswith("/*", position):
            closing = source.find("*/", position + 2)
            end = len(source) if closing < 0 else closing + 2
        elif (source.startswith('R"', position)
              and (raw := re.match(r'R"([^\s()\\]{0,16})\(', source[position:]))):
            delimiter = raw.group(1)
            closing = source.find(')' + delimiter + '"', position + raw.end())
            end = len(source) if closing < 0 else closing + len(delimiter) + 2
        elif source[position] in {'"', "'"}:
            quote = source[position]
            end = position + 1
            while end < len(source):
                if source[end] == "\\":
                    end += 2
                elif source[end] == quote:
                    end += 1
                    break
                else:
                    end += 1
        else:
            position += 1
            continue
        for index in range(position, min(end, len(source))):
            if result[index] != "\n":
                result[index] = " "
        position = end
    return "".join(result)


class GraphStore:
    """Read-only call graph with budgeted caller/callee context expansion."""

    def __init__(self, bundle: AnalysisBundle):
        self.bundle = bundle
        self._callers: dict[str, set[str]] = {key: set() for key in bundle.functions}
        self._callees: dict[str, set[str]] = {key: set() for key in bundle.functions}
        self._edges_by_pair: dict[tuple[str, str], list[CallEdge]] = {}
        for edge in bundle.edges:
            if edge.caller_id in self._callees and edge.callee_id in self._callers:
                self._callees[edge.caller_id].add(edge.callee_id)
                self._callers[edge.callee_id].add(edge.caller_id)
                self._edges_by_pair.setdefault(
                    (edge.caller_id, edge.callee_id), []
                ).append(edge)
        # Lexically reconstructed callback edges are NAVIGATION CANDIDATES,
        # never executable CallEdges or static provenance proof.  Keep them
        # separate so a field-name collision cannot silently prove an Entry.
        self._callback_hints: dict[tuple[str, str], list[dict[str, object]]] | None = None
        self._typed_field_writers: dict[tuple[str, str], list[str]] | None = None

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
                        **self._connection_evidence(
                            neighbour if relation == "caller_of" else current,
                            current if relation == "caller_of" else neighbour,
                        ),
                    }
                )
        for handoff in [
            *self.queue_handoff_candidates(selected),
            *self.callback_slot_candidates(selected),
        ]:
            identifier = str(handoff['function_id'])
            existing = choices.get(identifier)
            if existing is None:
                choices[identifier] = handoff
            else:
                existing_connections = existing['connections']
                assert isinstance(existing_connections, list)
                existing_connections.extend(handoff['connections'])
        return list(choices.values())

    @staticmethod
    def _pointer_object_type(source: str, receiver: str) -> str:
        """Conservative pointer type of a receiver in a C function body.

        This is NOT a whole-program points-to proof.  It only stops callback
        navigation from connecting obviously different struct types that use
        the same member name.
        """
        receiver = re.escape(receiver)
        match = re.search(
            rf"\b(?:(?:const|volatile)\s+)*(?:struct\s+)?"
            rf"(?P<type>[A-Za-z_]\w*)\s*\*\s*"
            rf"(?:(?:const|volatile)\s+)*{receiver}\b",
            source,
        )
        return match.group("type") if match else ""

    def _callback_slot_hints(self) -> dict[tuple[str, str], list[dict[str, object]]]:
        """Link source-located member callback assignments to invocations.

        `c->reader = tcp_read` and `c->reader(c, ...)` supply a useful
        *hypothesis* even without SVF. Neither assignment nor matching types
        establishes that both `c` values refer to the same object or that
        the relevant registration path executes. Do not add these pairs to
        `AnalysisBundle.edges` or any proof-bearing adjacency.
        """
        if self._callback_hints is not None:
            return self._callback_hints
        assignment = re.compile(
            r"\b(?P<object>[A-Za-z_]\w*)\s*(?:->|\.)\s*"
            r"(?P<slot>[A-Za-z_]\w*)\s*=\s*"
            r"(?:\([^;=]*\)\s*)?&?\s*(?P<target>[A-Za-z_]\w*)\s*;"
        )
        invocation = re.compile(
            r"\b(?P<object>[A-Za-z_]\w*)\s*(?:->|\.)\s*"
            r"(?P<slot>[A-Za-z_]\w*)\s*\("
        )
        functions_by_name: dict[str, list[str]] = {}
        for identifier, function in self.bundle.functions.items():
            functions_by_name.setdefault(function.name, []).append(identifier)
        registrations: dict[str, list[dict[str, object]]] = {}
        for function in self.bundle.functions.values():
            code = _code_only(function.source)
            for match in assignment.finditer(code):
                targets = functions_by_name.get(match.group("target"), [])
                # A source index may include several independent C build
                # targets (for example a server and its test executable).
                # A reference in one translation unit resolves to the
                # definition in that unit when it is unique there.  Do not
                # discard the callback merely because another file defines
                # an identically named function for a different target.
                same_file = [
                    identifier for identifier in targets
                    if self.get(identifier).file == function.file
                ]
                resolved = same_file if same_file else targets
                if len(resolved) != 1:
                    continue
                registrations.setdefault(match.group("slot"), []).append({
                    "target_id": resolved[0],
                    "registration_id": function.function_id,
                    "registration_line": function.start_line + function.source.count("\n", 0, match.start()),
                    "receiver_type": self._pointer_object_type(code, match.group("object")),
                })
        result: dict[tuple[str, str], list[dict[str, object]]] = {}
        for function in self.bundle.functions.values():
            code = _code_only(function.source)
            for match in invocation.finditer(code):
                receiver_type = self._pointer_object_type(code, match.group("object"))
                compatible = [
                    record for record in registrations.get(match.group("slot"), [])
                    if not (receiver_type and record["receiver_type"]
                            and receiver_type != record["receiver_type"])
                ]
                for record in compatible:
                    callee_id = str(record["target_id"])
                    if callee_id == function.function_id:
                        continue
                    target_builds = set(self.get(callee_id).build_targets)
                    invoker_builds = set(function.build_targets)
                    item = {
                        **record,
                        "invoker_id": function.function_id,
                        "invocation_line": function.start_line + function.source.count("\n", 0, match.start()),
                        "slot": match.group("slot"),
                        "invoker_type": receiver_type,
                        "build_target_relation": (
                            "overlap" if target_builds & invoker_builds
                            else "disjoint_unresolved" if target_builds and invoker_builds
                            else "unknown"
                        ),
                        "evidence_kind": "lexical_callback_navigation_only",
                    }
                    key = (function.function_id, callee_id)
                    if item not in result.setdefault(key, []):
                        result[key].append(item)
        self._callback_hints = result
        return result

    def callback_slot_candidates(
        self, function_ids: Iterable[str], *, limit: int | None = None
    ) -> list[dict[str, object]]:
        """Return only navigational neighbours of the selected functions."""
        selected = set(function_ids) & self.bundle.functions.keys()
        choices: dict[str, dict[str, object]] = {}
        for (caller_id, callee_id), records in self._callback_slot_hints().items():
            if caller_id in selected and callee_id not in selected:
                neighbour, current, relation = callee_id, caller_id, "callback_candidate_callee"
            elif callee_id in selected and caller_id not in selected:
                neighbour, current, relation = caller_id, callee_id, "callback_candidate_caller"
            else:
                continue
            target = self.get(neighbour)
            candidate = choices.setdefault(neighbour, {
                "function_id": neighbour,
                "name": target.name,
                "qualified_name": target.qualified_name,
                "file": target.file,
                "start_line": target.start_line,
                "connections": [],
            })
            for item in records:
                candidate["connections"].append({
                    "relation": relation,
                    "connected_function_id": current,
                    "slot": item["slot"],
                    "registration_function_id": item["registration_id"],
                    "registration_line": item["registration_line"],
                    "invocation_line": item["invocation_line"],
                    "build_target_relation": item["build_target_relation"],
                    "evidence_kind": "lexical_callback_navigation_only",
                    "proof_policy": "OPEN SOURCE AND VERIFY OBJECT IDENTITY; NOT STATIC PROOF",
                })
        ordered = sorted(
            choices.values(),
            key=lambda choice: (
                min(
                    {
                        "overlap": 0, "unknown": 1,
                        "disjoint_unresolved": 2,
                    }.get(str(item.get("build_target_relation", "")), 1)
                    for item in choice["connections"]
                ),
                str(choice["file"]),
                int(choice["start_line"]),
            ),
        )
        return ordered if limit is None else ordered[:max(0, limit)]

    def callback_registration_candidates(
        self, function_ids: Iterable[str]
    ) -> list[dict[str, object]]:
        """Expose source-located callback assignments as navigation questions.

        Assignment plus a matching invocation does not establish object
        identity, branch feasibility, or execution for a particular request.
        """
        selected = set(function_ids) & self.bundle.functions.keys()
        choices: dict[str, dict[str, object]] = {}
        for (invoker_id, target_id), records in self._callback_slot_hints().items():
            if not ({invoker_id, target_id} & selected):
                continue
            for record in records:
                registration_id = str(record["registration_id"])
                if (registration_id in selected
                    or registration_id not in self.bundle.functions):
                    continue
                registration = self.get(registration_id)
                choice = choices.setdefault(registration_id, {
                    "function_id": registration_id,
                    "name": registration.name,
                    "qualified_name": registration.qualified_name,
                    "file": registration.file,
                    "start_line": registration.start_line,
                    "connections": [],
                })
                connection = {
                    "relation": "callback_registration_candidate",
                    "connected_function_id": (
                        target_id if target_id in selected else invoker_id
                    ),
                    "callback_target_function_id": target_id,
                    "callback_invoker_function_id": invoker_id,
                    "slot": record["slot"],
                    "registration_line": record["registration_line"],
                    "invocation_line": record["invocation_line"],
                    "build_target_relation": record["build_target_relation"],
                    "proof_policy": (
                        "navigation only; inspect the assignment guard and "
                        "object lifecycle before attributing a callback"
                    ),
                }
                if connection not in choice["connections"]:
                    choice["connections"].append(connection)
        return sorted(choices.values(), key=lambda item: (
            str(item["file"]), int(item["start_line"]), str(item["function_id"]),
        ))

    def callback_navigation_path(
        self,
        source: str,
        target: str,
        *,
        max_return_depth: int | None = None,
        max_forward_depth: int | None = None,
        max_visited: int | None = None,
    ) -> list[str]:
        """Propose a return-then-forward path across callback candidates.

        Unlike `causal_path_from_entry`, this path is only for opening source.
        A successful return MUST NOT be used to promote `PROVEN_STATIC`.
        """
        if source not in self.bundle.functions or target not in self.bundle.functions:
            return []
        if source == target:
            return [source]
        # Function references (taking `&callback`) are not execution edges.
        # They must not shortcut the runtime path through the registration
        # function. Include only located executable calls and slot candidates.
        callers: dict[str, set[str]] = {}
        callees: dict[str, set[str]] = {}
        for (caller, callee), edges in self._edges_by_pair.items():
            if any(
                edge.kind in {"direct", "reported"}
                or (edge.kind == "indirect_possible" and edge.line is not None)
                or (edge.kind == "source_candidate" and edge.line is not None
                    and "clang-ast-cpp" in edge.providers
                    and any(label in edge.providers for label in (
                        "linkage-symbol-match", "virtual-override-candidate",
                    )))
                for edge in edges
            ):
                callers.setdefault(callee, set()).add(caller)
                callees.setdefault(caller, set()).add(callee)
        for (caller, callee), _records in self._callback_slot_hints().items():
            callers.setdefault(callee, set()).add(caller)
            callees.setdefault(caller, set()).add(callee)

        source_builds = set(self.get(source).build_targets)

        def navigation_rank(identifier: str) -> tuple[int, str, int, str]:
            function = self.get(identifier)
            candidate_builds = set(function.build_targets)
            # Build-target overlap is an ordering hint only. A callback in a
            # linked library may legitimately have a different target name.
            relation = (
                0 if source_builds & candidate_builds
                else 1 if not source_builds or not candidate_builds
                else 2
            )
            return relation, function.file, function.start_line, identifier

        graph_size = len(self.bundle.functions)
        return_limit = graph_size if max_return_depth is None else max(0, max_return_depth)
        forward_limit = graph_size if max_forward_depth is None else max(0, max_forward_depth)

        def descend(starts: list[tuple[str, list[str]]]) -> list[str]:
            queue = deque((node, path, 0) for node, path in starts)
            seen = {node for node, _path in starts}
            while queue:
                current, path, depth = queue.popleft()
                if current == target:
                    return path
                if depth >= forward_limit:
                    continue
                for nxt in sorted(callees.get(current, ()), key=navigation_rank):
                    if nxt in seen:
                        continue
                    seen.add(nxt)
                    if max_visited is not None and len(seen) > max_visited:
                        return []
                    queue.append((nxt, [*path, nxt], depth + 1))
            return []

        direct = descend([(source, [source])])
        if direct:
            return direct

        # Enumerate each possible return caller once, then run one combined
        # forward search from those callers. This avoids repeating a full
        # descendant search for every ascent node in a large daemon.
        ascent_queue = deque([(source, [source], 0)])
        ascent_seen = {source}
        ancestors: list[tuple[str, list[str]]] = []
        while ascent_queue:
            current, path, depth = ascent_queue.popleft()
            if depth >= return_limit:
                continue
            for caller in sorted(callers.get(current, ()), key=navigation_rank):
                if caller in ascent_seen:
                    continue
                ascent_seen.add(caller)
                if max_visited is not None and len(ascent_seen) > max_visited:
                    return []
                raised = [*path, caller]
                ancestors.append((caller, raised))
                ascent_queue.append((caller, raised, depth + 1))
        return descend(ancestors) if ancestors else []

    def queue_handoff_candidates(
        self, function_ids: Iterable[str], *, limit: int = 24
    ) -> list[dict[str, object]]:
        """Navigation hints for a producer/consumer split by an async queue.

        This does not insert a CallEdge: matching a queue field and operation
        spelling cannot prove that the same runtime object crosses threads.
        The candidate must be opened and corroborated by source/trace before
        it can contribute to any trusted Entry or scenario proof.
        """
        selected = set(function_ids) & self.bundle.functions.keys()
        operations = re.compile(
            r"\b(?P<api>(?:[A-Za-z_]\w*_(?:push|pop|enqueue|dequeue)|"
            r"(?:enqueue|dequeue|queue_push|queue_pop|cq_push|cq_pop)))"
            r"\s*\(\s*(?P<queue>&?\s*(?:[A-Za-z_]\w*\s*(?:->|\.)\s*)*"
            r"[A-Za-z_]\w*)",
        )
        producers: dict[str, list[tuple[str, str, int]]] = {}
        consumers: dict[str, list[tuple[str, str, int]]] = {}
        for identifier, function in self.bundle.functions.items():
            for match in operations.finditer(function.source):
                api = match.group('api')
                queue_expression = match.group('queue').strip()
                queue_name = re.split(r"->|\.", queue_expression)[-1].strip()
                if len(queue_name) < 4 or queue_name in {'queue', 'list', 'head'}:
                    continue
                site_line = function.start_line + function.source.count('\n', 0, match.start())
                row = (identifier, api, site_line)
                if api.endswith(('push', 'enqueue')):
                    producers.setdefault(queue_name, []).append(row)
                elif api.endswith(('pop', 'dequeue')):
                    consumers.setdefault(queue_name, []).append(row)
        choices: dict[str, dict[str, object]] = {}
        for queue_name in sorted(producers.keys() & consumers.keys()):
            for left in producers[queue_name]:
                for right in consumers[queue_name]:
                    if left[0] == right[0]:
                        continue
                    if left[0] in selected and right[0] not in selected:
                        current, next_item = left, right
                    elif right[0] in selected and left[0] not in selected:
                        current, next_item = right, left
                    else:
                        continue
                    function = self.get(next_item[0])
                    choice = choices.setdefault(next_item[0], {
                        'function_id': next_item[0],
                        'name': function.name,
                        'qualified_name': function.qualified_name,
                        'file': function.file,
                        'start_line': function.start_line,
                        'connections': [],
                    })
                    choice['connections'].append({
                        'relation': 'queue_handoff_candidate',
                        'connected_function_id': current[0],
                        'connected_function_name': self.get(current[0]).name,
                        'queue_field': queue_name,
                        'producer_api': left[1], 'producer_line': left[2],
                        'consumer_api': right[1], 'consumer_line': right[2],
                        'evidence_kind': 'lexical_navigation_only',
                    })
        return list(choices.values())[:max(0, limit)]

    def shared_field_candidates(self, function_ids: Iterable[str], *, limit: int = 32) -> list[dict[str, object]]:
        """Find possible writers of fields read through a locally declared pointer type.

        This lexical index is a navigation hint, never a data-flow edge or proof.
        The verifier must open the source and establish object and queue identity.
        """
        selected = [item for item in function_ids if item in self.bundle.functions]
        selected_set = set(selected)
        declaration = re.compile(r"\b([A-Za-z_]\w*)\s*\*\s*([A-Za-z_]\w*)\b")
        reads: dict[tuple[str, str], list[str]] = {}
        for current in selected:
            source = self.get(current).source
            for typ, var in declaration.findall(source):
                for field in set(re.findall(r"\b" + re.escape(var) + r"\s*->\s*([A-Za-z_]\w*)", source)):
                    reads.setdefault((typ, field), []).append(current)
        if self._typed_field_writers is None:
            writers: dict[tuple[str, str], list[str]] = {}
            for identifier, function in self.bundle.functions.items():
                for typ, var in declaration.findall(function.source):
                    for field in re.findall(
                        r"\b" + re.escape(var)
                        + r"\s*->\s*([A-Za-z_]\w*)\s*=(?!=)",
                        function.source,
                    ):
                        writers.setdefault((typ, field), []).append(identifier)
            self._typed_field_writers = writers
        matches_by_id: dict[str, list[tuple[str, str, str]]] = {}
        for (typ, field), parents in reads.items():
            for identifier in self._typed_field_writers.get((typ, field), []):
                if identifier in selected_set:
                    continue
                matches_by_id.setdefault(identifier, []).extend(
                    (typ, field, parent) for parent in parents
                )
        choices = []
        for identifier, matches in matches_by_id.items():
            function = self.get(identifier)
            if matches:
                typ, field, parent = matches[0]
                choices.append({
                    "function_id": identifier, "name": function.name,
                    "qualified_name": function.qualified_name, "file": function.file,
                    "start_line": function.start_line,
                    "connections": [{"relation": "shared_typed_field_candidate",
                        "connected_function_id": parent,
                        "connected_function_name": self.get(parent).name,
                        "type_name": typ, "field_name": field,
                        "evidence_kind": "lexical_navigation_only"}],
                    "_score": len(set(matches)),
                })
        choices.sort(key=lambda item: (-int(item["_score"]), str(item["file"]), int(item["start_line"])))
        for choice in choices:
            del choice["_score"]
        return choices[:limit]

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

    def shortest_path(
        self,
        source: str,
        target: str,
        max_depth: int = 8,
        *,
        allowed_edge_kinds: set[str] | None = None,
        require_located_indirect: bool = False,
    ) -> list[str]:
        """Return a structural call path subject to explicit evidence policy.

        The historical default intentionally remains the complete conservative
        graph for source navigation.  Proof checks must opt into an edge policy:
        a line-less SVF points-to edge is useful as a function-opening hint, but
        is not evidence that bytes actually traverse that callback.
        """

        if source == target:
            return [source]
        queue = deque([(source, [source])])
        seen = {source}
        while queue:
            current, path = queue.popleft()
            if len(path) > max_depth:
                continue
            for next_id in self._callees.get(current, set()):
                edges = self._edges_by_pair.get((current, next_id), [])
                if allowed_edge_kinds is not None:
                    edges = [
                        edge for edge in edges
                        if edge.kind in allowed_edge_kinds
                    ]
                if require_located_indirect:
                    edges = [
                        edge for edge in edges
                        if edge.kind != "indirect_possible" or edge.line is not None
                    ]
                if not edges:
                    continue
                if next_id == target:
                    return [*path, next_id]
                if next_id not in seen:
                    seen.add(next_id)
                    queue.append((next_id, [*path, next_id]))
        return []

    def shortest_evidenced_path(
        self, source: str, target: str, max_depth: int = 8
    ) -> list[str]:
        """Return a path usable as static reachability evidence.

        Direct calls are evidence.  A source-located SVF indirect edge may be
        checked against the opened callsite and target by a later agent.  A
        mere function reference, or a line-less whole-function SVF candidate,
        remains navigation metadata and is deliberately excluded.
        """

        return self.shortest_path(
            source,
            target,
            max_depth=max_depth,
            allowed_edge_kinds={"direct", "reported", "indirect_possible"},
            require_located_indirect=True,
        )

    def causal_path_from_entry(
        self,
        source: str,
        target: str,
        *,
        opened_function_ids: Iterable[str],
        max_return_depth: int = 6,
        max_forward_depth: int = 64,
        proven_direct_only: bool = False,
    ) -> list[str]:
        """Recover callback-return control flow using only opened evidence.

        An acquisition often lives inside ``c->read``.  Data then returns to
        the caller before a sibling parser/dispatcher runs, so a one-way call
        path from the read wrapper to the dispatcher cannot exist.  This
        method permits an initial caller ascent followed by normal forward
        calls.  A line-less SVF edge is admissible only when an opened,
        source-located function-reference edge registers that exact target.
        Such possible edges are navigation leads, not proof that this call
        occurred.  Proof callers can request only source-located direct edges.
        """

        opened = {
            item for item in opened_function_ids if item in self.bundle.functions
        }
        if source not in opened or target not in opened:
            return []

        registrations_by_target: dict[str, set[str]] = {}
        for edge in self.bundle.edges:
            if (
                edge.kind == "function_reference"
                and edge.line is not None
                and edge.caller_id in opened
                and edge.callee_id in opened
            ):
                registrations_by_target.setdefault(
                    edge.callee_id, set()
                ).add(edge.caller_id)
        callback_callers_by_target = {
            target_id: {
                function.function_id
                for function in self.callback_invocation_callers(
                    target_id,
                    registration_function_ids=registration_ids,
                )
            }
            for target_id, registration_ids in registrations_by_target.items()
        }

        def pair_is_executable(caller_id: str, callee_id: str) -> bool:
            for edge in self._edges_by_pair.get((caller_id, callee_id), []):
                if proven_direct_only:
                    if edge.kind == "direct" and edge.line is not None:
                        return True
                    continue
                if edge.kind in {"direct", "reported"}:
                    return True
                if edge.kind == "indirect_possible" and (
                    edge.line is not None
                    or caller_id in callback_callers_by_target.get(
                        callee_id, set()
                    )
                ):
                    return True
            return False

        def forward_path(start: str) -> list[str]:
            if start == target:
                return [start]
            queue: deque[tuple[str, list[str]]] = deque([(start, [start])])
            seen = {start}
            while queue:
                current, path = queue.popleft()
                if len(path) > max_forward_depth:
                    continue
                for next_id in self._callees.get(current, set()):
                    if next_id not in opened or not pair_is_executable(current, next_id):
                        continue
                    if next_id == target:
                        return [*path, next_id]
                    if next_id not in seen:
                        seen.add(next_id)
                        queue.append((next_id, [*path, next_id]))
            return []

        direct = forward_path(source)
        if direct:
            return direct
        queue: deque[tuple[str, list[str], int]] = deque([(source, [source], 0)])
        seen = {source}
        while queue:
            current, return_path, depth = queue.popleft()
            if depth >= max_return_depth:
                continue
            for caller_id in self._callers.get(current, set()):
                if caller_id not in opened or caller_id in seen:
                    continue
                if not pair_is_executable(caller_id, current):
                    continue
                seen.add(caller_id)
                raised = [*return_path, caller_id]
                descent = forward_path(caller_id)
                if descent:
                    return [*raised, *descent[1:]]
                queue.append((caller_id, raised, depth + 1))
        return []

    def callback_invocation_callers(
        self,
        function_id: str,
        *,
        registration_function_ids: Iterable[str],
    ) -> list[FunctionMetadata]:
        """Resolve callers that invoke a source-registered callback slot.

        Points-to analysis often reports a whole-function possible target with
        no callsite line.  That is insufficient proof by itself.  Once opened
        source establishes an assignment such as ``state->reader = socket_reader``, the
        slot name supplies the missing discriminator: only possible callers
        containing an invocation of that same slot (``c->read(...)``) are
        returned.  This keeps callback lifecycle recovery generic while
        avoiding the old all-target Cartesian product.
        """

        target = self.bundle.functions.get(function_id)
        if target is None:
            return []
        registrations = {
            item for item in registration_function_ids
            if item in self.bundle.functions
        }
        # Keep member slots and plain callback variables distinct.  Collapsing
        # ``c->read`` to the bare name ``read`` made an unrelated libc
        # ``read(fd, ...)`` look like an invocation of the registered member
        # callback whenever a conservative points-to edge was present.
        slots: set[tuple[str, str]] = set()
        target_name = re.escape(target.name)
        assignment = re.compile(
            rf"(?:(?:->|\.)\s*([A-Za-z_]\w*)|\b([A-Za-z_]\w*))\s*=\s*"
            rf"(?:\([^;=]+\)\s*)?&?\s*{target_name}\b"
        )
        for caller_id in registrations:
            edges = self._edges_by_pair.get((caller_id, function_id), [])
            if not any(
                edge.kind == "function_reference" and edge.line is not None
                for edge in edges
            ):
                continue
            for match in assignment.finditer(
                self.bundle.functions[caller_id].source
            ):
                if match.group(1):
                    slots.add(("member", match.group(1)))
                elif match.group(2):
                    slots.add(("plain", match.group(2)))
        if not slots:
            return []

        result: set[str] = set()
        for caller_id in self._callers.get(function_id, set()):
            edges = self._edges_by_pair.get((caller_id, function_id), [])
            if not any(edge.kind == "indirect_possible" for edge in edges):
                continue
            source = self.bundle.functions[caller_id].source
            invoked = False
            for slot_kind, slot in slots:
                if slot_kind == "member":
                    invoked = bool(re.search(
                        rf"(?:->|\.)\s*{re.escape(slot)}\s*\(", source
                    ))
                else:
                    for call in re.finditer(
                        rf"\b{re.escape(slot)}\s*\(", source
                    ):
                        prefix = source[max(0, call.start() - 16):call.start()]
                        if not re.search(r"(?:->|\.)\s*$", prefix):
                            invoked = True
                            break
                if invoked:
                    break
            if invoked:
                result.add(caller_id)
        return self._resolve(result)

    def _resolve(self, ids: Iterable[str]) -> list[FunctionMetadata]:
        return sorted(
            (self.bundle.functions[item] for item in ids if item in self.bundle.functions),
            key=lambda function: (function.file, function.start_line, function.name),
        )

    def _connection_evidence(self, caller_id: str, callee_id: str) -> dict[str, object]:
        edges = self._edges_by_pair.get((caller_id, callee_id), [])
        edge_kinds = {str(edge.kind) for edge in edges}
        return {
            "edge_kinds": sorted(edge_kinds),
            "edge_confidence": max(
                (float(edge.confidence) for edge in edges), default=0.0
            ),
            # Function-pointer registration and SVF points-to information are
            # hypotheses, not direct-call proof. Exposing their callsite lines
            # lets the Entry/Small Feature agents request the registration body
            # or emit a runtime breakpoint obligation instead of interpreting a
            # missing direct edge as a rejected TCP/TLS path.
            "edge_lines": sorted({
                int(edge.line) for edge in edges if edge.line is not None
            }),
            "callback_registration_candidate": bool(
                {"function_reference", "indirect_possible"} & edge_kinds
            ),
            "edge_providers": sorted({
                provider for edge in edges for provider in edge.providers
            }),
            "possible_indirect_target": any(
                edge.kind == "indirect_possible" for edge in edges
            ),
        }
