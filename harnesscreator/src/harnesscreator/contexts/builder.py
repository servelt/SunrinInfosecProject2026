from __future__ import annotations

import collections
import dataclasses
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable

from .model import RESOURCE_PRIORITY, ContextEntry, InputContext

# Edge kinds that represent "caller may transfer control to callee".
# function_reference (a function merely takes another's address, e.g. to
# register a callback) is not a call and is excluded.
CALL_EDGE_KINDS = ("direct", "indirect_possible", "reported")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


class CallGraph:
    def __init__(self, functions: Iterable[dict[str, Any]], edges: Iterable[dict[str, Any]]):
        self.functions = {item["function_id"]: item for item in functions}
        self.callees: dict[str, set[str]] = collections.defaultdict(set)
        self.callers: dict[str, set[str]] = collections.defaultdict(set)
        self.edge_kinds: collections.Counter[str] = collections.Counter()
        for edge in edges:
            kind = edge.get("kind")
            self.edge_kinds[kind] += 1
            if kind not in CALL_EDGE_KINDS:
                continue
            caller, callee = edge.get("caller_id"), edge.get("callee_id")
            if caller in self.functions and callee in self.functions:
                self.callees[caller].add(callee)
                self.callers[callee].add(caller)

    @classmethod
    def from_run(cls, run_dir: Path) -> "CallGraph":
        return cls(_read_jsonl(run_dir / "analysis" / "functions.jsonl"),
                   _read_jsonl(run_dir / "analysis" / "edges.jsonl"))

    def name(self, function_id: str | None) -> str:
        return (self.functions.get(function_id or "") or {}).get("name", "") if function_id else ""

    def _distances(self, start: str, neighbours: dict[str, set[str]]) -> dict[str, int]:
        distance = {start: 0}
        queue = collections.deque([start])
        while queue:
            current = queue.popleft()
            for nxt in sorted(neighbours.get(current, ())):
                if nxt not in distance:
                    distance[nxt] = distance[current] + 1
                    queue.append(nxt)
        return distance

    def ancestors(self, function_id: str) -> dict[str, int]:
        return self._distances(function_id, self.callers)

    def reachable(self, starts: Iterable[str]) -> set[str]:
        seen: set[str] = set()
        for start in starts:
            if start in self.functions and start not in seen:
                seen.update(self._distances(start, self.callees))
        return seen

    def nearest_driver(self, entry_function_id: str, candidate_ids: list[str]) -> str | None:
        """Driver of whichever candidate lies closest to the Entry function.

        Used to choose among alternative dispatchers named by earlier records;
        the driver of a chosen interpreter set is :meth:`driver`.
        """

        drivers = [self.driver(entry_function_id, [candidate]) for candidate in candidate_ids]
        up_entry = self.ancestors(entry_function_id)
        best: tuple[int, int, str, str] | None = None
        for candidate, found in zip(candidate_ids, drivers):
            if found is None:
                continue
            reach = self.ancestors(candidate)[found]
            key = (up_entry[found] + reach, max(up_entry[found], reach), self.name(found), found)
            if best is None or key < best:
                best = key
        return best[3] if best else None

    def driver(self, entry_function_id: str, interpreter_ids: list[str]) -> str | None:
        """Innermost function that leads to the acquisition and to every interpreting function.

        This is the common ancestor (self included) of the Entry function and
        all interpreting functions with the shortest paths to them.  An
        interpreter with no call path joining it to the others is left out, in
        a fixed order, rather than dropping the result.  ``None`` means no
        interpreter can be joined to the acquisition, which is reported
        instead of guessed.

        Taking the nearest ancestor of any single interpreter is wrong when
        the Entry function itself interprets part of the bytes: it would be
        returned as its own driver although the remaining interpreters are
        only reachable from its caller.
        """

        up_entry = self.ancestors(entry_function_id)
        joinable: list[tuple[int, str, str, dict[str, int]]] = []
        for interpreter in dict.fromkeys(interpreter_ids):
            if interpreter not in self.functions:
                continue
            up_interp = self.ancestors(interpreter)
            shared = [up_entry[candidate] + distance for candidate, distance in up_interp.items()
                      if candidate in up_entry]
            if shared:
                joinable.append((min(shared), self.name(interpreter), interpreter, up_interp))
        # candidate -> distance to its farthest interpreter, over the candidates that reach all of them
        common: dict[str, int] = {}
        for index, (_, _, _, up_interp) in enumerate(sorted(joinable, key=lambda item: item[:3])):
            pool = up_entry if index == 0 else common
            narrowed = {candidate: max(common.get(candidate, 0), up_interp[candidate])
                        for candidate in pool if candidate in up_interp}
            if narrowed:
                common = narrowed
        if not common:
            return None
        # Same distance measure as for a single interpreter: total path length, then the longer leg.
        return min(common, key=lambda candidate: (up_entry[candidate] + common[candidate],
                                                  max(up_entry[candidate], common[candidate]),
                                                  self.name(candidate), candidate))


_INTERNAL = ("eventfd", "signalfd", "timerfd", "self-pipe", "notification wakeup", "wakeup counter",
             "i/o notification", "io notification")
_NETWORK = ("tcp", "udp", "af_inet", "datagram", "network", "sock_stream", "sock_dgram", "internet")
_LOCAL_IPC = ("af_unix", "unix domain", "unix-domain", "named pipe", "fifo")
_FILE = ("file", "filesystem", "procfs", "backing-file")
_STDIN = ("standard input", "standard-input", "stdin")
_NETWORK_APIS = ("recv", "recvfrom", "recvmsg", "recvmmsg", "accept")


def classify_resource(source_api: str, channel_kind: str) -> str:
    """Map the Entry Verifier's free-text channel description to a resource kind.

    The mapping is a fixed keyword table so the decision is reproducible and
    visible in the output; text it cannot place is reported as ``unknown``.
    """

    api = (source_api or "").strip().lower()
    text = (channel_kind or "").lower()
    if any(word in text for word in _INTERNAL):
        return "internal"
    if api == "argv" or "argv" in text or "command-line argument" in text or "command line argument" in text:
        return "argv"
    if api in ("getenv", "secure_getenv") or "environment" in text:
        return "env"
    if any(word in text for word in _NETWORK) or (api in _NETWORK_APIS and "unix" not in text):
        return "network"
    if any(word in text for word in _LOCAL_IPC):
        return "local_ipc"
    if any(word in text for word in _FILE):
        return "file"
    if any(word in text for word in _STDIN):
        return "stdin"
    return "unknown"


_API_RESOURCE = {"argv": "argv", "getenv": "env", "secure_getenv": "env"}
_DATAGRAM_APIS = ("recvfrom", "recvmsg", "recvmmsg")


def api_resource(source_api: str) -> str | None:
    """Resource kind fixed by the acquisition API alone, or None when the API does not decide it."""

    return _API_RESOURCE.get((source_api or "").strip().lower())


def resolve_channel(entry: dict[str, Any], chosen: dict[str, Any] | None) -> tuple[str, str, str]:
    """(resource kind, delivery, origin) of one Entry.

    Order: the acquisition API when it fixes the kind; the enumerated choice
    recorded in contexts/classification.jsonl; the keyword table over the
    free-text description (kept for runs made without the classifier).
    """

    api, text = entry.get("source_api", ""), entry.get("channel_kind", "")
    fixed = api_resource(api)
    if fixed:
        return fixed, fixed, "source_api"
    if chosen and chosen.get("resource_kind"):
        resource = chosen["resource_kind"]
        if resource in ("network", "local_ipc"):
            delivery = chosen.get("delivery")
            if delivery not in ("stream", "datagram"):
                # Socket type not established: the API is the only remaining fact.
                delivery = "datagram" if api.strip().lower() in _DATAGRAM_APIS else "stream"
        elif resource in ("argv", "env", "file", "stdin"):
            delivery = resource
        else:
            delivery = "unknown"
        return resource, delivery, "classifier"
    resource = classify_resource(api, text)
    return resource, classify_delivery(resource, api, text), "keyword_table"


def classify_delivery(resource_kind: str, source_api: str, channel_kind: str) -> str:
    api = (source_api or "").strip().lower()
    text = (channel_kind or "").lower()
    if resource_kind in ("argv", "env", "file", "stdin"):
        return resource_kind
    if resource_kind in ("network", "local_ipc"):
        if api in ("recvfrom", "recvmsg", "recvmmsg") or "udp" in text or "datagram" in text or "dgram" in text:
            return "datagram"
        return "stream"
    return "unknown"


SOCKET_DELIVERIES = ("stream", "datagram")
_TRANSPORT_UNKNOWN_WORDS = ("not established", "not shown", "unknown", "unestablished", "unconfirmed",
                            "missing", "absent", "not supplied")


def _verifier_left_transport_open(entry: dict[str, Any]) -> bool:
    """The Entry Verifier's structured unknowns say the socket type was not established.

    Only ``unknowns`` is read: the classifier does not see that list, while the
    free-text channel description (which the Verifier prefixes with "ambiguous
    network/socket input" for most sockets, including UDP and TLS ones whose
    type it then states) is what the classifier already decided from.
    """

    for item in entry.get("unknowns") or []:
        text = str(item).lower()
        if any(word in text for word in ("transport", "socket type", "sock_stream", "sock_dgram",
                                         "tcp or udp", "udp or tcp")) \
                and any(word in text for word in _TRANSPORT_UNKNOWN_WORDS):
            return True
    return False


def delivery_candidates(entry: dict[str, Any], chosen: dict[str, Any] | None,
                        resource: str, delivery: str) -> tuple[list[str], str]:
    """Every physical delivery the evidence leaves possible for one Entry, and why.

    The candidates are derived from the resource kind, not from the acquisition
    API: any socket read (recv, recvfrom, recvmsg, read, SSL_read, ...) can sit
    on a stream or a datagram socket.  A delivery is fixed only when something
    states it positively -- the classifier's enumerated choice, or socket words
    in the keyword path -- and the Entry Verifier did not record the transport
    as open.  Otherwise every candidate is measured on the original program and
    the coverage decides; nothing is dropped for lack of evidence.
    """

    if resource not in ("network", "local_ipc"):
        return [delivery], "resource_kind"
    # The resolved delivery is listed first: it is the one reported for the Entry.
    every = [delivery] + [item for item in SOCKET_DELIVERIES if item != delivery]
    if _verifier_left_transport_open(entry):
        return every, "unresolved:entry_verifier"
    if chosen and chosen.get("resource_kind"):
        if chosen.get("delivery") in SOCKET_DELIVERIES:
            return [chosen["delivery"]], "classifier"
        return every, "unresolved:classifier"
    text = f"{entry.get('channel_kind', '')}".lower()
    if any(word in text for word in ("udp", "datagram", "dgram")):
        return ["datagram"], "keyword_table"
    if any(word in text for word in ("tcp", "tls", "ssl", "stream", "connection", "accept")):
        return ["stream"], "keyword_table"
    return every, "unresolved:keyword_table"


def entry_candidates(entry: dict[str, Any]) -> list[str]:
    """Candidate deliveries recorded on one context Entry (JSON form)."""

    candidates = [str(item) for item in entry.get("delivery_candidates") or []]
    if not candidates and entry.get("transport_unresolved") is True:
        candidates = list(SOCKET_DELIVERIES)  # contexts written before candidates were recorded
    return candidates or [str(entry.get("delivery", ""))]


def entry_supports_delivery(context: dict[str, Any], entry: dict[str, Any], delivery: str) -> bool:
    """True when this Entry is measured, prompted and harnessed under ``delivery``.

    An Entry whose delivery the evidence fixed stays bound to it.  An Entry
    with several candidates serves each candidate the context measures; the
    seed, build, replay and review gates are unchanged, so an untrue candidate
    simply yields no accepted seed.
    """

    if entry.get("delivery") == delivery:
        return True
    return delivery in context.get("deliveries", []) and delivery in entry_candidates(entry)


def _interpreters(entry: dict[str, Any], locator: dict[str, list[str]],
                  actions_by_entry: dict[str, list[dict[str, Any]]], graph: CallGraph) -> tuple[list[str], str]:
    entry_id = entry["entry_id"]
    located = [fid for fid in locator.get(entry_id, []) if fid in graph.functions]
    if located:
        return located, "locator"
    function_id = entry["entry_function_id"]
    # Earlier Action records name a dispatcher per Action.  They are model
    # output, so a dispatcher is used only when the call graph joins it to this
    # Entry's acquisition (a common ancestor exists).  All such dispatchers that
    # share the nearest driver are kept, so the result does not depend on which
    # dispatcher happened to be named most often in a particular run.
    drivers = {}
    for dispatcher in sorted({action.get("dispatcher_function_id") for action in actions_by_entry.get(entry_id, [])} - {None, ""}):
        if dispatcher in graph.functions:
            driver = graph.driver(function_id, [dispatcher])
            if driver is not None:
                drivers[dispatcher] = driver
    if drivers:
        nearest = graph.nearest_driver(function_id, sorted(drivers))
        kept = sorted((d for d, driver in drivers.items() if driver == nearest), key=lambda fid: (graph.name(fid), fid))
        if kept:
            return kept, "actions"
    hints = [fid for fid in entry.get("consumer_hints") or []
             if fid in graph.functions and graph.driver(function_id, [fid]) is not None]
    if hints:
        return sorted(hints, key=lambda fid: (graph.name(fid), fid)), "consumer_hint"
    return [entry["entry_function_id"]], "entry_function"


def unique_ids(items: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(items))


def build_contexts(run_dir: Path, *, include_unresolved: bool = False) -> dict[str, Any]:
    """Group verified Entries into input contexts.  Deterministic; no model calls."""

    run_dir = Path(run_dir)
    graph = CallGraph.from_run(run_dir)
    entries = _read_jsonl(run_dir / "entries" / "verified.jsonl")
    if include_unresolved:
        entries += _read_jsonl(run_dir / "entries" / "unresolved.jsonl")
    actions_by_entry: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for action in _read_jsonl(run_dir / "actions" / "discovered-semantic.jsonl"):
        actions_by_entry[action.get("entry_id", "")].append(action)
    locator = {row["entry_id"]: list(row.get("interpreter_function_ids") or [])
               for row in _read_jsonl(run_dir / "contexts" / "locator.jsonl")}
    chosen = {row["entry_id"]: row for row in _read_jsonl(run_dir / "contexts" / "classification.jsonl")}
    peers = {row["entry_id"]: row.get("peers") or [] for row in _read_jsonl(run_dir / "contexts" / "peers.jsonl")}

    grouped: dict[tuple[str, str], list[ContextEntry]] = collections.defaultdict(list)
    unparsed: list[ContextEntry] = []
    excluded: list[dict[str, Any]] = []
    for entry in entries:
        function_id = entry.get("entry_function_id", "")
        meta = graph.functions.get(function_id)
        if meta is None:
            excluded.append({"entry_id": entry.get("entry_id"), "reason": "entry function is not in the analysis graph"})
            continue
        resource, delivery, resource_source = resolve_channel(entry, chosen.get(entry.get("entry_id", "")))
        if resource == "internal":
            excluded.append({
                "entry_id": entry["entry_id"], "entry_function": meta.get("name"),
                "source_api": entry.get("source_api"), "channel_kind": entry.get("channel_kind"),
                "reason": "descriptor is created and written by the program itself (no external supplier)"})
            continue
        interpreters, origin = _interpreters(entry, locator, actions_by_entry, graph)
        driver = graph.driver(function_id, interpreters)
        candidates, basis = delivery_candidates(entry, chosen.get(entry.get("entry_id", "")), resource, delivery)
        if delivery not in candidates:
            delivery = candidates[0]
        record = ContextEntry(
            entry_id=entry["entry_id"], entry_function_id=function_id, entry_function=meta.get("name", ""),
            entry_file=meta.get("file", ""), entry_line=int(entry.get("entry_line") or 0),
            source_api=entry.get("source_api", ""), channel_kind=entry.get("channel_kind", ""),
            attacker_control=entry.get("attacker_control", "unknown"), entry_status=entry.get("status", ""),
            resource_kind=resource, delivery=delivery, resource_source=resource_source,
            interpreter_function_ids=interpreters, interpreter_source=origin, driver_function_id=driver,
            delivery_candidates=candidates, delivery_basis=basis,
            transport_unresolved=len(candidates) > 1)
        # A socket Entry whose descriptor may belong to a connection the program opened itself:
        # each such peer becomes its own Entry record with the peer_stream delivery, read by the
        # functions that interpret that peer's bytes.  The accepted side keeps the record above.
        entry_peers = peers.get(entry["entry_id"], []) if "stream" in candidates else []
        initiated = [peer for peer in entry_peers if peer.get("role") == "initiated"]
        for peer in initiated:
            readers = [fid for fid in peer.get("reader_function_ids") or [] if fid in graph.functions] \
                or [fid for fid in peer.get("via_function_ids") or [] if fid in graph.functions] or [function_id]
            peer_record = dataclasses.replace(
                record, delivery="peer_stream", delivery_candidates=["peer_stream"],
                transport_unresolved=False, interpreter_function_ids=readers, interpreter_source="peer",
                driver_function_id=graph.driver(function_id, readers),
                channel_kind=f"connection the program opens ({peer.get('descriptor', '')}; address from "
                             f"{peer.get('address_source', 'unknown')}: {peer.get('address_detail', '')})")
            # One peer connection, one context: every read of the descriptor the program opened is the
            # same connection to the same server (tinyproxy: the response headers read by readline and the
            # body relayed by read_buffer both arrive on server_fd), and a harness plays that server whatever
            # address the program chose.  The address source is kept in channel_kind, not used to split:
            # measured on tinyproxy, the model gave one server_fd "input", "configuration" and "unknown".
            descriptor = re.sub(r"\s+", "", str(peer.get("descriptor") or "")) or "?"
            grouped[(resource, f"peer:{descriptor}")].append(peer_record)
        accepted = [peer for peer in entry_peers if peer.get("role") == "accepted"]
        if initiated and not accepted:
            rest = [item for item in candidates if item != "stream"]
            if not rest:
                continue  # every peer of this descriptor is one the program connects to
            # The stream reading is the connection the program opens; a datagram
            # reading of the same unresolved socket is still measured on its own.
            record = dataclasses.replace(record, delivery=rest[0], delivery_candidates=rest,
                                         transport_unresolved=len(rest) > 1)
        if accepted:
            # The accepted side follows the same rule: one client connection, one context.  The
            # locator may have followed a server path of a shared reader (tinyproxy: safe_read's
            # interpreter came out as connect_to_upstream_proxy, the SOCKS reply parser), which put
            # the client Entry in a context of its own; the readers the peer analysis names for the
            # accepted descriptor are used instead when it names any.
            readers = [fid for peer in accepted for fid in peer.get("reader_function_ids") or []
                       if fid in graph.functions]
            if readers:
                record = dataclasses.replace(record, interpreter_function_ids=unique_ids(readers),
                                             interpreter_source="peer",
                                             driver_function_id=graph.driver(function_id, unique_ids(readers)))
            descriptor = re.sub(r"\s+", "", str(accepted[0].get("descriptor") or "")) or "?"
            grouped[(resource, f"accept:{descriptor}")].append(record)
            continue
        if origin == "entry_function" and entry["entry_id"] in locator:
            # The locator followed these bytes and found no function that reads
            # them (e.g. a body copied into a buffer and forwarded).  Used as its
            # own anchor, the Entry would form a context of its own whose
            # harness only repeats the delivery of a context that already
            # reaches it; it is placed after the other contexts are known.
            unparsed.append(record)
            continue
        anchor = driver or interpreters[0]
        grouped[(resource, anchor)].append(record)

    contexts: list[InputContext] = []
    for (resource, anchor), members in grouped.items():
        members.sort(key=lambda item: (item.entry_function, item.entry_line, item.entry_id))
        interpreters = sorted({fid for member in members for fid in member.interpreter_function_ids},
                              key=lambda fid: (graph.name(fid), fid))
        driver = members[0].driver_function_id
        if anchor.startswith(("peer:", "accept:")):
            joined = graph.driver(members[0].entry_function_id, interpreters)
            driver = joined if joined is not None else driver
        notes = []
        if driver is None:
            notes.append("no call path joins the acquisition and the interpreting function; grouped by interpreter")
        if any(member.interpreter_source == "entry_function" for member in members):
            notes.append("interpreting function unknown for at least one Entry; the Entry function was used")
        digest = hashlib.sha256(f"{resource}:{anchor}".encode()).hexdigest()[:12]
        if anchor.startswith("peer:"):
            notes.append("bytes sent by a peer the program connects to; the harness plays that peer")
        contexts.append(InputContext(
            context_id=f"ctx-{digest}", resource_kind=resource, priority=RESOURCE_PRIORITY.get(resource, 9),
            driver_function_id=driver, driver_function=graph.name(driver) if driver else "",
            interpreter_function_ids=interpreters, interpreter_functions=[graph.name(fid) for fid in interpreters],
            deliveries=sorted({item for member in members for item in member.delivery_candidates}),
            entries=members,
            target_function_ids=sorted(graph.reachable(interpreters)), notes=notes))
    contexts.sort(key=lambda ctx: (ctx.priority, -len(ctx.target_function_ids), ctx.context_id))

    # An Entry whose bytes nobody interprets joins a context of the same
    # resource and delivery whose target functions already contain its
    # acquisition function: that context's harness delivers those bytes on the
    # same channel.  Only such Entries are joined; Entries with their own
    # interpreter keep their own context even when reachable from another
    # driver (e.g. a server response read inside a client connection handler).
    for record in sorted(unparsed, key=lambda item: (item.entry_function, item.entry_line, item.entry_id)):
        host = next((ctx for ctx in contexts if ctx.resource_kind == record.resource_kind
                     and set(record.delivery_candidates) <= set(ctx.deliveries)
                     and record.entry_function_id in ctx.target_function_ids), None)
        if host is not None:
            host.entries.append(record)
            host.notes.append(f"Entry {record.entry_id} ({record.entry_function}) has no interpreting function; "
                              "joined because this context already reaches it on the same channel")
            continue
        interpreters = list(record.interpreter_function_ids)
        anchor = record.driver_function_id or interpreters[0]
        digest = hashlib.sha256(f"{record.resource_kind}:{anchor}".encode()).hexdigest()[:12]
        same = next((ctx for ctx in contexts if ctx.context_id == f"ctx-{digest}"), None)
        if same is not None:
            same.entries.append(record)
            same.deliveries = sorted(set(same.deliveries) | set(record.delivery_candidates))
            continue
        contexts.append(InputContext(
            context_id=f"ctx-{digest}", resource_kind=record.resource_kind,
            priority=RESOURCE_PRIORITY.get(record.resource_kind, 9),
            driver_function_id=record.driver_function_id,
            driver_function=graph.name(record.driver_function_id) if record.driver_function_id else "",
            interpreter_function_ids=interpreters, interpreter_functions=[graph.name(fid) for fid in interpreters],
            deliveries=sorted(record.delivery_candidates), entries=[record],
            target_function_ids=sorted(graph.reachable(interpreters)),
            notes=["interpreting function unknown for at least one Entry; the Entry function was used",
                   "the locator found no function that interprets these bytes and no other context reaches them"]))
    contexts.sort(key=lambda ctx: (ctx.priority, -len(ctx.target_function_ids), ctx.context_id))

    for context in contexts:
        open_entries = [member for member in context.entries if len(member.delivery_candidates) > 1]
        if open_entries:
            # Recorded for the reader; selection reads delivery_candidates.
            context.notes.append(
                "delivery not established for " + ", ".join(
                    f"{member.entry_function}({member.delivery_basis})" for member in open_entries)
                + "; each candidate delivery (" + ", ".join(sorted({item for member in open_entries
                                                                    for item in member.delivery_candidates}))
                + ") is measured separately on the original program")

    overlaps = []
    targets = {ctx.context_id: set(ctx.target_function_ids) for ctx in contexts}
    for index, left in enumerate(contexts):
        for right in contexts[index + 1:]:
            shared = targets[left.context_id] & targets[right.context_id]
            if shared:
                overlaps.append({
                    "left": left.context_id, "right": right.context_id, "shared_target_functions": len(shared),
                    "left_fraction": round(len(shared) / max(1, len(targets[left.context_id])), 4),
                    "right_fraction": round(len(shared) / max(1, len(targets[right.context_id])), 4)})
    return {
        "contexts": contexts, "excluded": excluded, "overlaps": overlaps,
        "summary": {
            "entries_considered": len(entries), "entries_excluded": len(excluded), "contexts": len(contexts),
            "by_resource_kind": dict(collections.Counter(ctx.resource_kind for ctx in contexts)),
            "interpreter_source": dict(collections.Counter(
                member.interpreter_source for ctx in contexts for member in ctx.entries)),
            "resource_source": dict(collections.Counter(
                member.resource_source for ctx in contexts for member in ctx.entries)),
            "graph_functions": len(graph.functions), "graph_edge_kinds": dict(graph.edge_kinds),
            "call_edge_kinds_used": list(CALL_EDGE_KINDS)},
    }


def write_contexts(run_dir: Path, result: dict[str, Any]) -> Path:
    out = Path(run_dir) / "contexts"
    out.mkdir(parents=True, exist_ok=True)
    with (out / "contexts.jsonl").open("w", encoding="utf-8") as handle:
        for ctx in result["contexts"]:
            handle.write(json.dumps(ctx.to_json(), ensure_ascii=False, sort_keys=True) + "\n")
    for name in ("excluded", "overlaps"):
        with (out / f"{name}.jsonl").open("w", encoding="utf-8") as handle:
            for row in result[name]:
                handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    (out / "summary.json").write_text(json.dumps(result["summary"], ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                                      encoding="utf-8")
    return out


def render_table(result: dict[str, Any]) -> str:
    lines = [f"contexts={result['summary']['contexts']} "
             f"(entries considered={result['summary']['entries_considered']}, excluded={result['summary']['entries_excluded']})"]
    for ctx in result["contexts"]:
        entries = ", ".join(f"{member.entry_function}::{member.source_api}" for member in ctx.entries)
        lines.append(
            f"  {ctx.context_id} | {ctx.resource_kind:9s} | {'/'.join(ctx.deliveries):15s} | "
            f"driver={ctx.driver_function or '-'} | interpreter={','.join(ctx.interpreter_functions)} | "
            f"targets={len(ctx.target_function_ids)} | entries={len(ctx.entries)}: {entries}")
    for row in result["excluded"]:
        lines.append(f"  excluded {row.get('entry_function') or row.get('entry_id')}: {row['reason']}")
    return "\n".join(lines)
