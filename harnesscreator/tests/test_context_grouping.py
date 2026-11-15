"""Grouping rules fixed on 2026-11-15 after a run whose UDP Entry was not joined to the TCP Entry."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from harnesscreator.contexts.agents import ContextLocatorAgent, EntryChannelClassifier
from harnesscreator.contexts.builder import CallGraph, api_resource, build_contexts, resolve_channel
from harnesscreator.contexts.cli import load_graph
from harnesscreator.llm.base import ScriptedLLM
from test_contexts_stage import write_run

# Channel descriptions written by the Entry Verifier (Claude Haiku 5.5) in the run of 2026-11-15.
TLS_TEXT = ("ambiguous network/socket input: TLS session read (SSL_read on mcp_backendconn_s.ssl) from the backend "
            "network peer; address family and transport (TCP, UDP, or AF_UNIX) are not established in the supplied source")
MEMINFO_TEXT = "filesystem_file_stdio: /proc/meminfo read via fopen/fgets (not network or socket input)"
UDP_TEXT = ("ambiguous network/socket input: recvfrom on c->sfd for conns that drive_machine routes to try_read_udp "
            "via the IS_UDP(c->transport) branch; the transport tag is UDP, but the socket family and type "
            "(SOCK_DGRAM, AF_UNIX, or other) are not established")

EXTRA_FUNCTIONS = ["event", "drive", "tcp_read", "udp_read", "parse_cmd", "tls_read", "tls_handler", "meminfo"]
EXTRA_EDGES = [("event", "drive"), ("drive", "tcp_read", "indirect_possible"), ("drive", "udp_read"),
               ("drive", "parse_cmd", "indirect_possible"), ("parse_cmd", "dispatch"),
               ("tls_handler", "tls_read"), ("main", "meminfo"), ("main", "event"), ("main", "tls_handler")]
ENTRIES = [
    {"entry_id": "e-tcp", "entry_function_id": "fn-tcp_read", "source_api": "read", "status": "VERIFIED",
     "channel_kind": "TCP stream socket input (SOCK_STREAM, AF_INET or AF_INET6)", "consumer_hints": ["fn-drive"]},
    {"entry_id": "e-udp", "entry_function_id": "fn-udp_read", "source_api": "recvfrom", "status": "VERIFIED",
     "channel_kind": UDP_TEXT, "consumer_hints": []},
    {"entry_id": "e-tls", "entry_function_id": "fn-tls_read", "source_api": "SSL_read", "status": "VERIFIED",
     "channel_kind": TLS_TEXT, "consumer_hints": ["fn-tls_handler"]},
    {"entry_id": "e-mem", "entry_function_id": "fn-meminfo", "source_api": "fgets", "status": "VERIFIED",
     "channel_kind": MEMINFO_TEXT, "consumer_hints": []},
]


def make_run(tmp: str) -> Path:
    run = Path(tmp)
    write_run(run, entries=ENTRIES, extra_functions=EXTRA_FUNCTIONS, extra_edges=EXTRA_EDGES)
    return run


def write_rows(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


class DriverTests(unittest.TestCase):
    def test_driver_reaches_every_interpreter_not_just_the_nearest_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            graph = CallGraph.from_run(make_run(tmp))
            # The Entry function reads part of the bytes itself; the rest is read by a sibling.
            self.assertEqual(graph.driver("fn-udp_read", ["fn-udp_read"]), "fn-udp_read")
            self.assertEqual(graph.driver("fn-udp_read", ["fn-udp_read", "fn-parse_cmd"]), "fn-drive")
            self.assertEqual(graph.driver("fn-udp_read", ["fn-parse_cmd", "fn-udp_read", "fn-drive"]), "fn-drive")
            # An interpreter that exists nowhere in the graph does not erase the result.
            self.assertEqual(graph.driver("fn-udp_read", ["fn-parse_cmd", "fn-missing"]), "fn-drive")
            self.assertEqual(graph.nearest_driver("fn-udp_read", ["fn-udp_read", "fn-parse_cmd"]), "fn-udp_read")


class ChannelTests(unittest.TestCase):
    def test_keyword_table_misplaces_the_recorded_descriptions(self):
        self.assertEqual(resolve_channel(ENTRIES[2], None), ("network", "datagram", "keyword_table"))
        self.assertEqual(resolve_channel(ENTRIES[3], None)[0], "network")

    def test_enumerated_choice_and_api_facts_take_precedence(self):
        self.assertEqual(resolve_channel(ENTRIES[2], {"resource_kind": "network", "delivery": "stream"}),
                         ("network", "stream", "classifier"))
        self.assertEqual(resolve_channel(ENTRIES[3], {"resource_kind": "file", "delivery": "not_applicable"}),
                         ("file", "file", "classifier"))
        # Socket type not established: recvfrom is the remaining fact.
        self.assertEqual(resolve_channel(ENTRIES[1], {"resource_kind": "network", "delivery": "unknown"}),
                         ("network", "datagram", "classifier"))
        self.assertEqual(resolve_channel(ENTRIES[2], {"resource_kind": "network", "delivery": "unknown"})[1], "stream")
        env = {"source_api": "getenv", "channel_kind": "read from the network configuration file"}
        self.assertEqual(resolve_channel(env, {"resource_kind": "file", "delivery": "not_applicable"}),
                         ("env", "env", "source_api"))
        self.assertEqual((api_resource("argv"), api_resource("read")), ("argv", None))

    def test_udp_joins_tcp_and_tls_is_not_taken_for_datagram(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = make_run(tmp)
            write_rows(run / "contexts" / "classification.jsonl", [
                {"entry_id": "e-tcp", "resource_kind": "network", "delivery": "stream"},
                {"entry_id": "e-udp", "resource_kind": "network", "delivery": "datagram"},
                {"entry_id": "e-tls", "resource_kind": "network", "delivery": "stream"},
                {"entry_id": "e-mem", "resource_kind": "file", "delivery": "not_applicable"}])
            write_rows(run / "contexts" / "locator.jsonl", [
                {"entry_id": "e-udp", "interpreter_function_ids": ["fn-udp_read", "fn-parse_cmd"]}])
            result = build_contexts(run)
            by_driver = {ctx.driver_function: ctx for ctx in result["contexts"]}
            client = by_driver["drive"]
            self.assertEqual({member.entry_id for member in client.entries}, {"e-tcp", "e-udp"})
            self.assertEqual(client.deliveries, ["datagram", "stream"])
            self.assertEqual(by_driver["tls_handler"].deliveries, ["stream"])
            self.assertEqual(by_driver["meminfo"].resource_kind, "file")
            datagram = [ctx for ctx in result["contexts"] if "datagram" in ctx.deliveries]
            self.assertEqual([ctx.driver_function for ctx in datagram], ["drive"])
            self.assertEqual(result["summary"]["resource_source"], {"classifier": 4})


def answer(interpreters=(), open_id="", remain=False, done=True):
    return {"interpreter_function_ids": list(interpreters), "open_function_id": open_id,
            "bytes_remain_after_return": remain, "done": done, "rationale": "scripted"}


class LocatorTests(unittest.IsolatedAsyncioTestCase):
    async def locate(self, tmp: str, responses: list[dict]):
        run = make_run(tmp)
        llm = ScriptedLLM(responses)
        agent = ContextLocatorAgent(llm, load_graph(run), CallGraph.from_run(run))
        return await agent.locate(ENTRIES[1]), llm

    async def test_bytes_left_in_storage_move_the_search_to_the_caller(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, llm = await self.locate(tmp, [
                answer(["fn-udp_read"], remain=True),   # reads the frame header, leaves the payload stored
                answer(["fn-parse_cmd"], remain=True),  # the caller hands the payload to the parser
                answer([], remain=True)])               # the next caller adds no reader: stop
        self.assertEqual(result["interpreter_function_ids"], ["fn-udp_read", "fn-parse_cmd"])
        self.assertEqual(result["climbed_function_ids"], ["fn-drive", "fn-event"])
        self.assertEqual(result["ended"], "model_done")
        self.assertEqual([call["payload"]["current_function"]["name"] for call in llm.calls],
                         ["udp_read", "drive", "event"])
        self.assertEqual(llm.calls[1]["payload"]["return_question_function"]["name"], "drive")

    async def test_search_ends_at_the_entry_function_when_nothing_outlives_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, llm = await self.locate(tmp, [answer(["fn-udp_read"], remain=False)])
        self.assertEqual(result["interpreter_function_ids"], ["fn-udp_read"])
        self.assertEqual(result["climbed_function_ids"], [])
        self.assertEqual(len(llm.calls), 1)

    async def test_caller_without_a_reader_is_passed_until_one_is_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, _ = await self.locate(tmp, [
                answer([], remain=True),                                  # only stores
                answer([], open_id="fn-parse_cmd", remain=True, done=False),  # caller: look at a callee
                answer(["fn-parse_cmd"], remain=True),
                answer([], remain=True)])
        self.assertEqual(result["interpreter_function_ids"], ["fn-parse_cmd"])
        self.assertEqual(result["climbed_function_ids"], ["fn-drive", "fn-event"])

    async def test_function_outside_the_graph_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, _ = await self.locate(tmp, [answer(["fn-nowhere"], remain=False)])
        self.assertEqual((result["interpreter_function_ids"], result["rejected_function_ids"]), ([], ["fn-nowhere"]))


class ClassifierTests(unittest.IsolatedAsyncioTestCase):
    async def test_choice_is_recorded_per_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = make_run(tmp)
            llm = ScriptedLLM([{"resource_kind": "network", "delivery": "stream", "rationale": "TLS on a socket"}])
            row = await EntryChannelClassifier(llm, load_graph(run)).classify(ENTRIES[2])
        self.assertEqual((row["entry_id"], row["resource_kind"], row["delivery"]), ("e-tls", "network", "stream"))
        self.assertEqual(llm.calls[0]["role"], "context_classifier")
        self.assertEqual(llm.calls[0]["payload"]["entry_function"]["name"], "tls_read")


if __name__ == "__main__":
    unittest.main()
