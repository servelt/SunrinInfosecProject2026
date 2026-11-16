"""Peers a program connects to (tinyproxy 2026-11-16: the web server's response had no context)."""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from harnesscreator.contexts.agents import seeds_from_items
from harnesscreator.contexts.builder import build_contexts
from harnesscreator.contexts.execution import ProgramRunner, ProgramSpec
from test_contexts_stage import write_run

# A two-function "proxy": serve() reads the client request, fetch() reads the server reply, both through read_line().
FUNCTIONS = ["serve", "fetch", "read_line", "parse_request", "parse_reply"]
EDGES = [("main", "serve"), ("serve", "read_line"), ("serve", "parse_request"), ("serve", "fetch"),
         ("fetch", "read_line"), ("fetch", "parse_reply")]
ENTRY = {"entry_id": "e-line", "entry_function_id": "fn-read_line", "source_api": "recv", "status": "VERIFIED",
         "channel_kind": "accepted TCP client socket", "consumer_hints": []}


def write_rows(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


class PeerContextTests(unittest.TestCase):
    def build(self, tmp: str, peers: list[dict]) -> dict:
        run = Path(tmp)
        write_run(run, entries=[ENTRY], extra_functions=FUNCTIONS, extra_edges=EDGES)
        write_rows(run / "contexts" / "classification.jsonl",
                   [{"entry_id": "e-line", "resource_kind": "network", "delivery": "stream"}])
        write_rows(run / "contexts" / "locator.jsonl",
                   [{"entry_id": "e-line", "interpreter_function_ids": ["fn-parse_request"]}])
        write_rows(run / "contexts" / "peers.jsonl", [{"entry_id": "e-line", "peers": peers}])
        return build_contexts(run)

    def test_server_reply_read_by_a_shared_helper_gets_its_own_context(self):
        peers = [
            {"role": "accepted", "descriptor": "client_fd", "via_function_ids": ["fn-serve"],
             "reader_function_ids": ["fn-parse_request"], "connect_function_id": "", "address_source": "unknown",
             "address_detail": "", "evidence": "accept in main"},
            {"role": "initiated", "descriptor": "server_fd", "via_function_ids": ["fn-fetch"],
             "reader_function_ids": ["fn-fetch"], "connect_function_id": "fn-fetch", "address_source": "input",
             "address_detail": "host from the request line", "evidence": "connect in fetch"}]
        with tempfile.TemporaryDirectory() as tmp:
            result = self.build(tmp, peers)
        by_delivery = {tuple(ctx.deliveries): ctx for ctx in result["contexts"]}
        self.assertEqual(set(by_delivery), {("stream",), ("peer_stream",)})
        peer = by_delivery[("peer_stream",)]
        self.assertEqual(peer.driver_function, "fetch")
        self.assertEqual(peer.entries[0].interpreter_source, "peer")
        self.assertIn("server_fd", peer.entries[0].channel_kind)
        self.assertNotEqual(peer.context_id, by_delivery[("stream",)].context_id)

    def test_without_peer_record_nothing_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.build(tmp, [])
        self.assertEqual([ctx.deliveries for ctx in result["contexts"]], [["stream"]])

    def test_only_initiated_peer_replaces_the_stream_entry(self):
        peers = [{"role": "initiated", "descriptor": "fd", "via_function_ids": ["fn-fetch"], "reader_function_ids": [],
                  "connect_function_id": "fn-fetch", "address_source": "configuration", "address_detail": "",
                  "evidence": ""}]
        with tempfile.TemporaryDirectory() as tmp:
            result = self.build(tmp, peers)
        self.assertEqual([ctx.deliveries for ctx in result["contexts"]], [["peer_stream"]])


class AcceptedSideTests(unittest.TestCase):
    """tinyproxy 2026-11-16: safe_read's client Entry got the SOCKS reply parser as interpreter and a context of its own."""

    def test_two_readers_of_one_client_descriptor_share_one_context(self):
        body = {"entry_id": "e-body", "entry_function_id": "fn-fetch", "source_api": "read", "status": "VERIFIED",
                "channel_kind": "accepted TCP client socket", "consumer_hints": []}
        client = lambda readers: {"role": "accepted", "descriptor": "connptr->client_fd", "via_function_ids": [],
                                  "reader_function_ids": readers, "connect_function_id": "", "address_source": "unknown",
                                  "address_detail": "", "evidence": ""}
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            write_run(run, entries=[ENTRY, body], extra_functions=FUNCTIONS, extra_edges=EDGES)
            write_rows(run / "contexts" / "classification.jsonl",
                       [{"entry_id": e, "resource_kind": "network", "delivery": "stream"} for e in ("e-line", "e-body")])
            write_rows(run / "contexts" / "locator.jsonl", [
                {"entry_id": "e-line", "interpreter_function_ids": ["fn-parse_request"]},
                {"entry_id": "e-body", "interpreter_function_ids": ["fn-parse_reply"]}])   # the server-side parser
            write_rows(run / "contexts" / "peers.jsonl", [
                {"entry_id": "e-line", "peers": [client(["fn-parse_request"])]},
                {"entry_id": "e-body", "peers": [client(["fn-serve"])]}])
            result = build_contexts(run)
        self.assertEqual(len(result["contexts"]), 1)
        context = result["contexts"][0]
        self.assertEqual({m.entry_id for m in context.entries}, {"e-line", "e-body"})
        self.assertNotIn("parse_reply", context.interpreter_functions)


class PeerSeedTests(unittest.TestCase):
    def test_trigger_alone_is_not_a_seed_and_harness_bytes_skip_the_trigger(self):
        item = lambda *texts: {"name": "n", "rationale": "", "evidence": [],
                               "messages": [{"encoding": "text", "data": t} for t in texts]}
        seeds = seeds_from_items([item("GET http://{PEER_HOST}:{PEER_PORT}/ HTTP/1.0\\r\\n\\r\\n"),
                                  item("GET http://{PEER_HOST}:{PEER_PORT}/ HTTP/1.0\\r\\n\\r\\n",
                                       "HTTP/1.0 200 OK\\r\\n", "\\r\\nbody")],
                                 context_id="c", delivery="peer_stream", origin="generator")
        self.assertEqual(len(seeds), 1)
        self.assertEqual(seeds[0].harness_bytes, b"HTTP/1.0 200 OK\r\n\r\nbody")


PROXY = textwrap.dedent("""
    import re, socket, sys
    listener = socket.create_server(("127.0.0.1", int(sys.argv[1])))
    while True:
        client, _ = listener.accept()
        request = client.recv(4096)
        host, port = re.search(rb"http://([^:/]+):(\\d+)/", request).groups()
        upstream = socket.create_connection((host.decode(), int(port)))
        upstream.sendall(b"GET / HTTP/1.0\\r\\n\\r\\n")
        reply = b""
        while chunk := upstream.recv(4096):
            reply += chunk
        upstream.close()
        client.sendall(b"PROXIED:" + reply)
        client.close()
""")


class PeerRunnerTests(unittest.TestCase):
    def test_runner_plays_the_server_the_program_connects_to(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "proxy.py"
            script.write_text(PROXY)
            import socket
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            spec = ProgramSpec(command=[sys.executable, str(script), str(port)], cwd=Path(tmp),
                               delivery="peer_stream", port=port, step_timeout=0.5)
            trigger = b"GET http://{PEER_HOST}:{PEER_PORT}/ HTTP/1.0\r\n\r\n"
            observation = asyncio.run(ProgramRunner(spec).run([trigger, b"HTTP/1.0 200 OK\r\n", b"\r\nhello"]))
            self.assertEqual(observation.error, "")
            self.assertEqual(observation.responses[0], b"GET / HTTP/1.0\r\n\r\n")   # what the program asked the peer
            self.assertEqual(observation.responses[-1], b"PROXIED:HTTP/1.0 200 OK\r\n\r\nhello")
            whole = asyncio.run(ProgramRunner(spec).run([trigger, b"HTTP/1.0 200 OK\r\n", b"\r\nhello"], paced=False))
            self.assertEqual(whole.responses[-1], b"PROXIED:HTTP/1.0 200 OK\r\n\r\nhello")


if __name__ == "__main__":
    unittest.main()
