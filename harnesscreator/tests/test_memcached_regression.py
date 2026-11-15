"""Opt-in integration test against a real local memcached checkout."""

import os
import unittest
from pathlib import Path

from harnesscreator.models import EntryRecord, EntrySiteKind, Evidence, ProjectSpec, Verdict
from harnesscreator.runtime.memcached_regression import (
    regression_cases_for_entry, run_memcached_regression, runtime_hints_for_entry,
)
from harnesscreator.runtime.boundary import BoundaryTrialRunner
from harnesscreator.agents.input_surfaces import InputSurfaceCase


class MemcachedOriginalTest(unittest.IsolatedAsyncioTestCase):
    async def test_runtime_hints_do_not_cross_tcp_udp_request_windows(self) -> None:
        checks = [
            {"name": "tcp_version", "status": "OBSERVED_EXPECTED",
             "trace_hits_by_request": [["tcp_read", "process_command_ascii"]]},
            {"name": "udp_version", "status": "OBSERVED_EXPECTED",
             "trace_hits_by_request": [["tcp_read", "try_read_udp", "process_command_ascii"]]},
        ]
        ids = {name: [name + "-id"] for name in (
            "tcp_read", "try_read_udp", "process_command_ascii",
        )}
        tcp_reached, tcp_hints = runtime_hints_for_entry("tcp_read", "tcp", checks, ids)
        udp_reached, udp_hints = runtime_hints_for_entry("try_read_udp", "udp", checks, ids)
        self.assertTrue(tcp_reached)
        self.assertTrue(udp_reached)
        self.assertEqual(tcp_hints, ["process_command_ascii-id"])
        self.assertEqual(udp_hints, ["process_command_ascii-id"])
        self.assertFalse(runtime_hints_for_entry("tcp_read", "udp", checks, ids)[0])

    async def test_udp_original_trial_waits_for_shared_listener_startup(self) -> None:
        root = os.environ.get("HC_MEMCACHED_ROOT")
        if not root:
            self.skipTest("set HC_MEMCACHED_ROOT to run real daemon regression")
        source = Path(root)
        project = ProjectSpec(
            source_root=source, output_root=source / "hc-runs",
            scenario_command=[str(source / "memcached"), "-u", "root", "-l", "127.0.0.1",
                              "-p", "23880", "-U", "23880", "-t", "1"],
            scenario_channel="auto", scenario_port=23880,
        ).normalized()
        udp_entry = EntryRecord(
            entry_id="udp-entry", candidate_id="candidate", status=Verdict.VERIFIED,
            entry_function_id="udp-fn", source_api="recvfrom", channel_kind="udp",
            attacker_control="datagram", provenance_path=[], consumer_hints=[],
            evidence=[Evidence("source", "udp-fn", "memcached.c", 1, "recvfrom")],
            unknowns=[], verifier_confidence=1.0, entry_line=1,
            site_kind=EntrySiteKind.DIRECT_ACQUISITION,
        )
        packet = b"\x31\x42\x00\x00\x00\x01\x00\x00version\r\n"
        case = InputSurfaceCase(
            case_id="udp-version", entry_id=udp_entry.entry_id,
            entry_function_id=udp_entry.entry_function_id, source_api="recvfrom",
            channel_kind="udp", data_hex=packet.hex(), origin="fixed-regression",
            rationale="UDP version",
        )
        trial = await BoundaryTrialRunner(project).run(case, udp_entry)
        self.assertEqual(trial.status, "OBSERVED_RESPONSE", trial.failure_reason)
        self.assertTrue(bytes.fromhex(trial.response_hex)[8:].startswith(b"VERSION "))

    async def test_only_observed_matching_fixed_vectors_are_replayed(self) -> None:
        tcp = EntryRecord(
            entry_id="tcp-entry", candidate_id="candidate", status=Verdict.VERIFIED,
            entry_function_id="tcp-fn", source_api="read", channel_kind="tcp",
            attacker_control="socket", provenance_path=[], consumer_hints=[],
            evidence=[Evidence("source", "tcp-fn", "memcached.c", 1, "read")],
            unknowns=[], verifier_confidence=1.0, entry_line=1,
            site_kind=EntrySiteKind.DIRECT_ACQUISITION,
        )
        checks = [
            {"name": "tcp_version", "status": "OBSERVED_EXPECTED",
             "requests_hex": [b"version\r\n".hex()]},
            {"name": "tcp_set_get_same_connection", "status": "OBSERVED_EXPECTED",
             "requests_hex": [b"set k 0 0 1\r\na\r\n".hex(), b"get k\r\n".hex()]},
            {"name": "udp_version", "status": "OBSERVED_EXPECTED",
             "requests_hex": [b"udp".hex()]},
        ]
        cases = regression_cases_for_entry(tcp, "tcp_read", checks)
        self.assertEqual(len(cases), 2)
        self.assertEqual(bytes.fromhex(cases[1].data_hex),
                         b"set k 0 0 1\r\na\r\nget k\r\n")
        self.assertTrue(all(case.origin == "memcached_fixed_regression" for case in cases))

    async def test_tcp_udp_and_set_get_on_one_server(self) -> None:
        root = os.environ.get("HC_MEMCACHED_ROOT")
        if not root:
            self.skipTest("set HC_MEMCACHED_ROOT to run real daemon regression")
        source = Path(root)
        project = ProjectSpec(
            source_root=source, output_root=source / "hc-runs",
            scenario_command=[str(source / "memcached"), "-u", "root", "-l", "127.0.0.1",
                              "-p", "23879", "-U", "23879", "-t", "1"],
            scenario_channel="auto", scenario_port=23879,
        ).normalized()
        gdb_trace = os.environ.get("HC_MEMCACHED_GDB") == "1"
        checks = await run_memcached_regression(project, gdb_trace=gdb_trace)
        self.assertEqual([item.name for item in checks], [
            "tcp_version", "tcp_set_get_same_connection", "udp_version",
        ])
        self.assertTrue(all(item.status == "OBSERVED_EXPECTED" for item in checks), checks)
        self.assertEqual(len({item.same_server_pid for item in checks}), 1)
        self.assertTrue(all(not item.handler_attributed for item in checks))
        if gdb_trace:
            self.assertIn("tcp_read", checks[0].trace_hits_by_request[0])
            self.assertIn("process_command_ascii", checks[0].trace_hits_by_request[0])
            self.assertIn("process_update_command", checks[1].trace_hits_by_request[0])
            self.assertTrue({"process_get_command", "process_get_cmd"}
                            & set(checks[1].trace_hits_by_request[1]))
            self.assertIn("try_read_udp", checks[2].trace_hits_by_request[0])
            self.assertIn("process_command_ascii", checks[2].trace_hits_by_request[0])


if __name__ == "__main__":
    unittest.main()
