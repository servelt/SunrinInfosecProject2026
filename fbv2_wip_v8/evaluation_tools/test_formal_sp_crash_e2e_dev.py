"""Public UAF toy: formal SP followup handoff in one provider-free sequence.

The controlled Fuzzer callback writes a known crash input. This verifies the
handoff and Gate, not autonomous Fuzzer discovery or Blind 3 performance.
"""
from __future__ import annotations

import asyncio
from dataclasses import asdict
import json
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
import sys
import time
import unittest
from unittest.mock import patch

import blind2_runner_draft as runner

sys.path.insert(0, str(runner.PRODUCT / "tests"))
import test_fuzzer_crash_consumer as consumer_fixture
from vulnerabilityanalysis.models import SuspiciousPoint
from vulnerabilityanalysis.runtime import RuntimeExecutor


class FormalSpCrashEndToEndDevTest(unittest.TestCase):
    def _prepare(self, root: Path, *, fixed: bool = False):
        # Source-backed Gate attribution consults the binary's DWARF sources.
        self.assertIsNotNone(shutil.which("gdb"), "gdb is required for source attribution")
        target = consumer_fixture.OFFICIAL_TARGET
        if fixed:
            target = target.replace("volatile char observed = buffer[0];",
                                    "volatile char observed = 0;")
            self.assertNotEqual(target, consumer_fixture.OFFICIAL_TARGET)
        with patch.object(consumer_fixture, "OFFICIAL_TARGET", target):
            fixture, token = (consumer_fixture.FuzzerCrashConsumerTest()
                              ._real_official_uaf(root / "official"))

        run = root / "run"
        (run / "sp").mkdir(parents=True)
        (run / "poc" / "POV1").mkdir(parents=True)
        (run / "runtime").mkdir(parents=True)
        (run / "run.json").write_text(json.dumps({"run_id": "public-uaf-handoff-dev"}))
        (run / "selection.json").write_text(json.dumps({"function_id": "fn-toy"}))
        point = SuspiciousPoint("SP1", "worker", "direction", "target_operation",
                                "target.c", "target.c:1", "read", "toy hypothesis",
                                [], "input controls marker", [], [], [], [])
        (run / "sp" / "candidates.json").write_text(json.dumps([asdict(point)]))

        clean_seed = run / "poc" / "POV1" / "input.bin"
        clean_seed.write_bytes(b"Y")
        clean = RuntimeExecutor(timeout_seconds=5).run(
            [str(fixture.binary), "{input}"], clean_seed)
        self.assertEqual(clean.exit_code, 0)
        self.assertFalse(clean.sanitizer)
        clean_log = run / "runtime" / "POV1.json"
        clean_log.write_text(json.dumps(asdict(clean)))
        (run / "poc" / "pocs.json").write_text(json.dumps([{
            "sp_id": point.sp_id, "poc_id": "POV1", "status": "EXECUTED_UNRESOLVED",
            "generated_input": str(clean_seed), "execution_log": str(clean_log),
        }]))
        return fixture, token, run

    def _execute(self, fixture, token, run: Path, *, mutate_authority=False):
        if mutate_authority:
            fixture.local.write_bytes(fixture.local.read_bytes() + b"\n/* changed */\n")
        ledger = runner.Ledger(started_at=time.time())
        checkpoint = run.parent / "BUDGET_CHECKPOINT.json"

        class NoModelProvider:
            def __init__(self):
                self.ledger = ledger
            def begin_function(self, _function_id):
                pass
            def end_function(self):
                pass

        async def prepared_scan(folder: Path, *_args, **_kwargs):
            self.assertEqual(folder.resolve(), run.resolve())
            (run / "scan.json").write_text(json.dumps({
                "selected_function_id": "fn-toy", "sp_llm_calls": 0,
                "hp_llm_calls": 0, "effective_sp_llm_call_limit": 4,
                "combined_llm_call_limit": 8,
            }))

        fuzzer_calls = []
        def controlled_fuzzer(point, binary, folder, *_args, seconds: int, **_kwargs):
            self.assertEqual(binary, fixture.binary)
            self.assertEqual(folder.resolve(), run.resolve())
            fuzzer_calls.append((point.sp_id, seconds))
            corpus = run / "corpus" / "candidate" / point.sp_id
            corpus.mkdir(parents=True, exist_ok=True)
            (corpus / "crash-public-uaf").write_bytes(b"X")
            return {"status": "RAN"}

        with (patch.object(runner.scan_mod, "scan_selected", prepared_scan),
              patch.object(runner.scan_mod, "run_targeted_fuzz", controlled_fuzzer)):
            def sequence():
                return asyncio.run(runner.run_sequence(
                    run, NoModelProvider(), ledger, fixture.upstream, checkpoint,
                    max_functions=1,
                    scan_options={
                        "run_command": [str(fixture.binary), "{input}"],
                        "target_binary": fixture.binary,
                        "official_qualification": token,
                    },
                    followup_fuzzer=fixture.binary,
                    consumer_budget={"per_item_wall_seconds": 120,
                                     "combined_wall_seconds": 120},
                ))
            if mutate_authority:
                with self.assertRaisesRegex(ValueError, "pin changed"):
                    sequence()
                rows = None
            else:
                rows = sequence()
        return rows, fuzzer_calls, checkpoint

    def test_public_uaf_controlled_fuzzer_reaches_real_gate(self):
        with TemporaryDirectory() as tmp:
            fixture, token, run = self._prepare(Path(tmp))
            rows, calls, checkpoint = self._execute(fixture, token, run)
            self.assertEqual(calls, [("SP1", 300)])
            self.assertEqual(rows[0]["status"], "COMPLETE")
            self.assertEqual(json.loads((run / "FUNCTION_CHECKPOINT.json").read_text())
                             ["status"], "COMPLETE")
            self.assertTrue(checkpoint.is_file())
            fuzz = json.loads((run / "runtime" / "runner_sp_followup_fuzz.json").read_text())
            self.assertEqual(fuzz[0]["new_fuzzer_crash_count"], 1)
            replay = fuzz[0]["original_replays"][0]
            self.assertEqual(replay["status"], "REPLAYED")
            self.assertTrue(replay["sanitizer"])
            consumed = json.loads((run / "runtime" /
                                   "runner_sp_followup_consumer.json").read_text())
            self.assertEqual(consumed[0]["status"], "VERIFIED")
            canonical = Path(consumed[0]["consumer_result"]["canonical_crash_artifact"])
            crash = json.loads(canonical.read_text())
            self.assertEqual(crash["independent_verification_status"], "VERIFIED")
            self.assertTrue(Path(crash["independent_root_cause_artifact"]).is_file())
            self.assertTrue(Path(crash["independent_security_artifact"]).is_file())
            runtime = Path(consumed[0]["consumer_result"]["runtime_artifact"])
            triage = json.loads(runtime.read_text())["crash_triage"]
            self.assertEqual(triage["category"], "TARGET_CRASH")
            self.assertEqual(triage["source_provenance"]["method"],
                             "DWARF_PATH_RELATIVE_PATH_SHA256")
            scan = json.loads((run / "scan.json").read_text())
            self.assertEqual(scan["verified_crash_ids"],
                             [consumed[0]["consumer_result"]["canonical_crash_id"]])

    def test_fixed_build_has_observation_but_no_verified(self):
        with TemporaryDirectory() as tmp:
            fixture, token, run = self._prepare(Path(tmp), fixed=True)
            rows, calls, _ = self._execute(fixture, token, run)
            self.assertEqual(calls, [("SP1", 300)])
            self.assertEqual(rows[0]["status"], "COMPLETE")
            consumed = json.loads((run / "runtime" /
                                   "runner_sp_followup_consumer.json").read_text())
            self.assertEqual(consumed[0]["status"],
                             "BLOCKED_ORIGINAL_REPLAY_NOT_REPRODUCED")
            self.assertFalse(json.loads((run / "scan.json").read_text())
                             .get("verified_crash_ids"))

    def test_authority_change_fails_closed_after_controlled_crash(self):
        with TemporaryDirectory() as tmp:
            fixture, token, run = self._prepare(Path(tmp))
            rows, calls, checkpoint = self._execute(
                fixture, token, run, mutate_authority=True)
            self.assertIsNone(rows)
            self.assertEqual(calls, [("SP1", 300)])
            self.assertTrue(checkpoint.is_file())
            self.assertEqual(json.loads((run / "FUNCTION_CHECKPOINT.json").read_text())
                             ["status"], "STOPPED_FAIL_CLOSED")
            self.assertFalse(json.loads((run / "scan.json").read_text())
                             .get("verified_crash_ids"))


if __name__ == "__main__":
    unittest.main()
