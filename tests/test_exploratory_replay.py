"""Observed original requests may diagnose a draft without certifying it."""
from __future__ import annotations

import tempfile
import unittest
import shutil
from pathlib import Path
from unittest.mock import AsyncMock, patch

from harnesscreator.models import (
    CommandReport, HarnessDraft, HarnessManifest, ProjectSpec, SeedSpec,
)
from harnesscreator.runtime.runner import CommandRunner, HarnessVerifierAgent, write_seed_suite


class RecordingRunner:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    async def run(self, argv: list[str], **kwargs) -> CommandReport:
        self.commands.append(argv)
        return CommandReport(
            argv=argv, returncode=0, stdout="ok", stderr="",
            duration_seconds=0.001,
        )


class ExploratoryReplayTest(unittest.IsolatedAsyncioTestCase):
    async def test_real_clang_harness_replays_observed_bytes(self):
        if shutil.which("clang") is None:
            self.skipTest("clang with libFuzzer is required")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            attempt = root / "attempt"
            attempt.mkdir()
            code = (
                "#include <stddef.h>\n#include <stdint.h>\n"
                "int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) "
                "{ return Size > 0 && Data[0] == 'G' ? 0 : 0; }\n"
            )
            (attempt / "fuzz_target.c").write_text(code)
            manifest = HarnessManifest(
                harness_id="real-observed", source_file="fuzz_target.c",
                build_target="test", engine="libfuzzer", sanitizers=["address"],
                execution_model="in_process_reset", headers=[], libraries=[],
                min_size=1, max_size=64, dispatch_strategy="one_scenario_per_harness",
                expected_anchors=[], expected_consumers=[],
                build_command=[
                    # Keep this tiny Linux/WSL ASan fixture at a fixed load
                    # address; its PIE build intermittently dies before main.
                    "clang", "-g", "-O1", "-fsanitize=fuzzer,address", "-no-pie",
                    "{harness}", "-o", "{output}/fuzzer",
                ],
                binary="{output}/fuzzer",
            )
            project = ProjectSpec(source_root=root, output_root=root / "runs").normalized()
            result = await HarnessVerifierAgent(CommandRunner(), project).verify(
                HarnessDraft(manifest=manifest, code=code), attempt,
                [SeedSpec("observed", b"GET key\r\n".hex(), "original request")],
                replay_only=True,
            )
            self.assertTrue(result.build_ok, result.reason)
            self.assertEqual(len(result.replays), 1, result.reason)
            self.assertEqual(
                result.replays[0].returncode, 0,
                result.replays[0].stdout + "\n" + result.replays[0].stderr,
            )
            self.assertFalse(result.qualified)
            self.assertIsNone(result.fuzz)

    async def test_command_backend_replays_witness_without_fuzzing_or_qualification(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            attempt = root / "attempt"
            attempt.mkdir()
            (attempt / "fuzz_target.c").write_text("int LLVMFuzzerTestOneInput(void);\n")
            binary = root / "fuzzer"
            binary.write_bytes(b"__asan_init")
            manifest = HarnessManifest(
                harness_id="observed", source_file="fuzz_target.c",
                build_target="test", engine="libfuzzer", sanitizers=["address"],
                execution_model="in_process_reset", headers=[], libraries=[],
                min_size=1, max_size=64, dispatch_strategy="one_scenario_per_harness",
                expected_anchors=[], expected_consumers=[],
                build_command=["trusted-build"], binary=str(binary),
            )
            draft = HarnessDraft(manifest=manifest, code="int LLVMFuzzerTestOneInput(void);")
            project = ProjectSpec(source_root=root, output_root=root / "runs").normalized()
            runner = RecordingRunner()
            verifier = HarnessVerifierAgent(runner, project)
            reached = AsyncMock(return_value=([], 1, None))
            witness = SeedSpec("observed", b"GET key\r\n".hex(), "original request")
            with patch.object(verifier, "_verify_reachability", reached):
                result = await verifier.verify(
                    draft, attempt, [witness], replay_only=True,
                )
            self.assertTrue(result.build_ok)
            self.assertFalse(result.qualified)
            self.assertEqual(result.reachable_seed_count, 1)
            self.assertIsNone(result.fuzz)
            self.assertEqual(len(result.replays), 1)
            self.assertEqual(len(runner.commands), 2)  # build + one repeated replay
            self.assertEqual(runner.commands[1].count(str(attempt / "seeds" / "llm-observed")), 1)
            self.assertIn("-runs=3", runner.commands[1])
            self.assertEqual((attempt / "seeds" / "llm-observed").read_bytes(),
                             b"GET key\r\n")
            self.assertFalse((attempt / "corpus").exists())
            reached.assert_awaited_once()

    async def test_no_witness_seed_does_not_run_synthetic_defaults(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            seeds = write_seed_suite(root, 1, 5, [], include_defaults=False)
            self.assertEqual(seeds, [])

    async def test_replay_only_cannot_be_combined_with_build_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = ProjectSpec(source_root=root, output_root=root / "runs").normalized()
            verifier = HarnessVerifierAgent(RecordingRunner(), project)
            with self.assertRaisesRegex(ValueError, "requires runtime_checks"):
                await verifier.verify(None, root, runtime_checks=False, replay_only=True)

    async def test_crash_attribution_replays_one_file_three_times(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            seed = root / "seed"
            seed.write_bytes(b"GET key\r\n")
            runner = RecordingRunner()
            project = ProjectSpec(source_root=root, output_root=root / "runs").normalized()
            verifier = HarnessVerifierAgent(runner, project)
            crash = CommandReport(
                argv=[str(root / "fuzzer"), str(seed)], returncode=1,
                stdout="", stderr="crash", duration_seconds=0.001,
            )
            with patch("harnesscreator.runtime.runner.shutil.which", return_value="/usr/bin/gdb"):
                await verifier._attribute(root / "fuzzer", seed, crash, root / "fuzz_target.c")
            self.assertEqual(len(runner.commands), 1)
            self.assertEqual(runner.commands[0].count(str(seed)), 1)
            self.assertIn("-runs=3", runner.commands[0])
