"""Real Clang/libFuzzer runtime proof for the supported in-process backend."""

import shutil
import tempfile
import unittest
from pathlib import Path

from harnesscreator.models import HarnessDraft, HarnessManifest, ProjectSpec, SeedSpec
from harnesscreator.runtime.runner import CommandRunner, HarnessVerifierAgent


class BoundaryDynamicFixture(unittest.IsolatedAsyncioTestCase):
    async def test_generated_style_harness_builds_replays_and_fuzzes(self) -> None:
        compiler = shutil.which("clang++")
        if not compiler:
            self.skipTest("clang++/libFuzzer unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.cc").write_text(
                "#include <stddef.h>\n"
                "extern \"C\" int parse_bytes(const unsigned char *p, size_t n) {\n"
                "  return n > 0 && p[0] == 'A';\n}\n",
                encoding="utf-8",
            )
            output = root / "artifact"
            output.mkdir()
            code = (
                "#include <stdint.h>\n#include <stddef.h>\n"
                "extern \"C\" int parse_bytes(const unsigned char *, size_t);\n"
                "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {\n"
                "  (void)parse_bytes(Data, Size);\n  return 0;\n}\n"
            )
            (output / "fuzz_target.cc").write_text(code, encoding="utf-8")
            build = [compiler, "-std=c++17", "-g", "-O1", "-no-pie",
                     "-fsanitize=fuzzer,address,undefined",
                     "{harness}", "{source_root}/target.cc", "-o", "{output}/fuzz_target"]
            project = ProjectSpec(
                source_root=root, output_root=root / "runs", build_command=build,
                harness_binary="{output}/fuzz_target", fuzz_seconds=1,
            ).normalized()
            manifest = HarnessManifest(
                harness_id="fixture", source_file="fuzz_target.cc", build_target="fixture",
                engine="libfuzzer", sanitizers=["address", "undefined"],
                execution_model="in_process_reset", headers=[], libraries=[],
                min_size=0, max_size=64, dispatch_strategy="single_input_boundary",
                expected_anchors=[], expected_consumers=[], build_command=build,
                binary="{output}/fuzz_target",
            )
            report = await HarnessVerifierAgent(CommandRunner(), project).verify(
                HarnessDraft(manifest, code), output,
                [SeedSpec("A", b"A".hex(), "application branch")],
                runtime_checks=True,
            )
            self.assertTrue(report.build_ok, report.reason)
            self.assertTrue(report.replays, report.reason)
            self.assertIsNotNone(report.fuzz, (report.reason, report.harness_faults,
                                              [(item.returncode, item.stderr[-500:])
                                               for item in report.replays]))
            self.assertFalse(report.harness_faults, report.reason)


if __name__ == "__main__":
    unittest.main()
