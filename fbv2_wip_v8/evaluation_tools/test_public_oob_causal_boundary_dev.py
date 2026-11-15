"""Real public ASan toy: an access frame is not the earlier bounds cause.

This is a development boundary check. It does not issue privileged dataflow
evidence, exercise the final Gate, or claim autonomous OOB verification.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


PREP = Path(__file__).resolve().parents[1]
PRODUCT = (Path(__file__).resolve().parents[1] / "product")
CLANG = PREP / "review_tools/local_clang/clang"
sys.path.insert(0, str(PRODUCT / "src"))

from vulnerabilityanalysis.final_verification import (  # noqa: E402
    freeze_poc, independent_replay, observed_crash_hypothesis,
    promote_verified, verify_root_cause,
)
from vulnerabilityanalysis.models import (  # noqa: E402
    Evidence, PoC, SecurityPropertyResult, SuspiciousPoint,
)
from vulnerabilityanalysis.runtime import RuntimeExecutor, triage_crash  # noqa: E402


TARGET = """#include <stdlib.h>
#include <stddef.h>
int parse(const unsigned char *data, size_t n) {
  unsigned char *buf = (unsigned char*)malloc(4);
  if (!buf) return 9;
  size_t index = n ? data[0] : 0;
  if (index <= 4) { /* CAUSE: permits one-past index */
    volatile unsigned char value = buf[index]; /* ACCESS */
    (void)value;
  }
  free(buf);
  return 0;
}
"""

HARNESS = """#include <stdio.h>
#include <stddef.h>
int parse(const unsigned char *, size_t);
int main(int argc, char **argv) {
  if (argc != 2) return 2;
  FILE *f = fopen(argv[1], "rb");
  if (!f) return 3;
  unsigned char input[1];
  size_t n = fread(input, 1, 1, f);
  fclose(f);
  return parse(input, n);
}
"""


def _line(marker: str) -> int:
    return next(i for i, line in enumerate(TARGET.splitlines(), 1) if marker in line)


class PublicOobCausalBoundaryDevTest(unittest.TestCase):
    def test_real_asan_access_frame_does_not_prove_earlier_bounds_cause(self):
        if not CLANG.is_file() or not shutil.which("gdb"):
            self.skipTest("local Clang and GDB are required for source-backed ASan control")
        with TemporaryDirectory(prefix="public-oob-causal-") as tmp:
            root = Path(tmp)
            source, harness, binary = root / "target.c", root / "harness.c", root / "toy"
            source.write_text(TARGET, encoding="utf-8")
            harness.write_text(HARNESS, encoding="utf-8")
            subprocess.run([str(CLANG), "-O0", "-g", "-fno-omit-frame-pointer",
                            "-fsanitize=address", str(source), str(harness), "-o",
                            str(binary)], capture_output=True, text=True, check=True,
                           timeout=30)
            normal, trigger = root / "normal.bin", root / "trigger.bin"
            normal.write_bytes(b"\x03")
            trigger.write_bytes(b"\x04")
            executor = RuntimeExecutor(timeout_seconds=8)
            normal_result = executor.run([str(binary), "{input}"], normal)
            result = executor.run([str(binary), "{input}"], trigger)
            self.assertEqual(normal_result.exit_code, 0)
            self.assertFalse(normal_result.sanitizer)
            self.assertIn("heap-buffer-overflow", result.sanitizer or "")

            cause_line, access_line = _line("CAUSE:"), _line("ACCESS */")
            self.assertNotEqual(cause_line, access_line)
            result.crash_triage = triage_crash(
                result, str(root), str(harness), f"target.c:{cause_line}",
                "parse", target_binary=binary)
            self.assertEqual(result.crash_triage["category"], "TARGET_CRASH")
            self.assertEqual(result.crash_triage["source_provenance"]["sha256"],
                             hashlib.sha256(source.read_bytes()).hexdigest())

            point = SuspiciousPoint(
                "sp-public", "worker", "direction", "parse", "target.c",
                f"target.c:{cause_line}", "one-past bounds check",
                "heap buffer overflow when input index equals allocation size",
                [], "first callback byte controls index", [], [], [], [],
                security_property="memory safety")
            # This evaluator-written JSON has no product issuer or execution
            # identity. Calling it DATAFLOW must not give it root-cause authority.
            artifact = root / "unissued-dataflow.json"
            artifact.write_text('{"index":4,"bound":4}', encoding="utf-8")
            unissued = Evidence("e-public", "DATAFLOW", str(artifact), point.sp_id,
                                "claim only", str(artifact), True, False)
            root_cause = verify_root_cause(
                point, result, root, harness, dataflow_evidence=[unissued])
            self.assertEqual(root_cause.crash_relation, "STACK_RELATED")
            self.assertEqual(root_cause.verdict, "UNKNOWN")

            poc = PoC("p-public", point.sp_id, "def build():\n    return bytes([4])\n",
                      str(trigger), [str(binary), "{input}"], "public control")
            fixed = freeze_poc(
                poc, point, binary, result.sanitizer, "public bounds check",
                f"parse:{source}:{access_line}", root / "fixed")
            replay = independent_replay(fixed, root / "replay", timeout_seconds=8)
            self.assertEqual(replay.status, "REPRODUCED")
            # Grant every other Gate premise in this isolated negative check.
            # Even then, a source cause without a trusted causal link cannot
            # become VERIFIED. This is not a real security-evidence issuer.
            assumed_security = SecurityPropertyResult(
                point.sp_id, "CONFIRMED", ["assumed-input"], ["assumed-harness"],
                ["assumed-impact"], [])
            self.assertFalse(promote_verified(
                point, result, root_cause, fixed, replay, assumed_security))
            self.assertNotEqual(point.status, "VERIFIED")

            observed, provenance = observed_crash_hypothesis(result, root, binary)
            self.assertIsNone(observed)
            self.assertEqual(provenance["blocker"], "UNSUPPORTED_CRASH_TYPE")

            # The same oracle would mark the access line EXACT. It identifies
            # the observed fault, so copying that line into a newly invented
            # cause cannot establish the preceding check as the root cause.
            point.code_location = f"target.c:{access_line}"
            access_only = verify_root_cause(point, result, root, harness)
            self.assertEqual(access_only.crash_relation, "EXACT")
            self.assertEqual(access_only.verdict, "CONFIRMED")


if __name__ == "__main__":
    unittest.main()
