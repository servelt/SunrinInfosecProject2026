"""A detected sanitizer crash must retain the report used by later gates."""

import sys
import tempfile
import unittest
from pathlib import Path

from vulnerabilityanalysis.final_verification import _signature
from vulnerabilityanalysis.runtime import RuntimeExecutor, _frames_by_section


class LongSanitizerLogTests(unittest.TestCase):
    def test_asan_frames_survive_long_following_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            seed = Path(temporary) / "seed"
            seed.write_bytes(b"a")
            script = (
                "import sys; "
                "sys.stderr.write('ERROR: AddressSanitizer: heap-buffer-overflow\\n'"
                "+'#0 0x1 in target /tmp/target.c:42\\n'+'Z'*120000)"
            )
            result = RuntimeExecutor().run([sys.executable, "-c", script, "{input}"], seed)
            self.assertEqual(result.sanitizer, "AddressSanitizer: heap-buffer-overflow")
            self.assertEqual(_frames_by_section(result.stderr)["access"][0][2], 42)
            self.assertEqual(_signature(result), "target:/tmp/target.c:42")


if __name__ == "__main__":
    unittest.main()
