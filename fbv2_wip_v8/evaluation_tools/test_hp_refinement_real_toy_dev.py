"""Actual public-toy runtime check of the scripted Code-Augur refinement loop."""
from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from hp_refinement_real_toy_dev import CLANG, run_control


@unittest.skipUnless(CLANG.is_file(), "local Clang evaluation wrapper required")
class HPRefinementRealToyTests(unittest.TestCase):
    def test_scripted_refinement_runs_two_real_guided_jobs(self):
        with TemporaryDirectory() as temp:
            output = Path(temp) / "public_toy"
            receipt = asyncio.run(run_control(output))
            self.assertEqual(receipt["kind"],
                             "PUBLIC_TOY_HP_SCRIPTED_REFINEMENT_CONTROL_V2")
            self.assertEqual(receipt["status"], "CONTROLLED_POSITIVE_ONLY")
            self.assertEqual(receipt["model_calls"], 0)
            self.assertEqual(receipt["first_assertion"]["status"], "VIOLATED")
            self.assertEqual(receipt["first_assertion"]["triage"],
                             "OVERSTRONG_ASSUMPTION")
            self.assertEqual(receipt["first_assertion"]["guided_status"],
                             "ASSERTION_WITNESS_OBSERVED")
            self.assertEqual(receipt["reanalysis_roles"],
                             ["function_analysis", "assertion_generator"])
            self.assertEqual(receipt["revised_assertion"]["status"],
                             "HELD_FOR_EXECUTION")
            self.assertEqual(receipt["revised_assertion"]["guided_status"], "RAN")
            self.assertNotEqual(receipt["first_assertion"]["guided_artifact"],
                                receipt["revised_assertion"]["guided_artifact"])
            self.assertFalse(receipt["vulnerability_verified"])
            for replay in receipt["original_replays"].values():
                self.assertEqual(replay["exit_code"], 0)
                self.assertIsNone(replay["sanitizer"])
                self.assertEqual(json.loads((output / replay["runtime_artifact"]).read_text())
                                 ["binary_sha256"], replay["binary_sha256"])
            for relative, expected_sha in {
                **receipt["source_and_input_sha256"],
                **receipt["artifact_sha256"],
            }.items():
                self.assertEqual(hashlib.sha256(
                    (output / relative).read_bytes()).hexdigest(), expected_sha)
            recorded = set(receipt["source_and_input_sha256"]) | \
                set(receipt["artifact_sha256"]) | {"CONTROL_RECEIPT.json"}
            actual = {str(path.relative_to(output)) for path in output.rglob("*")
                      if path.is_file()}
            self.assertEqual(actual, recorded)
            self.assertEqual(json.loads(
                (output / "CONTROL_RECEIPT.json").read_text()), receipt)

    def test_existing_output_is_rejected_before_target_work(self):
        with TemporaryDirectory() as temp:
            output = Path(temp) / "public_toy"
            output.mkdir()
            (output / "sentinel").write_bytes(b"keep")
            with self.assertRaisesRegex(ValueError, "start empty"):
                asyncio.run(run_control(output))
            self.assertEqual((output / "sentinel").read_bytes(), b"keep")
            self.assertFalse((output / "target.c").exists())


if __name__ == "__main__":
    unittest.main()
