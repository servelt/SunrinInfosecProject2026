"""Provider-free public Phase 1 pin and tamper controls; no Scan or model turn."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from dev_no_k_three_function_gate import make_public_fixture
from dev_phase1_chain_pin import issue_pin, verify_pin
from vulnerabilityanalysis.workflow import continue_phase1, run_phase1


class Phase1ChainPinTests(unittest.TestCase):
    def _fresh(self, root: Path, *, hp_state: bool = False) -> tuple[Path, Path, Path, Path]:
        artifact, repo, plan = make_public_fixture(root / "fixture")
        run = run_phase1(artifact, root / "runs", target_repository=repo,
                         direction_plan=plan,
                         selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV",
                         hp_project_state_dev=hp_state)
        pin_dir = root / "evaluator_pins"
        pin_dir.mkdir(mode=0o700)
        return artifact, plan, run, pin_dir

    def test_public_three_function_chain_is_pinned_before_each_model_turn(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            _, _, first, pin_dir = self._fresh(root)
            first_pin = pin_dir / "001.json"
            first_receipt = issue_pin(first, first_pin)
            self.assertEqual(first_receipt["selected_function_id"], "fn-a")
            self.assertEqual(first_receipt["state"], "PRE_MODEL")
            self.assertEqual(first_pin.stat().st_mode & 0o777, 0o600)
            self.assertIsNone(first_receipt["parent_pin_sha256"])
            self.assertFalse((first / "scan.json").exists())
            selection = json.loads((first / "selection.json").read_text())
            (first / "scan.json").write_text(json.dumps({
                "selected_function": selection["function_name"],
                "selected_function_id": selection["function_id"],
                "target_repository": str(root / "fixture"),
                "synthetic_identity_only": True,
            }, sort_keys=True) + "\n")
            with self.assertRaisesRegex(ValueError, "pre-model"):
                verify_pin(first_pin)
            second = continue_phase1(first)
            second_pin = pin_dir / "002.json"
            second_receipt = issue_pin(second, second_pin, parent_pin=first_pin)
            self.assertEqual(second_receipt["selected_function_id"], "fn-c")
            self.assertEqual(second_receipt["parent_run_id"], first.name)
            self.assertEqual(second_receipt["parent_pin_sha256"],
                             hashlib.sha256(first_pin.read_bytes()).hexdigest())
            self.assertEqual(second_receipt["parent_scan_sha256"],
                             hashlib.sha256((first / "scan.json").read_bytes()).hexdigest())
            self.assertEqual(verify_pin(second_pin), second_receipt)
            self.assertFalse((second / "scan.json").exists())

    def test_issue_is_single_write_and_requires_pre_model_state(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            _, _, run, pin_dir = self._fresh(root)
            pin = pin_dir / "001.json"
            issue_pin(run, pin)
            before = pin.read_bytes()
            with self.assertRaises(FileExistsError):
                issue_pin(run, pin)
            self.assertEqual(pin.read_bytes(), before)
            (run / "scan.json").write_text("{}\n")
            with self.assertRaisesRegex(ValueError, "pre-model"):
                issue_pin(run, pin_dir / "002.json")

    def test_digest_and_identity_tampering_fail_closed(self):
        for file_name in ("run.json", "direction_plan.json", "function_pool.json",
                          "selection.json", "workers.json", "directions.json"):
            with self.subTest(file_name=file_name), TemporaryDirectory() as temp:
                root = Path(temp)
                _, _, run, pin_dir = self._fresh(root)
                pin = pin_dir / "001.json"
                issue_pin(run, pin)
                with (run / file_name).open("ab") as stream:
                    stream.write(b" \n")
                with self.assertRaises(ValueError):
                    verify_pin(pin)
        with TemporaryDirectory() as temp:
            root = Path(temp)
            artifact, plan, run, pin_dir = self._fresh(root)
            pin = pin_dir / "001.json"
            issue_pin(run, pin)
            (artifact / "manifest.json").write_text("{}\n")
            with self.assertRaises(ValueError):
                verify_pin(pin)
            (plan).write_text("{}\n")
            with self.assertRaises(ValueError):
                verify_pin(pin)

    def test_symlinks_permissions_and_pin_value_change_are_rejected(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            _, _, run, pin_dir = self._fresh(root)
            pin = pin_dir / "001.json"
            issue_pin(run, pin)
            alias = pin_dir / "alias.json"
            alias.symlink_to(pin)
            with self.assertRaisesRegex(ValueError, "symlink"):
                verify_pin(alias)
            os.chmod(pin, 0o644)
            with self.assertRaisesRegex(ValueError, "0600"):
                verify_pin(pin)
            os.chmod(pin, 0o600)
            record = json.loads(pin.read_text())
            record["selected_function_id"] = "fn-b"
            pin.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
            with self.assertRaises(ValueError):
                verify_pin(pin)

    def test_phase1_file_symlink_is_rejected_even_with_same_bytes(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            _, plan, run, pin_dir = self._fresh(root)
            (run / "direction_plan.json").unlink()
            (run / "direction_plan.json").symlink_to(plan)
            with self.assertRaisesRegex(ValueError, "symlink"):
                issue_pin(run, pin_dir / "001.json")

    def test_parent_scan_and_pin_chain_cannot_change_after_continuation(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            _, _, first, pin_dir = self._fresh(root)
            first_pin = pin_dir / "001.json"
            issue_pin(first, first_pin)
            selection = json.loads((first / "selection.json").read_text())
            (first / "scan.json").write_text(json.dumps({
                "selected_function": selection["function_name"],
                "selected_function_id": selection["function_id"],
                "target_repository": str(root / "fixture"),
                "synthetic_identity_only": True,
            }, sort_keys=True) + "\n")
            second = continue_phase1(first)
            second_pin = pin_dir / "002.json"
            issue_pin(second, second_pin, parent_pin=first_pin)
            (first / "scan.json").write_text((first / "scan.json").read_text() + " \n")
            with self.assertRaises(ValueError):
                verify_pin(second_pin)
            (first / "scan.json").write_text(json.dumps({
                "selected_function": selection["function_name"],
                "selected_function_id": selection["function_id"],
                "target_repository": str(root / "fixture"),
                "synthetic_identity_only": True,
            }, sort_keys=True) + "\n")
            first_pin.write_bytes(first_pin.read_bytes() + b" \n")
            with self.assertRaises(ValueError):
                verify_pin(second_pin)

    def test_pin_copy_or_target_repository_location_is_rejected(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            _, _, run, pin_dir = self._fresh(root)
            pin = pin_dir / "001.json"
            issue_pin(run, pin)
            copied = pin_dir / "copy.json"
            copied.write_bytes(pin.read_bytes())
            os.chmod(copied, 0o600)
            with self.assertRaises(ValueError):
                verify_pin(copied)
            in_target = root / "fixture" / "private_pins"
            in_target.mkdir(mode=0o700)
            with self.assertRaisesRegex(ValueError, "outside run"):
                issue_pin(run, in_target / "001.json")

    def test_hp_state_files_are_pinned_in_initial_and_continuation_runs(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            _, _, first, pin_dir = self._fresh(root, hp_state=True)
            first_pin = pin_dir / "001.json"
            initial = issue_pin(first, first_pin)
            self.assertIn("hp_project_state.json", initial["phase1_files_sha256"])
            selection = json.loads((first / "selection.json").read_text())
            (first / "scan.json").write_text(json.dumps({
                "selected_function": selection["function_name"],
                "selected_function_id": selection["function_id"],
                "target_repository": str(root / "fixture"),
                "synthetic_identity_only": True,
            }, sort_keys=True) + "\n")
            second = continue_phase1(first)
            second_pin = pin_dir / "002.json"
            following = issue_pin(second, second_pin, parent_pin=first_pin)
            self.assertIn("hp_guided_corpus", following["phase1_files_sha256"])
            self.assertEqual(verify_pin(second_pin), following)


if __name__ == "__main__":
    unittest.main()
