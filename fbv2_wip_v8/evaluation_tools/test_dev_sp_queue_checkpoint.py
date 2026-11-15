"""Provider-free SP queue checkpoint acceptance tests.

These tests describe a non-resumable audit snapshot. They do not authorize a
new model turn or a continuation budget.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dev_sp_queue_checkpoint import read_checkpoint, write_checkpoint


def put(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


class SpQueueCheckpointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.run = self.root / "runs" / "r1"
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.source_file = self.repo / "target.c"
        self.source_file.write_bytes(b"int A(void) { return 0; }\n")
        self.source_manifest = self.root / "SOURCE_MANIFEST.json"
        put(self.source_manifest, {
            "kind": "DEV_SOURCE_MANIFEST_V1", "root": str(self.repo),
            "files": [{"path": "target.c",
                       "sha256": hashlib.sha256(self.source_file.read_bytes()).hexdigest(),
                       "mode": "100644"}],
        })
        self.binary = self.repo / "target-bin"
        self.binary.write_bytes(b"public synthetic binary\n")
        self.freeze = self.root / "FREEZE_MANIFEST.json"
        put(self.freeze, {"kind": "PUBLIC_TOY_FREEZE", "files": []})
        self.qualification = self.root / "QUALIFICATION.json"
        put(self.qualification, {"kind": "PUBLIC_TOY_QUALIFICATION"})
        self.checkpoint = self.root / "SP_QUEUE_CHECKPOINT.json"
        self.execution = {
            "run_command": [str(self.binary), "{input}"],
            "target_binary": str(self.binary),
            "target_repository": str(self.repo),
            "source_revision": "public-toy-revision",
            "source_mode": "DEV_SOURCE_MANIFEST",
            "source_manifest": str(self.source_manifest),
            "runtime_sanitizers": ["ADDRESS"],
            "freeze_manifest": str(self.freeze),
            "official_qualification": str(self.qualification),
            "candidate_budget_policy": "DRAIN_RANKED_DEV",
        }
        put(self.run / "run.json", {"run_id": "r1", "artifact": str(self.repo),
                                    "harness_id": "h1", "selection_policy": "SCORE"})
        put(self.run / "selection.json", {"function_id": "fn-a",
                                          "direction_id": "d1", "function_name": "A"})
        put(self.run / "function_pool.json", [{"function_id": "fn-a",
                                                "direction_id": "d1"}])
        put(self.run / "harness.json", {"harness_id": "h1"})
        put(self.run / "workers.json", [{"worker_id": "w1", "harness_id": "h1"}])
        put(self.run / "directions.json", [{"direction_id": "d1", "worker_id": "w1"}])
        put(self.run / "context.json", [{"kind": "SOURCE", "value": "public toy"}])
        put(self.run / "sp" / "initial_call_context.json", {"context": []})
        put(self.run / "sp" / "turn_budget.json", {"candidate_budget_policy": "DRAIN_RANKED_DEV",
                                                    "max_candidates": 3})
        put(self.run / "sp" / "candidates.json", [
            {"sp_id": "sp-a", "status": "OPEN", "wait_age": 2},
            {"sp_id": "sp-b", "status": "OPEN", "wait_age": 1},
            {"sp_id": "sp-c", "status": "OPEN", "wait_age": 0},
        ])
        put(self.run / "verification" / "sp-a.json", {
            "sp_id": "sp-a", "verdict": "UNKNOWN", "recommended_next_action": "GENERATE_POC"})
        put(self.run / "verification" / "sp-b.json", {
            "sp_id": "sp-b", "verdict": "UNKNOWN", "recommended_next_action": "GENERATE_POC"})
        self.input_path = self.run / "poc" / "poc-a" / "input.bin"
        self.input_path.parent.mkdir(parents=True)
        self.input_path.write_bytes(b"A")
        self.runtime_path = self.run / "runtime" / "poc-a.json"
        put(self.runtime_path, {"exit_code": 0, "sanitizer": None})
        put(self.run / "poc" / "pocs.json", [{
            "poc_id": "poc-a", "sp_id": "sp-a", "status": "INPUT_GENERATED",
            "generated_input": str(self.input_path),
            "execution_log": str(self.runtime_path),
        }])

    def _roundtrip(self) -> dict:
        write_checkpoint(self.run, self.checkpoint, self.execution)
        return read_checkpoint(self.checkpoint, self.run, self.execution)

    def _completed_queue(self) -> None:
        self.execution["candidate_budget_policy"] = "QUEUE_FIRST_DEV"
        put(self.run / "sp" / "turn_budget.json", {
            "candidate_budget_policy": "QUEUE_FIRST_DEV", "max_candidates": 3})
        put(self.run / "source_span.json", {
            "function_id": "fn-a", "source_file": str(self.source_file),
            "start_line": 1, "end_line": 1,
            "source_file_sha256": hashlib.sha256(self.source_file.read_bytes()).hexdigest(),
            "catalog_source_status": "MATCHED_CURRENT_CHECKOUT",
        })
        status = {"sp-a": "POV_ATTEMPTED",
                  "sp-b": "PENDING_POV_BUDGET",
                  "sp-c": "PENDING_VERIFY_BUDGET"}
        put(self.run / "sp" / "queue_first_dev.json", {
            "policy": "QUEUE_FIRST_DEV", "scope": "SP_QUEUE_ONLY",
            "run_state": "COMPLETED", "serial_only": True,
            "auto_resume": False,
            "ranked_candidate_ids": ["sp-a", "sp-b", "sp-c"],
            "pending_verify_ids": ["sp-c"],
            "pending_pov_ids": ["sp-b"], "status": status,
        })
        verification_hashes = {
            item: hashlib.sha256((self.run / "verification" / f"{item}.json").read_bytes()).hexdigest()
            for item in ("sp-a", "sp-b")}
        put(self.run / "scan.json", {
            "candidate_budget_policy": "QUEUE_FIRST_DEV",
            "selected_function_id": "fn-a",
            "target_repository": str(self.repo),
            "queued_sp_ids": ["sp-a", "sp-b", "sp-c"],
            "pending_sp_ids": ["sp-b", "sp-c"],
            "sp_queue_status": status,
            "sp_queue_artifact": str(self.run / "sp" / "queue_first_dev.json"),
            "verification_artifact_sha256": verification_hashes,
            "sp_verification_status": {
                "sp-a": "VERIFIER_EXECUTED", "sp-b": "VERIFIER_EXECUTED",
                "sp-c": "PENDING_VERIFY_BUDGET"},
        })

    def _git(self, *args: str) -> str:
        if shutil.which("git") is None:
            self.skipTest("git not installed")
        result = subprocess.run(["git", *args], cwd=self.repo, check=True,
                                capture_output=True, text=True, timeout=20)
        return result.stdout.strip()

    def _git_source(self) -> None:
        self._git("init", "-q")
        self._git("add", "target.c")
        self._git("-c", "user.name=toy", "-c", "user.email=toy@example.invalid",
                  "commit", "-qm", "first")
        self.execution.update(source_mode="GIT_HEAD", source_manifest=None,
                              source_revision=self._git("rev-parse", "HEAD"))

    def test_all_candidates_and_prior_pov_survive_roundtrip(self) -> None:
        snapshot = self._roundtrip()
        self.assertEqual([row["sp_id"] for row in snapshot["items"]],
                         ["sp-a", "sp-b", "sp-c"])
        self.assertEqual([row["stage"] for row in snapshot["items"]],
                         ["POV_RECORDED", "VERIFIER_RECORDED", "PENDING_VERIFY"])
        self.assertEqual(snapshot["items"][0]["povs"][0]["poc_id"], "poc-a")
        self.assertEqual(snapshot["items"][0]["povs"][0]["input"]["sha256"],
                         "559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd")
        self.assertFalse(snapshot["resume_eligible"])

    def test_completed_queue_snapshot_records_only_unstarted_budget_work(self) -> None:
        self._completed_queue()
        with self.assertRaises(ValueError):
            write_checkpoint(self.run, self.checkpoint, self.execution)
        write_checkpoint(self.run, self.checkpoint, self.execution,
                         completed_queue_first_dev=True)
        snapshot = read_checkpoint(self.checkpoint, self.run, self.execution,
                                   completed_queue_first_dev=True)
        self.assertEqual(snapshot["status"], "COMPLETED_QUEUE_AUDIT_ONLY")
        self.assertFalse(snapshot["resume_eligible"])
        self.assertFalse(snapshot["pretransport_proven"])
        self.assertEqual([(row["sp_id"], row["stage"]) for row in
                          snapshot["pending_budget_work"]], [
            ("sp-b", "PENDING_POV_BUDGET"),
            ("sp-c", "PENDING_VERIFY_BUDGET")])
        self.assertTrue(all(row["physical_attempt_state"] == "UNPROVEN"
                            for row in snapshot["pending_budget_work"]))

    def test_completed_queue_changed_status_or_official_pin_is_rejected(self) -> None:
        self._completed_queue()
        write_checkpoint(self.run, self.checkpoint, self.execution,
                         completed_queue_first_dev=True)
        queue_path = self.run / "sp" / "queue_first_dev.json"
        queue = json.loads(queue_path.read_text())
        queue["status"]["sp-c"] = "REFUTED"
        put(queue_path, queue)
        with self.assertRaises(ValueError):
            read_checkpoint(self.checkpoint, self.run, self.execution,
                            completed_queue_first_dev=True)
        queue["status"]["sp-c"] = "PENDING_VERIFY_BUDGET"
        put(queue_path, queue)
        self.qualification.write_text('{"kind":"changed"}\n')
        with self.assertRaises(ValueError):
            read_checkpoint(self.checkpoint, self.run, self.execution,
                            completed_queue_first_dev=True)

    def test_completed_queue_source_span_must_match_selected_pinned_source(self) -> None:
        self._completed_queue()
        span_path = self.run / "source_span.json"
        span = json.loads(span_path.read_text())
        span["source_file_sha256"] = "0" * 64
        put(span_path, span)
        with self.assertRaisesRegex(ValueError, 'SourceSpan file differs'):
            write_checkpoint(self.run, self.checkpoint, self.execution,
                             completed_queue_first_dev=True)

    def test_completed_queue_source_span_must_fit_pinned_source_lines(self) -> None:
        self._completed_queue()
        span_path = self.run / "source_span.json"
        span = json.loads(span_path.read_text())
        span["start_line"] = 999
        span["end_line"] = 999
        put(span_path, span)
        with self.assertRaisesRegex(ValueError, 'SourceSpan line range'):
            write_checkpoint(self.run, self.checkpoint, self.execution,
                             completed_queue_first_dev=True)

    def test_completed_queue_refuted_verifier_cannot_wait_for_pov(self) -> None:
        self._completed_queue()
        verifier = self.run / "verification" / "sp-b.json"
        put(verifier, {"sp_id": "sp-b", "verdict": "REFUTED",
                       "recommended_next_action": "REFUTE"})
        scan_path = self.run / "scan.json"
        scan = json.loads(scan_path.read_text())
        scan["verification_artifact_sha256"]["sp-b"] = hashlib.sha256(
            verifier.read_bytes()).hexdigest()
        put(scan_path, scan)
        with self.assertRaisesRegex(ValueError, 'pending PoV contradicts Verifier'):
            write_checkpoint(self.run, self.checkpoint, self.execution,
                             completed_queue_first_dev=True)

    def test_completed_queue_refuted_candidate_cannot_wait_for_verifier(self) -> None:
        self._completed_queue()
        candidates_path = self.run / "sp" / "candidates.json"
        candidates = json.loads(candidates_path.read_text())
        candidates[2]["status"] = "REFUTED"
        put(candidates_path, candidates)
        with self.assertRaisesRegex(ValueError, 'pending Verifier contradicts candidate'):
            write_checkpoint(self.run, self.checkpoint, self.execution,
                             completed_queue_first_dev=True)

    def test_completed_queue_inflight_model_state_is_not_claimable(self) -> None:
        self._completed_queue()
        queue_path = self.run / "sp" / "queue_first_dev.json"
        scan_path = self.run / "scan.json"
        queue = json.loads(queue_path.read_text())
        scan = json.loads(scan_path.read_text())
        queue["status"]["sp-c"] = "IN_FLIGHT_VERIFY"
        queue["pending_verify_ids"] = []
        scan["sp_queue_status"] = queue["status"]
        scan["pending_sp_ids"] = ["sp-b"]
        put(queue_path, queue)
        put(scan_path, scan)
        with self.assertRaisesRegex(ValueError, 'uncertain remote state'):
            write_checkpoint(self.run, self.checkpoint, self.execution,
                             completed_queue_first_dev=True)

    def test_completed_queue_requires_qualification_and_cannot_claim_transport(self) -> None:
        self._completed_queue()
        self.execution['official_qualification'] = None
        with self.assertRaisesRegex(ValueError, 'requires qualification'):
            write_checkpoint(self.run, self.checkpoint, self.execution,
                             completed_queue_first_dev=True)
        self.execution['official_qualification'] = str(self.qualification)
        write_checkpoint(self.run, self.checkpoint, self.execution,
                         completed_queue_first_dev=True)
        stored = json.loads(self.checkpoint.read_text())
        stored['pending_budget_work'][0]['physical_attempt_state'] = 'NOT_SENT'
        put(self.checkpoint, stored)
        with self.assertRaises(ValueError):
            read_checkpoint(self.checkpoint, self.run, self.execution,
                            completed_queue_first_dev=True)

    def test_provider_free_product_queue_can_be_snapshotted_without_resume(self) -> None:
        product = Path(os.environ.get(
            'VA_PRODUCT_ROOT',
            '/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis'))
        if not (product / 'tests' / 'test_sp_queue_first_dev.py').is_file():
            self.skipTest('live product Queue-first fixture unavailable')
        product_paths = [str(product / 'src'), str(product / 'tests')]
        sys.path[:0] = product_paths
        self.addCleanup(lambda: [sys.path.remove(path) for path in product_paths])
        from test_sp_queue_first_dev import QueueFirstDevTest

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scan, provider, ledger, run = QueueFirstDevTest()._external_run(
                root, maximum=3)
            self.assertGreater(len(provider.calls), 0)
            source_manifest = root / 'SOURCE_MANIFEST.json'
            put(source_manifest, {'kind': 'DEV_SOURCE_MANIFEST_V1',
                                  'root': str(root), 'files': [{
                'path': name,
                'sha256': hashlib.sha256((root / name).read_bytes()).hexdigest(),
                'mode': '100644',
            } for name in ('fuzz.c', 'target.c')]})
            freeze, qualification = root / 'FREEZE.json', root / 'QUALIFICATION.json'
            put(freeze, {'kind': 'SYNTHETIC_FREEZE'})
            put(qualification, {'kind': 'SYNTHETIC_QUALIFICATION'})
            execution = {
                'run_command': ['/usr/bin/true', '{input}'],
                'target_binary': str(root / 'target.bin'),
                'target_repository': str(root),
                'source_revision': 'public-toy',
                'source_mode': 'DEV_SOURCE_MANIFEST',
                'source_manifest': str(source_manifest),
                'runtime_sanitizers': [],
                'freeze_manifest': str(freeze),
                'official_qualification': str(qualification),
                'candidate_budget_policy': 'QUEUE_FIRST_DEV',
            }
            checkpoint = root / 'PRODUCT_QUEUE_SNAPSHOT.json'
            write_checkpoint(run, checkpoint, execution,
                             completed_queue_first_dev=True)
            snapshot = read_checkpoint(checkpoint, run, execution,
                                       completed_queue_first_dev=True)
            self.assertEqual([row['sp_id'] for row in snapshot['pending_budget_work']],
                             [item for item in scan['queued_sp_ids']
                              if scan['sp_queue_status'][item] in
                              {'PENDING_VERIFY_BUDGET', 'PENDING_POV_BUDGET'}])
            self.assertFalse(snapshot['resume_eligible'])
            self.assertTrue(all(row['physical_attempt_state'] == 'UNPROVEN'
                                for row in snapshot['pending_budget_work']))

    def test_prior_pov_files_without_product_index_are_rejected(self) -> None:
        # scan.py writes poc/pocs.json after the entire SP loop. If a later
        # candidate blocks, this earlier input/runtime may exist without the
        # product's candidate-to-PoV receipt. Names cannot prove completion.
        (self.run / "poc" / "pocs.json").unlink()
        (self.run / "poc" / "poc-a" / "generate.py").write_text(
            "def build():\n    return b'A'\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            write_checkpoint(self.run, self.checkpoint, self.execution)

    def test_changed_command_and_binary_are_rejected(self) -> None:
        self._roundtrip()
        changed = {**self.execution, "run_command": ["/usr/bin/false", "{input}"]}
        with self.assertRaises(ValueError):
            read_checkpoint(self.checkpoint, self.run, changed)
        self.binary.write_bytes(b"changed binary\n")
        with self.assertRaises(ValueError):
            read_checkpoint(self.checkpoint, self.run, self.execution)

    def test_runtime_executable_change_is_rejected(self) -> None:
        wrapper = self.repo / "wrapper"
        wrapper.write_bytes(b"first wrapper\n")
        execution = {**self.execution,
                     "run_command": [str(wrapper), str(self.binary), "{input}"]}
        write_checkpoint(self.run, self.checkpoint, execution)
        wrapper.write_bytes(b"second wrapper\n")
        with self.assertRaises(ValueError):
            read_checkpoint(self.checkpoint, self.run, execution)

    def test_source_and_verifier_mutation_are_rejected(self) -> None:
        self._roundtrip()
        put(self.run / "verification" / "sp-b.json", {
            "sp_id": "sp-b", "verdict": "REFUTED", "recommended_next_action": "REFUTE"})
        with self.assertRaises(ValueError):
            read_checkpoint(self.checkpoint, self.run, self.execution)

    def test_source_byte_mutation_after_snapshot_is_rejected(self) -> None:
        self._roundtrip()
        self.source_file.write_bytes(b"int A(void) { return 1; }\n")
        with self.assertRaises(ValueError):
            read_checkpoint(self.checkpoint, self.run, self.execution)

    def test_unlisted_source_file_is_rejected_by_dev_manifest(self) -> None:
        (self.repo / "extra.h").write_text("#define EXTRA 1\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            write_checkpoint(self.run, self.checkpoint, self.execution)

    def test_git_head_change_after_snapshot_is_rejected(self) -> None:
        self._git_source()
        self._roundtrip()
        self.source_file.write_bytes(b"int A(void) { return 2; }\n")
        self._git("add", "target.c")
        self._git("-c", "user.name=toy", "-c", "user.email=toy@example.invalid",
                  "commit", "-qm", "second")
        with self.assertRaises(ValueError):
            read_checkpoint(self.checkpoint, self.run, self.execution)

    def test_dirty_assume_unchanged_tracked_source_is_rejected(self) -> None:
        self._git_source()
        self._git("update-index", "--assume-unchanged", "target.c")
        self.source_file.write_bytes(b"int A(void) { return 3; }\n")
        with self.assertRaises(ValueError):
            write_checkpoint(self.run, self.checkpoint, self.execution)

    def test_dirty_assume_unchanged_after_snapshot_is_rejected(self) -> None:
        self._git_source()
        self._roundtrip()
        self._git("update-index", "--assume-unchanged", "target.c")
        self.source_file.write_bytes(b"int A(void) { return 5; }\n")
        with self.assertRaises(ValueError):
            read_checkpoint(self.checkpoint, self.run, self.execution)

    def test_staged_change_with_head_worktree_bytes_is_rejected(self) -> None:
        self._git_source()
        original = self.source_file.read_bytes()
        self.source_file.write_bytes(b"int A(void) { return 4; }\n")
        self._git("add", "target.c")
        self.source_file.write_bytes(original)
        with self.assertRaises(ValueError):
            write_checkpoint(self.run, self.checkpoint, self.execution)

    def test_untracked_generated_source_is_pinned_separately(self) -> None:
        self._git_source()
        generated = self.repo / "build" / "compiler_id.c"
        generated.parent.mkdir()
        generated.write_bytes(b"int compiler_id;\n")
        snapshot = self._roundtrip()
        untracked = snapshot["execution_identity"]["source_identity"][
            "untracked_source_files"]
        self.assertEqual([row["path"] for row in untracked],
                         ["build/compiler_id.c"])
        generated.write_bytes(b"int changed_compiler_id;\n")
        with self.assertRaises(ValueError):
            read_checkpoint(self.checkpoint, self.run, self.execution)

    def test_tracked_symlink_is_rejected(self) -> None:
        self._git_source()
        (self.repo / "link.h").symlink_to("target.c")
        self._git("add", "link.h")
        self._git("-c", "user.name=toy", "-c", "user.email=toy@example.invalid",
                  "commit", "-qm", "symlink")
        self.execution["source_revision"] = self._git("rev-parse", "HEAD")
        with self.assertRaises(ValueError):
            write_checkpoint(self.run, self.checkpoint, self.execution)

    def test_mismatched_checkout_owner_is_rejected(self) -> None:
        self._git_source()
        with mock.patch("dev_sp_queue_checkpoint.os.geteuid",
                        return_value=os.geteuid() + 1):
            with self.assertRaises(ValueError):
                write_checkpoint(self.run, self.checkpoint, self.execution)

    def test_source_root_symlink_alias_is_rejected(self) -> None:
        self._roundtrip()
        alias = self.root / "repo-alias"
        alias.symlink_to(self.repo, target_is_directory=True)
        changed = {**self.execution, "target_repository": str(alias)}
        with self.assertRaises(ValueError):
            read_checkpoint(self.checkpoint, self.run, changed)

    def test_prior_pov_input_mutation_is_rejected(self) -> None:
        self._roundtrip()
        self.input_path.write_bytes(b"B")
        with self.assertRaises(ValueError):
            read_checkpoint(self.checkpoint, self.run, self.execution)

    def test_orphan_pov_and_mismatched_verifier_are_rejected(self) -> None:
        put(self.run / "verification" / "sp-b.json", {"sp_id": "sp-c"})
        with self.assertRaises(ValueError):
            write_checkpoint(self.run, self.checkpoint, self.execution)
        put(self.run / "verification" / "sp-b.json", {"sp_id": "sp-b"})
        put(self.run / "poc" / "pocs.json", [{"poc_id": "orphan", "sp_id": "absent"}])
        with self.assertRaises(ValueError):
            write_checkpoint(self.run, self.checkpoint, self.execution)

    def test_duplicate_candidate_and_complete_scan_are_rejected(self) -> None:
        put(self.run / "sp" / "candidates.json", [
            {"sp_id": "sp-a", "status": "OPEN"},
            {"sp_id": "sp-a", "status": "OPEN"},
        ])
        with self.assertRaises(ValueError):
            write_checkpoint(self.run, self.checkpoint, self.execution)
        put(self.run / "sp" / "candidates.json", [{"sp_id": "sp-a", "status": "OPEN"}])
        put(self.run / "scan.json", {"selected_function_id": "fn-a"})
        with self.assertRaises(ValueError):
            write_checkpoint(self.run, self.checkpoint, self.execution)

    def test_checkpoint_is_single_write_and_private(self) -> None:
        self._roundtrip()
        self.assertEqual(self.checkpoint.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            write_checkpoint(self.run, self.checkpoint, self.execution)

    def test_checkpoint_cannot_be_marked_resume_eligible_by_edit(self) -> None:
        self._roundtrip()
        record = json.loads(self.checkpoint.read_text(encoding="utf-8"))
        record["resume_eligible"] = True
        put(self.checkpoint, record)
        with self.assertRaises(ValueError):
            read_checkpoint(self.checkpoint, self.run, self.execution)

    def test_checkpoint_inside_active_run_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            write_checkpoint(self.run, self.run / "SP_QUEUE_CHECKPOINT.json",
                             self.execution)


if __name__ == "__main__":
    unittest.main()
