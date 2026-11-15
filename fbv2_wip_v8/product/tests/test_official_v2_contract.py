"""Synthetic dual-pin official Harness qualification; no target execution."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch

from vulnerabilityanalysis.adapter import HarnessAdapter
from vulnerabilityanalysis.direct_input import CallbackProbe
from vulnerabilityanalysis.final_verification import _trusted_official_item
from vulnerabilityanalysis.models import Evidence, PoC, RuntimeResult, SuspiciousPoint
from vulnerabilityanalysis.official_harness import (
    hash_source_tree, hash_source_tree_v2, issue_official_pinned_qualification,
    validate_official_harness_execution)
from vulnerabilityanalysis.runtime import ProcessEnvelopeStop, _guarded_run_once


def digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def git_commit(folder: Path) -> str:
    subprocess.run(["git", "init", "-q", str(folder)], check=True)
    subprocess.run(["git", "-C", str(folder), "add", "."], check=True)
    subprocess.run(["git", "-C", str(folder), "-c", "user.name=Fixture",
                    "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture"], check=True)
    return subprocess.check_output(["git", "-C", str(folder), "rev-parse", "HEAD"], text=True).strip()


class Fixture:
    def __init__(self, root: Path):
        self.root = root
        self.oss = root / "oss"
        self.upstream = root / "upstream"
        script = self.oss / "projects" / "sample" / "build.sh"
        script.parent.mkdir(parents=True)
        script.write_text("#!/bin/sh\ncc tests/fuzz.c -o fuzz\n")
        self.upstream.mkdir()
        self.upstream_source = self.upstream / "tests" / "fuzz.c"
        self.upstream_source.parent.mkdir()
        self.upstream_source.write_text("int LLVMFuzzerTestOneInput(const char *p, unsigned n) { return 0; }\n")
        (self.upstream / "target.c").write_text("int target(void) { return 1; }\n")
        oss_revision = git_commit(self.oss)
        upstream_revision = git_commit(self.upstream)
        subprocess.run(["git", "-C", str(self.oss), "remote", "add", "origin",
                        "https://github.com/google/oss-fuzz"], check=True)
        subprocess.run(["git", "-C", str(self.upstream), "remote", "add", "origin",
                        "https://example.invalid/upstream.git"], check=True)
        self.local = root / "local-fuzz.c"
        self.local.write_bytes(self.upstream_source.read_bytes())
        self.binary = root / "fuzz-bin"
        self.binary.write_bytes(b"synthetic-binary")
        self.seed = root / "seed"
        self.seed.write_bytes(b"normal")
        self.receipt = root / "receipt.json"
        self.receipt.write_text(json.dumps({
            "kind": "OFFICIAL_OSS_FUZZ_UPSTREAM_BUILD_RECEIPT_V2",
            "oss_fuzz_revision": oss_revision, "upstream_revision": upstream_revision,
            "target_revision": upstream_revision,
            "build_script_path": "projects/sample/build.sh", "build_script_sha256": digest(script),
            "upstream_harness_path": "tests/fuzz.c", "upstream_harness_sha256": digest(self.upstream_source),
            "binary_sha256": digest(self.binary), "binary": str(self.binary),
            "chained_scripts": [],
            "compiled_sources": [{"path": str(self.upstream_source),
                                  "sha256": digest(self.upstream_source)}],
            "build_steps": [{"argv": ["cc", str(self.upstream_source), "-o", str(self.binary)],
                             "exit_code": 0,
                             "inputs": [{"path": str(self.upstream_source),
                                         "sha256": digest(self.upstream_source)}],
                             "outputs": [{"path": str(self.binary),
                                          "sha256": digest(self.binary)}]}]}))
        self.review = root / "review.json"
        self.review.write_text(json.dumps({
            "kind": "OFFICIAL_OSS_FUZZ_API_USE_REVIEW_V2", "status": "APPROVED",
            "decision": True, "reviewer_id": "reviewer", "reviewed_scope": "synthetic API use",
            "reviewed_at": "2026-10-27", "harness_sha256": digest(self.upstream_source),
            "oss_fuzz_repository": "https://github.com/google/oss-fuzz",
            "oss_fuzz_revision": oss_revision, "upstream_revision": upstream_revision,
            "upstream_repository": "https://example.invalid/upstream.git",
            "target_revision": upstream_revision,
            "target_source_tree_sha256": hash_source_tree_v2(self.upstream),
            "build_script_path": "projects/sample/build.sh", "build_script_sha256": digest(script),
            "upstream_harness_path": "tests/fuzz.c",
            "build_receipt_sha256": digest(self.receipt)}))
        self.contract = root / "contract.json"
        self.data = {
            "kind": "OFFICIAL_OSS_FUZZ_UPSTREAM_HARNESS_V2",
            "oss_fuzz": {"repository": "https://github.com/google/oss-fuzz",
                         "revision": oss_revision,
                         "build_script": {"path": "projects/sample/build.sh", "sha256": digest(script)},
                         "chained_scripts": []},
            "upstream_harness": {"repository": "https://example.invalid/upstream.git",
                                 "revision": upstream_revision, "path": "tests/fuzz.c",
                                 "sha256": digest(self.upstream_source)},
            "target": {"revision": upstream_revision, "source_root": str(self.upstream),
                       "source_tree_sha256": hash_source_tree_v2(self.upstream)},
            "local": {"harness_file": str(self.local), "harness_sha256": digest(self.local),
                      "binary": str(self.binary), "binary_sha256": digest(self.binary),
                      "normal_seed": str(self.seed), "normal_seed_sha256": digest(self.seed)},
            "build_receipt": {"file": str(self.receipt), "sha256": digest(self.receipt)},
            "api_review": {"file": str(self.review), "sha256": digest(self.review),
                           "reviewer_id": "reviewer"}}
        self.save_contract()

    def save_contract(self) -> None:
        self.contract.write_text(json.dumps(self.data, sort_keys=True))

    def issue(self):
        return issue_official_pinned_qualification(
            contract_path=self.contract, approved_contract_sha256=digest(self.contract),
            source_root=self.upstream, harness=self.local, binary=self.binary,
            normal_seed=self.seed, oss_fuzz_checkout=self.oss,
            upstream_checkout=self.upstream)

    def replace_receipt(self, receipt: dict) -> None:
        self.receipt.write_text(json.dumps(receipt))
        self.data["build_receipt"]["sha256"] = digest(self.receipt)
        review = json.loads(self.review.read_text())
        review["build_receipt_sha256"] = digest(self.receipt)
        self.review.write_text(json.dumps(review))
        self.data["api_review"]["sha256"] = digest(self.review)
        self.save_contract()


class _PhysicalProcessAccount:
    output_limit_bytes = 4096

    def __init__(self, limit: int):
        self.limit = limit
        self.deadline_monotonic = time.monotonic() + 60
        self.reservations = []
        self.settlements = []

    def before_process(self, command, *, cwd, env, timeout, kind, segment):
        if len(self.reservations) >= self.limit:
            raise ProcessEnvelopeStop("PENDING_PROCESS_BUDGET", "no process budget")
        lease = len(self.reservations)
        self.reservations.append((lease, segment, tuple(command)))
        return lease

    def after_process(self, lease, *, elapsed_seconds, cleanup_complete,
                      output_limited, error):
        self.settlements.append((lease, cleanup_complete, error))


class OfficialV2ContractTests(unittest.TestCase):
    def test_bounded_official_probe_and_controls_share_one_process_account(self):
        """The synthetic wire never launches a target, but uses the real envelope seam."""
        with TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            token = fixture.issue()
            self.assertIsNotNone(token)
            pov_input = fixture.root / "pov"
            pov_input.write_bytes(b"candidate input")
            source = fixture.upstream / "target.c"
            point = SuspiciousPoint(
                "sp-1", "worker", "direction", "target", str(source), "target.c:1",
                "return", "test", [], "input", [], [], [], [])
            poc = PoC("poc-1", "sp-1", "", str(pov_input), None, "crash")
            account = _PhysicalProcessAccount(4)
            current_account = [account]
            launches = []
            launch_baseline = [0]
            alter_binary_after_target = [False]
            original_binary = fixture.binary.read_bytes()

            def synthetic_wire(command, **kwargs):
                if command[0] == "git":
                    return _guarded_run_once(command, **kwargs)
                launches.append(tuple(command))
                self.assertEqual(len(current_account[0].reservations),
                                 len(launches) - launch_baseline[0])
                self.assertEqual(kwargs["output_limit_bytes"],
                                 current_account[0].output_limit_bytes)
                if "-x" in command:
                    script = Path(command[command.index("-x") + 1])
                    marker = re.search(r"VA_CALLBACK_[0-9a-f]+", script.read_text()).group()
                    (script.parent / "callback.bin").write_bytes(pov_input.read_bytes())
                    return subprocess.CompletedProcess(
                        command, 0,
                        f"{marker}_HIT\n{marker}_SIZE={pov_input.stat().st_size}\n", "")
                if command[0] == "gdb" and "info sources" in command:
                    return subprocess.CompletedProcess(command, 0, str(source), "")
                if command[1] == str(fixture.seed.resolve()):
                    return subprocess.CompletedProcess(command, 0, "", "")
                self.assertEqual(command[1], str(pov_input.resolve()))
                if alter_binary_after_target[0]:
                    fixture.binary.write_bytes(original_binary + b"changed during replay")
                return subprocess.CompletedProcess(
                    command, 1, "", "ERROR: AddressSanitizer: heap-buffer-overflow\n"
                    f"#0 0x1 in target {source}:1:1\n")

            def validate(run_name, physical_account):
                run = fixture.root / run_name
                run.mkdir()
                (run / "run.json").write_text(json.dumps({"run_id": run_name}))
                return validate_official_harness_execution(
                    token, run_dir=run, point=point, poc=poc,
                    target_repository=fixture.upstream,
                    process_envelope=physical_account)

            with patch("vulnerabilityanalysis.runtime._guarded_run_once",
                       side_effect=synthetic_wire), \
                 patch("vulnerabilityanalysis.direct_input.shutil.which",
                       return_value="/synthetic/gdb"), \
                 patch("vulnerabilityanalysis.direct_input.platform.machine",
                       return_value="x86_64"):
                proof = validate("run-positive", account)
                self.assertIsNotNone(proof)
                self.assertEqual([row[1] for row in account.reservations], [
                    "harness.callback_probe", "official.normal_seed_replay",
                    "official.pov_replay", "assertion.gdb_source_inventory"])
                self.assertEqual(len(launches), 4)
                self.assertEqual([row[0] for row in account.settlements], [0, 1, 2, 3])
                self.assertTrue(all(row[1] and row[2] is None
                                    for row in account.settlements))

                limited = _PhysicalProcessAccount(2)
                current_account[0] = limited
                before = len(launches)
                launch_baseline[0] = before
                with self.assertRaises(ProcessEnvelopeStop) as stopped:
                    validate("run-budget", limited)
                self.assertEqual(stopped.exception.status, "PENDING_PROCESS_BUDGET")
                self.assertEqual(len(launches) - before, 2)
                self.assertEqual(len(limited.settlements), 2)
                self.assertFalse((fixture.root / "run-budget" / "security" /
                                  "sp-1.poc-1.official_harness.json").exists())

                dwarf_limited = _PhysicalProcessAccount(3)
                current_account[0] = dwarf_limited
                before = len(launches)
                launch_baseline[0] = before
                with self.assertRaises(ProcessEnvelopeStop):
                    validate("run-dwarf-budget", dwarf_limited)
                self.assertEqual(len(launches) - before, 3)
                self.assertEqual(len(dwarf_limited.settlements), 3)
                self.assertFalse((fixture.root / "run-dwarf-budget" / "security" /
                                  "sp-1.poc-1.official_harness.json").exists())

                late_pin = _PhysicalProcessAccount(4)
                current_account[0] = late_pin
                before = len(launches)
                launch_baseline[0] = before
                alter_binary_after_target[0] = True
                self.assertIsNone(validate("run-late-pin", late_pin))
                self.assertEqual(len(launches) - before, 4)
                self.assertEqual(len(late_pin.settlements), 4)
                self.assertFalse((fixture.root / "run-late-pin" / "security" /
                                  "sp-1.poc-1.official_harness.json").exists())
                alter_binary_after_target[0] = False
                fixture.binary.write_bytes(original_binary)

                fixture.binary.write_bytes(fixture.binary.read_bytes() + b"changed")
                before = len(launches)
                pinned = _PhysicalProcessAccount(4)
                current_account[0] = pinned
                launch_baseline[0] = before
                self.assertIsNone(validate("run-pin-changed", pinned))
                self.assertEqual(len(launches), before)
                self.assertEqual(pinned.reservations, [])

    def test_v1_issuer_remains_available(self):
        with TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            revision = fixture.data["oss_fuzz"]["revision"]
            fixture.review.write_text(json.dumps({
                "kind": "OFFICIAL_OSS_FUZZ_API_USE_REVIEW_V1", "status": "APPROVED",
                "decision": True, "reviewer_id": "reviewer", "reviewed_scope": "synthetic API use",
                "reviewed_at": "2026-10-27", "harness_sha256": digest(fixture.local),
                "upstream_revision": revision}))
            fixture.contract.write_text(json.dumps({
                "kind": "OFFICIAL_OSS_FUZZ_HARNESS_V1",
                "oss_fuzz_repository": "https://github.com/google/oss-fuzz",
                "oss_fuzz_revision": revision, "oss_fuzz_harness_path": "projects/sample/fuzz.c",
                "source_root": str(fixture.upstream), "source_tree_sha256": hash_source_tree(fixture.upstream),
                "harness": str(fixture.local), "harness_sha256": digest(fixture.local),
                "upstream_harness_sha256": digest(fixture.local),
                "binary": str(fixture.binary), "binary_sha256": digest(fixture.binary),
                "normal_seed": str(fixture.seed), "normal_seed_sha256": digest(fixture.seed),
                "review_artifact": str(fixture.review), "review_sha256": digest(fixture.review),
                "reviewer_id": "reviewer"}))
            token = issue_official_pinned_qualification(
                contract_path=fixture.contract, approved_contract_sha256=digest(fixture.contract),
                source_root=fixture.upstream, harness=fixture.local,
                binary=fixture.binary, normal_seed=fixture.seed)
            self.assertIsNotNone(token)
            self.assertTrue(token.product_issued)
            self.assertEqual(token.contract_kind, "OFFICIAL_OSS_FUZZ_HARNESS_V1")

    def test_gate_accepts_only_product_runtime_v2_proof_and_rechecks_pins(self):
        with TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            token = fixture.issue()
            self.assertIsNotNone(token)
            run = fixture.root / "run"
            run.mkdir()
            (run / "run.json").write_text(json.dumps({"run_id": "run-1"}))
            pov_input = fixture.root / "pov"
            pov_input.write_bytes(b"candidate input")
            target_source = fixture.upstream / "target.c"
            point = SuspiciousPoint(
                "sp-1", "worker", "direction", "target", str(target_source), "target.c:1",
                "return", "test", [], "input", [], [], [], [])
            poc = PoC("poc-1", "sp-1", "", str(pov_input), None, "crash")
            normal = RuntimeResult(0, "", "", None, False, None, None, "NONE")
            crash = RuntimeResult(1, "", "AddressSanitizer: heap-buffer-overflow",
                                  None, False, "AddressSanitizer: heap-buffer-overflow", None, "CRASH")
            triage = {"category": "TARGET_CRASH", "top_source_frame": str(target_source),
                      "source_provenance": {
                          "checkout_source": str(target_source),
                          "observed_source": str(target_source),
                          "binary": str(fixture.binary),
                          "method": "DWARF_PATH_RELATIVE_PATH_SHA256",
                          "sha256": digest(target_source)}}
            with patch("vulnerabilityanalysis.direct_input.probe_libfuzzer_callback",
                       return_value=CallbackProbe(True, pov_input.stat().st_size,
                                                  digest(pov_input), "measured")), \
                 patch("vulnerabilityanalysis.runtime.RuntimeExecutor") as executor, \
                 patch("vulnerabilityanalysis.runtime.triage_crash", return_value=triage):
                executor.return_value.run.side_effect = [normal, crash]
                proof = validate_official_harness_execution(
                    token, run_dir=run, point=point, poc=poc,
                    target_repository=fixture.upstream)
            self.assertIsNotNone(proof)
            self.assertEqual(proof.contract_kind, fixture.data["kind"])
            item = Evidence(proof.harness_evidence_id, "HARNESS_VALIDITY",
                            "AUTOMATIC_OFFICIAL_HARNESS", point.sp_id, "runtime",
                            str(proof.harness_artifact), True, False)
            self.assertTrue(_trusted_official_item(item, proof, point))
            fixture.receipt.write_bytes(fixture.receipt.read_bytes() + b"x")
            self.assertFalse(_trusted_official_item(item, proof, point))

    def test_two_pins_receipt_and_review_issue_product_token(self):
        with TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            token = fixture.issue()
            self.assertIsNotNone(token)
            self.assertTrue(token.product_issued)
            self.assertEqual(token.contract_kind, fixture.data["kind"])
            self.assertEqual(token.build_receipt_sha256, digest(fixture.receipt))

    def test_local_pin_mutations_are_rejected(self):
        for name in ("local", "binary", "seed", "upstream_source"):
            with self.subTest(name=name), TemporaryDirectory() as tmp:
                fixture = Fixture(Path(tmp))
                path = getattr(fixture, name)
                path.write_bytes(path.read_bytes() + b"x")
                self.assertIsNone(fixture.issue())

    def test_script_or_revision_change_is_rejected(self):
        with TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            script = fixture.oss / "projects/sample/build.sh"
            script.write_bytes(script.read_bytes() + b"x")
            self.assertIsNone(fixture.issue())
        with TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            fixture.data["upstream_harness"]["revision"] = "a" * 40
            fixture.save_contract()
            self.assertIsNone(fixture.issue())

    def test_dirty_script_cannot_be_reapproved_as_same_revision(self):
        with TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            script = fixture.oss / "projects/sample/build.sh"
            script.write_bytes(script.read_bytes() + b"# changed after commit\n")
            fixture.data["oss_fuzz"]["build_script"]["sha256"] = digest(script)
            receipt = json.loads(fixture.receipt.read_text())
            receipt["build_script_sha256"] = digest(script)
            fixture.receipt.write_text(json.dumps(receipt))
            fixture.data["build_receipt"]["sha256"] = digest(fixture.receipt)
            review = json.loads(fixture.review.read_text())
            review["build_script_sha256"] = digest(script)
            review["build_receipt_sha256"] = digest(fixture.receipt)
            fixture.review.write_text(json.dumps(review))
            fixture.data["api_review"]["sha256"] = digest(fixture.review)
            fixture.save_contract()
            self.assertIsNone(fixture.issue())

    def test_assume_unchanged_target_differs_from_commit_is_rejected(self):
        with TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            subprocess.run(["git", "-C", str(fixture.upstream), "update-index",
                            "--assume-unchanged", "target.c"], check=True)
            target_file = fixture.upstream / "target.c"
            target_file.write_text("int target(void) { return 999; }\n")
            self.assertEqual(subprocess.check_output(
                ["git", "-C", str(fixture.upstream), "status", "--porcelain"],
                text=True).strip(), "")
            changed_tree = hash_source_tree_v2(fixture.upstream)
            fixture.data["target"]["source_tree_sha256"] = changed_tree
            review = json.loads(fixture.review.read_text())
            review["target_source_tree_sha256"] = changed_tree
            fixture.review.write_text(json.dumps(review))
            fixture.data["api_review"]["sha256"] = digest(fixture.review)
            fixture.save_contract()
            self.assertIsNone(fixture.issue())

    def test_v2_source_hash_ignores_git_remote_bookkeeping(self):
        with TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            before = hash_source_tree_v2(fixture.upstream)
            subprocess.run(["git", "-C", str(fixture.upstream), "remote", "set-url",
                            "origin", "https://example.invalid/changed.git"], check=True)
            self.assertEqual(hash_source_tree_v2(fixture.upstream), before)
            self.assertIsNone(fixture.issue())

    def test_receipt_must_name_compiled_harness_not_just_comment(self):
        with TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            receipt = json.loads(fixture.receipt.read_text())
            receipt["compiled_sources"] = []
            fixture.receipt.write_text(json.dumps(receipt))
            fixture.data["build_receipt"]["sha256"] = digest(fixture.receipt)
            review = json.loads(fixture.review.read_text())
            review["build_receipt_sha256"] = digest(fixture.receipt)
            fixture.review.write_text(json.dumps(review))
            fixture.data["api_review"]["sha256"] = digest(fixture.review)
            fixture.save_contract()
            self.assertIsNone(fixture.issue())

    def test_receipt_must_link_pinned_source_to_final_binary(self):
        with TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            receipt = json.loads(fixture.receipt.read_text())
            receipt["build_steps"][0]["inputs"] = [{"path": str(fixture.root / "other.c"),
                                                      "sha256": digest(fixture.upstream_source)}]
            fixture.receipt.write_text(json.dumps(receipt))
            fixture.data["build_receipt"]["sha256"] = digest(fixture.receipt)
            review = json.loads(fixture.review.read_text())
            review["build_receipt_sha256"] = digest(fixture.receipt)
            fixture.review.write_text(json.dumps(review))
            fixture.data["api_review"]["sha256"] = digest(fixture.review)
            fixture.save_contract()
            self.assertIsNone(fixture.issue())

    def test_v2_link_rejects_unproven_second_input(self):
        with TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            receipt = json.loads(fixture.receipt.read_text())
            harness_object = fixture.root / "fuzz.o"
            unknown_object = fixture.root / "unknown.o"
            receipt["build_steps"] = [
                {"argv": ["cc", "-c", str(fixture.upstream_source)], "exit_code": 0,
                 "inputs": [{"path": str(fixture.upstream_source),
                             "sha256": digest(fixture.upstream_source)}],
                 "outputs": [{"path": str(harness_object), "sha256": "a" * 64}]},
                {"argv": ["cc", str(harness_object), str(unknown_object)], "exit_code": 0,
                 "inputs": [{"path": str(harness_object), "sha256": "a" * 64},
                            {"path": str(unknown_object), "sha256": "b" * 64}],
                 "outputs": [{"path": str(fixture.binary), "sha256": digest(fixture.binary)}]},
            ]
            fixture.replace_receipt(receipt)
            self.assertIsNone(fixture.issue())

    def test_v2_link_accepts_two_pinned_sources_and_reverse_step_order(self):
        with TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            receipt = json.loads(fixture.receipt.read_text())
            target_source = fixture.upstream / "target.c"
            receipt["compiled_sources"].append({"path": str(target_source),
                                                "sha256": digest(target_source)})
            harness_object = fixture.root / "fuzz.o"
            target_object = fixture.root / "target.o"
            receipt["build_steps"] = [
                {"argv": ["cc", str(harness_object), str(target_object)], "exit_code": 0,
                 "inputs": [{"path": str(harness_object), "sha256": "a" * 64},
                            {"path": str(target_object), "sha256": "b" * 64}],
                 "outputs": [{"path": str(fixture.binary), "sha256": digest(fixture.binary)}]},
                {"argv": ["cc", "-c", str(target_source)], "exit_code": 0,
                 "inputs": [{"path": str(target_source), "sha256": digest(target_source)}],
                 "outputs": [{"path": str(target_object), "sha256": "b" * 64}]},
                {"argv": ["cc", "-c", str(fixture.upstream_source)], "exit_code": 0,
                 "inputs": [{"path": str(fixture.upstream_source),
                             "sha256": digest(fixture.upstream_source)}],
                 "outputs": [{"path": str(harness_object), "sha256": "a" * 64}]},
            ]
            fixture.replace_receipt(receipt)
            self.assertIsNotNone(fixture.issue())

    def test_v2_compiled_source_outside_pinned_checkout_is_not_trusted(self):
        with TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            receipt = json.loads(fixture.receipt.read_text())
            outside = fixture.root / "outside.c"
            outside.write_text("int unrelated(void) { return 1; }\n")
            receipt["compiled_sources"].append({"path": str(outside), "sha256": digest(outside)})
            receipt["build_steps"][0]["inputs"].append({"path": str(outside),
                                                         "sha256": digest(outside)})
            fixture.replace_receipt(receipt)
            self.assertIsNone(fixture.issue())

    def test_v2_binary_must_descend_from_official_harness(self):
        with TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            receipt = json.loads(fixture.receipt.read_text())
            target_source = fixture.upstream / "target.c"
            receipt["compiled_sources"].append({"path": str(target_source),
                                                "sha256": digest(target_source)})
            receipt["build_steps"] = [
                {"argv": ["cc", str(target_source), "-o", str(fixture.binary)],
                 "exit_code": 0,
                 "inputs": [{"path": str(target_source), "sha256": digest(target_source)}],
                 "outputs": [{"path": str(fixture.binary), "sha256": digest(fixture.binary)}]},
            ]
            fixture.replace_receipt(receipt)
            self.assertIsNone(fixture.issue())

    def test_v2_rejects_conflicting_hashes_for_one_path(self):
        with TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            receipt = json.loads(fixture.receipt.read_text())
            target_source = fixture.upstream / "target.c"
            receipt["compiled_sources"].append({"path": str(target_source),
                                                "sha256": digest(target_source)})
            shared = fixture.root / "shared.o"
            receipt["build_steps"] = [
                {"argv": ["cc", "-c", str(fixture.upstream_source)], "exit_code": 0,
                 "inputs": [{"path": str(fixture.upstream_source),
                             "sha256": digest(fixture.upstream_source)}],
                 "outputs": [{"path": str(shared), "sha256": "a" * 64}]},
                {"argv": ["cc", "-c", str(target_source)], "exit_code": 0,
                 "inputs": [{"path": str(target_source), "sha256": digest(target_source)}],
                 "outputs": [{"path": str(shared), "sha256": "b" * 64}]},
                {"argv": ["cc", str(shared), "-o", str(fixture.binary)], "exit_code": 0,
                 "inputs": [{"path": str(shared), "sha256": "a" * 64},
                            {"path": str(shared), "sha256": "b" * 64}],
                 "outputs": [{"path": str(fixture.binary), "sha256": digest(fixture.binary)}]},
            ]
            fixture.replace_receipt(receipt)
            self.assertIsNone(fixture.issue())

    def test_v2_rejects_duplicate_output_with_double_slash_alias(self):
        with TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            receipt = json.loads(fixture.receipt.read_text())
            target_source = fixture.upstream / "target.c"
            receipt["compiled_sources"].append({"path": str(target_source),
                                                "sha256": digest(target_source)})
            shared = fixture.root / "shared.o"
            alias = str(shared).replace("/shared.o", "//shared.o")
            receipt["build_steps"] = [
                {"argv": ["cc", "-c", str(fixture.upstream_source)], "exit_code": 0,
                 "inputs": [{"path": str(fixture.upstream_source),
                             "sha256": digest(fixture.upstream_source)}],
                 "outputs": [{"path": str(shared), "sha256": "a" * 64}]},
                {"argv": ["cc", "-c", str(target_source)], "exit_code": 0,
                 "inputs": [{"path": str(target_source), "sha256": digest(target_source)}],
                 "outputs": [{"path": alias, "sha256": "a" * 64}]},
                {"argv": ["cc", str(shared), "-o", str(fixture.binary)], "exit_code": 0,
                 "inputs": [{"path": str(shared), "sha256": "a" * 64}],
                 "outputs": [{"path": str(fixture.binary), "sha256": digest(fixture.binary)}]},
            ]
            fixture.replace_receipt(receipt)
            self.assertIsNone(fixture.issue())

    def test_v2_link_script_sha_must_match_local_file(self):
        with TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            receipt = json.loads(fixture.receipt.read_text())
            script = fixture.root / "link.txt"
            script.write_text("cc fuzz.o -o fuzz-bin\n")
            receipt["build_steps"][0]["argv"] = ["cmake", "-E", "cmake_link_script", str(script)]
            receipt["build_steps"][0]["link_script"] = {"path": str(script),
                                                       "sha256": "0" * 64}
            fixture.replace_receipt(receipt)
            self.assertIsNone(fixture.issue())

    def test_v2_valid_local_link_script_is_accepted(self):
        with TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            receipt = json.loads(fixture.receipt.read_text())
            script = fixture.root / "link.txt"
            script.write_text("cc fuzz.o -o fuzz-bin\n")
            receipt["build_steps"][0]["argv"] = ["cmake", "-E", "cmake_link_script", "link.txt"]
            receipt["build_steps"][0]["cwd"] = str(fixture.root)
            receipt["build_steps"][0]["link_script"] = {"path": str(script),
                                                       "sha256": digest(script)}
            fixture.replace_receipt(receipt)
            self.assertIsNotNone(fixture.issue())

    def test_unknown_claim_and_path_traversal_are_rejected(self):
        with TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            fixture.data["qualified"] = True
            fixture.save_contract()
            self.assertIsNone(fixture.issue())
        with TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            fixture.data["upstream_harness"]["path"] = "tests/../tests/fuzz.c"
            fixture.save_contract()
            self.assertIsNone(fixture.issue())

    def test_review_cannot_be_reused_for_other_repository(self):
        with TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            fixture.data["upstream_harness"]["repository"] = "https://example.invalid/other.git"
            fixture.save_contract()
            self.assertIsNone(fixture.issue())
        with TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            fixture.data["upstream_harness"]["repository"] = "https://example.invalid/other.git"
            review = json.loads(fixture.review.read_text())
            review["upstream_repository"] = "https://example.invalid/other.git"
            fixture.review.write_text(json.dumps(review))
            fixture.data["api_review"]["sha256"] = digest(fixture.review)
            fixture.save_contract()
            self.assertIsNone(fixture.issue())

    def test_review_cannot_be_reused_for_other_target_revision(self):
        with TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            review = json.loads(fixture.review.read_text())
            review["target_revision"] = "b" * 40
            fixture.review.write_text(json.dumps(review))
            fixture.data["api_review"]["sha256"] = digest(fixture.review)
            fixture.save_contract()
            self.assertIsNone(fixture.issue())

    def test_local_symlink_is_rejected_even_if_bytes_match(self):
        with TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            alias = fixture.root / "alias-fuzz.c"
            alias.symlink_to(fixture.local)
            fixture.data["local"]["harness_file"] = str(alias)
            fixture.save_contract()
            self.assertIsNone(issue_official_pinned_qualification(
                contract_path=fixture.contract, approved_contract_sha256=digest(fixture.contract),
                source_root=fixture.upstream, harness=alias, binary=fixture.binary,
                normal_seed=fixture.seed, oss_fuzz_checkout=fixture.oss,
                upstream_checkout=fixture.upstream))
    def test_adapter_reads_v2_without_granting_qualification(self):
        with TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            artifact = fixture.root / "artifact"
            attempt = artifact / "attempt"
            attempt.mkdir(parents=True)
            (artifact / "project.json").write_text(json.dumps({"source_root": str(fixture.upstream)}))
            analysis = artifact / "analysis"
            analysis.mkdir()
            (analysis / "functions.jsonl").write_text(json.dumps({
                "function_id": "fn-target", "name": "target", "file": "target.c"}) + "\n")
            (attempt / "manifest.json").write_text(json.dumps({
                "harness_id": "fixture", "source_file": str(fixture.local),
                "artifact_kind": fixture.data["kind"], "project_harness": True,
                "official_contract_path": str(fixture.contract),
                "official_contract_sha256": digest(fixture.contract),
                "catalog_producer": "EVALUATOR_GENERATED"}))
            harness = HarnessAdapter().load(attempt)
            self.assertEqual(harness.source_kind, "official_oss_fuzz")
            self.assertFalse(harness.metadata["official_provenance_verified"])
            self.assertIsNone(harness.metadata["qualified"])
            self.assertEqual(harness.metadata["official_pin"]["contract_sha256"], digest(fixture.contract))
