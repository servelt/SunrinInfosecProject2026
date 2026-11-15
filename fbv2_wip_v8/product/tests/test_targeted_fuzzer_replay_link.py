"""Targeted Fuzzer observations must retain exact replay provenance."""

import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from vulnerabilityanalysis.final_verification import crash_fingerprint
from vulnerabilityanalysis.models import (PoC, RootCauseResult, RuntimeResult,
                                          SuspiciousPoint, stable_id)
from vulnerabilityanalysis.scan import (_record_observed_crash, execute_poc,
                                        record_targeted_fuzzer_observations)


class TargetedFuzzerReplayLinkTests(unittest.TestCase):
    def test_first_independent_assessment_records_its_exact_input_source(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            point = SuspiciousPoint(
                "sp-synthetic", "worker", "direction", "parse", "target.c",
                "target.c:1", "read", "hypothesis", [], "bytes", [], [], [], [])
            inputs = []
            for index, data in enumerate((b"first", b"second")):
                path = root / f"input-{index}.bin"
                path.write_bytes(data)
                inputs.append(path)

            def runtime_result(*_args, **_kwargs):
                return RuntimeResult(
                    1, "", "ERROR: AddressSanitizer: heap-use-after-free\n",
                    None, False, "AddressSanitizer: heap-use-after-free", None,
                    "TARGET_CRASH")

            root_cause = RootCauseResult(
                point.sp_id, "crash", "UNKNOWN", None, None, None, [], [], [],
                "UNKNOWN", "UNKNOWN", [], [], [], "UNKNOWN")

            def independent_verifier(_run, crash_path, *_args, **_kwargs):
                record = json.loads(crash_path.read_text())
                record["independent_verification_status"] = "BLOCKED_ROOT_CAUSE"
                crash_path.write_text(json.dumps(record))

            with patch("vulnerabilityanalysis.scan.RuntimeExecutor.run",
                       side_effect=runtime_result), \
                 patch("vulnerabilityanalysis.scan.triage_crash",
                       return_value={"category": "TARGET_CRASH",
                                     "sp_linked": False}), \
                 patch("vulnerabilityanalysis.scan.verify_root_cause",
                       return_value=root_cause), \
                 patch("vulnerabilityanalysis.scan._verify_observed_target_crash",
                       side_effect=independent_verifier) as verify:
                for index, input_path in enumerate(inputs):
                    poc = PoC(f"poc-{index}", point.sp_id, "", str(input_path),
                              None, "crash")
                    execute_poc(poc, point, ["/synthetic/binary", "{input}"], root)

            self.assertEqual(verify.call_count, 1)
            canonical_path = next((root / "runtime" / "crashes").glob("*.json"))
            canonical = json.loads(canonical_path.read_text())
            self.assertEqual(len(canonical["observations"]), 2)
            self.assertEqual(canonical["independent_verification_source"], {
                "poc_id": "poc-0",
                "input_sha256": hashlib.sha256(inputs[0].read_bytes()).hexdigest(),
                "runtime_artifact": str(root / "runtime" / "poc-0.json"),
            })

    def test_canonical_observation_records_exact_executed_input_hash(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "runtime" / "crashes").mkdir(parents=True)
            witness = root / "input.bin"
            witness.write_bytes(b"the executed input")
            point = SuspiciousPoint(
                "sp-synthetic", "worker", "direction", "parse", "target.c",
                "target.c:1", "read", "hypothesis", [], "bytes", [], [], [], [])
            poc = PoC("poc-synthetic", point.sp_id, "", str(witness), None, "crash")
            runtime = RuntimeResult(
                1, "", "ERROR: AddressSanitizer: heap-use-after-free\n",
                None, False, "AddressSanitizer: heap-use-after-free", None,
                "TARGET_CRASH", crash_triage={"category": "TARGET_CRASH"})
            path, first = _record_observed_crash(
                root, poc, point, runtime, root / "runtime" / "poc-synthetic.json")
            self.assertTrue(first)
            observation = json.loads(path.read_text())["observations"][0]
            self.assertEqual(observation["input_sha256"],
                             hashlib.sha256(witness.read_bytes()).hexdigest())

    def _case(self, root: Path, *, input_hash_override: str | None = None,
              duplicate: bool = False, unrelated: bool = False,
              duplicate_exact: bool = False,
              canonical_status: str = "VERIFIED") -> tuple[Path, str, str, str]:
        sp_id = "sp-synthetic"
        corpus = root / "corpus" / "candidate" / sp_id
        corpus.mkdir(parents=True)
        (root / "runtime" / "crashes").mkdir(parents=True)
        witness = corpus / "crash-0"
        witness.write_bytes(b"synthetic crash input")
        input_sha = hashlib.sha256(witness.read_bytes()).hexdigest()
        observed_id = stable_id("sp-fuzzer-input", "1" * 64, input_sha)
        replay_poc_id = stable_id("poc", sp_id, input_sha, "fuzzer-replay")
        runtime_path = root / "runtime" / f"{replay_poc_id}.json"
        runtime = RuntimeResult(
            1, "", "ERROR: AddressSanitizer: heap-use-after-free\n",
            None, False, "AddressSanitizer: heap-use-after-free", None,
            "TARGET_CRASH", crash_triage={"category": "TARGET_CRASH"})
        runtime_path.write_text(json.dumps(runtime.__dict__))
        canonical_id = crash_fingerprint(runtime)
        observation = {
            "poc_id": replay_poc_id, "sp_id": sp_id,
            "input_sha256": input_hash_override or input_sha,
            "runtime_artifact": str(runtime_path),
        }
        canonical = root / "runtime" / "crashes" / f"{canonical_id}.json"
        observations = [observation]
        if unrelated:
            observations.append({"poc_id": "an-unrelated-poc"})
        if duplicate_exact:
            observations.append({**observation, "candidate_verdict": "UNKNOWN"})
        canonical.write_text(json.dumps({
            "crash_id": canonical_id,
            "independent_verification_status": canonical_status,
            "independent_verification_source": {
                "poc_id": replay_poc_id, "input_sha256": input_sha,
                "runtime_artifact": str(runtime_path),
            },
            "observations": observations,
        }))
        if duplicate:
            other = root / "runtime" / "crashes" / "other-crash-id.json"
            other.write_text(json.dumps({
                "crash_id": "other-crash-id", "observations": [
                    observation, {"poc_id": "an-unrelated-poc"}],
                "independent_verification_status": "BLOCKED_ROOT_CAUSE",
            }))
        seed_report = {"crash_inputs": [{
            "observed_crash_id": observed_id,
            "candidate_path": str(witness), "sha256": input_sha,
            "size": witness.stat().st_size,
        }]}
        record_targeted_fuzzer_observations(root, sp_id, seed_report)
        central = root / "runtime" / "fuzzer_crashes" / f"{observed_id}.json"
        return central, observed_id, canonical_id, input_sha

    def test_exact_replay_links_distinct_observed_and_canonical_ids(self):
        with TemporaryDirectory() as tmp:
            central_path, observed_id, canonical_id, input_sha = self._case(Path(tmp))
            self.assertNotEqual(observed_id, canonical_id)
            central = json.loads(central_path.read_text())
            self.assertEqual(central["status"], "PENDING_RUNTIME_REPLAY_AND_TRIAGE")
            self.assertEqual(central["replay_links"]["sp-synthetic"][input_sha], {
                "replay_poc_id": stable_id("poc", "sp-synthetic", input_sha,
                                            "fuzzer-replay"),
                "canonical_crash_id": canonical_id,
                "canonical_crash_artifact": str(central_path.parent.parent /
                                                "crashes" / f"{canonical_id}.json"),
                "canonical_record_verification_status": "VERIFIED",
                "canonical_verification_scope": "FIRST_OBSERVATION",
                "exact_input_independent_status": "VERIFIED",
            })

    def test_mismatched_or_ambiguous_canonical_evidence_does_not_link(self):
        for mismatch, duplicate, duplicate_exact in (
                ("0" * 64, False, False), (None, True, False),
                (None, False, True)):
            with self.subTest(mismatch=mismatch, duplicate=duplicate,
                              duplicate_exact=duplicate_exact):
                with TemporaryDirectory() as tmp:
                    central_path, _observed_id, _canonical_id, _input_sha = self._case(
                        Path(tmp), input_hash_override=mismatch,
                        duplicate=duplicate, duplicate_exact=duplicate_exact)
                    central = json.loads(central_path.read_text())
                    self.assertEqual(central["status"],
                                     "PENDING_RUNTIME_REPLAY_AND_TRIAGE")
                    self.assertFalse(central.get("replay_links"))

    def test_unrelated_observation_in_same_canonical_record_does_not_hide_exact_replay(self):
        with TemporaryDirectory() as tmp:
            central_path, _observed_id, canonical_id, input_sha = self._case(
                Path(tmp), unrelated=True)
            central = json.loads(central_path.read_text())
            self.assertEqual(central["replay_links"]["sp-synthetic"][input_sha][
                "canonical_crash_id"], canonical_id)
            self.assertEqual(central["status"], "PENDING_RUNTIME_REPLAY_AND_TRIAGE")

    def test_exact_source_blocked_status_is_preserved_without_gate_promotion(self):
        with TemporaryDirectory() as tmp:
            central_path, _observed_id, _canonical_id, input_sha = self._case(
                Path(tmp), canonical_status="BLOCKED_ROOT_CAUSE")
            central = json.loads(central_path.read_text())
            link = central["replay_links"]["sp-synthetic"][input_sha]
            self.assertEqual(link["canonical_record_verification_status"],
                             "BLOCKED_ROOT_CAUSE")
            self.assertEqual(link["canonical_verification_scope"],
                             "FIRST_OBSERVATION")
            self.assertEqual(link["exact_input_independent_status"],
                             "BLOCKED_ROOT_CAUSE")
            self.assertEqual(central["status"], "PENDING_RUNTIME_REPLAY_AND_TRIAGE")

    def test_symlinked_sp_corpus_ancestor_never_links_external_witness(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "run"
            root.mkdir()
            central_path, observed_id, _canonical_id, input_sha = self._case(root)
            central_path.unlink()
            corpus = root / "corpus" / "candidate" / "sp-synthetic"
            external = Path(tmp) / "external-corpus"
            corpus.rename(external)
            corpus.symlink_to(external, target_is_directory=True)
            witness = corpus / "crash-0"
            record_targeted_fuzzer_observations(root, "sp-synthetic", {
                "crash_inputs": [{"observed_crash_id": observed_id,
                                  "candidate_path": str(witness),
                                  "sha256": input_sha,
                                  "size": witness.stat().st_size}],
            })
            central = json.loads(central_path.read_text())
            self.assertEqual(central["status"], "PENDING_RUNTIME_REPLAY_AND_TRIAGE")
            self.assertFalse(central.get("replay_links"))

    def test_same_input_from_two_sps_keeps_order_independent_links(self):
        outcomes = []
        for order in (("sp-a", "sp-b"), ("sp-b", "sp-a")):
            with TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "runtime" / "crashes").mkdir(parents=True)
                data = b"shared crash input"
                input_sha = hashlib.sha256(data).hexdigest()
                observed_id = stable_id("sp-fuzzer-input", "1" * 64, input_sha)
                runtime = RuntimeResult(
                    1, "", "ERROR: AddressSanitizer: heap-use-after-free\n",
                    None, False, "AddressSanitizer: heap-use-after-free", None,
                    "TARGET_CRASH", crash_triage={"category": "TARGET_CRASH"})
                canonical_id = crash_fingerprint(runtime)
                observations = []
                reports = {}
                for sp_id in ("sp-a", "sp-b"):
                    corpus = root / "corpus" / "candidate" / sp_id
                    corpus.mkdir(parents=True)
                    witness = corpus / "crash-0"
                    witness.write_bytes(data)
                    poc_id = stable_id("poc", sp_id, input_sha, "fuzzer-replay")
                    runtime_path = root / "runtime" / f"{poc_id}.json"
                    runtime_path.write_text(json.dumps(runtime.__dict__))
                    observations.append({
                        "poc_id": poc_id, "sp_id": sp_id,
                        "input_sha256": input_sha,
                        "runtime_artifact": str(runtime_path),
                    })
                    reports[sp_id] = {"crash_inputs": [{
                        "observed_crash_id": observed_id,
                        "candidate_path": str(witness),
                        "sha256": input_sha, "size": len(data),
                    }]}
                (root / "runtime" / "crashes" / f"{canonical_id}.json").write_text(
                    json.dumps({"crash_id": canonical_id,
                                "independent_verification_status": "VERIFIED",
                                "observations": observations}))
                for sp_id in order:
                    record_targeted_fuzzer_observations(root, sp_id, reports[sp_id])
                central = json.loads((root / "runtime" / "fuzzer_crashes" /
                                      f"{observed_id}.json").read_text())
                self.assertEqual(central["status"],
                                 "PENDING_RUNTIME_REPLAY_AND_TRIAGE")
                self.assertEqual(set(central["replay_links"]), {"sp-a", "sp-b"})
                self.assertEqual({
                    sp_id: central["replay_links"][sp_id][input_sha]["replay_poc_id"]
                    for sp_id in order}, {
                    sp_id: stable_id("poc", sp_id, input_sha, "fuzzer-replay")
                    for sp_id in order})
                outcomes.append({sp_id: {
                    **central["replay_links"][sp_id][input_sha],
                    "canonical_crash_artifact": Path(central["replay_links"][
                        sp_id][input_sha]["canonical_crash_artifact"]).name,
                } for sp_id in ("sp-a", "sp-b")})
        self.assertEqual(outcomes[0], outcomes[1])

    def test_verified_signature_does_not_verify_later_distinct_input(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "runtime" / "crashes").mkdir(parents=True)
            sp_id = "sp-synthetic"
            corpus = root / "corpus" / "candidate" / sp_id
            corpus.mkdir(parents=True)
            runtime = RuntimeResult(
                1, "", "ERROR: AddressSanitizer: heap-use-after-free\n",
                None, False, "AddressSanitizer: heap-use-after-free", None,
                "TARGET_CRASH", crash_triage={"category": "TARGET_CRASH"})
            canonical_id = crash_fingerprint(runtime)
            observations = []
            rows = []
            for index, data in enumerate((b"first input", b"later input")):
                witness = corpus / f"crash-{index}"
                witness.write_bytes(data)
                input_sha = hashlib.sha256(data).hexdigest()
                poc_id = stable_id("poc", sp_id, input_sha, "fuzzer-replay")
                runtime_path = root / "runtime" / f"{poc_id}.json"
                runtime_path.write_text(json.dumps(runtime.__dict__))
                observations.append({
                    "poc_id": poc_id, "sp_id": sp_id,
                    "input_sha256": input_sha,
                    "runtime_artifact": str(runtime_path),
                })
                rows.append({
                    "observed_crash_id": stable_id(
                        "sp-fuzzer-input", "1" * 64, input_sha),
                    "candidate_path": str(witness), "sha256": input_sha,
                    "size": len(data),
                })
            (root / "runtime" / "crashes" / f"{canonical_id}.json").write_text(
                json.dumps({
                    "crash_id": canonical_id,
                    "independent_verification_status": "VERIFIED",
                    "independent_verification_source": {
                        "poc_id": observations[0]["poc_id"],
                        "input_sha256": observations[0]["input_sha256"],
                        "runtime_artifact": observations[0]["runtime_artifact"],
                    },
                    "observations": observations,
                }))
            record_targeted_fuzzer_observations(root, sp_id, {"crash_inputs": rows})
            links = []
            for row in rows:
                central = json.loads((root / "runtime" / "fuzzer_crashes" /
                    f"{row['observed_crash_id']}.json").read_text())
                self.assertEqual(central["status"],
                                 "PENDING_RUNTIME_REPLAY_AND_TRIAGE")
                links.append(central["replay_links"][sp_id][row["sha256"]])
            self.assertEqual([link["canonical_record_verification_status"]
                              for link in links],
                             ["VERIFIED", "VERIFIED"])
            self.assertEqual([link["exact_input_independent_status"] for link in links],
                             ["VERIFIED", "NOT_ASSESSED"])


if __name__ == "__main__":
    unittest.main()
