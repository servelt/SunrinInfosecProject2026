import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from vulnerabilityanalysis.scan import (retain_worker_initial_inputs,
    sync_worker_corpus, worker_corpus_folder, worker_corpus_identity)
from vulnerabilityanalysis.__main__ import worker_fuzz_seconds_used, worker_campaign_id
from vulnerabilityanalysis.workflow import write_json


class WorkerCorpusTest(unittest.TestCase):
    def test_two_function_runs_share_only_compatible_seed_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            target.mkdir()
            (target / "source.c").write_text("int target(void) { return 1; }\n")
            subprocess.run(["git", "init", "-q", str(target)], check=True)
            subprocess.run(["git", "-C", str(target), "add", "source.c"], check=True)
            subprocess.run(["git", "-C", str(target), "-c", "user.name=test",
                            "-c", "user.email=test@example.invalid", "commit", "-qm", "source"], check=True)
            harness = root / "harness.c"
            harness.write_text("int LLVMFuzzerTestOneInput(void) { return 0; }\n")
            binary = root / "fuzzer"
            binary.write_bytes(b"fuzzer-build-one")
            seed = root / "initial.bin"
            seed.write_bytes(b"initial")
            first, second = root / "results/fn-one", root / "results/fn-two"
            for run in (first, second):
                write_json(run / "run.json", {"harness_id": "h", "run_id": run.name})
                write_json(run / "harness.json", {"harness_path": str(harness)})
                write_json(run / "workers.json", [{"harness_id": "h", "worker_id": "w",
                                                   "sanitizer": "ASAN"}])
            identity = worker_corpus_identity(first, target, binary, ["ASAN"])
            shared = worker_corpus_folder(first, identity)
            self.assertEqual(shared, worker_corpus_folder(second,
                worker_corpus_identity(second, target, binary, ["ASAN"])))
            retain_worker_initial_inputs(shared, [seed, seed], first.name)
            first_import = sync_worker_corpus(first, shared, direction="import")
            self.assertEqual(first_import["new_count"], 1)
            (first / "corpus/global/pov.bin").write_bytes(b"pov-failure")
            (first / "corpus/global/sp.bin").write_bytes(b"sp-mutation")
            write_json(first / "corpus/initial_inputs.json", [{"sha256": hashlib.sha256(b"initial").hexdigest()}])
            write_json(first / "runtime/sp.targeted_fuzz.seeds.json", {
                "new_seeds": [{"sha256": hashlib.sha256(b"sp-mutation").hexdigest()}]})
            exported = sync_worker_corpus(first, shared, direction="export")
            self.assertEqual(exported["destination_count"], 3)
            reused = sync_worker_corpus(second, shared, direction="import")
            self.assertEqual(reused["new_count"], 3)
            self.assertEqual(len(list((second / "corpus/global").iterdir())), 3)
            provenance = json.loads((shared / "seed_provenance.json").read_text())
            self.assertIn({"run_id": first.name, "kind": "SP_FUZZ"},
                          provenance[hashlib.sha256(b"sp-mutation").hexdigest()]["origins"])
            self.assertEqual(sync_worker_corpus(second, shared, direction="import")["new_count"], 0)
            self.assertNotEqual(shared, worker_corpus_folder(second,
                worker_corpus_identity(second, target, binary, ["ASAN"],
                                       campaign_id="independent-blind-run")))
            write_json(first / "experiment_setup.json", {"worker_corpus": str(shared)})
            write_json(second / "experiment_setup.json", {"worker_corpus": str(shared)})
            write_json(first / "scan.json", {"fuzz_seconds_allocated": 3})
            write_json(second / "runtime/fuzz_allocation.json", {"allocated_seconds": 2})
            self.assertEqual(worker_fuzz_seconds_used(second, shared), 5)
            self.assertIsNone(worker_campaign_id(second, first))  # legacy campaign retained
            # Automatically created child runs have no experiment_setup.json;
            # a retry must still inherit the original worker corpus identity.
            child = root / "results/child"
            retry = root / "results/retry"
            write_json(child / "run.json", {"run_id": child.name,
                                             "parent_run_id": first.name})
            write_json(retry / "run.json", {"run_id": retry.name,
                                             "retry_source_run_id": child.name})
            self.assertIsNone(worker_campaign_id(retry, child))
            write_json(child / "runtime/fuzz_allocation.json", {"allocated_seconds": 2})
            write_json(retry / "runtime/fuzz_allocation.json", {"allocated_seconds": 1})
            self.assertEqual(worker_fuzz_seconds_used(second, shared), 8)
            isolated = worker_corpus_folder(first, worker_corpus_identity(
                first, target, binary, ["ASAN"], campaign_id="separate-campaign"))
            write_json(first / "experiment_setup.json", {"worker_corpus": str(isolated)})
            self.assertEqual(worker_campaign_id(retry, child), "separate-campaign")
            self.assertNotEqual(shared, worker_corpus_folder(second,
                worker_corpus_identity(second, target, binary, ["UBSAN"])))
            write_json(second / "workers.json", [{"harness_id": "h", "worker_id": "other-worker",
                                                  "sanitizer": "ASAN"}])
            self.assertNotEqual(shared, worker_corpus_folder(second,
                worker_corpus_identity(second, target, binary, ["ASAN"])))
            binary.write_bytes(b"fuzzer-build-two")
            self.assertNotEqual(shared, worker_corpus_folder(second,
                worker_corpus_identity(second, target, binary, ["ASAN"])))
            (target / "source.c").write_text("int target(void) { return 2; }\n")
            with self.assertRaisesRegex(ValueError, "unmodified tracked target"):
                worker_corpus_identity(second, target, binary, ["ASAN"])
