"""A refined HP Guided run imports only a recorded prior corpus snapshot."""

import asyncio
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulnerabilityanalysis.assertions import _load_pinned_prior_corpus
from vulnerabilityanalysis.models import Assertion, FunctionAnalysis
from vulnerabilityanalysis.scan import (_pin_refinement_prior_corpus,
                                        refine_overstrong_assertions)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class HPRefinementCorpusPinTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.execution = self.root / "assertions" / "old" / "executions" / "one"
        self.guided = self.execution / "guided_fuzz"
        self.corpus = self.guided / "corpus"
        self.corpus.mkdir(parents=True)
        self.seed = self.corpus / "initial-seed"
        self.seed.write_bytes(b"A")
        self.mutation = self.corpus / hashlib.sha1(b"B").hexdigest()
        self.mutation.write_bytes(b"B")
        self.manifest = self.guided / "corpus-manifest.json"
        self.rows = [
            {"path": str(self.seed), "sha256": sha(b"A"),
             "assertion_reached": True, "assertion_violated": False},
            {"path": str(self.mutation), "sha256": sha(b"B"),
             "assertion_reached": False, "assertion_violated": False},
        ]
        self.write_prior_report()
        self.revision = self.root / "assertions" / "old" / "refinement" / "new"

    def write_prior_report(self):
        self.manifest.write_text(json.dumps(self.rows, sort_keys=True) + "\n")
        (self.guided / "guided_fuzz.json").write_text(json.dumps({
            "status": "RAN", "corpus_manifest": str(self.manifest),
            "corpus_manifest_sha256": sha(self.manifest.read_bytes()),
        }) + "\n")

    def test_initial_seed_and_mutation_are_pinned_by_content_name(self):
        folder, allowlist, receipt = _pin_refinement_prior_corpus(
            self.execution, self.revision)
        self.assertEqual(len(allowlist), 2)
        self.assertEqual({row["local_name"] for row in allowlist},
                         {hashlib.sha1(b"A").hexdigest(),
                          hashlib.sha1(b"B").hexdigest()})
        self.assertEqual({data for _, data in
                          _load_pinned_prior_corpus(folder, allowlist)},
                         {b"A", b"B"})
        self.assertEqual(receipt["source_manifest_sha256"],
                         sha(self.manifest.read_bytes()))
        self.assertEqual(receipt["source_policy"],
                         "RECORDED_INITIAL_GUIDED_CORPUS_ONLY")

    def test_replayed_assertion_witness_retains_strict_corpus_lineage(self):
        report_path = self.guided / "guided_fuzz.json"
        report = json.loads(report_path.read_text())
        report["status"] = "ASSERTION_WITNESS_OBSERVED"
        report["violation_triage"] = {"assertion_status": "VIOLATED"}
        report_path.write_text(json.dumps(report))
        folder, allowlist, receipt = _pin_refinement_prior_corpus(
            self.execution, self.revision)
        self.assertEqual(receipt["status"], "PINNED")
        self.assertEqual({data for _, data in
                          _load_pinned_prior_corpus(folder, allowlist)}, {b"A", b"B"})

    def test_copied_byte_or_extra_file_is_rejected_on_guided_import(self):
        folder, allowlist, _ = _pin_refinement_prior_corpus(
            self.execution, self.revision)
        (folder / allowlist[0]["local_name"]).write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "prior corpus bytes differ"):
            _load_pinned_prior_corpus(folder, allowlist)
        (folder / allowlist[0]["local_name"]).write_bytes(b"A")
        (folder / "extra").write_bytes(b"C")
        with self.assertRaisesRegex(ValueError, "directory differs"):
            _load_pinned_prior_corpus(folder, allowlist)

    def test_changed_original_manifest_or_seed_is_rejected_before_pin(self):
        self.seed.write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "manifest.*bytes"):
            _pin_refinement_prior_corpus(self.execution, self.revision)
        self.seed.write_bytes(b"A")
        self.manifest.write_text(self.manifest.read_text() + " ")
        with self.assertRaisesRegex(ValueError, "manifest.*SHA"):
            _pin_refinement_prior_corpus(self.execution, self.revision)

    def test_oversized_tampered_input_cannot_skip_manifest_hash(self):
        self.seed.write_bytes(b"X" * 2_097_153)
        with self.assertRaisesRegex(ValueError, "manifest.*bytes"):
            _pin_refinement_prior_corpus(self.execution, self.revision)

    def test_empty_tampered_input_cannot_skip_manifest_hash(self):
        self.seed.write_bytes(b"")
        with self.assertRaisesRegex(ValueError, "manifest.*bytes"):
            _pin_refinement_prior_corpus(self.execution, self.revision)

    def test_original_oversized_input_is_explicitly_omitted(self):
        data = b"X" * 2_097_153
        self.seed.write_bytes(data)
        self.rows[0]["sha256"] = sha(data)
        self.write_prior_report()
        folder, allowlist, receipt = _pin_refinement_prior_corpus(
            self.execution, self.revision)
        self.assertEqual({entry["source_names"][0] for entry in allowlist},
                         {self.mutation.name})
        self.assertEqual(receipt["omitted_input_count"], 1)
        self.assertEqual({blob for _, blob in
                          _load_pinned_prior_corpus(folder, allowlist)}, {b"B"})

    def test_prior_corpus_symlink_is_rejected(self):
        self.mutation.unlink()
        self.mutation.symlink_to(self.seed)
        with self.assertRaisesRegex(ValueError, "linked prior corpus"):
            _pin_refinement_prior_corpus(self.execution, self.revision)

    def test_hash_named_input_must_match_its_content(self):
        self.mutation.write_bytes(b"C")
        self.rows[1]["sha256"] = sha(b"C")
        self.write_prior_report()
        with self.assertRaisesRegex(ValueError, "content name differs"):
            _pin_refinement_prior_corpus(self.execution, self.revision)

    def test_prior_report_without_manifest_digest_is_rejected(self):
        report_path = self.guided / "guided_fuzz.json"
        report = json.loads(report_path.read_text())
        del report["corpus_manifest_sha256"]
        report_path.write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, "manifest SHA-256 differs"):
            _pin_refinement_prior_corpus(self.execution, self.revision)

    def test_missing_prior_report_reuses_no_corpus(self):
        (self.guided / "guided_fuzz.json").unlink()
        folder, allowlist, receipt = _pin_refinement_prior_corpus(
            self.execution, self.revision)
        self.assertIsNone(folder)
        self.assertEqual(allowlist, [])
        self.assertEqual(receipt["status"], "NO_PINNED_PREVIOUS_GUIDED")

    def test_refinement_passes_pinned_allowlist_to_second_guided(self):
        run = self.root / "run"
        assertions = run / "assertions"
        assertions.mkdir(parents=True)
        source = self.root / "target.c"
        source.write_text("int target(int n) { return n; }\n")
        (run / "run.json").write_text('{"run_id":"pin-test"}')
        prior_runtime = self.execution / "runtime.json"
        prior_runtime.write_text("{}")
        (self.execution / "triage.json").write_text(json.dumps({
            "classification": "OVERSTRONG_ASSUMPTION",
            "input_path": str(self.seed),
            "original_runtime": str(prior_runtime),
            "source_review": "benign on the original binary",
        }))
        original = Assertion("old", "worker", "direction", "target",
                             "target.c:1", "n is below 2", "n < 2", [],
                             status="VIOLATED", execution_result=str(prior_runtime))
        (assertions / "results.json").write_text(json.dumps([asdict(original)]))

        class Roles:
            async def analyze_function(self, *_args, **_kwargs):
                return FunctionAnalysis("target", "target", "target.c",
                                        "revised", "seed", [], [],
                                        ["n is below 3"], [])

            async def generate_assertions(self, *_args, **_kwargs):
                return [Assertion("revised", "worker", "direction",
                                  "target", "target.c:1", "n is below 3",
                                  "n < 3", [])]

        observed = []

        def fake_execute(item, _source, _line, _seed, output, *_args, **_kwargs):
            output.mkdir(parents=True)
            runtime = output / "runtime.json"
            runtime.write_text("{}")
            item.status = "HELD_FOR_EXECUTION"
            item.execution_result = str(runtime)
            return item, None

        def fake_guided(*_args, **kwargs):
            observed.append({
                "seconds": kwargs["seconds"],
                "data": {data for _, data in _load_pinned_prior_corpus(
                    kwargs["prior_corpus"], kwargs["prior_corpus_allowlist"])},
            })
            return {"status": "RAN", "violation_witnesses": []}

        with patch("vulnerabilityanalysis.scan.refinement_rejection_reasons",
                   return_value=[]), patch(
                   "vulnerabilityanalysis.scan.execute_assertion",
                   side_effect=fake_execute), patch(
                   "vulnerabilityanalysis.scan.guided_fuzz_assertion",
                   side_effect=fake_guided):
            report = asyncio.run(refine_overstrong_assertions(
                run, Roles(), function_id="target", function_name="target",
                source_file="target.c", source=source.read_text(),
                original_source=source, source_start_line=1, context=[],
                build_command=["cc"], run_command=["./target"],
                fuzz_seconds=1, max_llm_calls=2))
        self.assertEqual(observed, [{"seconds": 1, "data": {b"A", b"B"}}])
        revision = report["refinements"][0]["revisions"][0]
        self.assertEqual(revision["prior_corpus_pin"]["status"], "PINNED")
        self.assertFalse(revision["prior_corpus_pin"]["continuation_corpus_imported"])


if __name__ == "__main__":
    unittest.main()
