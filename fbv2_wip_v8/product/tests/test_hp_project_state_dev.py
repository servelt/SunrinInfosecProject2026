"""Provider-free two-function contract for bounded Code-Augur HP state."""

import asyncio
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import test_phase1
import test_sp_hp_independence
from vulnerabilityanalysis.hp_project_state import (finalize_hp_project_state,
    carry_hp_project_state, load_hp_project_state, prior_phi_assertions_for_source)
from vulnerabilityanalysis.scan import scan_selected
from vulnerabilityanalysis.scan import run_assertions_for_scan
from vulnerabilityanalysis.models import Assertion
from vulnerabilityanalysis.models import RuntimeResult
from vulnerabilityanalysis.assertions import guided_fuzz_assertion
from vulnerabilityanalysis.workflow import continue_phase1, run_phase1


class HPProjectStateDevTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.artifact, self.source_root = test_phase1.HarnessCreatorArtifactTest()._id_artifact(self.root)
        self.first = run_phase1(self.artifact, self.root / "results",
                                target_repository=self.source_root,
                                hp_project_state_dev=True)

    def complete_first(self):
        selection = json.loads((self.first / "selection.json").read_text())
        (self.first / "scan.json").write_text(json.dumps({
            "selected_function": selection["function_name"],
            "target_repository": str(self.source_root),
        }))
        return selection

    def write_bounded_guided_evidence(self, *, disposition="PROPOSED", status="RAN",
                                      fuzzer_exit_code=0, witnessed=False, reached=True):
        selection = self.complete_first()
        aid, safe = "toy-assertion", "input length is bounded"
        analysis_path = self.first / "analysis" / "selected.json"
        analysis_path.parent.mkdir(exist_ok=True)
        analysis_path.write_text(json.dumps({
            "function_id": selection["function_id"],
            "function_name": selection["function_name"],
            "safe_assumptions": [safe],
            "hypothesis_evaluations": [{"judgment": "EXPLICIT_SAFE_JUDGMENT",
                 "safe_assumption": safe}],
        }))
        assertions = self.first / "assertions"
        assertions.mkdir(exist_ok=True)
        (assertions / "dispositions.json").write_text(json.dumps([{
            "safe_id": 0, "safe_assumption": safe, "status": disposition,
            "reason": "public toy assertion proposal"}]))
        execution = assertions / aid / "executions" / "one"
        guided = execution / "guided_fuzz"
        corpus = guided / "corpus"
        corpus.mkdir(parents=True, exist_ok=True)
        runtime_path = execution / "runtime.json"
        runtime_path.write_text("{}")
        seed = corpus / "initial-seed"
        seed.write_bytes(b"A")
        manifest = guided / "corpus-manifest.json"
        manifest.write_text(json.dumps([{
            "path": str(seed), "sha256": hashlib.sha256(b"A").hexdigest(),
            "assertion_reached": reached, "assertion_violated": False,
        }]))
        (guided / "guided_fuzz.json").write_text(json.dumps({
            "assertion_id": aid, "status": status,
            "fuzzer_exit_code": fuzzer_exit_code, "fuzzer_run_count": 1,
            "replayed_inputs": 1, "replayed_reached": int(reached),
            "replayed_violated": 0,
            "violation_witnesses": [str(seed)] if witnessed else [],
            "other_crash_artifacts": [], "corpus_manifest": str(manifest),
        }))
        (assertions / "results.json").write_text(json.dumps([{
            "assertion_id": aid, "safe_assumption": safe,
            "worker_id": "worker", "direction_id": selection["direction_id"],
            "function": selection["function_name"],
            "source_location": "target.c:1", "runtime_expression": "1",
            "status": "HELD_FOR_EXECUTION", "execution_result": str(runtime_path),
            "source_function_analysis": str(analysis_path),
        }]))
        return seed

    def test_two_functions_receive_same_pinned_boundary(self):
        first_selection = self.complete_first()
        first = load_hp_project_state(self.first, self.source_root)
        self.assertEqual(first["Phi"], [])
        self.assertEqual(first["C"], [])
        self.assertEqual(first["omissions"]["truncated_phi_count"], 0)
        self.assertEqual(first["T"]["attacker_control"], "UNKNOWN")
        second = continue_phase1(self.first)
        second_selection = json.loads((second / "selection.json").read_text())
        self.assertNotEqual(first_selection["function_id"], second_selection["function_id"])
        self.assertEqual(load_hp_project_state(second, self.source_root)["T"], first["T"])

    def test_unproven_safe_and_untrusted_guided_input_do_not_carry(self):
        self.complete_first()
        (self.first / "function_analysis.json").write_text(json.dumps({
            "function_id": "fn-parse", "function_name": "parse_input",
            "safe_assumptions": ["n is bounded"],
            "hypothesis_evaluations": [{"judgment": "EXPLICIT_SAFE_JUDGMENT",
                 "safe_assumption": "n is bounded"}],
        }))
        finalize_hp_project_state(self.first, self.source_root)
        second = continue_phase1(self.first)
        carried = load_hp_project_state(second, self.source_root)
        self.assertEqual(carried["Phi"], [])
        self.assertEqual(carried["C"], [])

    def test_bounded_provisional_phi_and_replayed_guided_input_carry(self):
        self.write_bounded_guided_evidence()
        final = finalize_hp_project_state(self.first, self.source_root)
        self.assertEqual(len(final["Phi"]), 1)
        self.assertEqual(final["Phi"][0]["status"], "UNFALSIFIED_PROVISIONAL")
        self.assertFalse(final["Phi"][0]["gate_eligible"])
        self.assertEqual(len(final["C"]), 1)
        self.assertFalse(final["C"][0]["gate_eligible"])
        self.assertIn("current assertion reachability UNKNOWN", final["C"][0]["interpretation"])
        second = continue_phase1(self.first)
        carried = load_hp_project_state(second, self.source_root)
        self.assertEqual(carried["Phi"], final["Phi"])
        self.assertEqual(carried["C"], final["C"])
        local = second / "hp_guided_corpus" / final["C"][0]["local_name"]
        self.assertEqual(local.name, hashlib.sha1(b"A").hexdigest())
        self.assertEqual(local.read_bytes(), b"A")
        local.write_bytes(b"B")
        with self.assertRaisesRegex(ValueError, "corpus input"):
            load_hp_project_state(second, self.source_root)

    def test_prior_phi_source_pin_and_cross_file_boundary(self):
        self.write_bounded_guided_evidence()
        finalize_hp_project_state(self.first, self.source_root)
        second = continue_phase1(self.first)
        source = self.source_root / "target.c"
        checks = prior_phi_assertions_for_source(second, self.source_root, source)
        self.assertEqual([(row.assertion_id, row.runtime_expression) for row in checks],
                         [("toy-assertion", "1")])
        source.write_text(source.read_text() + "/* changed after pin */\n")
        with self.assertRaisesRegex(ValueError, "boundary|mismatch"):
            prior_phi_assertions_for_source(second, self.source_root, source)

    def test_prior_phi_other_file_or_function_is_rejected(self):
        self.write_bounded_guided_evidence()
        (self.source_root / "other.c").write_text("int other(void) { return 0; }\n")
        results = self.first / "assertions" / "results.json"
        rows = json.loads(results.read_text())
        rows[0]["source_location"] = "other.c:1"
        results.write_text(json.dumps(rows))
        finalize_hp_project_state(self.first, self.source_root)
        second = continue_phase1(self.first)
        with self.assertRaisesRegex(ValueError, "UNSUPPORTED_CROSS_FILE_PRIOR_PHI"):
            prior_phi_assertions_for_source(second, self.source_root,
                                            self.source_root / "target.c")

    def test_cross_file_prior_phi_rejected_before_sp_or_hp_model_call(self):
        split_root = self.root / "cross_file_preflight"
        split_root.mkdir()
        artifact, source_root = test_phase1.HarnessCreatorArtifactTest()._id_artifact(split_root)
        (source_root / "target.c").write_text(
            "int parse_input(const unsigned char *data) { return data[0]; }\n")
        (source_root / "other.c").write_text(
            "int entry_input(const unsigned char *data, unsigned long size) {\n"
            "  return size ? data[0] : 0;\n}\n")
        index = split_root / "analysis" / "functions.jsonl"
        rows = [json.loads(line) for line in index.read_text().splitlines()]
        for row in rows:
            if row["name"] == "entry_input":
                row["file"], row["start_line"] = "other.c", 1
        index.write_text("".join(json.dumps(row) + "\n" for row in rows))
        self.source_root = source_root
        self.first = run_phase1(artifact, split_root / "runs",
                                target_repository=source_root, hp_project_state_dev=True)
        self.assertEqual(self.write_bounded_guided_evidence().read_bytes(), b"A")
        finalize_hp_project_state(self.first, source_root)
        second = continue_phase1(self.first)
        self.assertEqual(json.loads((second / "selection.json").read_text())["function_name"],
                         "entry_input")
        seed = second / "seed"
        seed.write_bytes(b"A")
        provider = test_sp_hp_independence.Provider()
        for seconds in (0, 1):
            with self.subTest(assertion_fuzz_seconds=seconds):
                with self.assertRaisesRegex(ValueError, "UNSUPPORTED_CROSS_FILE_PRIOR_PHI"):
                    asyncio.run(scan_selected(
                        second, provider, target_repository=source_root,
                        run_command=["/usr/bin/true", "{input}"],
                        hallucination_prevent="on",
                        assertion_build_command=["/usr/bin/true", "{source}", "{binary}"],
                        assertion_run_command=["{binary}", "{input}"], assertion_seed=seed,
                        assertion_fuzz_seconds=seconds, fuzz_budget_seconds=2))
        self.assertEqual(provider.roles, [])
        self.assertFalse((second / "sp" / "candidates.json").exists())

    def test_prior_phi_wrong_function_origin_is_rejected(self):
        self.write_bounded_guided_evidence()
        analysis = self.first / "analysis" / "selected.json"
        analysis_row = json.loads(analysis.read_text())
        analysis_row["function_name"] = "entry_input"
        analysis.write_text(json.dumps(analysis_row))
        results = self.first / "assertions" / "results.json"
        rows = json.loads(results.read_text())
        rows[0]["function"] = "entry_input"
        results.write_text(json.dumps(rows))
        finalize_hp_project_state(self.first, self.source_root)
        second = continue_phase1(self.first)
        with self.assertRaisesRegex(ValueError, "function origin"):
            prior_phi_assertions_for_source(second, self.source_root,
                                            self.source_root / "target.c")

    def test_prior_phi_retraction_requires_benign_original_replay(self):
        self.write_bounded_guided_evidence()
        finalize_hp_project_state(self.first, self.source_root)
        second = continue_phase1(self.first)
        aid = "toy-assertion"
        folder = second / "assertions" / "new" / "executions" / "one" / "guided_fuzz"
        triage_dir = folder / "prior_phi_triage" / aid
        triage_dir.mkdir(parents=True)
        witness = folder / "crash-prior"
        witness.write_bytes(b"A")
        original = triage_dir / "original-runtime.json"
        original.write_text(json.dumps({"exit_code": 0, "sanitizer": None,
                                        "timed_out": False}))
        instrumented = triage_dir / "runtime.json"
        instrumented.write_text(json.dumps({"stderr":
                                            f"VA_ASSERTION_VIOLATION:{aid}\n"}))
        source = self.source_root / "target.c"
        quote = source.read_text().splitlines()[0]
        triage_path = triage_dir / "triage.json"
        review = {"review_status": "CONFIRMED_BENIGN", "source_file": str(source),
                  "source_line": "1", "source_quote": quote,
                  "reason": "public toy source review"}
        base = {"assertion_id": aid, "assertion_status": "VIOLATED",
                "original_source": str(source),
                "original_source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "input_path": str(witness),
                "input_sha256": hashlib.sha256(witness.read_bytes()).hexdigest(),
                "instrumented_runtime": str(instrumented),
                "original_runtime": str(original), "source_review": review}
        guided_path = folder / "guided_fuzz.json"

        def write_case(classification):
            triage_path.write_text(json.dumps({**base, "classification": classification}))
            guided_path.write_text(json.dumps({"status": "PRIOR_PHI_WITNESS_OBSERVED",
                "prior_phi_ids": [aid],
                "prior_phi_witnesses": [{"assertion_id": aid,
                                          "input_path": str(witness)}],
                "prior_phi_triage": [{"assertion_id": aid,
                                      "input_path": str(witness),
                                      "assertion_status": "VIOLATED",
                                      "triage_artifact": str(triage_path),
                                      "classification": classification}]}))

        write_case("INSUFFICIENT_EVIDENCE")
        unknown = finalize_hp_project_state(second, self.source_root)
        self.assertEqual(len(unknown["Phi"]), 1)
        self.assertEqual(unknown["retractions"], [])
        self.assertEqual(unknown["pending_prior_phi_ids"], [aid])
        with self.assertRaisesRegex(ValueError, "PENDING_PRIOR_PHI_TRIAGE"):
            carry_hp_project_state(second, self.root / "blocked_third", self.source_root)
        write_case("OVERSTRONG_ASSUMPTION")
        missing_witness = json.loads(guided_path.read_text())
        missing_witness["prior_phi_witnesses"] = []
        guided_path.write_text(json.dumps(missing_witness))
        with self.assertRaisesRegex(ValueError, "independent benign replay"):
            finalize_hp_project_state(second, self.source_root)
        write_case("OVERSTRONG_ASSUMPTION")
        malformed = json.loads(guided_path.read_text())
        malformed.pop("status")
        guided_path.write_text(json.dumps(malformed))
        with self.assertRaisesRegex(ValueError, "independent benign replay"):
            finalize_hp_project_state(second, self.source_root)
        write_case("OVERSTRONG_ASSUMPTION")
        malformed = json.loads(guided_path.read_text())
        malformed["prior_phi_ids"] = aid
        guided_path.write_text(json.dumps(malformed))
        with self.assertRaisesRegex(ValueError, "identity list"):
            finalize_hp_project_state(second, self.source_root)
        write_case("OVERSTRONG_ASSUMPTION")
        wrong_path = json.loads(guided_path.read_text())
        wrong_path["prior_phi_witnesses"][0]["input_path"] = str(folder / "other")
        guided_path.write_text(json.dumps(wrong_path))
        with self.assertRaisesRegex(ValueError, "independent benign replay"):
            finalize_hp_project_state(second, self.source_root)
        write_case("OVERSTRONG_ASSUMPTION")
        original.write_text(json.dumps({"exit_code": 1, "sanitizer": None,
                                        "timed_out": False}))
        with self.assertRaisesRegex(ValueError, "independent benign replay"):
            finalize_hp_project_state(second, self.source_root)
        original.write_text(json.dumps({"exit_code": 0, "sanitizer": None,
                                        "timed_out": False}))
        retracted = finalize_hp_project_state(second, self.source_root)
        self.assertEqual(retracted["Phi"], [])
        self.assertEqual(retracted["pending_prior_phi_ids"], [])
        self.assertEqual([row["assertion_id"] for row in retracted["retractions"]], [aid])
        witness.write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "retraction artifact changed"):
            load_hp_project_state(second, self.source_root)

    def test_second_function_analyzer_receives_provisional_not_safe(self):
        self.write_bounded_guided_evidence()
        finalize_hp_project_state(self.first, self.source_root)
        second = continue_phase1(self.first)
        provider = test_sp_hp_independence.Provider()
        asyncio.run(scan_selected(second, provider, target_repository=self.source_root,
                                  run_command=["/usr/bin/true", "{input}"],
                                  hallucination_prevent="on"))
        payload = provider.function_payload
        self.assertIsNotNone(payload)
        prior = payload["analysis_scope"]["hp_project_state"]
        self.assertEqual(prior["T"]["attacker_control"], "UNKNOWN")
        self.assertEqual(prior["Phi"][0]["status"], "UNFALSIFIED_PROVISIONAL")
        self.assertIn("safety remains UNKNOWN", prior["Phi"][0]["interpretation"])
        self.assertEqual(prior["C"][0]["sha256"], hashlib.sha256(b"A").hexdigest())
        self.assertFalse(load_hp_project_state(second, self.source_root)["gate_eligible"])

    def test_missing_disposition_or_failed_guided_run_never_promotes_safe(self):
        for changed in ({"disposition": "NOT_INPUT_DEPENDENT"},
                        {"status": "ERROR"},
                        {"status": "ASSERTION_WITNESS_OBSERVED"},
                        {"status": "CRASH_OBSERVED_INCOMPLETE"},
                        {"status": "PENDING_SHARED_PHYSICAL_BUDGET"},
                        {"fuzzer_exit_code": 1},
                        {"witnessed": True}, {"reached": False}):
            with self.subTest(changed=changed):
                self.write_bounded_guided_evidence(**changed)
                state = finalize_hp_project_state(self.first, self.source_root)
                self.assertEqual(state["Phi"], [])
                self.assertEqual(state["C"], [])

    def test_verified_prior_corpus_is_passed_to_guided_fuzzer(self):
        """Provider-free plumbing check; this deliberately does not fuzz."""
        self.write_bounded_guided_evidence()
        finalize_hp_project_state(self.first, self.source_root)
        second = continue_phase1(self.first)
        source = self.source_root / "target.c"
        selected = json.loads((second / "selection.json").read_text())
        safe = "a bounded public toy assumption"
        analysis_path = second / "analysis.json"
        analysis_path.write_text(json.dumps({"function_name": selected["function_name"],
                                            "safe_assumptions": [safe]}))
        assertion = Assertion("second-assertion", "worker", selected["direction_id"],
                              selected["function_name"], "target.c:1", safe, "1", [],
                              source_function_analysis=str(analysis_path))
        (second / "assertions").mkdir(exist_ok=True)
        (second / "assertions" / "proposed.json").write_text(json.dumps([assertion.__dict__]))
        seed = second / "seed"
        seed.write_bytes(b"A")
        captured = []
        physical_runner = lambda _argv, **_kwargs: None

        def fake_execute(item, _source, _line, _seed, folder, *_args, **_kwargs):
            folder.mkdir(parents=True, exist_ok=True)
            runtime = folder / "runtime.json"
            runtime.write_text("{}")
            item.status = "HELD_FOR_EXECUTION"
            item.execution_result = str(runtime)
            return item, None

        def fake_guided(*_args, **kwargs):
            captured.append((kwargs.get("prior_corpus"),
                             kwargs.get("prior_corpus_allowlist"),
                             kwargs.get("guarded_runner"),
                             kwargs.get("prior_phi_assertions")))
            return {"status": "RAN", "violation_triage": {}}

        with patch("vulnerabilityanalysis.scan.assess_safe_assumption",
                   return_value={"quality": "POSSIBLE", "reasons": []}), \
             patch("vulnerabilityanalysis.scan.execute_assertion", side_effect=fake_execute), \
             patch("vulnerabilityanalysis.scan.guided_fuzz_assertion", side_effect=fake_guided):
            run_assertions_for_scan(second, source, seed, ["true", "{source}"],
                                    ["{binary}", "{input}"], fuzz_seconds=1,
                                    prior_guided_corpus=second / "hp_guided_corpus",
                                    guarded_runner=physical_runner)
        self.assertEqual(captured[0][0], second / "hp_guided_corpus")
        self.assertEqual(captured[0][1], load_hp_project_state(second, self.source_root)["C"])
        self.assertIs(captured[0][2], physical_runner)
        self.assertEqual([row.assertion_id for row in captured[0][3]], ["toy-assertion"])
        self.assertEqual(len(captured), 1)
        self.assertEqual(len(load_hp_project_state(second, self.source_root)["C"]), 1)
        (second / "hp_guided_corpus" / ("f" * 40)).write_bytes(b"unregistered")
        captured.clear()
        with patch("vulnerabilityanalysis.scan.assess_safe_assumption",
                   return_value={"quality": "POSSIBLE", "reasons": []}), \
             patch("vulnerabilityanalysis.scan.execute_assertion", side_effect=fake_execute), \
             patch("vulnerabilityanalysis.scan.guided_fuzz_assertion", side_effect=fake_guided):
            with self.assertRaisesRegex(ValueError, "registered C"):
                run_assertions_for_scan(second, source, seed, ["true", "{source}"],
                                        ["{binary}", "{input}"], fuzz_seconds=1,
                                        prior_guided_corpus=second / "hp_guided_corpus",
                                        guarded_runner=physical_runner)
        self.assertEqual(captured, [])

    def test_carried_seed_is_actually_imported_by_guided_fuzzer(self):
        """Mock build and fuzz execution; exercise the real corpus importer."""
        self.write_bounded_guided_evidence()
        finalize_hp_project_state(self.first, self.source_root)
        second = continue_phase1(self.first)
        source = self.source_root / "target.c"
        seed = second / "seed"
        seed.write_bytes(b"B")
        aid = "second-assertion"
        assertion = Assertion(aid, "worker", "direction", "parse_input", "target.c:1",
                              "input length is bounded", "1", [])

        def fake_instrument(_source, _line, _expr, destination, *_args, **_kwargs):
            destination.write_text("/* public toy */\n")
            return destination

        def fake_run(argv, **_kwargs):
            if "-o" in argv:
                Path(argv[argv.index("-o") + 1]).write_bytes(b"fake binary")
            return subprocess.CompletedProcess(argv, 0, "", "16 Extra Counters\n"
                f"VA_ASSERTION_HIT:{aid}\n")

        runtime = RuntimeResult(0, "", "stat::number_of_executed_units: 1\n",
                                None, False, None, None, "RAN")
        with patch("vulnerabilityanalysis.assertions.instrument_copy", side_effect=fake_instrument), \
             patch("vulnerabilityanalysis.assertions._run_assertion_command", side_effect=fake_run), \
             patch("vulnerabilityanalysis.assertions.fuzz_locally", return_value=runtime):
            report = guided_fuzz_assertion(
                assertion, source, 1, seed, second / "guided_import_probe",
                ["cc", "{source}", "-o", "{binary}"], ["{binary}", "{input}"],
                seconds=1, prior_corpus=second / "hp_guided_corpus",
                prior_corpus_allowlist=load_hp_project_state(second, self.source_root)["C"])
        self.assertEqual(report["status"], "RAN")
        self.assertEqual(len(report["carried_corpus"]), 1)
        self.assertEqual(report["carried_corpus"][0]["sha256"],
                         hashlib.sha256(b"A").hexdigest())
        self.assertEqual(report["corpus_reused_count"], 1)

        def inject_during_build(argv, **kwargs):
            result = fake_run(argv, **kwargs)
            if "-o" in argv:
                (second / "hp_guided_corpus" / ("f" * 40)).write_bytes(b"unregistered")
            return result

        with patch("vulnerabilityanalysis.assertions.instrument_copy", side_effect=fake_instrument), \
             patch("vulnerabilityanalysis.assertions._run_assertion_command",
                   side_effect=inject_during_build), \
             patch("vulnerabilityanalysis.assertions.fuzz_locally", return_value=runtime):
            with self.assertRaisesRegex(ValueError, "registered C"):
                guided_fuzz_assertion(assertion, source, 1, seed,
                    second / "guided_import_attack", ["cc", "{source}", "-o", "{binary}"],
                    ["{binary}", "{input}"], seconds=1,
                    prior_corpus=second / "hp_guided_corpus",
                    prior_corpus_allowlist=load_hp_project_state(second, self.source_root)["C"])
        (second / "hp_guided_corpus" / ("f" * 40)).unlink()
        registered = load_hp_project_state(second, self.source_root)["C"]
        def mutate_registered_during_build(argv, **kwargs):
            result = fake_run(argv, **kwargs)
            if "-o" in argv:
                (second / "hp_guided_corpus" / registered[0]["local_name"]).write_bytes(b"B")
            return result
        with patch("vulnerabilityanalysis.assertions.instrument_copy", side_effect=fake_instrument), \
             patch("vulnerabilityanalysis.assertions._run_assertion_command",
                   side_effect=mutate_registered_during_build), \
             patch("vulnerabilityanalysis.assertions.fuzz_locally", return_value=runtime):
            with self.assertRaisesRegex(ValueError, "bytes differ"):
                guided_fuzz_assertion(assertion, source, 1, seed,
                    second / "guided_import_mutation", ["cc", "{source}", "-o", "{binary}"],
                    ["{binary}", "{input}"], seconds=1,
                    prior_corpus=second / "hp_guided_corpus",
                    prior_corpus_allowlist=registered)

    def test_intermediate_symlink_in_analysis_origin_is_rejected(self):
        self.write_bounded_guided_evidence()
        linked = self.first / "analysis_link"
        linked.symlink_to(self.first / "analysis", target_is_directory=True)
        results = self.first / "assertions" / "results.json"
        rows = json.loads(results.read_text())
        rows[0]["source_function_analysis"] = str(linked / "selected.json")
        results.write_text(json.dumps(rows))
        with self.assertRaisesRegex(ValueError, "symlink|boundary"):
            finalize_hp_project_state(self.first, self.source_root)

    def test_corpus_directory_symlink_is_rejected_before_copy(self):
        self.write_bounded_guided_evidence()
        outside = self.root / "outside"
        outside.mkdir()
        (self.first / "hp_guided_corpus").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink|boundary"):
            finalize_hp_project_state(self.first, self.source_root)
        self.assertEqual(list(outside.iterdir()), [])

    def test_intermediate_symlink_in_guided_origin_is_rejected(self):
        seed = self.write_bounded_guided_evidence()
        corpus = seed.parent
        moved = self.root / "moved_corpus"
        corpus.rename(moved)
        corpus.symlink_to(moved, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            finalize_hp_project_state(self.first, self.source_root)

    def test_capacity_omissions_are_recorded(self):
        self.write_bounded_guided_evidence()
        with patch("vulnerabilityanalysis.hp_project_state.MAX_PHI_ROWS", 0), \
             patch("vulnerabilityanalysis.hp_project_state.MAX_CORPUS_FILES", 0):
            state = finalize_hp_project_state(self.first, self.source_root)
        self.assertEqual(state["Phi"], [])
        self.assertEqual(state["C"], [])
        self.assertEqual(state["omissions"]["truncated_phi_count"], 1)
        self.assertEqual(state["omissions"]["truncated_corpus_count"], 1)

    def test_oversize_guided_seed_is_counted_without_carry(self):
        self.write_bounded_guided_evidence()
        with patch("vulnerabilityanalysis.hp_project_state.MAX_INPUT_BYTES", 0):
            state = finalize_hp_project_state(self.first, self.source_root)
        self.assertEqual(state["Phi"], [])
        self.assertEqual(state["C"], [])
        self.assertEqual(state["omissions"]["oversize_corpus_count"], 1)

    def test_tampered_source_pin_rejected_before_next_function(self):
        self.complete_first()
        (self.source_root / "target.c").write_text("int changed(void) {return 0;}\n")
        with self.assertRaisesRegex(ValueError, "source|boundary"):
            continue_phase1(self.first)

    def test_tampered_harness_pin_rejected_before_next_function(self):
        self.complete_first()
        (self.artifact / "fuzz.c").write_text("int changed_harness(void) {return 0;}\n")
        with self.assertRaisesRegex(ValueError, "boundary"):
            continue_phase1(self.first)

    def test_tampered_state_hash_rejected_before_next_function(self):
        self.complete_first()
        state_path = self.first / "hp_project_state.json"
        state_path.write_bytes(state_path.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "state|SHA"):
            continue_phase1(self.first)

    def test_origin_manifest_tamper_rejected_before_following_function(self):
        self.write_bounded_guided_evidence()
        finalized = finalize_hp_project_state(self.first, self.source_root)
        origin = Path(finalized["C"][0]["origin_manifest_path"])
        origin.write_bytes(origin.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "origin manifest|Guided replay"):
            continue_phase1(self.first)


if __name__ == "__main__":
    unittest.main()
