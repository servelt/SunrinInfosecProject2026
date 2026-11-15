"""A checked HP corpus must stay pinned through the Guided import itself."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import vulnerabilityanalysis

PRODUCT_TESTS = Path(vulnerabilityanalysis.__file__).resolve().parents[2] / "tests"
sys.path.insert(0, str(PRODUCT_TESTS))
import test_hp_project_state_dev as hp_fixture
from vulnerabilityanalysis.hp_project_state import finalize_hp_project_state
from vulnerabilityanalysis.models import Assertion, RuntimeResult
from vulnerabilityanalysis.scan import run_assertions_for_scan
from vulnerabilityanalysis.workflow import continue_phase1


class HPImportedCorpusTimeOfCheckTest(unittest.TestCase):
    def _run_build_mutation(self, mutation):
        fixture = hp_fixture.HPProjectStateDevTest(
            "test_two_functions_receive_same_pinned_boundary")
        fixture.setUp()
        try:
            fixture.write_bounded_guided_evidence()
            finalize_hp_project_state(fixture.first, fixture.source_root)
            second = continue_phase1(fixture.first)
            selection = json.loads((second / "selection.json").read_text())
            safe = "a bounded public toy assumption"
            analysis = second / "analysis.json"
            analysis.write_text(json.dumps({"function_name": selection["function_name"],
                                            "safe_assumptions": [safe]}))
            assertion = Assertion("second-assertion", "worker", selection["direction_id"],
                                  selection["function_name"], "target.c:1", safe, "1", [],
                                  source_function_analysis=str(analysis))
            (second / "assertions").mkdir(exist_ok=True)
            (second / "assertions" / "proposed.json").write_text(
                json.dumps([assertion.__dict__]))
            seed = second / "seed"
            seed.write_bytes(b"B")
            prior = second / "hp_guided_corpus"
            tampered = b"unregistered or changed after the state check"
            tampered_sha = hashlib.sha256(tampered).hexdigest()
            registered_name = next(prior.iterdir()).name

            def fake_execute(item, _source, _line, _seed, folder, *_args, **_kwargs):
                folder.mkdir(parents=True)
                runtime = folder / "runtime.json"
                runtime.write_text("{}")
                item.status = "HELD_FOR_EXECUTION"
                item.execution_result = str(runtime)
                return item, None

            def fake_instrument(_source, _line, _expression, destination, *_args, **_kwargs):
                destination.write_text("/* public toy source */\n")
                return destination

            def fake_build(argv, **_kwargs):
                if "-o" in argv:
                    # The product checks C before calling Guided. Its build runs
                    # after that check and before Guided reads the prior corpus.
                    name = (hashlib.sha1(tampered).hexdigest() if mutation == "add"
                            else registered_name)
                    (prior / name).write_bytes(tampered)
                    Path(argv[argv.index("-o") + 1]).write_bytes(b"fake binary")
                return subprocess.CompletedProcess(
                    argv, 0, "", "16 Extra Counters\nVA_ASSERTION_HIT:second-assertion\n")

            runtime = RuntimeResult(0, "", "stat::number_of_executed_units: 1\n",
                                    None, False, None, None, "RAN")
            with patch("vulnerabilityanalysis.scan.assess_safe_assumption",
                       return_value={"quality": "POSSIBLE", "reasons": []}), \
                 patch("vulnerabilityanalysis.scan.execute_assertion",
                       side_effect=fake_execute), \
                 patch("vulnerabilityanalysis.assertions.instrument_copy",
                       side_effect=fake_instrument), \
                 patch("vulnerabilityanalysis.assertions._run_assertion_command",
                       side_effect=fake_build), \
                 patch("vulnerabilityanalysis.assertions.fuzz_locally",
                       return_value=runtime):
                try:
                    run_assertions_for_scan(
                        second, fixture.source_root / "target.c", seed,
                        ["cc", "{source}", "-o", "{binary}"],
                        ["{binary}", "{input}"], fuzz_seconds=1,
                        prior_guided_corpus=prior)
                except ValueError as exc:
                    self.assertRegex(str(exc),
                                     r"HP prior corpus (directory differs|bytes differ)")
                    return
            reports = list((second / "assertions").glob(
                "*/executions/*/guided_fuzz/guided_fuzz.json"))
            self.assertEqual(len(reports), 1)
            report = json.loads(reports[0].read_text())
            carried_shas = {row["sha256"] for row in report["carried_corpus"]}
            self.assertNotIn(tampered_sha, carried_shas,
                             "a changed input reached the next Guided corpus")
        finally:
            fixture.temporary.cleanup()

    def test_build_cannot_add_an_unregistered_carried_input(self):
        self._run_build_mutation("add")

    def test_build_cannot_replace_registered_carried_bytes(self):
        self._run_build_mutation("replace")


if __name__ == "__main__":
    unittest.main()
