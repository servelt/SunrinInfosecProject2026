"""A revised HP assertion cannot spend Guided time outside the Scan budget."""

import asyncio
from dataclasses import asdict
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulnerabilityanalysis.models import Assertion, FunctionAnalysis
from vulnerabilityanalysis.scan import refine_overstrong_assertions


class HPRefinementFuzzBudgetTest(unittest.TestCase):
    def test_refinement_uses_only_one_remaining_second(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / "run"
            folder = run / "assertions"
            folder.mkdir(parents=True)
            source = root / "target.c"
            source.write_text("int target(int n) { return n; }\n")
            seed = root / "seed"
            seed.write_bytes(b"A")
            (run / "run.json").write_text('{"run_id":"budget-test"}')
            old_dir = folder / "old" / "executions" / "one"
            old_dir.mkdir(parents=True)
            old_runtime = old_dir / "runtime.json"
            old_runtime.write_text("{}")
            (old_dir / "triage.json").write_text(json.dumps({
                "classification": "OVERSTRONG_ASSUMPTION",
                "input_path": str(seed), "original_runtime": str(old_runtime),
                "source_review": "benign on the original binary"}))
            original = Assertion("old", "worker", "direction", "target",
                                 "target.c:1", "n is below 2", "n < 2", [],
                                 status="VIOLATED", execution_result=str(old_runtime))
            second_dir = folder / "old2" / "executions" / "one"
            second_dir.mkdir(parents=True)
            second_runtime = second_dir / "runtime.json"
            second_runtime.write_text("{}")
            (second_dir / "triage.json").write_text((old_dir / "triage.json").read_text())
            second = Assertion("old2", "worker", "direction", "target",
                               "target.c:1", "n is below 2", "n < 2", [],
                               status="VIOLATED", execution_result=str(second_runtime))
            (folder / "results.json").write_text(json.dumps(
                [asdict(original), asdict(second)]))

            class Roles:
                async def analyze_function(self, *_args, **_kwargs):
                    return FunctionAnalysis("target", "target", "target.c",
                                            "revised", "seed", [], [],
                                            ["n is below 3"], [])

                async def generate_assertions(self, *_args, **_kwargs):
                    return [Assertion("revised", "worker", "direction",
                                      "target", "target.c:1", "n is below 3",
                                      "n < 3", [])]

            spent = []
            physical_runner = lambda _argv, **_kwargs: None

            def fake_execute(item, _source, _line, _seed, output, *_args,
                             **_kwargs):
                output.mkdir(parents=True)
                runtime = output / "runtime.json"
                runtime.write_text("{}")
                item.status = "HELD_FOR_EXECUTION"
                item.execution_result = str(runtime)
                return item, None

            def fake_guided(*_args, **kwargs):
                spent.append((kwargs["seconds"], kwargs.get("guarded_runner")))
                return {"status": "PENDING_SHARED_PHYSICAL_BUDGET",
                        "violation_witnesses": []}

            with patch("vulnerabilityanalysis.scan.refinement_rejection_reasons",
                       return_value=[]), patch(
                       "vulnerabilityanalysis.scan.execute_assertion",
                       side_effect=fake_execute), patch(
                       "vulnerabilityanalysis.scan.guided_fuzz_assertion",
                       side_effect=fake_guided):
                result = asyncio.run(refine_overstrong_assertions(
                    run, Roles(), function_id="target", function_name="target",
                    source_file="target.c", source=source.read_text(),
                    original_source=source, source_start_line=1, context=[],
                    build_command=["cc"], run_command=["./target"],
                    fuzz_seconds=600, fuzz_budget_remaining=1,
                    max_llm_calls=4, guarded_runner=physical_runner))
            self.assertEqual(spent, [(1, physical_runner)], result)
            self.assertEqual(result["guided_fuzz_reserved_seconds"], 1)
            self.assertEqual(result["status"],
                             "INCOMPLETE_HP_GUIDED_PHYSICAL_BUDGET")
            self.assertEqual(result["refinements"][0]["revisions"][0][
                "guided_fuzz_status"], "PENDING_SHARED_PHYSICAL_BUDGET")
            self.assertEqual(result["refinements"][1]["revisions"][0][
                "guided_fuzz_status"], "PENDING_FUZZ_BUDGET")

    def test_recursive_refinement_preserves_one_guarded_runner(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / "run"
            folder = run / "assertions"
            folder.mkdir(parents=True)
            source = root / "target.c"
            source.write_text("int target(int n) { return n; }\n")
            seed = root / "seed"
            seed.write_bytes(b"A")
            (run / "run.json").write_text('{"run_id":"recursive-pin-test"}')
            prior = folder / "old" / "executions" / "one"
            prior.mkdir(parents=True)
            runtime = prior / "runtime.json"
            runtime.write_text("{}")
            original = Assertion("old", "worker", "direction", "target",
                                 "target.c:1", "n below 2", "n < 2", [],
                                 status="VIOLATED", execution_result=str(runtime))
            (folder / "results.json").write_text(json.dumps([asdict(original)]))
            triage = {"classification": "OVERSTRONG_ASSUMPTION",
                      "input_path": str(seed), "original_runtime": str(runtime),
                      "source_review": "benign on the original binary"}
            (prior / "triage.json").write_text(json.dumps(triage))

            class Roles:
                def __init__(self):
                    self.round = 0

                async def analyze_function(self, *_args, **_kwargs):
                    self.round += 1
                    return FunctionAnalysis("target", "target", "target.c",
                                            "revised", "seed", [], [],
                                            [f"n below {self.round + 2}"], [])

                async def generate_assertions(self, analysis, *_args, **_kwargs):
                    return [Assertion(f"revised-{self.round}", "worker", "direction",
                                      "target", "target.c:1",
                                      analysis.safe_assumptions[0],
                                      f"n < {self.round + 2}", [])]

            def fake_execute(item, _source, _line, _seed, output, *_args, **_kwargs):
                output.mkdir(parents=True)
                artifact = output / "runtime.json"
                artifact.write_text("{}")
                (output / "triage.json").write_text(json.dumps({
                    **triage, "original_runtime": str(artifact)}))
                item.status = "VIOLATED"
                item.execution_result = str(artifact)
                return item, None

            physical_runner = lambda _argv, **_kwargs: None
            captured = []

            def fake_guided(*_args, **kwargs):
                captured.append(kwargs.get("guarded_runner"))
                return {"status": "RAN", "violation_witnesses": []}

            with (patch("vulnerabilityanalysis.scan.refinement_rejection_reasons",
                        return_value=[]),
                  patch("vulnerabilityanalysis.scan.execute_assertion",
                        side_effect=fake_execute),
                  patch("vulnerabilityanalysis.scan.guided_fuzz_assertion",
                        side_effect=fake_guided)):
                report = asyncio.run(refine_overstrong_assertions(
                    run, Roles(), function_id="target", function_name="target",
                    source_file="target.c", source=source.read_text(),
                    original_source=source, source_start_line=1, context=[],
                    build_command=["cc"], run_command=["./target"],
                    fuzz_seconds=1, fuzz_budget_remaining=2,
                    max_llm_calls=4, guarded_runner=physical_runner))
            self.assertEqual(captured, [physical_runner, physical_runner])
            self.assertEqual(report["guided_fuzz_reserved_seconds"], 2)
            self.assertEqual(len(report["refinements"]), 2)


if __name__ == "__main__":
    unittest.main()
