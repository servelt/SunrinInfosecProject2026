"""Public derived-relation toy: scripted HP with a cited manual T proposal.

This is a component control. The SAFE and Assertion are fixed responses, not
model findings; T provenance does not establish attacker reachability or safety.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
import stat
import sys
from tempfile import TemporaryDirectory
import unittest


PREP = Path(__file__).resolve().parents[1]
PRODUCT = (Path(__file__).resolve().parents[1] / "product")
sys.path[:0] = [str(PRODUCT / "src"), str(PREP / "review_tools")]

import compare_hp_derived_relation_fixture as toy  # noqa: E402
from vulnerabilityanalysis.hp_project_state import (attach_threat_model_proposal,
    load_hp_project_state)  # noqa: E402
from vulnerabilityanalysis.scan import scan_selected  # noqa: E402
from vulnerabilityanalysis.workflow import continue_phase1, run_phase1  # noqa: E402


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _citation(kind: str, path: Path, root: Path, snippet: str) -> dict:
    lines = path.read_text(encoding="utf-8").splitlines()
    matched = [(number, line) for number, line in enumerate(lines, 1)
               if snippet in line]
    if len(matched) != 1:
        raise ValueError("public T citation is not a unique original line")
    number, quote = matched[0]
    return {"kind": kind,
            "path": str(path.resolve()) if kind == "HARNESS" else
                    path.relative_to(root).as_posix(),
            "sha256": _sha(path), "line": number, "quote": quote}


def _manual_proposal(fixture: dict) -> dict:
    root, source, harness = fixture["source"].parent, fixture["source"], fixture["harness"]
    doc, build = root / "THREAT.md", root / "build.txt"
    doc.write_text("This public toy treats its two fuzz input bytes as untrusted.\n")
    build.write_text("clang -fsanitize=fuzzer,address target.c fuzz.c\n")
    h_input = _citation("HARNESS", harness, root, "unsigned count = d[0], pad = d[1];")
    h_call = _citation("HARNESS", harness, root, "if (A(count, pad")
    a_entry = _citation("SOURCE", source, root, "int A(unsigned count")
    a_count = _citation("SOURCE", source, root, "*out_count = count;")
    a_capacity = _citation("SOURCE", source, root, "*out_capacity = capacity;")
    relation = _citation("SOURCE", source, root, "return count + pad + 1u;")
    documentation = _citation("DOC", doc, root, "two fuzz input bytes")
    build_line = _citation("BUILD", build, root, "-fsanitize=fuzzer,address")
    def row(claim: str, evidence: list[dict]) -> dict:
        return {"claim": claim, "status": "PROPOSED", "evidence": evidence}
    return {"kind": "HP_THREAT_MODEL_PROPOSAL_DEV_V1",
            "claims": {
                "attacker_control": [row("Toy fuzz input bytes supply count and pad",
                                         [h_input, documentation])],
                "in_scope": [row("The toy build exercises A from its fuzz Harness",
                                 [h_call, a_entry, build_line])],
                "trust_boundary": [row("Harness input reaches A's published count and capacity",
                                      [h_input, h_call, a_count, a_capacity])],
                "security_relevant_state": [row("Capacity is derived from count and pad",
                                               [relation, a_capacity])],
                "out_of_scope": []},
            "unknowns": ["Production API exposure is not established by this toy Harness"]}


class ScriptedDerivedProvider:
    """Supply a source-grounded but fixed SAFE, then one fixed Assertion."""

    provider_free = True

    def __init__(self, assertion_line: int, assertion_quote: str):
        self.assertion_line = assertion_line
        self.assertion_quote = assertion_quote
        self.roles: list[str] = []
        self.function_payloads: list[dict] = []

    async def generate(self, request):
        self.roles.append(request.role)
        if request.role == "sp_generation":
            return {"suspicious_points": []}
        safe = "Published capacity exceeds the input-derived count"
        if request.role == "function_analysis":
            self.function_payloads.append(request.payload)
            first = len(self.function_payloads) == 1
            return {"summary": "scripted toy analysis; no model call",
                    "input_flow": "two Harness bytes determine count and pad",
                    "state_dependencies": ["capacity derives from count and pad"],
                    "context_requests": ([{"target": "CapacityFor",
                         "request_type": "FUNCTION", "reason": "inspect derived capacity",
                         "expected_information": "count plus pad plus one"}]
                         if first else []),
                    "safe_assumptions": [] if first else [safe],
                    "unknowns": ["CapacityFor body needed"] if first else [],
                    "input_sources": ["fuzzer bytes determine count and pad"],
                    "security_sensitive_operations": ["capacity controls allocation size"],
                    "validations": [], "memory_operations": [], "evidence": [],
                    "hypothesis_evaluations": [] if first else [{
                        "source_location": f"target.c:{self.assertion_line}",
                        "security_property": "allocated capacity exceeds count",
                        "source_file": "target.c", "source_line": self.assertion_line,
                        "source_quote": self.assertion_quote,
                        "input_influence": "INPUT_DEPENDENT", "hypothesis": safe,
                        "judgment": "EXPLICIT_SAFE_JUDGMENT",
                        "reason": "fixed public toy control, not autonomous model reasoning",
                        "safe_assumption": safe}]}
        if request.role == "assertion_generator":
            return {"assertions": [{"safe_id": 0, "safe_assumption": safe,
                    "runtime_expression": "capacity > count",
                    "source_line": self.assertion_line,
                    "required_context": [], "rationale": "scripted public toy control"}],
                "dispositions": [{"safe_id": 0, "safe_assumption": safe,
                    "status": "PROPOSED", "reason": "scripted public toy control"}]}
        raise AssertionError(f"unexpected provider role: {request.role}")


class ManualThreatGuidedToyTest(unittest.TestCase):
    @unittest.skipUnless((PREP / "review_tools/local_clang/clang").is_file(),
                         "public toy Clang/libFuzzer wrapper unavailable")
    def test_cited_t_to_guided_chain(self):
        with TemporaryDirectory(prefix="hp-t-guided-dev-") as temp:
            root = Path(temp)
            fixture = toy.prepare_fixture(root / "fixture")
            proposal = _manual_proposal(fixture)
            run = run_phase1(fixture["artifact"], root / "runs",
                             target_repository=fixture["source"].parent,
                             direction_plan=fixture["plan"],
                             selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV",
                             hp_project_state_dev=True)
            selection = json.loads((run / "selection.json").read_text())
            self.assertEqual(selection["function_name"], "A")
            state = attach_threat_model_proposal(run, fixture["source"].parent,
                                                 proposal)
            self.assertEqual(state["T"]["status"], "PROVENANCE_VALIDATED_DEV")
            self.assertEqual(state["T"]["proposal"], proposal)
            self.assertFalse(state["T"]["gate_eligible"])
            self.assertFalse(state["gate_eligible"])
            build = [str(PREP / "review_tools/local_clang/clang"), "-DLIBFUZZER",
                     "-fsanitize=fuzzer,address", "-g", "-O0", "{source}",
                     str(fixture["harness"]), "-o", "{binary}"]
            line = toy.base.source_line(fixture["source"], "return 1;")
            quote = fixture["source"].read_text().splitlines()[line - 1]
            provider = ScriptedDerivedProvider(line, quote)
            asyncio.run(scan_selected(
                run, provider, target_repository=fixture["source"].parent,
                hallucination_prevent="on", hp_context_round_limit=1,
                hp_llm_call_limit=5, sp_llm_call_limit=3, max_candidates=0,
                assertion_build_command=build,
                assertion_run_command=["{binary}", "{input}"],
                assertion_seed=fixture["seed"], assertion_fuzz_seconds=1,
                fuzz_budget_seconds=1, global_fuzz_enabled=False,
                targeted_fuzz_seconds=0))
            self.assertEqual(provider.roles.count("function_analysis"), 2)
            self.assertEqual(provider.roles.count("assertion_generator"), 1)
            self.assertEqual(len(provider.function_payloads), 2)
            for payload in provider.function_payloads:
                self.assertEqual(payload["analysis_scope"]["hp_project_state"]["T"],
                                 state["T"])
            self.assertTrue(provider.function_payloads[1]["context"])
            scan = json.loads((run / "scan.json").read_text())
            self.assertEqual(scan["safe_assumption_count"], 1)
            self.assertEqual(scan["assertion_count"], 1)
            self.assertEqual(scan["assertion_execution"]["status"], "EXECUTED")
            self.assertFalse(scan["verified_crash_ids"])
            results = json.loads((run / "assertions/results.json").read_text())
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["status"], "HELD_FOR_EXECUTION")
            guided_paths = list((run / "assertions").glob(
                "*/executions/*/guided_fuzz/guided_fuzz.json"))
            self.assertEqual(len(guided_paths), 1)
            guided = json.loads(guided_paths[0].read_text())
            self.assertEqual(guided["status"], "RAN", guided)
            self.assertGreater(guided.get("fuzz_seconds_actual", 0), 0)
            self.assertGreater(guided.get("replayed_reached", 0), 0)
            self.assertEqual(guided.get("replayed_violated"), 0)
            state_after = load_hp_project_state(run, fixture["source"].parent)
            self.assertEqual(state_after["T"], state["T"])
            self.assertFalse(state_after["gate_eligible"])
            self.assertTrue(state_after["Phi"] and state_after["C"])
            triage_path = Path(results[0]["execution_result"]).parent / "triage.json"
            triage = json.loads(triage_path.read_text())
            provenance = triage["hp_threat_model_provenance"]
            snapshot = Path(provenance["state_snapshot_path"])
            snapshot_stat = snapshot.lstat()
            self.assertTrue(stat.S_ISREG(snapshot_stat.st_mode))
            self.assertEqual(stat.S_IMODE(snapshot_stat.st_mode), 0o600)
            self.assertEqual(snapshot_stat.st_nlink, 1)
            self.assertEqual(_sha(snapshot), provenance["state_snapshot_sha256"])
            self.assertEqual(provenance["state_snapshot_sha256"],
                             provenance["state_sha256"])
            self.assertEqual(json.loads(snapshot.read_text())["T"], state["T"])
            self.assertNotEqual(_sha(run / "hp_project_state.json"),
                                provenance["state_sha256"])
            second = continue_phase1(run)
            next_selection = json.loads((second / "selection.json").read_text())
            self.assertNotEqual(next_selection["function_id"], selection["function_id"])
            carried = load_hp_project_state(second, fixture["source"].parent)
            self.assertEqual(carried["T"], state["T"])
            self.assertFalse(carried["gate_eligible"])


if __name__ == "__main__":
    unittest.main()
