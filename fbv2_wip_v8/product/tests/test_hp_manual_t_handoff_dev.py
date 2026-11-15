"""Provider-free toy checks for the development-only manual T handoff."""

import asyncio
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import shutil
import stat
import tempfile
import unittest

import test_phase1
from vulnerabilityanalysis.agents import AgentPipeline
from vulnerabilityanalysis.assertions import execute_assertion
from vulnerabilityanalysis.hp_project_state import (
    HPThreatProvenanceError, attach_threat_model_proposal,
    validated_manual_threat_context)
from vulnerabilityanalysis.models import Assertion, FunctionAnalysis
from vulnerabilityanalysis.scan import refine_overstrong_assertions, scan_selected
from vulnerabilityanalysis.workflow import run_phase1


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class _ScriptedProvider:
    def __init__(self, *, on_analysis=None, sp_candidate=False, safe=True):
        self.on_analysis = on_analysis
        self.sp_candidate = sp_candidate
        self.safe = safe
        self.roles = []
        self.analysis_payload = None
        self.assertion_payload = None

    async def generate(self, request):
        self.roles.append(request.role)
        if request.role == "sp_generation":
            return {"suspicious_points": [{
                "source_file": "target.c", "source_line": 3,
                "source_excerpt": "  if (value > 200) return;", "sp_condition": "",
                "suspicious_operation": "value > 200",
                "vulnerability_hypothesis": "a boundary may be inconsistent",
                "trigger_conditions": ["input byte exceeds 200"],
                "external_input_relation": "harness byte reaches parser",
                "required_state": [], "security_property": "input handling",
                "supporting_evidence": [], "contradicting_evidence": [],
                "unknowns": []}] if self.sp_candidate else []}
        if request.role == "function_analysis":
            self.analysis_payload = request.payload
            if self.on_analysis:
                self.on_analysis()
            safe = "input value is at most 200"
            return {"summary": "toy guard", "input_flow": "harness byte",
                    "state_dependencies": [], "context_requests": [],
                    "safe_assumptions": [safe] if self.safe else [],
                    "unknowns": [] if self.safe else ["toy assumption unproven"],
                    "input_sources": [],
                    "security_sensitive_operations": [], "validations": [],
                    "memory_operations": [], "evidence": [],
                    "safe_assumption_lifecycle": [],
                    "hypothesis_evaluations": [{"source_location": "target.c:3",
                        "security_property": "input bound", "hypothesis": "value can exceed 200",
                        "judgment": "EXPLICIT_SAFE_JUDGMENT", "reason": "scripted toy judgment",
                        "safe_assumption": safe, "source_file": "target.c",
                        "source_line": 3, "source_quote": "  if (value > 200) return;",
                        "input_influence": "INPUT_DEPENDENT"}] if self.safe else []}
        if request.role == "assertion_generator":
            self.assertion_payload = request.payload
            return {"assertions": [], "dispositions": [{"safe_id": 0,
                    "safe_assumption": "input value is at most 200",
                    "status": "NOT_EXPRESSIBLE", "reason": "handoff test only"}]}
        if request.role == "sp_verifier":
            return {"status": "UNKNOWN", "supporting_evidence": [],
                    "contradicting_evidence": [], "unknowns": ["toy state"],
                    "rationale": "scripted toy", "reachability": "UNKNOWN",
                    "controllability": "UNKNOWN", "guards": [], "required_state": [],
                    "contradiction_snippet": "", "contradiction_scope": "UNKNOWN",
                    "context_requests": [], "recommended_next_action": "REQUEST_CONTEXT"}
        if request.role == "poc_generator":
            return {"generator_script": "def build():\n    return b'A'\n",
                    "expected_behavior": "exercise toy parser",
                    "trigger_rationale": "scripted public toy"}
        raise AssertionError(request.role)


class HPManualTHandoffDevTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.artifact, self.repo = test_phase1.HarnessCreatorArtifactTest()._id_artifact(
            self.root)
        self.source = self.repo / "target.c"
        self.source.write_text(
            "void parse_input(const unsigned char *data) {\n"
            "  unsigned value = data[0];\n"
            "  if (value > 200) return;\n"
            "  (void)value;\n"
            "}\n"
            "void entry_input(const unsigned char *data) {\n"
            "  parse_input(data);\n"
            "}\n", encoding="utf-8")
        self.harness = self.artifact / "fuzz.c"
        self.harness.write_text(
            "extern void entry_input(const unsigned char *data);\n"
            "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {\n"
            "  if (size) entry_input(data);\n"
            "  return 0;\n"
            "}\n", encoding="utf-8")
        self.docs = self.repo / "THREAT.md"
        self.docs.write_text("Harness bytes are untrusted toy inputs.\n")
        self.build_file = self.repo / "build.txt"
        self.build_file.write_text("cc target.c fuzz.c -o toy\n")
        self.run = run_phase1(self.artifact, self.root / "runs",
                              target_repository=self.repo,
                              hp_project_state_dev=True)
        self.threat = attach_threat_model_proposal(
            self.run, self.repo, self._proposal())["T"]
        self.seed = self.root / "input.bin"
        self.seed.write_bytes(b"\xff")
        self.main = self.root / "main.c"
        self.main.write_text(
            "#include <stdio.h>\n"
            "extern void entry_input(const unsigned char *data);\n"
            "int main(int argc, char **argv) {\n"
            "  if (argc < 2) return 2;\n"
            "  FILE *f = fopen(argv[1], \"rb\");\n"
            "  if (!f) return 3;\n"
            "  int value = fgetc(f); fclose(f);\n"
            "  if (value == EOF) return 4;\n"
            "  unsigned char byte = (unsigned char)value;\n"
            "  (void)entry_input(&byte); return 0;\n"
            "}\n", encoding="utf-8")
        self.build = ["cc", "-g", "-O0", "{source}", str(self.main),
                      "-o", "{binary}"]
        self.command = ["{binary}", "{input}"]

    def _citation(self, kind: str, path: Path, line: int) -> dict:
        return {"kind": kind,
                "path": str(path) if kind == "HARNESS" else
                        path.relative_to(self.repo).as_posix(),
                "sha256": _sha(path), "line": line,
                "quote": path.read_text().splitlines()[line - 1]}

    def _proposal(self) -> dict:
        harness = self._citation("HARNESS", self.harness, 3)
        entry = self._citation("SOURCE", self.source, 7)
        parser = self._citation("SOURCE", self.source, 2)
        docs = self._citation("DOC", self.docs, 1)
        build = self._citation("BUILD", self.build_file, 1)
        row = lambda claim, evidence: {"claim": claim, "status": "PROPOSED",
                                        "evidence": evidence}
        return {"kind": "HP_THREAT_MODEL_PROPOSAL_DEV_V1",
                "claims": {
                    "attacker_control": [row("Harness supplies a byte to entry_input",
                                             [harness, docs])],
                    "in_scope": [row("entry_input calls parse_input", [entry, build])],
                    "trust_boundary": [row("Harness byte reaches parse_input",
                                           [harness, entry, parser])],
                    "security_relevant_state": [row("parse_input reads the byte", [parser])],
                    "out_of_scope": []},
                "unknowns": ["Production attacker control is not established by this toy"]}

    def _assertion(self) -> Assertion:
        return Assertion("a-toy", "w", "d", "parse_input", "target.c:3",
                         "input value is at most 200", "value <= 200", [])

    def test_initial_generator_receives_same_validated_t(self):
        provider = _ScriptedProvider()
        asyncio.run(scan_selected(
            self.run, provider, target_repository=self.repo,
            run_command=["/usr/bin/true", "{input}"], hallucination_prevent="on"))
        self.assertEqual(provider.analysis_payload["analysis_scope"]
                         ["hp_project_state"]["T"], self.threat)
        handoff = provider.assertion_payload["threat_model_context"]
        self.assertEqual(handoff["T"], self.threat)
        self.assertEqual(handoff["T_sha256"], validated_manual_threat_context(
            self.run, self.repo, self.threat)["T_sha256"])
        self.assertFalse(handoff["gate_eligible"])

    def test_untampered_candidate_reaches_sp_verifier(self):
        provider = _ScriptedProvider(sp_candidate=True)
        asyncio.run(scan_selected(
            self.run, provider, target_repository=self.repo,
            run_command=["/usr/bin/true", "{input}"], hallucination_prevent="on"))
        self.assertIn("sp_generation", provider.roles)
        self.assertIn("sp_verifier", provider.roles)

    def test_no_t_generator_payload_keeps_legacy_keys(self):
        provider = _ScriptedProvider()
        analysis = FunctionAnalysis("fn-parse", "parse_input", "target.c",
                                    "toy analysis", "harness byte", [], [],
                                    ["input value is at most 200"], [])
        asyncio.run(AgentPipeline(provider).generate_assertions(
            analysis, "w", "d", self.source.read_text()))
        self.assertNotIn("threat_model_context", provider.assertion_payload)

    def test_citation_changed_after_analysis_blocks_generator(self):
        provider = _ScriptedProvider(
            on_analysis=lambda: self.docs.write_text("changed\n"),
            sp_candidate=True)
        with self.assertRaises(HPThreatProvenanceError):
            asyncio.run(scan_selected(
                self.run, provider, target_repository=self.repo,
                run_command=["/usr/bin/true", "{input}"], hallucination_prevent="on"))
        self.assertIn("sp_generation", provider.roles)
        self.assertNotIn("assertion_generator", provider.roles)
        self.assertNotIn("sp_verifier", provider.roles)
        self.assertFalse((self.run / "assertions/proposed.json").is_file())

    def test_target_source_changed_after_analysis_blocks_sp_verifier(self):
        provider = _ScriptedProvider(
            on_analysis=lambda: self.source.write_text(
                self.source.read_text() + "/* changed */\n"),
            sp_candidate=True)
        with self.assertRaises(HPThreatProvenanceError):
            asyncio.run(scan_selected(
                self.run, provider, target_repository=self.repo,
                run_command=["/usr/bin/true", "{input}"], hallucination_prevent="on"))
        self.assertIn("sp_generation", provider.roles)
        self.assertNotIn("assertion_generator", provider.roles)
        self.assertNotIn("sp_verifier", provider.roles)

    def test_t_state_changed_after_analysis_blocks_sp_verifier(self):
        state_path = self.run / "hp_project_state.json"
        provider = _ScriptedProvider(
            on_analysis=lambda: state_path.write_bytes(state_path.read_bytes() + b"\n"),
            sp_candidate=True)
        with self.assertRaises(HPThreatProvenanceError):
            asyncio.run(scan_selected(
                self.run, provider, target_repository=self.repo,
                run_command=["/usr/bin/true", "{input}"], hallucination_prevent="on"))
        self.assertIn("sp_generation", provider.roles)
        self.assertNotIn("assertion_generator", provider.roles)
        self.assertNotIn("sp_verifier", provider.roles)

    def test_safe_zero_source_change_blocks_sp_verifier(self):
        provider = _ScriptedProvider(
            on_analysis=lambda: self.source.write_text(
                self.source.read_text() + "/* changed */\n"),
            sp_candidate=True, safe=False)
        with self.assertRaises(HPThreatProvenanceError):
            asyncio.run(scan_selected(
                self.run, provider, target_repository=self.repo,
                run_command=["/usr/bin/true", "{input}"], hallucination_prevent="on"))
        self.assertIn("function_analysis", provider.roles)
        self.assertNotIn("assertion_generator", provider.roles)
        self.assertNotIn("sp_verifier", provider.roles)

    def test_safe_zero_citation_change_blocks_sp_verifier(self):
        provider = _ScriptedProvider(
            on_analysis=lambda: self.docs.write_text("changed\n"),
            sp_candidate=True, safe=False)
        with self.assertRaises(HPThreatProvenanceError):
            asyncio.run(scan_selected(
                self.run, provider, target_repository=self.repo,
                run_command=["/usr/bin/true", "{input}"], hallucination_prevent="on"))
        self.assertIn("function_analysis", provider.roles)
        self.assertNotIn("assertion_generator", provider.roles)
        self.assertNotIn("sp_verifier", provider.roles)

    def test_safe_zero_malformed_rehashed_state_blocks_sp_verifier(self):
        state_path = self.run / "hp_project_state.json"

        def replace_state():
            state_path.write_text("[{}]\n")
            run_path = self.run / "run.json"
            record = json.loads(run_path.read_text())
            record["hp_project_state_sha256"] = _sha(state_path)
            run_path.write_text(json.dumps(record))

        provider = _ScriptedProvider(
            on_analysis=replace_state, sp_candidate=True, safe=False)
        with self.assertRaises(HPThreatProvenanceError):
            asyncio.run(scan_selected(
                self.run, provider, target_repository=self.repo,
                run_command=["/usr/bin/true", "{input}"], hallucination_prevent="on"))
        self.assertIn("function_analysis", provider.roles)
        self.assertNotIn("assertion_generator", provider.roles)
        self.assertNotIn("sp_verifier", provider.roles)

    @unittest.skipUnless(shutil.which("cc"), "C compiler required for public toy execution")
    def test_triage_provenance_and_refinement_generator_carry(self):
        binding = (self.run, self.repo, self.threat)
        assertion, _ = execute_assertion(
            self._assertion(), self.source, 3, self.seed,
            self.root / "with-t", self.build, self.command,
            manual_threat_binding=binding)
        self.assertEqual(assertion.status, "VIOLATED")
        triage = json.loads((self.root / "with-t/triage.json").read_text())
        self.assertEqual(triage["classification"], "OVERSTRONG_ASSUMPTION")
        self.assertEqual(triage["security_verdict"], "UNKNOWN")
        provenance = triage["hp_threat_model_provenance"]
        self.assertEqual(provenance["source_file_sha256"]["target.c"], _sha(self.source))
        self.assertEqual(provenance["state_sha256"], _sha(self.run / "hp_project_state.json"))
        self.assertEqual(provenance["status"], "PROVENANCE_VALIDATED_DEV")
        self.assertFalse(provenance["gate_eligible"])
        snapshot = Path(provenance["state_snapshot_path"])
        observed = snapshot.lstat()
        self.assertTrue(stat.S_ISREG(observed.st_mode))
        self.assertEqual(stat.S_IMODE(observed.st_mode), 0o600)
        self.assertEqual(observed.st_nlink, 1)
        self.assertEqual(_sha(snapshot), provenance["state_snapshot_sha256"])
        self.assertEqual(snapshot.read_bytes(),
                         (self.run / "hp_project_state.json").read_bytes())
        with self.assertRaises(FileExistsError):
            execute_assertion(self._assertion(), self.source, 3, self.seed,
                              self.root / "with-t", self.build, self.command,
                              manual_threat_binding=binding)
        self.assertEqual(_sha(snapshot), provenance["state_snapshot_sha256"])
        _, _ = execute_assertion(self._assertion(), self.source, 3, self.seed,
                                 self.root / "without-t", self.build, self.command)
        control = json.loads((self.root / "without-t/triage.json").read_text())
        self.assertEqual(control["classification"], triage["classification"])
        self.assertEqual(control["security_verdict"], triage["security_verdict"])
        self.assertNotIn("hp_threat_model_provenance", control)

        (self.run / "assertions").mkdir(exist_ok=True)
        (self.run / "assertions/results.json").write_text(json.dumps([asdict(assertion)]))

        class ScriptedRefinement:
            def __init__(self):
                self.analysis_scope = None
                self.threat_context = None

            async def analyze_function(self, *_args, **kwargs):
                self.analysis_scope = kwargs["analysis_scope"]
                return FunctionAnalysis("fn-parse", "parse_input", "target.c", "revised",
                                        "harness byte", [], [],
                                        ["input value is at most 255"], [])

            async def generate_assertions(self, *_args, **kwargs):
                self.threat_context = kwargs["threat_model_context"]
                return []

        pipeline = ScriptedRefinement()
        report = asyncio.run(refine_overstrong_assertions(
            self.run, pipeline, function_id="fn-parse", function_name="parse_input",
            source_file="target.c", source=self.source.read_text(),
            original_source=self.source, source_start_line=1, context=[],
            build_command=self.build, run_command=self.command,
            fuzz_seconds=0, max_llm_calls=2,
            analysis_scope={"hp_project_state": {"T": self.threat}}))
        self.assertEqual(report["llm_calls"], 2)
        self.assertEqual(pipeline.analysis_scope["hp_project_state"]["T"], self.threat)
        self.assertEqual(pipeline.threat_context["T"], self.threat)
        self.assertFalse(pipeline.threat_context["gate_eligible"])

    @unittest.skipUnless(shutil.which("cc"), "C compiler required for public toy execution")
    def test_refinement_two_rows_rechecks_t_before_next_model_call(self):
        first, _ = execute_assertion(
            self._assertion(), self.source, 3, self.seed,
            self.root / "violation-one", self.build, self.command,
            manual_threat_binding=(self.run, self.repo, self.threat))
        second = self._assertion()
        second.assertion_id = "a-toy-two"
        second, _ = execute_assertion(
            second, self.source, 3, self.seed,
            self.root / "violation-two", self.build, self.command,
            manual_threat_binding=(self.run, self.repo, self.threat))
        self.assertEqual([first.status, second.status], ["VIOLATED", "VIOLATED"])
        (self.run / "assertions").mkdir(exist_ok=True)
        (self.run / "assertions/results.json").write_text(
            json.dumps([asdict(first), asdict(second)]))

        class TamperingRefinement:
            def __init__(self, docs):
                self.docs = docs
                self.analysis_calls = 0

            async def analyze_function(self, *_args, **_kwargs):
                self.analysis_calls += 1
                self.docs.write_text("changed during first reanalysis\n")
                return FunctionAnalysis("fn-parse", "parse_input", "target.c",
                                        "no fresh safe", "harness byte", [], [], [], [])

            async def generate_assertions(self, *_args, **_kwargs):
                raise AssertionError("no fresh SAFE may request assertions")

        pipeline = TamperingRefinement(self.docs)
        with self.assertRaises(HPThreatProvenanceError):
            asyncio.run(refine_overstrong_assertions(
                self.run, pipeline, function_id="fn-parse",
                function_name="parse_input", source_file="target.c",
                source=self.source.read_text(), original_source=self.source,
                source_start_line=1, context=[], build_command=self.build,
                run_command=self.command, fuzz_seconds=0, max_llm_calls=4,
                analysis_scope={"hp_project_state": {"T": self.threat}}))
        self.assertEqual(pipeline.analysis_calls, 1)

    @unittest.skipUnless(shutil.which("cc"), "C compiler required for public toy execution")
    def test_tamper_rejected_before_build_or_run(self):
        for path in (self.docs, self.source, self.run / "hp_project_state.json"):
            with self.subTest(path=path):
                original = path.read_bytes()
                try:
                    path.write_bytes(original + b"\nchanged\n")
                    output = self.root / ("blocked-" + path.name)
                    with self.assertRaises(ValueError):
                        execute_assertion(
                            self._assertion(), self.source, 3, self.seed,
                            output, self.build, self.command,
                            manual_threat_binding=(self.run, self.repo, self.threat))
                    self.assertFalse(output.exists())
                finally:
                    path.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
