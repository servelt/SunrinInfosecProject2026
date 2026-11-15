"""The SP search must remain usable when HP is disabled or unavailable."""
import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from vulnerabilityanalysis.agents import AgentPipeline
from vulnerabilityanalysis.scan import scan_selected
from vulnerabilityanalysis.workflow import run_phase1


def fixture(root: Path) -> tuple[Path, Path]:
    repo = root / "repo"
    repo.mkdir()
    (repo / "target.c").write_text(
        "int parse(const unsigned char *data, unsigned long size) {\n"
        "  return size ? data[0] : 0;\n}\n")
    artifact = root / "harness"
    artifact.mkdir()
    (artifact / "fuzz.c").write_text(
        "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) "
        "{ return parse(data, size); }\n")
    (artifact / "manifest.json").write_text(json.dumps({
        "harness_id": "h", "source_file": "fuzz.c", "expected_consumers": ["parse"],
        "sanitizers": ["ASAN"]}))
    (artifact / "validation.json").write_text('{"build_ok": true}')
    (root / "project.json").write_text(json.dumps({"source_root": str(repo)}))
    (root / "analysis").mkdir()
    (root / "analysis/functions.jsonl").write_text(json.dumps({
        "function_id": "fn", "name": "parse", "file": "target.c"}) + "\n")
    return artifact, repo


class Provider:
    def __init__(self, fail_hp: bool = False):
        self.fail_hp = fail_hp
        self.roles = []
        self.sp_payload = None
        self.function_payload = None

    async def generate(self, request):
        self.roles.append(request.role)
        if request.role == "function_analysis":
            self.function_payload = request.payload
            if self.fail_hp:
                raise RuntimeError("HP model unavailable")
            return {"summary": "reviewed", "input_flow": "bytes", "state_dependencies": [],
                    "context_requests": [], "safe_assumptions": [], "unknowns": [],
                    "input_sources": [], "security_sensitive_operations": [],
                    "validations": [], "memory_operations": [], "evidence": [],
                    "safe_assumption_lifecycle": [],
                    "hypothesis_evaluations": []}
        if request.role == "sp_generation":
            self.sp_payload = request.payload
            return {"suspicious_points": []}
        raise AssertionError(request.role)


class FullPathProvider(Provider):
    async def generate(self, request):
        self.roles.append(request.role)
        if request.role == "sp_generation":
            self.sp_payload = request.payload
            return {"suspicious_points": [{
                "source_file": "target.c", "source_line": 2,
                "source_excerpt": "  return size ? data[0] : 0;", "sp_condition": "",
                "suspicious_operation": "data[0]", "vulnerability_hypothesis": "guard may fail",
                "trigger_conditions": ["nonempty input"],
                "external_input_relation": "harness bytes reach data",
                "required_state": [], "security_property": "memory safety",
                "supporting_evidence": [], "contradicting_evidence": [], "unknowns": []}]}
        if request.role == "function_analysis":
            self.function_payload = request.payload
            return {"summary": "reviewed", "input_flow": "harness bytes", "state_dependencies": [],
                    "context_requests": [], "safe_assumptions": ["size <= 4096 at entry"],
                    "unknowns": [], "input_sources": [], "security_sensitive_operations": [],
                    "validations": [], "memory_operations": [], "evidence": [],
                    "safe_assumption_lifecycle": [],
                    "hypothesis_evaluations": [{"source_location": "target.c:2",
                        "security_property": "bounded size", "hypothesis": "size may exceed 4096",
                        "judgment": "EXPLICIT_SAFE_JUDGMENT", "reason": "model claim for test",
                        "safe_assumption": "size <= 4096 at entry",
                        "source_file": "target.c", "source_line": 2,
                        "source_quote": "return size ? data[0] : 0;",
                        "input_influence": "UNKNOWN"}]}
        if request.role == "assertion_generator":
            return {"assertions": [{"safe_assumption": "size <= 4096 at entry",
                    "runtime_expression": "size <= 4096", "source_line": 2,
                    "required_context": [], "rationale": "test predicate", "safe_id": 0}],
                    "dispositions": [{"safe_id": 0,
                        "safe_assumption": "size <= 4096 at entry", "status": "PROPOSED",
                        "reason": "simple predicate"}]}
        if request.role == "sp_verifier":
            return {"status": "PLAUSIBLE", "supporting_evidence": [],
                    "contradicting_evidence": [], "unknowns": ["runtime state"],
                    "rationale": "needs execution", "reachability": "UNKNOWN",
                    "controllability": "UNKNOWN", "guards": [], "required_state": [],
                    "contradiction_snippet": "", "contradiction_scope": "UNKNOWN",
                    "context_requests": [], "recommended_next_action": "GENERATE_POC"}
        if request.role == "poc_generator":
            return {"generator_script": "def build():\n    return b'A'\n",
                    "expected_behavior": "exercise function", "trigger_rationale": "input"}
        raise AssertionError(request.role)


class NoSafeProvider(FullPathProvider):
    async def generate(self, request):
        if request.role == "function_analysis":
            return await Provider.generate(self, request)
        return await super().generate(request)


class FailingFullPathProvider(FullPathProvider):
    async def generate(self, request):
        if request.role == "function_analysis":
            self.roles.append(request.role)
            raise RuntimeError("HP model unavailable")
        return await super().generate(request)


class ContextRoundFailProvider(FullPathProvider):
    def __init__(self):
        super().__init__()
        self.analysis_rounds = 0

    async def generate(self, request):
        if request.role == "function_analysis":
            self.roles.append(request.role)
            self.analysis_rounds += 1
            if self.analysis_rounds == 2:
                raise RuntimeError("second HP context round unavailable")
            return {"summary": "first round only", "input_flow": "bytes",
                    "state_dependencies": [], "context_requests": [{
                        "target": "helper", "request_type": "FUNCTION",
                        "reason": "inspect the helper", "expected_information": "bounds",
                        "hypothesis_index": 0}],
                    "safe_assumptions": [], "unknowns": [], "input_sources": [],
                    "security_sensitive_operations": [], "validations": [],
                    "memory_operations": [], "evidence": [],
                    "safe_assumption_lifecycle": [],
                    "hypothesis_evaluations": [{
                        "source_location": "target.c:1",
                        "source_file": "target.c", "source_line": 1,
                        "source_quote": "int target(void) {",
                        "security_property": "helper bounds",
                        "input_influence": "INPUT_DEPENDENT",
                        "hypothesis": "helper may affect the input bound",
                        "judgment": "UNKNOWN",
                        "reason": "helper source is required",
                        "safe_assumption": "",
                    }]}
        return await super().generate(request)


class SPHPIndependenceTest(unittest.TestCase):
    def test_first_hp_round_failure_preserves_sp_and_marks_safe_unknown(self):
        with tempfile.TemporaryDirectory() as temp:
            artifact, repo = fixture(Path(temp))
            run = run_phase1(artifact, Path(temp) / "results", target_repository=repo)
            provider = FailingFullPathProvider()
            asyncio.run(scan_selected(run, provider, target_repository=repo,
                                      run_command=["/usr/bin/true", "{input}"],
                                      hallucination_prevent="on"))
            scan = json.loads((run / "scan.json").read_text())
            self.assertEqual((scan["sp_count"], scan["poc_count"]), (1, 1))
            self.assertTrue((run / "verification").is_dir())
            self.assertEqual(scan["hp_error"]["stage"], "FUNCTION_ANALYSIS")
            self.assertEqual(scan["assertion_execution"]["status"], "INCOMPLETE_HP_ERROR")
            self.assertIsNone(scan["safe_assumption_count"])
            self.assertFalse((run / "assertions" / "quality.json").exists())
            self.assertFalse((run / "assertions" / "quality_metrics.json").exists())

    def test_later_hp_context_failure_preserves_sp_and_partial_round_history(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact, repo = fixture(root)
            with (repo / "target.c").open("a") as stream:
                stream.write("int helper(void) { return 1; }\n")
            with (root / "analysis/functions.jsonl").open("a") as stream:
                stream.write(json.dumps({"function_id": "helper", "name": "helper",
                                         "file": "target.c"}) + "\n")
            run = run_phase1(artifact, root / "results", target_repository=repo)
            provider = ContextRoundFailProvider()
            asyncio.run(scan_selected(run, provider, target_repository=repo,
                                      run_command=["/usr/bin/true", "{input}"],
                                      hallucination_prevent="on"))
            scan = json.loads((run / "scan.json").read_text())
            self.assertEqual(provider.analysis_rounds, 2)
            self.assertEqual((scan["sp_count"], scan["poc_count"]), (1, 1))
            self.assertTrue((run / "verification").is_dir())
            self.assertEqual(scan["hp_error"]["stage"], "FUNCTION_ANALYSIS")
            self.assertEqual(scan["assertion_execution"]["status"], "INCOMPLETE_HP_ERROR")
            self.assertIsNone(scan["safe_assumption_count"])
            rounds = json.loads((run / "hp_analysis_rounds.json").read_text())
            self.assertEqual(rounds["final_analysis_status"], "INCOMPLETE")
            self.assertFalse((run / "assertions" / "quality.json").exists())

    def test_hp_off_skips_quality_after_sp_verification(self):
        with tempfile.TemporaryDirectory() as temp:
            artifact, repo = fixture(Path(temp))
            run = run_phase1(artifact, Path(temp) / "results", target_repository=repo)
            provider = FullPathProvider()
            asyncio.run(scan_selected(run, provider, target_repository=repo,
                                      run_command=["/usr/bin/true", "{input}"],
                                      hallucination_prevent="off"))
            scan = json.loads((run / "scan.json").read_text())
            self.assertEqual((scan["sp_count"], scan["poc_count"]), (1, 1))
            self.assertTrue((run / "verification").is_dir())
            self.assertEqual(scan["assertion_execution"]["status"], "DISABLED")
            self.assertNotIn("function_analysis", provider.roles)
            self.assertFalse((run / "assertions" / "proposed.json").exists())
            self.assertFalse((run / "assertions" / "quality.json").exists())
            self.assertFalse((run / "assertions" / "quality_metrics.json").exists())

    def test_hp_normal_keeps_quality_and_sp_verification(self):
        with tempfile.TemporaryDirectory() as temp:
            artifact, repo = fixture(Path(temp))
            run = run_phase1(artifact, Path(temp) / "results", target_repository=repo)
            provider = FullPathProvider()
            asyncio.run(scan_selected(run, provider, target_repository=repo,
                                      run_command=["/usr/bin/true", "{input}"],
                                      hallucination_prevent="on"))
            scan = json.loads((run / "scan.json").read_text())
            self.assertEqual((scan["sp_count"], scan["poc_count"],
                              scan["assertion_count"]), (1, 1, 1))
            self.assertIsNone(scan["hp_error"])
            self.assertEqual(scan["safe_assumption_count"], 1)
            self.assertTrue((run / "assertions" / "quality.json").exists())
            metrics = json.loads((run / "assertions" / "quality_metrics.json").read_text())
            self.assertEqual(metrics["initial"]["proposal_count"], 1)
            self.assertEqual(metrics["initial"]["quality_evaluated_count"], 1)
            self.assertTrue((run / "verification").is_dir())

    def test_safe_claim_does_not_call_assertion_generator_beyond_hp_limit(self):
        with tempfile.TemporaryDirectory() as temp:
            artifact, repo = fixture(Path(temp))
            run = run_phase1(artifact, Path(temp) / "results", target_repository=repo)
            provider = FullPathProvider()
            asyncio.run(scan_selected(run, provider, target_repository=repo,
                                      hallucination_prevent="on", hp_llm_call_limit=1,
                                      sp_llm_call_limit=1))
            self.assertEqual(provider.roles, ["sp_generation", "function_analysis"])
            pending = json.loads((run / "assertions" / "pending_generation.json").read_text())
            self.assertEqual(pending["reason"], "HP_CALL_LIMIT")
            scan = json.loads((run / "scan.json").read_text())
            self.assertEqual(scan["hp_llm_calls"], 1)
            self.assertEqual(scan["assertion_execution"]["status"], "PENDING_HP_BUDGET")

    def test_sp_generator_accepts_function_identity_without_hp_analysis(self):
        provider = Provider()
        identity = {"function_id": "fn", "function_name": "parse", "source_file": "target.c"}
        points = asyncio.run(AgentPipeline(provider).generate_sp(
            identity, "worker", "direction", "int parse(void) { return 0; }"))
        self.assertEqual(points, [])
        self.assertEqual(provider.sp_payload["analysis"], identity)
        self.assertEqual(provider.roles, ["sp_generation"])

    def test_hp_off_never_calls_function_analyzer(self):
        with tempfile.TemporaryDirectory() as temp:
            artifact, repo = fixture(Path(temp))
            run = run_phase1(artifact, Path(temp) / "results", target_repository=repo)
            provider = Provider(fail_hp=True)
            asyncio.run(scan_selected(run, provider, target_repository=repo,
                                      hallucination_prevent="off"))
            self.assertEqual(provider.roles, ["sp_generation"])
            self.assertEqual(provider.sp_payload["analysis"], {
                "function_id": "fn", "function_name": "parse", "source_file": "target.c"})
            self.assertEqual(json.loads((run / "scan.json").read_text())["sp_count"], 0)

    def test_hp_failure_does_not_stop_sp_path(self):
        with tempfile.TemporaryDirectory() as temp:
            artifact, repo = fixture(Path(temp))
            run = run_phase1(artifact, Path(temp) / "results", target_repository=repo)
            provider = Provider(fail_hp=True)
            asyncio.run(scan_selected(run, provider, target_repository=repo,
                                      hallucination_prevent="on"))
            self.assertEqual(provider.roles, ["sp_generation", "function_analysis"])
            self.assertEqual(json.loads((run / "scan.json").read_text())["sp_count"], 0)
            self.assertEqual(json.loads((run / "hp_error.json").read_text())["stage"],
                             "FUNCTION_ANALYSIS")

    def test_hp_failure_does_not_block_existing_sp_verification_and_poc(self):
        with tempfile.TemporaryDirectory() as temp:
            artifact, repo = fixture(Path(temp))
            run = run_phase1(artifact, Path(temp) / "results", target_repository=repo)
            provider = FailingFullPathProvider()
            asyncio.run(scan_selected(run, provider, target_repository=repo,
                                      run_command=["/usr/bin/true", "{input}"],
                                      hallucination_prevent="on"))
            self.assertEqual(provider.roles[:4],
                             ["sp_generation", "function_analysis", "sp_verifier",
                              "poc_generator"])
            scan = json.loads((run / "scan.json").read_text())
            self.assertEqual((scan["sp_count"], scan["poc_count"]), (1, 1))
            self.assertTrue((run / "poc" / "pocs.json").is_file())
            self.assertEqual(scan["hp_error"]["stage"], "FUNCTION_ANALYSIS")

    def test_hp_on_keeps_assertion_and_sp_verification_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            artifact, repo = fixture(Path(temp))
            run = run_phase1(artifact, Path(temp) / "results", target_repository=repo)
            provider = FullPathProvider()
            asyncio.run(scan_selected(run, provider, target_repository=repo,
                                      run_command=["/usr/bin/true", "{input}"],
                                      hallucination_prevent="on"))
            scan = json.loads((run / "scan.json").read_text())
            self.assertEqual((scan["sp_count"], scan["assertion_count"], scan["poc_count"]),
                             (1, 1, 1))
            self.assertEqual(scan["sp_llm_calls"], 3)
            self.assertEqual(scan["hp_llm_calls"], 2)
            self.assertEqual(scan["llm_calls"], 5)
            self.assertEqual(provider.roles,
                             ["sp_generation", "function_analysis",
                              "assertion_generator", "sp_verifier", "poc_generator"])
            self.assertEqual(provider.sp_payload["analysis"], {
                "function_id": "fn", "function_name": "parse", "source_file": "target.c"})
            scope = provider.function_payload["analysis_scope"]
            self.assertEqual(scope["worker"]["sanitizer"], "ASAN")
            self.assertEqual(scope["selected_function"]["role"], "CORE")
            self.assertIn("parse", scope["direction"]["core_functions"])
            self.assertIn("Scheduling and reachability metadata only",
                          scope["provenance_note"])
            self.assertTrue((run / "verification").is_dir())
            self.assertTrue((run / "function_analysis.json").is_file())
            provenance = json.loads((run / "function_analysis_provenance.json").read_text())
            self.assertEqual(provenance["function_name"], "parse")
            original = json.loads(Path(provenance["response_artifact"]).read_text())
            self.assertEqual(original["hypothesis_evaluations"][0]["judgment"],
                             "EXPLICIT_SAFE_JUDGMENT")
            requests = [json.loads(line) for line in
                        (run / "logs" / "agent_requests.jsonl").read_text().splitlines()]
            self.assertEqual(provenance["request_artifact"], next(
                row["request_artifact"] for row in requests
                if row["role"] == "function_analysis"))

    def test_hp_on_without_safe_assumption_keeps_sp_and_poc(self):
        with tempfile.TemporaryDirectory() as temp:
            artifact, repo = fixture(Path(temp))
            run = run_phase1(artifact, Path(temp) / "results", target_repository=repo)
            provider = NoSafeProvider()
            asyncio.run(scan_selected(run, provider, target_repository=repo,
                                      run_command=["/usr/bin/true", "{input}"],
                                      hallucination_prevent="on"))
            scan = json.loads((run / "scan.json").read_text())
            self.assertEqual((scan["sp_count"], scan["assertion_count"], scan["poc_count"]),
                             (1, 0, 1))
            self.assertNotIn("assertion_generator", provider.roles)
