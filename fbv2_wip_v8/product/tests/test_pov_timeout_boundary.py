"""A bad PoV input must not consume the rest of a function's scan."""

import asyncio
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vulnerabilityanalysis import analysis
from vulnerabilityanalysis.runtime import RuntimeCleanupError
from vulnerabilityanalysis.scan import scan_selected
from vulnerabilityanalysis.workflow import run_phase1


class PoVTimeoutBoundaryTest(unittest.TestCase):
    def _make_run(self, root: Path) -> tuple[Path, Path]:
        repo = root / "repo"
        repo.mkdir()
        (repo / "target.c").write_text(
            "int parse(const unsigned char *data, unsigned long size) {\n"
            "  if (size > 0) return data[0];\n  return 0;\n}\n")
        artifact = root / "hg"
        artifact.mkdir()
        (artifact / "fuzz.c").write_text(
            "int LLVMFuzzerTestOneInput(const char *p, unsigned long n) { return 0; }\n")
        (artifact / "manifest.json").write_text(json.dumps({
            "harness_id": "h", "source_file": "fuzz.c", "expected_consumers": ["parse"],
            "sanitizers": ["UNKNOWN"]}))
        (artifact / "validation.json").write_text('{"build_ok": true}')
        (root / "project.json").write_text(json.dumps({"source_root": str(repo)}))
        source_index = root / "analysis"
        source_index.mkdir()
        (source_index / "functions.jsonl").write_text(json.dumps({
            "function_id": "fn", "name": "parse", "file": "target.c"}) + "\n")
        return run_phase1(artifact, root / "results", target_repository=repo), repo

    def _provider(self):
        candidates = [{
            "source_file": "target.c", "source_line": 2,
            "source_excerpt": "if (size > 0) return data[0];", "sp_condition": "",
            "suspicious_operation": "data[index]",
            "vulnerability_hypothesis": f"candidate {number} index may exceed bounds",
            "trigger_conditions": ["large input"],
            "external_input_relation": "input byte controls index",
            "required_state": [], "security_property": "memory safety",
            "supporting_evidence": ["indexed read"],
            "contradicting_evidence": [], "unknowns": ["caller guard"]
        } for number in (1, 2)]
        verdict = {"status": "PLAUSIBLE", "supporting_evidence": [],
                   "contradicting_evidence": [], "unknowns": ["caller guard"],
                   "rationale": "needs runtime", "reachability": "UNKNOWN",
                   "controllability": "UNKNOWN", "guards": [], "required_state": [],
                   "contradiction_snippet": "", "contradiction_scope": "UNKNOWN",
                   "context_requests": [], "recommended_next_action": "GENERATE_POC"}
        poc = {"generator_script": "def build():\n    return b'B'\n",
               "expected_behavior": "probe", "trigger_rationale": "input"}
        class Provider:
            def __init__(self):
                self.responses = [{"suspicious_points": candidates}, verdict, poc,
                                  verdict, poc]

            async def generate(self, request):
                return self.responses.pop(0)
        return Provider()

    def test_child_timeout_is_local_and_next_pov_runs(self):
        with tempfile.TemporaryDirectory() as temp:
            run, repo = self._make_run(Path(temp))
            provider = self._provider()
            calls = 0

            def child_run(command, *, timeout):
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise subprocess.TimeoutExpired(command, timeout)
                Path(command[-2]).write_bytes(b"B")
                return subprocess.CompletedProcess(command, 0, "", "")

            with patch.object(analysis, "_guarded_run", side_effect=child_run):
                asyncio.run(scan_selected(run, provider, target_repository=repo,
                                          run_command=["/usr/bin/true", "{input}"],
                                          max_candidates=2, hallucination_prevent="off"))
            rows = json.loads((run / "poc/pocs.json").read_text())
            self.assertEqual(sorted(row["status"] for row in rows),
                             ["EXECUTED_UNRESOLVED", "INPUT_GENERATION_ERROR"])
            self.assertEqual(json.loads((run / "scan.json").read_text())["poc_count"], 2)
            self.assertEqual(calls, 2)
            self.assertEqual(provider.responses, [])
            receipt = next((run / "poc").glob("*/generate.py.resources.json"))
            self.assertEqual(json.loads(receipt.read_text())["attempts"][0]["status"],
                             "TIMED_OUT")

    def test_cleanup_failure_still_aborts_function(self):
        with tempfile.TemporaryDirectory() as temp:
            run, repo = self._make_run(Path(temp))
            provider = self._provider()
            failure = RuntimeCleanupError("cleanup incomplete", "", "partial stderr")
            with patch.object(analysis, "_guarded_run", side_effect=failure):
                with self.assertRaises(RuntimeCleanupError):
                    asyncio.run(scan_selected(run, provider, target_repository=repo,
                                              run_command=["/usr/bin/true", "{input}"],
                                              max_candidates=2, hallucination_prevent="off"))
            self.assertFalse((run / "scan.json").exists())
            self.assertEqual(len(provider.responses), 2)


if __name__ == "__main__":
    unittest.main()
