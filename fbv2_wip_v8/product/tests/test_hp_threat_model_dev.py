"""Provider-free contract for a cited, development-only Code-Augur T proposal."""

import asyncio
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import test_phase1
import test_sp_hp_independence
from vulnerabilityanalysis.hp_project_state import (attach_threat_model_proposal,
    load_hp_project_state)
from vulnerabilityanalysis.scan import scan_selected
from vulnerabilityanalysis.workflow import continue_phase1, run_phase1


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class HPThreatModelDevTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        artifact, self.repo = test_phase1.HarnessCreatorArtifactTest()._id_artifact(self.root)
        self.artifact = artifact
        self.harness = artifact / "fuzz.c"
        self.harness.write_text(
            "extern int entry_input(const unsigned char *data);\n"
            "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {\n"
            "    if (size > 0) entry_input(data);\n"
            "    return 0;\n"
            "}\n")
        self.docs = self.repo / "THREAT.md"
        self.docs.write_text("Harness bytes are untrusted test inputs.\n")
        self.build = self.repo / "build.txt"
        self.build.write_text("cc target.c fuzz.c -o toy\n")
        self.first = run_phase1(artifact, self.root / "results",
                                target_repository=self.repo,
                                hp_project_state_dev=True)

    def citation(self, kind: str, path: Path, line: int) -> dict:
        return {"kind": kind,
                "path": str(path) if kind == "HARNESS" else
                        path.relative_to(self.repo).as_posix(),
                "sha256": _sha(path), "line": line,
                "quote": path.read_text().splitlines()[line - 1]}

    def proposal(self) -> dict:
        harness = self.citation("HARNESS", self.harness, 3)
        entry = self.citation("SOURCE", self.repo / "target.c", 2)
        parse = self.citation("SOURCE", self.repo / "target.c", 1)
        docs = self.citation("DOC", self.docs, 1)
        build = self.citation("BUILD", self.build, 1)
        row = lambda claim, evidence: {
            "claim": claim, "status": "PROPOSED", "evidence": evidence}
        return {"kind": "HP_THREAT_MODEL_PROPOSAL_DEV_V1",
                "claims": {
                    "attacker_control": [row("Harness supplies untrusted data bytes to entry_input",
                                             [harness, docs])],
                    "in_scope": [row("Harness entry reaches parse_input through entry_input",
                                     [harness, entry, build])],
                    "trust_boundary": [row("Bytes cross from harness to entry_input and parse_input",
                                          [harness, entry, parse])],
                    "security_relevant_state": [row("parse_input reads the first input byte",
                                                   [parse])],
                    "out_of_scope": []},
                "unknowns": ["Production API exposure is not established by this toy harness"]}

    def test_proposal_carries_to_second_function_and_function_analyzer_payload(self):
        proposal = self.proposal()
        original_t = load_hp_project_state(self.first, self.repo)["T"]
        attached = attach_threat_model_proposal(self.first, self.repo, proposal)
        self.assertEqual(attached["T"]["status"], "PROVENANCE_VALIDATED_DEV")
        self.assertEqual(attached["T"]["threat_model_status"],
                         "PROVENANCE_VALIDATED_DEV")
        self.assertFalse(attached["T"]["gate_eligible"])
        self.assertFalse(attached["gate_eligible"])
        self.assertEqual(attached["T"]["proposal"], proposal)
        for key in ("source_root", "source_kind", "source_file_sha256", "harness_id",
                    "harness_path", "harness_sha256", "harness_manifest_sha256"):
            self.assertEqual(attached["T"][key], original_t[key])
        run = json.loads((self.first / "run.json").read_text())
        self.assertEqual(run["hp_project_state_sha256"],
                         _sha(self.first / "hp_project_state.json"))
        first_selection = json.loads((self.first / "selection.json").read_text())
        (self.first / "scan.json").write_text(json.dumps({
            "selected_function": first_selection["function_name"],
            "target_repository": str(self.repo)}))
        second = continue_phase1(self.first)
        second_selection = json.loads((second / "selection.json").read_text())
        self.assertNotEqual(first_selection["function_id"], second_selection["function_id"])
        self.assertEqual(load_hp_project_state(second, self.repo)["T"], attached["T"])
        provider = test_sp_hp_independence.Provider()
        asyncio.run(scan_selected(second, provider, target_repository=self.repo,
                                  run_command=["/usr/bin/true", "{input}"],
                                  hallucination_prevent="on"))
        self.assertEqual(provider.function_payload["analysis_scope"]
                         ["hp_project_state"]["T"], attached["T"])

    def test_missing_evidence_and_invalid_claim_schema_fail_before_pinning(self):
        for mutate in (
            lambda p: p["claims"]["attacker_control"][0].update(evidence=[]),
            lambda p: p["claims"]["trust_boundary"][0].update(status="VERIFIED"),
            lambda p: p["claims"].update(unsafe_auto_promotion=[]),
            lambda p: p["claims"]["trust_boundary"][0]["evidence"][0].update(kind=[]),
        ):
            with self.subTest(mutate=mutate):
                before = (self.first / "hp_project_state.json").read_bytes()
                proposal = self.proposal()
                mutate(proposal)
                with self.assertRaises(ValueError):
                    attach_threat_model_proposal(self.first, self.repo, proposal)
                self.assertEqual((self.first / "hp_project_state.json").read_bytes(), before)

    def test_wrong_line_hash_path_and_symlink_are_rejected(self):
        for field, value in (("line", 999), ("quote", "unrelated"),
                             ("sha256", "0" * 64), ("path", "../outside.c")):
            with self.subTest(field=field):
                proposal = self.proposal()
                proposal["claims"]["security_relevant_state"][0]["evidence"][0][field] = value
                with self.assertRaises(ValueError):
                    attach_threat_model_proposal(self.first, self.repo, proposal)
        linked = self.repo / "linked.md"
        linked.symlink_to(self.docs)
        proposal = self.proposal()
        evidence = proposal["claims"]["attacker_control"][0]["evidence"][1]
        evidence["path"] = linked.relative_to(self.repo).as_posix()
        with self.assertRaises(ValueError):
            attach_threat_model_proposal(self.first, self.repo, proposal)

    def test_cited_doc_build_source_harness_tamper_fails_state_load(self):
        attach_threat_model_proposal(self.first, self.repo, self.proposal())
        for path in (self.docs, self.build, self.repo / "target.c", self.harness):
            with self.subTest(path=path):
                original = path.read_bytes()
                try:
                    path.write_bytes(original + b"/* changed */\n")
                    with self.assertRaises(ValueError):
                        load_hp_project_state(self.first, self.repo)
                finally:
                    path.write_bytes(original)

    def test_cited_file_tamper_blocks_scan_before_any_model_turn(self):
        attach_threat_model_proposal(self.first, self.repo, self.proposal())
        self.docs.write_text(self.docs.read_text() + "changed\n")
        provider = test_sp_hp_independence.Provider()
        with self.assertRaises(ValueError):
            asyncio.run(scan_selected(self.first, provider,
                                      target_repository=self.repo,
                                      run_command=["/usr/bin/true", "{input}"],
                                      hallucination_prevent="on"))
        self.assertEqual(provider.roles, [])

    def test_proposal_cannot_be_attached_after_scan_has_started(self):
        (self.first / "sp").mkdir()
        with self.assertRaisesRegex(ValueError, "precede"):
            attach_threat_model_proposal(self.first, self.repo, self.proposal())

    def test_unknown_t_remains_legacy_and_cannot_claim_threat_model(self):
        state = load_hp_project_state(self.first, self.repo)
        self.assertEqual(state["T"]["threat_model_status"], "NOT_CONSTRUCTED")
        self.assertEqual(state["T"]["attacker_control"], "UNKNOWN")
        self.assertFalse(state["gate_eligible"])

    def test_pinned_boundary_field_cannot_be_changed_even_with_state_rehash(self):
        attach_threat_model_proposal(self.first, self.repo, self.proposal())
        state_path = self.first / "hp_project_state.json"
        state = json.loads(state_path.read_text())
        state["T"]["harness_sha256"] = "0" * 64
        state_path.write_text(json.dumps(state))
        run_path = self.first / "run.json"
        run = json.loads(run_path.read_text())
        run["hp_project_state_sha256"] = _sha(state_path)
        run_path.write_text(json.dumps(run))
        with self.assertRaisesRegex(ValueError, "boundary|pin"):
            load_hp_project_state(self.first, self.repo)


if __name__ == "__main__":
    unittest.main()
