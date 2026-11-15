"""Stored JSON cannot stand in for a live team Verifier call."""
import asyncio
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from unittest.mock import patch

from vulnerabilityanalysis.direct_harness import (issue_live_direct_qualification,
    qualify_direct_from_contract, validate_direct_harness_execution,
    _team_project_spec)
from vulnerabilityanalysis.direct_input import CallbackProbe
from vulnerabilityanalysis.final_verification import check_security_property
from vulnerabilityanalysis.models import Evidence, PoC, RuntimeResult, SuspiciousPoint


class FakeVerifier:
    def __init__(self, result):
        self.result = result
        self.calls = 0

    async def verify(self, draft, artifact_dir, llm_seeds, *, runtime_checks):
        self.calls += 1
        assert llm_seeds == [] and runtime_checks is True
        return self.result


class LiveDirectQualificationTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "target.c"
        self.harness = self.root / "fuzzer.c"
        self.binary = self.root / "fuzzer"
        self.seed = self.root / "normal.bin"
        self.review = self.root / "review.json"
        for path, data in ((self.source, b"target"), (self.harness, b"harness"),
                           (self.binary, b"binary"), (self.seed, b"seed")):
            path.write_bytes(data)
        self.review.write_text(json.dumps({
            "kind": "DIRECT_LIBFUZZER_API_USE_REVIEW_V1", "status": "APPROVED",
            "decision": True, "reviewer_id": "reviewer",
            "harness_source_sha256": self.digest(self.harness),
        }))
        self.review_hash = self.digest(self.review)
        self.pov = self.root / "pov.bin"
        self.pov.write_bytes(b"PoV bytes")
        (self.root / "run.json").write_text(json.dumps({"run_id": "run-1"}))
        self.draft = SimpleNamespace(
            manifest=SimpleNamespace(binary=str(self.binary), source_file="fuzzer.c"),
            code=self.harness.read_text())
        self.result = SimpleNamespace(
            qualified=True, build_ok=True, infrastructure_error=None,
            harness_faults=[], coverage_grew=True, target_findings=[])

    @staticmethod
    def digest(path):
        return sha256(path.read_bytes()).hexdigest()

    def issue(self, verifier=None, **changes):
        options = dict(source=self.source, harness=self.harness,
                       binary=self.binary, normal_seed=self.seed,
                       review_artifact=self.review, review_sha256=self.review_hash,
                       reviewer_id="reviewer")
        options.update(changes)
        return asyncio.run(issue_live_direct_qualification(
            verifier or FakeVerifier(self.result), self.draft, self.root, **options))

    def test_live_qualified_result_issues_an_ephemeral_token(self):
        verifier = FakeVerifier(self.result)
        token = self.issue(verifier)
        self.assertEqual(verifier.calls, 1)
        self.assertTrue(token.product_issued)
        self.assertEqual(token.binary_sha256, self.digest(self.binary))

    def test_bad_review_and_wrong_binary_are_rejected_before_verification(self):
        verifier = FakeVerifier(self.result)
        self.assertIsNone(self.issue(verifier, review_sha256="0" * 64))
        self.assertEqual(verifier.calls, 0)
        self.draft.manifest.binary = str(self.root / "other")
        self.assertIsNone(self.issue(verifier))
        self.assertEqual(verifier.calls, 0)

    def test_failed_or_inconclusive_team_verification_issues_no_token(self):
        for change in (dict(qualified=False), dict(infrastructure_error="ptrace denied"),
                       dict(harness_faults=["harness crash"]),
                       dict(coverage_grew=False)):
            with self.subTest(change=change):
                result = SimpleNamespace(**{**vars(self.result), **change})
                self.assertIsNone(self.issue(FakeVerifier(result)))

    def test_team_target_finding_qualification_does_not_require_coverage_growth(self):
        result = SimpleNamespace(**{**vars(self.result),
                                    "coverage_grew": False,
                                    "target_findings": ["team attributed target finding"]})
        self.assertTrue(self.issue(FakeVerifier(result)).product_issued)

    def test_contract_hash_is_required_before_any_team_execution(self):
        contract = self.root / "contract.json"
        contract.write_text("{}")
        with self.assertRaisesRegex(ValueError, "approved SHA-256"):
            asyncio.run(qualify_direct_from_contract(
                contract, target_repository=self.root, binary=self.binary,
                normal_seed=self.seed, approval_sha256="0" * 64))

    def test_team_project_spec_uses_distinct_output_root(self):
        """A source-local artifact dir must not fail ProjectSpec normalization."""
        fi_report = self.root / "fi.yaml"
        fi_report.write_text("functions: []\n")
        project = _team_project_spec(self.root, self.root, fi_report, 60)
        self.assertEqual(project.source_root, self.root.resolve())
        self.assertNotEqual(project.output_root, project.source_root)
        self.assertEqual(project.fuzz_seconds, 60)

    def test_gate_token_requires_fresh_callback_and_clean_normal_control(self):
        qualification = self.issue()
        point = SuspiciousPoint(
            "sp-1", "worker", "direction", "target", str(self.source),
            f"{self.source}:1", "write", "hypothesis", [], "external file",
            [], [], [], [])
        poc = PoC("pov-1", "sp-1", "generator", str(self.pov), None, "crash")
        normal = RuntimeResult(0, "", "", None, False, None, None, "COMPLETED")
        target = RuntimeResult(1, "", "AddressSanitizer", None, False,
                               "AddressSanitizer: heap-buffer-overflow", "#0 target", "CRASH")
        callback = CallbackProbe(True, self.pov.stat().st_size,
                                 self.digest(self.pov), "exact bytes")
        def validate(normal_result=normal, origin="TARGET_CRASH", target_result=target):
            with patch("vulnerabilityanalysis.direct_input.probe_libfuzzer_callback",
                       return_value=callback), \
                 patch("vulnerabilityanalysis.runtime.RuntimeExecutor.run",
                       side_effect=[normal_result, target_result]), \
                 patch("vulnerabilityanalysis.runtime.triage_crash",
                       return_value={"category": origin,
                                     "top_source_frame": str(self.source)}):
                return validate_direct_harness_execution(
                    qualification, run_dir=self.root, point=point, poc=poc,
                    target_repository=self.root)
        token = validate()
        self.assertTrue(token.product_issued)
        self.assertEqual(token.input_sha256, self.digest(self.pov))
        self.assertEqual(token.run_id, "run-1")
        bad_normal = RuntimeResult(1, "", "AddressSanitizer", None, False,
                                   "AddressSanitizer: heap-buffer-overflow", None, "CRASH")
        self.assertIsNone(validate(normal_result=bad_normal))
        self.assertIsNone(validate(origin="HARNESS_CRASH"))
        clean_exit_asan = RuntimeResult(
            0, "", "AddressSanitizer: heap-buffer-overflow", None, False,
            "AddressSanitizer: heap-buffer-overflow", "#0 target", "COMPLETED")
        self.assertIsNone(validate(target_result=clean_exit_asan))
        impact = self.root / "impact.json"
        impact.write_text("{}")
        evidence = [
            Evidence(token.delivery_evidence_id, "EXTERNAL_INPUT",
                     "AUTOMATIC_DIRECT_INPUT", point.sp_id, "measured callback",
                     str(token.delivery_artifact), True, False),
            Evidence(token.harness_evidence_id, "HARNESS_VALIDITY",
                     "AUTOMATIC_DIRECT_HARNESS", point.sp_id, "qualified harness",
                     str(token.harness_artifact), True, False),
            Evidence("impact", "SECURITY_IMPACT", "TEST", point.sp_id,
                     "reproduced target sanitizer", str(impact), True, False),
        ]
        self.assertEqual(check_security_property(
            point, evidence, trusted_direct=token).status, "CONFIRMED")
        self.assertEqual(check_security_property(point, evidence).status, "UNKNOWN")
        self.assertEqual(check_security_property(
            point, evidence, trusted_direct=replace(token, _issuer=object())).status,
            "UNKNOWN")
        other = SuspiciousPoint(**{**vars(point), "sp_id": "other-sp"})
        self.assertEqual(check_security_property(
            other, evidence, trusted_direct=token).status, "UNKNOWN")
        for path in (token.delivery_artifact, token.harness_artifact,
                     self.binary, self.pov):
            with self.subTest(path=path.name):
                before = path.read_bytes()
                path.write_bytes(before + b"changed")
                self.assertEqual(check_security_property(
                    point, evidence, trusted_direct=token).status, "UNKNOWN")
                path.write_bytes(before)
        self.review.write_text(self.review.read_text() + " ")
        self.assertEqual(check_security_property(
            point, evidence, trusted_direct=token).status, "UNKNOWN")
        self.pov.write_bytes(b"modified PoV")
        self.assertIsNone(validate())


if __name__ == "__main__":
    unittest.main()
