"""Fail-closed public-toy tests for an externally pinned OOB dev manifest."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from test_dev_oob_causal_witness import _source
from dev_oob_manifest_contract import (
    issue_manifest_bound_oob_witness,
    verify_manifest_bound_oob_witness,
    validate_official_v2_source_pin,
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class OOBManifestContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory(prefix="oob-manifest-dev-")
        cls.root = Path(cls.temp.name)
        cls.compiler = shutil.which("gcc-13")
        cls.debugger = shutil.which("gdb")
        if not cls.compiler or not cls.debugger:
            raise unittest.SkipTest("GCC 13 and GDB required")
        cls.source = cls.root / "target.c"
        cls.source.write_text(_source("heap"), encoding="utf-8")
        cls.binary = cls.root / "target-asan"
        built = subprocess.run(
            [cls.compiler, "-g", "-O0", "-fno-omit-frame-pointer",
             "-fsanitize=address", "-static-libasan", str(cls.source),
             "-o", str(cls.binary)],
            capture_output=True, text=True, timeout=30)
        if built.returncode != 0:
            raise AssertionError(built.stderr)
        cls.crash = cls.root / "crash.bin"
        cls.normal = cls.root / "normal.bin"
        cls.crash.write_bytes(b"X")
        cls.normal.write_bytes(b"A")
        debugger = Path(cls.debugger).absolute()
        backend = Path("/home/dawne/tools/system-local/usr/bin/gdb")
        if not backend.is_file():
            backend = debugger.resolve()
        cls.approved = {
            "invocation_path": str(debugger),
            "invocation_sha256": digest(debugger),
            "resolved_path": str(debugger.resolve()),
            "backend_path": str(backend.resolve()),
            "backend_sha256": digest(backend),
        }

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def manifest(self) -> tuple[Path, str]:
        row = {
            "kind": "OOB_PUBLIC_TOY_DEV_APPROVAL_V1",
            "scope": "PUBLIC_TOY_NO_GATE",
            "source_root": str(self.root),
            "source_path": str(self.source),
            "binary_path": str(self.binary),
            "crash_input_path": str(self.crash),
            "normal_input_path": str(self.normal),
            "pins": {
                "source_sha256": digest(self.source),
                "compiled_source_sha256": digest(self.source),
                "binary_sha256": digest(self.binary),
                "crash_input_sha256": digest(self.crash),
                "normal_input_sha256": digest(self.normal),
            },
            "spec": {"object_kind": "heap", "claimed_capacity": 4},
            "approved_debugger": self.approved,
            "official_v2": None,
        }
        path = self.root / "approval.json"
        path.write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")
        path.chmod(0o600)
        return path, digest(path)

    def issue(self, manifest: Path, expected: str):
        return issue_manifest_bound_oob_witness(
            manifest, expected, self.root / "witnesses", timeout_seconds=10)

    def test_pinned_public_toy_witness_and_readback(self):
        manifest, expected = self.manifest()
        result = self.issue(manifest, expected)
        self.assertEqual(result.status, "ISSUED_MANIFEST_BOUND_DEV_WITNESS", result.reason)
        self.assertFalse(result.gate_eligible)
        self.assertEqual(result.evidence["qualification_identity"], "NONE")
        self.assertEqual(result.evidence["approval_manifest_sha256"], expected)
        self.assertTrue(verify_manifest_bound_oob_witness(
            result, expected, result.evidence["manifest_binding_receipt_sha256"]))
        receipt = Path(result.evidence["manifest_binding_receipt_path"])
        self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)
        self.assertEqual(digest(receipt), result.evidence["manifest_binding_receipt_sha256"])

    def test_self_approved_fake_debugger_rejected_by_prior_expected_hash(self):
        manifest, expected = self.manifest()
        row = json.loads(manifest.read_text())
        fake = self.root / "fake" / "gdb"
        fake.parent.mkdir(exist_ok=True)
        fake.write_text("#!/bin/sh\nexit 0\n")
        fake.chmod(0o700)
        fake_digest = digest(fake)
        row["approved_debugger"] = {
            "invocation_path": str(fake),
            "invocation_sha256": fake_digest,
            "resolved_path": str(fake.resolve()),
            "backend_path": str(fake),
            "backend_sha256": fake_digest,
        }
        manifest.write_text(json.dumps(row, sort_keys=True) + "\n")
        result = self.issue(manifest, expected)
        self.assertEqual(result.status, "BLOCKED_APPROVAL_MANIFEST")
        self.assertFalse(result.gate_eligible)

    def test_source_binary_input_and_approved_tool_mutation_rejected(self):
        for path in (self.source, self.binary, self.crash):
            with self.subTest(path=path.name):
                manifest, expected = self.manifest()
                before = path.read_bytes()
                try:
                    path.write_bytes(before + b"\n")
                    self.assertEqual(self.issue(manifest, expected).status,
                                     "BLOCKED_APPROVAL_PINS")
                finally:
                    path.write_bytes(before)

    def test_inner_receipt_tamper_rejected_on_readback(self):
        manifest, expected = self.manifest()
        result = self.issue(manifest, expected)
        self.assertEqual(result.status, "ISSUED_MANIFEST_BOUND_DEV_WITNESS")
        inner = Path(result.evidence["receipt_path"])
        inner.write_bytes(inner.read_bytes() + b"\n")
        self.assertFalse(verify_manifest_bound_oob_witness(
            result, expected, result.evidence["manifest_binding_receipt_sha256"]))

    def test_cross_run_receipt_mix_rejected(self):
        manifest, expected = self.manifest()
        first = self.issue(manifest, expected)
        second = self.issue(manifest, expected)
        self.assertTrue(verify_manifest_bound_oob_witness(
            first, expected, first.evidence["manifest_binding_receipt_sha256"]))
        self.assertTrue(verify_manifest_bound_oob_witness(
            second, expected, second.evidence["manifest_binding_receipt_sha256"]))
        first_binding = Path(first.evidence["manifest_binding_receipt_path"])
        second_binding = Path(second.evidence["manifest_binding_receipt_path"])
        second_binding.write_bytes(first_binding.read_bytes())
        self.assertFalse(verify_manifest_bound_oob_witness(
            second, expected, second.evidence["manifest_binding_receipt_sha256"]))

    def test_rehashed_artifacts_cannot_self_approve_after_external_freeze(self):
        manifest, expected = self.manifest()
        result = self.issue(manifest, expected)
        self.assertEqual(result.status, "ISSUED_MANIFEST_BOUND_DEV_WITNESS")
        frozen_sha = result.evidence["manifest_binding_receipt_sha256"]
        inner = Path(result.evidence["receipt_path"])
        outer = Path(result.evidence["manifest_binding_receipt_path"])
        original = json.loads(inner.read_text())
        measurement = Path(original["artifacts"]["gdb_stdout.txt"]["path"])
        measurement.write_bytes(measurement.read_bytes() + b"edited after measurement\n")
        original["artifacts"]["gdb_stdout.txt"]["sha256"] = digest(measurement)
        original["artifacts"]["gdb_stdout.txt"]["size"] = measurement.stat().st_size
        inner.write_text(json.dumps(original, sort_keys=True) + "\n")
        result.evidence["receipt_sha256"] = digest(inner)
        binding = json.loads(outer.read_text())
        binding["inner_receipt_sha256"] = digest(inner)
        outer.write_text(json.dumps(binding, sort_keys=True) + "\n")
        result.evidence["manifest_binding_receipt_sha256"] = digest(outer)
        self.assertFalse(verify_manifest_bound_oob_witness(
            result, expected, frozen_sha))

    def test_official_v2_source_pin_requires_real_contract_and_receipt(self):
        manifest, expected = self.manifest()
        self.assertFalse(validate_official_v2_source_pin(
            manifest, expected, self.source, self.binary,
            self.normal, self.root, self.root))

    def test_official_source_mapping_rejects_fake_source_or_receipt(self):
        """Exercise the extra source mapping; product V2 validator is mocked.

        A real official approval is deliberately absent from this public toy.
        """
        upstream = self.root / "upstream-for-mapping-test"
        upstream.mkdir(exist_ok=True)
        compiled = upstream / "target.c"
        compiled.write_bytes(self.source.read_bytes())
        unrelated = upstream / "unrelated.c"
        unrelated.write_text("int unrelated(void) { return 0; }\n")
        receipt = self.root / "synthetic-v2-receipt.json"
        contract_path = self.root / "synthetic-v2-contract.json"
        row = {
            "kind": "OFFICIAL_OSS_FUZZ_UPSTREAM_HARNESS_V2",
            "oss_fuzz": {
                "repository": "https://github.com/google/oss-fuzz",
                "revision": "a" * 40,
                "build_script": {"path": "projects/toy/build.sh", "sha256": "a" * 64},
                "chained_scripts": [],
            },
            "upstream_harness": {
                "repository": "https://github.com/example/toy", "revision": "b" * 40,
                "path": "target.c", "sha256": "b" * 64,
            },
            "target": {"revision": "c" * 40, "source_root": str(self.root),
                       "source_tree_sha256": "c" * 64},
            "local": {"harness_file": str(self.source), "harness_sha256": "b" * 64,
                      "binary": str(self.binary), "binary_sha256": digest(self.binary),
                      "normal_seed": str(self.normal),
                      "normal_seed_sha256": digest(self.normal)},
            "build_receipt": {"file": str(receipt), "sha256": "d" * 64},
            "api_review": {"file": str(self.root / "none.json"),
                           "sha256": "e" * 64, "reviewer_id": "synthetic"},
        }

        def write(rows, *, linked_source=compiled):
            receipt.write_text(json.dumps({
                "compiled_sources": rows,
                "build_steps": [{
                    "argv": ["synthetic-compiler", str(linked_source), "-o", str(self.binary)],
                    "exit_code": 0,
                    "inputs": [{"path": str(linked_source), "sha256": digest(linked_source)}],
                    "outputs": [{"path": str(self.binary), "sha256": digest(self.binary)}],
                }],
            }) + "\n")
            row["build_receipt"]["sha256"] = digest(receipt)
            contract_path.write_text(json.dumps(row) + "\n")
            return digest(contract_path)

        good = [{"path": str(compiled), "sha256": digest(compiled)}]
        expected = write(good)
        with patch("dev_oob_manifest_contract.validate_v2_local_pins",
                   return_value=(self.source, self.source, receipt, contract_path)):
            self.assertTrue(validate_official_v2_source_pin(
                contract_path, expected, self.source, self.binary,
                self.normal, self.root, upstream))
            receipt.write_bytes(receipt.read_bytes() + b"\n")
            self.assertFalse(validate_official_v2_source_pin(
                contract_path, expected, self.source, self.binary,
                self.normal, self.root, upstream))
            expected = write(good)
            self.source.write_bytes(self.source.read_bytes() + b"\n")
            self.assertFalse(validate_official_v2_source_pin(
                contract_path, expected, self.source, self.binary,
                self.normal, self.root, upstream))
            self.source.write_text(_source("heap"), encoding="utf-8")
            self.assertFalse(validate_official_v2_source_pin(
                contract_path, expected, self.source, self.binary,
                self.normal, self.root, self.root))
            duplicate_expected = write(good + good)
            self.assertFalse(validate_official_v2_source_pin(
                contract_path, duplicate_expected, self.source, self.binary,
                self.normal, self.root, upstream))
            disconnected_expected = write(
                good + [{"path": str(unrelated), "sha256": digest(unrelated)}],
                linked_source=unrelated)
            self.assertFalse(validate_official_v2_source_pin(
                contract_path, disconnected_expected, self.source, self.binary,
                self.normal, self.root, upstream))
            fake_expected = write([{"path": str(compiled), "sha256": "0" * 64}])
            self.assertFalse(validate_official_v2_source_pin(
                contract_path, fake_expected, self.source, self.binary,
                self.normal, self.root, upstream))


if __name__ == "__main__":
    unittest.main()
