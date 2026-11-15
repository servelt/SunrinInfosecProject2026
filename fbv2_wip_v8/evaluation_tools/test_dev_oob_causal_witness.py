"""Fail-closed development evidence for two public C OOB toy families."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
import hashlib
import json
import os
from pathlib import Path
from dataclasses import replace
from unittest import mock

from dev_oob_causal_witness import (
    ApprovedDebugger, OOBWitnessSpec, issue_development_oob_witness,
    pin_development_inputs,
)
import dev_oob_causal_witness as witness_module


def _source(kind: str, *, fixed: bool = False, unsupported_index: bool = False) -> str:
    marker = "X" if kind == "heap" else "Z"
    capacity = 4 if kind == "heap" else 5
    if kind == "heap":
        object_lines = (
            f"    size_t capacity = {capacity};\n"
            "    unsigned char *buffer = (unsigned char *)malloc(capacity);\n"
            "    if (buffer == NULL) return 2;\n"
            "    buffer[1] = 0;\n"
        )
        tail = "    free(buffer);\n"
    else:
        object_lines = (
            f"    unsigned char buffer[{capacity}] = {{0}};\n"
            "    size_t capacity = sizeof(buffer);\n"
        )
        tail = ""
    crash_index = "capacity - 1" if fixed else "capacity"
    if unsupported_index:
        crash_index = "(capacity + 0)"
    return (
        "#include <stdio.h>\n#include <stdlib.h>\n#include <stddef.h>\n"
        "__attribute__((noinline)) static int target_operation(int marker) {\n"
        f"    if (marker != '{marker}') return 0;\n"
        + object_lines +
        f"    size_t index = marker == '{marker}' ? {crash_index} : 1;\n"
        "    volatile unsigned char observed = buffer[index]; /* OOB_CAUSAL_ACCESS */\n"
        + tail +
        "    return observed;\n"
        "}\n"
        "int main(int argc, char **argv) {\n"
        "    if (argc != 2) return 3;\n"
        "    FILE *stream = fopen(argv[1], \"rb\");\n"
        "    if (stream == NULL) return 4;\n"
        "    int marker = fgetc(stream);\n"
        "    fclose(stream);\n"
        "    return target_operation(marker);\n"
        "}\n"
    )


class DevelopmentOOBCausalWitnessTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory(prefix="dev-oob-causal-")
        cls.root = Path(cls.temp.name)
        cls.compiler = shutil.which("gcc-13")
        cls.debugger = shutil.which("gdb")
        if not cls.compiler or not cls.debugger:
            raise unittest.SkipTest("GCC 13 and GDB are required for the public C toy")
        debugger_path = Path(cls.debugger).absolute()
        backend_path = Path('/home/dawne/tools/system-local/usr/bin/gdb')
        if not backend_path.is_file():
            backend_path = debugger_path.resolve()
        cls.approved_debugger = ApprovedDebugger(
            invocation_path=str(debugger_path),
            invocation_sha256=hashlib.sha256(debugger_path.read_bytes()).hexdigest(),
            resolved_path=str(debugger_path.resolve()),
            backend_path=str(backend_path.resolve()),
            backend_sha256=hashlib.sha256(backend_path.read_bytes()).hexdigest(),
        )
        cls.fixtures = {}
        cls.compiled_source_hashes = {}
        for name, fixed, unsupported in (
            ("heap", False, False), ("stack", False, False),
            ("heap_fixed", True, False), ("heap_unbound", False, True),
        ):
            kind = "stack" if name == "stack" else "heap"
            folder = cls.root / name
            folder.mkdir()
            source = folder / "target.c"
            source.write_text(_source(kind, fixed=fixed, unsupported_index=unsupported))
            cls.compiled_source_hashes[name] = hashlib.sha256(source.read_bytes()).hexdigest()
            binary = folder / "target-asan"
            build = subprocess.run([
                cls.compiler, "-g", "-O0", "-fno-omit-frame-pointer",
                "-fsanitize=address", "-static-libasan", str(source), "-o", str(binary),
            ], capture_output=True, text=True, timeout=30)
            if build.returncode != 0:
                raise AssertionError(build.stderr)
            crash_input = folder / "crash.bin"
            crash_input.write_bytes(b"Z" if kind == "stack" else b"X")
            normal_input = folder / "normal.bin"
            normal_input.write_bytes(b"A")
            cls.fixtures[name] = (folder, source, binary, crash_input, normal_input)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def _issue(self, name: str, *, spec: OOBWitnessSpec | None = None,
               pins=None, debugger: Path | None = None,
               approved_debugger: ApprovedDebugger | None = None):
        folder, source, binary, crash_input, normal_input = self.fixtures[name]
        if spec is None:
            spec = OOBWitnessSpec("stack" if name == "stack" else "heap")
        if pins is None:
            pins = pin_development_inputs(
                source, binary, crash_input, normal_input,
                compiled_source_sha256=self.compiled_source_hashes[name])
        return issue_development_oob_witness(
            folder, source, binary, crash_input, normal_input,
            spec=spec, pins=pins, debugger=debugger or Path(self.debugger),
            approved_debugger=approved_debugger or self.approved_debugger,
            artifacts_root=folder / 'dev-witness-artifacts', timeout_seconds=10)

    def test_heap_actual_runtime_bound_index_and_asan_address_agree(self):
        result = self._issue("heap")
        self.assertEqual(result.status, "ISSUED_DEVELOPMENT_WITNESS", result.reason)
        self.assertEqual(result.evidence["object_kind"], "heap")
        self.assertEqual(result.evidence["capacity"], 4)
        self.assertEqual(result.evidence["index"], 4)
        self.assertEqual(result.evidence["input_marker"], ord("X"))
        self.assertEqual(result.evidence["access_address"],
                         result.evidence["buffer_address"] + 4)
        self.assertEqual(result.evidence["qualification_identity"], "NONE")
        self.assertFalse(result.gate_eligible)
        receipt_path = Path(result.evidence['receipt_path'])
        receipt = json.loads(receipt_path.read_text())
        self.assertEqual(receipt['run_id'], result.evidence['run_id'])
        self.assertEqual(receipt['pins']['binary_sha256'], result.evidence['binary_sha256'])
        self.assertEqual(receipt['approved_debugger']['backend_sha256'],
                         self.approved_debugger.backend_sha256)
        for name, artifact in receipt['artifacts'].items():
            path = Path(artifact['path'])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600, name)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),
                             artifact['sha256'], name)
        self.assertEqual(receipt_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(Path(receipt['artifacts']['witness.json']['path']).read_text())['run_id'],
                         result.evidence['run_id'])
        raw_gdb = ''.join(Path(receipt['artifacts'][name]['path']).read_text()
                          for name in ('gdb_stdout.txt', 'gdb_stderr.txt'))
        self.assertIn('ERROR: AddressSanitizer: heap-buffer-overflow', raw_gdb)
        self.assertIn(str(self.fixtures['heap'][2]), receipt['gdb_argv'])

    def test_stack_actual_runtime_bound_index_and_asan_address_agree(self):
        result = self._issue("stack")
        self.assertEqual(result.status, "ISSUED_DEVELOPMENT_WITNESS", result.reason)
        self.assertEqual(result.evidence["object_kind"], "stack")
        self.assertEqual(result.evidence["capacity"], 5)
        self.assertEqual(result.evidence["index"], 5)
        self.assertEqual(result.evidence["input_marker"], ord("Z"))
        self.assertEqual(result.evidence["access_address"],
                         result.evidence["buffer_address"] + 5)
        self.assertFalse(result.gate_eligible)

    def test_access_line_alone_without_supported_value_flow_is_rejected(self):
        result = self._issue("heap_unbound")
        self.assertEqual(result.status, "BLOCKED_SOURCE_SHAPE")
        self.assertFalse(result.gate_eligible)

    def test_wrong_claimed_object_bound_is_rejected(self):
        result = self._issue("heap", spec=OOBWitnessSpec("heap", claimed_capacity=3))
        self.assertEqual(result.status, "BLOCKED_CAUSAL_CLAIM")

    def test_fake_path_gdb_cannot_forge_measured_witness(self):
        fake_root = self.root / 'fake-debugger'
        fake_root.mkdir(exist_ok=True)
        fake = fake_root / 'gdb'
        marker = fake_root / 'executed'
        fake.write_text(f'#!/bin/sh\nprintf forged > {marker}\n')
        fake.chmod(0o700)
        with mock.patch.dict(os.environ, {'PATH': str(fake_root) + os.pathsep +
                                         os.environ.get('PATH', '')}):
            self.assertEqual(Path(shutil.which('gdb')).resolve(), fake.resolve())
            result = self._issue('heap', debugger=Path(shutil.which('gdb')))
        self.assertEqual(result.status, 'BLOCKED_DEBUG_ENVIRONMENT')
        self.assertFalse(marker.exists())

    def test_unapproved_tool_hash_and_backend_are_rejected(self):
        wrong_hash = replace(self.approved_debugger,
                             invocation_sha256='0' * 64)
        self.assertEqual(self._issue('heap', approved_debugger=wrong_hash).status,
                         'BLOCKED_DEBUG_ENVIRONMENT')
        wrong_backend = replace(self.approved_debugger,
                                backend_sha256='0' * 64)
        self.assertEqual(self._issue('heap', approved_debugger=wrong_backend).status,
                         'BLOCKED_DEBUG_ENVIRONMENT')

    def test_debugger_changed_after_measurement_is_rejected(self):
        private = self.root / 'changed-debugger'
        private.mkdir(exist_ok=True)
        copied = private / 'gdb'
        copied.write_bytes(Path(self.debugger).read_bytes())
        copied.chmod(0o700)
        approved = replace(
            self.approved_debugger,
            invocation_path=str(copied),
            resolved_path=str(copied.resolve()),
            invocation_sha256=hashlib.sha256(copied.read_bytes()).hexdigest(),
        )
        real_witness = witness_module._gdb_witness

        def changed_after_run(*args, **kwargs):
            measured = real_witness(*args, **kwargs)
            copied.write_bytes(copied.read_bytes() + b'\n# changed after execution\n')
            return measured

        with mock.patch.object(witness_module, '_gdb_witness', side_effect=changed_after_run):
            result = self._issue('heap', debugger=copied, approved_debugger=approved)
        self.assertEqual(result.status, 'BLOCKED_PIN_MISMATCH')

    def test_pinned_source_binary_and_input_byte_changes_are_rejected(self):
        folder, source, binary, crash_input, normal_input = self.fixtures["heap"]
        for changed in (source, binary, crash_input):
            with self.subTest(path=changed.name):
                pins = pin_development_inputs(
                    source, binary, crash_input, normal_input,
                    compiled_source_sha256=self.compiled_source_hashes["heap"])
                old = changed.read_bytes()
                try:
                    changed.write_bytes(old + b"\n")
                    result = self._issue("heap", pins=pins)
                    self.assertEqual(result.status, "BLOCKED_PIN_MISMATCH")
                finally:
                    changed.write_bytes(old)

    def test_source_changed_after_build_even_with_new_pin_is_rejected(self):
        folder, source, binary, crash_input, normal_input = self.fixtures["heap"]
        old = source.read_bytes()
        try:
            source.write_bytes(old + b"/* changed after build */\n")
            result = self._issue("heap")
            self.assertEqual(result.status, "BLOCKED_BUILD_SOURCE_MISMATCH")
        finally:
            source.write_bytes(old)

    def test_normal_input_and_fixed_binary_do_not_issue_witness(self):
        folder, source, binary, crash_input, normal_input = self.fixtures["heap"]
        other_normal = folder / "other-normal.bin"
        other_normal.write_bytes(b"B")
        self.addCleanup(other_normal.unlink)
        pins = pin_development_inputs(
            source, binary, normal_input, other_normal,
            compiled_source_sha256=self.compiled_source_hashes["heap"])
        normal = issue_development_oob_witness(
            folder, source, binary, normal_input, other_normal,
            spec=OOBWitnessSpec("heap"), pins=pins,
            debugger=Path(self.debugger), approved_debugger=self.approved_debugger,
            artifacts_root=folder / 'dev-witness-artifacts', timeout_seconds=10)
        self.assertEqual(normal.status, "BLOCKED_NO_TARGET_OOB")
        fixed = self._issue("heap_fixed")
        self.assertEqual(fixed.status, "BLOCKED_NO_TARGET_OOB")


if __name__ == "__main__":
    unittest.main()
