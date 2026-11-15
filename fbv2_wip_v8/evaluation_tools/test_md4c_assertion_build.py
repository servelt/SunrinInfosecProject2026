"""Provider-free checks for the isolated md4c Assertion relinker."""
from __future__ import annotations

from pathlib import Path
import hashlib
import json
import os
import resource
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
BUILDER = ROOT / 'tools/multi_tu_assertion_build.py'
SOURCES = ROOT / 'model_target'
NORMAL_SEEDS = tuple(sorted((ROOT / 'public/normal_seed_corpus').glob('seed_*.bin')))
EVIDENCE_DIR = ROOT / 'synthetic_route_20261028_retry1'
PRODUCT_SRC = (Path(__file__).resolve().parents[1] / "product" / "src")
sys.path.insert(0, str(PRODUCT_SRC))
from vulnerabilityanalysis.runtime import _guarded_run  # noqa: E402


class Md4cAssertionBuildTest(unittest.TestCase):
    def invoke(self, *args: Path | str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([sys.executable, '-I', str(BUILDER),
                               *map(str, args)], capture_output=True,
                              text=True, timeout=60)

    def test_syntax_preprocess_and_all_translation_unit_relinks(self) -> None:
        with tempfile.TemporaryDirectory(prefix='md4c-builder-regression-', dir=ROOT) as name:
            temp = Path(name)
            for rel in ('src/md4c.c', 'src/md4c-html.c', 'src/entity.c',
                        'test/fuzzers/fuzz-mdhtml.c'):
                with self.subTest(translation_unit=rel):
                    original = SOURCES / rel
                    copy = temp / original.name
                    copy.write_bytes(original.read_bytes() + b'\n/* harmless builder regression */\n')
                    syntax = self.invoke('-fsyntax-only', copy)
                    self.assertEqual(syntax.returncode, 0, syntax.stderr[-1200:])
                    binary = temp / (original.name + '.bin')
                    build = self.invoke(copy, '-o', binary)
                    self.assertEqual(build.returncode, 0, build.stderr[-1200:])
                    self.assertTrue(binary.read_bytes().startswith(b'\x7fELF'))
            macro = temp / 'va-macro-probe-test.c'
            macro.write_bytes((SOURCES / 'src/md4c.c').read_bytes() +
                              b'\nVA_MACRO_PROBE_BEGIN_0123456789abcdef0123456789abcdef 1 + 1 '
                              b'VA_MACRO_PROBE_END_0123456789abcdef0123456789abcdef\n')
            preprocessed = self.invoke('-E', '-P', macro)
            self.assertEqual(preprocessed.returncode, 0, preprocessed.stderr[-1200:])
            self.assertIn('VA_MACRO_PROBE_BEGIN_', preprocessed.stdout)

    def test_foreign_or_modified_original_line_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix='md4c-builder-negative-', dir=ROOT) as name:
            temp = Path(name)
            foreign = temp / 'md4c.c'
            foreign.write_text('int unrelated(void) { return 1; }\n')
            rejected = self.invoke(foreign, '-o', temp / 'foreign.bin')
            self.assertEqual(rejected.returncode, 2)
            self.assertFalse((temp / 'foreign.bin').exists())
            original = (SOURCES / 'src/md4c.c').read_bytes()
            first, rest = original.split(b'\n', 1)
            foreign.write_bytes(first + b' modified\n' + rest)
            rejected = self.invoke('-fsyntax-only', foreign)
            self.assertEqual(rejected.returncode, 2)

    def test_toolchain_pins_reject_changed_resource_or_loader(self) -> None:
        original = json.loads((ROOT / 'tools/multi_tu_assertion_build_manifest.json').read_text())
        with tempfile.TemporaryDirectory(prefix='md4c-toolchain-pin-', dir=ROOT) as name:
            manifest = Path(name) / 'manifest.json'
            for section in ('toolchain_trees', 'toolchain_loader_files'):
                with self.subTest(section=section):
                    changed = json.loads(json.dumps(original))
                    key = next(iter(changed[section]))
                    changed[section][key]['sha256'] = '0' * 64
                    manifest.write_text(json.dumps(changed))
                    environment = {**os.environ, 'VA_ASSERTION_BUILD_MANIFEST': str(manifest)}
                    rejected = subprocess.run([sys.executable, '-I', str(BUILDER),
                                               '--preflight'], env=environment,
                                              capture_output=True, text=True, timeout=60)
                    self.assertEqual(rejected.returncode, 2)
                    self.assertIn('local Assertion compiler', rejected.stderr)

    def test_unpinned_include_environment_cannot_change_compile(self) -> None:
        with tempfile.TemporaryDirectory(prefix='md4c-include-poison-', dir=ROOT) as name:
            poison = Path(name)
            (poison / 'stdint.h').write_text('#error unpinned CPATH header selected\n')
            environment = {**os.environ, 'CPATH': str(poison),
                           'C_INCLUDE_PATH': str(poison), 'LIBRARY_PATH': str(poison)}
            result = subprocess.run([sys.executable, '-I', str(BUILDER),
                                     '-fsyntax-only', str(SOURCES / 'src/md4c.c')],
                                    env=environment, capture_output=True,
                                    text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr[-1200:])

    def run_instrumented(self, binary: Path, seed: Path):
        environment = os.environ.copy()
        environment['LD_LIBRARY_PATH'] = '/home/dawne/tools/system-local/usr/lib/x86_64-linux-gnu'
        environment['ASAN_OPTIONS'] = 'disable_coredump=1:detect_leaks=1'
        old_soft, old_hard = resource.getrlimit(resource.RLIMIT_CORE)
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, old_hard))
            return _guarded_run([str(binary), str(seed)], env=environment, timeout=15)
        finally:
            resource.setrlimit(resource.RLIMIT_CORE, (old_soft, old_hard))

    def test_comment_only_builds_execute_all_normal_seeds(self) -> None:
        self.assertEqual(len(NORMAL_SEEDS), 10)
        record = {'kind': 'MD4C_ASSERTION_BUILDER_NORMAL_RUNTIME_CONTROL_V1',
                  'status': 'INCOMPLETE', 'source_units': [], 'seed_count': len(NORMAL_SEEDS),
                  'runs': [], 'builder_sha256': hashlib.sha256(BUILDER.read_bytes()).hexdigest(),
                  'manifest_sha256': hashlib.sha256(
                      (ROOT / 'tools/multi_tu_assertion_build_manifest.json').read_bytes()).hexdigest()}
        evidence = EVIDENCE_DIR / 'BUILDER_NORMAL_RUNTIME_CONTROLS.json'
        try:
            with tempfile.TemporaryDirectory(prefix='md4c-builder-runtime-', dir=ROOT) as name:
                temp = Path(name)
                for rel in ('src/md4c.c', 'src/md4c-html.c', 'src/entity.c',
                            'test/fuzzers/fuzz-mdhtml.c'):
                    original = SOURCES / rel
                    copy = temp / original.name
                    copy.write_bytes(original.read_bytes() + b'\n/* benign runtime control */\n')
                    binary = temp / (original.name + '.bin')
                    build = self.invoke(copy, '-o', binary)
                    self.assertEqual(build.returncode, 0, build.stderr[-1200:])
                    record['source_units'].append(rel)
                    for seed in NORMAL_SEEDS:
                        result = self.run_instrumented(binary, seed)
                        record['runs'].append({'source': rel, 'seed': seed.name,
                                               'exit_code': result.returncode,
                                               'stderr_tail': result.stderr[-240:]})
                        self.assertEqual(result.returncode, 0,
                                         f'{rel} {seed.name}: {result.stderr[-1200:]}')
            record['status'] = 'PASS'
        except BaseException as exc:
            record['status'] = 'FAIL'
            record['error_type'] = type(exc).__name__
            record['error'] = str(exc)[:1200]
            raise
        finally:
            evidence.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
            evidence.chmod(0o600)

    def test_harness_entry_abort_is_observed_at_runtime(self) -> None:
        self.assertEqual(len(NORMAL_SEEDS), 10)
        record = {'kind': 'MD4C_ASSERTION_BUILDER_ABORT_RUNTIME_CONTROL_V1',
                  'status': 'INCOMPLETE', 'seed': NORMAL_SEEDS[0].name,
                  'builder_sha256': hashlib.sha256(BUILDER.read_bytes()).hexdigest(),
                  'manifest_sha256': hashlib.sha256(
                      (ROOT / 'tools/multi_tu_assertion_build_manifest.json').read_bytes()).hexdigest()}
        evidence = EVIDENCE_DIR / 'BUILDER_ABORT_RUNTIME_CONTROL.json'
        try:
            with tempfile.TemporaryDirectory(prefix='md4c-builder-abort-', dir=ROOT) as name:
                temp = Path(name)
                original = SOURCES / 'test/fuzzers/fuzz-mdhtml.c'
                copy = temp / original.name
                marker = b'LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)\n{\n'
                contents = original.read_bytes()
                self.assertEqual(contents.count(marker), 1)
                copy.write_bytes(contents.replace(marker, marker + b'    abort();\n', 1))
                binary = temp / 'abort-control.bin'
                build = self.invoke(copy, '-o', binary)
                self.assertEqual(build.returncode, 0, build.stderr[-1200:])
                result = self.run_instrumented(binary, NORMAL_SEEDS[0])
                record['exit_code'] = result.returncode
                record['stderr_sha256'] = hashlib.sha256(result.stderr.encode()).hexdigest()
                record['stderr_tail'] = result.stderr[-1200:]
                self.assertNotEqual(result.returncode, 0, 'injected abort did not execute')
                self.assertIn('SUMMARY: libFuzzer: deadly signal', result.stderr,
                              f'abnormal exit lacks libFuzzer signal evidence: {result.stderr[-1200:]}')
            record['status'] = 'PASS'
        except BaseException as exc:
            record['status'] = 'FAIL'
            record['error_type'] = type(exc).__name__
            record['error'] = str(exc)[:1200]
            raise
        finally:
            evidence.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
            evidence.chmod(0o600)


if __name__ == '__main__':
    unittest.main()
