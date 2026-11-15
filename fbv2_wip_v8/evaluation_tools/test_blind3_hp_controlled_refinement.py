"""Public toy: exercise the HP refinement plumbing with scripted role outputs.

The first violating input is chosen by this test. This proves execution and
state handoff, not model discovery or vulnerability detection.
"""
from __future__ import annotations

import asyncio
from dataclasses import asdict
import json
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest

from vulnerabilityanalysis.models import Assertion, FunctionAnalysis
from vulnerabilityanalysis.scan import (refine_overstrong_assertions,
                                        run_assertions_for_scan)


@unittest.skipUnless(shutil.which('clang') and shutil.which('gdb'),
                     'clang/libFuzzer and GDB required')
class ControlledHPRefinementTest(unittest.TestCase):
    def test_violation_refinement_and_second_real_guided_job(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'target.c'
            source.write_text(
                '#include <stdint.h>\n#include <stddef.h>\n'
                'void target(const uint8_t *data, size_t size) {\n'
                '  if (!size) return;\n'
                '  unsigned value = data[0] <= 200 ? data[0] : 255;\n'
                '  if (value > 200) return;\n'
                '  (void)value;\n'
                '}\n', encoding='utf-8')
            harness = root / 'harness.c'
            harness.write_text(
                '#include <stdint.h>\n#include <stddef.h>\n'
                'void target(const uint8_t *, size_t);\n'
                'int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) '
                '{ target(data, size); return 0; }\n', encoding='utf-8')
            seed = root / 'seed'
            seed.write_bytes(b'\xff')
            held = root / 'held'
            held.write_bytes(b'\x00')
            run = root / 'run'
            (run / 'assertions').mkdir(parents=True)
            (run / 'run.json').write_text(json.dumps({'run_id': 'public-toy-refine'}))
            analysis = run / 'analysis.json'
            analysis.write_text(json.dumps({
                'function_name': 'target',
                'safe_assumptions': ['value <= 200']}))
            initial = Assertion('a-initial', 'w', 'd', 'target', 'target.c:6',
                                'value <= 200', 'value <= 200', [])
            initial.source_function_analysis = str(analysis)
            (run / 'assertions' / 'proposed.json').write_text(
                json.dumps([asdict(initial)]))
            build = ['clang', '-fsanitize=fuzzer,address', '-g', '-O0',
                     '{source}', str(harness), '-o', '{binary}']
            command = ['{binary}', '{input}']
            first = run_assertions_for_scan(
                run, source, seed, build, command, fuzz_seconds=1)
            self.assertEqual(first[0].status, 'VIOLATED')
            first_reports = list((run / 'assertions' / 'a-initial').glob(
                'executions/*/guided_fuzz/guided_fuzz.json'))
            self.assertEqual(len(first_reports), 1)
            first_guided = json.loads(first_reports[0].read_text())
            self.assertEqual(first_guided['status'], 'ASSERTION_WITNESS_OBSERVED')
            self.assertGreater(first_guided['fuzzer_run_count'], 0)
            self.assertGreater(first_guided['fuzz_seconds_actual'], 0)
            self.assertTrue(first_guided['violation_witnesses'])
            first_triage = json.loads(Path(first_guided['violation_triage'][
                'triage_artifact']).read_text())
            self.assertEqual(first_triage['classification'],
                             'OVERSTRONG_ASSUMPTION')

            class ScriptedRoles:
                def __init__(self):
                    self.calls = []

                async def analyze_function(self, *args, **kwargs):
                    self.calls.append('function_analysis')
                    return FunctionAnalysis(
                        'target', 'target', 'target.c', 'public toy guard',
                        'harness byte', [], [],
                        ['value <= 200 || value == 255'], [])

                async def generate_assertions(self, *args, **kwargs):
                    self.calls.append('assertion_generator')
                    expression = 'value <= 200 || value == 255'
                    return [Assertion('a-refined', 'w', 'd', 'target',
                                      'target.c:6', expression, expression, [])]

            roles = ScriptedRoles()
            report = asyncio.run(refine_overstrong_assertions(
                run, roles, function_id='target', function_name='target',
                source_file='target.c', source=source.read_text(),
                original_source=source, source_start_line=3, context=[],
                build_command=build, run_command=command, fuzz_seconds=1,
                max_llm_calls=2, harness_source=harness.read_text(),
                harness_source_path=harness))
            self.assertEqual(roles.calls,
                             ['function_analysis', 'assertion_generator'])
            self.assertEqual(report['refinements'][0]['status'],
                             'REFINED_AND_TESTED')
            revisions = report['refinements'][0]['revisions']
            self.assertEqual(len(revisions), 1)
            second_guided = Path(revisions[0]['guided_fuzz'])
            self.assertTrue(second_guided.is_file())
            self.assertNotEqual(second_guided, first_reports[0])
            second_report = json.loads(second_guided.read_text())
            self.assertEqual(second_report['status'], 'RAN')
            self.assertGreater(second_report['fuzzer_run_count'], 0)
            self.assertGreater(second_report['fuzz_seconds_actual'], 0)
            self.assertEqual(first[0].status, 'VIOLATED')

            original = root / 'original'
            subprocess.run(['clang', '-fsanitize=fuzzer,address', '-g', '-O0',
                            str(source), str(harness), '-o', str(original)],
                           check=True, capture_output=True, timeout=30)
            for path in (held, seed):
                completed = subprocess.run([str(original), str(path)],
                                           capture_output=True, timeout=10)
                self.assertEqual(completed.returncode, 0)


if __name__ == '__main__':
    unittest.main()
