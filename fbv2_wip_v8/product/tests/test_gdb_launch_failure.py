import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from vulnerabilityanalysis.models import RuntimeResult
from vulnerabilityanalysis.runtime import (parse_function_trace,
                                           trace_process_harness, trace_sp_location)


FAILURE = ("Breakpoint 1 at 0x123: file target.c, line 12.\n"
           "warning: Could not trace the inferior process.\n"
           "warning: ptrace: Operation not permitted\n"
           "During startup program exited with code 127.\n")


class GdbLaunchFailureTest(unittest.TestCase):
    def test_function_probe_startup_failure_is_unknown(self):
        self.assertIsNone(parse_function_trace(FAILURE, 'target'))
        self.assertFalse(parse_function_trace(
            'Breakpoint 1 at 0x123: target.c:12\n[Inferior 1 exited normally]\n', 'target'))

    def test_sp_probe_startup_failure_is_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'target.c'
            binary = Path(tmp) / 'target'
            seed = Path(tmp) / 'input'
            source.write_text('int target(void) { return 0; }\n')
            binary.write_bytes(b'binary')
            seed.write_bytes(b'seed')
            with (patch('vulnerabilityanalysis.runtime._mapped_dwarf_source',
                        return_value=(source, 'sha256')),
                  patch('vulnerabilityanalysis.runtime._guarded_run',
                        return_value=subprocess.CompletedProcess([], 1, '', FAILURE))):
                reached, condition, trace = trace_sp_location(
                    binary, seed, f'{source}:12')
            self.assertIsNone(reached)
            self.assertIsNone(condition)
            self.assertIn('COMPLETED=False', trace)

    def test_process_harness_probe_startup_failure_is_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'target.c'
            binary = root / 'target'
            seed = root / 'input'
            source.write_text('int target(void) { return 0; }\n')
            binary.write_bytes(b'binary')
            seed.write_bytes(b'seed')
            failed = RuntimeResult(1, '', FAILURE, None, False, None, None,
                                   'HARNESS_NOT_STARTED')
            command = ['python3', str(root / 'runner.py'), str(binary), '{input}']
            with (patch('vulnerabilityanalysis.runtime._mapped_dwarf_source',
                        return_value=(source, 'sha256')),
                  patch('vulnerabilityanalysis.runtime.RuntimeExecutor.run',
                        return_value=failed)):
                function, location, condition, trace = trace_process_harness(
                    command, seed, binary, 'target', source, f'{source}:1',
                    'value == 1', root / 'probe')
            self.assertEqual((function, location, condition), (None, None, None))
            self.assertIn('ptrace: Operation not permitted', trace)

    def test_process_harness_unverified_sp_hit_is_unknown_not_false(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, binary, seed = root / 'target.c', root / 'target', root / 'input'
            source.write_text('int target(void) { return 0; }\n')
            binary.write_bytes(b'binary')
            seed.write_bytes(b'seed')
            marker = 'VA_TRACE_deadbeef'
            command = [str(binary), '{input}']
            malformed_hit = (f'{marker}_FUNCTION_HIT\n{marker}_SP_BEGIN\n'
                             f'Line 99 of "{source}" starts at address 0x1\n'
                             f'{marker}_SP_END\n[Inferior 1 exited normally]\n')
            no_hit_unconfigured = (f'{marker}_FUNCTION_HIT\n'
                                   '[Inferior 1 exited normally]\n')
            no_hit_configured = ('Breakpoint 1 at 0x123: file target.c, line 1.\n'
                                 'Breakpoint 2 at 0x124: file target.c, line 1.\n'
                                 f'{marker}_FUNCTION_HIT\n'
                                 '[Inferior 1 exited normally]\n')
            for output, expected in ((malformed_hit, None),
                                     (no_hit_unconfigured, None),
                                     (no_hit_configured, False)):
                with (self.subTest(expected=expected),
                    patch('vulnerabilityanalysis.runtime.uuid.uuid4',
                          return_value=SimpleNamespace(hex='deadbeef')),
                    patch('vulnerabilityanalysis.runtime._mapped_dwarf_source',
                          return_value=(source, 'sha256')),
                    patch('vulnerabilityanalysis.runtime.RuntimeExecutor.run',
                          return_value=RuntimeResult(0, output, '', None, False,
                                                     None, None, 'NO_CRASH'))):
                    function, location, condition, _trace = trace_process_harness(
                        command, seed, binary, 'target', source, f'{source}:1',
                        None, root / 'probe')
                self.assertEqual((function, location, condition),
                                 (True, expected, None))

    def test_process_harness_missing_function_breakpoint_is_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, binary, seed = root / 'target.c', root / 'target', root / 'input'
            source.write_text('int target(void) { return 0; }\n')
            binary.write_bytes(b'binary')
            seed.write_bytes(b'seed')
            command = [str(binary), '{input}']
            for output, expected in (
                ('No symbol "target" in current context.\n'
                 'Breakpoint 2 at 0x124: file target.c, line 1.\n'
                 '[Inferior 1 exited normally]\n', None),
                ('Breakpoint 1 at 0x123: file target.c, line 1.\n'
                 '[Inferior 1 exited normally]\n', False),
                ('Breakpoint 1 at 0x123: file target.c, line 1.\n'
                 'Breakpoint 2 at 0x124: file target.c, line 1.\n'
                 'Program received signal SIGUSR1, User defined signal 1.\n', None),
            ):
                with (self.subTest(expected=expected),
                    patch('vulnerabilityanalysis.runtime._mapped_dwarf_source',
                          return_value=(source, 'sha256')),
                    patch('vulnerabilityanalysis.runtime.RuntimeExecutor.run',
                          return_value=RuntimeResult(0, output, '', None, False,
                                                     None, None, 'NO_CRASH'))):
                    function, location, condition, _trace = trace_process_harness(
                        command, seed, binary, 'target', source, f'{source}:1',
                        None, root / 'probe')
                self.assertEqual((function, location, condition),
                                 (expected, None, None))


if __name__ == '__main__':
    unittest.main()
