from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from vulnerabilityanalysis.assertions import instrument_copy


class ConditionalPreludeTests(unittest.TestCase):
    def _compile(self, suffix, source, assertion_line, *, guided=False):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / ('target' + suffix)
            out = Path(tmp) / ('copy' + suffix)
            src.write_text(source)
            instrument_copy(src, assertion_line, 'x >= 0', out, 'PRELUDE',
                            guided=guided)
            generated = out.read_text()
            compiler = 'g++' if suffix == '.cpp' else 'gcc'
            if shutil.which(compiler) is None:
                self.skipTest(f'{compiler} unavailable')
            compile_result = subprocess.run([compiler, '-fsyntax-only',
                                             '-Werror=implicit-function-declaration'
                                             if suffix == '.c' else '-Wall', str(out)],
                                            capture_output=True, text=True)
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            return generated

    def test_inactive_c_branch_before_target(self):
        generated = self._compile('.c',
            '#define _GNU_SOURCE\n'
            '#if 0\n'
            'int hidden(int x) { return x; }\n'
            '#endif\n'
            'int f(int x) {\n'
            '  return x;\n'
            '}\n', 6)
        self.assertLess(generated.index('#endif'), generated.index('#define VA_ASSERT'))

    def test_nested_inactive_cpp_branch_before_target(self):
        generated = self._compile('.cpp',
            '#if 1\n'
            '# if 0\n'
            'int hidden(int x) { return x; }\n'
            '# endif\n'
            '#endif\n'
            'namespace demo {\n'
            'int f(int x) {\n'
            '  return x;\n'
            '}\n'
            '}\n', 8)
        self.assertLess(generated.rindex('#endif'), generated.index('#define VA_ASSERT'))

    def test_assertion_inside_conditional_only_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / 'target.c'
            src.write_text('#if 1\nint f(int x) {\n  return x;\n}\n#endif\n')
            with self.assertRaisesRegex(ValueError, 'prelude.*conditional'):
                instrument_copy(src, 3, 'x >= 0', Path(tmp) / 'copy.c', 'PRELUDE')

    def test_ifdef_else_and_elif_before_active_c_function(self):
        generated = self._compile('.c',
            '#define _GNU_SOURCE\n'
            '#if defined(NEVER)\n'
            'int a(int x) { return x; }\n'
            '#elif defined(ALSO_NEVER)\n'
            'int b(int x) { return x; }\n'
            '#else\n'
            'int c(int x) { return x; }\n'
            '#endif\n'
            '#ifdef NEVER\n'
            'int d(int x) { return x; }\n'
            '#else\n'
            '#define SAFE_MACRO 1\n'
            '#endif\n'
            'int f(int x) {\n'
            '  return x;\n'
            '}\n', 15)
        self.assertLess(generated.rindex('#endif'), generated.index('#define VA_ASSERT'))
        self.assertLess(generated.index('#define SAFE_MACRO'), generated.index('#include <stdio.h>'))

    def test_ifndef_include_guard_before_active_cpp_function(self):
        generated = self._compile('.cpp',
            '#ifndef VA_LOCAL_DECLS\n'
            '#define VA_LOCAL_DECLS\n'
            'struct Value { int n; };\n'
            '#endif\n'
            'int f(int x) {\n'
            '  return x;\n'
            '}\n', 6)
        self.assertLess(generated.index('#endif'), generated.index('#include <stdio.h>'))

    def test_entire_file_inside_include_guard_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / 'target.cpp'
            src.write_text('#ifndef VA_FILE_GUARD\n#define VA_FILE_GUARD\n'
                           'int f(int x) {\n  return x;\n}\n#endif\n')
            with self.assertRaisesRegex(ValueError, 'prelude.*conditional'):
                instrument_copy(src, 4, 'x >= 0', Path(tmp) / 'copy.cpp', 'PRELUDE')

    def test_assertion_inside_active_branch_with_prior_top_level_code(self):
        generated = self._compile('.c',
            '#define _GNU_SOURCE\n'
            'int helper(void) { return 1; }\n'
            '#if 1\n'
            'int f(int x) {\n'
            '  return x;\n'
            '}\n'
            '#endif\n', 5)
        self.assertLess(generated.index('#define VA_ASSERT'), generated.index('#if 1'))

    def test_guided_c_prelude_skips_inactive_branch(self):
        generated = self._compile('.c',
            '#if 0\nint hidden(int x) { return x; }\n#endif\n'
            'int f(int x) {\n  return x;\n}\n', 5, guided=True)
        self.assertLess(generated.index('#endif'), generated.index('va_extra_counters'))


if __name__ == '__main__':
    unittest.main()
