from pathlib import Path
import tempfile
import unittest

from vulnerabilityanalysis.assertions import instrument_copy


class PreludePlacementTests(unittest.TestCase):
    def test_feature_macro_and_configured_header_remain_first(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            src = root / 'a.c'
            out = root / 'out.c'
            src.write_text('#define _GNU_SOURCE\n#include <limits.h>\nint f(int x) { return x; }\n')
            instrument_copy(src, 3, 'x >= 0', out, 'TEST1')
            result = out.read_text()
            self.assertLess(result.index('#define _GNU_SOURCE'), result.index('#include <stdio.h>'))
            self.assertLess(result.index('#include <limits.h>'), result.index('#include <stdio.h>'))
            self.assertLess(result.index('#define VA_ASSERT'), result.index('VA_ASSERT("TEST1"'))

    def test_continued_macro_is_not_split(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            src = root / 'b.c'
            out = root / 'out.c'
            src.write_text('#define X(v) \\\n  ((v) + 1)\nint f(int x) { return x; }\n')
            instrument_copy(src, 3, 'x >= 0', out, 'TEST2')
            result = out.read_text()
            self.assertLess(result.index('((v) + 1)'), result.index('#include <stdio.h>'))

    def test_no_existing_headers(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            src = root / 'c.c'
            out = root / 'out.c'
            src.write_text('int f(int x) {\n  return x;\n}\n')
            instrument_copy(src, 2, 'x >= 0', out, 'TEST3')
            result = out.read_text()
            self.assertLess(result.index('#include <stdio.h>'), result.index('VA_ASSERT("TEST3"'))

    def test_arbitrary_function_call_stays_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            src = root / 'd.c'
            src.write_text('int f(int x) { return x; }\n')
            with self.assertRaises(ValueError):
                instrument_copy(src, 1, 'strcmp(a, b) == 0', root / 'out.c', 'TEST4')


if __name__ == '__main__':
    unittest.main()
