"""Conservative, model-free tests for the assertion expression subset."""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from vulnerabilityanalysis.assertions import instrument_copy, validate_expression


class AssertionExpressionExtensionTests(unittest.TestCase):
    def test_single_character_and_common_escape_literals(self):
        for expression in ("buf[0] == 'a'", r"buf[0] == '\0'", r"buf[0] != '\n'"):
            with self.subTest(expression=expression):
                validate_expression(expression)

    def test_multicharacter_malformed_and_string_literals_stay_rejected(self):
        for expression in ("buf[0] == 'ab'", "buf[0] == '\\x41'",
                           "buf[0] == '\\'", 'buf[0] == "a"'):
            with self.subTest(expression=expression), self.assertRaises(ValueError):
                validate_expression(expression)

    def test_pure_bitwise_operators(self):
        validate_expression("(flags & 3) ^ (~mask & 3)")
        validate_expression("~flags & 1")
        for expression in ("flags ^= 1", "flags = ~mask", "flags++ ^ mask",
                           "flags ^", "~"):
            with self.subTest(expression=expression), self.assertRaises(ValueError):
                validate_expression(expression)

    @unittest.skipUnless(shutil.which("clang") or shutil.which("gcc"), "C compiler required")
    def test_complete_source_tag_sizeof_requires_build_validation(self):
        compiler = shutil.which("clang") or shutil.which("gcc")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "target.c"
            source.write_text("struct Fixed { unsigned char bytes[4]; };\n"
                              "int main(void) {\n"
                              "  unsigned count = 4;\n"
                              "  return 0;\n}\n")
            expression = "count <= sizeof(struct Fixed)"
            with self.assertRaises(ValueError):
                instrument_copy(source, 4, expression, root / "no-build.c", "a-no-build")
            copy = root / "with-build.c"
            instrument_copy(source, 4, expression, copy, "a-fixed",
                            build_command=[compiler, "{source}", "-o", "{binary}"])
            binary = root / "with-build"
            built = subprocess.run([compiler, str(copy), "-o", str(binary)],
                                   capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stderr)
            self.assertEqual(subprocess.run([str(binary)], capture_output=True).returncode, 0)
            with self.assertRaises(ValueError):
                instrument_copy(source, 4, "count <= sizeof(struct Missing)",
                                root / "unknown.c", "a-unknown",
                                build_command=[compiler, "{source}", "-o", "{binary}"])

    def test_pointer_cast_dereference_remains_rejected(self):
        with self.assertRaises(ValueError):
            validate_expression("((struct Fixed *)p)->bytes[0] == 0")

    def test_variable_length_typedef_sizeof_stays_rejected(self):
        with self.assertRaises(ValueError):
            validate_expression("count <= sizeof(arr_t)")

    @unittest.skipUnless(shutil.which("clang") or shutil.which("gcc"), "C compiler required")
    def test_new_expressions_compile_and_hold_for_normal_seed(self):
        compiler = shutil.which("clang") or shutil.which("gcc")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "target.c"
            source.write_text(
                "int main(void) {\n"
                "  unsigned flags = 5, mask = 2;\n"
                "  char buf[2] = {'a', 0};\n"
                "  return 0;\n"
                "}\n")
            for index, expression in enumerate((r"buf[1] == '\0'",
                                                "buf[0] == 'a'",
                                                "((flags & 3) ^ (~mask & 3)) == 0")):
                with self.subTest(expression=expression):
                    copy = root / f"instrumented{index}.c"
                    binary = root / f"instrumented{index}"
                    instrument_copy(source, 4, expression, copy, f"a-{index}")
                    built = subprocess.run([compiler, str(copy),
                                            "-o", str(binary)], capture_output=True, text=True)
                    self.assertEqual(built.returncode, 0, built.stderr)
                    run = subprocess.run([str(binary)], capture_output=True)
                    self.assertEqual(run.returncode, 0, run.stderr)


if __name__ == "__main__":
    unittest.main()
