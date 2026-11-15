"""Insertion must preserve the original C/C++ control-flow boundary."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from vulnerabilityanalysis.assertions import instrument_copy


class InstrumentControlFlowTest(unittest.TestCase):
    def test_label_inside_unbraced_body_is_rejected_for_c_and_cpp(self):
        source_text = ("int f(int x) {\n    if (x)\n    label:\n"
                       "        return 1;\n    return 0;\n}\n"
                       "int main(void) { return f(0); }\n")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for suffix, compiler in (("c", "gcc"), ("cpp", "g++")):
                with self.subTest(suffix=suffix):
                    source = root / f"target.{suffix}"
                    source.write_text(source_text)
                    if shutil.which(compiler):
                        original = root / f"original-{suffix}"
                        subprocess.run([compiler, str(source), "-o", str(original)], check=True)
                        self.assertEqual(subprocess.run([str(original)]).returncode, 0)
                    output = root / f"out.{suffix}"
                    with self.assertRaisesRegex(ValueError, "unbraced control body"):
                        instrument_copy(source, 4, "x >= 0", output, "a-label")
                    self.assertFalse(output.exists())

    def test_nested_and_macro_control_labels_are_rejected(self):
        sources = (
            "int f(int x) {\n if (x)\n if (x > 1)\n label:\n"
            " return 1;\n else\n return 2;\n return 0;\n}\n",
            "#define IF_ENABLED(x) if (x)\nint f(int x) {\n"
            " IF_ENABLED(x)\n label:\n return 1;\n return 0;\n}\n",
            "int f(int x) {\n while (x)\n label:\n"
            " return 1;\n return 0;\n}\n",
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index, source_text in enumerate(sources):
                with self.subTest(index=index):
                    source = root / f"target-{index}.c"
                    source.write_text(source_text)
                    line = source_text.splitlines().index(" return 1;") + 1
                    with self.assertRaisesRegex(ValueError, "unbraced control body"):
                        instrument_copy(source, line, "x >= 0", root / f"out-{index}.c", "a-label")

    def test_switch_case_default_and_braced_label_remain_supported(self):
        source_text = ("int f(int x) {\n switch (x) {\n case 1:\n return 1;\n"
                       " default:\n return 0;\n }\n}\n")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "target.c"
            source.write_text(source_text)
            for line in (4, 6):
                with self.subTest(line=line):
                    output = root / f"out-{line}.c"
                    instrument_copy(source, line, "x >= 0", output, f"a-{line}")
                    if shutil.which("gcc"):
                        result = subprocess.run(["gcc", "-fsyntax-only", str(output)],
                                                capture_output=True, text=True)
                        self.assertEqual(result.returncode, 0, result.stderr)

    def test_unbraced_if_does_not_change_normal_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "target.c"
            source.write_text(
                "int f(int x) {\n    if (x)\n        return 1;\n"
                "    return 0;\n}\nint main(void) { return f(0); }\n")
            if shutil.which("gcc"):
                original = root / "original"
                subprocess.run(["gcc", str(source), "-o", str(original)], check=True)
                self.assertEqual(subprocess.run([str(original)]).returncode, 0)
            output = root / "instrumented.c"
            with self.assertRaisesRegex(ValueError, "unbraced control body"):
                instrument_copy(source, 3, "x >= 0", output, "a-control")
            self.assertFalse(output.exists())

    def test_other_unbraced_bodies_are_rejected(self):
        sources = (
            "int f(int x) {\n    for (int i = 0; i < 1; ++i)\n"
            "        x = 1;\n    return x;\n}\n",
            "int f(int x) {\n    while (x)\n        x = 1;\n    return x;\n}\n",
            "int f(int x) {\n    if (x)\n        x = 2;\n"
            "    else\n        x = 1;\n    return x;\n}\n",
            "int f(int x) {\n    do\n        x = 1;\n"
            "    while (x < 0);\n    return x;\n}\n",
            "int f(int x) {\n    if (x &&\n        x < 2)\n"
            "        x = 1;\n    return x;\n}\n",
            "int f(int x) {\n    if (x)\n#if 1\n"
            "        x = 1;\n#endif\n    return x;\n}\n",
            "#define IF_ENABLED(x) if (x)\nint f(int x) {\n"
            "    IF_ENABLED(x)\n        x = 1;\n    return x;\n}\n",
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index, source_text in enumerate(sources):
                source = root / f"target_{index}.c"
                source.write_text(source_text)
                body_line = source.read_text().splitlines().index("        x = 1;") + 1
                if shutil.which("gcc"):
                    compiled = subprocess.run(["gcc", "-fsyntax-only", str(source)],
                                              capture_output=True, text=True)
                    self.assertEqual(compiled.returncode, 0, compiled.stderr)
                with self.subTest(index=index), self.assertRaisesRegex(
                        ValueError, "unbraced control body"):
                    instrument_copy(source, body_line, "x >= 0",
                                    root / f"instrumented_{index}.c", f"a-{index}")

    @unittest.skipUnless(shutil.which("g++"), "C++ compiler required")
    def test_unbraced_cpp_body_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "target.cpp"
            source.write_text("int f(int x) {\n    if (x)\n"
                              "        return 1;\n    return 0;\n}\n")
            with self.assertRaisesRegex(ValueError, "unbraced control body"):
                instrument_copy(source, 3, "x >= 0", root / "out.cpp", "a-cpp")

    def test_braced_body_and_following_statement_remain_supported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "target.c"
            source.write_text("int f(int x) {\n    if (x) {\n        x = 1;\n"
                              "    }\n    return x;\n}\n")
            for line in (3, 5):
                with self.subTest(line=line):
                    output = root / f"instrumented_{line}.c"
                    instrument_copy(source, line, "x >= 0", output, f"a-{line}")
                    self.assertTrue(output.exists())
                    if shutil.which("gcc"):
                        binary = root / f"instrumented_{line}"
                        completed = subprocess.run(["gcc", "-c", str(output),
                                                    "-o", str(binary)], capture_output=True,
                                                   text=True)
                        self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
