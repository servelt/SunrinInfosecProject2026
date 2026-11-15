"""Regression: detached child execution is not a measured source-line miss."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from vulnerabilityanalysis.runtime import trace_sp_location


class DetachedChildTraceTest(unittest.TestCase):
    def test_completed_single_process_run_can_confirm_unreached(self):
        compiler = shutil.which("cc")
        if not compiler or not shutil.which("gdb"):
            self.skipTest("C compiler and GDB required")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "single.c"
            source.write_text(
                "int target(void) {\n"
                "    return 1;\n"
                "}\n"
                "int main(int argc, char **argv) { return 0; }\n"
            )
            binary = root / "single"
            seed = root / "seed"
            seed.write_bytes(b"normal input")
            subprocess.run([compiler, "-g", "-O0", str(source), "-o", str(binary)],
                           check=True, capture_output=True)
            reached, condition, trace = trace_sp_location(binary, seed, f"{source}:2")
            self.assertIn("COMPLETED=True", trace)
            self.assertNotIn("Detaching after fork", trace)
            self.assertFalse(reached, trace)
            self.assertIsNone(condition, trace)

    def test_detached_child_with_assertion_tags_is_unknown(self):
        compiler = shutil.which("cc")
        if not compiler or not shutil.which("gdb"):
            self.skipTest("C compiler and GDB required")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "forked.c"
            source.write_text(
                "#include <stdio.h>\n"
                "#include <sys/types.h>\n"
                "#include <sys/wait.h>\n"
                "#include <unistd.h>\n"
                "int main(int argc, char **argv) {\n"
                "    pid_t child = fork();\n"
                "    if (child == 0) {\n"
                "        usleep(50000);\n"
                '        fprintf(stderr, "VA_ASSERTION_HIT:forkcase\\n");\n'
                '        fprintf(stderr, "VA_ASSERTION_VIOLATION:forkcase\\n");\n'
                "        _exit(0);\n"
                "    }\n"
                "    if (child < 0) return 2;\n"
                "    int status;\n"
                "    if (waitpid(child, &status, 0) < 0) return 3;\n"
                "    return 0;\n"
                "}\n"
            )
            binary = root / "forked"
            seed = root / "seed"
            seed.write_bytes(b"normal input")
            subprocess.run([compiler, "-g", "-O0", str(source), "-o", str(binary)],
                           check=True, capture_output=True)
            ordinary = subprocess.run([str(binary), str(seed)], capture_output=True,
                                      text=True, check=True)
            self.assertIn("VA_ASSERTION_HIT:forkcase", ordinary.stderr)
            self.assertIn("VA_ASSERTION_VIOLATION:forkcase", ordinary.stderr)
            reached, condition, trace = trace_sp_location(
                binary, seed, f"{source}:9", "child == 0")
            self.assertIn("Detaching after fork from child process", trace)
            self.assertIn("SP_PROBE_HITS=0", trace)
            self.assertIsNone(reached, trace)
            self.assertIsNone(condition, trace)


if __name__ == "__main__":
    unittest.main()
