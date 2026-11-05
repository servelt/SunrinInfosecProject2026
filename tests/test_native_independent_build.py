"""Tests the OSS-Fuzz-independent build path using actual LLVM executables."""
from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harnesscreator.cli import _run, build_parser
from harnesscreator.models import ProjectSpec
from harnesscreator.runtime.native_build import (
    NativeBuildUnresolved, build_native, discover_source_units,
)
from harnesscreator.runtime.runner import _with_native_build_evidence


class NativeBuildEvidenceForwarding(unittest.TestCase):
    def test_original_executable_and_compile_database_are_forwarded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "source"
            root.mkdir()
            original = root / "server"
            original.write_bytes(b"binary")
            db = root / "compile_commands.json"
            db.write_text("[]")
            project = ProjectSpec(
                source_root=root, output_root=Path(tmp) / "out",
                scenario_command=[str(original)], analysis_compile_database=db,
            )
            argv = ["python", "-m", "harnesscreator.runtime.native_build"]
            result = _with_native_build_evidence(argv, project)
            self.assertEqual(result[-4:], [
                "--compile-database", str(db), "--target-binary", str(original),
            ])
            self.assertEqual(_with_native_build_evidence(["python", "custom.py"], project),
                             ["python", "custom.py"])


class AutoVerificationSelection(unittest.IsolatedAsyncioTestCase):
    async def test_ignores_oss_fuzz_checkout_and_proceeds_to_source_discovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "project"
            source.mkdir()
            args = build_parser().parse_args([
                "run", str(source), "--allow-source-analysis",
                "--oss-fuzz-dir", "/does/not/exist/oss-fuzz",
            ])

            class ReachedSourceDiscovery(Exception):
                pass

            with patch("harnesscreator.cli._prepare_fuzz_introspector", side_effect=ReachedSourceDiscovery):
                with self.assertRaises(ReachedSourceDiscovery):
                    await _run(args)

    async def test_explicit_legacy_recipe_still_validates_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "project"
            source.mkdir()
            args = build_parser().parse_args([
                "run", str(source), "--verification-backend", "oss-fuzz",
                "--oss-fuzz-dir", "/does/not/exist/oss-fuzz",
            ])
            with self.assertRaisesRegex(ValueError, "usable OSS-Fuzz checkout"):
                await _run(args)


@unittest.skipUnless(shutil.which("clang") and shutil.which("clang++"), "Clang needed")
class NativeIndependentBuild(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "src"
        self.root.mkdir()
        self.output = Path(self.tmp.name) / "out"
        self.output.mkdir()

    def test_single_c_program_builds_with_original_main_renamed(self):
        (self.root / "service.c").write_text(
            '#include <stddef.h>\n#include <stdint.h>\n'
            'int handle(const uint8_t *p, size_t n){return (int)(n && p[0]==0x41);}\n'
            'int main(int argc, char **argv){return argc > 1;}\n'
        )
        harness = self.output / "fuzz_target.cc"
        harness.write_text(
            '#include <cstddef>\n#include <cstdint>\n'
            'extern "C" int handle(const uint8_t*, size_t);\n'
            'extern "C" int LLVMFuzzerTestOneInput(const uint8_t *p, size_t n) '
            '{(void)handle(p,n);return 0;}\n'
        )
        binary = build_native(self.root, harness, self.output)
        self.assertTrue(binary.is_file())
        self.assertEqual(binary.name, "hc-native-fuzzer")
        plan = json.loads((self.output / ".native-build" / "build-plan.json").read_text())
        self.assertEqual(plan["renamed_main"], [str(self.root / "service.c")])
        self.assertNotIn("oss-fuzz", json.dumps(plan).lower())
        result = __import__("subprocess").run([str(binary), "-runs=5"], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_small_two_file_program_builds_without_repo_registration(self):
        (self.root / "main.c").write_text(
            '#include <stdint.h>\n#include <stddef.h>\n'
            'int parse(const uint8_t*, size_t);\n'
            'int main(void){return parse((const uint8_t*)"A",1);}\n'
        )
        (self.root / "parse.c").write_text(
            '#include <stdint.h>\n#include <stddef.h>\n'
            'int parse(const uint8_t *p,size_t n){return n && p[0]==0x41;}\n'
        )
        harness = self.output / "fuzz_target.c"
        harness.write_text(
            '#include <stdint.h>\n#include <stddef.h>\n'
            'int parse(const uint8_t*,size_t);\n'
            'int LLVMFuzzerTestOneInput(const uint8_t *p,size_t n){(void)parse(p,n);return 0;}\n'
        )
        self.assertTrue(build_native(self.root, harness, self.output).exists())

    def test_multiple_executable_mains_do_not_guess(self):
        (self.root / "one.c").write_text("int main(void) {return 0;}\n")
        (self.root / "two.c").write_text("int main(void) {return 0;}\n")
        harness = self.output / "fuzz_target.c"
        harness.write_text(
            '#include <stddef.h>\n'
            'int LLVMFuzzerTestOneInput(const unsigned char *p,size_t n){return 0;}\n'
        )
        with self.assertRaisesRegex(NativeBuildUnresolved, "multiple program main"):
            build_native(self.root, harness, self.output)
        self.assertFalse((self.output / "hc-native-fuzzer").exists())

    def test_compile_database_is_read_without_running_compiler_commands(self):
        source = self.root / "source.c"
        source.write_text("int func(void) {return 0;}\n")
        db = [{
            "directory": str(self.root),
            "file": "source.c",
            "arguments": ["clang", "-I", "includes", "-D", "SAMPLE=1", "-Xclang", "-load", "evil.so", "-o", "/tmp/overwrite", "-c", "source.c"],
        }]
        (self.root / "compile_commands.json").write_text(json.dumps(db))
        units, evidence = discover_source_units(self.root)
        self.assertEqual(len(units), 1)
        self.assertEqual(units[0].source, source)
        self.assertIn("-D", units[0].flags)
        self.assertNotIn("-Xclang", units[0].flags)
        self.assertNotIn("/tmp/overwrite", units[0].flags)
        self.assertIn("compile_commands.json", evidence)

    def test_link_failure_cannot_be_mistaken_for_success(self):
        (self.root / "unresolved.c").write_text(
            "extern int missing_library_symbol(void);\n"
            "int routine(void) {return missing_library_symbol();}\n"
        )
        harness = self.output / "fuzz_target.c"
        harness.write_text(
            '#include <stddef.h>\n'
            'int routine(void);\n'
            'int LLVMFuzzerTestOneInput(const unsigned char *p,size_t n){(void)routine();return 0;}\n'
        )
        with self.assertRaisesRegex(NativeBuildUnresolved, "link failed"):
            build_native(self.root, harness, self.output)
        self.assertFalse((self.output / "hc-native-fuzzer").exists())


if __name__ == "__main__":
    unittest.main()

class NativePureCCompilerRequirement(unittest.TestCase):
    def test_c_only_fuzzer_build_does_not_need_clangxx(self):
        if not shutil.which('clang'):
            self.skipTest('clang required')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'src'
            out = Path(tmp) / 'out'
            root.mkdir()
            out.mkdir()
            (root / 'program.c').write_text(
                '#include <stddef.h>\nint handle(void) {return 1;}\n'
            )
            harness = out / 'fuzz_target.c'
            harness.write_text(
                '#include <stddef.h>\nint handle(void);\n'
                'int LLVMFuzzerTestOneInput(const unsigned char *p, size_t n) '
                '{(void)p;(void)n;return handle()-1;}\n'
            )
            original_which = shutil.which
            with patch('harnesscreator.runtime.native_build.shutil.which',
                       side_effect=lambda name: None if name == 'clang++' else original_which(name)):
                binary = build_native(root, harness, out)
            self.assertTrue(binary.is_file())
