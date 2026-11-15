import tempfile
import unittest
from pathlib import Path

from vulnerabilityanalysis.context import ContextResolver
from vulnerabilityanalysis.models import ContextRequest
from vulnerabilityanalysis.source import SourceRepository


class InitializerContextTests(unittest.TestCase):
    def resolve(self, source: str, *, build_command=None, other: str | None = None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "target.c").write_text(source)
            if other is not None:
                (root / "other.c").write_text(other)
            repository = SourceRepository(root, {"analyze": {"file": "target.c"}})
            resolver = ContextResolver(repository, build_command=build_command)
            request = ContextRequest("analyze", "global_hooks", "INITIALIZER",
                                     "allocator origin", "initial value")
            return resolver.resolve(request)

    def test_file_scope_initializer_is_returned_without_immutability_claim(self):
        rows = self.resolve("static int global_hooks = 1;\n"
                            "void set_hooks(void) { global_hooks = 2; }\n"
                            "int analyze(void) { return global_hooks; }\n",
                            other="static int global_hooks = 999;\n")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["source"], "static int global_hooks = 1;")
        self.assertEqual(rows[0]["runtime_immutability_proven"], "false")
        self.assertTrue(rows[0]["source_file"].endswith("target.c"))

    def test_function_local_assignment_is_not_a_global_initializer(self):
        rows = self.resolve("int analyze(void) { int global_hooks = 1; return global_hooks; }\n")
        self.assertEqual(rows, [])

    def test_file_scope_array_initializer_is_returned(self):
        rows = self.resolve('static const char* global_hooks[] = {"note", "tip"};\n'
                            'int analyze(void) { return global_hooks[0][0]; }\n')
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["source"],
                         'static const char* global_hooks[] = {"note", "tip"};')
        self.assertEqual(rows[0]["runtime_immutability_proven"], "false")

    def test_function_local_array_initializer_is_not_file_scope(self):
        rows = self.resolve('int analyze(void) { const char* global_hooks[] = '
                            '{"local"}; return global_hooks[0][0]; }\n')
        self.assertEqual(rows, [])

    def test_bare_file_scope_assignment_is_not_a_declaration(self):
        rows = self.resolve("global_hooks = 1;\nint analyze(void) { return 0; }\n")
        self.assertEqual(rows, [])

    def test_ambiguous_conditional_definitions_are_not_guessed(self):
        rows = self.resolve("#ifdef FIRST\nstatic int global_hooks = 1;\n"
                            "#else\nstatic int global_hooks = 2;\n#endif\n"
                            "int analyze(void) { return global_hooks; }\n")
        self.assertEqual(rows, [])

    def test_active_build_selects_exact_conditional_definition(self):
        rows = self.resolve("#ifdef FIRST\nstatic int global_hooks = 1;\n"
                            "#else\nstatic int global_hooks = 2;\n#endif\n"
                            "int analyze(void) { return global_hooks; }\n",
                            build_command=["/home/dawne/.local/bin/gcc", "-DFIRST", "{source}"])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["source"], "static int global_hooks = 1;")
        self.assertEqual(rows[0]["build_evidence"],
                         "EXACT_COMMAND_PREPROCESSED_DECLARATION")

    def test_existing_named_function_lookup_remains_available(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "target.c").write_text("int init_state(void) { return 1; }\n"
                                             "int analyze(void) { return init_state(); }\n")
            repository = SourceRepository(root, {
                "analyze": {"file": "target.c"},
                "init_state": {"file": "target.c"},
            })
            request = ContextRequest("analyze", "init_state", "INITIALIZER",
                                     "state origin", "initializer function")
            rows = ContextResolver(repository).resolve(request)
            self.assertEqual(len(rows), 1)
            self.assertIn("init_state(void)", rows[0]["source"])


if __name__ == "__main__":
    unittest.main()
