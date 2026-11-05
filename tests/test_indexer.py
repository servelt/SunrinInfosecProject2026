from pathlib import Path
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from harnesscreator.analysis import GraphStore, StaticAnalyzer
from harnesscreator.analysis.indexer import _iter_project_files
from harnesscreator.analysis.compile_priority import order_translation_units
from harnesscreator.models import ProjectSpec
from harnesscreator.runtime.preflight import source_analysis_binary


FIXTURE = Path(__file__).parent / "fixtures" / "c_project"


class StaticAnalyzerTest(unittest.TestCase):
    def test_original_in_tree_executable_selects_ast_order_without_duplicate_option(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            executable = root / "service"
            executable.write_bytes(b"binary")
            outside = Path(temporary) / "launcher"
            outside.write_bytes(b"binary")
            project = ProjectSpec(
                source_root=root, output_root=Path(temporary) / "output",
                scenario_command=[str(executable)], scenario_channel="stdin",
            )
            self.assertEqual(source_analysis_binary(project), executable)
            project.scenario_command = [str(outside)]
            self.assertIsNone(source_analysis_binary(project))
            project.analysis_binary = outside
            self.assertEqual(source_analysis_binary(project), outside)

    def test_ast_order_uses_recorded_compiler_directory_without_excluding_units(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build = root / "build"
            library = build / "library"
            library.mkdir(parents=True)
            executable = build / "service"
            executable.write_bytes(b"binary")
            product_c = root / "z_product.c"
            product_cpp = root / "z_product.cpp"
            library_c = root / "a_library.c"
            library_cpp = root / "a_library.cpp"
            unrecorded = root / "m_unrecorded.c"
            for path in (product_c, product_cpp, library_c, library_cpp, unrecorded):
                path.write_text("int f(void) { return 1; }\n", encoding="utf-8")
            database = root / "compile_commands.json"
            database.write_text(json.dumps([
                {"directory": str(build), "file": str(product_c)},
                {"directory": str(build), "file": str(product_cpp)},
                {"directory": str(library), "file": str(library_c)},
                {"directory": str(library), "file": str(library_cpp)},
            ]), encoding="utf-8")

            ordered = order_translation_units(
                [library_c, unrecorded, product_c, library_cpp, product_cpp],
                root, database, executable,
            )
            fallback = order_translation_units(
                [library_c, product_c], root, database, None,
            )

            self.assertEqual(ordered[:2], [product_c, product_cpp])
            self.assertEqual(set(ordered), {
                product_c, product_cpp, library_c, library_cpp, unrecorded,
            })
            self.assertEqual(fallback, [library_c, product_c])

    def test_compile_database_object_output_is_not_a_link_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "worker.c").write_text(
                "int worker(void) { return 1; }\n", encoding="utf-8",
            )
            (root / "compile_commands.json").write_text(json.dumps([{
                "directory": str(root),
                "file": str(root / "worker.c"),
                "output": str(root / "CMakeFiles/server.dir/worker.c.o"),
                "command": "cc -c worker.c -o CMakeFiles/server.dir/worker.c.o",
            }]), encoding="utf-8")
            bundle = StaticAnalyzer(root).index()
        worker = next(item for item in bundle.functions.values()
                      if item.name == "worker")
        self.assertEqual(worker.build_targets, [])

    def test_build_target_requires_exact_source_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "tools").mkdir()
            (root / "Makefile.am").write_text(
                "bin_PROGRAMS = server\n"
                "server_SOURCES = src/shared.c\n", encoding="utf-8",
            )
            (root / "src/shared.c").write_text(
                "int product_function(void) { return 1; }\n", encoding="utf-8",
            )
            (root / "tools/shared.c").write_text(
                "int tool_function(void) { return 2; }\n", encoding="utf-8",
            )
            bundle = StaticAnalyzer(root).index()
        by_name = {item.name: item for item in bundle.functions.values()}
        self.assertEqual(by_name["product_function"].build_targets, ["server"])
        self.assertEqual(by_name["tool_function"].build_targets, [])

    def test_source_walk_prunes_run_directories_before_recursion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "real.c").write_text("int real(void) { return 1; }\n")
            generated = root / "runs-old" / "nested"
            generated.mkdir(parents=True)
            (generated / "wrong.c").write_text("int wrong(void) { return 2; }\n")
            original_scandir = os.scandir

            def checked_scandir(path):
                self.assertFalse(str(path).startswith(str(root / "runs-old")))
                return original_scandir(path)

            with patch("os.scandir", side_effect=checked_scandir):
                paths = _iter_project_files(root)

            self.assertEqual(paths, [root / "real.c"])

    def test_cpp_plus_plus_extension_is_indexed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "listener.c++").write_text(
                "int parse_byte(const char *data) { return data[0]; }\n",
                encoding="utf-8",
            )
            names = {
                function.name for function in StaticAnalyzer(root).index().functions.values()
            }
            self.assertIn("parse_byte", names)

    def test_cpp_global_scope_input_call_in_member_function_is_indexed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "session.cpp").write_text(
                "#include <sys/socket.h>\n"
                "class Session {\n"
                "public:\n"
                "  char data[8];\n"
                "  int receive(int fd) { return ::recv(fd, data, sizeof(data), 0); }\n"
                "};\n",
                encoding="utf-8",
            )
            bundle = StaticAnalyzer(root).index()

        receiver = next(item for item in bundle.functions.values()
                        if item.name == "receive")
        self.assertIn("recv", receiver.external_calls)

    def test_cpp_global_scope_call_is_not_linked_to_same_named_member(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "session.cpp").write_text(
                "#include <sys/socket.h>\n"
                "class Session {\n"
                "public:\n"
                "  int recv(int) { return 0; }\n"
                "  int receive(int fd) { char data[8]; "
                "return ::recv(fd, data, sizeof(data), 0); }\n"
                "};\n",
                encoding="utf-8",
            )
            bundle = StaticAnalyzer(root).index()

        by_name = {item.name: item for item in bundle.functions.values()}
        self.assertIn("recv", by_name["receive"].external_calls)
        self.assertNotIn(by_name["recv"].function_id, by_name["receive"].callees)

    def test_explicit_output_directory_is_not_reindexed_as_project_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "custom-generated-artifacts"
            output.mkdir()
            (root / "real.c").write_text(
                "int real_function(void) { return 1; }\n", encoding="utf-8"
            )
            (output / "fuzz_target.cc").write_text(
                "int generated_harness_function(void) { return 2; }\n", encoding="utf-8"
            )

            bundle = StaticAnalyzer(root, excluded_paths=[output]).index()

        names = {function.name for function in bundle.functions.values()}
        self.assertIn("real_function", names)
        self.assertNotIn("generated_harness_function", names)

    def test_extracts_functions_external_entry_and_edges(self) -> None:
        bundle = StaticAnalyzer(FIXTURE).index()
        by_name = {function.name: function for function in bundle.functions.values()}

        self.assertIn("serve_client", by_name)
        self.assertIn("parse_frame", by_name)
        self.assertIn("recv", by_name["serve_client"].external_calls)
        self.assertIn(by_name["parse_frame"].function_id, by_name["serve_client"].callees)
        self.assertNotIn("fprintf", by_name)
        self.assertEqual(by_name["serve_client"].build_targets, ["frame-server"])
        self.assertEqual(by_name["serve_client"].headers, ["target.h"])
        self.assertEqual(by_name["serve_client"].declaration, "int serve_client(int fd);")
        self.assertFalse(bundle.completeness["authoritative"])

        graph = GraphStore(bundle)
        callers = graph.callers(by_name["parse_frame"].function_id)
        self.assertEqual([item.name for item in callers], ["serve_client"])
        context = graph.context([by_name["parse_frame"].function_id], max_depth=2, max_functions=4)
        self.assertEqual({item.name for item in context}, {"serve_client", "parse_frame"})

    def test_preserves_fuzz_introspector_reported_edges(self) -> None:
        payload = {
            "functions": [
                {
                    "functionName": "callback_owner",
                    "functionSourceFile": "missing.c",
                    "functionLinenumber": 1,
                    "Functions reached": ["indirect_target"],
                },
                {
                    "functionName": "indirect_target",
                    "functionSourceFile": "missing.c",
                    "functionLinenumber": 20,
                    "Functions reached": [],
                },
            ]
        }
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "fi.json"
            report.write_text(json.dumps(payload), encoding="utf-8")
            bundle = StaticAnalyzer(FIXTURE, report).index()
        by_name = {function.name: function for function in bundle.functions.values()}
        matching = [
            edge for edge in bundle.edges
            if edge.caller_id == by_name["callback_owner"].function_id
            and edge.callee_id == by_name["indirect_target"].function_id
        ]
        self.assertEqual(len(matching), 1)
        self.assertIn("fuzz-introspector", matching[0].providers)
        self.assertFalse(bundle.completeness["authoritative"])
        self.assertTrue(bundle.completeness["fuzz_introspector_used"])

    def test_bootstrap_index_records_address_taken_callback_edges(self) -> None:
        source = """
typedef void (*callback_t)(int);
static void on_event(int value) { (void)value; }
void register_event(callback_t callback);
void setup(void) { register_event(&on_event); }
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "callback.c").write_text(source, encoding="utf-8")
            bundle = StaticAnalyzer(root).index()
        by_name = {function.name: function for function in bundle.functions.values()}
        matching = [
            edge for edge in bundle.edges
            if edge.caller_id == by_name["setup"].function_id
            and edge.callee_id == by_name["on_event"].function_id
        ]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0].kind, "function_reference")
        self.assertLess(matching[0].confidence, 0.5)

        graph = GraphStore(bundle)
        choice = next(
            item for item in graph.frontier([by_name["on_event"].function_id])
            if item["function_id"] == by_name["setup"].function_id
        )
        connection = choice["connections"][0]
        self.assertTrue(connection["callback_registration_candidate"])
        self.assertIn(matching[0].line, connection["edge_lines"])

    def test_pointer_return_owner_records_member_callback_assignment(self) -> None:
        source = """
typedef int (*reader_t)(void *ctx, char *buf, int len);
struct connection { reader_t read; };
static int tcp_read(void *ctx, char *buf, int len) {
    (void)ctx; (void)buf; return len;
}
struct connection *conn_new(struct connection *c) {
    c->read = tcp_read;
    return c;
}
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "callback.c").write_text(source, encoding="utf-8")
            bundle = StaticAnalyzer(root).index()

        by_name = {function.name: function for function in bundle.functions.values()}
        self.assertIn("conn_new", by_name)
        matching = [
            edge for edge in bundle.edges
            if edge.caller_id == by_name["conn_new"].function_id
            and edge.callee_id == by_name["tcp_read"].function_id
        ]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0].kind, "function_reference")

    def test_indexes_pointer_return_without_space_before_star(self) -> None:
        source = """
unsigned char* buf_getptr(const unsigned char* buf, unsigned int len) {
    return (unsigned char*)buf + len;
}
int read_packet(int fd, unsigned char* buf, unsigned int len) {
    return read(fd, buf_getptr(buf, len), len);
}
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "packet.c").write_text(source, encoding="utf-8")
            bundle = StaticAnalyzer(root).index()

        by_name = {function.name: function for function in bundle.functions.values()}
        self.assertIn("buf_getptr", by_name)
        self.assertIn(by_name["buf_getptr"].function_id, by_name["read_packet"].callees)

    def test_indexes_allman_style_function_definition(self) -> None:
        source = """
int main(int argc, char **argv)
{
    return argc > 0 && argv != 0;
}
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "allman.c").write_text(source, encoding="utf-8")
            bundle = StaticAnalyzer(root).index()

        by_name = {function.name: function for function in bundle.functions.values()}
        self.assertIn("main", by_name)
        self.assertIn("return argc", by_name["main"].source)

    def test_indexes_c_function_with_space_before_parameter_list(self) -> None:
        # memcached spells its real process entry as ``int main (...)``.  A
        # source index that accepts only ``main(...)`` silently drops argv while
        # still finding helper-program mains, which makes the resulting Entry
        # inventory look plausible but target the wrong executable.
        source = """
int main (int argc, char **argv) {
    return argc > 0 && argv != 0;
}
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "spaced.c").write_text(source, encoding="utf-8")
            bundle = StaticAnalyzer(root).index()

        by_name = {function.name: function for function in bundle.functions.values()}
        self.assertIn("main", by_name)
        self.assertEqual(by_name["main"].signature, "int main (int argc, char **argv)")

    def test_cpp_alternative_braces_do_not_hide_following_functions(self) -> None:
        source = """
int main(int argc, char **argv) {
#ifdef USE_FIRST
    if (argc) {
#else
    if (argv) {
#endif
        return 0;
    }
}

int after_main(void) { return 1; }
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "conditional.c").write_text(source, encoding="utf-8")
            bundle = StaticAnalyzer(root).index()

        by_name = {function.name: function for function in bundle.functions.values()}
        self.assertIn("main", by_name)
        self.assertIn("after_main", by_name)
        self.assertLess(by_name["main"].end_line, by_name["after_main"].start_line)

    def test_can_require_fuzz_introspector(self) -> None:
        with self.assertRaisesRegex(ValueError, "Fuzz Introspector report not found"):
            StaticAnalyzer(FIXTURE, require_fuzz_introspector=True).index()

    def test_rejects_missing_explicit_fuzz_introspector_path(self) -> None:
        missing = FIXTURE / "does-not-exist" / "allFunctionsWithMain.yaml"
        with self.assertRaisesRegex(ValueError, "report path does not exist"):
            StaticAnalyzer(FIXTURE, missing).index()

    def test_imports_native_fuzz_introspector_yaml(self) -> None:
        report_text = """
All functions:
  - Function name: yaml_target
    Functions filename: missing.c
    Functions line number: 7
    Functions reached: []
"""
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "allFunctionsWithMain-target.yaml"
            report.write_text(report_text, encoding="utf-8")
            bundle = StaticAnalyzer(FIXTURE, report).index()
        self.assertIn("yaml_target", {function.name for function in bundle.functions.values()})
        self.assertFalse(bundle.completeness["authoritative"])

    def test_imports_build_free_end_line_and_ignores_function_macros(self) -> None:
        report_text = """
All functions:
  Elements:
  - functionName: parse_frame
    functionSourceFile: target.c
    functionLinenumber: 8
    functionLinenumberEnd: 13
    functionsReached: []
  - functionName: TRACE_FRAME
    functionSourceFile: target.c
    functionLinenumber: 5
    functionLinenumberEnd: 6
    functionsReached: []
"""
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "fuzzerLogFile-empty.data.yaml"
            report.write_text(report_text, encoding="utf-8")
            bundle = StaticAnalyzer(FIXTURE, report).index()

        by_name = {function.name: function for function in bundle.functions.values()}
        self.assertEqual(by_name["parse_frame"].end_line, 13)
        self.assertNotIn("TRACE_FRAME", by_name)

    def test_required_fi_report_keeps_partial_graph_explicit(self) -> None:
        source_bundle = StaticAnalyzer(FIXTURE).index()
        one_function = source_bundle.function_list()[0]
        payload = {
            "functions": [{
                "functionName": one_function.name,
                "functionSourceFile": one_function.file,
                "functionLinenumber": one_function.start_line,
                "Functions reached": [],
            }]
        }
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "partial.json"
            report.write_text(json.dumps(payload), encoding="utf-8")
            bundle = StaticAnalyzer(
                FIXTURE,
                report,
                require_fuzz_introspector=True,
            ).index()
        self.assertFalse(bundle.completeness["authoritative"])
        self.assertFalse(bundle.completeness["graph_closure_proven"])
        self.assertEqual(bundle.completeness["callers"], "partial")

    def test_required_fi_report_rejects_unrelated_project(self) -> None:
        payload = {
            "functions": [{
                "functionName": "unrelated_target",
                "functionSourceFile": "missing.c",
                "functionLinenumber": 1,
                "Functions reached": [],
            }]
        }
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "unrelated.json"
            report.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "no function matching"):
                StaticAnalyzer(
                    FIXTURE, report, require_fuzz_introspector=True,
                ).index()

    def test_strict_mode_accepts_a_project_covering_report(self) -> None:
        source_bundle = StaticAnalyzer(FIXTURE).index()
        payload = {
            "functions": [
                {
                    "functionName": function.qualified_name,
                    "functionSourceFile": function.file,
                    "functionLinenumber": function.start_line,
                    "functionLineNumberEnd": function.end_line,
                    "Functions reached": [
                        source_bundle.functions[callee].qualified_name
                        for callee in function.callees
                    ],
                }
                for function in source_bundle.function_list()
            ]
        }
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "allFunctions.json"
            report.write_text(json.dumps(payload), encoding="utf-8")
            bundle = StaticAnalyzer(
                FIXTURE,
                report,
                require_fuzz_introspector=True,
            ).index()
        self.assertFalse(bundle.completeness["authoritative"])
        self.assertEqual(bundle.completeness["fuzz_introspector_source_coverage"], 1.0)

    def test_maps_container_report_paths_back_to_the_checkout(self) -> None:
        source_bundle = StaticAnalyzer(FIXTURE).index()
        payload = {
            "functions": [
                {
                    "functionName": function.qualified_name,
                    "functionSourceFile": f"/container/build/project/{function.file}",
                    "functionLinenumber": function.start_line,
                    "functionLineNumberEnd": function.end_line,
                    "Functions reached": [],
                }
                for function in source_bundle.function_list()
            ]
        }
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "allFunctions.json"
            report.write_text(json.dumps(payload), encoding="utf-8")
            bundle = StaticAnalyzer(
                FIXTURE, report, require_fuzz_introspector=True
            ).index()

        self.assertFalse(bundle.completeness["authoritative"])
        self.assertEqual(bundle.completeness["fuzz_introspector_source_coverage"], 1.0)


if __name__ == "__main__":
    unittest.main()
