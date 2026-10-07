from pathlib import Path
import json
import tempfile
import unittest

from harnesscreator.analysis import GraphStore, StaticAnalyzer


FIXTURE = Path(__file__).parent / "fixtures" / "c_project"


class StaticAnalyzerTest(unittest.TestCase):
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

    def test_strict_mode_rejects_a_partial_fuzz_introspector_report(self) -> None:
        payload = {
            "functions": [{
                "functionName": "unrelated_target",
                "functionSourceFile": "missing.c",
                "functionLinenumber": 1,
                "Functions reached": [],
            }]
        }
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "partial.json"
            report.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "insufficiently covers"):
                StaticAnalyzer(
                    FIXTURE,
                    report,
                    require_fuzz_introspector=True,
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
        self.assertTrue(bundle.completeness["authoritative"])
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

        self.assertTrue(bundle.completeness["authoritative"])
        self.assertEqual(bundle.completeness["fuzz_introspector_source_coverage"], 1.0)


if __name__ == "__main__":
    unittest.main()
