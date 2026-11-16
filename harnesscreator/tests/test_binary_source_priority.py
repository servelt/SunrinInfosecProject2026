"""DWARF source evidence changes inspection order without removing sources."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
import json
from pathlib import Path

from harnesscreator.agents.entry import EntryGeneratorAgent
from harnesscreator.analysis.binary_sources import linked_source_priority
from harnesscreator.analysis.indexer import StaticAnalyzer
from harnesscreator.llm.base import ScriptedLLM
from harnesscreator.models import AnalysisBundle, FunctionMetadata
from harnesscreator.orchestrator import _preferred_entry_source_files


class BinarySourcePriorityTest(unittest.TestCase):
    def test_compile_record_prioritizes_source_without_excluding_others(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'a_demo.c').write_text(
                'int demo(void) { return 1; }\n', encoding='utf-8',
            )
            (root / 'z_daemon.c').write_text(
                'int daemon_entry(void) { return 2; }\n', encoding='utf-8',
            )
            database = root / 'compile_commands.json'
            database.write_text(json.dumps([{
                'directory': str(root), 'file': 'z_daemon.c',
                'arguments': ['cc', '-c', 'z_daemon.c'],
            }]), encoding='utf-8')
            bundle = StaticAnalyzer(root, compile_database=database).index()
            self.assertEqual(
                bundle.completeness['analysis_compile_database_files'],
                ['z_daemon.c'],
            )
            preferred, provider = _preferred_entry_source_files(
                {'matched_files': []}, bundle.completeness,
            )
            self.assertEqual(provider, 'observed_compile_command')
            generator = EntryGeneratorAgent(
                ScriptedLLM([]), chunk_size=1,
                preferred_source_files=preferred,
            )
            self.assertEqual(
                [batch[0][0].file for batch in generator.batches(bundle)],
                ['z_daemon.c', 'a_demo.c'],
            )

    def test_binary_source_match_takes_ordering_precedence(self):
        preferred, provider = _preferred_entry_source_files(
            {'matched_files': ['server.c']},
            {'analysis_compile_database_files': ['client.c']},
        )
        self.assertEqual(preferred, {'server.c'})
        self.assertEqual(provider, 'linked_binary_source_match')

    def test_fuzz_introspector_merge_preserves_ast_failure_diagnostics(self):
        with tempfile.TemporaryDirectory() as temporary:
            analyzer = StaticAnalyzer(Path(temporary))
            fallback = AnalysisBundle(
                functions={}, edges=[], completeness={
                    'analysis_compile_database_files': ['server.c'],
                    'analysis_compile_database_file_count': 1,
                    'clang_c_ast_failed_files': 1,
                    'clang_c_ast_failure_diagnostics': [
                        {'file': 'server.c', 'reason': 'missing generated header'}
                    ],
                },
            )
            merged = analyzer._merge(
                AnalysisBundle(functions={}, edges=[]), fallback,
            )
            self.assertEqual(
                merged.completeness['clang_c_ast_failure_diagnostics'],
                fallback.completeness['clang_c_ast_failure_diagnostics'],
            )
            self.assertEqual(
                merged.completeness['analysis_compile_database_files'],
                ['server.c'],
            )

    @unittest.skipUnless(shutil.which("cc"), "C compiler unavailable")
    def test_byte_identical_compiled_file_is_prioritized_but_others_remain(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            analysis = root / "analysis"
            build = root / "build"
            analysis.mkdir()
            build.mkdir()
            source = "int main(void) { return 0; }\n"
            (analysis / "z_daemon.c").write_text(source, encoding="utf-8")
            (build / "z_daemon.c").write_text(source, encoding="utf-8")
            (analysis / "a_demo.c").write_text(
                "int demo(void) { return 1; }\n", encoding="utf-8",
            )
            binary = build / "daemon"
            subprocess.run(
                ["cc", "-g", "-O0", str(build / "z_daemon.c"), "-o", str(binary)],
                check=True, capture_output=True,
            )
            report = linked_source_priority(
                binary, analysis, ["a_demo.c", "z_daemon.c"],
            )
            self.assertEqual(report["status"], "matched")
            self.assertEqual(report["matched_files"], ["z_daemon.c"])

            functions = [
                FunctionMetadata.create(
                    name="demo", signature="int demo(void)", file="a_demo.c",
                    start_line=1, end_line=1, source="int demo(void) { return 1; }",
                ),
                FunctionMetadata.create(
                    name="main", signature="int main(void)", file="z_daemon.c",
                    start_line=1, end_line=1, source="int main(void) { return 0; }",
                ),
            ]
            bundle = AnalysisBundle(
                functions={item.function_id: item for item in functions}, edges=[],
            )
            generator = EntryGeneratorAgent(
                ScriptedLLM([]), chunk_size=1,
                preferred_source_files=set(report["matched_files"]),
            )
            self.assertEqual(
                [batch[0][0].file for batch in generator.batches(bundle)],
                ["z_daemon.c", "a_demo.c"],
            )

            (analysis / "z_daemon.c").write_text(
                "int main(void) { return 1; }\n", encoding="utf-8",
            )
            changed = linked_source_priority(
                binary, analysis, ["a_demo.c", "z_daemon.c"],
            )
            self.assertEqual(changed["matched_files"], [])
            self.assertEqual(changed["symbol_file_hints"], [])

    def test_missing_binary_is_not_negative_source_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = linked_source_priority(
                root / "absent", root, ["daemon.c"],
            )
            self.assertEqual(report["status"], "unavailable")
            self.assertEqual(report["matched_files"], [])

    def test_symbol_file_hint_precedes_compile_record_without_excluding_sources(self):
        preferred, provider = _preferred_entry_source_files(
            {"matched_files": [], "symbol_file_hints": ["server.c"]},
            {"analysis_compile_database_files": ["client.c"]},
        )
        self.assertEqual(preferred, {"server.c"})
        self.assertEqual(provider, "linked_binary_symbol_file_hint")

    @unittest.skipUnless(shutil.which("cc"), "C compiler unavailable")
    def test_undebugged_binary_file_symbols_prioritize_linked_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "z_server.c").write_text(
                "int common(void); int main(void) { return common(); }\n",
                encoding="utf-8",
            )
            (root / "common.c").write_text(
                "int common(void) { return 0; }\n", encoding="utf-8",
            )
            (root / "a_client.c").write_text(
                "int client(void) { return 1; }\n", encoding="utf-8",
            )
            subprocess.run(
                ["cc", "-O2", "z_server.c", "common.c", "-o", "daemon"],
                cwd=root, check=True, capture_output=True,
            )
            report = linked_source_priority(
                root / "daemon", root,
                ["a_client.c", "z_server.c", "common.c"],
            )
            self.assertEqual(report["status"], "symbol_file_hints")
            self.assertEqual(report["matched_files"], [])
            self.assertEqual(
                report["symbol_file_hints"], ["common.c", "z_server.c"],
            )
            preferred, provider = _preferred_entry_source_files(report, {})
            self.assertEqual(provider, "linked_binary_symbol_file_hint")
            functions = [
                FunctionMetadata.create(
                    name=name, signature=f"int {name}(void)", file=file,
                    start_line=1, end_line=1,
                    source=f"int {name}(void) {{ return 0; }}",
                )
                for name, file in (
                    ("client", "a_client.c"), ("common", "common.c"),
                    ("server", "z_server.c"),
                )
            ]
            bundle = AnalysisBundle(
                functions={item.function_id: item for item in functions}, edges=[],
            )
            ordered = [
                batch[0][0].file for batch in EntryGeneratorAgent(
                    ScriptedLLM([]), chunk_size=1,
                    preferred_source_files=preferred,
                ).batches(bundle)
            ]
            self.assertEqual(set(ordered[:2]), preferred)
            self.assertEqual(ordered[2], "a_client.c")

    @unittest.skipUnless(shutil.which("cc"), "C compiler unavailable")
    def test_ambiguous_symbol_basename_is_not_promoted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "a").mkdir()
            (root / "b").mkdir()
            (root / "a" / "common.c").write_text(
                "int main(void) { return 0; }\n", encoding="utf-8",
            )
            (root / "b" / "common.c").write_text(
                "int other(void) { return 1; }\n", encoding="utf-8",
            )
            subprocess.run(
                ["cc", "-O2", "a/common.c", "-o", "daemon"],
                cwd=root, check=True, capture_output=True,
            )
            report = linked_source_priority(
                root / "daemon", root, ["a/common.c", "b/common.c"],
            )
            self.assertEqual(report["symbol_file_hints"], [])
            self.assertGreater(report["ambiguous_symbol_files"], 0)
