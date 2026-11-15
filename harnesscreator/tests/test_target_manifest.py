import tempfile
import unittest
import json
import shutil
import subprocess
from pathlib import Path

from harnesscreator.analysis.target_manifest import linked_make_sources
from harnesscreator.analysis.binary_sources import selected_binary_is_program
from harnesscreator.agents.entry import EntryGeneratorAgent, EntryVerifierAgent
from harnesscreator.analysis.graph import GraphStore
from harnesscreator.models import (
    AnalysisBundle, EntryCandidate, EntrySiteKind, FunctionMetadata, Verdict,
)


class TargetManifestTests(unittest.TestCase):
    def test_non_elf_file_is_not_classified_as_program(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "daemon"
            binary.write_bytes(b"not an ELF executable")
            self.assertFalse(selected_binary_is_program(binary))

    def _fixture(self, root: Path) -> tuple[Path, Path]:
        source = root / "src"
        build = source / "Release"
        build.mkdir(parents=True)
        (source / "server.c").write_text("int server(void) { return 1; }\n")
        (source / "Deprecated").mkdir()
        (source / "Deprecated" / "server.c").write_text(
            "int old_server(void) { return 1; }\n"
        )
        (build / "daemon").write_bytes(b"binary fixture")
        (build / "makefile").write_text(
            "-include sources.mk\n"
            "daemon: $(OBJS) $(USER_OBJS)\n"
            "\tcc -o \"daemon\" $(OBJS) $(USER_OBJS) $(LIBS)\n"
        )
        (build / "sources.mk").write_text(
            "C_SRCS := ../server.c\nOBJS := ./server.o\n"
            "USER_OBJS :=\nLIBS := -lpthread\n"
        )
        return source, build / "daemon"

    def test_exact_target_excludes_unlinked_obsolete_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, binary = self._fixture(Path(temporary))
            report = linked_make_sources(binary, source)
            self.assertEqual(report["status"], "configured_target_closure")
            self.assertEqual(report["source_files"], ["server.c"])
            live = FunctionMetadata.create(
                name="server", signature="int server(void)",
                file="server.c", start_line=1, end_line=1,
                source="int server(void) { return 1; }",
            )
            obsolete = FunctionMetadata.create(
                name="old_server", signature="int old_server(void)",
                file="Deprecated/server.c", start_line=1, end_line=1,
                source="int old_server(void) { return 1; }",
            )
            agent = EntryGeneratorAgent(
                None, configured_target_files=set(report["source_files"]),
            )
            self.assertEqual(
                agent.product_function_ids(AnalysisBundle(
                    functions={live.function_id: live,
                               obsolete.function_id: obsolete}, edges=[],
                )), {live.function_id},
            )

    def test_unknown_link_input_never_claims_complete_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, binary = self._fixture(Path(temporary))
            makefile = binary.parent / "makefile"
            makefile.write_text(
                makefile.read_text().replace(
                    "$(USER_OBJS) $(LIBS)",
                    "$(USER_OBJS) extra.o $(LIBS)",
                )
            )
            report = linked_make_sources(binary, source)
            self.assertEqual(report["status"], "unresolved")
            self.assertEqual(report["source_files"], [])

    def test_conditional_source_assignment_never_claims_complete_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, binary = self._fixture(Path(temporary))
            fragment = binary.parent / "sources.mk"
            fragment.write_text(
                fragment.read_text()
                + "ifeq ($(MODE),old)\n"
                + "C_SRCS += ../Deprecated/server.c\n"
                + "OBJS += ./old_server.o\n"
                + "endif\n"
            )
            report = linked_make_sources(binary, source)
            self.assertEqual(report["status"], "unresolved")
            self.assertIn("conditional", report["reason"])

    @unittest.skipUnless(shutil.which("ar"), "ar is required for archive membership")
    def test_configured_automake_target_excludes_other_program_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            for name in ("server.c", "helper.c", "client.c"):
                (source / name).write_text(f"int {name[:-2]}(void) {{ return 1; }}\n")
            (source / "daemon").write_bytes(b"selected executable")
            (source / "helper.o").write_bytes(b"object fixture")
            subprocess.run(
                ["ar", "rcs", "libhelpers.a", "helper.o"],
                cwd=source, check=True, capture_output=True,
            )
            (source / "Makefile").write_text(
                "am_daemon_OBJECTS = daemon-server.o\n"
                "daemon_OBJECTS = $(am_daemon_OBJECTS)\n"
                "daemon_SOURCES = server.c server.h\n"
                "daemon_LDADD = libhelpers.a\n"
                "LIBS = -lm\n"
                "daemon$(EXEEXT): $(daemon_OBJECTS) $(daemon_DEPENDENCIES)\n"
                "\t$(LINK) $(daemon_OBJECTS) $(daemon_LDADD) $(LIBS)\n"
                "include ./$(DEPDIR)/daemon-server.Po # am--include-marker\n"
            )
            database = source / "compile_commands.json"
            database.write_text(json.dumps([{
                "directory": str(source), "file": str(source / "server.c"),
                "output": "daemon-server.o", "arguments": [
                    "cc", "-c", "server.c", "-o", "daemon-server.o",
                ],
            }]))
            report = linked_make_sources(source / "daemon", source, database)
            self.assertEqual(report["status"], "configured_target_closure")
            self.assertEqual(report["source_files"], ["helper.c", "server.c"])
            self.assertNotIn("client.c", report["source_files"])
            (source / "server.c").write_text('#include "client.c"\n')
            unsafe = linked_make_sources(source / "daemon", source, database)
            self.assertEqual(unsafe["status"], "unresolved")
            (source / "server.c").write_text("int server(void) { return 1; }\n")
            makefile = source / "Makefile"
            makefile.write_text(
                makefile.read_text() +
                "daemon_LINK = cc hidden.o -o $@\n"
            )
            hidden_input = linked_make_sources(source / "daemon", source, database)
            self.assertEqual(hidden_input["status"], "unresolved")


class ExecutableEntryTests(unittest.IsolatedAsyncioTestCase):
    async def test_exported_api_argument_is_unresolved_for_executable(self):
        function = FunctionMetadata.create(
            name="library_api", signature="int library_api(const char *p)",
            file="lib.h", start_line=1, end_line=1,
            source="int library_api(const char *p) { return p[0]; }",
        )
        candidate = EntryCandidate(
            candidate_id="exported", function_id=function.function_id,
            source_api="library_api", line=1, channel_hint="api",
            rationale="public declaration", confidence=0.99,
            site_kind=EntrySiteKind.EXPORTED_API,
        )

        class Provider:
            async def complete_json(self, **_kwargs):
                return {
                    "status": "VERIFIED", "channel_kind": "api",
                    "attacker_control": "full", "provenance_path": [{
                        "function_id": function.function_id,
                        "relation": "public argument",
                    }],
                    "consumer_hints": [], "evidence": [{
                        "kind": "source", "function_id": function.function_id,
                        "file": function.file, "line": 1,
                        "detail": "caller supplies p",
                    }],
                    "unknowns": [], "confidence": 0.99,
                    "rationale": "public API", "first_acquisition_confirmed": True,
                    "context_complete": True, "requested_function_ids": [],
                }

        record = await EntryVerifierAgent(
            Provider(), GraphStore(AnalysisBundle(
                functions={function.function_id: function}, edges=[],
            )), selected_program=True,
        ).run(candidate)
        self.assertEqual(record.status, Verdict.UNRESOLVED)
        self.assertTrue(any("external caller" in item for item in record.unknowns))


if __name__ == "__main__":
    unittest.main()
