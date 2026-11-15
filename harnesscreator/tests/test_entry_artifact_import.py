"""Action runs can reuse a prior Entry verdict set without Entry model calls."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harnesscreator.llm.base import ScriptedLLM
from harnesscreator.models import (
    AnalysisBundle, EntryRecord, Evidence, FunctionMetadata, ProjectSpec, Verdict,
)
from harnesscreator.orchestrator import HarnessCreator
from harnesscreator.storage import ArtifactStore


class EntryArtifactImportTests(unittest.IsolatedAsyncioTestCase):
    async def test_action_pipeline_starts_with_saved_entries_and_no_entry_calls(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            text = "int receive(void) { char b[8]; return read(0, b, sizeof(b)); }\n"
            (source / "input.c").write_text(text, encoding="utf-8")
            function = FunctionMetadata.create(
                name="receive", signature="int receive(void)", file="input.c",
                start_line=1, end_line=1, source=text,
            )
            entry = EntryRecord(
                entry_id="saved-entry", candidate_id="saved-candidate",
                status=Verdict.VERIFIED,
                entry_function_id=function.function_id, source_api="read",
                channel_kind="stdin", attacker_control="full",
                provenance_path=[], consumer_hints=[],
                evidence=[Evidence("source", function.function_id, "input.c", 1,
                                   "reads caller input")],
                unknowns=[], verifier_confidence=1.0, entry_line=1,
                first_acquisition_confirmed=True,
            )
            saved = ArtifactStore(root / "previous")
            saved.write_jsonl("analysis/product-functions.jsonl", [function])
            saved.write_jsonl("entries/candidates.jsonl", [{"candidate_id": "saved-candidate"}])
            saved.write_jsonl("entries/verified.jsonl", [entry])
            saved.write_jsonl("entries/unresolved.jsonl", [])
            llm = ScriptedLLM([])
            project = ProjectSpec(
                source_root=source, output_root=root / "runs",
                name="fixture", require_fuzz_introspector=False,
                svf_enabled=False, scenario_channel="disabled",
                entry_artifacts_from=saved.root,
            )
            received = {}

            async def capture(_self, **kwargs):
                received.update(kwargs)
                return "reached-action-pipeline"

            with patch.object(HarnessCreator, "_run_scenario_pipeline", capture):
                result = await HarnessCreator(
                    project, llm,
                    precomputed_analysis=AnalysisBundle(
                        functions={function.function_id: function}, edges=[],
                    ),
                ).run()

            self.assertEqual(result, "reached-action-pipeline")
            self.assertEqual(llm.calls, [])
            self.assertEqual([item.entry_id for item in received["verified"]],
                             [entry.entry_id])
            run = next((root / "runs").iterdir())
            provenance = json.loads((run / "workflow" / "entry-provenance.json").read_text())
            self.assertEqual(provenance["source_run"], str(saved.root))

    async def test_import_rejects_changed_product_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            text = "int receive(void) { return 0; }\n"
            (source / "input.c").write_text(text, encoding="utf-8")
            function = FunctionMetadata.create(
                name="receive", signature="int receive(void)", file="input.c",
                start_line=1, end_line=1, source=text,
            )
            saved = ArtifactStore(root / "previous")
            saved.write_jsonl("analysis/product-functions.jsonl", [{
                "function_id": function.function_id, "source": "different source",
            }])
            project = ProjectSpec(
                source_root=source, output_root=root / "runs",
                name="fixture", require_fuzz_introspector=False,
                svf_enabled=False, scenario_channel="disabled",
                entry_artifacts_from=saved.root,
            )
            llm = ScriptedLLM([])
            with self.assertRaisesRegex(ValueError, "indexed product source differs"):
                await HarnessCreator(
                    project, llm,
                    precomputed_analysis=AnalysisBundle(
                        functions={function.function_id: function}, edges=[],
                    ),
                ).run()
            self.assertEqual(llm.calls, [])
