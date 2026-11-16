"""Completed semantic Actions can restart at grouping and input synthesis."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harnesscreator.agents.action_requests import ActionRequestAgent
from harnesscreator.llm.base import ScriptedLLM
from harnesscreator.models import (
    ActionExample, AnalysisBundle, EntryRecord, Evidence, ExternalActionSchema,
    FunctionMetadata, InputFieldConstraint, ProjectSpec, ProofStatus,
    ResponseBindingExtractor, Verdict,
)
from harnesscreator.orchestrator import HarnessCreator, _load_saved_semantic_actions
from harnesscreator.storage import ArtifactStore


class ReachedRequests(Exception):
    pass


class ActionArtifactImportTests(unittest.IsolatedAsyncioTestCase):
    async def test_reuses_actions_without_entry_or_action_llm_calls(self):
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
            evidence = Evidence("source", function.function_id, "input.c", 1, text)
            entry = EntryRecord(
                entry_id="saved-entry", candidate_id="saved-candidate",
                status=Verdict.VERIFIED, entry_function_id=function.function_id,
                source_api="read", channel_kind="stdin", attacker_control="full",
                provenance_path=[], consumer_hints=[], evidence=[evidence], unknowns=[],
                verifier_confidence=1.0, entry_line=1,
                first_acquisition_confirmed=True,
            )
            action = ExternalActionSchema(
                action_id="saved-action", entry_id=entry.entry_id, name="receive bytes",
                description="read external bytes", dispatcher_function_id=function.function_id,
                handler_function_id=function.function_id, discriminator="",
                channel_kind="stdin",
                fields=[InputFieldConstraint("data", 0, 1, evidence=[evidence])],
                examples=[ActionExample("41", evidence=[evidence])],
                success_markers_hex=[], failure_markers_hex=[], evidence=[evidence],
                inspected_function_ids=[function.function_id],
                status=ProofStatus.POSSIBLE, entry_function_id=function.function_id,
                response_bindings=[ResponseBindingExtractor("reply", 0, 1,
                                                            evidence=[evidence])],
                entry_probe_evidence=[evidence], selection_evidence=[evidence],
            )
            saved = ArtifactStore(root / "previous")
            saved.write_jsonl("analysis/product-functions.jsonl", [function])
            saved.write_jsonl("entries/candidates.jsonl", [{"candidate_id": "saved-candidate"}])
            saved.write_jsonl("entries/verified.jsonl", [entry])
            saved.write_jsonl("entries/unresolved.jsonl", [])
            saved.write_jsonl("entries/action-screening.jsonl", [{
                "entry_id": entry.entry_id, "disposition": "SELECTED",
            }])
            saved.write_jsonl("actions/discovered-semantic.jsonl", [action])
            saved.write_jsonl("actions/input-consumer-coverage.jsonl", [])
            saved.write_jsonl("actions/selector-hints.jsonl", [])
            loaded = _load_saved_semantic_actions(
                saved.root / "actions/discovered-semantic.jsonl"
            )
            self.assertIsInstance(loaded[0].examples[0], ActionExample)
            self.assertIsInstance(loaded[0].fields[0].evidence[0], Evidence)
            self.assertIsInstance(loaded[0].response_bindings[0], ResponseBindingExtractor)
            llm = ScriptedLLM([{
                "decision": "KEEP", "reason": "external bytes reach a distinct effect",
                "source_evidence": [{
                    "kind": "source", "function_id": function.function_id,
                    "line": 1, "detail": "read reaches handler",
                }],
            }])
            project = ProjectSpec(
                source_root=source, output_root=root / "runs", name="fixture",
                require_fuzz_introspector=False, svf_enabled=False,
                scenario_channel="disabled", action_artifacts_from=saved.root,
            )
            received = []

            async def capture(_self, actions, **kwargs):
                received.extend(actions)
                raise ReachedRequests

            with patch.object(ActionRequestAgent, "run", capture):
                with self.assertRaises(ReachedRequests):
                    await HarnessCreator(
                        project, llm,
                        precomputed_analysis=AnalysisBundle(
                            functions={function.function_id: function}, edges=[],
                        ),
                    ).run()
            self.assertEqual(len(llm.calls), 1)
            self.assertTrue(llm.calls[0]["session_key"].startswith("action_selection:"))
            self.assertEqual([item.action_id for item in received], [action.action_id])
            run = next((root / "runs").iterdir())
            self.assertTrue((run / "workflow/action-provenance.json").is_file())

    async def test_rejects_incomplete_action_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "completed artifact"):
                _load_saved_semantic_actions(
                    Path(temporary) / "actions/discovered-semantic.jsonl"
                )
