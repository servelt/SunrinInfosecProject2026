from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harnesscreator.agents.input_surfaces import InputSurfaceAgent
from harnesscreator.agents.entry_action_screen import EntryActionScreenAgent, EntryActionScreenResult
from harnesscreator.agents.scenario import InputActionAgent
from harnesscreator.analysis.graph import GraphStore
from harnesscreator.analysis.usage_evidence import UsageEvidenceBundle
from harnesscreator.llm.base import ScriptedLLM
from harnesscreator.models import (
    AnalysisBundle, EntryRecord, Evidence, FunctionMetadata, ProjectSpec,
    Verdict,
)
from harnesscreator.orchestrator import HarnessCreator
from harnesscreator.storage import ArtifactStore


class _SecondSurfaceReached(Exception):
    pass


class ActionSurfaceOverlapTest(unittest.IsolatedAsyncioTestCase):
    async def test_raw_surface_fallback_starts_after_action_discovery(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            functions = [
                FunctionMetadata.create(
                    name=f"receive_{index}",
                    signature=f"int receive_{index}(void)",
                    file=f"server_{index}.c", start_line=1, end_line=1,
                    source=(
                        f"int receive_{index}(void) {{ char b; "
                        "return read(0, &b, 1); }"
                    ),
                )
                for index in range(2)
            ]
            bundle = AnalysisBundle(
                functions={item.function_id: item for item in functions},
                edges=[],
            )
            entries = [
                EntryRecord(
                    entry_id=f"entry-{index}",
                    candidate_id=f"candidate-{index}",
                    status=Verdict.VERIFIED,
                    entry_function_id=function.function_id,
                    source_api="read", channel_kind="stdin",
                    attacker_control="local",
                    provenance_path=[], consumer_hints=[],
                    evidence=[Evidence(
                        "source", function.function_id, function.file, 1,
                        "first read from stdin",
                    )],
                    unknowns=[], verifier_confidence=1.0,
                    entry_line=1, first_acquisition_confirmed=True,
                )
                for index, function in enumerate(functions)
            ]
            project = ProjectSpec(
                source_root=root, output_root=root / "runs",
                scenario_command=["/bin/true"],
                scenario_channel="stdin", scenario_attribution="gdb",
            )
            action_finished = asyncio.Event()

            async def discover_actions(_agent, action_entries):
                self.assertEqual([item.entry_id for item in action_entries],
                                 ["entry-0", "entry-1"])
                action_finished.set()
                return []

            async def two_surfaces(agent, surface_entries):
                self.assertEqual([item.entry_id for item in surface_entries],
                                 ["entry-0", "entry-1"])
                self.assertTrue(action_finished.is_set())
                raise _SecondSurfaceReached

            async def selected_entries(_agent, screen_entries):
                return [EntryActionScreenResult(item.entry_id, "SELECTED")
                        for item in screen_entries]

            creator = HarnessCreator(project, ScriptedLLM([]))
            with patch.object(EntryActionScreenAgent, "run", new=selected_entries), \
                 patch.object(InputSurfaceAgent, "run", new=two_surfaces), \
                 patch.object(InputActionAgent, "run", new=discover_actions):
                with self.assertRaises(_SecondSurfaceReached):
                    await asyncio.wait_for(
                        creator._run_scenario_pipeline(
                            run_id="overlap-test",
                            store=ArtifactStore(root / "run"),
                            analysis=bundle, graph=GraphStore(bundle),
                            traced_llm=ScriptedLLM([]),
                            trace=lambda *_args: None,
                            usage_evidence=UsageEvidenceBundle(),
                            usage_artifacts=[], candidates=[],
                            verified=entries, unresolved=[],
                        ),
                        timeout=2,
                    )
            self.assertTrue(action_finished.is_set())
