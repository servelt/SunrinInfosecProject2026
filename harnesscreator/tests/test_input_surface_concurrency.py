from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from harnesscreator.agents.input_surfaces import InputSurfaceAgent
from harnesscreator.analysis.graph import GraphStore
from harnesscreator.models import (
    AnalysisBundle, EntryRecord, Evidence, FunctionMetadata, ProjectSpec,
    Verdict,
)


class _TwoSessionModel:
    max_concurrency = 2

    def __init__(self, later_entry_finished: asyncio.Event):
        self.later_entry_finished = later_entry_finished
        self.sessions: list[str] = []

    async def complete_json(self, *, payload, session_key, **_kwargs):
        self.sessions.append(session_key)
        if session_key.endswith("entry-first"):
            await asyncio.wait_for(self.later_entry_finished.wait(), 1)
            value = "41"
        else:
            value = "42"
        function = payload["current_function"]
        return {
            "samples": [{
                "data_hex": value,
                "rationale": "source comparison supplies a trial byte",
                "evidence": [{
                    "source_item_id": function["function_id"],
                    "line": function["start_line"] + 2,
                    "detail": "input byte is compared to this character",
                }],
                "connection_prelude_marker_hex": "",
                "connection_prelude_evidence": [],
            }],
            "requested_function_ids": [],
            "context_complete": True,
            "rationale": "one trial-byte hypothesis",
        }

    async def close_session(self, _session_key):
        return None


class InputSurfaceConcurrencyTest(unittest.IsolatedAsyncioTestCase):
    async def test_later_entry_can_finish_while_first_entry_waits(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            functions = [
                FunctionMetadata.create(
                    name=f"receive_{letter}",
                    signature=f"int receive_{letter}(void)",
                    file=f"{letter}.c", start_line=1, end_line=4,
                    source=(
                        f"int receive_{letter}(void) {{\n"
                        "  char c; read(0, &c, 1);\n"
                        f"  return c == '{letter}';\n"
                        "}"
                    ),
                )
                for letter in ("A", "B")
            ]
            entries = [
                EntryRecord(
                    entry_id=f"entry-{name}", candidate_id=f"candidate-{name}",
                    status=Verdict.VERIFIED,
                    entry_function_id=function.function_id,
                    source_api="read", channel_kind="stdin",
                    attacker_control="local", provenance_path=[],
                    consumer_hints=[], evidence=[Evidence(
                        "source", function.function_id, function.file, 2,
                        "read from stdin",
                    )], unknowns=[], verifier_confidence=1.0,
                    entry_line=2, first_acquisition_confirmed=True,
                )
                for name, function in zip(("first", "second"), functions)
            ]
            later_finished = asyncio.Event()
            completion_order: list[str] = []

            async def completed(entry, _cases):
                completion_order.append(entry.entry_id)
                if entry.entry_id == "entry-second":
                    later_finished.set()

            model = _TwoSessionModel(later_finished)
            agent = InputSurfaceAgent(
                model,
                GraphStore(AnalysisBundle(
                    functions={item.function_id: item for item in functions},
                    edges=[],
                )),
                ProjectSpec(source_root=root, output_root=root / "out"),
                on_entry_cases=completed,
            )
            cases = await asyncio.wait_for(agent.run(entries), 2)
            self.assertEqual(completion_order, ["entry-second", "entry-first"])
            self.assertEqual([case.entry_id for case in cases],
                             ["entry-first", "entry-second"])
            self.assertEqual(len(set(model.sessions)), 2)


if __name__ == "__main__":
    unittest.main()
