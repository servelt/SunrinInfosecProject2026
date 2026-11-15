"""Entry verification overlaps inventory only after candidates are final."""

import asyncio
import unittest
from dataclasses import replace

from harnesscreator.agents.entry import EntryGeneratorAgent, _direct_external_call_matches
from harnesscreator.models import AnalysisBundle, EntryCandidate, EntryRecord, FunctionMetadata, Verdict
from harnesscreator.orchestrator import _generate_and_verify_entries


class EntryPipelineTest(unittest.IsolatedAsyncioTestCase):
    async def test_final_inventory_sort_does_not_invalidate_verified_candidates(self) -> None:
        first = EntryCandidate(
            candidate_id="a", function_id="fn-a", source_api="recv",
            line=2, channel_hint="tcp", rationale="first", confidence=0.9,
        )
        second = EntryCandidate(
            candidate_id="b", function_id="fn-b", source_api="read",
            line=3, channel_hint="file", rationale="second", confidence=0.9,
        )

        class Generator:
            async def run(self, _bundle, *, on_final_candidates):
                on_final_candidates([second])
                on_final_candidates([first])
                return [first, second]

        class Verifier:
            async def run(self, candidate):
                return EntryRecord(
                    entry_id=candidate.candidate_id,
                    candidate_id=candidate.candidate_id,
                    status=Verdict.UNRESOLVED,
                    entry_function_id=candidate.function_id,
                    source_api=candidate.source_api,
                    channel_kind=candidate.channel_hint,
                    attacker_control="unknown", provenance_path=[],
                    consumer_hints=[], evidence=[], unknowns=[],
                    verifier_confidence=0.0,
                )

        candidates, records = await _generate_and_verify_entries(
            Generator(), Verifier(), AnalysisBundle(functions={}, edges=[]),
            max_concurrency=2,
        )
        self.assertEqual(candidates, [first, second])
        self.assertEqual([record.candidate_id for record in records], ["a", "b"])

    async def test_external_call_locator_ignores_comments_and_strings(self) -> None:
        source = (
            '/* recvfrom(sock, buf, len, 0, addr, size); */\n'
            'const char *message = "recvfrom(sock, buf)";\n'
            'int n = recvfrom(sock, buf, len, 0, addr, size);\n'
            '// recvfrom(sock, buf, len, 0, addr, size);\n'
        )
        matches = _direct_external_call_matches(source, 'recvfrom')
        self.assertEqual(len(matches), 1)
        self.assertEqual(source.count('\n', 0, matches[0].start()) + 1, 3)

    async def test_candidate_cannot_change_after_finalization(self) -> None:
        first = EntryCandidate(
            candidate_id="same-site", function_id="fn-recv", source_api="recv",
            line=17, channel_hint="network", rationale="batch result",
            confidence=0.55,
        )

        class Generator:
            async def run(self, _bundle, *, on_final_candidates):
                on_final_candidates([first])
                return [replace(first, channel_hint="TLS socket")]

        class Verifier:
            async def run(self, candidate):
                await asyncio.sleep(0)
                return EntryRecord(
                    entry_id=candidate.candidate_id,
                    candidate_id=candidate.candidate_id,
                    status=Verdict.UNRESOLVED,
                    entry_function_id=candidate.function_id,
                    source_api=candidate.source_api,
                    channel_kind=candidate.channel_hint,
                    attacker_control="unknown", provenance_path=[],
                    consumer_hints=[], evidence=[], unknowns=[],
                    verifier_confidence=0.0,
                )

        with self.assertRaisesRegex(ValueError, "changed after finalization"):
            await _generate_and_verify_entries(
                Generator(), Verifier(), AnalysisBundle(functions={}, edges=[]),
                max_concurrency=1,
            )

    async def test_final_candidate_is_verified_during_later_inventory(self) -> None:
        verification_started = asyncio.Event()
        first = EntryCandidate(
            candidate_id="site-one", function_id="fn-one", source_api="recv",
            line=2, channel_hint="plaintext TCP socket", rationale="final inventory",
            confidence=0.99,
        )
        second = EntryCandidate(
            candidate_id="site-two", function_id="fn-two", source_api="read",
            line=3, channel_hint="file", rationale="later inventory",
            confidence=0.8,
        )

        class Generator:
            async def run(self, _bundle, *, on_final_candidates):
                on_final_candidates([first])
                await asyncio.wait_for(verification_started.wait(), timeout=1)
                on_final_candidates([second])
                return [first, second]

        class Verifier:
            def __init__(self):
                self.calls = []

            async def run(self, candidate):
                self.calls.append(candidate)
                if candidate is first:
                    verification_started.set()
                return EntryRecord(
                    entry_id=candidate.candidate_id,
                    candidate_id=candidate.candidate_id,
                    status=Verdict.UNRESOLVED,
                    entry_function_id=candidate.function_id,
                    source_api=candidate.source_api,
                    channel_kind=candidate.channel_hint,
                    attacker_control="unknown", provenance_path=[],
                    consumer_hints=[], evidence=[], unknowns=[],
                    verifier_confidence=0.0, rationale=candidate.rationale,
                )

        verifier = Verifier()
        candidates, records = await _generate_and_verify_entries(
            Generator(), verifier, AnalysisBundle(functions={}, edges=[]),
            max_concurrency=2,
        )
        self.assertEqual(candidates, [first, second])
        self.assertEqual([record.candidate_id for record in records], [
            first.candidate_id, second.candidate_id,
        ])
        self.assertEqual(verifier.calls, [first, second])

    async def test_actual_generator_emits_revised_site_once_after_batch(self) -> None:
        first_function = FunctionMetadata.create(
            name="first", qualified_name="first", signature="void first(void)",
            file="first.c", start_line=1, end_line=1,
            source="void first(void) { recv(0, buf, 4, 0); }",
        )
        second_function = FunctionMetadata.create(
            name="second", qualified_name="second", signature="void second(void)",
            file="second.c", start_line=1, end_line=1,
            source="void second(void) { read(0, buf, 4); }",
        )
        first_function.external_calls = ["recv"]
        second_function.external_calls = ["read"]
        bundle = AnalysisBundle(functions={
            first_function.function_id: first_function,
            second_function.function_id: second_function,
        }, edges=[])
        verified_first = asyncio.Event()

        class Provider:
            max_concurrency = 1

            async def complete_json(self, **kwargs):
                function = kwargs["payload"]["functions"][0]
                if function["name"] == "second":
                    await asyncio.wait_for(verified_first.wait(), timeout=1)
                return {
                    "inspected_function_ids": [function["function_id"]],
                    "candidates": [{
                        "function_id": function["function_id"],
                        "source_api": "recv" if function["name"] == "first" else "read",
                        "line": 1,
                        "site_kind": "DIRECT_ACQUISITION",
                        "first_acquisition": True,
                        "boundary_subject": "remote TCP peer" if function["name"] == "first" else "file owner",
                        "channel_hint": "plaintext TCP socket" if function["name"] == "first" else "file",
                        "rationale": "final source analysis",
                        "confidence": 0.99,
                    }],
                }

        class Verifier:
            def __init__(self):
                self.calls = []

            async def run(self, candidate):
                self.calls.append(candidate)
                if candidate.function_id == first_function.function_id:
                    verified_first.set()
                return EntryRecord(
                    entry_id=candidate.candidate_id,
                    candidate_id=candidate.candidate_id,
                    status=Verdict.UNRESOLVED,
                    entry_function_id=candidate.function_id,
                    source_api=candidate.source_api,
                    channel_kind=candidate.channel_hint,
                    attacker_control="unknown", provenance_path=[],
                    consumer_hints=[], evidence=[], unknowns=[],
                    verifier_confidence=0.0, rationale=candidate.rationale,
                )

        verifier = Verifier()
        candidates, records = await _generate_and_verify_entries(
            EntryGeneratorAgent(Provider(), chunk_size=1), verifier, bundle,
            max_concurrency=1,
        )
        self.assertEqual(len(candidates), 2)
        self.assertEqual(len(records), 2)
        self.assertEqual(len(verifier.calls), 2)
        self.assertTrue(all(item.rationale == "final source analysis" for item in verifier.calls))
