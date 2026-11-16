from __future__ import annotations

import unittest

from harnesscreator.agents.scenario_harness import (
    action_harness_function_ids,
    build_harness_plan,
)
from harnesscreator.models import (
    ActionExample,
    Evidence,
    ExternalActionSchema,
    ScenarioStatus,
    ScenarioStep,
    ScenarioWitness,
)
from harnesscreator.orchestrator import _harness_action_function_ids


class HarnessPlanSourceRootsTest(unittest.TestCase):
    def test_branchless_action_keeps_handler_after_cited_helper(self) -> None:
        action = ExternalActionSchema(
            action_id="hello", entry_id="entry", name="HELLO", description="reply",
            dispatcher_function_id="handler", handler_function_id="handler",
            discriminator="", channel_kind="udp", fields=[],
            examples=[ActionExample("48454c4c4f0a")],
            success_markers_hex=["4f4b"], failure_markers_hex=[],
            evidence=[Evidence("source", "record", "daemon.c", 30, "reply trace")],
            inspected_function_ids=["entry", "handler", "record"],
            entry_function_id="entry",
        )
        path = _harness_action_function_ids([action], {"entry": "entry"})["hello"]
        witness = ScenarioWitness(
            "witness", "scenario", "hello",
            [ScenarioStep(0, "hello", "entry", "48454c4c4f0a", {}, ["4f4b"])],
            [], ["daemon"], "udp", None, ScenarioStatus.PROVEN_RUNTIME,
            "request-correlated original execution",
        )

        self.assertEqual(path, ("entry", "record", "handler"))
        plan = build_harness_plan(
            witness, action_function_ids={"hello": path},
            action_schemas={"hello": action},
        )
        self.assertEqual(plan.required_function_ids[-1], "handler")
        with self.assertRaisesRegex(ValueError, "target anchor differs"):
            build_harness_plan(
                witness,
                action_function_ids={"hello": ("entry", "handler", "record")},
                action_schemas={"hello": action},
            )

    def test_entry_handler_same_function_retains_both_anchor_positions(self) -> None:
        action = ExternalActionSchema(
            action_id="one", entry_id="entry", name="ONE", description="reply",
            dispatcher_function_id="entry", handler_function_id="entry",
            discriminator="", channel_kind="tcp", fields=[],
            examples=[ActionExample("31")], success_markers_hex=[],
            failure_markers_hex=[], evidence=[], inspected_function_ids=[],
            entry_function_id="entry",
        )
        self.assertEqual(action_harness_function_ids(action), ("entry", "entry"))

    def test_exploratory_functions_do_not_become_required_harness_path(self) -> None:
        def at(function_id: str) -> Evidence:
            return Evidence("source", function_id, "daemon.c", 10, "selected action")

        action = ExternalActionSchema(
            action_id="noop", entry_id="entry", name="NOOP", description="reply",
            dispatcher_function_id="dispatch", handler_function_id="handle",
            discriminator="NOOP", channel_kind="tcp", fields=[],
            examples=[ActionExample("4e4f4f500d0a")],
            success_markers_hex=["323030"], failure_markers_hex=[],
            evidence=[at("read_command"), at("dispatch"), at("handle")],
            success_evidence=[at("write_reply")],
            inspected_function_ids=[
                "entry", "read_command", "dispatch", "handle", "write_reply",
                "main", "parse_config", "logger", "allocator",
            ],
            entry_function_id="entry",
        )
        path = action_harness_function_ids(action)
        step = ScenarioStep(0, "noop", "entry", "4e4f4f500d0a", {}, ["323030"])
        witness = ScenarioWitness(
            "witness", "scenario", "noop", [step], [], ["daemon"], "tcp",
            None, ScenarioStatus.REPLAYED_RUNTIME, "original process reply observed",
        )
        plan = build_harness_plan(
            witness,
            action_function_ids={"noop": path},
            action_schemas={"noop": action},
            allow_observed=True,
        )

        self.assertEqual(path, (
            "entry", "dispatch", "read_command", "write_reply", "handle",
        ))
        self.assertEqual(plan.required_function_ids, [
            "dispatch", "read_command", "write_reply", "handle",
        ])
        self.assertTrue({"main", "parse_config", "logger", "allocator"}.isdisjoint(
            plan.required_function_ids
        ))
        self.assertEqual(action.inspected_function_ids[-4:], [
            "main", "parse_config", "logger", "allocator",
        ])


if __name__ == "__main__":
    unittest.main()
