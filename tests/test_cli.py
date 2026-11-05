import tempfile
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from harnesscreator.cli import (
    DEFAULT_ROLE_MODELS,
    DEFAULT_OLLAMA_ROLE_EFFORTS,
    _analysis_compile_database,
    _load_action_resume_continuations,
    _load_surface_resume_continuations,
    _resolve_ollama_models,
    _resolve_role_models,
    _run,
    build_parser,
)
from harnesscreator.llm import InvalidOutputSchemaError
from harnesscreator.models import ProjectSpec
from harnesscreator.orchestrator import HarnessCreator


class RoleModelRoutingTest(unittest.TestCase):
    def test_cli_resume_frontiers_are_accepted_by_orchestrator(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            action = [{"entry_id": "entry-a", "next_function_ids": ["fn-a"]}]
            surface = [{"entry_id": "entry-b", "next_function_ids": ["fn-b"]}]
            creator = HarnessCreator(
                ProjectSpec(source_root=root, output_root=root / "runs"),
                object(),
                action_resume_continuations=action,
                surface_resume_continuations=surface,
            )
            self.assertEqual(creator.action_resume_continuations, action)
            self.assertEqual(creator.surface_resume_continuations, surface)

    def test_run_directory_loads_input_surface_frontier(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            surface_dir = root / "input-surfaces"
            surface_dir.mkdir()
            (surface_dir / "continuations.json").write_text(
                json.dumps([{"entry_id": "entry-1",
                             "next_function_ids": ["fn-next"]}]),
                encoding="utf-8",
            )
            self.assertEqual(
                _load_surface_resume_continuations(root)[0]["entry_id"],
                "entry-1",
            )
            (surface_dir / "continuations.json").write_text(
                json.dumps(["invalid"]), encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "invalid Input Surface continuation"):
                _load_surface_resume_continuations(root)

    def test_run_directory_loads_action_frontier_but_jsonl_does_not(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            action_dir = root / "actions"
            action_dir.mkdir()
            (action_dir / "continuations.json").write_text(
                json.dumps({"entries": [{"entry_id": "entry-1",
                                        "next_function_ids": ["fn-next"]}]}),
                encoding="utf-8",
            )
            trajectory = root / "llm.jsonl"
            trajectory.write_text("", encoding="utf-8")
            self.assertEqual(
                _load_action_resume_continuations(root)[0]["entry_id"],
                "entry-1",
            )
            self.assertEqual(_load_action_resume_continuations(trajectory), [])
            (action_dir / "continuations.json").write_text(
                json.dumps({"entries": ["invalid"]}), encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "invalid Action continuation"):
                _load_action_resume_continuations(root)
            (action_dir / "continuations.json").unlink()
            (action_dir / "progress.json").write_text(
                json.dumps({"continuations": [{"entry_id": "entry-recovered"}]}),
                encoding="utf-8",
            )
            self.assertEqual(
                _load_action_resume_continuations(root)[0]["entry_id"],
                "entry-recovered",
            )

    def test_analysis_build_command_requires_an_exclusive_explicit_choice(self) -> None:
        for command in ("run", "analyze"):
            with self.subTest(command=command):
                args = build_parser().parse_args([
                    command, "/tmp/project", "--analysis-build-command", "make -B",
                ])
                self.assertEqual(args.analysis_build_command, "make -B")
                with patch(
                    "harnesscreator.runtime.compile_database_capture.capture_compile_database",
                    return_value=Path("/tmp/out/compile_commands.json"),
                ) as capture:
                    selected = _analysis_compile_database(
                        args, Path("/tmp/project"), Path("/tmp/out"),
                    )
                self.assertEqual(selected, Path("/tmp/out/compile_commands.json"))
                self.assertEqual(capture.call_args.args[2], ["make", "-B"])
                args.analysis_compile_database = Path("/tmp/existing.json")
                with self.assertRaisesRegex(ValueError, "choose either"):
                    _analysis_compile_database(
                        args, Path("/tmp/project"), Path("/tmp/out"),
                    )

    def test_analysis_compile_database_option_is_available_on_run_and_analyze(self) -> None:
        for command in ("run", "analyze"):
            with self.subTest(command=command):
                args = build_parser().parse_args([
                    command, "/tmp/project", "--analysis-compile-database",
                    "/tmp/project-build/compile_commands.json",
                ])
                self.assertEqual(
                    args.analysis_compile_database,
                    Path("/tmp/project-build/compile_commands.json"),
                )

    def test_uses_fixed_per_agent_defaults(self) -> None:
        args = build_parser().parse_args(["run", "/tmp/project"])

        active = _resolve_role_models(args)
        self.assertEqual(args.workflow, "action")
        self.assertEqual(set(active), {
            "entry_generator", "entry_verifier", "input_surface",
            "input_action", "state_dependency", "scenario_refiner",
            "harness_generator", "harness_verifier",
        })
        self.assertEqual(DEFAULT_ROLE_MODELS["entry_generator"], "gpt-5.6-sol")
        for role in (
            "entry_verifier",
            "input_action",
            "state_dependency",
            "harness_generator",
            "harness_verifier",
        ):
            self.assertEqual(DEFAULT_ROLE_MODELS[role], "gpt-5.6-sol")

    def test_codex_daybreak_flag_is_explicit(self) -> None:
        normal = build_parser().parse_args(["run", "/tmp/project"])
        daybreak = build_parser().parse_args([
            "run", "/tmp/project", "--provider", "codex", "--daybreak",
        ])
        doctor = build_parser().parse_args(["doctor", "--daybreak"])
        self.assertFalse(normal.daybreak)
        self.assertTrue(daybreak.daybreak)
        self.assertTrue(doctor.daybreak)

    def test_global_and_role_specific_overrides_are_explicit(self) -> None:
        args = build_parser().parse_args([
            "run",
            "/tmp/project",
            "--model",
            "global-model",
            "--candidate-model",
            "candidate-model",
            "--strong-model",
            "strong-model",
            "--coding-model",
            "coding-model",
        ])

        models = _resolve_role_models(args)
        self.assertEqual(models["entry_generator"], "candidate-model")
        self.assertEqual(models["entry_verifier"], "strong-model")
        self.assertEqual(models["input_action"], "strong-model")
        self.assertEqual(models["state_dependency"], "strong-model")
        self.assertNotIn("behavior_recovery", models)
        self.assertEqual(models["harness_verifier"], "strong-model")
        self.assertEqual(models["harness_generator"], "coding-model")

    def test_ollama_routes_only_action_roles(self) -> None:
        args = build_parser().parse_args(["run", "/tmp/project", "--provider", "ollama"])
        models = _resolve_ollama_models(args)
        expected = {
            "entry_generator": ("glm-5.3-flash:cloud", "high"),
            "entry_verifier": ("glm-5.3:cloud", "low"),
            "input_surface": ("glm-5.3:cloud", "high"),
            "input_action": ("glm-5.3:cloud", "high"),
            "state_dependency": ("glm-5.3:cloud", "high"),
            "scenario_refiner": ("glm-5.3:cloud", "high"),
            "harness_generator": ("kimi-k2.7-code:cloud", None),
            "harness_verifier": ("glm-5.3:cloud", "max"),
        }
        self.assertEqual(set(models), set(expected))
        self.assertEqual(
            {role: (models[role], DEFAULT_OLLAMA_ROLE_EFFORTS[role]) for role in models},
            expected,
        )

    def test_ollama_overrides_apply_to_action_and_state(self) -> None:
        args = build_parser().parse_args([
            "run", "/tmp/project", "--provider", "ollama",
            "--strong-model", "strong-override",
        ])
        models = _resolve_ollama_models(args)
        self.assertEqual(models["entry_generator"], "glm-5.3-flash:cloud")
        self.assertEqual(models["harness_generator"], "kimi-k2.7-code:cloud")
        self.assertEqual(models["input_action"], "strong-override")
        self.assertEqual(models["state_dependency"], "strong-override")
        self.assertEqual(models["scenario_refiner"], "strong-override")
        self.assertNotIn("behavior_recovery", models)
        self.assertEqual(DEFAULT_OLLAMA_ROLE_EFFORTS["entry_verifier"], "low")

    def test_legacy_scenario_alias_uses_action_models(self) -> None:
        args = build_parser().parse_args([
            "run", "/tmp/project", "--workflow", "legacy_scenario",
        ])
        self.assertEqual(_resolve_role_models(args), DEFAULT_ROLE_MODELS)
        self.assertIn("input_action", _resolve_ollama_models(args))

    def test_retired_boundary_workflow_is_not_a_cli_choice(self) -> None:
        with self.assertRaises(SystemExit):
            build_parser().parse_args([
                "run", "/tmp/project", "--workflow", "boundary",
            ])

    def test_run_requires_fuzz_introspector_by_default(self) -> None:
        args = build_parser().parse_args(["run", "/tmp/project"])
        self.assertTrue(args.require_fuzz_introspector)

        bootstrap = build_parser().parse_args([
            "run", "/tmp/project", "--allow-source-analysis"
        ])
        self.assertFalse(bootstrap.require_fuzz_introspector)


class RuntimeModeOptionsTest(unittest.TestCase):
    def test_attribution_trace_differential_and_exploration_flags_are_explicit(self) -> None:
        default_args = build_parser().parse_args(["run", "/tmp/project"])
        self.assertFalse(default_args.require_differential_validation)
        args = build_parser().parse_args([
            "run", "/tmp/project", "--scenario-attribution", "trace",
            "--require-differential-validation", "--scenario-exploratory-drafts",
        ])
        self.assertEqual(args.scenario_attribution, "trace")
        self.assertTrue(args.require_differential_validation)
        self.assertTrue(args.scenario_exploratory_drafts)

    def test_research_project_runner_is_not_a_cli_dependency(self) -> None:
        parser = build_parser()
        self.assertNotIn("--quartet-root", parser.format_help())
        with self.assertRaises(SystemExit):
            parser.parse_args(["run", "/tmp/project", "--quartet-root", "/tmp/unused"])


class ScenarioCliValidationTest(unittest.IsolatedAsyncioTestCase):
    async def test_oss_fuzz_strict_run_fails_before_expensive_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            source.mkdir()
            args = build_parser().parse_args([
                "run", str(source), "--verification-backend", "oss-fuzz",
                "--scenario-attribution", "trace",
            ])
            with patch("harnesscreator.cli._prepare_fuzz_introspector") as prepare:
                with self.assertRaisesRegex(ValueError, "native OSS-Fuzz adapter"):
                    await _run(args)
                prepare.assert_not_called()

    async def test_schema_validation_precedes_source_and_external_preflight(self) -> None:
        args = build_parser().parse_args(["run", "/definitely/missing/source"])

        with patch(
            "harnesscreator.cli.validate_active_output_schemas",
            side_effect=InvalidOutputSchemaError("broken test schema"),
        ) as validate:
            with self.assertRaisesRegex(
                InvalidOutputSchemaError, "broken test schema"
            ):
                await _run(args)

        validate.assert_called_once_with("action")

    async def test_source_discovery_does_not_require_scenario_command_or_channel(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            source.mkdir()
            args = build_parser().parse_args([
                "run", str(source), "--allow-source-analysis",
            ])
            self.assertEqual(args.scenario_channel, "auto")
            class DiscoveryReached(Exception):
                pass
            with patch("harnesscreator.cli._prepare_fuzz_introspector", side_effect=DiscoveryReached):
                with self.assertRaises(DiscoveryReached):
                    await _run(args)


if __name__ == "__main__":
    unittest.main()
