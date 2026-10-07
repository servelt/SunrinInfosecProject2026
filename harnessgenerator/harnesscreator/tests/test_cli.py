import unittest

from harnesscreator.cli import DEFAULT_ROLE_MODELS, _resolve_role_models, build_parser


class RoleModelRoutingTest(unittest.TestCase):
    def test_uses_fixed_per_agent_defaults(self) -> None:
        args = build_parser().parse_args(["run", "/tmp/project"])

        self.assertEqual(_resolve_role_models(args), DEFAULT_ROLE_MODELS)
        self.assertEqual(DEFAULT_ROLE_MODELS["entry_generator"], "gpt-5.6-luna")
        for role in (
            "entry_verifier",
            "small_feature",
            "large_feature",
            "harness_generator",
            "harness_verifier",
        ):
            self.assertEqual(DEFAULT_ROLE_MODELS[role], "gpt-5.5")

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
        self.assertEqual(models["small_feature"], "strong-model")
        self.assertEqual(models["large_feature"], "strong-model")
        self.assertEqual(models["harness_verifier"], "strong-model")
        self.assertEqual(models["harness_generator"], "coding-model")

    def test_run_requires_fuzz_introspector_by_default(self) -> None:
        args = build_parser().parse_args(["run", "/tmp/project"])
        self.assertTrue(args.require_fuzz_introspector)

        bootstrap = build_parser().parse_args([
            "run", "/tmp/project", "--allow-source-analysis"
        ])
        self.assertFalse(bootstrap.require_fuzz_introspector)


if __name__ == "__main__":
    unittest.main()
