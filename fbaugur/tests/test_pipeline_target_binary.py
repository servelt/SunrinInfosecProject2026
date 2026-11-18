from pathlib import Path

from fbaugur.cli import build_parser
from fbaugur.pipeline import harnesscreator_argv


def test_pipeline_passes_original_executable_to_context_harness_stage(tmp_path: Path):
    binary = tmp_path / "source" / "bin" / "daemon"
    args = build_parser().parse_args([
        "pipeline", str(tmp_path / "source"), "--coverage-root", str(tmp_path / "cov"),
        "--coverage-command", "true", "--port", "1234", "--provider", "codex",
        "--analysis-binary", str(binary),
    ])
    command = harnesscreator_argv(args, tmp_path / "run")
    assert command[command.index("--analysis-binary") + 1] == str(binary)


def test_harness_stage_uses_daybreak_only_for_eligible_codex_models(tmp_path: Path):
    parser = build_parser()
    common = ["pipeline", str(tmp_path / "source"), "--coverage-root", str(tmp_path / "cov"),
              "--coverage-command", "true", "--port", "1234", "--provider", "codex"]
    standard = parser.parse_args(common + ["--model-t1", "gpt-6.1-sol",
                                         "--model-t2", "gpt-6.1-sol",
                                         "--model-t3", "gpt-6.1-sol"])
    supported = parser.parse_args(common + ["--model-t1", "gpt-6-sol"])
    assert "--daybreak" not in harnesscreator_argv(standard, tmp_path / "standard")
    assert "--daybreak" in harnesscreator_argv(supported, tmp_path / "supported")


def _last(command: list[str], flag: str) -> str:
    return command[len(command) - 1 - command[::-1].index(flag) + 1]


def test_entry_model_overrides_entry_and_context_roles_only(tmp_path: Path):
    args = build_parser().parse_args([
        "pipeline", str(tmp_path / "source"), "--coverage-root", str(tmp_path / "cov"),
        "--coverage-command", "true", "--port", "1234", "--provider", "codex",
        "--model-t1", "gpt-6-sol", "--model-t2", "gpt-6-sol", "--model-t3", "gpt-6-luna",
        "--model-entry", "gpt-6.1-sol",
    ])
    command = harnesscreator_argv(args, tmp_path / "run")
    assert _last(command, "--candidate-model") == "gpt-6.1-sol"
    assert _last(command, "--strong-model") == "gpt-6.1-sol"
    assert _last(command, "--context-model") == "gpt-6.1-sol"
    assert _last(command, "--model") == "gpt-6-sol"          # seeds and harnesses: tier 2, not tier 3
    assert _last(command, "--coding-model") == "gpt-6-sol"
    assert "--daybreak" in command                              # tiers request it; turns pick per model
