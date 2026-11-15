"""Fresh CLI admission must reject before loading a provider or target."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import pytest

from devtools.original_public_live import python_tree_sha256
from devtools.original_public_live_entry import (
    _manual_sp_preimport_admission, _sp_fuzz_preimport_admission)


ENTRY = Path(__file__).resolve().parent.parent / "devtools" / "original_public_live_entry.py"


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(spec, sha, *extra):
    return subprocess.run(
        [sys.executable, "-I", "-B", str(ENTRY), "--spec", str(spec),
         "--spec-sha256", sha, *extra], capture_output=True, text=True,
        timeout=10, check=False)


def test_live_entry_requires_explicit_authorization_before_import(tmp_path):
    spec = tmp_path / "spec.json"
    spec.write_text("{}")
    outcome = _run(spec, _sha(spec))
    assert outcome.returncode == 2
    assert json.loads(outcome.stdout)["status"] == "INCOMPLETE_ADMISSION"
    assert "explicit public development" in outcome.stdout


def test_live_hp_mode_is_closed_before_import(tmp_path):
    spec = tmp_path / "spec.json"
    spec.write_text("{}")
    outcome = _run(spec, _sha(spec), "--authorize-public-dev-hp")
    assert outcome.returncode == 2
    assert json.loads(outcome.stdout) == {
        "status": "INCOMPLETE_ADMISSION",
        "reason": "HP_LIVE_MODE_NOT_VALIDATED",
    }


def test_manual_sp_control_requires_explicit_function_name(tmp_path):
    spec = tmp_path / "spec.json"
    spec.write_text("{}")
    outcome = _run(spec, _sha(spec), "--authorize-manual-sp-control")
    assert outcome.returncode == 2
    assert "--function-name is required" in outcome.stderr


def test_function_hint_is_rejected_outside_manual_control(tmp_path):
    spec = tmp_path / "spec.json"
    spec.write_text("{}")
    outcome = _run(spec, _sha(spec), "--authorize-public-dev",
                   "--function-name", "md_collect_marks")
    assert outcome.returncode == 2
    assert "--function-name is only valid" in outcome.stderr


def test_manual_sp_control_function_and_budget_are_signed():
    spec = {
        "manual_sp_control": {
            "enabled": True,
            "function_name": "md_consume_link_reference_definitions",
            "max_model_calls_by_role": {"sp": 3, "verifier": 6, "pov": 6},
            "automatic_discovery": False,
        },
        "caps": {"calls_per_agent": 6, "physical_model_calls": 15},
    }
    name = "md_consume_link_reference_definitions"
    _manual_sp_preimport_admission(
        spec, manual_mode=True, function_name=name, check_only=False)
    with pytest.raises(ValueError, match="differs from signed spec"):
        _manual_sp_preimport_admission(
            spec, manual_mode=True, function_name="md_collect_marks",
            check_only=False)
    with pytest.raises(ValueError, match="requires its explicit entry mode"):
        _manual_sp_preimport_admission(
            spec, manual_mode=False, function_name=None, check_only=False)
    spec["caps"]["physical_model_calls"] = 32
    with pytest.raises(ValueError, match="physical model cap"):
        _manual_sp_preimport_admission(
            spec, manual_mode=True, function_name=name, check_only=False)


def test_sp_fuzz_optin_is_pinned_and_live_mode_stays_closed():
    disabled = {"caps": {"sp_fuzz_seconds": 0, "sp_fuzz_max_items": 0},
                "hp": {"enabled": False}}
    assert _sp_fuzz_preimport_admission(disabled, check_only=False) is False
    enabled = {"caps": {"sp_fuzz_seconds": 10, "sp_fuzz_max_items": 1},
               "sp_fuzz": {"enabled": True, "seconds_per_item": 10,
                           "max_items": 1},
               "hp": {"enabled": False}}
    assert _sp_fuzz_preimport_admission(enabled, check_only=True) is True
    with pytest.raises(ValueError, match="SP_FUZZ_LIVE_MODE_NOT_CONNECTED"):
        _sp_fuzz_preimport_admission(enabled, check_only=False)
    enabled["sp_fuzz"]["seconds_per_item"] = 9
    with pytest.raises(ValueError, match="signed SP fuzz"):
        _sp_fuzz_preimport_admission(enabled, check_only=True)
    disabled["caps"]["sp_fuzz_seconds"] = 1
    with pytest.raises(ValueError, match="lacks signed opt-in"):
        _sp_fuzz_preimport_admission(disabled, check_only=True)


def test_live_entry_rejects_nonisolated_interpreter(tmp_path):
    spec = tmp_path / "spec.json"
    spec.write_text("{}")
    outcome = subprocess.run(
        [sys.executable, "-B", str(ENTRY), "--spec", str(spec),
         "--spec-sha256", _sha(spec), "--authorize-public-dev"],
        capture_output=True, text=True, timeout=10, check=False)
    assert outcome.returncode == 2
    assert "python -I isolation" in outcome.stdout


def test_live_entry_rejects_changed_external_spec_before_import(tmp_path):
    spec = tmp_path / "spec.json"
    spec.write_text("{}")
    original = _sha(spec)
    spec.write_text("{\"changed\":true}")
    outcome = _run(spec, original, "--authorize-public-dev")
    assert outcome.returncode == 2
    assert "pin changed before importing runtime" in outcome.stdout


def test_live_entry_rejects_prompt_change_before_import(tmp_path):
    engine = tmp_path / "engine"
    prompts = engine / "fuzzingbrain" / "agents" / "prompts"
    prompts.mkdir(parents=True)
    (engine / "fuzzingbrain" / "tools").mkdir()
    (engine / "fuzzingbrain" / "llm_config.yaml").write_text("model: fixture\n")
    (engine / "fuzzingbrain" / "tools" / "tools.yaml").write_text("tools: []\n")
    (engine / "fuzzingbrain" / "module.py").write_text("pass\n")
    prompt = prompts / "direction_planning_prompt.md"
    prompt.write_text("original\n")
    product = tmp_path / "product"
    evaluation = tmp_path / "evaluation"
    for root in (product, evaluation):
        root.mkdir()
        (root / "module.py").write_text("pass\n")
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps({
        "kind": "FBV2_ORIGINAL_PUBLIC_DEV_LIVE_SPEC_V1",
        "blind3_runs": 0, "oracle_queries": 0,
        "allow_synthetic_wire": False,
        "identity": {"engine_root": str(engine),
                     "engine_py_sha256": python_tree_sha256(engine),
                     "product_src": str(product),
                     "product_py_sha256": python_tree_sha256(product),
                     "evaluation_dir": str(evaluation),
                     "evaluation_py_sha256": python_tree_sha256(evaluation)},
    }))
    spec_sha = _sha(spec)
    prompt.write_text("changed\n")
    outcome = _run(spec, spec_sha, "--authorize-public-dev")
    assert outcome.returncode == 2
    assert "runtime source tree SHA-256 changed before import" in outcome.stdout
