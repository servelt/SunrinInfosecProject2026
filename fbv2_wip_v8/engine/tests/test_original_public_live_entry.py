"""Fresh CLI admission must reject before loading a provider or target."""

import asyncio
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import pytest

from devtools.original_public_live import (
    FULL_NOHINT_SP_ITERATION_POLICY, python_tree_sha256)
from devtools.original_public_live_spec import main as make_live_spec
from devtools.original_public_live_entry import (
    _bounded_nohint_preimport_admission,
    _live_result_exit_ok, _manual_sp_preimport_admission,
    _plain_pin_bytes,
    _preflight_seed_sandbox, _requires_seed_sandbox,
    _runtime_tree_pin,
    _sp_priority_seed_preimport_admission,
    _sp_fuzz_preimport_admission)
from devtools.original_public_live_entry import main as run_live_entry


ENTRY = Path(__file__).resolve().parent.parent / "devtools" / "original_public_live_entry.py"
LAUNCHER = (Path(__file__).resolve().parent.parent / "devtools" /
            "sp_signed_live_pinned_launcher.py")


def test_spec_pin_returns_the_exact_authenticated_bytes(tmp_path):
    spec = tmp_path / "spec.json"
    spec.write_text('{"version":1}')
    raw = _plain_pin_bytes(spec, _sha(spec), "spec")
    spec.write_text('{"version":2}')
    assert json.loads(raw) == {"version": 1}


@pytest.mark.parametrize("name", [
    "shadow.pyc", "shadow.pyo", "shadow.cpython-313-x86_64-linux-gnu.so",
])
def test_runtime_tree_rejects_unsigned_importable_bytes_before_import(
        tmp_path, name):
    (tmp_path / "module.py").write_text("VALUE = 1\n")
    (tmp_path / name).write_bytes(b"untrusted import candidate")
    with pytest.raises(ValueError, match="unsigned importable"):
        _runtime_tree_pin(tmp_path, "0" * 64, engine=False)
    with pytest.raises(ValueError, match="unsigned importable"):
        python_tree_sha256(tmp_path)


def test_runtime_tree_rejects_unreadable_package_before_import(tmp_path):
    (tmp_path / "module.py").write_text("VALUE = 1\n")
    package = tmp_path / "shadow_package"
    package.mkdir()
    (package / "__init__.pyc").write_bytes(b"untrusted package")
    package.chmod(0o111)
    try:
        with pytest.raises(ValueError, match="completely readable"):
            _runtime_tree_pin(tmp_path, "0" * 64, engine=False)
        with pytest.raises(ValueError, match="completely readable"):
            python_tree_sha256(tmp_path)
    finally:
        package.chmod(0o700)


def test_new_full_sp_spec_requires_explicit_finite_process_wall():
    required = []
    for name in ("product-src", "evaluation-dir", "contract-path",
                 "manifest-path", "task-path", "oss-fuzz-checkout",
                 "upstream-checkout", "codex-executable", "run-dir", "output"):
        required.extend(("--" + name, "/unused"))
    required.extend(("--codex-model", "test-model",
                     "--mongo-url", "mongodb://127.0.0.1:1",
                     "--full-nohint-sp"))
    with pytest.raises(SystemExit) as missing:
        make_live_spec(required)
    assert missing.value.code == 2
    with pytest.raises(SystemExit) as invalid:
        make_live_spec(required + ["--full-nohint-sp-process-wall-seconds", "0"])
    assert invalid.value.code == 2


def test_parallel_hp_spec_requires_explicit_gate_budget(capsys):
    required = []
    for name in ("product-src", "evaluation-dir", "contract-path",
                 "manifest-path", "task-path", "oss-fuzz-checkout",
                 "upstream-checkout", "codex-executable", "run-dir", "output"):
        required.extend(("--" + name, "/unused"))
    required.extend((
        "--codex-model", "test-model", "--mongo-url", "mongodb://127.0.0.1:1",
        "--sp-priority-one-seed-dev", "--sp-concurrent-queue-dev",
        "--sp-completion-extended-dev", "--enable-hp", "--parallel-hp-dev",
        "--sp-invariant-focus", "ARITHMETIC_RANGE",
        "--hp-physical-builder", "/unused",
        "--hp-physical-manifest", "/unused"))
    with pytest.raises(SystemExit) as missing:
        make_live_spec(required)
    assert missing.value.code == 2
    assert "explicit Gate lead and wall limits" in capsys.readouterr().err
    with_gate = required + [
        "--hp-gate-max-leads", "1",
        "--hp-gate-replay-wall-seconds", "90",
        "--hp-gate-source-wall-seconds", "90"]
    with pytest.raises(SystemExit) as missing_guided:
        make_live_spec(with_gate)
    assert missing_guided.value.code == 2
    assert "explicit Guided fuzz seconds" in capsys.readouterr().err
    with pytest.raises(SystemExit) as invalid_guided:
        make_live_spec(with_gate + ["--hp-guided-seconds", "11"])
    assert invalid_guided.value.code == 2


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(spec, sha, *extra):
    return subprocess.run(
        [sys.executable, "-I", "-S", "-B", str(LAUNCHER),
         "--entry", str(ENTRY), "--entry-sha256", _sha(ENTRY), "--",
         "--spec", str(spec), "--spec-sha256", sha, *extra],
        capture_output=True, text=True,
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


def test_bounded_nohint_hp_failure_is_not_a_success_exit():
    base = {"status": "EXECUTED_UNVERIFIED"}
    assert _live_result_exit_ok(base, hp_required=False)
    assert not _live_result_exit_ok(base, hp_required=True)
    assert not _live_result_exit_ok(
        {**base, "hp_result": {"status": "HP_POST_WORKER_BLOCKED"}},
        hp_required=True)
    assert _live_result_exit_ok(
        {**base, "hp_result": {"status": "HP_POST_WORKER_COMPLETE"}},
        hp_required=True)
    assert not _live_result_exit_ok(
        {**base, "hp_result": {"status": "HP_POST_WORKER_COMPLETE",
                               "physical_execution_status":
                                   "NOT_RUN_NO_PROPOSAL"}},
        hp_required=True, hp_physical_required=True)
    assert _live_result_exit_ok(
        {**base, "hp_result": {"status": "HP_POST_WORKER_COMPLETE",
                               "physical_execution_status": "COMPLETE"}},
        hp_required=True, hp_physical_required=True)


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
            "max_model_calls_by_role": {"sp": 6, "verifier": 6, "pov": 6},
            "automatic_discovery": False,
        },
        "caps": {"calls_per_agent": 6, "physical_model_calls": 18},
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
    full = {**enabled, "caps": {**enabled["caps"],
                                 "full_nohint_sp": True}}
    assert _sp_fuzz_preimport_admission(full, check_only=False) is True
    enabled["sp_fuzz"]["seconds_per_item"] = 9
    with pytest.raises(ValueError, match="signed SP fuzz"):
        _sp_fuzz_preimport_admission(enabled, check_only=True)
    disabled["caps"]["sp_fuzz_seconds"] = 1
    with pytest.raises(ValueError, match="lacks signed opt-in"):
        _sp_fuzz_preimport_admission(disabled, check_only=True)


def test_seed_preflight_applies_to_no_hint_worker_and_skips_controls():
    assert _requires_seed_sandbox({}) is True
    assert _requires_seed_sandbox({"hp": {"enabled": True}}) is True
    assert _requires_seed_sandbox({"manual_sp_control": {"enabled": True}}) is False
    assert _requires_seed_sandbox({"hp_only": {"enabled": True}}) is False


def test_seed_preflight_rejects_an_inspectable_image_without_python(monkeypatch):
    from fuzzingbrain.fuzzer import seed_sandbox

    def missing_python(_code, _count):
        raise seed_sandbox.SeedSandboxError(
            'seed generator failed: exec: "python": executable file not found')

    monkeypatch.setattr(seed_sandbox, "execute_seed_generator", missing_python)
    with pytest.raises(seed_sandbox.SeedSandboxError, match="python"):
        _preflight_seed_sandbox()


def test_sp_priority_one_seed_scope_is_signed_without_sp_function_limit():
    scope = {"kind": "SP_PRIORITY_ONE_SEED_DEV_V2",
             "seed_directions": 1, "sp_function_limit": None,
             "sp_queue_policy": "DRAIN_CANDIDATES_BEFORE_NEXT_FUNCTION"}
    spec = {"caps": {"seed_direction_limit": 1,
                     "bounded_nohint_dev": False},
            "development_seed_scope": scope.copy(),
            "hp": {"enabled": False}}
    assert _sp_priority_seed_preimport_admission(spec) is True
    assert _sp_priority_seed_preimport_admission(
        {"caps": {"seed_direction_limit": 5}}) is False
    spec["development_seed_scope"]["sp_function_limit"] = 3
    with pytest.raises(ValueError, match="SP-priority Seed"):
        _sp_priority_seed_preimport_admission(spec)
    spec["development_seed_scope"] = scope.copy()
    spec["development_seed_scope"]["sp_queue_policy"] = "SKIP_VERIFIER"
    with pytest.raises(ValueError, match="SP-priority Seed"):
        _sp_priority_seed_preimport_admission(spec)
    spec["development_seed_scope"] = scope.copy()
    spec["manual_sp_control"] = {"function_name": "target"}
    with pytest.raises(ValueError, match="SP-priority Seed"):
        _sp_priority_seed_preimport_admission(spec)
    del spec["manual_sp_control"]
    spec["caps"]["sp_fuzz_seconds"] = 1
    with pytest.raises(ValueError, match="SP-priority Seed"):
        _sp_priority_seed_preimport_admission(spec)
    del spec["caps"]["sp_fuzz_seconds"]
    spec["caps"]["seed_direction_limit"] = 5.0
    with pytest.raises(ValueError, match="SP-priority Seed"):
        _sp_priority_seed_preimport_admission(spec)


def test_sp_completion_budget_requires_separate_exact_scope():
    scope = {"kind": "SP_PRIORITY_ONE_SEED_COMPLETION_DEV_V1",
             "seed_directions": 1, "sp_function_limit": None,
             "sp_queue_policy": "DRAIN_CANDIDATES_BEFORE_NEXT_FUNCTION"}
    caps = {"seed_direction_limit": 1, "bounded_nohint_dev": False,
            "physical_model_calls": 80, "calls_per_agent": 32,
            "model_wall_seconds": 1200, "total_wall_seconds": 2100}
    spec = {"caps": caps, "development_seed_scope": scope,
            "hp": {"enabled": False}}
    assert _sp_priority_seed_preimport_admission(spec) is True
    for key, value in (("physical_model_calls", 81),
                       ("calls_per_agent", 33),
                       ("model_wall_seconds", 1201),
                       ("total_wall_seconds", 2101)):
        changed = {**spec, "caps": {**caps, key: value}}
        with pytest.raises(ValueError, match="SP-priority Seed"):
            _sp_priority_seed_preimport_admission(changed)
    changed = {**spec, "development_seed_scope": {
        **scope, "kind": "SP_PRIORITY_ONE_SEED_DEV_V2"}}
    with pytest.raises(ValueError, match="SP-priority Seed"):
        _sp_priority_seed_preimport_admission(changed)
    changed = {**spec, "hp": {"enabled": True}}
    with pytest.raises(ValueError, match="SP-priority Seed"):
        _sp_priority_seed_preimport_admission(changed)


def test_extended_sp_budget_requires_separate_exact_scope():
    scope = {"kind": "SP_PRIORITY_ONE_SEED_EXTENDED_DEV_V1",
             "seed_directions": 1, "sp_function_limit": None,
             "sp_queue_policy": "DRAIN_CANDIDATES_BEFORE_NEXT_FUNCTION"}
    caps = {"seed_direction_limit": 1, "bounded_nohint_dev": False,
            "physical_model_calls": 120, "calls_per_agent": 64,
            "model_wall_seconds": 1500, "total_wall_seconds": 2400}
    spec = {"caps": caps, "development_seed_scope": scope,
            "hp": {"enabled": False}}
    assert _sp_priority_seed_preimport_admission(spec) is True
    for key, value in (("physical_model_calls", 121),
                       ("calls_per_agent", 65),
                       ("model_wall_seconds", 1501),
                       ("total_wall_seconds", 2401)):
        changed = {**spec, "caps": {**caps, key: value}}
        with pytest.raises(ValueError, match="SP-priority Seed"):
            _sp_priority_seed_preimport_admission(changed)
    changed = {**spec, "hp": {"enabled": True}}
    with pytest.raises(ValueError, match="SP-priority Seed"):
        _sp_priority_seed_preimport_admission(changed)


def test_generic_invariant_sp_scope_binds_family_and_candidate_fairness():
    scope = {
        "kind": "SP_PRIORITY_ONE_SEED_EXTENDED_DEV_V2",
        "seed_directions": 1, "sp_function_limit": None,
        "sp_queue_policy": "DRAIN_CANDIDATES_BEFORE_NEXT_FUNCTION",
        "security_invariant_focus": "BOUNDS_EXTENT",
        "direction_selection":
            "GENERIC_SECURITY_FAMILY_PRIORITY_MODEL_TIE_V1",
        "pov_attempts_per_candidate": 3,
    }
    caps = {
        "seed_direction_limit": 1, "bounded_nohint_dev": False,
        "physical_model_calls": 120, "calls_per_agent": 64,
        "model_wall_seconds": 1500, "total_wall_seconds": 2400,
        "security_invariant_focus": "BOUNDS_EXTENT",
        "pov_attempts_per_candidate": 3,
    }
    spec = {"caps": caps, "development_seed_scope": scope,
            "hp": {"enabled": False}}
    assert _sp_priority_seed_preimport_admission(spec) is True
    for changed in (
        {**spec, "caps": {**caps, "security_invariant_focus":
                           "LIFETIME_OWNERSHIP"}},
        {**spec, "caps": {**caps, "pov_attempts_per_candidate": 4}},
        {**spec, "development_seed_scope": {
            **scope, "direction_selection": "KNOWN_FUNCTION_FIRST"}},
    ):
        with pytest.raises(ValueError, match="SP-priority Seed"):
            _sp_priority_seed_preimport_admission(changed)

def test_extended_scope_binds_generic_sp_start_envelope():
    caps = {
        "seed_direction_limit": 1, "bounded_nohint_dev": False,
        "physical_model_calls": 120, "calls_per_agent": 64,
        "model_wall_seconds": 1500, "total_wall_seconds": 2400,
        "security_invariant_focus": "LIFETIME_OWNERSHIP",
        "pov_attempts_per_candidate": 3,
        "sp_start_min_remaining_calls": 30,
        "sp_start_min_remaining_wall_seconds": 600,
    }
    scope = {
        "kind": "SP_PRIORITY_ONE_SEED_EXTENDED_DEV_V3",
        "seed_directions": 1, "sp_function_limit": None,
        "sp_queue_policy": "DRAIN_CANDIDATES_BEFORE_NEXT_FUNCTION",
        "security_invariant_focus": "LIFETIME_OWNERSHIP",
        "direction_selection":
            "GENERIC_SECURITY_FAMILY_PRIORITY_MODEL_TIE_V1",
        "pov_attempts_per_candidate": 3,
        "sp_start_min_remaining_calls": 30,
        "sp_start_min_remaining_wall_seconds": 600,
    }
    spec = {"caps": caps, "development_seed_scope": scope,
            "hp": {"enabled": False}}
    assert _sp_priority_seed_preimport_admission(spec) is True
    for changed in (
        {**spec, "caps": {**caps, "sp_start_min_remaining_calls": 29}},
        {**spec, "caps": {**caps,
                           "sp_start_min_remaining_wall_seconds": None}},
        {**spec, "development_seed_scope": {
            **scope, "sp_start_min_remaining_calls": 29}},
    ):
        with pytest.raises(ValueError, match="SP-priority Seed"):
            _sp_priority_seed_preimport_admission(changed)


def test_concurrent_queue_scope_has_workers_but_no_role_budget_or_reserve():
    caps = {
        "seed_direction_limit": 1, "bounded_nohint_dev": False,
        "physical_model_calls": 120, "calls_per_agent": 64,
        "model_wall_seconds": 1500, "total_wall_seconds": 2400,
        "security_invariant_focus": "LIFETIME_OWNERSHIP",
        "pov_attempts_per_candidate": 3,
        "sp_start_min_remaining_calls": None,
        "sp_start_min_remaining_wall_seconds": None,
        "sp_concurrent_queue": True,
        "seed_required_unique": 5,
        "sp_discovery_agents": 3,
        "sp_verify_agents": 2,
        "sp_pov_agents": 2,
    }
    scope = {
        "kind": "SP_PERSISTENT_CONCURRENT_QUEUE_DEV_V1",
        "seed_directions": 1, "sp_function_limit": None,
        "sp_queue_policy": "PERSISTENT_CONCURRENT_QUEUE_V1",
        "security_invariant_focus": "LIFETIME_OWNERSHIP",
        "direction_selection":
            "GENERIC_SECURITY_FAMILY_PRIORITY_MODEL_TIE_V1",
        "pov_attempts_per_candidate": 3,
        "worker_pool": {"discovery": 3, "verifier": 2, "pov": 2},
    }
    spec = {"caps": caps, "development_seed_scope": scope,
            "hp": {"enabled": False}}
    assert _sp_priority_seed_preimport_admission(spec) is True
    for required in (None, True, 0, 129, "5"):
        with pytest.raises(ValueError, match="SP-priority Seed"):
            _sp_priority_seed_preimport_admission({
                **spec, "caps": {**caps, "seed_required_unique": required}})
    for changed in (
        {**spec, "caps": {**caps, "sp_verify_agents": 1}},
        {**spec, "caps": {**caps,
                           "sp_start_min_remaining_calls": 1,
                           "sp_start_min_remaining_wall_seconds": 1}},
        {**spec, "development_seed_scope": {
            **scope, "sp_queue_policy":
                "DRAIN_CANDIDATES_BEFORE_NEXT_FUNCTION"}},
    ):
        with pytest.raises(ValueError, match="SP-priority Seed"):
            _sp_priority_seed_preimport_admission(changed)


def test_combined_concurrent_hp_scope_is_exact_and_has_no_reserve():
    caps = {
        "seed_direction_limit": 1, "bounded_nohint_dev": False,
        "physical_model_calls": 120, "calls_per_agent": 64,
        "model_wall_seconds": 1500, "total_wall_seconds": 2400,
        "security_invariant_focus": "LIFETIME_OWNERSHIP",
        "pov_attempts_per_candidate": 3,
        "sp_start_min_remaining_calls": None,
        "sp_start_min_remaining_wall_seconds": None,
        "sp_concurrent_queue": True, "sp_discovery_agents": 3,
        "seed_required_unique": 5,
        "sp_verify_agents": 2, "sp_pov_agents": 2,
    }
    scope = {
        "kind": "SP_PERSISTENT_CONCURRENT_QUEUE_HP_POST_WORKER_DEV_V1",
        "seed_directions": 1, "sp_function_limit": None,
        "sp_queue_policy": "PERSISTENT_CONCURRENT_QUEUE_V1",
        "security_invariant_focus": "LIFETIME_OWNERSHIP",
        "direction_selection":
            "GENERIC_SECURITY_FAMILY_PRIORITY_MODEL_TIE_V1",
        "pov_attempts_per_candidate": 3,
        "worker_pool": {"discovery": 3, "verifier": 2, "pov": 2},
    }
    hp = {"enabled": True, "max_items": 1, "max_model_calls": 3,
          "assets": {}, "physical": {}}
    spec = {"caps": caps, "development_seed_scope": scope, "hp": hp}
    assert _sp_priority_seed_preimport_admission(spec) is True
    for changed in (
        {**spec, "hp": {**hp, "max_model_calls": 4}},
        {**spec, "hp": {"enabled": False}},
        {**spec, "caps": {**caps, "sp_verify_agents": 1}},
        {**spec, "caps": {**caps,
                           "sp_start_min_remaining_calls": 3}},
        {**spec, "development_seed_scope": {
            **scope, "worker_pool": {"discovery": 3,
                                      "verifier": 2, "pov": 1}}},
    ):
        with pytest.raises(ValueError, match="SP-priority Seed"):
            _sp_priority_seed_preimport_admission(changed)


    parallel = {**spec, "caps": {**caps, "model_turn_seconds": 600,
                                 "physical_model_calls": None,
                                 "calls_per_agent": None},
                "development_seed_scope": {
        **scope,
        "kind": "SP_PERSISTENT_CONCURRENT_QUEUE_HP_PARALLEL_DEV_V1"}}
    assert _sp_priority_seed_preimport_admission(parallel) is True
    for field, value in (("physical_model_calls", 120),
                         ("calls_per_agent", 64)):
        with pytest.raises(ValueError, match="SP-priority Seed"):
            _sp_priority_seed_preimport_admission({
                **parallel, "caps": {**parallel["caps"], field: value}})
    for seconds in (299, 300, 600, 601, 1200, None, True, "600"):
        changed = {**parallel, "caps": {
            **parallel["caps"], "model_turn_seconds": seconds}}
        if type(seconds) is int and 300 <= seconds <= 600:
            assert _sp_priority_seed_preimport_admission(changed) is True
        else:
            with pytest.raises(ValueError, match="SP-priority Seed"):
                _sp_priority_seed_preimport_admission(changed)
    for changed in (
        {**parallel, "hp": {"enabled": False}},
        {**parallel, "caps": {**parallel["caps"], "sp_pov_agents": 1}},
        {**parallel, "development_seed_scope": {
            **parallel["development_seed_scope"],
            "worker_pool": {"discovery": 3, "verifier": 2, "pov": 1}}},
    ):
        with pytest.raises(ValueError, match="SP-priority Seed"):
            _sp_priority_seed_preimport_admission(changed)


def test_parallel_hp_requires_explicit_profile_mode(
        tmp_path, capsys):
    spec = tmp_path / "parallel-spec.json"
    spec.write_text(json.dumps({"development_seed_scope": {
        "kind": "SP_PERSISTENT_CONCURRENT_QUEUE_HP_PARALLEL_DEV_V1"}}))
    exit_code = run_live_entry([
        "--spec", str(spec), "--spec-sha256", _sha(spec),
        "--authorize-public-dev"])
    assert exit_code == 2
    result = json.loads(capsys.readouterr().out)
    assert result == {
        "status": "INCOMPLETE_ADMISSION",
        "reason": "HP_PARALLEL_EXPLICIT_MODE_REQUIRED",
        "model_physical_calls": 0,
    }

    # The review-only check route reaches the ordinary fresh-interpreter
    # bootstrap; this test process has intentionally not entered through it.
    exit_code = run_live_entry([
        "--spec", str(spec), "--spec-sha256", _sha(spec), "--check-only"])
    assert exit_code == 2
    result = json.loads(capsys.readouterr().out)
    assert result["reason"] == (
        "public live development requires python -I -S isolation")


def test_parallel_hp_exit_requires_proven_analysis():
    from devtools.original_public_live_entry import _live_result_exit_ok

    result = {"status": "EXECUTED_UNVERIFIED"}
    assert not _live_result_exit_ok(
        result, hp_required=False, parallel_hp_required=True)
    result["parallel_hp_diagnostic"] = {
        "analysis_status": "HP_PARALLEL_EVIDENCE_UNPROVEN",
        "security_gate_credit": "NOT_CREDITED",
        "discovery_credit": "NOT_CREDITED",
    }
    assert not _live_result_exit_ok(
        result, hp_required=False, parallel_hp_required=True)
    result["parallel_hp_diagnostic"]["analysis_status"] = (
        "HP_PARALLEL_ANALYSIS_COMPLETE")
    result["parallel_hp_diagnostic"].update({
        "analysis_outcome": "NO_SAFE_ASSUMPTION",
        "physical_status": "NOT_RUN"})
    assert _live_result_exit_ok(
        result, hp_required=False, parallel_hp_required=True)
    result["status"] = "EXECUTED_GATE_VERIFIED_DISCOVERY_UNPROVEN"
    assert _live_result_exit_ok(
        result, hp_required=False, parallel_hp_required=True)
    assert not _live_result_exit_ok(
        result, hp_required=True, parallel_hp_required=True)
    result["parallel_hp_diagnostic"].update({
        "analysis_outcome": "ASSERTIONS_PROPOSED_UNVERIFIED",
        "assertion_observations": {
            "initial_assertion_reached": False,
            "guided_crash_observed_ungated": True},
        "physical_status": "HP_GUIDED_CRASH_OBSERVED_UNGATED",
        "gate_status": "HP_GATE_PENDING_OR_INCOMPLETE"})
    assert not _live_result_exit_ok(
        result, hp_required=False, parallel_hp_required=True)
    result["parallel_hp_diagnostic"].update({
        "gate_status": "HP_GATE_VERIFIED_DISCOVERY_UNPROVEN",
        "security_gate_credit": "HP_GATE_VERIFIED",
        "unprocessed_lead_count": 0,
        "rejected_lead_count": 0,
        "pending_lead_count": 0})
    assert _live_result_exit_ok(
        result, hp_required=False, parallel_hp_required=True)
    for field in ("unprocessed_lead_count", "rejected_lead_count",
                  "pending_lead_count"):
        result["parallel_hp_diagnostic"][field] = 1
        assert not _live_result_exit_ok(
            result, hp_required=False, parallel_hp_required=True)
        result["parallel_hp_diagnostic"][field] = 0
    result["parallel_hp_diagnostic"]["physical_status"] = (
        "HP_ASSERTION_HANDOFF_BLOCKED")
    assert not _live_result_exit_ok(
        result, hp_required=False, parallel_hp_required=True)


def test_parallel_hp_factory_binds_current_run_and_rejects_reinstall(
        tmp_path, monkeypatch):
    from devtools import parallel_hp_analysis
    from devtools.original_public_live_entry import _install_signed_parallel_hp

    bound = SimpleNamespace(executor=SimpleNamespace())
    spec = {
        "development_seed_scope": {
            "kind": "SP_PERSISTENT_CONCURRENT_QUEUE_HP_PARALLEL_DEV_V1"},
        "sp_live_admission": {
            "contract_kind": "SP_HP_PARALLEL_SIGNED_LIVE_ADMISSION_V1"},
        "hp": {"enabled": True},
    }
    spec_path = tmp_path / "signed-parallel.json"
    calls = []

    async def fake_run(**kwargs):
        calls.append(kwargs)
        return {"status": "HP_PARALLEL_ANALYSIS_COMPLETE"}

    monkeypatch.setattr(parallel_hp_analysis, "run_parallel_hp_analysis",
                        fake_run)
    _install_signed_parallel_hp(
        bound, spec, spec_path=spec_path, spec_sha256="a" * 64)
    strategy, directions = object(), [object()]
    result = asyncio.run(bound.executor.parallel_hp_async_factory(
        strategy, directions))
    assert result["status"] == "HP_PARALLEL_ANALYSIS_COMPLETE"
    assert calls == [{"bound": bound, "strategy": strategy,
                      "directions": directions, "hp": spec["hp"],
                      "spec_path": spec_path, "spec_sha256": "a" * 64}]
    with pytest.raises(ValueError, match="factory admission"):
        _install_signed_parallel_hp(
            bound, spec, spec_path=spec_path, spec_sha256="a" * 64)


def test_parallel_hp_gate_preimport_requires_bounded_signed_policy():
    from devtools.original_public_live_entry import (
        _parallel_hp_gate_preimport_admission)

    policy = {"enabled": True, "max_leads": 1,
              "replay_timeout_seconds": 10,
              "replay_wall_seconds": 90,
              "source_wall_seconds": 90,
              "output_limit_bytes": 4_000_000}
    spec = {
        "development_seed_scope": {
            "kind": "SP_PERSISTENT_CONCURRENT_QUEUE_HP_PARALLEL_DEV_V1"},
        "caps": {"pov_timeout_seconds": 10,
                 "gate_aux_reservation_seconds_per_observation": 600,
                 "seed_required_unique": 5},
        "hp": {"physical": {"output_limit_bytes": 4_000_000}},
        "hp_gate": policy,
        "sp_gate_unsupported_crash_policy":
            "PENDING_HUMAN_REVIEW_NO_TERMINAL_CREDIT_V1",
    }
    _parallel_hp_gate_preimport_admission(spec)
    for changed in (
            {**spec, "hp_gate": {**policy, "max_leads": 4}},
            {**spec, "hp_gate": {**policy,
                                 "output_limit_bytes": 4_000_001}},
            {**spec, "hp_gate": None},
            {**spec, "sp_gate_unsupported_crash_policy": None},
            {**spec, "sp_gate_unsupported_crash_policy": "TERMINAL"},
            {**spec, "caps": {**spec["caps"],
                               "seed_required_unique": 4}},
            {**spec, "development_seed_scope": {
                "kind": "SP_PERSISTENT_CONCURRENT_QUEUE_HP_POST_WORKER_DEV_V1"}}):
        with pytest.raises(ValueError, match="HP Gate"):
            _parallel_hp_gate_preimport_admission(changed)



def test_full_nohint_sp_preimport_requires_all_directions_and_no_hints():
    caps = {"seed_direction_limit": 5, "bounded_nohint_dev": False,
            "full_nohint_sp": True, "physical_model_calls": None,
            "calls_per_agent": None, "model_wall_seconds": None,
            "total_wall_seconds": 3000, "sp_fuzz_seconds": 0,
            "sp_fuzz_max_items": 0,
            "sp_iteration_policy": dict(FULL_NOHINT_SP_ITERATION_POLICY)}
    spec = {"caps": caps, "hp": {"enabled": False}}
    assert _sp_priority_seed_preimport_admission(spec) is False
    longer = {**spec, "caps": {**caps, "total_wall_seconds": 14_400}}
    assert _sp_priority_seed_preimport_admission(longer) is False
    with_sp_fuzz = {
        **longer,
        "caps": {**longer["caps"], "sp_fuzz_seconds": 10,
                 "sp_fuzz_max_items": 1},
        "sp_fuzz": {"enabled": True, "seconds_per_item": 10,
                    "max_items": 1},
    }
    assert _sp_fuzz_preimport_admission(
        with_sp_fuzz, check_only=False) is True
    assert _sp_priority_seed_preimport_admission(with_sp_fuzz) is False
    for changed in (
            {**spec, "caps": {**caps, "seed_direction_limit": 1}},
            {**spec, "caps": {**caps, "physical_model_calls": 120}},
            {**spec, "caps": {**caps, "sp_iteration_policy": None}},
            {**spec, "caps": {**caps, "total_wall_seconds": 0}},
            {**spec, "caps": {**caps, "total_wall_seconds": None}},
            {**spec, "hp": {"enabled": True}},
            {**spec, "manual_sp_control": {"function_name": "md_html"}}):
        with pytest.raises(ValueError, match="full no-hint SP"):
            _sp_priority_seed_preimport_admission(changed)


def test_bounded_nohint_scope_is_exactly_signed_and_excludes_hints():
    spec = {
        "caps": {"bounded_nohint_dev": True, "physical_model_calls": 48,
                 "calls_per_agent": 20, "model_wall_seconds": 900,
                 "total_wall_seconds": 1800, "global_fuzz_seconds": 30,
                 "sp_fuzz_max_items": 0, "sp_fuzz_seconds": 0},
        "development_scope": {
            "kind": "BOUNDED_NOHINT_DEV_V1", "seed_directions": 2,
            "sp_functions": 3, "sp_max_iterations": 7,
            "selection": "DIRECTION_RISK_PHASE_CANONICAL_V1"},
        "hp": {"enabled": False},
    }
    assert _bounded_nohint_preimport_admission(spec) is True
    spec["development_scope"]["sp_functions"] = 4
    with pytest.raises(ValueError, match="bounded no-hint"):
        _bounded_nohint_preimport_admission(spec)
    spec["development_scope"]["sp_functions"] = 3
    spec["development_scope"]["sp_max_iterations"] = 8
    with pytest.raises(ValueError, match="bounded no-hint"):
        _bounded_nohint_preimport_admission(spec)
    spec["development_scope"]["sp_max_iterations"] = 7
    spec["manual_sp_control"] = {"function_name": "target"}
    with pytest.raises(ValueError, match="bounded no-hint"):
        _bounded_nohint_preimport_admission(spec)


def test_bounded_nohint_completion_scope_requires_exact_80_call_profile():
    spec = {
        "caps": {"bounded_nohint_dev": True, "physical_model_calls": 80,
                 "calls_per_agent": 32, "model_wall_seconds": 1200,
                 "total_wall_seconds": 2100, "global_fuzz_seconds": 30,
                 "sp_fuzz_max_items": 0, "sp_fuzz_seconds": 0},
        "development_scope": {
            "kind": "BOUNDED_NOHINT_COMPLETION_DEV_V1",
            "seed_directions": 2, "sp_functions": 3,
            "sp_max_iterations": 7,
            "selection": "DIRECTION_RISK_PHASE_GENERIC_SURFACE_MODEL_TIE_V4"},
        "hp": {"enabled": False},
    }
    assert _bounded_nohint_preimport_admission(spec) is True
    for key, value in (("physical_model_calls", 48),
                       ("calls_per_agent", 20),
                       ("model_wall_seconds", 900),
                       ("total_wall_seconds", 1800)):
        changed = {**spec, "caps": {**spec["caps"], key: value}}
        with pytest.raises(ValueError, match="bounded no-hint"):
            _bounded_nohint_preimport_admission(changed)


def test_bounded_nohint_hp_requires_separate_mode_and_physical_recipe():
    spec = {
        "caps": {"bounded_nohint_dev": True, "physical_model_calls": 48,
                 "calls_per_agent": 20, "model_wall_seconds": 900,
                 "total_wall_seconds": 1800, "global_fuzz_seconds": 30,
                 "sp_fuzz_max_items": 0, "sp_fuzz_seconds": 0},
        "development_scope": {
            "kind": "BOUNDED_NOHINT_DEV_V1", "seed_directions": 2,
            "sp_functions": 1, "sp_max_iterations": 7,
            "selection": "DIRECTION_RISK_PHASE_CANONICAL_V1"},
        "hp": {"enabled": True, "max_items": 1, "max_model_calls": 5,
               "assets": {}, "physical": {}},
    }
    with pytest.raises(ValueError, match="bounded no-hint HP"):
        _bounded_nohint_preimport_admission(spec)
    assert _bounded_nohint_preimport_admission(
        spec, bounded_hp_mode=True) is True
    spec["hp"]["max_model_calls"] = 3
    with pytest.raises(ValueError, match="bounded no-hint HP"):
        _bounded_nohint_preimport_admission(spec, bounded_hp_mode=True)
    spec["hp"]["max_model_calls"] = 5
    spec["development_scope"]["sp_functions"] = 3
    with pytest.raises(ValueError, match="bounded no-hint"):
        _bounded_nohint_preimport_admission(
            spec, bounded_hp_mode=True)
    spec["development_scope"]["sp_functions"] = 1
    spec["hp"].pop("physical")
    with pytest.raises(ValueError, match="bounded no-hint HP"):
        _bounded_nohint_preimport_admission(
            spec, bounded_hp_mode=True)
    spec["hp"] = {"enabled": False}
    with pytest.raises(ValueError, match="bounded no-hint"):
        _bounded_nohint_preimport_admission(spec)
    spec["development_scope"]["sp_functions"] = 3
    with pytest.raises(ValueError, match="requires signed HP"):
        _bounded_nohint_preimport_admission(
            spec, bounded_hp_mode=True)
    spec.pop("development_scope")
    spec["caps"]["bounded_nohint_dev"] = False
    with pytest.raises(ValueError, match="requires bounded scope"):
        _bounded_nohint_preimport_admission(
            spec, bounded_hp_mode=True)


def test_live_entry_rejects_nonisolated_interpreter(tmp_path):
    spec = tmp_path / "spec.json"
    spec.write_text("{}")
    outcome = subprocess.run(
        [sys.executable, "-B", str(ENTRY), "--spec", str(spec),
         "--spec-sha256", _sha(spec), "--authorize-public-dev"],
        capture_output=True, text=True, timeout=10, check=False)
    assert outcome.returncode == 2
    assert "python -I -S isolation" in outcome.stdout


def test_live_entry_rejects_direct_execution_without_pinned_launcher(tmp_path):
    spec = tmp_path / "spec.json"
    spec.write_text("{}")
    outcome = subprocess.run(
        [sys.executable, "-I", "-S", "-B", str(ENTRY), "--spec", str(spec),
         "--spec-sha256", _sha(spec), "--authorize-public-dev"],
        capture_output=True, text=True, timeout=10, check=False)
    assert outcome.returncode == 2
    assert "sealed launcher image is absent" in outcome.stdout


def test_live_entry_rejects_caller_forged_launcher_witness(tmp_path):
    spec = tmp_path / "spec.json"
    spec.write_text("{}")
    code = (
        "import hashlib,os,pathlib,sys;"
        f"e=pathlib.Path({str(ENTRY)!r});"
        f"l=pathlib.Path({str(LAUNCHER)!r});"
        f"s=pathlib.Path({str(spec)!r});"
        "g=sys.modules['__main__'].__dict__;"
        "g['__file__']=str(e);"
        "g['_FBV2_PINNED_LAUNCHER_WITNESS']={"
        "'entry_path':str(e),'entry_sha256':hashlib.sha256(e.read_bytes()).hexdigest(),"
        "'launcher_code':sys._getframe().f_code,'launcher_path':str(l),"
        "'launcher_sha256':hashlib.sha256(l.read_bytes()).hexdigest(),"
        "'pid':os.getpid(),'used':False};"
        "sys.argv=[str(e),'--spec',str(s),'--spec-sha256',"
        "hashlib.sha256(s.read_bytes()).hexdigest(),'--authorize-public-dev'];"
        "exec(compile(e.read_bytes(),str(e),'exec'),g)"
    )
    outcome = subprocess.run(
        [sys.executable, "-I", "-S", "-B", "-c", code],
        capture_output=True, text=True, timeout=10, check=False)
    assert outcome.returncode == 2
    assert "sealed launcher image is absent" in outcome.stdout


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
