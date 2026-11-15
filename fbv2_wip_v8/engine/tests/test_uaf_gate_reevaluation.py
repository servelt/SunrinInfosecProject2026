"""Provider-free contracts for saved UAF evidence and later Gate evaluation."""

import hashlib
import json
from dataclasses import replace
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest


PRODUCT_SRC = Path(__file__).resolve().parents[2] / "product" / "src"
EVALUATION_TOOLS = Path(__file__).resolve().parents[2] / "evaluation_tools"
if str(PRODUCT_SRC) not in sys.path:
    sys.path.insert(0, str(PRODUCT_SRC))
if str(EVALUATION_TOOLS) not in sys.path:
    sys.path.insert(0, str(EVALUATION_TOOLS))

from devtools.product_qualified_runtime import (
    _derive_uaf_causal_measurement,
    assess_uaf_gate_measurement,
    evaluate_measured_uaf_with_product_root_cause,
    prepare_qualified_uaf_gate_reevaluation,
    run_enveloped_uaf_causal_measurement,
)
from vulnerabilityanalysis.models import RuntimeResult
from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2


def _private_json(path, payload):
    raw = (json.dumps(payload, sort_keys=True, separators=(",", ":")) +
           "\n").encode()
    path.write_bytes(raw)
    path.chmod(0o600)
    return raw


def _plan(tmp_path, *, vulnerability_type="use-after-free"):
    source_root = tmp_path / "target"
    source_path = source_root / "src" / "parser.c"
    source_path.parent.mkdir(parents=True, exist_ok=True)
    source_path.write_text("\n" * 60)
    binary = tmp_path / "target.bin"
    input_path = tmp_path / "input.bin"
    binary.write_bytes(b"provider-free-target-pin")
    input_path.write_bytes(b"provider-free-input")
    probe = tmp_path / "probe.py"
    probe.write_text(
        "import hashlib,json,sys\n"
        "binary,input_path,source=sys.argv[1:]\n"
        "input_data=open(input_path,'rb').read()\n"
        "input_sha=hashlib.sha256(input_data).hexdigest()\n"
        "raw={'kind':'FBV2_UAF_RAW_TRACE_V1','evaluation_id':'eval-1',"
        "'input_sha256':input_sha,'events':["
        "{'kind':'input_read','sequence':0,'input_sha256':input_sha,"
        "'input_size':len(input_data)},"
        "{'kind':'allocation','sequence':1,'generation':7,'base':'0x1000',"
        "'size':256,'function_name':'allocate_buffer','source_file':source,"
        "'line':40},"
        "{'kind':'reallocation','sequence':2,'old_base':'0x1000',"
        "'old_size':256,'new_base':'0x2000','new_size':512,'generation':7,"
        "'pointer_before':'0x1080','pointer_after':'0x1080',"
        "'function_name':'realloc_buffer','source_file':source,'line':41},"
        "{'kind':'access','sequence':3,'generation':7,'pointer_base':'0x1080',"
        "'pointer_offset':8,'address':'0x1088','width':8,"
        "'operation':'memmove','function_name':'parse','source_file':source,"
        "'line':42}]}\n"
        "print(json.dumps(raw,sort_keys=True,separators=(',',':')))\n"
        "sys.stderr.write('ERROR: AddressSanitizer: heap-use-after-free on address 0x1088 at pc 0x1\\n'"
        "+'READ of size 8 at 0x1088 thread T0\\n'"
        "+f'#0 0x1 in parse {source}:42:7\\n'"
        "+'0x1088 is located 136 bytes inside of 256-byte region [0x1000,0x1100)\\n'"
        "+'freed by thread T0 here:\\n'"
        "+f'#0 0x2 in realloc_buffer {source}:41:3\\n'"
        "+'previously allocated by thread T0 here:\\n'"
        "+f'#0 0x4 in allocate_buffer {source}:40:2\\n')\n"
        "raise SystemExit(1)\n")
    python = Path(sys.executable).resolve()
    command = [str(python), str(probe), str(binary), str(input_path),
               str(source_path)]
    original_runtime = tmp_path / "original-runtime.json"
    original_physical = tmp_path / "original-physical.json"
    hypothesis = tmp_path / "authenticated-untrusted-sp-hypothesis.json"
    function_map = tmp_path / "measurement-function-map.json"
    build_provenance = tmp_path / "build-provenance.json"
    canonical_hypothesis = {
        "kind": "FBV2_AUTHENTICATED_UNTRUSTED_SP_HYPOTHESIS_V1",
        "trust": "UNTRUSTED_MODEL_HYPOTHESIS",
        "task_id": "task-1", "direction_id": "direction-1",
        "sp_id": "sp-1", "campaign_function_id": "function-1",
        "function_name": "parse", "vulnerability_type": vulnerability_type,
        "hypothesis": "stale pointer after moving realloc",
        "pov_guidance": None, "source_file": None,
        "code_location": "UNKNOWN", "exact_source_location_status": "UNPROVEN",
        "evidence_authority": "NONE", "automatic_discovery": False,
        "discovery_credit": "NOT_CREDITED_BY_LINEAGE_ONLY",
    }
    function_mapping = {
        "kind": "FBV2_PINNED_FUNCTION_INDEX_MAPPING_V1",
        "authority": "PINNED_FUNCTION_INDEX_MAPPING_NOT_MODEL_EXACT_LOCATION",
        "exact_model_source_location_status": "UNPROVEN",
        "task_id": "task-1", "run_id": "run-1",
        "direction_id": "direction-1", "sp_id": "sp-1",
        "campaign_function_id": "function-1", "function_name": "parse",
        "source_file": "src/parser.c", "source_start_line": 40,
        "source_end_line": 50, "source_file_path": str(source_path),
        "source_file_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
        "source_tree_sha256": "3" * 64,
    }
    _private_json(hypothesis, canonical_hypothesis)
    _private_json(function_map, function_mapping)
    for path, payload in ((original_runtime, b"{\"runtime\":true}\n"),
                          (original_physical, b"{\"physical\":true}\n"),
                          (build_provenance,
                           b"{\"profile\":\"synthetic\"}\n")):
        path.write_bytes(payload)
        path.chmod(0o600)
    return {
        "kind": "FBV2_UAF_GATE_REEVALUATION_PLAN_V1",
        "status": "PREPARED_NO_TARGET_REPLAY",
        "evaluation_id": "eval-1",
        "original_task_id": "task-1",
        "original_run_id": "run-1",
        "original_sp_id": "sp-1",
        "original_pov_id": "pov-1",
        "input_sha256": hashlib.sha256(input_path.read_bytes()).hexdigest(),
        "input_size": input_path.stat().st_size,
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "original_binary_path": str(binary),
        "original_binary_sha256":
            hashlib.sha256(binary.read_bytes()).hexdigest(),
        "source_tree_sha256": "3" * 64,
        "harness_sha256": "4" * 64,
        "function_name": "parse",
        "source_file": "src/parser.c",
        "source_root": str(source_root),
        "source_file_path": str(source_path),
        "source_file_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
        "source_start_line": 40,
        "source_end_line": 50,
        "vulnerability_type": vulnerability_type,
        "input_path": str(input_path),
        "binary_path": str(binary),
        "measurement_ledger_path": str(tmp_path / "process-ledger.json"),
        "measurement_work_item_id": "eval-1",
        "measurement_assertion_id": "UAF_CAUSAL",
        "measurement_attempt_id": "ONE_SHOT",
        "measurement_segment": "uaf.causal_trace",
        "measurement_lease_key":
            "eval-1:UAF_CAUSAL:ONE_SHOT:000000:uaf.causal_trace",
        "measurement_process_kind": "AUX_PROCESS",
        "measurement_command": command,
        "measurement_command_pins": {
            str(python): hashlib.sha256(python.read_bytes()).hexdigest(),
            str(probe): hashlib.sha256(probe.read_bytes()).hexdigest(),
        },
        "measurement_emitter_path": str(probe),
        "measurement_emitter_sha256":
            hashlib.sha256(probe.read_bytes()).hexdigest(),
        "measurement_environment": {"LC_ALL": "C", "TZ": "UTC"},
        "measurement_profile": "SYNTHETIC_PROVIDER_FREE",
        "measurement_build_provenance_path": str(build_provenance),
        "measurement_build_provenance_sha256":
            hashlib.sha256(build_provenance.read_bytes()).hexdigest(),
        "measurement_expected_operation": "memmove",
        "measurement_target_command": [str(binary), "-runs=1", str(input_path)],
        "original_runtime_receipt_path": str(original_runtime),
        "original_runtime_receipt_sha256":
            hashlib.sha256(original_runtime.read_bytes()).hexdigest(),
        "original_physical_receipt_path": str(original_physical),
        "original_physical_receipt_sha256":
            hashlib.sha256(original_physical.read_bytes()).hexdigest(),
        "untrusted_sp_hypothesis_path": str(hypothesis),
        "untrusted_sp_hypothesis_sha256":
            hashlib.sha256(hypothesis.read_bytes()).hexdigest(),
        "authenticated_untrusted_sp_hypothesis_sha256": hashlib.sha256(
            json.dumps(canonical_hypothesis, sort_keys=True,
                       separators=(",", ":"), allow_nan=False).encode()).hexdigest(),
        "measurement_function_map_path": str(function_map),
        "measurement_function_map_sha256":
            hashlib.sha256(function_map.read_bytes()).hexdigest(),
        "function_mapping_authority":
            "PINNED_FUNCTION_INDEX_MAPPING_NOT_MODEL_EXACT_LOCATION",
        "exact_model_source_location_status": "UNPROVEN",
        "measurement_timeout_seconds": 5.0,
        "measurement_wall_seconds": 20.0,
        "measurement_output_limit_bytes": 200_000,
    }


def _runtime(source_path, *, access_line=42, stderr_override=None):
    stderr = (
        "ERROR: AddressSanitizer: heap-use-after-free on address 0x1088 at pc 0x1\n"
        "READ of size 8 at 0x1088 thread T0\n"
        f"#0 0x1 in parse {source_path}:{access_line}:7\n"
        "0x1088 is located 136 bytes inside of 256-byte region [0x1000,0x1100)\n"
        "freed by thread T0 here:\n"
        f"#0 0x2 in realloc_buffer {source_path}:41:3\n"
        "previously allocated by thread T0 here:\n"
        f"#0 0x4 in allocate_buffer {source_path}:40:2\n")
    if stderr_override is not None:
        stderr = stderr_override
    return RuntimeResult(
        1, "", stderr, None, False,
        "AddressSanitizer: heap-use-after-free on address 0x1088 at pc 0x1",
        None, "SANITIZER_CRASH",
        crash_triage={"category": "TARGET_CRASH"})


def _raw_trace(plan, *, new_base="0x2000", new_size=512,
               access_address="0x1088", pointer_offset=8,
               operation="memmove", include_input=True):
    events = []
    if include_input:
        events.append({
            "kind": "input_read", "sequence": 0,
            "input_sha256": plan["input_sha256"],
            "input_size": plan["input_size"],
        })
    events.extend([
        {"kind": "allocation", "sequence": 1, "generation": 7,
         "base": "0x1000", "size": 256,
         "function_name": "allocate_buffer",
         "source_file": plan["source_file_path"], "line": 40},
        {"kind": "reallocation", "sequence": 2, "generation": 7,
         "old_base": "0x1000", "old_size": 256,
         "new_base": new_base, "new_size": new_size,
         "pointer_before": "0x1080", "pointer_after": "0x1080",
         "function_name": "realloc_buffer",
         "source_file": plan["source_file_path"], "line": 41},
        {"kind": "access", "sequence": 3, "generation": 7,
         "pointer_base": "0x1080", "pointer_offset": pointer_offset,
         "address": access_address, "width": 8, "operation": operation,
         "function_name": "parse", "source_file": plan["source_file_path"],
         "line": 42},
    ])
    return {"kind": "FBV2_UAF_RAW_TRACE_V1",
            "evaluation_id": plan["evaluation_id"],
            "input_sha256": plan["input_sha256"], "events": events}


def _measurement(tmp_path, plan, runtime=None, **mutations):
    plan_bytes = _private_json(tmp_path / "plan.json", plan)
    result = run_enveloped_uaf_causal_measurement(
        tmp_path / "plan.json",
        expected_plan_sha256=hashlib.sha256(plan_bytes).hexdigest())
    assert result["status"] == "MEASURED"
    measurement = dict(result["measurement"])
    measurement.update(mutations)
    return measurement, result["process_ledger"], result["runtime"]


def test_preparation_authenticates_old_run_without_replaying_target(tmp_path):
    command_root = tmp_path / "command"
    command_root.mkdir()
    command_plan = _plan(command_root)
    source_root = tmp_path / "frozen-source"
    source_file = source_root / "src" / "parser.c"
    source_file.parent.mkdir(parents=True)
    source_file.write_text("\n" * 60)
    lineage = {
        "status": "VERIFIED", "runtime_status": "CRASH_OBSERVED",
        "task_id": "a" * 24, "run_id": "old-run", "sp_id": "b" * 24,
        "direction_id": "c" * 24,
        "input_sha256": command_plan["input_sha256"],
        "binary_sha256": command_plan["binary_sha256"],
        "input_path": command_plan["input_path"],
        "binary_path": command_plan["binary_path"],
        "source_tree_sha256": "3" * 64,
        "harness_sha256": "4" * 64,
        "runtime_receipt_sha256": "7" * 64,
        "physical_receipt_sha256": "8" * 64,
        "runtime_receipt_path": "/old/runtime.json",
        "physical_receipt_path": "/old/physical.json",
    }
    authenticated = {
        "kind": "FBV2_AUTHENTICATED_UNTRUSTED_SP_HYPOTHESIS_V1",
        "trust": "UNTRUSTED_MODEL_HYPOTHESIS",
        "task_id": lineage["task_id"],
        "direction_id": lineage["direction_id"],
        "sp_id": lineage["sp_id"],
        "campaign_function_id": "function-1",
        "function_name": "parse",
        "vulnerability_type": "use-after-free",
        "hypothesis": "stale pointer after moving realloc",
        "pov_guidance": None,
        "source_file": None,
        "code_location": "UNKNOWN",
        "exact_source_location_status": "UNPROVEN",
        "evidence_authority": "NONE",
        "automatic_discovery": False,
        "discovery_credit": "NOT_CREDITED_BY_LINEAGE_ONLY",
    }
    lineage["untrusted_sp_hypothesis"] = authenticated
    lineage["untrusted_sp_hypothesis_sha256"] = hashlib.sha256(
        json.dumps(authenticated, sort_keys=True, separators=(",", ":"),
                   allow_nan=False).encode()).hexdigest()
    function_snapshot = {
        "kind": "FBV2_ORIGINAL_SP_UNTRUSTED_HYPOTHESIS_V1",
        "function_name": "parse", "function_id": "function-1",
        "source_file": "src/parser.c",
        "source_start_line": 40, "source_end_line": 50,
        "vulnerability_type": "use-after-free",
        "hypothesis": "stale pointer after moving realloc",
        "pov_guidance": None,
    }
    adapter = SimpleNamespace(
        binding=SimpleNamespace(qualification=SimpleNamespace(
            source_root=source_root)))
    output = tmp_path / "new-evaluation"
    with patch(
            "devtools.product_qualified_runtime."
            "verify_qualified_pov_runtime_lineage", return_value=lineage), patch(
            "devtools.product_qualified_runtime."
            "_original_sp_hypothesis_snapshot", return_value=function_snapshot):
        prepared = prepare_qualified_uaf_gate_reevaluation(
            adapter, "d" * 24, object(), recheck=lambda: None,
            evaluation_id="eval-1", output_dir=output,
            measurement_command=command_plan["measurement_command"],
            measurement_command_pins=
                command_plan["measurement_command_pins"],
            measurement_binary_path=command_plan["binary_path"],
            measurement_build_provenance_path=
                command_plan["measurement_build_provenance_path"],
            measurement_emitter_path=
                command_plan["measurement_emitter_path"],
            measurement_environment=
                command_plan["measurement_environment"],
            measurement_profile="SYNTHETIC_PROVIDER_FREE",
            measurement_expected_operation="memmove",
            measurement_target_command=command_plan[
                "measurement_target_command"],
            measurement_timeout_seconds=5)
    assert prepared["status"] == "PREPARED_NO_TARGET_REPLAY"
    plan = json.loads((output / "plan.json").read_text())
    assert plan["original_run_id"] == "old-run"
    assert plan["product_gate_evaluated"] is False
    assert plan["original_runtime_receipt_path"] == "/old/runtime.json"
    assert plan["authenticated_untrusted_sp_hypothesis_sha256"] == (
        lineage["untrusted_sp_hypothesis_sha256"])
    assert plan["function_mapping_authority"] == (
        "PINNED_FUNCTION_INDEX_MAPPING_NOT_MODEL_EXACT_LOCATION")
    assert plan["exact_model_source_location_status"] == "UNPROVEN"
    assert json.loads((output / "authenticated-untrusted-sp-hypothesis.json")
                      .read_text()) == authenticated

    mutated_snapshot = dict(function_snapshot)
    mutated_snapshot.update({
        "vulnerability_type": "double-free",
        "hypothesis": "mutable database replacement",
    })
    with patch(
            "devtools.product_qualified_runtime."
            "verify_qualified_pov_runtime_lineage", return_value=lineage), patch(
            "devtools.product_qualified_runtime."
            "_original_sp_hypothesis_snapshot", return_value=mutated_snapshot):
        with pytest.raises(ValueError, match="function span is unproven"):
            prepare_qualified_uaf_gate_reevaluation(
                adapter, "d" * 24, object(), recheck=lambda: None,
                evaluation_id="eval-mutated-db",
                output_dir=tmp_path / "mutated-db-evaluation",
                measurement_command=command_plan["measurement_command"],
                measurement_command_pins=
                    command_plan["measurement_command_pins"],
                measurement_binary_path=command_plan["binary_path"],
                measurement_build_provenance_path=
                    command_plan["measurement_build_provenance_path"],
                measurement_emitter_path=
                    command_plan["measurement_emitter_path"],
                measurement_environment=
                    command_plan["measurement_environment"],
                measurement_profile="SYNTHETIC_PROVIDER_FREE",
                measurement_expected_operation="memmove",
                measurement_target_command=command_plan[
                    "measurement_target_command"],
                measurement_timeout_seconds=5)


def test_measured_uaf_invokes_real_product_root_cause_only_after_admission(
    tmp_path,
):
    plan = _plan(tmp_path)
    measurement, ledger, runtime = _measurement(tmp_path, plan)
    result = evaluate_measured_uaf_with_product_root_cause(
        plan, measurement, runtime,
        target_root=Path(plan["source_root"]),
        harness_path=tmp_path / "fuzzer.c", process_ledger=ledger)
    assert result["status"] == "CAUSAL_LINK_SUPPORTED"
    assert result["product_root_cause_invoked"] is True
    assert result["product_root_cause_verdict"] == "CONFIRMED"
    assert result["product_root_cause_location"].endswith("parser.c:42")
    assert result["original_sp_causal_attribution_status"] == (
        "UNPROVEN_MECHANISM_NOT_STRUCTURED")
    assert result["product_gate_credit"] is False


def test_raw_boolean_claims_cannot_replace_address_relation(tmp_path):
    plan = _plan(tmp_path)
    raw = {
        "kind": "FBV2_UAF_RAW_TRACE_V1",
        "evaluation_id": plan["evaluation_id"],
        "input_sha256": plan["input_sha256"],
        "input_consumed_sequence": 0,
        # These asserted booleans are deliberately ignored by the derivation.
        "stale_pointer_observed": True,
        "sp_condition_reached": True,
        "events": [
            {"kind": "input_read", "sequence": 0,
             "input_sha256": plan["input_sha256"],
             "input_size": plan["input_size"]},
            {"kind": "allocation", "sequence": 1, "generation": 7,
             "base": "0x1000", "size": 256,
             "function_name": "allocate_buffer",
             "source_file": plan["source_file_path"], "line": 40},
            {"kind": "reallocation", "sequence": 2,
             "old_base": "0x1000", "old_size": 256,
             "new_base": "0x2000", "new_size": 512, "generation": 7,
             "pointer_before": "0x1080", "pointer_after": "0x2080",
             "function_name": "realloc_buffer",
             "source_file": plan["source_file_path"], "line": 41},
            {"kind": "access", "sequence": 3, "generation": 7,
             "pointer_base": "0x2080", "pointer_offset": 8,
             "address": "0x1088",
             "width": 8, "operation": "memmove",
             "function_name": "parse",
             "source_file": plan["source_file_path"], "line": 42},
        ],
    }
    with pytest.raises(ValueError, match="causal relation"):
        _derive_uaf_causal_measurement(
            plan, raw, _runtime(plan["source_file_path"]).stderr)


def test_runner_receipt_binds_exact_evaluation_lease_and_command(tmp_path):
    plan = _plan(tmp_path)
    measurement, ledger, _ = _measurement(tmp_path, plan)
    physical = json.loads(Path(measurement["physical_receipt_path"]).read_text())
    state, _ = ledger.receipt_snapshot()
    matches = [row for row in state["finished"]
               if row["key"] == plan["measurement_lease_key"]]
    assert len(matches) == 1
    assert physical["lease"] == matches[0]
    assert physical["lease"]["kind"] == "AUX_PROCESS"
    assert physical["command"] == plan["measurement_command"]
    assert physical["evaluation_id"] == plan["evaluation_id"]


def test_offset_access_in_same_freed_object_is_supported(tmp_path):
    plan = _plan(tmp_path)
    derived = _derive_uaf_causal_measurement(
        plan, _raw_trace(plan), _runtime(plan["source_file_path"]).stderr)
    assert derived["pointer_base"] == "0x1080"
    assert derived["pointer_offset"] == 8
    assert derived["access_address"] == "0x1088"


def test_realloc_null_or_invalid_new_size_is_rejected(tmp_path):
    plan = _plan(tmp_path)
    stderr = _runtime(plan["source_file_path"]).stderr
    for new_base, new_size in (("0x0", 512), ("0x2000", -1),
                               ("0x2000", 0)):
        with pytest.raises(ValueError):
            _derive_uaf_causal_measurement(
                plan, _raw_trace(plan, new_base=new_base,
                                 new_size=new_size), stderr)


def test_asan_fault_address_must_equal_raw_access_address(tmp_path):
    plan = _plan(tmp_path)
    wrong = _runtime(plan["source_file_path"]).stderr.replace(
        "address 0x1088", "address 0xDEADBEEF").replace(
        "at 0x1088", "at 0xDEADBEEF")
    with pytest.raises(ValueError, match="address and region"):
        _derive_uaf_causal_measurement(plan, _raw_trace(plan), wrong)


def test_asan_width_and_lifetime_frames_must_match_raw_events(tmp_path):
    plan = _plan(tmp_path)
    stderr = _runtime(plan["source_file_path"]).stderr
    wrong_width = stderr.replace("READ of size 8", "READ of size 4")
    with pytest.raises(ValueError, match="differs from ASan"):
        _derive_uaf_causal_measurement(plan, _raw_trace(plan), wrong_width)
    wrong_free = stderr.replace("in realloc_buffer", "in unrelated_free")
    with pytest.raises(ValueError, match="differs from ASan"):
        _derive_uaf_causal_measurement(plan, _raw_trace(plan), wrong_free)


def test_input_sequence_number_without_input_event_is_rejected(tmp_path):
    plan = _plan(tmp_path)
    raw = _raw_trace(plan, include_input=False)
    raw["input_consumed_sequence"] = 0
    with pytest.raises(ValueError, match="cardinality"):
        _derive_uaf_causal_measurement(
            plan, raw, _runtime(plan["source_file_path"]).stderr)


def test_wrong_operation_is_not_original_measurement_operation(tmp_path):
    plan = _plan(tmp_path)
    with pytest.raises(ValueError, match="differs from ASan"):
        _derive_uaf_causal_measurement(
            plan, _raw_trace(plan, operation="not_memmove"),
            _runtime(plan["source_file_path"]).stderr)


def test_md4c_profile_requires_actual_target_execution_receipt(tmp_path):
    plan = _plan(tmp_path)
    plan["measurement_profile"] = "MD4C_INSTRUMENTED_V1"
    plan["measurement_environment"]["ASAN_OPTIONS"] = (
        "abort_on_error=1:detect_leaks=0:symbolize=1")
    stderr = _runtime(plan["source_file_path"]).stderr
    raw = _raw_trace(plan)
    raw["target_execution"] = {
        "binary_path": plan["binary_path"],
        "binary_sha256": plan["binary_sha256"],
        "input_path": plan["input_path"],
        "input_sha256": plan["input_sha256"],
        "command": plan["measurement_target_command"],
        "returncode": 1, "signal": None,
        "stdout_sha256": hashlib.sha256(b"").hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest(),
    }
    assert _derive_uaf_causal_measurement(
        plan, raw, stderr)["target_execution"]["returncode"] == 1
    raw["target_execution"]["binary_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="target execution is unproven"):
        _derive_uaf_causal_measurement(plan, raw, stderr)


def test_approved_plan_change_is_rejected_before_ledger_creation(tmp_path):
    plan = _plan(tmp_path)
    raw = _private_json(tmp_path / "plan.json", plan)
    approved = hashlib.sha256(raw).hexdigest()
    plan["measurement_timeout_seconds"] = 4.0
    _private_json(tmp_path / "plan.json", plan)
    with pytest.raises(ValueError, match="approved UAF plan changed"):
        run_enveloped_uaf_causal_measurement(
            tmp_path / "plan.json", expected_plan_sha256=approved)
    assert not (tmp_path / "process-ledger.json").exists()


def test_original_frozen_receipt_change_is_rejected_before_ledger(tmp_path):
    plan = _plan(tmp_path)
    raw = _private_json(tmp_path / "plan.json", plan)
    Path(plan["original_runtime_receipt_path"]).write_text("changed\n")
    with pytest.raises(ValueError, match="artifact changed"):
        run_enveloped_uaf_causal_measurement(
            tmp_path / "plan.json",
            expected_plan_sha256=hashlib.sha256(raw).hexdigest())
    assert not (tmp_path / "process-ledger.json").exists()


@pytest.mark.parametrize("path_key", [
    "untrusted_sp_hypothesis_path",
    "measurement_function_map_path",
])
def test_hypothesis_and_function_map_tamper_are_rejected_before_ledger(
    tmp_path, path_key,
):
    plan = _plan(tmp_path)
    raw = _private_json(tmp_path / "plan.json", plan)
    artifact = Path(plan[path_key])
    artifact.write_bytes(artifact.read_bytes() + b" ")
    with pytest.raises(ValueError, match="artifact changed"):
        run_enveloped_uaf_causal_measurement(
            tmp_path / "plan.json",
            expected_plan_sha256=hashlib.sha256(raw).hexdigest())
    assert not (tmp_path / "process-ledger.json").exists()


@pytest.mark.parametrize("mutation", [
    {"original_sp_id": None},
    {"measurement_command_pins": {}},
    {"measurement_emitter_path": "/untrusted/emitter"},
])
def test_incomplete_plan_provenance_is_rejected_before_ledger(
    tmp_path, mutation,
):
    plan = _plan(tmp_path)
    plan.update(mutation)
    raw = _private_json(tmp_path / "plan.json", plan)
    with pytest.raises((ValueError, OSError)):
        run_enveloped_uaf_causal_measurement(
            tmp_path / "plan.json",
            expected_plan_sha256=hashlib.sha256(raw).hexdigest())
    assert not (tmp_path / "process-ledger.json").exists()


def test_malformed_trace_preserves_one_shot_outputs_and_incomplete_receipt(
    tmp_path,
):
    plan = _plan(tmp_path)
    probe = Path(plan["measurement_emitter_path"])
    probe.write_text(
        "import sys\n"
        "print('not-json')\n"
        "sys.stderr.write('captured-before-parse-failure\\n')\n"
        "raise SystemExit(1)\n")
    digest = hashlib.sha256(probe.read_bytes()).hexdigest()
    plan["measurement_command_pins"][str(probe)] = digest
    plan["measurement_emitter_sha256"] = digest
    raw = _private_json(tmp_path / "plan.json", plan)
    approved = hashlib.sha256(raw).hexdigest()
    result = run_enveloped_uaf_causal_measurement(
        tmp_path / "plan.json", expected_plan_sha256=approved)
    assert result["status"] == "INCOMPLETE"
    assert (tmp_path / "stdout.raw").read_bytes() == b"not-json\n"
    assert b"captured-before-parse-failure" in (
        tmp_path / "asan.stderr.raw").read_bytes()
    incomplete = json.loads((tmp_path / "incomplete.json").read_text())
    assert incomplete["automatic_retry_permitted"] is False
    assert (tmp_path / "execution.json").is_file()
    with pytest.raises(ValueError, match="one-shot identity"):
        run_enveloped_uaf_causal_measurement(
            tmp_path / "plan.json", expected_plan_sha256=approved)


def test_runtime_result_mismatch_never_invokes_product_root_cause(tmp_path):
    plan = _plan(tmp_path)
    measurement, ledger, runtime = _measurement(tmp_path, plan)
    mismatched = replace(runtime, exit_code=-6, signal=6)
    result = evaluate_measured_uaf_with_product_root_cause(
        plan, measurement, mismatched,
        target_root=Path(plan["source_root"]),
        harness_path=tmp_path / "fuzzer.c", process_ledger=ledger)
    assert result["status"] == "UNPROVEN"
    assert result["reason"] == (
        "RUNTIME_RESULT_NOT_ISSUED_BY_MEASUREMENT_EXECUTION")
    assert result["product_root_cause_invoked"] is False


@pytest.mark.parametrize("mutation, reason", [
    ({"access_frame": {"function_name": "other",
                       "source_file": "/tmp/target/src/parser.c", "line": 42}},
     "ASAN_ACCESS_OUTSIDE_ORIGINAL_FUNCTION_SPAN"),
    ({"access_frame": {"function_name": "parse",
                       "source_file": "/tmp/target/src/parser.c", "line": 90}},
     "ASAN_ACCESS_OUTSIDE_ORIGINAL_FUNCTION_SPAN"),
    ({"sanitizer_family": "out-of-bounds"},
     "UAF_CAUSAL_CONDITION_UNPROVEN"),
    ({"sp_condition_reached": None}, "UAF_CAUSAL_CONDITION_UNPROVEN"),
    ({"accessed_object": "heap-object-2"}, "UAF_CAUSAL_CONDITION_UNPROVEN"),
])
def test_negative_measurements_never_reach_product_root_cause(
    tmp_path, mutation, reason,
):
    plan = _plan(tmp_path)
    measurement, ledger, runtime = _measurement(
        tmp_path, plan, **mutation)
    result = evaluate_measured_uaf_with_product_root_cause(
        plan, measurement, runtime,
        target_root=Path(plan["source_root"]),
        harness_path=tmp_path / "fuzzer.c", process_ledger=ledger)
    assert result["status"] == "UNPROVEN"
    assert result["reason"] == reason
    assert result["product_root_cause_invoked"] is False
    assert result["product_gate_credit"] is False


def test_runtime_stderr_hash_mismatch_is_rejected(tmp_path):
    plan = _plan(tmp_path)
    measurement, ledger, runtime = _measurement(
        tmp_path, plan, asan_stderr_sha256="0" * 64)
    result = assess_uaf_gate_measurement(
        plan, measurement, runtime_stderr=runtime.stderr,
        process_ledger=ledger)
    assert result["status"] == "UNPROVEN"
    assert result["reason"] == "MEASUREMENT_IDENTITY_MISMATCH"


def test_self_authored_receipt_not_in_supplied_ledger_is_rejected(tmp_path):
    plan = _plan(tmp_path)
    measurement, _original_ledger, runtime = _measurement(tmp_path, plan)
    unrelated = PersistentProcessLedgerV2.create(
        tmp_path / "unrelated-ledger.json", wall_total_seconds=30,
        fuzz_total_seconds=0)
    result = assess_uaf_gate_measurement(
        plan, measurement, runtime_stderr=runtime.stderr,
        process_ledger=unrelated)
    assert result["status"] == "UNPROVEN"
    assert result["reason"] == "UAF_CAUSAL_CONDITION_UNPROVEN"


def test_non_uaf_original_sp_cannot_claim_observed_uaf(tmp_path):
    plan = _plan(tmp_path, vulnerability_type="buffer-overflow")
    measurement, ledger, runtime = _measurement(tmp_path, plan)
    result = assess_uaf_gate_measurement(
        plan, measurement, runtime_stderr=runtime.stderr,
        process_ledger=ledger)
    assert result["status"] == "UNPROVEN"
    assert result["reason"] == "MEASUREMENT_IDENTITY_MISMATCH"


def test_claimed_access_line_must_exist_in_raw_asan_stack(tmp_path):
    plan = _plan(tmp_path)
    measurement, ledger, runtime = _measurement(
        tmp_path, plan,
        access_frame={"function_name": "parse",
                      "source_file": plan["source_file_path"], "line": 43})
    result = assess_uaf_gate_measurement(
        plan, measurement, runtime_stderr=runtime.stderr,
        process_ledger=ledger)
    assert result["status"] == "UNPROVEN"
    assert result["reason"] == "ASAN_ACCESS_OUTSIDE_ORIGINAL_FUNCTION_SPAN"


def test_empty_asan_stderr_cannot_support_measurement(tmp_path):
    plan = _plan(tmp_path)
    measurement, ledger, _runtime_result = _measurement(tmp_path, plan)
    result = assess_uaf_gate_measurement(
        plan, measurement, runtime_stderr="",
        process_ledger=ledger)
    assert result["status"] == "UNPROVEN"
    assert result["reason"] == "MEASUREMENT_SCHEMA_OR_IDENTITY_MISMATCH"


def test_symlinked_trace_receipt_is_rejected_before_read(tmp_path):
    plan = _plan(tmp_path)
    measurement, ledger, runtime = _measurement(tmp_path, plan)
    trace = Path(measurement["trace_receipt_path"])
    original = tmp_path / "original-trace.json"
    trace.rename(original)
    trace.symlink_to(original)
    result = assess_uaf_gate_measurement(
        plan, measurement, runtime_stderr=runtime.stderr,
        process_ledger=ledger)
    assert result["status"] == "UNPROVEN"
