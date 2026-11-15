"""Provider-free official V2 interleaved route preflight and state admission.

The externally pinned route is development evidence, not a Blind 3 approval.
This CLI has no model, Target, Oracle, Scan-completion or Fuzzer command.
"""

from __future__ import annotations

import argparse
from dataclasses import fields
import json
from pathlib import Path
import sys
import time

from dev_blind3_official_interleaved_adapter import (
    OfficialInterleavedAdapter, _qualified, load_route_spec, sha256,
)
from dev_global_appserver_bridge import DevelopmentGlobalAppServer
from dev_global_request_ledger import DevelopmentBudget, DevelopmentRequestLedger
from dev_persistent_physical_fuzz_ledger import PersistentPhysicalFuzzLedger
from vulnerabilityanalysis.official_harness import issue_official_pinned_qualification


def reissue_product_qualification(spec: dict):
    pins = spec["qualification"]
    started = time.monotonic()
    qualified = issue_official_pinned_qualification(
        contract_path=Path(pins["contract_path"]),
        approved_contract_sha256=pins["contract_sha256"],
        source_root=Path(pins["source_root"]),
        harness=Path(pins["harness"]), binary=Path(pins["binary"]),
        normal_seed=Path(pins["normal_seed"]),
        oss_fuzz_checkout=Path(pins["oss_fuzz_checkout"]),
        upstream_checkout=Path(pins["upstream_checkout"]),
    )
    if qualified is None:
        raise ValueError("product did not issue official V2 qualification")
    _qualified(spec, qualified)
    return qualified, round((time.monotonic() - started) * 1000, 3)


def _budget(spec: dict) -> DevelopmentBudget:
    names = {field.name for field in fields(DevelopmentBudget)}
    row = spec["model_budget"]
    if type(row) is not dict or set(row) != names:
        raise ValueError("official interleaved model budget schema changed")
    return DevelopmentBudget(**row)


def _backend(spec: dict, model: DevelopmentRequestLedger,
             physical: PersistentPhysicalFuzzLedger) -> DevelopmentGlobalAppServer:
    return DevelopmentGlobalAppServer(
        ledger=model, physical_ledger=physical, role_models=spec["role_models"],
        cwd=Path(spec["model_cwd"]), wire_cwd="/work",
        launch_prefix=[spec["python_executable"], spec["sandbox_launcher"]],
        executable=spec["codex_executable"],
        executable_sha256=spec["codex_executable_sha256"],
        model=spec["default_model"], effort=spec["default_effort"],
        timeout_seconds=300, event_log_path=Path(spec["event_log_path"]),
    )


def prepare(spec_path: Path, expected_sha256: str) -> dict:
    spec = load_route_spec(spec_path, expected_sha256)
    qualified, qualification_wall_ms = reissue_product_qualification(spec)
    budget = _budget(spec)
    model = DevelopmentRequestLedger.create(
        budget, Path(spec["model_ledger_path"]))
    physical = PersistentPhysicalFuzzLedger.create(
        Path(spec["physical_ledger_path"]),
        total_seconds=spec["physical_resource_seconds"])
    backend = _backend(spec, model, physical)
    adapter = OfficialInterleavedAdapter(
        route_spec=spec_path, route_sha256=expected_sha256,
        qualification=qualified, ledger=model, physical_ledger=physical,
        backend=backend)
    state = adapter.prepare()
    return {
        "status": "DEV_PUBLIC_V2_NOT_READY", "official_v2_qualified": True,
        "route_sha256": expected_sha256, "state_path": str(state),
        "worklist_sha256": spec["worklist_sha256"],
        "adapter_sha256": sha256(Path(__file__).with_name(
            "dev_blind3_official_interleaved_adapter.py")),
        "runner_sha256": sha256(Path(__file__)),
        "qualification_wall_ms": qualification_wall_ms,
        "model_logical": model.logical, "model_physical": model.physical,
        "target_runs": 0, "oracle_queries": 0, "blind3_runs": 0,
        "scan_count": adapter.read()["scan_count"],
    }


def restore_and_inspect(spec_path: Path, expected_sha256: str) -> dict:
    """Restore then inspect; recovery may persist terminal normalization."""
    spec = load_route_spec(spec_path, expected_sha256)
    qualified, qualification_wall_ms = reissue_product_qualification(spec)
    budget = _budget(spec)
    model = DevelopmentRequestLedger.restore(
        Path(spec["model_ledger_path"]), budget)
    physical = PersistentPhysicalFuzzLedger.restore(
        Path(spec["physical_ledger_path"]),
        total_seconds=spec["physical_resource_seconds"])
    backend = _backend(spec, model, physical)
    adapter = OfficialInterleavedAdapter(
        route_spec=spec_path, route_sha256=expected_sha256,
        qualification=qualified, ledger=model, physical_ledger=physical,
        backend=backend)
    state = adapter.read()
    return {
        "status": "DEV_PUBLIC_V2_NOT_READY", "official_v2_qualified": True,
        "route_sha256": expected_sha256,
        "qualification_wall_ms": qualification_wall_ms,
        "work_item_count": len(state["work_items"]),
        "scan_count": state["scan_count"],
        "completed_work_items": state["completed_work_items"],
        "model_logical": model.logical, "model_physical": model.physical,
        "target_runs": 0, "oracle_queries": 0, "blind3_runs": 0,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--prepare", action="store_true")
    mode.add_argument("--read", action="store_true",
                      help="restore/inspect; may persist terminal normalization")
    args = parser.parse_args()
    spec = load_route_spec(args.spec, args.sha256)
    if args.preflight:
        _, wall_ms = reissue_product_qualification(spec)
        result = {"status": "DEV_PUBLIC_V2_NOT_READY",
                  "official_v2_qualified": True,
                  "qualification_wall_ms": wall_ms,
                  "model_calls": 0, "target_runs": 0,
                  "oracle_queries": 0, "blind3_runs": 0}
    elif args.prepare:
        result = prepare(args.spec, args.sha256)
    else:
        result = restore_and_inspect(args.spec, args.sha256)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
