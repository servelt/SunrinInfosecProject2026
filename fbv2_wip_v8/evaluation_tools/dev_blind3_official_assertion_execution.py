"""Stage16 provider-free wiring from a pinned Assertion handoff to product APIs.

Only fixed synthetic call methods may run. Real Assertion build, seed probe,
GDB, Guided campaigns, replay and Gate require a future physical wall/process
envelope and a separate live approval.  This module cannot authorize --execute.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
from dataclasses import replace

from dev_blind3_official_assertion_handoff import (
    OfficialInterleavedAdapter, ProductFuzzPhysicalRunner,
    _pinned_file, _private_companion_json, load_execution_contract, sha256,
)
from vulnerabilityanalysis import interleaved_assertion_dev, runtime
from vulnerabilityanalysis import interleaved_dev as base
from vulnerabilityanalysis.interleaved_roles_dev import _hp_context
from vulnerabilityanalysis.models import Assertion
from vulnerabilityanalysis.source import SourceRepository

KIND = "OFFICIAL_V2_ASSERTION_WIRING_DEV_V1"
STATUS = "DEV_SYNTHETIC_ONLY"
SPEC_KEYS = frozenset({
    "kind", "status", "route_sha256", "stage15_contract_path",
    "stage15_contract_sha256", "harness_sha256", "binary_sha256",
    "seed_sha256", "builder_sha256", "manifest_sha256", "runtime_sha256",
    "runtime_path", "stage16_adapter_path",
    "product_handoff_validator_sha256", "stage16_adapter_sha256",
    "wall_process_envelope", "synthetic_guided_seconds",
    "oracle_queries", "blind3_runs", "target_executions",
})


class SyntheticProductCalls:
    """Fixed no-process stand-in for both existing product API signatures."""

    __slots__ = ("execute_status", "failure_mode", "manifest_drift_to",
                 "calls", "guided_runner")

    def __init__(self, *, execute_status: str = "HELD_FOR_EXECUTION",
                 failure_mode: str = "NONE",
                 manifest_drift_to: Path | None = None):
        if (execute_status not in {"HELD_FOR_EXECUTION", "VIOLATED", "BLOCKED"} or
                failure_mode not in {"NONE", "AFTER_PARTIAL_RUNTIME",
                                     "DRIFT_ASSERTION_ID"} or
                manifest_drift_to is not None and
                not isinstance(manifest_drift_to, Path)):
            raise ValueError("invalid fixed synthetic Assertion behavior")
        self.execute_status = execute_status
        self.failure_mode = failure_mode
        self.manifest_drift_to = manifest_drift_to
        self.calls: list[dict] = []
        self.guided_runner = None

    def execute_assertion(self, assertion: Assertion, original_source: Path,
                          before_line: int, input_path: Path, output_dir: Path,
                          build_command: list[str], run_command: list[str],
                          *, source_context: list[dict]):
        self.calls.append({"api": "execute_assertion",
                           "assertion_id": assertion.assertion_id,
                           "source": str(original_source),
                           "line": before_line, "seed": str(input_path),
                           "build_command": list(build_command),
                           "run_command": list(run_command),
                           "context_count": len(source_context)})
        if self.failure_mode == "AFTER_PARTIAL_RUNTIME":
            (output_dir / "runtime.json").write_text('{"partial":',
                                                     encoding="utf-8")
            raise runtime.RuntimeCleanupError(
                "synthetic cleanup failure", "partial", "")
        if self.manifest_drift_to is not None:
            os.environ["VA_ASSERTION_BUILD_MANIFEST"] = str(
                self.manifest_drift_to)
        if self.failure_mode == "DRIFT_ASSERTION_ID":
            return replace(assertion, status=self.execute_status,
                           assertion_id="different-synthetic-assertion"), None
        return replace(assertion, status=self.execute_status), None

    def guided_fuzz_assertion(self, assertion: Assertion, original_source: Path,
                              before_line: int, seed: Path, output_dir: Path,
                              build_command: list[str], run_command: list[str],
                              *, seconds: int, source_context: list[dict],
                              guarded_runner: ProductFuzzPhysicalRunner):
        self.calls.append({"api": "guided_fuzz_assertion",
                           "assertion_id": assertion.assertion_id,
                           "source": str(original_source),
                           "line": before_line, "seed": str(seed),
                           "build_command": list(build_command),
                           "run_command": list(run_command),
                           "seconds": seconds,
                           "context_count": len(source_context)})
        self.guided_runner = guarded_runner
        return {"status": "SYNTHETIC_WIRING_ONLY"}


_SYNTH_EXECUTE = SyntheticProductCalls.execute_assertion
_SYNTH_GUIDED = SyntheticProductCalls.guided_fuzz_assertion


def _prepare_synthetic_output(path: Path) -> None:
    """Create a private empty fake-output directory without following links."""
    parent = path.parent
    if path.name != "synthetic-output" or parent.is_symlink():
        raise ValueError("Stage16 synthetic output path changed")
    descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY |
                         getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(descriptor)
        if (info.st_uid != os.getuid() or
                stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError("Stage16 synthetic output parent is unsafe")
        os.mkdir(path.name, mode=0o700, dir_fd=descriptor)
        os.fsync(descriptor)
        child_fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY |
                           getattr(os, "O_NOFOLLOW", 0), dir_fd=descriptor)
        try:
            child = os.fstat(child_fd)
            if (child.st_uid != os.getuid() or
                    stat.S_IMODE(child.st_mode) != 0o700):
                raise ValueError("Stage16 synthetic output directory is unsafe")
        finally:
            os.close(child_fd)
    finally:
        os.close(descriptor)


def load_wiring_contract(path: Path, digest: str,
                         adapter: OfficialInterleavedAdapter) -> dict:
    """Recheck the entire Stage15 execution identity plus runtime source."""
    contract_path = _pinned_file(str(path), digest, private=True)
    row = json.loads(contract_path.read_text(encoding="utf-8"))
    if (type(row) is not dict or set(row) != SPEC_KEYS or
            row["kind"] != KIND or row["status"] != STATUS or
            row["route_sha256"] != adapter.route_sha256 or
            row["wall_process_envelope"] != "UNPROVEN_BLOCK_ACTUAL" or
            row["oracle_queries"] != 0 or row["blind3_runs"] != 0 or
            row["target_executions"] != 0 or
            row["runtime_path"] != str(Path(runtime.__file__).resolve()) or
            row["stage16_adapter_path"] != str(Path(__file__).resolve()) or
            type(row["synthetic_guided_seconds"]) is not int or
            not 1 <= row["synthetic_guided_seconds"] <= 60):
        raise ValueError("Stage16 synthetic wiring contract changed")
    stage15 = load_execution_contract(
        Path(row["stage15_contract_path"]), row["stage15_contract_sha256"],
        adapter)
    if any(row[name] != stage15[source] for name, source in (
            ("harness_sha256", "qualification_harness_sha256"),
            ("binary_sha256", "qualification_binary_sha256"),
            ("seed_sha256", "qualification_seed_sha256"),
            ("builder_sha256", "builder_sha256"),
            ("manifest_sha256", "manifest_sha256"))):
        raise ValueError("Stage16 differs from qualified Stage15 execution")
    for filename, expected in (
            (Path(row["runtime_path"]), row["runtime_sha256"]),
            (Path(interleaved_assertion_dev.__file__).resolve(),
             row["product_handoff_validator_sha256"]),
            (Path(row["stage16_adapter_path"]), row["stage16_adapter_sha256"])):
        _pinned_file(str(filename), expected)
    return row


def run_synthetic_assertion_wiring(
        adapter: OfficialInterleavedAdapter, ordinal: int, proposal_index: int,
        wiring_contract_path: Path, wiring_contract_sha256: str,
        *, synthetic_calls: SyntheticProductCalls | None = None) -> Path:
    """Exercise the real product call signatures with fake functions only.

    A persisted ARMED receipt precedes either fake call. Any error leaves the
    ROLE_GUARD pending, preserves the original exception, and prohibits retry.
    """
    if (type(synthetic_calls) is not SyntheticProductCalls or
            SyntheticProductCalls.execute_assertion is not _SYNTH_EXECUTE or
            SyntheticProductCalls.guided_fuzz_assertion is not _SYNTH_GUIDED):
        raise RuntimeError("STOPPED_EXECUTION_ENVELOPE_UNPROVEN")
    with adapter._role_lock():
        adapter._check_identity()
        spec = load_wiring_contract(wiring_contract_path,
                                    wiring_contract_sha256, adapter)
        state = adapter.read()
        if (type(ordinal) is not int or type(proposal_index) is not int or
                not 0 <= ordinal < len(state["work_items"])):
            raise ValueError("Stage16 work item or proposal index invalid")
        handoffs = [row for row in state.get("assertion_execution_handoffs", [])
                    if row["ordinal"] == ordinal and
                    row["proposal_index"] == proposal_index]
        if len(handoffs) != 1 or handoffs[0]["status"] != "EXECUTION_HANDOFF_READY":
            raise ValueError("Stage16 lacks exactly one settled handoff")
        handoff = handoffs[0]
        if (handoff["contract_path"] != spec["stage15_contract_path"] or
                handoff["contract_sha256"] !=
                spec["stage15_contract_sha256"] or
                any(row["ordinal"] == ordinal and
                    row["proposal_index"] == proposal_index for row in
                    state.get("assertion_execution_attempts", []))):
            raise ValueError("Stage16 handoff changed or was already reserved")
        item = state["work_items"][ordinal]
        source_root = adapter.qualification.source_root
        harness = base._pinned_harness(state, Path(state["source_run"]),
                                       source_root)
        repository = SourceRepository(source_root, harness.function_catalog)
        span = base._pinned_span(repository, item)
        source = Path(item["source_file"])
        if not source.is_absolute():
            source = source_root / source
        source = source.resolve(strict=True)
        if (not source.is_relative_to(source_root.resolve(strict=True)) or
                sha256(source) != item["source_file_sha256"]):
            raise ValueError("Stage16 source file differs from SourceSpan")
        proposals = json.loads(Path(handoff["proposal_path"]).read_text())
        proposal = proposals["assertions"][proposal_index]
        assertion = Assertion(**proposal)
        if assertion.assertion_id != handoff["assertion_id"]:
            raise ValueError("Stage16 Assertion proposal identity changed")
        try:
            site, line_text = assertion.source_location.rsplit(":", 1)
            line = int(line_text)
        except (AttributeError, ValueError) as exc:
            raise ValueError("Stage16 Assertion source location invalid") from exc
        if (not span.start_line <= line <= span.end_line or
                Path(site).parts != source.parts[-len(Path(site).parts):]):
            raise ValueError("Stage16 Assertion site differs from SourceSpan")
        context, context_pins = _hp_context(adapter.state_path, item)
        base._check_context_file_pins(context_pins)
        physical_runner = ProductFuzzPhysicalRunner(adapter.physical_ledger,
                                                    kind="HP")
        if (physical_runner.ledger is not adapter.physical_ledger or
                physical_runner.ledger.path !=
                Path(adapter.spec["physical_ledger_path"])):
            raise ValueError("Stage16 Guided runner split physical ledger")
        model_before = sha256(adapter.ledger.checkpoint_path)
        physical_before = sha256(adapter.physical_ledger.path)
        guard_id = ""
        attempt_path = Path(handoff["companion_path"]).with_name(
            "ASSERTION_EXECUTION_ATTEMPT.json")
        anchor = {
            "kind": interleaved_assertion_dev.ATTEMPT_ANCHOR_KIND,
            "ordinal": ordinal, "work_item_id": item["work_item_id"],
            "assertion_id": assertion.assertion_id,
            "proposal_index": proposal_index,
            "handoff_companion_sha256": handoff["companion_sha256"],
            "attempt_path": str(attempt_path), "attempt_sha256": None,
            "contract_path": str(wiring_contract_path),
            "contract_sha256": wiring_contract_sha256,
            "guard_id": guard_id, "status": "ARMED",
        }
        receipt = {
            "kind": interleaved_assertion_dev.ATTEMPT_KIND,
            "guard_id": guard_id, "status": "ARMED",
            "ordinal": ordinal, "work_item_id": item["work_item_id"],
            "assertion_id": assertion.assertion_id,
            "proposal_index": proposal_index,
            "handoff_companion_sha256": handoff["companion_sha256"],
            "contract_sha256": wiring_contract_sha256,
            "source_file_sha256": item["source_file_sha256"],
            "source_span_sha256": item["source_span_sha256"],
            "harness_sha256": spec["harness_sha256"],
            "binary_sha256": spec["binary_sha256"],
            "seed_sha256": spec["seed_sha256"],
            "builder_sha256": spec["builder_sha256"],
            "manifest_sha256": spec["manifest_sha256"],
            "runtime_sha256": spec["runtime_sha256"],
            "model_ledger_before_sha256": model_before,
            "model_ledger_after_sha256": model_before,
            "physical_ledger_before_sha256": physical_before,
            "physical_ledger_after_sha256": physical_before,
            "synthetic_execute_calls": 0, "synthetic_guided_calls": 0,
            "target_execution_count": 0, "guided_fuzz_seconds": 0,
            "instrumented_assertion_state": "NOT_RUN",
            "test_original_target_state": "NOT_RUN",
            "official_asan_replay_state": "NOT_RUN",
            "root_cause_state": "NOT_RUN", "gate_state": "NOT_RUN",
            "verified": False,
        }
        adapter._write_role_guard("assertion_execution_synthetic", ordinal,
                                  item["work_item_id"], "PENDING",
                                  assertion.assertion_id)
        # Bind the write-ahead execution receipt to the same durable role
        # guard nonce rather than an unrelated local identifier.
        guard_id = adapter._active_guard[3]
        anchor["guard_id"] = guard_id
        receipt["guard_id"] = guard_id
        try:
            state.setdefault("assertion_execution_attempts", []).append(anchor)
            base._private_json(adapter.state_path, state, replace=True)
            _private_companion_json(attempt_path, adapter.state_path.parent,
                                    receipt, replace=False)
            adapter._check_identity(allow_pending_guard=True)
            if load_wiring_contract(wiring_contract_path,
                                    wiring_contract_sha256, adapter) != spec:
                raise ValueError("Stage16 identity changed before synthetic call")
            output = attempt_path.parent / "synthetic-output"
            _prepare_synthetic_output(output)
            build_command = load_execution_contract(
                Path(spec["stage15_contract_path"]),
                spec["stage15_contract_sha256"], adapter)["build_command"]
            run_command = ["{binary}", "{input}"]
            result, _evidence = synthetic_calls.execute_assertion(
                assertion, source, line, adapter.qualification.normal_seed,
                output, build_command, run_command, source_context=context)
            if not isinstance(result, Assertion):
                raise ValueError("synthetic Assertion callback returned wrong type")
            immutable = ("assertion_id", "worker_id", "direction_id", "function",
                         "source_location", "safe_assumption",
                         "runtime_expression", "required_context",
                         "source_function_analysis", "safe_judgment",
                         "safe_reason")
            if any(getattr(result, name) != getattr(assertion, name)
                   for name in immutable):
                raise ValueError("synthetic Assertion return identity changed")
            # A first execution can change environment, Context, source, or a
            # ledger. Do not dispatch Guided until those pins are rechecked.
            if (sha256(adapter.ledger.checkpoint_path) != model_before or
                    sha256(adapter.physical_ledger.path) != physical_before):
                raise ValueError("synthetic Assertion changed a physical ledger")
            adapter._check_identity(allow_pending_guard=True)
            if load_wiring_contract(wiring_contract_path,
                                    wiring_contract_sha256, adapter) != spec:
                raise ValueError("Stage16 identity changed before Guided")
            guided_calls = 0
            if result.status in {"HELD_FOR_EXECUTION", "VIOLATED"}:
                synthetic_calls.guided_fuzz_assertion(
                    result, source, line, adapter.qualification.normal_seed,
                    output / "guided_fuzz", build_command, run_command,
                    seconds=spec["synthetic_guided_seconds"],
                    source_context=context, guarded_runner=physical_runner)
                guided_calls = 1
            if (sha256(adapter.ledger.checkpoint_path) != model_before or
                    sha256(adapter.physical_ledger.path) != physical_before):
                raise ValueError("synthetic wiring changed model or physical ledger")
            if load_wiring_contract(wiring_contract_path,
                                    wiring_contract_sha256, adapter) != spec:
                raise ValueError("Stage16 identity changed after synthetic call")
            receipt.update(status="SYNTHETIC_WIRING_ONLY",
                           synthetic_execute_calls=1,
                           synthetic_guided_calls=guided_calls)
            _private_companion_json(attempt_path, adapter.state_path.parent,
                                    receipt, replace=True)
            anchor["status"] = "SYNTHETIC_WIRING_ONLY"
            anchor["attempt_sha256"] = sha256(attempt_path)
            base._private_json(adapter.state_path, state, replace=True)
            adapter._check_identity(allow_pending_guard=True)
            if load_wiring_contract(wiring_contract_path,
                                    wiring_contract_sha256, adapter) != spec:
                raise ValueError("Stage16 identity changed before return")
            adapter._write_role_guard("assertion_execution_synthetic", ordinal,
                                      item["work_item_id"],
                                      "VALIDATED_COMPLETE",
                                      assertion.assertion_id)
            return attempt_path
        except BaseException as original:
            try:
                adapter._record_pin_failure("assertion_execution_synthetic",
                                            ordinal, original)
            except BaseException as marker_error:
                original.add_note("Stage16 stop marker failed: " +
                                  type(marker_error).__name__)
            raise
