"""Scripted SAFE proposal through FBv2 HP handoff into real local execution."""
from dataclasses import asdict
from functools import partial
from pathlib import Path
import hashlib
import json
import tempfile

from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2
from dev_process_envelope_v2 import DevelopmentProcessEnvelopeV2
from devtools.original_hp_preparation import (
    PreparedHPFunction, prepare_hp_function, run_prepared_hp_assertion_handoff,
)
from fuzzingbrain.core.models.direction import Direction
from fuzzingbrain.core.models.function import Function
from vulnerabilityanalysis.assertions import execute_assertion, guided_fuzz_assertion
from vulnerabilityanalysis.models import Assertion
from vulnerabilityanalysis.official_harness import (
    _qualification_pins_ok, issue_official_pinned_qualification,
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def main() -> None:
    spec = json.loads(Path("/tmp/fbv2-public-md4c-v3.json").read_text())
    admission = spec["admission"]
    contract_path = Path(admission["contract_path"])
    contract = json.loads(contract_path.read_text())
    target, local = contract["target"], contract["local"]
    q = issue_official_pinned_qualification(
        contract_path=contract_path,
        approved_contract_sha256=admission["contract_sha256"],
        source_root=Path(target["source_root"]),
        harness=Path(local["harness_file"]), binary=Path(local["binary"]),
        normal_seed=Path(local["normal_seed"]),
        oss_fuzz_checkout=Path(admission["oss_fuzz_checkout"]),
        upstream_checkout=Path(admission["upstream_checkout"]),
    )
    if q is None or not _qualification_pins_ok(q):
        raise RuntimeError("official public md4c qualification unavailable")
    function = Function(
        task_id="manual-hp-control-task", name="md_collect_marks",
        file_path="src/md4c.c", start_line=3255,
        analyzed_by_directions=["manual-hp-control-direction"])
    direction = Direction(
        task_id=function.task_id, direction_id="manual-hp-control-direction",
        fuzzer="fuzz-mdhtml", name="manual HP physical control",
        core_functions=[function.name])
    work = prepare_hp_function(
        function=function, direction=direction, qualification=q,
        fuzzer="fuzz-mdhtml", sanitizer="address")
    if type(work) is not PreparedHPFunction:
        raise RuntimeError(f"HP source preparation failed: {work}")
    assertion = Assertion(
        "hp-control-nonnull", "MANUAL_CONTROL", work.direction_id,
        work.function_name, "src/md4c.c:3264",
        "ctx != NULL && lines != NULL", "ctx != NULL && lines != NULL", [],
        generation_method="SCRIPTED_CONTROL")
    proposals = [asdict(assertion)]
    analysis_result = {
        "status": "ASSERTIONS_PROPOSED_UNVERIFIED",
        "assertion_execution": "NOT_RUN",
        "function_id": work.function_id,
        "direction_id": work.direction_id,
        "assertion_count": 1,
        "proposed_assertion_count": 1,
        "assertion_proposals": proposals,
        "prepared_work_sha256": hashlib.sha256(canonical(asdict(work))).hexdigest(),
        "assertion_proposals_sha256": hashlib.sha256(canonical(proposals)).hexdigest(),
    }
    builder = Path("/home/dawne/SunrinInfosecProject2026/reference/"
                   "blind2_v2_preparation_20261027/tools/multi_tu_assertion_build.py")
    manifest = builder.with_name("multi_tu_assertion_build_manifest.json")
    builder_sha, manifest_sha = digest(builder), digest(manifest)
    root = Path(tempfile.mkdtemp(prefix="md4c-hp-handoff-control-"))
    ledger = PersistentProcessLedgerV2.create(
        root / "process-ledger.json", wall_total_seconds=120,
        fuzz_total_seconds=30)

    def check_pins(phase, command):
        if (not _qualification_pins_ok(q) or digest(builder) != builder_sha or
                digest(manifest) != manifest_sha):
            raise RuntimeError(f"HP control pin changed at {phase}")

    envelope = DevelopmentProcessEnvelopeV2(
        ledger, work_item_id="md4c-hp-handoff-control",
        assertion_id=assertion.assertion_id, attempt_id=root.name,
        output_limit_bytes=4_000_000, total_wall_seconds=120,
        pin_hook=check_pins)
    handoff = run_prepared_hp_assertion_handoff(
        work=work, qualification=q, analysis_result=analysis_result,
        worker_id=assertion.worker_id, assertion_id=assertion.assertion_id,
        output_dir=root / "hp", build_command=[str(builder), "{source}", "-o", "{binary}"],
        run_command=["{binary}", "{input}"], guided_seconds=1,
        timeout_seconds=30, provider_free_fixture=True,
        execute_callback=partial(execute_assertion, process_envelope=envelope),
        guided_callback=partial(guided_fuzz_assertion, process_envelope=envelope),
        builder_manifest_path=manifest, builder_manifest_sha256=manifest_sha)
    receipt, receipt_sha = ledger.receipt_snapshot()
    summary = {
        "kind": "PROVIDER_FREE_SCRIPTED_HP_HANDOFF_PHYSICAL_CONTROL",
        "run_dir": str(root), "handoff": handoff,
        "model_calls": 0, "automatic_discovery": False,
        "builder_sha256": builder_sha, "manifest_sha256": manifest_sha,
        "source_sha256": digest(q.source_root / "src/md4c.c"),
        "seed_sha256": digest(q.normal_seed),
        "official_binary_sha256": q.binary_sha256,
        "process_finished": len(receipt.get("finished", [])),
        "process_active": len(receipt.get("active", {})),
        "process_stop": receipt.get("stop_status"),
        "process_sha256": receipt_sha,
    }
    (root / "control-summary.json").write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n")
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
