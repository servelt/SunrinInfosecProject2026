"""Bounded provider-free md4c HP Assertion physical integration control."""
from pathlib import Path
import hashlib
import json
import tempfile

from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2
from dev_process_envelope_v2 import DevelopmentProcessEnvelopeV2
from vulnerabilityanalysis.assertions import execute_assertion
from vulnerabilityanalysis.models import Assertion
from vulnerabilityanalysis.official_harness import (
    _qualification_pins_ok, issue_official_pinned_qualification,
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
    builder = Path("/home/dawne/SunrinInfosecProject2026/reference/"
                   "blind2_v2_preparation_20261027/tools/multi_tu_assertion_build.py")
    manifest = builder.with_name("multi_tu_assertion_build_manifest.json")
    builder_sha, manifest_sha = digest(builder), digest(manifest)
    frozen = json.loads(manifest.read_text())
    if (frozen["harness_source"] != str(q.harness.resolve()) or
            frozen["source_root"] != str(q.source_root.resolve()) or
            frozen["official_binary_sha256"] != q.binary_sha256 or
            frozen["source_files"]["test/fuzzers/fuzz-mdhtml.c"] != q.harness_sha256 or
            frozen["builder_sha256"] != builder_sha):
        raise RuntimeError("isolated Assertion build manifest differs from qualification")
    root = Path(tempfile.mkdtemp(prefix="md4c-hp-positive-control-"))
    ledger = PersistentProcessLedgerV2.create(
        root / "process-ledger.json", wall_total_seconds=120, fuzz_total_seconds=0)

    def check_pins(phase, command):
        if (not _qualification_pins_ok(q) or digest(builder) != builder_sha or
                digest(manifest) != manifest_sha):
            raise RuntimeError(f"HP physical control pin changed at {phase}")

    envelope = DevelopmentProcessEnvelopeV2(
        ledger, work_item_id="md4c-hp-positive-control",
        assertion_id="hp-control-false", attempt_id=root.name,
        output_limit_bytes=4_000_000, total_wall_seconds=120,
        pin_hook=check_pins)
    assertion = Assertion(
        "hp-control-false", "MANUAL_CONTROL", "MANUAL_CONTROL",
        "md_collect_marks", "src/md4c.c:3264",
        "n_lines == 0", "n_lines == 0", [],
        generation_method="SCRIPTED_CONTROL")
    source = q.source_root / "src/md4c.c"
    build = [str(builder), "{source}", "-o", "{binary}"]
    run = ["{binary}", "{input}"]
    guided = None
    executed, evidence = execute_assertion(
        assertion, source, 3264, q.normal_seed, root / "execution",
        build, run, timeout_seconds=30, process_envelope=envelope)
    receipt, receipt_sha = ledger.receipt_snapshot()
    summary = {
        "kind": "PROVIDER_FREE_MANUAL_HP_POSITIVE_CONTROL",
        "run_dir": str(root),
        "assertion_status": executed.status,
        "guided_status": guided.get("status") if guided else "NOT_RUN",
        "guided_seconds_budget": 0,
        "automatic_discovery": False,
        "security_gate_credit": "NOT_CREDITED",
        "model_calls": 0,
        "builder_sha256": builder_sha,
        "manifest_sha256": manifest_sha,
        "source_sha256": digest(source),
        "seed_sha256": digest(q.normal_seed),
        "official_binary_sha256": q.binary_sha256,
        "process_finished": len(receipt.get("finished", [])),
        "process_active": len(receipt.get("active", {})),
        "process_stop": receipt.get("stop_status"),
        "process_sha256": receipt_sha,
        "evidence_id": getattr(evidence, "evidence_id", None),
    }
    (root / "control-summary.json").write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n")
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
