"""Export original-program network request sequences for StateAFL.

This is an evidence-preserving interchange format, not a fuzzer verdict.
StateAFL's replayable format is a sequence of little-endian u32 lengths and
message bytes. Only requests actually sent during one original-program run
are exported; the planned templates can contain unresolved response bindings.
"""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Iterable

from ..models import ScenarioStatus, ScenarioWitness
from ..storage import ArtifactStore


_EXPORTABLE = {
    ScenarioStatus.PROVEN_RUNTIME,
    ScenarioStatus.OBSERVED_RUNTIME,
    ScenarioStatus.REPLAYED_RUNTIME,
    ScenarioStatus.UNPROVEN,
}
_STATEAFL_REFERENCE_COMMIT = "d923e22f7b2688db45b08f3fa3a29a566e7ff3a4"


def export_stateafl_seeds(
    store: ArtifactStore,
    witnesses: Iterable[ScenarioWitness],
) -> dict[str, Any]:
    """Write network replay seeds and an explicit proof/omission manifest.

    ``proven`` means the original request was causally attributed by this
    workflow; ``exploratory`` has an accepted response without attribution;
    ``diagnostic`` has a locally completed request write or a response, but
    no proof that the peer parsed or accepted the request.
    None is a qualified harness corpus or a crash verdict.
    """
    rows: list[dict[str, Any]] = []
    for witness in witnesses:
        row: dict[str, Any] = {
            "witness_id": witness.witness_id,
            "scenario_id": witness.scenario_id,
            "status": str(witness.status),
            "channel": witness.channel,
            "seed_path": None,
            "reason": "",
        }
        reason = _ineligible_reason(witness)
        if reason:
            row["reason"] = reason
            rows.append(row)
            continue
        messages = [bytes.fromhex(item.request_hex) for item in witness.observations]
        content = b"".join(
            len(message).to_bytes(4, "little") + message
            for message in messages
        )
        grade = (
            "proven" if witness.status is ScenarioStatus.PROVEN_RUNTIME
            else "diagnostic" if witness.status is ScenarioStatus.UNPROVEN
            else "exploratory"
        )
        # The witness ID is derived from runtime data in the normal workflow;
        # hash it again for a safe, collision-resistant artifact basename.
        basename = sha256(
            witness.witness_id.encode("utf-8") + b"\0" + content
        ).hexdigest()[:24]
        relative = f"research/stateafl/{grade}/{basename}.replay"
        store.write_bytes(relative, content)
        row.update({
            "seed_path": relative,
            "message_count": len(messages),
            "message_lengths": [len(message) for message in messages],
            "original_responses_hex": [
                item.response_hex for item in witness.observations
            ],
            "connection_prelude_hex": (
                witness.connection_prelude_hex if witness.channel == "tcp" else ""
            ),
            "expected_success_markers_hex": [
                list(item.expected_success_markers_hex) for item in witness.steps
            ],
            "local_write_completed_steps": [
                item.index for item in witness.observations
                if item.request_write_completed
            ],
            "sha256": sha256(content).hexdigest(),
            "response_bound_steps": [
                item.index for item in witness.steps if item.request_binding_uses
            ],
            "tcp_connect_after_launch_seconds": (
                witness.tcp_connect_after_launch_seconds
                if witness.channel == "tcp" else None
            ),
            "startup_measurement_policy": (
                "one original-run observation; not a safe StateAFL -D value"
            ),
            "reason": (
                "original requests causally attributed by the configured verifier"
                if grade == "proven" else
                "original request write or reply observed; peer receipt, "
                "acceptance and handler reach are unproven" if grade == "diagnostic" else
                "observed original sequence; request-to-handler attribution "
                "is unproven"
            ),
        })
        rows.append(row)
    manifest = {
        "format": "StateAFL replayable: repeated little-endian u32 length + message",
        "reference_repository": "https://github.com/stateafl/stateafl",
        "reference_commit": _STATEAFL_REFERENCE_COMMIT,
        "source": "materialized original-program request observations",
        "scope": "TCP/UDP, one original process and one connection/socket per scenario",
        "automatic_fuzzing_started": False,
        "qualified_harness_claim": False,
        "diagnostic_seed_policy": (
            "A completed local request write, or an original reply, can "
            "preserve an input hypothesis for process-level experimentation. "
            "Neither proves peer receipt, request acceptance, or target reach."
        ),
        "mutation_limitation": (
            "Response-derived later requests are exported as the observed "
            "concrete bytes. StateAFL will not automatically recompute those "
            "bindings after a preceding request is mutated."
        ),
        "rows": rows,
    }
    store.write_json("research/stateafl/manifest.json", manifest)
    return manifest


def snapshot_stateafl_seeds(
    store: ArtifactStore, *, transport: str, tier: str,
) -> Path | None:
    """Freeze eligible original-run bytes before concurrent source analysis.

    The live manifest is refreshed as more scenarios finish. A campaign must
    read one immutable manifest and its matching bytes, even if that refresh
    occurs while the instrumented server is being built.
    """
    manifest = json.loads(
        (store.root / "research/stateafl/manifest.json").read_text(encoding="utf-8")
    )
    if manifest.get("qualified_harness_claim") is not False:
        raise ValueError("StateAFL seed manifest is missing its proof boundary")
    selected = [
        row for row in manifest.get("rows", [])
        if isinstance(row, dict)
        and row.get("channel") == transport
        and row.get("seed_path")
        and Path(str(row["seed_path"])).parts[:3]
            == ("research", "stateafl", tier)
    ]
    if not selected:
        return None
    snapshot_root = store.root / "research/stateafl/network-harness-source"
    snapshot = ArtifactStore(snapshot_root)
    for row in selected:
        relative = Path(str(row["seed_path"]))
        source = (store.root / relative).resolve(strict=True)
        if store.root not in source.parents:
            raise ValueError("StateAFL seed path escapes the original run")
        content = source.read_bytes()
        if sha256(content).hexdigest() != row.get("sha256"):
            raise ValueError(f"StateAFL seed changed before snapshot: {source}")
        snapshot.write_bytes(relative, content)
    snapshot.write_json("research/stateafl/manifest.json", {
        **manifest, "rows": selected,
        "source_snapshot_of": str(store.root),
    })
    return snapshot_root


def stateafl_seed_fingerprints(
    run_root: Path, *, transport: str, tier: str,
) -> tuple[str, ...]:
    """Identify distinct replay sequences selected for one campaign."""
    manifest = json.loads(
        (run_root / "research/stateafl/manifest.json").read_text(encoding="utf-8")
    )
    return tuple(sorted({
        str(row["sha256"])
        for row in manifest.get("rows", [])
        if isinstance(row, dict)
        and row.get("channel") == transport
        and row.get("seed_path")
        and row.get("sha256")
        and Path(str(row["seed_path"])).parts[:3]
            == ("research", "stateafl", tier)
    }))


def _ineligible_reason(witness: ScenarioWitness) -> str:
    if witness.channel not in {"tcp", "udp"}:
        return "StateAFL's server transport does not match this input channel"
    if witness.status not in _EXPORTABLE:
        return "no accepted original-program sequence at this proof level"
    if witness.original_program_crashed or witness.process_returncode not in {None, 0}:
        return "original program crashed or exited unsuccessfully"
    if not witness.steps or len(witness.observations) != len(witness.steps):
        return "original execution did not observe every request step"
    for step, observation in zip(witness.steps, witness.observations):
        if step.index != observation.index or step.action_id != observation.action_id:
            return "step and original observation order do not match"
        try:
            message = bytes.fromhex(observation.request_hex)
        except ValueError:
            return "original observation has invalid request bytes"
        if not message or len(message) > 0xFFFFFFFF:
            return "empty or oversized request cannot be replayed as one message"
        if witness.status is ScenarioStatus.UNPROVEN:
            if not observation.response_hex and not observation.request_write_completed:
                return "diagnostic request has neither a completed local write nor a reply"
            if (observation.detail.startswith("transport/response failure:")
                and not observation.request_write_completed):
                return "diagnostic original request had a transport failure before write completion"
            # A completed local write can time out before any reply. This is
            # still useful as an input hypothesis for server-first or quiet
            # protocols; it does not establish peer receipt or acceptance.
            continue
        if not observation.success:
            return "original request did not satisfy its success check"
        if (witness.status is ScenarioStatus.PROVEN_RUNTIME
            and not observation.target_reached):
            return "proven witness lacks request-attributed target reach"
        if (witness.status is not ScenarioStatus.PROVEN_RUNTIME
            and not observation.response_success):
            return "exploratory request has no accepted response"
    return ""
