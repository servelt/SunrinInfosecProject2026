"""Explicit, signed public-development HP extension after the original Worker.

The original FBv2 result is immutable here. HP uses its campaign model gate,
has a separate one-shot run claim and result receipt, and never grants Gate or
automatic-discovery credit. Import this module only after the live entry pins
the engine, product, evaluation code and HP prompt assets.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any
from uuid import uuid4

from devtools.original_hp_post_worker import _private_directory, run_post_worker_hp


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_HP_ASSETS = {
    "function_analysis_prompt_sha256": Path("prompts/function_analysis.md"),
    "assertion_generator_prompt_sha256": Path("prompts/assertion_generator.md"),
    "config_sha256": Path("config/default.yaml"),
}
_HP_RESULT = "HP_PUBLIC_DEV_RESULT.json"
_HP_PHYSICAL_FIELDS = frozenset({
    "enabled", "builder_path", "builder_sha256", "manifest_path",
    "manifest_sha256", "guided_seconds", "total_wall_seconds",
    "output_limit_bytes",
})
_TRUSTED_MD4C_BUILDER = Path(
    "/home/dawne/SunrinInfosecProject2026/reference/"
    "blind2_v2_preparation_20261027/tools/multi_tu_assertion_build.py")
_TRUSTED_MD4C_BUILDER_SHA256 = (
    "fbe9616f102d76205bb6d20b49c225f7043f5393d675c6387ea965d423139ffc")
_TRUSTED_MD4C_MANIFEST_SHA256 = (
    "200d5248f835e3942dcd853934d309949b9b73354cb64956ca15cf5750539dd1")


def _validate_hp_physical_spec(physical: Any) -> None:
    """Pin one md4c relink recipe; this is not a generic build approval."""
    if physical is None:
        return
    if (type(physical) is not dict or set(physical) != _HP_PHYSICAL_FIELDS or
            physical.get("enabled") is not True or
            type(physical.get("guided_seconds")) is not int or
            not 1 <= physical["guided_seconds"] <= 10 or
            type(physical.get("total_wall_seconds")) is not int or
            not 60 <= physical["total_wall_seconds"] <= 180 or
            type(physical.get("output_limit_bytes")) is not int or
            not 1 <= physical["output_limit_bytes"] <= 4_000_000):
        raise ValueError("signed HP physical cap is invalid")
    for name, digest_name in (("builder_path", "builder_sha256"),
                              ("manifest_path", "manifest_sha256")):
        path = Path(physical[name]) if type(physical.get(name)) is str else None
        digest = physical.get(digest_name)
        if (path is None or not path.is_absolute() or path.is_symlink() or
                not path.is_file() or path != path.resolve(strict=True) or
                type(digest) is not str or not _SHA.fullmatch(digest) or
                hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            raise ValueError("signed HP physical recipe pin changed")
    builder = Path(physical["builder_path"])
    manifest = Path(physical["manifest_path"])
    if (builder != _TRUSTED_MD4C_BUILDER or
            physical["builder_sha256"] != _TRUSTED_MD4C_BUILDER_SHA256 or
            manifest != builder.with_name(
                "multi_tu_assertion_build_manifest.json") or
            physical["manifest_sha256"] != _TRUSTED_MD4C_MANIFEST_SHA256):
        raise ValueError("signed HP physical builder is not trusted")


def hp_asset_hashes(product_src: Path) -> dict[str, str]:
    """Read fixed product asset paths; a spec cannot select other files."""
    root = Path(product_src).parent
    if (not root.is_absolute() or root.is_symlink() or
            root != root.resolve(strict=True) or not root.is_dir()):
        raise ValueError("HP product root is not canonical")
    values: dict[str, str] = {}
    for key, relative in _HP_ASSETS.items():
        path = root / relative
        if (path.is_symlink() or not path.is_file() or
                path != path.resolve(strict=True) or root not in path.parents):
            raise ValueError("HP prompt/config path is unavailable")
        values[key] = hashlib.sha256(path.read_bytes()).hexdigest()
    return values


def validate_hp_spec(hp: Any, product_src: Path, *, enabled: bool) -> None:
    """Require an exact opt-in contract before runtime import or any HP turn."""
    if not enabled:
        if hp is not None and hp != {"enabled": False}:
            raise ValueError("ordinary public development cannot enable HP")
        return
    if (type(hp) is not dict or set(hp) not in (
            {"enabled", "max_items", "max_model_calls", "assets"},
            {"enabled", "max_items", "max_model_calls", "assets", "physical"}) or
            hp["enabled"] is not True or hp["max_items"] != 1 or
            type(hp["max_items"]) is not int or
            hp["max_model_calls"] != 3 or
            type(hp["max_model_calls"]) is not int or
            type(hp["assets"]) is not dict or
            set(hp["assets"]) != set(_HP_ASSETS) or
            any(type(value) is not str or not _SHA.fullmatch(value)
                for value in hp["assets"].values())):
        raise ValueError("signed HP opt-in or cap is invalid")
    if hp_asset_hashes(product_src) != hp["assets"]:
        raise ValueError("HP prompt/config SHA-256 changed")
    _validate_hp_physical_spec(hp.get("physical"))


def _check_signed_spec(path: Path, expected_sha256: str) -> bytes:
    if (type(expected_sha256) is not str or
            not _SHA.fullmatch(expected_sha256) or
            not path.is_absolute() or path.is_symlink() or
            path != path.resolve(strict=True) or not path.is_file()):
        raise ValueError("HP signed public-development spec changed")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("HP signed public-development spec changed")
    return raw


def _check_signed_hp_spec(path: Path, expected_sha256: str,
                          hp: dict[str, Any]) -> None:
    raw = _check_signed_spec(path, expected_sha256)
    try:
        signed_hp = json.loads(raw)["hp"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ValueError("HP signed opt-in is unavailable") from exc
    if signed_hp != hp:
        raise ValueError("HP opt-in differs from signed spec")


def _write_once(path: Path, row: dict[str, Any]) -> str:
    data = (json.dumps(row, sort_keys=True, default=str,
                       separators=(",", ":")) + "\n").encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY |
                        os.O_NOFOLLOW)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    return hashlib.sha256(data).hexdigest()


def _verified_hp_provenance(gate: Any, work: Any, worker_id: str,
                            row: dict[str, Any]) -> dict[str, Any]:
    """Re-read both HP role responses immediately before a physical claim."""
    provenance = row.get("hp_model_provenance")
    if (row.get("proposal_origin") != "VERIFIED_CAMPAIGN_MODEL" or
            type(provenance) is not dict or
            set(provenance) != {"function_analysis_turns",
                                "assertion_generator_turn"}):
        raise ValueError("HP model proposal provenance is unavailable")
    analysis_turns = provenance["function_analysis_turns"]
    assertion_turn = provenance["assertion_generator_turn"]
    if (type(analysis_turns) is not list or
            not 1 <= len(analysis_turns) <= 2 or
            type(assertion_turn) is not dict):
        raise ValueError("HP model role provenance is incomplete")
    turns = [*analysis_turns, assertion_turn]
    records = gate.snapshot()["records"]
    seen: set[str] = set()
    responses: dict[str, list[dict[str, Any]]] = {
        "function_analysis": [], "assertion_generator": []}
    for index, turn in enumerate(turns):
        role = ("function_analysis" if index < len(analysis_turns)
                else "assertion_generator")
        owner = f"hp:{work.function_id}:{work.direction_id}:{role}"
        if (type(turn) is not dict or set(turn) != {
                "role", "owner_id", "request_id", "response_sha256",
                "thread_id", "turn_id"} or
                turn.get("role") != role or turn.get("owner_id") != owner or
                type(turn.get("request_id")) is not str or
                not turn["request_id"] or turn["request_id"] in seen or
                type(turn.get("response_sha256")) is not str or
                not _SHA.fullmatch(turn["response_sha256"])):
            raise ValueError("HP model role provenance changed")
        seen.add(turn["request_id"])
        matching = [entry for entry in records
                    if entry.get("request_id") == turn["request_id"]]
        evidence = gate.verify_response_evidence(turn["request_id"])
        if (len(matching) != 1 or
                matching[0].get("status") != "COMPLETED" or
                matching[0].get("role") != role or
                matching[0].get("owner_id") != owner or
                evidence.get("status") != "VERIFIED" or
                any(evidence.get(key) != turn[key] for key in (
                    "request_id", "response_sha256", "thread_id", "turn_id"))):
            raise ValueError("HP model response evidence changed")
        raw = Path(evidence["response_path"]).read_bytes()
        if hashlib.sha256(raw).hexdigest() != turn["response_sha256"]:
            raise ValueError("HP model response bytes changed")
        parsed = json.loads(raw)
        if type(parsed) is not dict:
            raise ValueError("HP model response body is invalid")
        responses[role].append(parsed)
    # The two verified turns must explain the exact selected Assertion. An
    # unrelated completed request with the right role is not its provenance.
    final_analysis = responses["function_analysis"][-1]
    generated = responses["assertion_generator"][0]
    raw_safes = final_analysis.get("safe_assumptions")
    judgments = final_analysis.get("hypothesis_evaluations")
    generated_rows = generated.get("assertions")
    dispositions = generated.get("dispositions")
    proposals = row.get("assertion_proposals")
    if (type(raw_safes) is not list or type(judgments) is not list or
            type(generated_rows) is not list or type(dispositions) is not list or
            type(proposals) is not list):
        raise ValueError("HP model SAFE or Assertion body is incomplete")
    linked = {item.get("safe_assumption") for item in judgments
              if type(item) is dict and
              item.get("judgment") == "EXPLICIT_SAFE_JUDGMENT" and
              item.get("safe_assumption")}
    # Match AgentPipeline.analyze_function: unlinked raw SAFE text is removed
    # before Assertion Generator assigns safe_id, while model-authored text in
    # each Assertion/disposition is normalized by safe_id.
    safes = [safe for safe in raw_safes if safe in linked]
    from vulnerabilityanalysis.models import stable_id
    if len(proposals) != len(generated_rows):
        raise ValueError("HP saved Assertion count differs from model response")
    expected_rows = []
    for item in generated_rows:
        if (type(item) is not dict or
                type(item.get("safe_id")) is not int or
                type(item.get("runtime_expression")) is not str or
                type(item.get("source_line")) is not int or
                type(item.get("safe_assumption")) is not str):
            raise ValueError("HP model Assertion row is invalid")
        safe_id = item["safe_id"]
        valid_id = 0 <= safe_id < len(safes)
        safe = (safes[safe_id] if valid_id else item["safe_assumption"])
        identity_kind = "LLM" if valid_id else "LLM_INVALID_SAFE_ID"
        expected_rows.append((
            stable_id("assert", identity_kind, worker_id,
                      work.direction_id, work.function_name, safe,
                      item["runtime_expression"], item["source_line"]),
            safe, item["runtime_expression"],
            f"{work.source_file}:{item['source_line']}",
            "LLM"))
    actual_rows = []
    for proposal in proposals:
        if type(proposal) is not dict:
            raise ValueError("HP saved Assertion row is invalid")
        actual_rows.append((
            proposal.get("assertion_id"), proposal.get("safe_assumption"),
            proposal.get("runtime_expression"),
            proposal.get("source_location"),
            proposal.get("generation_method")))
    if any(any(type(value) is not str for value in item)
           for item in actual_rows):
        raise ValueError("HP saved Assertion identity is invalid")
    if sorted(actual_rows) != sorted(expected_rows):
        raise ValueError("HP saved Assertions differ from model response")
    for proposal in proposals:
        if type(proposal) is not dict or proposal.get("status") != "PROPOSED":
            continue
        safe = proposal.get("safe_assumption")
        if (type(safe) is not str or safe not in safes or safe not in linked or
                proposal.get("generation_method") != "LLM" or
                proposal.get("worker_id") != worker_id or
                proposal.get("function") != work.function_name or
                proposal.get("direction_id") != work.direction_id):
            raise ValueError("HP proposal is not linked to Function Analysis")
        matches = [item for item in generated_rows if
                   type(item) is dict and
                   type(item.get("safe_id")) is int and
                   0 <= item["safe_id"] < len(safes) and
                   safes[item["safe_id"]] == safe and
                   item.get("runtime_expression") ==
                       proposal.get("runtime_expression") and
                   proposal.get("source_location") ==
                       f"{work.source_file}:{item.get('source_line')}"]
        if len(matches) != 1:
            raise ValueError("HP proposal differs from Assertion response")
        selected = matches[0]
        disposition = [item for item in dispositions if
                       type(item) is dict and
                       type(item.get("safe_id")) is int and
                       item["safe_id"] == selected["safe_id"]]
        if (len(disposition) != 1 or
                disposition[0].get("status") != "PROPOSED" or
                type(disposition[0].get("reason")) is not str or
                not disposition[0]["reason"].strip() or
                proposal.get("assertion_id") != stable_id(
                    "assert", "LLM", worker_id, work.direction_id,
                    work.function_name, safe,
                    proposal["runtime_expression"], selected["source_line"])):
            raise ValueError("HP proposal identity differs from model response")
    return provenance


def _claim_hp_run(bound: Any, worker_receipt: dict[str, Any],
                  hp: dict[str, Any], spec_sha256: str) -> str:
    root = bound.identity.run_dir
    if (not _private_directory(root) or type(spec_sha256) is not str or
            not _SHA.fullmatch(spec_sha256)):
        raise ValueError("HP run claim identity is unsafe")
    original = worker_receipt.get("original_result")
    if (type(original) is not dict or
            type(original.get("worker_id")) is not str or
            worker_receipt.get("task_id") != bound.identity.task_id or
            worker_receipt.get("run_id") != bound.identity.run_id):
        raise ValueError("HP run claim Worker identity is unavailable")
    process, process_sha = bound.process_ledger.receipt_snapshot()
    if (process.get("stop_status") is not None or
            bool(process.get("active"))):
        raise ValueError("HP run claim process account is unsettled")
    row = {"kind": "FBV2_HP_RUN_CLAIM_V1",
           "task_id": bound.identity.task_id,
           "run_id": bound.identity.run_id,
           "worker_id": original["worker_id"],
           "spec_sha256": spec_sha256,
           "hp_assets": hp["assets"],
           "model_physical_before": bound.model_gate.snapshot()["physical"],
           "process_receipt_sha256_before": process_sha,
           "original_result_sha256": hashlib.sha256(json.dumps(
               original, sort_keys=True, default=str,
               separators=(",", ":")).encode()).hexdigest()}
    return _write_once(root / "HP_RUN_CLAIM.json", row)


def _hp_client_type(asset_check):
    """Reuse isolated process startup without FBv2 host-MCP instructions."""
    from fuzzingbrain.llms.codex_tool_bridge import (
        isolated_codex_appserver_client_class)
    from vulnerabilityanalysis.llm import CodexAppServerClient

    isolated = isolated_codex_appserver_client_class(CodexAppServerClient)

    class PinnedHPClient(isolated):
        async def _request(self, method: str, params: dict[str, Any]):
            # The isolated class changes developerInstructions for FBv2 host
            # MCP proposals. HP must retain the product's no-tool instructions.
            prior = self._fbv2_request_stage
            self._fbv2_request_stage = method
            try:
                return await CodexAppServerClient._request(self, method, params)
            finally:
                self._fbv2_request_stage = prior

        async def generate(self, request):
            asset_check()
            result = await super().generate(request)
            asset_check()
            return result

    return PinnedHPClient


def _pipeline_factory(bound: Any, hp: dict[str, Any], role: str,
                      spec_path: Path, spec_sha256: str):
    from devtools.campaign_model_gate import CampaignLedgeredProvider
    from vulnerabilityanalysis.agents import AgentPipeline

    def check():
        _check_signed_hp_spec(spec_path, spec_sha256, hp)
        bound.recheck()
        validate_hp_spec(hp, bound.identity.product_src, enabled=True)

    client_type = _hp_client_type(check)

    def build(work):
        check()
        event_dir = bound.identity.run_dir / "model_events"
        if not _private_directory(event_dir):
            raise ValueError("HP event directory is unsafe")
        transport = client_type(
            cwd=bound.identity.task_path, model=bound.identity.codex_model,
            effort=bound.identity.codex_effort,
            executable=str(bound.identity.codex_executable),
            executable_sha256=bound.identity.codex_executable_sha256,
            event_log_path=event_dir / f"hp_{role}_{uuid4().hex}.jsonl")
        provider = CampaignLedgeredProvider(
            transport, bound.model_gate, role=role,
            owner_id=f"hp:{work.function_id}:{work.direction_id}:{role}")
        return AgentPipeline(provider, max_context_requests=2)

    return build


def _physical_handoff_factory(bound: Any, hp: dict[str, Any],
                              worker_receipt: dict[str, Any],
                              spec_path: Path, spec_sha256: str):
    """Return one md4c-only, signed V2 physical handoff for HP proposals.

    This is constructed only by the pinned public development runner. It is
    deliberately not a generic repository build adapter and cannot enable the
    public live CLI while its outer admission guard remains in place.
    """
    physical = hp.get("physical")
    _validate_hp_physical_spec(physical)
    if physical is None:
        return None
    from dev_process_envelope_v2 import DevelopmentProcessEnvelopeV2
    from devtools.original_hp_preparation import (
        PreparedHPFunction, _prepared_pins_ok,
        _qualified_relink_recipe_ok, run_prepared_hp_assertion_handoff)
    builder = Path(physical["builder_path"])
    manifest = Path(physical["manifest_path"])
    build_command = [str(builder), "{source}", "-o", "{binary}"]
    q = bound.admission.qualification
    root = bound.identity.run_dir
    worker_id = worker_receipt["original_result"]["worker_id"]
    try:
        recipe = json.loads(manifest.read_bytes())
        qualified_recipe = (
            type(recipe) is dict and
            recipe.get("schema") == "MULTI_TU_ASSERTION_BUILD_V1" and
            recipe.get("kind") == "MD4C_ISOLATED_ASSERTION_RELINK_V1" and
            recipe.get("builder_sha256") == physical["builder_sha256"] and
            recipe.get("source_root") == str(Path(q.source_root).resolve()) and
            recipe.get("harness_source") == str(Path(q.harness).resolve()) and
            recipe.get("official_binary") == str(Path(q.binary).resolve()) and
            recipe.get("official_binary_sha256") == q.binary_sha256)
    except (OSError, ValueError, TypeError, AttributeError):
        qualified_recipe = False
    if not qualified_recipe:
        raise ValueError("HP physical recipe is not qualified for this target")

    def recheck(work: PreparedHPFunction, claim: Path | None = None,
                claim_sha: str | None = None) -> None:
        _check_signed_hp_spec(spec_path, spec_sha256, hp)
        validate_hp_spec(hp, bound.identity.product_src, enabled=True)
        bound.recheck()
        if (not _prepared_pins_ok(work, q) or
                not _qualified_relink_recipe_ok(
                    work=work, qualification=q, build_command=build_command,
                    manifest_path=manifest,
                    manifest_sha256=physical["manifest_sha256"])):
            raise ValueError("HP qualified md4c build recipe changed")
        if claim is not None and (claim_sha is None or
                claim.is_symlink() or not claim.is_file() or
                hashlib.sha256(claim.read_bytes()).hexdigest() != claim_sha):
            raise ValueError("HP one-shot physical claim changed")

    def handoff(work: PreparedHPFunction, row: dict[str, Any]) -> dict[str, Any]:
        if type(work) is not PreparedHPFunction or type(row) is not dict:
            raise ValueError("HP physical work or proposal is invalid")
        recheck(work)
        proposals = row.get("assertion_proposals")
        canonical = lambda value: json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            allow_nan=False).encode()
        if (row.get("status") != "ASSERTIONS_PROPOSED_UNVERIFIED" or
                row.get("assertion_execution") != "NOT_RUN" or
                row.get("function_id") != work.function_id or
                row.get("direction_id") != work.direction_id or
                type(proposals) is not list or
                row.get("assertion_count") != len(proposals) or
                row.get("proposed_assertion_count") != sum(
                    type(item) is dict and item.get("status") == "PROPOSED"
                    for item in proposals) or
                row.get("prepared_work_sha256") != hashlib.sha256(
                    canonical(asdict(work))).hexdigest() or
                row.get("assertion_proposals_sha256") != hashlib.sha256(
                    canonical(proposals)).hexdigest()):
            raise ValueError("HP physical proposal receipt changed")
        # AgentPipeline can derive STATIC_RULE Assertions when the model
        # returns assertions=[]. The saved HP row pins context files but not
        # the exact excerpts presented to that derivation. Recomputing from
        # current source could silently use evidence the model never saw.
        if any(type(item) is dict and item.get("status") == "PROPOSED" and
               item.get("generation_method") == "STATIC_RULE"
               for item in proposals):
            return {"status": "HP_ASSERTION_HANDOFF_BLOCKED",
                    "reason": "MODEL_SAFE_STATIC_ASSERTION_CONTEXT_UNPROVEN",
                    "sp_global_effect": "UNCHANGED",
                    "security_gate_credit": "NOT_CREDITED",
                    "discovery_credit": "NOT_CREDITED"}
        provenance = _verified_hp_provenance(
            bound.model_gate, work, worker_id, row)
        proposal_ids = [item.get("assertion_id") for item in proposals
                        if type(item) is dict]
        if (len(proposal_ids) != len(proposals) or
                any(type(identifier) is not str or
                    re.fullmatch(r"[A-Za-z0-9_-]+", identifier) is None
                    for identifier in proposal_ids) or
                len(set(proposal_ids)) != len(proposal_ids)):
            raise ValueError("HP Assertion IDs are missing or duplicated")
        proposed = [item for item in proposals if type(item) is dict and
                    item.get("status") == "PROPOSED"]
        if not proposed:
            return {"status": "HP_ASSERTION_HANDOFF_BLOCKED",
                    "reason": "NO_PROPOSED_ASSERTION",
                    "sp_global_effect": "UNCHANGED",
                    "security_gate_credit": "NOT_CREDITED",
                    "discovery_credit": "NOT_CREDITED"}
        try:
            ranked = sorted(proposed, key=lambda item: (
                int(item["source_location"].rsplit(":", 1)[1]),
                item["assertion_id"]))
            if any(int(item["source_location"].rsplit(":", 1)[1]) < 1
                   for item in ranked):
                raise ValueError("HP Assertion source line is invalid")
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise ValueError("HP Assertion selection input is invalid") from exc
        assertion_id = ranked[0]["assertion_id"]
        selection = {"policy": "SOURCE_LINE_THEN_ASSERTION_ID_V1",
                     "proposed_count": len(ranked),
                     "selected_assertion_id": assertion_id,
                     "not_run": [
                         {"assertion_id": item["assertion_id"],
                          "status": "NOT_RUN",
                          "reason": "BUDGET_NOT_SELECTED"}
                         for item in ranked[1:]]}
        state, before_sha = bound.process_ledger.receipt_snapshot()
        if (state.get("stop_status") is not None or state.get("active") or
                state["wall_total_seconds"] - state["wall_spent_seconds"] <
                    physical["total_wall_seconds"] or
                state["fuzz_total_seconds"] - state["fuzz_spent_seconds"] <
                    physical["guided_seconds"] + 24.5):
            raise ValueError("HP physical shared budget is unavailable")
        if not _private_directory(root):
            raise ValueError("HP physical claim directory is unsafe")
        proposal_sha = hashlib.sha256(canonical(row)).hexdigest()
        # A fixed run-level path forbids a second physical attempt even if a
        # different Assertion ID is later presented to this factory.
        claim_path = root / "HP_PHYSICAL_CLAIM.json"
        claim = {"kind": "FBV2_HP_PHYSICAL_CLAIM_V1",
                 "task_id": bound.identity.task_id,
                 "run_id": bound.identity.run_id,
                 "worker_id": worker_id,
                 "function_id": work.function_id,
                 "direction_id": work.direction_id,
                 "assertion_id": assertion_id,
                 "assertion_selection": selection,
                 "proposal_sha256": proposal_sha,
                 "hp_model_provenance": provenance,
                 "hp_model_provenance_sha256": hashlib.sha256(
                     canonical(provenance)).hexdigest(),
                 "source_sha256": work.source_sha256,
                 "source_tree_sha256": work.source_tree_sha256,
                 "harness_sha256": work.harness_sha256,
                 "binary_sha256": work.binary_sha256,
                 "builder_sha256": physical["builder_sha256"],
                 "manifest_sha256": physical["manifest_sha256"],
                 "spec_sha256": spec_sha256,
                 "process_ledger_sha256_before": before_sha}
        claim_sha = _write_once(claim_path, claim)

        def pin(_phase: str, _command: list[str]) -> None:
            recheck(work, claim_path, claim_sha)

        envelope = DevelopmentProcessEnvelopeV2(
            bound.process_ledger, work_item_id=bound.identity.task_id,
            assertion_id=assertion_id, attempt_id=bound.identity.run_id,
            output_limit_bytes=physical["output_limit_bytes"],
            total_wall_seconds=physical["total_wall_seconds"], pin_hook=pin)
        result = run_prepared_hp_assertion_handoff(
            work=work, qualification=q, analysis_result=row,
            worker_id=worker_id, assertion_id=assertion_id,
            output_dir=root / "hp-physical" / assertion_id,
            build_command=build_command,
            run_command=["{binary}", "{input}"],
            guided_seconds=physical["guided_seconds"],
            timeout_seconds=30.0, provider_free_fixture=False,
            builder_manifest_path=manifest,
            builder_manifest_sha256=physical["manifest_sha256"],
            live_process_envelope=envelope,
            live_claim_path=claim_path,
            live_claim_sha256=claim_sha)
        result["physical_claim_path"] = str(claim_path)
        result["physical_claim_sha256"] = claim_sha
        result["process_ledger_sha256_before"] = before_sha
        result["assertion_selection"] = selection
        return result

    return handoff


def run_signed_hp_after_worker(bound: Any, worker_receipt: dict[str, Any],
                               hp: dict[str, Any], *, spec_path: Path,
                               spec_sha256: str
                               ) -> dict[str, Any]:
    """Consume one signed HP opportunity; persist outcome separately."""
    spec_path = Path(spec_path)
    _check_signed_hp_spec(spec_path, spec_sha256, hp)
    validate_hp_spec(hp, bound.identity.product_src, enabled=True)
    bound.recheck()
    before = bound.model_gate.snapshot()["physical"]
    root = bound.identity.run_dir
    if before + hp["max_model_calls"] > bound.caps.physical_model_calls:
        hp_result = {"status": "HP_POST_WORKER_BLOCKED",
                     "reason": "HP_MODEL_BUDGET_UNAVAILABLE",
                     "sp_global_effect": "UNCHANGED",
                     "security_gate_credit": "NOT_CREDITED"}
        claim_sha = None
    else:
        claim_sha = _claim_hp_run(bound, worker_receipt, hp, spec_sha256)
        try:
            physical_factory = _physical_handoff_factory(
                bound, hp, worker_receipt, spec_path, spec_sha256)
            hp_result = asyncio.run(run_post_worker_hp(
                bound=bound, worker_receipt=worker_receipt,
                analysis_pipeline_factory=_pipeline_factory(
                    bound, hp, "function_analysis", spec_path, spec_sha256),
                assertion_pipeline_factory=_pipeline_factory(
                    bound, hp, "assertion_generator", spec_path, spec_sha256),
                max_items=hp["max_items"],
                physical_handoff_factory=physical_factory))
        except BaseException as exc:
            hp_result = {"status": "HP_POST_WORKER_PARTIAL_BLOCKED",
                         "reason": "HP_UNEXPECTED_EXCEPTION",
                         "error_type": type(exc).__name__,
                         "sp_global_effect": "UNCHANGED",
                         "security_gate_credit": "NOT_CREDITED"}
    after = bound.model_gate.snapshot()["physical"]
    process, process_sha = bound.process_ledger.receipt_snapshot()
    try:
        _check_signed_hp_spec(spec_path, spec_sha256, hp)
        validate_hp_spec(hp, bound.identity.product_src, enabled=True)
        bound.recheck()
        pins_ok = True
    except Exception:
        pins_ok = False
    if (not pins_ok or after < before or
            after - before > hp["max_model_calls"] or
            process.get("stop_status") is not None or process.get("active")):
        hp_result = {"status": "HP_POST_WORKER_PARTIAL_BLOCKED",
                     "reason": "HP_PHYSICAL_ACCOUNT_UNSETTLED",
                     "sp_global_effect": "UNCHANGED",
                     "security_gate_credit": "NOT_CREDITED"}
    elif hp_result.get("status") == "HP_POST_WORKER_COMPLETE":
        rows = hp_result.get("rows")
        if type(rows) is not list or hp_result.get("selected_count") == 0:
            hp_result = {**hp_result, "status": "HP_POST_WORKER_NO_OPPORTUNITY",
                         "reason": "NO_SP_ANALYZED_FUNCTION"}
        elif any(type(row) is not dict or
                 str(row.get("status", "")).startswith("INCOMPLETE")
                 for row in rows):
            hp_result = {**hp_result,
                         "status": "HP_POST_WORKER_PARTIAL_BLOCKED",
                         "reason": "HP_ITEM_INCOMPLETE"}
    physical_requested = hp.get("physical") is not None
    if hp_result.get("status") == "HP_POST_WORKER_COMPLETE":
        physical_status = hp_result.get("physical_execution_status")
        if not physical_requested:
            hp_result = {**hp_result,
                         "analysis_status": "COMPLETE",
                         "physical_execution_status": "NOT_REQUESTED"}
        elif physical_status not in {"COMPLETE", "NOT_RUN_NO_PROPOSAL"}:
            hp_result = {**hp_result,
                         "status": "HP_POST_WORKER_PARTIAL_BLOCKED",
                         "reason": "HP_PHYSICAL_COMPLETION_UNPROVEN"}
    physical_status = hp_result.get("physical_execution_status", "UNKNOWN")
    receipt = {"kind": "FBV2_PUBLIC_DEV_HP_RESULT_V1",
               "task_id": bound.identity.task_id,
               "run_id": bound.identity.run_id,
               "worker_id": worker_receipt["original_result"]["worker_id"],
               "claim_sha256": claim_sha,
               "hp_assets": hp["assets"],
               "max_items": hp["max_items"],
               "max_model_calls": hp["max_model_calls"],
               "model_physical_before": before,
               "model_physical_after": after,
               "process_receipt_sha256_after": process_sha,
               "hp_result": hp_result,
               "analysis_status": hp_result.get("analysis_status", "INCOMPLETE"),
               "physical_execution_status": physical_status,
               "completion_scope": ("PHYSICAL_HANDOFF_COMPLETE" if
                   physical_status == "COMPLETE" else "ANALYSIS_ONLY" if
                   physical_status in {"NOT_REQUESTED", "NOT_RUN_NO_PROPOSAL"}
                   else "INCOMPLETE"),
               "original_status": worker_receipt.get("status"),
               "sp_global_effect": "UNCHANGED",
               "security_gate_credit": "NOT_CREDITED"}
    receipt_sha = _write_once(root / _HP_RESULT, receipt)
    return {"status": hp_result["status"], "result_path": str(root / _HP_RESULT),
            "result_sha256": receipt_sha, "model_physical_calls": after - before,
            "analysis_status": receipt["analysis_status"],
            "physical_execution_status": physical_status,
            "completion_scope": receipt["completion_scope"],
            "sp_global_effect": "UNCHANGED",
            "security_gate_credit": "NOT_CREDITED"}
