from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from devtools import original_public_live_entry as entry


def _write(path: Path, value: object) -> str:
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fixture(tmp_path: Path, monkeypatch):
    task = tmp_path / "task"
    (task / "repo").mkdir(parents=True)
    (task / "repo/source.c").write_text("int f(void) { return 0; }\n")
    executable = task / "repo/tool.sh"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)
    subprocess.run(["git", "init", "-q", str(task / "repo")], check=True)
    subprocess.run(["git", "-C", str(task / "repo"), "config",
                    "core.fileMode", "true"], check=True)
    subprocess.run(["git", "-C", str(task / "repo"), "add", "."],
                   check=True)
    subprocess.run(
        ["git", "-C", str(task / "repo"), "-c", "user.name=Test",
         "-c", "user.email=test@example.com", "commit", "-qm", "fixture"],
        check=True)
    private = Ed25519PrivateKey.generate()
    public_path = tmp_path / "approval.pub"
    public_path.write_bytes(private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo))
    public_sha = hashlib.sha256(public_path.read_bytes()).hexdigest()
    monkeypatch.setattr(entry, "_TRUSTED_SP_APPROVAL_PUBLIC_KEY_SHA256",
                        frozenset({public_sha}))
    runtime_python = tmp_path / "runtime-python"
    runtime_python.write_bytes(b"pinned test runtime\n")
    runtime_python.chmod(0o755)
    runtime_python_sha = hashlib.sha256(
        runtime_python.read_bytes()).hexdigest()
    runtime_supervisor = tmp_path / "runtime-supervisor.py"
    runtime_supervisor.write_text("# pinned supervisor\n")
    runtime_supervisor_sha = hashlib.sha256(
        runtime_supervisor.read_bytes()).hexdigest()
    runtime_manifest = tmp_path / "runtime-closure.json"
    runtime_manifest_sha = _write(runtime_manifest, {
        "kind": "FBV2_SP_RUNTIME_CLOSURE_V1",
        "runtime_python_sha256": runtime_python_sha,
        "supervisor_sha256": runtime_supervisor_sha,
    })

    project = "fixture-project"
    revision = "a" * 40
    binary = b"fixture asan binary\n"
    coverage = b"fixture coverage binary\n"
    binary_sha = hashlib.sha256(binary).hexdigest()
    coverage_sha = hashlib.sha256(coverage).hexdigest()
    contract = tmp_path / "contract.json"
    contract.write_text("{}\n")
    contract_sha = hashlib.sha256(contract.read_bytes()).hexdigest()
    manifest = tmp_path / "manifest.json"
    manifest_sha = _write(manifest, {
        "asan_binary": {"path": str(tmp_path / "fixture-fuzzer"),
                        "sha256": binary_sha},
        "coverage_binary": {"path": str(tmp_path / "fixture-coverage"),
                            "sha256": coverage_sha},
        "fuzzer_name": "fixture-fuzzer", "project_name": project,
        "schema": "fbv2-prebuilt-v1", "source_commit": revision,
    })
    repo_sha = entry._clean_repo_tree_sha256(task / "repo")
    git_sha = entry._source_git_inventory_sha256(task / "repo/.git")
    prebuilt = task / ".fbv2_prebuilt" / manifest_sha
    (prebuilt / "binaries/address").mkdir(parents=True)
    (prebuilt / "binaries/coverage").mkdir(parents=True)
    (prebuilt / "mongodb").mkdir(parents=True)
    (prebuilt / "binaries/address/fixture-fuzzer").write_bytes(binary)
    (prebuilt / "binaries/coverage/fixture-fuzzer").write_bytes(coverage)
    (prebuilt / "mongodb/callgraph.json").write_text("[]")
    (prebuilt / "mongodb/functions.json").write_text("[]")
    prereg = tmp_path / "prereg.json"
    selection = tmp_path / "selection.json"
    clean = tmp_path / "clean.json"
    preflight = tmp_path / "preflight.json"
    qualification = tmp_path / "qualification.json"
    prereg_sha = _write(prereg, {
        "external_calls_authorized": False,
        "additional_repository": {
            "maximum_campaign_attempts": 1,
            "historical_answer_material_allowed": False,
            "sp_fuzzer_enabled": False,
            "hp_enabled": False,
            "fixed_family": "ARITHMETIC_RANGE",
            "source_git_inventory_sha256": git_sha,
        },
    })
    qualification_sha = _write(qualification, {
        "binary_sha256": binary_sha,
        "contract_path": str(contract), "contract_sha256": contract_sha,
        "product_issued": True, "product_issuer_sha256": "9" * 64,
        "source_tree_sha256": repo_sha, "upstream_revision": revision,
    })
    selection_sha = _write(selection, {
        "selected_family": "ARITHMETIC_RANGE",
        "selected_tuple": [project, revision, qualification_sha],
        "model_calls": 0, "target_calls": 0,
    })
    entry._canonicalize_task_metadata(
        task, entry._task_executable_paths(
            task, manifest_sha, json.loads(manifest.read_bytes())))
    prepared_sha = entry._full_plain_tree_sha256(task)
    clean_sha = _write(clean, {
        "historical_answer_material_count": 0,
        "provider_calls": 0,
        "target_calls": 0,
        "source_revision": revision, "source_tree_sha256": repo_sha,
        "task_prepared_tree_sha256": prepared_sha,
        "task_repo_tree_sha256": repo_sha,
    })
    preflight_sha = _write(preflight, {
        "status": "PINNED_PROVIDER_FREE", "model_calls": 0,
        "target_executions": 0, "fuzzer_seconds": 0,
        "product_issued": True, "project_name": project,
        "fuzzer": "fixture-fuzzer", "binary_sha256": binary_sha,
        "contract_sha256": contract_sha,
        "manifest_path": str(manifest), "manifest_sha256": manifest_sha,
    })
    spec = {
        "admission": {"contract_path": str(contract),
                      "contract_sha256": contract_sha,
                      "manifest_path": str(manifest),
                      "manifest_sha256": manifest_sha,
                      "product_issuer_sha256": "9" * 64},
        "caps": {
            "calls_per_agent": 64,
            "gate_aux_reservation_seconds_per_observation": 600,
            "global_fuzz_seconds": 30, "global_reservation_seconds": 67.5,
            "model_turn_seconds": 300, "model_wall_seconds": 1500,
            "physical_model_calls": 120, "pov_attempts_per_candidate": 3,
            "pov_timeout_seconds": 10, "pov_wall_seconds": 25,
            "sp_fuzz_max_items": 0, "sp_fuzz_seconds": 0,
            "sp_start_min_remaining_calls": 30,
            "sp_start_min_remaining_wall_seconds": 600,
            "security_invariant_focus": "ARITHMETIC_RANGE",
            "total_fuzz_seconds": 67.5, "total_wall_seconds": 2400,
        },
        "development_seed_scope": {
            "direction_selection": "GENERIC_SECURITY_FAMILY_PRIORITY_MODEL_TIE_V1",
            "seed_directions": 1, "sp_function_limit": None,
            "security_invariant_focus": "ARITHMETIC_RANGE",
        },
        "identity": {
            "codex_executable_sha256": "4" * 64,
            "engine_py_sha256": "5" * 64,
            "evaluation_py_sha256": "6" * 64,
            "product_py_sha256": "7" * 64,
            "task_id": "1" * 24, "run_id": "2" * 24,
            "task_path": str(task),
            "mongo_url": "mongodb://127.0.0.1:27027",
            "mongo_database": "fresh_test_database",
        },
        "sp_live_admission": {
            "enabled": True,
            "contract_kind": "SP_SIGNED_LIVE_ADMISSION_V1",
            "one_attempt": True,
            "approval_public_key_path": str(public_path),
            "approval_public_key_sha256": public_sha,
            "preregistration_path": str(prereg),
            "preregistration_sha256": prereg_sha,
            "qualification_path": str(qualification),
            "qualification_sha256": qualification_sha,
            "selection_receipt_path": str(selection),
            "selection_receipt_sha256": selection_sha,
            "clean_task_audit_path": str(clean),
            "clean_task_audit_sha256": clean_sha,
            "provider_free_preflight_path": str(preflight),
            "provider_free_preflight_sha256": preflight_sha,
            "task_prepared_tree_sha256": prepared_sha,
            "live_entry_sha256": hashlib.sha256(
                Path(entry.__file__).read_bytes()).hexdigest(),
            "pinned_launcher_path": str(Path(entry.__file__).with_name(
                "sp_signed_live_pinned_launcher.py")),
            "pinned_launcher_sha256": hashlib.sha256(Path(
                entry.__file__).with_name(
                    "sp_signed_live_pinned_launcher.py").read_bytes()).hexdigest(),
            "runtime_python_path": str(runtime_python),
            "runtime_python_sha256": runtime_python_sha,
            "runtime_closure_manifest_path": str(runtime_manifest),
            "runtime_closure_manifest_sha256": runtime_manifest_sha,
            "runtime_closure_supervisor_path": str(runtime_supervisor),
            "runtime_closure_supervisor_sha256": runtime_supervisor_sha,
            "check_receipt_path": str(tmp_path / "check.json"),
            "live_authorization_path": str(tmp_path / "live-auth.json"),
            "internal_preflight_receipt_path": str(
                tmp_path / "internal-preflight.json"),
            "claim_path": str(tmp_path / "claim.json"),
        },
    }
    spec_sha = "8" * 64
    scope = entry._expected_sp_approval_scope(
        spec, spec_sha, spec["sp_live_admission"],
        json.loads(selection.read_bytes()), json.loads(clean.read_bytes()))
    body = {
        "decision": True, "kind": "FBV2_SP_NOHINT_LIVE_APPROVAL_V1",
        "reviewed_at": "2026-11-08T00:00:00Z", "reviewer_id": "human",
        "scope": scope, "status": "APPROVED",
    }
    signature = private.sign(entry._canonical_json(body))
    approval = {**body, "signature": {
        "kind": "ED25519_CANONICAL_JSON_V1", "key_id": public_sha,
        "value_base64": base64.b64encode(signature).decode(),
    }}
    approval_path = tmp_path / "approval.json"
    approval_sha = _write(approval_path, approval)
    return (spec, spec_sha, approval_path, approval_sha, public_path,
            public_sha, private)


def _combined_fixture(tmp_path: Path, monkeypatch):
    """Upgrade the ordinary fixture to the exact SP+post-Worker-HP V2 scope."""
    values = _fixture(tmp_path, monkeypatch)
    spec, spec_sha, v1_approval, v1_approval_sha, public, public_sha, private = (
        values)
    optin = spec["sp_live_admission"]
    optin["contract_kind"] = "SP_HP_POST_WORKER_SIGNED_LIVE_ADMISSION_V2"
    prereg_path = Path(optin["preregistration_path"])
    prereg = json.loads(prereg_path.read_bytes())
    prereg["additional_repository"]["hp_enabled"] = True
    optin["preregistration_sha256"] = _write(prereg_path, prereg)
    spec["caps"].update({
        "sp_start_min_remaining_calls": None,
        "sp_start_min_remaining_wall_seconds": None,
        "sp_concurrent_queue": True,
        "seed_required_unique": 5,
        "sp_discovery_agents": 3,
        "sp_verify_agents": 2,
        "sp_pov_agents": 2,
    })
    spec["development_seed_scope"] = {
        "kind": "SP_PERSISTENT_CONCURRENT_QUEUE_HP_POST_WORKER_DEV_V1",
        "seed_directions": 1,
        "sp_function_limit": None,
        "sp_queue_policy": "PERSISTENT_CONCURRENT_QUEUE_V1",
        "security_invariant_focus": "ARITHMETIC_RANGE",
        "direction_selection":
            "GENERIC_SECURITY_FAMILY_PRIORITY_MODEL_TIE_V1",
        "pov_attempts_per_candidate": 3,
        "worker_pool": {"discovery": 3, "verifier": 2, "pov": 2},
    }
    spec["hp"] = {
        "enabled": True, "max_items": 1, "max_model_calls": 3,
        "assets": {"fixture": "1" * 64},
        "physical": {"fixture": "2" * 64},
    }
    selection = json.loads(Path(optin["selection_receipt_path"]).read_bytes())
    clean = json.loads(Path(optin["clean_task_audit_path"]).read_bytes())
    scope = entry._expected_sp_approval_scope(
        spec, spec_sha, optin, selection, clean)
    body = {
        "decision": True,
        "kind": "FBV2_SP_HP_POST_WORKER_LIVE_APPROVAL_V2",
        "reviewed_at": "2026-11-10T00:00:00Z",
        "reviewer_id": "human",
        "scope": scope,
        "status": "APPROVED",
    }
    approval = {**body, "signature": {
        "kind": "ED25519_CANONICAL_JSON_V1", "key_id": public_sha,
        "value_base64": base64.b64encode(
            private.sign(entry._canonical_json(body))).decode(),
    }}
    approval_path = tmp_path / "combined-approval.json"
    approval_sha = _write(approval_path, approval)
    return (spec, spec_sha, approval_path, approval_sha, public, public_sha,
            private, v1_approval, v1_approval_sha)


def test_parallel_hp_approval_is_distinct_from_post_worker(
        tmp_path, monkeypatch):
    (spec, spec_sha, post_approval, post_approval_sha, public, public_sha,
     private, _, _) = _combined_fixture(tmp_path, monkeypatch)
    optin = spec["sp_live_admission"]
    spec["development_seed_scope"]["kind"] = (
        "SP_PERSISTENT_CONCURRENT_QUEUE_HP_PARALLEL_DEV_V1")
    spec["hp_gate"] = {
        "enabled": True, "max_leads": 1,
        "replay_timeout_seconds": 10,
        "replay_wall_seconds": 90,
        "source_wall_seconds": 90,
        "output_limit_bytes": 4_000_000,
    }
    spec["sp_gate_unsupported_crash_policy"] = (
        "PENDING_HUMAN_REVIEW_NO_TERMINAL_CREDIT_V1")
    optin["contract_kind"] = "SP_HP_PARALLEL_SIGNED_LIVE_ADMISSION_V1"
    prereg_path = Path(optin["preregistration_path"])
    prereg = json.loads(prereg_path.read_bytes())
    prereg["additional_repository"]["hp_execution_order"] = (
        "PARALLEL_AFTER_SHARED_DIRECTION_V1")
    prereg["additional_repository"]["hp_gate"] = spec["hp_gate"]
    prereg["additional_repository"]["seed_required_unique"] = 5
    prereg["additional_repository"][
        "sp_gate_unsupported_crash_policy"] = (
            spec["sp_gate_unsupported_crash_policy"])
    optin["preregistration_sha256"] = _write(prereg_path, prereg)
    old_prereg_path = tmp_path / "post-worker-prereg.json"
    old_prereg = json.loads(prereg_path.read_bytes())
    del old_prereg["additional_repository"]["hp_execution_order"]
    del old_prereg["additional_repository"]["hp_gate"]
    del old_prereg["additional_repository"]["seed_required_unique"]
    del old_prereg["additional_repository"][
        "sp_gate_unsupported_crash_policy"]
    old_prereg_sha = _write(old_prereg_path, old_prereg)
    with pytest.raises(ValueError, match="support evidence"):
        entry._sp_support_rows({**spec, "sp_live_admission": {
            **optin, "preregistration_path": str(old_prereg_path),
            "preregistration_sha256": old_prereg_sha}})
    selection = json.loads(Path(optin["selection_receipt_path"]).read_bytes())
    clean = json.loads(Path(optin["clean_task_audit_path"]).read_bytes())
    scope = entry._expected_sp_approval_scope(
        spec, spec_sha, optin, selection, clean)
    assert "hp_post_worker" not in scope
    assert scope["hp_parallel"]["concurrent_with_sp"] is True
    assert scope["hp_parallel"]["security_gate_credit"] == (
        "HP_GATE_VERIFIED_ONLY_AFTER_REPROOF")
    assert scope["hp_parallel"]["gate_policy"] == spec["hp_gate"]
    assert scope["sp_gate_policy"]["unsupported_crash_type"] == (
        "PENDING_HUMAN_REVIEW_NO_TERMINAL_CREDIT_V1")
    for field, value in (("seed_required_unique", 4),
                         ("sp_gate_unsupported_crash_policy", "TERMINAL")):
        changed_prereg = json.loads(prereg_path.read_bytes())
        changed_prereg["additional_repository"][field] = value
        changed_path = tmp_path / f"mismatched-{field}.json"
        changed_sha = _write(changed_path, changed_prereg)
        with pytest.raises(ValueError, match="support evidence"):
            entry._sp_support_rows({**spec, "sp_live_admission": {
                **optin, "preregistration_path": str(changed_path),
                "preregistration_sha256": changed_sha}})
    assert scope["hp_parallel"]["selection_policy"] == (
        "PARALLEL_HP_PRE_SP_SELECTION_V1")
    with pytest.raises(ValueError, match="scope"):
        entry._verify_sp_approval(
            spec, spec_sha, approval_path=post_approval,
            approval_sha256=post_approval_sha, public_key_path=public,
            public_key_sha256=public_sha)

    body = {
        "decision": True, "kind": "FBV2_SP_HP_PARALLEL_LIVE_APPROVAL_V1",
        "reviewed_at": "2026-11-14T00:00:00Z", "reviewer_id": "human",
        "scope": scope, "status": "APPROVED",
    }
    approval_path = tmp_path / "parallel-approval.json"
    approval_sha = _write(approval_path, {**body, "signature": {
        "kind": "ED25519_CANONICAL_JSON_V1", "key_id": public_sha,
        "value_base64": base64.b64encode(
            private.sign(entry._canonical_json(body))).decode(),
    }})
    entry._verify_sp_approval(
        spec, spec_sha, approval_path=approval_path,
        approval_sha256=approval_sha, public_key_path=public,
        public_key_sha256=public_sha)

    post_optin = {**optin,
                  "contract_kind": "SP_HP_POST_WORKER_SIGNED_LIVE_ADMISSION_V2"}
    with pytest.raises(ValueError, match="admission"):
        entry._sp_support_rows({**spec, "sp_live_admission": post_optin})
    wrong_receipt = tmp_path / "post-check.json"
    wrong_sha = _write(wrong_receipt, {
        "kind": "FBV2_SP_HP_POST_WORKER_CHECK_ONLY_RECEIPT_V2"})
    with pytest.raises(ValueError, match="scope"):
        entry._verify_sp_check_receipt(
            spec, spec_sha, {**optin, "check_receipt_path": str(wrong_receipt)},
            approval_sha256=approval_sha, receipt_path=wrong_receipt,
            receipt_sha256=wrong_sha)
    receipt_path = Path(optin["check_receipt_path"])
    receipt_sha = _write(receipt_path, {
        "approval_sha256": approval_sha,
        "engine_py_sha256": spec["identity"]["engine_py_sha256"],
        "evaluation_py_sha256": spec["identity"]["evaluation_py_sha256"],
        "kind": "FBV2_SP_HP_PARALLEL_CHECK_ONLY_RECEIPT_V1",
        "model_calls": 0, "nonce": "a" * 64,
        "product_py_sha256": spec["identity"]["product_py_sha256"],
        "run_id": spec["identity"]["run_id"],
        "runtime_python_sha256": optin["runtime_python_sha256"],
        "runtime_closure_manifest_sha256":
            optin["runtime_closure_manifest_sha256"],
        "runtime_closure_supervisor_sha256":
            optin["runtime_closure_supervisor_sha256"],
        "spec_sha256": spec_sha, "status": "PREFLIGHT_READY",
        "target_calls": 0, "task_id": spec["identity"]["task_id"],
        "task_prepared_tree_sha256": optin["task_prepared_tree_sha256"],
    })
    entry._verify_sp_check_receipt(
        spec, spec_sha, optin, approval_sha256=approval_sha,
        receipt_path=receipt_path, receipt_sha256=receipt_sha)
    authorization_scope = {
        "approval_sha256": approval_sha,
        "check_receipt_sha256": receipt_sha, "one_attempt": True,
        "public_key_sha256": public_sha,
        "run_id": spec["identity"]["run_id"],
        "spec_sha256": spec_sha,
        "task_id": spec["identity"]["task_id"],
    }
    auth_body = {
        "decision": True,
        "kind": "FBV2_SP_HP_PARALLEL_LIVE_AUTHORIZATION_V1",
        "reviewed_at": "2026-11-14T00:01:00Z", "reviewer_id": "human",
        "scope": authorization_scope, "status": "APPROVED",
    }
    auth_path = Path(optin["live_authorization_path"])
    auth_sha = _write(auth_path, {**auth_body, "signature": {
        "kind": "ED25519_CANONICAL_JSON_V1", "key_id": public_sha,
        "value_base64": base64.b64encode(
            private.sign(entry._canonical_json(auth_body))).decode(),
    }})
    entry._verify_sp_live_authorization(
        spec, spec_sha, optin, approval_sha256=approval_sha,
        check_receipt_sha256=receipt_sha, authorization_path=auth_path,
        authorization_sha256=auth_sha)
    claim_sha = entry._claim_sp_live_once(
        spec, spec_sha, optin, approval_sha256=approval_sha,
        check_receipt_sha256=receipt_sha,
        live_authorization_sha256=auth_sha)
    assert len(claim_sha) == 64
    assert json.loads(Path(optin["claim_path"]).read_bytes())["kind"] == (
        "FBV2_SP_HP_PARALLEL_LIVE_CLAIM_V1")
    assert entry._signed_sp_kind(spec, "database_collection") != (
        entry._signed_sp_kind(
            {**spec, "development_seed_scope": {
                **spec["development_seed_scope"],
                "kind": "SP_PERSISTENT_CONCURRENT_QUEUE_HP_POST_WORKER_DEV_V1"}},
            "database_collection"))


def _refreeze_task(spec: dict,
                   executable_paths: set[str] | None = None) -> None:
    task = Path(spec["identity"]["task_path"])
    manifest_path = Path(spec["admission"]["manifest_path"])
    manifest = json.loads(manifest_path.read_bytes())
    entry._canonicalize_task_metadata(
        task, executable_paths if executable_paths is not None else
        entry._task_executable_paths(
            task, spec["admission"]["manifest_sha256"], manifest))
    prepared_sha = entry._full_plain_tree_sha256(task)
    optin = spec["sp_live_admission"]
    optin["task_prepared_tree_sha256"] = prepared_sha
    clean_path = Path(optin["clean_task_audit_path"])
    clean = json.loads(clean_path.read_bytes())
    clean["task_prepared_tree_sha256"] = prepared_sha
    optin["clean_task_audit_sha256"] = _write(clean_path, clean)


def test_exact_signed_sp_approval_is_accepted(tmp_path, monkeypatch):
    values = _fixture(tmp_path, monkeypatch)
    spec, spec_sha, approval, approval_sha, public, public_sha, _ = values
    optin, parsed = entry._verify_sp_approval(
        spec, spec_sha, approval_path=approval, approval_sha256=approval_sha,
        public_key_path=public, public_key_sha256=public_sha)
    assert optin["one_attempt"] is True
    assert parsed["scope"]["execution"]["signed_spec_sha256"] == spec_sha
    assert parsed["scope"]["pins"]["runtime_python_sha256"] == (
        optin["runtime_python_sha256"])
    assert parsed["scope"]["pins"]["runtime_closure_manifest_sha256"] == (
        optin["runtime_closure_manifest_sha256"])
    assert parsed["scope"]["pins"]["runtime_closure_supervisor_sha256"] == (
        optin["runtime_closure_supervisor_sha256"])


def test_combined_hp_v2_approval_is_exact_and_v1_cannot_cross_authorize(
        tmp_path, monkeypatch):
    values = _combined_fixture(tmp_path, monkeypatch)
    (spec, spec_sha, approval, approval_sha, public, public_sha, private,
     v1_approval, v1_approval_sha) = values
    optin, parsed = entry._verify_sp_approval(
        spec, spec_sha, approval_path=approval, approval_sha256=approval_sha,
        public_key_path=public, public_key_sha256=public_sha)
    assert optin["contract_kind"] == (
        "SP_HP_POST_WORKER_SIGNED_LIVE_ADMISSION_V2")
    assert parsed["kind"] == "FBV2_SP_HP_POST_WORKER_LIVE_APPROVAL_V2"
    assert parsed["scope"]["modes"]["hp"] is True
    assert parsed["scope"]["hp_post_worker"]["model_budget_reserved"] is False
    assert parsed["scope"]["caps"]["seed_required_unique"] == 5
    changed_seed_policy = {**spec, "caps": {
        **spec["caps"], "seed_required_unique": 1}}
    with pytest.raises(ValueError, match="scope"):
        entry._verify_sp_approval(
            changed_seed_policy, spec_sha, approval_path=approval,
            approval_sha256=approval_sha, public_key_path=public,
            public_key_sha256=public_sha)
    with pytest.raises(ValueError, match="scope"):
        entry._verify_sp_approval(
            spec, spec_sha, approval_path=v1_approval,
            approval_sha256=v1_approval_sha, public_key_path=public,
            public_key_sha256=public_sha)

    receipt = {
        "approval_sha256": approval_sha,
        "engine_py_sha256": spec["identity"]["engine_py_sha256"],
        "evaluation_py_sha256": spec["identity"]["evaluation_py_sha256"],
        "kind": "FBV2_SP_HP_POST_WORKER_CHECK_ONLY_RECEIPT_V2",
        "model_calls": 0, "nonce": "c" * 64,
        "product_py_sha256": spec["identity"]["product_py_sha256"],
        "run_id": spec["identity"]["run_id"], "spec_sha256": spec_sha,
        "runtime_python_sha256": optin["runtime_python_sha256"],
        "runtime_closure_manifest_sha256":
            optin["runtime_closure_manifest_sha256"],
        "runtime_closure_supervisor_sha256":
            optin["runtime_closure_supervisor_sha256"],
        "status": "PREFLIGHT_READY", "target_calls": 0,
        "task_id": spec["identity"]["task_id"],
        "task_prepared_tree_sha256": optin["task_prepared_tree_sha256"],
    }
    receipt_path = Path(optin["check_receipt_path"])
    receipt_sha = _write(receipt_path, receipt)
    entry._verify_sp_check_receipt(
        spec, spec_sha, optin, approval_sha256=approval_sha,
        receipt_path=receipt_path, receipt_sha256=receipt_sha)
    wrong_receipt = {**receipt,
                     "kind": "FBV2_SP_SIGNED_CHECK_ONLY_RECEIPT_V1"}
    wrong_path = tmp_path / "wrong-v1-receipt.json"
    wrong_sha = _write(wrong_path, wrong_receipt)
    with pytest.raises(ValueError, match="scope"):
        entry._verify_sp_check_receipt(
            spec, spec_sha, {**optin, "check_receipt_path": str(wrong_path)},
            approval_sha256=approval_sha, receipt_path=wrong_path,
            receipt_sha256=wrong_sha)

    auth_scope = {
        "approval_sha256": approval_sha,
        "check_receipt_sha256": receipt_sha,
        "one_attempt": True,
        "public_key_sha256": public_sha,
        "run_id": spec["identity"]["run_id"],
        "spec_sha256": spec_sha,
        "task_id": spec["identity"]["task_id"],
    }

    def signed_authorization(kind: str) -> dict:
        body = {
            "decision": True, "kind": kind,
            "reviewed_at": "2026-11-10T00:01:00Z",
            "reviewer_id": "human", "scope": auth_scope,
            "status": "APPROVED",
        }
        return {**body, "signature": {
            "kind": "ED25519_CANONICAL_JSON_V1", "key_id": public_sha,
            "value_base64": base64.b64encode(
                private.sign(entry._canonical_json(body))).decode(),
        }}

    auth_path = Path(optin["live_authorization_path"])
    auth_sha = _write(auth_path, signed_authorization(
        "FBV2_SP_HP_POST_WORKER_LIVE_AUTHORIZATION_V2"))
    entry._verify_sp_live_authorization(
        spec, spec_sha, optin, approval_sha256=approval_sha,
        check_receipt_sha256=receipt_sha,
        authorization_path=auth_path, authorization_sha256=auth_sha)
    wrong_auth_path = tmp_path / "wrong-v1-authorization.json"
    wrong_auth_sha = _write(wrong_auth_path, signed_authorization(
        "FBV2_SP_CHECK_ONLY_LIVE_AUTHORIZATION_V1"))
    with pytest.raises(ValueError, match="authorization"):
        entry._verify_sp_live_authorization(
            spec, spec_sha,
            {**optin, "live_authorization_path": str(wrong_auth_path)},
            approval_sha256=approval_sha,
            check_receipt_sha256=receipt_sha,
            authorization_path=wrong_auth_path,
            authorization_sha256=wrong_auth_sha)
    claim_sha = entry._claim_sp_live_once(
        spec, spec_sha, optin, approval_sha256=approval_sha,
        check_receipt_sha256=receipt_sha,
        live_authorization_sha256=auth_sha)
    claim = json.loads(Path(optin["claim_path"]).read_bytes())
    assert claim["kind"] == "FBV2_SP_HP_POST_WORKER_LIVE_CLAIM_V2"
    assert hashlib.sha256(Path(optin["claim_path"]).read_bytes()
                          ).hexdigest() == claim_sha


def test_combined_hp_v2_rejects_v1_admission_contract(tmp_path, monkeypatch):
    spec, *_ = _combined_fixture(tmp_path, monkeypatch)
    spec["sp_live_admission"]["contract_kind"] = "SP_SIGNED_LIVE_ADMISSION_V1"
    with pytest.raises(ValueError, match="admission"):
        entry._sp_support_rows(spec)


def test_runtime_python_symlink_or_hash_change_is_rejected(
        tmp_path, monkeypatch):
    spec, *_ = _fixture(tmp_path, monkeypatch)
    optin = spec["sp_live_admission"]
    runtime = Path(optin["runtime_python_path"])
    alias = tmp_path / "runtime-alias"
    alias.symlink_to(runtime)
    optin["runtime_python_path"] = str(alias)
    with pytest.raises(ValueError, match="runtime Python"):
        entry._sp_support_rows(spec)
    optin["runtime_python_path"] = str(runtime)
    optin["runtime_python_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="runtime Python"):
        entry._sp_support_rows(spec)


def test_fresh_process_runtime_must_match_signed_path(tmp_path, monkeypatch):
    spec, *_ = _fixture(tmp_path, monkeypatch)
    optin = spec["sp_live_admission"]
    runtime = optin["runtime_python_path"]
    spec_path = tmp_path / "signed-spec.json"
    spec_sha = _write(spec_path, spec)
    monkeypatch.setattr(entry, "_SIGNED_RUNTIME_CLOSURE_IDENTITY", {
        "FBV2_RUNTIME_CLOSURE_MANIFEST_PATH":
            optin["runtime_closure_manifest_path"],
        "FBV2_RUNTIME_CLOSURE_MANIFEST_SHA256":
            optin["runtime_closure_manifest_sha256"],
        "FBV2_RUNTIME_CLOSURE_SPEC_PATH": str(spec_path),
        "FBV2_RUNTIME_CLOSURE_SPEC_SHA256": spec_sha,
        "FBV2_RUNTIME_CLOSURE_SUPERVISOR_PATH":
            optin["runtime_closure_supervisor_path"],
        "FBV2_RUNTIME_CLOSURE_SUPERVISOR_SHA256":
            optin["runtime_closure_supervisor_sha256"],
        "FBV2_RUNTIME_CLOSURE_SUPERVISOR_PID": "1",
        "runtime_python_path": runtime,
        "runtime_python_sha256": optin["runtime_python_sha256"],
        "trusted_site_packages": str(entry._TRUSTED_SITE_PACKAGES),
    }, raising=False)
    monkeypatch.setattr(sys, "executable", runtime)
    entry._verify_signed_sp_runtime(spec, spec_path, spec_sha)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "other-python"))
    with pytest.raises(ValueError, match="runtime Python path changed"):
        entry._verify_signed_sp_runtime(spec, spec_path, spec_sha)


def test_missing_or_scope_changed_approval_is_rejected(tmp_path, monkeypatch):
    values = _fixture(tmp_path, monkeypatch)
    spec, spec_sha, approval, approval_sha, public, public_sha, _ = values
    with pytest.raises(ValueError, match="required"):
        entry._verify_sp_approval(
            spec, spec_sha, approval_path=None, approval_sha256=None,
            public_key_path=public, public_key_sha256=public_sha)
    changed = json.loads(approval.read_bytes())
    changed["scope"]["caps"]["physical_model_calls"] = 121
    changed_path = tmp_path / "changed.json"
    changed_sha = _write(changed_path, changed)
    with pytest.raises(ValueError, match="scope"):
        entry._verify_sp_approval(
            spec, spec_sha, approval_path=changed_path,
            approval_sha256=changed_sha, public_key_path=public,
            public_key_sha256=public_sha)


def test_prepared_task_extra_file_and_symlink_change_identity(tmp_path, monkeypatch):
    values = _fixture(tmp_path, monkeypatch)
    spec = values[0]
    task = Path(spec["identity"]["task_path"])
    original = entry._full_plain_tree_sha256(task)
    (task / ".fbv2_prebuilt").chmod(0o755)
    (task / ".fbv2_prebuilt/notes.txt").write_text("answer material\n")
    assert entry._full_plain_tree_sha256(task) != original
    (task / ".fbv2_prebuilt/notes.txt").unlink()
    (task / "repo").chmod(0o755)
    (task / "repo/build").symlink_to(tmp_path)
    with pytest.raises(ValueError, match="symlink"):
        entry._full_plain_tree_sha256(task)


@pytest.mark.parametrize("relative", [
    ".fbv2_prebuilt/HISTORICAL_ANSWER.txt",
    "repo/.git/HISTORICAL_ANSWER.txt",
    "HISTORICAL_ANSWER.txt",
])
def test_preexisting_answer_material_is_not_made_clean_by_rehashing(
        tmp_path, monkeypatch, relative):
    spec, *_ = _fixture(tmp_path, monkeypatch)
    task = Path(spec["identity"]["task_path"])
    extra = task / relative
    extra.parent.chmod(0o755)
    extra.parent.mkdir(parents=True, exist_ok=True)
    extra.write_text("known answer\n")
    _refreeze_task(spec)
    with pytest.raises(ValueError, match=(
            "inventory|historical-answer-like|Git inventory")):
        entry._sp_support_rows(spec)


def test_task_extended_attribute_is_rejected(tmp_path, monkeypatch):
    import os

    spec, *_ = _fixture(tmp_path, monkeypatch)
    source = Path(spec["identity"]["task_path"]) / "repo/source.c"
    source.chmod(0o644)
    try:
        os.setxattr(source, "user.fbv2_context", b"known answer")
    except OSError as exc:
        pytest.skip(f"test filesystem has no user xattr support: {exc}")
    try:
        with pytest.raises(ValueError, match="extended attributes"):
            entry._sp_support_rows(spec)
    finally:
        os.removexattr(source, "user.fbv2_context")


def test_unreadable_directory_cannot_hide_preexisting_file(tmp_path, monkeypatch):
    spec, *_ = _fixture(tmp_path, monkeypatch)
    branches = (Path(spec["identity"]["task_path"]) /
                "repo/.git/branches")
    branches.chmod(0o755)
    (branches / "context.txt").write_text("known answer\n")
    branches.chmod(0)
    try:
        with pytest.raises(ValueError, match="inaccessible node"):
            entry._sp_support_rows(spec)
    finally:
        branches.chmod(0o700)


def test_git_index_bytes_are_independently_pinned(tmp_path, monkeypatch):
    spec, *_ = _fixture(tmp_path, monkeypatch)
    task = Path(spec["identity"]["task_path"])
    manifest = json.loads(Path(spec["admission"]["manifest_path"]).read_bytes())
    executable_paths = entry._task_executable_paths(
        task, spec["admission"]["manifest_sha256"], manifest)
    index = task / "repo/.git/index"
    index.chmod(0o644)
    index.write_bytes(index.read_bytes() + b"optional-answer-extension")
    _refreeze_task(spec, executable_paths)
    with pytest.raises(ValueError, match="Git inventory"):
        entry._sp_support_rows(spec)


def test_mode_and_mtime_channels_are_rejected(tmp_path, monkeypatch):
    spec, *_ = _fixture(tmp_path, monkeypatch)
    source = Path(spec["identity"]["task_path"]) / "repo/source.c"
    source.chmod(0o454)
    source.touch()
    with pytest.raises(ValueError, match="metadata is not canonical"):
        entry._sp_support_rows(spec)


def test_git_tracked_executable_mode_remains_clean_after_canonicalization(
        tmp_path, monkeypatch):
    spec, *_ = _fixture(tmp_path, monkeypatch)
    task = Path(spec["identity"]["task_path"])
    executable = task / "repo/tool.sh"
    assert executable.stat().st_mode & 0o777 == 0o555
    status = subprocess.run(
        ["git", "--no-optional-locks", "status", "--porcelain",
         "--untracked-files=normal"], cwd=task / "repo", text=True,
        capture_output=True, check=True,
        env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"}).stdout
    assert status == ""
    entry._sp_support_rows(spec)


def test_git_executable_inventory_ignores_inherited_repository_overrides(
        tmp_path, monkeypatch):
    spec, *_ = _fixture(tmp_path, monkeypatch)
    task = Path(spec["identity"]["task_path"])
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "outside-git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(tmp_path / "outside-worktree"))
    monkeypatch.setenv("GIT_INDEX_FILE", str(tmp_path / "outside-index"))
    executable = entry._git_tracked_executable_paths(task)
    assert executable == {"repo/tool.sh"}
    entry._sp_support_rows(spec)


def test_live_lock_erases_post_signature_atime_channel(tmp_path, monkeypatch):
    spec, *_ = _fixture(tmp_path, monkeypatch)
    task = Path(spec["identity"]["task_path"])
    expected_sha = spec["sp_live_admission"]["task_prepared_tree_sha256"]
    nodes = [task, *entry._verified_plain_tree_paths(task)]
    hidden_atime = entry._CANONICAL_TASK_MTIME_NS + 123456789
    for path in nodes:
        info = path.lstat()
        path.chmod(info.st_mode | 0o200, follow_symlinks=False)
        os.utime(path, ns=(hidden_atime, info.st_mtime_ns),
                 follow_symlinks=False)
        path.chmod(info.st_mode, follow_symlinks=False)
    assert any(path.lstat().st_atime_ns == hidden_atime for path in nodes)
    entry._lock_task_readonly(task, expected_sha)
    assert all(path.lstat().st_atime_ns ==
               entry._CANONICAL_TASK_MTIME_NS for path in nodes)
    entry._sp_support_rows(spec)


def test_check_receipt_and_one_shot_claim_are_exact(tmp_path, monkeypatch):
    values = _fixture(tmp_path, monkeypatch)
    spec, spec_sha, _, approval_sha, _, public_sha, private = values
    optin = spec["sp_live_admission"]
    receipt = {
        "approval_sha256": approval_sha,
        "engine_py_sha256": spec["identity"]["engine_py_sha256"],
        "evaluation_py_sha256": spec["identity"]["evaluation_py_sha256"],
        "kind": "FBV2_SP_SIGNED_CHECK_ONLY_RECEIPT_V1",
        "model_calls": 0, "nonce": "a" * 64,
        "product_py_sha256": spec["identity"]["product_py_sha256"],
        "run_id": spec["identity"]["run_id"], "spec_sha256": spec_sha,
        "runtime_python_sha256": optin["runtime_python_sha256"],
        "runtime_closure_manifest_sha256":
            optin["runtime_closure_manifest_sha256"],
        "runtime_closure_supervisor_sha256":
            optin["runtime_closure_supervisor_sha256"],
        "status": "PREFLIGHT_READY", "target_calls": 0,
        "task_id": spec["identity"]["task_id"],
        "task_prepared_tree_sha256": optin["task_prepared_tree_sha256"],
    }
    receipt_path = Path(optin["check_receipt_path"])
    receipt_sha = _write(receipt_path, receipt)
    parsed = entry._verify_sp_check_receipt(
        spec, spec_sha, optin, approval_sha256=approval_sha,
        receipt_path=receipt_path, receipt_sha256=receipt_sha)
    assert parsed["model_calls"] == 0
    auth_body = {
        "decision": True,
        "kind": "FBV2_SP_CHECK_ONLY_LIVE_AUTHORIZATION_V1",
        "reviewed_at": "2026-11-08T00:01:00Z", "reviewer_id": "human",
        "scope": {
            "approval_sha256": approval_sha,
            "check_receipt_sha256": receipt_sha,
            "one_attempt": True, "public_key_sha256": public_sha,
            "run_id": spec["identity"]["run_id"], "spec_sha256": spec_sha,
            "task_id": spec["identity"]["task_id"],
        },
        "status": "APPROVED",
    }
    auth = {**auth_body, "signature": {
        "kind": "ED25519_CANONICAL_JSON_V1", "key_id": public_sha,
        "value_base64": base64.b64encode(
            private.sign(entry._canonical_json(auth_body))).decode(),
    }}
    auth_path = Path(optin["live_authorization_path"])
    auth_sha = _write(auth_path, auth)
    verified = entry._verify_sp_live_authorization(
        spec, spec_sha, optin, approval_sha256=approval_sha,
        check_receipt_sha256=receipt_sha,
        authorization_path=auth_path, authorization_sha256=auth_sha)
    assert verified["scope"]["check_receipt_sha256"] == receipt_sha
    entry._claim_sp_live_once(
        spec, spec_sha, optin, approval_sha256=approval_sha,
        check_receipt_sha256=receipt_sha,
        live_authorization_sha256=auth_sha)
    with pytest.raises(FileExistsError):
        entry._claim_sp_live_once(
            spec, spec_sha, optin, approval_sha256=approval_sha,
            check_receipt_sha256=receipt_sha,
            live_authorization_sha256=auth_sha)

    wrong = json.loads(auth_path.read_bytes())
    wrong["scope"]["check_receipt_sha256"] = "f" * 64
    wrong_path = tmp_path / "wrong-live-auth.json"
    wrong_sha = _write(wrong_path, wrong)
    with pytest.raises(ValueError, match="authorization"):
        entry._verify_sp_live_authorization(
            spec, spec_sha, {**optin,
                             "live_authorization_path": str(wrong_path)},
            approval_sha256=approval_sha,
            check_receipt_sha256=receipt_sha,
            authorization_path=wrong_path, authorization_sha256=wrong_sha)


@pytest.mark.parametrize("combined", [False, True])
def test_live_database_must_be_fresh_and_is_claimed_once(
        tmp_path, monkeypatch, combined):
    import pymongo

    values = (_combined_fixture(tmp_path, monkeypatch) if combined else
              _fixture(tmp_path, monkeypatch))
    spec, spec_sha, _, approval_sha, _, _, _ = values[:7]

    class Collection:
        def __init__(self):
            self.rows = []

        def insert_one(self, row):
            self.rows.append(row)

        def count_documents(self, _query):
            return len(self.rows)

        def find(self, _query):
            return list(self.rows)

    class Database:
        def __init__(self):
            self.collections = {}

        def list_collection_names(self):
            return sorted(self.collections)

        def create_collection(self, name):
            if name in self.collections:
                raise RuntimeError("already exists")
            self.collections[name] = Collection()

        def __getitem__(self, name):
            return self.collections[name]

    database = Database()

    class Admin:
        def command(self, value):
            assert value == "ping"

    class Client:
        admin = Admin()

        def __getitem__(self, _name):
            return database

        def close(self):
            pass

    monkeypatch.setattr(pymongo, "MongoClient", lambda *_a, **_kw: Client())
    entry._claim_sp_live_database_once(
        spec, spec_sha, approval_sha256=approval_sha,
        check_receipt_sha256="9" * 64,
        live_authorization_sha256="a" * 64)
    expected_name = ("__fbv2_sp_hp_post_worker_live_claim_v2"
                     if combined else "__fbv2_sp_signed_live_claim_v1")
    assert database.list_collection_names() == [expected_name]
    entry._reverify_sp_live_database_claim(
        spec, spec_sha, approval_sha256=approval_sha,
        check_receipt_sha256="9" * 64,
        live_authorization_sha256="a" * 64)
    with pytest.raises(ValueError, match="not fresh"):
        entry._claim_sp_live_database_once(
            spec, spec_sha, approval_sha256=approval_sha,
            check_receipt_sha256="9" * 64,
            live_authorization_sha256="a" * 64)


@pytest.mark.parametrize("mutation", [
    "kind", "field", "extra_document", "extra_collection",
])
def test_combined_v2_database_claim_mutation_fails_revalidation(
        tmp_path, monkeypatch, mutation):
    import pymongo

    values = _combined_fixture(tmp_path, monkeypatch)
    spec, spec_sha, _, approval_sha = values[:4]

    class Collection:
        def __init__(self):
            self.rows = []

        def insert_one(self, row):
            self.rows.append(row)

        def count_documents(self, _query):
            return len(self.rows)

        def find(self, _query):
            return list(self.rows)

    class Database:
        def __init__(self):
            self.collections = {}

        def list_collection_names(self):
            return sorted(self.collections)

        def create_collection(self, name):
            self.collections[name] = Collection()

        def __getitem__(self, name):
            return self.collections[name]

    database = Database()

    class Client:
        admin = type("Admin", (), {"command": lambda _self, value: value})()

        def __getitem__(self, _name):
            return database

        def close(self):
            pass

    monkeypatch.setattr(pymongo, "MongoClient", lambda *_a, **_kw: Client())
    entry._claim_sp_live_database_once(
        spec, spec_sha, approval_sha256=approval_sha,
        check_receipt_sha256="9" * 64,
        live_authorization_sha256="a" * 64)
    name = "__fbv2_sp_hp_post_worker_live_claim_v2"
    if mutation == "kind":
        database[name].rows[0]["kind"] = "FBV2_SP_SIGNED_LIVE_DATABASE_CLAIM_V1"
    elif mutation == "field":
        database[name].rows[0]["approval_sha256"] = "0" * 64
    elif mutation == "extra_document":
        database[name].rows.append({"_id": "extra"})
    else:
        database.collections["unexpected"] = Collection()
    with pytest.raises(ValueError, match="claim changed"):
        entry._reverify_sp_live_database_claim(
            spec, spec_sha, approval_sha256=approval_sha,
            check_receipt_sha256="9" * 64,
            live_authorization_sha256="a" * 64)


def test_unsigned_ordinary_sp_live_is_closed():
    with pytest.raises(ValueError, match="signed SP live admission"):
        entry._require_signed_sp_live({}, ordinary_sp_live=True)
    entry._require_signed_sp_live({}, ordinary_sp_live=False)


@pytest.mark.parametrize("field,value", [
    ("selected_revision", "b" * 40),
    ("false_counter", False),
    ("stale_repo", "c" * 64),
])
def test_support_evidence_is_cross_bound_and_exact_typed(
        tmp_path, monkeypatch, field, value):
    spec, *_ = _fixture(tmp_path, monkeypatch)
    optin = spec["sp_live_admission"]
    if field == "selected_revision":
        path = Path(optin["selection_receipt_path"])
        row = json.loads(path.read_bytes())
        row["selected_tuple"][1] = value
        optin["selection_receipt_sha256"] = _write(path, row)
    elif field == "false_counter":
        path = Path(optin["provider_free_preflight_path"])
        row = json.loads(path.read_bytes())
        row["model_calls"] = value
        optin["provider_free_preflight_sha256"] = _write(path, row)
    else:
        path = Path(optin["clean_task_audit_path"])
        row = json.loads(path.read_bytes())
        row["task_repo_tree_sha256"] = value
        optin["clean_task_audit_sha256"] = _write(path, row)
    with pytest.raises(ValueError, match="support evidence"):
        entry._sp_support_rows(spec)


def test_pinned_launcher_reads_the_authenticated_entry_image(tmp_path):
    from devtools import sp_signed_live_pinned_launcher as launcher

    source = tmp_path / "entry.py"
    source.write_text("VALUE = 1\n")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    assert launcher.pinned_bytes(source, digest) == b"VALUE = 1\n"
    with pytest.raises(ValueError, match="changed"):
        launcher.pinned_bytes(source, "0" * 64)


def test_pinned_launcher_rejects_site_startup_before_signed_entry():
    launcher = (Path(__file__).resolve().parents[1] / "devtools" /
                "sp_signed_live_pinned_launcher.py")
    unsafe = subprocess.run(
        [sys.executable, "-I", "-B", str(launcher)], capture_output=True,
        text=True, check=False, timeout=10)
    assert unsafe.returncode != 0
    assert "requires python -I -S isolation" in unsafe.stderr
    safe = subprocess.run(
        [sys.executable, "-I", "-S", "-B", str(launcher)],
        capture_output=True, text=True, check=False, timeout=10)
    assert safe.returncode == 2
    assert "required" in safe.stderr
