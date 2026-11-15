"""HP-only manual control remains closed until signed live admission is complete."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from devtools.original_public_live_entry import (
    _hp_only_preimport_admission, _hp_only_runtime_preflight)
from devtools import original_hp_live_optin as hp_live
from devtools.original_hp_preparation import (
    PreparedHPFunction, _assumption_lifecycle_live_admission_ok)
from vulnerabilityanalysis import official_harness
from bson import ObjectId


ENTRY = (Path(__file__).resolve().parent.parent / "devtools" /
         "original_public_live_entry.py")
LAUNCHER = (Path(__file__).resolve().parent.parent / "devtools" /
            "sp_signed_live_pinned_launcher.py")
PRODUCT_SRC = Path(official_harness.__file__).resolve().parent.parent
ENROLLED_HUMAN_KEY_SHA256 = (
    "8d68a3290a43e29ad4834269d1a9843ac9fac0fdc617910780c278f557b852c5")


def _approval_key(tmp_path: Path):
    private = Ed25519PrivateKey.generate()
    public_path = tmp_path / "human-approval-ed25519.pub.pem"
    public_path.write_bytes(private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))
    return private, public_path, hashlib.sha256(public_path.read_bytes()).hexdigest()


def test_production_human_approval_key_is_explicitly_enrolled():
    assert hp_live._TRUSTED_HUMAN_APPROVAL_PUBLIC_KEY_SHA256 == frozenset({
        ENROLLED_HUMAN_KEY_SHA256})


def _sign_approval(private, public_sha: str, body: dict) -> dict:
    signature = private.sign(hp_live._canonical_json_bytes(body))
    return {**body, "signature": {
        "kind": "ED25519_CANONICAL_JSON_V1",
        "key_id": public_sha,
        "value_base64": base64.b64encode(signature).decode("ascii"),
    }}


def _selection_spec(tmp_path: Path):
    task = tmp_path / "task"
    manifest_sha = "a" * 64
    catalog = (task / ".fbv2_prebuilt" / manifest_sha /
               "mongodb" / "functions.json")
    catalog.parent.mkdir(parents=True)
    catalog.write_text("[]\n")
    spec = {
        "identity": {"task_path": str(task),
                     "task_id": str(ObjectId()), "run_id": str(ObjectId())},
        "admission": {"manifest_sha256": manifest_sha},
        "caps": {"physical_model_calls": 4, "calls_per_agent": 4},
        "hp": {"enabled": True, "max_model_calls": 4, "physical": {}},
        "hp_only": {
            "enabled": True, "function_name": "md_collect_marks",
            "automatic_discovery": False,
            "source_tree_sha256": "b" * 64,
            "functions_json_sha256": hashlib.sha256(
                catalog.read_bytes()).hexdigest(),
        },
    }
    return spec, catalog


def test_hp_only_preimport_requires_exact_signed_selection_and_mode(tmp_path):
    spec, catalog = _selection_spec(tmp_path)
    _hp_only_preimport_admission(spec, hp_only_mode=True,
                                 function_name="md_collect_marks",
                                 check_only=False)
    _hp_only_preimport_admission(spec, hp_only_mode=False,
                                 function_name=None, check_only=True)
    with pytest.raises(ValueError, match="differs from signed spec"):
        _hp_only_preimport_admission(spec, hp_only_mode=True,
                                     function_name="other", check_only=False)
    with pytest.raises(ValueError, match="explicit entry mode"):
        _hp_only_preimport_admission(spec, hp_only_mode=False,
                                     function_name=None, check_only=False)
    catalog.write_text("[{}]\n")
    with pytest.raises(ValueError, match="catalog pin changed"):
        _hp_only_preimport_admission(spec, hp_only_mode=True,
                                     function_name="md_collect_marks",
                                     check_only=False)


def test_hp_only_third_context_round_requires_signed_five_call_cap(tmp_path):
    spec, _ = _selection_spec(tmp_path)
    spec["hp_only"]["max_context_reanalyses"] = 3
    spec["hp"]["max_model_calls"] = 5
    spec["caps"]["physical_model_calls"] = 5
    spec["caps"]["calls_per_agent"] = 5
    _hp_only_preimport_admission(
        spec, hp_only_mode=True, function_name="md_collect_marks",
        check_only=False)
    spec["caps"]["physical_model_calls"] = 4
    with pytest.raises(ValueError, match="physical model cap"):
        _hp_only_preimport_admission(
            spec, hp_only_mode=True, function_name="md_collect_marks",
            check_only=False)


def test_hp_only_preimport_requires_pinned_human_lifecycle_approval(tmp_path):
    spec, _ = _selection_spec(tmp_path)
    approval = tmp_path / "approval.json"
    private, public_key, public_sha = _approval_key(tmp_path)
    scope = {
        "kind": "FBV2_HP_ASSUMPTION_LIFECYCLE_LIVE_SCOPE_V2",
        "contract_kind": "HP_PER_ASSUMPTION_EVIDENCE_CLOSURE_V5",
        "execution": {
            "task_id": spec["identity"]["task_id"],
            "run_id": spec["identity"]["run_id"],
            "signed_spec_subject_sha256": "f" * 64,
        },
        "selection": {
            "function_name": "md_collect_marks",
            "automatic_discovery": False,
            "one_attempt": True,
        },
    }
    body = {
        "kind": "FBV2_HP_ASSUMPTION_LIFECYCLE_LIVE_APPROVAL_V2",
        "status": "APPROVED", "decision": True,
        "reviewer_id": "human-fixture", "reviewed_at": "2026-11-06T00:00:00Z",
        "scope": scope,
    }
    approval.write_text(json.dumps(_sign_approval(
        private, public_sha, body)))
    spec["hp_only"]["assumption_evidence_closure"] = {
        "enabled": True,
        "contract_kind": "HP_PER_ASSUMPTION_EVIDENCE_CLOSURE_V5",
        "one_attempt": True,
        "approval_path": str(approval),
        "approval_sha256": hashlib.sha256(approval.read_bytes()).hexdigest(),
        "approval_public_key_path": str(public_key),
        "approval_public_key_sha256": public_sha,
    }
    _hp_only_preimport_admission(
        spec, hp_only_mode=True, function_name="md_collect_marks",
        check_only=False)
    approval.write_text("{}\n")
    with pytest.raises(ValueError, match="approval pin changed"):
        _hp_only_preimport_admission(
            spec, hp_only_mode=True, function_name="md_collect_marks",
            check_only=False)


def _lifecycle_approval_case(tmp_path, monkeypatch):
    approval_path = tmp_path / "human-approval.json"
    private, public_key_path, public_key_sha = _approval_key(tmp_path)
    monkeypatch.setattr(
        hp_live, "_TRUSTED_HUMAN_APPROVAL_PUBLIC_KEY_SHA256",
        frozenset({public_key_sha}))
    task_id, run_id = str(ObjectId()), str(ObjectId())
    q = SimpleNamespace(
        source_tree_sha256="1" * 64, contract_sha256="2" * 64,
        harness_sha256="3" * 64, binary_sha256="4" * 64,
        normal_seed_sha256="5" * 64)
    bound = SimpleNamespace(
        identity=SimpleNamespace(
            task_id=task_id, run_id=run_id,
            product_src=PRODUCT_SRC,
            codex_role_models={
                "function_analysis": {"model": "model-a", "reasoning": "high"},
                "assertion_generator": {"model": "model-b", "reasoning": "high"},
            },
            codex_model="fallback", codex_effort="high",
            codex_executable_sha256="6" * 64),
        admission=SimpleNamespace(
            qualification=q,
            summary={"manifest_sha256": "7" * 64}),
        caps=SimpleNamespace(
            physical_model_calls=5, calls_per_agent=5,
            model_wall_seconds=2900, model_turn_seconds=900),
    )
    hp = {"enabled": True, "max_model_calls": 5, "physical": {
        "enabled": True, "guided_seconds": 5,
        "total_wall_seconds": 120, "output_limit_bytes": 100000,
        "builder_path": "/fixture/builder", "builder_sha256": "8" * 64,
        "manifest_path": "/fixture/manifest", "manifest_sha256": "9" * 64,
    }}
    control = {
        "enabled": True, "function_name": "parse_array",
        "automatic_discovery": False,
        "source_tree_sha256": q.source_tree_sha256,
        "functions_json_sha256": "a" * 64,
        "max_context_reanalyses": 3,
        "assumption_evidence_closure": {
            "enabled": True,
            "contract_kind": "HP_PER_ASSUMPTION_EVIDENCE_CLOSURE_V5",
            "one_attempt": True,
            "approval_path": str(approval_path),
            "approval_sha256": "0" * 64,
            "approval_public_key_path": str(public_key_path),
            "approval_public_key_sha256": public_key_sha,
        },
    }
    spec_document = {
        "identity": {"task_id": task_id, "run_id": run_id},
        "hp": hp, "hp_only": control,
        "caps": {
            "physical_model_calls": 5, "calls_per_agent": 5,
            "model_wall_seconds": 2900, "model_turn_seconds": 900,
        },
    }
    subject_sha = hp_live._signed_spec_subject_sha256(spec_document)
    scope = hp_live._assumption_lifecycle_live_scope(
        bound, hp, control, signed_spec_subject_sha256=subject_sha)
    approval_body = {
        "kind": "FBV2_HP_ASSUMPTION_LIFECYCLE_LIVE_APPROVAL_V2",
        "status": "APPROVED", "decision": True,
        "reviewer_id": "human-fixture", "reviewed_at": "2026-11-06T00:00:00Z",
        "scope": scope,
    }
    approval_path.write_text(json.dumps(
        _sign_approval(private, public_key_sha, approval_body), sort_keys=True))
    control["assumption_evidence_closure"]["approval_sha256"] = (
        hashlib.sha256(approval_path.read_bytes()).hexdigest())
    spec_path = tmp_path / "signed-live-spec.json"
    spec_path.write_text(json.dumps(spec_document, sort_keys=True))
    spec_sha = hashlib.sha256(spec_path.read_bytes()).hexdigest()
    return (bound, hp, control, spec_path, spec_sha, approval_path,
            private, public_key_sha)


def test_lifecycle_live_approval_binds_complete_runtime_scope(
        tmp_path, monkeypatch):
    bound, hp, control, spec, spec_sha, _, _, _ = _lifecycle_approval_case(
        tmp_path, monkeypatch)
    token = hp_live._validate_assumption_lifecycle_live_approval(
        bound, hp, control, spec_path=spec, spec_sha256=spec_sha)
    assert token["kind"] == "FBV2_HP_ASSUMPTION_LIFECYCLE_LIVE_ADMISSION_V2"
    assert token["task_id"] == bound.identity.task_id
    assert token["run_id"] == bound.identity.run_id
    assert token["scope"]["selection"]["function_name"] == "parse_array"
    assert token["scope"]["budgets"]["max_context_reanalyses"] == 3
    assert token["scope"]["function_analysis_schema_sha256"] == (
        hp_live._assumption_lifecycle_live_scope(
            bound, hp, control,
            signed_spec_subject_sha256=token["signed_spec_subject_sha256"])[
            "function_analysis_schema_sha256"])


@pytest.mark.parametrize("mutation", ["model", "budget", "approval"])
def test_lifecycle_live_approval_rejects_scope_or_receipt_change(
        tmp_path, monkeypatch, mutation):
    (bound, hp, control, spec, spec_sha, approval,
     private, public_sha) = _lifecycle_approval_case(tmp_path, monkeypatch)
    if mutation == "model":
        bound.identity.codex_role_models["function_analysis"]["model"] = "changed"
    elif mutation == "budget":
        bound.caps.model_wall_seconds = 2901
    else:
        row = json.loads(approval.read_text())
        row["decision"] = False
        row.pop("signature")
        approval.write_text(json.dumps(
            _sign_approval(private, public_sha, row), sort_keys=True))
        control["assumption_evidence_closure"]["approval_sha256"] = (
            hashlib.sha256(approval.read_bytes()).hexdigest())
        document = json.loads(spec.read_text())
        document["hp_only"] = control
        spec.write_text(json.dumps(document, sort_keys=True))
        spec_sha = hashlib.sha256(spec.read_bytes()).hexdigest()
    with pytest.raises(ValueError):
        hp_live._validate_assumption_lifecycle_live_approval(
            bound, hp, control, spec_path=spec, spec_sha256=spec_sha)


def test_lifecycle_approval_is_bound_to_one_task_run_and_spec_subject(
        tmp_path, monkeypatch):
    (bound, hp, control, spec, spec_sha, _approval,
     _private, _public_sha) = _lifecycle_approval_case(tmp_path, monkeypatch)
    hp_live._validate_assumption_lifecycle_live_approval(
        bound, hp, control, spec_path=spec, spec_sha256=spec_sha)
    bound.identity.task_id = str(ObjectId())
    bound.identity.run_id = str(ObjectId())
    document = json.loads(spec.read_text())
    document["identity"]["task_id"] = bound.identity.task_id
    document["identity"]["run_id"] = bound.identity.run_id
    spec.write_text(json.dumps(document, sort_keys=True))
    changed_sha = hashlib.sha256(spec.read_bytes()).hexdigest()
    with pytest.raises(ValueError):
        hp_live._validate_assumption_lifecycle_live_approval(
            bound, hp, control, spec_path=spec, spec_sha256=changed_sha)


@pytest.mark.parametrize("mutation", ["unsigned_reviewer", "float_budget"])
def test_lifecycle_approval_requires_signature_and_exact_json_types(
        tmp_path, monkeypatch, mutation):
    (bound, hp, control, spec, _spec_sha, approval,
     private, public_sha) = _lifecycle_approval_case(tmp_path, monkeypatch)
    row = json.loads(approval.read_text())
    row.pop("signature")
    if mutation == "unsigned_reviewer":
        row["reviewer_id"] = "forged-reviewer"
        # Preserve the old signature over different bytes: authentication fails.
        signed = _sign_approval(private, public_sha, {
            **row, "reviewer_id": "human-fixture"})
        signed["reviewer_id"] = "forged-reviewer"
    else:
        row["scope"]["budgets"]["max_model_calls"] = 5.0
        signed = _sign_approval(private, public_sha, row)
    approval.write_text(json.dumps(signed, sort_keys=True))
    control["assumption_evidence_closure"]["approval_sha256"] = (
        hashlib.sha256(approval.read_bytes()).hexdigest())
    document = json.loads(spec.read_text())
    document["hp_only"] = control
    spec.write_text(json.dumps(document, sort_keys=True))
    spec_sha = hashlib.sha256(spec.read_bytes()).hexdigest()
    with pytest.raises(ValueError):
        hp_live._validate_assumption_lifecycle_live_approval(
            bound, hp, control, spec_path=spec, spec_sha256=spec_sha)


def test_lifecycle_approval_rejects_spec_nominated_unenrolled_key(
        tmp_path, monkeypatch):
    bound, hp, control, spec, spec_sha, _, _, _ = _lifecycle_approval_case(
        tmp_path, monkeypatch)
    monkeypatch.setattr(
        hp_live, "_TRUSTED_HUMAN_APPROVAL_PUBLIC_KEY_SHA256", frozenset())
    with pytest.raises(ValueError):
        hp_live._validate_assumption_lifecycle_live_approval(
            bound, hp, control, spec_path=spec, spec_sha256=spec_sha)


def test_execution_boundary_rechecks_lifecycle_admission_token(
        tmp_path, monkeypatch):
    bound, hp, control, spec, spec_sha, _, _, _ = _lifecycle_approval_case(
        tmp_path, monkeypatch)
    token = hp_live._validate_assumption_lifecycle_live_approval(
        bound, hp, control, spec_path=spec, spec_sha256=spec_sha)
    q = bound.admission.qualification
    work = SimpleNamespace(
        task_id=token["task_id"],
        function_name="parse_array",
        source_tree_sha256=q.source_tree_sha256,
        contract_sha256=q.contract_sha256,
        harness_sha256=q.harness_sha256,
        binary_sha256=q.binary_sha256,
        selection_origin="SIGNED_MANUAL_HP_CONTROL",
        analysis_scope={"selection_evidence": {
            "spec_sha256": token["spec_sha256"],
            "run_id": token["run_id"]}})
    gate = SimpleNamespace(physical_max=5, wall_seconds=2900.0)

    def pipeline(role):
        route = bound.identity.codex_role_models[role]
        transport = SimpleNamespace(
            model=route["model"], effort=route["reasoning"],
            executable_sha256=bound.identity.codex_executable_sha256,
            timeout_seconds=900)
        return SimpleNamespace(
            provider=SimpleNamespace(provider=transport, gate=gate),
            max_context_requests=2)

    analysis = pipeline("function_analysis")
    assertion = pipeline("assertion_generator")
    kwargs = dict(
        work=work, qualification=q, analysis_pipeline=analysis,
        assertion_pipeline=assertion, max_context_reanalyses=3,
        catalog_manifest_sha256="7" * 64)
    assert _assumption_lifecycle_live_admission_ok(token, **kwargs) is True
    changed = json.loads(json.dumps(token))
    changed["scope"]["budgets"]["max_context_reanalyses"] = 2
    assert _assumption_lifecycle_live_admission_ok(changed, **kwargs) is False
    analysis.provider.provider.model = "changed"
    assert _assumption_lifecycle_live_admission_ok(token, **kwargs) is False


def test_signed_hp_only_passes_signed_context_round_cap(tmp_path, monkeypatch):
    bound, hp, control, spec, _, _ = _hp_only_case(tmp_path, monkeypatch)
    control["max_context_reanalyses"] = 3
    hp["max_model_calls"] = 5
    spec.write_text(json.dumps({"hp": hp, "hp_only": control}))
    digest = hashlib.sha256(spec.read_bytes()).hexdigest()
    captured = []

    class Provider:
        async def close(self):
            pass

    monkeypatch.setattr(hp_live, "_pipeline_factory",
                        lambda *_a, **_kw: lambda _work:
                        SimpleNamespace(provider=Provider()))
    monkeypatch.setattr(hp_live, "_settled_model", lambda *_a: True)
    import devtools.original_hp_preparation as hp_preparation

    async def scripted_analysis(**kwargs):
        captured.append(kwargs["max_context_reanalyses"])
        return {"status": "NO_SAFE_ASSUMPTION"}

    monkeypatch.setattr(hp_preparation, "run_prepared_hp_analysis",
                        scripted_analysis)
    outcome = hp_live.run_signed_hp_only(
        bound, hp, control, spec_path=spec, spec_sha256=digest)
    assert outcome["status"] == "HP_ONLY_NO_PROPOSAL"
    assert captured == [3]


def test_signed_hp_only_wires_rechecked_lifecycle_admission_to_runner(
        tmp_path, monkeypatch):
    bound, hp, control, spec, _, _ = _hp_only_case(tmp_path, monkeypatch)
    control["assumption_evidence_closure"] = {
        "enabled": True,
        "contract_kind": "HP_PER_ASSUMPTION_EVIDENCE_CLOSURE_V5",
        "one_attempt": True,
        "approval_path": str(tmp_path / "approval.json"),
        "approval_sha256": "a" * 64,
    }
    spec.write_text(json.dumps({"hp": hp, "hp_only": control}))
    digest = hashlib.sha256(spec.read_bytes()).hexdigest()
    token = {
        "kind": "FBV2_HP_ASSUMPTION_LIFECYCLE_LIVE_ADMISSION_V1",
        "fixture": True,
    }
    validations = []
    monkeypatch.setattr(
        hp_live, "_validate_assumption_lifecycle_live_approval",
        lambda *_a, **_kw: validations.append(True) or token)

    class Provider:
        async def close(self):
            pass

    monkeypatch.setattr(hp_live, "_pipeline_factory",
                        lambda *_a, **_kw: lambda _work:
                        SimpleNamespace(provider=Provider()))
    monkeypatch.setattr(hp_live, "_settled_model", lambda *_a: True)
    import devtools.original_hp_preparation as hp_preparation
    captured = []

    async def scripted_analysis(**kwargs):
        captured.append((kwargs["per_assumption_evidence_closure"],
                         kwargs["assumption_lifecycle_live_admission"]))
        return {"status": "NO_SAFE_ASSUMPTION"}

    monkeypatch.setattr(hp_preparation, "run_prepared_hp_analysis",
                        scripted_analysis)
    outcome = hp_live.run_signed_hp_only(
        bound, hp, control, spec_path=spec, spec_sha256=digest)
    assert outcome["status"] == "HP_ONLY_NO_PROPOSAL"
    assert captured == [(True, token)]
    assert len(validations) >= 3


def test_check_only_uses_complete_runtime_lifecycle_validation(
        tmp_path, monkeypatch):
    bound, hp, control, spec_path, _, _ = _hp_only_case(tmp_path, monkeypatch)
    control["assumption_evidence_closure"] = {
        "enabled": True,
        "contract_kind": "HP_PER_ASSUMPTION_EVIDENCE_CLOSURE_V5",
        "one_attempt": True,
        "approval_path": str(tmp_path / "approval.json"),
        "approval_sha256": "a" * 64,
        "approval_public_key_path": str(tmp_path / "approval.pub"),
        "approval_public_key_sha256": "b" * 64,
    }
    spec = {"hp": hp, "hp_only": control}
    spec_path.write_text(json.dumps(spec))
    spec_sha = hashlib.sha256(spec_path.read_bytes()).hexdigest()
    calls = []
    token = {"kind": "complete-runtime-fixture"}
    monkeypatch.setattr(
        hp_live, "_validate_assumption_lifecycle_live_approval",
        lambda *_a, **_kw: calls.append(True) or token)
    assert _hp_only_runtime_preflight(
        bound, spec, spec_path=spec_path, spec_sha256=spec_sha) is token
    assert calls == [True]
    monkeypatch.setattr(
        hp_live, "_validate_assumption_lifecycle_live_approval",
        lambda *_a, **_kw: (_ for _ in ()).throw(
            ValueError("full scope mismatch")))
    with pytest.raises(ValueError, match="full scope mismatch"):
        _hp_only_runtime_preflight(
            bound, spec, spec_path=spec_path, spec_sha256=spec_sha)


def test_signed_hp_only_passes_four_turn_provenance_cap_to_physical_handoff(
        tmp_path, monkeypatch):
    bound, hp, control, spec, _, _ = _hp_only_case(tmp_path, monkeypatch)
    control["max_context_reanalyses"] = 3
    hp["max_model_calls"] = 5
    spec.write_text(json.dumps({"hp": hp, "hp_only": control}))
    digest = hashlib.sha256(spec.read_bytes()).hexdigest()
    captured = []

    class Provider:
        async def close(self):
            pass

    monkeypatch.setattr(hp_live, "_pipeline_factory",
                        lambda *_a, **_kw: lambda _work:
                        SimpleNamespace(provider=Provider()))
    monkeypatch.setattr(hp_live, "_settled_model", lambda *_a: True)
    import devtools.original_hp_preparation as hp_preparation

    async def scripted_analysis(**_kwargs):
        return {
            "status": "ASSERTIONS_PROPOSED_UNVERIFIED",
            "proposed_assertion_count": 1,
            "assertion_proposals": [{"assertion_id": "assert-fixture"}],
        }

    def physical_factory(*_args, **kwargs):
        captured.append(kwargs["signed_max_analysis_turns"])
        return lambda *_handoff: {
            "status": "HP_ASSERTION_HANDOFF_BLOCKED",
            "assertion_id": "assert-fixture",
            "reason": "PROVIDER_FREE_TEST_STOP",
        }

    monkeypatch.setattr(hp_preparation, "run_prepared_hp_analysis",
                        scripted_analysis)
    monkeypatch.setattr(hp_live, "_physical_handoff_factory",
                        physical_factory)
    outcome = hp_live.run_signed_hp_only(
        bound, hp, control, spec_path=spec, spec_sha256=digest)
    assert outcome["status"] == "HP_ONLY_PHYSICAL_INCOMPLETE"
    assert captured == [4]


@pytest.mark.parametrize("change", [
    lambda s: s["hp_only"].update(automatic_discovery=True),
    lambda s: s["hp_only"].update(function_name="../unsafe"),
    lambda s: s["hp_only"].update(source_tree_sha256="0"),
    lambda s: s["hp_only"].update(extra=True),
    lambda s: s["hp"].pop("physical"),
    lambda s: s["caps"].update(physical_model_calls=5),
    lambda s: s.update(manual_sp_control={}),
])
def test_hp_only_preimport_rejects_unqualified_selection(tmp_path, change):
    spec, _ = _selection_spec(tmp_path)
    change(spec)
    with pytest.raises(ValueError):
        _hp_only_preimport_admission(spec, hp_only_mode=True,
                                     function_name="md_collect_marks",
                                     check_only=False)


def test_hp_only_live_mode_rejects_invalid_spec_before_import(tmp_path):
    spec = tmp_path / "spec.json"
    spec.write_text("{}\n")
    digest = hashlib.sha256(spec.read_bytes()).hexdigest()
    completed = subprocess.run(
        [sys.executable, "-I", "-S", "-B", str(LAUNCHER),
         "--entry", str(ENTRY), "--entry-sha256",
         hashlib.sha256(ENTRY.read_bytes()).hexdigest(), "--",
         "--spec", str(spec),
         "--spec-sha256", digest, "--authorize-public-dev-hp-only",
         "--hp-only-function-name", "md_collect_marks"],
        capture_output=True, text=True, check=False, timeout=10)
    assert completed.returncode == 2
    assert json.loads(completed.stdout) == {
        "status": "INCOMPLETE_ADMISSION",
        "error_type": "ValueError",
        "reason": "only explicit public development is admitted",
    }


def _hp_only_case(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    source = root / "parser.c"
    source.write_text("int parse_input(const char *p) {\n  return *p;\n}\n")
    harness = tmp_path / "fuzzer.cc"
    harness.write_text("int LLVMFuzzerTestOneInput() { return 0; }\n")
    prebuild = tmp_path / "prebuild"
    catalog = prebuild / "mongodb" / "functions.json"
    catalog.parent.mkdir(parents=True)
    catalog.write_text(json.dumps([{
        "name": "parse_input", "file_path": "parser.c",
        "content": source.read_text(), "start_line": 1, "end_line": 3,
        "reached_by_fuzzers": ["fuzz_fixture"]}]))
    run_dir = tmp_path / "run"
    run_dir.mkdir(mode=0o700)
    task_id, run_id = str(ObjectId()), str(ObjectId())
    q = SimpleNamespace(
        product_issued=True,
        contract_kind="OFFICIAL_OSS_FUZZ_UPSTREAM_HARNESS_V2",
        source_root=root, harness=harness, source_tree_sha256="b" * 64,
        contract_sha256="c" * 64,
        harness_sha256=hashlib.sha256(harness.read_bytes()).hexdigest(),
        binary_sha256="d" * 64)
    monkeypatch.setattr(official_harness, "OfficialPinnedQualification",
                        type(q))
    monkeypatch.setattr(official_harness, "_qualification_pins_ok",
                        lambda value: value is q)
    monkeypatch.setattr(hp_live, "validate_hp_spec", lambda *_a, **_kw: None)
    state = {"stop_status": None, "active": {}, "finished": []}
    bound = SimpleNamespace(
        identity=SimpleNamespace(task_id=task_id, run_id=run_id,
                                 run_dir=run_dir, product_src=tmp_path),
        admission=SimpleNamespace(
            qualification=q, prepared={"prebuild_dir": str(prebuild)},
            summary={"manifest_path": str(tmp_path / "manifest.json"),
                     "manifest_sha256": "e" * 64}),
        executor=SimpleNamespace(fuzzer="fuzz_fixture"),
        model_gate=SimpleNamespace(snapshot=lambda: {
            "physical": 0, "records": []}),
        process_ledger=SimpleNamespace(receipt_snapshot=lambda:
                                       (state, "e" * 64)),
        recheck=lambda: None)
    hp = {"enabled": True, "max_model_calls": 4}
    control = {"enabled": True, "function_name": "parse_input",
               "automatic_discovery": False,
               "source_tree_sha256": q.source_tree_sha256,
               "functions_json_sha256": hashlib.sha256(
                   catalog.read_bytes()).hexdigest()}
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps({"hp": hp, "hp_only": control}))
    return bound, hp, control, spec, catalog, run_dir


def test_signed_hp_only_selection_has_own_claim_and_no_sp_worker(
        tmp_path, monkeypatch):
    bound, hp, control, spec, catalog, run_dir = _hp_only_case(
        tmp_path, monkeypatch)
    digest = hashlib.sha256(spec.read_bytes()).hexdigest()
    work, actor_id, recheck, claim_sha = hp_live._prepare_signed_hp_only(
        bound, hp, control, spec_path=spec, spec_sha256=digest)
    assert isinstance(work, PreparedHPFunction)
    assert work.selection_origin == "SIGNED_MANUAL_HP_CONTROL"
    assert work.analysis_scope["selection_evidence"]["spec_sha256"] == digest
    assert actor_id == "hp-control:" + bound.identity.run_id
    assert not (run_dir / "HP_RUN_CLAIM.json").exists()
    assert not (run_dir / "HP_PHYSICAL_CLAIM.json").exists()
    assert not (run_dir / "PUBLIC_DEV_RESULT.json").exists()
    assert (run_dir / "HP_ONLY_SELECTION_CLAIM.json").is_file()
    assert claim_sha == hashlib.sha256(
        (run_dir / "HP_ONLY_SELECTION_CLAIM.json").read_bytes()).hexdigest()
    recheck()
    with pytest.raises(FileExistsError):
        hp_live._prepare_signed_hp_only(
            bound, hp, control, spec_path=spec, spec_sha256=digest)
    catalog.write_text("[]\n")
    with pytest.raises(ValueError, match="selection or claim changed"):
        recheck()


def test_signed_hp_only_claim_tamper_blocks_downstream(tmp_path, monkeypatch):
    bound, hp, control, spec, _, run_dir = _hp_only_case(tmp_path, monkeypatch)
    digest = hashlib.sha256(spec.read_bytes()).hexdigest()
    _, _, recheck, _ = hp_live._prepare_signed_hp_only(
        bound, hp, control, spec_path=spec, spec_sha256=digest)
    (run_dir / "HP_ONLY_SELECTION_CLAIM.json").write_text("{}\n")
    with pytest.raises(ValueError, match="selection or claim changed"):
        recheck()


def test_hp_only_provider_close_uses_same_event_loop(tmp_path, monkeypatch):
    bound, hp, control, spec, _, run_dir = _hp_only_case(tmp_path, monkeypatch)
    digest = hashlib.sha256(spec.read_bytes()).hexdigest()
    running = []

    class Provider:
        async def close(self):
            running.append(asyncio.get_running_loop())

    providers = [Provider(), Provider()]
    monkeypatch.setattr(hp_live, "_pipeline_factory",
                        lambda *_a, **_kw: lambda _work:
                        SimpleNamespace(provider=providers.pop(0)))
    monkeypatch.setattr(hp_live, "_settled_model", lambda *_a: True)
    import devtools.original_hp_preparation as hp_preparation

    async def scripted_analysis(**_kwargs):
        running.append(asyncio.get_running_loop())
        return {"status": "NO_SAFE_ASSUMPTION"}

    monkeypatch.setattr(hp_preparation, "run_prepared_hp_analysis",
                        scripted_analysis)
    outcome = hp_live.run_signed_hp_only(
        bound, hp, control, spec_path=spec, spec_sha256=digest)
    assert outcome["status"] == "HP_ONLY_NO_PROPOSAL"
    assert outcome["physical_execution_status"] == "NOT_RUN_NO_PROPOSAL"
    assert len(running) == 3 and running[0] is running[1] is running[2]
    assert json.loads((run_dir / "HP_ONLY_RESULT.json").read_text())[
        "automatic_discovery"] is False


def test_hp_only_safe_with_zero_assertion_is_no_proposal(
        tmp_path, monkeypatch):
    bound, hp, control, spec, _, run_dir = _hp_only_case(
        tmp_path, monkeypatch)
    digest = hashlib.sha256(spec.read_bytes()).hexdigest()

    class Provider:
        async def close(self):
            pass

    monkeypatch.setattr(hp_live, "_pipeline_factory",
                        lambda *_a, **_kw: lambda _work:
                        SimpleNamespace(provider=Provider()))
    monkeypatch.setattr(hp_live, "_settled_model", lambda *_a: True)
    monkeypatch.setattr(hp_live, "_physical_handoff_factory",
                        lambda *_a, **_kw: lambda *_args:
                        (_ for _ in ()).throw(AssertionError(
                            "zero assertions have no physical handoff")))
    import devtools.original_hp_preparation as hp_preparation

    async def no_assertion(**_kwargs):
        return {"status": "ASSERTIONS_PROPOSED_UNVERIFIED",
                "safe_assumption_count": 1,
                "assertion_count": 0,
                "proposed_assertion_count": 0,
                "assertion_proposals": [],
                "assertion_execution": "NOT_RUN"}

    monkeypatch.setattr(hp_preparation, "run_prepared_hp_analysis",
                        no_assertion)
    outcome = hp_live.run_signed_hp_only(
        bound, hp, control, spec_path=spec, spec_sha256=digest)
    assert outcome["status"] == "HP_ONLY_NO_PROPOSAL"
    assert outcome["physical_execution_status"] == "NOT_RUN_NO_PROPOSAL"
    receipt = json.loads((run_dir / "HP_ONLY_RESULT.json").read_text())
    assert receipt["analysis"]["safe_assumption_count"] == 1
    assert receipt["analysis"]["proposed_assertion_count"] == 0
    assert receipt["physical"] is None
    assert receipt["automatic_discovery"] is False


def test_hp_only_context_limit_is_analysis_incomplete(
        tmp_path, monkeypatch):
    bound, hp, control, spec, _, run_dir = _hp_only_case(
        tmp_path, monkeypatch)
    digest = hashlib.sha256(spec.read_bytes()).hexdigest()

    class Provider:
        async def close(self):
            pass

    monkeypatch.setattr(hp_live, "_pipeline_factory",
                        lambda *_a, **_kw: lambda _work:
                        SimpleNamespace(provider=Provider()))
    monkeypatch.setattr(hp_live, "_settled_model", lambda *_a: True)
    import devtools.original_hp_preparation as hp_preparation

    async def context_limited(**_kwargs):
        return {
            "status": "INCOMPLETE_HP_CONTEXT",
            "reason": "CONTEXT_ROUND_LIMIT",
            "context_requests": [{
                "target": "parse_array", "request_type": "FUNCTION",
                "round": 2, "status": "SKIPPED_CONTEXT_ROUND_LIMIT"}],
        }

    monkeypatch.setattr(hp_preparation, "run_prepared_hp_analysis",
                        context_limited)
    outcome = hp_live.run_signed_hp_only(
        bound, hp, control, spec_path=spec, spec_sha256=digest)
    assert outcome["status"] == "HP_ONLY_ANALYSIS_INCOMPLETE"
    assert (outcome["physical_execution_status"] ==
            "NOT_RUN_ANALYSIS_INCOMPLETE")
    receipt = json.loads((run_dir / "HP_ONLY_RESULT.json").read_text())
    assert receipt["analysis"]["reason"] == "CONTEXT_ROUND_LIMIT"
    assert receipt["physical"] is None
    assert receipt["automatic_discovery"] is False


def test_hp_only_failed_physical_handoff_keeps_incomplete_receipt(
        tmp_path, monkeypatch):
    bound, hp, control, spec, _, run_dir = _hp_only_case(tmp_path, monkeypatch)
    digest = hashlib.sha256(spec.read_bytes()).hexdigest()

    class Provider:
        async def close(self):
            pass

    monkeypatch.setattr(hp_live, "_pipeline_factory",
                        lambda *_a, **_kw: lambda _work:
                        SimpleNamespace(provider=Provider()))
    monkeypatch.setattr(hp_live, "_settled_model", lambda *_a: True)
    monkeypatch.setattr(hp_live, "_physical_handoff_factory",
                        lambda *_a, **_kw: lambda *_args:
                        (_ for _ in ()).throw(ValueError("build blocked")))
    import devtools.original_hp_preparation as hp_preparation

    async def scripted_analysis(**_kwargs):
        return {"status": "ASSERTIONS_PROPOSED_UNVERIFIED"}

    monkeypatch.setattr(hp_preparation, "run_prepared_hp_analysis",
                        scripted_analysis)
    outcome = hp_live.run_signed_hp_only(
        bound, hp, control, spec_path=spec, spec_sha256=digest)
    assert outcome["status"] == "HP_ONLY_PHYSICAL_INCOMPLETE"
    receipt = json.loads((run_dir / "HP_ONLY_RESULT.json").read_text())
    assert receipt["physical"]["error_type"] == "ValueError"
    assert receipt["security_gate_credit"] == "NOT_CREDITED"


def test_hp_only_model_error_closes_providers_and_records_failure(
        tmp_path, monkeypatch):
    bound, hp, control, spec, _, run_dir = _hp_only_case(tmp_path, monkeypatch)
    digest = hashlib.sha256(spec.read_bytes()).hexdigest()
    closed = []

    class Provider:
        async def close(self):
            closed.append(asyncio.get_running_loop())

    monkeypatch.setattr(hp_live, "_pipeline_factory",
                        lambda *_a, **_kw: lambda _work:
                        SimpleNamespace(provider=Provider()))
    monkeypatch.setattr(hp_live, "_settled_model", lambda *_a: True)
    import devtools.original_hp_preparation as hp_preparation

    async def error_analysis(**_kwargs):
        raise ValueError("scripted model error")

    monkeypatch.setattr(hp_preparation, "run_prepared_hp_analysis",
                        error_analysis)
    result = hp_live.run_signed_hp_only(
        bound, hp, control, spec_path=spec, spec_sha256=digest)
    assert result["status"] == "HP_ONLY_ANALYSIS_INCOMPLETE"
    assert len(closed) == 2 and closed[0] is closed[1]
    receipt = json.loads((run_dir / "HP_ONLY_RESULT.json").read_text())
    assert receipt["analysis"]["error_type"] == "ValueError"
    assert receipt["physical"] is None


def test_hp_only_stale_claim_after_model_response_never_reaches_physical(
        tmp_path, monkeypatch):
    bound, hp, control, spec, _, run_dir = _hp_only_case(tmp_path, monkeypatch)
    digest = hashlib.sha256(spec.read_bytes()).hexdigest()

    class Provider:
        async def close(self):
            pass

    monkeypatch.setattr(hp_live, "_pipeline_factory",
                        lambda *_a, **_kw: lambda _work:
                        SimpleNamespace(provider=Provider()))
    monkeypatch.setattr(hp_live, "_settled_model", lambda *_a: True)
    reached = []
    monkeypatch.setattr(hp_live, "_physical_handoff_factory",
                        lambda *_a, **_kw: reached.append(True))
    import devtools.original_hp_preparation as hp_preparation

    async def scripted_analysis(**_kwargs):
        (run_dir / "HP_ONLY_SELECTION_CLAIM.json").write_text("{}\n")
        return {"status": "ASSERTIONS_PROPOSED_UNVERIFIED"}

    monkeypatch.setattr(hp_preparation, "run_prepared_hp_analysis",
                        scripted_analysis)
    outcome = hp_live.run_signed_hp_only(
        bound, hp, control, spec_path=spec, spec_sha256=digest)
    assert outcome["status"] == "HP_ONLY_ACCOUNT_UNSETTLED"
    assert reached == []


def test_hp_only_forged_complete_without_process_lease_is_incomplete(
        tmp_path, monkeypatch):
    bound, hp, control, spec, _, run_dir = _hp_only_case(tmp_path, monkeypatch)
    digest = hashlib.sha256(spec.read_bytes()).hexdigest()

    class Provider:
        async def close(self):
            pass

    monkeypatch.setattr(hp_live, "_pipeline_factory",
                        lambda *_a, **_kw: lambda _work:
                        SimpleNamespace(provider=Provider()))
    monkeypatch.setattr(hp_live, "_settled_model", lambda *_a: True)
    monkeypatch.setattr(hp_live, "_physical_handoff_factory",
                        lambda *_a, **_kw: lambda *_args: {
                            "status": "HP_ASSERTION_HANDOFF_COMPLETE",
                            "guided_status": "RAN", "assertion_id": "fake",
                            "guided_report": {"status": "RAN",
                                              "assertion_id": "fake",
                                              "fuzzer_run_count": 999}})
    import devtools.original_hp_preparation as hp_preparation

    async def scripted_analysis(**_kwargs):
        return {"status": "ASSERTIONS_PROPOSED_UNVERIFIED"}

    monkeypatch.setattr(hp_preparation, "run_prepared_hp_analysis",
                        scripted_analysis)
    outcome = hp_live.run_signed_hp_only(
        bound, hp, control, spec_path=spec, spec_sha256=digest)
    assert outcome["status"] == "HP_ONLY_PHYSICAL_INCOMPLETE"
    assert json.loads((run_dir / "HP_ONLY_RESULT.json").read_text())[
        "security_gate_credit"] == "NOT_CREDITED"


def test_hp_only_reachability_must_be_a_catalog_list(tmp_path, monkeypatch):
    bound, hp, control, spec, catalog, run_dir = _hp_only_case(
        tmp_path, monkeypatch)
    rows = json.loads(catalog.read_text())
    rows[0]["reached_by_fuzzers"] = "fuzz_fixture"
    catalog.write_text(json.dumps(rows))
    control["functions_json_sha256"] = hashlib.sha256(
        catalog.read_bytes()).hexdigest()
    spec.write_text(json.dumps({"hp": hp, "hp_only": control}))
    digest = hashlib.sha256(spec.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="not uniquely reachable"):
        hp_live._prepare_signed_hp_only(
            bound, hp, control, spec_path=spec, spec_sha256=digest)
    assert not (run_dir / "HP_ONLY_SELECTION_CLAIM.json").exists()


def test_hp_only_result_mongo_mirror_is_insert_only_and_read_back(tmp_path):
    class InsertResult:
        acknowledged = True

    class Collection:
        def __init__(self):
            self.rows = {}

        def insert_one(self, row):
            if row["_id"] in self.rows:
                raise RuntimeError("duplicate result")
            self.rows[row["_id"]] = dict(row)
            return InsertResult()

        def find_one(self, query):
            row = self.rows.get(query["_id"])
            return dict(row) if row is not None else None

    class Database:
        def __init__(self):
            self.collection = Collection()

        def __getitem__(self, name):
            assert name == "hp_only_results"
            return self.collection

    path = tmp_path / "HP_ONLY_RESULT.json"
    receipt = {
        "kind": "FBV2_HP_ONLY_RESULT_V1", "status": "HP_ONLY_NO_PROPOSAL",
        "automatic_discovery": False,
        "security_gate_credit": "NOT_CREDITED",
        "analysis": {
            "assumption_lifecycle_contract": {
                "kind": "HP_PER_ASSUMPTION_EVIDENCE_CLOSURE_V5",
                "omitted_prior_candidate": "INCOMPLETE",
            },
            "assumption_lifecycle_history": [{
                "assumption_id": "safe-fixture",
                "safe_assumption": "fixture",
                "source_location": "fixture.c:1",
                "security_property": "memory safety",
                "disposition": "RECLASSIFIED_VALIDATION",
                "reason": "existing guard",
                "required_context": [],
                "evidence_dependencies": ["fixture.c:1"],
                "round": 1,
                "assertion_eligible": False,
            }],
            "assumption_lifecycle_ledger": [{
                "assumption_id": "safe-fixture",
                "safe_assumption": "fixture",
                "source_location": "fixture.c:1",
                "security_property": "memory safety",
                "disposition": "RECLASSIFIED_VALIDATION",
                "reason": "existing guard",
                "required_context": [],
                "evidence_dependencies": ["fixture.c:1"],
            }],
        },
    }
    digest = hp_live._write_once(path, receipt)
    database = Database()
    bound = SimpleNamespace(
        identity=SimpleNamespace(task_id="task", run_id="run"),
        server=SimpleNamespace(repos=SimpleNamespace(db=database)))
    settled = hp_live._persist_hp_only_result(bound, path, digest)
    assert settled == {
        "status": "PERSISTED_AND_READ_BACK",
        "record_id": "hp-only-result:task:run",
    }
    stored = database.collection.rows[settled["record_id"]]
    assert stored["receipt"] == receipt
    assert stored["receipt"]["analysis"]["assumption_lifecycle_history"] == (
        receipt["analysis"]["assumption_lifecycle_history"])
    assert stored["receipt"]["analysis"]["assumption_lifecycle_ledger"] == (
        receipt["analysis"]["assumption_lifecycle_ledger"])
    assert stored["receipt_sha256"] == digest
    with pytest.raises(RuntimeError, match="duplicate result"):
        hp_live._persist_hp_only_result(bound, path, digest)

