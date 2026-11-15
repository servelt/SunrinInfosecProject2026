"""Provider-free official V2 route tests; never run a model or Target."""

from __future__ import annotations

from dataclasses import asdict, replace
import asyncio
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

PRODUCT = (Path(__file__).resolve().parents[1] / "product")
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(PRODUCT / "src"), str(Path(__file__).resolve().parent)]

from dev_blind3_official_interleaved_adapter import (  # noqa: E402
    CODE_FILES, KIND, STATUS, OfficialInterleavedAdapter, _qualified,
    load_route_spec, sha256,
)
from dev_blind3_official_interleaved_runner import (  # noqa: E402
    _backend, _budget, prepare, restore_and_inspect,
    reissue_product_qualification,
)
from dev_global_request_ledger import (  # noqa: E402
    DevelopmentBudget, DevelopmentRequestLedger, GLOBAL_ONLY_DEV_PROFILE,
)
from dev_global_appserver_bridge import DevelopmentGlobalAppServer  # noqa: E402
from dev_persistent_physical_fuzz_ledger import PersistentPhysicalFuzzLedger  # noqa: E402


class OfficialInterleavedAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="stage13-official-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.output = self.root / "output"
        self.output.mkdir(mode=0o700)
        model_cwd = self.root / "model_cwd"
        model_cwd.mkdir(mode=0o700)
        codex_home = self.root / "codex_home"
        codex_home.mkdir(mode=0o700)
        config = ROOT / "tools/codex_config.toml"
        shutil.copyfile(config, codex_home / "config.toml")
        (codex_home / "config.toml").chmod(0o600)
        (codex_home / "auth.json").write_text("{}", encoding="utf-8")
        (codex_home / "auth.json").chmod(0o600)
        previous = os.environ.get("CODEX_HOME")
        os.environ["CODEX_HOME"] = str(codex_home)
        self.addCleanup(self._restore_home, previous)
        receipt = json.loads((ROOT / "review/STAGE7_OFFICIAL_PHASE1_20261031/"
                              "STAGE7_PROVIDER_FREE_RECEIPT.json").read_text())
        contract = json.loads((ROOT / "tools/FROZEN_CONTRACT_ATTEMPT3.json").read_text())
        q = self._issue()
        self.assertIsNotNone(q)
        budget = DevelopmentBudget(
            physical_max=128, logical_max=128, retries_max=2,
            wall_seconds=7200, initial_starts_required=1,
            profile=GLOBAL_ONLY_DEV_PROFILE)
        self.spec = {
            "kind": KIND, "status": STATUS,
            "source_run": receipt["source_run"],
            "worklist_path": receipt["worklist_path"],
            "worklist_sha256": receipt["worklist_sha256"],
            "output_dir": str(self.output),
            "target_repository": str(q.source_root),
            "qualification": {}, "role_models": contract["role_models"],
            "default_model": contract["default_model"],
            "default_effort": contract["default_effort"],
            "code_sha256": {name: sha256(path) for name, path in CODE_FILES.items()},
            "config_path": str(config), "config_sha256": sha256(config),
            "codex_executable": contract["codex_executable_path"],
            "codex_executable_sha256": contract["codex_executable_sha256"],
            "sandbox_launcher": str(ROOT / "evaluation_tools/blind2_model_sandbox.py"),
            "sandbox_launcher_sha256": sha256(ROOT / "evaluation_tools/blind2_model_sandbox.py"),
            "python_executable": sys.executable,
            "python_executable_sha256": sha256(Path(sys.executable)),
            "codex_home": str(codex_home), "model_cwd": str(model_cwd),
            "event_log_path": str(self.output / "MODEL_EVENTS.jsonl"),
            "model_ledger_path": str(self.output / "MODEL_LEDGER.json"),
            "physical_ledger_path": str(self.output / "PHYSICAL_LEDGER.json"),
            "physical_resource_seconds": 7200, "model_budget": asdict(budget),
            "role_route_sha256": hashlib.sha256(json.dumps(
                contract["role_models"], sort_keys=True,
                separators=(",", ":")).encode()).hexdigest(),
            "workspace_route_sha256": contract["route_sha256"],
            "allow_synthetic_wire": False, "oracle_queries": 0,
            "blind3_runs": 0,
        }
        for name in ("source_root", "harness", "binary", "normal_seed",
                     "contract_path", "review_artifact", "build_receipt_path",
                     "oss_fuzz_checkout", "upstream_checkout"):
            self.spec["qualification"][name] = str(getattr(q, name))
        for name in ("source_tree_sha256", "harness_sha256", "binary_sha256",
                     "normal_seed_sha256", "contract_sha256", "review_sha256",
                     "build_receipt_sha256", "contract_kind", "reviewer_id",
                     "upstream_revision", "oss_fuzz_revision"):
            self.spec["qualification"][name] = getattr(q, name)
        self.path = self.root / "route.json"
        self._write_spec()

    @staticmethod
    def _restore_home(previous: str | None) -> None:
        if previous is None:
            os.environ.pop("CODEX_HOME", None)
        else:
            os.environ["CODEX_HOME"] = previous

    def _write_spec(self) -> None:
        self.path.write_text(json.dumps(self.spec, sort_keys=True), encoding="utf-8")
        self.path.chmod(0o600)
        self.spec_sha = sha256(self.path)

    def _issue(self):
        from vulnerabilityanalysis.official_harness import issue_official_pinned_qualification
        contract = ROOT / "public/OFFICIAL_HARNESS_CONTRACT.json"
        return issue_official_pinned_qualification(
            contract_path=contract, approved_contract_sha256=sha256(contract),
            source_root=ROOT / "model_target",
            harness=ROOT / "v2_artifact_stage/attempt/fuzz-mdhtml.c",
            binary=ROOT / "build/asan",
            normal_seed=ROOT / "public/normal_seed_corpus/seed_00.bin",
            oss_fuzz_checkout=ROOT / "oss_fuzz_checkout",
            upstream_checkout=ROOT / "upstream_asan_final")

    def _adapter_after_prepare(self) -> OfficialInterleavedAdapter:
        prepare(self.path, self.spec_sha)
        q, _ = reissue_product_qualification(self.spec)
        model = DevelopmentRequestLedger.restore(
            Path(self.spec["model_ledger_path"]), _budget(self.spec))
        physical = PersistentPhysicalFuzzLedger.restore(
            Path(self.spec["physical_ledger_path"]), total_seconds=7200)
        return OfficialInterleavedAdapter(
            route_spec=self.path, route_sha256=self.spec_sha,
            qualification=q, ledger=model, physical_ledger=physical,
            backend=_backend(self.spec, model, physical))

    def test_product_issued_v2_prepare_read_no_model_or_target(self) -> None:
        q, wall_ms = reissue_product_qualification(self.spec)
        self.assertTrue(q.product_issued)
        self.assertGreater(wall_ms, 0)
        result = prepare(self.path, self.spec_sha)
        self.assertEqual(result["status"], STATUS)
        self.assertEqual(result["model_physical"], 0)
        self.assertEqual(result["scan_count"], 0)
        model_before = sha256(Path(self.spec["model_ledger_path"]))
        physical_before = sha256(Path(self.spec["physical_ledger_path"]))
        restored = restore_and_inspect(self.path, self.spec_sha)
        self.assertEqual(restored["work_item_count"], 700)
        self.assertEqual(restored["completed_work_items"], 0)
        self.assertEqual(sha256(Path(self.spec["model_ledger_path"])),
                         model_before)
        self.assertEqual(sha256(Path(self.spec["physical_ledger_path"])),
                         physical_before)
        self.assertFalse(Path(self.spec["event_log_path"]).exists())

    def test_synthetic_flag_and_forged_qualification_rejected(self) -> None:
        q = self._issue()
        with self.assertRaises(ValueError):
            _qualified(self.spec, replace(q, _issuer=object()))
        self.spec["allow_synthetic_wire"] = True
        self._write_spec()
        with self.assertRaises(ValueError):
            load_route_spec(self.path, self.spec_sha)

    def test_binary_drift_rejected_without_mutating_official_file(self) -> None:
        q = self._issue()
        wrong = self.root / "wrong-binary"
        wrong.write_bytes(b"probe only")
        with self.assertRaises(ValueError):
            _qualified(self.spec, replace(q, binary=wrong))
        with self.assertRaises(ValueError):
            _qualified(self.spec, replace(q, harness=wrong))
        with self.assertRaises(ValueError):
            _qualified(self.spec, replace(q, normal_seed=wrong))
        with self.assertRaises(ValueError):
            _qualified(self.spec, replace(q, source_root=self.root))

    def test_same_function_across_directions_has_distinct_work_item_id(self) -> None:
        prepare(self.path, self.spec_sha)
        state = json.loads((self.output / "partial_work/WORK_ITEM_STATE.json").read_text())
        items = state["work_items"]
        self.assertEqual(len({item["work_item_id"] for item in items}), len(items))
        self.assertLess(len({item["function_id"] for item in items}), len(items))
        self.assertEqual(state["scan_count"], 0)

    def test_worklist_sha_drift_blocks_before_ledger_creation(self) -> None:
        self.spec["worklist_sha256"] = "0" * 64
        self._write_spec()
        with self.assertRaises(ValueError):
            prepare(self.path, self.spec_sha)
        self.assertFalse(Path(self.spec["model_ledger_path"]).exists())

    def test_pending_sourcespan_tamper_blocks_read_and_pre_send(self) -> None:
        adapter = self._adapter_after_prepare()
        state = adapter.read()
        state["work_items"][0]["source_span_sha256"] = "0" * 64
        adapter.state_path.write_text(json.dumps(state, sort_keys=True) + "\n")
        with self.assertRaises(ValueError):
            adapter.read()
        with self.assertRaises(ValueError):
            asyncio.run(adapter.sp(0))
        self.assertEqual(adapter.ledger.physical, 0)

    def test_post_role_pin_failure_persists_a_stop_marker(self) -> None:
        adapter = self._adapter_after_prepare()

        async def drift(*_args, **_kwargs):
            adapter.backend.timeout_seconds = 301
            return self.root / "test-only-artifact"

        with patch("dev_blind3_official_interleaved_adapter.generate_sp_stage", drift):
            with self.assertRaises(ValueError):
                asyncio.run(adapter.sp(0))
        marker = adapter.state_path.parent / "OFFICIAL_PIN_FAILURE.json"
        self.assertTrue(marker.is_file())
        adapter.backend.timeout_seconds = 300
        with self.assertRaises(ValueError):
            adapter.read()
        self.assertEqual(adapter.ledger.physical, 0)

    def test_marker_write_failure_leaves_pending_guard_on_restart(self) -> None:
        adapter = self._adapter_after_prepare()

        async def drift(*_args, **_kwargs):
            adapter.backend.timeout_seconds = 301
            raise RuntimeError("original role failure")

        with (patch("dev_blind3_official_interleaved_adapter.generate_sp_stage", drift),
              patch.object(adapter, "_record_pin_failure", side_effect=OSError(
                  "test-only marker write failure"))):
            with self.assertRaisesRegex(RuntimeError, "original role failure"):
                asyncio.run(adapter.sp(0))
        guard = json.loads((adapter.state_path.parent / "ROLE_GUARD.json").read_text())
        self.assertEqual(guard["status"], "PENDING")
        self.assertFalse((adapter.state_path.parent /
                          "OFFICIAL_PIN_FAILURE.json").exists())
        q, _ = reissue_product_qualification(self.spec)
        restored_model = DevelopmentRequestLedger.restore(
            Path(self.spec["model_ledger_path"]), _budget(self.spec))
        restored_physical = PersistentPhysicalFuzzLedger.restore(
            Path(self.spec["physical_ledger_path"]), total_seconds=7200)
        replacement = _backend(self.spec, restored_model, restored_physical)
        with self.assertRaises(ValueError):
            OfficialInterleavedAdapter(
                route_spec=self.path, route_sha256=self.spec_sha,
                qualification=q, ledger=restored_model,
                physical_ledger=restored_physical, backend=replacement)
        self.assertEqual(adapter.ledger.physical, 0)

    def test_unbind_failure_preserves_original_role_error(self) -> None:
        adapter = self._adapter_after_prepare()

        async def fail_role(*_args, **_kwargs):
            raise RuntimeError("original role failure")

        with (patch("dev_blind3_official_interleaved_adapter.generate_sp_stage",
                    fail_role),
              patch.object(adapter.backend, "unbind_scope", side_effect=OSError(
                  "test-only unbind failure"))):
            with self.assertRaisesRegex(RuntimeError, "original role failure"):
                asyncio.run(adapter.sp(0))
        self.assertEqual(json.loads((adapter.state_path.parent /
                                     "ROLE_GUARD.json").read_text())["status"],
                         "PENDING")
        self.assertTrue((adapter.state_path.parent /
                         "OFFICIAL_PIN_FAILURE.json").is_file())

    def test_success_state_cannot_resume_when_terminal_guard_write_fails(self) -> None:
        from test_dev_global_appserver_bridge import FakeWireServer
        from test_dev_interleaved_crossrole_stage import _RoleWire, _wire_sp_response
        import vulnerabilityanalysis.interleaved_dev as stage
        from vulnerabilityanalysis.source import SourceRepository

        adapter = self._adapter_after_prepare()
        state = adapter.read()
        harness = stage._pinned_harness(
            state, Path(state["source_run"]), adapter.qualification.source_root)
        repository = SourceRepository(adapter.qualification.source_root,
                                      harness.function_catalog)
        adapter.backend.sent = []
        adapter.backend.responses = [_wire_sp_response(
            repository, state["work_items"][0], 1)]
        write_guard = adapter._write_role_guard

        def fail_terminal(role, ordinal, scope, status, sp_id=None):
            if status != "PENDING":
                raise OSError("test-only terminal guard failure")
            return write_guard(role, ordinal, scope, status, sp_id)

        with (patch.object(DevelopmentGlobalAppServer, "start", FakeWireServer.start),
              patch.object(DevelopmentGlobalAppServer, "_thread_for",
                           FakeWireServer._thread_for),
              patch.object(DevelopmentGlobalAppServer, "_delete_ephemeral_thread",
                           FakeWireServer._delete_ephemeral_thread),
              patch.object(DevelopmentGlobalAppServer, "_transport_request",
                           FakeWireServer._transport_request),
              patch.object(DevelopmentGlobalAppServer, "_collect", _RoleWire._collect),
              patch.object(adapter, "_write_role_guard", side_effect=fail_terminal),
              patch.object(adapter, "_record_pin_failure", side_effect=OSError(
                  "test-only marker failure"))):
            with self.assertRaises(OSError):
                asyncio.run(adapter.sp(0))
        raw = json.loads(adapter.state_path.read_text())
        self.assertEqual(raw["work_items"][0]["state"],
                         "SP_GENERATED_HP_PENDING")
        guard = json.loads((adapter.state_path.parent / "ROLE_GUARD.json").read_text())
        self.assertEqual(guard["status"], "PENDING")
        self.assertEqual(adapter.ledger.physical, 1)
        q, _ = reissue_product_qualification(self.spec)
        restored_model = DevelopmentRequestLedger.restore(
            Path(self.spec["model_ledger_path"]), _budget(self.spec))
        restored_physical = PersistentPhysicalFuzzLedger.restore(
            Path(self.spec["physical_ledger_path"]), total_seconds=7200)
        replacement = _backend(self.spec, restored_model, restored_physical)
        with self.assertRaises(ValueError):
            OfficialInterleavedAdapter(
                route_spec=self.path, route_sha256=self.spec_sha,
                qualification=q, ledger=restored_model,
                physical_ledger=restored_physical, backend=replacement)

    def test_official_adapter_a_b_hp_a_verifier_pov_one_owner(self) -> None:
        from test_dev_global_appserver_bridge import FakeWireServer
        from test_dev_interleaved_crossrole_stage import (
            _RoleWire, _verdict, _wire_sp_response,
        )
        import vulnerabilityanalysis.interleaved_dev as stage
        from vulnerabilityanalysis.source import SourceRepository

        adapter = self._adapter_after_prepare()
        state = adapter.read()
        rows = state["work_items"]
        harness = stage._pinned_harness(
            state, Path(state["source_run"]), adapter.qualification.source_root)
        repository = SourceRepository(adapter.qualification.source_root,
                                      harness.function_catalog)
        hp_response = {
            "summary": "reviewed", "input_flow": "input may reach source",
            "state_dependencies": [], "context_requests": [],
            "safe_assumptions": [], "unknowns": [], "input_sources": [],
            "security_sensitive_operations": [], "validations": [],
            "memory_operations": [], "evidence": [],
            "hypothesis_evaluations": [],
        }
        adapter.backend.sent = []
        b_span = repository.open_function_span(rows[1]["function_id"])
        b_lines = b_span.source.splitlines()
        b_index = next(index for index, line in enumerate(b_lines) if line.strip())
        b_response = _wire_sp_response(repository, rows[0], 1)
        b_point = b_response["suspicious_points"][0]
        b_point["source_file"] = rows[1]["source_file"]
        b_point["source_line"] = b_span.start_line + b_index
        b_point["source_excerpt"] = b_lines[b_index]
        adapter.backend.responses = [
            _wire_sp_response(repository, rows[0], 3),
            b_response,
            hp_response, _verdict(), {
                "generator_script": 'def build():\n    return b"seed"\n',
                "expected_behavior": "public candidate",
                "trigger_rationale": "public seed"},
        ]
        with (patch.object(DevelopmentGlobalAppServer, "start", FakeWireServer.start),
              patch.object(DevelopmentGlobalAppServer, "_thread_for",
                           FakeWireServer._thread_for),
              patch.object(DevelopmentGlobalAppServer, "_delete_ephemeral_thread",
                           FakeWireServer._delete_ephemeral_thread),
              patch.object(DevelopmentGlobalAppServer, "_transport_request",
                           FakeWireServer._transport_request),
              patch.object(DevelopmentGlobalAppServer, "_collect", _RoleWire._collect)):
            async def sequence() -> None:
                await adapter.sp(0)
                await adapter.sp(1)
                await adapter.hp(1)
                sp_id = adapter.read()["work_items"][0]["candidate_ids"][0]
                await adapter.verifier(0, sp_id)
                await adapter.pov(0, sp_id)
            asyncio.run(sequence())
        saved = adapter.read()
        self.assertEqual(saved["work_items"][0]["sp_queue"][0]["state"],
                         "POV_GENERATED_UNVALIDATED")
        self.assertEqual(len(saved["work_items"][0]["candidate_ids"]), 3)
        self.assertEqual(saved["scan_count"], 0)
        self.assertEqual((adapter.ledger.logical, adapter.ledger.physical), (5, 5))
        self.assertEqual(len(adapter.backend.sent), 5)
        self.assertEqual([row["physical"] for row in adapter.backend.sent],
                         [1, 2, 3, 4, 5])
        self.assertTrue(all(row["attempt_status"] == "STARTED"
                            for row in adapter.backend.sent))

    def test_cancel_after_physical_start_is_incomplete_and_blocks_next(self) -> None:
        from test_dev_global_appserver_bridge import FakeWireServer
        from test_dev_interleaved_appserver_stage import StageWire

        adapter = self._adapter_after_prepare()
        adapter.backend.sent = []
        adapter.backend.outcomes = ["cancel"]
        with (patch.object(DevelopmentGlobalAppServer, "start", FakeWireServer.start),
              patch.object(DevelopmentGlobalAppServer, "_thread_for",
                           FakeWireServer._thread_for),
              patch.object(DevelopmentGlobalAppServer, "_delete_ephemeral_thread",
                           FakeWireServer._delete_ephemeral_thread),
              patch.object(DevelopmentGlobalAppServer, "_transport_request",
                           FakeWireServer._transport_request),
              patch.object(DevelopmentGlobalAppServer, "_collect", StageWire._collect)):
            with self.assertRaises(asyncio.CancelledError):
                asyncio.run(adapter.sp(0))
            state = adapter.read()
            self.assertEqual(state["work_items"][0]["state"],
                             "INCOMPLETE_UNCERTAIN_MODEL_TURN")
            self.assertEqual(adapter.ledger.physical, 1)
            self.assertEqual(adapter.backend.sent[0]["attempt_status"], "STARTED")
            guard = json.loads((adapter.state_path.parent /
                                "ROLE_GUARD.json").read_text())
            self.assertEqual(guard["status"], "VALIDATED_INCOMPLETE")
            self.assertFalse((adapter.state_path.parent /
                              "OFFICIAL_PIN_FAILURE.json").exists())
            with self.assertRaises(ValueError):
                asyncio.run(adapter.sp(1))
            self.assertEqual(adapter.ledger.physical, 1)

    def test_completed_malformed_response_is_incomplete_without_resend(self) -> None:
        from test_dev_global_appserver_bridge import FakeWireServer
        from test_dev_interleaved_appserver_stage import StageWire

        adapter = self._adapter_after_prepare()
        adapter.backend.sent = []
        adapter.backend.outcomes = ["malformed"]
        with (patch.object(DevelopmentGlobalAppServer, "start", FakeWireServer.start),
              patch.object(DevelopmentGlobalAppServer, "_thread_for",
                           FakeWireServer._thread_for),
              patch.object(DevelopmentGlobalAppServer, "_delete_ephemeral_thread",
                           FakeWireServer._delete_ephemeral_thread),
              patch.object(DevelopmentGlobalAppServer, "_transport_request",
                           FakeWireServer._transport_request),
              patch.object(DevelopmentGlobalAppServer, "_collect", StageWire._collect)):
            with self.assertRaises(json.JSONDecodeError):
                asyncio.run(adapter.sp(0))
            state = adapter.read()
            self.assertEqual(state["work_items"][0]["state"],
                             "INCOMPLETE_PRODUCT_RESPONSE")
            self.assertEqual(adapter.ledger.attempts[-1]["status"], "ERROR")
            self.assertEqual(adapter.ledger.turns[-1]["status"],
                             "INCOMPLETE_PRODUCT_RESPONSE")
            guard = json.loads((adapter.state_path.parent /
                                "ROLE_GUARD.json").read_text())
            self.assertEqual(guard["status"], "VALIDATED_INCOMPLETE")
            self.assertEqual(adapter.ledger.physical, 1)
            self.assertEqual(len(adapter.backend.sent), 1)
            self.assertFalse((adapter.state_path.parent /
                              "OFFICIAL_PIN_FAILURE.json").exists())
            with self.assertRaises(ValueError):
                asyncio.run(adapter.sp(0))
            self.assertEqual(adapter.ledger.physical, 1)


if __name__ == "__main__":
    unittest.main()
