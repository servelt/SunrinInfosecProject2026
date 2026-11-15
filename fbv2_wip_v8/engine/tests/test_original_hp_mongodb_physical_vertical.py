"""Actual-Mongo, provider-free HP vertical using the public utf8proc fixture.

This test deliberately uses scripted model responses, but the product
Assertion instrumentation, Clang build, seed replay, Guided Fuzzing, V2
process envelope, persistent process ledger, and Mongo repositories are real.
It grants no vulnerability, Gate, or automatic-discovery credit.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
from uuid import uuid4

from bson import ObjectId
from pymongo import MongoClient
import pytest

from fuzzingbrain.core.models.direction import Direction
from fuzzingbrain.core.models.function import Function
from fuzzingbrain.core.models.worker import Worker, WorkerStatus
from fuzzingbrain.db.repository import RepositoryManager


PRODUCT_SRC = Path(__file__).resolve().parents[2] / "product" / "src"
EVAL_TOOLS = Path(__file__).resolve().parents[2] / "evaluation_tools"
for dependency in (PRODUCT_SRC, EVAL_TOOLS):
    if str(dependency) not in sys.path:
        sys.path.insert(0, str(dependency))

from dev_process_envelope_v2 import DevelopmentProcessEnvelopeV2
from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2
from vulnerabilityanalysis import assertions as product_assertions
from vulnerabilityanalysis import official_harness
from vulnerabilityanalysis.agents import AgentPipeline

from devtools.original_hp_post_worker import run_post_worker_hp
from devtools.original_hp_preparation import run_prepared_hp_assertion_handoff
from devtools import original_hp_live_optin as hp_live


UTF8PROC_ROOT = Path(
    "/home/dawne/SunrinInfosecProject2026/reference_archive_20261028/"
    "by_date/20261019/hp-utf8proc-ab-20261019")
SOURCE_ROOT = UTF8PROC_ROOT / "source"
SOURCE = SOURCE_ROOT / "utf8proc.c"
HARNESS = SOURCE_ROOT / "test/fuzzer.c"
SEED = UTF8PROC_ROOT / "evidence/normal_seed.bin"
OFFICIAL_BINARY = UTF8PROC_ROOT / "build/utf8proc_asan_fuzzer"
CLANG = Path(
    "/home/dawne/SunrinInfosecProject2026/reference/"
    "blind2_v2_preparation_20261027/review_tools/local_clang/clang")


class ScriptedProvider:
    def __init__(self, role: str, response: dict):
        self.role = role
        self.response = response
        self.requests = []
        self.closed = False

    async def generate(self, request):
        assert request.role == self.role
        self.requests.append(request)
        return self.response

    async def close(self):
        self.closed = True


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _analysis_reply(source_line: int, source_quote: str) -> dict:
    assumption = (
        "The compaction loop preserves 0 <= wpos <= rpos < length before "
        "the buffer write.")
    return {
        "summary": "Compacts normalized codepoints in place",
        "input_flow": "Harness bytes are copied to buffer and select options",
        "state_dependencies": ["wpos", "rpos", "length"],
        "context_requests": [],
        "safe_assumptions": [assumption],
        "unknowns": [],
        "input_sources": ["buffer", "length", "options"],
        "security_sensitive_operations": ["buffer[wpos] write"],
        "validations": ["rpos < length loop bound"],
        "memory_operations": [source_quote],
        "evidence": [source_quote],
        "safe_assumption_lifecycle": [],
        "hypothesis_evaluations": [{
            "source_location": f"utf8proc.c:{source_line}",
            "source_file": "utf8proc.c",
            "source_line": source_line,
            "source_quote": source_quote,
            "security_property": "in-bounds compaction write",
            "input_influence": "INPUT_DEPENDENT",
            "hypothesis": "wpos may overtake the consumed input cursor",
            "judgment": "EXPLICIT_SAFE_JUDGMENT",
            "reason": "each consumed element emits at most one output element",
            "safe_assumption": assumption,
        }],
    }


def _assertion_reply(source_line: int) -> dict:
    assumption = (
        "The compaction loop preserves 0 <= wpos <= rpos < length before "
        "the buffer write.")
    return {
        "assertions": [{
            "safe_id": 0,
            "safe_assumption": assumption,
            "runtime_expression": (
                "(wpos >= 0) && (wpos <= rpos) && (rpos < length)"),
            "source_line": source_line,
            "required_context": [],
            "rationale": "measure the cursor invariant immediately before write",
        }],
        "dispositions": [{
            "safe_id": 0,
            "safe_assumption": assumption,
            "status": "PROPOSED",
            "reason": "the local scalar invariant is runtime-expressible",
        }],
    }


def _mongo_client() -> MongoClient:
    client = MongoClient(
        "mongodb://127.0.0.1:27027/?directConnection=true",
        serverSelectionTimeoutMS=2_000,
    )
    try:
        client.admin.command("ping")
    except Exception as exc:
        client.close()
        pytest.skip(f"actual MongoDB unavailable: {type(exc).__name__}")
    return client


def test_actual_mongodb_utf8proc_assertion_guided_vertical(
        tmp_path, monkeypatch):
    required = (SOURCE, HARNESS, SEED, OFFICIAL_BINARY, CLANG)
    if not all(path.is_file() for path in required):
        pytest.skip("frozen public utf8proc fixture or pinned clang unavailable")
    assert _sha(SOURCE) == (
        "0a9e6face8672baa2d99024bb7af2ff9aba97c8cb365fa138ba37d959c8b984c")
    assert _sha(HARNESS) == (
        "c740c1a8a90cdc82fcd565ae31b64459bcd5d5b7e291bdfe9a895333113002a0")
    assert _sha(SEED) == (
        "b734e19f91571da29890a77983dd46ef8208ae5e870abfebeca565920ffbddb3")

    class Qualification:
        def __init__(self):
            self.product_issued = True
            self.contract_kind = "OFFICIAL_OSS_FUZZ_UPSTREAM_HARNESS_V2"
            self.source_root = SOURCE_ROOT.resolve()
            self.harness = HARNESS.resolve()
            self.binary = OFFICIAL_BINARY.resolve()
            self.normal_seed = SEED.resolve()
            self.source_tree_sha256 = hashlib.sha256(
                SOURCE.read_bytes() + HARNESS.read_bytes()).hexdigest()
            self.harness_sha256 = _sha(HARNESS)
            self.binary_sha256 = _sha(OFFICIAL_BINARY)
            self.normal_seed_sha256 = _sha(SEED)
            self.contract_sha256 = hashlib.sha256(
                b"utf8proc-official-harness-provider-free-v1").hexdigest()

    qualification = Qualification()
    monkeypatch.setattr(
        official_harness, "OfficialPinnedQualification", Qualification)
    monkeypatch.setattr(
        official_harness, "_qualification_pins_ok",
        lambda candidate: candidate is qualification)
    monkeypatch.setenv("ASAN_OPTIONS", "detect_leaks=0")
    monkeypatch.delenv("VA_ASSERT_TRACE", raising=False)

    client = _mongo_client()
    database_name = "fbv2_hp_vertical_" + uuid4().hex
    database = client[database_name]
    repos = RepositoryManager(database)
    try:
        task_id, worker_id = str(ObjectId()), str(ObjectId())
        run_id = "hpvertical" + uuid4().hex
        direction = Direction(
            task_id=task_id, fuzzer="utf8proc_fuzzer", name="normalization",
            status="completed", core_functions=["utf8proc_normalize_utf32"],
            entry_functions=["LLVMFuzzerTestOneInput"])
        assert repos.directions.save(direction)

        source_lines = SOURCE.read_text(encoding="utf-8").splitlines(True)
        function = Function(
            task_id=task_id, name="utf8proc_normalize_utf32",
            file_path="utf8proc.c", start_line=617, end_line=752,
            content="".join(source_lines[616:752]),
            analyzed_by_directions=[direction.direction_id],
            reached_by_fuzzers=["utf8proc_fuzzer"])
        assert repos.functions.save(function)

        original = {
            "worker_id": worker_id, "task_type": "pov",
            "fuzzer": "utf8proc_fuzzer", "sanitizer": "address",
            "strategy": "POV Fullscan Strategy (Streaming)",
        }
        worker = Worker(
            worker_id=worker_id, task_id=task_id,
            fuzzer="utf8proc_fuzzer", sanitizer="address",
            status=WorkerStatus.COMPLETED, finished_at=datetime.now(),
            result_summary=original)
        assert repos.workers.save(worker)

        plan_path = tmp_path / "direction-plan.json"
        plan = {
            "kind": "FBV2_DEV_DIRECTION_PLAN_V1", "status": "COMPLETED",
            "task_id": task_id, "fuzzer": "utf8proc_fuzzer",
            "direction_ids": [direction.direction_id], "direction_count": 1,
        }
        plan_path.write_text(json.dumps(plan, sort_keys=True), encoding="utf-8")
        plan_sha = _sha(plan_path)

        ledger = PersistentProcessLedgerV2.create(
            tmp_path / "process-ledger.json",
            wall_total_seconds=600, fuzz_total_seconds=60)
        _, process_sha = ledger.receipt_snapshot()
        model_snapshot = {"campaign_id": run_id, "physical": 0, "records": []}
        model_gate = SimpleNamespace(
            campaign_id=run_id, snapshot=lambda: model_snapshot)
        global_result = {"status": "RAN", "cleanup_complete": True}
        campaign = SimpleNamespace(
            ledger=ledger,
            campaign=SimpleNamespace(
                process_envelope=SimpleNamespace(ledger=ledger)),
            reservation_key=f"GLOBAL_FUZZ:{task_id}:{run_id}",
            final_result=global_result)
        executor = SimpleNamespace(
            task_id=task_id, fuzzer="utf8proc_fuzzer", repos=repos,
            _worker_context=SimpleNamespace(
                worker_id=worker_id, status="completed"))

        def recheck():
            if (_sha(SOURCE) !=
                    "0a9e6face8672baa2d99024bb7af2ff9aba97c8cb365fa138ba37d959c8b984c" or
                    _sha(HARNESS) != qualification.harness_sha256 or
                    _sha(SEED) != qualification.normal_seed_sha256 or
                    _sha(OFFICIAL_BINARY) != qualification.binary_sha256):
                raise RuntimeError("utf8proc fixture pin changed")

        bound = SimpleNamespace(
            identity=SimpleNamespace(task_id=task_id, run_id=run_id),
            executor=executor,
            strategy=SimpleNamespace(
                executor=executor,
                _development_direction_plan=(plan_path, plan_sha)),
            server=SimpleNamespace(repos=repos),
            admission=SimpleNamespace(
                qualification=qualification,
                prepared={"fuzzer_name": "utf8proc_fuzzer"}),
            model_gate=model_gate, process_ledger=ledger,
            global_campaign=campaign, recheck=recheck)
        receipt = {
            "kind": "FBV2_PUBLIC_DEV_ORIGINAL_RESULT_V1",
            "task_id": task_id, "run_id": run_id,
            "execution_status": "EXECUTED", "global_status": "RAN",
            "original_result": original, "model_physical_calls": 0,
            "process_receipt_sha256": process_sha,
            "process_stop_status": None,
        }

        analysis_providers = []
        assertion_providers = []

        def analysis_factory(_work):
            provider = ScriptedProvider(
                "function_analysis",
                _analysis_reply(650, "buffer[wpos++] = uc;"))
            analysis_providers.append(provider)
            return AgentPipeline(provider)

        def assertion_factory(_work):
            provider = ScriptedProvider(
                "assertion_generator", _assertion_reply(650))
            assertion_providers.append(provider)
            return AgentPipeline(provider)

        build_command = [
            str(CLANG), "-std=c11", "-O1", "-g",
            "-fno-omit-frame-pointer", "-fsanitize=fuzzer,address",
            "-I" + str(SOURCE_ROOT.resolve()), "{source}",
            str(HARNESS.resolve()), "-o", "{binary}",
        ]

        def physical_handoff(work, analysis_result):
            proposals = [row for row in analysis_result["assertion_proposals"]
                         if row.get("status") == "PROPOSED"]
            assert len(proposals) == 1
            assertion_id = proposals[0]["assertion_id"]
            envelope = DevelopmentProcessEnvelopeV2(
                ledger, work_item_id=task_id, assertion_id=assertion_id,
                attempt_id=run_id, output_limit_bytes=8_000_000,
                total_wall_seconds=300, wall_limit_scope="LOCAL",
                pin_hook=lambda _phase, _command: recheck())

            def execute_with_seed_trace(*args, **kwargs):
                prior = os.environ.get("VA_ASSERT_TRACE")
                os.environ["VA_ASSERT_TRACE"] = "1"
                try:
                    return product_assertions.execute_assertion(
                        *args, process_envelope=envelope, **kwargs)
                finally:
                    if prior is None:
                        os.environ.pop("VA_ASSERT_TRACE", None)
                    else:
                        os.environ["VA_ASSERT_TRACE"] = prior

            def guided_without_hit_log(*args, **kwargs):
                prior = os.environ.pop("VA_ASSERT_TRACE", None)
                try:
                    return product_assertions.guided_fuzz_assertion(
                        *args, process_envelope=envelope, **kwargs)
                finally:
                    if prior is not None:
                        os.environ["VA_ASSERT_TRACE"] = prior

            return run_prepared_hp_assertion_handoff(
                work=work, qualification=qualification,
                analysis_result=analysis_result, worker_id=worker_id,
                assertion_id=assertion_id,
                output_dir=(tmp_path / "hp-physical" / assertion_id),
                build_command=build_command,
                run_command=["{binary}", "{input}"],
                guided_seconds=1, timeout_seconds=30,
                provider_free_fixture=True,
                execute_callback=execute_with_seed_trace,
                guided_callback=guided_without_hit_log)

        result = asyncio.run(run_post_worker_hp(
            bound=bound, worker_receipt=receipt,
            analysis_pipeline_factory=analysis_factory,
            assertion_pipeline_factory=assertion_factory,
            max_items=1, provider_free_fixture=True,
            physical_handoff_factory=physical_handoff))

        assert result["status"] == "HP_POST_WORKER_COMPLETE", result
        assert result["analysis_status"] == "COMPLETE"
        assert result["physical_execution_status"] == "COMPLETE"
        assert result["selected_count"] == 1
        assert result["sp_global_effect"] == "UNCHANGED"
        assert result["security_gate_credit"] == "NOT_CREDITED"
        row = result["rows"][0]
        assert row["status"] == "ASSERTIONS_PROPOSED_UNVERIFIED"
        assert row["safe_selection_observation"]["selection_reason"] == (
            "RETAINED_EXPLICIT_SAFE")
        physical = row["physical_handoff"]
        assert physical["status"] == "HP_ASSERTION_HANDOFF_COMPLETE"
        assert physical["assertion_status"] == "HELD_FOR_EXECUTION"
        assert physical["guided_status"] == "RAN"
        assert physical["guided_report"]["fuzzer_run_count"] >= 1
        assert physical["guided_report"]["extra_counters_loaded"] is True
        assert not physical["guided_report"]["violation_witnesses"]
        assert all(provider.closed for provider in
                   [*analysis_providers, *assertion_providers])

        state, after_sha = ledger.receipt_snapshot()
        assert after_sha != process_sha
        assert state["active"] == {}
        assert state["stop_status"] is None
        assert any(row["kind"] == "AUX_PROCESS" for row in state["finished"])
        assert any(row["kind"] == "HP_FUZZ" and
                   row["key"].endswith(":guided.initial_campaign")
                   for row in state["finished"])
        assert all(row["cleanup_complete"] and not row["overrun"]
                   for row in state["finished"])

        stored_worker = repos.workers.find_by_id(worker_id)
        stored_function = repos.functions.find_by_id(function.function_id)
        assert stored_worker.status == WorkerStatus.COMPLETED
        assert stored_worker.result_summary == original
        assert stored_function.analyzed_by_directions == [direction.direction_id]
        assert result["original_result"] == original
    finally:
        client.drop_database(database_name)
        client.close()


def test_hp_only_actual_mongodb_and_physical_without_sp_worker(
        tmp_path, monkeypatch):
    """The signed HP-only seam settles without inventing an SP Worker."""
    required = (SOURCE, HARNESS, SEED, OFFICIAL_BINARY, CLANG)
    if not all(path.is_file() for path in required):
        pytest.skip("frozen public utf8proc fixture or pinned clang unavailable")

    class Qualification:
        def __init__(self):
            self.product_issued = True
            self.contract_kind = "OFFICIAL_OSS_FUZZ_UPSTREAM_HARNESS_V2"
            self.source_root = SOURCE_ROOT.resolve()
            self.harness = HARNESS.resolve()
            self.binary = OFFICIAL_BINARY.resolve()
            self.normal_seed = SEED.resolve()
            self.source_tree_sha256 = hashlib.sha256(
                SOURCE.read_bytes() + HARNESS.read_bytes()).hexdigest()
            self.harness_sha256 = _sha(HARNESS)
            self.binary_sha256 = _sha(OFFICIAL_BINARY)
            self.normal_seed_sha256 = _sha(SEED)
            self.contract_sha256 = hashlib.sha256(
                b"utf8proc-hp-only-provider-free-v1").hexdigest()

    qualification = Qualification()
    monkeypatch.setattr(
        official_harness, "OfficialPinnedQualification", Qualification)
    monkeypatch.setattr(
        official_harness, "_qualification_pins_ok",
        lambda candidate: candidate is qualification)
    monkeypatch.setattr(hp_live, "validate_hp_spec", lambda *_a, **_kw: None)
    monkeypatch.setattr(hp_live, "_settled_model", lambda *_a, **_kw: True)
    monkeypatch.setenv("ASAN_OPTIONS", "detect_leaks=0")
    monkeypatch.delenv("VA_ASSERT_TRACE", raising=False)

    client = _mongo_client()
    database_name = "fbv2_hp_only_vertical_" + uuid4().hex
    database = client[database_name]
    repos = RepositoryManager(database)
    try:
        task_id, run_id = str(ObjectId()), str(ObjectId())
        run_dir = tmp_path / "run"
        run_dir.mkdir(mode=0o700)
        prebuild = tmp_path / "prebuild"
        catalog = prebuild / "mongodb" / "functions.json"
        catalog.parent.mkdir(parents=True)
        source_lines = SOURCE.read_text(encoding="utf-8").splitlines(True)
        catalog.write_text(json.dumps([{
            "name": "utf8proc_normalize_utf32", "file_path": "utf8proc.c",
            "content": "".join(source_lines[616:752]),
            "start_line": 617, "end_line": 752,
            "reached_by_fuzzers": ["utf8proc_fuzzer"],
        }]), encoding="utf-8")
        catalog_sha = _sha(catalog)
        manifest = tmp_path / "manifest.json"
        manifest.write_text("{}\n", encoding="utf-8")
        ledger = PersistentProcessLedgerV2.create(
            tmp_path / "process-ledger.json",
            wall_total_seconds=600, fuzz_total_seconds=60)
        model_snapshot = {"campaign_id": run_id, "physical": 0,
                          "records": []}
        model_gate = SimpleNamespace(
            campaign_id=run_id, snapshot=lambda: model_snapshot)
        executor = SimpleNamespace(
            task_id=task_id, fuzzer="utf8proc_fuzzer", repos=repos)

        def recheck():
            if (_sha(SOURCE) !=
                    "0a9e6face8672baa2d99024bb7af2ff9aba97c8cb365fa138ba37d959c8b984c" or
                    _sha(HARNESS) != qualification.harness_sha256 or
                    _sha(SEED) != qualification.normal_seed_sha256 or
                    _sha(OFFICIAL_BINARY) != qualification.binary_sha256 or
                    _sha(catalog) != catalog_sha):
                raise RuntimeError("utf8proc HP-only fixture pin changed")

        bound = SimpleNamespace(
            identity=SimpleNamespace(
                task_id=task_id, run_id=run_id, run_dir=run_dir,
                product_src=PRODUCT_SRC),
            executor=executor, server=SimpleNamespace(repos=repos),
            admission=SimpleNamespace(
                qualification=qualification,
                prepared={"prebuild_dir": str(prebuild),
                          "fuzzer_name": "utf8proc_fuzzer"},
                summary={"manifest_path": str(manifest),
                         "manifest_sha256": _sha(manifest)}),
            model_gate=model_gate, process_ledger=ledger, recheck=recheck)
        hp = {"enabled": True, "max_model_calls": 4}
        control = {
            "enabled": True, "function_name": "utf8proc_normalize_utf32",
            "automatic_discovery": False,
            "source_tree_sha256": qualification.source_tree_sha256,
            "functions_json_sha256": catalog_sha,
        }
        spec = tmp_path / "spec.json"
        spec.write_text(json.dumps({"hp": hp, "hp_only": control}),
                        encoding="utf-8")
        spec_sha = _sha(spec)

        providers = []

        def pipeline_factory(_bound, _hp, role, *_args, **_kwargs):
            def make(_work):
                response = (_analysis_reply(650, "buffer[wpos++] = uc;")
                            if role == "function_analysis" else
                            _assertion_reply(650))
                provider = ScriptedProvider(role, response)
                providers.append(provider)
                return AgentPipeline(provider)
            return make

        monkeypatch.setattr(hp_live, "_pipeline_factory", pipeline_factory)
        import devtools.original_hp_preparation as hp_preparation
        actual_analysis = hp_preparation.run_prepared_hp_analysis

        async def provider_free_analysis(**kwargs):
            # This test proves HP-only integration, not live Provider credit.
            kwargs.update(
                provider_free_fixture=True,
                context_build_command=None,
                context_source_hashes=None,
                context_build_environment=None,
                context_process_envelope=None,
                catalog_manifest_path=None,
                catalog_manifest_sha256=None,
                max_context_reanalyses=1)
            return await actual_analysis(**kwargs)

        monkeypatch.setattr(
            hp_preparation, "run_prepared_hp_analysis", provider_free_analysis)

        build_command = [
            str(CLANG), "-std=c11", "-O1", "-g",
            "-fno-omit-frame-pointer", "-fsanitize=fuzzer,address",
            "-I" + str(SOURCE_ROOT.resolve()), "{source}",
            str(HARNESS.resolve()), "-o", "{binary}",
        ]

        def physical_factory(_bound, _hp, _worker, *_args, **kwargs):
            actor_id = kwargs["actor_id"]

            def handoff(work, analysis_result):
                proposals = [row for row in
                             analysis_result["assertion_proposals"]
                             if row.get("status") == "PROPOSED"]
                assert len(proposals) == 1
                assertion_id = proposals[0]["assertion_id"]
                envelope = DevelopmentProcessEnvelopeV2(
                    ledger, work_item_id=task_id,
                    assertion_id=assertion_id, attempt_id=run_id,
                    output_limit_bytes=8_000_000,
                    total_wall_seconds=300, wall_limit_scope="LOCAL",
                    pin_hook=lambda _phase, _command: recheck())

                def execute(*args, **call_kwargs):
                    prior = os.environ.get("VA_ASSERT_TRACE")
                    os.environ["VA_ASSERT_TRACE"] = "1"
                    try:
                        return product_assertions.execute_assertion(
                            *args, process_envelope=envelope, **call_kwargs)
                    finally:
                        if prior is None:
                            os.environ.pop("VA_ASSERT_TRACE", None)
                        else:
                            os.environ["VA_ASSERT_TRACE"] = prior

                def guided(*args, **call_kwargs):
                    prior = os.environ.pop("VA_ASSERT_TRACE", None)
                    try:
                        return product_assertions.guided_fuzz_assertion(
                            *args, process_envelope=envelope, **call_kwargs)
                    finally:
                        if prior is not None:
                            os.environ["VA_ASSERT_TRACE"] = prior

                return run_prepared_hp_assertion_handoff(
                    work=work, qualification=qualification,
                    analysis_result=analysis_result, worker_id=actor_id,
                    assertion_id=assertion_id,
                    output_dir=tmp_path / "hp-only-physical" / assertion_id,
                    build_command=build_command,
                    run_command=["{binary}", "{input}"], guided_seconds=1,
                    timeout_seconds=30, provider_free_fixture=True,
                    execute_callback=execute, guided_callback=guided)
            return handoff

        monkeypatch.setattr(
            hp_live, "_physical_handoff_factory", physical_factory)
        result = hp_live.run_signed_hp_only(
            bound, hp, control, spec_path=spec, spec_sha256=spec_sha)

        assert result["status"] == "HP_ONLY_PHYSICAL_COMPLETE", result
        assert result["physical_execution_status"] == "COMPLETE"
        assert result["mongo_persistence_status"] == (
            "PERSISTED_AND_READ_BACK")
        assert database.workers.count_documents({}) == 0
        assert database.suspicious_points.count_documents({}) == 0
        stored = database.hp_only_results.find_one(
            {"_id": result["mongo_record_id"]})
        assert stored is not None
        receipt_bytes = Path(result["result_path"]).read_bytes()
        assert hashlib.sha256(receipt_bytes).hexdigest() == result["result_sha256"]
        assert stored["receipt"] == json.loads(receipt_bytes)
        assert stored["receipt"]["physical"]["guided_status"] == "RAN"
        assert stored["receipt"]["automatic_discovery"] is False
        (tmp_path / "mongo-readback.json").write_text(
            json.dumps(stored, sort_keys=True, separators=(",", ":"),
                       default=str) + "\n", encoding="utf-8")
        assert all(provider.closed for provider in providers)
        state, _ = ledger.receipt_snapshot()
        assert state["active"] == {}
        assert any(row["kind"] == "HP_FUZZ" for row in state["finished"])
    finally:
        client.drop_database(database_name)
        client.close()
