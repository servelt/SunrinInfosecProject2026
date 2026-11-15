"""Second-target Actual-Mongo HP vertical using public cJSON evidence.

The scripted replies are a provider-free integration fixture.  They grant no
model, vulnerability, Harness Generator, Gate, or automatic-discovery credit.
The source instrumentation, Clang/ASan build, seed replay, guided campaign,
Mongo state, and V2 process receipts are real product paths.
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
from vulnerabilityanalysis.models import RuntimeResult

from devtools.original_hp_post_worker import run_post_worker_hp
from devtools.original_hp_preparation import run_prepared_hp_assertion_handoff


CJSON_ROOT = Path(
    "/home/dawne/SunrinInfosecProject2026/reference_archive_20261028/"
    "by_date/20261023/hp-cjson-independent-preflight-20261023")
SOURCE = CJSON_ROOT / "source/cJSON.c"
HARNESS = CJSON_ROOT / "cjson_length_fuzzer.cc"
SEED = CJSON_ROOT / "seeds/normal.json"
OFFICIAL_BINARY = CJSON_ROOT / "build/cjson_length_fuzzer"
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


def _analysis_reply() -> dict:
    assumption = (
        "The parser cursor offset does not exceed the supplied buffer length "
        "before parse_value dispatches to a value parser.")
    quote = "if ((input_buffer == NULL) || (input_buffer->content == NULL))"
    return {
        "summary": "Dispatches a bounded parse buffer to a JSON value parser",
        "input_flow": "Harness bytes initialize parse_buffer content and length",
        "state_dependencies": ["input_buffer->offset", "input_buffer->length"],
        "context_requests": [],
        "safe_assumptions": [assumption],
        "unknowns": [],
        "input_sources": ["input_buffer->content", "input_buffer->length"],
        "security_sensitive_operations": ["buffer_at_offset(input_buffer)"],
        "validations": ["can_read", "can_access_at_index"],
        "memory_operations": ["buffer_at_offset(input_buffer)"],
        "evidence": [quote],
        "safe_assumption_lifecycle": [],
        "hypothesis_evaluations": [{
            "source_location": "source/cJSON.c:1320",
            "source_file": "source/cJSON.c",
            "source_line": 1320,
            "source_quote": quote,
            "security_property": "bounded parser cursor",
            "input_influence": "INPUT_DEPENDENT",
            "hypothesis": "the parser cursor may advance beyond the input length",
            "judgment": "EXPLICIT_SAFE_JUDGMENT",
            "reason": "the parser helpers advance offset only after bounded reads",
            "safe_assumption": assumption,
        }],
    }


def _assertion_reply() -> dict:
    assumption = (
        "The parser cursor offset does not exceed the supplied buffer length "
        "before parse_value dispatches to a value parser.")
    return {
        "assertions": [{
            "safe_id": 0,
            "safe_assumption": assumption,
            "runtime_expression": "input_buffer->offset <= input_buffer->length",
            "source_line": 1320,
            "required_context": [],
            "rationale": "measure the parser cursor invariant before dispatch",
        }],
        "dispositions": [{
            "safe_id": 0,
            "safe_assumption": assumption,
            "status": "PROPOSED",
            "reason": "the local cursor and length are runtime-expressible",
        }],
    }


def _mongo_client() -> MongoClient:
    client = MongoClient(
        "mongodb://127.0.0.1:27027/?directConnection=true",
        serverSelectionTimeoutMS=2_000)
    try:
        client.admin.command("ping")
    except Exception as exc:
        client.close()
        pytest.skip(f"actual MongoDB unavailable: {type(exc).__name__}")
    return client


@pytest.mark.parametrize(
    "forced_guided", ["RAN", "CRASH_OBSERVED_INCOMPLETE", None],
    ids=["complete-terminal", "isolated-public-crash-terminal", "actual-smoke"])
def test_actual_mongodb_cjson_assertion_guided_terminal_states(
        tmp_path, monkeypatch, forced_guided):
    required = (SOURCE, HARNESS, SEED, OFFICIAL_BINARY, CLANG)
    if not all(path.is_file() for path in required):
        pytest.skip("frozen public cJSON fixture or pinned clang unavailable")
    pins = {
        SOURCE: "fdfd427d82fadb395076567edf470c80cebee319e38fd417198508fe11ae56e7",
        HARNESS: "d742b2fc61f175670bd77f4eb8ea3930a62f41c67d2e0bbcdd369f6b09fcfd26",
        SEED: "39f94024cbcf740958d8bb6e25095e33ee260776744698ff4e0d43a4454bf72f",
        OFFICIAL_BINARY: "18218bdc0973d1c0edee48cfde30d052a58c9d6cbf83a774a5152aad9edc1f82",
    }
    assert all(_sha(path) == digest for path, digest in pins.items())

    class Qualification:
        def __init__(self):
            self.product_issued = True
            # The product path intentionally accepts only its official-harness
            # contract.  The type and pin validator are replaced only inside
            # this provider-free test; this is not an issued qualification.
            self.contract_kind = "OFFICIAL_OSS_FUZZ_UPSTREAM_HARNESS_V2"
            self.source_root = CJSON_ROOT.resolve()
            self.harness = HARNESS.resolve()
            self.binary = OFFICIAL_BINARY.resolve()
            self.normal_seed = SEED.resolve()
            self.source_tree_sha256 = hashlib.sha256(
                SOURCE.read_bytes() + HARNESS.read_bytes()).hexdigest()
            self.harness_sha256 = _sha(HARNESS)
            self.binary_sha256 = _sha(OFFICIAL_BINARY)
            self.normal_seed_sha256 = _sha(SEED)
            self.contract_sha256 = hashlib.sha256(
                b"cjson-public-reference-provider-free-v1").hexdigest()

    qualification = Qualification()
    monkeypatch.setattr(
        official_harness, "OfficialPinnedQualification", Qualification)
    monkeypatch.setattr(
        official_harness, "_qualification_pins_ok",
        lambda candidate: candidate is qualification)
    monkeypatch.setenv("ASAN_OPTIONS", "detect_leaks=0")
    monkeypatch.delenv("VA_ASSERT_TRACE", raising=False)
    if forced_guided is not None:
        def deterministic_fuzz(binary, corpus, *, seconds,
                               single_process=False, max_len=None,
                               guarded_runner=None, process_envelope=None,
                               env=None,
                               process_kind="HP_FUZZ",
                               process_segment="fuzz.campaign"):
            assert single_process is True
            assert process_envelope is not None
            assert isinstance(env, dict)
            assert env.get("ASAN_OPTIONS") == "handle_abort=0"
            command = [str(Path(binary).resolve()), str(Path(corpus).resolve()),
                       f"-max_total_time={seconds}"]
            lease = process_envelope.before_process(
                command, cwd=Path(corpus), env=None, timeout=seconds + 15,
                kind=process_kind, segment=process_segment)
            if forced_guided == "CRASH_OBSERVED_INCOMPLETE":
                (Path(corpus) / "crash-forced-public-control").write_bytes(
                    SEED.read_bytes())
                runtime = RuntimeResult(
                    1, "", "ERROR: AddressSanitizer: forced public control\n"
                    "stat::number_of_executed_units: 1\n", None, False,
                    "AddressSanitizer", None, "TARGET_CRASH",
                    coverage={"initial_edges": 50, "final_edges": 51,
                              "initial_features": 52, "final_features": 53,
                              "status": "INCREASED"})
            else:
                runtime = RuntimeResult(
                    0, "", "stat::number_of_executed_units: 64\n",
                    None, False, None, None, "NO_CRASH",
                    coverage={"initial_edges": 50, "final_edges": 51,
                              "initial_features": 52, "final_features": 53,
                              "status": "INCREASED"})
            process_envelope.after_process(
                lease, elapsed_seconds=0.001, cleanup_complete=True,
                output_limited=False, error=None)
            return runtime

        monkeypatch.setattr(
            product_assertions, "fuzz_locally", deterministic_fuzz)

    client = _mongo_client()
    database_name = "fbv2_hp_cjson_vertical_" + uuid4().hex
    database = client[database_name]
    repos = RepositoryManager(database)
    try:
        task_id, worker_id = str(ObjectId()), str(ObjectId())
        run_id = "hpcjson" + uuid4().hex
        direction = Direction(
            task_id=task_id, fuzzer="cjson_length_fuzzer", name="json-parse",
            status="completed", core_functions=["parse_value"],
            entry_functions=["LLVMFuzzerTestOneInput"])
        assert repos.directions.save(direction)

        source_lines = SOURCE.read_text(encoding="utf-8").splitlines(True)
        function = Function(
            task_id=task_id, name="parse_value",
            file_path="source/cJSON.c", start_line=1312, end_line=1364,
            content="".join(source_lines[1311:1364]),
            analyzed_by_directions=[direction.direction_id],
            reached_by_fuzzers=["cjson_length_fuzzer"])
        assert repos.functions.save(function)

        original = {
            "worker_id": worker_id, "task_type": "pov",
            "fuzzer": "cjson_length_fuzzer", "sanitizer": "address",
            "strategy": "POV Fullscan Strategy (Streaming)",
        }
        worker = Worker(
            worker_id=worker_id, task_id=task_id,
            fuzzer="cjson_length_fuzzer", sanitizer="address",
            status=WorkerStatus.COMPLETED, finished_at=datetime.now(),
            result_summary=original)
        assert repos.workers.save(worker)

        plan_path = tmp_path / "direction-plan.json"
        plan = {
            "kind": "FBV2_DEV_DIRECTION_PLAN_V1", "status": "COMPLETED",
            "task_id": task_id, "fuzzer": "cjson_length_fuzzer",
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
        campaign = SimpleNamespace(
            ledger=ledger,
            campaign=SimpleNamespace(
                process_envelope=SimpleNamespace(ledger=ledger)),
            reservation_key=f"GLOBAL_FUZZ:{task_id}:{run_id}",
            final_result={"status": "RAN", "cleanup_complete": True})
        executor = SimpleNamespace(
            task_id=task_id, fuzzer="cjson_length_fuzzer", repos=repos,
            _worker_context=SimpleNamespace(
                worker_id=worker_id, status="completed"))

        def recheck():
            if any(_sha(path) != digest for path, digest in pins.items()):
                raise RuntimeError("cJSON fixture pin changed")

        bound = SimpleNamespace(
            identity=SimpleNamespace(task_id=task_id, run_id=run_id),
            executor=executor,
            strategy=SimpleNamespace(
                executor=executor,
                _development_direction_plan=(plan_path, plan_sha)),
            server=SimpleNamespace(repos=repos),
            admission=SimpleNamespace(
                qualification=qualification,
                prepared={"fuzzer_name": "cjson_length_fuzzer"}),
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

        providers = []

        def pipeline(role, response):
            provider = ScriptedProvider(role, response)
            providers.append(provider)
            return AgentPipeline(provider)

        build_command = [
            str(CLANG), "-O1", "-g", "-fno-omit-frame-pointer",
            "-fsanitize=fuzzer,address", "-I" + str((CJSON_ROOT / "source").resolve()),
            "{source}", str(HARNESS.resolve()), "-o", "{binary}",
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
                output_dir=tmp_path / "hp-physical" / assertion_id,
                build_command=build_command,
                run_command=["{binary}", "{input}"],
                guided_seconds=1, timeout_seconds=30,
                provider_free_fixture=True,
                execute_callback=execute_with_seed_trace,
                guided_callback=guided_without_hit_log)

        result = asyncio.run(run_post_worker_hp(
            bound=bound, worker_receipt=receipt,
            analysis_pipeline_factory=lambda _work: pipeline(
                "function_analysis", _analysis_reply()),
            assertion_pipeline_factory=lambda _work: pipeline(
                "assertion_generator", _assertion_reply()),
            max_items=1, provider_free_fixture=True,
            physical_handoff_factory=physical_handoff))

        if forced_guided == "RAN":
            assert result["status"] == "HP_POST_WORKER_COMPLETE", json.dumps(
                result, ensure_ascii=False, indent=2, default=str)
        elif forced_guided == "CRASH_OBSERVED_INCOMPLETE":
            assert result["status"] == "HP_POST_WORKER_PARTIAL_BLOCKED", result
        else:
            assert result["status"] in {
                "HP_POST_WORKER_COMPLETE", "HP_POST_WORKER_PARTIAL_BLOCKED"}, json.dumps(
                    result, ensure_ascii=False, indent=2, default=str)
        # COMPLETE reports the complete selection cardinality.  An early
        # physical-handoff PARTIAL_BLOCKED response intentionally preserves
        # only rows that were actually processed, so it has no
        # ``selected_count`` field.
        if result["status"] == "HP_POST_WORKER_COMPLETE":
            assert result["selected_count"] == 1
        else:
            assert len(result["rows"]) == 1
        assert result["sp_global_effect"] == "UNCHANGED"
        assert result["security_gate_credit"] == "NOT_CREDITED"
        row = result["rows"][0]
        assert row["status"] == "ASSERTIONS_PROPOSED_UNVERIFIED"
        physical = row["physical_handoff"]
        assert physical.get("assertion_status") == "HELD_FOR_EXECUTION", physical
        assert physical["guided_report"]["fuzzer_run_count"] >= 1
        assert physical["guided_report"]["extra_counters_loaded"] is True
        assert not physical["guided_report"]["violation_witnesses"]
        if physical["guided_status"] == "RAN":
            assert result["status"] == "HP_POST_WORKER_COMPLETE"
            assert result["analysis_status"] == "COMPLETE"
            assert result["physical_execution_status"] == "COMPLETE"
            assert physical["status"] == "HP_ASSERTION_HANDOFF_COMPLETE"
        else:
            # The frozen reference harness can rediscover its known public
            # cJSON crash.  It is not an Assertion violation or HP discovery.
            assert physical["guided_status"] == "CRASH_OBSERVED_INCOMPLETE"
            assert physical["status"] == "HP_GUIDED_CRASH_OBSERVED_UNGATED"
            assert result["status"] == "HP_POST_WORKER_PARTIAL_BLOCKED"
            assert result["reason"] == "HP_PHYSICAL_HANDOFF_INCOMPLETE"
            assert physical["guided_report"]["other_crash_artifacts"]
            assert result["security_gate_credit"] == "NOT_CREDITED"
        assert all(provider.closed for provider in providers)

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

        assert repos.workers.find_by_id(worker_id).result_summary == original
        assert result["original_result"] == original
    finally:
        client.drop_database(database_name)
        client.close()
