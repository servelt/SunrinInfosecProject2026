"""Development-only durable Global charge around the existing campaign.

The product campaign still owns its guarded libFuzzer process and its legacy
SharedPhysicalFuzzBudget. This wrapper reserves and settles the *same* measured
Global seconds in the V2 process ledger used by the qualified Crash consumer's
AUX processes. The two Global receipts describe one physical run; they must
never be added as if they were separate execution time.

This module does not authorize the Blind runner or launch a target by itself.
"""

from __future__ import annotations

import math
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any

from dev_global_campaign import DevGlobalCampaign
from dev_persistent_physical_fuzz_ledger import PhysicalBudgetExhausted
from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2
from dev_process_envelope_v2 import DevelopmentProcessEnvelopeV2


_KEY = re.compile(r"[A-Za-z0-9:_-]+\Z")


class AccountedGlobalCampaign:
    """One-shot adapter for original FBv2's Global bridge API."""

    def __init__(self, campaign: DevGlobalCampaign,
                 ledger: PersistentProcessLedgerV2, *, reservation_key: str):
        if (type(campaign) is not DevGlobalCampaign or
                type(ledger) is not PersistentProcessLedgerV2 or
                type(reservation_key) is not str or not _KEY.fullmatch(reservation_key) or
                type(campaign.process_envelope) is not DevelopmentProcessEnvelopeV2 or
                campaign.process_envelope.ledger is not ledger or
                campaign.require_accounted_consumer is not True or
                campaign.process is not None or
                campaign.final_result is not None or
                not campaign._authority_ok()):
            raise ValueError("Global campaign lacks one qualified durable process account")
        self.campaign = campaign
        self.ledger = ledger
        self.reservation_key = reservation_key
        self.require_accounted_consumer = True
        self._start_attempted = False
        self._reservation_active = False
        self._settlement_failed = False
        self._final_result: dict[str, Any] | None = None
        self._no_seed_gate: Any = None
        self._no_seed_receipt_sha256: str | None = None

    def _check_no_seed_proof(self, gate: Any, direction_ids: list[str],
                             request_ids: list[str]) -> None:
        if (not direction_ids or len(set(direction_ids)) != len(direction_ids) or
                any(type(value) is not str or not value for value in direction_ids) or
                not request_ids or len(set(request_ids)) != len(request_ids) or
                any(type(value) is not str or not value for value in request_ids) or
                not self.reservation_key.endswith(':' + gate.campaign_id)):
            raise ValueError('no-seed model identity is invalid')
        snapshot = gate.snapshot()
        for row in snapshot['records']:
            if (type(row) is not dict or
                    row.get('status') != 'COMPLETED' or
                    type(row.get('request_id')) is not str or
                    gate.verify_response_evidence(
                        row['request_id']).get('status') != 'VERIFIED'):
                raise ValueError('model activity is unsettled')
            events = row.get('tool_events', [])
            if type(events) is not list:
                raise ValueError('model tool list is invalid')
            for event in events:
                if (type(event) is not dict or
                        event.get('status') != 'COMPLETED' or
                        type(event.get('call_id')) is not str or
                        gate.verify_tool_event(
                            row['request_id'], event['call_id']).get('status') !=
                            'VERIFIED'):
                    raise ValueError('model tool is unsettled')
        rows = [row for row in snapshot['records'] if row.get('role') == 'seed']
        if (snapshot.get('campaign_id') != gate.campaign_id or
                {row.get('request_id') for row in rows} != set(request_ids) or
                {row.get('owner_id') for row in rows} != set(direction_ids) or
                any(row.get('status') != 'COMPLETED' for row in rows)):
            raise ValueError('no-seed model turns are incomplete or mismatched')
        for row in rows:
            request_id = row['request_id']
            if gate.verify_response_evidence(request_id).get('status') != 'VERIFIED':
                raise ValueError('no-seed model response is unverified')
            events = row.get('tool_events', [])
            if type(events) is not list:
                raise ValueError('no-seed model tool list is invalid')
            for event in events:
                if (type(event) is not dict or event.get('status') != 'COMPLETED' or
                        type(event.get('call_id')) is not str or
                        gate.verify_tool_event(request_id, event['call_id']).get(
                            'status') != 'VERIFIED'):
                    raise ValueError('no-seed model tool is unverified')

    def record_clean_no_seed(self, *, plan_path: Path, plan_sha256: str,
                             direction_ids: list[str], model_gate: Any
                             ) -> dict[str, Any]:
        """Settle a completed zero-Seed phase without creating a physical debit."""
        if (self._start_attempted or self._final_result is not None or
                self.campaign.process is not None or
                self.campaign.final_result is not None or
                self.campaign.run_dir.exists() or self.campaign.seeds or
                not self.campaign._authority_ok() or
                plan_path.is_symlink() or not plan_path.is_file() or
                hashlib.sha256(plan_path.read_bytes()).hexdigest() != plan_sha256):
            raise ValueError('no-seed Global was already started or authority changed')
        plan = json.loads(plan_path.read_text(encoding='utf-8'))
        if (plan.get('status') != 'COMPLETED' or
                not set(direction_ids).issubset(set(plan.get('direction_ids', [])))):
            raise ValueError('no-seed Direction plan is not pinned')
        process, process_sha = self.ledger.receipt_snapshot()
        if (process['stop_status'] is not None or process['active'] or
                any(row['key'] == self.reservation_key for row in process['finished'])):
            raise ValueError('no-seed process ledger is not settled')
        model_rows = model_gate.snapshot()['records']
        seed_rows = [row for row in model_rows
                     if row.get('role') == 'seed']
        request_ids = sorted(row['request_id'] for row in seed_rows)
        self._check_no_seed_proof(model_gate, direction_ids, request_ids)
        self._start_attempted = True
        self.campaign.stage_direction_seeds(plan_path, plan_sha256, [])
        status = self.campaign.start()
        if (status != 'NOT_STARTED_NO_DIRECTION_SEED' or
                self.campaign.final_result !=
                    {'status': status, 'seed_count': 0} or
                self.campaign.process is not None or self.campaign.seeds):
            raise RuntimeError('no-seed Global start did not prove a clean skip')
        seed_manifest = self.campaign.run_dir / 'DIRECTION_SEEDS.json'
        raw_result = self.campaign.run_dir / 'DEV_GLOBAL_RESULT.json'
        if (seed_manifest.is_symlink() or raw_result.is_symlink() or
                not seed_manifest.is_file() or not raw_result.is_file() or
                json.loads(seed_manifest.read_text(encoding='utf-8')) != {
                    'direction_plan_path': str(plan_path.resolve()),
                    'direction_plan_sha256': plan_sha256,
                    'seed_count': 0, 'seeds': []} or
                json.loads(raw_result.read_text(encoding='utf-8')) !=
                    self.campaign.final_result or
                any((self.campaign.run_dir / 'corpus' / 'global').iterdir())):
            raise RuntimeError('no-seed campaign files are inconsistent')
        for path in (seed_manifest, raw_result):
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        result = {'status': 'SKIPPED_NO_SEED', 'cleanup_complete': True,
                  'physical_seconds': 0.0, 'seed_count': 0,
                  'direction_plan_sha256': plan_sha256,
                  'seed_direction_ids': list(direction_ids),
                  'seed_request_ids': request_ids,
                  'process_ledger_sha256_at_skip': process_sha,
                  'process_ledger_revision_at_skip': process['revision'],
                  'direction_seed_manifest_sha256': hashlib.sha256(
                      seed_manifest.read_bytes()).hexdigest(),
                  'raw_global_result_sha256': hashlib.sha256(
                      raw_result.read_bytes()).hexdigest(),
                  'global_charge_relation': 'NO_PHYSICAL_GLOBAL_RUN'}
        receipt_path = self.campaign.run_dir / 'DEV_GLOBAL_NO_SEED_SETTLEMENT.json'
        data = (json.dumps(result, sort_keys=True) + '\n').encode()
        fd = os.open(receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(fd)
        parent_fd = os.open(receipt_path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        self._no_seed_gate = model_gate
        self._no_seed_receipt_sha256 = hashlib.sha256(data).hexdigest()
        self._final_result = result
        return self.final_result

    def __getattr__(self, name: str) -> Any:
        return getattr(self.campaign, name)

    @property
    def final_result(self) -> dict[str, Any] | None:
        if self._final_result is not None:
            snapshot, _digest = self.ledger.receipt_snapshot()
            if self._final_result.get('status') == 'SKIPPED_NO_SEED':
                result = self._final_result
                receipt_path = (self.campaign.run_dir /
                                'DEV_GLOBAL_NO_SEED_SETTLEMENT.json')
                seed_manifest = self.campaign.run_dir / 'DIRECTION_SEEDS.json'
                raw_result = self.campaign.run_dir / 'DEV_GLOBAL_RESULT.json'
                corpus = self.campaign.run_dir / 'corpus' / 'global'
                if (receipt_path.is_symlink() or not receipt_path.is_file() or
                        hashlib.sha256(receipt_path.read_bytes()).hexdigest() !=
                            self._no_seed_receipt_sha256 or
                        json.loads(receipt_path.read_text(encoding='utf-8')) !=
                            result or
                        self.campaign.process is not None or self.campaign.seeds or
                        self.campaign.final_result !=
                            {'status': 'NOT_STARTED_NO_DIRECTION_SEED',
                             'seed_count': 0} or
                        seed_manifest.is_symlink() or
                        not seed_manifest.is_file() or
                        hashlib.sha256(seed_manifest.read_bytes()).hexdigest() !=
                            result['direction_seed_manifest_sha256'] or
                        json.loads(seed_manifest.read_text(encoding='utf-8')) != {
                            'direction_plan_path': str(self.campaign.plan_path),
                            'direction_plan_sha256': result['direction_plan_sha256'],
                            'seed_count': 0, 'seeds': []} or
                        raw_result.is_symlink() or not raw_result.is_file() or
                        hashlib.sha256(raw_result.read_bytes()).hexdigest() !=
                            result['raw_global_result_sha256'] or
                        json.loads(raw_result.read_text(encoding='utf-8')) !=
                            self.campaign.final_result or
                        not corpus.is_dir() or corpus.is_symlink() or
                        any(corpus.iterdir()) or
                        snapshot['stop_status'] is not None or
                        self.reservation_key in snapshot['active'] or
                        any(row['key'] == self.reservation_key
                            for row in snapshot['finished']) or
                        hashlib.sha256(self.campaign.plan_path.read_bytes()).hexdigest() !=
                            result['direction_plan_sha256']):
                    raise RuntimeError('durable no-seed Global proof changed')
                self._check_no_seed_proof(
                    self._no_seed_gate, result['seed_direction_ids'],
                    result['seed_request_ids'])
                return result
            charged = [row for row in snapshot["finished"]
                       if row["key"] == self.reservation_key]
            if (len(charged) != 1 or
                    charged[0] != self._final_result["durable_global_charge"] or
                    self.reservation_key in snapshot["active"] or
                    (self._final_result["status"] == "RAN" and
                     snapshot["stop_status"] is not None)):
                raise RuntimeError("Global durable charge or later stop changed")
        return self._final_result

    def stage_direction_seeds(self, *args: Any, **kwargs: Any) -> None:
        if self._start_attempted:
            raise RuntimeError("Global seed stage is sealed after start attempt")
        self.campaign.stage_direction_seeds(*args, **kwargs)

    def stage_harness_normal_seed(self) -> None:
        if self._start_attempted:
            raise RuntimeError("Global seed stage is sealed after start attempt")
        self.campaign.stage_harness_normal_seed()

    def _mark_uncertain(self, reason: str) -> None:
        if self._reservation_active:
            self.ledger.mark_stop("STOPPED_UNCERTAIN_PROCESS", reason)

    def _settle(self, result: dict[str, Any]) -> dict[str, Any]:
        if self._settlement_failed or not self._reservation_active:
            raise RuntimeError("Global physical reservation is not active")
        measured = result.get("physical_seconds") if type(result) is dict else None
        cleanup = result.get("cleanup_complete") if type(result) is dict else None
        secondary = result.get("global_budget_charge") if type(result) is dict else None
        secondary_rows = [row for row in self.campaign.budget.records
                          if row.get("key") == "GLOBAL"]
        if (type(measured) not in (int, float) or not math.isfinite(measured) or
                measured < 0 or type(cleanup) is not bool or
                type(secondary) is not dict or
                len(secondary_rows) != 1 or secondary_rows[0] != secondary or
                secondary.get("key") != "GLOBAL" or
                secondary.get("reserved_seconds") !=
                self.campaign.global_wall_reservation_seconds or
                type(secondary.get("physical_seconds")) not in (int, float) or
                not math.isclose(float(measured),
                                 float(secondary["physical_seconds"]),
                                 rel_tol=0, abs_tol=1e-9)):
            self._settlement_failed = True
            self._mark_uncertain("Global physical result or secondary charge missing")
            raise RuntimeError("Global physical result cannot be settled durably")
        # The exact physical debit may commit before the receipt can be read.
        # A post-commit read failure must never expose the campaign's raw RAN
        # result on a later finish/abort call.
        self._settlement_failed = True
        row = self.ledger.finish(
            self.reservation_key, physical_seconds=float(measured),
            cleanup_complete=cleanup)
        self._reservation_active = False
        try:
            with self.ledger._lock:
                snapshot, receipt_sha = self.ledger.receipt_snapshot()
                charged = dict(result)
                charged["durable_global_charge"] = row
                charged["durable_process_ledger_path"] = str(self.ledger.path)
                charged["durable_process_ledger_sha256"] = receipt_sha
                charged["durable_process_ledger_revision"] = snapshot["revision"]
                charged["global_charge_relation"] = "SAME_PHYSICAL_SECONDS_SECONDARY_BUDGET"
                if snapshot["stop_status"] is not None:
                    charged["original_global_status"] = charged["status"]
                    charged["status"] = snapshot["stop_status"]
                self._final_result = charged
                self._settlement_failed = False
        except BaseException as original:
            try:
                self.ledger.mark_stop(
                    "STOPPED_PIN_DRIFT", "Global durable charge receipt unavailable")
            except BaseException as cleanup:
                original.add_note("Global receipt stop failed: " +
                                  type(cleanup).__name__)
            raise
        return charged

    def _recover_failed_start(self, original: BaseException) -> None:
        if (self._settlement_failed or not self._reservation_active or
                self.ledger.snapshot()["stop_status"] is not None):
            return
        try:
            result = self.campaign.final_result
            if result is None and self.campaign.process is not None:
                result = self.campaign.abort()
            if result is None:
                self._mark_uncertain("Global start failed without a physical stop receipt")
            else:
                self._settle(result)
        except BaseException as cleanup:
            original.add_note(
                "Global physical start recovery failed: " +
                type(cleanup).__name__ + ": " + str(cleanup))
            try:
                self._mark_uncertain("Global start recovery could not prove cleanup")
            except BaseException as stop_error:
                original.add_note("Global uncertain stop failed: " +
                                  type(stop_error).__name__)

    def start(self) -> str:
        if self._start_attempted:
            raise RuntimeError("Global physical start cannot be retried")
        self._start_attempted = True
        if not self.campaign.seeds:
            return self.campaign.start()  # Existing no-seed path starts no process.
        if (self.campaign.budget.available <
                self.campaign.global_wall_reservation_seconds):
            raise PhysicalBudgetExhausted(
                "secondary Global reservation exceeds its physical budget")
        self.ledger.reserve(self.reservation_key, "GLOBAL_FUZZ",
                            self.campaign.global_wall_reservation_seconds)
        self._reservation_active = True
        try:
            status = self.campaign.start()
            if status != "ACTIVE":
                result = self.campaign.final_result
                if result is None:
                    self._mark_uncertain("Global start returned without a stop receipt")
                    raise RuntimeError("Global start did not prove process disposition")
                self._settle(result)
            return status
        except BaseException as original:
            self._recover_failed_start(original)
            raise

    def _finish_or_abort(self, kind: str) -> dict[str, Any]:
        if self._final_result is not None:
            return self.final_result
        if self._settlement_failed:
            raise RuntimeError("Global durable settlement receipt is incomplete")
        if not self._reservation_active:
            raise RuntimeError("Global has no repeatable durable settlement")
        try:
            result = getattr(self.campaign, kind)()
            return self._settle(result)
        except BaseException as original:
            if self._settlement_failed:
                raise
            if (self._reservation_active and
                    self.ledger.snapshot()["stop_status"] is not None):
                raise
            # A failed finish may already have charged the campaign's
            # secondary ledger. Do not ask abort to charge it a second time.
            charged = [row for row in self.campaign.budget.records
                       if row.get("key") == "GLOBAL"]
            if self._reservation_active and len(charged) == 1:
                try:
                    self._settle({
                        "status": "INCOMPLETE_GLOBAL_SETTLEMENT",
                        "physical_seconds": charged[0]["physical_seconds"],
                        "cleanup_complete": False,
                        "global_budget_charge": charged[0],
                    })
                except BaseException as cleanup:
                    original.add_note(
                        "Global charged-result reconciliation failed: " +
                        type(cleanup).__name__ + ": " + str(cleanup))
            elif self._reservation_active and kind == "finish":
                try:
                    result = self.campaign.abort()
                    self._settle(result)
                except BaseException as cleanup:
                    original.add_note(
                        "Global abort after finish failure failed: " +
                        type(cleanup).__name__ + ": " + str(cleanup))
            if self._reservation_active:
                try:
                    self._mark_uncertain("Global settlement failed without measured cleanup")
                except BaseException as stop_error:
                    original.add_note("Global uncertain stop failed: " +
                                      type(stop_error).__name__)
            raise

    def finish(self) -> dict[str, Any]:
        return self._finish_or_abort("finish")

    def abort(self) -> dict[str, Any]:
        return self._finish_or_abort("abort")
