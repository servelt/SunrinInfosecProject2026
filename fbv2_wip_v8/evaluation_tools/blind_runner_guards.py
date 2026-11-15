"""Preflight and accounting for the blind runner draft; no model/fuzzer launch here."""
from __future__ import annotations
from dataclasses import dataclass, field
import hashlib
import json
import math
import os
from pathlib import Path
import time

K, SP_MAX, HP_ANALYSIS_MAX, HP_ASSERT_MAX = 24, 4, 3, 1
LOGICAL_MAX, PHYSICAL_MAX, RETRY_MAX = 192, 194, 2
FUZZ_MAX, ASSERT_FUZZ_MAX, SEED_FUZZ_MAX = 7200, 600, 300
WALL_MAX = 86400
SP_ROLES = frozenset({'sp_generation', 'sp_verifier', 'poc_generator'})
HP_ROLES = frozenset({'function_analysis', 'assertion_generator'})


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1048576), b''):
            h.update(chunk)
    return h.hexdigest()


def check_contract(contract: dict, root: Path | dict[str, Path]) -> None:
    expected = dict(k_functions=K, sp_per_function=SP_MAX, hp_per_function=4,
                    logical_max=LOGICAL_MAX, physical_max=PHYSICAL_MAX,
                    manual_retries_max=RETRY_MAX, fuzz_seconds_combined=FUZZ_MAX,
                    wall_seconds=WALL_MAX)
    if any(contract.get('limits', {}).get(k) != v for k, v in expected.items()):
        raise ValueError('fixed preregistered limit changed')
    if contract.get('max_candidates_per_function') != 2:
        raise ValueError('fixed candidate cap changed')
    if contract.get('runtime_sanitizers') != ['address']:
        raise ValueError('fixed runtime Sanitizer changed')
    if contract.get('fuzz_overrun_policy', 'LOCKOUT_V1') not in {
            'LOCKOUT_V1', 'PHYSICAL_DEBIT_V1'}:
        raise ValueError('unapproved fuzz overrun policy')
    pins = contract.get('sha256_pins')
    if not isinstance(pins, dict) or not pins:
        raise ValueError('no frozen source/product/prompt/runner/input pins')
    roots = {'reference': root} if isinstance(root, Path) else root
    if not roots or any(key not in {'reference', 'product'} for key in roots):
        raise ValueError('only reference and live product roots may be pinned')
    for name, want in pins.items():
        if '::' in name:
            namespace, relative = name.split('::', 1)
        else:
            namespace, relative = 'reference', name
        if namespace not in roots:
            raise ValueError(f'unapproved pin namespace: {namespace}')
        base = roots[namespace].resolve()
        path = (base / relative).resolve()
        if not path.is_relative_to(base) or not path.is_file():
            raise ValueError(f'pinned path unavailable: {name}')
        if not isinstance(want, str) or len(want) != 64 or digest(path) != want:
            raise ValueError(f'pinned digest mismatch: {name}')


def consume_approval(approval: Path, consumed: Path, contract: Path,
                     runner: Path) -> None:
    want = {'approved': True, 'contract_sha256': digest(contract),
            'runner_sha256': digest(runner)}
    if json.loads(approval.read_text()) != want:
        raise ValueError('approval does not bind exact contract and runner')
    # O_EXCL fails closed across competing processes; an interrupted run uses it up.
    fd = os.open(consumed, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump({**want, 'consumed_at_unix': time.time()}, stream)
        stream.flush()
        os.fsync(stream.fileno())
    approval.unlink(missing_ok=True)


@dataclass
class Ledger:
    started_at: float
    functions: list[str] = field(default_factory=list)
    counts: dict[str, dict[str, int]] = field(default_factory=dict)
    logical: int = 0
    physical: int = 0
    retries: int = 0
    fuzz_actual: float = 0.0
    # Budget accounting remains bounded by FUZZ_MAX. Physical consumption and
    # any overrun are recorded separately and survive checkpoint restoration.
    fuzz_physical_actual: float = 0.0
    fuzz_overrun_seconds: float = 0.0
    fuzz_overrun_blocked: bool = False
    fuzz_overrun_events: list[dict] = field(default_factory=list)
    # The frozen Blind 2 contract uses LOCKOUT_V1. A future contract may
    # explicitly opt into physical-time debit without changing old receipts.
    fuzz_overrun_policy: str = 'LOCKOUT_V1'
    attempts: list[dict] = field(default_factory=list)
    pending: list[dict] = field(default_factory=list)
    active_turn: dict | None = None
    active_fuzz: dict | None = None

    def wall(self, now: float | None = None) -> None:
        if (time.time() if now is None else now) - self.started_at >= WALL_MAX:
            raise ValueError('wall limit reached')

    def select(self, function_id: str) -> None:
        self.wall()
        if function_id in self.functions or len(self.functions) >= K:
            raise ValueError('selection not eligible')
        self.functions.append(function_id)
        self.counts[function_id] = {}

    def mark_pending(self, item_id: str, reason: str) -> None:
        if not any(row['id'] == item_id for row in self.pending):
            self.pending.append({'id': item_id, 'reason': reason})

    def begin_turn(self, function_id: str, role: str, request_hash: str) -> str:
        self.wall()
        if self.active_turn or self.active_fuzz or function_id not in self.counts:
            raise ValueError('turn outside selected idle function')
        if role not in SP_ROLES | HP_ROLES or len(request_hash) != 64:
            raise ValueError('unapproved role or unpinned request')
        counts = self.counts[function_id]
        sp = sum(counts.get(r, 0) for r in SP_ROLES)
        if (self.logical >= LOGICAL_MAX or self.physical >= PHYSICAL_MAX or
                role in SP_ROLES and sp >= SP_MAX or
                role == 'function_analysis' and counts.get(role, 0) >= HP_ANALYSIS_MAX or
                role == 'assertion_generator' and counts.get(role, 0) >= HP_ASSERT_MAX):
            raise ValueError('logical turn limit reached')
        self.logical += 1
        counts[role] = counts.get(role, 0) + 1
        turn_id = f'L{self.logical:03d}'
        self.active_turn = {'id': turn_id, 'function_id': function_id,
                            'role': role, 'hash': request_hash, 'attempts': 0}
        return turn_id

    def start_attempt(self, request_hash: str, retry: bool = False) -> int:
        self.wall()
        turn = self.active_turn
        if not turn or self.physical >= PHYSICAL_MAX:
            raise ValueError('physical start rejected')
        if turn['hash'] != request_hash:
            raise ValueError('retry request content changed')
        if retry:
            previous = self.attempts[-1] if self.attempts else None
            if (turn['attempts'] != 1 or not previous or
                    previous.get('retry_eligible') is not True or
                    self.retries >= RETRY_MAX):
                raise ValueError('retry rejected')
            self.retries += 1
        elif turn['attempts']:
            raise ValueError('second start requires retry classification')
        self.physical += 1
        turn['attempts'] += 1
        self.attempts.append({'turn_id': turn['id'], 'physical': self.physical,
                              'request_hash': request_hash, 'status': 'STARTED'})
        return self.physical

    def finish_attempt(self, *, completed: bool, error: str = '', accepted: bool = False,
                       visible: bool = False, response_saved: bool = False,
                       internal_retry: bool = False, request_id: str | None = None) -> bool:
        if not self.active_turn or not self.attempts or self.attempts[-1]['status'] != 'STARTED':
            raise ValueError('no active physical attempt')
        eligible = (not completed and accepted and not visible and not response_saved and
                    not internal_retry and 'stream disconnected before completion' in error and
                    self.active_turn['attempts'] == 1 and self.retries < RETRY_MAX and
                    self.physical < PHYSICAL_MAX)
        self.attempts[-1].update(status='COMPLETED' if completed else 'ERROR',
                                 error=error, request_id=request_id, accepted=accepted,
                                 visible=visible, response_saved=response_saved,
                                 internal_retry=internal_retry, retry_eligible=eligible)
        if completed:
            self.active_turn = None
        return eligible

    def abandon_turn(self, item_id: str, reason: str) -> None:
        if not self.active_turn:
            raise ValueError('no active turn')
        self.mark_pending(item_id, reason)
        self.active_turn = None

    def begin_fuzz(self, item_id: str, kind: str, requested: float) -> float:
        self.wall()
        if self.active_turn or self.active_fuzz or requested <= 0:
            raise ValueError('fuzz operation not eligible')
        if kind not in {'ASSERTION', 'FAILED_POV_SEED'}:
            raise ValueError('unapproved fuzz kind')
        if self.fuzz_overrun_policy not in {'LOCKOUT_V1', 'PHYSICAL_DEBIT_V1'}:
            raise ValueError('unapproved fuzz overrun policy')
        if self.fuzz_overrun_blocked:
            self.mark_pending(item_id, 'PENDING_FUZZ_OVERRUN_LOCKOUT')
            return 0.0
        cap = ASSERT_FUZZ_MAX if kind == 'ASSERTION' else SEED_FUZZ_MAX
        # The caller accepts integral seconds. A fractional remainder must not
        # become a zero-second Fuzzer invocation or consume an active slot.
        allowed = int(min(requested, cap, FUZZ_MAX - self.fuzz_budget_used()))
        if allowed < 1:
            self.mark_pending(item_id, 'PENDING_FUZZ_BUDGET')
            return 0.0
        self.active_fuzz = {'id': item_id, 'kind': kind, 'reserved': allowed}
        return allowed

    def fuzz_budget_used(self) -> float:
        """Use measured physical time only under the explicit future policy."""
        if self.fuzz_overrun_policy == 'PHYSICAL_DEBIT_V1':
            return self.fuzz_physical_actual
        if self.fuzz_overrun_policy == 'LOCKOUT_V1':
            return self.fuzz_actual
        raise ValueError('unapproved fuzz overrun policy')

    def finish_fuzz(self, actual: float, reason: str, *,
                    physical_actual: float | None = None) -> dict:
        job = self.active_fuzz
        physical = actual if physical_actual is None else physical_actual
        if (not job or not math.isfinite(actual) or not math.isfinite(physical)
                or actual < 0 or actual > job['reserved'] or physical < actual):
            raise ValueError('invalid measured fuzz time')
        self.fuzz_actual += actual
        self.fuzz_physical_actual += physical
        overrun = max(0.0, physical - job['reserved'])
        if overrun:
            self.fuzz_overrun_seconds += overrun
            if self.fuzz_overrun_policy == 'LOCKOUT_V1':
                self.fuzz_overrun_blocked = True
            self.fuzz_overrun_events.append({
                'id': job['id'], 'kind': job['kind'],
                'reserved_seconds': job['reserved'],
                'physical_actual_seconds': physical,
                'overrun_seconds': overrun})
            if self.fuzz_overrun_policy == 'LOCKOUT_V1':
                self.mark_pending(job['id'], 'FUZZ_OVERRAN_RESERVED_TIME')
        self.active_fuzz = None
        return {**job, 'actual': actual, 'physical_actual': physical,
                'overrun_seconds': overrun, 'reason': reason}

    def checkpoint(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + '.tmp')
        with temporary.open('w') as stream:
            json.dump(self.__dict__, stream, sort_keys=True, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)

    @classmethod
    def restore(cls, path: Path) -> 'Ledger':
        """Recover conservatively; never resend an in-flight model turn."""
        state = cls(**json.loads(path.read_text()))
        if (len(state.functions) > K or state.logical > LOGICAL_MAX or
                state.physical > PHYSICAL_MAX or state.retries > RETRY_MAX or
                state.fuzz_actual > FUZZ_MAX or
                not math.isfinite(state.fuzz_physical_actual) or
                not math.isfinite(state.fuzz_overrun_seconds) or
                state.fuzz_physical_actual < 0 or state.fuzz_overrun_seconds < 0 or
                type(state.fuzz_overrun_blocked) is not bool or
                state.fuzz_overrun_policy not in {'LOCKOUT_V1', 'PHYSICAL_DEBIT_V1'} or
                (state.fuzz_overrun_policy == 'LOCKOUT_V1' and
                 state.fuzz_overrun_seconds > 0 and not state.fuzz_overrun_blocked) or
                not isinstance(state.fuzz_overrun_events, list) or
                state.physical > state.logical + state.retries):
            raise ValueError('checkpoint budget counters invalid')
        if state.active_turn:
            item = state.active_turn['id']
            if state.attempts and state.attempts[-1]['status'] == 'STARTED':
                state.attempts[-1]['status'] = 'INTERRUPTED_UNCERTAIN_REMOTE_STATE'
            state.mark_pending(item, 'INCONCLUSIVE_INTERRUPTED_MODEL_TURN')
            state.active_turn = None
        if state.active_fuzz:
            job = state.active_fuzz
            state.fuzz_actual += job['reserved']
            if state.fuzz_overrun_policy == 'PHYSICAL_DEBIT_V1':
                # The physical duration is unknown after an interrupted job.
                # Charge the reservation and halt further Fuzzing for review.
                state.fuzz_physical_actual += job['reserved']
                state.fuzz_overrun_blocked = True
            state.mark_pending(job['id'], 'INTERRUPTED_FUZZ_FULL_RESERVATION_CHARGED')
            state.active_fuzz = None
        if state.fuzz_actual > FUZZ_MAX:
            raise ValueError('restored Fuzzing reservation exceeds combined cap')
        state.checkpoint(path)
        return state
