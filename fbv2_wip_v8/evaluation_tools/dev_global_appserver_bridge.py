"""Development-only App Server request guard backed by one global ledger.

The guard debits each physical ``turn/start`` before the wire request. It does
not replace the frozen Blind 2 runner or claim a complete Blind 3 contract.
"""

from __future__ import annotations

import asyncio
from contextlib import nullcontext
import hashlib
import json
import math
from pathlib import Path
import sys
from typing import Any, Awaitable, Callable

PRODUCT = Path('/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis')
sys.path.insert(0, str(PRODUCT / 'src'))

from vulnerabilityanalysis.llm import (  # noqa: E402
    AppServerError, CodexAppServerClient, LLMRequest, ModelAuditError,
    ModelToolEventError, ProviderSafetyRefusedError,
)

from dev_global_request_ledger import (  # noqa: E402
    DIRECTION_ROLE, FUNCTION_ROLES, DevelopmentBudgetExhausted,
    DevelopmentRequestLedger,
)
from dev_persistent_physical_fuzz_ledger import (  # noqa: E402
    PersistentPhysicalFuzzLedger,
)
from pinned_codex_delta_protocol import PinnedCodexDeltaGuard  # noqa: E402


def request_hash(request: LLMRequest) -> str:
    value = {'role': request.role, 'instructions': request.instructions,
             'payload': request.payload, 'schema': request.output_schema,
             'session_key': request.session_key, 'model': request.model,
             'effort': request.effort}
    return hashlib.sha256(json.dumps(value, ensure_ascii=False,
                         sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _note_cleanup(primary: BaseException, operation: str,
                  secondary: BaseException) -> None:
    primary.add_note(f'{operation} failed: {type(secondary).__name__}')


def _safe_error_text(error: BaseException) -> str:
    try:
        return str(error)
    except BaseException:
        return type(error).__name__


def artifact_hash(artifact: dict[str, Any]) -> str:
    """Normalize the product request artifact to the wire guard's identity."""
    if set(artifact) != {'role', 'instructions', 'payload', 'output_schema',
                         'model', 'reasoning'}:
        raise ValueError('product request artifact shape changed')
    value = {'role': artifact['role'], 'instructions': artifact['instructions'],
             'payload': artifact['payload'], 'schema': artifact['output_schema'],
             'session_key': None, 'model': artifact['model'],
             'effort': artifact['reasoning']}
    return hashlib.sha256(json.dumps(value, ensure_ascii=False,
                         sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def verify_product_request_order(ledger: DevelopmentRequestLedger,
                                 request_artifacts: list[Path],
                                 *, scope_id: str) -> None:
    """Match each product request artifact to its logical function turn."""
    turns = [row for row in ledger.turns if row['scope_id'] == scope_id]
    if len(turns) != len(request_artifacts):
        raise ValueError('product request count differs from ledger turns')
    for row, path in zip(turns, request_artifacts, strict=True):
        if not path.is_file() or path.is_symlink():
            raise ValueError('product request artifact missing or linked')
        artifact = json.loads(path.read_text(encoding='utf-8'))
        if artifact['role'] != row['role'] or artifact_hash(artifact) != row['hash']:
            raise ValueError('product request order or content differs from ledger')


def verify_model_event_order(ledger: DevelopmentRequestLedger,
                             event_log: Path) -> None:
    """Bind accepted App Server turn IDs to the ordered physical ledger rows.

    The product event log records only server events, not request bodies. The
    ledger binds each accepted server turn ID to a request SHA before response
    collection; this check confirms the completed event sequence matches it.
    """
    if not event_log.is_file() or event_log.is_symlink():
        raise ValueError('model event log missing or linked')
    # Only the harmless notifications consumed by the pinned product client
    # may appear here. Item type alone cannot identify command/fs/MCP events.
    delta_methods = frozenset({
        'item/agentMessage/delta', 'item/reasoning/textDelta',
        'item/reasoning/summaryTextDelta',
    })
    allowed_methods = frozenset({
        '<response>', 'account/rateLimits/updated',
        'thread/started', 'thread/status/changed',
        'thread/tokenUsage/updated', 'thread/settings/updated',
        'turn/started', 'turn/completed', 'turn/moderationMetadata',
        'model/safetyBuffering/updated',
        'item/started', 'item/updated', 'item/completed',
        'item/reasoning/summaryPartAdded', *delta_methods,
        'error',
        *CodexAppServerClient.PURE_STARTUP_NOTIFICATIONS,
    })
    attempts = [row for row in ledger.attempts
                if isinstance(row.get('app_server_turn_id'), str)]
    expected_ids = [row['app_server_turn_id'] for row in attempts]
    if len(expected_ids) != len(set(expected_ids)):
        raise ValueError('duplicate App Server turn identity')
    positions = {turn_id: index for index, turn_id in enumerate(expected_ids)}
    attempts_by_id = {row['app_server_turn_id']: row for row in attempts}
    completed: list[str] = []
    terminal_seen: set[str] = set()
    terminal_status: dict[str, str] = {}
    terminal_raw: dict[str, dict[str, Any]] = {}
    turn_threads: dict[str, str] = {}
    safety_events: dict[str, dict[str, Any]] = {}
    safety_summaries: set[str] = set()
    stale_pending: tuple[str, str] | None = None
    latest_position = -1
    for line in event_log.read_text(encoding='utf-8').splitlines():
        row = json.loads(line)
        if not isinstance(row, dict):
            raise ValueError('model event log contains a tool or server request')
        classification = row.get('classification')
        if stale_pending is not None and classification != 'STALE_OR_UNRELATED_TURN_EVENT':
            raise ValueError('stale turn summary missing after duplicate')
        if classification == 'STALE_OR_UNRELATED_TURN_EVENT':
            if (set(row) != {'method', 'classification', 'thread_id', 'turn_id'} or
                    row['method'] != 'turn/completed' or
                    stale_pending != (row['thread_id'], row['turn_id'])):
                raise ValueError('stale turn summary differs from bound duplicate')
            stale_pending = None
            continue
        if classification == 'PROVIDER_SAFETY_BUFFERING':
            expected_keys = {
                'classification', 'buffered', 'thread_id', 'turn_id',
                'role', 'requested_model', 'faster_models', 'reasons',
                'use_cases', 'buffer_to_turn_end_seconds',
                'buffer_to_stop_seconds', 'turn_status',
            }
            turn_id = row.get('turn_id')
            raw = safety_events.get(turn_id)
            attempt = attempts_by_id.get(turn_id)
            if (set(row) != expected_keys or not isinstance(turn_id, str) or
                    turn_id in safety_summaries or raw is None or attempt is None or
                    not isinstance(row.get('thread_id'), str) or
                    row['thread_id'] != raw['thread_id'] or
                    row['thread_id'] != turn_threads.get(turn_id) or
                    row.get('role') != attempt.get('role') or
                    row.get('requested_model') != raw['model'] or
                    type(row.get('buffered')) is not bool or
                    row['buffered'] != raw['buffered'] or
                    row.get('faster_models') != sorted(raw['faster_models']) or
                    row.get('reasons') != sorted(raw['reasons']) or
                    row.get('use_cases') != sorted(raw['use_cases']) or
                    row.get('turn_status') not in
                    ('completed', 'incomplete', 'provider_safety_refused')):
                raise ValueError('provider safety summary differs from raw turn')
            end = row['buffer_to_turn_end_seconds']
            stop = row['buffer_to_stop_seconds']
            if (row['buffered'] and (
                    row['turn_status'] == 'completed' and
                    (type(end) not in (int, float) or
                     not math.isfinite(end) or end < 0 or stop is not None) or
                    row['turn_status'] != 'completed' and
                    (type(stop) not in (int, float) or
                     not math.isfinite(stop) or stop < 0 or end is not None)) or
                    not row['buffered'] and (end is not None or stop is not None)):
                raise ValueError('provider safety duration differs from status')
            if (row['turn_status'] == 'completed' and
                    terminal_status.get(turn_id) != 'completed' or
                    row['turn_status'] == 'incomplete' and
                    attempt['status'] != 'ERROR' or
                    row['turn_status'] == 'provider_safety_refused'):
                raise ValueError('provider safety terminal status differs from ledger')
            safety_summaries.add(turn_id)
            continue
        if classification is not None:
            raise ValueError('unknown model event audit classification')
        if (row.get('method') not in allowed_methods or
                row.get('server_request') is not False or
                row.get('item_type') not in (None, 'userMessage',
                                              'agentMessage', 'reasoning') or
                not isinstance(row.get('thread_id'), str) or
                not isinstance(row.get('turn_id'), str)):
            raise ValueError('model event log contains a tool or server request')
        method = row['method']
        params = row.get('params')
        if method == '<response>':
            if (params is not None or row['thread_id'] or row['turn_id'] or
                    row['item_type'] is not None):
                raise ValueError('invalid App Server response audit row')
            continue
        if method in delta_methods:
            if (params is not None or row['item_type'] is not None or
                    not row['thread_id'] or not row['turn_id']):
                raise ValueError('invalid model delta audit row')
        else:
            # The product intentionally omits params for deltas. For all
            # other notifications, missing/truncated params cannot prove a
            # harmless event, so the audit fails closed.
            if not isinstance(params, dict):
                raise ValueError('model notification params unavailable')
            if CodexAppServerClient._unapproved_event_label(
                    {'method': method, 'params': params}) is not None:
                raise ValueError('model event log contains a tool or server request')
            if row['thread_id'] != str(params.get('threadId', '')):
                raise ValueError('model event thread identity changed')
            if method in ('item/started', 'item/updated', 'item/completed'):
                item = params.get('item')
                if (not isinstance(item, dict) or
                        row['item_type'] != item.get('type')):
                    raise ValueError('model event item identity changed')
            elif row['item_type'] is not None:
                raise ValueError('model event item identity changed')
            if method != 'turn/completed' and row['turn_id'] != str(
                    params.get('turnId', '')):
                raise ValueError('model event turn identity changed')
        turn_id = row['turn_id']
        if method == 'turn/started':
            turn = params.get('turn')
            if not isinstance(turn, dict) or not isinstance(turn.get('id'), str):
                raise ValueError('started App Server turn identity missing')
            turn_id = turn['id']
        elif method == 'turn/completed':
            turn = params.get('turn')
            if (not isinstance(turn, dict) or not isinstance(turn.get('id'), str)
                    or not row['thread_id'] or row['turn_id'] != turn['id']):
                raise ValueError('completed App Server turn identity changed')
        if method in ('turn/started', 'turn/completed') and 'items' in turn:
            items = turn['items']
            if (not isinstance(items, list) or any(
                    not isinstance(item, dict) or
                    item.get('type') not in
                    ('userMessage', 'agentMessage', 'reasoning')
                    for item in items)):
                raise ValueError('model event log contains a tool or server request')
        if turn_id:
            if turn_id not in positions:
                raise ValueError('model event turn order differs from ledger')
            if (turn_id in turn_threads and
                    turn_threads[turn_id] != row['thread_id']):
                raise ValueError('model event thread identity changed')
            turn_threads[turn_id] = row['thread_id']
            if method == 'turn/completed' and turn_id in terminal_seen:
                if params != terminal_raw.get(turn_id):
                    raise ValueError('stale turn completion changed')
                stale_pending = (row['thread_id'], turn_id)
            elif positions[turn_id] < latest_position:
                raise ValueError('model event turn order differs from ledger')
            latest_position = max(latest_position, positions[turn_id])
        if method == 'model/safetyBuffering/updated':
            if not turn_id or turn_id in safety_summaries:
                raise ValueError('late or unbound safety buffering notification')
            raw = safety_events.setdefault(turn_id, {
                'thread_id': row['thread_id'], 'model': params['model'],
                'buffered': False, 'faster_models': set(),
                'reasons': set(), 'use_cases': set(),
            })
            if (raw['thread_id'] != row['thread_id'] or
                    raw['model'] != params['model']):
                raise ValueError('safety buffering model or thread changed')
            raw['buffered'] |= params['showBufferingUi']
            raw['reasons'].update(params['reasons'])
            raw['use_cases'].update(params['useCases'])
            if params['fasterModel'] is not None:
                raw['faster_models'].add(params['fasterModel'])
        if method == 'error':
            attempt = attempts_by_id.get(turn_id)
            will_retry = params.get('willRetry', False)
            if (not row['thread_id'] or not turn_id or attempt is None or
                    attempt['status'] != 'ERROR' or
                    type(will_retry) is not bool or
                    bool(attempt.get('internal_retry')) != will_retry or
                    CodexAppServerClient._has_embedded_item(params)):
                raise ValueError('Provider error differs from ledger outcome')
        if method == 'turn/completed':
            if turn_id in terminal_seen:
                if stale_pending == (row['thread_id'], turn_id):
                    continue
                raise ValueError('duplicate or unbound turn completion')
            terminal_seen.add(turn_id)
            status = params['turn'].get('status')
            terminal_status[turn_id] = status
            terminal_raw[turn_id] = params
            attempt_status = attempts_by_id[turn_id]['status']
            if status == 'completed':
                if (attempt_status != 'COMPLETED' and
                        not (attempt_status == 'ERROR' and
                             attempts_by_id[turn_id].get(
                                 'server_terminal_status') == 'completed')):
                    raise ValueError('App Server success differs from ledger outcome')
                if attempt_status == 'COMPLETED':
                    completed.append(turn_id)
            elif not isinstance(status, str) or attempt_status != 'ERROR':
                raise ValueError('App Server failure differs from ledger outcome')
    completed_expected = [row['app_server_turn_id'] for row in attempts
                          if row['status'] == 'COMPLETED']
    completed_product_error_expected = [row['app_server_turn_id'] for row in attempts
        if row['status'] == 'ERROR' and
           row.get('server_terminal_status') == 'completed']
    if (completed != completed_expected or set(safety_events) != safety_summaries
            or any(terminal_status.get(turn_id) != 'completed'
                   for turn_id in completed_product_error_expected)
            or stale_pending is not None):
        raise ValueError('completed App Server turns differ from ledger')


class DevelopmentGlobalAppServer(PinnedCodexDeltaGuard, CodexAppServerClient):
    """Account Direction and function turns through one durable physical chain."""

    INTERLEAVED_ACCOUNTING_OWNER = 'APP_SERVER_TURN_START_V1'

    # The product's event acceptance checks deliberately name the base class
    # and retain their 4 KiB bound. Only its private recorder uses ``self``.
    # Actual official V2 Direction item params exceeded 113 KiB, so the
    # earlier 64 KiB limit made the strict offline audit reject a harmless
    # completed turn. Keep complete non-delta params in this private log up
    # to a bounded 1 MiB; larger events remain unproven and fail closed.
    STARTUP_NOTIFICATION_AUDIT_MAX_BYTES = 1 << 20

    def __init__(self, *, ledger: DevelopmentRequestLedger,
                 role_models: dict[str, dict[str, str]],
                 retry_route_check: Callable[[], Awaitable[None]] | None = None,
                 physical_ledger: PersistentPhysicalFuzzLedger | None = None,
                 **kwargs: Any):
        if (physical_ledger is not None and
                type(physical_ledger) is not PersistentPhysicalFuzzLedger):
            raise TypeError('physical model-start guard must use the durable ledger')
        super().__init__(**kwargs)
        self.ledger = ledger
        self.physical_ledger = physical_ledger
        self.role_models = role_models
        self.retry_route_check = retry_route_check
        self.scope_id: str | None = None
        self._request_hash: str | None = None
        self._accepted_turn_id: str | None = None
        self._visible_output = False
        self._internal_retry = False
        self._server_terminal_status: str | None = None

    def bind_scope(self, scope_id: str) -> None:
        if self.scope_id is not None or not scope_id:
            raise ValueError('development scope already bound or invalid')
        self.scope_id = scope_id

    def unbind_scope(self) -> None:
        self.scope_id = None

    def verify_interleaved_event_log(self) -> None:
        if self.event_log_path is None:
            raise ValueError('development App Server event log missing')
        verify_model_event_order(self.ledger, Path(self.event_log_path))

    async def _transport_request(self, method: str, params: dict, *, response_envelope=None) -> dict:
        """Override only in provider-free tests; production uses the real wire."""
        return await super()._request(method, params, response_envelope=response_envelope)

    async def _request(self, method: str, params: dict, *, response_envelope=None) -> dict:
        if method != 'turn/start':
            return await self._transport_request(method, params, response_envelope=response_envelope)
        active = self.ledger.active_turn
        if (active is None or self.scope_id != active['scope_id'] or
                self._request_hash != active['hash']):
            raise ValueError('turn/start outside the guarded logical turn')
        route = self.role_models[active['role']]
        if (params.get('model') != route['model'] or
                params.get('effort') != route['reasoning']):
            raise ValueError('development model route changed')
        # The durable model start and physical STOP use one admission order.
        # Release the physical lock before awaiting the provider response.
        guard = (self.physical_ledger.model_start_guard()
                 if self.physical_ledger is not None else nullcontext())
        with guard:
            self.ledger.start_attempt(self._request_hash,
                                      retry=active['attempts'] > 0)
        response = await self._transport_request(method, params, response_envelope=response_envelope)
        self._accepted_turn_id = (response.get('turn') or {}).get('id')
        if not self._accepted_turn_id:
            raise AppServerError('turn/start returned no turn id')
        self.ledger.attempts[-1]['app_server_turn_id'] = self._accepted_turn_id
        self.ledger.checkpoint()
        return response

    async def _read(self) -> dict:
        message = await super()._read()
        params = message.get('params') or {}
        if message.get('method') == 'error' and params.get('willRetry') is True:
            self._internal_retry = True
            if self._process and self._process.returncode is None:
                self._process.kill()
            raise AppServerError('internal retry announced; stopped')
        if params.get('turnId') == self._accepted_turn_id:
            item = params.get('item') or {}
            if (message.get('method') == 'item/agentMessage/delta' and
                    params.get('delta')) or (
                    message.get('method') == 'item/completed' and
                    item.get('type') == 'agentMessage' and item.get('text')):
                self._visible_output = True
        return message

    async def _collect(self, thread_id: str, turn_id: str, *,
                       deadline=None, response_limit_bytes=None, response_envelope=None) -> str:
        # turn/start can queue notifications before its response supplies the
        # accepted turn ID. Bind those deltas before the product collector.
        for message in self._notifications:
            self._guard_pinned_delta(
                message, expected_thread=thread_id, expected_turn=turn_id)
        # Notifications may arrive before turn/start responds. The base
        # collector ignores willRetry=True for the active turn, which would
        # allow an unaccounted physical Provider retry.
        for message in self._notifications:
            params = message.get('params') or {}
            if (message.get('method') == 'error' and
                    params.get('willRetry') is True and
                    params.get('threadId') == thread_id and
                    params.get('turnId') == turn_id):
                self._internal_retry = True
                if self._process and self._process.returncode is None:
                    self._process.kill()
                raise AppServerError('internal retry announced; stopped')
            item = params.get('item') or {}
            if params.get('turnId') == turn_id and (
                    message.get('method') == 'item/agentMessage/delta' and
                    params.get('delta') or
                    message.get('method') == 'item/completed' and
                    item.get('type') == 'agentMessage' and item.get('text')):
                self._visible_output = True
        result = await super()._collect(
            thread_id, turn_id, deadline=deadline,
            response_limit_bytes=response_limit_bytes, response_envelope=response_envelope)
        # Product parsing/schema checks happen after _collect. A server turn
        # can complete while the product request still ends as ERROR.
        self._server_terminal_status = 'completed'
        return result

    async def generate(self, request: LLMRequest) -> dict[str, Any]:
        if (self.scope_id is None or request.role not in self.role_models or
                request.role not in FUNCTION_ROLES | {DIRECTION_ROLE}):
            raise ValueError('unregistered development role or scope')
        if self.forbidden_tool_event:
            raise ModelToolEventError('FORBIDDEN_MODEL_TOOL_EVENT: provider session tainted')
        if self.audit_log_failed:
            raise ModelAuditError('MODEL_AUDIT_WRITE_FAILED: provider session tainted')
        if self.provider_safety_refused:
            raise ProviderSafetyRefusedError('PROVIDER_SAFETY_REFUSED: provider session blocked')
        route = self.role_models[request.role]
        if (request.model != route['model'] or
                request.effort != route['reasoning']):
            raise ValueError('development model or reasoning changed')
        digest = request_hash(request)
        self._request_hash = digest
        self.ledger.begin_turn(self.scope_id, request.role, digest)
        try:
            for ordinal in (1, 2):
                self._accepted_turn_id = None
                self._visible_output = False
                self._internal_retry = False
                self._server_terminal_status = None
                try:
                    result = await super().generate(request)
                except BaseException as exc:
                    if self.ledger.tainted:
                        raise
                    row = self.ledger.attempts[-1] if self.ledger.attempts else None
                    eligible = False
                    completed_server_product_error = bool(
                        self._server_terminal_status == 'completed' and
                        self._accepted_turn_id)
                    if (row is not None and self.ledger.active_turn is not None and
                            row['turn_id'] == self.ledger.active_turn['id'] and
                            row['status'] == 'STARTED'):
                        if self._server_terminal_status is not None:
                            row['server_terminal_status'] = self._server_terminal_status
                        if completed_server_product_error:
                            try:
                                if (request.raw_response_path is None or
                                        not request.raw_response_path.is_file()):
                                    raise ValueError('completed raw response missing')
                                raw = request.raw_response_path.read_bytes()
                                row['product_response_error_type'] = type(exc).__name__
                                row['product_response_error_sha256'] = (
                                    hashlib.sha256(raw).hexdigest())
                            except BaseException as receipt_error:
                                completed_server_product_error = False
                                _note_cleanup(exc, 'product_response_receipt',
                                              receipt_error)
                        try:
                            eligible = self.ledger.finish_attempt(
                                completed=False, error=_safe_error_text(exc),
                                accepted=bool(self._accepted_turn_id),
                                visible=self._visible_output,
                                response_saved=bool(request.raw_response_path and
                                                    request.raw_response_path.is_file()),
                                internal_retry=self._internal_retry)
                        except BaseException as cleanup_error:
                            _note_cleanup(exc, 'finish_attempt', cleanup_error)
                    if (eligible and ordinal == 1 and
                            type(exc) is AppServerError and
                            self.retry_route_check is not None):
                        try:
                            await self.retry_route_check()
                        except BaseException as route_exc:
                            if self.ledger.active_turn is not None:
                                try:
                                    self.ledger.abandon_turn(type(route_exc).__name__)
                                except BaseException as cleanup_error:
                                    _note_cleanup(route_exc, 'abandon_turn', cleanup_error)
                            raise
                        continue
                    if self.ledger.active_turn is not None:
                        try:
                            self.ledger.abandon_turn(
                                type(exc).__name__,
                                budget_exhausted=isinstance(exc, DevelopmentBudgetExhausted),
                                completed_server_product_error=(
                                    completed_server_product_error and row is not None and
                                    row['status'] == 'ERROR'))
                        except BaseException as cleanup_error:
                            _note_cleanup(exc, 'abandon_turn', cleanup_error)
                    raise
                try:
                    if self._server_terminal_status is not None:
                        self.ledger.attempts[-1]['server_terminal_status'] = (
                            self._server_terminal_status)
                    self.ledger.finish_attempt(completed=True,
                        accepted=bool(self._accepted_turn_id),
                        visible=self._visible_output,
                        response_saved=bool(request.raw_response_path and
                                            request.raw_response_path.is_file()))
                except BaseException as original:
                    try:
                        await self._await_cleanup(self.close())
                    except BaseException as cleanup_error:
                        _note_cleanup(original, 'close', cleanup_error)
                    raise
                return result
            raise RuntimeError('development retry loop exhausted')
        finally:
            self._request_hash = None
