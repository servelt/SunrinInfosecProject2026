"""Evaluator guard for the exact delta shapes in pinned Codex 0.164.0.

The product client intentionally omits delta text from its private event log.
Evaluator subclasses must check the complete wire object before accepting it;
only method, identity and a digest are written when a shape is rejected.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from vulnerabilityanalysis.llm import (  # noqa: E402
    AppServerError, ModelAuditError, _append_private_jsonl,
)


_STRING_FIELDS = frozenset({'threadId', 'turnId', 'itemId'})
_DELTA_FIELDS = {
    'item/agentMessage/delta': _STRING_FIELDS | {'delta'},
    'item/reasoning/textDelta': _STRING_FIELDS | {'delta', 'contentIndex'},
    'item/reasoning/summaryTextDelta': _STRING_FIELDS | {'delta', 'summaryIndex'},
    'item/reasoning/summaryPartAdded': _STRING_FIELDS | {'summaryIndex'},
}
_INDEX_FIELDS = frozenset({'contentIndex', 'summaryIndex'})
_MIN_I64 = -(1 << 63)
_MAX_I64 = (1 << 63) - 1


def pinned_delta_violation(message: dict[str, Any], *,
                           expected_thread: str | None = None,
                           expected_turn: str | None = None) -> str | None:
    """Return a stable violation label; unrelated methods have no contract here."""
    method = message.get('method')
    expected = _DELTA_FIELDS.get(method)
    if expected is None:
        return None
    params = message.get('params')
    if not isinstance(params, dict) or set(params) != expected:
        return 'UNAPPROVED_DELTA_SHAPE'
    if (any(type(params[key]) is not str or not params[key]
            for key in _STRING_FIELDS) or
            'delta' in expected and type(params['delta']) is not str or
            any(type(params[key]) is not int or
                not _MIN_I64 <= params[key] <= _MAX_I64
                for key in expected & _INDEX_FIELDS)):
        return 'UNAPPROVED_DELTA_SHAPE'
    if ((expected_thread is not None and params['threadId'] != expected_thread) or
            (expected_turn is not None and params['turnId'] != expected_turn)):
        return 'UNRELATED_DELTA_TURN'
    return None


class PinnedCodexDeltaGuard:
    """Mix in before CodexAppServerClient in each evaluator's MRO."""

    def _guard_pinned_delta(self, message: dict[str, Any], *,
                            expected_thread: str | None = None,
                            expected_turn: str | None = None) -> None:
        label = pinned_delta_violation(
            message, expected_thread=expected_thread,
            expected_turn=expected_turn)
        if label is None:
            return
        params = message.get('params')
        try:
            encoded = json.dumps(params, ensure_ascii=False, sort_keys=True,
                                 separators=(',', ':')).encode('utf-8')
            params_sha = hashlib.sha256(encoded).hexdigest()
        except (TypeError, ValueError):
            params_sha = None
        if self.event_log_path is not None:
            row = {
                'classification': 'UNAPPROVED_DELTA_SHAPE',
                'method': str(message.get('method', ''))[:160],
                'thread_id': (str(params.get('threadId', ''))[:80]
                              if isinstance(params, dict) else ''),
                'turn_id': (str(params.get('turnId', ''))[:80]
                            if isinstance(params, dict) else ''),
                'params_sha256': params_sha,
                'violation': label,
            }
            try:
                _append_private_jsonl(self.event_log_path, row)
            except (OSError, AppServerError) as exc:
                self.audit_log_failed = True
                raise ModelAuditError('MODEL_AUDIT_WRITE_FAILED: delta violation') from exc
        self._forbid_model_event(label)

    def _record_server_event(self, message: dict[str, Any]) -> None:
        # The base _read calls this before returning the wire message. Check
        # before it can record a malformed summaryPartAdded params object.
        self._guard_pinned_delta(message)
        super()._record_server_event(message)

    async def _read(self) -> dict[str, Any]:
        message = await super()._read()
        self._guard_pinned_delta(
            message, expected_thread=self._active_thread_id,
            expected_turn=self._active_turn_id)
        return message
