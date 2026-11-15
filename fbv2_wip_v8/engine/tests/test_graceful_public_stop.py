"""Provider-free checks for the public FullScan stop boundary."""

import signal
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from devtools.campaign_model_gate import CampaignModelGate, CampaignStopping
from devtools.original_public_live import graceful_public_stop_signals


def _bound(tmp_path):
    gate = CampaignModelGate(tmp_path / "ledger.json", "stop-test", None, None,
                             create=True)
    strategy = SimpleNamespace(stop_calls=0)

    def request_stop():
        strategy.stop_calls += 1

    strategy.request_graceful_stop = request_stop
    return SimpleNamespace(model_gate=gate, strategy=strategy,
                           executor=SimpleNamespace())


def test_first_sigint_closes_admission_and_requests_drain(tmp_path):
    bound = _bound(tmp_path)
    handlers = {}
    timers = []

    def install(number, handler):
        handlers[number] = handler
        return signal.SIG_DFL

    with patch("devtools.original_public_live.signal.getsignal",
               return_value=signal.SIG_DFL), patch(
            "devtools.original_public_live.signal.signal",
            side_effect=install), patch(
            "devtools.original_public_live.signal.getitimer",
            return_value=(0.0, 0.0)), patch(
            "devtools.original_public_live.signal.setitimer",
            side_effect=lambda *args: timers.append(args)):
        with graceful_public_stop_signals(bound, grace_seconds=12.0):
            handlers[signal.SIGINT](signal.SIGINT, None)
            assert bound.model_gate.admission_open is False
            assert bound.strategy.stop_calls == 1
            assert bound.executor.graceful_stop_requested is True
            assert timers[-1] == (signal.ITIMER_REAL, 12.0)
            with pytest.raises(CampaignStopping):
                bound.model_gate.reserve(
                    request_id="after-stop", role="sp", owner_id="owner",
                    request_sha256="a" * 64)


def test_second_stop_signal_forces_interrupt(tmp_path):
    bound = _bound(tmp_path)
    handlers = {}

    def install(number, handler):
        handlers[number] = handler
        return signal.SIG_DFL

    with patch("devtools.original_public_live.signal.getsignal",
               return_value=signal.SIG_DFL), patch(
            "devtools.original_public_live.signal.signal",
            side_effect=install), patch(
            "devtools.original_public_live.signal.getitimer",
            return_value=(0.0, 0.0)), patch(
            "devtools.original_public_live.signal.setitimer"):
        with graceful_public_stop_signals(bound, grace_seconds=12.0):
            handlers[signal.SIGTERM](signal.SIGTERM, None)
            with pytest.raises(KeyboardInterrupt):
                handlers[signal.SIGTERM](signal.SIGTERM, None)
