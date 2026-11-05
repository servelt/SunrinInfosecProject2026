from __future__ import annotations

import hashlib
import json
import shlex
import socket
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from harnesscreator.runtime.stateafl_campaign import (
    StateAFLCampaignSpec, _check_stateafl_host, _replay_one_crash,
    prepare_stateafl_campaign, probe_stateafl_seed_coverage,
    run_stateafl_campaign,
)
from harnesscreator.runtime.network_harness import NetworkHarnessConfig
from harnesscreator.runtime.stateafl_seeds import (
    snapshot_stateafl_seeds, stateafl_seed_fingerprints,
)
from harnesscreator.storage import ArtifactStore


def _spec(tmp_path: Path, *, tier: str = "diagnostic") -> StateAFLCampaignSpec:
    root = tmp_path / "original"
    seed = b"\x04\x00\x00\x00PING"
    source = root / f"research/stateafl/{tier}/seed.replay"
    source.parent.mkdir(parents=True)
    source.write_bytes(seed)
    manifest = root / "research/stateafl/manifest.json"
    manifest.write_text(json.dumps({
        "qualified_harness_claim": False,
        "rows": [{
            "seed_path": str(source.relative_to(root)),
            "channel": "tcp", "sha256": hashlib.sha256(seed).hexdigest(),
            "connection_prelude_hex": "",
        }],
    }))
    afl = tmp_path / "afl-fuzz"
    afl.write_text("#!/bin/sh\nexit 0\n")
    afl.chmod(0o755)
    return StateAFLCampaignSpec(
        run_dir=root, output_dir=tmp_path / "campaign", afl_fuzz=afl,
        server_command=("/bin/true", "-F"),
        transport="tcp", host="127.0.0.1", port=9010,
        seconds=2, seed_tier=tier, research_only=tier != "proven",
    )


def test_campaign_preserves_proof_tier_and_never_guesses_state_mode(tmp_path):
    spec = _spec(tmp_path)
    prepared = prepare_stateafl_campaign(spec)
    argv = prepared["argv"]
    assert prepared["status"] == "PREPARED_UNQUALIFIED"
    assert prepared["qualified_harness_claim"] is False
    assert prepared["vulnerability_claim"] is False
    assert argv[argv.index("-N") + 1] == "tcp://127.0.0.1/9010"
    assert "-E" not in argv
    assert "-D" not in argv
    assert argv[-3:] == ["--", str(Path("/bin/true").resolve()), "-F"]
    assert list((spec.output_dir / "inputs").glob("*.replay"))[0].read_bytes() == (
        b"\x04\x00\x00\x00PING"
    )


@pytest.mark.parametrize("transport", ["tcp", "udp"])
def test_instrumented_server_replays_original_response_marker(tmp_path, transport):
    server = tmp_path / "server.py"
    server.write_text(
        "import socket,sys\n"
        "kind,port=sys.argv[1],int(sys.argv[2])\n"
        "sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM if kind=='tcp' else socket.SOCK_DGRAM)\n"
        "sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
        "sock.bind(('127.0.0.1',port))\n"
        "if kind=='tcp':\n"
        " sock.listen(1)\n"
        " with sock.accept()[0] as peer:\n"
        "  data=peer.recv(1024)\n"
        "  peer.sendall(b'OK\\n' if data==b'PING' else b'ERR\\n')\n"
        "else:\n"
        " data,peer=sock.recvfrom(1024)\n"
        " sock.sendto(b'OK\\n' if data==b'PING' else b'ERR\\n',peer)\n"
        "sock.close()\n",
        encoding="utf-8",
    )
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if transport == "tcp" else socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    spec = replace(
        _spec(tmp_path),
        server_command=(sys.executable, str(server), transport, str(port)),
        transport=transport, port=port,
        seed_replay_timeout_ms=2000,
        seed_replay_budget_seconds=3,
        startup_delay_us=100000 if transport == "udp" else None,
    )
    manifest_path = spec.run_dir / "research/stateafl/manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["rows"][0]["channel"] = transport
    manifest["rows"][0]["original_responses_hex"] = [b"OK\n".hex()]
    manifest["rows"][0]["expected_success_markers_hex"] = [[b"OK\n".hex()]]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    prepared = prepare_stateafl_campaign(spec)
    replay = prepared["seed_replay_probe"]
    assert replay["status"] == "ORACLE_MARKERS_OBSERVED"
    assert replay["records"][0]["observed_responses_hex"] == [b"OK\n".hex()]
    assert replay["qualified_harness_claim"] is False
    assert replay["target_reach_claim"] is False


def test_response_probe_does_not_promote_a_seed_without_original_oracle(tmp_path):
    spec = replace(_spec(tmp_path), seed_replay_timeout_ms=200,
                   seed_replay_budget_seconds=1)
    prepared = prepare_stateafl_campaign(spec)
    assert prepared["seed_replay_probe"]["status"] == "INCONCLUSIVE"
    assert prepared["seed_replay_probe"]["records"][0]["status"] == "NOT_TESTABLE"


def test_response_probe_does_not_guess_missing_pre_request_observation(tmp_path):
    spec = replace(_spec(tmp_path), seed_replay_timeout_ms=200,
                   seed_replay_budget_seconds=1)
    manifest_path = spec.run_dir / "research/stateafl/manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    row = manifest["rows"][0]
    del row["connection_prelude_hex"]
    row["original_responses_hex"] = [b"OK\n".hex()]
    row["expected_success_markers_hex"] = [[b"OK\n".hex()]]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    replay = prepare_stateafl_campaign(spec)["seed_replay_probe"]
    assert replay["records"][0]["status"] == "NOT_TESTABLE"


def test_response_probe_reports_instrumented_behavior_mismatch(tmp_path):
    server = tmp_path / "changed.py"
    server.write_text(
        "import socket,sys\n"
        "sock=socket.socket(); sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
        "sock.bind(('127.0.0.1',int(sys.argv[1]))); sock.listen(1)\n"
        "with sock.accept()[0] as peer:\n"
        " peer.recv(1024); peer.sendall(b'ERR\\n')\n"
        "sock.close()\n",
        encoding="utf-8",
    )
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    spec = replace(
        _spec(tmp_path),
        server_command=(sys.executable, str(server), str(port)),
        port=port, seed_replay_timeout_ms=1000,
        seed_replay_budget_seconds=2,
    )
    manifest_path = spec.run_dir / "research/stateafl/manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["rows"][0]["original_responses_hex"] = [b"OK\n".hex()]
    manifest["rows"][0]["expected_success_markers_hex"] = [[b"OK\n".hex()]]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    replay = prepare_stateafl_campaign(spec)["seed_replay_probe"]
    assert replay["status"] == "INCONCLUSIVE"
    assert replay["records"][0]["status"] == "ORACLE_NOT_OBSERVED"
    assert replay["records"][0]["observed_responses_hex"] == [b"ERR\n".hex()]
    assert replay["qualified_harness_claim"] is False


@pytest.mark.parametrize("respond", [False, True])
def test_server_first_banner_is_not_mistaken_for_request_response(tmp_path, respond):
    server = tmp_path / "banner.py"
    server.write_text(
        "import socket,sys\n"
        "sock=socket.socket(); sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
        "sock.bind(('127.0.0.1',int(sys.argv[1]))); sock.listen(1)\n"
        "with sock.accept()[0] as peer:\n"
        " peer.sendall(b'200 Ready\\n')\n"
        " peer.recv(1024)\n"
        " if sys.argv[2]=='yes': peer.sendall(b'200 Command okay\\n')\n"
        "sock.close()\n",
        encoding="utf-8",
    )
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    spec = replace(
        _spec(tmp_path),
        server_command=(sys.executable, str(server), str(port), "yes" if respond else "no"),
        port=port, seed_replay_timeout_ms=1000,
        seed_replay_budget_seconds=2,
    )
    manifest_path = spec.run_dir / "research/stateafl/manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["rows"][0]["connection_prelude_hex"] = b"200 Ready\n".hex()
    manifest["rows"][0]["original_responses_hex"] = [b"200 Command okay\n".hex()]
    manifest["rows"][0]["expected_success_markers_hex"] = [[b"200".hex()]]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    replay = prepare_stateafl_campaign(spec)["seed_replay_probe"]
    assert replay["records"][0]["status"] == (
        "ORACLE_MARKERS_OBSERVED" if respond else "ORACLE_NOT_OBSERVED"
    )
    if not respond:
        assert replay["records"][0]["observed_responses_hex"] == [""]


def test_response_probe_stops_new_seeds_at_operator_total_budget(tmp_path):
    server = tmp_path / "silent.py"
    server.write_text(
        "import socket,sys,time\n"
        "sock=socket.socket(); sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
        "sock.bind(('127.0.0.1',int(sys.argv[1]))); sock.listen(1)\n"
        "with sock.accept()[0] as peer:\n"
        " peer.recv(1024); time.sleep(3)\n"
        "sock.close()\n",
        encoding="utf-8",
    )
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    spec = replace(
        _spec(tmp_path),
        server_command=(sys.executable, str(server), str(port)),
        port=port, seed_replay_timeout_ms=3000,
        seed_replay_budget_seconds=1,
    )
    manifest_path = spec.run_dir / "research/stateafl/manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    row = manifest["rows"][0]
    row["original_responses_hex"] = [b"OK\n".hex()]
    row["expected_success_markers_hex"] = [[b"OK\n".hex()]]
    second = b"\x04\x00\x00\x00PONG"
    second_path = spec.run_dir / "research/stateafl/diagnostic/second.replay"
    second_path.write_bytes(second)
    manifest["rows"].append({
        **row, "seed_path": str(second_path.relative_to(spec.run_dir)),
        "sha256": hashlib.sha256(second).hexdigest(),
    })
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    started = time.monotonic()
    replay = prepare_stateafl_campaign(spec)["seed_replay_probe"]
    elapsed = time.monotonic() - started
    assert replay["records"][1]["status"] == "BUDGET_EXHAUSTED"
    assert replay["budget_exhausted"] is True
    assert elapsed < 2.5


def test_network_response_probe_requires_explicit_total_budget(tmp_path):
    base = _spec(tmp_path)
    config_path = tmp_path / "network.json"
    data = {
        "afl_fuzz": str(base.afl_fuzz),
        "server_build_manifest": str(tmp_path / "build.json"),
        "server_command": ["/bin/true"],
        "transport": "tcp", "host": "127.0.0.1", "port": 9010,
        "seconds": 2, "seed_tier": "diagnostic", "research_only": True,
        "seed_replay_timeout_ms": 1000,
    }
    config_path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="seed_replay_budget_seconds together"):
        NetworkHarnessConfig.load(config_path)
    data["seed_replay_budget_seconds"] = 3
    config_path.write_text(json.dumps(data), encoding="utf-8")
    spec = NetworkHarnessConfig.load(config_path).spec(base.run_dir, tmp_path)
    assert spec.seed_replay_timeout_ms == 1000
    assert spec.seed_replay_budget_seconds == 3


def test_early_campaign_uses_frozen_seeds_after_live_manifest_changes(tmp_path):
    spec = _spec(tmp_path)
    snapshot = snapshot_stateafl_seeds(
        ArtifactStore(spec.run_dir), transport="tcp", tier="diagnostic",
    )
    assert snapshot is not None
    frozen_hashes = stateafl_seed_fingerprints(
        snapshot, transport="tcp", tier="diagnostic",
    )
    live = spec.run_dir / "research/stateafl/diagnostic/seed.replay"
    live.write_bytes(b"\x04\x00\x00\x00PONG")
    (spec.run_dir / "research/stateafl/manifest.json").write_text(json.dumps({
        "qualified_harness_claim": False, "rows": [],
    }))
    assert stateafl_seed_fingerprints(
        spec.run_dir, transport="tcp", tier="diagnostic",
    ) != frozen_hashes
    prepared = prepare_stateafl_campaign(replace(spec, run_dir=snapshot))
    assert prepared["seed_count"] == 1
    assert prepared["original_run"] == str(spec.run_dir.resolve())
    assert list((spec.output_dir / "inputs").glob("*.replay"))[0].read_bytes() == (
        b"\x04\x00\x00\x00PING"
    )


def test_network_campaign_stops_when_parent_analysis_fails(tmp_path):
    spec = _spec(tmp_path)
    afl = tmp_path / "afl-sleep"
    afl.write_text(
        "#!/usr/bin/env python3\nimport time\n"
        "time.sleep(30)\n", encoding="utf-8",
    )
    afl.chmod(0o755)
    stop = threading.Event()
    timer = threading.Timer(0.2, stop.set)
    timer.start()
    try:
        with patch("harnesscreator.runtime.stateafl_campaign._check_stateafl_host"):
            result = run_stateafl_campaign(
                replace(spec, afl_fuzz=afl, seconds=30), stop_event=stop,
            )
    finally:
        timer.cancel()
    assert result["status"] == "CANCELLED_PARENT_ANALYSIS"
    assert result["elapsed_seconds"] < 10
    assert result["qualified_harness_claim"] is False


def test_action_run_network_harness_uses_same_source_and_build(tmp_path):
    base = _spec(tmp_path)
    source_root = tmp_path / "project"
    source_root.mkdir()
    server = tmp_path / "server"
    server.write_bytes(b"instrumented fixture")
    server.chmod(0o755)
    build = tmp_path / "build.json"
    build.write_text(json.dumps({
        "source_root": str(source_root),
        "server_binary": str(server),
        "server_sha256": hashlib.sha256(server.read_bytes()).hexdigest(),
        "afl_coverage_object_detected": True,
        "afl_runtime_symbol_detected": True,
    }))
    config = tmp_path / "network.json"
    config.write_text(json.dumps({
        "afl_fuzz": str(base.afl_fuzz),
        "server_build_manifest": str(build),
        "server_command": [str(server), "--config", "fixture.conf"],
        "transport": "tcp", "host": "127.0.0.1", "port": 9010,
        "seconds": 2, "seed_tier": "diagnostic", "research_only": True,
        "replay_server_command": [sys.executable, "original-server.py"],
        "replay_timeout_ms": 2000,
    }))
    loaded = NetworkHarnessConfig.load(config)
    loaded.preflight(source_root)
    replay_spec = loaded.spec(base.run_dir, source_root)
    assert replay_spec.replay_server_command == (
        str(Path(sys.executable).resolve()), "original-server.py",
    )
    assert replay_spec.replay_timeout_ms == 2000
    result = loaded.prepare_or_run(base.run_dir, source_root)
    assert result["status"] == "PREPARED_UNQUALIFIED"
    assert result["seed_count"] == 1
    assert result["qualified_harness_claim"] is False
    assert result["server_build_evidence"]["server_sha256"] == (
        hashlib.sha256(server.read_bytes()).hexdigest()
    )
    assert (base.run_dir / "research/stateafl/network-harness/inputs").is_dir()


def test_network_harness_replay_config_requires_a_complete_runnable_command(tmp_path):
    base = _spec(tmp_path)
    config = tmp_path / "network.json"
    data = {
        "afl_fuzz": str(base.afl_fuzz),
        "server_build_manifest": str(tmp_path / "build.json"),
        "server_command": ["/bin/true"],
        "transport": "tcp", "host": "127.0.0.1", "port": 9010,
        "seconds": 2, "seed_tier": "diagnostic", "research_only": True,
        "replay_server_command": [str(tmp_path / "missing-server")],
    }
    config.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="both replay_server_command"):
        NetworkHarnessConfig.load(config)
    data["replay_timeout_ms"] = 2000
    config.write_text(json.dumps(data))
    with pytest.raises(FileNotFoundError):
        NetworkHarnessConfig.load(config).preflight(tmp_path)


def test_original_crash_replay_rejects_the_instrumented_executable(tmp_path):
    spec = _spec(tmp_path)
    with pytest.raises(ValueError, match="byte-identical"):
        prepare_stateafl_campaign(replace(
            spec, replay_server_command=spec.server_command,
            replay_timeout_ms=1000,
        ))


def test_network_harness_keeps_package_when_host_blocks_execution(tmp_path):
    base = _spec(tmp_path)
    source_root = tmp_path / "project"
    source_root.mkdir()
    server = tmp_path / "server"
    server.write_bytes(b"instrumented fixture")
    server.chmod(0o755)
    build = tmp_path / "build.json"
    build.write_text(json.dumps({
        "source_root": str(source_root),
        "server_binary": str(server),
        "server_sha256": hashlib.sha256(server.read_bytes()).hexdigest(),
        "afl_coverage_object_detected": True,
        "afl_runtime_symbol_detected": True,
    }))
    config = tmp_path / "network.json"
    config.write_text(json.dumps({
        "afl_fuzz": str(base.afl_fuzz),
        "server_build_manifest": str(build),
        "server_command": [str(server)],
        "transport": "tcp", "host": "127.0.0.1", "port": 9010,
        "seconds": 2, "seed_tier": "diagnostic", "research_only": True,
        "execute": True,
    }))
    with patch(
        "harnesscreator.runtime.network_harness.run_stateafl_campaign",
        side_effect=ValueError("host ASLR is enabled"),
    ):
        result = NetworkHarnessConfig.load(config).prepare_or_run(
            base.run_dir, source_root,
        )
    assert result["status"] == "PREPARED_EXECUTION_BLOCKED"
    assert result["seed_count"] == 1
    assert result["execution_blocker"] == "host ASLR is enabled"
    assert result["qualified_harness_claim"] is False


def test_network_harness_build_mode_binds_generated_server(tmp_path):
    base = _spec(tmp_path)
    source_root = tmp_path / "project"
    source_root.mkdir()
    config = tmp_path / "network.json"
    config.write_text(json.dumps({
        "afl_fuzz": str(base.afl_fuzz),
        "server_command": ["{server_binary}", "--config", "server.conf"],
        "transport": "tcp", "host": "127.0.0.1", "port": 9010,
        "seconds": 2, "seed_tier": "diagnostic", "research_only": True,
        "build": {
            "compiler": "/bin/true", "command": ["make", "server"],
            "server_relative_path": "server",
        },
    }))

    def fake_build(spec):
        binary = spec.output_dir / "source/server"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"instrumented fixture")
        binary.chmod(0o755)
        report = {
            "source_root": str(source_root),
            "server_binary": str(binary),
            "server_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "afl_coverage_object_detected": True,
            "afl_runtime_symbol_detected": True,
        }
        (spec.output_dir / "build.json").write_text(json.dumps(report))
        return report

    loaded = NetworkHarnessConfig.load(config)
    loaded.preflight(source_root)
    with patch("harnesscreator.runtime.network_harness.build_stateafl_server",
               side_effect=fake_build) as build_call:
        result = loaded.prepare_or_run(base.run_dir, source_root)
        second_seed = b"\x04\x00\x00\x00PONG"
        second_path = base.run_dir / "research/stateafl/diagnostic/second.replay"
        second_path.write_bytes(second_seed)
        manifest = base.run_dir / "research/stateafl/manifest.json"
        rows = json.loads(manifest.read_text())
        rows["rows"].append({
            "seed_path": str(second_path.relative_to(base.run_dir)),
            "channel": "tcp", "sha256": hashlib.sha256(second_seed).hexdigest(),
        })
        manifest.write_text(json.dumps(rows))
        refined = loaded.prepare_or_run(
            base.run_dir, source_root,
            reuse_build_manifest=base.run_dir / "research/stateafl/instrumented-build/build.json",
            campaign_name="network-harness-refined",
        )
    assert build_call.call_count == 1
    assert result["status"] == "PREPARED_UNQUALIFIED"
    assert result["seed_count"] == 1
    assert result["argv"][-3:] == [
        str(base.run_dir / "research/stateafl/instrumented-build/source/server"),
        "--config", "server.conf",
    ]
    assert result["qualified_harness_claim"] is False
    assert refined["status"] == "PREPARED_UNQUALIFIED"
    assert refined["seed_count"] == 2
    assert (base.run_dir / "research/stateafl/network-harness-refined/inputs").is_dir()


def test_network_harness_build_mode_skips_without_selected_seeds(tmp_path):
    base = _spec(tmp_path)
    source_root = tmp_path / "project"
    source_root.mkdir()
    config = tmp_path / "network.json"
    config.write_text(json.dumps({
        "afl_fuzz": str(base.afl_fuzz),
        "server_command": ["{server_binary}"],
        "transport": "udp", "host": "127.0.0.1", "port": 9010,
        "seconds": 2, "seed_tier": "diagnostic", "research_only": True,
        "build": {
            "compiler": "/bin/true", "command": ["make", "server"],
            "server_relative_path": "server",
        },
    }))
    with patch("harnesscreator.runtime.network_harness.build_stateafl_server") as build_call:
        result = NetworkHarnessConfig.load(config).prepare_or_run(
            base.run_dir, source_root,
        )
    assert result["status"] == "BLOCKED_UNQUALIFIED"
    assert "no selected network seeds" in result["reason"]
    build_call.assert_not_called()


def test_early_network_preparation_does_not_build_after_parent_failure(tmp_path):
    base = _spec(tmp_path)
    source_root = tmp_path / "project"
    source_root.mkdir()
    config = tmp_path / "network.json"
    config.write_text(json.dumps({
        "afl_fuzz": str(base.afl_fuzz),
        "server_command": ["{server_binary}"],
        "transport": "tcp", "host": "127.0.0.1", "port": 9010,
        "seconds": 30, "seed_tier": "diagnostic", "research_only": True,
        "build": {
            "compiler": "/bin/true", "command": ["make", "server"],
            "server_relative_path": "server",
        },
    }))
    stop = threading.Event()
    stop.set()
    with patch("harnesscreator.runtime.network_harness.build_stateafl_server") as build_call:
        result = NetworkHarnessConfig.load(config).prepare_or_run(
            base.run_dir, source_root, stop_event=stop,
        )
    assert result["status"] == "CANCELLED_BEFORE_PREPARATION"
    build_call.assert_not_called()


def test_action_run_network_harness_rejects_other_source(tmp_path):
    base = _spec(tmp_path)
    source_root = tmp_path / "project"
    source_root.mkdir()
    server = tmp_path / "server"
    server.write_bytes(b"instrumented fixture")
    server.chmod(0o755)
    build = tmp_path / "build.json"
    build.write_text(json.dumps({
        "source_root": str(tmp_path / "other-project"),
        "server_binary": str(server),
        "server_sha256": hashlib.sha256(server.read_bytes()).hexdigest(),
        "afl_coverage_object_detected": True,
        "afl_runtime_symbol_detected": True,
    }))
    config = tmp_path / "network.json"
    config.write_text(json.dumps({
        "afl_fuzz": str(base.afl_fuzz),
        "server_build_manifest": str(build),
        "server_command": [str(server)],
        "transport": "tcp", "host": "127.0.0.1", "port": 9010,
        "seconds": 2, "seed_tier": "diagnostic", "research_only": True,
    }))
    result = NetworkHarnessConfig.load(config).prepare_or_run(
        base.run_dir, source_root,
    )
    assert result["status"] == "BLOCKED_UNQUALIFIED"
    assert "different source checkout" in result["reason"]
    assert not (base.run_dir / "research/stateafl/network-harness/campaign.json").exists()
    with pytest.raises(ValueError, match="different source checkout"):
        NetworkHarnessConfig.load(config).preflight(source_root)


def test_diagnostic_seed_requires_research_only(tmp_path):
    spec = replace(_spec(tmp_path), research_only=False)
    with pytest.raises(ValueError, match="research-only"):
        prepare_stateafl_campaign(spec)
    assert not spec.output_dir.exists()


def test_campaign_binds_to_instrumented_build_digest(tmp_path):
    spec = _spec(tmp_path)
    server = tmp_path / "server"
    server.write_bytes(b"ELF fixture")
    server.chmod(0o755)
    build_manifest = tmp_path / "build.json"
    build_manifest.write_text(json.dumps({
        "server_binary": str(server),
        "server_sha256": hashlib.sha256(server.read_bytes()).hexdigest(),
        "afl_coverage_object_detected": True,
        "afl_runtime_symbol_detected": True,
    }))
    bound = replace(
        spec, server_command=(str(server),), server_build_manifest=build_manifest,
    )
    prepared = prepare_stateafl_campaign(bound)
    assert prepared["server_build_evidence"]["server_sha256"] == (
        hashlib.sha256(server.read_bytes()).hexdigest()
    )


def test_campaign_rejects_stale_or_uninstrumented_build(tmp_path):
    spec = _spec(tmp_path)
    server = tmp_path / "server"
    server.write_bytes(b"ELF fixture")
    server.chmod(0o755)
    build_manifest = tmp_path / "build.json"
    report = {
        "server_binary": str(server),
        "server_sha256": hashlib.sha256(server.read_bytes()).hexdigest(),
        "afl_coverage_object_detected": False,
        "afl_runtime_symbol_detected": True,
    }
    bound = replace(
        spec, server_command=(str(server),), server_build_manifest=build_manifest,
    )
    build_manifest.write_text(json.dumps(report))
    with pytest.raises(ValueError, match="AFL runtime and compiler-inserted coverage"):
        prepare_stateafl_campaign(bound)
    report["afl_coverage_object_detected"] = True
    report["afl_runtime_symbol_detected"] = False
    build_manifest.write_text(json.dumps(report))
    with pytest.raises(ValueError, match="AFL runtime and compiler-inserted coverage"):
        prepare_stateafl_campaign(bound)
    report["afl_runtime_symbol_detected"] = True
    build_manifest.write_text(json.dumps(report))
    server.write_bytes(b"changed")
    with pytest.raises(ValueError, match="changed since"):
        prepare_stateafl_campaign(bound)
    assert not spec.output_dir.exists()


def test_memory_limit_requires_explicit_choice(tmp_path):
    spec = replace(_spec(tmp_path), memory_limit_unlimited=True)
    assert prepare_stateafl_campaign(spec)["argv"][-5:-3] == ["-m", "none"]


def test_changed_or_malformed_seed_is_rejected_before_campaign(tmp_path):
    spec = _spec(tmp_path)
    seed = spec.run_dir / "research/stateafl/diagnostic/seed.replay"
    seed.write_bytes(b"\x04\x00\x00\x00PONG")
    with pytest.raises(ValueError, match="changed since the manifest"):
        prepare_stateafl_campaign(spec)
    manifest = spec.run_dir / "research/stateafl/manifest.json"
    raw = json.loads(manifest.read_text())
    raw["rows"][0]["sha256"] = hashlib.sha256(seed.read_bytes()).hexdigest()
    manifest.write_text(json.dumps(raw))
    seed.write_bytes(b"\x09\x00\x00\x00PONG")
    raw["rows"][0]["sha256"] = hashlib.sha256(seed.read_bytes()).hexdigest()
    manifest.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="invalid StateAFL message"):
        prepare_stateafl_campaign(spec)
    assert not spec.output_dir.exists()


def test_campaign_status_is_fuzzer_execution_not_harness_qualification(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "harnesscreator.runtime.stateafl_campaign._check_stateafl_host",
        lambda _environment: None,
    )
    spec = _spec(tmp_path, tier="proven")
    spec.afl_fuzz.write_text(
        "#!/bin/sh\n"
        "while [ \"$1\" != '-o' ]; do shift; done\n"
        "shift; mkdir -p \"$1\"\n"
        "printf 'execs_done : 7\\npaths_total : 2\\nbitmap_cvg : 0.31%%\\nunique_crashes : 27\\n' > \"$1/fuzzer_stats\"\n"
    )
    result = run_stateafl_campaign(
        spec, environment={"AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1"}
    )
    assert result["status"] == "FUZZING_OBSERVED_UNQUALIFIED"
    assert result["fuzzer_stats"]["execs_done"] == "7"
    assert result["reported_unique_crashes"] == "27"
    assert result["crash_handling_check_bypassed"] is True
    assert result["reported_crashes_verified"] is False
    assert result["qualified_harness_claim"] is False
    assert result["vulnerability_claim"] is False


def test_zero_coverage_probe_skips_long_fuzzing_without_claiming_harness_success(
    tmp_path, monkeypatch,
):
    monkeypatch.setattr(
        "harnesscreator.runtime.stateafl_campaign._check_stateafl_host",
        lambda _environment: None,
    )
    base = _spec(tmp_path, tier="proven")
    marker = tmp_path / "afl-was-started"
    base.afl_fuzz.write_text(f"#!/bin/sh\ntouch {marker}\n")
    showmap = tmp_path / "afl-showmap"
    showmap.write_text("#!/bin/sh\nexit 0\n")
    showmap.chmod(0o755)
    spec = replace(
        base, afl_showmap=showmap, coverage_probe_timeout_ms=1000,
        coverage_probe_budget_seconds=5,
    )
    monkeypatch.setattr(
        "harnesscreator.runtime.stateafl_campaign.probe_stateafl_seed_coverage",
        lambda _spec, _prepared: {
            "status": "NO_COVERAGE_OBSERVED", "seed_count": 1,
            "qualified_harness_claim": False, "target_reach_claim": False,
        },
    )
    result = run_stateafl_campaign(spec)
    assert result["status"] == "SEED_COVERAGE_NOT_OBSERVED"
    assert result["coverage_probe"]["status"] == "NO_COVERAGE_OBSERVED"
    assert result["qualified_harness_claim"] is False
    assert not marker.exists()
    assert json.loads((spec.output_dir / "campaign.json").read_text())["status"] == result["status"]


def test_coverage_probe_checks_later_seed_before_rejecting_campaign(
    tmp_path, monkeypatch,
):
    base = _spec(tmp_path, tier="proven")
    inputs = base.output_dir / "inputs"
    inputs.mkdir(parents=True)
    for name, request in (("0000-a.replay", b"A"), ("0001-b.replay", b"B")):
        (inputs / name).write_bytes(len(request).to_bytes(4, "little") + request)
    showmap = tmp_path / "afl-showmap"
    showmap.write_text("#!/bin/sh\nexit 0\n")
    showmap.chmod(0o755)
    spec = replace(
        base, afl_showmap=showmap, coverage_probe_timeout_ms=1000,
        coverage_probe_budget_seconds=5,
    )
    counts = iter((0, 0, 0, 0, 14, 14))

    def map_observation(_spec, _argv, path, _messages, *, deadline=None):
        count = next(counts)
        return {
            "map_entries": count, "map_sha256": str(count),
            "returncode": 0, "error": "",
            "map_path": str(path.relative_to(spec.output_dir)),
        }

    monkeypatch.setattr(
        "harnesscreator.runtime.stateafl_campaign._probe_one_map",
        map_observation,
    )
    result = probe_stateafl_seed_coverage(
        spec, {"argv": ["--", "/bin/true"]},
    )
    assert result["status"] == "INPUT_AFFECTED_COVERAGE"
    assert result["seeds_probed"] == 2
    assert [item["status"] for item in result["seed_results"]] == [
        "NO_COVERAGE_OBSERVED", "INPUT_AFFECTED_COVERAGE",
    ]


def test_zero_dry_run_range_without_completed_calibration_is_unknown(
    tmp_path, monkeypatch,
):
    monkeypatch.setattr(
        "harnesscreator.runtime.stateafl_campaign._check_stateafl_host",
        lambda _environment: None,
    )
    spec = _spec(tmp_path, tier="proven")
    spec.afl_fuzz.write_text(
        "#!/bin/sh\n"
        "while [ \"$1\" != '-o' ]; do shift; done\n"
        "shift; mkdir -p \"$1\"\n"
        "printf 'Bitmap range : 0 to 0 bits (average: 0.00 bits)\\n'\n"
        "printf 'execs_done : 37\\npaths_total : 2\\nbitmap_cvg : 0.00%%\\n' > \"$1/fuzzer_stats\"\n",
    )
    result = run_stateafl_campaign(spec)
    assert result["status"] == "EXECUTIONS_OBSERVED_COVERAGE_UNKNOWN"
    assert result["dry_run_max_bitmap_bits"] == 0
    assert result["calibrated_seed_observed"] is False
    assert result["qualified_harness_claim"] is False


def test_interrupted_first_calibration_does_not_refute_instrumentation(
    tmp_path, monkeypatch,
):
    monkeypatch.setattr(
        "harnesscreator.runtime.stateafl_campaign._check_stateafl_host",
        lambda _environment: None,
    )
    from dataclasses import replace
    spec = replace(_spec(tmp_path, tier="proven"), seconds=1)
    spec.afl_fuzz.write_text(
        "#!/bin/sh\n"
        "while [ \"$1\" != '-o' ]; do shift; done\n"
        "shift; mkdir -p \"$1\"\n"
        "printf 'execs_done : 37\\ncycles_done : 0\\nbitmap_cvg : 0.00%%\\n' > \"$1/fuzzer_stats\"\n"
        "printf 'Attempting dry run with id:000000\\n\\033[1;90mBitmap range : \\033[0m0 to 0 bits (average: 0.00 bits)\\n'\n"
        "sleep 2\n"
    )
    result = run_stateafl_campaign(spec)
    assert result["time_limit_reached"] is True
    assert result["calibrated_seed_observed"] is False
    assert result["status"] == "CALIBRATION_INTERRUPTED_COVERAGE_UNKNOWN"


def test_explicit_stateafl_instrumentation_rejection_is_distinct(
    tmp_path, monkeypatch,
):
    monkeypatch.setattr(
        "harnesscreator.runtime.stateafl_campaign._check_stateafl_host",
        lambda _environment: None,
    )
    spec = _spec(tmp_path, tier="proven")
    spec.afl_fuzz.write_text(
        "#!/bin/sh\n"
        "while [ \"$1\" != '-o' ]; do shift; done\n"
        "shift; mkdir -p \"$1\"\n"
        "printf 'No instrumentation detected\\n'\n"
    )
    result = run_stateafl_campaign(spec)
    assert result["status"] == "NO_INSTRUMENTATION_DETECTED"


def test_seed_dry_run_timeout_is_not_reported_as_missing_coverage(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "harnesscreator.runtime.stateafl_campaign._check_stateafl_host",
        lambda _environment: None,
    )
    spec = _spec(tmp_path, tier="proven")
    spec.afl_fuzz.write_text(
        "#!/bin/sh\n"
        "printf \"Test case 'id:000000' results in a timeout\\n\"\n"
        "printf 'Location : perform_dry_run(), afl-fuzz.c:4508\\n'\n"
        "exit 1\n"
    )
    result = run_stateafl_campaign(spec)
    assert result["status"] == "SEED_DRY_RUN_TIMEOUT"
    assert result["seed_dry_run_timeout"] is True
    assert result["qualified_harness_claim"] is False


def test_rounded_zero_percent_with_nonempty_bitmap_remains_observed(
    tmp_path, monkeypatch,
):
    monkeypatch.setattr(
        "harnesscreator.runtime.stateafl_campaign._check_stateafl_host",
        lambda _environment: None,
    )
    spec = _spec(tmp_path, tier="proven")
    spec.afl_fuzz.write_text(
        "#!/bin/sh\n"
        "while [ \"$1\" != '-o' ]; do shift; done\n"
        "shift; mkdir -p \"$1\"\n"
        "printf '    len = 33, map size = 1, exec speed = 42 us\\n'\n"
        "printf '\\033[1;90mBitmap range : \\033[0m1 to 1 bits (average: 1.00 bits)\\n'\n"
        "printf 'execs_done : 37\\nbitmap_cvg : 0.00%%\\n' > \"$1/fuzzer_stats\"\n",
    )
    result = run_stateafl_campaign(spec)
    assert result["status"] == "FUZZING_OBSERVED_UNQUALIFIED"
    assert result["dry_run_max_bitmap_bits"] == 1
    assert result["calibrated_seed_observed"] is True


def test_original_replay_observes_crash_only_after_request_delivery(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "harnesscreator.runtime.stateafl_campaign._check_stateafl_host",
        lambda _environment: None,
    )
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    server = tmp_path / "original_server.py"
    server.write_text(
        "import os, resource, signal, socket, sys\n"
        "resource.setrlimit(resource.RLIMIT_CORE, (0, 0))\n"
        "with socket.socket() as listener:\n"
        "    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        "    listener.bind(('127.0.0.1', int(sys.argv[1])))\n"
        "    listener.listen(1)\n"
        "    with listener.accept()[0] as peer:\n"
        "        request = peer.recv(1024)\n"
        "        if request == b'BOOM':\n"
        "            os.kill(os.getpid(), signal.SIGABRT)\n"
        "        print('ERROR: AddressSanitizer', file=sys.stderr)\n"
        "        peer.sendall(b'OK')\n",
        encoding="utf-8",
    )
    spec = replace(
        _spec(tmp_path), port=port,
        replay_server_command=(sys.executable, str(server), str(port)),
        replay_timeout_ms=2000,
    )
    boom = tmp_path / "boom.replay"
    clean = tmp_path / "clean.replay"
    boom.write_bytes(b"\x04\x00\x00\x00BOOM")
    clean.write_bytes(b"\x04\x00\x00\x00PING")
    spec.afl_fuzz.write_text(
        "#!/bin/sh\n"
        "while [ \"$1\" != '-o' ]; do shift; done\n"
        "shift\n"
        "mkdir -p \"$1/replayable-crashes\"\n"
        "printf 'StateAFL crash directory' > \"$1/replayable-crashes/README.txt\"\n"
        f"cp {shlex.quote(str(boom))} \"$1/replayable-crashes/boom\"\n"
        f"cp {shlex.quote(str(clean))} \"$1/replayable-crashes/clean\"\n"
        "printf 'execs_done : 2\\nbitmap_cvg : 0.31%%\\n' > \"$1/fuzzer_stats\"\n",
        encoding="utf-8",
    )
    result = run_stateafl_campaign(spec)
    assert result["status"] == "FUZZING_OBSERVED_UNQUALIFIED"
    by_name = {
        Path(item["artifact"]).name: item
        for item in result["original_crash_replays"]
    }
    assert set(by_name) == {"boom", "clean"}
    assert by_name["boom"]["status"] == "ORIGINAL_REPLAY_CRASH_OBSERVED"
    assert by_name["boom"]["original_returncode"] < 0
    assert by_name["boom"]["messages_sent"] == 1
    assert by_name["boom"]["request_caused_crash_proven"] is False
    assert by_name["boom"]["vulnerability_claim"] is False
    assert by_name["clean"]["status"] == "ORIGINAL_REPLAY_INCONCLUSIVE"
    assert by_name["clean"]["sanitizer_report_observed"] is True


def test_stateafl_host_preflight_uses_upstream_linux_abort_conditions(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "harnesscreator.runtime.stateafl_campaign.sys.platform", "linux"
    )
    (tmp_path / "randomize_va_space").write_text("2\n")
    (tmp_path / "core_pattern").write_text("core\n")
    with pytest.raises(ValueError, match="ASLR is enabled"):
        _check_stateafl_host({}, proc_sys=tmp_path)
    (tmp_path / "randomize_va_space").write_text("0\n")
    (tmp_path / "core_pattern").write_text("|/usr/bin/handler\n")
    with pytest.raises(ValueError, match="piped core_pattern"):
        _check_stateafl_host({}, proc_sys=tmp_path)
    _check_stateafl_host(
        {"AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1"}, proc_sys=tmp_path
    )
    (tmp_path / "core_pattern").write_text("core\n")
    _check_stateafl_host({}, proc_sys=tmp_path)


def test_original_startup_crash_is_not_a_replayed_request_crash(tmp_path):
    server = tmp_path / "abort_before_listen.py"
    server.write_text(
        "import os, resource, signal\n"
        "resource.setrlimit(resource.RLIMIT_CORE, (0, 0))\n"
        "os.kill(os.getpid(), signal.SIGABRT)\n",
        encoding="utf-8",
    )
    spec = replace(
        _spec(tmp_path), replay_server_command=(sys.executable, str(server)),
        replay_timeout_ms=500,
    )
    spec.output_dir.mkdir()
    artifact = spec.output_dir / "startup.replay"
    data = b"\x04\x00\x00\x00BOOM"
    artifact.write_bytes(data)
    result = _replay_one_crash(spec, artifact, data, 0.5)
    assert result["status"] == "ORIGINAL_REPLAY_INCONCLUSIVE"
    assert result["messages_sent"] == 0
    assert result["vulnerability_claim"] is False
