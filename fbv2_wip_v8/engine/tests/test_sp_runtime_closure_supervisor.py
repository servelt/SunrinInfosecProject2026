from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from fuzzingbrain.fuzzer import seed_sandbox


ENGINE = Path(__file__).resolve().parents[1]
SUPERVISOR_PATH = ENGINE / "devtools/sp_runtime_closure_supervisor.py"
LAUNCHER = ENGINE / "devtools/sp_signed_live_pinned_launcher.py"
ENTRY = ENGINE / "devtools/original_public_live_entry.py"
LOADER = importlib.util.spec_from_file_location(
    "sp_runtime_closure_supervisor_tested", SUPERVISOR_PATH)
assert LOADER is not None and LOADER.loader is not None
supervisor = importlib.util.module_from_spec(LOADER)
LOADER.loader.exec_module(supervisor)


def test_complete_tree_hash_changes_for_content_inventory_and_link(tmp_path):
    root = tmp_path / "closure"
    root.mkdir()
    (root / "module.py").write_text("value = 1\n")
    first = supervisor.tree_sha256(root)
    (root / "module.py").write_text("value = 2\n")
    assert supervisor.tree_sha256(root) != first
    (root / "module.py").write_text("value = 1\n")
    (root / "extra.py").write_text("pass\n")
    assert supervisor.tree_sha256(root) != first
    (root / "extra.py").unlink()
    (root / "alias.py").symlink_to("module.py")
    linked = supervisor.tree_sha256(root)
    assert linked != first
    (root / "alias.py").unlink()
    assert supervisor.tree_sha256(root) == first


def test_tree_hash_rejects_escaping_link(tmp_path):
    root = tmp_path / "closure"
    root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("pass\n")
    (root / "escape.py").symlink_to(outside)
    with pytest.raises(ValueError, match="escapes root"):
        supervisor.tree_sha256(root)


def test_loader_environment_is_fail_closed(monkeypatch):
    allowed = {
        "HOME": "/home/dawne", "USER": "dawne", "LOGNAME": "dawne",
        "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin", "TERM": "dumb", "NO_COLOR": "1",
        "CODEX_HOME": "/home/dawne/.codex",
        "FBV2_SEED_DOCKER_CLI_SHA256":
            "84a8553077099a6a56b5ec36651dc17f5a1b89c26e33971e02906818c2f2626d",
        "FBV2_SEED_DOCKER_IMAGE_ID":
            "sha256:0514bc76712d64f8bb48adcb95b1ab0d88c69fee95d62fe4c18ee948bee9b1e1",
    }
    monkeypatch.setattr(os, "environ", allowed.copy())
    assert supervisor._clean_environment() == allowed
    os.environ["LD_PRELOAD"] = "/tmp/evil.so"
    with pytest.raises(ValueError, match="loader environment"):
        supervisor._clean_environment()
    del os.environ["LD_PRELOAD"]
    os.environ["UNREVIEWED_ENV"] = "1"
    with pytest.raises(ValueError, match="not exact"):
        supervisor._clean_environment()
    os.environ.clear()
    os.environ.update(allowed)
    os.environ["PATH"] = "/tmp/hostile:/usr/bin:/bin"
    with pytest.raises(ValueError, match="not exact"):
        supervisor._clean_environment()


def test_exact_environment_selects_the_pinned_system_docker(monkeypatch):
    expected_sha = supervisor._EXPECTED_ENVIRONMENT[
        "FBV2_SEED_DOCKER_CLI_SHA256"]
    assert hashlib.sha256(Path("/usr/bin/docker").read_bytes()).hexdigest() == expected_sha
    monkeypatch.setenv("PATH", supervisor._EXPECTED_ENVIRONMENT["PATH"])
    monkeypatch.setenv("FBV2_SEED_DOCKER_CLI_SHA256", expected_sha)
    image = supervisor._EXPECTED_ENVIRONMENT["FBV2_SEED_DOCKER_IMAGE_ID"]
    monkeypatch.setenv("FBV2_SEED_DOCKER_IMAGE_ID", image)
    monkeypatch.setattr(seed_sandbox, "_command_output", lambda *args, **kwargs:
                        SimpleNamespace(returncode=0, stdout=image + "\n", stderr=""))
    docker, selected_image = seed_sandbox._docker_binary_and_image()
    assert docker == "/usr/bin/docker"
    assert selected_image == image


@pytest.mark.parametrize("mutation", [
    ("forbidden_absent_paths", []),
    ("initial_sys_path", ["/tmp/attacker"]),
    ("sanitized_sys_path", ["/tmp/attacker"]),
])
def test_manifest_semantics_are_exact(tmp_path, mutation):
    manifest_path = tmp_path / "runtime-closure.json"
    manifest = supervisor._manifest_value(SUPERVISOR_PATH)
    manifest[mutation[0]] = mutation[1]
    manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n")
    wanted = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="manifest contract changed"):
        supervisor._verify_manifest(manifest_path, wanted)


def test_manifest_tree_root_and_exclusions_are_exact(tmp_path):
    manifest_path = tmp_path / "runtime-closure.json"
    manifest = supervisor._manifest_value(SUPERVISOR_PATH)
    manifest["trees"][0]["root"] = str(tmp_path)
    manifest["trees"][0]["excluded_top_level"] = ["everything"]
    manifest["trees"][0]["sha256"] = supervisor.tree_sha256(
        tmp_path, ("everything",))
    manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n")
    wanted = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="manifest contract changed"):
        supervisor._verify_manifest(manifest_path, wanted)


def test_signed_sp_launcher_rejects_direct_execution_without_supervisor(
        tmp_path):
    spec = tmp_path / "spec.json"
    approval = tmp_path / "approval.json"
    spec.write_text("{}\n")
    approval.write_text("{}\n")
    result = subprocess.run([
        sys.executable, "-I", "-S", "-B", str(LAUNCHER),
        "--entry", str(ENTRY), "--entry-sha256",
        hashlib.sha256(ENTRY.read_bytes()).hexdigest(), "--",
        "--spec", str(spec), "--spec-sha256",
        hashlib.sha256(spec.read_bytes()).hexdigest(),
        "--sp-live-approval", str(approval),
        "--sp-live-approval-sha256",
        hashlib.sha256(approval.read_bytes()).hexdigest(), "--check-only",
    ], capture_output=True, text=True, check=False, timeout=10)
    assert result.returncode != 0
    assert "runtime closure supervisor handoff is absent" in result.stderr


def test_actual_closure_supervises_sealed_entry_before_spec_admission(tmp_path):
    manifest = tmp_path / "runtime-closure.json"
    measured = subprocess.run([
        "/usr/bin/python3.12", "-I", "-S", "-B", str(SUPERVISOR_PATH),
        "measure", "--output", str(manifest),
    ], capture_output=True, text=True, check=True, timeout=60)
    assert json.loads(measured.stdout)["manifest"] == str(manifest)
    manifest_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
    supervisor_sha = hashlib.sha256(SUPERVISOR_PATH.read_bytes()).hexdigest()
    launcher_sha = hashlib.sha256(LAUNCHER.read_bytes()).hexdigest()
    entry_sha = hashlib.sha256(ENTRY.read_bytes()).hexdigest()
    spec = tmp_path / "invalid-control-spec.json"
    spec.write_text(json.dumps({
        "kind": "INVALID_PROVIDER_FREE_CONTROL",
        "sp_live_admission": {
            "live_entry_sha256": entry_sha,
            "pinned_launcher_path": str(LAUNCHER),
            "pinned_launcher_sha256": launcher_sha,
            "runtime_closure_manifest_path": str(manifest),
            "runtime_closure_manifest_sha256": manifest_sha,
            "runtime_closure_supervisor_path": str(SUPERVISOR_PATH),
            "runtime_closure_supervisor_sha256": supervisor_sha,
            "runtime_python_path":
                "/home/dawne/tools/miniconda3/bin/python3.13",
            "runtime_python_sha256":
                "061098801118fbed7d0bbc66ad5c4592f8f031ac2622377bdab3c24e85b6b20d",
        },
    }, sort_keys=True) + "\n")
    spec_sha = hashlib.sha256(spec.read_bytes()).hexdigest()
    environment = {
        "CODEX_HOME": "/home/dawne/.codex", "HOME": "/home/dawne",
        "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "LOGNAME": "dawne",
        "NO_COLOR": "1", "PATH": "/usr/bin:/bin", "TERM": "dumb",
        "USER": "dawne",
        "FBV2_SEED_DOCKER_CLI_SHA256":
            "84a8553077099a6a56b5ec36651dc17f5a1b89c26e33971e02906818c2f2626d",
        "FBV2_SEED_DOCKER_IMAGE_ID":
            "sha256:0514bc76712d64f8bb48adcb95b1ab0d88c69fee95d62fe4c18ee948bee9b1e1",
    }
    result = subprocess.run([
        "/usr/bin/python3.12", "-I", "-S", "-B", "-c",
        supervisor._BOOTSTRAP_SOURCE, str(SUPERVISOR_PATH), supervisor_sha,
        "exec", "--manifest", str(manifest), "--manifest-sha256",
        manifest_sha, "--spec", str(spec), "--spec-sha256", spec_sha,
        "--launcher", str(LAUNCHER), "--launcher-sha256", launcher_sha,
        "--entry", str(ENTRY), "--entry-sha256", entry_sha, "--",
        "--spec", str(spec), "--spec-sha256", spec_sha,
        "--sp-live-approval", str(tmp_path / "absent-approval.json"),
        "--sp-live-approval-sha256", "0" * 64, "--check-only",
    ], env=environment, capture_output=True, text=True, check=False, timeout=60)
    # A user namespace can map the host's root-owned interpreter to 65534.
    # The signed bootstrap must reject that ownership before it reaches the
    # deliberately invalid spec. Preserve both fail-closed outcomes.
    if os.stat("/usr/bin/python3.12").st_uid != 0:
        assert result.returncode == 1
        assert "runtime closure bootstrap Python is not root-owned" in result.stderr
        return
    assert result.returncode == 2
    row = json.loads(result.stdout)
    assert row["status"] == "INCOMPLETE_ADMISSION"
    assert row["reason"] == "only explicit public development is admitted"
