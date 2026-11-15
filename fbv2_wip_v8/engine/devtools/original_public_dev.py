"""Pinned, provider-free admission for the original FBv2 development path.

This command validates the existing md4c prebuilt adapter and the product's
official V2 qualification. ``scripted`` additionally runs the original
WorkerExecutor/POVFullscanStrategy queue handoff with scripted roles. Neither
mode calls a model, target, or fuzzer. A live launch is deliberately closed
in this preflight CLI. The separate ``original_public_live_entry.py`` requires
a fresh interpreter, explicit public-development authorization, source pins,
and bounded model/process accounts before it enters the original Worker.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

from fuzzingbrain.analyzer.prebuilt_adapter import prepare_prebuilt


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_V2 = "OFFICIAL_OSS_FUZZ_UPSTREAM_HARNESS_V2"


@dataclass(frozen=True)
class PinnedAdmission:
    summary: dict
    qualification: object
    prepared: dict


def _plain_pinned_bytes(path: Path, sha256: str, label: str) -> bytes:
    if (not isinstance(sha256, str) or not _SHA.fullmatch(sha256) or
            not path.is_absolute() or path.is_symlink() or
            path != path.resolve() or not path.is_file()):
        raise ValueError(f"{label} identity mismatch")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError
            chunks = []
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            after = os.fstat(fd)
        finally:
            os.close(fd)
        current = path.stat(follow_symlinks=False)
        raw = b"".join(chunks)
        identity = lambda row: (row.st_dev, row.st_ino, row.st_size,
                                row.st_mtime_ns, row.st_ctime_ns)
        if (identity(before) != identity(after) or
                (current.st_dev, current.st_ino) !=
                    (after.st_dev, after.st_ino) or
                hashlib.sha256(raw).hexdigest() != sha256):
            raise ValueError
        return raw
    except (OSError, ValueError):
        raise ValueError(f"{label} identity mismatch") from None


def _plain_pinned(path: Path, sha256: str, label: str) -> Path:
    _plain_pinned_bytes(path, sha256, label)
    return path


def admit_pinned(*, product_src: Path, product_issuer_sha256: str,
              contract_path: Path, contract_sha256: str, manifest_path: Path,
              manifest_sha256: str, task_path: Path, oss_fuzz_checkout: Path,
              upstream_checkout: Path) -> PinnedAdmission:
    """Reissue the product qualification and validate the prebuilt FBv2 input.

    The adapter writes only its derived prebuilt metadata/snapshots into the
    supplied task workspace. It never launches analysis or target processes.
    """
    issuer = _plain_pinned(product_src / "vulnerabilityanalysis" /
                           "official_harness.py", product_issuer_sha256,
                           "product qualification issuer")
    if (not product_src.is_absolute() or product_src.is_symlink() or
            product_src != product_src.resolve() or
            not issuer.is_relative_to(product_src)):
        raise ValueError("product source path is not canonical")
    contract_raw = _plain_pinned_bytes(
        contract_path, contract_sha256, "official V2 contract")
    manifest_raw = _plain_pinned_bytes(
        manifest_path, manifest_sha256, "prebuilt manifest")
    if (not task_path.is_absolute() or task_path.is_symlink() or
            task_path != task_path.resolve() or
            not (task_path / "repo").is_dir()):
        raise ValueError("prebuilt task workspace is unavailable")
    contract = json.loads(contract_raw)
    if contract.get("kind") != _V2:
        raise ValueError("official upstream Harness V2 contract required")
    manifest = json.loads(manifest_raw)
    if manifest.get("schema") != "fbv2-prebuilt-v1":
        raise ValueError("FBv2 prebuilt manifest required")
    # Import the product issuer only after its implementation bytes are pinned.
    cached = sys.modules.get("vulnerabilityanalysis.official_harness")
    if cached is not None and Path(getattr(cached, "__file__", "")).resolve() != issuer:
        raise ValueError("cached product qualification issuer is not the pinned implementation")
    if str(product_src) not in sys.path:
        sys.path.insert(0, str(product_src))
    # A long-lived worker may already have imported the package. Resolve the
    # exact pinned submodule, not a stale attribute cached on that package.
    official_harness = (cached if cached is not None else
                        importlib.import_module("vulnerabilityanalysis.official_harness"))
    if Path(getattr(official_harness, "__file__", "")).resolve() != issuer:
        raise ValueError("loaded product qualification issuer is not the pinned implementation")
    issue_official_pinned_qualification = official_harness.issue_official_pinned_qualification

    local = contract["local"]
    q = issue_official_pinned_qualification(
        contract_path=contract_path,
        approved_contract_sha256=contract_sha256,
        source_root=Path(contract["target"]["source_root"]),
        harness=Path(local["harness_file"]), binary=Path(local["binary"]),
        normal_seed=Path(local["normal_seed"]),
        oss_fuzz_checkout=oss_fuzz_checkout,
        upstream_checkout=upstream_checkout,
    )
    if (q is None or q.product_issued is not True or
            q.contract_kind != _V2 or
            q.binary_sha256 != manifest["asan_binary"]["sha256"] or
            q.upstream_revision != manifest["source_commit"]):
        raise ValueError("product-issued qualification does not match FBv2 prebuilt input")
    prepared = prepare_prebuilt(
        manifest_path, manifest_sha256, task_path,
        manifest["project_name"], ["address"])
    if (prepared["fuzzer_name"] != manifest["fuzzer_name"] or
            hashlib.sha256(Path(prepared["asan_binary"]).read_bytes()).hexdigest()
            != q.binary_sha256):
        raise ValueError("prepared FBv2 binary identity changed")
    _plain_pinned(issuer, product_issuer_sha256, "product qualification issuer")
    _plain_pinned(contract_path, contract_sha256, "official V2 contract")
    _plain_pinned(manifest_path, manifest_sha256, "prebuilt manifest")
    summary = {
        "status": "PINNED_PROVIDER_FREE",
        "contract_sha256": contract_sha256,
        "manifest_sha256": manifest_sha256,
        "manifest_path": str(manifest_path),
        "binary_sha256": q.binary_sha256,
        "project_name": manifest["project_name"],
        "fuzzer": prepared["fuzzer_name"],
        "function_count": prepared["function_count"],
        "reachable_count": prepared["reachable_count"],
        "product_issued": True,
        "model_calls": 0, "target_executions": 0, "fuzzer_seconds": 0,
    }
    return PinnedAdmission(summary, q, prepared)


def preflight(**kwargs) -> dict:
    """JSON-safe summary of a product-qualified, provider-free admission."""
    return admit_pinned(**kwargs).summary


def build_provider_free_executor(admission: PinnedAdmission, *, workspace: Path,
                                 task_path: Path, repos: object, task_id: str,
                                 llm_client_factory: object,
                                 original_global_bridge_factory: object,
                                 qualified_pov_runtime_binding: object = None,
                                 qualified_seed_generator: object = None,
                                 analysis_socket_path: str | None = None):
    """Construct the original Worker and strategy without executing a role.

    The official binary path is deliberate: WorkerExecutor's guarded bridge
    checks path identity against the product qualification, while the prebuilt
    adapter's snapshot is only for the AnalysisServer. The caller owns the
    shared model gate and the qualified Global campaign factory.
    """
    from fuzzingbrain.worker.executor import WorkerExecutor
    from fuzzingbrain.worker.strategies.pov_fullscan import POVFullscanStrategy

    q = admission.qualification
    prepared = admission.prepared
    if (admission.summary.get("product_issued") is not True or
            getattr(q, "product_issued", None) is not True or
            getattr(q, "contract_kind", None) != _V2 or
            not callable(llm_client_factory) or
            not callable(original_global_bridge_factory) or
            getattr(q, "binary_sha256", None) !=
            hashlib.sha256(Path(q.binary).read_bytes()).hexdigest() or
            getattr(q, "binary_sha256", None) !=
            hashlib.sha256(Path(prepared["asan_binary"]).read_bytes()).hexdigest()):
        raise ValueError("original Worker construction lacks qualified pinned dependencies")
    if (not workspace.is_absolute() or workspace.is_symlink() or
            workspace != workspace.resolve() or workspace.exists() or
            not workspace.parent.is_dir()):
        raise ValueError("original Worker workspace must be a new canonical directory")
    if (not task_path.is_absolute() or task_path.is_symlink() or
            task_path != task_path.resolve() or
            not (task_path / "repo").is_dir()):
        raise ValueError("original Worker task workspace changed")
    executor = WorkerExecutor(
        workspace_path=str(workspace), task_workspace_path=str(task_path),
        project_name=admission.summary["project_name"],
        fuzzer=prepared["fuzzer_name"], sanitizer="address", task_type="pov",
        repos=repos, task_id=task_id, fuzzer_binary_path=str(q.binary),
        llm_client_factory=llm_client_factory,
        require_original_global_bridge=True,
        original_global_bridge_factory=original_global_bridge_factory,
        qualified_pov_runtime_binding=qualified_pov_runtime_binding,
        qualified_seed_generator=qualified_seed_generator,
        analysis_socket_path=analysis_socket_path)
    strategy = executor._get_strategy()
    if not isinstance(strategy, POVFullscanStrategy):
        raise RuntimeError("original Worker did not select POVFullscanStrategy")
    return executor, strategy


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("preflight", "scripted", "live"),
                        required=True)
    for name in ("product-src", "contract-path", "manifest-path", "task-path",
                 "oss-fuzz-checkout", "upstream-checkout"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("product-issuer-sha256", "contract-sha256", "manifest-sha256"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    if args.mode == "live":
        parser.error("live is unavailable in the provider-free CLI; use the "
                     "fresh-interpreter public-development entry with explicit "
                     "source pins and physical caps")
    admission = admit_pinned(
        product_src=args.product_src,
        product_issuer_sha256=args.product_issuer_sha256,
        contract_path=args.contract_path, contract_sha256=args.contract_sha256,
        manifest_path=args.manifest_path, manifest_sha256=args.manifest_sha256,
        task_path=args.task_path, oss_fuzz_checkout=args.oss_fuzz_checkout,
        upstream_checkout=args.upstream_checkout)
    result = admission.summary
    if args.mode == "scripted":
        from bson import ObjectId
        import mongomock
        from fuzzingbrain.db.repository import RepositoryManager
        from devtools.campaign_model_gate import (
            CampaignModelGate, wrap_campaign_client_factory)

        with tempfile.TemporaryDirectory(prefix="fbv2-original-scripted-") as folder:
            scratch = Path(folder)
            gate = CampaignModelGate(scratch / "model-ledger.json",
                                     "provider-free-" + str(ObjectId()),
                                     physical_max=1, wall_seconds=30, create=True)

            def no_transport(*_args):
                raise RuntimeError("scripted Worker must not start model transport")

            client_factory = wrap_campaign_client_factory(gate, no_transport)
            repos = RepositoryManager(mongomock.MongoClient()["fbv2_scripted_launcher"])
            executor, strategy = build_provider_free_executor(
                admission, workspace=scratch / "worker", task_path=args.task_path,
                repos=repos, task_id=str(ObjectId()),
                llm_client_factory=client_factory,
                original_global_bridge_factory=no_transport)
            if (executor.fuzzer_binary_path != admission.qualification.binary or
                    strategy.executor is not executor or
                    gate.snapshot()["physical"] != 0):
                raise RuntimeError("scripted original Worker construction changed")
            result["original_worker_constructed"] = True
        # The test uses the original executor/strategy/pipeline and scripted
        # roles. It is a handoff check, not a qualified live execution.
        import pytest
        test_path = (Path(__file__).resolve().parent.parent / "tests" /
                     "test_original_global_bridge_vertical.py")
        if pytest.main(["-q", str(test_path)]) != 0:
            raise RuntimeError("original scripted queue handoff failed")
        result["scripted_original_queue_handoff"] = "PASS"
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
