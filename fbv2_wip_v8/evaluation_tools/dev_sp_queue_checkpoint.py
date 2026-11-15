"""Development-only SP queue snapshot; deliberately incapable of resuming.

The snapshot binds every existing candidate and prior artifact to one immutable
run identity. It has no model transport, approval, or physical-attempt proof.
``resume_eligible`` is always false; a future resume API needs a separate
trusted ledger and approval transaction.
An opt-in completed QUEUE_FIRST_DEV snapshot records budget-pending IDs and
their final accumulated Context hash. It still marks physical attempts as
UNPROVEN and never permits a resumed model request.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
from typing import Any
from uuid import uuid4


KIND = "SP_QUEUE_CHECKPOINT_V1"
EXECUTION_FIELDS = frozenset({
    "run_command", "target_binary", "target_repository", "source_revision",
    "source_mode", "source_manifest",
    "runtime_sanitizers", "freeze_manifest", "official_qualification",
    "candidate_budget_policy",
})
CORE_FILES = (
    "run.json", "selection.json", "function_pool.json", "harness.json",
    "workers.json", "directions.json", "context.json",
    "sp/candidates.json", "sp/turn_budget.json",
)
MAX_JSON_BYTES = 64 * 1024 * 1024
SOURCE_SUFFIXES = frozenset({
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hxx",
    ".inc", ".inl", ".def", ".s", ".asm",
})
GIT = Path("/usr/bin/git")


def _check_no_symlink(path: Path) -> Path:
    path = path.absolute()
    current = path
    while True:
        if current.is_symlink():
            raise ValueError(f"linked checkpoint input: {current}")
        if current.parent == current:
            break
        current = current.parent
    return path


def _sha256(path: Path) -> str:
    _check_no_symlink(path)
    if not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
        raise ValueError(f"regular file required: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _json(path: Path) -> Any:
    _check_no_symlink(path)
    if not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
        raise ValueError(f"regular JSON file required: {path}")
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError(f"oversize JSON file: {path}")
    return json.loads(path.read_text(encoding="utf-8"),
                      object_pairs_hook=_unique_object)


def _within_run(source_run: Path, supplied: str) -> Path:
    if not isinstance(supplied, str) or not supplied:
        raise ValueError("artifact path missing")
    path = Path(supplied)
    path = path if path.is_absolute() else source_run / path
    _check_no_symlink(path)
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(source_run):
        raise ValueError("artifact escapes source run")
    return resolved


def _file_mode(path: Path) -> str:
    _check_no_symlink(path)
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
        raise ValueError("source file is not a local owned regular file")
    return "100755" if metadata.st_mode & 0o111 else "100644"


def _source_paths(root: Path) -> set[str]:
    """Find likely C/C++ source files missing from either source contract."""
    result: set[str] = set()
    for directory, dirs, files in os.walk(root, followlinks=False):
        base = Path(directory)
        _check_no_symlink(base)
        for name in list(dirs):
            if name == ".git" and base == root:
                _check_no_symlink(base / name)
                dirs.remove(name)
            else:
                _check_no_symlink(base / name)
        for name in files:
            path = base / name
            if path.suffix.lower() in SOURCE_SUFFIXES:
                _file_mode(path)
                result.add(path.relative_to(root).as_posix())
    return result


def _git_command(root: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    if not GIT.is_file():
        raise ValueError("fixed Git executable is unavailable")
    environment = {
        "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
        "HOME": "/nonexistent", "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    }
    try:
        result = subprocess.run([str(GIT), *args], cwd=root, env=environment,
                                capture_output=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("Git source inspection unavailable") from exc
    if len(result.stdout) > MAX_JSON_BYTES or len(result.stderr) > 4096:
        raise ValueError("Git source inspection output too large")
    return result


def _git_bytes(root: Path, *args: str) -> bytes:
    result = _git_command(root, *args)
    if result.returncode:
        raise ValueError("Git source inspection failed: " +
                         result.stderr.decode("utf-8", "replace").strip())
    return result.stdout


def _source_file_record(root: Path, relative: str, mode: str,
                        algorithm: str) -> tuple[str, str]:
    path = root / relative
    if not path.resolve(strict=True).is_relative_to(root):
        raise ValueError("tracked source path escapes source root")
    if _file_mode(path) != mode:
        raise ValueError("tracked source file mode changed")
    length = path.stat().st_size
    source_hash = hashlib.sha256()
    git_hash = hashlib.new(algorithm)
    git_hash.update(f"blob {length}\0".encode())
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            source_hash.update(chunk)
            git_hash.update(chunk)
    if path.stat().st_size != length:
        raise ValueError("source file changed while hashing")
    return source_hash.hexdigest(), git_hash.hexdigest()


def _relative_source_path(value: Any) -> str:
    if (not isinstance(value, str) or not value or "\\" in value or
            Path(value).is_absolute() or any(part in {"", ".", ".."}
                                             for part in value.split("/"))):
        raise ValueError("unsafe source manifest path")
    return value


def _git_source_identity(root: Path, revision: str) -> dict[str, Any]:
    top = _git_bytes(root, "rev-parse", "--show-toplevel").decode("utf-8").strip()
    if Path(top) != root:
        raise ValueError("Git top-level differs from target repository")
    head = _git_bytes(root, "rev-parse", "--verify", "HEAD").decode().strip()
    if head != revision:
        raise ValueError("Git HEAD differs from pinned source revision")
    tree = _git_bytes(root, "rev-parse", "HEAD^{tree}").decode().strip()
    algorithm = _git_bytes(root, "rev-parse", "--show-object-format=storage").decode().strip()
    if algorithm not in {"sha1", "sha256"}:
        raise ValueError("unsupported Git object format")
    raw = _git_bytes(root, "ls-tree", "-r", "-z", "HEAD")
    records: list[dict[str, str]] = []
    names: set[str] = set()
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        try:
            header, encoded_name = entry.split(b"\t", 1)
            mode_b, type_b, oid_b = header.split(b" ", 2)
            name = _relative_source_path(encoded_name.decode("utf-8"))
            mode, kind, oid = mode_b.decode(), type_b.decode(), oid_b.decode()
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError("invalid Git tree entry") from exc
        if (mode not in {"100644", "100755"} or kind != "blob" or
                len(oid) != (40 if algorithm == "sha1" else 64) or
                name in names):
            raise ValueError("symlink, submodule, or duplicate Git tree entry")
        names.add(name)
        source_sha, observed_oid = _source_file_record(root, name, mode, algorithm)
        if observed_oid != oid:
            raise ValueError("tracked file bytes differ from HEAD tree")
        records.append({"path": name, "sha256": source_sha,
                        "git_oid": oid, "mode": mode})
    index: dict[str, tuple[str, str]] = {}
    for entry in _git_bytes(root, "ls-files", "--stage", "-z").split(b"\0"):
        if not entry:
            continue
        try:
            header, encoded_name = entry.split(b"\t", 1)
            mode_b, oid_b, stage_b = header.split(b" ", 2)
            name = _relative_source_path(encoded_name.decode("utf-8"))
            mode, oid, stage = mode_b.decode(), oid_b.decode(), stage_b.decode()
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError("invalid Git index entry") from exc
        if stage != "0" or name in index:
            raise ValueError("unmerged or duplicate Git index entry")
        index[name] = (mode, oid)
    if index != {row["path"]: (row["mode"], row["git_oid"])
                 for row in records}:
        raise ValueError("Git index differs from HEAD tree")
    # Status is a useful corroborating receipt; the blob and mode checks
    # above remain authoritative because assume-unchanged may hide dirtiness.
    if _git_bytes(root, "status", "--porcelain=v1", "-z",
                  "--untracked-files=no"):
        raise ValueError("Git reports dirty tracked files")
    if not records:
        raise ValueError("Git source tree is empty")
    # Build systems may create untracked source-like files (for example CMake
    # compiler-ID probes). Pin their bytes for snapshot identity, but do not
    # treat them as committed or officially qualified build inputs.
    untracked = []
    for name in sorted(_source_paths(root) - names):
        path = root / name
        untracked.append({"path": name, "sha256": _sha256(path),
                          "mode": _file_mode(path)})
    return {"mode": "GIT_HEAD", "root": str(root), "head": head,
            "tree": tree, "object_format": algorithm,
            "git_executable_sha256": _sha256(GIT),
            "files": sorted(records, key=lambda row: row["path"]),
            "untracked_source_files": untracked}


def _manifest_source_identity(root: Path, supplied: str) -> dict[str, Any]:
    probe = _git_command(root, "rev-parse", "--show-toplevel")
    if probe.returncode == 0 or b"not a git repository" not in probe.stderr:
        raise ValueError("development source manifest cannot bypass Git checkout")
    if not isinstance(supplied, str) or not supplied:
        raise ValueError("development source manifest missing")
    path = _check_no_symlink(Path(supplied)).resolve(strict=True)
    manifest = _json(path)
    if (not isinstance(manifest, dict) or
            set(manifest) != {"kind", "root", "files"} or
            manifest["kind"] != "DEV_SOURCE_MANIFEST_V1" or
            manifest["root"] != str(root) or
            not isinstance(manifest["files"], list) or
            not manifest["files"]):
        raise ValueError("development source manifest contract invalid")
    records: list[dict[str, str]] = []
    names: set[str] = set()
    for row in manifest["files"]:
        if not isinstance(row, dict) or set(row) != {"path", "sha256", "mode"}:
            raise ValueError("development source row invalid")
        name = _relative_source_path(row["path"])
        expected_sha, mode = row["sha256"], row["mode"]
        if (name in names or mode not in {"100644", "100755"} or
                not isinstance(expected_sha, str) or len(expected_sha) != 64 or
                any(ch not in "0123456789abcdef" for ch in expected_sha)):
            raise ValueError("development source row identity invalid")
        names.add(name)
        source = root / name
        if not source.resolve(strict=True).is_relative_to(root) or \
                _file_mode(source) != mode or _sha256(source) != expected_sha:
            raise ValueError("development source bytes or mode differ from manifest")
        records.append({"path": name, "sha256": expected_sha, "mode": mode})
    if not _source_paths(root).issubset(names):
        raise ValueError("development source manifest omits a source-like file")
    return {"mode": "DEV_SOURCE_MANIFEST", "root": str(root),
            "manifest_path": str(path), "manifest_sha256": _sha256(path),
            "files": sorted(records, key=lambda row: row["path"])}


def _source_identity(root: Path, execution: dict[str, Any]) -> dict[str, Any]:
    _check_no_symlink(root)
    if not root.is_dir() or root.stat().st_uid != os.geteuid():
        raise ValueError("target repository ownership or directory invalid")
    mode = execution["source_mode"]
    if mode == "GIT_HEAD":
        if execution["source_manifest"] is not None:
            raise ValueError("Git mode cannot use a development source manifest")
        return _git_source_identity(root, execution["source_revision"])
    if mode == "DEV_SOURCE_MANIFEST":
        return _manifest_source_identity(root, execution["source_manifest"])
    raise ValueError("unknown source identity mode")


def _execution_identity(execution: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(execution, dict) or set(execution) != EXECUTION_FIELDS:
        raise ValueError("execution identity fields changed")
    command = execution["run_command"]
    sanitizers = execution["runtime_sanitizers"]
    if (not isinstance(command, list) or not command or
            any(not isinstance(arg, str) or not arg for arg in command) or
            not isinstance(sanitizers, list) or
            any(not isinstance(value, str) or not value for value in sanitizers) or
            not isinstance(execution["source_revision"], str) or
            not execution["source_revision"] or
            not isinstance(execution["candidate_budget_policy"], str) or
            not execution["candidate_budget_policy"]):
        raise ValueError("invalid execution identity")
    if not Path(command[0]).is_absolute() or "{input}" in command[0]:
        raise ValueError("runtime executable must be an absolute pinned file")
    command_executable = _check_no_symlink(Path(command[0])).resolve(strict=True)
    command_files = []
    for index, arg in enumerate(command):
        if "{input}" in arg or not Path(arg).is_absolute():
            continue
        path = _check_no_symlink(Path(arg))
        if path.is_file():
            command_files.append({"index": index, "path": str(path.resolve(strict=True)),
                                  "sha256": _sha256(path)})
    source_root = _check_no_symlink(Path(execution["target_repository"]))
    if not source_root.is_dir():
        raise ValueError("target repository missing")
    source_root = source_root.resolve(strict=True)
    source_identity = _source_identity(source_root, execution)
    files: dict[str, dict[str, str] | None] = {}
    for key in ("target_binary", "freeze_manifest", "official_qualification"):
        supplied = execution[key]
        if supplied is None and key == "official_qualification":
            files[key] = None
            continue
        if not isinstance(supplied, str) or not supplied:
            raise ValueError(f"{key} path missing")
        path = _check_no_symlink(Path(supplied)).resolve(strict=True)
        files[key] = {"path": str(path), "sha256": _sha256(path)}
    return {
        "run_command": command.copy(), "runtime_sanitizers": sanitizers.copy(),
        "command_executable": {"path": str(command_executable),
                               "sha256": _sha256(command_executable)},
        "command_file_arguments": command_files,
        "target_repository": str(source_root.resolve(strict=True)),
        "source_revision": execution["source_revision"],
        "source_identity": source_identity,
        "candidate_budget_policy": execution["candidate_budget_policy"],
        **files,
    }


def _run_files(source_run: Path) -> dict[str, str]:
    manifest: dict[str, str] = {}
    for directory, dirs, files in os.walk(source_run, followlinks=False):
        base = Path(directory)
        _check_no_symlink(base)
        for name in dirs:
            _check_no_symlink(base / name)
        for name in files:
            path = base / name
            relative = path.relative_to(source_run).as_posix()
            manifest[relative] = _sha256(path)
    return dict(sorted(manifest.items()))


def _completed_queue_state(source_run: Path, files: dict[str, str],
                           execution_identity: dict[str, Any],
                           selection: dict[str, Any],
                           candidate_ids: list[str],
                           candidates: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Describe budget-pending work without authorizing a model request."""
    if any(name not in files for name in
           ("scan.json", "sp/queue_first_dev.json", "source_span.json")):
        raise ValueError("completed Queue-first run lacks final evidence")
    if execution_identity["official_qualification"] is None:
        raise ValueError("completed Queue-first snapshot requires qualification file")
    scan = _json(source_run / "scan.json")
    queue = _json(source_run / "sp/queue_first_dev.json")
    span = _json(source_run / "source_span.json")
    if (not isinstance(scan, dict) or not isinstance(queue, dict) or
            not isinstance(span, dict)):
        raise ValueError("completed Queue-first evidence is malformed")
    source_file = span.get("source_file")
    if (span.get("function_id") != selection.get("function_id") or
            not isinstance(source_file, str) or not Path(source_file).is_absolute() or
            span.get("catalog_source_status") != "MATCHED_CURRENT_CHECKOUT"):
        raise ValueError("selected function SourceSpan identity differs")
    source_root = Path(execution_identity["target_repository"])
    source_path = _check_no_symlink(Path(source_file)).resolve(strict=True)
    if not source_path.is_relative_to(source_root):
        raise ValueError("selected SourceSpan escapes pinned source")
    source_name = source_path.relative_to(source_root).as_posix()
    source_rows = (execution_identity["source_identity"]["files"] +
                   execution_identity["source_identity"].get("untracked_source_files", []))
    source_hashes = {row["path"]: row["sha256"] for row in source_rows}
    if source_hashes.get(source_name) != span.get("source_file_sha256"):
        raise ValueError("selected SourceSpan file differs from pinned source")
    start_line, end_line = span.get("start_line"), span.get("end_line")
    line_count = 0
    last_byte = b""
    with source_path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            line_count += chunk.count(b"\n")
            last_byte = chunk[-1:]
    line_count += int(bool(last_byte and last_byte != b"\n"))
    if (type(start_line) is not int or type(end_line) is not int or
            start_line < 1 or end_line < start_line or end_line > line_count):
        raise ValueError("selected SourceSpan line range differs from pinned source")
    ranked = queue.get("ranked_candidate_ids")
    status = queue.get("status")
    if (execution_identity["candidate_budget_policy"] != "QUEUE_FIRST_DEV" or
            scan.get("candidate_budget_policy") != "QUEUE_FIRST_DEV" or
            queue.get("policy") != "QUEUE_FIRST_DEV" or
            queue.get("scope") != "SP_QUEUE_ONLY" or
            queue.get("run_state") != "COMPLETED" or
            queue.get("serial_only") is not True or
            queue.get("auto_resume") is not False or
            not isinstance(ranked, list) or
            any(not isinstance(item, str) for item in ranked) or
            not isinstance(status, dict) or
            len(ranked) != len(set(ranked)) or set(ranked) != set(candidate_ids) or
            set(status) != set(candidate_ids) or
            scan.get("selected_function_id") != selection.get("function_id") or
            scan.get("queued_sp_ids") != ranked or
            scan.get("sp_queue_status") != status or
            scan.get("sp_queue_artifact") !=
                str(source_run / "sp/queue_first_dev.json") or
            scan.get("target_repository") != execution_identity["target_repository"]):
        raise ValueError("completed Queue-first identity or status differs")
    pending_verify = [item for item in ranked if status[item] == "PENDING_VERIFY_BUDGET"]
    pending_pov = [item for item in ranked if status[item] == "PENDING_POV_BUDGET"]
    pending_any = [item for item in ranked if status[item] in
                   {"PENDING_VERIFY_BUDGET", "PENDING_POV_BUDGET",
                    "PENDING_NEW_EVIDENCE"}]
    if (queue.get("pending_verify_ids") != pending_verify or
            queue.get("pending_pov_ids") != pending_pov or
            scan.get("pending_sp_ids") != pending_any):
        raise ValueError("completed Queue-first pending lists differ")
    verification_hashes = scan.get("verification_artifact_sha256")
    verifier_statuses = scan.get("sp_verification_status")
    if not isinstance(verification_hashes, dict) or not isinstance(verifier_statuses, dict):
        raise ValueError("Verifier hash index is missing")
    expected_verification = {name.removeprefix("verification/").removesuffix(".json"): value
                             for name, value in files.items()
                             if name.startswith("verification/") and name.endswith(".json")}
    if verification_hashes != expected_verification:
        raise ValueError("Verifier hash index differs from files")
    for item in pending_verify:
        if (item in expected_verification or
                verifier_statuses.get(item) != "PENDING_VERIFY_BUDGET"):
            raise ValueError("pending Verifier has a completed artifact")
        candidate = candidates[candidate_ids.index(item)]
        if candidate.get("status") in {"REFUTED", "VERIFIED"}:
            raise ValueError("pending Verifier contradicts candidate")
    for item in pending_pov:
        if (item not in expected_verification or
                verifier_statuses.get(item) != "VERIFIER_EXECUTED"):
            raise ValueError("pending PoV has no completed Verifier")
        candidate = candidates[candidate_ids.index(item)]
        verification = _json(source_run / "verification" / f"{item}.json")
        if (candidate.get("status") in {"REFUTED", "VERIFIED"} or
                not isinstance(verification, dict) or
                verification.get("verdict") == "REFUTED" or
                verification.get("recommended_next_action") in
                    {"REFUTE", "REANALYZE"}):
            raise ValueError("pending PoV contradicts Verifier or candidate")
    work: list[dict[str, str]] = []
    for item in ranked:
        stage = status[item]
        if stage in {"IN_FLIGHT_VERIFY", "IN_FLIGHT_POV"}:
            raise ValueError("in-flight model request has uncertain remote state")
        if stage not in {"PENDING_VERIFY_BUDGET", "PENDING_POV_BUDGET"}:
            continue
        key = hashlib.sha256(json.dumps({
            "run_id": source_run.name, "function_id": selection["function_id"],
            "sp_id": item, "stage": stage,
            "context_sha256": files["context.json"],
        }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        work.append({"work_id": key, "sp_id": item, "stage": stage,
                     "context_sha256": files["context.json"],
                     "physical_attempt_state": "UNPROVEN"})
    return work


def _snapshot(source_run: Path, execution: dict[str, Any], *,
              completed_queue_first_dev: bool = False) -> dict[str, Any]:
    source_run = _check_no_symlink(source_run).resolve(strict=True)
    if not source_run.is_dir() or ((source_run / "scan.json").exists() and
                                   not completed_queue_first_dev):
        raise ValueError("partial source run required; completed scan cannot be snapshotted")
    files = _run_files(source_run)
    if any(name not in files for name in CORE_FILES):
        raise ValueError("partial source run missing core evidence")
    identity = _execution_identity(execution)
    run = _json(source_run / "run.json")
    selection = _json(source_run / "selection.json")
    pool = _json(source_run / "function_pool.json")
    harness = _json(source_run / "harness.json")
    directions = _json(source_run / "directions.json")
    workers = _json(source_run / "workers.json")
    budget = _json(source_run / "sp" / "turn_budget.json")
    candidates = _json(source_run / "sp" / "candidates.json")
    if (not isinstance(run, dict) or run.get("run_id") != source_run.name or
            not isinstance(selection, dict) or not isinstance(pool, list) or
            not isinstance(harness, dict) or not isinstance(directions, list) or
            not isinstance(workers, list) or not isinstance(budget, dict) or
            not isinstance(candidates, list) or
            budget.get("candidate_budget_policy") != identity["candidate_budget_policy"] or
            run.get("harness_id") != harness.get("harness_id") or
            not any(isinstance(row, dict) and
                    row.get("function_id") == selection.get("function_id") and
                    row.get("direction_id") == selection.get("direction_id")
                    for row in pool) or
            not any(isinstance(row, dict) and
                    row.get("direction_id") == selection.get("direction_id") and
                    any(isinstance(worker, dict) and
                        worker.get("worker_id") == row.get("worker_id") and
                        worker.get("harness_id") == run.get("harness_id")
                        for worker in workers) for row in directions)):
        raise ValueError("source run identity is inconsistent")
    if not candidates:
        raise ValueError("candidate queue is empty")
    ids = [row.get("sp_id") for row in candidates if isinstance(row, dict)]
    if (len(ids) != len(candidates) or
            any(not isinstance(item, str) or not item or "/" in item or
                "\\" in item or item in {".", ".."} for item in ids) or
            any(not isinstance(row.get("status"), str) or not row["status"]
                for row in candidates) or
            len(set(ids)) != len(ids)):
        raise ValueError("candidate IDs missing, duplicated, or unsafe")
    if completed_queue_first_dev and "scan.json" not in files:
        raise ValueError("completed Queue-first run requires scan.json")
    pending_budget_work = (_completed_queue_state(source_run, files, identity,
                                                   selection, ids, candidates)
                           if completed_queue_first_dev else [])
    id_set = set(ids)
    for name in files:
        if name.startswith("verification/") and name.endswith(".json"):
            verification_row = _json(source_run / name)
            if (Path(name).stem not in id_set or
                    not isinstance(verification_row, dict) or
                    verification_row.get("sp_id") != Path(name).stem):
                raise ValueError("Verifier artifact does not match candidate")
    pov_rows = (_json(source_run / "poc" / "pocs.json")
                if "poc/pocs.json" in files else [])
    if not isinstance(pov_rows, list):
        raise ValueError("PoV rows are not a list")
    pov_ids: set[str] = set()
    by_candidate: dict[str, list[dict[str, Any]]] = {item: [] for item in ids}
    for row in pov_rows:
        if not isinstance(row, dict):
            raise ValueError("PoV row is invalid")
        sp_id, poc_id = row.get("sp_id"), row.get("poc_id")
        if (not isinstance(sp_id, str) or sp_id not in id_set or
                not isinstance(poc_id, str) or not poc_id or
                poc_id in pov_ids or f"verification/{sp_id}.json" not in files or
                not isinstance(row.get("status"), str) or not row["status"]):
            raise ValueError("orphan or duplicate PoV")
        pov_ids.add(poc_id)
        recorded: dict[str, Any] = {"poc_id": poc_id, "status": row.get("status")}
        for key, result_key in (("generated_input", "input"),
                                ("execution_log", "runtime")):
            value = row.get(key)
            if value is not None:
                path = _within_run(source_run, value)
                rel = path.relative_to(source_run).as_posix()
                if rel not in files:
                    raise ValueError("PoV artifact omitted from run manifest")
                recorded[result_key] = {"relative_path": rel,
                                        "sha256": files[rel]}
            else:
                recorded[result_key] = None
        by_candidate[sp_id].append(recorded)
    # Product Scan writes pocs.json after the candidate loop. A preceding PoV
    # may have files when a later candidate is interrupted. Without the
    # product index, their filenames do not prove candidate disposition.
    unindexed_pov = {Path(name).parts[1] for name in files
                     if len(Path(name).parts) >= 3 and
                     Path(name).parts[0] == "poc" and
                     Path(name).parts[1] not in pov_ids}
    unindexed_runtime = {Path(name).stem for name in files
                         if name.startswith("runtime/poc-") and
                         name.endswith(".json") and
                         Path(name).stem not in pov_ids}
    if unindexed_pov or unindexed_runtime:
        raise ValueError("prior PoV artifacts lack a product candidate receipt")
    items: list[dict[str, Any]] = []
    for ordinal, candidate in enumerate(candidates):
        sp_id = ids[ordinal]
        encoded = json.dumps(candidate, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False).encode()
        verification = f"verification/{sp_id}.json"
        povs = by_candidate[sp_id]
        items.append({
            "sp_id": sp_id, "ordinal": ordinal,
            "candidate_status": candidate.get("status"),
            "candidate_row_sha256": hashlib.sha256(encoded).hexdigest(),
            "stage": ("POV_RECORDED" if povs else
                      "VERIFIER_RECORDED" if verification in files else
                      "PENDING_VERIFY"),
            "verification": ({"relative_path": verification,
                              "sha256": files[verification]}
                             if verification in files else None),
            "povs": povs,
        })
    return {"kind": KIND, "source_run": str(source_run),
            "resume_eligible": False, "pretransport_proven": False,
            "status": ("COMPLETED_QUEUE_AUDIT_ONLY" if completed_queue_first_dev
                       else "AUDIT_SNAPSHOT_ONLY"),
            **({"pending_budget_work": pending_budget_work}
               if completed_queue_first_dev else {}),
            "execution_identity": identity,
            "source_identity": {
                "run_id": run["run_id"], "function_id": selection["function_id"],
                "direction_id": selection["direction_id"],
                "harness_id": run["harness_id"],
            },
            "files": files, "items": items}


def write_checkpoint(source_run: Path, checkpoint_path: Path,
                     execution: dict[str, Any], *,
                     completed_queue_first_dev: bool = False) -> Path:
    """Create a private, single-write audit snapshot; never a resume permit."""
    source_run = Path(source_run)
    checkpoint_path = _check_no_symlink(Path(checkpoint_path))
    if checkpoint_path.is_relative_to(source_run.resolve(strict=True)):
        raise ValueError("checkpoint must be outside source run")
    if checkpoint_path.exists():
        raise FileExistsError(checkpoint_path)
    snapshot = _snapshot(source_run, execution,
                         completed_queue_first_dev=completed_queue_first_dev)
    # Quiescent source is required. A second pass catches modifications during
    # serialization; the reader checks the source again before later use.
    if snapshot != _snapshot(source_run, execution,
                              completed_queue_first_dev=completed_queue_first_dev):
        raise ValueError("source run changed during checkpoint capture")
    checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = checkpoint_path.with_name(checkpoint_path.name + "." +
                                          uuid4().hex + ".tmp")
    data = (json.dumps(snapshot, sort_keys=True, indent=2,
                       ensure_ascii=False) + "\n").encode()
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, checkpoint_path, follow_symlinks=False)
        directory = os.open(checkpoint_path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)
    return checkpoint_path


def read_checkpoint(checkpoint_path: Path, source_run: Path,
                    execution: dict[str, Any], *,
                    completed_queue_first_dev: bool = False) -> dict[str, Any]:
    """Validate byte identity and return evidence; never resume work."""
    checkpoint_path = _check_no_symlink(Path(checkpoint_path))
    if checkpoint_path.is_relative_to(Path(source_run).resolve(strict=True)):
        raise ValueError("checkpoint must be outside source run")
    if (not checkpoint_path.is_file() or
            stat.S_IMODE(checkpoint_path.stat().st_mode) != 0o600):
        raise ValueError("private checkpoint missing")
    stored = _json(checkpoint_path)
    fresh = _snapshot(Path(source_run), execution,
                      completed_queue_first_dev=completed_queue_first_dev)
    if (not isinstance(stored, dict) or set(stored) != set(fresh) or
            stored != fresh or stored.get("resume_eligible") is not False or
            stored.get("pretransport_proven") is not False):
        raise ValueError("queue checkpoint or source identity changed")
    return stored
