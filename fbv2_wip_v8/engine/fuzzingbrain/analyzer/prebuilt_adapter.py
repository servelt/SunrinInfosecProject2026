"""Opt-in, provider-free adapter for a pinned prebuilt fuzzer and V2 catalog.

The adapter prepares the existing prebuild Mongo JSON format. It does not run a
compiler, model, target, or fuzzer, and it does not change the Worker pipeline.
"""

import argparse
from collections import defaultdict, deque
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess


class PrebuiltIdentityError(ValueError):
    """The supplied artifacts cannot be attributed to the selected source."""


def _strip_c_comments_and_literals(source):
    """Mask comments and quoted text while preserving token boundaries."""
    output = []
    index = 0
    state = "code"
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if char == "/" and next_char == "/":
                output.extend("  ")
                state = "line_comment"
                index += 2
                continue
            if char == "/" and next_char == "*":
                output.extend("  ")
                state = "block_comment"
                index += 2
                continue
            if char in ('"', "'"):
                output.append(" ")
                state = char
            else:
                output.append(char)
        elif state == "line_comment":
            output.append("\n" if char == "\n" else " ")
            if char == "\n":
                state = "code"
        elif state == "block_comment":
            if char == "*" and next_char == "/":
                output.extend("  ")
                state = "code"
                index += 2
                continue
            output.append("\n" if char == "\n" else " ")
        else:
            if char == "\\" and next_char:
                output.extend((" ", "\n" if next_char == "\n" else " "))
                index += 2
                continue
            output.append("\n" if char == "\n" else " ")
            if char == state:
                state = "code"
        index += 1
    return "".join(output)


def lexically_calls_function(source, function_name):
    """Return whether a function body contains a direct-looking call.

    This is deliberately conservative lexical evidence, not an AST or runtime
    reachability claim.  Comments, string/character literals, and the
    function's own declaration are excluded before matching an identifier
    followed by ``(``.
    """
    if not isinstance(source, str) or not re.fullmatch(
        r"[A-Za-z_][A-Za-z_0-9]*", function_name or ""
    ):
        return False
    code = _strip_c_comments_and_literals(source)
    body_start = code.find("{")
    if body_start < 0:
        return False
    body = code[body_start + 1 :]
    return bool(re.search(r"\b" + re.escape(function_name) + r"\s*\(", body))


def _matching_close(source, start, opening, closing):
    depth = 0
    for index in range(start, len(source)):
        if source[index] == opening:
            depth += 1
        elif source[index] == closing:
            depth -= 1
            if depth == 0:
                return index
    return -1


def _harness_lexically_calls_entry(source, entry_name):
    """Require a direct-looking call in the fuzzer body, not a comment/string.

    This is only lexical source evidence; it is not AST or runtime proof.
    """
    if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", entry_name):
        return False
    code = _strip_c_comments_and_literals(source)
    for match in re.finditer(r"\bLLVMFuzzerTestOneInput\s*\(", code):
        open_paren = code.index("(", match.start())
        close_paren = _matching_close(code, open_paren, "(", ")")
        if close_paren < 0:
            continue
        after = close_paren + 1
        while after < len(code) and code[after].isspace():
            after += 1
        if after >= len(code) or code[after] != "{":
            continue
        close_brace = _matching_close(code, after, "{", "}")
        if close_brace < 0:
            continue
        body = code[after + 1:close_brace]
        if re.search(r"\b" + re.escape(entry_name) + r"\s*\(", body):
            return True
    return False


def _sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_pinned_bytes(path, expected, label):
    """Read canonical pinned bytes once, rejecting alias and split-read races."""
    path = Path(path)
    if (not isinstance(expected, str) or len(expected) != 64 or
            not path.is_absolute() or path.is_symlink() or
            path != path.resolve() or not path.is_file()):
        raise PrebuiltIdentityError(f"{label} SHA-256 mismatch")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise OSError
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
                hashlib.sha256(raw).hexdigest() != expected):
            raise OSError
        return raw
    except OSError:
        raise PrebuiltIdentityError(f"{label} SHA-256 mismatch") from None


def _pinned_file(record, label):
    if not isinstance(record, dict) or set(record) != {"path", "sha256"}:
        raise PrebuiltIdentityError(f"{label}: path and sha256 are required")
    path = Path(record["path"])
    expected = record["sha256"]
    if (not path.is_absolute() or len(expected) != 64 or
            path != path.resolve()):
        raise PrebuiltIdentityError(f"{label}: invalid absolute path or SHA-256")
    if not path.is_file() or path.is_symlink():
        raise PrebuiltIdentityError(f"{label}: missing, non-file, or symlink")
    if _sha256(path) != expected:
        raise PrebuiltIdentityError(f"{label}: SHA-256 mismatch")
    return path


def _read_jsonl(path, label):
    records = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if line.strip():
                try:
                    records.append(json.loads(line))
                except (ValueError, TypeError) as exc:
                    raise PrebuiltIdentityError(
                        f"{label}:{line_number}: invalid JSON"
                    ) from exc
    if not records:
        raise PrebuiltIdentityError(f"{label}: empty catalog")
    return records


def _source_path(repo, relative):
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        raise PrebuiltIdentityError(f"source path escapes repository: {relative}")
    target = repo / path
    if not target.is_file() or target.is_symlink():
        raise PrebuiltIdentityError(f"source missing or symlink: {relative}")
    if not target.resolve().is_relative_to(repo.resolve()):
        raise PrebuiltIdentityError(f"source path escapes repository: {relative}")
    return target


def _source_language(relative):
    """Preserve the pinned source file's C/C++ language in FBv2 metadata."""
    suffix = Path(relative).suffix
    if suffix == '.c':
        return 'c'
    if suffix in {'.C', '.cc', '.cpp', '.cxx', '.c++'}:
        return 'cpp'
    raise PrebuiltIdentityError(f"unsupported or ambiguous source language: {relative}")


_DIRECTORY_FLAGS = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                    getattr(os, "O_NOFOLLOW", 0) |
                    getattr(os, "O_CLOEXEC", 0))
_FILE_READ_FLAGS = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                    getattr(os, "O_CLOEXEC", 0))
_TRUSTED_GIT = Path("/usr/bin/git")
_TRUSTED_GIT_SHA256 = (
    "eb54b535467e0975c1284d4c4d08eea779aeb248a5d34b02e2ee171382e22201")


def _identity(row):
    return (row.st_dev, row.st_ino, row.st_size,
            row.st_mtime_ns, row.st_ctime_ns)


def _open_output_directory(parent_fd, name, *, create=True):
    """Open one owned output directory relative to an already pinned parent."""
    if (not isinstance(name, str) or not name or name in {".", ".."} or
            "/" in name or "\x00" in name):
        raise PrebuiltIdentityError("derived output directory name is invalid")
    if create:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        except OSError as exc:
            raise PrebuiltIdentityError(
                "derived output directory cannot be created safely") from exc
    descriptor = None
    try:
        descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        opened = os.fstat(descriptor)
        linked = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISDIR(opened.st_mode) or
                _identity(opened) != _identity(linked) or
                opened.st_uid != os.geteuid() or
                stat.S_IMODE(opened.st_mode) & 0o022):
            raise OSError
        return descriptor
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        raise PrebuiltIdentityError(
            "derived output directory is linked or unsafe") from exc


def _read_output_file(directory_fd, name):
    try:
        descriptor = os.open(name, _FILE_READ_FLAGS, dir_fd=directory_fd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise PrebuiltIdentityError("derived output leaf is unsafe") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise OSError
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        linked = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if _identity(before) != _identity(after) or _identity(after) != _identity(linked):
            raise OSError
        return b"".join(chunks)
    except OSError as exc:
        raise PrebuiltIdentityError("derived output leaf changed") from exc
    finally:
        os.close(descriptor)


def _publish_bytes(directory_fd, name, payload, mode, label):
    existing = _read_output_file(directory_fd, name)
    if existing is not None:
        if existing != payload:
            raise PrebuiltIdentityError(f"{label} snapshot mismatch")
        return
    temporary = ".fbv2-" + secrets.token_hex(16)
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL |
             getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    descriptor = os.open(temporary, flags, mode, dir_fd=directory_fd)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short derived-output write")
            view = view[written:]
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.link(temporary, name, src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd, follow_symlinks=False)
    except FileExistsError:
        if _read_output_file(directory_fd, name) != payload:
            raise PrebuiltIdentityError(f"{label} publication raced")
    finally:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass


def _atomic_json_at(directory_fd, name, value):
    payload = json.dumps(value, sort_keys=True).encode("utf-8")
    _publish_bytes(directory_fd, name, payload, 0o400, "JSON")
    return payload


def _snapshot_binary_at(source, directory_fd, name, expected_sha256):
    """Publish exact source bytes beneath an already opened directory FD."""
    payload = _read_pinned_bytes(source, expected_sha256, "binary")
    _publish_bytes(directory_fd, name, payload, 0o500, "pinned binary")
    return payload


def _verify_output_directory(path, descriptor):
    try:
        linked = path.stat(follow_symlinks=False)
        opened = os.fstat(descriptor)
        if (path.is_symlink() or not stat.S_ISDIR(linked.st_mode) or
                _identity(linked) != _identity(opened)):
            raise OSError
    except OSError as exc:
        raise PrebuiltIdentityError(
            "derived output directory changed during publication") from exc


def prepare_prebuilt(manifest_path, manifest_sha256, task_path, project_name, sanitizers):
    """Validate pins and return FBv2 build metadata plus static import files.

    The caller must independently pin the manifest SHA. All referenced artifact
    bytes are checked before any build bypass.
    """
    manifest_path = Path(manifest_path)
    task_path = Path(task_path)
    manifest_raw = _read_pinned_bytes(
        manifest_path, manifest_sha256, "prebuilt manifest")
    try:
        manifest = json.loads(manifest_raw)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise PrebuiltIdentityError("prebuilt manifest: invalid JSON") from exc
    if manifest.get("schema") != "fbv2-prebuilt-v1":
        raise PrebuiltIdentityError("unsupported prebuilt manifest schema")
    if manifest.get("project_name") != project_name:
        raise PrebuiltIdentityError("project name mismatch")
    if sanitizers != ["address"]:
        raise PrebuiltIdentityError("prebuilt adapter supports address only")
    fuzzer_name = manifest.get("fuzzer_name")
    entry_name = manifest.get("entry_function")
    if (not isinstance(fuzzer_name, str) or not fuzzer_name
            or Path(fuzzer_name).name != fuzzer_name
            or not isinstance(entry_name, str) or not entry_name):
        raise PrebuiltIdentityError("fuzzer_name and entry_function are required")
    entry_names = manifest.get("entry_functions", [entry_name])
    if (not isinstance(entry_names, list) or not entry_names
            or any(not isinstance(name, str) or not name for name in entry_names)
            or len(set(entry_names)) != len(entry_names)
            or entry_name not in entry_names):
        raise PrebuiltIdentityError("entry_functions must be unique and include entry_function")

    repo = task_path / "repo"
    git_dir = repo / ".git"
    git_index = git_dir / "index"
    _read_pinned_bytes(_TRUSTED_GIT, _TRUSTED_GIT_SHA256, "Git executable")
    if (not repo.is_absolute() or repo.is_symlink() or repo != repo.resolve() or
            not git_dir.is_dir() or git_dir.is_symlink() or
            not git_index.is_file() or git_index.is_symlink()):
        raise PrebuiltIdentityError("source Git identity is not canonical")
    git_environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_DIR": str(git_dir),
        "GIT_INDEX_FILE": str(git_index),
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_WORK_TREE": str(repo),
        "LC_ALL": "C",
    }
    commit = subprocess.run(
        [str(_TRUSTED_GIT), "--no-optional-locks",
         f"--git-dir={git_dir}", f"--work-tree={repo}",
         "rev-parse", "HEAD"], cwd=repo,
        text=True, capture_output=True, check=True, env=git_environment,
    ).stdout.strip()
    if commit != manifest.get("source_commit"):
        raise PrebuiltIdentityError("source commit mismatch")
    status = subprocess.run(
        [str(_TRUSTED_GIT), "--no-optional-locks",
         f"--git-dir={git_dir}", f"--work-tree={repo}",
         "status", "--porcelain",
         "--untracked-files=normal"], cwd=repo, text=True,
        capture_output=True, check=True, env=git_environment,
    ).stdout
    if status:
        raise PrebuiltIdentityError("source repository is not clean")
    _read_pinned_bytes(_TRUSTED_GIT, _TRUSTED_GIT_SHA256, "Git executable")
    source_hashes = manifest.get("source_files")
    if not isinstance(source_hashes, dict) or not source_hashes:
        raise PrebuiltIdentityError("source_files SHA-256 map is required")
    for relative, expected in source_hashes.items():
        if not isinstance(expected, str) or len(expected) != 64:
            raise PrebuiltIdentityError(f"invalid source SHA-256: {relative}")
        if _sha256(_source_path(repo, relative)) != expected:
            raise PrebuiltIdentityError(f"source SHA-256 mismatch: {relative}")
    harness = manifest.get("harness_source")
    if harness not in source_hashes:
        raise PrebuiltIdentityError("harness source must be pinned")
    harness_source = _source_path(repo, harness).read_text(encoding="utf-8")
    for name in entry_names:
        if not _harness_lexically_calls_entry(harness_source, name):
            raise PrebuiltIdentityError(f"harness has no lexical direct call to selected entry: {name}")

    asan = _pinned_file(manifest.get("asan_binary"), "ASan binary")
    coverage = _pinned_file(manifest.get("coverage_binary"), "coverage binary")
    if asan.name != fuzzer_name:
        raise PrebuiltIdentityError("ASan binary name must match fuzzer_name")
    if coverage.name != fuzzer_name:
        raise PrebuiltIdentityError("coverage binary name must match fuzzer_name")
    catalog = manifest.get("catalog", {})
    functions = _read_jsonl(_pinned_file(catalog.get("functions"), "functions catalog"), "functions")
    edges = _read_jsonl(_pinned_file(catalog.get("edges"), "edges catalog"), "edges")
    by_id = {}
    by_name = {}
    source_texts = {}
    for function in functions:
        name, identifier, relative = (
            function.get("name"), function.get("function_id"), function.get("file")
        )
        if not all(isinstance(x, str) and x for x in (name, identifier, relative)):
            raise PrebuiltIdentityError("catalog function missing identity")
        if name in by_name or identifier in by_id or name == fuzzer_name:
            raise PrebuiltIdentityError("catalog has duplicate/ambiguous function name or ID")
        if relative not in source_hashes:
            raise PrebuiltIdentityError(f"catalog source is not pinned: {relative}")
        if relative not in source_texts:
            source_texts[relative] = _source_path(repo, relative).read_text(encoding="utf-8")
        excerpt = function.get("source")
        source_text = source_texts[relative]
        if not isinstance(excerpt, str) or not excerpt or source_text.count(excerpt) != 1:
            raise PrebuiltIdentityError(f"catalog source excerpt mismatch: {name}")
        offset = source_text.index(excerpt)
        actual_start = source_text.count("\n", 0, offset) + 1
        actual_end = source_text.count("\n", 0, offset + len(excerpt.rstrip("\r\n"))) + 1
        if (type(function.get("start_line")) is not int
                or type(function.get("end_line")) is not int
                or (function["start_line"], function["end_line"]) != (actual_start, actual_end)):
            raise PrebuiltIdentityError(f"catalog source line mismatch: {name}")
        for role, binary_hash in (
            ("asan", manifest["asan_binary"]["sha256"]),
            ("coverage", manifest["coverage_binary"]["sha256"]),
        ):
            linkage = function.get("role_linkage", {}).get(role, {})
            if (linkage.get("binary_sha256") != binary_hash
                    or linkage.get("source_sha256") != source_hashes[relative]):
                raise PrebuiltIdentityError(f"catalog {role} linkage mismatch: {name}")
        by_id[identifier] = function
        by_name[name] = function
    for name in entry_names:
        if name not in by_name:
            raise PrebuiltIdentityError(f"entry function missing from catalog: {name}")

    adjacency = defaultdict(set)
    reverse = defaultdict(set)
    for edge in edges:
        caller, callee = edge.get("caller_id"), edge.get("callee_id")
        if caller not in by_id or callee not in by_id:
            raise PrebuiltIdentityError("catalog edge references unknown function")
        if edge.get("confidence") not in {
            "COMPILER_AST_AND_OBJECT", "COMPILER_AST_AND_LINKED_OBJECT"
        }:
            raise PrebuiltIdentityError("catalog edge lacks compiled confidence")
        adjacency[caller].add(callee)
        reverse[callee].add(caller)
    roots = {by_name[name]["function_id"] for name in entry_names}
    distances = {root: 0 for root in roots}
    queue = deque(sorted(roots))
    while queue:
        caller = queue.popleft()
        for callee in sorted(adjacency[caller]):
            if callee not in distances:
                distances[callee] = distances[caller] + 1
                queue.append(callee)
    if len(distances) < 2:
        raise PrebuiltIdentityError("entry has no reachable source call graph")

    function_docs = []
    # The harness-to-library caller context comes from the pinned manifest
    # declaration and harness source check, not a compiler-AST catalog edge.
    # Leave the harness out of callgraph_nodes so it does not become a
    # reachable library function in the original Function Pool.
    graph_docs = []
    for function in functions:
        identifier = function["function_id"]
        name = function["name"]
        function_docs.append({
            "name": name, "file_path": function["file"],
            "start_line": function.get("start_line", 0),
            "end_line": function.get("end_line", 0),
            "content": function.get("source", ""),
            "language": _source_language(function["file"]),
            "reached_by_fuzzers": [fuzzer_name] if identifier in distances else [],
        })
        if identifier in distances:
            graph_docs.append({
                "fuzzer_id": fuzzer_name, "fuzzer_name": fuzzer_name,
                "function_name": name, "call_depth": distances[identifier],
                "callers": sorted(
                    [by_id[x]["name"] for x in reverse[identifier] if x in distances]
                    + ([fuzzer_name] if identifier in roots else [])),
                "callees": sorted(by_id[x]["name"] for x in adjacency[identifier] if x in distances),
            })
    # Direction Planning queries a Function named after the fuzzer for source.
    function_docs.append({
        "name": fuzzer_name, "file_path": harness,
        "content": harness_source, "language": _source_language(harness),
        "reached_by_fuzzers": [],
    })
    if (not re.fullmatch(r"[0-9a-f]{64}", manifest_sha256 or "") or
            not task_path.is_absolute() or task_path.is_symlink() or
            not task_path.is_dir() or task_path.resolve(strict=True) != task_path):
        raise PrebuiltIdentityError("derived output task root is unsafe")
    output_dir = task_path / ".fbv2_prebuilt" / manifest_sha256
    asan_snapshot = output_dir / "binaries" / "address" / fuzzer_name
    coverage_snapshot = output_dir / "binaries" / "coverage" / fuzzer_name
    descriptors = []
    try:
        task_fd = os.open(task_path, _DIRECTORY_FLAGS)
        descriptors.append(task_fd)
        _verify_output_directory(task_path, task_fd)
        prebuilt_fd = _open_output_directory(task_fd, ".fbv2_prebuilt")
        descriptors.append(prebuilt_fd)
        output_fd = _open_output_directory(prebuilt_fd, manifest_sha256)
        descriptors.append(output_fd)
        binaries_fd = _open_output_directory(output_fd, "binaries")
        descriptors.append(binaries_fd)
        address_fd = _open_output_directory(binaries_fd, "address")
        descriptors.append(address_fd)
        coverage_fd = _open_output_directory(binaries_fd, "coverage")
        descriptors.append(coverage_fd)
        mongodb_fd = _open_output_directory(output_fd, "mongodb")
        descriptors.append(mongodb_fd)

        _snapshot_binary_at(
            asan, address_fd, fuzzer_name,
            manifest["asan_binary"]["sha256"])
        _snapshot_binary_at(
            coverage, coverage_fd, fuzzer_name,
            manifest["coverage_binary"]["sha256"])
        functions_raw = _atomic_json_at(
            mongodb_fd, "functions.json", function_docs)
        graph_raw = _atomic_json_at(
            mongodb_fd, "callgraph.json", graph_docs)

        # The digest directory is content-addressed and complete after this
        # point.  Read/execute remains possible while accidental later writes
        # fail.  The owner can still chmod its own directory; the open-FD and
        # final inode checks close this invocation's check/publication race.
        for descriptor in (address_fd, coverage_fd, mongodb_fd, binaries_fd,
                           output_fd):
            # The signed live Task contract canonicalizes every directory to
            # 0555.  Keep that exact mode when an already-prepared fixture is
            # admitted again; changing it to 0500 here would make the
            # subsequent canonical-metadata recheck reject our own output.
            os.fchmod(descriptor, 0o555)

        paths_and_fds = (
            (task_path, task_fd),
            (task_path / ".fbv2_prebuilt", prebuilt_fd),
            (output_dir, output_fd),
            (output_dir / "binaries", binaries_fd),
            (output_dir / "binaries" / "address", address_fd),
            (output_dir / "binaries" / "coverage", coverage_fd),
            (output_dir / "mongodb", mongodb_fd),
        )
        for path, descriptor in paths_and_fds:
            _verify_output_directory(path, descriptor)
        if (_read_output_file(address_fd, fuzzer_name) is None or
                _read_output_file(coverage_fd, fuzzer_name) is None or
                _read_output_file(mongodb_fd, "functions.json") != functions_raw or
                _read_output_file(mongodb_fd, "callgraph.json") != graph_raw):
            raise PrebuiltIdentityError(
                "derived output changed during final verification")
    except OSError as exc:
        raise PrebuiltIdentityError("derived output publication failed") from exc
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
    return {
        "fuzzer_name": fuzzer_name,
        "asan_binary": str(asan_snapshot), "coverage_binary": str(coverage_snapshot),
        "harness_source": str(_source_path(repo, harness)),
        "prebuild_dir": str(output_dir), "work_id": "pinned",
        "function_count": len(function_docs), "reachable_count": len(distances),
        "harness_entry_count": len(roots),
        "harness_edge_provenance": "PINNED_MANIFEST_AND_HARNESS_LEXICAL_TOKEN_CANDIDATE",
        "manifest_sha256": manifest_sha256,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate and prepare prebuilt FBv2 artifacts without a provider")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--task-path", required=True)
    parser.add_argument("--project", required=True)
    args = parser.parse_args()
    print(json.dumps(prepare_prebuilt(args.manifest, args.manifest_sha256, args.task_path, args.project, ["address"]), indent=2))
