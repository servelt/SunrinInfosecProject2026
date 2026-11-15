"""Hash an explicit, Oracle-free execution surface without selecting functions.

The spec lists real roots and files/directories relative to each root. This tool
does not read evaluator-only data, rank functions, or launch a target/model.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_relative(value: str) -> Path:
    path = Path(value)
    if (not value or path.is_absolute() or ".." in path.parts or
            "evaluator_only" in path.parts or "oracle" in value.lower()):
        raise ValueError(f"prohibited freeze path: {value}")
    return path


def build_manifest(spec_path: Path) -> dict:
    spec_path = spec_path.resolve(strict=True)
    spec = json.loads(spec_path.read_text())
    roots = {key: Path(value).resolve(strict=True)
             for key, value in spec["roots"].items()}
    if not roots or not spec.get("groups"):
        raise ValueError("freeze spec needs roots and groups")
    if any("evaluator_only" in root.parts or "oracle" in str(root).lower()
           for root in roots.values()):
        raise ValueError("freeze root may not enter evaluator-only material")
    entries: list[dict] = []
    for group, definition in sorted(spec["groups"].items()):
        root_name = definition["root"]
        root = roots[root_name]
        suffixes = tuple(definition.get("suffixes", []))
        excluded = {_safe_relative(value).as_posix()
                    for value in definition.get("exclude", [])}
        found = 0
        for relative in definition["paths"]:
            rel = _safe_relative(relative)
            source = root / rel
            if not source.exists() or source.is_symlink():
                raise ValueError(f"missing or linked freeze input: {root_name}:{rel}")
            files = sorted(source.rglob("*")) if source.is_dir() else [source]
            for file in files:
                if file.is_symlink():
                    raise ValueError(f"unsafe freeze input: {file}")
                if file.is_dir():
                    continue
                if not file.is_file() or not file.resolve().is_relative_to(root):
                    raise ValueError(f"unsafe freeze input: {file}")
                if suffixes and file.suffix not in suffixes:
                    continue
                name = file.relative_to(root).as_posix()
                if name in excluded:
                    continue
                if "evaluator_only" in Path(name).parts or "oracle" in name.lower():
                    raise ValueError(f"prohibited freeze input: {name}")
                entries.append({"group": group, "root": root_name, "path": name,
                                "size": file.stat().st_size, "sha256": digest(file)})
                found += 1
        if found == 0:
            raise ValueError(f"empty freeze group: {group}")
    keys = [(row["root"], row["path"]) for row in entries]
    if len(keys) != len(set(keys)):
        raise ValueError("freeze spec pins one file more than once")
    entries.sort(key=lambda row: (row["root"], row["path"]))
    body = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    return {"kind": "ORACLE_FREE_FREEZE_MANIFEST_V1",
            "spec_sha256": digest(spec_path), "roots": {k: str(v) for k, v in roots.items()},
            "entry_count": len(entries), "entries_sha256": hashlib.sha256(body).hexdigest(),
            "entries": entries}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("spec", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    manifest = build_manifest(args.spec)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(f"hashed {manifest['entry_count']} files: {manifest['entries_sha256']}")
