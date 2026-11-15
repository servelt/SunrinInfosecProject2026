from __future__ import annotations

import dataclasses
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Iterable

from .models import as_json


class ArtifactStore:
    """Run-scoped artifact writer using replace-based atomic publication."""

    def __init__(self, root: Path):
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def directory(self, relative: str | Path) -> Path:
        path = self._resolve(relative)
        path.mkdir(parents=True, exist_ok=True)
        return path

    def write_json(self, relative: str | Path, value: object) -> Path:
        return self.write_text(relative, json.dumps(_convert(value), ensure_ascii=False, indent=2, sort_keys=True) + "\n")

    def write_jsonl(self, relative: str | Path, values: Iterable[object]) -> Path:
        target = self._resolve(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                for item in values:
                    json.dump(_convert(item), stream, ensure_ascii=False, sort_keys=True)
                    stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(target)
        finally:
            if temporary.exists():
                temporary.unlink()
        return target

    def append_jsonl(self, relative: str | Path, value: object) -> Path:
        """Durably append one record without rebuilding the complete JSONL file."""
        target = self._resolve(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(_convert(value), ensure_ascii=False, sort_keys=True) + "\n"
        descriptor = os.open(target, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(line)
            stream.flush()
            os.fsync(stream.fileno())
        return target

    def append_text(self, relative: str | Path, content: str, *, durable: bool = False) -> Path:
        """Append text, optionally syncing it before returning."""
        target = self._resolve(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(target, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            if durable:
                os.fsync(stream.fileno())
        return target

    def write_text(self, relative: str | Path, content: str) -> Path:
        target = self._resolve(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(target)
        finally:
            if temporary.exists():
                temporary.unlink()
        return target

    def write_bytes(self, relative: str | Path, content: bytes) -> Path:
        target = self._resolve(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(target)
        finally:
            if temporary.exists():
                temporary.unlink()
        return target

    def _resolve(self, relative: str | Path) -> Path:
        value = Path(relative)
        if value.is_absolute():
            raise ValueError("artifact paths must be relative")
        target = (self.root / value).resolve()
        if target != self.root and self.root not in target.parents:
            raise ValueError(f"artifact path escapes run root: {relative}")
        return target


def _convert(value: object) -> Any:
    if dataclasses.is_dataclass(value):
        return as_json(value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _convert(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_convert(item) for item in value]
    return value
