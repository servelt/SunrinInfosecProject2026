"""Source-grounded, deterministic request template materialization.

This is deliberately a *partial* grammar. Field locations are obtained from a
concrete source-backed example and InputFieldConstraint records. The engine
supports variable-size fields and a few explicit, auditable dependencies; it
never invents a checksum, a length rule or an unobserved protocol field.
"""
from __future__ import annotations

import re
import zlib
from dataclasses import dataclass
from typing import Mapping

from ..models import ActionExample, InputFieldConstraint


@dataclass(frozen=True)
class RenderedRequest:
    data: bytes
    # Updated ranges are computed from rendered lengths, not fixed offsets.
    offsets: dict[str, tuple[int, int]]
    bindings: dict[str, bytes]
    operations: tuple[str, ...]


_RELATION = re.compile(r"^(length_of|crc32_of)\(([A-Za-z_][\w.-]*)\)$")
_RESIZABLE = {"ascii_token", "ascii_bytes", "variable_bytes", "bytes_var", "raw_var"}


def _encode_derived(value: int, encoding: str, *, original_width: int) -> bytes:
    normalized = encoding.casefold().strip()
    if normalized in {"ascii_decimal", "decimal", "decimal_ascii"}:
        return str(value).encode("ascii")
    if normalized in {"u16be", "u16le", "u32be", "u32le"}:
        width = int(normalized[1:3]) // 8
        return value.to_bytes(width, "big" if normalized.endswith("be") else "little")
    if normalized == "u8":
        return value.to_bytes(1, "big")
    if normalized == "fixed_ascii_decimal":
        encoded = str(value).encode("ascii")
        if len(encoded) != original_width:
            raise ValueError("derived ASCII length changed in a fixed-width field")
        return encoded
    raise ValueError(f"unsupported derived field encoding {encoding!r}")


def render_request(
    example: ActionExample,
    fields: list[InputFieldConstraint],
    *,
    override_bindings: Mapping[str, bytes] | None = None,
    max_size: int = 1_048_576,
) -> RenderedRequest:
    """Render a template from a concrete example and source-located fields.

    Derived values may only be recomputed when the field has source evidence,
    declares a recognized relation, and refers to another *annotated field*.
    Offsets are recomputed after variable-width replacements. Ambiguous field
    names, overlapping ranges and out-of-bound annotations fail closed.
    """
    original = bytes.fromhex(example.data_hex)
    overrides = dict(override_bindings or {})
    ordered = sorted(fields, key=lambda item: (item.offset, item.name))
    cursor = 0
    names: set[str] = set()
    values: dict[str, bytes] = {}
    records: list[tuple[str, bytes, InputFieldConstraint | None]] = []
    for field in ordered:
        if not field.evidence or field.name in names:
            raise ValueError("ambiguous or unsupported source field")
        if field.offset < cursor or field.width <= 0 or field.offset + field.width > len(original):
            raise ValueError("overlapping or out-of-range field")
        if field.offset > cursor:
            records.append(("literal", original[cursor:field.offset], None))
        raw = original[field.offset:field.offset + field.width]
        claimed = example.bindings.get(field.binding) if field.binding else None
        if claimed is not None and bytes.fromhex(claimed) != raw:
            raise ValueError("example binding disagrees with source field bytes")
        selected = overrides.get(field.binding, raw) if field.binding else raw
        if not isinstance(selected, bytes):
            raise ValueError("field binding value must be bytes")
        if field.binding and len(selected) != len(raw) and field.encoding.casefold() not in _RESIZABLE:
            raise ValueError("fixed-width binding cannot be resized")
        relation = field.relation.strip()
        # Non-machine-readable relations remain explanatory source notes.
        # Never execute them as rules, and never discard existing candidates.
        names.add(field.name)
        values[field.name] = selected
        records.append(("field", selected, field))
        cursor = field.offset + field.width
    if cursor < len(original):
        records.append(("literal", original[cursor:], None))
    # Resolve dependencies recursively, not by the original field width.
    # Earlier implementations silently retained stale lengths when a derived
    # field depended on another derived field. Cycles/unknown dependencies are
    # unresolved, never guessed.
    fields_by_name = {field.name: field for field in ordered}
    original_values = {
        field.name: original[field.offset:field.offset + field.width] for field in ordered
    }
    resolving: set[str] = set()
    resolved: dict[str, bytes] = {}

    def resolve(name: str) -> bytes:
        if name in resolved:
            return resolved[name]
        if name in resolving:
            raise ValueError(f"cyclic derived field relation: {name}")
        field = fields_by_name.get(name)
        if field is None:
            raise ValueError(f"dependency references unknown field: {name}")
        resolving.add(name)
        relation = field.relation.strip()
        match = _RELATION.fullmatch(relation)
        if match:
            op, target = match.groups()
            if target not in fields_by_name:
                raise ValueError(f"dependency references unknown field: {target}")
            payload = resolve(target)
            number = len(payload) if op == "length_of" else zlib.crc32(payload)
            value = _encode_derived(number, field.encoding, original_width=field.width)
        else:
            # Opaque means a plain source field; free-form descriptions of
            # unknown relationships are safe ONLY while the original request
            # is unchanged. Otherwise they may describe a stale length,
            # checksum, frame total or dependent flag that we cannot update.
            if relation.casefold() not in {"", "opaque", "none", "literal", "independent"}:
                if any(values[key] != initial for key, initial in original_values.items()):
                    raise ValueError(
                        f"unsupported relation {relation!r} for field {name!r} "
                        "while mutating a source request"
                    )
            value = values[name]
        resolving.remove(name)
        resolved[name] = value
        return value

    for field in ordered:
        resolve(field.name)

    # Resolve derived fields against final target values, so the declaration
    # order does not matter (e.g. the length prefix comes before the payload).
    rendered: list[bytes] = []
    offsets: dict[str, tuple[int, int]] = {}
    bindings: dict[str, bytes] = {}
    operations: list[str] = []
    at = 0
    for kind, raw, field in records:
        if kind == "field":
            assert field is not None
            raw = resolved[field.name]
            match = _RELATION.fullmatch(field.relation.strip())
            if match:
                op, target = match.groups()
                operations.append(f"{field.name}={op}({target})")
            offsets[field.name] = (at, len(raw))
            if field.binding:
                previous = bindings.get(field.binding)
                if previous is not None and previous != raw:
                    raise ValueError("same binding maps to distinct values")
                bindings[field.binding] = raw
        rendered.append(raw)
        at += len(raw)
        if at > max_size:
            raise ValueError("rendered request exceeds maximum")
    return RenderedRequest(b"".join(rendered), offsets, bindings, tuple(operations))


def request_ir_summary(fields: list[InputFieldConstraint]) -> list[dict[str, object]]:
    """Serializable rules passed to generation/review, with no invented data."""
    return [{
        "name": field.name, "offset": field.offset, "width": field.width,
        "encoding": field.encoding, "binding": field.binding,
        "relation": field.relation,
        "source_evidence": [{"function_id": e.function_id, "line": e.line} for e in field.evidence],
    } for field in fields]
