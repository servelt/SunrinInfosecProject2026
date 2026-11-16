from __future__ import annotations

import json
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


class UpstreamToolError(RuntimeError):
    pass


@dataclass(slots=True)
class UpstreamProcessResult:
    provider: str
    command: list[str]
    cwd: str
    returncode: int
    duration_seconds: float
    stdout: str
    stderr: str
    output: Path
    cached: bool = False


def fuzzgen_reports_to_rubick_a2dg(
    reports: Iterable[Path],
    output_directory: Path,
) -> list[Path]:
    """Translate FuzzGen's exported graph shape into RUBICK's A2DG I/O shape.

    This is a field-for-field process adapter.  It performs no call-order,
    dependency, coalescing, or automata inference; those operations remain in
    the two upstream implementations.
    """

    output_directory.mkdir(parents=True, exist_ok=True)
    outputs: list[Path] = []
    output_index = 0
    for report in reports:
        payload = json.loads(report.read_text(encoding="utf-8"))
        if payload.get("schema") != "harnesscreator.fuzzgen.aadg.v1":
            raise UpstreamToolError(
                f"cannot adapt non-FuzzGen evidence to RUBICK: {report}"
            )
        for graph in payload.get("graphs", []):
            if not isinstance(graph, dict):
                continue
            raw_nodes = [
                node for node in graph.get("nodes", []) if isinstance(node, dict)
            ]
            api_ids = [str(node.get("id")) for node in raw_nodes]
            if not api_ids:
                continue
            start = "__start__"
            end = "__end__"
            edges = [
                {
                    "from": str(edge.get("from")),
                    "to": str(edge.get("to")),
                }
                for edge in graph.get("control_edges", [])
                if isinstance(edge, dict)
                and not bool(edge.get("back_edge", False))
                and str(edge.get("from")) in api_ids
                and str(edge.get("to")) in api_ids
            ]
            incoming = {node_id: 0 for node_id in api_ids}
            outgoing = {node_id: 0 for node_id in api_ids}
            for edge in edges:
                incoming[edge["to"]] += 1
                outgoing[edge["from"]] += 1
            edges.extend(
                {"from": start, "to": node_id}
                for node_id, count in incoming.items()
                if count == 0
            )
            edges.extend(
                {"from": node_id, "to": end}
                for node_id, count in outgoing.items()
                if count == 0
            )
            info: dict[str, dict[str, str]] = {
                start: {"type": "START"},
                end: {"type": "END"},
            }
            for node in raw_nodes:
                node_id = str(node.get("id"))
                signature = _fuzzgen_node_signature(node)
                info[node_id] = {"type": "API", "sig": signature}
            a2dg: dict[str, Any] = {
                "name": str(graph.get("name") or f"fuzzgen-{output_index}"),
                "nodes": [start, *api_ids, end],
                "edges": edges,
                "info": info,
            }
            output = output_directory / f"fuzzgen-{output_index:04d}.a2dg.json"
            output.write_text(
                json.dumps(a2dg, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            outputs.append(output)
            output_index += 1
    return outputs


def run_rubick_a2dg(
    research_repos_root: Path,
    inputs: Iterable[Path],
    output: Path,
    *,
    timeout_seconds: int = 300,
) -> UpstreamProcessResult:
    input_paths = [path.resolve() for path in inputs]
    if not input_paths:
        raise UpstreamToolError("RUBICK requires at least one A2DG input")
    bridge = (
        research_repos_root
        / "Rubick"
        / "rubick"
        / "source"
        / "automata"
        / "harnesscreator_bridge.py"
    )
    if not bridge.is_file():
        raise UpstreamToolError(f"locked RUBICK bridge is missing: {bridge}")
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        str(bridge),
        "--output",
        str(output),
        *[str(path) for path in input_paths],
    ]
    started = time.monotonic()
    completed = subprocess.run(
        command,
        cwd=bridge.parent,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()[-4000:]
        raise UpstreamToolError(
            f"RUBICK A2DG process failed with exit {completed.returncode}: {detail}"
        )
    if not output.is_file():
        raise UpstreamToolError("RUBICK process exited successfully without an NFA output")
    try:
        payload = json.loads(output.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise UpstreamToolError(f"RUBICK emitted invalid JSON: {exc}") from exc
    if payload.get("schema") != "harnesscreator.rubick.nfa-set.v1":
        raise UpstreamToolError("RUBICK output has an unexpected bridge schema")
    return UpstreamProcessResult(
        provider="RUBICK",
        command=command,
        cwd=str(bridge.parent),
        returncode=completed.returncode,
        duration_seconds=time.monotonic() - started,
        stdout=completed.stdout[-4000:],
        stderr=completed.stderr[-4000:],
        output=output,
    )


def _fuzzgen_node_signature(node: dict[str, Any]) -> str:
    for key in ("callee", "function", "name", "signature"):
        value = str(node.get(key, "")).strip()
        if value:
            return value
    raise UpstreamToolError("FuzzGen AADG node is missing its API signature")
