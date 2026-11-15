"""Write RUN/index.json: the read-only facts every tool server process needs.

The tool servers are separate short-lived processes (one per agent), so they read
this file instead of re-parsing the HarnessCreator run each time.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .project import Project

DELIVERY_TEXT = {
    "stream": ("The harness input is the whole byte stream of ONE connection to the program: the bytes are "
               "sent in order, then the write side is closed and the reply is read until the program closes. "
               "Several protocol requests in one input are therefore just concatenated bytes."),
    "datagram": ("The harness input is a sequence of datagrams: each datagram is a 2-byte big-endian length "
                 "followed by that many bytes, and each is sent as one packet to the program. A generator may "
                 "return a list of bytes objects (one per datagram) and the framing is added for you."),
}
MESSAGE_RULE = {
    "stream": "A returned list of messages is concatenated into one stream.",
    "datagram": "A returned list of messages becomes one length-prefixed datagram each.",
}


def build_index(run_dir: Path, project: Project, *, harnesscreator_src: Path, sanitizer: str) -> dict[str, Any]:
    functions: dict[str, list[dict[str, Any]]] = {}
    for name, items in project.by_name.items():
        functions[name] = [{"file": fn.file, "start": fn.start_line, "end": fn.end_line,
                            "source": fn.source, "signature": fn.signature} for fn in items]
    harnesses = {}
    for harness in project.harnesses.values():
        harnesses[harness.harness_id] = {
            "delivery": harness.delivery, "source_path": str(harness.source_path),
            "binary": str(harness.binary), "build_plan": str(harness.build_plan) if harness.build_plan else "",
            "command": harness.command, "port": harness.port, "seeds": len(harness.seeds),
            "delivery_text": DELIVERY_TEXT[harness.delivery], "message_rule": MESSAGE_RULE[harness.delivery],
            "sanitizer": sanitizer,
        }
    index = {
        "program": project.name,
        "source_root": str(project.source_root),
        "harnesscreator_src": str(harnesscreator_src),
        "sanitizer": sanitizer,
        "functions": functions,
        "callers": {k: sorted(v) for k, v in project.callers.items()},
        "callees": {k: sorted(v) for k, v in project.callees.items()},
        "targets": sorted(project.target_names),
        # Measured by HarnessCreator on this program, used by the invariant recorder.
        "executed_by_seeds": sorted(project.executed_names & project.target_names),
        "closed_files": sorted(project.closed_files),
        "interpreters": project.interpreter_names,
        "driver": project.context.get("driver_function"),
        "harnesses": harnesses,
        "facts": project.facts(),
    }
    (Path(run_dir) / "index.json").write_text(json.dumps(index, ensure_ascii=False), encoding="utf-8")
    return index
