from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

# Resource kinds follow the attack-surface split between channels and data
# items; argv/env and internal descriptors are this project's additions.
RESOURCE_KINDS = ("network", "local_ipc", "stdin", "file", "argv", "env", "internal", "unknown")

# Priority is an ordering choice of this project (not taken from a paper):
# remotely reachable channels first, launch-time inputs last.
RESOURCE_PRIORITY = {"network": 0, "local_ipc": 1, "stdin": 2, "file": 3, "argv": 4, "env": 5, "unknown": 6}

DELIVERIES = ("stream", "datagram", "file", "argv", "env", "stdin", "unknown")


@dataclass
class ContextEntry:
    entry_id: str
    entry_function_id: str
    entry_function: str
    entry_file: str
    entry_line: int
    source_api: str
    channel_kind: str
    attacker_control: str
    entry_status: str
    resource_kind: str
    delivery: str
    interpreter_function_ids: list[str]
    interpreter_source: str  # locator | actions | consumer_hint | entry_function
    driver_function_id: str | None
    resource_source: str = "keyword_table"  # source_api | classifier | keyword_table


@dataclass
class InputContext:
    context_id: str
    resource_kind: str
    priority: int
    driver_function_id: str | None
    driver_function: str
    interpreter_function_ids: list[str]
    interpreter_functions: list[str]
    deliveries: list[str]
    entries: list[ContextEntry]
    target_function_ids: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        data = asdict(self)
        data["target_function_count"] = len(self.target_function_ids)
        return data


@dataclass
class Seed:
    """One complete input for a context: an ordered list of byte messages.

    stream: sent in order on one connection.  datagram: one datagram each.
    stdin/file: concatenated.  The number of protocol commands inside is not
    part of the definition.
    """

    seed_id: str
    context_id: str
    delivery: str
    messages_hex: list[str]
    origin: str  # project_artifact | source_reading | frontier
    rationale: str = ""
    evidence: list[dict[str, Any]] = field(default_factory=list)
    parent_seed_id: str | None = None
    target_function_id: str | None = None

    @property
    def messages(self) -> list[bytes]:
        return [bytes.fromhex(item) for item in self.messages_hex]


@dataclass
class SeedResult:
    seed_id: str
    context_id: str
    delivery: str
    status: str  # ACCEPTED_NEW | ACCEPTED_REDUNDANT | REJECTED_NO_TARGET | RUN_FAILED | COVERAGE_UNAVAILABLE
    reason: str
    responses_hex: list[str]
    covered_target_function_ids: list[str]
    new_target_function_ids: list[str]
    new_target_lines: int
    process_exit: str
