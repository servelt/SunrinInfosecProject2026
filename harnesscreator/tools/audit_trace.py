#!/usr/bin/env python3
"""Measure repeated Action/State source reads from a HarnessCreator run log.

Usage: python3 audit_trace.py /path/to/run.stderr.log
This script does not contact a model or execute the target daemon.
"""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re


ACTION = re.compile(
    r"\[ACTION BRANCH\]\s+"
    r"(entry-[a-fA-F0-9]+)\s*\|\s*"
    r"(opseed-[a-fA-F0-9]+)\s+\[.*?\]\s*->\s*([\w:]+)"
)
STATE = re.compile(
    r"\[STATE OPEN\]\s+(action-[a-fA-F0-9]+)\s*\|\s*([\w:]+)"
)


def audit(log_text: str) -> dict[str, object]:
    action_events = []
    state_events = []
    for line in log_text.splitlines():
        action = ACTION.search(line)
        if action:
            action_events.append(action.groups())
        state = STATE.search(line)
        if state:
            state_events.append(state.groups())

    action_names = Counter(function for _, _, function in action_events)
    state_names = Counter(function for _, function in state_events)
    first_state_handler: dict[str, str] = {}
    for action_id, function in state_events:
        first_state_handler.setdefault(action_id, function)
    first_handler_counts = Counter(first_state_handler.values())

    return {
        "action_branch_source_opens": len(action_events),
        "distinct_operation_seed_ids": len({seed for _, seed, _ in action_events}),
        "distinct_entry_seed_pairs": len({(entry, seed) for entry, seed, _ in action_events}),
        "distinct_action_function_names": len(action_names),
        "distinct_entry_function_pairs": len({(entry, function) for entry, _, function in action_events}),
        "top_reopened_action_functions": action_names.most_common(10),
        "state_source_opens": len(state_events),
        "distinct_state_action_ids": len(first_state_handler),
        "distinct_state_function_names": len(state_names),
        "distinct_first_state_handler_names": len(first_handler_counts),
        "state_group_minimum_by_handler_name_only_at_size_6": sum(
            (count + 5) // 6 for count in first_handler_counts.values()
        ),
        "interpretation": (
            "The grouping minimum ignores Entry identity, function IDs, source "
            "windows, model omissions, and individual fallback. It is NOT a "
            "prediction of new LLM call counts or coverage."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(args.log.read_text(encoding="utf-8", errors="replace")),
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
