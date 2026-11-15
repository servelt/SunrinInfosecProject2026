#!/usr/bin/env python3
"""Recompute V7 selection counterfactuals from the copied pinned evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "engine"))

from fuzzingbrain.agents.sp_generators import (  # noqa: E402
    generic_security_family_priority,
    generic_security_risk_priority,
)


def main() -> None:
    receipt_path = HERE / "V7_SP_FUNCTION_SELECTION_RECEIPT.json"
    functions_path = HERE / "V7_PINNED_FUNCTIONS.json"
    receipt = json.loads(receipt_path.read_text())
    functions = json.loads(functions_path.read_text())
    source_by_name = {row["name"]: row["content"] for row in functions}
    names = {
        json.dumps(row["canonical_identity"], sort_keys=True): row["function_name"]
        for row in receipt["occurrences"]
    }

    def function_name(row: dict) -> str:
        return names[json.dumps(row["canonical_identity"], sort_keys=True)]

    selected = receipt["selected_functions"]
    target = "md_consume_link_reference_definitions"
    original_order = next(
        row["selection_order"] for row in selected
        if function_name(row) == target
    )
    results = {}
    for policy in ("generic", "lifetime_family"):
        def score(row: dict) -> int:
            source = source_by_name[function_name(row)]
            if policy == "generic":
                return generic_security_risk_priority(source, "address")["score"]
            return generic_security_family_priority(
                source, "address", "LIFETIME_OWNERSHIP")["family_score"]

        ranked = [
            row
            for phase in receipt["phase_order"]
            for row in sorted(
                (item for item in selected if item["phase"] == phase),
                key=lambda item: -score(item),
            )
        ]
        results[policy] = {
            "target_score": score(next(
                row for row in selected if function_name(row) == target)),
            "target_counterfactual_order_zero_based": next(
                index for index, row in enumerate(ranked)
                if function_name(row) == target),
            "selected_count": len(ranked),
        }

    report = {
        "kind": "V81_V7_SELECTION_COUNTERFACTUAL_V1",
        "evidence_sha256": {
            receipt_path.name: hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
            functions_path.name: hashlib.sha256(functions_path.read_bytes()).hexdigest(),
        },
        "v7_target_original_order_zero_based": original_order,
        "results": results,
        "limitation": "This sorts V7's pinned selected rows; it is not a V8.1 Live result.",
    }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
