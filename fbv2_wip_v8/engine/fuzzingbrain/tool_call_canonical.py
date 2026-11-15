"""Pure canonicalization for retained model-proposed host tool calls."""

from __future__ import annotations

import json
from typing import Any, Mapping


DIRECT_SEED_CODE_MAX_BYTES = 32 * 1024
DIRECT_SEED_COUNT_MAX = 16


class ToolProposalCanonicalizationError(ValueError):
    """A completed model response cannot denote a valid host tool call."""


def canonicalize_tool_proposal(
    proposal: Mapping[str, Any], *, role: str,
) -> tuple[str, dict[str, Any]]:
    """Derive the one canonical executable call from retained model bytes."""
    if not isinstance(proposal, Mapping):
        raise ToolProposalCanonicalizationError("tool proposal is not an object")
    name = proposal.get("name")
    raw_arguments = proposal.get("arguments")
    if not isinstance(name, str) or not name or not isinstance(raw_arguments, str):
        raise ToolProposalCanonicalizationError("tool proposal fields are invalid")

    has_code = "seed_generator_code" in proposal
    has_count = "seed_num_seeds" in proposal
    if has_code != has_count:
        raise ToolProposalCanonicalizationError("partial direct Seed transport")
    direct_transport = has_code and has_count

    if name == "create_seed":
        if role != "seed" or not direct_transport:
            raise ToolProposalCanonicalizationError(
                "create_seed requires the Seed direct transport")
        if raw_arguments != "{}":
            raise ToolProposalCanonicalizationError(
                "create_seed arguments must be the exact {} sentinel")
        seed_code = proposal["seed_generator_code"]
        seed_count = proposal["seed_num_seeds"]
        if not isinstance(seed_code, str) or not seed_code:
            raise ToolProposalCanonicalizationError("Seed source is empty")
        try:
            seed_bytes = seed_code.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ToolProposalCanonicalizationError(
                "Seed source is not valid UTF-8") from exc
        if len(seed_bytes) > DIRECT_SEED_CODE_MAX_BYTES:
            raise ToolProposalCanonicalizationError("Seed source exceeds byte cap")
        if (type(seed_count) is not int or
                not 1 <= seed_count <= DIRECT_SEED_COUNT_MAX):
            raise ToolProposalCanonicalizationError("Seed count is outside cap")
        return name, {"generator_code": seed_code, "num_seeds": seed_count}

    if role == "seed" and not direct_transport:
        raise ToolProposalCanonicalizationError(
            "Seed proposal is missing direct transport sentinels")
    if role != "seed" and direct_transport:
        raise ToolProposalCanonicalizationError("Seed transport role mismatch")
    if direct_transport and (
        type(proposal["seed_generator_code"]) is not str or
        proposal["seed_generator_code"] != "" or
        type(proposal["seed_num_seeds"]) is not int or
        proposal["seed_num_seeds"] != 0
    ):
        raise ToolProposalCanonicalizationError(
            "non-create_seed tool populated direct Seed fields")
    try:
        arguments = json.loads(raw_arguments)
    except json.JSONDecodeError as exc:
        raise ToolProposalCanonicalizationError(
            "tool arguments are not JSON") from exc
    if not isinstance(arguments, dict):
        raise ToolProposalCanonicalizationError("tool arguments must be an object")
    return name, arguments
