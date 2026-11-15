"""Read task-scoped repository leases without granting validation credit.

Call only after the producer pools have joined. The digest describes a single
read of each collection; it is not a transaction or a proof of quiescence.
"""

import hashlib
import json
import re

from bson import ObjectId

from fuzzingbrain.core.models.direction import DirectionStatus
from fuzzingbrain.core.models.suspicious_point import SPStatus


def candidate_claim_snapshot(repos, task_id: str) -> dict:
    result = {
        "kind": "FBV2_CANDIDATE_CLAIM_SNAPSHOT_V1",
        "task_id": task_id,
        "scope": ["directions", "suspicious_points"],
        "status": "UNPROVEN",
        "active_document_count": None,
    }
    if type(task_id) is not str or not ObjectId.is_valid(task_id):
        return {**result, "reason": "INVALID_TASK_ID"}
    task = ObjectId(task_id)
    normalized = []
    counts = {"directions": 0, "suspicious_points": 0}
    try:
        for name, statuses, busy in (
            ("directions", {s.value for s in DirectionStatus}, {"in_progress"}),
            ("suspicious_points", {s.value for s in SPStatus},
             {"verifying", "generating_pov"}),
        ):
            required = {"_id", "task_id", "status", "processor_id"}
            if name == "suspicious_points":
                required |= {"verification_claim_token", "pov_active_claims"}
            # Read string aliases too, then reject their noncanonical schema.
            # Otherwise a drifted writer's active lease would be invisible.
            rows = getattr(repos, name).collection.find(
                {"task_id": {"$in": [task, re.compile(
                    "^" + str(task) + "$", re.IGNORECASE)]}},
                {field: 1 for field in required})
            seen = set()
            for row in rows:
                if (type(row) is not dict or not required <= row.keys() or
                        not isinstance(row["_id"], ObjectId) or
                        row["_id"] in seen or row["task_id"] != task or
                        row["status"] not in statuses or
                        (row["processor_id"] is not None and
                         (type(row["processor_id"]) is not str or
                          not row["processor_id"]))):
                    raise ValueError("malformed lease row")
                seen.add(row["_id"])
                active = row["processor_id"] is not None or row["status"] in busy
                token_present = False
                pov_count = 0
                if name == "suspicious_points":
                    token = row["verification_claim_token"]
                    if (token is not None and
                            (type(token) is not str or not token)):
                        raise ValueError("malformed verification token")
                    if type(row["pov_active_claims"]) is not list:
                        raise ValueError("malformed PoV claims")
                    token_present = token is not None
                    pov_count = len(row["pov_active_claims"])
                    active = active or token_present or pov_count > 0
                counts[name] += int(active)
                normalized.append({
                    "collection": name, "id": str(row["_id"]),
                    "status": row["status"],
                    "processor_present": row["processor_id"] is not None,
                    "verification_token_present": token_present,
                    "pov_active_claim_count": pov_count,
                })
    except Exception as exc:
        return {**result, "reason": "CLAIM_SNAPSHOT_READ_OR_SCHEMA_FAILED",
                "error_type": type(exc).__name__}
    normalized.sort(key=lambda row: (row["collection"], row["id"]))
    raw = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
    total = sum(counts.values())
    return {**result, "status": "ACTIVE" if total else "NO_ACTIVE_CLAIMS",
            "active_document_count": total, "active_documents_by_collection": counts,
            "document_count": len(normalized),
            "snapshot_sha256": hashlib.sha256(raw).hexdigest(), "rows": normalized}
