"""
Database Repository

CRUD operations for all FuzzingBrain models.
"""

import base64
import binascii
import hashlib
import re
from datetime import datetime
from pathlib import Path
from typing import Optional, List, TypeVar, Generic, Type
from pymongo.database import Database
from pymongo.collection import Collection
from bson import ObjectId
from loguru import logger

from ..core.models import (
    Task,
    POV,
    Patch,
    Worker,
    Fuzzer,
    Function,
    CallGraphNode,
    SuspiciousPoint,
    Direction,
    DirectionStatus,
)


T = TypeVar("T")


class BaseRepository(Generic[T]):
    """Base repository with common CRUD operations"""

    def __init__(self, db: Database, collection_name: str, model_class: Type[T]):
        self.db = db
        self.collection: Collection = db[collection_name]
        self.model_class = model_class

    def save(self, entity: T) -> bool:
        """
        Save entity to database (upsert).

        Returns:
            True if saved successfully
        """
        try:
            data = entity.to_dict()
            self.collection.replace_one({"_id": data["_id"]}, data, upsert=True)
            return True
        except Exception as e:
            logger.error(f"Failed to save {self.model_class.__name__}: {e}")
            return False

    def _convert_id(self, entity_id: str):
        """Convert entity_id to ObjectId if it's a valid ObjectId string."""
        try:
            # Check if it's a valid ObjectId string (24 hex characters)
            if len(entity_id) == 24:
                return ObjectId(entity_id)
        except Exception:
            pass
        return entity_id

    def find_by_id(self, entity_id: str) -> Optional[T]:
        """Find entity by ID"""
        try:
            # Try with ObjectId first, then fallback to string
            _id = self._convert_id(entity_id)
            data = self.collection.find_one({"_id": _id})
            if data:
                return self.model_class.from_dict(data)
            return None
        except Exception as e:
            logger.error(f"Failed to find {self.model_class.__name__} by id: {e}")
            return None

    def find_all(self, query: dict = None, limit: int = 0, skip: int = 0) -> List[T]:
        """Find all entities matching query"""
        try:
            query = query or {}
            cursor = self.collection.find(query).skip(skip)
            if limit > 0:
                cursor = cursor.limit(limit)
            return [self.model_class.from_dict(doc) for doc in cursor]
        except Exception as e:
            logger.error(f"Failed to find {self.model_class.__name__}s: {e}")
            return []

    def find_one(self, query: dict) -> Optional[T]:
        """Find single entity matching query"""
        try:
            data = self.collection.find_one(query)
            if data:
                return self.model_class.from_dict(data)
            return None
        except Exception as e:
            logger.error(f"Failed to find {self.model_class.__name__}: {e}")
            return None

    def update(self, entity_id: str, updates: dict) -> bool:
        """Update entity fields"""
        try:
            updates["updated_at"] = datetime.now()
            _id = self._convert_id(entity_id)
            result = self.collection.update_one({"_id": _id}, {"$set": updates})
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Failed to update {self.model_class.__name__}: {e}")
            return False

    def delete(self, entity_id: str) -> bool:
        """Delete entity by ID"""
        try:
            _id = self._convert_id(entity_id)
            result = self.collection.delete_one({"_id": _id})
            return result.deleted_count > 0
        except Exception as e:
            logger.error(f"Failed to delete {self.model_class.__name__}: {e}")
            return False

    def count(self, query: dict = None) -> int:
        """Count entities matching query"""
        try:
            query = query or {}
            return self.collection.count_documents(query)
        except Exception as e:
            logger.error(f"Failed to count {self.model_class.__name__}s: {e}")
            return 0

    def exists(self, entity_id: str) -> bool:
        """Check if entity exists"""
        _id = self._convert_id(entity_id)
        return self.collection.count_documents({"_id": _id}, limit=1) > 0


class TaskRepository(BaseRepository[Task]):
    """Repository for Task model"""

    # Fields managed exclusively by WorkerLLMBuffer via $inc.
    # Must NOT be included in save() to avoid overwriting buffer increments.
    _LLM_FIELDS = ("llm_calls", "llm_cost", "llm_input_tokens", "llm_output_tokens")

    def __init__(self, db: Database):
        super().__init__(db, "tasks", Task)

    def save(self, task: Task) -> bool:
        """Save task to database (upsert).

        Uses $set instead of replace_one to avoid overwriting llm_* fields
        that are managed by WorkerLLMBuffer via atomic $inc.
        """
        try:
            data = task.to_dict()
            doc_id = data.pop("_id")
            for key in self._LLM_FIELDS:
                data.pop(key, None)
            self.collection.update_one({"_id": doc_id}, {"$set": data}, upsert=True)
            return True
        except Exception as e:
            logger.error(f"Failed to save Task: {e}")
            return False

    def find_by_status(self, status: str) -> List[Task]:
        """Find tasks by status"""
        return self.find_all({"status": status})

    def find_pending(self) -> List[Task]:
        """Find all pending tasks"""
        return self.find_by_status("pending")

    def find_running(self) -> List[Task]:
        """Find all running tasks"""
        return self.find_by_status("running")

    def find_by_project(self, project_name: str) -> List[Task]:
        """Find tasks by project name"""
        return self.find_all({"project_name": project_name})

    def update_status(self, task_id: str, status: str, error_msg: str = None) -> bool:
        """Update task status"""
        updates = {"status": status}
        if error_msg:
            updates["error_msg"] = error_msg
        return self.update(task_id, updates)

    def add_pov(self, task_id: str, pov_id: str) -> bool:
        """Add POV ID to task"""
        try:
            result = self.collection.update_one(
                {"_id": ObjectId(task_id)},
                {"$push": {"pov_ids": pov_id}, "$set": {"updated_at": datetime.now()}},
            )
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Failed to add POV to task: {e}")
            return False

    def add_patch(self, task_id: str, patch_id: str) -> bool:
        """Add Patch ID to task"""
        try:
            result = self.collection.update_one(
                {"_id": ObjectId(task_id)},
                {
                    "$push": {"patch_ids": patch_id},
                    "$set": {"updated_at": datetime.now()},
                },
            )
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Failed to add patch to task: {e}")
            return False


class POVRepository(BaseRepository[POV]):
    """Repository for POV model"""

    def __init__(self, db: Database):
        super().__init__(db, "povs", POV)

    def find_by_task(self, task_id: str) -> List[POV]:
        """Find all POVs for a task"""
        return self.find_all({"task_id": ObjectId(task_id)})

    def find_active_by_task(self, task_id: str) -> List[POV]:
        """Find active POVs for a task"""
        return self.find_all({"task_id": ObjectId(task_id), "is_active": True})

    def find_successful_by_task(self, task_id: str) -> List[POV]:
        """Find successful POVs for a task"""
        return self.find_all(
            {"task_id": ObjectId(task_id), "is_active": True, "is_successful": True}
        )

    def find_by_harness(self, task_id: str, harness_name: str) -> List[POV]:
        """Find POVs for a specific harness"""
        return self.find_all(
            {"task_id": ObjectId(task_id), "harness_name": harness_name}
        )

    def deactivate(self, pov_id: str) -> bool:
        """Mark POV as inactive"""
        return self.update(pov_id, {"is_active": False})

    def mark_successful(self, pov_id: str) -> bool:
        """Mark POV as successful"""
        return self.update(pov_id, {"is_successful": True})


class PatchRepository(BaseRepository[Patch]):
    """Repository for Patch model"""

    def __init__(self, db: Database):
        super().__init__(db, "patches", Patch)

    def find_by_task(self, task_id: str) -> List[Patch]:
        """Find all patches for a task"""
        return self.find_all({"task_id": ObjectId(task_id)})

    def find_active_by_task(self, task_id: str) -> List[Patch]:
        """Find active patches for a task"""
        return self.find_all({"task_id": ObjectId(task_id), "is_active": True})

    def find_by_pov(self, pov_id: str) -> List[Patch]:
        """Find patches for a specific POV"""
        return self.find_all({"pov_id": pov_id})

    def find_valid_by_task(self, task_id: str) -> List[Patch]:
        """Find valid patches (passes all checks)"""
        return self.find_all(
            {
                "task_id": ObjectId(task_id),
                "is_active": True,
                "apply_check": True,
                "compilation_check": True,
                "pov_check": True,
                "test_check": True,
            }
        )

    def update_checks(
        self,
        patch_id: str,
        apply: bool = None,
        compile: bool = None,
        pov: bool = None,
        test: bool = None,
    ) -> bool:
        """Update patch verification checks"""
        updates = {}
        if apply is not None:
            updates["apply_check"] = apply
        if compile is not None:
            updates["compilation_check"] = compile
        if pov is not None:
            updates["pov_check"] = pov
        if test is not None:
            updates["test_check"] = test
        if updates:
            return self.update(patch_id, updates)
        return False


class SuspiciousPointRepository(BaseRepository[SuspiciousPoint]):
    """Repository for SuspiciousPoint model"""

    _PIPELINE_OWNED_FIELDS = {
        # Creation-time identity and frozen hypothesis provenance.  Source
        # merging has its own atomic add_source() method; generic replacement
        # must not move a live claim to another campaign, candidate, function,
        # direction, or contributor.
        "_id", "suspicious_point_id", "task_id", "direction_id",
        "function_name", "created_by_agent_id", "sources", "description",
        "vuln_type", "static_reachable", "important_controlflow",
        "merged_duplicates", "created_at",
        "status", "processor_id", "verification_claim_token",
        "verification_result_claim_token", "is_checked", "is_real",
        "is_important", "score", "verification_notes",
        "verification_disposition", "verification_refutation_evidence",
        "pov_guidance", "reachability_status", "reachability_multiplier",
        "reachability_reason", "checked_at", "verified_by_agent_id",
        "pipeline_incomplete_reason", "pipeline_incomplete_stage",
        # PoV claims and every field derived from their outcome are owned by
        # the token-bound transition methods below.  Protecting only the two
        # claim arrays would let a generic update forge a winner or corrupt a
        # contributor snapshot and permanently strand the queue.
        "pov_id", "pending_pov_ids", "pending_pov_artifacts",
        "pov_success_by", "pov_attempted_by", "pov_failed_by",
        "pov_incomplete_by", "pov_local_failures", "pov_generated_at",
        "pov_active_claims", "pov_settled_claims",
    }

    def __init__(self, db: Database):
        super().__init__(db, "suspicious_points", SuspiciousPoint)
        # Create indexes for faster queries
        self._ensure_indexes()

    def save(self, entity: SuspiciousPoint) -> bool:
        """Create a suspicious point without replacing existing state.

        Suspicious-point transitions are owned by claim-token CAS methods.
        A generic upsert would let a stale object replace an active claim or
        recreate the disabled terminal REFUTED state, so creation is
        insert-only. Historical REFUTED rows remain readable; this method only
        rejects creation of new ones.
        """
        try:
            import math
            from ..core.models import SPStatus

            # Validate the model before ``to_dict()`` normalizes malformed
            # identifiers (for example an empty task ID becomes ``None``).
            # Creation is the only non-CAS write for an SP, so it must admit
            # only a complete, claimable candidate and no pre-populated
            # verifier/PoV state.
            model_initial = (
                type(entity.suspicious_point_id) is str and
                ObjectId.is_valid(entity.suspicious_point_id) and
                type(entity.task_id) is str and
                ObjectId.is_valid(entity.task_id) and
                type(entity.direction_id) is str and
                (not entity.direction_id or
                 ObjectId.is_valid(entity.direction_id)) and
                type(entity.function_name) is str and
                bool(entity.function_name) and
                (entity.created_by_agent_id is None or
                 (type(entity.created_by_agent_id) is str and
                  ObjectId.is_valid(entity.created_by_agent_id))) and
                entity.verified_by_agent_id is None and
                type(entity.description) is str and bool(entity.description) and
                type(entity.vuln_type) is str and bool(entity.vuln_type) and
                type(entity.score) in {int, float} and
                math.isfinite(entity.score) and 0.0 <= entity.score <= 1.0 and
                type(entity.is_checked) is bool and not entity.is_checked and
                type(entity.is_real) is bool and not entity.is_real and
                # is_important is also a creation-time queue priority, not
                # solely a verifier verdict, so either boolean is valid.
                type(entity.is_important) is bool and
                type(entity.static_reachable) is bool and
                type(entity.reachability_status) is str and
                type(entity.reachability_reason) is str and
                type(entity.reachability_multiplier) in {int, float} and
                math.isfinite(entity.reachability_multiplier) and
                type(entity.important_controlflow) is list and
                all(type(item) is dict
                    for item in entity.important_controlflow) and
                entity.merged_duplicates == [] and
                entity.processor_id is None and
                entity.verification_claim_token is None and
                entity.pov_claim_token is None and
                entity.verification_notes is None and
                entity.pov_guidance is None and
                entity.checked_at is None
            )
            if not model_initial:
                logger.warning(
                    "Rejected malformed initial suspicious-point creation")
                return False

            data = entity.to_dict()
            sources = data.get("sources")
            clean_initial = (
                data.get("status") == SPStatus.PENDING_VERIFY.value and
                data.get("processor_id") is None and
                data.get("is_checked") is False and
                data.get("is_real") is False and
                data.get("verification_disposition") is None and
                data.get("verification_refutation_evidence") is None and
                data.get("pipeline_incomplete_reason") is None and
                data.get("pipeline_incomplete_stage") is None and
                data.get("pov_id") is None and
                data.get("pending_pov_ids") == [] and
                data.get("pending_pov_artifacts") == [] and
                data.get("pov_success_by") is None and
                data.get("pov_attempted_by") == [] and
                data.get("pov_failed_by") == [] and
                data.get("pov_incomplete_by") == [] and
                data.get("pov_local_failures") == [] and
                data.get("pov_generated_at") is None and
                type(sources) is list and len(sources) == 1 and
                type(sources[0]) is dict and
                set(sources[0]) == {"harness_name", "sanitizer"} and
                type(sources[0].get("harness_name")) is str and
                bool(sources[0]["harness_name"]) and
                type(sources[0].get("sanitizer")) is str and
                bool(sources[0]["sanitizer"])
            )
            if (not clean_initial or
                    data.get("status") == "refuted" or
                    data.get("verification_disposition") == "REFUTED" or
                    data.get("verification_refutation_evidence") is not None):
                logger.warning(
                    "Rejected non-initial suspicious-point creation")
                return False
            # Hidden lease fields are persisted even though claim tokens are
            # intentionally omitted from model-visible serialization.  A new
            # signed campaign can therefore prove queue settlement without
            # treating a missing field as an empty lease.
            data.update({
                "verification_claim_token": None,
                "verification_result_claim_token": None,
                "pov_active_claims": [],
                "pov_settled_claims": [],
            })
            result = self.collection.insert_one(data)
            return bool(result.acknowledged)
        except Exception as e:
            logger.error(f"Failed to create SuspiciousPoint: {e}")
            return False

    def _ensure_indexes(self):
        """Create indexes for common query patterns."""
        try:
            self.collection.create_index("task_id")
            self.collection.create_index("status")
            self.collection.create_index("function_name")
            self.collection.create_index("score")
            self.collection.create_index([("task_id", 1), ("status", 1)])
            self.collection.create_index([("task_id", 1), ("function_name", 1)])
            self.collection.create_index([("task_id", 1), ("score", -1)])
            self.collection.create_index([("task_id", 1), ("is_checked", 1)])
            # Compound index for claim_for_verify priority sorting
            self.collection.create_index(
                [
                    ("task_id", 1),
                    ("status", 1),
                    ("is_important", -1),
                    ("score", -1),
                    ("created_at", 1),
                ]
            )
        except Exception as e:
            logger.debug(f"Index creation for suspicious_points: {e}")

    def update(self, entity_id: str, updates: dict) -> bool:
        """Reject generic writes to Verifier- or PoV-owned state."""
        if not isinstance(updates, dict):
            logger.warning(
                "Rejected malformed generic suspicious-point update")
            return False
        # MongoDB accepts dotted $set paths. Compare their top-level owner,
        # not only the exact key, or ``pov_active_claims.0.claim_token`` can
        # replace a live capability through the generic CRUD API.
        if not all(type(key) is str for key in updates):
            logger.warning(
                "Rejected malformed generic suspicious-point update keys")
            return False
        update_roots = {key.split(".", 1)[0] for key in updates}
        if update_roots & self._PIPELINE_OWNED_FIELDS:
            logger.warning(
                "Rejected generic write to pipeline-owned suspicious-point fields")
            return False
        return super().update(entity_id, updates)

    def find_by_task(self, task_id: str) -> List[SuspiciousPoint]:
        """Find all suspicious points for a task"""
        return self.find_all({"task_id": ObjectId(task_id)})

    def find_by_function(
        self, task_id: str, function_name: str
    ) -> List[SuspiciousPoint]:
        """Find suspicious points for a specific function"""
        return self.find_all(
            {"task_id": ObjectId(task_id), "function_name": function_name}
        )

    def find_unchecked(self, task_id: str) -> List[SuspiciousPoint]:
        """Find unchecked suspicious points for a task"""
        return self.find_all({"task_id": ObjectId(task_id), "is_checked": False})

    def find_real(self, task_id: str) -> List[SuspiciousPoint]:
        """Find verified real vulnerabilities for a task"""
        return self.find_all(
            {"task_id": ObjectId(task_id), "is_checked": True, "is_real": True}
        )

    def find_important(self, task_id: str) -> List[SuspiciousPoint]:
        """Find important (high priority) suspicious points"""
        return self.find_all({"task_id": ObjectId(task_id), "is_important": True})

    def find_by_score(
        self, task_id: str, min_score: float = 0.0
    ) -> List[SuspiciousPoint]:
        """Find suspicious points with score >= min_score, sorted by score descending"""
        try:
            cursor = self.collection.find(
                {"task_id": ObjectId(task_id), "score": {"$gte": min_score}}
            ).sort("score", -1)
            return [self.model_class.from_dict(doc) for doc in cursor]
        except Exception as e:
            logger.error(f"Failed to find suspicious points by score: {e}")
            return []

    def mark_checked(self, sp_id: str, is_real: bool, notes: str = None) -> bool:
        """Mark a suspicious point as checked"""
        updates = {"is_checked": True, "is_real": is_real, "checked_at": datetime.now()}
        if notes:
            updates["verification_notes"] = notes
        return self.update(sp_id, updates)

    def mark_important(self, sp_id: str) -> bool:
        """Mark a suspicious point as important (high priority)"""
        return self.update(sp_id, {"is_important": True})

    def update_score(self, sp_id: str, score: float) -> bool:
        """Update the score of a suspicious point"""
        return self.update(sp_id, {"score": score})

    def add_source(self, sp_id: str, harness_name: str, sanitizer: str) -> bool:
        """
        Add a new source to an existing SP.

        Args:
            sp_id: Suspicious point ID
            harness_name: Harness name to add
            sanitizer: Sanitizer to add

        Returns:
            True if source was added, False if already exists or error
        """
        try:
            # Keep durable contributors identical to claim_for_pov's
            # isolation identity. An empty or non-string source can never be
            # claimed and would leave an otherwise exhausted candidate stuck.
            if (type(harness_name) is not str or not harness_name or
                    type(sanitizer) is not str or not sanitizer):
                return False
            from ..core.models import SPStatus

            new_source = {"harness_name": harness_name, "sanitizer": sanitizer}
            base_query = {
                "_id": ObjectId(sp_id),
                "sources": {"$not": {"$elemMatch": new_source}},
            }
            # Persist the new contributor independently of the current state.
            # A status-qualified two-query add can lose the source when the
            # last old contributor commits FAILED between those queries.
            result = self.collection.update_one(
                base_query,
                {"$addToSet": {"sources": new_source},
                 "$set": {"updated_at": datetime.now()}},
            )
            source_added = result.modified_count == 1

            # If failure won immediately before or after the source merge,
            # reopen using the now-durable contributor. This query also makes
            # an identical retry recover a crash after the source add but
            # before this reopen. A contributor already attempted, failed or
            # interrupted is not fresh work and must not reopen the terminal
            # candidate.
            reopened = self.collection.update_one(
                {"_id": ObjectId(sp_id),
                 "status": SPStatus.FAILED.value,
                 # FAILED is shared by Verifier and PoV failure paths. Only
                 # a candidate that completed verification and has a durable
                 # PoV contributor failure may be reopened directly to PoV.
                 "is_checked": True,
                 "pov_failed_by.0": {"$exists": True},
                 "sources": {"$elemMatch": new_source},
                 "pov_attempted_by": {"$not": {"$elemMatch": new_source}},
                 "pov_failed_by": {"$not": {"$elemMatch": new_source}},
                 "pov_incomplete_by": {"$not": {"$elemMatch": new_source}},
                 "pov_success_by": None},
                {"$set": {"status": SPStatus.PENDING_POV.value,
                           "processor_id": None,
                           "updated_at": datetime.now()}},
            )
            return source_added or reopened.modified_count == 1
        except Exception as e:
            logger.error(f"Failed to add source to SP {sp_id}: {e}")
            return False

    def add_merged_duplicate(
        self,
        sp_id: str,
        description: str,
        vuln_type: str,
        harness_name: str,
        sanitizer: str,
        score: float = 0.0,
    ) -> bool:
        """
        Record a merged duplicate for human review.

        When an SP is identified as a duplicate and merged, this records
        the original description and metadata for later review.

        Args:
            sp_id: Suspicious point ID that the duplicate was merged into
            description: Description of the duplicate SP
            vuln_type: Vulnerability type of the duplicate
            harness_name: Harness that discovered the duplicate
            sanitizer: Sanitizer used
            score: Score of the duplicate

        Returns:
            True if recorded successfully
        """
        try:
            merged_record = {
                "description": description,
                "vuln_type": vuln_type,
                "harness_name": harness_name,
                "sanitizer": sanitizer,
                "score": score,
                "merged_at": datetime.now().isoformat(),
            }
            result = self.collection.update_one(
                {"_id": ObjectId(sp_id)},
                {"$push": {"merged_duplicates": merged_record}},
            )
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Failed to add merged duplicate to SP {sp_id}: {e}")
            return False

    def find_with_merged_duplicates(self, task_id: str) -> List[SuspiciousPoint]:
        """
        Find all SPs that have merged duplicates (for human review).

        Returns:
            List of SPs with at least one merged duplicate
        """
        return self.find_all(
            {
                "task_id": ObjectId(task_id),
                "merged_duplicates": {"$exists": True, "$ne": []},
            }
        )

    def count_by_status(
        self,
        task_id: str,
        status: str = None,
        harness_name: str = None,
        sanitizer: str = None,
        raise_on_error: bool = False,
    ) -> int | dict:
        """
        Get count of suspicious points by status.

        If status is provided, returns int count for that specific status.
        If status is None, returns dict with all status counts.

        Args:
            task_id: Task ID
            status: Optional status to filter by (pending_verify, verifying, pending_pov, etc.)
            harness_name: Optional fuzzer/harness name filter
            sanitizer: Optional sanitizer filter

        Returns:
            int if status specified, dict of counts otherwise
        """
        try:
            # If specific status requested, return count for that status
            if status is not None:
                query = {"task_id": ObjectId(task_id), "status": status}
                # Filter by sources array (not top-level fields)
                if harness_name and sanitizer:
                    query["sources"] = {
                        "$elemMatch": {
                            "harness_name": harness_name,
                            "sanitizer": sanitizer,
                        }
                    }
                return self.collection.count_documents(query)

            # Otherwise return all counts (original behavior)
            total = self.collection.count_documents({"task_id": ObjectId(task_id)})
            checked = self.collection.count_documents(
                {"task_id": ObjectId(task_id), "is_checked": True}
            )
            real = self.collection.count_documents(
                {"task_id": ObjectId(task_id), "is_checked": True, "is_real": True}
            )
            important = self.collection.count_documents(
                {"task_id": ObjectId(task_id), "is_important": True}
            )
            return {
                "total": total,
                "checked": checked,
                "unchecked": total - checked,
                "real": real,
                "false_positive": checked - real,
                "important": important,
            }
        except Exception as e:
            logger.error(f"Failed to count suspicious points: {e}")
            if raise_on_error:
                raise
            if status is not None:
                return 0
            return {
                "total": 0,
                "checked": 0,
                "unchecked": 0,
                "real": 0,
                "false_positive": 0,
                "important": 0,
            }

    # =========================================================================
    # Pipeline Methods (Claim-based task distribution)
    # =========================================================================

    def claim_for_verify(
        self,
        task_id: str,
        processor_id: str,
        harness_name: str = None,
        sanitizer: str = None,
        raise_on_error: bool = False,
    ) -> Optional[SuspiciousPoint]:
        """
        Atomically claim a suspicious point for verification.

        Uses find_one_and_update with atomic operation to prevent race conditions.
        Returns the claimed SP, or None if no SP available.

        Args:
            task_id: Task ID to filter
            processor_id: ID of the agent claiming the task
            harness_name: Filter by harness name (if provided)
            sanitizer: Filter by sanitizer (if provided)

        Returns:
            Claimed SuspiciousPoint, or None if none available
        """
        try:
            from pymongo import ReturnDocument
            from uuid import uuid4
            from ..core.models import SPStatus

            # Build filter query
            query = {
                "task_id": ObjectId(task_id),
                "status": SPStatus.PENDING_VERIFY.value,
            }
            # Filter by sources array for worker isolation
            if harness_name and sanitizer:
                query["sources"] = {
                    "$elemMatch": {"harness_name": harness_name, "sanitizer": sanitizer}
                }

            # Atomic claim: find pending_verify and update to verifying
            claim_token = uuid4().hex
            result = self.collection.find_one_and_update(
                query,
                {
                    "$set": {
                        "status": SPStatus.VERIFYING.value,
                        "processor_id": processor_id,
                        "verification_claim_token": claim_token,
                        # A new lease must never inherit an unfinished
                        # predecessor's verdict. Historical evidence belongs
                        # in append-only receipts, not the active verdict.
                        "verification_result_claim_token": None,
                        "is_checked": False,
                        "is_real": False,
                        "is_important": False,
                        "verification_disposition": None,
                        "verification_refutation_evidence": None,
                        "verification_notes": None,
                        "pov_guidance": None,
                        "verified_by_agent_id": None,
                        "checked_at": None,
                    }
                },
                # Priority: is_important DESC, score DESC, created_at ASC
                sort=[("is_important", -1), ("score", -1),
                      ("created_at", 1), ("_id", 1)],
                return_document=ReturnDocument.AFTER,
            )

            if result:
                logger.debug(
                    f"Claimed SP {result['_id']} for verification by {processor_id}"
                )
                return self.model_class.from_dict(result)
            return None

        except Exception as e:
            logger.error(f"Failed to claim SP for verification: {e}")
            if raise_on_error:
                raise
            return None

    def claim_for_pov(
        self,
        task_id: str,
        processor_id: str,
        min_score: float = 0.5,
        harness_name: str = None,
        sanitizer: str = None,
        raise_on_error: bool = False,
    ) -> Optional[SuspiciousPoint]:
        """
        Claim a suspicious point for POV generation (parallel mode).

        Multiple workers can attempt the same SP simultaneously.
        First to succeed wins and sets pov_success_by.

        Args:
            task_id: Task ID to filter
            processor_id: ID of the agent claiming the task
            min_score: Minimum score threshold for POV generation
            harness_name: Filter by harness name (if provided)
            sanitizer: Filter by sanitizer (if provided)

        Returns:
            Claimed SuspiciousPoint, or None if none available
        """
        try:
            from pymongo import ReturnDocument
            from uuid import uuid4
            from ..core.models import SPStatus

            # A concurrent PoV claim without a stable contributor identity
            # cannot be deduplicated or generation-bound.
            if (type(harness_name) is not str or not harness_name or
                    type(sanitizer) is not str or not sanitizer or
                    type(processor_id) is not str or not processor_id):
                return None
            claim_token = uuid4().hex

            # Build filter query
            query = {
                "task_id": ObjectId(task_id),
                "status": {
                    "$in": [SPStatus.PENDING_POV.value, SPStatus.GENERATING_POV.value]
                },
                "score": {"$gte": min_score},
                "pov_success_by": None,  # Not already succeeded
            }
            # Filter by sources array for worker isolation
            if harness_name and sanitizer:
                query["sources"] = {
                    "$elemMatch": {"harness_name": harness_name, "sanitizer": sanitizer}
                }
                # Exclude SPs that this worker has already attempted
                query["pov_attempted_by"] = {
                    "$not": {
                        "$elemMatch": {
                            "harness_name": harness_name,
                            "sanitizer": sanitizer,
                        }
                    }
                }
                # A contributor that reached a terminal local state must not
                # be admitted again merely because release_claim removed its
                # old attempt row while a sibling kept the shared SP active.
                query["pov_failed_by"] = {
                    "$not": {"$elemMatch": {
                        "harness_name": harness_name,
                        "sanitizer": sanitizer,
                    }}
                }
                query["pov_incomplete_by"] = {
                    "$not": {"$elemMatch": {
                        "harness_name": harness_name,
                        "sanitizer": sanitizer,
                    }}
                }
                query["pov_active_claims"] = {
                    "$not": {"$elemMatch": {
                        "harness_name": harness_name,
                        "sanitizer": sanitizer,
                    }}
                }

            # Parallel claim: add self to attempted list, set status to generating
            attempt_record = {"harness_name": harness_name, "sanitizer": sanitizer}
            active_claim = {
                **attempt_record,
                "processor_id": processor_id,
                "claim_token": claim_token,
            }
            result = self.collection.find_one_and_update(
                query,
                {
                    "$set": {
                        "status": SPStatus.GENERATING_POV.value,
                    },
                    "$addToSet": {
                        "pov_attempted_by": attempt_record,
                        "pov_active_claims": active_claim,
                    },
                },
                # Priority: is_important DESC, score DESC
                sort=[("is_important", -1), ("score", -1),
                      ("created_at", 1), ("_id", 1)],
                return_document=ReturnDocument.AFTER,
            )

            if result:
                logger.debug(
                    f"Claimed SP {result['_id']} for POV generation by {harness_name}/{sanitizer}"
                )
                result = dict(result)
                result["pov_claim_token"] = claim_token
                return self.model_class.from_dict(result)
            return None

        except Exception as e:
            logger.error(f"Failed to claim SP for POV generation: {e}")
            if raise_on_error:
                raise
            return None

    def complete_verify(
        self,
        sp_id: str,
        is_real: bool,
        score: float,
        notes: str = None,
        is_important: bool = False,
        proceed_to_pov: bool = False,
        processor_id: str = None,
        claim_token: str = None,
        verification_disposition: str = None,
    ) -> bool:
        """
        Complete verification of a suspicious point.

        Args:
            sp_id: Suspicious point ID
            is_real: Whether it's a real vulnerability
            score: Updated score
            notes: Verification notes
            is_important: Whether to mark as important
            proceed_to_pov: Whether to proceed to POV generation stage

        Returns:
            True if successful
        """
        try:
            from ..core.models import SPStatus

            # Verifier reasoning cannot establish physical exploit success.
            if is_real is not False:
                return False
            # Determine next status
            # Terminal REFUTED is disabled until a compiler-backed,
            # whole-hypothesis proof exists.  Enforce that invariant in the
            # persistence boundary as well as the model-facing Host so a
            # future queue worker cannot recreate the unsafe transition.
            if verification_disposition not in {
                    None, "TESTABLE_UNCERTAIN", "SUPPORTED"}:
                return False
            explicitly_admitted = verification_disposition in {
                "TESTABLE_UNCERTAIN", "SUPPORTED"}
            if explicitly_admitted and not proceed_to_pov:
                return False
            if proceed_to_pov:
                next_status = SPStatus.PENDING_POV.value
            else:
                # A legacy score/priority gate is not a factual refutation.
                next_status = SPStatus.REVIEWED_NOT_ADMITTED.value

            updates = {
                "status": next_status,
                "processor_id": None,  # Release the lock
                "is_checked": True,
                "is_real": is_real,
                "score": score,
                "is_important": is_important,
                "checked_at": datetime.now(),
            }
            if notes:
                updates["verification_notes"] = notes

            updates["updated_at"] = datetime.now()
            query = {
                "_id": self._convert_id(sp_id),
                "status": SPStatus.VERIFYING.value,
            }
            if processor_id is not None:
                query["processor_id"] = processor_id
            if claim_token is not None:
                query["verification_claim_token"] = claim_token
                query["verification_result_claim_token"] = claim_token
                query["is_checked"] = True
            else:
                query["verification_claim_token"] = {"$exists": False}
            if verification_disposition is not None:
                query["verification_disposition"] = verification_disposition
            else:
                # A caller cannot bypass an already-recorded explicit
                # disposition by omitting it from complete_verify().
                query["$or"] = [
                    {"verification_disposition": {"$exists": False}},
                    {"verification_disposition": None},
                ]
            updates["verification_claim_token"] = None
            result = self.collection.update_one(query, {"$set": updates})
            return result.modified_count > 0

        except Exception as e:
            logger.error(f"Failed to complete verification: {e}")
            return False

    def update_verifier_fields(
        self, sp_id: str, updates: dict, processor_id: str = None,
        claim_token: str = None,
    ) -> bool:
        """Write a Verifier tool result only while its candidate is verifying.

        A cancelled tool may finish after the campaign has sealed its claim.
        Its late verdict must not alter fields on an incomplete candidate.
        """
        try:
            from ..core.models import SPStatus

            allowed = {"is_checked", "is_real", "is_important", "score",
                       "verification_notes", "verification_disposition",
                       "verification_refutation_evidence",
                       "pov_guidance",
                       "reachability_status", "reachability_multiplier",
                       "reachability_reason", "checked_at",
                       "verified_by_agent_id"}
            if not isinstance(updates, dict) or not updates or set(updates) - allowed:
                return False
            if "is_real" in updates and updates["is_real"] is not False:
                return False
            if ("verification_disposition" in updates and
                    updates["verification_disposition"] not in {
                        "TESTABLE_UNCERTAIN", "SUPPORTED"}):
                return False
            if "verification_refutation_evidence" in updates:
                return False
            query = {"_id": self._convert_id(sp_id),
                     "status": SPStatus.VERIFYING.value}
            if processor_id is not None:
                # claim_for_verify stores the process-local agent ID exactly
                # as supplied; it is not a Mongo document reference.
                query["processor_id"] = processor_id
            if claim_token is not None:
                query["verification_claim_token"] = claim_token
            else:
                query["verification_claim_token"] = {"$exists": False}
            result = self.collection.update_one(
                query,
                {"$set": {**updates,
                          "verification_result_claim_token": claim_token,
                          "updated_at": datetime.now()}},
            )
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Failed to update Verifier fields: {e}")
            return False

    @staticmethod
    def _pov_contributor_keys(rows) -> set[tuple[str, str]]:
        if not isinstance(rows, list):
            return set()
        return {
            (row.get("harness_name"), row.get("sanitizer"))
            for row in rows if isinstance(row, dict) and
            isinstance(row.get("harness_name"), str) and
            isinstance(row.get("sanitizer"), str)
        }

    @staticmethod
    def _pov_interruption_terminal(rows):
        """Return the strongest contributor interruption state and reason."""
        from ..core.models import SPStatus

        reasons = [row.get("reason") for row in rows
                   if isinstance(row, dict)]
        if any(reason not in {
                "user_stop_before_transport", "budget_before_transport"
        } for reason in reasons):
            return SPStatus.INCOMPLETE_UNCERTAIN, "uncertain_remote"
        if "budget_before_transport" in reasons:
            return SPStatus.PENDING_BUDGET, "budget_before_transport"
        return SPStatus.PENDING_STOP, "user_stop_before_transport"

    def complete_pov(
        self,
        sp_id: str,
        pov_id: str = None,
        success: bool = True,
        harness_name: str = None,
        sanitizer: str = None,
        local_failure_reason: str = None,
        local_failure_attempts: int = None,
        require_claim: bool = False,
        processor_id: str = None,
        claim_token: str = None,
    ) -> bool:
        """
        Complete POV generation for a suspicious point (parallel mode).

        On success: marks SP as pov_generated, records pov_success_by
        On failure: worker already in pov_attempted_by, check if others still trying

        Args:
            sp_id: Suspicious point ID
            pov_id: Generated POV ID (if successful)
            success: Whether POV generation succeeded
            harness_name: Worker's harness name
            sanitizer: Worker's sanitizer

        Returns:
            True if successful
        """
        try:
            from ..core.models import SPStatus

            if local_failure_reason is not None:
                if (success or local_failure_reason != "invalid_model_tool_json" or
                        type(local_failure_attempts) is not int or
                        local_failure_attempts < 0 or
                        not harness_name or not sanitizer):
                    return False
            # The token is mandatory for every PoV outcome write.  Keeping a
            # boolean compatibility flag must not create a tokenless bypass
            # around the generation lease.
            if not processor_id or not claim_token:
                return False
            active_claim = {
                "harness_name": harness_name,
                "sanitizer": sanitizer,
                "processor_id": processor_id,
                "claim_token": claim_token,
            }
            if success:
                if (not isinstance(pov_id, str) or not pov_id or
                        not isinstance(harness_name, str) or not harness_name or
                        not isinstance(sanitizer, str) or not sanitizer):
                    return False
                # Success - record who succeeded
                success_record = {"harness_name": harness_name, "sanitizer": sanitizer}
                query = {
                    "_id": ObjectId(sp_id),
                    "status": SPStatus.GENERATING_POV.value,
                    "pov_success_by": None,
                    "pov_failed_by": {"$not": {"$elemMatch": success_record}},
                    "pov_incomplete_by": {
                        "$not": {"$elemMatch": success_record}},
                }
                query["sources"] = {"$elemMatch": success_record}
                query["pov_attempted_by"] = {"$elemMatch": success_record}
                query["pov_active_claims"] = {"$elemMatch": active_claim}
                result = self.collection.update_one(
                    query,
                    {
                        "$set": {
                            "status": SPStatus.POV_GENERATED.value,
                            "processor_id": None,
                            "pov_id": pov_id,
                            "pov_success_by": success_record,
                            "pov_generated_at": datetime.now(),
                            "is_real": True,
                            # The shared candidate is terminal.  Retire every
                            # sibling lease atomically so no losing token is
                            # reported as active after the winner commits.
                            "pov_active_claims": [],
                        },
                    },
                )
                if result.modified_count > 0:
                    logger.info(
                        f"SP {sp_id}: POV succeeded by {harness_name}/{sanitizer}"
                    )
                    return True
                else:
                    # Someone else already succeeded
                    logger.info(
                        f"SP {sp_id}: POV succeeded by {harness_name}/{sanitizer} but another worker already won"
                    )
                    return False
            else:
                # A claim records only that a contributor started. Record its
                # terminal failure separately before deciding whether every
                # contributor has finished. Otherwise the first failure can
                # seal a candidate while another contributor is still running.
                contributor = {"harness_name": harness_name,
                               "sanitizer": sanitizer}
                claim_guard = {
                    "pov_active_claims": {"$elemMatch": active_claim}
                }
                additions = {"pov_failed_by": contributor}
                if local_failure_reason is not None:
                    additions["pov_local_failures"] = {
                        **contributor, "reason": local_failure_reason,
                        "pov_attempts": local_failure_attempts}
                recorded = self.collection.update_one(
                    {"_id": ObjectId(sp_id),
                     "status": SPStatus.GENERATING_POV.value,
                     "pov_success_by": None,
                     "sources": {"$elemMatch": contributor},
                     "pov_attempted_by": {"$elemMatch": contributor},
                     "pov_failed_by": {"$not": {"$elemMatch": contributor}},
                     "pov_incomplete_by": {
                         "$not": {"$elemMatch": contributor}},
                     **claim_guard},
                    {"$addToSet": additions,
                     "$pull": {"pov_active_claims": active_claim}},
                )
                if recorded.modified_count != 1:
                    return False
                logger.info(f"SP {sp_id}: POV failed by {harness_name}/{sanitizer}")

                # Only finished contributors count toward terminal failure.
                sp = self.find_by_id(sp_id)
                if sp:
                    sources_set = {
                        (s["harness_name"], s["sanitizer"]) for s in sp.sources
                    }
                    attempted_set = self._pov_contributor_keys(
                        sp.pov_attempted_by)
                    failed_set = self._pov_contributor_keys(sp.pov_failed_by)
                    incomplete_set = self._pov_contributor_keys(
                        sp.pov_incomplete_by)
                    active_set = attempted_set - failed_set - incomplete_set
                    if sp.pov_incomplete_by and not active_set:
                        terminal, reason = self._pov_interruption_terminal(
                            sp.pov_incomplete_by)
                        changed = self.collection.update_one(
                            {"_id": ObjectId(sp_id),
                             "status": SPStatus.GENERATING_POV.value,
                             "pov_success_by": None,
                             "pov_attempted_by": sp.pov_attempted_by,
                             "pov_failed_by": sp.pov_failed_by,
                             "pov_incomplete_by": sp.pov_incomplete_by},
                            {"$set": {
                                "status": terminal.value,
                                "processor_id": None,
                                "pipeline_incomplete_stage": "pov",
                                "pipeline_incomplete_reason": reason,
                                "updated_at": datetime.now(),
                            }},
                        )
                        if changed.modified_count == 1:
                            return True
                        current = self.find_by_id(sp_id)
                        return bool(current is not None and (
                            current.status == SPStatus.POV_GENERATED.value or
                            current.status == terminal.value))
                    if sources_set and sources_set == failed_set and sp.pov_success_by is None:
                        # A concurrent winner or an uncertain-state seal must
                        # not be overwritten by this terminal transition.
                        changed = self.collection.update_one(
                            {"_id": ObjectId(sp_id),
                             "status": SPStatus.GENERATING_POV.value,
                             "pov_success_by": None,
                             "sources": sp.sources,
                             "pov_failed_by": sp.pov_failed_by},
                            {"$set": {"status": SPStatus.FAILED.value,
                                      "updated_at": datetime.now()}},
                        )
                        if changed.modified_count != 1:
                            current = self.find_by_id(sp_id)
                            if (current is None or current.pov_success_by is not None or
                                    contributor not in current.pov_failed_by):
                                return False
                            current_sources = {
                                (s["harness_name"], s["sanitizer"])
                                for s in current.sources}
                            current_failed = {
                                (a["harness_name"], a["sanitizer"])
                                for a in current.pov_failed_by}
                            return (current.status == SPStatus.GENERATING_POV.value or
                                    (current.status == SPStatus.FAILED.value and
                                     current_sources == current_failed))
                        logger.info(
                            f"SP {sp_id}: All contributors failed, marking as FAILED"
                        )
                    # A successful parallel contributor may have won after
                    # the snapshot above. Let the pipeline handle that winner
                    # instead of reporting this losing failure as authoritative.
                    current = self.collection.find_one(
                        {"_id": ObjectId(sp_id)},
                        {"status": 1, "pov_success_by": 1},
                    )
                    return bool(current is not None and
                                current.get("status") in {
                                    SPStatus.GENERATING_POV.value,
                                    SPStatus.FAILED.value,
                                } and current.get("pov_success_by") is None)
                return False

        except Exception as e:
            logger.error(f"Failed to complete POV generation: {e}")
            return False

    def preserve_incomplete_candidate(
        self, sp_id: str, updates: dict, *, stage: str,
        harness_name: str = None, sanitizer: str = None,
        processor_id: str = None, claim_token: str = None,
    ) -> bool:
        """Seal an interrupted claim without overwriting a concurrent winner."""
        try:
            from ..core.models import SPStatus

            expected = (SPStatus.VERIFYING if stage == "verifier" else
                        SPStatus.GENERATING_POV if stage == "pov" else None)
            if expected is None:
                return False
            if stage == "pov":
                reason = updates.get("pipeline_incomplete_reason")
                if (not isinstance(harness_name, str) or not harness_name or
                        not isinstance(sanitizer, str) or not sanitizer or
                        not isinstance(reason, str) or not reason or
                        not isinstance(processor_id, str) or not processor_id or
                        not isinstance(claim_token, str) or not claim_token):
                    return False
                contributor = {"harness_name": harness_name,
                               "sanitizer": sanitizer}
                active_claim = {
                    **contributor,
                    "processor_id": processor_id,
                    "claim_token": claim_token,
                }
                interruption = {**contributor, "reason": reason}
                recorded = self.collection.update_one(
                    {"_id": ObjectId(sp_id),
                     "status": SPStatus.GENERATING_POV.value,
                     "pov_success_by": None,
                     "sources": {"$elemMatch": contributor},
                     "pov_attempted_by": {"$elemMatch": contributor},
                     "pov_failed_by": {
                         "$not": {"$elemMatch": contributor}},
                     "pov_incomplete_by": {
                         "$not": {"$elemMatch": contributor}},
                     "pov_active_claims": {"$elemMatch": active_claim}},
                    {"$addToSet": {"pov_incomplete_by": interruption},
                     "$pull": {"pov_active_claims": active_claim},
                     "$set": {"updated_at": datetime.now()}},
                )
                if recorded.modified_count != 1:
                    # A sibling may already have won the shared candidate by
                    # retaining qualified Runtime/Gate evidence. Preserve this
                    # contributor's terminal stop without downgrading that
                    # authoritative Pending state.
                    recorded = self.collection.update_one(
                        {"_id": ObjectId(sp_id),
                         "status": {"$in": [
                             SPStatus.PENDING_QUALIFIED_RUNTIME.value,
                             SPStatus.PENDING_INDEPENDENT_VALIDATION.value,
                         ]},
                         "pov_success_by": None,
                         "sources": {"$elemMatch": contributor},
                         "pov_attempted_by": {"$elemMatch": contributor},
                         "pov_failed_by": {
                             "$not": {"$elemMatch": contributor}},
                         "pov_incomplete_by": {
                             "$not": {"$elemMatch": contributor}},
                         "pov_active_claims": {"$elemMatch": active_claim}},
                        {"$addToSet": {"pov_incomplete_by": interruption},
                         "$pull": {"pov_active_claims": active_claim},
                         "$set": {"updated_at": datetime.now()}},
                    )
                    if recorded.modified_count == 1:
                        return True
                    current = self.find_by_id(sp_id)
                    if current is None:
                        return False
                    contributor_key = (harness_name, sanitizer)
                    # A sibling's Pending evidence alone does not prove that
                    # this contributor's stop was saved. Only its own durable
                    # incomplete row (or a final sibling success that makes
                    # loser bookkeeping non-authoritative) can settle it.
                    return bool(
                        current.status == SPStatus.POV_GENERATED.value and
                        contributor_key in self._pov_contributor_keys(
                            current.pov_attempted_by) or
                        contributor_key in self._pov_contributor_keys(
                            current.pov_incomplete_by) and
                        current.status in {
                            SPStatus.GENERATING_POV.value,
                            SPStatus.PENDING_QUALIFIED_RUNTIME.value,
                            SPStatus.PENDING_INDEPENDENT_VALIDATION.value,
                            SPStatus.PENDING_STOP.value,
                            SPStatus.PENDING_BUDGET.value,
                            SPStatus.INCOMPLETE_UNCERTAIN.value})
                current = self.find_by_id(sp_id)
                if current is None:
                    return False
                attempted = self._pov_contributor_keys(
                    current.pov_attempted_by)
                settled = (self._pov_contributor_keys(current.pov_failed_by) |
                           self._pov_contributor_keys(current.pov_incomplete_by))
                if attempted - settled:
                    # A sibling contributor is already in flight. Keep the
                    # shared candidate writable so its success can win.
                    return True
                terminal, terminal_reason = self._pov_interruption_terminal(
                    current.pov_incomplete_by)
                terminal_updates = {
                    **updates,
                    "status": terminal.value,
                    "processor_id": None,
                    "pipeline_incomplete_reason": terminal_reason,
                    "pipeline_incomplete_stage": "pov",
                    "updated_at": datetime.now(),
                }
                changed = self.collection.update_one(
                    {"_id": ObjectId(sp_id),
                     "status": SPStatus.GENERATING_POV.value,
                     "pov_success_by": None,
                     "pov_attempted_by": current.pov_attempted_by,
                     "pov_failed_by": current.pov_failed_by,
                     "pov_incomplete_by": current.pov_incomplete_by},
                    {"$set": terminal_updates},
                )
                if changed.modified_count == 1:
                    return True
                latest = self.find_by_id(sp_id)
                if latest is None:
                    return False
                if (latest.status == SPStatus.POV_GENERATED.value or
                        latest.status == terminal.value):
                    return True
                latest_active = (
                    self._pov_contributor_keys(latest.pov_attempted_by) -
                    self._pov_contributor_keys(latest.pov_failed_by) -
                    self._pov_contributor_keys(latest.pov_incomplete_by))
                return (latest.status == SPStatus.GENERATING_POV.value and
                        bool(latest_active))
            query = {"_id": ObjectId(sp_id), "status": expected.value}
            if stage == "verifier":
                if not processor_id or not claim_token:
                    return False
                query.update({
                    "processor_id": processor_id,
                    "verification_claim_token": claim_token,
                })
                updates = {**updates, "verification_claim_token": None}
            result = self.collection.update_one(
                query, {"$set": {**updates, "updated_at": datetime.now()}})
            return result.modified_count == 1
        except Exception as exc:
            logger.error(f"Failed to preserve incomplete SP: {exc}")
            return False

    def preserve_pov_pending_runtime(
        self, sp_id: str, pov_ids: List[str], *, task_id: str,
        harness_name: str, sanitizer: str, validation_pending: bool = False,
        processor_id: str = None, claim_token: str = None,
    ) -> bool:
        """Retain generated PoV bytes without claiming execution or success.

        This opt-in transition is deliberately not included in claim_for_pov.
        A later qualified Runtime consumer must recheck each retained hash.
        """
        try:
            from ..core.models import SPStatus

            if (not pov_ids or len(set(pov_ids)) != len(pov_ids) or
                    any(not ObjectId.is_valid(value) for value in pov_ids) or
                    not ObjectId.is_valid(sp_id) or not ObjectId.is_valid(task_id) or
                    not harness_name or not sanitizer or
                    not processor_id or not claim_token):
                return False
            artifacts = []
            observed_crash = False
            for pov_id in pov_ids:
                record = self.db["povs"].find_one({"_id": ObjectId(pov_id)})
                if (not isinstance(record, dict) or
                        record.get("task_id") != ObjectId(task_id) or
                        record.get("suspicious_point_id") != ObjectId(sp_id) or
                        record.get("harness_name") != harness_name or
                        record.get("sanitizer") != sanitizer or
                        record.get("is_successful") is not False or
                        not record.get("is_active") or
                        not isinstance(record.get("blob"), str)):
                    return False
                try:
                    blob = base64.b64decode(record["blob"], validate=True)
                except (ValueError, binascii.Error):
                    return False
                if not blob or len(blob) > 2_097_152:
                    return False
                runtime = record.get("qualified_runtime")
                if validation_pending:
                    if (not isinstance(runtime, dict) or
                            runtime.get("status") != "CRASH_OBSERVED" or
                            runtime.get("input_sha256") !=
                            hashlib.sha256(blob).hexdigest() or
                            not isinstance(runtime.get("binary_sha256"), str) or
                            not re.fullmatch(r"[0-9a-f]{64}",
                                             runtime["binary_sha256"]) or
                            not isinstance(runtime.get("sanitizer"), str) or
                            not runtime["sanitizer"]):
                        return False
                    for path_key, sha_key in (
                        ("runtime_receipt_path", "runtime_receipt_sha256"),
                        ("physical_receipt_path", "physical_receipt_sha256"),
                    ):
                        receipt_path = Path(runtime.get(path_key, ""))
                        if (not receipt_path.is_absolute() or
                                receipt_path.is_symlink() or
                                any(parent.is_symlink()
                                    for parent in receipt_path.parents) or
                                not receipt_path.is_file() or
                                receipt_path.stat().st_size > 16_000_000 or
                                hashlib.sha256(receipt_path.read_bytes()).hexdigest()
                                != runtime.get(sha_key)):
                            return False
                    observed_crash = True
                blob_path = record.get("blob_path")
                if blob_path is not None:
                    path = Path(blob_path)
                    if (path.is_symlink() or any(parent.is_symlink()
                                                for parent in path.parents) or
                            not path.is_file() or path.stat().st_size != len(blob) or
                            path.read_bytes() != blob):
                        return False
                artifacts.append({
                    "pov_id": pov_id,
                    "blob_sha256": hashlib.sha256(blob).hexdigest(),
                    "blob_path": blob_path,
                    "harness_name": harness_name,
                    "sanitizer": sanitizer,
                    **({"qualified_runtime": runtime} if validation_pending else {}),
                })
            if validation_pending and not observed_crash:
                return False
            contributor = {"harness_name": harness_name,
                           "sanitizer": sanitizer}
            active_claim = {
                **contributor,
                "processor_id": processor_id,
                "claim_token": claim_token,
            }
            query = {
                 "_id": ObjectId(sp_id), "task_id": ObjectId(task_id),
                 "pov_success_by": None,
                 "sources": {"$elemMatch": contributor},
                 "pov_attempted_by": {"$elemMatch": contributor},
                 "pov_failed_by": {"$not": {"$elemMatch": contributor}},
                 "pov_incomplete_by": {"$not": {"$elemMatch": contributor}},
                 "pov_active_claims": {"$elemMatch": active_claim},
            }
            if validation_pending:
                query["status"] = {"$in": [
                    SPStatus.GENERATING_POV.value,
                    SPStatus.PENDING_QUALIFIED_RUNTIME.value,
                    SPStatus.PENDING_INDEPENDENT_VALIDATION.value,
                ]}
                status = SPStatus.PENDING_INDEPENDENT_VALIDATION.value
            else:
                query["status"] = {"$in": [
                    SPStatus.GENERATING_POV.value,
                    SPStatus.PENDING_QUALIFIED_RUNTIME.value,
                ]}
                status = SPStatus.PENDING_QUALIFIED_RUNTIME.value
            result = self.collection.update_one(
                query,
                {"$set": {
                    "status": status,
                    "processor_id": None,
                    "pipeline_incomplete_stage": ("independent_validation"
                                                  if validation_pending else
                                                  "qualified_runtime"),
                    "pipeline_incomplete_reason": (
                        "runtime_crash_observed_gate_pending"
                        if validation_pending else "pov_generated_runtime_pending"),
                 },
                 "$addToSet": {
                     "pending_pov_ids": {"$each": list(pov_ids)},
                     "pending_pov_artifacts": {"$each": artifacts},
                     "pov_settled_claims": active_claim,
                 },
                 "$pull": {"pov_active_claims": active_claim}},
            )
            if result.modified_count == 1:
                return True
            if not validation_pending:
                # A crash observed by a sibling is stronger than this normal
                # Runtime-pending contribution. Preserve the latter without
                # downgrading the shared independent-validation state.
                query["status"] = SPStatus.PENDING_INDEPENDENT_VALIDATION.value
                result = self.collection.update_one(
                    query, {"$addToSet": {
                        "pending_pov_ids": {"$each": list(pov_ids)},
                        "pending_pov_artifacts": {"$each": artifacts},
                        "pov_settled_claims": active_claim,
                    }, "$pull": {"pov_active_claims": active_claim}})
                if result.modified_count == 1:
                    return True
            current = self.collection.find_one({
                "_id": ObjectId(sp_id), "task_id": ObjectId(task_id),
                "pov_success_by": None,
                "sources": {"$elemMatch": contributor},
                "pov_attempted_by": {"$elemMatch": contributor},
                "pov_failed_by": {"$not": {"$elemMatch": contributor}},
                "pov_incomplete_by": {"$not": {"$elemMatch": contributor}},
                "pov_settled_claims": {"$elemMatch": active_claim},
                "status": {"$in": [
                    SPStatus.PENDING_QUALIFIED_RUNTIME.value,
                    SPStatus.PENDING_INDEPENDENT_VALIDATION.value,
                ]},
            }, {"pending_pov_ids": 1})
            return bool(current is not None and
                        set(pov_ids) <= set(current.get("pending_pov_ids", [])))
        except (OSError, ValueError, TypeError) as exc:
            logger.error(f"Failed to retain PoV inputs pending Runtime: {exc}")
            return False

    def release_claim(
        self,
        sp_id: str,
        revert_status: str = None,
        harness_name: str = None,
        sanitizer: str = None,
        processor_id: str = None,
        claim_token: str = None,
    ) -> bool:
        """
        Release a claimed SP (e.g., on agent failure).

        Args:
            sp_id: Suspicious point ID
            revert_status: Status to revert to (if None, keeps current status)
            harness_name: If provided with sanitizer, also remove from pov_attempted_by
                         so the same worker can retry on crash recovery
            sanitizer: If provided with harness_name, also remove from pov_attempted_by

        Returns:
            True if successful
        """
        try:
            from ..core.models import SPStatus

            update_ops = {"$set": {"processor_id": None, "updated_at": datetime.now()}}
            if revert_status:
                update_ops["$set"]["status"] = revert_status
            # Clean up pov_attempted_by so same worker can retry after crash
            if harness_name and sanitizer:
                update_ops["$pull"] = {
                    "pov_attempted_by": {
                        "harness_name": harness_name,
                        "sanitizer": sanitizer,
                    }
                }

            _id = self._convert_id(sp_id)
            if revert_status == SPStatus.PENDING_POV.value:
                if (not harness_name or not sanitizer or not processor_id or
                        not claim_token):
                    return False
                contributor = {"harness_name": harness_name,
                               "sanitizer": sanitizer}
                active_claim = {
                    **contributor,
                    "processor_id": processor_id,
                    "claim_token": claim_token,
                }
                # All contributor lists form one CAS snapshot. A sibling may
                # fail or stop between read and write; retry against the new
                # snapshot instead of leaving a zero-active GENERATING_POV.
                for _ in range(4):
                    current = self.collection.find_one({
                        "_id": _id,
                        "status": SPStatus.GENERATING_POV.value,
                        "pov_success_by": None,
                        "pov_attempted_by": {"$elemMatch": contributor},
                        "pov_active_claims": {"$elemMatch": active_claim},
                    })
                    if current is None:
                        return False
                    attempted = current.get("pov_attempted_by", [])
                    failed_rows = current.get("pov_failed_by", [])
                    incomplete_rows = current.get("pov_incomplete_by", [])
                    remaining = [row for row in attempted if not (
                        isinstance(row, dict) and
                        row.get("harness_name") == harness_name and
                        row.get("sanitizer") == sanitizer)]
                    failed = self._pov_contributor_keys(failed_rows)
                    incomplete = self._pov_contributor_keys(incomplete_rows)
                    active = (self._pov_contributor_keys(remaining) - failed -
                              incomplete)
                    next_status = (SPStatus.GENERATING_POV.value if active else
                                   SPStatus.PENDING_POV.value)
                    query = {
                        "_id": _id,
                        "status": SPStatus.GENERATING_POV.value,
                        "pov_success_by": None,
                        "pov_attempted_by": attempted,
                        "pov_active_claims": {"$elemMatch": active_claim},
                    }
                    # Preserve the complete contributor-list snapshot without
                    # confusing an absent legacy field with a stored empty
                    # array. ``current.get(..., [])`` is appropriate for the
                    # state calculation above, but an equality predicate for
                    # ``[]`` does not match a missing field in every Mongo
                    # implementation (notably mongomock).  Keep the CAS exact
                    # by pinning either the observed value or its absence.
                    for field, rows in (
                        ("pov_failed_by", failed_rows),
                        ("pov_incomplete_by", incomplete_rows),
                    ):
                        query[field] = (rows if field in current else
                                        {"$exists": False})
                    result = self.collection.update_one(
                        query, {"$set": {
                            "status": next_status,
                            "processor_id": None,
                            "pov_attempted_by": remaining,
                            "updated_at": datetime.now(),
                        }, "$pull": {"pov_active_claims": active_claim}})
                    if result.modified_count == 1:
                        return True
                return False
            query = {"_id": _id}
            if revert_status in (SPStatus.PENDING_VERIFY.value,
                                 SPStatus.FAILED.value):
                # Every active Verifier lease is tokenized.  A legacy or
                # tokenless caller must not be able to release a current
                # worker, even when it knows the candidate ID.
                if not processor_id or not claim_token:
                    return False
                query["status"] = SPStatus.VERIFYING.value
            elif revert_status is None:
                if claim_token is not None:
                    if not processor_id:
                        return False
                    query["status"] = SPStatus.VERIFYING.value
                elif harness_name and sanitizer:
                    query["status"] = SPStatus.GENERATING_POV.value
                else:
                    return False
            else:
                return False
            if processor_id is not None:
                query["processor_id"] = processor_id
            if (revert_status in (SPStatus.PENDING_VERIFY.value,
                                  SPStatus.FAILED.value) or
                    (revert_status is None and claim_token is not None)):
                if claim_token is None:
                    query["verification_claim_token"] = {"$exists": False}
                else:
                    query["verification_claim_token"] = claim_token
                update_ops["$set"]["verification_claim_token"] = None
                update_ops["$set"]["verification_result_claim_token"] = None
                if revert_status == SPStatus.PENDING_VERIFY.value:
                    update_ops["$set"].update({
                        "is_checked": False,
                        "is_real": False,
                        "is_important": False,
                        "verification_disposition": None,
                        "verification_refutation_evidence": None,
                        "verification_notes": None,
                        "pov_guidance": None,
                        "verified_by_agent_id": None,
                        "checked_at": None,
                    })
            if harness_name and sanitizer:
                query["pov_attempted_by"] = {"$elemMatch": {
                    "harness_name": harness_name,
                    "sanitizer": sanitizer,
                }}
            result = self.collection.update_one(query, update_ops)
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Failed to release claim: {e}")
            return False

    def count_by_pipeline_status(self, task_id: str) -> dict:
        """Get count of suspicious points by pipeline status"""
        try:
            from ..core.models import SPStatus

            counts = {
                "pending_verify": 0,
                "verifying": 0,
                "verified": 0,
                "pending_pov": 0,
                "generating_pov": 0,
                "pov_generated": 0,
                "failed": 0,
            }

            for status in SPStatus:
                counts[status.value] = self.collection.count_documents(
                    {
                        "task_id": ObjectId(task_id),
                        "status": status.value,
                    }
                )

            counts["total"] = sum(counts.values())
            return counts

        except Exception as e:
            logger.error(f"Failed to count by pipeline status: {e}")
            return {"total": 0}

    def is_pipeline_complete(
        self,
        task_id: str,
        harness_name: str = None,
        sanitizer: str = None,
    ) -> bool:
        """
        Check if all SPs have finished processing for this worker.

        For verify stage: checks pending_verify and verifying
        For POV stage (parallel mode): checks if there are SPs that:
            - This worker is a contributor (in sources)
            - Not yet succeeded (pov_success_by is None)
            - This worker hasn't attempted yet

        Args:
            task_id: Task ID to filter
            harness_name: Filter by harness name (if provided)
            sanitizer: Filter by sanitizer (if provided)

        Returns:
            True if no more work for this worker
        """
        try:
            from ..core.models import SPStatus

            if harness_name and sanitizer:
                # Check verify stage SPs
                verify_query = {
                    "task_id": ObjectId(task_id),
                    "status": {
                        "$in": [SPStatus.PENDING_VERIFY.value,
                                SPStatus.VERIFYING.value,
                                SPStatus.PENDING_BUDGET.value,
                                SPStatus.PENDING_STOP.value,
                                SPStatus.INCOMPLETE_UNCERTAIN.value,
                                SPStatus.PENDING_QUALIFIED_RUNTIME.value,
                                SPStatus.PENDING_INDEPENDENT_VALIDATION.value]
                    },
                    "sources": {
                        "$elemMatch": {
                            "harness_name": harness_name,
                            "sanitizer": sanitizer,
                        }
                    },
                }
                verify_pending = self.collection.count_documents(verify_query)

                # Check POV stage SPs (parallel mode)
                # SP is available if: contributor + not succeeded + not attempted by me
                pov_query = {
                    "task_id": ObjectId(task_id),
                    "status": {
                        "$in": [
                            SPStatus.PENDING_POV.value,
                            SPStatus.GENERATING_POV.value,
                            SPStatus.PENDING_BUDGET.value,
                            SPStatus.PENDING_STOP.value,
                            SPStatus.INCOMPLETE_UNCERTAIN.value,
                            SPStatus.PENDING_QUALIFIED_RUNTIME.value,
                            SPStatus.PENDING_INDEPENDENT_VALIDATION.value,
                        ]
                    },
                    "sources": {
                        "$elemMatch": {
                            "harness_name": harness_name,
                            "sanitizer": sanitizer,
                        }
                    },
                    "pov_success_by": None,  # Not already succeeded
                    "pov_attempted_by": {
                        "$not": {
                            "$elemMatch": {
                                "harness_name": harness_name,
                                "sanitizer": sanitizer,
                            }
                        }
                    },
                }
                pov_pending = self.collection.count_documents(pov_query)

                return verify_pending == 0 and pov_pending == 0
            else:
                # No worker filter - check all pending/in-progress
                query = {
                    "task_id": ObjectId(task_id),
                    "status": {
                        "$in": [
                            SPStatus.PENDING_VERIFY.value,
                            SPStatus.VERIFYING.value,
                            SPStatus.PENDING_POV.value,
                            SPStatus.GENERATING_POV.value,
                            SPStatus.PENDING_BUDGET.value,
                            SPStatus.PENDING_STOP.value,
                            SPStatus.INCOMPLETE_UNCERTAIN.value,
                            SPStatus.PENDING_QUALIFIED_RUNTIME.value,
                            SPStatus.PENDING_INDEPENDENT_VALIDATION.value,
                        ]
                    },
                }
                in_progress = self.collection.count_documents(query)
                return in_progress == 0

        except Exception as e:
            logger.error(f"Failed to check pipeline completion: {e}")
            return False


class DirectionRepository(BaseRepository[Direction]):
    """Repository for Direction model (Full-scan analysis directions)"""

    def __init__(self, db: Database):
        super().__init__(db, "directions", Direction)
        # Create indexes for faster queries
        self._ensure_indexes()

    def _ensure_indexes(self):
        """Create indexes for common query patterns."""
        try:
            self.collection.create_index("task_id")
            self.collection.create_index("status")
            self.collection.create_index("fuzzer")
            self.collection.create_index([("task_id", 1), ("fuzzer", 1)])
            self.collection.create_index([("task_id", 1), ("status", 1)])
            self.collection.create_index([("task_id", 1), ("fuzzer", 1), ("status", 1)])
        except Exception as e:
            logger.debug(f"Index creation for directions: {e}")

    def find_by_task(self, task_id: str) -> List[Direction]:
        """Find all directions for a task"""
        return self.find_all({"task_id": ObjectId(task_id)})

    def find_by_fuzzer(self, task_id: str, fuzzer: str) -> List[Direction]:
        """Find all directions for a specific fuzzer"""
        return self.find_all({"task_id": ObjectId(task_id), "fuzzer": fuzzer})

    def find_pending(self, task_id: str, fuzzer: str = None) -> List[Direction]:
        """Find pending directions"""
        query = {"task_id": ObjectId(task_id), "status": DirectionStatus.PENDING.value}
        if fuzzer:
            query["fuzzer"] = fuzzer
        return self.find_all(query)

    def find_by_priority(self, task_id: str, fuzzer: str = None) -> List[Direction]:
        """Find directions sorted by priority (high risk first)"""
        try:
            query = {"task_id": ObjectId(task_id)}
            if fuzzer:
                query["fuzzer"] = fuzzer
            # Sort by risk level (high > medium > low) and then by created_at
            cursor = self.collection.find(query).sort(
                [
                    (
                        "risk_level",
                        1,
                    ),  # 'high' < 'low' < 'medium' alphabetically, need custom sort
                    ("created_at", 1),
                ]
            )
            directions = [self.model_class.from_dict(doc) for doc in cursor]
            # Custom sort by priority score (descending)
            return sorted(
                directions, key=lambda d: d.get_priority_score(), reverse=True
            )
        except Exception as e:
            logger.error(f"Failed to find directions by priority: {e}")
            return []

    def claim(
        self, task_id: str, fuzzer: str, processor_id: str
    ) -> Optional[Direction]:
        """
        Atomically claim a direction for analysis.

        Args:
            task_id: Task ID
            fuzzer: Fuzzer name
            processor_id: ID of the agent claiming

        Returns:
            Claimed Direction, or None if none available
        """
        try:
            from pymongo import ReturnDocument

            # Find pending directions, prioritize high risk
            # Custom sort needed because risk_level is string
            pending = self.find_pending(task_id, fuzzer)
            if not pending:
                return None

            # Sort by priority
            pending.sort(key=lambda d: d.get_priority_score(), reverse=True)
            target = pending[0]

            # Atomic claim
            result = self.collection.find_one_and_update(
                {
                    "_id": ObjectId(target.direction_id),
                    "status": DirectionStatus.PENDING.value,
                },
                {
                    "$set": {
                        "status": DirectionStatus.IN_PROGRESS.value,
                        "processor_id": processor_id,
                        "started_at": datetime.now(),
                    }
                },
                return_document=ReturnDocument.AFTER,
            )

            if result:
                logger.debug(f"Claimed direction {result['_id']} by {processor_id}")
                return self.model_class.from_dict(result)
            return None

        except Exception as e:
            logger.error(f"Failed to claim direction: {e}")
            return None

    def complete(
        self,
        direction_id: str,
        sp_count: int = 0,
        functions_analyzed: int = 0,
    ) -> bool:
        """
        Mark direction as completed.

        Args:
            direction_id: Direction ID
            sp_count: Number of SPs found
            functions_analyzed: Number of functions analyzed

        Returns:
            True if successful
        """
        return self.update(
            direction_id,
            {
                "status": DirectionStatus.COMPLETED.value,
                "processor_id": None,
                "sp_count": sp_count,
                "functions_analyzed": functions_analyzed,
                "completed_at": datetime.now(),
            },
        )

    def skip(self, direction_id: str, reason: str = "") -> bool:
        """Mark direction as skipped"""
        updates = {
            "status": DirectionStatus.SKIPPED.value,
            "processor_id": None,
            "completed_at": datetime.now(),
        }
        if reason:
            updates["risk_reason"] = f"Skipped: {reason}"
        return self.update(direction_id, updates)

    def release_claim(self, direction_id: str) -> bool:
        """Release a claimed direction (e.g., on agent failure)"""
        return self.update(
            direction_id,
            {
                "status": DirectionStatus.PENDING.value,
                "processor_id": None,
                "started_at": None,
            },
        )

    def count_by_status(self, task_id: str, fuzzer: str = None) -> dict:
        """Get count of directions by status"""
        try:
            query = {"task_id": ObjectId(task_id)}
            if fuzzer:
                query["fuzzer"] = fuzzer

            counts = {
                "pending": 0,
                "in_progress": 0,
                "completed": 0,
                "skipped": 0,
            }

            for status in DirectionStatus:
                q = {**query, "status": status.value}
                counts[status.value] = self.collection.count_documents(q)

            counts["total"] = sum(counts.values())
            return counts

        except Exception as e:
            logger.error(f"Failed to count directions by status: {e}")
            return {"total": 0}

    def is_all_complete(self, task_id: str, fuzzer: str = None) -> bool:
        """Check if all directions are completed or skipped"""
        try:
            query = {"task_id": ObjectId(task_id)}
            if fuzzer:
                query["fuzzer"] = fuzzer
            query["status"] = {
                "$in": [
                    DirectionStatus.PENDING.value,
                    DirectionStatus.IN_PROGRESS.value,
                ]
            }
            pending = self.collection.count_documents(query)
            return pending == 0
        except Exception as e:
            logger.error(f"Failed to check direction completion: {e}")
            return False

    def get_stats(self, task_id: str, fuzzer: str = None) -> dict:
        """Get statistics for directions"""
        try:
            query = {"task_id": ObjectId(task_id)}
            if fuzzer:
                query["fuzzer"] = fuzzer

            pipeline = [
                {"$match": query},
                {
                    "$group": {
                        "_id": None,
                        "total_directions": {"$sum": 1},
                        "total_sp_count": {"$sum": "$sp_count"},
                        "total_functions_analyzed": {"$sum": "$functions_analyzed"},
                        "completed": {
                            "$sum": {"$cond": [{"$eq": ["$status", "completed"]}, 1, 0]}
                        },
                        "high_risk": {
                            "$sum": {"$cond": [{"$eq": ["$risk_level", "high"]}, 1, 0]}
                        },
                        "medium_risk": {
                            "$sum": {
                                "$cond": [{"$eq": ["$risk_level", "medium"]}, 1, 0]
                            }
                        },
                        "low_risk": {
                            "$sum": {"$cond": [{"$eq": ["$risk_level", "low"]}, 1, 0]}
                        },
                    }
                },
            ]

            result = list(self.collection.aggregate(pipeline))
            if result:
                stats = result[0]
                del stats["_id"]
                return stats
            return {
                "total_directions": 0,
                "total_sp_count": 0,
                "total_functions_analyzed": 0,
                "completed": 0,
                "high_risk": 0,
                "medium_risk": 0,
                "low_risk": 0,
            }

        except Exception as e:
            logger.error(f"Failed to get direction stats: {e}")
            return {}

    def delete_by_task(self, task_id: str) -> int:
        """Delete all directions for a task"""
        try:
            result = self.collection.delete_many({"task_id": ObjectId(task_id)})
            return result.deleted_count
        except Exception as e:
            logger.error(f"Failed to delete directions for task: {e}")
            return 0


class WorkerRepository(BaseRepository[Worker]):
    """
    Repository for Worker model.

    Workers use MongoDB ObjectId as primary key.
    Queries by task_id also use ObjectId.
    """

    def __init__(self, db: Database):
        super().__init__(db, "workers", Worker)

    def find_by_id(self, worker_id: str) -> Optional[Worker]:
        """Find worker by ObjectId string."""
        try:
            data = self.collection.find_one({"_id": ObjectId(worker_id)})
            if data:
                return Worker.from_dict(data)
            return None
        except Exception as e:
            logger.error(f"Failed to find Worker by id: {e}")
            return None

    def find_by_task(self, task_id: str) -> List[Worker]:
        """Find all workers for a task (by ObjectId)."""
        try:
            # task_id is stored as ObjectId in workers collection
            cursor = self.collection.find({"task_id": ObjectId(task_id)})
            return [Worker.from_dict(doc) for doc in cursor]
        except Exception as e:
            logger.error(f"Failed to find workers by task: {e}")
            return []

    def find_running_by_task(self, task_id: str) -> List[Worker]:
        """Find running workers for a task."""
        try:
            cursor = self.collection.find(
                {"task_id": ObjectId(task_id), "status": "running"}
            )
            return [Worker.from_dict(doc) for doc in cursor]
        except Exception as e:
            logger.error(f"Failed to find running workers: {e}")
            return []

    def find_by_status(self, status: str) -> List[Worker]:
        """Find workers by status"""
        return self.find_all({"status": status})

    def find_by_fuzzer(
        self, task_id: str, fuzzer: str, sanitizer: str
    ) -> Optional[Worker]:
        """Find worker by task, fuzzer, and sanitizer."""
        try:
            data = self.collection.find_one(
                {
                    "task_id": ObjectId(task_id),
                    "fuzzer": fuzzer,
                    "sanitizer": sanitizer,
                }
            )
            if data:
                return Worker.from_dict(data)
            return None
        except Exception as e:
            logger.error(f"Failed to find worker by fuzzer: {e}")
            return None

    # Fields managed exclusively by WorkerLLMBuffer via $inc.
    # Must NOT be included in save() to avoid overwriting buffer increments.
    _LLM_FIELDS = ("llm_calls", "llm_cost", "llm_input_tokens", "llm_output_tokens")

    def save(self, worker: Worker) -> bool:
        """Save worker to database (upsert by ObjectId).

        Uses $set instead of replace_one to avoid overwriting llm_* fields
        that are managed by WorkerLLMBuffer via atomic $inc.
        """
        try:
            data = worker.to_dict()
            # Ensure _id is ObjectId
            if isinstance(data.get("_id"), str):
                data["_id"] = ObjectId(data["_id"])
            doc_id = data.pop("_id")
            for key in self._LLM_FIELDS:
                data.pop(key, None)
            self.collection.update_one({"_id": doc_id}, {"$set": data}, upsert=True)
            return True
        except Exception as e:
            logger.error(f"Failed to save Worker: {e}")
            return False

    def update(self, worker_id: str, updates: dict) -> bool:
        """Update worker fields by ObjectId."""
        try:
            updates["updated_at"] = datetime.now()
            result = self.collection.update_one(
                {"_id": ObjectId(worker_id)}, {"$set": updates}
            )
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Failed to update Worker: {e}")
            return False

    def update_status(self, worker_id: str, status: str, error_msg: str = None) -> bool:
        """Update worker status"""
        updates = {"status": status}
        if error_msg:
            updates["error_msg"] = error_msg
        return self.update(worker_id, updates)

    def update_results(self, worker_id: str, povs: int = 0, patches: int = 0) -> bool:
        """Update worker results"""
        return self.update(
            worker_id, {"pov_generated": povs, "patch_generated": patches}
        )

    def update_strategy(self, worker_id: str, strategy: str) -> bool:
        """Update current strategy and add to history"""
        try:
            result = self.collection.update_one(
                {"_id": ObjectId(worker_id)},
                {
                    "$set": {
                        "current_strategy": strategy,
                        "updated_at": datetime.now(),
                    },
                    "$push": {"strategy_history": strategy},
                },
            )
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Failed to update worker strategy: {e}")
            return False


class FuzzerRepository(BaseRepository[Fuzzer]):
    """Repository for Fuzzer model"""

    def __init__(self, db: Database):
        super().__init__(db, "fuzzers", Fuzzer)

    def find_by_task(self, task_id: str) -> List[Fuzzer]:
        """Find all fuzzers for a task"""
        return self.find_all({"task_id": ObjectId(task_id)})

    def find_successful_by_task(self, task_id: str) -> List[Fuzzer]:
        """Find successfully built fuzzers"""
        return self.find_all({"task_id": ObjectId(task_id), "status": "success"})

    def find_by_name(self, task_id: str, fuzzer_name: str) -> Optional[Fuzzer]:
        """Find fuzzer by task and name"""
        return self.find_one({"task_id": ObjectId(task_id), "fuzzer_name": fuzzer_name})

    def update_status(
        self,
        fuzzer_id: str,
        status: str,
        error_msg: str = None,
        binary_path: str = None,
    ) -> bool:
        """Update fuzzer build status"""
        updates = {"status": status}
        if error_msg:
            updates["error_msg"] = error_msg
        if binary_path:
            updates["binary_path"] = binary_path
        return self.update(fuzzer_id, updates)


class FunctionRepository(BaseRepository[Function]):
    """Repository for Function model (static analysis metadata)"""

    def __init__(self, db: Database):
        super().__init__(db, "functions", Function)
        # Create indexes for faster queries
        self._ensure_indexes()

    def _ensure_indexes(self):
        """Create indexes for common query patterns."""
        try:
            self.collection.create_index("task_id")
            self.collection.create_index("name")
            self.collection.create_index([("task_id", 1), ("name", 1)])
            self.collection.create_index([("task_id", 1), ("file_path", 1)])
            # SP Find v2: Index for analysis tracking
            self.collection.create_index(
                [("task_id", 1), ("analyzed_by_directions", 1)]
            )
            self.collection.create_index([("task_id", 1), ("reached_by_fuzzers", 1)])
        except Exception as e:
            logger.debug(f"Index creation for functions: {e}")

    def find_by_task(self, task_id: str) -> List[Function]:
        """Find all functions for a task"""
        return self.find_all({"task_id": ObjectId(task_id)})

    def find_by_name(self, task_id: str, name: str) -> Optional[Function]:
        """Find function by task and name"""
        # First try by constructed ID
        function_id = f"{task_id}_{name}"
        result = self.find_by_id(function_id)
        if result:
            return result
        # Fallback: query by task_id + name fields (for legacy data)
        return self.find_one({"task_id": ObjectId(task_id), "name": name})

    def find_by_file(self, task_id: str, file_path: str) -> List[Function]:
        """Find all functions in a specific file"""
        return self.find_all({"task_id": ObjectId(task_id), "file_path": file_path})

    def save_many(self, functions: List[Function]) -> int:
        """
        Bulk save functions.

        Returns:
            Number of functions saved successfully
        """
        if not functions:
            return 0
        try:
            docs = [f.to_dict() for f in functions]
            # Use bulk write with upsert
            from pymongo import UpdateOne

            operations = [
                UpdateOne({"_id": doc["_id"]}, {"$set": doc}, upsert=True)
                for doc in docs
            ]
            result = self.collection.bulk_write(operations)
            return result.upserted_count + result.modified_count
        except Exception as e:
            logger.error(f"Failed to bulk save functions: {e}")
            return 0

    def delete_by_task(self, task_id: str) -> int:
        """Delete all functions for a task"""
        try:
            result = self.collection.delete_many({"task_id": ObjectId(task_id)})
            return result.deleted_count
        except Exception as e:
            logger.error(f"Failed to delete functions for task: {e}")
            return 0

    # =========================================================================
    # SP Find v2: Analysis Tracking Methods
    # =========================================================================

    def mark_analyzed_by_direction(self, function_id: str, direction_id: str) -> bool:
        """
        Mark a function as analyzed by a specific direction.

        Uses $addToSet to prevent duplicates.

        Args:
            function_id: Function ID
            direction_id: Direction ID that analyzed this function

        Returns:
            True if successful
        """
        try:
            result = self.collection.update_one(
                {"_id": function_id},
                {"$addToSet": {"analyzed_by_directions": ObjectId(direction_id)}},
            )
            return result.modified_count > 0 or result.matched_count > 0
        except Exception as e:
            logger.error(f"Failed to mark function as analyzed: {e}")
            return False

    def mark_many_analyzed(self, function_ids: List[str], direction_id: str) -> int:
        """
        Mark multiple functions as analyzed by a direction.

        Args:
            function_ids: List of function IDs
            direction_id: Direction ID

        Returns:
            Number of functions updated
        """
        if not function_ids:
            return 0
        try:
            result = self.collection.update_many(
                {"_id": {"$in": function_ids}},
                {"$addToSet": {"analyzed_by_directions": ObjectId(direction_id)}},
            )
            return result.modified_count
        except Exception as e:
            logger.error(f"Failed to mark functions as analyzed: {e}")
            return 0

    def get_functions_for_analysis(
        self,
        task_id: str,
        fuzzer_name: str,
        direction_id: str,
        function_names: List[str] = None,
        prioritize_unanalyzed: bool = True,
        limit: int = 0,
    ) -> List[Function]:
        """
        Get functions for SP Find analysis with priority ordering.

        Priority order (when prioritize_unanalyzed=True):
        1. Functions not analyzed by ANY direction
        2. Functions not analyzed by THIS direction
        3. Functions already analyzed by this direction (if exhausted)

        Args:
            task_id: Task ID
            fuzzer_name: Fuzzer name (to filter reachable functions)
            direction_id: Current direction ID
            function_names: Optional list of function names (small pool)
                           If None, uses all reachable functions (big pool)
            prioritize_unanalyzed: Whether to prioritize unanalyzed functions
            limit: Max functions to return (0 = no limit)

        Returns:
            List of Functions ordered by priority
        """
        try:
            # Base query: functions reachable by this fuzzer
            base_query = {
                "task_id": ObjectId(task_id),
                "reached_by_fuzzers": fuzzer_name,
            }

            # If small pool specified, filter by function names
            if function_names:
                base_query["name"] = {"$in": function_names}

            if not prioritize_unanalyzed:
                # Simple query without priority
                cursor = self.collection.find(base_query)
                if limit > 0:
                    cursor = cursor.limit(limit)
                return [self.model_class.from_dict(doc) for doc in cursor]

            # Priority 1: Not analyzed by ANY direction
            query_p1 = {
                **base_query,
                "$or": [
                    {"analyzed_by_directions": {"$exists": False}},
                    {"analyzed_by_directions": {"$size": 0}},
                ],
            }

            # Priority 2: Not analyzed by THIS direction
            query_p2 = {
                **base_query,
                "analyzed_by_directions": {"$nin": [ObjectId(direction_id)]},
            }

            # Priority 3: All functions (including already analyzed)
            query_p3 = base_query

            results = []
            seen_ids = set()

            # Collect from each priority level
            for query in [query_p1, query_p2, query_p3]:
                if limit > 0 and len(results) >= limit:
                    break
                cursor = self.collection.find(query)
                for doc in cursor:
                    if doc["_id"] not in seen_ids:
                        seen_ids.add(doc["_id"])
                        results.append(self.model_class.from_dict(doc))
                        if limit > 0 and len(results) >= limit:
                            break

            return results

        except Exception as e:
            logger.error(f"Failed to get functions for analysis: {e}")
            return []

    def get_unanalyzed_count(
        self,
        task_id: str,
        fuzzer_name: str = None,
        direction_id: str = None,
    ) -> dict:
        """
        Get count of unanalyzed functions.

        Args:
            task_id: Task ID
            fuzzer_name: Optional fuzzer name filter
            direction_id: Optional direction ID to check

        Returns:
            Dict with counts:
            - total: Total functions
            - unanalyzed_by_any: Not analyzed by any direction
            - unanalyzed_by_direction: Not analyzed by specific direction (if provided)
        """
        try:
            base_query = {"task_id": ObjectId(task_id)}
            if fuzzer_name:
                base_query["reached_by_fuzzers"] = fuzzer_name

            total = self.collection.count_documents(base_query)

            # Count not analyzed by any direction
            query_unanalyzed = {
                **base_query,
                "$or": [
                    {"analyzed_by_directions": {"$exists": False}},
                    {"analyzed_by_directions": {"$size": 0}},
                ],
            }
            unanalyzed_by_any = self.collection.count_documents(query_unanalyzed)

            result = {
                "total": total,
                "unanalyzed_by_any": unanalyzed_by_any,
                "analyzed_by_any": total - unanalyzed_by_any,
            }

            # If direction specified, count for that direction
            if direction_id:
                query_not_by_dir = {
                    **base_query,
                    "analyzed_by_directions": {"$nin": [ObjectId(direction_id)]},
                }
                unanalyzed_by_dir = self.collection.count_documents(query_not_by_dir)
                result["unanalyzed_by_direction"] = unanalyzed_by_dir
                result["analyzed_by_direction"] = total - unanalyzed_by_dir

            return result

        except Exception as e:
            logger.error(f"Failed to get unanalyzed count: {e}")
            return {"total": 0, "unanalyzed_by_any": 0, "analyzed_by_any": 0}

    def get_analysis_coverage(self, task_id: str, fuzzer_name: str = None) -> dict:
        """
        Get analysis coverage statistics.

        Args:
            task_id: Task ID
            fuzzer_name: Optional fuzzer name filter

        Returns:
            Dict with coverage stats:
            - total_functions: Total function count
            - analyzed_functions: Functions analyzed by at least one direction
            - coverage_percent: Percentage of functions analyzed
            - by_direction: Dict mapping direction_id to count
        """
        try:
            base_query = {"task_id": ObjectId(task_id)}
            if fuzzer_name:
                base_query["reached_by_fuzzers"] = fuzzer_name

            total = self.collection.count_documents(base_query)
            if total == 0:
                return {
                    "total_functions": 0,
                    "analyzed_functions": 0,
                    "coverage_percent": 0.0,
                    "by_direction": {},
                }

            # Count analyzed (has at least one direction)
            query_analyzed = {
                **base_query,
                "analyzed_by_directions": {"$exists": True, "$ne": []},
            }
            analyzed = self.collection.count_documents(query_analyzed)

            # Aggregate by direction
            pipeline = [
                {"$match": base_query},
                {"$unwind": "$analyzed_by_directions"},
                {"$group": {"_id": "$analyzed_by_directions", "count": {"$sum": 1}}},
            ]
            by_direction = {}
            for doc in self.collection.aggregate(pipeline):
                by_direction[doc["_id"]] = doc["count"]

            return {
                "total_functions": total,
                "analyzed_functions": analyzed,
                "coverage_percent": round(analyzed / total * 100, 2)
                if total > 0
                else 0.0,
                "by_direction": by_direction,
            }

        except Exception as e:
            logger.error(f"Failed to get analysis coverage: {e}")
            return {
                "total_functions": 0,
                "analyzed_functions": 0,
                "coverage_percent": 0.0,
                "by_direction": {},
            }


class CallGraphNodeRepository(BaseRepository[CallGraphNode]):
    """Repository for CallGraphNode model (call graph relationships)"""

    def __init__(self, db: Database):
        super().__init__(db, "callgraph_nodes", CallGraphNode)
        # Create indexes for faster queries
        self._ensure_indexes()

    def _ensure_indexes(self):
        """Create indexes for common query patterns."""
        try:
            self.collection.create_index("task_id")
            self.collection.create_index("function_name")
            self.collection.create_index("call_depth")
            self.collection.create_index([("task_id", 1), ("function_name", 1)])
            self.collection.create_index([("task_id", 1), ("fuzzer_id", 1)])
            self.collection.create_index([("task_id", 1), ("call_depth", 1)])
        except Exception as e:
            logger.debug(f"Index creation for callgraph_nodes: {e}")

    def find_by_task(self, task_id: str) -> List[CallGraphNode]:
        """Find all call graph nodes for a task"""
        return self.find_all({"task_id": ObjectId(task_id)})

    def find_by_fuzzer(self, task_id: str, fuzzer_id: str) -> List[CallGraphNode]:
        """Find all nodes for a specific fuzzer"""
        return self.find_all({"task_id": ObjectId(task_id), "fuzzer_id": fuzzer_id})

    def find_by_function(
        self, task_id: str, fuzzer_id: str, function_name: str
    ) -> Optional[CallGraphNode]:
        """Find node by function name for a specific fuzzer"""
        node_id = f"{task_id}_{fuzzer_id}_{function_name}"
        return self.find_by_id(node_id)

    def find_callers(
        self, task_id: str, fuzzer_id: str, function_name: str
    ) -> List[str]:
        """Get list of callers for a function"""
        node = self.find_by_function(task_id, fuzzer_id, function_name)
        return node.callers if node else []

    def find_callees(
        self, task_id: str, fuzzer_id: str, function_name: str
    ) -> List[str]:
        """Get list of callees for a function"""
        node = self.find_by_function(task_id, fuzzer_id, function_name)
        return node.callees if node else []

    def find_by_depth(
        self, task_id: str, fuzzer_id: str, depth: int
    ) -> List[CallGraphNode]:
        """Find all nodes at a specific call depth"""
        return self.find_all(
            {"task_id": ObjectId(task_id), "fuzzer_id": fuzzer_id, "call_depth": depth}
        )

    def save_many(self, nodes: List[CallGraphNode]) -> int:
        """
        Bulk save call graph nodes.

        Returns:
            Number of nodes saved successfully
        """
        if not nodes:
            return 0
        try:
            docs = [n.to_dict() for n in nodes]
            from pymongo import UpdateOne

            operations = [
                UpdateOne({"_id": doc["_id"]}, {"$set": doc}, upsert=True)
                for doc in docs
            ]
            result = self.collection.bulk_write(operations)
            return result.upserted_count + result.modified_count
        except Exception as e:
            logger.error(f"Failed to bulk save call graph nodes: {e}")
            return 0

    def delete_by_task(self, task_id: str) -> int:
        """Delete all nodes for a task"""
        try:
            result = self.collection.delete_many({"task_id": ObjectId(task_id)})
            return result.deleted_count
        except Exception as e:
            logger.error(f"Failed to delete call graph nodes for task: {e}")
            return 0

    def delete_by_fuzzer(self, task_id: str, fuzzer_id: str) -> int:
        """Delete all nodes for a specific fuzzer"""
        try:
            result = self.collection.delete_many(
                {"task_id": ObjectId(task_id), "fuzzer_id": fuzzer_id}
            )
            return result.deleted_count
        except Exception as e:
            logger.error(f"Failed to delete call graph nodes for fuzzer: {e}")
            return 0


class RepositoryManager:
    """
    Central repository manager.

    Provides access to all repositories with a shared database connection.
    """

    def __init__(self, db: Database):
        self.db = db
        self._tasks: Optional[TaskRepository] = None
        self._povs: Optional[POVRepository] = None
        self._patches: Optional[PatchRepository] = None
        self._suspicious_points: Optional[SuspiciousPointRepository] = None
        self._directions: Optional[DirectionRepository] = None
        self._workers: Optional[WorkerRepository] = None
        self._fuzzers: Optional[FuzzerRepository] = None
        self._functions: Optional[FunctionRepository] = None
        self._callgraph_nodes: Optional[CallGraphNodeRepository] = None

    @property
    def tasks(self) -> TaskRepository:
        """Get TaskRepository"""
        if self._tasks is None:
            self._tasks = TaskRepository(self.db)
        return self._tasks

    @property
    def povs(self) -> POVRepository:
        """Get POVRepository"""
        if self._povs is None:
            self._povs = POVRepository(self.db)
        return self._povs

    @property
    def patches(self) -> PatchRepository:
        """Get PatchRepository"""
        if self._patches is None:
            self._patches = PatchRepository(self.db)
        return self._patches

    @property
    def suspicious_points(self) -> SuspiciousPointRepository:
        """Get SuspiciousPointRepository"""
        if self._suspicious_points is None:
            self._suspicious_points = SuspiciousPointRepository(self.db)
        return self._suspicious_points

    @property
    def directions(self) -> DirectionRepository:
        """Get DirectionRepository"""
        if self._directions is None:
            self._directions = DirectionRepository(self.db)
        return self._directions

    @property
    def workers(self) -> WorkerRepository:
        """Get WorkerRepository"""
        if self._workers is None:
            self._workers = WorkerRepository(self.db)
        return self._workers

    @property
    def fuzzers(self) -> FuzzerRepository:
        """Get FuzzerRepository"""
        if self._fuzzers is None:
            self._fuzzers = FuzzerRepository(self.db)
        return self._fuzzers

    @property
    def functions(self) -> FunctionRepository:
        """Get FunctionRepository"""
        if self._functions is None:
            self._functions = FunctionRepository(self.db)
        return self._functions

    @property
    def callgraph_nodes(self) -> CallGraphNodeRepository:
        """Get CallGraphNodeRepository"""
        if self._callgraph_nodes is None:
            self._callgraph_nodes = CallGraphNodeRepository(self.db)
        return self._callgraph_nodes


# Global repository manager instance
_repo_manager: Optional[RepositoryManager] = None


def get_repos(db: Database = None) -> RepositoryManager:
    """
    Get the global repository manager.

    Args:
        db: Database instance (required on first call)

    Returns:
        RepositoryManager instance
    """
    global _repo_manager
    if _repo_manager is None:
        if db is None:
            raise RuntimeError("Database not initialized. Pass db on first call.")
        _repo_manager = RepositoryManager(db)
    return _repo_manager


def init_repos(db: Database) -> RepositoryManager:
    """Initialize repository manager with database"""
    global _repo_manager
    _repo_manager = RepositoryManager(db)
    return _repo_manager
