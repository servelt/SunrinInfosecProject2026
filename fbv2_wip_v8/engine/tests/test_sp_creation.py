"""
Suspicious Point Creation Tests

Tests the SP creation flow: LLM tool call → create_suspicious_point_impl → client → DB.

Business invariants under test:
1. No direction_id in context → create SP blocked (Layer A guard)
2. LLM params (function_name, vuln_type, description, score) forwarded correctly to client
3. harness_name/sanitizer/direction_id/agent_id come from ContextVar, not LLM
4. New SP defaults to PENDING_VERIFY status so claim_for_verify() can pick it up
5. created_by_agent_id is set from context (not LLM)
6. sources array contains the correct harness/sanitizer pair
"""

import mongomock
import pytest
from unittest.mock import patch, MagicMock

from bson import ObjectId

from fuzzingbrain.core.models.suspicious_point import SuspiciousPoint
from fuzzingbrain.db.repository import SuspiciousPointRepository
from fuzzingbrain.tools.suspicious_points import (
    create_suspicious_point_impl,
    set_sp_context,
    set_sp_agent_id,
    get_sp_context,
)


# =========================================================================
# Helpers
# =========================================================================


def _mock_client_create_success(sp_id=None):
    """Return a mock AnalysisClient whose create_suspicious_point returns success."""
    client = MagicMock()
    sid = sp_id or str(ObjectId())
    client.create_suspicious_point.return_value = {
        "id": sid,
        "created": True,
        "merged": False,
    }
    return client


@pytest.fixture
def sp_repo():
    """SuspiciousPointRepository backed by mongomock."""
    client = mongomock.MongoClient()
    db = client["test_fuzzingbrain"]
    return SuspiciousPointRepository(db)


# =========================================================================
# Tests: Direction guard (Layer A)
# =========================================================================


class TestDirectionGuard:
    """
    SP creation access is controlled at the agent level via include_sp_create_tools.
    The tool itself does not gate on direction_id — delta mode has no directions.
    """

    @patch("fuzzingbrain.tools.suspicious_points._get_client")
    @patch("fuzzingbrain.tools.suspicious_points._ensure_client", return_value=None)
    def test_no_direction_id_allows_creation(self, _ensure, mock_get_client):
        """Without direction_id (delta mode), create must succeed."""
        client = _mock_client_create_success()
        mock_get_client.return_value = client

        set_sp_context("fuzz_png", "address", direction_id="", agent_id=str(ObjectId()))

        result = create_suspicious_point_impl(
            function_name="parse_chunk",
            vuln_type="buffer-overflow",
            description="heap overflow in chunk parser",
        )

        assert result["success"] is True
        client.create_suspicious_point.assert_called_once()

    @patch("fuzzingbrain.tools.suspicious_points._get_client")
    @patch("fuzzingbrain.tools.suspicious_points._ensure_client", return_value=None)
    def test_with_direction_id_allows_creation(self, _ensure, mock_get_client):
        """With direction_id set (fullscan SPG agent), create must succeed."""
        client = _mock_client_create_success()
        mock_get_client.return_value = client

        direction_id = str(ObjectId())
        set_sp_context("fuzz_png", "address", direction_id=direction_id)

        result = create_suspicious_point_impl(
            function_name="parse_chunk",
            vuln_type="buffer-overflow",
            description="heap overflow",
        )

        assert result["success"] is True
        client.create_suspicious_point.assert_called_once()

    @pytest.mark.parametrize("merged", [False, True])
    @patch("fuzzingbrain.tools.suspicious_points._get_client")
    @patch("fuzzingbrain.tools.suspicious_points._ensure_client", return_value=None)
    def test_create_result_preserves_db_identity(self, _ensure, mock_get_client,
                                                 merged):
        sp_id = str(ObjectId())
        client = _mock_client_create_success(sp_id)
        client.create_suspicious_point.return_value["merged"] = merged
        mock_get_client.return_value = client
        set_sp_context("fuzz_png", "address", direction_id=str(ObjectId()))

        result = create_suspicious_point_impl(
            function_name="parse_chunk", vuln_type="buffer-overflow",
            description="user length reaches copy")

        assert result["success"] is True
        assert result["id"] == sp_id
        assert result.get("merged", False) is merged

    def test_analyzer_does_not_issue_id_when_db_save_fails(self):
        from types import SimpleNamespace
        from fuzzingbrain.analyzer.server import AnalysisServer

        repo = SimpleNamespace(save=MagicMock(return_value=False))
        server = SimpleNamespace(task_id=str(ObjectId()),
                                 repos=SimpleNamespace(suspicious_points=repo))
        with pytest.raises(RuntimeError, match="was not saved"):
            AnalysisServer._save_new_sp_sync(
                server, "parse_chunk", "fuzz_png", "address",
                "user length reaches copy", "buffer-overflow", 0.7, [],
                str(ObjectId()), str(ObjectId()))
        repo.save.assert_called_once()

    def test_analyzer_canonicalizes_live_string_controlflow_before_save(self):
        """The actual concurrent Live model emitted expression strings."""
        from types import SimpleNamespace
        from fuzzingbrain.analyzer.server import AnalysisServer

        saved = []
        repo = SimpleNamespace(save=lambda point: saved.append(point) or True)
        server = SimpleNamespace(task_id=str(ObjectId()),
                                 repos=SimpleNamespace(suspicious_points=repo))
        function_name = "md_add_mark"
        sp_id = AnalysisServer._save_new_sp_sync(
            server, function_name, "fuzz-mdhtml", "address",
            "growth arithmetic may overflow", "integer-overflow", 0.55,
            AnalysisServer._canonicalize_important_controlflow(
                function_name,
                ["ctx->alloc_marks += ctx->alloc_marks / 2",
                 "realloc(ctx->marks, size)"]),
            str(ObjectId()), str(ObjectId()))

        assert ObjectId.is_valid(sp_id)
        assert saved[0].important_controlflow == [
            {"type": "expression",
             "name": "ctx->alloc_marks += ctx->alloc_marks / 2",
             "location": function_name},
            {"type": "expression", "name": "realloc(ctx->marks, size)",
             "location": function_name},
        ]

    def test_live_string_controlflow_crosses_real_insert_only_repository(self):
        """Exercise the exact Host -> V1f repository boundary that failed Live."""
        from types import SimpleNamespace
        from fuzzingbrain.analyzer.server import AnalysisServer

        repo = SuspiciousPointRepository(
            mongomock.MongoClient()["live_controlflow_contract"])
        # AnalysisServer stores this as ObjectId in production.  The Host
        # creation boundary must convert it back to the repository's canonical
        # string model field before the insert-only save.
        task_id = ObjectId()
        server = SimpleNamespace(
            task_id=task_id,
            repos=SimpleNamespace(suspicious_points=repo),
        )
        function_name = "md_add_mark"
        sp_id = AnalysisServer._save_new_sp_sync(
            server, function_name, "fuzz-mdhtml", "address",
            "growth arithmetic may overflow", "integer-overflow", 0.55,
            AnalysisServer._canonicalize_important_controlflow(
                function_name,
                ["if(ctx->n_marks >= ctx->alloc_marks)",
                 "realloc(ctx->marks, ctx->alloc_marks * sizeof(MD_MARK))"]),
            str(ObjectId()), str(ObjectId()))

        stored = repo.find_by_id(sp_id)
        assert stored is not None
        assert stored.task_id == str(task_id)
        assert stored.status == "pending_verify"
        assert stored.important_controlflow[0] == {
            "type": "expression",
            "name": "if(ctx->n_marks >= ctx->alloc_marks)",
            "location": function_name,
        }

    def test_merge_requires_source_and_duplicate_receipts(self, sp_repo):
        from types import SimpleNamespace
        from fuzzingbrain.analyzer.server import AnalysisServer

        task_id = str(ObjectId())
        point = SuspiciousPoint(
            task_id=task_id, function_name="parse_chunk",
            sources=[{"harness_name": "fuzz_png", "sanitizer": "address"}],
            description="first candidate", vuln_type="buffer-overflow")
        assert sp_repo.save(point)
        server = SimpleNamespace(
            repos=SimpleNamespace(suspicious_points=sp_repo))

        assert AnalysisServer._merge_sp_source_sync(
            server, point.suspicious_point_id, "fuzz_png", "address",
            "second description", "buffer-overflow", 0.8) is False
        stored = sp_repo.find_by_id(point.suspicious_point_id)
        assert stored is not None
        assert len(stored.merged_duplicates) == 1

        sp_repo.add_merged_duplicate = MagicMock(return_value=False)
        with pytest.raises(RuntimeError, match="merge was not persisted"):
            AnalysisServer._merge_sp_source_sync(
                server, point.suspicious_point_id, "other_harness", "address",
                "third description", "buffer-overflow", 0.7)

    @pytest.mark.parametrize("value", ["not-a-list", [1], [""],
                                         [{"type": "function"}]])
    def test_controlflow_canonicalization_rejects_malformed_values(self, value):
        from fuzzingbrain.analyzer.server import AnalysisServer

        with pytest.raises(ValueError, match="important_controlflow"):
            AnalysisServer._canonicalize_important_controlflow("target", value)

    def test_controlflow_canonicalization_preserves_documented_objects(self):
        from fuzzingbrain.analyzer.server import AnalysisServer

        value = [{"type": "function", "name": "realloc",
                  "location": "src/md4c.c"}]
        assert AnalysisServer._canonicalize_important_controlflow(
            "target", value) == value


# =========================================================================
# Tests: LLM params → client field flow
# =========================================================================


class TestSPFieldFlow:
    """
    Business rule: LLM-provided params must reach the client unchanged.
    System-injected fields (harness, sanitizer, direction_id, agent_id)
    must come from ContextVar.
    """

    @patch("fuzzingbrain.tools.suspicious_points._get_client")
    @patch("fuzzingbrain.tools.suspicious_points._ensure_client", return_value=None)
    def test_llm_params_forwarded_to_client(self, _ensure, mock_get_client):
        """All LLM-provided fields must arrive at the client."""
        client = _mock_client_create_success()
        mock_get_client.return_value = client

        direction_id = str(ObjectId())
        set_sp_context("fuzz_png", "address", direction_id=direction_id)

        create_suspicious_point_impl(
            function_name="decompress_data",
            vuln_type="use-after-free",
            description="UAF after realloc in decompression loop",
            score=0.85,
            important_controlflow=[
                {"type": "function", "name": "realloc", "location": "line 42"}
            ],
        )

        kw = client.create_suspicious_point.call_args[1]
        assert kw["function_name"] == "decompress_data"
        assert kw["vuln_type"] == "use-after-free"
        assert kw["description"] == "UAF after realloc in decompression loop"
        assert kw["score"] == 0.85
        assert kw["important_controlflow"] == [
            {"type": "function", "name": "realloc", "location": "line 42"}
        ]

    @patch("fuzzingbrain.tools.suspicious_points._get_client")
    @patch("fuzzingbrain.tools.suspicious_points._ensure_client", return_value=None)
    def test_context_fields_injected_from_contextvar(self, _ensure, mock_get_client):
        """harness_name, sanitizer, direction_id, agent_id must come from ContextVar."""
        client = _mock_client_create_success()
        mock_get_client.return_value = client

        direction_id = str(ObjectId())
        agent_id = str(ObjectId())
        set_sp_context(
            "fuzz_png", "address", direction_id=direction_id, agent_id=agent_id
        )

        create_suspicious_point_impl(
            function_name="f",
            vuln_type="buffer-overflow",
            description="d",
        )

        kw = client.create_suspicious_point.call_args[1]
        assert kw["harness_name"] == "fuzz_png"
        assert kw["sanitizer"] == "address"
        assert kw["direction_id"] == direction_id
        assert kw["agent_id"] == agent_id

    @patch("fuzzingbrain.tools.suspicious_points._get_client")
    @patch("fuzzingbrain.tools.suspicious_points._ensure_client", return_value=None)
    def test_different_worker_different_context(self, _ensure, mock_get_client):
        """Switching context must change harness/sanitizer in subsequent calls."""
        client = _mock_client_create_success()
        mock_get_client.return_value = client

        d1 = str(ObjectId())
        set_sp_context("fuzz_png", "address", direction_id=d1)
        create_suspicious_point_impl(
            function_name="f1", vuln_type="bof", description="d1"
        )
        first = client.create_suspicious_point.call_args[1]

        d2 = str(ObjectId())
        set_sp_context("fuzz_icc", "memory", direction_id=d2)
        create_suspicious_point_impl(
            function_name="f2", vuln_type="uaf", description="d2"
        )
        second = client.create_suspicious_point.call_args[1]

        assert first["harness_name"] == "fuzz_png"
        assert first["sanitizer"] == "address"
        assert second["harness_name"] == "fuzz_icc"
        assert second["sanitizer"] == "memory"

    @patch("fuzzingbrain.tools.suspicious_points._get_client")
    @patch("fuzzingbrain.tools.suspicious_points._ensure_client", return_value=None)
    def test_default_score_is_half(self, _ensure, mock_get_client):
        """If LLM doesn't provide score, default is 0.5."""
        client = _mock_client_create_success()
        mock_get_client.return_value = client

        set_sp_context("fuzz_png", "address", direction_id=str(ObjectId()))

        create_suspicious_point_impl(
            function_name="f",
            vuln_type="bof",
            description="d",
            # score not provided
        )

        assert client.create_suspicious_point.call_args[1]["score"] == 0.5


# =========================================================================
# Tests: SP initial state in DB
# =========================================================================


class TestSPInitialState:
    """
    Business rule: a newly created SP must have status=PENDING_VERIFY.
    claim_for_verify() queries for this status — wrong initial status = dead SP.
    Also: created_by_agent_id and sources must be correctly populated.
    """

    def test_sp_model_defaults_to_pending_verify(self):
        """SuspiciousPoint() defaults to PENDING_VERIFY."""
        sp = SuspiciousPoint()
        assert sp.status == "pending_verify"

    def test_sp_model_defaults_unchecked(self):
        """New SP must be is_checked=False, is_real=False, is_important=False."""
        sp = SuspiciousPoint()
        assert sp.is_checked is False
        assert sp.is_real is False
        assert sp.is_important is False

    def test_sp_saved_with_pending_verify_found_by_claim(self, sp_repo):
        """Save SP → claim_for_verify must find it."""
        task_id = str(ObjectId())
        sp = SuspiciousPoint(
            task_id=task_id,
            function_name="parse_chunk",
            description="heap overflow",
            vuln_type="buffer-overflow",
            score=0.8,
            sources=[{"harness_name": "fuzz_png", "sanitizer": "address"}],
        )
        sp_repo.save(sp)

        claimed = sp_repo.claim_for_verify(
            task_id=task_id,
            processor_id=str(ObjectId()),
        )

        assert claimed is not None
        assert claimed.function_name == "parse_chunk"

    def test_created_by_agent_id_persisted(self, sp_repo):
        """created_by_agent_id from server must round-trip through DB."""
        task_id = str(ObjectId())
        agent_id = str(ObjectId())

        sp = SuspiciousPoint(
            task_id=task_id,
            function_name="f",
            description="candidate hypothesis",
            vuln_type="buffer-overflow",
            created_by_agent_id=agent_id,
            sources=[{"harness_name": "fuzz_png", "sanitizer": "address"}],
        )
        sp_repo.save(sp)

        found = sp_repo.find_by_task(task_id)
        assert len(found) == 1
        assert found[0].created_by_agent_id == agent_id

    def test_sources_contain_harness_and_sanitizer(self, sp_repo):
        """The sources array must record which harness/sanitizer discovered this SP."""
        task_id = str(ObjectId())
        sp = SuspiciousPoint(
            task_id=task_id,
            function_name="f",
            description="candidate hypothesis",
            vuln_type="buffer-overflow",
            sources=[{"harness_name": "fuzz_png", "sanitizer": "address"}],
        )
        sp_repo.save(sp)

        found = sp_repo.find_by_task(task_id)
        assert len(found) == 1
        assert found[0].sources == [
            {"harness_name": "fuzz_png", "sanitizer": "address"}
        ]

    def test_direction_id_persisted(self, sp_repo):
        """SP must record which direction it belongs to."""
        task_id = str(ObjectId())
        direction_id = str(ObjectId())

        sp = SuspiciousPoint(
            task_id=task_id,
            function_name="f",
            description="candidate hypothesis",
            vuln_type="buffer-overflow",
            direction_id=direction_id,
            sources=[{"harness_name": "fuzz_png", "sanitizer": "address"}],
        )
        sp_repo.save(sp)

        found = sp_repo.find_by_task(task_id)
        assert len(found) == 1
        assert found[0].direction_id == direction_id


# =========================================================================
# Tests: SP context isolation
# =========================================================================


class TestSPContextIsolation:
    """
    Business rule: set_sp_context only affects current context.
    set_sp_agent_id sets agent_id without touching direction_id.
    """

    def test_set_sp_agent_id_preserves_direction_id(self):
        """set_sp_agent_id must NOT clear direction_id."""
        direction_id = str(ObjectId())
        set_sp_context("fuzz_png", "address", direction_id=direction_id)

        # Agent startup calls set_sp_agent_id
        new_agent_id = str(ObjectId())
        set_sp_agent_id(new_agent_id)

        _, _, ctx_direction, ctx_agent = get_sp_context()
        assert ctx_direction == direction_id, "direction_id must not be cleared"
        assert ctx_agent == new_agent_id

    def test_set_sp_context_replaces_all_fields(self):
        """set_sp_context replaces everything including direction_id."""
        set_sp_context(
            "fuzz_png", "address", direction_id="old_dir", agent_id="old_agent"
        )
        set_sp_context(
            "fuzz_icc", "memory", direction_id="new_dir", agent_id="new_agent"
        )

        harness, san, direction, agent = get_sp_context()
        assert harness == "fuzz_icc"
        assert san == "memory"
        assert direction == "new_dir"
        assert agent == "new_agent"
