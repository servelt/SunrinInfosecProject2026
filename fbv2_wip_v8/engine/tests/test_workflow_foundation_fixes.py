from types import SimpleNamespace
import asyncio

from bson import ObjectId
import mongomock

from fuzzingbrain.agents.sp_generators import generic_security_family_priority
from fuzzingbrain.analyzer.importer import StaticAnalysisImporter
from fuzzingbrain.core.models.suspicious_point import SuspiciousPoint
from fuzzingbrain.core.models.function import Function
from fuzzingbrain.analyzer.server import AnalysisServer
from fuzzingbrain.db.repository import RepositoryManager
from fuzzingbrain.tools.suspicious_points import update_suspicious_point_impl


class _SaveResult:
    def __init__(self, result, existing=None):
        self.result = result
        self.existing = existing

    def save(self, _entity):
        return self.result

    def find_by_id(self, _identity):
        return self.existing


def _importer(tmp_path, save_result=True, logs=None, existing=None):
    logs = logs if logs is not None else []
    repos = SimpleNamespace(functions=_SaveResult(save_result, existing))
    return StaticAnalysisImporter(
        "a" * 24, str(tmp_path / "introspector"), str(tmp_path / "repo"),
        repos, log_callback=lambda message, level: logs.append((level, message)),
    )


def test_function_save_false_is_not_counted_as_imported(tmp_path):
    logs = []
    importer = _importer(tmp_path, save_result=False, logs=logs)
    saved = importer._save_function(
        {"name": "parse", "file_path": "parser.c"}, {}, "int parse(void){}")
    assert saved is False
    assert importer.functions_imported == 0
    assert any(level == "WARN" and "Failed to save" in message
               for level, message in logs)


def test_same_name_different_source_identity_fails_closed(tmp_path):
    existing = SimpleNamespace(
        file_path="src/a/parser.c", start_line=10, name="parse")
    logs = []
    importer = _importer(tmp_path, logs=logs, existing=existing)
    saved = importer._save_function({
        "name": "parse", "file_path": "src/b/parser.c", "start_line": 20,
    }, {}, "int parse(void){}")
    assert saved is False
    assert importer.functions_imported == 0
    assert any("Function identity collision" in message for _, message in logs)


def test_ambiguous_basename_resolution_fails_closed(tmp_path):
    repo = tmp_path / "repo"
    (repo / "a").mkdir(parents=True)
    (repo / "b").mkdir(parents=True)
    (repo / "a" / "parser.c").write_text("a")
    (repo / "b" / "parser.c").write_text("b")
    logs = []
    importer = _importer(tmp_path, logs=logs)
    assert importer._resolve_file_path("/missing/parser.c") is None
    assert any(level == "WARN" and "Ambiguous source path" in message
               for level, message in logs)


def test_unique_basename_resolution_remains_supported(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    expected = repo / "parser.c"
    expected.write_text("only")
    importer = _importer(tmp_path)
    assert importer._resolve_file_path("/missing/parser.c") == expected


def test_url_literal_does_not_hide_lifecycle_operation():
    source = 'void f(char *p) { const char *u = "http://example"; free(p); }'
    result = generic_security_family_priority(
        source, "address", "LIFETIME_OWNERSHIP")
    assert result["lifecycle_operations"] == 1


def test_comment_text_does_not_create_lifecycle_operation():
    source = 'void f(char *p) { /* free(p); */ const char *u = "free(p)"; }'
    result = generic_security_family_priority(
        source, "address", "LIFETIME_OWNERSHIP")
    assert result["lifecycle_operations"] == 0


def _refutation_server(tmp_path):
    task_id = str(ObjectId())
    repo = tmp_path / "repo"
    repo.mkdir()
    source = "int parse(void) {\n  if (0) { dangerous(); }\n  return 0;\n}\n"
    (repo / "parser.c").write_text(source)
    db = mongomock.MongoClient()["host_refutation"]
    repos = RepositoryManager(db)
    assert repos.functions.save(Function(
        task_id=task_id, name="parse", file_path="parser.c",
        start_line=1, end_line=4, content=source))
    point = SuspiciousPoint(
        task_id=task_id, function_name="parse",
        description="dangerous(); is the suspicious sink",
        vuln_type="buffer-overflow", sources=[{
            "harness_name": "fuzz", "sanitizer": "address"}])
    assert repos.suspicious_points.save(point)
    claim = repos.suspicious_points.claim_for_verify(
        task_id, "verify_1", "fuzz", "address")
    server = AnalysisServer(task_id=task_id, task_path=str(tmp_path),
                            project_name="fixture", sanitizers=["address"])
    server.repos = repos
    evidence = {
        "source_path": "parser.c", "line_start": 2,
        "quote": "  if (0) { dangerous(); }",
        "sink_quote": "dangerous();",
        "contradiction_scope": "WHOLE_HYPOTHESIS",
        "unresolved_context": [],
        "mechanical_check": "LITERAL_FALSE_GUARD",
    }
    return server, repos, point, claim, evidence


def test_literal_false_guard_cannot_terminally_refute_without_cfg(tmp_path):
    server, repos, point, claim, evidence = _refutation_server(tmp_path)
    params = {
        "id": point.suspicious_point_id, "is_checked": True,
        "is_real": False, "is_important": False, "score": 0.0,
        "verification_disposition": "REFUTED",
        "verification_notes": "literal-false guarded sink",
        "refutation_evidence": evidence,
        "agent_id": str(ObjectId()),
        "claim_token": claim.verification_claim_token,
    }
    try:
        asyncio.run(server._update_suspicious_point(params))
    except ValueError as exc:
        assert "compiler-backed CFG proof" in str(exc)
    else:
        raise AssertionError("textual if (0) became terminal REFUTED")
    stored = repos.suspicious_points.find_by_id(point.suspicious_point_id)
    assert stored.status == "verifying"
    assert stored.verification_disposition is None
    assert stored.verification_refutation_evidence is None


def test_host_rejects_standalone_refutation_evidence(tmp_path):
    server, repos, point, claim, evidence = _refutation_server(tmp_path)
    params = {
        "id": point.suspicious_point_id,
        "is_checked": True,
        "is_real": False,
        "is_important": False,
        "score": 0.1,
        "refutation_evidence": evidence,
        "agent_id": str(ObjectId()),
        "claim_token": claim.verification_claim_token,
    }
    try:
        asyncio.run(server._update_suspicious_point(params))
    except ValueError as exc:
        assert "refutation_evidence is disabled" in str(exc)
    else:
        raise AssertionError("standalone refutation evidence was ignored")
    stored = repos.suspicious_points.find_by_id(point.suspicious_point_id)
    assert stored.status == "verifying"
    assert stored.verification_refutation_evidence is None


def test_refuted_rejects_wrong_quote_partial_scope_and_context(tmp_path):
    for mutate in (
        lambda row: row.update(quote="  if (0) { other(); }"),
        lambda row: row.update(contradiction_scope="PARTIAL"),
        lambda row: row.update(unresolved_context=["caller"]),
        lambda row: row.update(mechanical_check="SEMANTIC_ARGUMENT"),
    ):
        case = tmp_path / str(ObjectId())
        case.mkdir()
        server, repos, point, claim, evidence = _refutation_server(case)
        mutate(evidence)
        params = {
            "id": point.suspicious_point_id, "is_checked": True,
            "is_real": False, "is_important": False, "score": 0.0,
            "verification_disposition": "REFUTED",
            "verification_notes": "untrusted refutation",
            "refutation_evidence": evidence,
            "agent_id": str(ObjectId()),
            "claim_token": claim.verification_claim_token,
        }
        try:
            asyncio.run(server._update_suspicious_point(params))
        except ValueError:
            pass
        else:
            raise AssertionError("invalid REFUTED evidence was accepted")
        stored = repos.suspicious_points.find_by_id(point.suspicious_point_id)
        assert stored.status == "verifying"
        assert stored.verification_disposition is None


def _refutation_case(tmp_path, source, *, start_line, end_line,
                     line_start, quote, sink_quote="free(p);"):
    task_id = str(ObjectId())
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "target.c").write_text(source)
    db = mongomock.MongoClient()["host_refutation_boundary"]
    repos = RepositoryManager(db)
    function_source = "\n".join(
        source.splitlines()[start_line - 1:end_line])
    assert repos.functions.save(Function(
        task_id=task_id, name="target", file_path="target.c",
        start_line=start_line, end_line=end_line, content=function_source))
    point = SuspiciousPoint(
        task_id=task_id, function_name="target",
        description=f"{sink_quote} is the suspicious sink",
        vuln_type="use-after-free", sources=[{
            "harness_name": "fuzz", "sanitizer": "address"}])
    assert repos.suspicious_points.save(point)
    server = AnalysisServer(task_id=task_id, task_path=str(tmp_path),
                            project_name="fixture", sanitizers=["address"])
    server.repos = repos
    evidence = {
        "source_path": "target.c", "line_start": line_start,
        "quote": quote, "sink_quote": sink_quote,
        "contradiction_scope": "WHOLE_HYPOTHESIS",
        "unresolved_context": [],
        "mechanical_check": "LITERAL_FALSE_GUARD",
    }
    return server, point, evidence


def test_refuted_rejects_literal_false_text_inside_string(tmp_path):
    source = (
        "void target(char *p) {\n"
        '  const char *s = "if (0) { free(p); }";\n'
        "  free(p);\n"
        "}\n")
    server, point, evidence = _refutation_case(
        tmp_path, source, start_line=1, end_line=4, line_start=2,
        quote='  const char *s = "if (0) { free(p); }";')
    valid, _ = server._validate_refutation_evidence(
        point.suspicious_point_id, evidence)
    assert not valid


def test_refuted_rejects_comment_guard_before_reachable_sink(tmp_path):
    source = (
        "void target(char *p) {\n"
        "  /* if (0) { free(p); } */\n"
        "  free(p);\n"
        "}\n")
    server, point, evidence = _refutation_case(
        tmp_path, source, start_line=1, end_line=4, line_start=2,
        quote="  /* if (0) { free(p); } */")
    valid, _ = server._validate_refutation_evidence(
        point.suspicious_point_id, evidence)
    assert not valid


def test_refuted_rejects_unprotected_duplicate_sink(tmp_path):
    source = (
        "void target(char *p, int live) {\n"
        "  if (0) { free(p); }\n"
        "  if (live) { free(p); }\n"
        "}\n")
    server, point, evidence = _refutation_case(
        tmp_path, source, start_line=1, end_line=4, line_start=2,
        quote="  if (0) { free(p); }")
    valid, _ = server._validate_refutation_evidence(
        point.suspicious_point_id, evidence)
    assert not valid


def test_refuted_rejects_whitespace_equivalent_live_call(tmp_path):
    source = (
        "void target(char *p) {\n"
        "  if (0) { free(p); }\n"
        "  free ( p );\n"
        "}\n")
    server, point, evidence = _refutation_case(
        tmp_path, source, start_line=1, end_line=4, line_start=2,
        quote="  if (0) { free(p); }")
    valid, _ = server._validate_refutation_evidence(
        point.suspicious_point_id, evidence)
    assert not valid

    claim = server.repos.suspicious_points.claim_for_verify(
        point.task_id, "verify_1", "fuzz", "address")
    params = {
        "id": point.suspicious_point_id, "is_checked": True,
        "is_real": False, "is_important": False, "score": 0.0,
        "verification_disposition": "REFUTED",
        "verification_notes": "unsafe whole-hypothesis claim",
        "refutation_evidence": evidence,
        "agent_id": str(ObjectId()),
        "claim_token": claim.verification_claim_token,
    }
    try:
        asyncio.run(server._update_suspicious_point(params))
    except ValueError:
        pass
    else:
        raise AssertionError("equivalent reachable sink became terminal REFUTED")
    stored = server.repos.suspicious_points.find_by_id(
        point.suspicious_point_id)
    assert stored.status == "verifying"
    assert stored.verification_disposition is None


def test_refuted_rejects_comment_separated_live_call(tmp_path):
    source = (
        "void target(char *p) {\n"
        "  if (0) { free(p); }\n"
        "  free/**/(p);\n"
        "}\n")
    server, point, evidence = _refutation_case(
        tmp_path, source, start_line=1, end_line=4, line_start=2,
        quote="  if (0) { free(p); }")
    valid, _ = server._validate_refutation_evidence(
        point.suspicious_point_id, evidence)
    assert not valid


def test_refuted_rejects_parenthesized_live_callee(tmp_path):
    source = (
        "void target(char *p) {\n"
        "  if (0) { free(p); }\n"
        "  (free)(p);\n"
        "}\n")
    server, point, evidence = _refutation_case(
        tmp_path, source, start_line=1, end_line=4, line_start=2,
        quote="  if (0) { free(p); }")
    valid, _ = server._validate_refutation_evidence(
        point.suspicious_point_id, evidence)
    assert not valid


def test_refuted_rejects_expression_aliased_live_callee(tmp_path):
    source = (
        "void target(char *p) {\n"
        "  if (0) { free(p); }\n"
        "  (0, free)(p);\n"
        "}\n")
    server, point, evidence = _refutation_case(
        tmp_path, source, start_line=1, end_line=4, line_start=2,
        quote="  if (0) { free(p); }")
    valid, _ = server._validate_refutation_evidence(
        point.suspicious_point_id, evidence)
    assert not valid


def test_refuted_rejects_cpp_raw_string_guard_decoy(tmp_path):
    source = (
        "void target(char *p) {\n"
        '  const char *s = R"tag(if (0) { free(p); })tag";\n'
        "  free (p);\n"
        "}\n")
    server, point, evidence = _refutation_case(
        tmp_path, source, start_line=1, end_line=4, line_start=2,
        quote='  const char *s = R"tag(if (0) { free(p); })tag";')
    valid, _ = server._validate_refutation_evidence(
        point.suspicious_point_id, evidence)
    assert not valid


def test_refuted_rejects_dead_sink_from_different_function(tmp_path):
    source = (
        "void decoy(char *p) {\n"
        "  if (0) { free(p); }\n"
        "}\n"
        "void target(char *p) {\n"
        "  free(p);\n"
        "}\n")
    server, point, evidence = _refutation_case(
        tmp_path, source, start_line=4, end_line=6, line_start=2,
        quote="  if (0) { free(p); }")
    valid, _ = server._validate_refutation_evidence(
        point.suspicious_point_id, evidence)
    assert not valid


def test_literal_false_guard_rejects_cfg_preprocessor_and_indirect_cases(
        tmp_path):
    cases = [
        (
            "void target(char *p) {\n"
            "  goto LIVE;\n"
            "  if (0) { LIVE: free(p); }\n"
            "}\n",
            1, 4, 3, "  if (0) { LIVE: free(p); }",
        ),
        (
            "void target(char *p) {\n"
            "  switch (1) {\n"
            "    if (0) { case 1: free(p); }\n"
            "  }\n"
            "}\n",
            1, 5, 3, "    if (0) { case 1: free(p); }",
        ),
        (
            "#define if(x) if(1)\n"
            "void target(char *p) {\n"
            "  if (0) { free(p); }\n"
            "}\n",
            2, 4, 3, "  if (0) { free(p); }",
        ),
        (
            "void target(char *p, void (*g_free)(void *)) {\n"
            "  if (0) { free(p); }\n"
            "  (*g_free)(p);\n"
            "}\n",
            1, 4, 2, "  if (0) { free(p); }",
        ),
        (
            "void target(char *p, void (**tbl)(void *), int k) {\n"
            "  if (0) { free(p); }\n"
            "  tbl[k](p);\n"
            "}\n",
            1, 4, 2, "  if (0) { free(p); }",
        ),
    ]
    for index, (source, start, end, line_start, quote) in enumerate(cases):
        case = tmp_path / str(index)
        case.mkdir()
        server, point, evidence = _refutation_case(
            case, source, start_line=start, end_line=end,
            line_start=line_start, quote=quote)
        valid, reason = server._validate_refutation_evidence(
            point.suspicious_point_id, evidence)
        assert not valid
        assert "compiler-backed CFG proof" in reason


def test_verification_disposition_survives_database_round_trip():
    point = SuspiciousPoint(
        task_id="a" * 24, function_name="parse",
        verification_disposition="TESTABLE_UNCERTAIN")
    restored = SuspiciousPoint.from_dict(point.to_dict())
    assert restored.verification_disposition == "TESTABLE_UNCERTAIN"


def test_invalid_verification_disposition_is_rejected_before_transport():
    result = update_suspicious_point_impl(
        "b" * 24, verification_disposition="MAYBE")
    assert result == {
        "success": False, "error": "invalid verification_disposition"}
