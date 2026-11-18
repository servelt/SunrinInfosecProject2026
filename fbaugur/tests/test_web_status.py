"""Resumed web sessions show the current pipeline attempt."""

from pathlib import Path

from fbaugur.web.status import current_attempt_lines, hc_run_of, pipeline_dir_of, stage1


def test_resumed_session_uses_latest_pipeline_and_stage(tmp_path: Path) -> None:
    old = tmp_path / "old"
    new = tmp_path / "new"
    old_hc = old / "harness" / "old-run"
    new_hc = new / "harness" / "new-run"
    for directory in (old_hc, new_hc):
        directory.mkdir(parents=True)
        (directory / "project.json").write_text("{}", encoding="utf-8")
    lines = [
        f"pipeline directory: {old}",
        f"[stage 1] skipped; reusing {old_hc}",
        "[stage 1] finished",
        f"pipeline directory: {new}",
        "[stage 1] harness generation",
    ]
    assert pipeline_dir_of(lines) == new
    current = current_attempt_lines(lines)
    assert current == lines[-2:]
    assert hc_run_of(current, new) == new_hc


def test_blocked_harness_status_is_not_reported_as_generated(tmp_path: Path) -> None:
    hc = tmp_path / "harness"
    status = hc / "context-harnesses" / "ctx-abcdef-stream" / "status.json"
    status.parent.mkdir(parents=True)
    status.write_text('{"status":"GENERATION_BLOCKED","generated":false,"built":false,'
                      '"attempts":[],"reason":"the context has no Entry with this delivery"}', encoding="utf-8")
    result = stage1([
        "[WORKFLOW] 3.1 harness for ctx-abcdef over tcp: started",
        "[WORKFLOW] 3.1 harness for ctx-abcdef over tcp: finished in 0s (exit 1)",
        "[WORKFLOW] 2.2 normal inputs for ctx-fedcba over tcp: started",
    ], hc, alive=True)
    assert result["status"]["hg"] == "wait"
    assert result["details"]["hg"]["summary"] == "생성 0개 · 생성 전 차단 1개"
    assert result["details"]["hg"]["rows"][0]["c"] == "생성 전 차단 · 시도 0회"
