"""Model-controlled search text must never become a host rg option."""

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from fuzzingbrain.tools.code_viewer import (
    search_code, search_code_impl, set_code_viewer_context,
)


@pytest.mark.parametrize("search", [search_code, search_code_impl])
def test_model_search_pattern_is_after_end_of_options(tmp_path, search):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "source.c").write_text("int main(void) { return 0; }\n")
    set_code_viewer_context(str(tmp_path))
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    with patch("fuzzingbrain.tools.code_viewer.subprocess.run",
               side_effect=fake_run):
        search("--pre=untrusted-command")

    assert calls[0] == ["which", "rg"]
    assert calls[1][-3:] == ["--", "--pre=untrusted-command", "."]


@pytest.mark.parametrize("search", [search_code, search_code_impl])
def test_search_actually_walks_the_configured_repo(tmp_path, search):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "source.c").write_text(
        "static void resize_shared_buffer(void) {}\n", encoding="utf-8")
    set_code_viewer_context(str(tmp_path))

    result = search("resize_shared_buffer", "*.c")

    assert result["success"] is True
    assert result["count"] == 1
    assert result["matches"][0]["file"] == "source.c"


@pytest.mark.parametrize("search", [search_code, search_code_impl])
def test_invalid_regex_is_a_tool_failure_not_a_successful_empty_search(
        tmp_path, search):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "source.c").write_text("int target;\n", encoding="utf-8")
    set_code_viewer_context(str(tmp_path))

    result = search("[")

    assert result["success"] is False
    assert result["returncode"] >= 2
    assert "failed" in result["error"].lower()


@pytest.mark.parametrize("search", [search_code, search_code_impl])
def test_valid_no_match_remains_successful_negative_evidence(tmp_path, search):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "source.c").write_text("int target;\n", encoding="utf-8")
    set_code_viewer_context(str(tmp_path))

    result = search("definitely_absent_symbol")

    assert result["success"] is True
    assert result["count"] == 0


@pytest.mark.parametrize("search", [search_code, search_code_impl])
def test_requested_context_lines_are_returned_around_match(tmp_path, search):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "source.c").write_text(
        "before_two\nbefore_one\nTARGET\nafter_one\nafter_two\n",
        encoding="utf-8",
    )
    set_code_viewer_context(str(tmp_path))

    result = search("TARGET", "*.c", context_lines=2)

    assert result["success"] is True
    assert result["count"] == 1
    assert result["matches"][0]["context"] == [
        "before_two", "before_one", "TARGET", "after_one", "after_two",
    ]
