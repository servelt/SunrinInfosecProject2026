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
    assert calls[1][-2:] == ["--", "--pre=untrusted-command"]
