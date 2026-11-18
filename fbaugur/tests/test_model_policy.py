from fbaugur.config import codex_daybreak_args


def test_daybreak_is_only_requested_for_supported_models() -> None:
    assert codex_daybreak_args("gpt-6-sol") == [
        "-c", "daybreak=true", "--enable", "cli_daybreak",
    ]
    assert codex_daybreak_args("gpt-5.6-cyber")
    assert codex_daybreak_args("gpt-6.1-sol") == []
    assert codex_daybreak_args("gpt-6-astra") == []
    assert codex_daybreak_args("gpt-6-luna") == []
    assert codex_daybreak_args("future-model") == []
