"""A manual control cannot spill model turns into another FBv2 role."""

from types import SimpleNamespace

import pytest

from devtools.manual_sp_control import _bounded_client_factory
from fuzzingbrain.worker.pipeline import IncompleteInjectedAgent


def test_manual_sp_model_role_budgets_are_separate():
    records = []
    created = []

    def make_client(role, owner):
        client = SimpleNamespace(role=role, owner=owner, max_calls=6)
        created.append(client)
        return client

    bound = SimpleNamespace(
        executor=SimpleNamespace(llm_client_factory=make_client),
        model_gate=SimpleNamespace(snapshot=lambda: {"records": records}),
    )
    factory = _bounded_client_factory(bound)

    assert factory("sp", "one").max_calls == 3
    records.extend({"role": "sp"} for _ in range(3))
    with pytest.raises(IncompleteInjectedAgent):
        factory("sp_large", "two")

    assert factory("verifier", "three").max_calls == 6
    records.extend({"role": "verifier"} for _ in range(5))
    assert factory("verifier", "four").max_calls == 1
    records.append({"role": "verifier"})
    with pytest.raises(IncompleteInjectedAgent):
        factory("verifier", "five")

    assert factory("pov", "six").max_calls == 6
    with pytest.raises(ValueError):
        factory("seed", "forbidden")
    assert len(created) == 4
