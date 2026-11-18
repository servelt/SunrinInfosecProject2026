"""Function equivalence is measured for every verified seed, not one per set of function names."""

import types

from harnesscreator.contexts.measured_harness import covering_seeds, equivalence_seeds


def _seed(name, functions, size=10):
    return types.SimpleNamespace(seed_id=name, functions_beyond_baseline=functions, data=b"x" * size)


def test_seeds_with_the_same_functions_are_all_measured():
    # Follow-up review item 1 (LightFTP): four seeds, the same two functions beyond the baseline.
    seeds = [_seed(f"s{i}", ["lowcase_a", "strncmpi"], 10 + i) for i in range(4)]
    assert len(covering_seeds(seeds)) == 1
    assert [s.seed_id for s in equivalence_seeds(seeds)] == ["s0", "s1", "s2", "s3"]


def test_the_limit_keeps_the_covering_seeds_first():
    seeds = [_seed(f"a{i}", ["f"]) for i in range(5)] + [_seed("b", ["g"])]
    chosen = equivalence_seeds(seeds, limit=3)
    assert len(chosen) == 3 and "b" in [s.seed_id for s in chosen]
