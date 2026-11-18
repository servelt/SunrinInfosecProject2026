from harnesscreator.contexts.coverage import CoverageSnapshot, TargetMap


def test_inactive_same_name_branch_is_not_credited_as_compiled_or_covered():
    functions = [
        {"function_id": "windows", "file": "src/common.c", "name": "receive",
         "start_line": 380, "end_line": 385},
        {"function_id": "linux", "file": "src/common.c", "name": "receive",
         "start_line": 442, "end_line": 447},
    ]
    snapshot = CoverageSnapshot(
        known_functions={("src/common.c", "receive")},
        functions={("src/common.c", "receive")},
        known_function_ranges={("src/common.c", "receive", 442, 447)},
        function_ranges={("src/common.c", "receive", 442, 447)},
        known_lines={("src/common.c", "receive", 443)},
        lines={("src/common.c", "receive", 443)},
    )
    targets = TargetMap(functions, {"windows", "linux"})
    assert targets.compiled_functions(snapshot) == {"linux"}
    assert targets.covered_functions(snapshot) == {"linux"}
    assert targets.covered_lines(snapshot) == {("linux", 443)}
    assert TargetMap(functions, {"windows"}).compiled_functions(snapshot) == set()
