"""Early link-closure feedback must not change discovery or proof status."""
from __future__ import annotations
from pathlib import Path
from harnesscreator.models import HarnessPlan, ProjectSpec, ScenarioStep
from harnesscreator.runtime.preflight import inspect_build_closure_for_plan, inspect_capabilities


def plan(paths):
    step = ScenarioStep(0, 'parse', 'entry', b'X'.hex(), {}, [])
    return HarnessPlan(
        plan_id='p', witness_id='w', scenario_id='s', target_action_id='parse',
        setup_steps=[], fuzz_step=step, required_function_ids=[],
        entry_function_ids=[], input_mapping='raw', reset_strategy='in_process_reset',
        build_target='UNRESOLVED', min_size=1, max_size=4096,
        required_source_files=paths,
    )


def test_reports_small_original_source_as_candidate_without_building(tmp_path: Path):
    (tmp_path/'main.c').write_text('int parser(int x) { return x; }')
    proj=ProjectSpec(tmp_path,tmp_path/'out').normalized()
    answer=inspect_build_closure_for_plan(proj,plan(['main.c']))
    assert answer['status']=='CANDIDATE'
    assert answer['builder']=='standalone-small-source-layout'
    assert not (tmp_path/'out').exists()


def test_does_not_treat_external_source_as_build_target(tmp_path: Path):
    (tmp_path/'main.c').write_text('int parser(int x) { return x; }')
    outside=tmp_path.parent/'not-in-project-file.c'
    proj=ProjectSpec(tmp_path,tmp_path/'out').normalized()
    answer=inspect_build_closure_for_plan(proj,plan([str(outside)]))
    assert answer['status']=='UNRESOLVED'
    assert 'REQUIRED_SOURCE_UNAVAILABLE' in answer['reason']


def test_ambiguous_make_file_is_recorded_without_execution(tmp_path: Path):
    (tmp_path/'Makefile').write_text(
        'bin_PROGRAMS = left right\nleft_SOURCES = left.c\nright_SOURCES = right.c\n'
    )
    (tmp_path/'left.c').write_text('int main(void){return 0;}')
    (tmp_path/'right.c').write_text('int main(void){return 0;}')
    proj=ProjectSpec(tmp_path,tmp_path/'out').normalized()
    answer=inspect_build_closure_for_plan(proj,plan([]))
    assert answer['status']=='UNRESOLVED'
    assert answer['reason']=='NO_REQUIRED_SOURCE_EVIDENCE'


def test_generated_subdirectory_make_target_is_reported_before_generation(tmp_path: Path):
    build = tmp_path / 'Release'
    build.mkdir()
    (tmp_path / 'server.c').write_text('int main(void){return 0;}\n')
    original = build / 'server'
    original.write_bytes(b'original binary')
    (build / 'makefile').write_text(
        '-include sources.mk\n-include subdir.mk\n-include objects.mk\n'
        'all: server\nserver: $(OBJS)\n\tcc -o server $(OBJS) $(LIBS)\n'
    )
    (build / 'sources.mk').write_text('C_SRCS :=\nOBJS :=\n')
    (build / 'subdir.mk').write_text(
        'C_SRCS += ../server.c\nOBJS += ./server.o\n'
        '%.o: ../%.c\n\tcc -c -o "$@" "$<"\n'
    )
    (build / 'objects.mk').write_text('LIBS := -lm\n')
    project = ProjectSpec(
        tmp_path, tmp_path / 'out',
        scenario_command=[str(original)],
        build_command=['python', '-m', 'harnesscreator.runtime.native_build'],
    ).normalized()
    capability = inspect_capabilities(project)
    assert capability['configured_makefile'] == str(build / 'makefile')
    result = inspect_build_closure_for_plan(project, plan(['server.c']))
    assert result['status'] == 'CANDIDATE'
    assert result['builder'] == 'recorded-make-target'
    assert result['build_target'] == 'server'
    assert not (tmp_path / 'out').exists()


def test_preflight_does_not_report_a_different_make_executable(tmp_path: Path):
    (tmp_path / 'Makefile').write_text(
        'bin_PROGRAMS = other\nother_SOURCES = other.c\n'
    )
    (tmp_path / 'other.c').write_text('int main(void){return 0;}\n')
    original = tmp_path / 'server'
    original.write_bytes(b'original binary')
    project = ProjectSpec(
        tmp_path, tmp_path / 'out', scenario_command=[str(original)],
        build_command=['python', '-m', 'harnesscreator.runtime.native_build'],
    ).normalized()
    result = inspect_build_closure_for_plan(project, plan(['other.c']))
    assert result['status'] == 'UNRESOLVED'
    assert result['reason'] == 'ORIGINAL_EXECUTABLE_MAKE_CLOSURE_NOT_MATCHED'


def test_malformed_build_graph_does_not_abort_other_harness_plans(tmp_path: Path, monkeypatch):
    import harnesscreator.runtime.preflight as preflight
    (tmp_path / "handler.c").write_text("int handler(void){return 0;}")
    spec = ProjectSpec(tmp_path, tmp_path / "out").normalized()

    def explode(*args, **kwargs):
        raise RuntimeError("project contains unsupported build metadata")

    monkeypatch.setattr(preflight, "inspect_build_closure_for_plan", explode)
    result = preflight.safe_inspect_build_closure_for_plan(spec, plan(["handler.c"]))
    assert result["status"] == "UNRESOLVED"
    assert result["action_id"] == "parse"
    assert "BUILD_PREFLIGHT_ERROR" in result["reason"]
    assert not (tmp_path / "out").exists()
