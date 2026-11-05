# 2026-10-29 복원 및 검증

## 복원 기준

- 2026-10-26~27에 남아 있던 `C:\sunrininfosec\SunrinInfosecProject2026\harnessgenerator\harnesscreator` 작업 트리를 복사했다. 복원 직후에는 `boundary`가 기본값이었으나, 사용자 정정에 따라 **Action 경로를 기본값으로 바꾸고 Behavior 경로를 실행 설정에서 제거했다**. `legacy_scenario`는 Action의 호환 별칭이다.
- 기존 `/mnt/c/harness/harnesscreator`는 `/mnt/c/harness/harnesscreator-legacy-20261029`로 이동해 보존했다. 복원본은 `/mnt/c/harness/harnesscreator`에 배치했다.

## 이번 수정

1. `ProjectSpec`와 CLI의 기본 모드를 Action으로 바꾸고 `boundary` 선택을 거부한다. 모델 역할도 Entry/Input Surface/Action/State Dependency/Scenario Refiner/Harness만 라우팅한다 (`models.py`, `cli.py`, `orchestrator.py`).
2. 원래 트리의 `boundary_harness.py`와 `behavior.py`에서 확인해 고친 두 결함은 기록으로 남겼지만, 해당 모듈은 현재 워크플로우에서 호출하지 않는다.
3. `pytest-asyncio`가 없는 환경에서도 비동기 런타임 시험 세 파일을 실행할 수 있게 `asyncio.run()`을 사용했다 (`tests/test_original_process_cold_start.py`, `tests/test_post_fuzz_gate.py`, `tests/test_stateful_stdin_runtime.py`).

## 검증

- Action 전환 후 전체 결과: **464 passed, 4 skipped, 36 subtests passed**. 실행 명령은 `ASAN_OPTIONS=detect_leaks=0 PYTHONPATH=/mnt/c/harness/harnesscreator/src /root/pwnenv/bin/python -m pytest -q`다. 이 환경의 LeakSanitizer 제약 때문에 `detect_leaks=0`을 사용했고, 로컬 소켓 시험에는 격리 밖 실행 권한이 필요했다.
- 기본 설정의 Action 통합 시험은 Entry → Action → 상태 관계 → 시나리오 → C 하네스 생성 → 빌드를 통과했다. `boundary`는 CLI에서 선택할 수 없고, 오케스트레이터 import에도 Behavior/ExecutionContract/Boundary 모듈이 없다. 과거 모듈 파일과 평가 문서는 기록으로만 남겨 두었다.
- `PYTHONPATH=/mnt/c/harness/harnesscreator/src /root/pwnenv/bin/python -m harnesscreator.cli --help`가 정상 종료했다.

## 아직 입증되지 않은 범위

- Action 워크플로우를 실제 Memcached 전체 입력에 다시 적용해 하네스 생성과 `QUALIFIED`까지 확인한 결과는 아직 없다. Action 경로의 기존 C 픽스처 시험과 실제 Memcached 성공을 구분한다.
