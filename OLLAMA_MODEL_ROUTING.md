# Ollama 모델 배정

기존 HarnessCreator의 에이전트 구성과 워크플로우를 유지했다. 이전 Small/Large Feature에서 담당한 분석 역할만 현재의 Input Action, State Dependency, Scenario Refiner에 대응시켰다.

| 역할 | Ollama 모델 | `think` |
| --- | --- | --- |
| Entry Generator | `glm-5.3-flash:cloud` | `high` |
| Entry Verifier | `glm-5.3:cloud` | `low` |
| Input Action Agent | `glm-5.3:cloud` | `high` |
| State Dependency Agent | `glm-5.3:cloud` | `high` |
| Scenario Refiner | `glm-5.3:cloud` | `high` |
| Harness Generator | `kimi-k2.7-code:cloud` | 전송하지 않음. 모델 기본값 사용 |
| Harness Verifier | `glm-5.3:cloud` | `max` |
| Small Feature (구형 비활성 경로) | `glm-5.3:cloud` | `high` |
| Large Feature (구형 비활성 경로) | `glm-5.3:cloud` | `high` |

## 실행 시 주의사항

- `harnesscreator run ... --provider ollama --ollama-url http://127.0.0.1:11434`를 사용한다. 기존 CLI의 기본 provider는 변경하지 않았다.
- `--model`, `--candidate-model`, `--strong-model`, `--coding-model`을 사용하면 지정한 역할의 모델명을 덮어쓴다. 위 표를 그대로 사용하려면 이 인자를 생략한다.
- `--effort`는 현재 Ollama 역할별 `think` 값을 변경하지 않는다. 역할별 값은 `src/harnesscreator/cli.py`의 `DEFAULT_OLLAMA_ROLE_EFFORTS`에 정의했다.
- `:cloud` 모델을 사용하려면 Ollama에 해당 모델 접근 권한이 있어야 한다. 가용 여부는 실제 계정과 서버에서 확인한다.
- 모델 라우팅의 기존 값은 보존했다. 최신 소스에서는 입력 경로 탐색과 실행 검증을 분리하는 변경도 적용했다(`UNIVERSAL_INPUT_EXECUTION.md`). 범용 하네스 생성 성공을 보증하지 않는다.

## 수정된 파일

- `src/harnesscreator/cli.py`: 각 역할 모델과 추론 수준을 원래 정책에 맞게 적용. 누락된 `scenario_refiner` 모델 경로 보완.
- `tests/test_cli.py`: 모델·추론 수준, 명시적 `--strong-model` 오버라이드 회귀 테스트.

## 실행 전 테스트

가상환경에서 다음 명령을 실행한다.

```bash
PYTHONPATH=src python -m pytest -q tests/test_cli.py tests/test_ollama_provider.py
```
