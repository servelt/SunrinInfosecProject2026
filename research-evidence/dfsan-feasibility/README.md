# 입력 의존성 계측의 적용성 반례

[Clang DataFlowSanitizer 공식 문서](https://clang.llvm.org/docs/DataFlowSanitizer.html)의 `dfsan_set_label`과 `-dfsan-conditional-callbacks`만 사용한 작은 실험이다. `check.sh`는 같은 입력을 두 바이너리에 보내고, 구조체와 함수 포인터를 거친 뒤 **입력값으로 분기한 경우에만** 조건 콜백이 나타나는지 검사한다. 다음 명령으로 재현한다.

```sh
sh research-evidence/dfsan-feasibility/check.sh
```

이 실험이 뒷받침하는 것은 계측된 **한 C 번역 단위**에서 입력값이 조건에 영향을 줬는지 구별할 수 있다는 점뿐이다. 바이트 표식은 원본 `read` 다음에 수동으로 붙였다. Clang 14 런타임에서는 비 PIE로 링크해도 현재 WSL에서 실행이 간헐적으로 시작 단계 세그폴트(`139`)로 종료된다. 따라서 `check.sh`는 이 환경에서 안정적인 통과 검사가 아니다. 실행이 완료된 양성/음성 쌍에서는 각각 `tainted_conditions=1/0`을 관찰했지만, 이 결과를 제품 계측 가능성이나 재현성의 증거로 사용하지 않는다. 실제 데몬에 적용하려면 대상 빌드와 라이브러리의 DFSan 계측, 정확한 외부 입력 호출 선택, 요청별 표식 구분, 조건이 선택한 효과의 귀속, 기존 동작과의 차이 검증이 필요하다. 특히 조건 콜백 한 번은 정상 요청 수락·handler 실행·하네스 자격을 증명하지 않는다. 공식 문서도 비계측 라이브러리의 ABI 처리를 별도 과제로 명시한다.

OSS-Fuzz의 로컬 빌더에 있는 Clang 22에서는 공식 문서의 `-dfsan-reaches-function-callbacks`도 별도로 시험했다. `probe_reach.c`를 계측해 입력 바이트에 표식을 붙인 뒤 구조체와 함수 포인터를 통해 `process_request`를 호출하자 `REACH process_request.dfsan label=1`이 나왔다. 음성 반례 `UNRELATED_CONDITION_ONLY`에서도 함수가 입력을 읽기만 하고 실제 결과는 설정값으로 정하지만 같은 `REACH` 기록이 나왔다. 따라서 **함수 도달 콜백만으로 입력→효과를 확정하면 오탐**이다. 로컬 Clang 14는 해당 플래그를 지원하지 않았다. 컨테이너 기본 seccomp에서는 DFSan 런타임의 Linux `personality` 호출이 거절돼 시작하지 못했으며, 이 격리 실험에서는 `--security-opt seccomp=unconfined`가 필요했다. 이 기능을 제품의 `PROVEN_STATIC` 또는 `QUALIFIED` 판정에 연결하지 않았다.

## 작업자 스레드에 대한 추가 실험, 2026-10-31

`probe_thread.c`는 `fread`로 받은 한 바이트에 수동으로 표식을 붙이고, 다른 `pthread`의 `handle`에서 그 바이트의 표식을 확인한다. 동일 소스를 `-DLABEL_INPUT` 유무로 빌드했다. 다음 명령을 격리된 Linux 환경에서 실행할 수 있다.

```sh
clang -O1 -g -no-pie -fsanitize=dataflow -DLABEL_INPUT -pthread research-evidence/dfsan-feasibility/probe_thread.c -o /tmp/hc-dfsan-thread-labeled
clang -O1 -g -no-pie -fsanitize=dataflow -pthread research-evidence/dfsan-feasibility/probe_thread.c -o /tmp/hc-dfsan-thread-unlabeled
printf X | /tmp/hc-dfsan-thread-labeled
printf X | /tmp/hc-dfsan-thread-unlabeled
```

이 WSL의 Clang 14에서 첫 실행은 표식 1/0과 `REACHED=1/0`을 각각 출력했다. 하지만 동일 바이너리를 각각 20회 반복하니 양성 15회·출력 없는 세그폴트 5회, 음성 18회·출력 없는 세그폴트 2회였다. 따라서 스레드 간 표식 전달의 **가능성**은 관찰했으나 이 환경에서 안정적인 원본 추적 수단으로 사용할 수 없다. 더구나 표식을 `fread` 직후 수동으로 붙였고 `handle` 안에 검사 코드를 넣었다. 임의 데몬의 실제 획득 위치, 비계측 라이브러리 경계, 비동기 요청 ID, 정상 결과 귀속은 아직 자동화되지 않았다. 기존 `probe_reach.c`의 음성 반례 때문에 표식이 handler에 도달했다는 사실만으로 정상 기능이 수행됐다고 판정할 수도 없다.

## 원본 코드를 수정하지 않은 `recv` 표식 실험, 2026-10-31

`probe_interpose.c`는 계측된 프로그램의 `recv`를 `LD_PRELOAD`로 가로채 실제 반환 버퍼에 DFSan 표식을 붙인다. 같은 라이브러리의 생성자가 함수 도달 콜백을 등록한다. `probe_interpose_main.c`는 소켓에서 읽은 바이트를 별도 작업자 스레드의 `handle_request`로 전달한다. 재현 명령은 `sh research-evidence/dfsan-feasibility/check_interpose.sh`이다. 로컬 OSS-Fuzz Ubuntu 24.04 빌더의 Clang 22에서 `--security-opt seccomp=unconfined`로 실행한 결과, 20회 양성 실행 모두 handler에서 라벨 1과 함수 도달 콜백을 보였고, 20회 비계측 대조 실행 모두 라벨 0이며 도달 콜백이 없었다. 컨테이너의 기본 seccomp에서는 DFSan의 `personality` 호출이 거절되어 이 결과를 얻지 못했다. `--privileged` 컨테이너에서도 같은 20/20 양성·음성 결과를 얻었다.

이 실험은 **원본 C 파일에 수동으로 표식을 추가하지 않고도 한 `recv` 경로의 스레드 간 입력 흐름을 관찰할 수 있다**는 좁은 결과다. 프로그램은 여전히 DFSan으로 다시 빌드해야 한다. 다른 입력 API, TLS/비계측 라이브러리, 여러 요청이 하나의 read에 섞이거나 나뉘는 경우, 요청별 라벨 관리와 응답·상태의 의미적 성공 귀속은 해결하지 않았다. 함수 도달 콜백은 위의 `UNRELATED_CONDITION_ONLY` 반례처럼 입력이 효과를 선택했다는 증명이 아니므로 `PROVEN_RUNTIME`이나 `QUALIFIED`로 올리지 않는다.

## `read`에는 런타임 래퍼 뒤의 표식이 필요했다

같은 사전 로드 방식만 쓰고 최소 소켓 예제의 `recv`를 `read`로 바꾸면 `ACQUIRE read`는 기록되지만 handler의 라벨은 0이었다. 실제 Dropbear에서도 `read` 직후의 진단용 `dfsan_get_label(in)`이 0이고 표식 있는 조건 콜백이 없었다. 사전 로드 함수가 표식을 붙인 **뒤** DFSan의 기존 `read` 래퍼가 비계측 반환 버퍼의 표식을 초기화하는 것으로 해석된다. 이 해석은 두 재현의 관찰과 일치하지만, 런타임 내부 실행 순서를 별도로 계측한 증명은 아니다.

[Clang 공식 DFSan 문서](https://clang.llvm.org/docs/DataFlowSanitizer.html#abi-list)는 비계측 함수의 사용자 정의 `__dfsw_F` 래퍼와 인수·반환 라벨 ABI를 명시한다. 그 형식에 맞춰 `probe_wrap_read.c`를 비계측 객체로 컴파일하고 링크 시 `--wrap=__dfsw_read`를 지정했다. 기존 DFSan 래퍼가 끝난 **후** 실제 소켓 읽기 버퍼에 표식을 붙인다. `sh research-evidence/dfsan-feasibility/check_wrap_read.sh`로 20회 반복한 최소 예제에서 래퍼 적용은 라벨 1과 handler 도달 콜백 20/20, 래퍼 없는 대조는 라벨 0과 도달 콜백 없음 20/20이었다.

실제 Dropbear 복사본 `/tmp/hc-dropbear-dfsan-interpose-20261031`도 OSS-Fuzz 빌더의 Clang 22로 `-fsanitize=dataflow -mllvm -dfsan-reaches-function-callbacks -mllvm -dfsan-conditional-callbacks`를 사용해 빌드했다. 먼저 원본 파일을 수정하지 않고 사전 로드만 하자 SSH 배너 교환은 됐지만 표식 있는 조건은 0개였다. 원인 확인을 위해 **격리된 실험 복사본에만** `read` 직후 진단용 라벨 출력을 추가했고, 기존 상태에서는 0을 확인했다. 이어 위 사용자 정의 래퍼 객체를 Dropbear와 링크하니 같은 SSH 버전 문자열을 보낸 실행에서 읽기 29회에 표식이 남았고, 표식 있는 조건 28회를 관찰했다. 컨테이너의 `llvm-symbolizer`로 확인한 조건 위치는 `src/common-session.c:487`의 개행 판정과 `:492`의 CR 판정이다. 진단 출력 때문에 실험 복사본의 줄 번호는 원본보다 한 줄 밀렸다.

이는 **실제 C 데몬의 외부 소켓 입력이 조건에 영향을 주는 흐름을, 제품 전용 파서 규칙 없이 관찰한 실험**이다. 아직 제품의 자동 계측기는 아니다. 재빌드·링크 설정, `recvfrom`/TLS 등 다른 획득 API, 여러 읽기와 여러 요청의 라벨 구분, fork 후 요청 ID, 비계측 라이브러리, 성공 결과와 입력의 인과 관계를 해결해야 한다. 라벨이 닿은 조건이 정상 기능을 완료했다는 뜻도 아니므로 하네스 적격 판정에는 사용하지 않는다.

## 두 번째 실제 데몬: LightFTP 평문 제어 연결, 2026-10-31

Dropbear와 다른 입력 처리 구조를 가진 LightFTP v2.0 소스의 **실험용 복사본**을 `/tmp/hc-lightftp-dfsan-20261031`에 만들었다. 이 복사본의 `main.c`, `ftpserv.c`, `cfgparse.c`, `x_malloc.c`를 Clang 22 DFSan으로 빌드했다. LightFTP는 평문 명령에 `recv`, TLS 명령에 `gnutls_record_recv`를 사용한다. GnuTLS는 계측되지 않았으므로 링크 시 `fun:gnutls_*=uninstrumented`와 `fun:gnutls_*=discard` ABI 목록을 적용했다. **따라서 이 결과는 평문 제어 연결에만 해당한다.** TLS 입력의 표식 전달은 검증하지 않았다.

동일한 계측 바이너리와 `probe_interpose.c`에서 `HC_DISABLE_LABEL`만 바꿔 대조했다. `NOOP\r\n` 요청은 양쪽 모두 `200 Command okay.`를 받았다. 표식 적용 시 `ACQUIRE recv` 1회와 입력 의존 조건 콜백 12회가 나왔고, 표식만 끈 대조 실행에서는 같은 획득 1회와 조건 콜백 0회가 나왔다. `llvm-symbolizer`가 조건 위치를 `ftpserv.c:1846`의 CR/LF 검사와 `:1918`, `:1922`의 명령 토큰 분리로 확인했다. `USER anonymous\r\n`도 `331 User anonymous OK. Password required` 응답과 입력 의존 조건 17회를 보였다. 두 요청 모두 함수 도달 콜백은 0회였다. 따라서 **조건 콜백은 실제 입력 파싱의 증거이지만 handler 실행 또는 응답의 인과 증거로 승격할 수 없다.**

실험 바이너리는 일반화된 빌드 어댑터가 아니라 소스 파일을 직접 열거해 빌드한 것이다. 요청별 라벨, 명령별 조건/handler 귀속, 여러 TCP 읽기의 조립, TLS ABI, 원본 실행과 하네스의 등가성은 미해결이다. 현재 제품의 `PROVEN_RUNTIME` 또는 `QUALIFIED` 결과는 이 실험으로 증가하지 않는다.

### 함수 진입을 실제 요청 구간과 연결한 후속 실험

[Clang의 `-finstrument-functions` 옵션](https://clang.llvm.org/docs/ClangCommandLineReference.html)과 [GCC의 콜백 ABI 설명](https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html)을 근거로 `probe_request_scope.c`를 별도 비계측 객체로 만들었다. 실험용 LightFTP 복사본만 `-finstrument-functions -rdynamic -no-pie`로 다시 빌드하고 이 객체를 링크했다. 콜백은 소켓 `recv` 이후 같은 스레드·fd에서 목표 함수 진입을 기록하고 첫 `send`까지의 구간을 남긴다. 컴파일 명령은 다음과 같다.

```sh
clang -O0 -g -c probe_request_scope.c -o probe_request_scope.o
clang -O0 -g -finstrument-functions -rdynamic -no-pie \
  main.c ftpserv.c cfgparse.c x_malloc.c probe_request_scope.o \
  -lpthread -lgnutls -ldl -o fftp-scope
```

`HC_TARGET_FUNCTION=ftpNOOP`으로 원본 서버에 단일 클라이언트·단일 요청을 보내자 `NOOP\r\n`에서는 같은 스레드·fd·요청 번호의 `RECV 4e4f4f500d0a → ENTER ftpNOOP → SEND 323030...0d0a`가 나왔고 클라이언트도 `200 Command okay.`를 받았다. 같은 조건에서 `BOGUS\r\n`을 보내면 `RECV → SEND 500 Syntax error`만 나오고 `ftpNOOP` 진입은 없었다. 원자료는 실험 복사본의 `lightftp-scope.err` 및 `lightftp-scope-negative.err`다. 이는 **해당 두 번의 통제된 원본 실행**에서 실제 간접 호출 대상이 선택되었는지를 구별한다. 앞의 DFSan 결과는 입력이 파싱 조건에 영향을 줬음을 별도로 뒷받침한다.

이 프로브는 아직 제품의 요청 귀속 증명으로 쓰지 않는다. `recv` 1회가 논리 요청 1개라는 전제를 쓰므로 요청 분할·합쳐 읽기·파이프라이닝에서 요청 번호가 틀릴 수 있다. 비동기 작업자나 다른 스레드로 넘어간 함수는 같은 스레드 구간에서 보이지 않는다. `send` 후에도 핸들러가 실행될 수 있고, `send`가 한 응답의 끝이라는 보장도 없다. 이 전제를 검사하거나 요청 경계가 확인되지 않은 결과는 미확정으로 남겨야 한다.

이 한계는 같은 LightFTP에서 재현했다. 한 논리 요청 `NOOP\r\n`을 클라이언트가 `NO`와 `OP\r\n`으로 나눠 보내고 중간에 0.2초를 두자, 원본은 여전히 `200`을 응답했다. 하지만 프로브는 두 `recv`를 요청 1과 2로 잘못 나눴고 `ftpNOOP` 진입을 **요청 2의 `OP\r\n`에 귀속**했다. 원자료는 `lightftp-scope-fragment.err`다. 따라서 함수를 한 번 실제로 열었다는 사실만으로 입력 바이트 전체와 해당 함수의 관계를 증명할 수 없다는 반례가 확보됐다. 제품에 넣으려면 원본 프로그램의 논리 메시지 경계를 확인하는 계측 또는 그와 동등한 근거가 먼저 필요하다.

별도의 [C++ 작업자 반례](probe_scope_threaded.cpp)는 같은 `HELLO` 요청을 수신 스레드에서 직접 처리하거나 `std::thread`에 넘긴다. `python3 research-evidence/dfsan-feasibility/check_scope_threaded.py`로 재현하면 두 실행 모두 `OK` 응답을 내지만, 기존 `probe_request_scope.c`의 함수 진입 기록은 같은 스레드에서만 나온다. 작업자 실행에도 `RECV`는 기록되는데 `ENTER`는 빠진다. 이 프로브가 스레드 지역 `active_fd`를 사용하기 때문이다. 따라서 `recv` 시각·fd·같은 스레드 함수 진입의 조합을 일반 C++ 데몬의 요청 귀속 증거로 승격하지 않는다. 작업자/큐를 통과하는 값 자체의 추적이나 그와 동등한 확인이 추가로 필요하다.

같은 C++ 예제를 [DFSan 대조 스크립트](check_cpp_dfsan_thread.sh)로 다시 컴파일했다. [Clang DFSan 문서](https://clang.llvm.org/docs/DataFlowSanitizer.html#abi-list)가 요구하는 비계측 C++ 런타임 ABI 선언이 없으면 `std::thread::join` 등의 `.dfsan` 심볼을 찾지 못해 링크가 실패했다. 실험에서는 이 한 파일의 미해결 C++ 런타임 심볼만 ABI 목록에 넣었고, 프로젝트의 다른 번역 단위까지 일괄 비계측 처리하는 규칙으로 사용하지 않았다. 표식을 붙인 `recv` 버퍼는 같은 스레드와 작업자 스레드의 처리 함수에서 모두 20/20회 라벨 1로 확인됐고, 대조군은 모두 라벨 0이었다.

그러나 이 예제의 `std::memcmp` 기반 성공 조건에서는 두 스레드 모두 DFSan 함수 도달·조건 콜백이 **0회**였다. 같은 처리를 바이트별 비교로 바꾼 대조 바이너리에서는 두 스레드 모두 20회 실행 동안 함수 도달 콜백 240회와 조건 콜백 100회가 기록됐다. 기본 `memcmp` 바이너리를 그대로 두고 `DFSAN_OPTIONS=strict_data_dependencies=0`만 적용하면 각각 함수 도달 40회·조건 20회로 바뀌었다. [Clang 문서의 해당 옵션](https://clang.llvm.org/docs/DataFlowSanitizer.html#environment-variables)은 사용자 정의 라이브러리 래퍼가 명시적 의존성만 전파할지 결정한다. 이 결과는 **기본 설정의 콜백 음성이 실제 처리 함수 미도달을 뜻하지 않는다**는 반례다. 옵션을 끄면 반대로 과도한 의존성이 생길 수 있으므로 양성 콜백도 의미적 성공이나 요청 귀속으로 승격하지 않는다. 이 결과는 해당 Clang 22·libc++·DFSan ABI 설정의 재현이며 모든 `memcmp` 구현의 성질이라는 주장이 아니다. 일반 C++ 데몬에 적용하려면 런타임 ABI/라이브러리 처리와 source-backed 성공 조건을 별도 검증해야 한다.

이 설정 변경을 실제 LightFTP 실험 빌드에도 [대조 실행](check_lightftp_strict.sh)했다. 이미 빌드해 둔 `/tmp/hc-lightftp-dfsan-20261031/fftp-dfsan`과 같은 `NOOP\r\n` 요청을 사용했다. 세 경우 모두 `200` 응답을 받았다. 표식 없는 대조군은 획득 1회·조건 0회·함수 도달 0회, 기본 엄격 모드는 획득 1회·조건 12회·함수 도달 0회, `strict_data_dependencies=0`은 획득 1회·조건 15회·함수 도달 0회였다. **C++ 작은 예제에서 콜백을 회복한 설정이 이 실제 C 데몬의 목표 함수 콜백을 회복하지 않았다.** LightFTP의 `ftpserv.c:443–446`에서 `ftpNOOP`은 요청 문자열을 읽지 않고 상수 `success200`을 `sendstring`에 전달한다. 따라서 이 handler의 입력값 도달 콜백 부재는 코드를 읽은 결과와도 일치한다. 입력값은 앞선 dispatcher의 조건에 영향을 주지만 그 사실만으로 콜백이 `ftpNOOP` 진입을 기록하지 않는다. 이 실행은 handler 귀속 증거 또는 제품 하네스 자격이 아니다.

LightFTP에서는 소스의 `ftpserv.c:1914`가 호출하는 `recvcmd`가 CR/LF를 확인한 뒤 반환하는 수집 함수임을 확인할 수 있다. 연구 프로브에 `HC_ACQUISITION_FUNCTION=recvcmd`를 지정해 함수 진입부터 반환까지 받은 조각을 **같은 실험 요청 번호**로 기록하도록 바꿨다. 앞의 분할 입력을 다시 보내자 `ACQUIRE_BEGIN request=1 → RECV 4e4f → RECV 4f500d0a → ACQUIRE_END request=1 fragments=2 total=6 → ENTER ftpNOOP request=1 → SEND 200 request=1`이 나왔다. 별도 실행에서 같은 연결로 `BOGUS` 다음 `NOOP`을 보내자 첫 요청에는 `ftpNOOP` 진입이 없고 두 번째 요청에만 있었다. 원자료는 각각 `lightftp-scope-boundary.err`, `lightftp-scope-two.err`다.

이 보정은 **LightFTP 소스에서 확인한 함수 경계**에 한정된다. 다른 데몬의 입력 수집 함수가 여러 메시지를 한 번에 처리하거나, 한 메시지를 여러 함수 호출·스레드·프로세스에 걸쳐 처리한다면 같은 규칙은 성립하지 않는다. 함수 종료만으로 요청 성공을 알 수도 없다. 자동 생성기는 각 대상에서 수집 경계와 성공 결과를 별도로 입증해야 하며, 이 연구 프로브의 출력만으로 `ScenarioWitness`를 적격으로 바꾸지 않는다.
