"""Approval-gated, three-request schema probe. Never runs a target or fuzzer."""
from __future__ import annotations

import argparse
import asyncio
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
from importlib.metadata import version as distribution_version
import json
import os
from pathlib import Path
import sys
import tempfile
import tomllib
from typing import Any

HERE = Path(__file__).resolve().parent
PRODUCT = Path('/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis')
PRIOR_CLIENT = Path('/home/dawne/SunrinInfosecProject2026/reference/hp-libical-nonblind-contract-20261025')
CONTRACT = HERE / 'ASSERTION_SCHEMA_PROBE_CONTRACT_FINAL.json'
APPROVAL = HERE / 'ASSERTION_SCHEMA_PROBE_APPROVAL.json'
CONSUMED = HERE / 'ASSERTION_SCHEMA_PROBE_APPROVAL_CONSUMED.json'
REQUESTS = HERE / 'ASSERTION_SCHEMA_PROBE_REQUESTS.json'
sys.path.insert(0, str(PRODUCT / 'src'))

from vulnerabilityanalysis.agents import AgentPipeline  # noqa: E402
from vulnerabilityanalysis.llm import AppServerError, CodexAppServerClient, LLMRequest  # noqa: E402
from vulnerabilityanalysis.models import FunctionAnalysis  # noqa: E402


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def save(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, sort_keys=True, indent=2)
        stream.write('\n')


def static_preflight(contract: dict[str, Any]) -> list[dict[str, Any]]:
    require(contract['status'] == 'AWAITING_EXPLICIT_APPROVAL', 'contract not final')
    require(contract['logical_model_calls_max'] == 3 and
            contract['physical_turn_starts_max'] == 3 and
            contract['fuzz_seconds_max'] == 0 and contract['manual_retries_max'] == 0,
            'budget changed')
    require(Path(sys.executable).absolute() == Path(contract['python_executable']) and
            sha(Path(sys.executable)) == contract['python_executable_sha256'],
            'Python environment changed')
    for package, required_version in contract['python_distributions'].items():
        require(distribution_version(package) == required_version,
                f'Python dependency changed: {package}')
    for label, row in contract['pinned_files'].items():
        path = Path(row['path'])
        require(path.is_file() and sha(path) == row['sha256'], f'pin mismatch: {label}')
    rows = json.loads(REQUESTS.read_text())
    require(len(rows) == 3 and
            [row['role'] for row in rows] ==
            ['function_analysis', 'function_analysis', 'assertion_generator'],
            'fixed role sequence changed')
    require([row['payload']['function_name'] for row in rows[:2]] ==
            ['read_guarded', 'bounded_index'], 'analysis function changed')
    assumption_ids = rows[2]['payload']['safe_assumption_ids']
    require([row['safe_id'] for row in assumption_ids] == [0, 1] and
            'dispositions' in rows[2]['output_schema']['required'],
            'two-SAFE assertion schema changed')
    require(rows[2]['payload']['source_start_line'] == 3 and
            rows[2]['payload']['analysis']['function_name'] == 'read_guarded',
            'Assertion source changed')
    forbidden = ('evaluator_only', 'public-testcase', 'AddressSanitizer',
                 'heap-buffer-overflow', 'libarchive', 'libical')
    serialized = json.dumps(rows, ensure_ascii=False)
    require(not any(word.casefold() in serialized.casefold() for word in forbidden),
            'non-synthetic material in fixed requests')
    return rows


def approval_present() -> None:
    require(APPROVAL.is_file(), 'one-use approval absent')
    data = json.loads(APPROVAL.read_text())
    require(data.get('approved') is True and data.get('one_use') is True and
            data.get('contract_sha256') == sha(CONTRACT),
            'approval does not match exact contract')
    require(not CONSUMED.exists(), 'approval already consumed')


def prepare_codex_state(contract: dict[str, Any]) -> None:
    config_path = PRIOR_CLIENT / 'codex_config.toml'
    config = tomllib.loads(config_path.read_text())
    provider = config['model_providers']['hp_openai_zero_retry']
    require(config['model'] == 'gpt-5.6-sol' and
            config['model_reasoning_effort'] == 'max' and
            config['model_provider'] == 'hp_openai_zero_retry' and
            provider['requires_openai_auth'] is True and
            provider['request_max_retries'] == provider['stream_max_retries'] == 0,
            'zero-retry provider configuration changed')
    state = Path('/tmp/codex-va-assertion-schema-probe-20261026')
    state.mkdir(mode=0o700, exist_ok=True)
    state.chmod(0o700)
    auth = Path('/home/dawne/.codex/auth.json')
    require(auth.is_file(), 'existing ChatGPT authentication unavailable')
    for name, original in (('auth.json', auth), ('config.toml', config_path)):
        link = state / name
        if not link.exists() and not link.is_symlink():
            link.symlink_to(original)
        require(link.is_symlink() and link.resolve() == original.resolve(),
                f'private Codex state link changed: {name}')
    descriptor, probe = tempfile.mkstemp(dir=state)
    os.write(descriptor, b'ok')
    os.close(descriptor)
    Path(probe).unlink()
    require(sha(Path(contract['codex_binary'])) == contract['codex_binary_sha256'],
            'Codex executable changed')
    os.environ['CODEX_HOME'] = str(state)


class NoRetryProbeClient(CodexAppServerClient):
    def __init__(self, *, route_hash: str, **kwargs: Any):
        super().__init__(**kwargs)
        self.route_hash = route_hash
        self.physical_starts = 0
        self.function_name: str | None = None
        self.analysis_starts = 0
        self.assertion_starts = 0
        self.attempts: list[dict[str, Any]] = []
        self._attempt: dict[str, Any] | None = None
        self._active_turn_id: str | None = None
        self._visible_output = False

    def begin(self, name: str) -> None:
        require(self.function_name is None, 'previous function remains active')
        self.function_name = name
        self.analysis_starts = self.assertion_starts = 0

    def end(self) -> None:
        self.function_name = None

    async def verify_route(self) -> None:
        await self.start()
        account = await self._request('account/read', {'refreshToken': False})
        route = account.get('workspaceRouting')
        require(account.get('requiresOpenaiAuth') is True and isinstance(route, dict),
                'account authentication or Workspace Routing unavailable')
        digest = hashlib.sha256(json.dumps(route, sort_keys=True).encode()).hexdigest()
        require(digest == self.route_hash, 'Workspace Routing fingerprint changed')
        models = (await self._request('model/list', {'includeHidden': True})).get('data', [])
        require(any(isinstance(item, dict) and
                    (item.get('id') == self.model or item.get('model') == self.model)
                    for item in models), 'approved model unavailable')

    async def _request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == 'turn/start':
            require(self.function_name is not None and self._attempt is not None,
                    'model start outside fixed request')
            require(self.physical_starts < 3, 'physical turn/start cap exhausted')
            require(params.get('model') == 'gpt-5.6-sol' and params.get('effort') == 'max',
                    'model routing changed')
            input_text = (params.get('input') or [{}])[0].get('text', '')
            role = input_text.split('\n', 1)[0].removeprefix('ROLE: ').strip()
            require(role == self._attempt['role'], 'unapproved model role')
            self.physical_starts += 1
            self._attempt['physical_turn_start'] = self.physical_starts
            self._attempt['request_id'] = self._request_id + 1
            self._attempt['request_sha256'] = hashlib.sha256(json.dumps({
                'input': params.get('input'), 'outputSchema': params.get('outputSchema'),
                'model': params.get('model'), 'effort': params.get('effort')},
                ensure_ascii=False, sort_keys=True).encode()).hexdigest()
            response = await super()._request(method, params)
            self._attempt['turn_id'] = (response.get('turn') or {}).get('id')
            return response
        return await super()._request(method, params)

    async def _read(self) -> dict[str, Any]:
        message = await super()._read()
        if message.get('method') == 'error' and (message.get('params') or {}).get('willRetry') is True:
            raise AppServerError('internal provider retry announced; stopped')
        params = message.get('params') or {}
        if self._active_turn_id and params.get('turnId') == self._active_turn_id:
            if message.get('method') == 'item/agentMessage/delta' and params.get('delta'):
                self._visible_output = True
            elif message.get('method') == 'item/completed':
                item = params.get('item') or {}
                if item.get('type') == 'agentMessage' and item.get('text'):
                    self._visible_output = True
        return message

    async def _collect(self, thread_id: str, turn_id: str) -> str:
        self._active_turn_id = turn_id
        try:
            return await super()._collect(thread_id, turn_id)
        finally:
            self._active_turn_id = None

    async def generate(self, request: LLMRequest) -> dict[str, Any]:
        require(self.function_name is not None, 'request outside fixed function')
        require(request.role in {'function_analysis', 'assertion_generator'},
                'unapproved role')
        if request.role == 'function_analysis':
            require(self.analysis_starts == 0, 'duplicate function analysis')
            self.analysis_starts += 1
        else:
            require(self.assertion_starts == 0, 'duplicate Assertion generation')
            self.assertion_starts += 1
        self._visible_output = False
        self._attempt = {'function': self.function_name, 'role': request.role,
                         'ordinal': 1,
                         'started_at': datetime.now(timezone.utc).isoformat()}
        try:
            result = await super().generate(request)
            self._attempt.update(status='COMPLETED', visible_output=self._visible_output,
                                 response_sha256=hashlib.sha256(json.dumps(
                                     result, ensure_ascii=False, sort_keys=True).encode()).hexdigest())
            return result
        except BaseException as exc:
            self._attempt.update(status='ERROR', error=f'{type(exc).__name__}: {exc}',
                                 visible_output=self._visible_output,
                                 raw_response_written=bool(request.raw_response_path and
                                                           request.raw_response_path.is_file()))
            raise
        finally:
            self._attempt['finished_at'] = datetime.now(timezone.utc).isoformat()
            self.attempts.append(self._attempt)
            self._attempt = None


class Replay:
    def __init__(self, response: dict[str, Any]):
        self.response = response

    async def generate(self, request: LLMRequest) -> dict[str, Any]:
        return self.response


async def parse_assertion_response(request: dict[str, Any],
                                   response: dict[str, Any]) -> dict[str, Any]:
    payload = request['payload']
    analysis_data = dict(payload['analysis'])
    analysis_data.pop('safe_assumption_ids', None)
    analysis = FunctionAnalysis(**analysis_data)
    source = (HERE / 'assertion_schema_fixture.c').read_text()
    first = source[source.index('unsigned read_guarded('):source.index('\n\nsize_t bounded_index(')]
    pipeline = AgentPipeline(Replay(response))
    proposals = await pipeline.generate_assertions(
        analysis, 'synthetic-worker', 'synthetic-direction', first,
        source_start_line=3)
    return {'safe_count': len(analysis.safe_assumptions),
            'model_assertion_count': len(response.get('assertions', [])),
            'parsed_assertion_count': len(proposals),
            'dispositions': pipeline.last_assertion_dispositions,
            'disposition_errors': pipeline.last_assertion_disposition_errors,
            'parsed_assertion_statuses': [row.status for row in proposals]}


async def run_live(contract: dict[str, Any], requests: list[dict[str, Any]]) -> Path:
    client = NoRetryProbeClient(
        route_hash=contract['workspace_routing_sha256'], cwd=HERE,
        model='gpt-5.6-sol', effort='max', timeout_seconds=600,
        executable=contract['codex_binary'])
    try:
        # This check precedes approval consumption and never starts a model turn.
        await client.verify_route()
        approval_present()
        save(CONSUMED, {'contract_sha256': sha(CONTRACT),
                        'consumed_at': datetime.now(timezone.utc).isoformat()})
        output = HERE / 'assertion_schema_probe_runs' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        output.mkdir(parents=True, mode=0o700)
        results: list[dict[str, Any]] = []
        status = 'INCOMPLETE'
        try:
            # Detect a route change between approval consumption and the first request.
            # A failed second check leaves a receipt, but never starts a model turn.
            await client.verify_route()
            for index, row in enumerate(requests):
                static_preflight(contract)
                function = (row['payload']['function_name'] if index < 2 else
                            row['payload']['analysis']['function_name'])
                client.begin(function)
                try:
                    model_request = LLMRequest(
                        role=row['role'], instructions=row['instructions'],
                        payload=row['payload'], output_schema=row['output_schema'],
                        model='gpt-5.6-sol', effort='max',
                        raw_response_path=output / 'raw' / f'{index+1:02d}.txt')
                    response = await client.generate(model_request)
                    save(output / f'{index+1:02d}_response.json', response)
                    result = {'role': row['role'], 'function': function,
                              'response_sha256': sha(output / f'{index+1:02d}_response.json')}
                    if index < 2:
                        hypotheses = response.get('hypothesis_evaluations', [])
                        result.update(hypothesis_count=len(hypotheses),
                                      input_influence=[item.get('input_influence')
                                                       for item in hypotheses])
                    else:
                        result.update(await parse_assertion_response(row, response))
                    results.append(result)
                    save(output / f'{index+1:02d}_parsed.json', result)
                finally:
                    client.end()
            status = 'COMPLETE_FORMAT_PROBE_ONLY'
        except BaseException as exc:
            save(output / 'blocked.json', {'type': type(exc).__name__, 'message': str(exc),
                                            'completed_requests': len(results)})
            raise
        finally:
            save(output / 'result.json', {'status': status, 'results': results,
                'physical_turn_starts': client.physical_starts,
                'manual_retries': 0, 'attempts': client.attempts,
                'fuzz_seconds': 0, 'pov_count': 0, 'oracle_comparison': 'NOT_PERFORMED'})
        return output
    finally:
        await client.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', help='requires exact one-use approval')
    args = parser.parse_args()
    contract = json.loads(CONTRACT.read_text())
    requests = static_preflight(contract)
    if not args.run:
        print(json.dumps({'status': 'STATIC_PREFLIGHT_PASS', 'fixed_requests': len(requests),
                          'model_calls': 0, 'fuzz_seconds': 0}))
        return
    approval_present()
    prepare_codex_state(contract)
    print(asyncio.run(run_live(contract, requests)))


if __name__ == '__main__':
    main()
