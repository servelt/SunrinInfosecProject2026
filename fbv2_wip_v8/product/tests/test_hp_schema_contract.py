"""HP live response contracts must be strict without losing valid Assertions."""
import asyncio
import unittest

from vulnerabilityanalysis.agents import (
    AgentPipeline, _ANALYSIS, _ASSERTIONS, _offline_legacy_schema,
    function_analysis_schema_sha256,
)
from vulnerabilityanalysis.models import FunctionAnalysis


class Provider:
    def __init__(self, response):
        self.response = response
        self.requests = []

    async def generate(self, request):
        self.requests.append(request)
        return self.response


def analysis(*names):
    return FunctionAnalysis('fn', 'target', 'target.c', 'summary', 'input', [], [],
                            list(names), [])


class HPSchemaContractTests(unittest.TestCase):
    def test_function_analysis_schema_has_stable_sha_shape(self):
        first = function_analysis_schema_sha256()
        self.assertRegex(first, r'^[0-9a-f]{64}$')
        self.assertEqual(first, function_analysis_schema_sha256())

    def test_live_schema_requires_all_new_fields(self):
        self.assertIn('safe_assumption_lifecycle', _ANALYSIS['required'])
        self.assertEqual(set(_ANALYSIS['properties']), set(_ANALYSIS['required']))
        row = _ANALYSIS['properties']['hypothesis_evaluations']['items']
        for key in ('source_file', 'source_line', 'source_quote', 'input_influence'):
            self.assertIn(key, row['required'])
        self.assertEqual(set(row['properties']), set(row['required']))
        self.assertIn('dispositions', _ASSERTIONS['required'])
        self.assertEqual(set(_ASSERTIONS['properties']), set(_ASSERTIONS['required']))
        lifecycle = _ANALYSIS['properties']['safe_assumption_lifecycle']['items']
        self.assertEqual(set(lifecycle['properties']), set(lifecycle['required']))
        self.assertEqual(
            set(lifecycle['properties']['disposition']['enum']),
            {'PROPOSED', 'NEEDS_CONTEXT', 'VALIDATED_SAFE',
             'RECLASSIFIED_VALIDATION', 'INVALIDATED', 'INCOMPLETE',
             'ASSERTION_INELIGIBLE'})

    def test_live_schema_every_object_requires_every_declared_property(self):
        def check(schema, path='$'):
            if not isinstance(schema, dict):
                return
            if schema.get('type') == 'object' and 'properties' in schema:
                self.assertEqual(
                    set(schema['properties']), set(schema.get('required', [])),
                    f'strict provider object mismatch at {path}')
            for key, value in schema.items():
                if isinstance(value, dict):
                    check(value, f'{path}.{key}')
                elif isinstance(value, list):
                    for index, item in enumerate(value):
                        check(item, f'{path}.{key}[{index}]')

        check(_ANALYSIS)

    def test_offline_legacy_schema_alone_allows_missing_lifecycle(self):
        schema = _offline_legacy_schema('function_analysis')
        self.assertIn('safe_assumption_lifecycle', schema['properties'])
        self.assertNotIn('safe_assumption_lifecycle', schema['required'])

    def test_safe_ids_replace_exact_text_matching(self):
        response = {'assertions': [{
            'safe_id': 0, 'safe_assumption': '  may be rephrased  ',
            'runtime_expression': '1', 'source_line': 1,
            'required_context': [], 'rationale': 'test expression'}],
            'dispositions': [{'safe_id': 0, 'safe_assumption': 'also rephrased',
                              'status': 'PROPOSED', 'reason': 'can be checked'}]}
        provider = Provider(response)
        pipeline = AgentPipeline(provider)
        proposals = asyncio.run(pipeline.generate_assertions(
            analysis('original exact SAFE wording'), 'w', 'd',
            'void target(void) { return; }'))
        self.assertEqual(len(proposals), 1)
        self.assertEqual(proposals[0].safe_assumption, 'original exact SAFE wording')
        self.assertEqual(pipeline.last_assertion_dispositions[0]['safe_assumption'],
                         'original exact SAFE wording')
        self.assertEqual(provider.requests[0].payload['safe_assumption_ids'][0]['safe_id'], 0)

    def test_missing_disposition_keeps_valid_proposal_and_records_reason(self):
        response = {'assertions': [{
            'safe_id': 0, 'safe_assumption': 'first',
            'runtime_expression': '1', 'source_line': 1,
            'required_context': [], 'rationale': 'test expression'}],
            'dispositions': []}
        pipeline = AgentPipeline(Provider(response))
        proposals = asyncio.run(pipeline.generate_assertions(
            analysis('first'), 'w', 'd', 'void target(void) { return; }'))
        self.assertEqual(len(proposals), 1)
        self.assertEqual(pipeline.last_assertion_dispositions[0]['status'],
                         'MISSING_DISPOSITION')

    def test_old_response_fallback_requires_explicit_offline_mode(self):
        old = {'assertions': []}
        live = AgentPipeline(Provider(old))
        with self.assertRaisesRegex(Exception, 'MISSING_DISPOSITION'):
            asyncio.run(live.generate_assertions(
                analysis('first'), 'w', 'd', 'void target(void) {}'))
        offline = AgentPipeline(Provider(old), legacy_offline_replay=True)
        asyncio.run(offline.generate_assertions(
            analysis('first'), 'w', 'd', 'void target(void) {}'))
        self.assertEqual(offline.last_assertion_dispositions[0]['status'], 'OTHER')


if __name__ == '__main__':
    unittest.main()
