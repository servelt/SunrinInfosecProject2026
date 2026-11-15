"""Opt-in, model-free official-Harness Global fuzzing development baseline.

This path does not execute FBv2 Direction, SP, or HP. It may only use the
product-issued V2 Harness normal seed or committed upstream example seeds,
the existing Global campaign, and the
same durable physical process ledger for Global and Crash consumer processes.
No finding from this baseline is a model-assisted discovery claim.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import re
import sys
from typing import Any

# Isolated Python omits the script directory. Load the checked-in development
# modules only from this entrypoint's own directory.
_TOOL_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_TOOL_ROOT))

from dev_accounted_global_campaign import AccountedGlobalCampaign
from dev_global_campaign import DevGlobalCampaign, write_json
from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2
from dev_process_envelope_v2 import DevelopmentProcessEnvelopeV2
from vulnerabilityanalysis.official_harness import (
    OfficialPinnedQualification, _qualification_pins_ok,
    issue_official_pinned_qualification,
)


MAX_GLOBAL_SECONDS = 60
MAX_GLOBAL_RESERVATION_SECONDS = 120
MAX_TOTAL_WALL_SECONDS = 3600
MAX_TOTAL_FUZZ_SECONDS = 120
MAX_REPLAY_LIMIT = 2
MAX_PROCESS_OUTPUT_BYTES = 16_777_216
# The product consumer can enter nested original replay, official Harness
# validation, and GDB/root-cause work. Reserve a conservative per-observation
# envelope before permitting a Gate claim. Actual elapsed time is settled by
# the same physical ledger and may be much smaller.
CONSUMER_WALL_RESERVATION_SECONDS = 600


def _bounded_number(value: object, minimum: float, maximum: float) -> bool:
    return (type(value) in (int, float) and math.isfinite(value) and
            minimum <= value <= maximum)


def prepare_baseline(output: Path, qualification: OfficialPinnedQualification, *,
                     global_seconds: int, global_wall_reservation_seconds: float,
                     wall_total_seconds: float, fuzz_total_seconds: float,
                     replay_limit: int, process_output_limit_bytes: int,
                     run_id: str, prior_baseline: Path | None = None,
                     prior_spec_manifest: Path | None = None,
                     prior_spec_manifest_sha256: str | None = None,
                     upstream_seed_corpus: Path | None = None,
                     md4c_spec_examples: bool = False,
                     md4c_spec_composites: bool = False,
                     md4c_spec_flags: bool = False
                     ) -> AccountedGlobalCampaign:
    """Prepare one fresh baseline; no model or Target is called here."""
    if (type(run_id) is not str or not re.fullmatch(r'[A-Za-z0-9_-]+', run_id) or
            type(qualification) is not OfficialPinnedQualification or
            not qualification.product_issued or
            qualification.contract_kind != 'OFFICIAL_OSS_FUZZ_UPSTREAM_HARNESS_V2' or
            not _qualification_pins_ok(qualification) or
            output.exists() or
            type(global_seconds) is not int or
            not 1 <= global_seconds <= MAX_GLOBAL_SECONDS or
            not _bounded_number(global_wall_reservation_seconds,
                                global_seconds + 12.5,
                                MAX_GLOBAL_RESERVATION_SECONDS) or
            not _bounded_number(wall_total_seconds, 1,
                                MAX_TOTAL_WALL_SECONDS) or
            not _bounded_number(fuzz_total_seconds, 1,
                                MAX_TOTAL_FUZZ_SECONDS) or
            type(replay_limit) is not int or
            not 0 <= replay_limit <= MAX_REPLAY_LIMIT or
            type(process_output_limit_bytes) is not int or
            not 1 <= process_output_limit_bytes <= MAX_PROCESS_OUTPUT_BYTES or
            wall_total_seconds <= global_wall_reservation_seconds or
            sum((prior_baseline is not None,
                 upstream_seed_corpus is not None,
                 md4c_spec_examples is True,
                 md4c_spec_composites is True,
                 md4c_spec_flags is True)) > 1 or
            (prior_spec_manifest is None) !=
            (prior_spec_manifest_sha256 is None) or
            (prior_spec_manifest is not None and prior_baseline is None) or
            type(md4c_spec_examples) is not bool or
            type(md4c_spec_composites) is not bool or
            type(md4c_spec_flags) is not bool or
            wall_total_seconds < (global_wall_reservation_seconds +
                                  replay_limit * CONSUMER_WALL_RESERVATION_SECONDS) or
            fuzz_total_seconds < global_wall_reservation_seconds):
        raise ValueError('baseline requires fresh output and pinned V2 authority with headroom')
    output = output.resolve()
    output.mkdir(parents=True, mode=0o700)
    ledger = PersistentProcessLedgerV2.create(
        output / 'process-ledger.json',
        wall_total_seconds=wall_total_seconds,
        fuzz_total_seconds=fuzz_total_seconds)
    work_item_id = ('UPSTREAM_PINNED_SPEC_FUZZ_CONTINUATION'
                    if prior_spec_manifest is not None else
                    'UPSTREAM_PINNED_SPEC_FLAG_PROFILES'
                    if md4c_spec_flags else
                    'UPSTREAM_PINNED_SPEC_COMPOSITES'
                    if md4c_spec_composites else
                    'UPSTREAM_PINNED_SPEC_EXAMPLES' if md4c_spec_examples else
                    'UPSTREAM_PINNED_SEED_CORPUS' if upstream_seed_corpus is not None
                    else 'HARNESS_NORMAL_SEED_FUZZ_CONTINUATION'
                    if prior_baseline is not None else 'HARNESS_NORMAL_SEED')

    def pin_hook(_phase: str, _command: list[str]) -> None:
        if not _qualification_pins_ok(qualification):
            raise ValueError('official V2 authority changed during baseline')

    account = DevelopmentProcessEnvelopeV2(
        ledger, work_item_id=work_item_id, assertion_id='GLOBAL',
        attempt_id=run_id, output_limit_bytes=process_output_limit_bytes,
        total_wall_seconds=wall_total_seconds, pin_hook=pin_hook)
    campaign = DevGlobalCampaign(
        output, qualification, total_fuzz_seconds=fuzz_total_seconds,
        global_seconds=global_seconds,
        global_wall_reservation_seconds=global_wall_reservation_seconds,
        replay_limit=replay_limit, process_envelope=account,
        require_accounted_consumer=True)
    wrapped = AccountedGlobalCampaign(
        campaign, ledger, reservation_key=f'GLOBAL_FUZZ:{work_item_id}:{run_id}')
    if md4c_spec_examples or md4c_spec_composites or md4c_spec_flags:
        wrapped.stage_md4c_spec_examples(
            combine_examples=md4c_spec_composites,
            flag_profiles=md4c_spec_flags)
    elif upstream_seed_corpus is not None:
        wrapped.stage_upstream_seed_corpus(upstream_seed_corpus)
    elif prior_baseline is None:
        wrapped.stage_harness_normal_seed()
    else:
        wrapped.stage_harness_continuation(
            prior_baseline, spec_manifest=prior_spec_manifest,
            spec_manifest_sha256=prior_spec_manifest_sha256)
    identity_kind = ('UPSTREAM_PINNED_SPEC_FUZZ_CONTINUATION_V1'
                     if prior_spec_manifest is not None else
                     'UPSTREAM_PINNED_SPEC_FLAG_PROFILES_BASELINE_V1'
                     if md4c_spec_flags else
                     'UPSTREAM_PINNED_SPEC_COMPOSITES_BASELINE_V1'
                     if md4c_spec_composites else
                     'UPSTREAM_PINNED_SPEC_EXAMPLES_BASELINE_V1'
                     if md4c_spec_examples else
                     'UPSTREAM_PINNED_SEED_CORPUS_BASELINE_V1'
                     if upstream_seed_corpus is not None else
                     'HARNESS_NORMAL_SEED_GLOBAL_BASELINE_V1')
    write_json(output / 'BASELINE_IDENTITY.json', {
        'kind': identity_kind,
        'work_item_id': work_item_id,
        'run_id': run_id, 'seed_provenance': wrapped.seed_provenance,
        'direction_plan_used': False, 'model_calls': 0,
        'discovery_claim': ('BASELINE_ONLY' if prior_baseline is None and
                            upstream_seed_corpus is None and
                            not md4c_spec_examples and
                            not md4c_spec_composites and
                            not md4c_spec_flags else 'EXPLORATION_ONLY'),
        'prior_baseline': (str(prior_baseline) if prior_baseline else None),
        'prior_spec_manifest': (str(prior_spec_manifest)
                                if prior_spec_manifest else None),
        'prior_spec_manifest_sha256': prior_spec_manifest_sha256,
        'upstream_seed_corpus': (str(upstream_seed_corpus)
                                 if upstream_seed_corpus is not None else None),
        'md4c_spec_examples': md4c_spec_examples,
        'md4c_spec_composites': md4c_spec_composites,
        'md4c_spec_flags': md4c_spec_flags,
        'qualification_contract_sha256': qualification.contract_sha256,
        'harness_sha256': qualification.harness_sha256,
        'binary_sha256': qualification.binary_sha256,
        'normal_seed_sha256': qualification.normal_seed_sha256,
        'process_ledger': str(ledger.path),
        'global_seconds': global_seconds,
        'global_wall_reservation_seconds': global_wall_reservation_seconds,
        'wall_total_seconds': wall_total_seconds,
        'fuzz_total_seconds': fuzz_total_seconds,
        'replay_limit': replay_limit})
    return wrapped


def run_baseline(campaign: AccountedGlobalCampaign) -> dict[str, Any]:
    """Execute only the prequalified bounded Global path, then settle it."""
    try:
        started = campaign.start()
        if started != 'ACTIVE':
            result = campaign.final_result
            if result is None:
                raise RuntimeError('baseline did not start or settle')
        else:
            result = campaign.finish()
        # The provenance receipt is separate from a Gate finding. Neither a
        # controlled normal seed nor its descendants may be called Direction work.
        final = {**result, 'seed_provenance': campaign.seed_provenance,
                 'model_calls': 0, 'direction_plan_used': False,
                 'discovery_claim': ('BASELINE_ONLY' if campaign.seed_provenance ==
                                     'HARNESS_NORMAL_SEED' else 'EXPLORATION_ONLY')}
        write_json(campaign.output / 'BASELINE_RESULT.json', final)
        return final
    except BaseException as original:
        # No exception from the cleanup receipt may replace the actual failure.
        # If the Global guard disposition is still unknown, leave a durable
        # stop so a later invocation cannot reinterpret this as a free retry.
        receipt: dict[str, Any] = {'status': 'INCOMPLETE',
                                   'seed_provenance': campaign.seed_provenance,
                                   'model_calls': 0, 'direction_plan_used': False,
                                   'error_type': type(original).__name__}
        try:
            snapshot, sha = campaign.ledger.receipt_snapshot()
            if (campaign.reservation_key in snapshot['active'] and
                    snapshot['stop_status'] is None):
                campaign.ledger.mark_stop(
                    'STOPPED_UNCERTAIN_PROCESS',
                    'baseline failed with an unclosed Global reservation')
                snapshot, sha = campaign.ledger.receipt_snapshot()
            receipt['process_ledger_sha256'] = sha
            receipt['process_ledger_stop_status'] = snapshot['stop_status']
            receipt['global_reservation_active'] = (
                campaign.reservation_key in snapshot['active'])
        except BaseException as cleanup:
            receipt['cleanup_error_type'] = type(cleanup).__name__
            original.add_note('baseline process receipt unavailable: ' +
                              type(cleanup).__name__)
        try:
            write_json(campaign.output / 'BASELINE_INCOMPLETE.json', receipt)
        except BaseException as cleanup:
            original.add_note('baseline incomplete receipt write failed: ' +
                              type(cleanup).__name__)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--public-dev-only', action='store_true')
    for name in ('contract', 'source-root', 'harness', 'binary', 'normal-seed',
                 'oss-fuzz-checkout', 'upstream-checkout', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--contract-sha256', required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--prior-baseline', type=Path)
    parser.add_argument('--prior-spec-manifest', type=Path)
    parser.add_argument('--prior-spec-manifest-sha256')
    parser.add_argument('--upstream-seed-corpus', type=Path)
    parser.add_argument('--md4c-spec-examples', action='store_true')
    parser.add_argument('--md4c-spec-composites', action='store_true')
    parser.add_argument('--md4c-spec-flags', action='store_true')
    parser.add_argument('--global-seconds', type=int, required=True)
    parser.add_argument('--global-wall-reservation-seconds', type=float, required=True)
    parser.add_argument('--wall-total-seconds', type=float, required=True)
    parser.add_argument('--fuzz-total-seconds', type=float, required=True)
    parser.add_argument('--replay-limit', type=int, required=True)
    parser.add_argument('--process-output-limit-bytes', type=int, default=1_048_576)
    args = parser.parse_args(argv)
    if not args.public_dev_only:
        parser.error('explicit --public-dev-only is required')
    qualification = issue_official_pinned_qualification(
        contract_path=args.contract,
        approved_contract_sha256=args.contract_sha256,
        source_root=args.source_root, harness=args.harness, binary=args.binary,
        normal_seed=args.normal_seed, oss_fuzz_checkout=args.oss_fuzz_checkout,
        upstream_checkout=args.upstream_checkout)
    if qualification is None:
        raise ValueError('official V2 Harness qualification failed')
    campaign = prepare_baseline(
        args.output, qualification, global_seconds=args.global_seconds,
        global_wall_reservation_seconds=args.global_wall_reservation_seconds,
        wall_total_seconds=args.wall_total_seconds,
        fuzz_total_seconds=args.fuzz_total_seconds,
        replay_limit=args.replay_limit,
        process_output_limit_bytes=args.process_output_limit_bytes,
        run_id=args.run_id, prior_baseline=args.prior_baseline,
        prior_spec_manifest=args.prior_spec_manifest,
        prior_spec_manifest_sha256=args.prior_spec_manifest_sha256,
        upstream_seed_corpus=args.upstream_seed_corpus,
        md4c_spec_examples=args.md4c_spec_examples,
        md4c_spec_composites=args.md4c_spec_composites,
        md4c_spec_flags=args.md4c_spec_flags)
    result = run_baseline(campaign)
    print(json.dumps({
        'status': result['status'], 'seed_provenance': campaign.seed_provenance,
        'model_calls': 0, 'process_ledger': str(campaign.ledger.path),
        'result': str(campaign.output / 'BASELINE_RESULT.json')}, sort_keys=True))
    return 0 if result['status'] == 'RAN' else 2


if __name__ == '__main__':
    raise SystemExit(main())
