# FBv2 V8.1 SP priority and HP boundary review

2026-11-15 · unsigned engineering candidate · no Live execution

## Confirmed V8 defect

The proposed V8 spec sets `caps.full_nohint_sp=false`,
`caps.seed_direction_limit=1`, `caps.sp_concurrent_queue=true`, and
`caps.security_invariant_focus=LIFETIME_OWNERSHIP`. The production setup in
`engine/devtools/original_public_live.py` selects the focused concurrent
branch and does not set `strategy._full_nohint_sp`. V8's new cross-Direction
sort in `engine/fuzzingbrain/worker/strategies/pov_fullscan.py` was guarded by
`_full_nohint_sp`, so it did not run in the actual V8 signed candidate.
The V8 test set that flag explicitly and missed this configuration mismatch.

V8.1 extends the sort guard only to the focused concurrent queue path while
retaining the existing full-nohint path. Other paths keep their previous
ordering. The score remains the existing `_function_campaign_priority` score;
for this candidate it is the pre-registered `LIFETIME_OWNERSHIP` family score.
The change does not select a particular function or create a vulnerability
finding.

## Counterfactual correction

`review_v81/recompute_priority.py` uses the copied V7 pinned 167-function
catalog and V7 selection receipt. The previously missed
`md_consume_link_reference_definitions` had zero-based V7 order 72. A stable
global sort of those selected rows by the V7/V8 family's actual score puts it
at order 51 (family score 20). The old V8 postmortem's order 15 used the
different all-family generic score 75. Both are counterfactual re-sorts of
V7 data, not an observed V8.1 model run. The V7 run started 53 SP generator
conversations, covering orders 0–52 in its original schedule.

The selection receipt now names the two order meanings: `occurrence_order`
enumerates pre-priority Direction-interleaved candidates;
`selected_order` is the planned phase execution order. A test checks that a
high-scoring function from Direction 2 is selected before a lower-scoring
function from Direction 1 while both order fields remain interpretable.

## HP shared boundary

Read-only red-team inspection found no confirmed defect in V8's shared
`CampaignModelGate`/boundary-lock propagation. The HP factory obtains the
same lock as SP, and SP audited host-tool spans hold it across claim,
side effect, and receipt. A new provider-free test constructs the actual HP
pipeline factory and gate: HP reservation remains undebited while the shared
boundary is held, completes once after release, and a cancelled waiter
creates no reservation or transport call. The original V8 source remains
preserved; this test is in the V8.1 copy.

## Evidence and scope

- V8 to V8.1 changed Engine files: `pov_fullscan.py`,
  `test_fullscan_client_factory.py`, `test_original_hp_signed_optin.py`.
  The exact diff is `review_v81/V8_TO_V81_SOURCE_AND_TEST.patch`.
- Engine source pin: `7cf82feae7fd340d22c8a4cc023bd8802bc8905b57dfef61e4ce52b1d5135b95`.
  Product and Evaluation pins are unchanged from V8.
- Focused Engine regression: 159 passed, 0 failed. Raw log and JUnit are
  `V81_FOCUSED_FINAL_RAW.log` and `V81_FOCUSED_FINAL_JUNIT.xml`.
- Engine full regression on the final test tree: 1,713 passed, one skipped,
  six subtests passed. Raw log and JUnit are `V81_ENGINE_FULL_FINAL_RAW.log`
  and `V81_ENGINE_FULL_FINAL_JUNIT.xml`. The preceding full regression,
  before the extra HP contention test was added, passed 1,712 tests,
  skipped one, and passed six subtests.
- The official unsigned spec, prepared admission support, and Scope were
  generated afresh for V8.1. `verify_unsigned_v81.py` reported
  `UNSIGNED_STATIC_ADMISSION_VALIDATED` with zero model, Target, and Fuzzer
  calls. The new Run and human approval files do not exist.

This is engineering evidence, not external independent approval. V8.1 has
not been signed, checked-only, run Live, or shown SP/HP physical E2E success.
The fixed md4c harness remains the campaign input; general HarnessCreator
output is not integrated into this signed candidate.
