# V7 single Live postmortem (2026-11-15)

This report reads the completed V7 run. V7 signed source, approvals, and run artifacts were not changed. The V8 directory is an unsigned work copy.

## Outcome

- Run `6af93982f18af15109f18fee`: `INCOMPLETE`, reason `uncertain_remote`; 397 physical model calls. Final Claim settlement is `UNPROVEN` and active process count is 0. `run/PUBLIC_DEV_RESULT.json` SHA-256: `b436bf4636b3a0f3becaf6eacf689b1acbc69e4c0ffe4006265dabc5592c88cf`.
- Global fuzz ran for 32.834 seconds with 5 seeds and observed 0 crashes. `run/global_campaign/DEV_GLOBAL_RESULT.json` SHA-256: `f94604c3ff130e84076737fd86d59b5528ecd9dad01fdf66a60afe1ca7d913a7`.
- Seven distinct SP IDs produced 54 distinct PoV inputs. All 54 `run/pov-runtime/*/runtime.json` receipts report `NO_CRASH` on ASan binary SHA-256 `4b75a6c4e8ace630d9db101592a84d68145448090ba824abc9d597fa8a759196`. No SP Gate VERIFIED is evidenced.
- The selected md4c source revision is `fb83eb2bedcf730bc721ab91b07c80d011cbe38f`. A historical controlled input produced `CRASH_OBSERVED` with the same source revision, harness hash, and ASan binary, but `automatic_discovery=false` and `discovery_credit=NOT_CREDITED`. That input's SHA-256 is absent from all 54 new PoVs. The historical result is not V7 automatic discovery evidence.

## SP terminal error

Model ledger row 391 (`sp`) is `UNCERTAIN` with `AppServerError`. The corresponding FullSPGenerator log at 15:20:51 records an App Server `Invalid prompt` policy rejection with `willRetry: false`. The gate conservatively converts this transport exception to `CampaignUncertain`. Rows 382 and 395 (`pov`) became `UNCERTAIN` with `CancelledError` during abort. The run stopped before final settlement. This is separate from the 54 observed `NO_CRASH` PoVs.

The matching App Server event stream for turn
`01a1dddd-721d-7d12-81fd-512ac4ceb7b1` contains one `turn/started`,
382 agent-message deltas, one moderation metadata event, and a final `error`.
It has no `turn/completed`. `willRetry: false` says the server did not plan a
retry; it does not prove the turn completed or provide a final response. The
V8 work copy keeps this case `UNCERTAIN` and does not silently skip the
function or credit its partial output.

## HP parallel defect

`HP_PARALLEL_ANALYSIS_RESULT.json` records `INCOMPLETE_HP_ERROR`, `CampaignUncertain`, phase `FUNCTION_ANALYSIS`, one completed Function Analysis turn, two requested context items both `FETCHED`, and zero context reanalyses. The second analysis was not reserved in the model ledger. The first HP turn ended at 15:08:50.775; the HP result was written at 15:08:55.493.

An SP PoV `create_pov` tool was running from 15:08:42.078 to 15:09:01.441. `CampaignModelGate.reserve()` rejects any unfinished host tool event as `CampaignUncertain` (`devtools/campaign_model_gate.py:600-603`). SP clients use the shared boundary lock for both model reservation and the full host tool span. The HP `_pipeline_factory()` constructed its own `CampaignLedgeredProvider` without that lock (`devtools/original_hp_live_optin.py:1030-1070` in V7). A provider-free reproduction of the actual gate confirms that a STARTED SP tool prevents an HP model reservation without a physical debit, and that reservation succeeds after the tool is COMPLETED.

The V8 work copy passes the same shared lock to parallel HP Function Analysis and Assertion Generator providers and rejects a mismatched gate or missing lock. It does not relax the rule for orphaned or failed tool events. Focused tests: 77 passed. Independent review, new spec, signatures, check-only, and Live have not been done for V8.

## SP function coverage and V8 scheduling candidate

V7's `SP_FUNCTION_SELECTION_RECEIPT.json` selected 155 unique functions. The
known UAF source function `md_consume_link_reference_definitions` was present
in `small/new` at zero-based order 72. The run started only orders 0 through
52, so the generator did not directly analyze that function. The downstream
`md_collect_marks` was analyzed at order 26 and returned `ANALYZED_NO_SP` with
`INSUFFICIENT` context. `md_push_block_bytes` produced a different arithmetic
overflow hypothesis; its verifier disposition was `TESTABLE_UNCERTAIN`.

The existing generic ASan source score for the UAF source function is 75,
rank 16 of the pinned 167-function catalog. The old scheduler first sorts
functions within each Direction by this score, then interleaves Directions.
On the exact V7 selected-function receipt, sorting each phase globally by the
same generic score moves the function from zero-based order 72 to 15;
`md_collect_marks` moves 26 to 7. This is a scheduling counterfactual, not a
new model or Target result. It does not imply that the model would discover
the bug when the function is analyzed.

In the first 53 selected functions, the old schedule covers all five
Directions with counts 12/10/10/10/11 and a minimum score of 20. The
counterfactual covers all five with counts 10/8/13/14/8 and a minimum score
of 44. Thus the observed gain does not depend on removing a Direction.

The V8 work copy applies global score ordering only to the signed full-nohint
SP path. Phase order and duplicate removal remain in force; equal scores keep
the previous interleaved order. This broadens priority for any high-scoring
source surface without identifying md4c functions in production policy. The
synthetic cross-Direction priority test and focused SP/HP suite passed 157/157.
The full engine suite passed 1711 tests, skipped one, and passed six subtests
with `python3 -m pytest -q tests --disable-warnings --maxfail=1` (261.79s).
This V8 policy change requires a new unsigned spec and independent review
before a new signed campaign.
