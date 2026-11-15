# FBv2 SP/HP V8.1 work in progress

This directory is a team-review snapshot. The folder name stays `fbv2_wip_v8` to preserve the earlier link; the current code on this branch is V8.1. It does not replace the repository's existing Product code or FBv2 submodule automatically.

- Engine orchestrates the parallel SP/HP campaign; Product supplies analysis, physical execution, and Independent Gate functions. Evaluation Tools contain development adapters and tests.
- The V8 cross-Direction SP priority change was inactive for the proposed concurrent family profile. V8.1 enables it for that actual profile. See `review/v81/V81_FUNCTIONAL_REVIEW_REPORT.md` and the exact patch.
- The campaign uses the pre-registered `LIFETIME_OWNERSHIP` family score. On pinned V7 data, the missed md4c UAF function moves from zero-based order 72 to counterfactual order 51. This is a scheduling calculation, not a new model result.
- HP still shares the model gate and host-tool boundary; a new provider-free test covers reservation delay and cancellation.
- Final V8.1 Engine provider-free regression: 1713 passed, 1 skipped, 6 subtests passed. Focused regression: 159 passed. Raw logs and JUnit are in `review/v81/`.
- V7 Live ended INCOMPLETE; V8.1 has not been run Live. No automatic vulnerability was independently VERIFIED. The md4c experiment uses a pinned fuzz-mdhtml harness; general automatic HarnessCreator integration is not part of this signed campaign.
- V8.1 external functional cold review is pending. This is not a signed or merge-ready Live release.

The unsigned spec and approval Scope are not committed because they contain host-specific absolute paths. The self-contained V8.1 review ZIP is supplied separately. Tests require the project dependencies and some pinned historical fixtures.
