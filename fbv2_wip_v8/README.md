# FBv2 SP/HP V8 work in progress

This directory contains the current Engine, Product, and Evaluation source snapshot for team review. It is not the signed Live release.

- SP and HP paths are connected. V8 changes the full no-hint SP function order to use generic source risk across Directions and gives parallel HP the shared model boundary lock.
- V7 physical Live ended INCOMPLETE; no automatic vulnerability was independently VERIFIED. V8 has not been run Live.
- Engine provider-free regression: 1711 passed, 1 skipped, 6 subtests passed. Focused SP/HP regression: 157 passed. Logs and JUnit are in review/.
- The md4c experiment uses the pinned fuzz-mdhtml harness. General automatic harness creation is not part of this signed campaign.
- V8 independent review is HOLD for the SP priority and HP parallel behavior. Do not treat this branch as a completed discovery result.

Run tests from engine/: `python3 -m pytest -q tests`. Product dependencies and pinned local fixtures are needed for wider reproduction. The unsigned V8 spec and approval Scope were intentionally not committed because they embed local absolute paths.

The copied tree was smoke-tested with three focused engine files: 155 passed and 2 failed because those two tests require historical cJSON fixtures under `reference/_HISTORY`, which are outside this share. The original V8 regression logs in `review/` were produced in the development tree. This branch is a source handoff under a new directory; it does not replace the repository's existing Product code or FBv2 submodule automatically.
