# Catalog/build integrity preflight

`catalog_build_integrity.py` checks every Catalog row and existing edge against
**separate ASan and Coverage build evidence**. It does not select or rank
functions. Until a frozen evaluator build receipt exists, the result is
`BLOCKED: MISSING_FROZEN_BUILD_PROVENANCE`.

The receipt must pin both final binaries and a build capture for each role. A
build capture contains the actual compile command, source and object hashes,
active AST evidence, the link command, input object hashes, and normalized
final link evidence. The active AST evidence lists definitions with exact
source text and direct call edges. The final link evidence lists functions
present in the linked binary. The receipt hash must be frozen before the
selection or model run; the evaluator passes that hash separately to the
preflight. An object filename map and archive `nm` output alone cannot supply
the active branch or final link evidence.

The current Function Pool has no per-role eligibility filter. Accordingly, a
Catalog row that is inactive or absent from the final binary in either role
blocks the whole preflight. A future role-aware Pool could use a different,
explicitly reviewed rule. The checker also blocks if an existing producer edge
has no role-specific active call or has unlinked endpoints. This applies to
original rows and edges as well as supplemental ones.

`ATTESTED_RECEIPT_CONSISTENT` means the pinned files and their claims agree
with one another. It does **not** independently prove that the compiler and
linker produced the claimed AST and link evidence. The evaluator must review
and freeze the receipt producer and build process. No md4c/miniz correctness
or blind evaluation readiness is inferred from a synthetic passing fixture.

Run the synthetic checks with:

```sh
python -m unittest discover -s evaluation_tools -p test_catalog_build_integrity.py -v
```

The CLI writes a report containing counts and reason codes only. It exits 2
on `BLOCKED` and does not print function names or selection order.

## V2 role evidence in the md4c repair draft

V1 receipts remain supported for existing frozen evaluations. The new V2
receipt distinguishes an out-of-line linked symbol from a source function
with a concrete DWARF inline instance inside an executable ELF section. It
accepts either a decoded `DW_AT_ranges` list or a `low_pc/high_pc` range whose
high address form is verified in the DWARF abbreviation. A bare `DW_AT_inline`
flag does not prove executable code. The separate full-candidate regression
compares role-specific AST definitions and concrete inline evidence with all
recorded executable identities; this checker alone does not independently
re-enumerate omitted functions from raw DWARF. The V2 receipt pins the role
binary, role source, AST capture commands, object/link record,
and indirect-reference sidecar. A Catalog function must have executable
evidence in both ASan and Coverage roles; a Callback reference is preserved
but cannot satisfy the direct-call graph check. Direct edges must match the
recorded source call line and role-specific resolution.

`ATTESTED_RECEIPT_CONSISTENT` remains an internal-coherence result. It does
not convert a static call edge into measured runtime reachability, and does
not independently prove the compiler or DWARF producer. The new md4c receipt
and this checker require independent review and a new freeze before use.
