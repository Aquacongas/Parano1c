# Paranoid O(1) Roadmap

This roadmap starts from the cleaned architecture in `architecture.md`. The goal is one clear pre-launch O(1) path: headers are native, blocks issue certificates, history recursively folds fixed certificate chunks.

Status convention:

- `[x]` means implemented in code and at least targeted release validation was run.
- `[ ]` means still required. It is not necessarily a wrong idea; it is unfinished work.
- Some early-phase cleanup items remain open while later architectural work proceeds. They stay unchecked until the legacy API/name/format actually disappears from code.

## Phase 0 — remove ambiguity

- [x] Add `architecture.md` as the source of truth.
- [x] Stop building runtime accepted-block certificate records with the old hash-only helper; use the IVC receipt certificate path instead.
- [x] Remove hash-only certificate proof constructors from public `noid_recursive` re-exports.
- [x] Delete remaining hash-only/digest-only certificate helpers from `noid_recursive/src/block_certificate.rs` after tests/benches are moved to the certificate path.
- [x] Remove accepted-block certificate `backend_kind` selector now that there is only one certificate backend.
- [ ] Rename public APIs so legacy words disappear because legacy code disappears, not because it is hidden. Still open: public/local-audit names still use `FullAccepted*` and broad `Checkpoint*` wording even after the public package path was simplified.
- [x] Remove pre-launch version fields/suffixes from O(1)/certificate structs, function names, benches, and public re-exports:
  - removed legacy suffix debt from history-checkpoint and accepted-block-certificate names;
  - removed O(1)/certificate version constants and serialized `version` fields;
  - removed accepted-block predicate/version slots from proof-facing claim schedules;
  - removed backend kind integers where there is only one backend.
- [x] Document sync mode selection: retained-block catch-up first, snapshot/O(1) only beyond the retained window.
- [x] Document full-block data retention: only the last 18 full blocks are normal replay/serving data; older full payloads are prunable after certificate/checkpoint consumption.
- [x] Add sync-mode boundary tests for peer gaps `17`, `18`, and `19` using current rule `gap <= 18` catch-up and `gap > 18` snapshot.
- [x] Audit all sync call sites so small-gap catch-up uses `RECENT_BLOCK_RETENTION_DEPTH`, while reorg safety/finality uses `CONSENSUS_FINALITY_DEPTH`.
- [x] Add storage pruning tests that prove old block bodies, block proofs, auth sidecars, and transient history claims are not required after certificate/checkpoint coverage.
- [x] Replace `docs/security.md` entirely with a concise security boundary aligned with `architecture.md`.

## Phase 1 — certificate authority

Goal: accepted-block certificates are the only input consumed by O(1) history.

Tasks:

- [ ] Define the final `AcceptedBlockCertificate` API with no version/backend multiplexing.
- [x] Keep certificate issuance after `AcceptBlock` only.
- [ ] Prove a fixed certificate statement from accepted block artifacts.
- [ ] Ensure certificate verifier cost is independent of transaction count.
- [ ] Add tests:
  - certificate rejects wrong block id;
  - certificate rejects wrong parent state root;
  - certificate rejects wrong child state root;
  - certificate rejects wrong tx root;
  - certificate rejects tampered accepted-claim digest;
  - certificate proof size/verify time is independent of tx count.
- [ ] Add benches:
  - certificate issuance for coinbase-only;
  - 1 Standard4x8;
  - 16 Standard4x8;
  - max Standard4x8 block;
  - Sweep25x2 cases;
  - certificate verification for all of the above.

Notes:

- Issuance may be expensive and tx-count dependent.
- Verification inside O(1) must be fixed-size/fixed-cost.

## Phase 2 — delete transaction-shaped O(1) inputs

Goal: the public history relation does not consume retained blocks, transaction bodies, auth witnesses, tx-root paths, or exact-state slot paths.

Tasks:

- [ ] Split `noid_block/src/accepted_block_batch.rs` into:
  - private certificate issuance / audit helpers;
  - public O(1) certificate chunk helpers.
- [x] Remove transaction-shaped data from the public checkpoint package: it now serializes only `step_statement`, `certificate_batch_statement`, and `checkpoint_step_proof`.
- [x] Build node checkpoint packages from stored `AcceptedBlockCertificateRecord`s plus canonical headers, not retained block bodies/proofs/sidecars.
- [x] Package construction now binds to stored start/end header anchors and does not rerun header PoW/header-integer trace checks.
- [x] Remove `noid_recursive::checkpoint_proof` helpers that built/verified checkpoint steps from accepted-block component proofs.
- [ ] Remove from all remaining public O(1)-adjacent inputs:
  - `tx_body_standard_inputs`;
  - `tx_body_sweep_inputs`;
  - `authorization_witnesses`;
  - `authorization_traces`;
  - `exact_state_killshot_inputs`.
- [x] Keep retained full witnesses only inside the 18-block full-data window and local retained-block validation/proof helpers; checkpoint package build no longer needs them.
- [ ] Delete public APIs whose verification time grows with transaction count.

## Phase 3 — chunk of 16 certificates

Goal: one chunk proof folds up to 16 accepted-block certificates.

Final chunk relation:

```text
VerifyCertificateChunk16(
    start_header_anchor,
    end_header_anchor,
    start_accumulator,
    certificate[0..16]
) -> end_accumulator
```

Tasks:

- [ ] Define final chunk structs without version/backend fields.
- [ ] Verify receipt/header binding against header anchors, not by re-proving PoW/ASERT.
- [ ] Verify certificate receipt projection.
- [ ] Verify certificate proof validity.
- [ ] Verify state continuity across receipts.
- [ ] Verify accumulator update over ordered accepted-block claims.
- [ ] Support padded short final chunks with fixed proof shape.
- [ ] Add negative tests for every binding above.
- [ ] Bench chunk prove/verify for:
  - 16 coinbase-only certificates;
  - mixed certificates;
  - certificates issued from max-heavy blocks.

## Phase 4 — real recursive previous-proof validity

Goal: O(1) history proof is recursive, not a digest-linked list.

Final recursive step:

```text
HistoryStep(
    previous_history_proof,
    certificate_chunk_16,
    local_header_anchors
) -> next_history_proof
```

Tasks:

- [ ] The proof must verify `previous_history_proof` inside the new proof.
- [ ] Remove paths that only check `previous_proof_digest` shape.
- [ ] Define one final `HistoryProof` object.
- [ ] Public verifier input:
  - proof bytes;
  - local start/end header anchors;
  - expected snapshot boundary height/state root.
- [ ] Add tests:
  - fake previous proof rejected;
  - previous proof from another chain rejected;
  - skipped chunk rejected;
  - reordered certificates rejected;
  - wrong local header anchor rejected.
- [ ] Bench repeated chunks and confirm final proof size is constant.

## Phase 5 — snapshot integration

Goal: P2P snapshot sync accepts only the final O(1) proof.

Tasks:

- [ ] `GetHistoryProof` serves only the final `HistoryProof`.
- [ ] Remove old checkpoint proof envelope from P2P serving.
- [ ] Keep header sync before proof verification.
- [ ] Do not request snapshot/O(1) when retained-block catch-up can close the gap.
- [ ] Keep segment root verification and exact state-root rebuild.
- [ ] Keep retained suffix replay through normal `AcceptBlock`.
- [ ] Ensure a served snapshot proof boundary leaves a retained suffix of at most 18 full blocks available from the serving peer.
- [x] Raise the pre-launch history proof wire cap so the current 100 KiB checkpoint IVC core is not rejected by RPC/P2P.
- [ ] Tighten history proof wire cap again after measuring the final proof format.

## Phase 6 — cleanup names and files

Goal: the code structure matches the architecture.

Tasks:

- [x] Delete `noid_recursive/src/history_proof.rs` if the final O(1) path no longer uses it.
- [x] Delete `noid_recursive/src/prove.rs` and `noid_recursive/src/verify.rs` local-history cache APIs if they remain separate from the final path.
- [x] Delete digest-only tests/benches or convert them to certificate-path tests.
- [ ] Rename modules:
  - `checkpoint_proof.rs` -> `history.rs` or `o1_history.rs`;
  - `checkpoint_ivc_backend.rs` -> `history_chunk.rs`;
  - `block_certificate_ivc.rs` -> `certificate_proof.rs`.
- [x] Remove legacy suffixes and pre-launch O(1)/certificate version fields after the naming/format pass.
- [x] Run full workspace release tests and compile all benches.

## Phase 7 — performance targets

Initial targets before network launch:

- certificate verification: fixed time independent of transaction count;
- chunk verification: fixed time for 16 certificates;
- final history proof size: constant across chunks;
- snapshot proof verification: fast enough to run before segment download;
- certificate issuance: benchmarked and parallelizable, but allowed to be block-cost dependent.

Bench commands to add/finalize:

```text
cargo bench -p bench_prover --bench full_accepted_batch
cargo bench -p noid_recursive --bench checkpoint_ivc
```

Add dedicated benches once the final APIs exist:

```text
cargo bench -p noid_recursive --bench o1_certificate
cargo bench -p noid_recursive --bench o1_chunk16
cargo bench -p noid_recursive --bench o1_recursive
```
