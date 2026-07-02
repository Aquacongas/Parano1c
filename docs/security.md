# Security Specification

`architecture.md` is the source of truth for the pre-launch architecture. This document records the security boundaries that must hold while the O(1) cryptography is completed.

## Sync authority

Paranoid has two sync modes:

- `gap <= RECENT_BLOCK_RETENTION_DEPTH` (`18` blocks): sync headers/full blocks and run normal `AcceptBlock` for every missing block. No snapshot and no O(1) history proof.
- `gap > RECENT_BLOCK_RETENTION_DEPTH`: snapshot sync may be used. Headers are still validated from genesis before the snapshot boundary is accepted.

Headers are stored permanently from genesis. Full block data is retained only for the recent 18-block serving/replay window and is prunable after certificate/checkpoint consumption.

## Header boundary

The header layer is native and linear. It verifies:

- block ids and parent links;
- Poseidon2b PoW digest and strict target comparison;
- ASERT target updates;
- median-time-past and timestamp rules;
- cumulative chainwork;
- finalized-prefix fork choice;
- rolling header anchors.

The O(1) layer must not re-prove PoW, ASERT, MTP, chainwork arithmetic, or header parent links. It binds to locally verified header anchors.

## Block acceptance boundary

`AcceptBlock(parent_state, block, BlockProof, BlockAuthSidecar)` is the expensive tx-count-dependent path. It verifies:

- canonical transaction root;
- public transaction logic;
- authorization proof(s) for non-coinbase transactions;
- exact UTXO sparse-Merkle transition;
- ReuseGuard transition;
- child state root equals the block header `state_root`.

The block header `state_root` is the exact composite root:

```text
state_root = Poseidon2b(EXSTROT, log_slots, exact UTXO sparse-Merkle root, ReuseGuard root)
```

After a block is accepted, the node issues an accepted-block certificate. Certificate issuance may be expensive; certificate verification inside O(1) must be fixed-size/fixed-cost.

## O(1) history boundary

The final O(1) history proof folds fixed chunks of accepted-block certificates:

```text
previous_history_proof + certificate_chunk_16 + local_header_anchors -> next_history_proof
```

The proof must verify:

- previous O(1) proof validity, or the genesis/base case;
- accepted-block certificate validity;
- receipt projection from each certificate statement;
- receipt/header-anchor binding;
- state-root continuity across receipts;
- accumulator continuity over ordered accepted-block claims.

The O(1) relation must not consume transaction bodies, wallet authorization witnesses, tx-root paths, exact-state slot paths, retained full blocks, or PoW/header integer witnesses.

## Snapshot boundary

A snapshot package is valid only if the verifier:

1. validates headers and chainwork from genesis to the snapshot boundary;
2. computes local header anchors;
3. verifies the O(1) history proof against those anchors;
4. downloads state segments;
5. recomputes segment roots and the exact state root;
6. requires that root to equal `header[F].state_root`;
7. replays the retained suffix, at most 18 full blocks, through normal `AcceptBlock`.

## Forbidden authority

The final architecture must not accept:

- hash-only or digest-only accepted-block certificate proofs;
- checkpoint/head records that only prove digest shape;
- local accepted-claim sidecars as public authority;
- retained full block witnesses inside public O(1) history;
- any O(1) relation that re-proves header PoW/ASERT instead of binding to verified header anchors;
- marker, stub, empty, checksum-only, or non-consensus proof objects.

## Completion evidence before network use

Before public snapshot acceptance, keep fresh evidence for:

- boundary tests for `17`, `18`, and `19` block sync gaps;
- positive and negative tests for header anchors, state roots, certificate digests, receipt projection, and recursive heads;
- one chunk over 16 accepted-block certificates;
- repeated chunks with constant final proof size;
- verifier time for the final public O(1) proof;
- differential tests proving the optimized certificate relation matches native block validation on accepted and rejected blocks.
