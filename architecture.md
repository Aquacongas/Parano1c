# O(1) architecture

This document is the source of truth for the pre-launch architecture. There is one design and one network protocol. The O(1)/certificate path has no pre-launch version multiplexing; relation identifiers are schema identifiers, not network forks.

## Core rule

Paranoid has five separate decisions/layers:

1. **Sync mode selection** — choose ordinary retained-block catch-up or snapshot sync.
2. **Header chain** — native, linear, stored from genesis.
3. **Full-block retention** — keep only the recent full-data window.
4. **Block acceptance** — expensive per-block validation and certificate issuance.
5. **O(1) history** — recursive proof over fixed-size accepted-block certificates.

Do not mix these layers.

```text
peer_tip - local_tip fits retained-block window
    -> fetch headers/blocks
    -> AcceptBlock for every missing block
    -> no snapshot and no O(1) history proof

peer_tip - local_tip is beyond retained-block window
    -> snapshot boundary + O(1) history proof
    -> state segments
    -> retained suffix replay through AcceptBlock

headers from genesis
    -> local header anchors

block + proof + auth sidecar + pre-state
    -> AcceptBlock
    -> accepted-block certificate

previous O(1) proof + 16 certificates + local header anchors
    -> next O(1) proof
```

## Sync mode selection

A node must not use snapshot/O(1) sync for a small ordinary catch-up.

If a peer is ahead but the missing suffix fits the retained-block serving window, the node downloads headers and retained full blocks and applies each block through normal `AcceptBlock`. No snapshot manifest, state segments, or O(1) history proof are needed.

The current pre-launch window is:

```text
RECENT_BLOCK_RETENTION_DEPTH = 18 blocks
```

The current node code requests snapshot sync only for a gap greater than the retained full-block depth, so the practical boundary is:

```text
gap <= 18  -> retained-block catch-up
gap >  18  -> snapshot/O(1) path may be used
```

Tests cover the `17`, `18`, and `19` block gap boundary.

Relevant code:

- `noid_node/src/main.rs` compact-block gap handling;
- `noid_p2p/src/network.rs` retained suffix serving;
- `noid_chain/src/consensus/params.rs` retention/finality constants.

## Full-block retention layer

Headers are permanent; full block data is not.

A node retains full block payload data only for the recent serving/replay window:

```text
RECENT_BLOCK_RETENTION_DEPTH = 18 blocks
```

“Full block data” means the data needed to replay or serve a block natively:

- block body bytes;
- `BlockProof` bytes;
- `BlockAuthSidecar` bytes;
- undo logs and transient accepted-claim/full-witness material.

Anything older than this window is prunable and must not be required by snapshot/O(1) sync. The long-term history authority after pruning is:

- headers and header anchors from genesis;
- accepted-block certificate records written at block acceptance time;
- O(1) history proofs/checkpoint coverage;
- current state snapshot/segments.

Implementation detail: accepted-block certificates are written when a block is accepted. Checkpoint/O(1) package construction consumes stored certificate records plus headers, not old full payloads. The protocol must treat only the last 18 full blocks as available for normal block sync and retained suffix replay.

Relevant code:

- `noid_chain/src/consensus/params.rs` (`RECENT_BLOCK_RETENTION_DEPTH`);
- `noid_chain/src/storage/mdbx_store.rs` pruning of `recent`, `block_proofs`, `block_auth_sidecars`, and history claims;
- `noid_p2p/src/network.rs` recent block serving.

## Header chain layer

Headers are stored and verified from genesis by every node. This is intentional.

The header layer verifies and stores:

- block id / parent links;
- Poseidon2b PoW digest and strict target comparison;
- ASERT target updates;
- median-time-past and timestamp rules;
- cumulative chainwork;
- finalized-prefix fork choice;
- rolling `HeaderChainAnchor` values.

The O(1) layer must not re-prove PoW, ASERT, MTP, integer chainwork arithmetic, or header parent links. It only binds to locally verified header anchors.

Relevant code:

- `noid_chain/src/block_header.rs`
- `noid_chain/src/consensus/pow.rs`
- `noid_chain/src/header_anchor.rs`
- `noid_node/src/main.rs` header sync paths

## Block acceptance layer

Block acceptance is the expensive path. It may depend on transaction count, proof sizes, authorization proofs, and exact state paths.

A receiving node accepts a block only through the production predicate:

```text
AcceptBlock(parent_state, block, BlockProof, BlockAuthSidecar) -> child_state
```

This predicate checks:

- native consensus/header admission for the next block;
- canonical tx root and public transaction logic;
- one AuthGKR proof per non-coinbase transaction;
- exact sparse-Merkle UTXO transition;
- ReuseGuard transition;
- child state root equals the block header state root.

After accepting a block, the node builds an accepted-block certificate. Certificate construction is allowed to be expensive because it happens once per accepted block, not during snapshot sync.

Relevant code:

- `noid_block/src/validate.rs`
- `noid_block/src/exact_state_transition.rs`
- `noid_block/src/accepted_block_certificate.rs`
- `noid_gkr/src/owner_auth.rs`
- `noid_gkr/src/wallet_authorization.rs`

## Accepted-block certificate

The certificate is the boundary between expensive block validation and fast O(1) history.

A certificate contains:

- a fixed accepted-block statement;
- a proof that the statement was produced by the accepted-block relation;
- a fixed receipt projected from the statement;
- a validity handle committed to the certificate proof.

The statement binds:

- block height and block id;
- parent block id;
- parent and child state roots;
- tx root;
- digests of block body, block proof, and auth sidecar;
- accepted-block claim digest;
- accepted state-transition claim digest;
- exact transition digest;
- resource counters.

The O(1) history layer verifies certificates and receipts. It does not read transaction bodies, wallet authorization proofs, tx-root paths, exact-state slot paths, retained full blocks, or header PoW witnesses. Current checkpoint package construction follows this boundary: it reads canonical headers, stored `AcceptedBlockCertificateRecord`s, and already-validated start/end `HeaderChainAnchor`s from the header DB.

Current cleanup decision:

- runtime certificate records use the IVC receipt certificate path;
- hash-only/digest-only certificate proofs are removed and are not public O(1) authority;
- the remaining work is to replace the receipt-projection proof with the final fixed accepted-block certificate relation.

## O(1) history layer

The O(1) history proof is recursive over fixed chunks of accepted-block certificates.

Chunk size:

```text
O1_CHUNK_BLOCKS = 16
```

For a chunk, the prover supplies 16 accepted-block certificate records or a final padded short chunk. The proof checks:

1. previous O(1) proof validity, or genesis/base case;
2. each accepted-block certificate validity;
3. receipt projection from each certificate statement;
4. receipt/header-anchor binding against the locally verified header chain;
5. state continuity:
   ```text
   receipt[i].parent_state_root == state[i-1]
   receipt[i].child_state_root  == state[i]
   ```
6. accumulator continuity over ordered accepted-block claims;
7. construction of the next history head.

The public verifier receives a bounded proof and local header anchors. It checks the proof against those anchors. It does not replay blocks.

The final recursive relation must prove:

```text
Verify(previous_history_proof) AND VerifyCertificateChunk16(...)
```

A digest link to a previous proof is not enough.

Relevant current code to simplify into this model:

- `noid_recursive/src/checkpoint_proof.rs`
- `noid_recursive/src/checkpoint_ivc_backend.rs`
- `noid_recursive/src/block_certificate.rs`
- `noid_recursive/src/block_certificate_ivc.rs`
- `noid_block/src/accepted_block_batch.rs`

## Snapshot sync

Snapshot sync uses O(1) history only to authorize a finalized state boundary. State transfer is not O(1); segments scale with state size.

Snapshot sync is only for gaps beyond the retained-block catch-up window. If the node can reach the peer tip by downloading the peer's retained full blocks, it should do that instead.

The verifier order is:

1. sync and validate headers from genesis to the snapshot boundary;
2. compute local header anchors;
3. verify O(1) history proof against those anchors;
4. download manifest segments;
5. recompute segment roots;
6. rebuild exact state root and require it equals `header[F].state_root`;
7. replay the retained suffix, at most 18 full blocks, through normal `AcceptBlock`.

Relevant code:

- `noid_p2p/src/protocol.rs`
- `noid_p2p/src/network.rs`
- `noid_node/src/main.rs`
- `noid_chain/src/storage/mdbx_context.rs`
- `noid_chain/src/storage/mdbx_store.rs`

## Cryptographic domains

Poseidon2b domains are fixed by `noid_poseidon2b/src/native/domain.rs`.

Important separation:

- `BLOCKHDR` — semantic block id;
- `POWHDR__` — mining digest;
- `TXBODY__` — tx body hash;
- `EXSTSLT_`, `EXSTNOD_`, `EXSTROT_` — exact state;
- `RGDBUCK_`, `RGDNODE_` — ReuseGuard;
- `HDRPROJ_`, `HDRANCH_` — header anchors;
- `HISTCLM_`, `HISTTRN_`, `HISTPRF_` — history/certificate/O(1) proof commitments.

## What is not part of the final architecture

Remove or keep strictly private until removed:

- public hash-only accepted-block certificate proofs;
- digest-only checkpoint authority;
- local history claim sidecars as public authority;
- public history proof paths that only check shape/digests;
- O(1) relations that replay transaction bodies or exact-state witnesses;
- O(1) relations that re-prove PoW/ASERT/header integer rules;
- multiple protocol versions before launch.
