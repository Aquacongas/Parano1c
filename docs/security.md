# Security Specification

This document states the current security boundary for Paranoid consensus,
history proofs, and snapshot sync. It avoids describing inactive proof
experiments as production authority.

## Current Status

Trustless arbitrary-peer snapshot sync is not enabled.

The current network authority is:

- native header validation from genesis;
- native block validation for retained blocks;
- detached block proof and authorization sidecar verification during block
  acceptance;
- local storage of accepted history claim fields for future proof workers.

The current history claim sidecar is not public authority. It is a local witness
derived after block acceptance.

## Semantic Block

A semantic block consists of:

- canonical 212-byte `BlockHeader`;
- ordered transaction bodies committed by `tx_root`;
- detached validation witness required for acceptance:
  `BlockProof` and `BlockAuthSidecar`.

Detached witness bytes are not part of semantic block identity or mining work.
They must verify before a block is accepted, but alternative valid encodings do
not create alternative block ids.

Consensus capacity is defined by semantic counters:

```text
max raw txs including coinbase = 256
max user txs                  = max raw txs - 1 coinbase
max live inputs               = 1020
max user outputs              = 2040
max owner groups              = 1020
max user actions              = 3060
```

Byte limits remain DoS/admission controls. They are not the public O(1)
history authority.

## Header And PoW

The chain-link block id is:

```text
block_id = Poseidon2b(BLOCKHDR, semantic_header_fields)
```

The mining digest is:

```text
pow_digest = Poseidon2b(POWHDR__, pow_header_fields)
```

The PoW field schedule has exactly 16 `Block128` elements:

```text
prev_block_hash       2 fields
state_root            2 fields
tx_root               2 fields
timestamp             1 field
height                1 field
miner_address         2 fields
nonce                 1 field
difficulty_target     2 fields
log_slots             1 field
active_slot_count     1 field
alloc_counter         1 field
```

Consensus accepts PoW only when:

```text
pow_digest < difficulty_target
```

as little-endian 256-bit integers. Equality is rejected.

ASERT target calculation, median-time-past, cumulative chainwork, target floor,
and finalized-prefix fork choice are deterministic integer rules. The PoW hash
primitive is Poseidon2b; target arithmetic is integer consensus code.

## Cryptographic Domains

Consensus hash domains are fixed byte tags mapped into Poseidon2b capacity IVs.
The important separation for block validity is:

```text
BLOCKHDR != POWHDR__
```

Therefore a PoW digest cannot be replayed as a chain-link block id, and a block
id cannot be replayed as mining work.

Consensus and history authority must use Poseidon2b/KillShot-compatible
relations. Non-consensus checksums may appear in local tooling, but they are
not consensus PoW, state-root, accepted-claim, or public history authority.

## Accepted State-Transition Claim

`AcceptedStateTransitionClaim` is emitted only after full block validation has
accepted the transition. It contains 42 fixed `Block128` fields and a
Poseidon2b `TAG_HISTCLM` digest.

The claim is useful because it gives the history worker a compact witness for:

- block height and block id;
- parent and child state roots;
- transaction root;
- slot-count and allocation counters;
- exact UTXO and ReuseGuard roots;
- semantic action/value counters;
- exact transition digest.

However, current block headers do not commit to `claim_digest`. A public
snapshot verifier must not accept arbitrary claim fields from a peer.

Before public O(1) activation, the recursive history proof must derive the
accepted claim from the full accepted-block relation.

Until then, accepted-claim sidecars are local proof-worker inputs only.

## Authorization Boundary

For every non-coinbase transaction, the verifier derives a canonical
authorization statement from the transaction body and authenticated state view:

```text
statement =
    tx_hash
    ordered input slots
    actual unique owners
    input_to_owner mapping
    owner count and capacity
    protocol/domain identifiers
    Poseidon2b PCS commitment binding
```

The authorization relation is:

```text
exists spend_secret:
    H_ADDR_fixed(spend_secret) = owner
```

The proof is accepted only if the owner-batched authorization proof verifies
against the canonical statement. Public history proofs must preserve this
boundary: a cached owner, marker proof, or host-provided statement is not
authority.

## Exact State Boundary

State authority is the exact sparse-state transition:

```text
parent state
+ ordered accepted actions
= child state
```

The child root must equal the block header `state_root`. ReuseGuard updates and
UTXO updates are part of the same accepted transition. A public history proof
must prove or recursively verify this relation; it cannot replace it with a
digest-only local cache.

## Snapshot Authority

A public snapshot package must be verified in this order:

1. Verify headers and chainwork from genesis natively.
2. Compute the local header anchor for checkpoint height `F`.
3. Verify `HistoryCheckpointProof` against that anchor and state root.
4. Recompute snapshot segment roots into one state root.
5. Require the snapshot root to equal `header[F].state_root`.
6. Replay retained suffix blocks after `F` through normal block validation.

The history proof does not replace native header validation. Header validation
stays linear.

## Required O(1) History Language

Public O(1) snapshot sync can be enabled only for a verifier whose accepted
language is equivalent to:

```text
exists finalized semantic blocks and detached validation witnesses:
    S_i = AcceptBlockTimeless(S_{i-1}, B_i, W_i)
    for every finalized block in the proven range
```

The recursive proof must check:

- previous proof validity or the fixed genesis base case;
- exact start/end state continuity;
- Poseidon2b `BLOCKHDR` ids and parent links;
- Poseidon2b `POWHDR__` digest and strict target comparison, if headers are
  proven inside the recursive relation rather than verified natively;
- transaction-root binding to ordered block bodies;
- one authorization proof per non-coinbase transaction;
- exact sparse-Merkle UTXO transition;
- exact ReuseGuard transition;
- exact state-root continuity;
- accepted-claim reconstruction or a consensus claim commitment;
- chain/checkpoint accumulator update over the same ordered accepted blocks.

The current checkpoint IVC chunk core is not yet this full language. It proves
fixed checkpoint/certificate/claim continuity; the next production gate is to
encode the full accepted-block component verifier inside the IVC backend.

## History Proof Activation Gate

Trustless public snapshot sync stays fail-closed until all are true:

- final public proof size is constant across repeated checkpoint chunks;
- final verifier checks previous-proof validity, not just final digest shape;
- proof-core Merkle and Fiat-Shamir hashing on the public recursive path are
  Poseidon2b-compatible;
- accepted claims are derived in-proof from full block validation;
- snapshot root is checked against locally verified headers;
- retained suffix replay is deterministic;
- pruning waits for proven coverage.

Forbidden before activation:

- accepting peer snapshots as trustless;
- pruning because of a digest-only worker head;
- serving a linear chunk-receipt chain as the final O(1) proof;
- treating local history claim sidecars as public authority;
- accepting marker, stub, empty, or checksum-only proof objects;
- using non-consensus checksums as recursive authority.

## Assumptions

The intended production security rests on:

- Poseidon2b collision/preimage resistance for consensus commitments;
- correctness and soundness of the active KillShot/GKR/sumcheck/PCS
  components;
- Fiat-Shamir soundness for the selected transcript hash;
- authorization knowledge soundness;
- sparse-Merkle and ReuseGuard binding;
- exact integer semantics for PoW target, ASERT, MTP, chainwork, and resource
  counters;
- recursive verifier soundness.

The deprecated history workbench has been removed. Production history proof
work now lives in the Poseidon2b-backed `noid_ivc_core`, `noid_ivc_prover`, and
`noid_recursive` path.

## Evidence Required Before Network Use

Before enabling public snapshot acceptance, keep fresh `--release` evidence for:

- unit and integration tests over current claim/header layouts;
- positive and negative tests for tampered header anchors, state roots, claim
  digests, and recursive heads;
- one recursive step over one 16-claim chunk;
- repeated chunks with constant final proof size;
- verifier time for the final public proof;
- differential tests proving the optimized proof relation matches native block
  validation on accepted and rejected blocks.
