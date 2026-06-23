# FIX1 — hard finality, exact chainwork, snapshot fail-closed

## Status

This document captures the approved minimal fix scope before the BIG WIN state-format work.

The goal of FIX1 is to close dangerous consensus/sync paths without building a temporary checkpoint-snapshot storage subsystem on top of the current segmented FRI state format.

## Implementation status after FIX1 pass

The FIX1 items before BIG WINs are implemented:

1. **Exact cumulative chainwork** — done.
   - Exact canonical cumulative chainwork is persisted in `T_CHAIN_WORK`.
   - `ConsensusMeta` stores the current tip, exact cumulative work, and finalized checkpoint.
   - Restart no longer approximates historical work with `GENESIS_TARGET`.
   - Reorg restores exact ancestor chainwork from storage.

2. **Persisted hard-finality machinery** — done.
   - `FinalizedCheckpoint` is non-optional.
   - New DB initializes finalized checkpoint to genesis.
   - Invalid/missing consensus metadata fails explicitly; no silent migration fallback.
   - Finalized pair survives restart.

3. **Finalized-prefix checks in reorg/fork/snapshot paths** — done for current FIX1 paths.
   - Reorg rejects branches that would replace the finalized prefix.
   - Batch reorg defers finalized update until the replacement branch is fully applied.
   - Snapshot installation from arbitrary peers is fail-closed, so it cannot bypass finalized-prefix rules.

4. **Exact-height snapshot verifier** — done.
   - Accepted snapshot proof height must equal manifest/snapshot height.
   - `proof.acc.state_root` must match the manifest/header state root.
   - Lag modes and proof-behind-tip acceptance were removed.

5. **Fail closed when aligned immutable snapshot generation is absent** — done.
   - Public arbitrary-peer snapshot manifest/segment serving is disabled.
   - Public state snapshot install returns an explicit error until immutable checkpoint generation exists.
   - Deep gaps/deep forks no longer recover by installing an arbitrary peer snapshot.

Validation run for this pass:

```text
cargo fmt
cargo test -p noid_chain
cargo check -p noid_node
cargo test -p noid_p2p
```

BIG WINs are **not** part of FIX1 and are **not done** here. They remain the next separate phase:

- wallet Auth-only;
- state transition redesign;
- unique-owner Auth;
- one-column AuthGKR;
- minimal BlockValidityProof.

Current sync behavior after FIX1:

- Normal recent-block validation remains the trustless sync path.
- With the current testnet parameters, `CONSENSUS_FINALITY_DEPTH = 18` and recent block retention is also `18`.
- A node that is more than 18 blocks behind an arbitrary peer should not catch up via public snapshot sync now.
- That is intentional fail-closed behavior until immutable checkpoint generations and the real recursive verifier are implemented.
- Live tests with a gap greater than 18 blocks should expect refusal/fail-closed behavior, not successful public snapshot sync.

## Approved scope for this session

1. Exact cumulative chainwork.
2. Persisted hard finality machinery.
3. Finalized-prefix checks in fork choice, reorg, and snapshot paths.
4. Exact-height snapshot verifier.
5. Fail closed when no aligned snapshot generation exists.
6. Remove/soften public trustless snapshot claims until the real recursive verifier exists.
7. Stage candidate headers; do not write unaccepted candidate headers into canonical header storage.

## Explicitly out of scope for now

Do not add yet:

- `T_CHECKPOINT_META`
- `T_CHECKPOINT_SEGMENTS`
- full checkpoint snapshot server
- full state clone for checkpoint generation
- rollback clone through undo logs
- sparse rollback / copy-on-write checkpoint state
- immutable snapshot generation retention subsystem

Reason: upcoming BIG WIN work is expected to change the state commitment and transition format. Checkpoint storage over the current segmented FRI format would likely be thrown away.

## Core invariants

### Hard finality

Every canonical node has a persisted finalized checkpoint:

```text
FinalizedCheckpoint {
    height: u64,
    hash: [u8; 32],
}
```

The checkpoint is not optional.

Invariants:

1. `finalized.height` is monotonically non-decreasing.
2. `finalized.hash` at a finalized height never changes.
3. Fork choice considers maximum cumulative work only among candidates that preserve the finalized prefix:

```text
candidate_hash_at(finalized.height) == finalized.hash
```

4. A heavier branch inside the finality window may be accepted.
5. A heavier branch that changes a finalized block is rejected.

### Snapshot anchoring

Snapshot verification is exact-height only:

```text
snapshot.height == recursive_proof.height
snapshot.state_root == recursive_proof.acc.state_root
```

No lag grace. No `proof_h .. tip` gap acceptance.

If an aligned immutable snapshot generation is not available, public snapshot serving/acceptance fails closed.

## Constants split

Do not bind consensus finality to undo retention.

Introduce separate parameters:

```rust
pub const CONSENSUS_FINALITY_DEPTH: u64 = 18; // testnet initial value only
pub const UNDO_RETENTION_DEPTH: u64 = 18;
pub const RECENT_BLOCK_RETENTION_DEPTH: u64 = UNDO_RETENTION_DEPTH;
```

`CONSENSUS_FINALITY_DEPTH` is a protocol parameter and must be selected independently for mainnet. `18` blocks at 15 seconds is about 4.5 minutes; a network partition longer than this can create incompatible finalized prefixes and require manual/social recovery.

## Exact cumulative chainwork

Fork choice is safe only if cumulative work is exact.

Required changes:

- persist exact cumulative chainwork;
- store chainwork per canonical height;
- restore exact work from storage after restart;
- never approximate old work with `GENESIS_TARGET`;
- during reorg, roll back to `chainwork[ancestor_height]`;
- compute candidate work from real difficulty targets;
- after reorg success, persist exact new cumulative work.

Canonical metadata should be written atomically as:

```text
ConsensusMeta {
    tip_height,
    tip_hash,
    cumulative_chainwork,
    finalized,
}
```

This metadata must be committed in the same MDBX transaction as header/state/undo updates.

## No migration fallback

The network is not launched. Do not silently infer missing finalized metadata.

Allowed behavior:

```text
new DB     -> genesis ConsensusMeta and finalized genesis
invalid DB -> explicit error / purge recovery path
```

Disallowed behavior:

```rust
if finalized_absent {
    derive_from_tip_minus_finality_depth();
}
```

## Reorg and fork choice rules

Production fork choice flow:

```text
candidate headers/body/proofs downloaded
-> staged outside canonical header table
-> full header validation
-> exact candidate cumulative work
-> finalized-prefix check
-> work comparison among eligible candidates
-> full block/proof validation
-> atomic canonical commit metadata
```

Reorg reject conditions:

```text
ancestor_height < finalized.height
```

or:

```text
ancestor_height == finalized.height
and ancestor_hash != finalized.hash
```

Snapshot must not be used to recover into an incompatible finalized prefix.

## Candidate headers staging

Candidate headers must not be written directly into canonical `T_HEADERS` before acceptance.

The validation pipeline must include:

- PoW;
- linkage;
- height;
- ASERT difficulty transition;
- median-time-past;
- future-time bound;
- log-slots expansion consensus rule;
- exact cumulative work;
- finalized-prefix compatibility.

## Snapshot verifier now

Remove current lag modes:

- no `FINALITY_DEPTH + grace` proof lag acceptance;
- no Mode B acceptance of proof behind snapshot;
- no snapshot at live tip unless proof is exactly at that same height.

Required checks:

```text
proof.height == manifest.height
proof.acc.state_root == manifest.state_root
header(manifest.height).state_root == manifest.state_root
H(header(manifest.height)) == manifest.hash
segment_roots(manifest) == manifest.state_root
proof.acc.chain_hash == expected_chain_hash_from_exact_headers
manifest preserves local finalized prefix
```

Until immutable checkpoint generation exists:

```text
public arbitrary-peer snapshot sync: disabled / fail closed
trusted seed snapshot: allowed only if explicitly marked trusted
normal recent-block validation: trustless
```

## Future checkpoint generation requirements

When snapshot serving returns after BIG WINs, it must use immutable generations.

Generation ID:

```text
SnapshotId = H(
    checkpoint_hash,
    checkpoint_state_root,
    tail_tip_hash
)
```

A generation pins:

- checkpoint height/hash/root;
- state metadata;
- segment set;
- recursive proof;
- tail tip height/hash;
- nullifier window as of checkpoint;
- tail headers/blocks/BlockProofs/Auth sidecars.

Clients that install snapshot at `h` must verify the tail:

```text
h + 1 .. tail_tip
```

A server may advertise a generation only while complete tail data is retained.

## Future snapshot install requirements

Future `install_state_snapshot(...)` must be one atomic MDBX transaction that:

- deletes old missing segments;
- writes new segments;
- writes state metadata;
- replaces/rebuilds owner index;
- sets tip to checkpoint;
- sets finalized to checkpoint;
- writes recursive proof;
- writes nullifier window;
- writes consensus metadata.

In-memory state changes only after successful commit.

## Current RecursiveBlockAir limitation

Exact-height anchoring closes the immediate gap:

```text
proof at h + snapshot at tip + unverified h+1..tip
```

It does not prove the current recursive circuit verifies the full historical `BlockProof` verifier relation.

Current `RecursiveBlockAir` checks folding bucket claims, previous recursive claim, and state-root pins. It does not yet prove the full block verifier, PoW, ASERT difficulty, timestamp, AuthGKR, NativeDelta/state-binding, or FRI source/Merkle relations.

Therefore, public trustless snapshot sync must remain disabled until the real recursive verifier exists.

## Approved implementation order

1. Exact cumulative chainwork.
2. Persisted hard-finality machinery.
3. Finalized-prefix checks in all reorg/snapshot paths.
4. Exact-height snapshot verifier.
5. Fail closed when aligned snapshot generation is absent.
6. BIG WINs, separately:
   - wallet Auth-only;
   - state transition redesign;
   - unique-owner Auth;
   - one-column AuthGKR;
   - minimal BlockValidityProof.
7. Immutable checkpoint generation for the new state format.
8. Real recursive verifier.
9. Only then enable trustless public snapshot sync.

## Test checklist

### Chainwork

- restart restores exact cumulative work;
- no `GENESIS_TARGET` approximation remains;
- reorg to ancestor restores exact ancestor chainwork;
- heavier-by-work branch beats longer-but-less-work branch;
- equal-work tie-break remains deterministic.

### Hard finality

- heavier branch inside finality window accepted;
- heavier branch changing finalized block rejected;
- finalized pair persists across restart;
- finalized height is monotonic;
- incompatible finalized prefixes do not auto-resolve via snapshot.

### Snapshot

- reject `manifest.height > proof.height`;
- reject `manifest.height < proof.height`;
- reject `manifest.state_root != proof.acc.state_root`;
- reject `segment_roots != manifest.state_root`;
- reject snapshot that does not preserve local finalized prefix;
- reject public snapshot when no aligned immutable generation exists.
