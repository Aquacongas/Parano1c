# Header-Anchored O(1) History Roadmap

## Goal

Build O(1) snapshot sync for history/state:

```text
verified headers from genesis
+ O(1) proof over finalized state-transition history
+ snapshot segment recomputation to the proven state_root
= accepted snapshot boundary
```

Headers are linear and mandatory. They are stored once and validated by the
node. The proof backend does not prove header consensus; it binds state history
to the header anchors the node has already checked.

## Selected Backend

Use the in-tree binary-field backend, but not as one giant history batch proof.
A single batch proof would still carry a size/verification dependency on the
history length. The finalized history path must be an incremental accumulator:
each step folds the previous accumulator plus the next accepted state-transition
claim into a new constant-size accumulator instance.

```text
History backend
= Block128 binary tower field
  + Poseidon2b transcript and claim hashing
  + streaming CLMUL RLC accumulator for ordered history rows
  + noid_fri_binius compact interleaved PCS for fixed step/decider openings
  + ARC/PCD-style hash-based accumulation for unbounded finalized history
  + chain accumulator over accepted state-transition claims
```

This is the backend to implement first. It matches the current field, hash, FRI,
and state commitment code already present in the repository. The PCS proves the
fixed step relation and decider openings; the accumulation layer is what keeps
the served finalized proof constant-size in the number of blocks.

The proof rows are history/state rows:

- header-anchor projection rows;
- accepted state-transition claim rows;
- exact state-root and counter transition rows;
- chain accumulator items;
- snapshot segment roots.

The verifier sees constant-size endpoints, accumulator instances, and the final
decider proof. The prover streams rows and folds them into the accumulator
instead of materializing a large retained history table.

Current measured native envelope baseline with the fixed decider hash-proof
slot, release bench on 2026-06-29:

```text
cargo test -p bench_prover --release --bench history_accumulator_lite -- --nocapture

n=1:   public_proof=9.71 KB, cache_proof=9.71 KB, local_cache=988 B, decider_statement=176 B, decider_proof=9.06 KB, decider_hash_proofs=8.02 KB, arc_pcd_accum=172 B, accum_state=188 B, arc_pcd_step_proof=12.47 KB, arc_pcd_chunk18_step_proof=21.97 KB, arc_pcd_one_step_proof=20.21 KB, arc_pcd_recursive_step_proof=8.02 KB, arc_pcd_recursive_chain_head=8.96 KB, recursive_head_cache=9.93 KB, arc_pcd_recursive_chunk_chain_head=15.26 KB, recursive_chunk_head_cache=16.23 KB, arc_pcd_recursive_history_proof=10.12 KB, arc_pcd_recursive_chunk_history_proof=16.42 KB, verify_envelope=9.30 ms, fold_envelope=20.06 ms, cache_fold=0.91 ms, cache_proof_time=18.10 ms, core_accum=0.08 ms
n=18:  public_proof=9.71 KB, cache_proof=9.71 KB, local_cache=988 B, decider_statement=176 B, decider_proof=9.06 KB, decider_hash_proofs=8.02 KB, arc_pcd_accum=172 B, accum_state=188 B, arc_pcd_step_proof=12.47 KB, arc_pcd_chunk18_step_proof=21.97 KB, arc_pcd_one_step_proof=20.21 KB, arc_pcd_recursive_step_proof=8.02 KB, arc_pcd_recursive_chain_head=8.96 KB, recursive_head_cache=9.93 KB, arc_pcd_recursive_chunk_chain_head=15.26 KB, recursive_chunk_head_cache=16.23 KB, arc_pcd_recursive_history_proof=10.12 KB, arc_pcd_recursive_chunk_history_proof=16.42 KB, verify_envelope=7.92 ms, fold_envelope=28.39 ms, cache_fold=12.24 ms, cache_proof_time=21.89 ms, core_accum=0.21 ms
n=255: public_proof=9.71 KB, cache_proof=9.71 KB, local_cache=988 B, decider_statement=176 B, decider_proof=9.06 KB, decider_hash_proofs=8.02 KB, arc_pcd_accum=172 B, accum_state=188 B, arc_pcd_step_proof=12.47 KB, arc_pcd_chunk18_step_proof=21.97 KB, arc_pcd_one_step_proof=20.21 KB, arc_pcd_recursive_step_proof=8.02 KB, arc_pcd_recursive_chain_head=8.96 KB, recursive_head_cache=9.93 KB, arc_pcd_recursive_chunk_chain_head=15.26 KB, recursive_chunk_head_cache=16.23 KB, arc_pcd_recursive_history_proof=10.12 KB, arc_pcd_recursive_chunk_history_proof=16.42 KB, verify_envelope=9.85 ms, fold_envelope=112.10 ms, cache_fold=143.94 ms, cache_proof_time=20.77 ms, core_accum=1.25 ms

fixed field schedules:
accum_state_hash_fields=16
pcd_step_fields=54, pcd_step_hash_fields=56
arc_pcd_accum_fields=12, arc_pcd_accum_hash_fields=14
arc_recursive_step_fields=12, arc_recursive_step_hash_fields=14
arc_recursive_chunk_step_fields=12, arc_recursive_chunk_step_hash_fields=14
tagged_pair_hash_fields=6

fixed step wrapper over one header projection + one 42-field claim:
proof=5.47 KB, prove=15.40-16.57 ms, verify=3.88-4.39 ms, native discharge=1.32-3.20 ms

fixed PCD step statement:
statement=752 B, native build=3.53-5.44 ms

batched fixed ARC/PCD step proof:
proof=12.47 KB, prove=34.44-38.64 ms, verify=11.53-13.11 ms

padded fixed ARC/PCD chunk step component:
proof=21.97 KB, live=1/18/18 for n=1/18/255, prove=531.25-587.50 ms, verify=151.07-178.61 ms

raw chunk verifier Fiat-Shamir transcript proof:
proof=6.83 KB, traces=4, ops=10349, perms=5426, trace_build=151.44-179.14 ms, prove=2.38-2.65 s, verify=411.82-451.13 ms, native discharge=297.30-337.69 ms

sound one-step `ArcPcdV1` base case:
proof=20.21 KB, prove=59.00-61.74 ms, untrusted verify=23.49-24.64 ms

fixed recursive ARC/PCD step component:
statement=172 B, proof=8.02 KB, prove=20.03-22.71 ms, verify=5.95-7.62 ms

staged recursive ARC/PCD chain head:
proof head=8.96 KB, recursive-head cache=9.93 KB, worker_fold=77.74 ms/1.64 s/24.62 s for 1/18/255 blocks, serve_head=0.00-0.01 ms, shape verify=5.57-7.08 ms

staged recursive ARC/PCD chunk chain head:
proof head=15.26 KB, recursive-chunk-head cache=16.23 KB, chunk_count=1/1/15 for 1/18/255 blocks, worker_fold=846.36 ms/864.69 ms/15.38 s, serve_head=0.01-0.02 ms, shape verify=81.60-95.53 ms

recursive chunk-step verifier Fiat-Shamir transcript proof:
proof=5.94 KB, traces=2, ops=995, perms=588, trace_build=6.53-7.79 ms, prove=279.16-316.05 ms, verify=39.53-45.37 ms, native discharge=31.11-36.78 ms

staged multi-step `ArcPcdV1` history proof from recursive-chunk-head cache:
proof=16.42 KB, build_from_cache=87.26-104.53 ms, native shape verify=87.24-102.15 ms, untrusted fail-closed check=82.95-100.82 ms

staged multi-step `ArcPcdV1` history proof from recursive-head cache:
proof=10.12 KB, build_from_cache=8.02-9.49 ms, native shape verify=7.76-9.75 ms, untrusted fail-closed check=7.94-9.06 ms

fixed-field GKR hash proofs for canonical history schedules:
PCD step hash proof=4.45 KB, prove=15.81-17.51 ms, verify=2.81-4.33 ms, native discharge=1.42-2.36 ms
ARC accumulator hash proof=3.86 KB, prove=6.23-8.21 ms, verify=1.55-2.85 ms, native discharge=0.64-0.74 ms
tagged pair hash proof=3.56 KB, prove=3.83-5.55 ms, verify=2.02-2.51 ms, native discharge=0.47-0.57 ms
```

This benchmark currently measures the constant public envelope, the incremental
local finalized-history cache, a fixed-size decider proof slot with fixed hash
proofs, and the streaming folding kernel. The served proof size is constant in
the number of covered blocks. `cache_fold` is the one-time/incremental catch-up
cost; `cache_proof_time` is proof assembly from an already-current cache and is
constant in the covered history. The native decider slot proves the fixed hash
schedules it checks, but it is not yet the final trustless backend proof. The
native envelope now builds the `HistoryArcPcdAccumulator` by applying the fixed
PCD step relation for every covered step, not by hashing only the start/end
boundary. The accumulation-state, PCD-step, ARC-accumulator, and tagged-pair
digests use explicit even no-padding field schedules so the GKR component
proves the same schedule the native verifier hashes.
The recursive payload digests are now canonical field transcripts, not Rust
struct serialization. They absorb explicit domain tags, lengths, GKR round
polynomials, batch-eval finals, metadata, statements, and accumulator digests
in verifier-visible order. This gives the recursive backend a stable object to
verify. It does not by itself prove previous proof-chain validity.
The native decider hash slot now batches the five 6-field tagged-pair
commitment checks into one fixed hash proof and keeps the 14-field ARC
accumulator hash as one separate proof. That cuts the native proof/cache proof
to 9.71 KB and the envelope verifier to 7.92-9.85 ms in the latest release
bench.
There is now a fixed-size `HistoryArcPcdStepProof` for one ARC/PCD accumulator
transition. It batches the two 16-field previous/next accumulation-state digest
checks into one fixed hash proof, keeps the 56-field PCD-step digest as one
proof, and batches the two 6-field root/transcript tagged-pair updates into one
fixed hash proof. This is still a step proof, not the final unbounded recursive
verifier; untrusted snapshot acceptance remains fail-closed.
There is also a padded fixed-size `HistoryArcPcdChunkStepProof` for proof-worker
experiments. It always proves an 18-block shape: live blocks first, canonical
zero padding after that. It batches 18 history claim hashes, 36 state hashes,
18 PCD-step hashes, and 36 accumulator-update hashes. The component is
constant-size at 21.97 KB and proves 18 live blocks in 531.25-587.50 ms, but
raw native verification is still 151.07-178.61 ms for 18 live blocks. Its
Fiat-Shamir verifier transcript proof is fixed-size at 6.83 KB, but costs
2.38-2.65 s to prove and 411.82-451.13 ms to verify, with about 1.9 GB memory
high-water in the current bench run. This is useful as a negative benchmark and
as a chunked worker relation correctness oracle, not as the final public
verifier path; the final path must verify the recursive decider, not replay
this raw chunk verifier.
`ArcPcdV1` now has a sound one-step base case: for `step_count == 1`, the
public proof carries both the accepted-claim `HistoryStepProof` and the
`HistoryArcPcdStepProof`, and `verify_history_proof_untrusted` verifies them
end-to-end against local header anchors. The one-step decider is lean: it does
not carry the duplicate native-fold decider hash proofs, and the verifier
recomputes those decider commitments directly while requiring `hash_proofs ==
None`. Multi-step `ArcPcdV1` remains fail-closed with `BackendVerifierMissing`
until recursive accumulation is implemented.
The next recursive component is also fixed: `HistoryArcPcdRecursiveStepProof`
binds `(previous proof-chain digest, previous ARC accumulator, current one-step
proof digest, next ARC accumulator)` into a new proof-chain digest with explicit
14-field recursive-step and accumulator schedules. It batches the recursive-step
statement hash plus previous/next ARC accumulator hashes into one fixed hash
proof, with the next proof-chain digest as one separate tagged-pair proof. This
is the object that will be verified inside the recursive backend; by itself it
is not yet sufficient to open multi-step untrusted acceptance.
There is now also a staged `HistoryArcPcdRecursiveChainHead` and a separate
`LocalHistoryRecursiveHeadCache` for proof-worker use. The ordinary
`LocalHistoryCache` remains the cheap node hot-path cache; the recursive-head
cache wraps it and stores one final head object. Serving the already-current
head is constant and measured at 0.00-0.01 ms, and shape verification is about
5.57-7.08 ms. The recursive head is now an explicit staged payload in
multi-step `ArcPcdV1 HistoryProof`; the served proof from an already-current
recursive-head cache is 10.12 KB, builds in 8.02-9.49 ms, and native shape
verification takes 7.76-9.75 ms. Public untrusted verification remains
fail-closed with `BackendVerifierMissing` for this payload because the current
head proves only the final recursive step shape, not the full accumulated
recursive verifier relation. The worker fold is still one proof per finalized
block and is measured at 24.62 s for 255 blocks, so this is an internal/async
finalized-chain artifact, not the target <2 s served snapshot prover.

There is now also a staged `HistoryArcPcdRecursiveChunkChainHead` and
`LocalHistoryRecursiveChunkHeadCache`. This cache stores no pending headers or
witnesses; callers pass a transient bounded chunk of `1..=18` finalized blocks
to the proof worker, and the cache stores only one final chunk head. The head
now carries the fixed Fiat-Shamir verifier transcript proof for its final
recursive chunk-step verifier. In the latest release bench the head is
constant-size at 15.26 KB, the cache is constant-size at 16.23 KB, and 255
blocks fold as 15 chunks in 15.38 s. The chunk head has its own `ArcPcdV1
HistoryProof` payload in the public envelope: served proof size is 16.42 KB,
build-from-cache is 87.26-104.53 ms, and native verification is
87.24-102.15 ms. The embedded recursive chunk-step verifier transcript proof
remains fixed at 5.94 KB, proves in 279.16-316.05 ms, and verifies in
39.53-45.37 ms. Multi-step untrusted acceptance still remains fail-closed with
`BackendVerifierMissing`: this payload proves the final recursive verifier
transcript and final accumulator boundary, but the full previous-proof validity
relation is not yet implemented. Opening acceptance before that would be a
digest-only shortcut and is explicitly forbidden.

## Public Proof Language

`HistoryProof` public inputs:

- `start_anchor: HeaderChainAnchor`;
- `end_anchor: HeaderChainAnchor`;
- `history_accumulator_start`;
- `history_accumulator_end`;
- optional finalized checkpoint id;
- snapshot root, which must equal `end_anchor.state_root`.

`HeaderChainAnchor` is computed from the node's canonical header store. There
must be no second header store.

Verification rule:

```text
local canonical headers -> local HeaderChainAnchor
HistoryProof anchors    -> proof HeaderChainAnchor
accept only if they match
```

## State-Transition Claim

Add a sealed `AcceptedStateTransitionClaim`. It is emitted only after full live
block validation has accepted the block.

Minimum fields:

- height;
- block id;
- parent state root;
- child state root, equal to `header.state_root`;
- tx root, equal to `header.tx_root`;
- parent and child `log_slots`;
- parent and child `active_slot_count`;
- parent and child `alloc_counter`;
- parent and child exact UTXO root;
- parent and child ReuseGuard root;
- touched slot count;
- minted, spent, fee, reward, and supply counters;
- semantic resource counters;
- exact state transition digest;
- claim digest.

Coinbase-only blocks must produce a non-empty claim. Miner reward is a real
state transition and must be part of the history accumulator.

## Finalized And Recent Ranges

For a snapshot at tip `H`:

```text
finalized HistoryProof through H-18
+ retained recent suffix H-17..H
= snapshot boundary at H
```

The recent suffix stays inside the normal retention window. If proof production
lags near the 18-block boundary, pruning stops until the finalized proof catches
up.

If the transport wants a single served proof object:

```text
finalized HistoryProof
+ suffix transition proof
= served current HistoryProof
```

## Implementation Phases

### 1. Freeze The Claim Language

- Add `AcceptedStateTransitionClaim`.
- Build it from accepted validation artifacts.
- Bind each claim to canonical header fields.
- Cover coinbase-only blocks.
- Add release tests for 1, 2, 18 blocks and coinbase-only blocks.

### 2. Integrate Header Anchors

- Use `HeaderChainAnchor` as the proof/header boundary.
- Compute anchors from the existing header store only.
- Reject snapshot proofs whose anchors do not match local headers.
- Keep header validation native.

### 3. Build History Accumulator Bench

Create `history_accumulator_lite` from the existing streaming accumulator
harness, but feed real history/state rows:

- header projections;
- accepted state-transition claims;
- exact root/counter transitions;
- chain accumulator rows;
- snapshot segment roots.

Run benches in release mode only. Do not record history performance numbers
until this benchmark exists and has fresh results.

### 4. Implement The Proof Backend

Phase 4A, public envelope:

- `HistoryProof` has no linear rows or claim vectors.
- `HistoryProof` includes a fixed-size decider proof slot; benchmarked proof
  size must include that slot.
- `HistoryProofWitness` carries headers and transition rows only for the prover.
- Release tests prove serialized `HistoryProof` size is constant for 1, 18, and
  255 witness items.
- Release bench prints proof size and envelope verifier time.
- Untrusted verification rejects native and reserved backend variants until the
  real backend verifier is implemented.

Phase 4B, accumulator step:

- Define the fixed step statement:
  `prev_history_accumulator + header projection + AcceptedStateTransitionClaim
  -> next_history_accumulator`.
- Prove the step relation with the in-tree binary-field GKR/FRI-Binius backend.
- The step must cover header projection folding, chain accumulator extension,
  state root/counter continuity, and coinbase-only claims.
- Public step verifier input must be fixed-size.

Phase 4C, unbounded finalized history:

- Use `HistoryPcdStepStatement` as the fixed recursive step relation:
  `previous HistoryAccumulationState + verified HistoryStepProof ->
  next HistoryAccumulationState`.
- Use `HistoryArcPcdAccumulator` as the fixed public accumulator instance:
  start state digest, current state digest, PCD root, step-relation digest, and
  transcript digest.
- Use canonical `Block128` field schedules for the decider backend:
  `HistoryPcdStepStatement` has 54 semantic fields and a 56-field hash input;
  `HistoryArcPcdAccumulator` has 12 semantic fields and a 14-field hash input.
  Tagged-pair commitments use 6-field hash inputs. Digest checks must bind
  these field schedules, not Rust struct serialization.
- Implement ARC/PCD-style accumulation over step proofs.
- The finalized accumulator instance must be constant-size.
- The final decider proof must verify the accumulator against
  `start_anchor`, `end_anchor`, `history_accumulator_start`, and
  `history_accumulator_end`.
- The untrusted snapshot path must not accept digest-only folded roots.

### 5. Snapshot Verification

Verification order:

1. sync and validate headers from genesis;
2. compute local `HeaderChainAnchor`;
3. verify `HistoryProof`;
4. recompute snapshot segment roots into one state root;
5. compare recomputed root to `end_anchor.state_root`;
6. apply the retained recent suffix if the snapshot is served at current tip.

Target budget after implementation:

- proof generation: <2 s for the served O(1) snapshot proof path;
- verification: <1 s for the trustless verifier;
- optimization below that is future work after the full verifier is sound.

These are targets, not measured results.

### 6. Live Tests

After implementation:

- two-node live sync with node 2 joining before block 18;
- two-node live sync with node 2 joining after block 18 through snapshot;
- 20+ block run at laptop start difficulty;
- restart with snapshot enabled;
- reorg-failed fallback into snapshot path;
- log checks for manifest, anchor, suffix, snapshot root, and retention events.

## Acceptance Gates

- No history performance number without a fresh release bench.
- No pruning before finalized proof covers the range.
- No snapshot accept unless local headers match proof anchors.
- No empty claim for coinbase-only blocks.
- No second header store.
- No untrusted `HistoryProof` verifier that accepts a digest-only folded root.
- No multi-step `ArcPcdV1` acceptance until the proof verifies full previous-proof validity and current bounded-chunk validity, not just final head shape.
- No temporary trusted snapshot path: if the verifier is not sound, it must fail closed.
