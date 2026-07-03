# Cryptography design for O(1) sync

This document is the single cryptographic source of truth for the O(1) history
path. It supersedes the earlier version, which described the intended objects but
did not name the two errors in the current implementation or the ordered way out.

Read `architecture.md` first for the five-layer split. This document only covers
the cryptography of the O(1) history proof and its certificate/receipt inputs.

## 0. Fixed assumptions (do not relitigate)

- One node type. Every node is the same: it keeps full state, holds its own
  keys/wallet, builds and advances its own O(1) history proof, and optionally
  mines — mining is just a flag. There is no light/SPV class and no
  archival/prover sub-tier. O(1) sync is the mechanism a fresh or lagging node
  uses to join or catch up (verify the recursive proof + download state segments),
  after which it builds history forward like every other node.
- Every node validates and stores headers from genesis. PoW, ASERT, MTP,
  timestamp windows, cumulative-work arithmetic, and finalized fork choice are
  verified natively by the header layer.
- Full block payloads (body, `BlockProof`, `BlockAuthSidecar`, undo logs) are
  retained only for the last 18 blocks.
- A gap of 18 or fewer blocks is closed by retained-block catch-up, never by
  snapshot/O(1).
- O(1) history folds accepted-block certificates recursively, **one block per
  step by default**. Batching `K` blocks per step is a benchmark-decided
  optimization, not an architectural constant; `16` is not fundamental.
- Certificate/acceptance-proof issuance happens once, when a node accepts a block,
  and may be block-cost dependent. A block's payload is retained until the node has
  folded the block into its history proof, so issuance is self-paced
  (coverage-gated), never a wall-clock deadline — a slow node pays in bounded disk,
  not correctness. See §3 "Hardware independence". Certificate *verification* inside
  O(1) must be fixed-cost and independent of transaction count.
- Sync-mode selection: a gap of ≤18 blocks is closed by fetching retained blocks
  directly and replaying `AcceptBlock`; only a gap >18 uses O(1) snapshot sync.

## 1. Why O(1) history exists at all

A header commits to a `state_root`, but PoW does not check that the `state_root`
is the result of valid execution. A miner can place any `state_root` in a header.
So the header chain alone proves *"this state root sits under the heaviest PoW"*,
not *"this state root is the result of a valid chain of `AcceptBlock`
transitions from genesis."*

The O(1) history proof exists to prove exactly the second statement, so that a
snapshot-syncing node can trust a finalized `state_root` without replaying every
historical block. This is the entire security purpose. Everything in this
document is judged against it.

Consequence: the O(1) proof **must carry execution validity** (the result of
verifying each historical `BlockProof`/`BlockAuthSidecar`/exact-state
transition), aggregated recursively. Header binding alone is not sufficient.

## 2. The two errors in the current implementation

The live path is
`prove_history_checkpoint_recursive_head_record`
→ `prove_history_checkpoint_step_proof_from_verified_full_accepted_output`
→ `prove_history_checkpoint_step_proof_with_ivc_chunk_certificate_proof_components`.
It makes two mirror-image mistakes.

### Error 1 — it proves what the header layer already proved

The live chunk carries `RecursiveConsensusState` (cumulative chainwork, ASERT
anchor, MTP ring, expansion ring) and `HeaderWitness` (raw PoW fields, target),
and runs `verify_pow_header_witness_batch_native` + `build_header_integer_trace`.
This re-proves PoW/ASERT/chainwork that the header layer already verified
natively. `RecursiveConsensusState` even leaks into the public boundary via
`HistoryCheckpointHead.consensus_digest` and
`HistoryCheckpointBatchSummary.start_consensus/end_consensus`.

This is wasted work and a wrong trust boundary. Header consensus is not an O(1)
responsibility.

### Error 2 — it does not prove what only O(1) can prove

The live chunk (`HistoryCheckpointIvcChunkCoreProof`) folds only receipt
projection (statement→receipt hash consistency) and the accepted-claim batch
digest. It never verifies a production `BlockProof`/`BlockAuthSidecar`, so it
does not carry execution validity. A peer could present a receipt committing to
any `child_state_root` and the current chunk relation would accept it.

The execution-validity verifiers already exist and are correct
(`block_certificate_backend.rs`: `verify_exact_state_killshot`, block spine,
authorization, state-root, guard-bucket, slot-leaf killshots). They are simply
**not wired into the recursion** — they are exercised only by the isolated
`full_accepted_batch` audit/bench path.

### The correction

Invert both: stop proving header consensus in O(1); start folding the existing
execution-validity verifiers into the recursion. "Cryptography not finished" is
mostly a wiring problem, not a missing-primitive problem.

## 3. The corrected model: three tiers of recursion

Transaction-count dependence is allowed in exactly one place — tier 1, at block
acceptance time, while the payload is still retained. Everything above tier 1 is
fixed-size in and fixed-size out.

```text
Tier 1 — Acceptance proof (per block, during AcceptBlock)
    verify(BlockProof + BlockAuthSidecar + exact-state transition)   // variable
    -> BlockProofAcceptanceReceipt  +  AcceptanceProof               // FIXED
    This is the only tier whose cost depends on tx_count.
    Produced once, when the block is live and payloads are retained.

Tier 2 — Certificate chunk (K blocks per step, default K = 1)
    verify(K x AcceptanceProof)                                      // fixed in
    bind each receipt to a local HeaderProjectionSlot (equality only)
    fold projection_root: start_anchor -> end_anchor
    fold ChainAccumulator.chain_hash over ordered accepted-block claims
    check state continuity: receipt[i].parent_state == receipt[i-1].child_state
    check block continuity: receipt[i].parent_block == receipt[i-1].block_id
    (K > 1 only) constrain padded slots of a short final chunk to no-op
    -> ChunkProof                                                    // FIXED

Tier 3 — History step (recursive)
    verify(previous HistoryProof)   <- real in-circuit recursion, not a digest link
    verify(one ChunkProof)
    next_head == advance(previous_head, chunk_summary)
    -> HistoryProof                                                  // constant size
```

Tier 1 absorbs all tx-count variability into a fixed receipt+proof. Tiers 2 and 3
only ever verify fixed-size inner proofs, so chunk and final verification are
flat, and the final proof size is constant in chain length.

### On chunk size K (per-block vs batching)

K affects soundness in no way — K=1 and K=16 yield the same constant-size final
`HistoryProof` for the snapshot verifier. But K is **not** an unbounded knob: it
has a hard ceiling from block pruning (see the liveness constraint below). Within
that ceiling the choice is about node prover work and cadence.

**Pruning ceiling.** `RECENT_BLOCK_RETENTION_DEPTH = 18` is the *serving/reorg*
obligation — what a node must keep available to serve peers and handle reorgs — not
a wall-clock deadline for proving. A batching scheme that gathers K unfolded blocks
before acting must keep its working window under the retained set, so K ∈ [1, 16]
(16 = the current `HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS`, the largest batch under
18 with margin). Per-block (K=1) keeps the working window minimal.

**Hardware independence (this is the load-bearing rule).** History-building must
NOT depend on a node's compute speed. A rule like "tier-1 must finish within
block_time" is wrong: a miner may pair a fast prover with a weak node, and no
protocol invariant may hinge on any one machine's speed or on timings measured on
one developer's box. Two rules keep it hardware-independent:

1. **Pruning is gated on coverage progress, not the clock.** A history-building
   node prunes a block's payload only once it has folded that block into its own
   history proof — the prune cutoff is `min(tip − serving_window,
   history_proof_covered_to)`, and only where a certificate already exists. (The
   current code already gates on both coverage and certificate existence.) A slow
   prover therefore just keeps more un-folded payloads: it pays in bounded extra
   disk proportional to its lag, never in lost data or a broken proof. Progress,
   not wall-clock, drives pruning.

2. **A node that cannot keep up syncs forward instead of falling apart.** Every node
   is node + prover together (mining is just an on/off flag) and advances its own
   history proof forward from wherever it synced. If proving cannot keep pace and a
   node drifts more than the serving window behind the tip,
   it does not rebuild the gap block-by-block — it O(1) snapshot-syncs to a recent
   boundary, adopting a peer's history proof (verified at fixed, hardware-
   independent cost against its own headers) and resumes building forward. Verify
   cost is flat, so this escape hatch is available even to the weakest node.

So correctness never depends on proving speed. A slow node's only penalty is more
frequent sync-forward and more transient disk — bounded by its lag under
coverage-gated pruning — never lost data, a broken proof, or a consensus split.
Network liveness needs only that enough nodes prove fast enough to keep some recent
history proof available to sync from; since every node is a prover, that is just
"enough nodes have adequate hardware", not a special archival tier. Tier 2/3
folding over already-captured receipts is never under time pressure; it uses only
unfolded receipts (bounded rolling buffer) plus permanent headers.

### Storage cost: receipts are transient (O(1)), not stored forever (O(N))

A receipt is folded into the recursive `HistoryProof` exactly once and then
**dropped**. That is the defining property of IVC: proof π_i already attests to all
of history [0..i], so producing π_{i+1} needs only π_i and block i+1 — never the
older receipts. A node therefore keeps receipts only for the blocks between
`history_proof_covered_to` and the tip — a bounded window (≤ K ≤ 16). Permanent
per-node storage is just: all headers (O(N), tiny, already the accepted cost), one
constant-size `HistoryProof`, and current state. Receipts are **not** an O(N)
store.

Caveat about current code: `T_ACCEPTED_BLOCK_CERTIFICATES` is written per block and
**never pruned** — `prune_after_commit` deletes only payloads and merely uses a
certificate's existence as the prune gate. That is O(N) certificate storage, and it
is a direct consequence of the history head still being digest-linked
(`previous_proof_digest`) instead of truly recursive: with a digest link the stored
records are the real authority and cannot be dropped. Finishing tier-3 real
recursion is exactly what makes them droppable — then prune
`T_ACCEPTED_BLOCK_CERTIFICATES` at heights ≤ `history_proof_covered_to` (that
coverage marker already exists). O(1) storage is a payoff of Phase 4, not a
separate feature.

The only cost that batching amortizes is the tier-3 recursion overhead R — the
cost of verifying the previous `HistoryProof` in-circuit. Per N blocks:

```text
K = 1  : N steps  -> N*R + N*A
K = 16 : N/16 steps -> (N/16)*R + N*A     (A = per-acceptance-proof verify cost)
```

The `N*A` term is identical; batching only saves `(1 - 1/K)*N*R`. So batching is
worth its complexity only if R dominates A.

**Default decision: K = 1 (per-block).** Reasons:
- Smallest working window: a per-block prover folds each block immediately, so its
  un-folded backlog — and the extra disk a slow prover pays under coverage-gated
  pruning — stays minimal. Larger K holds more un-folded payloads as working space.
- It removes the most confusing machinery — fixed 16-slot arrays, padded
  short-final-chunk handling, and the whole certificate-batch statement layer.
- Lowest latency: a node advances its history proof the instant it accepts a
  block, not after 16.
- Uniform recursion: every step is `fold(prev_proof, one_block)`, easiest to make
  sound and to test.
- This engine is a streaming tower IVC, designed for cheap per-step folding, which
  keeps R low — the regime where batching barely helps.

Batching stays available as a reversible optimization, bounded by the pruning
ceiling: build the clean per-block core first, then, if the tier-3 bench shows R
dominates, raise K up to ~16 (never past the 18-block window). You can always
batch a per-block core; you cannot easily simplify a batch-first design. The final
K is settled by the tier-3 bench (see §10), which requires the recursion to exist
first — so this decision is recorded now but realized when tier-2/3 is built, not
by prematurely ripping the current 16-chunk out of half-finished code.

## 3b. Tier-1 circuit: Strategy B and the deferred-FRI binding (soundness-critical)

**Strategy choice = B** (algebraic claims in-circuit, FRI deferred). Not C
(Nova-style folding): production `BlockProof`s are STARKs, not relaxed-R1CS
instances, so folding needs a STARK→foldable adapter that either duplicates the
production prover (the explicit non-goal, §7) or is a large new soundness-critical
component — and Nova still has a final "decider", so it relocates the deferred
check rather than removing it. B reuses the production `BlockProof` directly and
adds the least machinery. Not A (full in-circuit incl. FRI): FRI/RS-encoding in a
boolean R1CS is likely infeasible in size.

**"More trustless" is not the axis — all three are equally sound if built right.**
Trustlessness is binary. The real axes are soundness-critical *surface* and
feasibility. Deferral is **inherent to O(1)**, not a weakness of B: any O(1)
recursion defers *something* to one final check — that is exactly why per-step and
final verification are constant instead of O(chain). So the job is never "avoid
deferral"; it is "make the single final binding exact and audit it hardest." This
binding is the one place a subtle bug becomes accepted fake state.

**New-peer snapshot sync — the ParanO(1)d guarantee.** A fresh peer with no
history:
1. syncs + validates all headers genesis→F natively (PoW/chainwork) → trusts
   `header[F].state_root = R_F` under heaviest work;
2. computes local header anchors;
3. verifies ONE self-contained O(1) proof against those anchors — this certifies
   R_F is the result of valid execution from genesis;
4. downloads state segments, recomputes roots, requires rebuilt root == R_F;
5. replays the ≤18 retained blocks natively.

The peer trusts nobody: every step is local validation or proof verification. A
fake snapshot is cryptographically impossible **iff step 3's proof is sound**,
which reduces entirely to the binding contract below (plus proof-system soundness
and the standard PoW/51% assumption on the header chain — O(1) makes *state*
trustless *given* the header chain; it cannot and does not defend against a 51%
alternate chain).

**Snapshot decider.** Internally the history accumulates via B (deferred FRI,
cheap per step). The proof *served to a new peer* is discharged by a **decider**:
the accumulated deferred-FRI commitment is verified (the one expensive FRI check,
done once at snapshot-serving time) and wrapped so the new peer verifies a single
self-contained O(1) object. The new peer never has to trust a separate, unbound
native check.

**The binding contract (audit this hardest):**
1. `deferred_fri_commit` is a Poseidon2b running hash committing, for each folded
   block, to *exactly* the FRI transcript data its in-circuit algebraic claims
   consumed: query points, opened values, Merkle caps/roots, and Fiat-Shamir
   challenges, in canonical order.
2. The in-circuit R1CS consumes opened values *only* as bound by
   `deferred_fri_commit` — the values the algebra uses are constrained equal to the
   values absorbed into the commitment. No opening may enter the algebra "for
   free."
3. Tier-3 folds it: `next_deferred = H(prev_deferred, this_block_deferred)`. The
   final proof carries one accumulated commitment over all blocks.
4. The decider verifies that *every* opening in the accumulated commitment is
   FRI-valid (low-degree + Merkle-consistent), covering exactly the committed set —
   no more, no less.
5. `deferred_fri_commit`, the accumulator, and the recursive head are all bound to
   the same header anchors the new peer computed locally; any mismatch rejects.
6. Soundness (informal): (algebra verifies in-circuit) ∧ (every committed opening
   is FRI-valid at the decider) ∧ (public inputs == local anchors) ⇒ R_F is valid
   execution from genesis. The only ways to break it are (a) an opening used
   in-circuit but absent from `deferred_fri_commit`, or (b) a decider that does not
   cover the full committed set — both forbidden by (1),(2),(4).

The tier-1 envelope carries this: `AcceptanceProof { receipt, deferred_fri_commit,
r1cs_proof }` (see `noid_recursive::acceptance`). Slice 1 (landed) is the
strategy-independent boundary — the native `receipt ↔ HeaderProjectionSlot`
equality relation, pure equality, no header consensus. The in-circuit `r1cs_proof`
and the real `deferred_fri_commit` are the subsequent slices.

## 4. Data objects (native, from local header DB + stored records)

- `HeaderProjectionSlot` — projection of a locally validated header. Its fields
  and digest must match whatever `HeaderChainAnchor.projection_root` already
  folds. It is a projection of an already-validated header, **never** a proof of
  header validity. (Exists: `header_projection.rs`.)
- `HeaderProjectionChunk { start_anchor, slots[<=16], end_anchor }` — the only
  header input to tier 2. Replaces `AcceptedClaimBatchWitness`/`HeaderWitness`.
  (Exists: `header_projection.rs`; not yet wired.)
- `BlockProofAcceptanceReceipt` — the tier-1 output: fixed commitment to the
  verified acceptance (roots, counters, tx_root, claim digests, source-proof
  digests). (Exists: `block_certificate.rs`.)
- `AcceptedBlockCertificateRecord { acceptance_receipt, .. }` — stored per
  accepted block, consumed by tier 2 before payload pruning. (Exists:
  `accepted_block_certificate.rs`.)

## 5. Proof objects (target: exactly two)

```rust
// Tier 2 output. Replaces HistoryCheckpointIvcChunkCoreProof
// + AcceptedClaimBatchDigestProof + AcceptedBlockCertificateBatchDigestProof.
pub struct ChunkProof {
    pub chunk_len: u32,
    pub start_anchor_digest: Digest,
    pub end_anchor_digest: Digest,
    pub start_accumulator_digest: Digest,
    pub end_accumulator_digest: Digest,
    pub proof: Vec<u8>,   // verifies K acceptance proofs + bindings, fixed size (K default 1)
}

// Tier 3 output. Replaces the entire HistoryCheckpointHead / *StepStatement /
// *StepProof / *StepDigestProof / *StepBackendProof / *RecursivePayload /
// *RecursiveHeadProof / StoredHistoryCheckpointHeadRecord / HistoryCheckpointProof
// tower.
pub struct HistoryProof {
    pub engine_id: u32,
    pub start_height: u64,
    pub end_height: u64,
    pub start_anchor_digest: Digest,
    pub end_anchor_digest: Digest,
    pub start_accumulator_digest: Digest,
    pub end_accumulator_digest: Digest,
    pub head_digest: Digest,
    pub proof: Vec<u8>,   // recursively verifies prev HistoryProof + one ChunkProof
}
```

One prove function per object (`prove_chunk`, `prove_history_step`), not six
`prove_history_checkpoint_step_proof_*` variants. No `consensus_digest` anywhere
in these objects.

The public snapshot verifier receives a `HistoryProof` plus local start/end
`HeaderChainAnchor`s from its own header DB, and checks the proof's public inputs
match those anchors. Nothing else is trusted.

## 6. What each tier must and must not prove

Tier 1 (acceptance) must bind:
1. `statement_digest == hash(statement)`;
2. `BlockProof.meta.prev_block_state_root == parent_state_root`;
3. `BlockProof.meta.new_state_root == child_state_root`;
4. block tx hashes produce `tx_root`;
5. public transaction logic verified;
6. authorization proofs from `BlockAuthSidecar` match all non-coinbase tx bodies;
7. exact-state transition from `BlockProof.state_transition` maps parent→child;
8. state counters match the verified transition;
9. `accepted_block_claim_digest` derived from the same accepted-block transcript.

Tier 2 (chunk) must bind: K tier-1 verifications (K default 1); receipt↔`HeaderProjectionSlot`
equality (height, block_id, parent_block_id, child_state_root, tx_root, counters);
`start_anchor.projection_root` folds to `end_anchor.projection_root` over the
slots; `ChainAccumulator::extend` including the `chain_hash` Poseidon update;
state and block continuity across receipts; padded slots are no-ops.

Tier 3 (history) must bind: in-circuit verification of the previous `HistoryProof`;
one `ChunkProof`; `next_head == advance(previous_head, chunk_summary)`.

No tier may prove PoW, target comparison, ASERT, MTP, timestamp windows,
cumulative-work arithmetic, or finalized fork choice. Those are header-layer
responsibilities. O(1) only checks equality against local header projections and
anchors.

## 7. Cut-list — delete Universe A from the O(1) path

The header-consensus path and the six-variant tower must leave the public O(1)
boundary. Move anything still needed for the private 18-block retained/audit path
into a clearly private module; do not keep it as public O(1) authority.

Remove from the O(1) path:
- `pow_header.rs` (`HeaderWitness`, `RecursiveConsensusState`,
  `verify_pow_header_witness_batch_native`) — header consensus.
- `header_integer.rs` — integer chainwork arithmetic.
- `accepted_batch.rs` in the part exposing
  `AcceptedClaimBatchWitness`/`Output`/`Digest`.
- `RecursiveConsensusState` / `consensus_digest` from `HistoryCheckpointHead` and
  `HistoryCheckpointBatchSummary`.
- Five of six `prove_history_checkpoint_step_proof_*` variants. Keep exactly one
  path, renamed `prove_history_step`.
- `HistoryCheckpointStepDigestProof`, `HistoryCheckpointStepBackendProof`,
  `HistoryCheckpointRecursivePayload`, `HistoryCheckpointRecursiveHeadProof`
  (digest-linked), and the digest-link fields of
  `StoredHistoryCheckpointHeadRecord` — collapse into `HistoryProof`.
- Duplicate accounting of the same 16 blocks: keep one accumulator update inside
  the chunk relation, delete the second digest proof.

Wire in (this is the unfinished cryptography):
- Tier 1: turn the current receipt-projection into a real proof-carrying wrapper
  that verifies `BlockProof`/sidecar/exact-state once at accept time, reusing the
  existing `block_certificate_backend.rs` verifiers instead of leaving them
  orphaned.
- Tier 2: make `HeaderProjectionChunk` the only header input; add `projection_root`
  and `chain_hash` folds to the relation.
- Tier 3: replace `previous_proof_digest` with in-circuit verification of the
  previous proof.

## 8. Phased plan (maps to roadmap.md)

1. **Collapse variants (delete-only).** Remove the four dead public
   `prove_history_checkpoint_step_proof_*` entry points and any transitively
   dead helpers/types; keep the one live path working. Reduces surface with no
   semantic change. *(roadmap Phase 0/6 cleanup)*
2. **Tier-1 proof-carrying receipt.** Fold the existing execution-validity
   verifiers into a fixed acceptance proof at accept time. Benchmark the extra
   acceptance-time cost separately from `block_scaling`. *(roadmap Phase 1/2)*
3. **Tier-2 header-projection chunk.** Swap chunk inputs to `HeaderProjectionChunk`;
   delete `AcceptedClaimBatch`/`HeaderWitness`/`RecursiveConsensusState` from the
   chunk; add projection_root + accumulator chain_hash folds. *(roadmap Phase 3)*
4. **Tier-3 real recursion.** Verify the previous `HistoryProof` in-circuit;
   collapse the head/step/record tower into one `HistoryProof`. *(roadmap Phase 4)*
5. **Snapshot integration.** `GetHistoryProof` serves only `HistoryProof`; verify
   against local anchors before segment download. *(roadmap Phase 5)*

Order matters: Universe A must be removed before/with tier 2, or the two
accounting systems for the same 16 blocks keep diverging. Build tiers bottom-up
(1 → 2 → 3) because each tier verifies the fixed output of the one below.

## 9. Negative tests required (per tier)

Tier 1: wrong block id / parent-state / child-state / tx_root / exact-transition
digest / accepted-claim digest each rejected; a receipt/proof from one block is
not reusable for another; acceptance does not re-run a second transaction/auth/
exact-state prover from scratch (it verifies the existing artifacts once).

Tier 2: reordered certificates rejected; skipped certificate rejected; wrong
parent block rejected; wrong state transition between receipts rejected; wrong
header anchor rejected; wrong tx_root in receipt↔header binding rejected; wrong
accumulator `chain_hash` rejected; wrong padding rejected.

Tier 3: fake previous proof rejected; previous proof from another chain rejected;
previous proof for a different height rejected; two chunks fold to one final
proof; final verify time and proof bytes stay constant as chunk count grows.

## 10. Bench plan

Separate issuance from verification, and keep them honest about which tier they
measure.

- Tier 1 (issuance): coinbase-only, 1 std tx, 16 std tx, max std block, sweep,
  mixed. Measure extra acceptance/aggregation time *after* normal `BlockProof`
  verification, peak memory, receipt/proof bytes, record bytes. Must not
  duplicate the production prover; `block_scaling` stays the source baseline.
- Tier 2 (chunk): sweep K in {1, 2, 4, 8, 16}; for each K measure coinbase, small,
  max-heavy, and a short final chunk. Measure chunk prove/verify, proof bytes, and
  the cost of the K inner verifications. Must be flat within a K.
- Tier 3 (recursive): step counts 1, 2, 10, 100, 1000. Final proof size and final
  verify time must not grow with step count. Cross with the tier-2 K sweep to read
  off the recursion overhead R and settle the default K.

## Non-goals

O(1) must never contain: PoW proof, ASERT proof, MTP proof, header consensus
replay, old block-body download, or any public verification whose cost grows with
transaction count.
