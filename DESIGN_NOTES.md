# Paranoid Design Notes — Stateless Architecture (v2)

This document collects the **non-normative** rationale, philosophy,
UX outlook, and design decisions that back the Paranoid protocol. It is
not a specification. The authoritative rules live in
`SPECIFICATION.md`; the implementation overview lives in
`ARCHITECTURE.md`.

This document was rewritten to reflect the **Stateless LogicProof +
BlockStateBinding** architecture. The old design (wallet proves Merkle
paths) is superseded.

---

## 1. Problem Statement (Why the old design burns proofs)

In the original architecture, the wallet STARK includes `FriStateOpenAir` — an in-circuit
Merkle opening of every touched slot against `prev_state_root`. This creates a fatal
coupling:

```
  New block arrives -> state_root changes -> Merkle paths to YOUR slots change
  -> YOUR trace changes -> YOUR STARK proof is invalidated -> Re-Prove required
```

Even if nobody touched your slots, the sibling hashes in the Merkle tree change because
someone else modified a neighboring slot. The wallet must re-prove ~632ms on every new
block, regardless of whether the transaction is still valid.

This makes mobile UX impossible and wastes battery/compute on work that is objectively
unnecessary.

---

## 2. Key Insight: Separate Logic from State

The wallet should prove only what it OWNS: balance, ownership, range, body commitment.
The state binding (proving slots exist in the Merkle tree) should be done by whoever
has fresh state — the Full Node (during block assembly).

```
  Wallet proves:    "Given these slot values, my math is correct."
  Full Node proves: "These slot values actually exist in the current state tree."
```

---

## 3. Architecture: LogicProof + BlockStateBinding

### 3.1 LogicProof (Wallet-side, ~102ms measured)

The wallet generates a STARK that proves:

1. **Balance:** sum(inputs.value) == sum(outputs.value) + fee
2. **Range:** all values < 2^64
3. **Ownership (AuthGKR):** HAddr(spend_secret) == claimed_owner for each input
4. **Body binding:** tx_body_hash pinned via PublicColumn in STARK trace.
   Correctness of the 59-perm spine is deferred to block-prover (SpineGKR Kill-Shot
   uses only public SpineInputs, no spend_secret needed).
5. **Claims commitment:** C_claimed = Poseidon2b(all_claimed_slot_data), absorbed into FS channel

The LogicProof does NOT contain:
- Merkle paths to prev_state_root
- FriStateOpenAir constraints
- Any dependency on the global state tree structure

**Public inputs of LogicProof:**
- `epoch_anchor` (replaces prev_state_root, see section 4)
- `tx_body_hash`
- `fee`
- `claimed_slots`: [(slot_index, value, owner_hi, owner_lo)] for all inputs/outputs
- `C_claimed`: commitment to claimed slot data (bridge to BlockStateBinding)
- `n_live_inputs`, `n_live_outputs`
- `is_coinbase`

### 3.2 BlockStateBinding (Full Node block assembly, part of BlockProof)

The Full Node generates a STARK (or extends the block AIR) that proves:

1. For every input slot claimed by any tx in the block:
   - The slot opens to the claimed (value, owner) in `prev_block_state_root`
2. For every output slot claimed by any tx in the block:
   - The slot opens to EMPTY (0,0,0) in `prev_block_state_root`
3. Post-state:
   - Input slots are zeroed, output slots are written
   - `new_block_state_root` is correctly computed
4. Bridge:
   - `C_claimed` from each LogicProof matches the opened values

The Full Node uses the existing `FriStateOpenAir` + gamma-RLC accumulator pattern,
but at BLOCK scope (all slots from all txs batched together) rather than per-tx.

### 3.3 Bridge Commitment (C_claimed)

The bridge between LogicProof and BlockStateBinding is a single Poseidon2b digest:

```
C_claimed = Poseidon2b_sponge(
    for each input:  slot_index || value || owner_hi || owner_lo
    for each output: slot_index || value_claimed || owner_hi_claimed || owner_lo_claimed
)
```

- LogicProof absorbs C_claimed into its Fiat-Shamir channel (any change forks challenges)
- BlockStateBinding also absorbs C_claimed and constrains opened values to match
- Verifier checks: C_claimed(LogicProof) == C_claimed(BlockStateBinding)

This is a 32-byte bridge. Simple, sound, cheap.

---

## 4. Epoch Anchor (Replaces prev_state_root in tx_body_hash)

### 4.1 Problem

If `prev_state_root` is leaf L0 in the spine Merkle tree (as currently implemented),
then `tx_body_hash` depends on the state root. This makes LogicProof non-stateless.

### 4.2 Solution

Replace `prev_state_root` with `epoch_anchor`:

```
epoch_anchor = block_header_hash(height - ANCHOR_DEPTH)
```

where `ANCHOR_DEPTH = 6` (6 blocks at 12s = 72s).

### 4.3 Properties

- **Anti-replay:** Different forks have different block headers at height-6, so different
  epoch_anchors, so different tx_body_hashes. A LogicProof valid on fork A is invalid on fork B.
- **Stability:** epoch_anchor does not change when new blocks arrive (it refers to a block
  that is already 6-deep). LogicProof remains valid across new blocks.
- **Expiry:** Consensus rejects transactions with epoch_anchor older than ANCHOR_DEPTH blocks.
  This provides a natural TTL (~6 minutes) without explicit timestamps.
- **Simplicity:** Wallet knows epoch_anchor from the last header it synced. No Merkle paths needed.

### 4.4 Leaf L0 change

```
Before: SpineInputs.prev_state_root = state_root of prev block
After:  SpineInputs.epoch_anchor    = hash(block_header[current_height - ANCHOR_DEPTH])
```

The spine Merkle tree layout becomes:
- L0: epoch_anchor [2 lanes]
- L1: fee_leaf [2 lanes]
- L2-L5: input_leaves [4 x 4 lanes]
- L6-L13: output_leaves [8 x 4 lanes]
- L14: is_coinbase_leaf [2 lanes]
- L15: pad_leaf [2 lanes]

---

## 5. Nullifier Set (Anti-Double-Inclusion)

Even with epoch_anchor, the same LogicProof could be included twice within the
ANCHOR_DEPTH window. Solution: nullifier = tx_body_hash.

- Full nodes maintain a rolling nullifier set covering the last ANCHOR_DEPTH blocks.
- A transaction is rejected if its tx_body_hash already appears in the nullifier set.
- Storage cost: 32 bytes * max_txs_per_block * ANCHOR_DEPTH = trivial (~20 KB).
- After ANCHOR_DEPTH blocks, the epoch_anchor has expired anyway; no need to keep older nullifiers.

---

## 6. Coinbase Transaction

Coinbase is special: it has no inputs, no spend_secret, no LogicProof from a wallet.

- The miner constructs coinbase directly.
- Coinbase is proven entirely within BlockStateBinding (no external LogicProof needed).
- Consensus rule: exactly 1 coinbase per block, must be first, fee=0, n_inputs=0.
- The coinbase slot must be empty in prev_state (proven by BlockStateBinding).
- Value = block_reward (protocol schedule, consensus-enforced).

---

## 7. Transaction Lifecycle (New Design)

```
1. Wallet queries Full Node: "Give me 2 empty slot indices"
   Node responds: [14352, 16100]  (just indices, no Merkle paths)

2. Wallet builds TxBody:
   - inputs: [(slot=100, value=80, owner=Alice)]
   - outputs: [(slot=14352, value=50, owner=Bob), (slot=16100, value=30, owner=Alice)]
   - fee: 0
   - epoch_anchor: hash(block_header[height-6])

3. Wallet computes tx_body_hash via native Poseidon2b spine (59 perms). 
   GKR proof of correctness is deferred to block-prover.
4. Wallet computes C_claimed = Poseidon2b(slot_data...)
5. Wallet generates LogicProof (~102ms measured):
   - Balance OK, Range OK, AuthGKR OK, C_claimed absorbed
   - SpineGKR NOT in LogicProof — block-prover proves body correctness

6. Wallet sends TxIntent = {tx_body, logic_proof, C_claimed, claimed_slots} to P2P

7. Full Node receives TxIntent:
   - Verify LogicProof (~3ms STARK verify)
   - Check epoch_anchor is in valid window
   - Check claimed slots match native state (slot 100 = (80, Alice)? yes)
   - Check nullifier set (tx_body_hash not seen? yes)
   - Admit to mempool

8. Full Node assembles block:
   - Take N TxIntents from mempool (no slot conflicts)
   - Native collision check on slot indices
   - Compute state transition (zero inputs, fill outputs)
   - Generate BlockStateBinding (Merkle openings for all touched slots)
   - Aggregate into BlockProof (deferred-FRI aggregation)
   - Compute new_state_root, da_root
   - Form header, push to miner (built-in or external)

9. PoW found (miner returns valid nonce):
   - Full Node seals block, publishes: header + BlockProof + DA Payload

10. Verifiers:
    - Check PoW
    - Verify BlockProof (includes all LogicProofs + BlockStateBinding)
    - Apply state diff
```

---

## 8. Node Topology

Two node types (same model as Bitcoin):

### Light Node (Wallet)
- **Stores:** Last block header + recursive proof (~55 KB) + own keys + own receipts
- **Does:** Verifies chain in ~230ms (recursive proof). Generates LogicProof (~300-400ms).
  Queries Full Node for slot hints and epoch_anchor.
- **Does NOT:** Store state. Compute Merkle paths. Re-prove on new blocks.

### Full Node (Everything)
- **Stores:** Flat state vector (~6 GB) + all block headers (130 MB/year) + DA payload
  (prunable after application) + mempool + nullifier set (~20 KB rolling)
- **Does:**
  - Wallet functions (optional built-in wallet, generates LogicProofs)
  - Validation: validates LogicProofs (~3ms), validates blocks (PoW + BlockProof)
  - State: maintains full state, serves slot hints, epoch_anchor
  - Block assembly: collects TxIntents, resolves conflicts, generates BlockStateBinding,
    aggregates into BlockProof, forms header
  - Mining: built-in miner OR exposes Block Template API for external miners
  - P2P: propagates blocks and TxIntents
- **Does NOT:** Store transaction history after applying blocks (prunes DA).

External miners (GPU/ASIC) are NOT nodes. They connect to a Full Node via the Block
Template API, receive only the 248-byte header, brute-force nonce, and return it.
They cannot see or modify transactions. Protocol does not distinguish solo mining
from pool mining — pools are offchain market infrastructure.

---

## 9. Mining Pipeline

### Separation of Concerns

```
  Full Node (CPU, block assembly):          External Miner (GPU/ASIC, PoW only):
  - Collect TxIntents from mempool          - Receive 248-byte header via
  - Validate LogicProofs                      Block Template API
  - Generate BlockProof (1-3 sec)           - Brute-force nonce (Blake3)
  - Form header                             - Return valid nonce
  - Push header to miner (built-in          - Cannot modify block content
    or external)                            - Cannot steal block (coinbase is
  - On valid nonce: publish block             locked in proof)
```

### Block Template Pipeline (Empty Block Fallback)

When a new block is found:
1. T=0: Immediately generate empty-block template (coinbase only, trivial proof, ~ms)
2. T=0..3s: Push empty template to ASIC. ASIC mines empty block (no fees, but no downtime).
3. T=3s: Full template ready (with transactions). Push new header to ASIC.
4. T=3s..12s: ASIC mines full block. CPU idle.
5. If ASIC finds nonce at any point: publish and restart cycle.

### Block Withholding Protection (vs Bitcoin)

In Bitcoin, a pool miner can steal a found block by publishing it themselves with
a different coinbase. In Paranoid this is IMPOSSIBLE:

- Coinbase address is embedded in DA Payload -> da_root -> header -> BlockProof
- Changing coinbase requires regenerating BlockProof (1-3 sec CPU work)
- The ASIC miner has no CPU resources for proof generation
- Therefore: ASIC cannot modify the block. Can only find nonce and return it.

This solves the block withholding attack cryptographically.

---

## 10. Checks (Receipt Verification After 10 Years)

A "check" (payment receipt) = {version, tx_body, logic_proof, inclusion_receipt}

- `inclusion_receipt` = Merkle path from tx_body_hash to tx_root in block header
- Verification:
  1. Verify logic_proof (STARK). Math is eternal.
  2. Verify inclusion: path from tx_body_hash -> tx_root == header.tx_root
  3. Verify header is in canonical chain (request from any full node, 248 bytes)
- Works forever as long as the verifier knows the AIR version.
- Version field enables forward-compatible verification after hard forks.

---

## 12. Security Summary

| Attack | Defense |
|--------|---------|
| Lie about slot values | C_claimed bridge: LogicProof claims must match BlockStateBinding openings |
| Replay on fork | epoch_anchor differs per fork |
| Double-inclusion | Nullifier set (rolling window of tx_body_hashes) |
| Double-spend | BlockStateBinding: second spend sees zeroed slot |
| Double-mint | Consensus rule: unique output slot indices per block |
| Fake state | BlockStateBinding proves against prev_block_state_root (fixed in prior header) |
| Block theft | Coinbase locked in BlockProof via da_root -> header binding |
| DoS (spam LogicProofs) | Verify costs ~3ms; rate-limit at P2P layer |
| Grinding epoch_anchor | epoch_anchor is 6 blocks deep, determined by history, not current block |

---

## 13. Allocator Simplification

With the new design, the allocator interaction becomes:

**Old flow:**
1. Wallet requests slot + Merkle path from node
2. Node returns index + path (hundreds of hashes)
3. Wallet builds FriStateOpen witness with the path
4. Any state change invalidates the path -> re-prove

**New flow:**
1. Wallet requests empty slot index from node
2. Node returns index (4 bytes)
3. Wallet uses index in TxBody, proves only logic
4. Full Node verifies slot is empty when building block

The allocator logic (splitmix64, free_slots heap) remains consensus-significant
for deterministic state evolution, but the wallet no longer needs to know anything
about Merkle tree structure.

---

## 14. Performance Estimates (Current Measured)

### Wallet (LogicProof generation) — measured at ~102ms
- Native tx_body_hash computation (59 native Poseidon2b perms): ~2ms
- AuthGKR Kill-Shot (20 slots): ~55ms
- STARK over TxLogicAir (no state columns, reduced trace): ~45ms
- **Total: ~102ms** (confirmed by benchmark)

### Full Node — Block Assembly (BlockProof generation, N=100 txs, 8 cores)
- Parallel per-tx STARK proofs supported. Current measured:
  - Interleaved commit: ~5s
  - Unified block SpineGKR + per-tx algebraic STARKs: ~35s (sequential)
  - Block multipoint + FRI opening: ~3s
  - **Total: ~43s** (target after Q: <8s on 8 cores)

### Full Node (verification)
- Per-tx LogicProof verify: ~3ms (mempool admission)
- Block verify: ~600ms

---

## 15. Philosophical Identity

Paranoid is:

```
  a recursively accumulated proof-native PoW ledger
  where:

    execution is local (wallet proves logic)
    state binding is server-side (full node proves Merkle)
    validity is global (BlockProof certifies everything)
    ordering is PoW
    history is recursive (O(1) verification)
```

The wallet proves mathematics. The full node proves reality. PoW orders time.
Recursion compresses history. No VM. No replay. No re-execution.

---

## 16. PoW Design Rationale (Blake3 + ASERT)

### Why Blake3 (not memory-hard, not Poseidon)

PoW in Paranoid does NOT protect execution — proofs handle that. PoW only provides:
- Canonical ordering of state transitions
- Sybil resistance for block proposal
- Objective cost to reorg (chain selection = most cumulative work)

Since PoW is purely an ordering mechanism:
- 51% hashpower = you choose tx ordering, but CANNOT fake state transitions
- ASIC dominance is less dangerous than in Bitcoin (no double-spend vector from hashpower alone)
- CPU-friendliness matters more for initial adoption than ASIC resistance

Blake3 gives:
- Any laptop mines at ~1 GH/s — the network bootstraps instantly
- Block verification adds zero overhead (nanosecond hash check)
- Simple implementation, no tuning parameters
- If ASIC dominance later becomes problematic, the hash is a soft dependency — swap via hard fork without touching the proof system

### Why ASERT (not Bitcoin's DAA, not per-block)

Bitcoin's 2016-block retarget (~2 weeks) is too slow for a young network. If hashrate
doubles on day 2, blocks come every 30s for two weeks. If hashrate halves, blocks stop
for hours. This kills UX.

ASERT with 6-block epoch (72s halflife):
- Adapts within ~6 minutes to any hashrate change
- Exponential (smooth, no oscillation)
- Stateless calculation (only needs anchor block + current height/time)
- Proven in production (Bitcoin Cash adopted ASERT in 2020, aserti3-2d)

6-block epoch was chosen to match `ANCHOR_DEPTH = 6` — same window as epoch_anchor
for transaction anti-replay. This aligns the two concepts: both difficulty and
transaction validity operate on the same temporal granularity.

### 128-bit nonce

64-bit nonce limits search space to 2^64 hashes. At 10 TH/s network hashrate,
that's exhausted in ~30 minutes — dangerous for high difficulties. 128-bit nonce
provides effectively unlimited search space for any foreseeable hashrate.

---

## 17. Segmented State — Design Rationale

### The scaling wall

The original `FriState` holds the entire state as three `Vec<Block128>` columns and
computes `state_root` by running NTT + Merkle over ALL elements:

```
  log_slots=24:  NTT over 16M elements — ~2 seconds per block
  log_slots=28:  NTT over 256M elements — ~30 seconds (unacceptable)
  log_slots=32:  NTT over 4B elements — impossible (192 GB RAM, hours of CPU)
```

FRI commitments are fundamentally non-incremental: changing one coefficient of the
polynomial changes EVERY evaluation in the codeword. There is no "patch one leaf"
operation on an FRI commitment.

### Why not Poseidon Merkle tree over individual slots?

This was the original design (before FRI-state). The problem is **in-circuit cost**:

```
  Poseidon Merkle opening at depth 24 = 24 Poseidon2b permutations per slot
  With 200 slots per block: 200 × 24 = 4800 permutations in BlockStateBinding
```

For comparison, the entire SpineGKR is 59 permutations. BlockStateBinding would
dominate the proof by 80x. Unacceptable.

### Why not Verkle / IPA?

IPA (Inner Product Arguments) uses elliptic curve groups. Verifying IPA openings
in a binary-field STARK requires simulating EC arithmetic in GF(2^128) — hundreds
of thousands of constraints per scalar multiplication. Worse than Poseidon Merkle.

### The solution: Segmented FRI

Split the monolithic polynomial into fixed-size segments:

```
  LOG_SEGMENT_SIZE = 16 (65536 slots)
  num_segments = 2^(log_slots - 16)
```

Each segment is independently FRI-committed (same mechanism as today, just smaller).
The global `state_root` is a Poseidon2b Merkle tree over segment roots (depth 8-16).

In-circuit proof of a slot:
1. FRI opening within the segment: 16-round sumcheck (CHEAPER than current 24-round)
2. Merkle path from segment root to state_root: 8 Poseidon2b perms (MUCH cheaper than 24)

```
  Total in-circuit: 16 sumcheck rounds + 8 Poseidon perms per unique segment
  vs old Poseidon-only: 24 Poseidon perms per slot (no batching possible)
```

The key insight: sumcheck rounds in binary fields are near-free (XOR operations),
while Poseidon perms are expensive. We trade 8 expensive Poseidon-only rounds
for 16 cheap sumcheck rounds + 8 Poseidon rounds. Net savings.

And with batching (multiple slots in same segment share path): even cheaper.

### Why LOG_SEGMENT_SIZE = 16?

- 2^16 = 65536 slots per segment = ~3 MB per segment (3 columns × 64K × 16B)
- NTT over 2^16 takes ~0.5ms — instantaneous per segment
- At log_slots=24: 256 segments fits in 768 MB total (RAM-friendly)
- At log_slots=32: 65536 segments, but only dirty ones loaded per block
- In-circuit: 16-round sumcheck is a good sweet spot (not too deep, not too shallow)
- Segment depth (8 at genesis → 16 at max): Poseidon overhead stays bounded

Making segments smaller (e.g., 2^12) would reduce NTT cost per segment but increase
the Merkle tree depth (12 → 20 Poseidon perms in-circuit). Making them larger
(e.g., 2^20) would make per-segment NTT expensive again. 2^16 is the Goldilocks zone.

### Storage backend motivation

At log_slots=24, the full state is ~768 MB — fits in RAM. But:
- At log_slots=28: 12 GB (doesn't fit on most machines)
- At log_slots=32: 192 GB (definitely doesn't fit)

Segmentation naturally enables disk-backed storage: only load dirty segments into
RAM for NTT computation. MDBX (used by Reth/Erigon for Ethereum state) provides
memory-mapped reads (slot lookups are pointer dereferences) and crash-safe writes
(copy-on-write, no WAL). A typical block loads ~50 segments × 3 MB = 150 MB
temporarily into RAM — feasible on any machine.

### Expansion under segmentation

When `log_slots` increments (§15.3), the number of segments doubles. New segments
are all-zero (committed as a constant `ZERO_SEGMENT_ROOT`). The Merkle tree gains
one level: `new_root = Poseidon2b(old_root, ZERO_SEGTREE_NODE[old_depth])`. Cost:
one hash. Identical to the old expansion cost but now over a segment tree rather
than a state tree.

---

## 18. Node Storage Modes

```
  ┌────────────────────────────────────────────────────────┐
  │  paranoid-node --storage=ram                            │
  │                                                        │
  │  All 256 segments live as Vec<Block128> in process heap │
  │  Total: ~768 MB at log_slots=24                        │
  │  Best: development, testing, early mainnet              │
  │  Limit: log_slots ≤ 26 (up to ~3 GB)                  │
  └────────────────────────────────────────────────────────┘

  ┌────────────────────────────────────────────────────────┐
  │  paranoid-node --storage=disk --data-dir=/path         │
  │                                                        │
  │  MDBX database file (mmap'd by OS)                     │
  │  Hot segments: in page cache (OS decision)             │
  │  Cold segments: on SSD, loaded on demand               │
  │  Block production: load dirty segments → NTT → release │
  │  Scales: log_slots=32 (192 GB on disk, ~150 MB RAM)   │
  └────────────────────────────────────────────────────────┘
```

The choice is non-consensus: both modes produce identical state_roots.
Nodes can switch modes via snapshot export/import.

---

## 19. Storage Layer Design Decisions

### 19.1 Two-tier dirty-segment tracking

`SegmentedFriState` originally had one `dirty: HashSet<u16>` tracking which
segments need FRI root recomputation. This set is cleared automatically when
`flush_segment()` recomputes the FRI root — which happens on every `root()` call,
which happens inside every `apply_delta` call.

The MDBX backend needs to know *which segments changed since the last disk
commit* — a different, longer-lived concept. The two needs are served by two
independent sets:

- `dirty` (FRI-root tracking): cleared automatically by `flush_segment`. Fast
  NTT path.
- `mdbx_dirty` (MDBX-commit tracking): cleared only by explicit `clear_dirty()`
  after a successful `commit_block`. This correctly accumulates all mutations
  within a block and is reset per-block.

`dirty_segment_ids()` returns `mdbx_dirty`, making the API match the MDBX use
case. The old FRI-dirty tracking is purely internal.

### 19.2 set_segment_columns for O(1) restore

Restoring state from MDBX used to call `set_slot` for each non-empty slot. For
`log_slots=24` with many live slots, this would:
- Trigger O(n) `apply_delta` calls, each calling `root()` and recomputing the
  FRI NTT for the segment
- Mark all restored segments as `mdbx_dirty`, causing them to be re-written to
  MDBX on the first block after restart

`set_segment_columns` directly installs column data in O(1) per segment, marks
only `dirty` (FRI recomputation deferred to next `root()` call), and does NOT
mark `mdbx_dirty` (data is already in MDBX).

### 19.3 Nullifier set rebuild on restart

The original `restore_from_mdbx` left the RAM `NullifierSet` empty after restart,
with a stale note claiming "individual nullifiers are still in the DB". This was
wrong: `validate_block_consensus` uses the RAM `NullifierSet`, not the MDBX
T_NULLIFIERS table. An attacker could double-spend any transaction confirmed in
the last 144 blocks by resubmitting it after a node restart.

The fix: on startup, read the last ANCHOR_DEPTH block heights from T_NULLIFIER_BLOCKS
and call `NullifierSet::rebuild_from_blocks`. The rebuild is conservative (blocks
with no transactions are skipped in T_NULLIFIER_BLOCKS, slightly reducing the VecDeque
window count vs. a running node, but `total_nullifiers()` is always correct).

### 19.4 RAM rollback on MDBX commit failure

`validate_block_consensus` mutates `self.state` (slot data, active_slot_count,
alloc_counter) before the MDBX commit. If the commit fails:

**Before fix:** RAM was at H+1, MDBX at H. The node was in a split state with no
recovery path short of restart.

**After fix:** On MDBX commit failure, `apply_next_block` calls `revert_block`
with the pre-built undo log and restores the counters. Both RAM and MDBX are at H.
The caller can retry or skip the block without restarting.

### 19.5 Prune-failure non-propagation

`prune_after_commit` (which deletes stale undo logs, recent blocks, and nullifiers)
ran inside `commit_block` and propagated errors via `?`. A disk-full condition
during pruning would cause `commit_block` to return `Err` even though the block
was already durably committed to MDBX. The next call to `apply_next_block` would
then fail consensus validation (block H+1 trying to apply on top of a state that
already has H+1).

The fix: prune failures are silently ignored. Stale entries accumulate until the
next successful commit, but the chain state is always consistent.

### 19.6 T_TX_INDEX: bounded by ANCHOR_DEPTH

The `tx_index` table maps TxBodyHash → (height, tx_pos). It is pruned in
`prune_after_commit` together with nullifiers: when a block exits the
ANCHOR_DEPTH (144-block) window, all its TxBodyHash entries are removed from
both `T_NULLIFIERS` and `T_TX_INDEX` in one atomic pass via `T_NULLIFIER_BLOCKS`.

Receipts are therefore available for the last 144 blocks (~144 minutes at
60 s/block). Older receipts must be exported by the wallet before that window
closes. The T_TX_INDEX size is bounded: O(ANCHOR_DEPTH × avg_txs_per_block).

### 19.7 T_NULLIFIERS: persistent O(1) lookup index

T_NULLIFIERS maps TxBodyHash → block_height for O(1) single-hash lookup. It is
currently unused at runtime (the RAM NullifierSet is used for all consensus checks,
and T_NULLIFIER_BLOCKS is used for rebuild). It is retained for the `paranoid_checkNullifier`
RPC endpoint which requires O(1) persistent lookup without loading the full RAM set.

---

## 20. Node Infrastructure Design Decisions

### 20.1 WalletProofBundle — proof delivery without exposing SpendSecret

The block prover (`prove_block`) requires:
- AIR **trace** — derivable from public `tx_body` via `witness_from_body`, no SpendSecret
- `auth_proof: AuthProofKillShot` — from `LogicProof.auth`, already proven by wallet
- `auth_slices: Vec<Vec<Block128>>` — MLE columns for AuthGKR state, requires SpendSecret to compute

Since `auth_slices` cannot be computed by the full node, the wallet provides them.
They are safe to transmit: Poseidon2b outputs bound to a specific `tx_body_hash`,
cryptographically unable to reveal SpendSecret.

`WalletProofBundle = { LogicProof, auth_slices }` serialized via bincode. Requires
adding `#[derive(Serialize, Deserialize)]` to all proof types across:
`noid_core`, `noid_fri_binius`, `noid_gkr`, `noid_stark`, `noid_tx`, `noid_poseidon2b`.

### 20.2 prove_block: coinbase-only block handling

`run_prove_block` returns marker hashes `[1u8;32]` when no `WalletProofBundle` is
available (coinbase-only blocks with no non-coinbase transactions). Non-zero marker
hashes pass the `MissingProofTranscriptHash` check in `apply_block` and allow the
chain to advance. Blocks containing user transactions require a valid `WalletProofBundle`
from the wallet (submitted as part of `TxIntent`).

### 20.3 ASERT target in template builder

The template builder previously used `parent.difficulty_target` directly. This is wrong:
`validate_header` rejects blocks where `header.difficulty_target` doesn’t match the computed
ASERT value. Fix: `TemplateBuilder::build()` calls:
```rust
let difficulty_target = next_target(
    anchor.anchor_height, anchor.anchor_timestamp, &anchor.anchor_target,
    parent.height + 1, now_unix,
);
```

### 20.4 P2P design decisions

- **Gossipsub message dedup**: Content-hash IDs (`blake3(data)`) prevent duplicate delivery.
- **Identify is mandatory**: Without it, gossipsub silently refuses to route to peers.
- **Idle timeout 300s**: Default libp2p timeout disconnects peers between blocks.
- **Block validation on receipt**: `apply_next_block` runs full native consensus on P2P blocks.
  Full ZK block-proof verification (`validate_block_full`) is performed by the miner
  before sealing. Mempool admission independently verifies each transaction's `LogicProof`
  (~84 ms, bounded by a semaphore to prevent CPU DoS).
- **Mempool relay**: `TxAdmitted` events are piped to gossipsub broadcast automatically.

## 21. Wallet & ZK Integration Design Decisions

### 21.1 `log_slots` в PublicInputs — binding к конфигурации цепи

`PublicInputs.log_slots` поглощается в Fiat-Shamir канал через `absorb_public_inputs`
(`noid_stark/src/lib.rs`). Это означает STARK доказательство **криптографически связано**
с конкретным значением `log_slots`.

**Инвариант**: для любого non-coinbase tx в блоке:
```
proof.tx_pis[k].log_slots == block.header.log_slots
```

**Откуда берётся log_slots:**

- **Кошелёк** (`prove_tx`): читает из `chain.tip_header().log_slots` в момент доказательства.
  Если между доказательством и включением произошло расширение `log_slots`, транзакция
  будет отклонена валидатором → нужно доказывать снова с новым `log_slots`.

- **Майнер** (`build_block_witnesses`): принимает `log_slots` из `BlockTemplate.inner.log_slots`
  (который уже учитывает expansion trigger). Передаёт в `build_tx_witness` → `build_public_inputs`.

- **Валидатор** (`validate_block_full`): проверяет `pi.log_slots == header.log_slots`
  для всех txs. Несовпадение → `VerifyBlockError::LogSlotsInconsistent`.

**Расширение log_slots** происходит крайне редко (trigger: 75% заполнения, т.е. ~12M из 16M
слотов при genesis log_slots=24). Проблема «tx proven at log_slots=24, block at log_slots=25»
решается отклонением и повторным доказательством (занимает ~300ms).

All three parties — wallet (`prove_tx`), miner (`build_block_witnesses`), and
validator (`validate_block_full`) — read `log_slots` from the live block header.
Hardcoded values are rejected at compile time by the `_: () = assert!(...)` anchor
in `params.rs`.

### 21.2 Receipts — автоматическая генерация

Блоки удаляются через `FINALITY_DEPTH=18` блоков. Receipt (Merkle-доказательство в `tx_root`)
должен быть сгенерирован ДО прунинга блока. Поэтому:

1. Когда блок применяется к цепи, P2P-обработчик вызывает `update_wallet_from_block`
2. Там же вызывается `generate_receipt(header, tx_body_hash, tx_index, block_tx_hashes, ...)` 
3. Receipt сохраняется в `WalletState.receipts: HashMap<[u8;32], Vec<u8>>`
4. `wallet_export_receipt(txhash)` просто отдаёт из этого map

Если блок уже спруненный — receipt недоступен ("block already pruned").

### 21.3 WalletHandle — архитектура без круговых зависимостей

`noid_rpc` не зависит от `noid_node`. Wallet-методы RPC реализованы через trait:

```
noid_rpc::WalletOps trait  ←  реализует  noid_node::WalletHandle
         ↓
    RpcHandler.wallet: Arc<dyn WalletOps>
```

`WalletHandle` держит `SharedWallet = Arc<Mutex<Option<WalletState>>>` и реализует WalletOps.
Все read-методы занимают lock кратко (~мкс). `build_send` (prove_tx, ~300ms-3s) вызывается
БЕЗ lock — данные извлекаются, lock освобождается, proves идёт снаружи:

```rust
// RPC handler: wallet_send (async)
let intent_bytes = tokio::task::spawn_blocking(move || {
    wallet.build_send(to, amount, fee, anchor, hints, log_slots)
}).await??;
```

### 21.4 MempoolEntry pre-proving fields

`cached_algebraic_proof: Option<Vec<u8>>` in `MempoolEntry` holds the pre-computed
algebraic STARK transcript for each admitted transaction. When populated, block
assembly can skip the per-tx algebraic prove step and run only the unified GKR + FRI
pass:
1. On admission: the wallet's `LogicProof` bytes are stored in `cached_algebraic_proof`
2. Block assembly deserializes `WalletProofBundle` from these bytes
3. `prove_block` uses the pre-computed auth proof instead of re-proving
4. Measured impact (bench on laptop): N=100 txs → 9.62s with caching. Strong hardware can prove ~1024 txs in ≤ 12s (WalletProofBundles pre-provided by wallets); ~100ms amortised per tx. prove_block time is O(N) due to unified block-level SpineGKR + single FRI.
