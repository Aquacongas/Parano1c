# PARANOID — ROADMAP TO MAINNET

**Architecture**: Proof-native UTXO chain on binary towers GF(2^128).  
**Principle**: Every transaction is a mathematical theorem. No trust, no history, no archive nodes.

---

## Current State (Baseline)

The cryptographic engine is complete and battle-tested:

```
noid_core         GF(2^128) tower, CLMUL/AVX2, MLE, sumcheck, NTT, transcript.
noid_poseidon2b   Poseidon2b native + AIR (perm, sponge, domain tags, compress).
noid_fri          Generic FRI (foundational dep: Channel, Blake3, NTT, code).
noid_fri_binius   Production PCS: interleaved commit, compact FRI, mixed opening.
noid_binius       Bit/byte packing for DA bandwidth reduction.
noid_gkr          Kill-Shot GKR: Spine (N×59), Auth (20-slot), Merkle (32-slot).
noid_air          AIRs + gates + compositions. Production: TxLogicAir (81 cols, 2048 rows).
noid_stark        STARK engine: prove_logic/verify_logic (Split GKR).
noid_tx           TxBody, TxIntent, PublicInputs, C_claimed, wire serialization.
noid_chain        BlockHeader, Block, SegmentedFriState, BlockStateBinding, NullifierSet.
noid_block        Block aggregation via deferred-opening (prove_block / verify_block).
noid_recursive    O(1) recursive chain: 6.5 KB proof, 5 ms verify.
bench_prover      Performance harness.
```

**Phase S (Stateless) — ✅ DONE**  
**Phase Q (Parallel STARK) — ✅ DONE**  
**Phase F (Segmented State) — ✅ DONE**  
**Phase H (Recursive Chain) — ✅ DONE**

What exists: ZK engine, state machine, block aggregation, wire formats, wallet logic, O(1) sync.  
What does NOT exist: networking, mempool, RPC, wallet CLI, mining, consensus validation, node binary.

**NEXT TO IMPLEMENT**: Phase 1 (Consensus Core) — in progress.

### Phase 1 Progress
- ✅ P.1 `params.rs` — all consensus constants
- ✅ P.2 `emission.rs` — block reward (halves per log_slots expansion, floor 1 NOID)
- ✅ P.3 `difficulty.rs` — BCH ASERT port with fixed-point [u64;4] arithmetic
- ✅ P.4 `pow.rs` — Blake3 PoW over header_core (parallel-proving design)
- ✅ P.5 `timestamps.rs` — MTP + future-drift rules
- ✅ P.6 `header.rs` — header chain validation (prev_hash, height, difficulty, timestamp, PoW, proof, log_slots)
- ✅ P.7 `block.rs` — coinbase structure (1 coinbase, first, zero inputs) + amount check in validation.rs
- ✅ P.8 `checks.rs` — per-tx: body_hash binding, epoch_anchor non-zero, nullifier; cross-tx slot conflicts
- ✅ P.9 `validation.rs` — `validate_block_consensus()`: header + coinbase amount + per-tx + apply_block orchestrator
- ✅ P.10 `da_prune.rs` — `BlockUndoLog`, `build_undo_log`, `revert_block`, `prune_undo_logs`
- ✅ P.11 `fork_choice.rs` — `choose_chain` (height → difficulty → hash tie-break), `reorg_allowed`
- ❌ P.12 `reorg.rs` — full reorg orchestration (needs P2P, Phase 3)
- ✅ P.13 `genesis.rs` — `genesis_header`, `genesis_state_root` (hardcoded), `GENESIS_NONCE = 2`
- ✅ P.14 `receipt.rs` — ParanoidReceipt with Blake3 Merkle + direction bitmask
- ✅ `allocator.rs` — splitmix64-based slot hint generator (free_slots removed)

**Architecture note**: `validate_block_consensus()` handles all native rules. ZK verification
(`verify_logic` per tx + `verify_block` for BlockProof) is layered on top in
`noid_block::validate_block_full()` — to be implemented in Phase 2 (see P.9 note below).

- ✅ P.20 `chain_context.rs` — `ChainContext` struct, `init_from_genesis()`, `apply_next_block()`
- ✅ P.21 `nullifier.rs` — `pop_latest_block()`, `rebuild_from_blocks()` for reorg support
- ✅ P.22 `validation.rs` — §15.3.6 expansion trigger: `log_slots` must increment iff occupancy ≥ 75%
- ✅ P.23 `checks.rs` + `params.rs` — fee overflow guard (`fee > u64::MAX` → `BadFee`); `MIN_FEE_BASE`, `FEE_PER_OUTPUT`, `min_fee()` constants
- ✅ P.24 `block.rs` — `apply_genesis_block()` genesis bootstrap (bypasses witness/proof checks)
- ✅ P.16 Fee market — designed (see P.16 section below)
- ✅ P.17 Economic attack surface — analysed (see P.17 section below)
- ✅ P.18 Failure & recovery semantics — designed (see P.18 section below)
- ✅ P.19 Recursive failure domains — designed (see P.19 section below)

- ✅ P.12 `reorg.rs` — `find_common_ancestor`, `apply_reorg` (full within-finality-window reorg)
- ✅ P.13 `prove_genesis_recursive()` — genesis `RecursiveBlockProof` (null witness, zero rounds)
- ✅ P.25 `ordering.rs` — `order_block_txs()`: coinbase first, descending fee, hash tie-break (miner policy)
- ✅ P.26 `conflict.rs` — `resolve_slot_conflicts()`: winners by argmin(tx_body_hash) per contested slot
- ✅ P.27 `mempool.rs` — `Mempool`, `MempoolEntry`, `MempoolError`: admit, evict_expired, select_for_block, on_block_confirmed
- ✅ P.28 `mempool_checks.rs` — `validate_tx_for_mempool()`: anchor hash check, slot liveness, state emptiness
- ✅ P.29 `template.rs` — `BlockTemplate`, `build_block_template()`: conflict resolution → state apply → coinbase → header_core for miner
- ✅ P.30 `noid_block::validate.rs` — `validate_block_full()` (native + ZK), `build_tx_airs()`
- ✅ P.31 `noid_block::block_chain_context.rs` — `BlockChainContext`: consensus + recursive proof in one struct
- ✅ `noid_tx::ANCHOR_DEPTH = 144` — tx validity window 2.4h normal / 3 days @ 30min blocks

**Phase 1 is COMPLETE.** All consensus logic, validation, mempool, template, reorg, and recursive chain are implemented as pure in-memory Rust with no I/O.

**What Phase 2 adds** (storage + network layer on top of this logic):
- MDBX: persist headers/state/undo-logs across restarts
- P2P: block/tx propagation
- Block Template API: external miner interface (248-byte header_core)
- Mempool pre-proving loop (tokio async + rayon)

---

## Fundamental Architecture Decisions

### Block Production: Parallel PoW + Prove

**Problem solved**: `proof_transcript_hash` is in the block header → previously PoW needed proof first → sequential.

**Solution**: PoW runs over `header_core` WITHOUT `proof_transcript_hash`. Both proceed in parallel.

```
header_core = {
  prev_block_hash, state_root, tx_root, timestamp, height,
  miner_address, nonce, difficulty_target,
  log_slots, active_slot_count, alloc_counter
}

PoW   = Blake3(header_core || nonce) < difficulty_target   ← runs independently
Proof = prove_block(txs) → BlockProof                      ← runs in parallel

Block = header_core + proof_transcript_hash + txs + BlockProof

Chain hash: next block's prev_block_hash = Blake3(FULL header including proof_transcript_hash)
→ proof IS committed to chain, just not inside the PoW computation
```

**Security**: `state_root` in `header_core` depends on all txs + `miner_address` (via coinbase output). Stealing another miner's proof is impossible — it commits to a different `state_root` (different miner gets coinbase → different post-state).

**Result**:
- PoW always targets 60s regardless of proving time (ASERT works independently) ✓
- Weak prover: proves in 100s, publishes late — ASERT sees longer intervals, auto-adjusts ✓
- Strong prover: proves in 5s, waits for PoW — publishes at ~60s ✓
- Block always has valid proof before publication ✓

**Template refresh triggers**:
1. Every 15 seconds
2. 100+ new txs in mempool
3. New block received from P2P (prev_hash changes)

### Emission: Anti-Spam Inverse Proportionality

**No halving.** Pure inverse relationship with slot occupancy:

```rust
const BASE_REWARD: u64  = 50 * 1_000_000;  // 50 NOID in μNOID
const USAGE_SCALE: u64  = 1_000_000;        // every 1M occupied slots halves the reward
const FLOOR_REWARD: u64 = 1 * 1_000_000;   // 1 NOID minimum forever

fn block_reward(active_slot_count: u64) -> u64 {
    let divisor = 1 + active_slot_count / USAGE_SCALE;
    (BASE_REWARD / divisor).max(FLOOR_REWARD)
}
```

| Occupied slots | Reward |
|----------------|--------|
| 0 | 50 NOID |
| 1M | 25 NOID |
| 4M | 10 NOID |
| 16M (2^24, genesis) | ~3 NOID |
| Always | ≥ 1 NOID |

**Anti-spam property**: Filling slots to inflate reward reduces the reward for everyone including the spammer. Network health is incentivized.

### DA Policy: Delete Immediately

**DA deleted right after `apply_block`.** No retention window.

```
AFTER apply_block(block):
  ✅ Keep: BlockHeader (FOREVER — needed for receipt verification)
  ✅ Keep: Current SegmentedFriState (FOREVER)
  ✅ Keep: RecursiveBlockProof tip (FOREVER)
  ✅ Keep: BlockUndoLog (last 6 blocks = 1 epoch, then delete)
  ❌ Delete: BlockProof bytes
  ❌ Delete: PackedWitness / DA trace
  ❌ Delete: Raw tx list
```

**Reorg handling without DA**: Keep compact undo logs (not full DA):
```rust
pub struct BlockUndoLog {
    pub block_height: u64,
    pub slot_changes: Vec<(u32, SlotValue)>,  // (slot_index, value_before)
}
// Max size: 48B/slot × 12 slots/tx × 1024 txs = ~590 KB per block
// Keep last 6 blocks in memory. After 6 confirmations = finality → discard.
```

Reorg within 6 blocks: apply UndoLog entries in reverse (no network access needed).  
Reorg deeper than 6: rejected by finality rule.

### Receipt Design (ParanoidReceipt)

A receipt is a **claim** about a transaction. **Verification uses the live network**.

```rust
pub struct ParanoidReceipt {
    pub version:       u8,
    pub tx_body_hash:  [u8; 32],
    pub merkle_path:   Vec<[u8; 32]>,   // Merkle path from tx_body_hash to tx_root
    pub claimed_root:  [u8; 32],        // the tx_root this tx is claimed to be in
    pub claimed_height: u64,
    pub summary:       TxSummary,       // from/to/amount/timestamp (human-readable)
    // Optional: for air-gapped verification
    pub chain_cert:    Option<RecursiveBlockProof>,
}
```

**Why this is unforgeable**:
- Change `claimed_root` → Merkle path no longer matches → Step 1 fails
- Change `merkle_path` → Merkle check fails → Step 1 fails
- Change `tx_body_hash` → Merkle check fails AND network won't find it → Both steps fail
- Change `claimed_height` → Network returns wrong `tx_root` → Step 2 mismatch

**Verification process**:
```
STEP 1 (offline, math):
  MerkleVerify(tx_body_hash, merkle_path, claimed_root) == true
  → Proves: tx_body_hash included in this Merkle root

STEP 2 (online, canonical chain):
  Ask any node: getHeaderByHeight(claimed_height)
  received_header = canonical header at this height
  
  IF received_header.tx_root == claimed_root:
    → CONFIRMED: tx is in canonical chain
  IF received_header.tx_root != claimed_root:
    → REORGED: this block was reorganized (tx invalid)
  
  PoW check: Blake3(received_header) < received_header.difficulty_target
  → Proves: real computational work done (header is genuine)

STEP 2 (offline with cert):
  verify_tip(chain_cert, expected_hash = hash(header))
  → RecursiveProof proves this block is in canonical chain
```

**Why we keep headers forever**: exactly for Step 2. Even in 10 years, any node can check `getHeaderByHeight(12345)` and verify the tx_root.

### Units

```
1 NOID = 1_000_000 μNOID (microNOID)
All values in wire format: u64 in μNOID
Max single value: 2^64 - 1 μNOID ≈ 1.8 × 10^13 NOID (more than enough)
Display: "10.500000 NOID" (6 decimal places)
```

### Slot Allocation

Wallets need free slot indices for transaction outputs. Slots are allocated via a node-side deterministic PRNG:

```
SLOT SPACE GROWTH:
  Genesis:   log_slots = 24  →  2^24 = 16,777,216 slots
  Auto-expansion: when active_slot_count ≥ ~75% capacity
                  log_slots += 1, capacity doubles, new segments are virtual zeros
  Maximum:   log_slots = 32  →  2^32 = 4,294,967,296 slots

NATIVE ALLOCATOR (node-side):

  alloc_counter = consensus-significant field in BlockHeader
  Incremented by +1 for each new output created in the block.

Wallet flow:
  1. wallet → node: paranoid_getSlotHints(count = N)
  2. node:  mask = 2^current_log_slots - 1  (grows with network!)
            seed = current alloc_counter
            for i in 0..N:
              loop: candidate = PRNG(seed++) & mask
              if state[candidate] == EMPTY: slots.push(candidate)
            return slots: [201, 4503, 12877]
  3. wallet: puts these in TxBody.outputs[i].slot_index
  4. miner:  BlockStateBinding verifies each slot is EMPTY in current state

HINTS ARE NON-AUTHORITATIVE:
  Two wallets may receive the same hint.
  Miner resolves conflicts: first tx in wins, second is dropped.
  Dropped wallet: error → get new hints → rebuild tx (~156ms)
  Conflict rate: very low (2^log_slots available slots, small fraction occupied).

CONFLICT HANDLING IN MEMPOOL:
  Track reserved_slots: HashSet<u32> (slots claimed by pending txs)
  When issuing hints: exclude reserved_slots from candidates
  When tx is confirmed or evicted: release its slots from reserved_slots
```

### Key Management (Mode 1 for launch)

```
On wallet init:
  master_secret = random_bytes(32)
  encrypted     = ChaCha20-Poly1305(master_secret, key=Argon2id(password))
  save as ~/.paranoid/wallet.secret

Address derivation:
  address_n = derive_address(Poseidon2b(master_secret, n, "paranoid-derive-v1"))
```

Mode 2 (Object Secret) — designed, implemented later:
```
spend_secret = Poseidon2b(Blake3(file_bytes), user_salt, "paranoid-object-v1")
```

---

## Phase S — Stateless Architecture ✅ DONE

### S.1 Epoch Anchor ✅
`TxBody.epoch_anchor: Digest`, `ANCHOR_DEPTH = 6`. Anti-replay across forks.

### S.2 Claims Commitment (C_claimed) ✅
`compute_claims_commitment(inputs, outputs) -> Digest`. Poseidon2b sponge under `TAG_CLAIMS`.

### S.3 TxLogicAir ✅
81 columns, `log_rows = 11` (2048 rows). Balance, range, auth pin. No state columns.

### S.4 LogicProof Pipeline ✅
`prove_logic` / `verify_logic`. Split GKR: wallet proves AuthGKR, block prover handles SpineGKR.  
Measured: prove ~156ms, verify ~84ms, proof size ~26 KB.

### S.5 BlockStateBinding ✅
Opens all input/output slots, verifies pre-conditions, C_claimed bridge.

### S.6 Integrated BlockProof ✅
`prove_block` + `verify_block`. N per-tx parallel algebraic STARKs + unified block SpineGKR + single FRI.  
Measured (100 txs): prove ~10s, verify ~2.8s.

### S.7 Nullifier Set ✅
Rolling 6-block window. O(1) lookup and insertion.

### S.8 TxIntent Wire Format ✅
`spend_secret` never on wire. Deterministic encoding.

---

## Phase Q — Parallel Per-Tx STARK ✅ DONE

**Goal**: Reduce `prove_block` from ~43s to <10s at 100 txs (8 cores).

**Key insight**: Replace sequential block Fiat-Shamir with independent per-tx channels seeded from `H(prev_state_root || cap || tx_index)`. The Merkle cap cryptographically binds all columns post-commit. Parallel execution is sound because the witness is immutable after commit.

### Q.1 Per-Tx Channel Factory ✅
`per_tx_algebraic_channel(prev_state_root, cap, tx_index)` with full domain separation.

### Q.2 Fixed Column Separation ✅
`FixedColumns` struct: selectors shared across all txs via zero-copy refs. Saves ~65 MB per 100-tx block.

### Q.3 Parallel Stage 5 (prove_block) ✅
`(0..n_tx).into_par_iter()` over independent per-tx algebraic STARKs.

### Q.4 Segmented Transcript Absorption ✅
Merkle-reduce per-tx digests for Stage 6 channel seeding. Unlocks streaming verification.

### Q.5 Parallel Verifier ✅
`verify_block` Stage 2b: `into_par_iter()` over per-tx auth Kill-Shots + algebraic STARKs.

**Performance (measured)**:

| Metric | Before Q | After Q (8 cores) |
|--------|---------|-------------------|
| prove_block (100 tx) | ~43s | ~10s |
| verify_block (100 tx) | ~15s | ~2.8s |
| RecursiveProof size | 6.5 KB | 6.5 KB (unchanged) |

**Soundness**: Non-adaptive soundness for committed witnesses. Cap is collision-resistant (Blake3). Per-tx challenges cannot be predicted before commit. Cross-tx binding enforced by Stage 6. See Soundness Summary.

---

## Phase F — Segmented State ✅ DONE

**Goal**: Scale state beyond 2^16 slots. Segment state into independently FRI-committed chunks.

### F.1 RAM Backend & Virtual Zero Segments ✅
`RamBackend`, pre-computed zero subtree roots. Empty segments: zero allocation.

### F.2 Segmented FRI Commitment ✅
`2^(log_slots - 16)` segments of `2^16` slots each. Independent FRI roots per segment.

### F.3 Segment Merkle Tree ✅
Global `state_root` = Poseidon2b Merkle tree over segment roots. O(log N) dirty updates.

### F.4 Dirty Tracking ✅
Only modified segments recomputed. Target: <50ms for state root update in typical block.

### F.5 Merkle Kill-Shot Integration ✅
Reuses `noid_gkr` `prove_merkle_killshot` / `verify_merkle_killshot`. No AIR rows for Poseidon2b.

### F.6 BlockStateBinding Refactor ✅
Two-tier: FRI opening against `seg_root` + Merkle path to `state_root` via Kill-Shot.

### F.7 Automatic Expansion ✅
`log_slots += 1`: upper half becomes zero segments. One Poseidon2b compression.

---

## Phase H — Recursive Chain ✅ DONE

**Goal**: O(1) chain verification. Any node verifies entire history with 6.5 KB + 5 ms.

### Key Metrics (Measured)

| Metric | Value |
|--------|-------|
| `RecursiveBlockProof` size | **6.5 KB** (constant regardless of chain length) |
| `verify_tip` time | **~5 ms** (O(1)) |
| `prove_recursive_step` overhead | **~30 ms/block** |
| New node sync | **6.5 KB** download + state snapshot |
| compact FRI rounds in rec proof | **0** (n_rounds = 0, pure tensor decomposition) |

### Implementation Summary

**H.1** Chain Accumulator: `ChainAccumulator { height, state_root, chain_hash }`. Rolling Poseidon2b: `chain_hash_n = compress(chain_hash_{n-1}, H_BLOCK(header_n))`. ✅  
**H.2** Algebraic Replay Witness: extracts multipoint rounds + FRI data from BlockProof. ✅  
**H.3** STARKPack insight: `COMPACT_TAU=8, log_rows=8 → n_rounds=0 → zero Merkle paths`. ✅  
**H.4** `RecursiveBlockAir` (8 cols, 256 rows): FoldCheckGate for sumcheck consistency + state root pin. ✅  
**H.5** `prove_recursive_step → RecursiveBlockProof` (6.5 KB). ✅  
**H.6** Poseidon2b in compact FRI round trees (Phase A). ✅  
**H.7** `verify_tip(rec_proof, ...) → ~5ms O(1)`. ✅  

---

## Phase 1 — Consensus Core

**Goal**: All block validity rules, emission, DA pruning, ASERT, fork choice. Pure logic, no I/O.

Reference: `noid_consensus` crate with provider traits (Reference: Reth `crates/consensus`).

### P.0 Crate Structure & Trait Architecture

```rust
// noid_consensus/src/lib.rs
pub trait HeaderProvider { fn get_header(&self, height: u64) -> Option<BlockHeader>; }
pub trait NullifierProvider { fn contains(&self, hash: &TxBodyHash) -> bool; }
pub trait StateProvider { fn get_slot(&self, idx: u32) -> SlotValue; }

pub enum ConsensusError { InvalidPoW, BadTimestamp, BadTxRoot, /* ... 16 variants */ }
```

### P.1 Consensus Parameters (`params.rs`) ✅

```rust
// Timing
pub const BLOCK_TIME:           u64   = 60;
pub const EPOCH_LENGTH:         u64   = 6;
pub const HALFLIFE:             u64   = 360;           // EPOCH_LENGTH × BLOCK_TIME
pub const MAX_FUTURE_DRIFT:     u64   = 120;
pub const MEDIAN_TIME_BLOCKS:   usize = 11;
// Block limits
pub const BLOCK_MAX_TXS:        usize = 1024;
pub const MAX_INPUTS:           usize = 4;
pub const MAX_OUTPUTS:          usize = 8;
// Epoch anchor / finality
pub const ANCHOR_DEPTH:         u64   = 6;
pub const FINALITY_DEPTH:       u64   = 18;            // 3 × EPOCH_LENGTH
pub const UNDO_LOG_RETENTION:   u64   = FINALITY_DEPTH; // must equal FINALITY_DEPTH
// Slot state
pub const LOG_SLOTS_GENESIS:    u32   = 24;
pub const LOG_SLOTS_MAX:        u32   = 32;
pub const LOG_SEGMENT_SIZE:     u32   = 16;
pub const EXPAND_NUM:           u64   = 3;             // trigger at 75 %
pub const EXPAND_DENOM:         u64   = 4;
// PoW
pub const GENESIS_TARGET:       [u8;32] = /* 2^252 */;
// Emission
pub const MICRONOID_PER_NOID:   u64   = 1_000_000;
pub const BASE_REWARD_MICRONOID: u64  = 50_000_000;   // 50 NOID
pub const FLOOR_REWARD_MICRONOID: u64 = 1_000_000;    // 1 NOID
// Fee policy (non-consensus, local node enforcement)
pub const MIN_FEE_BASE:         u64   = 5_000;         // 0.005 NOID
pub const FEE_PER_OUTPUT:       u64   = 2_000;         // 0.002 NOID/output
pub const fn min_fee(n_outputs: u64) -> u64 { MIN_FEE_BASE + n_outputs * FEE_PER_OUTPUT }
// PRNG
// splitmix64 constants embedded in allocator.rs (no separate params)
// Pre-proving channel
pub const PRETX_CHANNEL_TAG: &[u8] = b"paranoid-pretx-v1";
```

**Done when**: All constants match SPECIFICATION.md. ✅ *Implemented and tested.*

### P.2 Emission Schedule (`emission.rs`) ✅

```rust
// Halves once per log_slots expansion (not per active_slot_count).
pub fn block_reward(log_slots: u32) -> u64 {
    (BASE_REWARD_MICRONOID >> (log_slots - LOG_SLOTS_GENESIS)).max(FLOOR_REWARD_MICRONOID)
}
pub fn total_fees(txs: &[TxBody]) -> u64
pub fn max_coinbase_value(log_slots: u32, non_coinbase_txs: &[TxBody]) -> u64
```

Halving table: 24→50, 25→25, 26→12.5, 27→6.25, 28→3.125, 29→1.5625, 30+→1 NOID (floor).

**Done when**: Verified by property tests (floor, monotone, halving). ✅ *Implemented and tested.*

### P.3 ASERT Difficulty (`difficulty.rs`)

Reference: Bitcoin Cash ASERT.

```rust
pub fn next_target(anchor_height, anchor_timestamp, anchor_target, height, timestamp) -> [u8;32]
```

- Fixed-point 256-bit arithmetic — **NO FLOATS**
- Clamp: `[MIN_TARGET, MAX_TARGET]`
- Deterministic across all architectures

**Done when**: 50+ test vectors pass; zero floating point in codebase.

### P.4 PoW Validation (`pow.rs`)

```
PoW = Blake3(header_core_bytes) < difficulty_target

header_core does NOT include proof_transcript_hash.
Full block hash = Blake3(header_core + proof_transcript_hash + other fields).
```

**Done when**: Rejects wrong nonces, wrong targets, malformed headers.

### P.5 Timestamp Rules (`timestamps.rs`)

- `block_ts > median_time_past(last 11 headers)`
- `block_ts <= local_time + MAX_FUTURE_DRIFT`

**Done when**: Rejects backward and far-future timestamps.

### P.6 Header Chain Validation (`header.rs`) ✅

Checks (in order):
1. `prev_block_hash == Blake3(full parent header)`
2. `height == parent.height + 1`
3. `difficulty_target == expected_target(parent, anchor)` (ASERT)
4. Timestamp rules: MTP + future drift (P.5)
5. PoW: `Blake3(header_core) < difficulty_target` (P.4)
6. `proof_transcript_hash != [0u8;32]` (block must have proof)
7. `log_slots >= parent.log_slots` (monotone sanity check)

Precise `log_slots` expansion rule is enforced in P.9 `validate_block_consensus`.

**Done when**: Full header chain validates from genesis. ✅ *Implemented and tested.*

### P.7 Coinbase & Reward Rules (`block.rs` + `validation.rs`) ✅

Structural checks in `apply_block()`:
- At most one coinbase per block (first tx)
- `is_coinbase == true` → zero valid inputs
- Coinbase must be first tx

Amount check in `validate_block_consensus()`:
- `sum(coinbase.outputs[*].value) <= max_coinbase_value(header.log_slots, fees)`
- `max_coinbase_value = block_reward(log_slots) + total_fees(non_coinbase_txs)`
- Over-claiming → `ConsensusError::InflatedCoinbase`

**Done when**: Inflated coinbase rejected. ✅ *Implemented and tested.*

### P.8 Per-Transaction Consensus Checks (`checks.rs`) ✅

Order (cheapest first):
1. `fee <= u64::MAX` (overflow guard → `BadFee`)
2. `hash(tx.body) == tx.tx_body_hash` (→ `BadTxBodyHash`)
3. For non-coinbase: `epoch_anchor != [0;32]` (→ `BadEpochAnchor`)
4. `tx_body_hash` not in nullifier set (→ `NullifierCollision`)
5. Cross-tx slot conflicts via `validate_block_slot_conflicts()` (→ `SlotConflict`)

Deferred to ZK layer (`validate_block_full`):
- Epoch anchor hash against real headers (needs HeaderProvider)
- Balance: `Σ inputs == Σ outputs + fee` (proven by LogicProof)
- Ownership: spend_secret → owner (proven by AuthGKR)
- Output slots empty: `is_mint ⇒ prev == 0` (proven by BlockStateBinding)

**Done when**: All native checks enforced; double-spend caught. ✅ *Implemented and tested.*

### P.9 Block Validation Pipeline (`validation.rs`) ✅

`validate_block_consensus()` orchestrates cheapest-first:

```
1. validate_header()           — PoW, timestamps, difficulty, prev_hash, height    O(1)
2. §15.3.6 expansion trigger  — log_slots must/must-not expand based on occupancy  O(1)
3. BLOCK_MAX_TXS check        — hard DoS cap                                       O(1)
4. validate_block_slot_conflicts() — cross-tx input/output uniqueness              O(txs)
5. validate_tx_consensus() ×N — fee overflow, body_hash, anchor, nullifier         O(txs)
6. Coinbase amount check      — value ≤ block_reward + fees                        O(txs)
7. apply_block()              — state_root, active_count, alloc_counter            O(txs)
```

NOT checked here (ZK layer, to be added in `noid_block::validate_block_full`):
- LogicProof verifies (STARK + AuthGKR)
- BlockStateBinding verifies (Merkle openings)
- C_claimed bridge
- BlockProof aggregate
- epoch_anchor hash vs actual headers
- da_root / witness_root

**Done when**: All native invariants enforced. ✅ *Implemented and tested.*

### P.10 DA Pruning (`da_prune.rs`) ✅

```rust
pub struct BlockUndoLog {
    pub block_height: u64,
    pub slot_changes: Vec<(u32, SlotValue)>,  // pre-block values, ~590 KB max
}

// Call BEFORE apply_block; captures pre-state of all touched slots.
pub fn build_undo_log(state: &ChainState, block: &Block, height: u64) -> BlockUndoLog

// Restore state to pre-block. O(touched_slots).
pub fn revert_block(state: &mut ChainState, undo: &BlockUndoLog)

// Prune logs older than UNDO_LOG_RETENTION (= FINALITY_DEPTH = 18) blocks.
pub fn prune_undo_logs(logs: &mut HashMap<u64, BlockUndoLog>, current_height: u64)
```

Key invariant: `UNDO_LOG_RETENTION == FINALITY_DEPTH == 18`. This ensures any reorg
within the finality window can always be reverted. (Was `EPOCH_LENGTH = 6` — fixed.)

**Done when**: DA pruned; reorgs within 18 blocks always revertable. ✅ *Implemented and tested.*

### P.11 Fork Choice (`fork_choice.rs`)

1. Most cumulative PoW work (heaviest chain)
2. Tie-break: lower block hash (lexicographic)

Finality: reorgs deeper than `FINALITY_DEPTH = 18` blocks rejected.

**Done when**: Deterministic winner; deep reorgs rejected.

### P.12 Reorg Logic (`reorg.rs`)

Reference: Grin `chain/chain.rs`.

Steps: find common ancestor → reject if > FINALITY_DEPTH → revert state using UndoLogs → restore txs to mempool → apply new chain → update NullifierSet → update RecursiveProof.

**Done when**: 1-3 block reorgs handled; state consistent after reorg.

### P.13 Genesis Block (`genesis.rs`)

```rust
pub fn genesis_block() -> Block            // target = 2^252
pub fn genesis_state() -> SegmentedFriState  // all slots empty
pub fn genesis_recursive_proof() -> RecursiveBlockProof
```

Byte-identical on every node.

### P.14 Receipt Generation (`receipt.rs`)

```rust
pub fn generate_receipt(block: &Block, tx_body_hash: TxBodyHash) -> ParanoidReceipt
pub fn verify_receipt_online(receipt: &ParanoidReceipt, node: &RpcClient) -> ReceiptResult
pub fn verify_receipt_offline(receipt: &ParanoidReceipt) -> ReceiptResult
```

**Done when**: Receipts generated; verified correctly; reorged tx detected; headers stored forever.

### P.15 Canonical Serialization (`serial.rs`)

Goal: Byte-identical encoding across all architectures.

Topics:
- Endianness policy (little-endian everywhere)
- Canonical integer encoding (fixed-width, no varint for consensus fields)
- Digest serialization order
- Transcript byte encoding
- Network framing rules
- Snapshot encoding format

**Done when**: Same input → same bytes on ARM, x86, WASM, RISC-V.

### P.16 Fee Market & Resource Accounting ✅ (designed)

#### Cost model

| Resource | Cost driver | Paid by |
|---|---|---|
| Proving (~84ms CPU/tx) | fixen per tx | miner bears, fee compensates |
| DA bytes (Binius-packed) | ~200–500 B/tx | sender |
| Permanent state slot | 1 slot per output, forever | sender |
| Verification (~8ms/tx) | linear in block | miner bears |

PoW provides only ordering and Sybil resistance. Proving is the dominant cost.

#### Phase 1 — flat minimum fee (non-consensus, local policy)

```rust
// Enforced at mempool admission (not in ZK circuit, not in validate_block_consensus).
pub const MIN_FEE_BASE:    u64 = 5_000;   // 0.005 NOID  (covers proving amortized)
pub const FEE_PER_OUTPUT:  u64 = 2_000;   // 0.002 NOID per output (state allocation)
pub const fn min_fee(n_outputs: u64) -> u64 { MIN_FEE_BASE + n_outputs * FEE_PER_OUTPUT }
```

Examples: 1 output → 0.007 NOID; 8 outputs → 0.021 NOID; coinbase → exempt.

#### Phase 3 — dynamic floor (with mempool)

When mempool is congested, nodes raise the floor:
```
mempool_fee_floor = max(MIN_FEE_BASE,
                        median(last 50 admitted fee_rates) × 0.9)
```
Floor resets to `MIN_FEE_BASE` when mempool drops below 50 % capacity.

#### Miner incentives

Block reward + fees form total miner income. Empty blocks collect reward but no fees.
With Phase 1.5 pre-proving, full blocks take ~0 extra latency → no incentive to mine empty.
Fee income from 1024 txs at minimum fee: 1024 × 0.005 = 5.12 NOID (10 % of genesis reward).

**Done when**: `min_fee` enforced at mempool admission; fee constants in `params.rs`. ✅

---

### P.17 Economic Attack Surface ✅ (analysed)

#### A1 — Slot spam (state-filling attack)

Goal: fill 75 % of 2^24 slots to trigger expansion and halve miner reward.

```
Cost to fill 12.6M slots from empty state:
  Txs needed: 12.6M / 8 outputs = 1.575M txs
  Blocks:     1.575M / 1024 = 1538 blocks = 25.6 hours of chain time
  Min fee:    1.575M × 0.005 NOID = 7875 NOID
  Proving:    84ms × 1.575M = 36.75 CPU-hours (must produce valid proofs)
  Loss:       reward halves from 50 → 25 NOID; during attack: 1538 × 50 = 76900 NOID forgone
  Net attack cost: ≈46000 NOID minimum
```

After expansion: reward halves to 25 NOID — the attacker harms themselves as much as the network.

#### A2 — Empty block mining

Miner skips proving (0 txs) to start PoW earlier.
With Phase 1.5 pre-proving: full blocks have ~0 extra latency → incentive eliminated.
Without pre-proving: ~12s advantage at 1024 txs. ASERT auto-adjusts to slower intervals.

#### A3 — Prover centralization

A 2× faster prover gains ~10 % latency advantage (12s vs 6s proving / 60s PoW window).
ZK proof security is independent of who proves — a centralized prover cannot forge proofs.
ASIC risk: Blake3 is CPU/GPU-friendly now; fork-able hash function if ASICs dominate.

#### A4 — Double-spend attack

Requires reorg of ≥ FINALITY_DEPTH = 18 blocks. Needs 51 % hash power AND proving capacity.
With 51 % hash power but no proving: blocks rejected (MissingProof / invalid BlockProof).
With both: cost = honest miners’ accumulated work × 18 blocks. Equivalent to Bitcoin 51 % + ZK compute.

#### A5 — Epoch anchor manipulation

Wallet sends tx with anchor = arbitrary 32-byte hash (not from our chain).
Native check: anchor non-zero. Full check (anchor ∈ chain): at mempool admission, full node
verifies anchor against stored headers. If node doesn’t check this — tx included, ZK proof
still binds the anchor in `tx_body_hash`, but state validity is unaffected.
Conclusion: anchor check at mempool admission is important for UX (correct window), not security.

#### A6 — DA flooding

Attacker submits max-DA txs. Binius packing limits DA/tx. Hard cap `BLOCK_MAX_TXS = 1024`.
Block DA maximum: 1024 txs × ~500 bytes = ~512 KB/block. At 1 block/min = ~30 MB/hour.
DA is pruned immediately after `apply_block` — no long-term storage pressure.

---

### P.18 Failure & Recovery Semantics ✅ (designed)

#### Phase 1 (RAM backend)

All state in memory. On crash: state is lost. On restart: replay blocks from genesis.
- `apply_block` is transactional on a snapshot — snapshot swapped only on success.
- No partial state writes possible in Phase 1.
- Recovery: restart always produces the same `state_root` by deterministic replay.

#### Phase 2 (MDBX backend) — atomic commit protocol

```
BEGIN MDBX TXN
  1. write dirty segment data (slot changes)
  2. write new BlockHeader (height → bytes, stored forever)
  3. write header_by_hash (hash → height)
  4. update chain_tip (best height, best hash)
  5. update state_root, active_slot_count, alloc_counter
  6. write BlockUndoLog (height → undo, kept FINALITY_DEPTH blocks)
  7. delete expired UndoLog (height ≤ current - UNDO_LOG_RETENTION)
COMMIT

AFTER COMMIT (best-effort, re-runnable on restart):
  8. delete block DA (txs + BlockProof) — if crash here: DA survives one extra block, safe
  9. update recursive proof (async, separate MDBX txn)
```

If COMMIT fails: node is at state `H-1`; apply block `H` again on receipt from peer.
If crash after COMMIT but before step 8: safe, DA has an extra copy, deleted on next startup.

**Recovery invariant**: After any restart, `chain_tip.height == H` implies `state_root` in DB
matches the deterministic state root of block `H`. No replay needed.

#### Disk full

Segment data: 2^24 slots × 48 bytes = 805 MB at genesis, grows with active slots.
Headers: 276 bytes × forever. At 1 block/min × 10 years ≈ 1.46 GB.
DA: deleted immediately — 0 long-term growth.
Recursive proof: 6.5 KB (single tip value).

Mitigation: alert at 80 % disk usage; graceful shutdown before corruption.

---

### P.19 Recursive Failure Domains ✅ (designed)

The recursive prover is independent of the consensus path. Full nodes always validate
natively. Recursive proof exists only for O(1) light-client verification.

#### Three operating modes

```
NORMAL   : rec_proof lag ≤ 3 blocks  — O(1) sync available, all light clients happy
DEGRADED : lag 4–18 blocks           — warn light clients; full node operates normally
FALLBACK : lag > 18 blocks = FINALITY_DEPTH — light clients verify last 18 headers natively
```

Thresholds: `REC_PROOF_LAG_WARNING = 3`, `REC_PROOF_LAG_FALLBACK = FINALITY_DEPTH = 18`.

#### Crash recovery

```
Last proved height: K
Chain tip:         K + N

Recovery:
  for h in (K+1)..=(K+N):
    block      = storage.get_block(h)
    block_proof = storage.get_block_proof(h)
    acc        = accumulator.extend(block, block_proof)
    rec_proof  = prove_recursive(acc, block_proof)  // ~2s each
    storage.set_recursive_proof(h, rec_proof)

Time: N × 2s. At N = FINALITY_DEPTH (18): ~36s recovery.
```

#### Accumulator corruption detection

```rust
// Recompute from stored headers (O(H) Poseidon2b ops, fast even for 10M blocks)
fn verify_accumulator_integrity(acc: &ChainAccumulator, headers: &[(u64, BlockHeader)]) -> bool {
    let mut expected = genesis_accumulator(...);
    for (height, header) in headers {
        expected = expected.extend(header.state_root, full_block_hash(header), *height);
    }
    expected == *acc
}
```

Headers are stored forever — recomputation is always possible.

#### Key invariant: recursive proof is NOT required for consensus finality

A block is final after `FINALITY_DEPTH = 18` confirmations regardless of recursive prover status.
Recursive proof is required only for O(1) new-node sync. The chain continues safely in FALLBACK mode.

---

### P.20 Chain Context (`chain_context.rs`) ✅

```rust
pub struct ChainContext {
    pub headers:    HashMap<u64, BlockHeader>,  // all headers, forever
    pub nullifiers: NullifierSet,               // last ANCHOR_DEPTH blocks
    pub state:      ChainState,                 // current UTXO state
    pub undo_logs:  HashMap<u64, BlockUndoLog>, // last FINALITY_DEPTH blocks
    pub tip_height: u64,
    pub tip_hash:   [u8; 32],
}

impl ChainContext {
    pub fn init_from_genesis() -> Self;
    pub fn apply_next_block(&mut self, block: &Block, local_time: u64) -> Result<[u8;32], ConsensusError>;
    pub fn anchor_info(&self) -> AnchorInfo;
    pub fn prev_timestamps(&self) -> Vec<u64>;
}
```

This is the single source of truth for in-memory chain state. Phase 2 replaces the
inner fields with MDBX-backed equivalents behind the same interface.

**Done when**: Full node can be initialised from genesis and advance block-by-block. ✅

### P.21 NullifierSet reorg support (`nullifier.rs`) ✅

```rust
pub fn pop_latest_block(&mut self) -> Option<Vec<TxBodyHash>>
pub fn rebuild_from_blocks(blocks: impl IntoIterator<Item=Vec<TxBodyHash>>) -> Self
```

During reorg: call `pop_latest_block()` N times to revert N blocks, then rebuild from new chain.

**Done when**: Reorg reverts nullifier window correctly. ✅

### P.25 Canonical Transaction Ordering (consensus-significant) ❌

Transaction order within a block determines `tx_root` which is in the header.
Two nodes must produce identical tx ordering for the same set of admitted txs.

**Proposed rule** (to be adopted into SPECIFICATION.md §7):
```
1. Coinbase tx first (if present)
2. Remaining txs: descending fee_rate (fee / n_inputs_outputs)
3. Ties: ascending tx_body_hash (lexicographic)
```

This is deterministic, fee-incentive-compatible, and easy to verify.

**Done when**: Rule in SPECIFICATION §7; validator checks ordering; test with equal-fee txs.

### P.26 Slot Conflict Resolution (`consensus/conflict.rs`) ❌

When two txs in the block candidate set claim the same output slot (SPECIFICATION.md §15.2):

```rust
/// Returns (winners, losers). Losers’ wallets must rebuild with new hints.
pub fn resolve_slot_conflicts(txs: Vec<Transaction>) -> (Vec<Transaction>, Vec<TxBodyHash>)
```

Algorithm:
```
for each conflicting (slot, [tx_a, tx_b, ...]):
    winner = argmin(tx.tx_body_hash)   // lexicographic minimum
    losers = rest
```

This is O(txs × max_outputs). Called before block assembly, not during validation.

**Done when**: Conflict resolution deterministic; losers returned to mempool for rebuild.

---

## Phase 1.5 — Pre-Proving Optimization (CORE — implement with mempool)

**Goal**: Reduce `prove_block` latency by pre-computing per-tx proofs as they arrive.

**This is not optional** — it's the architecture that makes 1024-tx blocks viable without increasing block time.

### Protocol Change: New Seed Scheme

**Old** (current): `H(prev_state_root || cap || tx_index)` — depends on block-specific cap, can't pre-compute  
**New**: `H(tx_body_hash || "paranoid-pretx-v1")` — depends only on tx content, pre-computable

**Security argument**:
- AlgebraicStarkProof proves tx logic only (balance, auth_tag, format) — not state transitions
- Proof is bound to tx content via trace columns → `cap` provides block-level binding at Stage 6
- Replay across blocks: impossible — different tx set → different `cap` → different block-level challenges
- Replay across forks: nullifier set handles this at consensus level
- `prev_state_root` in seed was redundant — `cap` already provides block-specificity

### Orphan Block Handling

When another node finds a block first:

```
MEMPOOL STATE: 1000 txs, all pre-proved

Receive foreign block (contains 200 of our txs):
  1. apply_block(): update state, add to nullifiers
  2. mempool.on_block(confirmed_hashes):
     a. Remove 200 confirmed txs from pool → their proofs discarded
     b. 800 remaining txs: pre-proved proofs STILL VALID (no state_root dependency)
     c. SpineMleAccumulator.remove_txs(200_confirmed)
        → O(200 * 59) = O(11800) ops

Build next block:
  800 txs with ready proofs + new arrivals
  Proving time: ~11s instead of ~44s
  
  Even if 100% orphan (0 overlap):
  Next block: 1000 surviving txs with valid proofs → ~11s
```

### Implementation

**MempoolEntry** stores cached proof:
```rust
pub struct MempoolEntry {
    pub intent:         TxIntent,
    pub cached_proof:   Arc<RwLock<Option<CachedAlgebraicProof>>>,
    pub spine_state_in: Vec<[Block128; 4]>,  // 59 slots for SpineMLE
    pub fee_rate:       u64,
}
```

**On admission** (after verify_logic passes):
```rust
// Spawn background pre-proving
let handle = tokio::task::spawn_blocking(move || {
    let ch = pre_tx_channel(&tx_body_hash);
    prove_air_algebraic_with_channel(air, &trace, &pi, ch)
});
entry.cached_proof.set_pending(handle);
```

**SpineMleAccumulator**:
```rust
pub struct SpineMleAccumulator {
    slots: Vec<[Block128; 4]>,  // collected slot_state_in vectors
    index: HashMap<TxBodyHash, usize>,  // tx → slot range
}

impl SpineMleAccumulator {
    pub fn add_tx(&mut self, hash: TxBodyHash, state_ins: &[[Block128; 4]; N_SPINE_SLOTS])
    pub fn remove_txs(&mut self, hashes: &[TxBodyHash])  // on block confirmed
    pub fn build_mle(&self, selected: &[TxBodyHash]) -> BlockSpineMle
}
```

**prove_block modification**:
```rust
// For each tx: use cached proof if available, otherwise prove on-the-fly
let tx_proofs: Vec<AlgebraicStarkProof> = selected_txs.par_iter().map(|tx| {
    if let Some(proof) = tx.cached_proof.get_ready() {
        proof  // O(0) — already done
    } else {
        prove_air_algebraic_pretx(tx)  // O(100ms) — rare, tx just arrived
    }
}).collect();
```

**Estimated impact** for 1024 txs:
```
SEQUENTIAL (current):    ~44s
With pre-proving:        ~12s (GKR 10s + per-tx 0s + MLE 1s + FRI 1s)
With parallel PoW:   max(12s, 60s) = 60s  ← PoW bottleneck, not proving
```

**Done when**: 1024-tx block prove < 15s; orphan block handling correct; no proof reuse across blocks.

---

## Phase 2 — Persistent Storage

Reference: Reth `crates/storage/db` (MDBX), Erigon database layout.

### MDBX Backend (`noid_chain/src/storage/mdbx.rs`)

Phase 1 uses `ChainContext` (in-memory `HashMap<u64, BlockHeader>` + `SegmentedFriState`). On restart: state is lost, must replay from genesis.

Phase 2 replaces the inner stores with MDBX:

**Database tables**:

```
headers           : height:u64 → BlockHeader bytes (276B, FOREVER)
header_by_hash    : [u8;32]    → height:u64
chain_tips        : "best"     → (height, hash)
state_segments    : (seg_id, local_idx) → SlotValue (48B, FOREVER)
nullifiers        : TxBodyHash → block_height:u64 (last ANCHOR_DEPTH=144 blocks)
alloc_counter     : "current"  → u64
active_slot_count : "current"  → u64
recursive_proof   : "tip"      → RecursiveBlockProof bytes (6.5 KB, FOREVER)
undo_logs         : height:u64 → BlockUndoLog (last FINALITY_DEPTH=18 blocks, ~11.5 MB max)
recent_blocks     : height:u64 → (Block bytes, BlockProof bytes) [last 18 blocks for peers]
tx_index          : TxBodyHash → (height, tx_index) [optional: receipt lookup]
```

DA (full BlockProof + PackedWitness) deleted immediately after `apply_block`.
`recent_blocks` kept ≤ FINALITY_DEPTH blocks for peer sync. After that: only header persists.

**Atomic commit protocol** (7 steps, see P.18 design above for details).

**Done when**: Crash-safe; state survives SIGKILL; DA pruned immediately; headers always available.

### BlockChainContext → MdbxChainContext

`BlockChainContext` (Phase 1) uses in-memory `ChainContext` for consensus state and `Option<RecursiveBlockProof>` for the recursive chain. Phase 2 replaces this with an `MdbxChainContext` that implements the same interface but persists to MDBX:

```rust
pub struct MdbxChainContext {
    db: mdbx::Environment,
    // Same methods as BlockChainContext but crash-consistent
}
```

The Phase 1 logic (validation, template, reorg, mempool) is already pure and can be reused unchanged.

### Storage Trait

```rust
pub trait BlockStore: HeaderProvider + StateProvider + NullifierProvider {
    fn put_block(&mut self, block: &Block, proof: &BlockProof) -> Result<()>;
    fn get_header(&self, height: u64) -> Option<BlockHeader>;     // ALWAYS available
    fn get_recent_block(&self, height: u64) -> Option<Block>;     // None if pruned (>18 blocks)
    fn best_tip(&self) -> (u64, [u8;32]);
    fn get_state(&self) -> &SegmentedFriState;
    fn get_recursive_proof(&self) -> Option<RecursiveBlockProof>;
}
```

---

## Phase 3 — Node Infrastructure

**TODO Phase 3**: Extract consensus provider traits into a `noid_consensus` crate.
Currently `validate_block_consensus()` and all consensus functions live in `noid_chain`.
When P2P, mempool, and RPC all need to import consensus rules from different crates,
create `noid_consensus` with `HeaderProvider`, `NullifierProvider`, `StateProvider` traits
and move `noid_chain::consensus::*` there. `noid_chain` becomes a dependency of `noid_consensus`.

### Mempool (`noid_mempool/`)

Reference: Reth `crates/transaction-pool`.

**Admission pipeline** (cheapest checks first):
1. `tx_limits`: MAX_INPUTS, MAX_OUTPUTS, fee ≥ min_relay_fee
2. `epoch_anchor` in valid window
3. Nullifier check (no double-spend)
4. Slot conflict check (no conflict within mempool)
5. `verify_logic(...)` — O(84ms), ZK verification last

**Template refresh**: Every 15s OR 100+ new txs OR new P2P block.

**Pre-prove hook** (Phase 1.5): On tx admission, spawn background `pre_prove_tx` task.

### Mining Engine (`noid_miner/`)

**Pipeline (parallel proving + PoW)**:

```rust
loop {
    let template = node.get_template();

    // Spawn proving in background
    let prove_handle = tokio::task::spawn_blocking(|| prove_block(&template.witnesses));

    // Simultaneously search PoW over header_core (without proof_transcript_hash)
    let pow_handle = spawn_pow_search(template.header_core.clone(), threads);

    // Wait for BOTH to complete
    let (proof, nonce) = tokio::join!(prove_handle, pow_handle);

    // Assemble final block
    let proof_hash = proof_transcript_hash(&proof);
    let full_header = template.header_core.with_proof_hash(proof_hash).with_nonce(nonce);
    let block = Block { header: full_header, /* ... */ };

    node.submit_and_broadcast(block, proof).await;
}
```

**PoW search**: Blake3 over `header_core || nonce`, parallel threads, interrupt on solution.

**Done when**: Solo mining works; parallel proving + PoW verified; ASERT adapts correctly to prove time.

### P2P Networking (`noid_p2p/`)

Reference: `rust-libp2p`.

**Protocol**: `/paranoid/1.0.0`

```
Requests:
  GetHeaders { start: u64, count: u16 } → Vec<BlockHeader>   // headers forever
  GetRecentBlock { height: u64 }        → Option<Block>       // only last 18 blocks
  GetState {}                           → StateSnapshot        // current state
  GetRecursiveProof {}                  → RecursiveBlockProof  // 6.5 KB

GossipSub topics:
  /paranoid/blocks/1  — New full blocks (header + proof)
  /paranoid/txs/1     — New TxIntents
```

**O(1) sync (no history download)**:
```
1. Get RecursiveBlockProof (6.5 KB) + tip BlockHeader from peer
2. verify_tip(proof, header) → 5 ms
3. Get StateSnapshot from peer + verify state.root() == header.state_root
4. Apply recent blocks (last 18) to catch up
5. Done. Full node in < 60 seconds.
```

**Done when**: Two nodes sync and reach consensus; tx/block broadcast < 1s.

### RPC API (`noid_rpc/`)

Reference: `jsonrpsee`.

```
ALWAYS AVAILABLE:
  paranoid_blockCount
  paranoid_getHeaderByHeight(h)      → BlockHeader   (stored forever)
  paranoid_getHeaderByHash(hash)     → BlockHeader
  paranoid_getRecursiveProof         → RecursiveBlockProof (6.5 KB)
  paranoid_getSlot(slot_index)       → { value, owner } | EMPTY
  paranoid_getActiveSlotCount        → u64
  paranoid_getChainInfo              → { height, best_hash, target, active_slots }

ONLY WITHIN RECENT 18 BLOCKS:
  paranoid_getBlock(height)          → Block | null

WALLET SUPPORT:
  paranoid_getSlotHints(count)       → Vec<u32>    (free slot indices)
  paranoid_getEpochAnchor            → Digest
  paranoid_submitTxIntent(hex)       → TxBodyHash | Error

RECEIPT:
  paranoid_verifyReceipt(receipt)    → ReceiptVerifyResult
  // Checks: Merkle inclusion + header.tx_root matches claimed_root

MINING:
  paranoid_getBlockTemplate(addr)    → { header_core, witnesses }
  paranoid_submitBlock(block_hex)    → BlockHash | Error

WEBSOCKET:
  paranoid_subscribe("newBlock")     → stream BlockHeader
  paranoid_subscribe("txConfirmed", hash) → fires when tx in block
```

### Node Binary (`noid_node/`)

```toml
[network]
listen = "/ip4/0.0.0.0/tcp/8333"
seeds = ["seed1.paranoid.network"]
max_peers = 50

[storage]
backend = "mdbx"
path = "~/.paranoid/data"

[rpc]
listen = "127.0.0.1:8332"

[mining]
enabled = false
threads = 0       # 0 = all cores
miner_address = "..."
```

**Startup**: Load config → Open MDBX → Prune old UndoLogs → Start P2P → O(1) sync → Start mempool → Start RPC → (if --mine) Start miner → Background recursive proof updater.

---

## Phase 4 — Wallet Core

### Key Management (`noid_wallet/`)

```rust
pub struct Keystore { master_secret: SpendSecret }

impl Keystore {
    pub fn generate(password: &str) -> (Self, PathBuf)
    pub fn load(path: &Path, password: &str) -> Result<Self>
    pub fn derive_address(&self, index: u32) -> (SpendSecret, Address)
}
```

Encryption: `Argon2id(password)` → `ChaCha20-Poly1305(master_secret)`.

### UTXO Scanner

```rust
impl Scanner {
    pub fn process_block(&mut self, block: &Block) // Full node mode
    pub async fn sync_from_rpc(&mut self, rpc: &RpcClient) // Light mode
}
```

Generates `ParanoidReceipt` for each confirmed tx touching owned slots.

### Transaction Builder

```
1. Coin selection (BnB algorithm reference: Bitcoin Core)
2. GET paranoid_getSlotHints(n_outputs) → free slot indices
3. Build TxBody + compute auth_tags
4. prove_logic(witness) → LogicProof (~156ms)
5. Submit via RPC or directly to mempool
```

### Receipt Management

```rust
pub fn export_receipt(history: &WalletHistory, tx_hash: TxBodyHash) -> Vec<u8>
pub fn verify_receipt_online(receipt: &ParanoidReceipt, rpc: &RpcClient) -> ReceiptResult
```

### CLI (`noid_cli/`)

```
noid wallet init               — Generate wallet file
noid wallet address [--index N]
noid wallet balance
noid wallet send <addr> <amount> [--fee N]
noid wallet history
noid wallet receipt <txhash>   — Export .paranoid-receipt file
noid wallet verify <file>      — Verify receipt (online)

noid node start [--mine]
noid node status
```

---

## Phase 5 — Integration Testing

### Multi-Node Harness

```rust
let net = TestNetwork::new(5);
net.mine_blocks(20);
net.submit_tx(alice, bob, 10_NOID);
net.mine_blocks(1);
assert!(net.all_agree_on_state_root());
assert_eq!(net.get_balance(bob), 10_NOID);
```

### Adversarial Scenarios

- Invalid PoW → rejected
- Invalid BlockProof → rejected  
- Double-spend → rejected
- Timestamp manipulation → rejected
- Over-claimed coinbase → rejected
- Slot spam to inflate reward → reward decreases → not profitable
- Reorg 1-3 blocks → handled via UndoLogs
- Fork at depth 19 → rejected (finality)
- DA deletion: headers always available; blocks unavailable after 18 blocks ✓

### Performance Targets

```
Block prove (100 txs, 8 cores):  < 60s total (prove ~10s + PoW ~50s)
Block prove (1024 txs, 8 cores): < 120s total (prove ~100s + PoW ~1s)
Block validate (100 txs):        < 5s
O(1) sync (fresh node):          < 30s (state snapshot, ~3 GB at log_slots=26)
Receipt verify (online):         < 200ms
Wallet send:                     < 500ms (156ms proof + network)
```

### DA Pruning Correctness

- Headers retrievable at any height ✓
- State always current ✓
- BlockProof and DA deleted immediately ✓
- Reorg works via UndoLog ✓
- Node restart: identical state_root ✓

---

## Phase 6 — Devnet

### Genesis Configuration

```rust
DEVNET_TARGET = 2^252   // trivial PoW — instant mining
DEVNET_LOG_SLOTS = 20   // 1M slots (smaller for devnet)
```

### Seed Infrastructure

- 3 seed nodes, DNS: `devnet-seed.paranoid.network`
- Faucet: `POST /faucet/{address}` → 100 NOID

### Receipt Verifier Web App

```
URL: receipt.paranoid.network

Upload: .paranoid-receipt file
Result: 
  ✅ CONFIRMED: Alice sent 10.500000 NOID to Bob
     Block 12345 | 2026-05-31 14:32:05 UTC
     Merkle: ✓  |  Canonical chain: ✓

  ❌ REORGED: This block was reorganized. Transaction invalid.
```

No blockchain explorer. No address lookup. No surveillance.

### Devnet Wallet App (Tauri)

- Full node integrated (runs `noid_node` in background)
- Wallet: generate, send, receive, history, export receipts
- Mining button (--mine)
- Node status panel

---

## Phase 7 — Testnet

### Testnet Genesis

```
TESTNET_TARGET  = 2^240   // ~65K expected hashes
BLOCK_TIME      = 60s
INITIAL_REWARD  = 50 NOID (at 0 active slots)
```

### Security Hardening

- External audit: ZK engine + consensus
- Fuzzing: P2P messages, block deserialization, mempool admission
- Dependency audit

### Success Criteria

- [ ] 10,000+ blocks without incident
- [ ] 50+ independent nodes
- [ ] Reorg recovery in production
- [ ] O(1) sync: 0 → 10,000 blocks
- [ ] Wallet send-receive-receipt end-to-end
- [ ] DA deletion verified (no history accumulation)
- [ ] Receipt verification tested (online + offline)
- [ ] 30-day window with no consensus bugs

---

## Phase 8 — Mainnet

### Genesis Ceremony

- Parameters published 72h in advance
- Any node can participate from block 1
- `MAINNET_TARGET = 2^235`, `LOG_SLOTS = 24`

---

## Phase 9 — Optimizations (Stage K)

### K.1 Reduced Inner Queries

Profile and reduce FRI inner query count for block-internal proofs (not wallet proofs). Target: `NUM_INNER_QUERIES = 16` for block prove path, `64` for LogicProof (wallet security unchanged).

### K.2 Parallel Recursive Prover

Partition recursive AIR trace across cores. Target: `prove_recursive_step` < 10ms.

### K.3 MDBX Zero-Copy Reads

`MdbxBackend` returns `SegmentView<'txn>` (mmap slice) instead of `Vec<Block128>`. Eliminates memcpy for state reads. Critical for `log_slots > 26`.

### K.4 Proof Compression

Delta-encode FRI Merkle paths. Estimated 20-30% proof size reduction for BlockProof.

---

## Phase 10 — GUI Wallet (Stage G)

### G.1 Framework: Tauri + Web UI
Rust backend (`noid_node` + `noid_wallet`), HTML/CSS/JS frontend.

### G.2 Modes
- **Full Node** (default): integrated node + optional mining
- **Light Mode**: connects to remote RPC

### G.3 Wallet UI
- Balance display
- Send / Receive
- Transaction history
- Receipt export (QR code + file)
- Receipt verify

### G.4 Full Node Controls
- Sync progress
- Peer count
- Mining toggle + hashrate
- Block height + network stats

---

## Dependency Graph

```
Phase S (Stateless)    ✅ DONE
    │
    ▼
Phase Q (Parallel STARK) ✅ DONE
    │
    ▼
Phase F (Segmented State) ✅ DONE ─── locked state format before recursion
    │
    ▼
Phase H (Recursive Chain) ✅ DONE ─── O(1) sync foundation
    │
    ▼
Phase 1 (Consensus)  ─────────────── uses RecursiveProofs for fast validation
    │
    ├── Phase 1.5 (Pre-Proving) ────── parallelizes mempool proving
    │
    ▼
Phase 2 (Storage: MDBX)
    │
    ▼
Phase 3 (Node: Mempool + Miner + P2P + RPC)
    │
    ▼
Phase 4 (Wallet Core)
    │
    ▼
Phase 5 (Integration Tests)
    │
    ▼
Phase 6 (Devnet)
    │
    ▼
Phase 7 (Testnet + Audits)
    │
    ▼
Phase 8 (Mainnet)
    │
    ▼
Phase 9 (Optimizations) — post-mainnet
Phase 10 (GUI Wallet) — overlaps Testnet
```

Critical path: **S → Q → F → H → P1 → P2 → P3 → Testnet → Mainnet**

---

## Design Invariants (Final)

1. **No archive nodes.** History does not exist. DA deleted immediately.
2. **No blockchain explorer.** Receipts prove specific transactions. Not surveillance tools.
3. **Proof-native.** Block without valid ZK proof = INVALID. Period.
4. **Parallel PoW + Prove.** PoW over `header_core` (no `proof_transcript_hash`). Prove in parallel. ASERT handles timing.
5. **Transparent.** All values on-chain.
6. **PoW = spam protection + ordering.** ZK proofs = correctness.
7. **Post-quantum by architecture.** No signatures, no elliptic curves.
8. **Full node scales with usage.** ~3 GB at genesis (log_slots=24), grows as network expands (max log_slots=32 → ~192 GB). Headers and recursive proof stay constant.
9. **O(1) sync.** 6.5 KB + 5 ms = verified entire history.
10. **Anti-spam emission.** More slots → lower reward. Spam hurts spammer.
11. **Receipts replace explorers.** Prove your tx. Don't surveil others.
12. **GF(2^128) everywhere.** One algebraic universe.
13. **128-bit security** on all components.
14. **Deterministic consensus.** Byte-identical `state_root` everywhere.
15. **Atomic state updates.** One MDBX transaction per block. No partial state.

---

## Soundness Summary

| Component | Security | Mechanism |
|---|---|---|
| FRI-Binius | 128-bit | 64 queries × 2-bit rate |
| Blake3 Merkle | 128-bit | collision resistance |
| Gamma batching | 128-bit | Horner RLC over GF(2^128) |
| SpineGKR (N×59) | 128-bit | Schwartz-Zippel, dynamic-var |
| AuthGKR (20 slots) | 128-bit | Schwartz-Zippel, 14-var |
| MerkleGKR (32 slots) | 128-bit | Schwartz-Zippel, 14-var |
| Batch-eval | 128-bit | degree-2 sumcheck + RLC |
| Fiat-Shamir | collision-resistant | Poseidon2b sponge |
| Parallel per-tx STARK | 128-bit | non-adaptive: cap-derived seeds |
| Parallel PoW | ordering-only | Blake3 + ASERT DAA |
| Recursion | 128-bit | native GF(2^128) field |
| Receipt (Merkle) | 128-bit | collision resistance on tx_root |
| Receipt (canonical) | 128-bit | PoW + live header chain |

No trusted setup. No elliptic curves. Post-quantum.

---

## Appendix A — Transcript & Fiat-Shamir Architecture

Goal: Formalize all transcript domains, challenge derivation, domain separation constants.

**Domain tag registry**:
```rust
TAG_TX_ALGEBRAIC   = 0x5458_414C_4745_4252_4149_4332_3032_3600  // "TXALGEBR AIC2026"
TAG_STATE_BINDING  = 0x5354_4154_4542_494E_4449_4E47_3230_3236  // "STATEBINDING2026"
TAG_BLOCK_MULTIPT  = 0x424C_4F43_4B4D_554C_5449_504F_494E_5400  // "BLOCKMULTIPOINT\0"
TAG_PRE_PROVE      = 0x5052455F50524F56455F563100000000000000  // "PRE_PROVE_V1"
PROTOCOL_VERSION   = 1
```

**Challenge derivation** (in order for per-tx STARK):
```
ch = Channel::new()
ch.observe(TAG_TX_ALGEBRAIC)
ch.observe(PROTOCOL_VERSION)
ch.observe(prev_state_root_hi, prev_state_root_lo)
absorb_cap(ch, cap)
ch.observe(tx_index)
```

**Invariants**:
- All channels start fresh (no inherited state from other channels)
- `cap` absorbed AFTER all columns committed (Commit-then-Challenge)
- `tx_index` prevents cross-tx reuse
- Stage 6 channel seeded AFTER Stage 5 outputs committed (Merkle reduce)
- Recursive replay uses deterministic transcript reconstruction

**Topics pending formal spec**:
- Streaming transcript reduction semantics
- Cross-protocol collision prevention proof
- Version migration policy
- Recursive replay compatibility guarantees
