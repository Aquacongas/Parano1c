# Paranoid Production API Specification

Last Updated: 2026-05-22

## Overview

This document specifies the production APIs consumed by wallets (light nodes),
full nodes, and external miners on the Paranoid mainnet. All APIs operate over
the Paranoid binary tower field GF(2^128) with Poseidon2b hash commitments and
FRI-Binius polynomial commitment scheme (interleaved packing, mixed-length
multipoint close).

Architecture: Stateless LogicProof (wallet) + BlockStateBinding (full node).
Two node types: Light Node (wallet) and Full Node (everything including block
assembly and mining). Wallets prove only math (balance, range, auth, spine).
Full Nodes prove state (Merkle openings) and coordinate PoW (built-in or
external miner via Block Template API).

---

## Table of Contents

1. [Wallet API](#1-wallet-api)
2. [Node API](#2-node-api)
3. [Prover API](#3-prover-api)
4. [Verifier API](#4-verifier-api)
5. [Block Producer API (Full Node)](#5-block-producer-api-full-node)
6. [Light Client API](#6-light-client-api)
7. [Data Availability API](#7-data-availability-api)
8. [Wire Formats](#8-wire-formats)
9. [Error Codes](#9-error-codes)

---

## 1. Wallet API

The wallet constructs transactions, derives cryptographic material, and
submits proven TxIntents to the network. The wallet is STATELESS with
respect to the global state tree — it never needs Merkle paths.

### 1.1 Transaction Construction

#### `create_transaction`

Constructs a `TxBody` from semantic user intent.

**Inputs:**
| Field | Type | Description |
|-------|------|-------------|
| `inputs` | `[TxInput; 0..4]` | UTXOs to spend (slot_index, claimed_value, claimed_owner) |
| `outputs` | `[TxOutput; 0..8]` | New UTXOs to create |
| `fee` | `u128` | Transaction fee |
| `epoch_anchor` | `[u8; 32]` | Hash of block header at (height - ANCHOR_DEPTH) |

**Output:** `TxIntent { body: TxBody, tx_body_hash: TxBodyHash, claims_commitment: Digest, logic_proof: LogicProof }`

**Semantics:**
- Wallet derives `spend_secret` from local keystore for each input
- Wallet computes `auth_tag[i] = H_AUTH(spend_secret[i], tx_body_hash)` per input
- Wallet picks `output.slot_index` for each output (requests indices from node)
- `tx_body_hash` = canonical 16-leaf Poseidon2b Merkle (epoch_anchor at L0)
- `claims_commitment` = Poseidon2b_sponge(all claimed slot data)
- Dummy inputs/outputs padded with `valid = false` up to MAX bounds

**Constraints:**
- `sum(inputs.value) == sum(outputs.value) + fee`
- All values < 2^64
- No duplicate output slot indices
- epoch_anchor must be within ANCHOR_DEPTH window (6 blocks)

---

#### `derive_address`

Derives the owner address from a spend secret.

```
Address = H_ADDR(spend_secret)
        = Poseidon2b(spend_secret[0..16], spend_secret[16..32], IV=TAG_ADDRESS)
```

**Input:** `spend_secret: SpendSecret` (32 bytes)
**Output:** `address: Address` (32 bytes)

---

#### `compute_auth_tag`

Computes the replay-protection authentication tag.

```
AuthTag = H_AUTH(spend_secret, tx_body_hash)
        = Poseidon2b(spend_secret || tx_body_hash, IV=TAG_AUTHTAG)
```

**Inputs:**
| Field | Type | Description |
|-------|------|-------------|
| `spend_secret` | `[u8; 32]` | Preimage of owner address |
| `tx_body_hash` | `[u8; 32]` | Canonical hash of tx body |

**Output:** `auth_tag: AuthTag` (32 bytes)

**Security:** The auth tag binds the spender's identity to this specific
transaction body, preventing proof replay. Without this binding, a valid
proof for one tx_body could be re-attached to a different tx_body. There
are no signatures in Paranoid — ownership is proven via zero-knowledge
proof of the spend_secret preimage.

---

#### `compute_tx_body_hash`

Computes the canonical transaction body hash (59-perm Poseidon2b Merkle spine).

```
tx_body_hash = MerkleSpine59(
  epoch_anchor,
  fee_leaf,
  input_leaves[0..4],
  output_leaves[0..8],
  is_coinbase_leaf,
  pad_leaf
)
```

**Input:** `TxBody` (full transaction body)
**Output:** `TxBodyHash` (32 bytes)

**Leaf Layout (16 leaves, depth-4 Merkle):**
| Leaf | Content |
|------|---------|
| L0 | `epoch_anchor` (2 field elements) |
| L1 | `fee_leaf = H(fee, 0)` |
| L2-L5 | `input_leaves[0..4]` = `H(slot_index, value, owner_hi, owner_lo)` |
| L6-L13 | `output_leaves[0..8]` = `H(slot_index, value, owner_hi, owner_lo)` |
| L14 | `is_coinbase_leaf = H(is_coinbase as u128, 0)` |
| L15 | `pad_leaf = (0, 0)` |

---

#### `compute_claims_commitment`

Computes the bridge commitment between LogicProof and BlockStateBinding.

```
C_claimed = Poseidon2b_sponge(
    for each input:  slot_index || value || owner_hi || owner_lo
    for each output: slot_index || value || owner_hi || owner_lo
)
```

**Input:** `claimed_slots: Vec<ClaimedSlot>`
**Output:** `claims_commitment: Digest` (32 bytes)

**Security:** This commitment bridges the wallet's LogicProof to the miner's
BlockStateBinding. The LogicProof absorbs C_claimed into its Fiat-Shamir
channel; the BlockStateBinding verifies that opened Merkle values match.
Without this bridge, a wallet could lie about slot values.

---

### 1.2 Slot Discovery

#### `query_free_slots`

Queries the node for available (empty) slot indices for output placement.

**Input:** `count: u32` (number of slots needed)
**Output:** `slots: Vec<u32>` (available slot indices, sorted ascending)

**Node implementation:** Returns from `ChainState.free_slots` min-heap.

**Note:** In the stateless design, the wallet receives ONLY slot indices
(4 bytes each). No Merkle paths are returned. The miner will verify
slot emptiness at block time via BlockStateBinding.

---

#### `query_slot_state`

Queries the current value at a specific state slot.

**Input:** `slot_index: u32`
**Output:**
```
SlotValue {
  value: u64,
  owner_hi: u128,
  owner_lo: u128,
}
```

Returns `(0, 0, 0)` for empty slots.

---

#### `get_epoch_anchor`

Returns the current epoch anchor for transaction construction.

**Output:**
```
EpochAnchorInfo {
  epoch_anchor: [u8; 32],       // H_BLOCK(header[tip_height - ANCHOR_DEPTH])
  anchor_height: u64,           // height of the anchor block
  tip_height: u64,              // current chain tip height
  expires_at_height: u64,       // tip_height + ANCHOR_DEPTH (last valid block)
}
```

**Semantics:** The epoch anchor is the hash of the block header at
`tip_height - ANCHOR_DEPTH` (where ANCHOR_DEPTH = 6). A LogicProof
using this anchor remains valid for approximately 6 minutes (6 blocks
at 60s target).

---

### 1.3 Proof Submission

#### `submit_tx_intent`

Submits a proven TxIntent (LogicProof + claimed data) to the mempool.

**Input:**
```
TxIntent {
  body: TxBody,
  tx_body_hash: TxBodyHash,
  claims_commitment: Digest,
  claimed_slots: Vec<ClaimedSlot>,
  logic_proof: LogicProof,
}
```

**Output:** `Result<TxId, SubmitError>`

**Node behavior on receipt:**
1. Verify LogicProof (~3ms STARK verify)
2. Check epoch_anchor is within ANCHOR_DEPTH window
3. Check tx_body_hash not in nullifier set
4. Native slot verification: claimed values match current state
5. Admit to mempool if all checks pass

---

## 2. Node API

Full nodes maintain chain state, validate TxIntents, serve data, and
maintain the nullifier set.

### 2.1 State Queries

#### `get_state_root`

Returns the current chain state root.

**Output:** `state_root: [u8; 32]` (Poseidon2b FRI-committed Merkle root)

---

#### `get_block_header`

Returns a block header at a given height.

**Input:** `height: u64`
**Output:**
```
BlockHeader {
  prev_block_hash: [u8; 32],
  state_root: [u8; 32],
  tx_root: [u8; 32],
  da_root: [u8; 32],
  timestamp: u64,
  height: u64,
  miner_address: [u8; 32],
  nonce: u128,                       // 128-bit PoW nonce (Blake3)
  difficulty_target: [u8; 32],       // 256-bit ASERT target
  proof_transcript_hash: [u8; 32],
  witness_root: [u8; 32],
  log_slots: u32,                    // consensus-significant (24..=32)
  active_slot_count: u64,            // live UTXOs after this block
  alloc_counter: u64,                // monotonic PRNG seed for allocator
}
```

---

#### `get_chain_info`

Returns current chain parameters.

**Output:**
```
ChainInfo {
  height: u64,
  state_root: [u8; 32],
  log_slots: u32,                   // 24..=32
  active_slot_count: u64,
  alloc_counter: u64,
  tip_block_hash: [u8; 32],
  tip_timestamp: u64,
  epoch_anchor: [u8; 32],           // current valid epoch_anchor
  anchor_height: u64,               // height of the anchor block
}
```

---

### 2.2 Transaction Submission

#### `submit_tx_intent`

Accepts a TxIntent (LogicProof + claimed slots) for mempool inclusion.

**Input:** `TxIntent` (see 1.3)
**Output:** `Result<TxId, SubmitError>`

**Validation steps:**
1. Verify `tx_body_hash` matches canonical re-computation from body
2. Verify `epoch_anchor` is within valid ANCHOR_DEPTH window
3. Verify LogicProof (STARK + SpineGKR + AuthGKR)
4. Verify `claims_commitment` matches hash of `claimed_slots`
5. Check tx_body_hash NOT in nullifier set (anti-double-inclusion)
6. Native slot check: each input slot has claimed (value, owner)
7. Native slot check: each output slot is empty (0, 0, 0)
8. Check no conflicting spends in mempool

---

#### `get_mempool_status`

Returns mempool statistics.

**Output:**
```
MempoolStatus {
  pending_count: u32,
  total_fees: u64,
  oldest_epoch_anchor_height: u64,
}
```

---

### 2.3 Block Queries

#### `get_block`

Returns a full block at a given height.

**Input:** `height: u64`
**Output:**
```
Block {
  header: BlockHeader,
  tx_intents: Vec<TxIntent>,
  block_proof: BlockProof,
}
```

---

#### `get_tx_by_hash`

Looks up a transaction by its body hash.

**Input:** `tx_body_hash: [u8; 32]`
**Output:** `Option<(TxIntent, BlockHeight, TxIndex)>`

---

### 2.4 Nullifier Set

#### `check_nullifier`

Checks whether a tx_body_hash has already been included.

**Input:** `tx_body_hash: [u8; 32]`
**Output:** `bool` (true = already included, reject)

**Implementation:** Rolling window of tx_body_hashes covering the last
ANCHOR_DEPTH blocks. Storage: ~32 bytes * max_txs_per_block * 6 = trivial.
Entries expire automatically when their epoch_anchor window closes.

---

## 3. Prover API

The prover generates cryptographic proofs. In the stateless design,
there are two distinct prover roles:
- **Wallet prover:** Generates LogicProof (balance, range, auth, spine)
- **Miner prover:** Generates BlockStateBinding (Merkle openings)

### 3.1 LogicProof (Wallet-side)

#### `prove_logic`

End-to-end proving of transaction logic. This is the wallet hot path.
Single-transcript: SpineGKR Kill-Shot -> AuthGKR Kill-Shot -> STARK.
Does NOT include any state tree operations.

**Rust signature:**
```rust
pub fn prove_logic(witness: &LogicWitness) -> Result<LogicProof, ProveLogicError>
```

**Input — `LogicWitness`:**
```rust
pub struct LogicWitness<'a> {
    pub air: &'a dyn Air,          // TxLogicAir (no FriStateOpen)
    pub trace: &'a Trace,          // Column witness on hypercube
    pub pi: &'a PublicInputs,      // Public inputs (epoch_anchor, C_claimed, etc.)
    pub spine_inputs: &'a SpineInputs,  // epoch_anchor at L0, tx-body boundary pins
    pub auth_inputs: &'a AuthInputs,    // Spend secrets + expected public outputs
    pub claims_commitment: Digest,      // C_claimed absorbed into FS channel
}
```

**Output — `LogicProof`:**
```rust
pub struct LogicProof {
    pub stark: StarkProof,
    pub spine: SpineProofKillShot,
    pub auth: AuthProofKillShot,
    pub spine_boundary_commitment: FriCommitment,
    pub auth_boundary_commitment: FriCommitment,
}
```

**Pipeline stages (internal):**
1. Validate trace against AIR (`air.check(trace)`)
2. Build + FRI-commit spine boundary MLE (log_len = N_BOUNDARY_VARS = 15)
3. Seed spine Poseidon2bChannel with boundary commitment + C_claimed
4. Run SpineGKR Kill-Shot
5. Build auth boundary MLE (14 vars), zero-pad to 2^15, FRI-commit at log_len = 15
6. Seed auth Poseidon2bChannel with boundary commitment
7. Run AuthGKR Kill-Shot
8. Thread both `(r_B, v_B)` reductions into STARK `extras_transcript`
9. Both boundary MLEs ride as `ExtraColumn`s in STARK mixed-length multipoint close
10. STARK prove: zero-check + FRI over the logic-only AIR

**Measured performance (estimated, stateless design):**
| Metric | Estimated | Notes |
|--------|-----------|-------|
| Total prove | ~300-400 ms | No Merkle path hashing |
| SpineGKR | ~45 ms | 59 Poseidon2b perms (Kill-Shot) |
| AuthGKR | ~55 ms | 20 Poseidon2b perms (Kill-Shot) |
| STARK + FRI-Binius | ~200-300 ms | Reduced AIR (no FriStateOpen cols) |
| Proof size | ~45 KB | Smaller AIR = fewer columns |

---

### 3.2 SpineGKR Kill-Shot

#### `prove_spine_killshot`

Proves 59-perm tx-body Merkle spine via Kill Shot GKR.

**Input:**
```
SpineCircuit         // Static 59-slot topology (compile-time constant)
SpineInputs {
  epoch_anchor: [Block128; 2],       // L0 (replaces prev_state_root)
  fee_leaf: [Block128; 2],
  input_leaves: [[Block128; 4]; 4],
  output_leaves: [[Block128; 4]; 8],
  is_coinbase_leaf: [Block128; 2],
  pad_leaf: [Block128; 2],
}
claimed_tx_body_hash: [Block128; 2]
channel: &mut Poseidon2bChannel     // Fiat-Shamir state
```

**Output:**
```
SpineProofKillShot {
  kill_shot: SpineKillShotProof,    // unified + shift round polys
  state_batch: BatchEvalProof,      // discharge state(r') and state(r'')
  sin_batch: BatchEvalProof,        // discharge s_in(r'')
  sout_batch: BatchEvalProof,       // discharge s_out(r'')
}
SpineKillShotReductions {
  state: BatchEvalReduction { point, value },
  sin: BatchEvalReduction { point, value },
  sout: BatchEvalReduction { point, value },
}
```

**Soundness:** Unified sumcheck over 15-variable hypercube; shift gadget
provides second independent evaluation point; batch-eval collapses all
claims to (r_B, v_B) for STARK bridge.

---

### 3.3 AuthGKR Kill-Shot

#### `prove_auth_killshot`

Proves 20-perm auth sponges (4 inputs x 5 slots) via Kill Shot GKR.
Privacy-preserving: `spend_secret` never enters Fiat-Shamir transcript.

**Input:**
```
AuthCircuit          // Static 20-slot topology
AuthInputs {
  spend_secret: [[Block128; 2]; 4],       // WITNESS ONLY
  tx_body_hash: [Block128; 2],
  expected_address: [[Block128; 2]; 4],   // public pins
  expected_auth_tag: [[Block128; 2]; 4],  // public pins
}
channel: &mut Poseidon2bChannel
```

**Output:**
```
AuthProofKillShot {
  kill_shot: AuthKillShotProof,
  state_batch: BatchEvalProof,
  sin_batch: BatchEvalProof,
  sout_batch: BatchEvalProof,
}
AuthKillShotReductions {
  state: BatchEvalReduction { point, value },
  sin: BatchEvalReduction { point, value },
  sout: BatchEvalReduction { point, value },
}
```

**Privacy guarantee:** The verifier never receives `spend_secret`. Public
boundary (tx_body_hash, expected_address, expected_auth_tag) seeds all
challenges. Address and AuthTag outputs are lifted as public EvalClaims
into the batch-eval sumcheck.

---

### 3.4 STARK Prove (Logic AIR)

#### `prove_air`

Produces the STARK seal over the logic-only AIR trace.

**Input:**
```
air: &dyn Air,                    // TxLogicAir (balance, range, auth gates only)
trace: &Trace,                    // Column witness
pi: &PublicInputs,
```

**Output:** `StarkProof`

**STARK proof contains:**
```
StarkProof {
  log_rows: usize,
  column_commitments: Vec<FriCommitment>,
  base_openings: Vec<Block128>,
  zero_check_rounds: Vec<RoundPoly>,
  shift_partials: Vec<Vec<Block128>>,
  multipoint_rounds: Vec<RoundPoly>,
  multipoint_batch: BatchedEvalProof,
  multipoint_batch_mixed: Option<MixedBatchedEvalProof>,
}
```

---

### 3.5 BlockStateBinding Prove (Miner-side)

#### `prove_block_state_binding`

Generates the block-level Merkle state binding proof. This proves that
all claimed slot values (from all TxIntents in the block) actually exist
in the current state tree.

**Rust signature:**
```rust
pub fn prove_block_state_binding(
    witness: &BlockStateWitness,
) -> Result<BlockStateBindingProof, ProveBlockStateError>
```

**Input — `BlockStateWitness`:**
```rust
pub struct BlockStateWitness<'a> {
    pub prev_state_root: [u8; 32],
    pub new_state_root: [u8; 32],
    pub slot_openings: Vec<SlotOpening>,     // Merkle paths for all touched slots
    pub claimed_slots: Vec<ClaimedSlot>,     // from all TxIntents
    pub claims_commitments: Vec<Digest>,     // C_claimed per tx (bridge check)
    pub coinbase: Option<CoinbaseTx>,
}
```

**Output — `BlockStateBindingProof`:**
```rust
pub struct BlockStateBindingProof {
    pub stark: StarkProof,                   // over BlockStateAir
    pub gamma_rlc_accumulator: Block128,     // gamma-RLC linking all slot checks
}
```

**What it proves:**
1. For every input slot: opens to claimed (value, owner) in prev_state_root
2. For every output slot: opens to EMPTY (0, 0, 0) in prev_state_root
3. Post-state: inputs zeroed, outputs written, new_state_root correct
4. Bridge: C_claimed from each LogicProof matches the opened values
5. Coinbase: valid if present (empty slot, correct reward)

**Performance (estimated, N=100 txs, 8 cores):**
| Metric | Estimated | Notes |
|--------|-----------|-------|
| BlockStateBinding AIR | ~200-400 ms | 1200 slots, gamma-RLC |
| Merkle path hashing | ~100-200 ms | Batched Poseidon2b |
| STARK prove | ~300-500 ms | Over BlockStateAir |

---

### 3.6 STARK + GKR Bridge (internal to `prove_logic`)

The production path (`prove_logic`) integrates both GKR sub-proofs into a
single STARK transcript. The binding mechanism:

1. Spine boundary MLE (2^15 cells) is FRI-committed; its root seeds the
   spine GKR Fiat-Shamir channel.
2. Auth boundary MLE (2^15 cells, zero-padded from 14 vars) is
   FRI-committed; its root seeds the auth GKR channel.
3. Both `(r_B, v_B)` reductions from Kill-Shot batch-eval are absorbed
   into the STARK `extras_transcript` (spine first, auth second).
4. Both boundary MLEs ride as `ExtraColumn`s in the STARK's FRI-Binius
   mixed-length multipoint close.

There is no separate `prove_air_with_spine` / `prove_air_with_auth`
entry point in production. The unified `prove_logic` orchestrator handles
the full pipeline.

---

## 4. Verifier API

Verifiers (nodes, light clients) validate proofs.

### 4.1 LogicProof Verification

#### `verify_logic`

End-to-end verification of a LogicProof.
Replays the single-transcript flow: SpineGKR -> AuthGKR -> STARK.

**Rust signature:**
```rust
pub fn verify_logic(
    air: &dyn Air,
    pi: &PublicInputs,
    spine_inputs: &SpineInputs,
    auth_inputs: &AuthInputs,
    claims_commitment: &Digest,
    proof: &LogicProof,
) -> Result<(), VerifyLogicError>
```

**Error enum:**
```rust
pub enum VerifyLogicError {
    SpineBoundaryLogLen,   // spine commitment has wrong log_len
    AuthBoundaryLogLen,    // auth commitment has wrong log_len
    SpineKillShot,         // SpineGKR Kill-Shot rejected
    AuthKillShot,          // AuthGKR Kill-Shot rejected
    Stark(VerifyError),    // Inner STARK verification failed
    ClaimsCommitment,      // C_claimed mismatch
}
```

**Verification steps:**
1. Recompute C_claimed from claimed_slots, verify match
2. Check `spine_boundary_commitment.log_len == N_BOUNDARY_VARS`
3. Seed spine channel with boundary commitment + C_claimed
4. Verify SpineGKR Kill-Shot
5. Check `auth_boundary_commitment.log_len == N_AUTH_BOUNDARY_VARS`
6. Seed auth channel with boundary commitment, verify AuthGKR Kill-Shot
7. Rebuild `extras_transcript` (spine reduction + auth reduction)
8. Verify STARK with extra columns (both boundary MLEs as ExtraColumns)

**Measured performance (estimated):**
| Metric | Estimated | Notes |
|--------|-----------|-------|
| Total verify | ~3 ms | Mempool admission hot path |
| SpineGKR verify | ~1 ms | Replay sumcheck transcript |
| AuthGKR verify | ~1 ms | Replay sumcheck transcript |
| STARK + FRI verify | ~1 ms | Reduced column count |

---

### 4.2 BlockStateBinding Verification

#### `verify_block_state_binding`

Verifies the miner's state binding proof.

**Rust signature:**
```rust
pub fn verify_block_state_binding(
    prev_state_root: &[u8; 32],
    new_state_root: &[u8; 32],
    claims_commitments: &[Digest],
    proof: &BlockStateBindingProof,
) -> Result<(), VerifyBlockStateError>
```

**Checks:**
1. STARK proof over BlockStateAir verifies
2. gamma-RLC accumulator correctly links all slot openings
3. C_claimed per tx matches opened values (bridge integrity)
4. State transition: prev_state_root -> new_state_root correct

---

### 4.3 Individual Verifiers

#### `verify_spine_killshot`

**Input:** `proof, circuit, inputs, claimed_hash, channel`
**Output:** `Option<SpineKillShotReductions>` (None = reject)

#### `verify_auth_killshot`

**Input:** `proof, circuit, inputs, channel`
**Output:** `Option<AuthKillShotReductions>` (None = reject)

#### `verify_air`

**Input:** `air, pi, proof`
**Output:** `Result<(), VerifyError>`

---

## 5. Block Producer API (Full Node)

The Full Node's block assembly subsystem collects TxIntents, generates
BlockStateBinding, aggregates into BlockProof, and coordinates PoW
(built-in or external miner via Block Template API).

### 5.1 Block Assembly

#### `assemble_block`

Constructs a candidate block from mempool TxIntents.

**Input:**
```
AssembleRequest {
  parent_header: BlockHeader,
  tx_intents: Vec<TxIntent>,         // max BLOCK_MAX_TXS = 1024
  miner_address: Address,
  block_reward: u64,                  // protocol schedule
  timestamp: u64,
}
```

**Output:**
```
CandidateBlock {
  header: BlockHeader,
  tx_intents: Vec<TxIntent>,
  coinbase: CoinbaseTx,
  state_root: [u8; 32],             // after all txs + coinbase applied
  tx_root: [u8; 32],                // Merkle of tx_body_hashes
  da_root: [u8; 32],                // Merkle of DA payload
}
```

**Validation during assembly:**
- No input slot consumed by > 1 tx
- No output slot written by > 1 tx
- Epoch anchor check: all tx_intents use valid epoch_anchors
- Nullifier check: no duplicate tx_body_hashes
- Deterministic tie-break on conflict: `argmin(tx_body_hash)`
- Coinbase tx: first in block, fee=0, n_inputs=0, value=block_reward+sum(fees)

---

#### `compute_tx_root`

Computes the Merkle root over all transaction body hashes.

```
tx_root = PoseidonMerkle([tx_body_hash_0, ..., tx_body_hash_n], IV=COMPRESS)
```

Zero-padded to next power of 2. Empty block returns zero digest.

---

### 5.2 Block Proof Generation

#### `prove_block`

End-to-end block proving: BlockStateBinding + LogicProof aggregation +
single FRI opening.

**Input:**
```
ProveBlockRequest {
  candidate: CandidateBlock,
  state_witness: BlockStateWitness,   // Merkle paths for all touched slots
}
```

**Output:**
```
BlockProof {
  logic_proofs: Vec<LogicProof>,              // from TxIntents (passed through)
  block_state_binding: BlockStateBindingProof, // miner-generated
  aggregated_fri: AggregatedFriProof,         // single FRI opening
  accumulator: Accumulator,                    // IVC fold
}
```

**Pipeline (mining CPU, 8 cores):**
1. Validate all LogicProofs from TxIntents (parallel, ~3ms each)
2. Compute native state transition (zero inputs, fill outputs)
3. Generate BlockStateBinding witness (all Merkle paths)
4. Prove BlockStateBinding AIR (~200-400ms)
5. Aggregate all column commitments for single FRI opening (~300ms)
6. IVC fold all proofs into Accumulator
7. **Total: ~1-2s on 8 cores**

---

#### `seal_block`

Finalizes block by finding PoW nonce.

**Input:**
```
SealRequest {
  candidate: CandidateBlock,
  block_proof: BlockProof,
  difficulty_target: u128,
}
```

**Output:**
```
SealedBlock {
  header: BlockHeader,               // with nonce filled
  block_proof: BlockProof,
  da_payload: DaPayload,
}
```

**Mining pipeline (separation of concerns):**
```
CPU (Full Node):                    GPU/ASIC (Miner):
- Collect TxIntents                 - Receive 248-byte header
- Validate LogicProofs              - Brute-force nonce (Blake3)
- Generate BlockProof (1-3s)        - Return valid nonce
- Form header                       - Cannot modify block content
- Push header to miner              - Cannot steal (coinbase in proof)
```

**Empty block fallback:**
1. T=0: Generate empty template (coinbase only, trivial proof)
2. T=0..3s: Push empty template to ASIC (mines empty block)
3. T=3s: Full template ready. Push new header to ASIC.
4. T=3s..60s: ASIC mines full block.

---

### 5.3 Block Validation

#### `validate_block`

Full block validation for incoming blocks from peers.

**Input:** `SealedBlock`
**Output:** `Result<StateTransition, BlockValidateError>`

**Checks:**
1. PoW valid against difficulty target
2. Every LogicProof verifies (STARK + SpineGKR + AuthGKR)
3. BlockStateBinding proof verifies
4. Bridge check: C_claimed per tx matches BlockStateBinding openings
5. No double-spend (no input slot consumed twice)
6. No double-mint (no output slot written twice)
7. All epoch_anchors within valid window
8. No tx_body_hash in nullifier set
9. Balance holds per tx (sum inputs == sum outputs + fee)
10. All values < 2^64
11. Coinbase: first tx, fee=0, n_inputs=0, value=reward+fees
12. `header.state_root` matches computed final state
13. `header.tx_root` matches computed Merkle root
14. `header.da_root` matches DA payload commitment
15. Block proof (IVC) verifies via `decide()`

---

## 6. Light Client API

Light clients verify the entire chain history with O(1) work.

### 6.1 Sync

#### `sync_light_client`

Downloads and verifies the chain tip.

**Input:**
```
SyncRequest {
  known_height: u64,           // last verified height (0 for fresh)
  known_block_hash: [u8; 32],  // last verified hash
}
```

**Output:**
```
SyncResponse {
  tip_header: BlockHeader,
  block_proof: BlockProof,     // recursive proof covering genesis to tip
  state_root: [u8; 32],
}
```

**Verification:** Verify the recursive STARK proof (~200 ms) plus one
native FRI Merkle check for the tip block (~80 ms). Total ~280 ms
proves the entire chain from genesis to tip. Proof size (~55 KB) is
independent of chain length.

---

#### `verify_inclusion`

Verifies a transaction is included in a specific block.

**Input:**
```
InclusionRequest {
  tx_body_hash: [u8; 32],
  block_height: u64,
  merkle_path: Vec<[u8; 32]>,   // path within tx_root tree
}
```

**Output:** `bool` (true if tx is provably included)

---

### 6.2 SPV Queries

#### `get_slot_proof`

Returns a slot value with Merkle proof against the state root.

**Input:** `slot_index: u32, block_height: u64`
**Output:**
```
SlotProof {
  value: SlotValue,
  merkle_path: Vec<[u8; 32]>,
  state_root: [u8; 32],
}
```

---

### 6.3 Check Verification (Payment Receipts)

#### `verify_check`

Verifies a "check" (payment receipt) for eternal proof of payment.

**Input:**
```
Check {
  version: u8,                    // AIR version for forward-compatibility
  tx_body: TxBody,
  logic_proof: LogicProof,
  inclusion_receipt: InclusionReceipt,
}

InclusionReceipt {
  block_height: u64,
  tx_index: u32,
  merkle_path: Vec<[u8; 32]>,    // tx_body_hash -> tx_root
  block_header: BlockHeader,
}
```

**Output:** `Result<CheckVerified, CheckError>`

**Verification:**
1. Verify logic_proof (STARK). Math is eternal.
2. Verify inclusion: path from tx_body_hash -> tx_root == header.tx_root
3. Verify header is in canonical chain (request from any full node)
4. Version field enables forward-compatible verification after hard forks.

---

## 7. Data Availability API

DA layer for witness data (required for full node state reconstruction
from raw blocks).

### 7.1 Witness Packing

#### `pack_witness`

Packs AIR trace columns into Binius-optimized DA payload.

**Input:** `trace: &Trace`
**Output:**
```
PackedWitness {
  columns: Vec<PackedWitnessColumn>,
  witness_root: [u8; 32],       // Poseidon2b Merkle of packed data
}
```

**Column types (packing ratios):**
| Type | Bits/cell | Pack ratio | Description |
|------|-----------|------------|-------------|
| Bit | 1 | 128x | Boolean columns |
| Byte | 8 | 16x | Range-check witness |
| Block128 | 128 | 1x | Field elements |

---

#### `verify_witness_root`

Verifies witness data matches the `witness_root` in block header.

**Input:** `packed: &PackedWitness, expected_root: [u8; 32]`
**Output:** `bool`

---

### 7.2 DA Payload Structure

```
DaPayload {
  tx_bodies: Vec<TxBody>,              // all tx bodies in block order
  coinbase_address: Address,           // miner's coinbase output
  coinbase_slot: u32,                  // allocated slot for coinbase
}

da_root = PoseidonMerkle(serialize(DaPayload))
```

The `da_root` is committed in the block header. Changing coinbase
(address or slot) changes `da_root` -> changes header -> invalidates
BlockProof -> prevents block theft.

---

## 8. Wire Formats

### 8.1 TxIntent Wire Format (Network Payload)

The network payload MUST NOT contain spend_secret. The prover-side
struct includes it for proof generation, but the broadcast wire format
carries only public data.

```
ClaimedSlot (49 bytes):
  slot_index:    u32  (4 bytes, LE)
  value:         u64  (8 bytes, LE)
  owner_hi:      u128 (16 bytes, LE)
  owner_lo:      u128 (16 bytes, LE)
  is_input:      u8   (1 byte, 0=output, 1=input)

TxInput (network wire, 77 bytes):
  slot_index:    u32  (4 bytes, LE)
  value:         u64  (8 bytes, LE)
  owner:         [u8; 32]
  auth_tag:      [u8; 32]
  valid:         u8   (1 byte, 0 or 1)

  NOTE: spend_secret is NEVER transmitted.

TxOutput (45 bytes):
  slot_index:    u32  (4 bytes, LE)
  value:         u64  (8 bytes, LE)
  owner:         [u8; 32]
  valid:         u8   (1 byte, 0 or 1)

TxBody:
  epoch_anchor:     [u8; 32]
  fee:              u128 (16 bytes, LE)
  n_inputs:         u8
  inputs:           [TxInput; n_inputs]  (padded to MAX_INPUTS=4)
  n_outputs:        u8
  outputs:          [TxOutput; n_outputs] (padded to MAX_OUTPUTS=8)
  is_coinbase:      u8 (0 or 1)

TxIntent (network broadcast):
  body:                TxBody
  tx_body_hash:        [u8; 32]
  claims_commitment:   [u8; 32]
  claimed_slots:       [ClaimedSlot; n_inputs + n_outputs]
  logic_proof:         LogicProof (~45 KB)
```

### 8.2 PublicInputs Wire Format

```
PublicInputs (fixed):
  epoch_anchor:         [u8; 32]
  tx_body_hash:         [u8; 32]
  claims_commitment:    [u8; 32]
  fee:                  u128 (16 bytes, LE)
  n_live_inputs:        u8
  n_live_outputs:       u8
  is_coinbase:          u8
```

### 8.3 Block Header Wire Format

```
BlockHeader (328 bytes):
  prev_block_hash:        [u8; 32]
  state_root:             [u8; 32]   -- Poseidon2b Merkle over segment FRI roots
  tx_root:                [u8; 32]
  da_root:                [u8; 32]
  timestamp:              u64 (8 bytes, LE)
  height:                 u64 (8 bytes, LE)
  miner_address:          [u8; 32]
  nonce:                  u128 (16 bytes, LE) -- 128-bit PoW nonce (Blake3)
  difficulty_target:      [u8; 32]   -- 256-bit ASERT target
  proof_transcript_hash:  [u8; 32]
  witness_root:           [u8; 32]   -- Binius-packed DA witness root
  log_slots:              u32 (4 bytes, LE)
  active_slot_count:      u64 (8 bytes, LE)
  alloc_counter:          u64 (8 bytes, LE)
```

### 8.4 Proof Wire Formats

```
SpineProofKillShot:
  kill_shot.main:   15 rounds x degree-10 x 16 bytes = 2400 B
  kill_shot.shift:  15 rounds x degree-3 x 16 bytes  =  720 B
  main_finals:      12 witness claims x 16 bytes      =  192 B
  shift_finals:     3 witness claims x 16 bytes       =   48 B
  state_batch:      15 rounds x 3 x 16 bytes          =  720 B
  sin_batch:        15 rounds x 3 x 16 bytes          =  720 B
  sout_batch:       15 rounds x 3 x 16 bytes          =  720 B
  TOTAL: ~5.5 KB

AuthProofKillShot:
  kill_shot.main:   14 rounds x degree-10 x 16 bytes = 2240 B
  kill_shot.shift:  14 rounds x degree-3 x 16 bytes  =  672 B
  main_finals:      12 witness claims x 16 bytes      =  192 B
  shift_finals:     3 witness claims x 16 bytes       =   48 B
  state_batch:      14 rounds x 3 x 16 bytes          =  672 B
  sin_batch:        14 rounds x 3 x 16 bytes          =  672 B
  sout_batch:       14 rounds x 3 x 16 bytes          =  672 B
  TOTAL: ~5.2 KB

LogicProof (total, estimated):
  SpineGKR Kill-Shot:                                 =  5.5 KB
  AuthGKR Kill-Shot:                                  =  5.2 KB
  STARK + FRI-Binius (reduced columns):               = ~34 KB
  Metadata + misc:                                    =  ~1 KB
  ─────────────────────────────────────────────────────────────
  TOTAL (estimated): ~45 KB

BlockStateBindingProof:
  STARK over BlockStateAir:                           = ~30-50 KB
  gamma-RLC accumulator:                              =  16 B
  ─────────────────────────────────────────────────────────────
  TOTAL (estimated): ~30-50 KB (depends on touched slot count)

BlockProof (full):
  N x LogicProof:                                     = N * 45 KB
  BlockStateBindingProof:                             = ~40 KB
  Aggregated FRI:                                     = ~10 KB
  IVC Accumulator:                                    = ~5 KB
  ─────────────────────────────────────────────────────────────
  After IVC folding (recursive): ~55 KB (independent of N)
```

---

## 9. Error Codes

### Transaction Errors

| Code | Name | Description |
|------|------|-------------|
| `E001` | `EpochAnchorExpired` | epoch_anchor is older than ANCHOR_DEPTH blocks |
| `E002` | `SlotOutOfRange` | Slot index >= 2^log_slots |
| `E003` | `DuplicateOutputSlot` | Two outputs target same slot |
| `E004` | `OutputSlotNotEmpty` | Output slot already occupied (native check) |
| `E005` | `UnknownOrSpentInput` | Input slot empty or value/owner mismatch |
| `E006` | `BalanceMismatch` | Sum of inputs != sum of outputs + fee |
| `E007` | `ValueOverflow` | Value >= 2^64 |
| `E008` | `InvalidAuthTag` | Auth tag verification failed |
| `E009` | `InvalidAddress` | Address != H_ADDR(spend_secret) |
| `E010` | `NullifierDuplicate` | tx_body_hash already in nullifier set |
| `E011` | `ClaimsCommitmentMismatch` | C_claimed != hash(claimed_slots) |
| `E012` | `EpochAnchorInvalid` | epoch_anchor does not match any known header |

### Proof Errors

| Code | Name | Description |
|------|------|-------------|
| `P001` | `StarkVerifyFailed` | STARK proof rejected |
| `P002` | `SpineGkrFailed` | SpineGKR Kill-Shot rejected |
| `P003` | `AuthGkrFailed` | AuthGKR Kill-Shot rejected |
| `P004` | `BoundaryMismatch` | GKR boundary != STARK public column |
| `P005` | `TranscriptDesync` | Fiat-Shamir replay diverged |
| `P006` | `FriOpeningFailed` | FRI query verification failed |
| `P007` | `PublicInputMismatch` | PI inconsistent with proof |
| `P008` | `BlockStateBridgeMismatch` | C_claimed(LogicProof) != C_claimed(BlockState) |
| `P009` | `BlockStateRootMismatch` | BlockStateBinding state roots incorrect |

### Block Errors

| Code | Name | Description |
|------|------|-------------|
| `B001` | `InvalidPoW` | PoW nonce does not meet target |
| `B002` | `StateRootMismatch` | header.state_root != computed |
| `B003` | `TxRootMismatch` | header.tx_root != computed |
| `B004` | `DoubleSpend` | Same input consumed twice in block |
| `B005` | `DoubleMint` | Same output slot written twice in block |
| `B006` | `TxCountExceeded` | > BLOCK_MAX_TXS (1024) |
| `B007` | `IvcDecideFailed` | Block proof accumulator rejected |
| `B008` | `ChainBreak` | prev_block_hash doesn't link |
| `B009` | `DaRootMismatch` | header.da_root != computed |
| `B010` | `NullifierConflict` | Duplicate tx_body_hash within block |
| `B011` | `EpochAnchorOutOfWindow` | TxIntent uses expired epoch_anchor |
| `B012` | `CoinbaseInvalid` | Coinbase violates rules (not first, wrong value, etc.) |
| `B013` | `BlockWithholdingDetected` | da_root inconsistent with coinbase |

---

## Appendix A: Cryptographic Primitives

### Hash Functions

| Function | IV Tag | Input | Output | Usage |
|----------|--------|-------|--------|-------|
| H_ADDR | TAG_ADDRESS | spend_secret (32B) | Address (32B) | Derive owner address |
| H_AUTH | TAG_AUTHTAG | spend_secret + tx_body_hash | AuthTag (32B) | Replay protection |
| H_BLOCK | BLOCKHDR | header fields | block_hash (32B) | Block identification |
| H_TXBODY | TXBODY | 16-leaf Merkle | tx_body_hash (32B) | Transaction binding |
| H_UTXO | (implicit) | value + owner | commitment (32B) | State slot leaf |
| H_COMPRESS | COMPRESS | left + right digest | digest (32B) | Merkle internal |
| H_FSCHALNG | FSCHALNG | proof bytes | digest (32B) | Proof transcript binding |
| H_CLAIMS | CLAIMS | slot data sponge | C_claimed (32B) | LogicProof<->BlockState bridge |

All use Poseidon2b over GF(2^128) with domain-separated capacity IVs.

### Field Parameters

| Parameter | Value |
|-----------|-------|
| Field | GF(2^128), binary tower |
| S-box | x^7 (degree-7 power map) |
| Rounds | 4 full + 58 partial + 4 full = 66 |
| State width | 4 field elements (512 bits) |
| Capacity | 2 elements (lanes 2-3) |
| Rate | 2 elements (lanes 0-1) |

---

## Appendix B: Constants

| Constant | Value | Description |
|----------|-------|-------------|
| MAX_INPUTS | 4 | Max spending inputs per tx |
| MAX_OUTPUTS | 8 | Max outputs per tx |
| ANCHOR_DEPTH | 6 | Blocks deep for epoch_anchor |
| STATE_LOG_SLOTS | 24 | Mainnet state depth (16.7M slots) |
| MIN_LOG_SLOTS | 24 | Minimum accepted |
| MAX_LOG_SLOTS | 32 | Maximum (4B slots) |
| BLOCK_MAX_TXS | 1024 | Hard cap on txs per block |
| BLOCK_TARGET_TIME | 60 | Target seconds between blocks |
| N_SPINE_PERMS | 59 | Poseidon2b perms in tx-body spine |
| N_AUTH_SLOTS | 20 | Auth sponge slots (4 inputs x 5) |
| N_AUTH_INPUTS | 4 | Auth inputs per transaction |
| SPINE_UNIFIED_VARS | 15 | SpineGKR hypercube dimension |
| AUTH_UNIFIED_VARS | 14 | AuthGKR hypercube dimension |
| FRI_TAU | 7 | FRI folding factor |
| FRI_NUM_QUERIES | 64 | FRI query repetitions (prod) |
| FRI_LOG_RATE | 2 | Reed-Solomon rate = 4 |
| TX_LOGIC_LOG_ROWS | 13 | Logic AIR trace depth (8192 rows) |

---

## Appendix C: Transaction Lifecycle (Stateless Design)

```
Light Node (Wallet)             Full Node                 External Miner (GPU/ASIC)
  |                               |                              |
  |-- get_epoch_anchor ---------->|                              |
  |<- epoch_anchor, heights ------|                              |
  |                               |                              |
  |-- query_free_slots(2) ------->|                              |
  |<- [14352, 16100] (indices) ---|                              |
  |                               |                              |
  |   build TxBody (local)        |                              |
  |   compute tx_body_hash        |                              |
  |   compute C_claimed           |                              |
  |   prove_logic (~300-400ms)    |                              |
  |                               |                              |
  |-- submit_tx_intent ---------->|                              |
  |   (body, hash, C, slots,     |                              |
  |    logic_proof)               |                              |
  |                               |-- verify_logic (~3ms)        |
  |                               |-- check epoch_anchor         |
  |                               |-- check nullifier            |
  |                               |-- native slot verify         |
  |                               |-- admit to mempool           |
  |                               |                              |
  |                               |   assemble_block             |
  |                               |   (collision check, order)   |
  |                               |                              |
  |                               |   prove_block_state_binding  |
  |                               |   (Merkle openings, ~400ms)  |
  |                               |                              |
  |                               |   aggregate + IVC fold       |
  |                               |   (single FRI opening)       |
  |                               |                              |
  |                               |-- push header (248B) ------->|
  |                               |                   nonce search|
  |                               |<-- valid nonce --------------|
  |                               |                              |
  |                               |-- broadcast SealedBlock ---->|
  |                               |                              |
  |                               |-- validate_block             |
  |                               |   (15 checks, ~600ms)       |
  |                               |                              |
  |                               |-- update ChainState          |
  |                               |-- update nullifier set       |
  |                               |                              |
```

**Key difference from old design:** The wallet NEVER receives Merkle paths.
It gets only slot indices (4 bytes). The miner proves state binding at block
time. If a new block arrives while the wallet is proving, the LogicProof
remains valid (epoch_anchor is stable for ~6 minutes).

---

## Appendix D: Security Model

### Threat Model

| Actor | Capability | Mitigation |
|-------|-----------|------------|
| Malicious prover | Forge proof for invalid tx | Soundness: STARK + GKR (Schwartz-Zippel over 2^128) |
| Double-spender | Spend same UTXO twice | BlockStateBinding: second spend sees zeroed slot |
| Replay attacker | Reuse proof for different tx | auth_tag binds proof to specific tx_body_hash |
| Double-inclusion | Include same tx twice | Nullifier set (rolling window of tx_body_hashes) |
| Address forger | Claim ownership without secret | H_ADDR is one-way (Poseidon2b preimage) |
| Slot value liar | Lie about input/output values | C_claimed bridge: LogicProof claims must match BlockStateBinding openings |
| Fork replay | Replay tx on different fork | epoch_anchor differs per fork (hash of fork-specific block) |
| Miner censor | Exclude valid transactions | PoW decentralization (no execution = fast blocks) |
| Block thief | Steal found block | Coinbase locked in BlockProof via da_root -> header binding |
| State corruptor | Tamper with state | FRI-committed state root in every block header |
| DoS spam | Flood invalid LogicProofs | Verify costs ~3ms; rate-limit at P2P layer |
| Epoch grinder | Manipulate epoch_anchor | Anchor is 6 blocks deep, determined by history |

### Soundness Parameters

| Component | Security (bits) | Basis |
|-----------|----------------|-------|
| STARK zero-check | ~122 | Schwartz-Zippel: 13 rounds x degree-4 / 2^128 |
| FRI proximity | 128 | 64 queries x log2(rate=4) = 64 x 2 bits |
| SpineGKR | ~121 | Degree-9 unified sumcheck, 15 rounds: 135/2^128 |
| AuthGKR | ~121 | Degree-9 unified sumcheck, 14 rounds: 126/2^128 |
| Poseidon2b (collision) | 128 | Birthday bound on 256-bit capacity |
| Fiat-Shamir | 128 | Poseidon2b sponge in QROM |
| IVC fold | ~128 | Schwartz-Zippel in mixing scalar alpha |
| C_claimed bridge | 128 | Poseidon2b sponge binding (preimage resistance) |
| **System total** | **~120** | **min(all components); bottleneck = GKR sumcheck** |
