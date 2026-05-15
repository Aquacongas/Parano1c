# Paranoid Production API Specification

Version: 1.0.0-phase1
Last Updated: 2026-05-14

## Overview

This document specifies the production APIs consumed by wallets, full nodes,
miners, and light clients on the Paranoid mainnet. All APIs operate over the
Paranoid binary tower field GF(2^128) with Poseidon2b hash commitments.

---

## Table of Contents

1. [Wallet API](#1-wallet-api)
2. [Node API](#2-node-api)
3. [Prover API](#3-prover-api)
4. [Verifier API](#4-verifier-api)
5. [Block Producer (Miner) API](#5-block-producer-miner-api)
6. [Light Client API](#6-light-client-api)
7. [Data Availability API](#7-data-availability-api)
8. [Wire Formats](#8-wire-formats)
9. [Error Codes](#9-error-codes)

---

## 1. Wallet API

The wallet constructs transactions, derives cryptographic material, and
submits proven state transitions to the network.

### 1.1 Transaction Construction

#### `create_transaction`

Constructs a `TxBody` from semantic user intent.

**Inputs:**
| Field | Type | Description |
|-------|------|-------------|
| `inputs` | `[TxInput; 0..4]` | UTXOs to spend |
| `outputs` | `[TxOutput; 0..8]` | New UTXOs to create |
| `fee` | `u64` | Transaction fee (lamports) |
| `prev_state_root` | `[u8; 32]` | Current chain state root |

**Output:** `Transaction { body: TxBody, tx_body_hash: TxBodyHash }`

**Semantics:**
- Wallet derives `spend_secret` from local keystore for each input
- Wallet computes `auth_tag[i] = H_AUTH(spend_secret[i], tx_body_hash)` per input
- Wallet picks `output.slot_index` for each output (must target empty slots)
- `tx_body_hash` = canonical 16-leaf Poseidon2b Merkle of body fields
- Dummy inputs/outputs padded with `valid = false` up to MAX bounds

**Constraints:**
- `sum(inputs.value) == sum(outputs.value) + fee`
- All values < 2^64
- No duplicate output slot indices
- Each output slot must be empty in current state

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
transaction body, preventing signature replay.

---

#### `compute_tx_body_hash`

Computes the canonical transaction body hash (59-perm Poseidon2b Merkle spine).

```
tx_body_hash = MerkleSpine59(
  prev_state_root,
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
| L0 | `prev_state_root` (2 field elements) |
| L1 | `fee_leaf = H(fee, 0)` |
| L2-L5 | `input_leaves[0..4]` = `H(slot_index, value, owner_hi, owner_lo)` |
| L6-L13 | `output_leaves[0..8]` = `H(slot_index, value, owner_hi, owner_lo)` |
| L14 | `is_coinbase_leaf = H(is_coinbase as u128, 0)` |
| L15 | `pad_leaf = (0, 0)` |

---

### 1.2 Slot Discovery

#### `query_free_slots`

Queries the node for available (empty) slot indices for output placement.

**Input:** `count: u32` (number of slots needed)
**Output:** `slots: Vec<u32>` (available slot indices, sorted ascending)

**Node implementation:** Returns from `ChainState.free_slots` min-heap.

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

### 1.3 Proof Request

#### `submit_proven_transaction`

Submits a fully proven transaction to the mempool.

**Input:**
```
ProvenTransaction {
  body: TxBody,
  tx_body_hash: TxBodyHash,
  public_inputs: PublicInputs,
  spine_inputs: SpineInputs,
  auth_inputs: AuthInputs,           // spend_secret zeroed (verifier doesn't need it)
  proof: TxProof,                    // stark + spine + auth + boundary commitments
}
```

**Output:** `TxId` (32-byte hash of tx_body_hash)

**Node behavior:** Verifies all three proofs, validates state transition,
admits to mempool if valid.

---

## 2. Node API

Full nodes maintain chain state, validate transactions, and serve data.

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
  timestamp: u64,
  miner_address: [u8; 32],
  nonce: u64,
  proof_transcript_hash: [u8; 32],
  witness_root: [u8; 32],
}
```

---

#### `get_slot_opening`

Returns a Merkle opening proof for a specific state slot.

**Input:** `slot_index: u32`
**Output:**
```
SlotOpening {
  value: SlotValue,
  column_openings: [SlotColumnOpening; 3],  // value, owner_hi, owner_lo
}
```

Each `SlotColumnOpening` contains the FRI evaluation proof at the
slot's hypercube point, used by the prover to build the in-circuit
FRI state opening witness.

---

#### `get_chain_info`

Returns current chain parameters.

**Output:**
```
ChainInfo {
  height: u64,
  state_root: [u8; 32],
  log_slots: u8,                    // 24..=32
  active_slot_count: u64,
  tip_block_hash: [u8; 32],
  tip_timestamp: u64,
}
```

---

### 2.2 Transaction Submission

#### `submit_transaction`

Accepts a proven transaction for mempool inclusion.

**Input:** `ProvenTransaction` (see 1.3)
**Output:** `Result<TxId, SubmitError>`

**Validation steps:**
1. Verify `tx_body_hash` matches canonical re-computation
2. Verify `prev_state_root` matches current tip (or mempool fork)
3. Verify STARK proof against PublicInputs
4. Verify SpineGKR Kill-Shot proof
5. Verify AuthGKR Kill-Shot proof
6. Apply state transition natively to confirm `new_state_root`
7. Check no conflicting spends in mempool

---

#### `get_mempool_status`

Returns mempool statistics.

**Output:**
```
MempoolStatus {
  pending_count: u32,
  total_fees: u64,
  oldest_timestamp: u64,
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
  transactions: Vec<ProvenTransaction>,
}
```

---

#### `get_tx_by_hash`

Looks up a transaction by its body hash.

**Input:** `tx_body_hash: [u8; 32]`
**Output:** `Option<(ProvenTransaction, BlockHeight, TxIndex)>`

---

## 3. Prover API

The prover generates cryptographic proofs for transactions. Runs
client-side (wallet) or as a prover service.

### 3.1 Full Transaction Proof

#### `prove_tx`

End-to-end proving of a validated transaction. This is the mainnet hot path.
Single-transcript: SpineGKR Kill-Shot -> AuthGKR Kill-Shot -> STARK.

**Rust signature:**
```rust
pub fn prove_tx(witness: &TxWitness) -> Result<TxProof, ProveTxError>
```

**Input — `TxWitness`:**
```rust
pub struct TxWitness<'a> {
    pub air: &'a dyn Air,          // TxValidityCompositeWithSpine
    pub trace: &'a Trace,          // Column witness on hypercube
    pub pi: &'a PublicInputs,      // Public inputs for this transaction
    pub spine_inputs: &'a SpineInputs,  // Derived from tx-body boundary pins
    pub auth_inputs: &'a AuthInputs,    // Spend secrets + expected public outputs
}
```

**Output — `TxProof`:**
```rust
pub struct TxProof {
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
3. Seed spine Poseidon2bChannel with boundary commitment, run SpineGKR Kill-Shot
4. Build auth boundary MLE (14 vars), zero-pad to 2^15, FRI-commit at log_len = 15
5. Seed auth Poseidon2bChannel with boundary commitment, run AuthGKR Kill-Shot
6. Thread both `(r_B, v_B)` reductions into STARK `extras_transcript` (spine first, auth second)
7. Both boundary MLEs ride as `ExtraColumn`s in the STARK mixed-length multipoint close
8. STARK prove: zero-check + FRI over the skinny AIR

**Performance targets (Phase 1):**
| Metric | Target | Notes |
|--------|--------|-------|
| Total prove | < 300 ms | Client-side, single thread |
| SpineGKR | <= 50 ms | 59 Poseidon2b perms |
| AuthGKR | <= 60 ms | 20 Poseidon2b perms |
| STARK | remainder | Balance + Range + State opening |

---

### 3.2 SpineGKR Kill-Shot

#### `prove_spine_killshot`

Proves 59-perm tx-body Merkle spine via Kill Shot GKR.

**Input:**
```
SpineCircuit         // Static 59-slot topology (compile-time constant)
SpineInputs {
  prev_state_root: [Block128; 2],
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

### 3.4 STARK Prove

#### `prove_air`

Produces the STARK seal over the AIR trace.

**Input:**
```
air: &dyn Air,                    // TxValidityCompositeWithSpine
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

### 3.5 STARK + GKR Bridge

#### `prove_air_with_spine`

STARK proof with SpineGKR boundary commitment integrated.

**Input:** `air, trace, pi, spine_inputs`
**Output:** `StarkProofWithSpine { stark, spine, boundary_commitment }`

The boundary commitment (FRI of the spine's unified MLE at log_len=15)
seeds the GKR Poseidon2b channel, and the reduction (r_B, v_B) is
absorbed into the STARK's extras-transcript, binding GKR to STARK.

---

#### `prove_air_with_auth`

STARK proof with AuthGKR boundary commitment integrated.

**Input:** `air, trace, pi, auth_inputs`
**Output:** `StarkProofWithAuth { stark, auth, boundary_commitment }`

Same binding mechanism as spine bridge.

---

## 4. Verifier API

Verifiers (nodes, light clients) validate proofs.

### 4.1 Full Transaction Verification

#### `verify_tx`

End-to-end verification of a proven transaction.
Replays the single-transcript flow: SpineGKR -> AuthGKR -> STARK.

**Rust signature:**
```rust
pub fn verify_tx(
    air: &dyn Air,
    pi: &PublicInputs,
    spine_inputs: &SpineInputs,
    auth_inputs: &AuthInputs,
    proof: &TxProof,
) -> Result<(), VerifyTxError>
```

**Error enum:**
```rust
pub enum VerifyTxError {
    SpineBoundaryLogLen,   // spine commitment has wrong log_len
    AuthBoundaryLogLen,    // auth commitment has wrong log_len
    SpineKillShot,         // SpineGKR Kill-Shot rejected
    AuthKillShot,          // AuthGKR Kill-Shot rejected
    Stark(VerifyError),    // Inner STARK verification failed
}
```

**Verification steps:**
1. Check `spine_boundary_commitment.log_len == N_BOUNDARY_VARS`
2. Seed spine channel with boundary commitment, verify SpineGKR Kill-Shot
3. Check `auth_boundary_commitment.log_len == N_AUTH_BOUNDARY_VARS`
4. Seed auth channel with boundary commitment, verify AuthGKR Kill-Shot
5. Rebuild `extras_transcript` (spine reduction + auth reduction)
6. Verify STARK with extra columns (both boundary MLEs as ExtraColumns)

**Performance targets (Phase 1):**
| Metric | Target | Notes |
|--------|--------|-------|
| Total verify | < 30 ms | Single thread |
| SpineGKR verify | <= 2 ms | Replay sumcheck transcript |
| AuthGKR verify | <= 25 ms | Replay sumcheck transcript |
| STARK verify | remainder | FRI query verification |

---

### 4.2 Individual Verifiers

#### `verify_spine_killshot`

**Input:** `proof, circuit, inputs, claimed_hash, channel`
**Output:** `Option<SpineKillShotReductions>` (None = reject)

#### `verify_auth_killshot`

**Input:** `proof, circuit, inputs, channel`
**Output:** `Option<AuthKillShotReductions>` (None = reject)

#### `verify_air`

**Input:** `air, pi, proof`
**Output:** `Result<(), VerifyError>`

#### `verify_air_with_spine`

**Input:** `air, pi, spine_inputs, proof`
**Output:** `Result<(), VerifyError>`

#### `verify_air_with_auth`

**Input:** `air, pi, auth_inputs, proof`
**Output:** `Result<(), VerifyError>`

---

## 5. Block Producer (Miner) API

Miners aggregate proven transactions into blocks.

### 5.1 Block Assembly

#### `assemble_block`

Constructs a candidate block from mempool transactions.

**Input:**
```
AssembleRequest {
  parent_header: BlockHeader,
  transactions: Vec<ProvenTransaction>,   // max BLOCK_MAX_TXS = 1024
  miner_address: Address,
  coinbase_credit: u64,                    // block_reward + sum(fees)
  timestamp: u64,
}
```

**Output:**
```
CandidateBlock {
  header: BlockHeader,                    // proof_transcript_hash TBD
  transactions: Vec<ProvenTransaction>,
  state_root: [u8; 32],                  // after all txs applied
  tx_root: [u8; 32],                     // Merkle of tx_body_hashes
}
```

**Validation during assembly:**
- Sequential state root chaining: `tx[i].prev_root == post_root[i-1]`
- No input slot consumed by > 1 tx
- No output slot minted by > 1 tx
- Deterministic tie-break on conflict: `argmin(tx_body_hash)`
- Coinbase tx (if present) must be first, with `fee=0, n_inputs=0`

---

#### `compute_tx_root`

Computes the Merkle root over all transaction body hashes.

```
tx_root = PoseidonMerkle([tx_body_hash_0, ..., tx_body_hash_n], IV=COMPRESS)
```

Zero-padded to next power of 2. Empty block returns zero digest.

---

### 5.2 Block Proof (IVC Accumulation)

#### `fold_block_proofs`

Accumulates per-tx proofs into a single block proof via IVC.

**Input:**
```
FoldRequest {
  per_tx_proofs: Vec<TxProof>,
  accumulator: Option<Accumulator>,     // None for first block
}
```

**Output:**
```
Accumulator {
  log_len: usize,
  z: Vec<Block128>,                     // shared opening point
  y_acc: Block128,                      // running sum
  column_commitments: Vec<FriCommitment>,
  per_step_openings: Vec<Block128>,
  per_step_proofs: Vec<EvalProof>,
  step_count: usize,
}
```

**Semantics:**
- Each tx proof's consensus-significant column is folded
- Mixing scalar `alpha_k` derived from Fiat-Shamir (bound to history)
- Update: `y_acc <- y_acc + alpha_k * opening_k` (XOR in char-2)
- Single `decide()` call validates all accumulated proofs

---

#### `seal_block`

Finalizes block with PoW and proof transcript.

**Input:**
```
SealRequest {
  candidate: CandidateBlock,
  block_proof: Accumulator,
  difficulty_target: u128,
}
```

**Output:**
```
Block {
  header: BlockHeader,      // with proof_transcript_hash + nonce filled
  transactions: Vec<ProvenTransaction>,
}
```

---

### 5.3 Block Validation

#### `validate_block`

Full block validation for incoming blocks from peers.

**Input:** `Block`
**Output:** `Result<StateTransition, BlockValidateError>`

**Checks:**
1. Every tx proof verifies (STARK + SpineGKR + AuthGKR)
2. State root chain is valid (sequential prev/new roots)
3. No double-spend (no input slot consumed twice)
4. No double-mint (no output slot written twice)
5. Balance holds per tx
6. All values < 2^64
7. Output slots were empty pre-tx
8. `is_activation`/`is_deactivation` match active_slot_count delta
9. `log_slots` increment iff 7-day occupancy > 90%
10. Block proof (IVC) verifies via `decide()`
11. PoW valid against difficulty target
12. `header.state_root` matches final post-root
13. `header.tx_root` matches computed Merkle root

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
  block_proof: Accumulator,    // single recursive proof from genesis
  state_root: [u8; 32],
}
```

**Verification:** Call `decide()` on the received `Accumulator`. One
FRI verification proves the entire chain from genesis to tip. Proof
size is independent of chain length.

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

## 7. Data Availability API

DA layer for witness data (optional for consensus; required for
full node state reconstruction from raw blocks).

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

## 8. Wire Formats

### 8.1 Transaction Wire Format

```
TxInput (109 bytes):
  slot_index:    u32  (4 bytes, LE)
  value:         u64  (8 bytes, LE)
  owner:         [u8; 32]
  spend_secret:  [u8; 32]
  auth_tag:      [u8; 32]
  valid:         u8   (1 byte, 0 or 1)

TxOutput (45 bytes):
  slot_index:    u32  (4 bytes, LE)
  value:         u64  (8 bytes, LE)
  owner:         [u8; 32]
  valid:         u8   (1 byte, 0 or 1)

TxBody:
  prev_state_root:  [u8; 32]
  new_state_root:   [u8; 32]
  fee:              u128 (16 bytes, LE)
  n_inputs:         u8
  inputs:           [TxInput; n_inputs]  (padded to MAX_INPUTS=4)
  n_outputs:        u8
  outputs:          [TxOutput; n_outputs] (padded to MAX_OUTPUTS=8)
  is_coinbase:      u8 (0 or 1)

Transaction:
  body:             TxBody
  tx_body_hash:     [u8; 32]
```

### 8.2 PublicInputs Wire Format

```
PublicInputs (variable, ~154 bytes):
  prev_state_root:    [u8; 32]
  new_state_root:     [u8; 32]
  tx_body_hash:       [u8; 32]
  fee:                u64 (8 bytes, LE)
  n_live_inputs:      u8
  n_live_outputs:     u8
  coinbase_credit:    u64 (8 bytes, LE)
  log_slots:          u8
  is_activation:      [u8; MAX_OUTPUTS]   (8 booleans)
  is_deactivation:    [u8; MAX_INPUTS]    (4 booleans)
```

### 8.3 Block Header Wire Format

```
BlockHeader (228 bytes):
  prev_block_hash:        [u8; 32]
  state_root:             [u8; 32]
  tx_root:                [u8; 32]
  timestamp:              u64 (8 bytes, LE)
  miner_address:          [u8; 32]
  nonce:                  u64 (8 bytes, LE)
  proof_transcript_hash:  [u8; 32]
  witness_root:           [u8; 32]
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

StarkProof (estimated for log_rows=13, 291 cols, 75 shifted, NUM_QUERIES=64):
  column_roots:     291 x 32 bytes                    =  9.3 KB
  base_openings:    291 x 16 bytes                    =  4.7 KB
  zero_check:       13 rounds x 5 x 16 bytes          =  1.0 KB
  shift_partials:   75 x 14 x 16 bytes                = 16.8 KB
  multipoint:       15 rounds x 3 x 16 bytes (n_max=15) =  0.7 KB
  mixed FRI (2 groups, 64 queries each, TAU=7):
    group log_len=13 (291 base cols):        64*(27*32 + 12*16) + 2.5 KB =  69 KB
    group log_len=15 (spine + auth padded):  64*(44*32 + 16*16) + 2.7 KB = 107 KB
    column_openings (293 x 16) + group metadata                          =   8 KB
  TOTAL: ~213 KB (estimated)
```

---

## 9. Error Codes

### Transaction Errors

| Code | Name | Description |
|------|------|-------------|
| `E001` | `StaleState` | `prev_state_root` does not match current tip |
| `E002` | `SlotOutOfRange` | Slot index >= 2^log_slots |
| `E003` | `DuplicateOutputSlot` | Two outputs target same slot |
| `E004` | `OutputSlotNotEmpty` | Output slot already occupied |
| `E005` | `UnknownOrSpentInput` | Input slot empty or value/owner mismatch |
| `E006` | `BalanceMismatch` | Sum of inputs != sum of outputs + fee |
| `E007` | `ValueOverflow` | Value >= 2^64 |
| `E008` | `InvalidAuthTag` | Auth tag verification failed |
| `E009` | `InvalidAddress` | Address != H_ADDR(spend_secret) |

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
| STATE_LOG_SLOTS | 24 | Mainnet state depth (16.7M slots) |
| MIN_LOG_SLOTS | 24 | Minimum accepted |
| MAX_LOG_SLOTS | 32 | Maximum (4B slots) |
| BLOCK_MAX_TXS | 1024 | Hard cap on txs per block |
| N_SPINE_PERMS | 59 | Poseidon2b perms in tx-body spine |
| N_AUTH_SLOTS | 20 | Auth sponge slots (4 inputs x 5) |
| N_AUTH_INPUTS | 4 | Auth inputs per transaction |
| SPINE_UNIFIED_VARS | 15 | SpineGKR hypercube dimension |
| AUTH_UNIFIED_VARS | 14 | AuthGKR hypercube dimension |
| FRI_TAU | 7 | FRI folding factor |
| FRI_NUM_QUERIES | 64 | FRI query repetitions (prod) |
| FRI_LOG_RATE | 2 | Reed-Solomon rate = 4 |
| TX_VALIDITY_LOG_ROWS | 13 | AIR trace depth (8192 rows) |

---

## Appendix C: Transaction Lifecycle

```
Wallet                          Node                           Miner
  |                               |                              |
  |-- create_transaction -------->|                              |
  |   (TxBody + auth material)   |                              |
  |                               |                              |
  |-- prove_transaction --------->|                              |
  |   (local prover runs)        |                              |
  |                               |                              |
  |-- submit_proven_tx ---------->|                              |
  |                               |-- validate (verify proofs)   |
  |                               |-- admit to mempool           |
  |                               |                              |
  |                               |-- get_mempool_txs ---------->|
  |                               |                              |
  |                               |   assemble_block             |
  |                               |   (order, resolve conflicts) |
  |                               |                              |
  |                               |   fold_block_proofs          |
  |                               |   (IVC accumulation)         |
  |                               |                              |
  |                               |   seal_block (PoW)           |
  |                               |                              |
  |                               |<-- broadcast Block --------->|
  |                               |                              |
  |                               |-- validate_block             |
  |                               |   (full verification)        |
  |                               |                              |
  |                               |-- update ChainState          |
  |                               |                              |
```

---

## Appendix D: Security Model

### Threat Model

| Actor | Capability | Mitigation |
|-------|-----------|------------|
| Malicious prover | Forge proof for invalid tx | Soundness: STARK + GKR (Schwartz-Zippel over 2^128) |
| Double-spender | Spend same UTXO twice | Slot-based state: input must be non-empty |
| Replay attacker | Reuse old auth_tag | auth_tag binds to specific tx_body_hash |
| Address forger | Claim ownership without secret | H_ADDR is one-way (Poseidon2b preimage) |
| Miner censor | Exclude valid transactions | PoW decentralization (no execution = fast blocks) |
| State corruptor | Tamper with state between txs | FRI-committed state root in every block header |

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
| **System total** | **~120** | **min(all components); bottleneck = GKR sumcheck** |
