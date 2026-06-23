# PARANOID: System Protocol

## Abstract

Paranoid is a UTXO-based statechain where every user-transaction block carries a validity proof. Nodes verify proof objects instead of re-executing wallet logic. The entire chain history compresses into a single ~43 KB encoded recursive STARK, verifiable in a few milliseconds.

This document specifies the complete protocol: all layers, their interfaces, and the data flow from wallet to finalized block.

---

## 1. Layer Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Layer 5: Chain (Recursive STARK)                                       │
│  Folds all block proofs into one O(1) proof. Verifies full history.     │
├─────────────────────────────────────────────────────────────────────────┤
│  Layer 4: Consensus (PoW + Fork Choice)                                 │
│  Blake3 PoW, ASERT difficulty, fork choice by cumulative chainwork.      │
├─────────────────────────────────────────────────────────────────────────┤
│  Layer 3: Block (Aggregation + State Binding)                           │
│  Shape-specific tx buckets, source-bound FRI, canonical BlockProof.      │
│  NativeDelta binds block state transitions to pre/post segment MLEs.      │
├─────────────────────────────────────────────────────────────────────────┤
│  Layer 2: Transaction (LogicProof)                                      │
│  Per-tx: FROST-GKR Kill-Shot (Spine + Auth) + TxLogicAir STARK.         │
│  Stateless. Produced by wallet. Valid until epoch_anchor expires.         │
├─────────────────────────────────────────────────────────────────────────┤
│  Layer 1: State (Segmented FRI)                                         │
│  Flat UTXO slot array. Poseidon2b Merkle root. Segments of 2^16 slots.  │
├─────────────────────────────────────────────────────────────────────────┤
│  Layer 0: Field Arithmetic (Binary Tower GF(2^128))                     │
│  All cryptography operates in the same field. No extension mismatches.   │
└─────────────────────────────────────────────────────────────────────────┘
```

**Design principle:** Every layer produces a commitment that the layer above consumes as a public input. No layer trusts any other layer; security reduces to the field arithmetic and the Fiat-Shamir random oracle.

---

## 2. Layer 0: Field Arithmetic

### 2.1 Binary Tower GF(2^128)

All cryptographic operations use the binary tower:

```
GF(2) ⊂ GF(2^8) ⊂ GF(2^16) ⊂ GF(2^32) ⊂ GF(2^64) ⊂ GF(2^128)
```

Each extension is quadratic: `F_{2K} = F_K[X] / (X^2 + X + τ_K)` where `τ_K` is a fixed irreducible element in `F_K`. Addition is XOR. Multiplication uses Karatsuba at each tower level.

**Three load-bearing properties:**

1. **Frobenius endomorphism.** Squaring `x ↦ x^2` is GF(2)-linear (bit-shuffle, zero cost). This makes `x^7 = x · x^2 · x^4` require only 2 field multiplications after the two free squarings.

2. **Single field everywhere.** FRI, sumcheck, Poseidon2b, GKR, and all AIR constraints operate in the same GF(2^128). No field-switching, no extension towers at proof time.

3. **SIMD parallelism.** Tower elements pack naturally into 128-bit registers (CLMUL on x86, PMULL on ARM).

### 2.2 Implementation: `noid_core`

| Module | Role |
|--------|------|
| `tower/` | Type hierarchy: `Bit`, `Block8`, ..., `Block128` with full arithmetic |
| `field.rs` | `TowerField` trait: `ZERO`, `ONE`, `invert()`, `from_uniform_bytes()` |
| `packed/` | SIMD-vectorized operations: `karatsuba`, `pow7`, `square`, `mul_table` |
| `ntt.rs` | Number-theoretic transform for RS encoding |
| `mle/` | Multilinear extension: `eq`, `evaluate`, `fold`, `split` |
| `sumcheck/` | Generic sumcheck prover/verifier (configurable degree) |

---

## 3. Layer 1: State Model

### 3.1 UTXO Slot Array

The state is a flat array of `2^log_slots` slots (genesis: `2^24 = 16,777,216`; max: `2^32`):

```
Slot = {
    value:    Block128   (16 bytes)  -- amount in μNOID
    owner_hi: Block128   (16 bytes)  -- owner address bits [128..255]
    owner_lo: Block128   (16 bytes)  -- owner address bits [0..127]
}
```

Empty slots are `(0, 0, 0)`. Spent slots become empty and are recycled by the allocator (deterministic PRNG from `alloc_counter`).

### 3.2 Segmentation

- Segment size: `2^16 = 65,536` slots (~3 MB materialized)
- Segments with no live slots are virtual zero (no RAM, no disk)
- State root = Poseidon2b Merkle tree over per-segment FRI roots

### 3.3 Expansion

Triggered when `median(active_slot_count, last 18 blocks) >= 75% * capacity`:

1. Double `num_segments` by appending virtual-zero upper half
2. New root = `compress(old_root, precomputed_zero_subtree_root)`
3. O(1) computation. No data migration.

### 3.4 State Root Binding

The state root appears in the block header (`offset 32, 32 bytes`). It commits the node to the exact UTXO state after applying all transactions in the block. Any inconsistency between the committed root and the actual state transition is detected by NativeDelta state verification: verifier-reconstructed per-segment claims, the random-point delta identity, and source-bound pre/post segment MLE openings under the parent and new state roots.

---

## 4. Layer 2: Transaction Proof

A transaction proof is **stateless**: produced by the wallet without knowledge of the current chain state. It proves ownership and balance conservation. State binding happens at Layer 3.

### 4.1 Transaction Structure

```
TxIntent = {
    shape:         TxShape        -- Standard4x8 or Sweep25x2
    epoch_anchor:  [u8; 32]      -- recent block hash within ANCHOR_DEPTH window
    fee:           u64           -- fee in μNOID
    inputs:        [TxInput; shape max]
    outputs:       [TxOutput; shape max]
    is_coinbase:   bool
    logic_proof:   LogicProof    -- shape-specific validity proof bundle
}

TxInput = {
    slot_index:  u32
    value:       u64
    owner:       [u8; 32]       -- public: H_ADDR(spend_secret)
    auth_tag:    [u8; 32]       -- public: H_AUTH(spend_secret, tx_body_hash)
}

TxOutput = {
    slot_index:  u32
    value:       u64
    owner:       [u8; 32]       -- recipient address
}
```

### 4.2 tx_body_hash

The transaction body hash is deterministic from public data only:

```
tx_body_hash = ShapeSpineMerkle(
    epoch_anchor,
    fee_leaf,
    shape_leaf,
    input_leaves[0..shape_max_inputs],
    output_leaves[0..shape_max_outputs],
    is_coinbase_leaf,
    pad_leaf
)
```

`Standard4x8` uses the 16-leaf / 59-permutation spine. `Sweep25x2` uses its distinct wider 32-leaf body layout and sweep spine. The shape leaf is part of the hash, so a proof for one shape cannot be replayed as another shape.

### 4.3 Ownership Authentication

For each input `i`:

```
Address[i]  = H_ADDR(spend_secret[i])   = Poseidon2b sponge with TAG_ADDR IV
AuthTag[i]  = H_AUTH(spend_secret[i], tx_body_hash) = Poseidon2b sponge with TAG_AUTH IV
```

Standard auth uses 5 permutations per input, 20 slots total. `Sweep25x2` widens the same ownership relation to 25 inputs / 125 auth permutation slots. The FROST-GKR Auth Kill-Shot proves all auth slots for the selected shape simultaneously.

**Privacy:** `spend_secret` never enters the Fiat-Shamir transcript. Only `(tx_body_hash, Address[], AuthTag[])` are absorbed. The proof reveals MLE evaluations of the execution trace at random points, not raw secret values.

### 4.4 TxLogicAir STARK

After GKR proves the hash computations, `TxLogicAir` proves:

| Constraint | What it proves | Max degree |
|------------|---------------|------------|
| Balance conservation | `Σ inputs.value == Σ outputs.value + fee` | 4 (carry-ripple adder) |
| Range bounds | All values fit in 64 bits | 2 (bit decomposition) |
| tx_body_hash pin | GKR spine output matches STARK public column | 1 (equality) |
| Address/AuthTag pins | GKR auth outputs match STARK public columns | 1 (equality) |

Zero-check: 11 rounds, degree-5 round polynomial. Soundness: `55/2^128`.

### 4.5 Proof Composition (Single Transcript)

All components share one `Poseidon2bChannel`:

```
1. Spine Kill-Shot (unified + shift + 3× batch-eval)
2. Auth Kill-Shot (unified + shift + 3× batch-eval)
3. STARK prover:
   a. Commit columns → absorb cap
   b. extra_transcript = [spine_ks_bytes || auth_ks_bytes]  ← GKR binding
   c. Zero-check draw
   d. FRI opening (all columns + boundary MLEs)
```

The `extra_transcript` hook binds GKR proofs to the STARK: any byte-level tamper forks all downstream challenges (`z`, `β`, `γ`, FRI queries).

---

## 5. Layer 3: Block Aggregation

### 5.1 Bucket Interleaved Commitment

All same-shape transaction traces inside one non-empty block bucket share one per-bucket `InterleavedCommitment`: one Merkle cap covers all columns of that bucket. Standard and `Sweep25x2` transactions use separate buckets because their AIR shapes differ. Each bucket cap is absorbed into its Fiat-Shamir channel before any challenge, so there is no per-transaction commitment that could be selectively forged inside the bucket.

The canonical `BlockProof` binds all non-empty bucket proofs together with common NativeDelta state openings: one pre-state and one post-state `SegmentMleOpening` per dirty segment. The block header separately binds the public Auth sidecar through `witness_root`.

### 5.2 Deferred FRI (Per-Bucket Opening)

Instead of N independent FRI openings (O(N × FRI_cost)), each bucket prover runs a **multipoint sumcheck** that reduces that bucket's N terminal claims to a single evaluation point `r_block`. One FRI-Binius mixed opening closes all bucket columns simultaneously.

**Proof size scales as O(log N)** in the FRI layer per non-empty bucket, not O(N × per-tx FRI).

### 5.3 NativeDelta state binding

For every dirty state segment, the verifier reconstructs spend/mint claims from the canonical block body and the pre-block segmented state. It derives a segment evaluation point and batching challenge from the transition endpoints:

```text
(r_seg, gamma_seg) = FS("STATE_DELTA_EVAL", prev_state_root, new_state_root, seg_id, state_binding_index, n_tx, eff_log)
```

The checked identity is:

```text
post_lane(r_seg) = pre_lane(r_seg) + Σ_i eq(r_seg, local_slot_i) · delta_i
```

for the three segment lanes `[value, owner_hi, owner_lo]`. The proof then opens the pre-state segment MLE under `prev_state_root` and the post-state segment MLE under `new_state_root`. Both openings carry the same `seg_id`, the same `eval_point`, a compact mixed opening for the three lanes, and a Poseidon2b Merkle path from the segment root to the block state root.

For user-transaction blocks this NativeDelta check is mandatory production validity. Coinbase-only blocks have no user claims and use the explicit empty-proof/stub path.

### 5.4 Claim Bridge

`TxLogicAir` and `SweepTxLogicAir` produce public claimed slot indices, values, owners, body hashes, and claim commitments. NativeDelta reconstructs the ordered state action surface from those public block bodies and the pre-state. Neither layer can lie independently:

- transaction AIRs are stateless and cannot mutate chain state;
- NativeDelta has no wallet secret and cannot forge ownership;
- any mismatch between public transaction claims and pre-state reads is rejected before the post-state opening is accepted.

---

## 6. Layer 4: Consensus

### 6.1 Proof of Work

- Hash function: Blake3 (256-bit output)
- PoW input: 212-byte `header_core` with nonce included
- Nonce: 128-bit LE at bytes `[144..160]` of `header_core` and of the full header
- Validity: `Blake3(header_core) < difficulty_target`
- Target block time: 15 seconds

`header_core` is the byte-level preimage:

```text
core[0..32]    prev_block_hash
core[32..64]   state_root
core[64..96]   tx_root
core[96..104]  timestamp LE u64
core[104..112] height LE u64
core[112..144] miner_address
core[144..160] nonce LE u128
core[160..192] difficulty_target
core[192..196] log_slots LE u32
core[196..204] active_slot_count LE u64
core[204..212] alloc_counter LE u64
```

It excludes the full-header fields `proof_transcript_hash` and `witness_root`, allowing PoW search and BlockProof generation to run in parallel. The full block hash used for chain linking still hashes `header_core || proof_transcript_hash || witness_root`.

### 6.2 Difficulty Adjustment (ASERT)

Exponential moving average, computed every `EPOCH_LENGTH = 6` blocks:

```
next_target = anchor_target × 2^((time_elapsed - expected_time) / halflife)
```

Properties: stateless (computable from any header + anchor), immune to timewarp, O(1) computation.

### 6.3 Fork Choice

Heaviest chain by cumulative PoW work. A competing fork reorgs the incumbent only if its extra work is strictly greater, or if extra work is equal and the competing tip height is greater.

### 6.4 Finality

`FINALITY_DEPTH = 18` blocks. After 18 confirmations:
- Undo logs are pruned
- Block bodies and public Auth sidecars are pruned
- `BlockProof` bytes become eligible for pruning only after the stored recursive proof has covered that height
- Reorg is structurally impossible (no undo data)

### 6.5 Transaction Validity Window

`ANCHOR_DEPTH = 144` (~36 minutes) is the anchor-depth parameter. For block validation, accepted anchor heights are:

```text
[block_height - ANCHOR_DEPTH - 1, block_height - 1]
```

with saturation near genesis, so the consensus window contains up to 145 recent past headers. This provides:

- **Replay protection without permanent storage:** after the anchor window expires, replay is structurally impossible
- **Nullifier pruning:** nullifiers (`tx_body_hash` values) only need to cover the bounded anchor window

---

## 7. Layer 5: Recursive Chain Proof

### 7.1 RecursiveBlockAir

A 256-row, 10-column STARK that proves accumulator continuity:

| Rows | Purpose | Gate |
|------|---------|------|
| 0–10 | Primary block bucket degree-2 multipoint sumcheck folding | FoldCheckGate (`Lagrange([p0,p1,p2], r)`) |
| 11–21 | Secondary block bucket degree-2 multipoint sumcheck folding | FoldCheckGate (`Lagrange([p0,p1,p2], r)`) |
| 22–32 | Previous recursive degree-2 sumcheck folding | FoldCheckGate (`Lagrange([p0,p1,p2], r)`) |
| 33 | State root continuity pin | WeightedLinearGate (degree 2) |
| 34–255 | Padding (zero) | — |

At `2^8 = 256` rows, a multilinear polynomial is fully determined by its hypercube evaluation table. FRI proximity testing is redundant; the tensor check is exact. Therefore `n_rounds = 0` in the FRI layer.

### 7.2 Chain Accumulator

```
ChainAccumulator {
    height:      u64
    state_root:  [Block128; 2]
    chain_hash:  [u8; 32]
}

extend(block_hash, chain_claim, new_state_root):
    inner      = compress(block_hash, claim_bytes)
    chain_hash = compress(prev_chain_hash, inner)
    state_root = new_state_root
    height    += 1
```

The recursive step distinguishes:

- `block_initial_claim`: bucket-local multipoint sumcheck target checked by `RecursiveBlockAir`.
- `chain_claim`: canonical block proof claim folded into `chain_hash`.

These values are bound at two levels:
1. **STARK:** `[block_initial_claim, block_secondary_initial_claim, rec_initial_claim, chain_claim]` is absorbed into `extra_transcript` → forks all challenges
2. **Chain/header:** `verify_recursive_step` checks `chain_claim` against `proof_transcript_hash` for non-stub blocks, recomputes `chain_hash`, and asserts equality

### 7.3 Properties

- **Size:** ~43 KB encoded constant (independent of chain length)
- **Verification:** a few milliseconds (one STARK verify)
- **Coverage:** a recursive proof at height `h` proves the chain from genesis through block `h`; healthy nodes target finalized history near `tip - FINALITY_DEPTH`
- **Unforgeable:** soundness ~2^-123 (RecursiveBlockAir zero-check)

---

## 8. Transaction Lifecycle

### 8.1 End-to-End Flow

```
Wallet                    Mempool              Miner                   Network
  │                         │                    │                       │
  │ 1. Build TxIntent       │                    │                       │
  │    (select inputs,      │                    │                       │
  │     compute fee,        │                    │                       │
  │     pick epoch_anchor)  │                    │                       │
  │                         │                    │                       │
  │ 2. Prove (local)        │                    │                       │
  │    SpineGKR → tx_body   │                    │                       │
  │    AuthGKR → ownership  │                    │                       │
  │    TxLogicAir → balance │                    │                       │
  │    FRI → commit         │                    │                       │
  │                         │                    │                       │
  │ 3. Submit ────────────> │                    │                       │
  │                         │                    │                       │
  │                         │ 4. Admission       │                       │
  │                         │    prefilter       │                       │
  │                         │    (fee, anchor,   │                       │
  │                         │    slots, nullifier)│                      │
  │                         │    + LogicProof    │                       │
  │                         │    verify + final  │                       │
  │                         │    recheck         │                       │
  │                         │                    │                       │
  │                         │ 5. Gossip after final admission ───────────>
  │                         │                    │                       │
  │                         │ 6. Template ─────> │                       │
  │                         │    (max 256 txs)   │                       │
  │                         │                    │                       │
  │                         │                    │ 7. Parallel:          │
  │                         │                    │    PoW (Blake3 nonce) │
  │                         │                    │    prove_block        │
  │                         │                    │                       │
  │                         │                    │ 8. Seal header        │
  │                         │                    │    (state_root,       │
  │                         │                    │     tx_root,          │
  │                         │                    │     proof_hash)       │
  │                         │                    │                       │
  │                         │                    │ 9. Gossip ──────────> │
  │                         │                    │                       │
  │                         │                    │                 10. Verify:
  │                         │                    │                     proof/header binding
  │                         │                    │                     + cheap consensus
  │                         │                    │                     + full BlockProof
  │                         │                    │                     + proven state δ
  │                         │                    │                       │
  │                         │                    │ 11. Async:            │
  │                         │                    │     prove_recursive   │
  │                         │                    │     → ~43 KB proof    │
```

### 8.2 Timing

| Step | Duration | Bottleneck |
|------|----------|-----------|
| Wallet prove (`Standard4x8`, 4-in/8-out) | ~98.07 ms | wallet proof generation |
| Wallet verify (`Standard4x8`, 4-in/8-out) | ~27.58 ms | wallet proof verification |
| Mempool admission | <1 ms native prefilter + bounded LogicProof worker + final recheck | Slot lookups / proof workers |
| Block prove (100 standard-shape txs, proof-native `block_scaling` mix) | ~14.75 s | bucket proof + NativeDelta openings |
| Block verify (100 standard-shape txs, proof-native `block_scaling` mix) | ~4.91 s | bucket verify + NativeDelta openings |
| PoW (target 15s) | ~15 s | Blake3 nonce search |
| Recursive proof verify | a few ms | RecursiveBlockAir verify |

---

## 9. Block Structure

### 9.1 Block Header (276 bytes)

```
Offset  Size  Field                    Purpose
  0      32   prev_block_hash          Chain link
 32      32   state_root               Poseidon2b Merkle over segment FRI roots
 64      32   tx_root                  Poseidon2b Merkle over tx_body_hashes
 96       8   timestamp                Unix seconds
104       8   height                   Block number
112      32   miner_address            Coinbase recipient (32 bytes)
144      16   nonce                    Blake3 PoW nonce (128-bit LE)
160      32   difficulty_target        ASERT target (256-bit LE)
192      32   proof_transcript_hash    canonical BlockProof claim hash
224      32   witness_root             BlockAuthSidecar root
256       4   log_slots                log2(state capacity)
260       8   active_slot_count        Live UTXOs after this block
268       8   alloc_counter            Allocator PRNG seed after this block
                                       Total: 276 bytes
```

The 212-byte PoW `header_core` is not “the header with nonce zeroed”. It is the header fields above with `proof_transcript_hash` and `witness_root` omitted; `log_slots`, `active_slot_count`, and `alloc_counter` are appended immediately after `difficulty_target` in the PoW preimage. The nonce is included and patched in place by miners at byte offset 144.

### 9.2 Block Body

```
Block = {
    header:        BlockHeader
    transactions:  Vec<TxIntent>     (max 256)
}
```

The `tx_root` in the header is the Poseidon2b Merkle root over all `tx_body_hash` values in the block (max depth 8 for 256 txs).

### 9.3 Coinbase-Only Blocks

Blocks with no user transactions:
- Have empty `block_proof_bytes` and empty `block_auth_sidecar_bytes`
- `proof_transcript_hash = STUB_MARKER = [1u8; 32]`
- Skip user proof verification because there are no user slot claims to bind
- Still pass proof/header stub binding, cheap consensus checks, and deterministic coinbase `apply_state_delta`
- `STUB_MARKER` prevents stripping a real proof and claiming coinbase-only

---

## 10. Receipts

### 10.1 Design Principle

The node does NOT store transaction history. Users store their own payment receipts (~300 bytes).

### 10.2 Receipt Structure

```
ParanoidReceipt = {
    version:         u8
    tx_body_hash:    [u8; 32]
    merkle_path:     Vec<[u8; 32]>    (<=8 siblings)
    merkle_dirs:     u32              (bitmask for sibling direction)
    claimed_root:    [u8; 32]         (tx_root from block header)
    claimed_height:  u64
    summary:         TxSummary        (human-readable details)
    summary_hash:    [u8; 32]         (Blake3 integrity)
    chain_cert:      Option<Vec<u8>>  (optional RecursiveProof)
}
```

### 10.3 Verification

1. **Merkle check (offline):** Reconstruct tx_root from `tx_body_hash` + path. Compare with `claimed_root`.
2. **Header check (against stored headers):** Verify `header[claimed_height].tx_root == claimed_root`.
3. **Guarantee:** A forged transaction cannot produce a valid BlockProof → cannot enter a block → cannot appear in any `tx_root`.

---

## 11. Crate Map

| Crate | Layer | Role |
|-------|-------|------|
| `noid_core` | 0 | Field arithmetic, tower types, MLE, sumcheck, NTT |
| `noid_poseidon2b` | 0-1 | Hash function: permutation, compression, sponge |
| `noid_fri` | 0-2 | Generic FRI protocol: commit, prove, verify |
| `noid_fri_binius` | 2-3 | Compact FRI, interleaved commitment, mixed opening |
| `noid_gkr` | 2 | FROST-GKR Kill-Shot: spine + auth + batch-eval |
| `noid_air` | 2-3 | AIR definitions: TxLogicAir, SweepTxLogicAir, recursive/helper gates |
| `noid_stark` | 2-3 | STARK prover/verifier, interleaved composition |
| `noid_tx` | 2 | Transaction types, wire format, body_hash, claims |
| `noid_block` | 3 | Block validation, witness builder |
| `noid_recursive` | 5 | RecursiveBlockAir, accumulator, recursive prove/verify |
| `noid_chain` | 1-4 | State management, consensus, storage (MDBX) |
| `noid_mempool` | 4 | Transaction pool, fee floor, admission |
| `noid_miner` | 4 | Block template, PoW solver |
| `noid_p2p` | 4 | libp2p networking, gossip, sync protocols |
| `noid_rpc` | — | JSON-RPC API (jsonrpsee) |
| `noid_node` | — | Binary: daemon + wallet + CLI |

---

## 12. Invariants

These properties hold at all times for a correct node:

1. **State root binding.** The stored state root equals the Poseidon2b Merkle root over all segment FRI roots. Verified for user-transaction blocks by NativeDelta state-delta identity plus source-bound pre/post segment MLE openings; coinbase-only blocks have no user slot claims and use the canonical stub path plus deterministic coinbase delta.

2. **Recursive proof covers finalized history.** A stored recursive proof at height `h` proves every block from genesis through `h`. Snapshot serving accepts only proofs whose lag from the snapshot tip is bounded by `FINALITY_DEPTH + 2`.

3. **No double-spend within anchor window.** Nullifier set covers all `tx_body_hash` values in the last `ANCHOR_DEPTH` blocks. After expiry, structural replay protection (anchor check) takes over.

4. **Domain-separated transcripts.** Wallet proofs use domain-separated Fiat-Shamir transcripts. Block proving uses per-tx algebraic transcripts seeded by the common bucket commitment and tx index, then Merkle-reduces those transcript digests into the block multipoint channel. Recursive proofs bind the canonical block claim into the chain accumulator.

5. **Stateless transaction validity.** A valid `LogicProof` remains valid across block boundaries until its `epoch_anchor` expires. No re-proving needed.

6. **Expansion is monotonic.** `log_slots` can only increase. State capacity never shrinks.

---

*Cross-references: [Security Model](security.md) for formal proofs. [Cryptography](cryptography.md) for the proof stack. [Network](network.md) for P2P protocol. [CLI](cli.md) for operations.*
