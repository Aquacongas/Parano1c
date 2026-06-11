# Paranoid Zero: System Protocol

## Abstract

Paranoid Zero is a UTXO-based blockchain where every block carries a zero-knowledge proof of its validity. Nodes verify ZK proofs instead of re-executing transactions. The entire chain history compresses into a single 6.5 KB recursive STARK, verifiable in ~5 ms.

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
│  N transaction proofs under one InterleavedCommitment + single FRI.      │
│  BlockStateBindingAir proves state transitions against state MLE.        │
├─────────────────────────────────────────────────────────────────────────┤
│  Layer 2: Transaction (ZK Proof)                                        │
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

1. **Frobenius endomorphism.** Squaring `x ↦ x^2` is GF(2)-linear (bit-shuffle, zero cost). This makes `x^7 = x · x^2 · x^4` require only 3 multiplications.

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

The state root appears in the block header (`offset 32, 32 bytes`). It commits the node to the exact UTXO state after applying all transactions in the block. Any inconsistency between the committed root and the actual state is detected by `BlockStateBindingAir` (Layer 3).

---

## 4. Layer 2: Transaction Proof

A transaction proof is **stateless**: produced by the wallet without knowledge of the current chain state. It proves ownership and balance conservation. State binding happens at Layer 3.

### 4.1 Transaction Structure

```
TxIntent = {
    epoch_anchor:  [u8; 32]     -- block hash within last 144 blocks
    fee:           u64           -- fee in μNOID
    inputs:        [TxInput; 1..4]
    outputs:       [TxOutput; 1..8]
    is_coinbase:   bool
    logic_proof:   LogicProof    -- ZK proof bundle
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
tx_body_hash = SpineMerkle(
    prev_state_root,
    fee_leaf,
    input_leaves[0..4],
    output_leaves[0..8],
    is_coinbase_leaf,
    pad_leaf
)
```

59 Poseidon2b permutations arranged as a Merkle tree (4 leaf-hash + 8 leaf-hash + 15 compress + 1 wrap = 59 slots). The FROST-GKR Spine Kill-Shot proves this computation.

### 4.3 Ownership Authentication

For each input `i`:

```
Address[i]  = H_ADDR(spend_secret[i])   = Poseidon2b sponge with TAG_ADDR IV
AuthTag[i]  = H_AUTH(spend_secret[i], tx_body_hash) = Poseidon2b sponge with TAG_AUTH IV
```

5 permutations per input, 20 slots total. The FROST-GKR Auth Kill-Shot proves all 20 simultaneously.

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

### 5.1 Interleaved Commitment

All N transaction traces in a block share a **single** `InterleavedCommitment`: one Merkle cap covers all columns of all transactions. The cap is absorbed into the Fiat-Shamir channel before any challenge. There is no per-transaction commitment that could be selectively forged.

### 5.2 Deferred FRI (Single Opening)

Instead of N independent FRI openings (O(N × FRI_cost)), the block prover runs a **multipoint sumcheck** that reduces all N terminal claims to a single evaluation point `r_block`. One FRI-Binius mixed opening closes all columns simultaneously.

**Proof size scales as O(log N)** in the FRI layer, not O(N).

### 5.3 BlockStateBindingAir

This AIR proves that the slot-state transitions claimed by transactions are consistent with the actual state MLE:

| Terminal constraint | What it proves |
|--------------------|---------------|
| Gamma-RLC terminal | Accumulated pre-state openings match the verifier-supplied batched claims from TxLogicAir outputs |
| Delta-acc terminal | Net state MLE change equals `prev_opening ⊕ new_opening` from externally-verified state roots |

Both terminal values are **verifier-hardcoded** from the block header's state root fields. Max constraint degree: 3. Zero-check soundness: `44/2^128`.

### 5.4 The C_claimed Bridge

`TxLogicAir` produces `C_claimed` (commitment over slot indices and values it claims). `BlockStateBindingAir` takes `C_claimed` as a public input and verifies each claim against the actual state MLE. Neither layer can lie independently:

- `TxLogicAir` is stateless (cannot touch state)
- `BlockStateBindingAir` has no secret (cannot forge ownership)

---

## 6. Layer 4: Consensus

### 6.1 Proof of Work

- Hash function: Blake3 (256-bit output)
- PoW input: 212-byte `header_core` (header with nonce zeroed)
- Nonce: 128-bit (bytes 144..160 of the header)
- Validity: `Blake3(header_core_with_nonce) < difficulty_target`
- Target block time: 15 seconds

### 6.2 Difficulty Adjustment (ASERT)

Exponential moving average, computed every `EPOCH_LENGTH = 6` blocks:

```
next_target = anchor_target × 2^((time_elapsed - expected_time) / halflife)
```

Properties: stateless (computable from any header + anchor), immune to timewarp, O(1) computation.

### 6.3 Fork Choice

Heaviest chain by cumulative PoW work. Ties: incumbent wins.

### 6.4 Finality

`FINALITY_DEPTH = 18` blocks. After 18 confirmations:
- Undo logs are pruned
- Block bodies are pruned
- Reorg is structurally impossible (no undo data)

### 6.5 Transaction Validity Window

`ANCHOR_DEPTH = 144` blocks (~36 minutes). A transaction's `epoch_anchor` must reference a header hash within this window. This provides:

- **Replay protection without permanent storage:** after 144 blocks, the anchor expires → replay structurally impossible
- **Nullifier pruning:** nullifiers (tx_body_hash values) only need to cover the 144-block window

---

## 7. Layer 5: Recursive Chain Proof

### 7.1 RecursiveBlockAir

A 256-row, 8-column STARK that proves accumulator continuity:

| Rows | Purpose | Gate |
|------|---------|------|
| 0–10 | Block-n multipoint sumcheck folding | FoldCheckGate (degree 2) |
| 11–21 | Previous recursive sumcheck folding | FoldCheckGate (degree 2) |
| 22 | State root continuity pin | WeightedLinearGate (degree 2) |
| 23–255 | Padding (zero) | — |

At `2^8 = 256` rows, a multilinear polynomial is fully determined by its hypercube evaluation table. FRI proximity testing is redundant; the tensor check is exact. Therefore `n_rounds = 0` in the FRI layer.

### 7.2 Chain Accumulator

```
ChainAccumulator {
    height:      u64
    state_root:  [Block128; 2]
    chain_hash:  [u8; 32]
}

extend(block_hash, block_initial_claim, new_state_root):
    inner      = compress(block_hash, claim_bytes)
    chain_hash = compress(prev_chain_hash, inner)
    state_root = new_state_root
    height    += 1
```

The `block_initial_claim` is bound at two levels:
1. **STARK:** absorbed into `extra_transcript` → forks all challenges
2. **Chain:** `verify_recursive_step` recomputes `chain_hash` and asserts equality

### 7.3 Properties

- **Size:** ~6.5 KB constant (independent of chain length)
- **Verification:** ~5 ms (one STARK verify)
- **Coverage:** proves the entire chain from genesis to `height - FINALITY_DEPTH`
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
  │                         │    checks (fee,    │                       │
  │                         │    anchor, slots,  │                       │
  │                         │    nullifier)      │                       │
  │                         │                    │                       │
  │                         │ 5. Gossip ─────────────────────────────────>
  │                         │                    │                       │
  │                         │ 6. Template ─────> │                       │
  │                         │    (max 256 txs)   │                       │
  │                         │                    │                       │
  │                         │                    │ 7. Parallel:          │
  │                         │                    │    PoW (Blake3 nonce) │
  │                         │                    │    ZK (prove_block)   │
  │                         │                    │                       │
  │                         │                    │ 8. Seal header        │
  │                         │                    │    (state_root,       │
  │                         │                    │     tx_root,          │
  │                         │                    │     proof_hash)       │
  │                         │                    │                       │
  │                         │                    │ 9. Gossip ──────────> │
  │                         │                    │                       │
  │                         │                    │                 10. Verify:
  │                         │                    │                     consensus
  │                         │                    │                     + ZK proof
  │                         │                    │                     + state δ
  │                         │                    │                       │
  │                         │                    │ 11. Async:            │
  │                         │                    │     prove_recursive   │
  │                         │                    │     → 6.5 KB proof    │
```

### 8.2 Timing

| Step | Duration | Bottleneck |
|------|----------|-----------|
| Wallet prove (1 tx) | ~150 ms | GKR unified sumcheck |
| Mempool admission | <1 ms | Slot lookups |
| Block prove (full, 256 txs) | ~10 s | Interleaved FRI |
| PoW (target 15s) | ~15 s | Blake3 nonce search |
| Block verify (full) | ~50 ms/tx | GKR verify + STARK |
| Recursive step | ~2 s | RecursiveBlockAir prove |

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
192      32   proof_transcript_hash    Fiat-Shamir hash of BlockProof
224      32   witness_root             Binius-packed DA payload root
256       4   log_slots                log2(state capacity)
260       8   active_slot_count        Live UTXOs after this block
268       8   alloc_counter            Allocator PRNG seed after this block
                                       Total: 276 bytes
```

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
- Have empty `block_proof_bytes`
- `proof_transcript_hash = STUB_MARKER = [1u8; 32]`
- Skip ZK verification entirely (nothing to prove)
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
| `noid_air` | 2-3 | AIR definitions: TxLogicAir, BlockStateBindingAir, gates |
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

1. **State root binding.** The stored state root equals the Poseidon2b Merkle root over all segment FRI roots. Verified by `BlockStateBindingAir` for every block.

2. **Recursive proof covers finalized history.** `recursive_proof.height >= tip - FINALITY_DEPTH`. Proves every block from genesis to that height satisfies all ZK constraints.

3. **No double-spend within anchor window.** Nullifier set covers all `tx_body_hash` values in the last `ANCHOR_DEPTH` blocks. After expiry, structural replay protection (anchor check) takes over.

4. **Single transcript.** Every proof (transaction, block, recursive) is bound to a single `Poseidon2bChannel`. No forked transcripts exist anywhere in the system.

5. **Stateless transaction validity.** A valid `LogicProof` remains valid across block boundaries until its `epoch_anchor` expires. No re-proving needed.

6. **Expansion is monotonic.** `log_slots` can only increase. State capacity never shrinks.

---

*Cross-references: [Security Model](security.md) for formal proofs. [Cryptography](cryptography.md) for the ZK stack. [Network](network.md) for P2P protocol. [CLI](cli.md) for operations.*
