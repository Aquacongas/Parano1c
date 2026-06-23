# PARANOID. The Proof-Native Transparent UTXO Statechain

> The proof of the entire chain history from genesis fits in **~43 KB**. Verification takes a few milliseconds.
> No archive nodes. No history replay. No signatures. No trusted setup.

---

Blockchains have a fundamental architectural flaw: to validate the present, you must replay the past. Every major network inherits this property, full nodes download and re-execute every transaction back to genesis. This isn't a temporary limitation; it is baked into the model.

Paranoid removes this requirement entirely.

In Paranoid, validity is established once, locally, by the party with the most information — the wallet owner. The result is a cryptographic proof that the network verifies without re-executing. Recursive composition collapses the entire chain history into a single compact proof. The present can be verified without the past. **Truth is a function of mathematics, not time.**

---

## The Fundamental Shift

| | Classic blockchain | Paranoid |
|---|---|---|
| Validation model | Re-execute everywhere | Verify proof once |
| Full sync | Replay N GB of history | State snapshot + ~43 KB recursive proof; proof verification in a few ms |
| History required to validate | Yes. From genesis | No |
| Signatures | ECDSA / EdDSA | None. Hash-preimage ownership proof |
| Quantum safety | No (discrete log problem) | Yes. Hash-only primitives |
| 51% attack capability | Spend others' coins | Choose ordering only |
| State growth | Spent outputs accumulate forever | Spent outputs removed; slots freed and reused |
| Block proofs | None. Trust replays | `verify_block()` on every node |

A 51% miner in Paranoid can only choose the ordering of valid transitions. They cannot forge proofs. They cannot spend coins they do not own. The proof layer is the security boundary; PoW is the ordering mechanism.

---

## How It Works

### Execution is Local

When you send NOID, your wallet builds a stateless **LogicProof** that proves:
- You know the secret behind the input address (`Address = Poseidon2b(spend_secret)`)
- Inputs equal outputs plus fee
- All values are in range
- The transaction body is cryptographically bound

This proof is **stateless**: no Merkle paths, no dependency on the current state root. It is valid across block boundaries until the epoch anchor expires (~36 minutes). You prove it once, on your device.

### The Network Verifies, Not Executes

Every full node independently verifies the validity proof of each user-transaction block it receives. A canonical `BlockProof` covers:
- All per-transaction LogicProofs, aggregated in shape-specific buckets (`Standard4x8`, `Sweep25x2`)
- Mandatory NativeDelta state-root transition proof: input slots held the claimed values, output slots were empty, and the post-block `state_root` follows from the proven delta
- Source-bound per-bucket FRI openings for non-empty transaction-shape buckets, all bound into one block proof transcript

The full node never re-runs the wallet logic as a production acceptance rule. It verifies the proof, then commits only the proven state delta.

### History Collapses Recursively

Every block extends a rolling accumulator:

```
inner_n       = Poseidon2b_compress(H_BLOCK(header_n), block_initial_claim_n)
chain_hash_n  = Poseidon2b_compress(chain_hash_{n-1}, inner_n)
```

`block_initial_claim` encodes the MLE evaluation of the block's slot-state transitions and is folded into every step, binding the chain hash to both the block header and the block's state-transition proof. The recursive proof proves that this accumulator was correctly computed from genesis, and that the current `state_root` is the result. It is a single STARK over a 256-row trace — constant size regardless of chain length.

**Result:** A new node downloads:
1. The current **state snapshot**. Only populated FRI segments (~3 MB each,
   one per 65,536 UTXOs; scales with UTXO set size)
2. The **RecursiveProof** (~43 KB encoded)
3. Verifies the recursive proof in a few milliseconds, then applies the authenticated snapshot segments

No genesis replay. No archive nodes. No trust assumption.

---

## Cryptographic Architecture

*This section is aimed at proof-system engineers. Skip to [Running Paranoid](#running-paranoid) if you just want to use it.*

### Field: Binary Tower GF(2^128)

All arithmetic runs over `GF(2^128)` in the **binary tower** representation. Multiplication is `CLMUL` on x86 (one instruction, ~1ns); addition is XOR. The field naturally supports the Frobenius endomorphism (`x → x²` is linear over GF(2) — free squaring, no multiplications).

Poseidon2b is a native GF(2^128) permutation: S-box is `x^7 = x · x² · x⁴` with the MDS matrix operating over the tower. The AIR and all proof systems operate over the same field — no field extension towers, no splitting.

### Polynomial Commitment: FRI-Binius

The PCS is **FRI-Binius** — Reed-Solomon over binary towers with compact interleaved FRI. Key properties:

- **COMPACT_TAU = 8** and release-mode **COMPACT_NUM_QUERIES = 64**. With `log_rows = 8`, the recursive RecursiveBlockAir has exactly **zero FRI Merkle paths**. The recursive proof is pure sumcheck algebra.
- **Interleaved commitment + source-bound mixed opening**: all columns for same-shape transactions in a non-empty block bucket are committed jointly in one Merkle cap. Each non-empty bucket has a `MixedOpeningProof` containing a `SourceBindingProof`; the verifier authenticates the queried compact-FRI round-0 symbols to the committed source columns.
- **Vector-mode cap**: mixed openings reject `n_cols > MAX_MIXED_OPEN_VECTOR_COLS = 256`, keeping the vector-binding Schwartz-Zippel term at most `255 / 2^128 < 2^-120`. Wider terminal claims must be reduced before this PCS surface.
- **Segmented state PCS**: the UTXO state is divided into independent 2^16-slot segments, each with its own FRI commitment. Only dirty segments are re-committed per block.

### FROST-GKR Kill-Shot

This is Paranoid's core cryptographic innovation. Poseidon2b proof generation is the bottleneck in proof systems that use it. The standard approach decomposes S-box constraints into degree-2 layers:

```
Standard (spine only): 59 permutations × 8 sumchecks × 9 rounds = 4,248 FS challenges
                       per-tx proof hash component: >280 KB
```

FROST-GKR exploits the Frobenius endomorphism in GF(2^128):

```
x² = square(x)              // free: Frobenius is GF(2)-linear
x⁴ = square(x²)             // free
x⁷ = (x · x²) · x⁴          // 2 field multiplications
```

S-box evaluation requires only **2 field multiplications** (+ 2 free squarings). This makes the S-box natively degree-7 — no auxiliary columns, no degree-2 decomposition needed. A single **unified sumcheck** (round polynomial degree 9: eq × selector × s_in⁷) runs over all 59 (or 20) permutations simultaneously. The MDS matrix transition is handled by a **Shift Gadget** — a bounded-degree polynomial over the permutation state that folds into the same sumcheck.

The result is a single Kill-Shot proof per GKR instance:

| | Baseline degree-2 GKR | FROST-GKR Kill-Shot |
|---|---|---|
| Fiat-Shamir rounds | 4,248 | **30** |
| S-box model | degree-2 auxiliary layers | native degree-7 over GF(2^128) |
| Transaction-body binding | many per-layer transcripts | one SpineGKR transcript |
| Ownership/Auth binding | many per-layer transcripts | one AuthGKR transcript |
| Sweep wallet spine | wallet-side | **removed; block-side only** |

Current end-to-end wallet proof timings and sizes are listed in [Performance](#performance).

**Two Kill-Shot instances per transaction:**
- **SpineGKR** (59 permutations) — computes `tx_body_hash` from the full transaction body. Binds every field of every input and output into a single 32-byte hash that the STARK pins.
- **AuthGKR** (20 permutations) — computes `Address[i]` and `AuthTag[i]` per input. Proves ownership and replay protection in one unified circuit.

Both are single-transcript, bound into the per-tx STARK via `extra_transcript`. Any byte-level tamper forks every subsequent Fiat-Shamir challenge.

### Three-Level Proof Stack

```
┌─────────────────────────────────────────────────────────────┐
│  RecursiveProof  ·  ~43 KB ·  O(1) verify · few ms          │
│  RecursiveBlockAir: 256×10 trace, COMPACT_TAU=8             │
│  Proves: accumulator continuity from genesis to h=N         │
└──────────────────────┬──────────────────────────────────────┘
                       │ each step wraps ↓
┌──────────────────────▼──────────────────────────────────────┐
│  BlockProof  ·  O(txs) verify                               │
│  = Standard/Sweep shape buckets for tx logic aggregation    │
│  + SpineGKR/AuthGKR binding for each included transaction   │
│  + mandatory NativeDelta state transition for user-tx blocks│
│  + per-bucket mixed FRI openings                            │
└──────────────────────┬──────────────────────────────────────┘
                       │ wallet produces ↓
┌──────────────────────▼──────────────────────────────────────┐
│  LogicProof  ·  stateless                                   │
│  TxLogicAir: balance + range + ownership binding            │
│  AuthGKR Kill-Shot: proof-of-knowledge of spending secret preimage │
│  Stateless: no Merkle paths, no state_root dependency       │
└─────────────────────────────────────────────────────────────┘
```

**Stateless / stateful proof separation:** The LogicProof is created by the wallet — the only party that knows the spending secret. It is stateless and valid until the epoch anchor expires. The block producer creates the NativeDelta state transition proof from public transaction bodies and current state openings: the verifier reconstructs the canonical delta, checks the delta-MLE identity, and binds pre/post segment openings to `prev_state_root` and `new_state_root`. The claim bridge binds transaction bucket claims to the state-binding openings, so neither layer can lie independently.

### Deferred FRI Aggregation

All same-shape transaction STARK traces inside a bucket share one Merkle commitment (`InterleavedCommitment`). Instead of per-tx FRI openings, each non-empty bucket runs a **multipoint sumcheck** that reduces that bucket's terminal claims to one evaluation point `r_block`. One source-bound FRI-Binius mixed opening closes that bucket.

Block proof size scales as `O(log N)` in the FRI layer per non-empty bucket and `O(N)` in the algebraic layer — not `O(N × per-tx FRI)`.

---

## State Model

The UTXO state is a flat array of `2^log_slots` slots:

```
slot[i] = { value: u64, owner_hi: [u8;16], owner_lo: [u8;16] }
```

An empty slot is canonical zero `(0, 0, 0)`. Spending a UTXO zeros its slot — **the slot is immediately available for reuse**. There are no stale entries — spent outputs leave no residue in the state. State size is proportional to the UTXO set, not transaction history.

### Segmented FRI Commitment

State is divided into independent **2^16-slot segments** (65,536 slots each), each with its own FRI Merkle root. The global `state_root = Poseidon2b_Merkle(seg_roots[])`. Only segments modified by a block are re-committed. The zone-based allocator places sequential outputs in the same segment, bounding the number of dirty segments per block.

Only **populated segments** are stored and transmitted. A production 2^16-slot segment has exact canonical encoded size `5 + 65,536 × 3 × 16 = 3,145,733` bytes (~3 MB). A node with 100,000 UTXOs holds ~2 populated segments ≈ 6 MB of state, regardless of `log_slots` capacity. Snapshot size grows with UTXO set size, not with total slot capacity.

### Automatic Expansion

When the UTXO set reaches 75% of capacity, `log_slots` increments by 1 (capacity doubles). The trigger is computed identically by every node from the median of the last 18 `active_slot_count` values. No governance, no hard fork.

Block reward halves with each expansion. Attacking by filling slots halves the attacker's own mining income.

| log_slots | Slots | Block reward |
|---|---|---|
| 24 (genesis) | 16,777,216 | 50 NOID |
| 25 | 33,554,432 | 25 NOID |
| 26 | 67,108,864 | 12.5 NOID |
| … | … | … |
| 32 (max) | 4,294,967,296 | 1 NOID (floor) |

---

## Ownership: No Signatures

There are no digital signatures in Paranoid. Ownership is proven by a **proof-of-knowledge** — a Poseidon2b hash preimage proof over GF(2^128). This is a soundness guarantee (you cannot forge ownership), not a privacy guarantee (proofs from different secrets are distinguishable).

Your **spending secret** is any 32 bytes: random, a passphrase hash, anything. At the protocol layer an address is derived from one spending secret; wallet HD-style indexes derive distinct spending secrets first:

```
spend_secret_i = H_DERIVE(master_secret, i)        // wallet-local index i
Address_i      = H_ADDR(spend_secret_i)            // protocol primitive
AuthTag        = H_AUTH(spend_secret_i, tx_body_hash)  // per-tx replay protection
```

To spend, the wallet proves knowledge of the `spend_secret_i` whose hash equals the stored address. This is proven by the AuthGKR Kill-Shot. The spending secret never leaves the device — it is used to compute a proof, then zeroed from memory.

**Post-quantum by construction.** Zero elliptic curve operations. No discrete logarithm.
The entire stack is hash-based and algebraic:

| Component | Classical | Post-Quantum | Notes |
|---|---|---|---|
| FRI-Binius PCS | 128 bits | **128 bits** | Information-theoretic proximity checks with 64 queries at rate 1/4; quantum-invariant by proof |
| STARK / GKR sumcheck | ~120 bits | **~120 bits** | Schwartz–Zippel over GF(2¹²⁸); quantum-invariant by proof; bottleneck is FROST-GKR (348/2¹²⁸) |
| Poseidon2b preimage | 256 bits | **128 bits** | Grover: O(√2²⁵⁶); **PQ < classical** |
| Blake3 / Poseidon2b collision | 128 bits | **~128 bits** | Grover on 2nd-preimage; BHT collision is O(2⁸⁵) but requires O(2⁸⁵) QRAM (impractical) |
| **System min** | **~120 bits** | **~120 bits** | Bottleneck: FROST-GKR subproof bound |

The algebraic layers (FRI proximity, sumcheck, GKR) are **information-theoretic** — their
soundness bound holds against any prover, classical or quantum, by the Schwartz–Zippel lemma.
This is proven, not assumed.

The system bottleneck is the FROST-GKR subproof bound at ~120 bits (348/2^128). For
hash-based components, post-quantum security is lower than classical for Poseidon2b preimage
(256 -> 128 bits via Grover), but the algebraic layer already caps the system at ~120 bits
regardless. The ~120-bit PQ claim holds under the standard quantum circuit model (NIST
assumption). The theoretical BHT collision attack (O(2^85) quantum) requires O(2^85) QRAM
cells — hardware that does not exist and may never be physically realizable at that scale.

---

## Proof-of-Work: Ordering, Not Security

PoW in Paranoid has a single job: **ordering**. It picks the canonical sequence of valid state transitions. Block validity is already established by the proof system.

**Algorithm:** Blake3 over the 212-byte `header_core` PoW input. `header_core` includes the 128-bit nonce and these fields, in order: `prev_block_hash`, `state_root`, `tx_root`, `timestamp`, `height`, `miner_address`, `nonce`, `difficulty_target`, `log_slots`, `active_slot_count`, `alloc_counter`. It excludes `proof_transcript_hash` and `witness_root`; the full 276-byte header hash still commits both for chain linking. Miners patch nonce bytes `[144..160]` in `header_core`.

**Why Blake3:** PoW is byte-native and cheap to verify. The coinbase recipient is part of `header_core` (`miner_address`) and the block transaction root; changing it after solving changes the PoW input and block binding. User-transaction blocks additionally bind the canonical `BlockProof` via `proof_transcript_hash` and the public Auth sidecar via `witness_root`.

**Difficulty:** ASERT algorithm (Bitcoin Cash variant), 6-block epoch, 90-second halflife. Responds to any hashrate change within ~7 minutes. Floor: difficulty never eases below genesis target — ASERT can only move harder.

| Parameter | Value |
|---|---|
| Block time target | 15 s |
| Genesis difficulty | 2^229 |
| ASERT halflife | 90 s (6 epochs × 15 s) |
| Finality depth | 18 blocks |
| Epoch anchor window | 144-block depth (145 accepted anchor heights) |
| Header size | 276 bytes |
| Nonce width | 128 bits |

---

## Security Model

**Soundness guarantees** (what the proof system makes cryptographically infeasible to fake):
- Ownership: spender knows the Poseidon2b preimage of the input address — ~120-bit soundness via Schwartz–Zippel over GF(2¹²⁸); bottleneck is FROST-GKR subproof bound (348/2¹²⁸)
- Balance is conserved; all values are in range
- State root is correctly computed from the claimed slot transitions
- `tx_body_hash` binding prevents cross-transaction replay of proof artifacts
- Every block accepted by a full node has been proof-verified before application

**Privacy model** (what the proof system does NOT provide):
- The protocol is **not zero-knowledge** in the standard simulator sense. Two different secrets produce different (distinguishable) proof transcripts
- Transaction graph analysis by proof pattern is possible for observers that record public transaction/block/proof traffic before the 18-block pruning window; finalized nodes do not retain this history
- `spend_secret` cannot be recovered from any proof or wire artifact — computational one-wayness under Poseidon2b preimage resistance
- See [docs/security.md](docs/security.md) for the formal analysis

**What PoW guarantees:**
- Canonical ordering of valid transitions
- Sybil resistance for block proposal
- Reorg cost proportional to cumulative work (FINALITY_DEPTH = 18 blocks)

**What 51% hashpower cannot do:**
- Forge a valid proof for slots the attacker does not own
- Produce a `state_root` inconsistent with actual transitions
- Spend outputs without knowing the spending secret
- Fabricate a valid RecursiveProof (requires breaking the underlying soundness assumption)

**Snapshot sync security:** new nodes verify the RecursiveProof and header anchor before accepting a snapshot. The manifest must describe strictly sorted segment IDs within the `u16` segment namespace, exact canonical segment encoding, and segment roots reconstructing the advertised `state_root`. Each received segment is bounded by `MAX_SEGMENT_BYTES = 8 MiB`, decoded, and root-checked before snapshot application; at most `MAX_INFLIGHT_SEGMENTS = 8` segment requests are in flight. A malicious peer cannot serve a fabricated snapshot without breaking the recursive proof or a segment-root check.

**Replay protection:** `epoch_anchor` — a recent block hash committed inside the tx body hash and therefore inside all proofs. Transactions expire after ~144 blocks.

---

## No Block History

Paranoid does not store block history. After FINALITY_DEPTH (18 blocks), full block data and public Auth sidecars are pruned. `BlockProof` bytes are retained until the block is both finalized and folded into the recursive proof. Only block **headers** (276 bytes each) are kept permanently.

**Permanent storage:**
| Data | Size |
|---|---|
| Headers | ~553 MB/year (276 bytes × every block, forever) |
| UTXO set | ~3 MB per 65,536 unspent outputs (populated segments only) |
| Recursive proof | ~43 KB encoded (single entry, overwritten on each advance) |

**Temporary storage:**
| Data | Retention | Size |
|---|---|---|
| Block bytes | last 18 blocks | 276-byte header (fixed) + tx bodies: ~530 B (coinbase-only) – ~192 KB (256 txs) |
| Public Auth sidecars | last 18 blocks | shape-mix dependent |
| BlockProofs | finalized and recursive-consumed window | 0 (coinbase-only); user-tx proof size depends on shape mix and tx count |
| Undo logs | last 18 blocks | ~few KB per block |
| Nullifier window | last 144 blocks | ~few KB |

At any given time the node holds at most 18 blocks' worth of block bodies, public Auth sidecars, and undo logs. `BlockProof` bytes may remain longer only if the background recursive updater is behind; pruning is gated by the stored recursive proof height, not kept as permanent history. In the current `block_scaling` bench, the 100-transaction standard-only fixture mix produces a 10.75 MB `BlockProof` and an 11.80 MB public Auth sidecar on the reference 2023 Intel Core i7-1365U laptop.

| RAM | ~60–120 MB (jemalloc, small-state node) |

---

## Performance

Measured on a 2023 Intel Core i7-1365U laptop, release/bench profile, production proof paths; no mock/native shortcuts.

Wallet proof benchmark (`cargo bench --bench alice_sends_bob`):

| Scenario | Prove median | Verify median | Wallet bundle | Logic proof | STARK | AuthGKR |
|---|---:|---:|---:|---:|---:|---:|
| Standard4x8, 1 input / 2 outputs | 110.11 ms | 27.34 ms | 288.00 KB | 286.30 KB | 169.12 KB | 117.17 KB |
| Standard4x8, 4 inputs / 8 outputs | 98.07 ms | 27.58 ms | 290.82 KB | 289.11 KB | 168.84 KB | 120.27 KB |
| Sweep25x2, 5 inputs / 2 outputs | 422.76 ms | 133.16 ms | 285.33 KB | 280.67 KB | 114.41 KB | 166.27 KB |
| Sweep25x2, 10 inputs / 2 outputs | 578.40 ms | 138.51 ms | 284.58 KB | 279.92 KB | 114.78 KB | 165.14 KB |
| Sweep25x2, 25 inputs / 2 outputs | 574.80 ms | 143.18 ms | 284.02 KB | 279.36 KB | 114.53 KB | 164.83 KB |
| Sweep25x2 consolidation, 25 inputs / 1 output | 576.91 ms | 138.72 ms | 283.71 KB | 279.05 KB | 114.69 KB | 164.36 KB |

Logical split compositions from the same run:

| Composition | Prove total | Verify total | Bundle total | Logic total |
|---|---:|---:|---:|---:|
| 26 inputs: Sweep25x2(25) + Standard4x8 tail | 684.90 ms | 170.51 ms | 572.02 KB | 565.66 KB |
| 50 inputs: Sweep25x2(25) + Sweep25x2(25) | 1.15 s | 286.36 ms | 568.04 KB | 558.72 KB |

Selected block scaling rows (`cargo bench --bench block_scaling`, up to 100 transactions shown here). Wallet proofs are pre-built for block timing; wallet pre-proof time is reported separately by the bench and is not block-time work. The standard-only rows use the benchmark's standard-shape fixture mix (`Standard4x8` and smaller standard sends), not an all-`Standard4x8` worst case.

| Block proof path | Prove full block | Verify full block | BlockProof | Auth sidecar | BlockProof + sidecar |
|---|---:|---:|---:|---:|---:|
| 10 × standard-only mix | 2.67 s | 586.08 ms | 3.58 MB | 1.18 MB | 4.77 MB |
| 20 × standard-only mix | 4.05 s | 1.10 s | 4.40 MB | 2.36 MB | 6.76 MB |
| 100 × standard-only mix | 14.75 s | 4.91 s | 10.75 MB | 11.80 MB | 22.55 MB |
| 1 × Sweep25x2 | 835.71 ms | 231.51 ms | 935.59 KB | 166.36 KB | 1.08 MB |
| 4 × Sweep25x2 | 2.36 s | 577.76 ms | 3.07 MB | 664.05 KB | 3.72 MB |
| 10 × Sweep25x2 | 5.72 s | 1.50 s | 4.01 MB | 1.63 MB | 5.64 MB |
| 8 standard-shape + 2 Sweep25x2 | 4.88 s | 902.34 ms | 4.50 MB | 1.27 MB | 5.76 MB |
| 5 standard-shape + 5 Sweep25x2 | 5.34 s | 1.08 s | 5.94 MB | 1.40 MB | 7.34 MB |

PoW search and BlockProof generation run **in parallel**. Public Auth sidecars are stored only for the **last 18 blocks** (reorg window); `BlockProof` bytes are pruned once they are both finalized and consumed by the recursive updater.

Full-block proofs do not accumulate on disk. What persists forever is the **RecursiveProof** (~43 KB encoded) — a single entry that is overwritten with each advance and proves the entire chain history from genesis.

---

## Running Paranoid

### Node Modes

```
--mode relay     Full node, no mining (default).
                 Verifies all blocks, serves snapshots, relays txs.
                 Suitable for: exchanges, explorers, infrastructure.

--mode miner     Internal PoW + BlockProof generator.
                 Mines blocks with the built-in wallet as coinbase.

--mode extminer  Serves block templates to noid-extminer clients.
                 Node generates BlockProofs; external processes do PoW.
                 Requires: --mining-key <TOKEN>
```

### Quick Start

```bash
# --- First node on a new network ---
paranoid --mode miner --genesis \
  --p2p-listen 0.0.0.0:9400 \
  --rpc-listen 127.0.0.1:9401

# --- Join an existing network (relay node) ---
paranoid --mode relay \
  --seed node1.noid.network \
  --p2p-listen 0.0.0.0:9400 \
  --rpc-listen 127.0.0.1:9401

# --- Join and mine ---
paranoid --mode miner \
  --seed node1.noid.network \
  --p2p-listen 0.0.0.0:9400 \
  --rpc-listen 127.0.0.1:9401

# --- Mining pool (node generates BlockProofs; external miners do PoW) ---
paranoid --mode extminer \
  --seed node1.noid.network \
  --rpc-listen 0.0.0.0:9401 \
  --mining-key my_secret_token \
  --allow-custom-coinbase       # each miner specifies their own payout address

# --- External PoW miner (solo) ---
noid-extminer --rpc http://127.0.0.1:9401

# --- External PoW miner (pool) ---
noid-extminer --rpc http://pool.example.com:9401 \
  --key my_secret_token \
  --coinbase noid1my_payout_address
```

Relay node syncs automatically on first start:
1. Connects to peers
2. Downloads the current state snapshot and RecursiveProof
3. Verifies the proof cryptographically (O(1), a few milliseconds on the reference laptop)
4. Applies the snapshot and begins receiving new blocks

No history download. No archive dependency.

### Local Development / Testing (3-node setup)

```bash
# Node A: genesis miner
paranoid --mode miner --genesis \
  --p2p-listen 0.0.0.0:10000 --rpc-listen 127.0.0.1:10001

# Node B: relay, syncs from A
paranoid --mode relay \
  --data-dir /tmp/nodeB \
  --p2p-listen 0.0.0.0:10002 --rpc-listen 127.0.0.1:10003 \
  --seed 127.0.0.1:10000

# Node C: relay, syncs from B (tests multi-hop sync)
paranoid --mode relay \
  --data-dir /tmp/nodeC \
  --p2p-listen 0.0.0.0:10004 --rpc-listen 127.0.0.1:10005 \
  --seed 127.0.0.1:10002
```

---

## CLI

```bash
# Chain
noid-cli status          # height, state root, difficulty, active slots
noid-cli mempool         # pending txs, fee floor

# Wallet
noid-cli address         # primary address (bech32m, noid1…)
noid-cli balance         # confirmed balance + UTXO count
noid-cli utxos           # all owned UTXOs with slot indices
noid-cli send <addr> <NOID>   # amount in human NOID; omit --fee or use --fee 0 for auto
noid-cli history         # confirmed TX history
noid-cli consolidate     # merge small UTXOs
noid-cli receipt <hash>  # export Merkle payment receipt
noid-cli scan            # rescan state (after wallet restore)

# Node
noid-cli stop            # graceful shutdown
```

Connect to `http://127.0.0.1:9401` by default. Override with `--rpc <url>`.

**Fee formula:** `base + input_fee × inputs + output_fee × outputs + state_growth_fee × max(0, outputs - inputs)`. The state-growth component scales with occupancy and is burned; omitted fee / `--fee 0` auto-computes the current minimum.  
**1 NOID = 1,000,000 μNOID.**  
**Addresses:** bech32m, prefix `noid1`.

---

## JSON-RPC (port 9401)

```
paranoid_blockCount / paranoid_getChainInfo
paranoid_getBlockHash / paranoid_getBlockHeader
paranoid_getHeaderByHeight / paranoid_getHeaderByHash
paranoid_getBlock                     (last 18 blocks only)
paranoid_getSlot / paranoid_getSlotsByOwner / paranoid_getActiveSlotCount
paranoid_getStateInfo / paranoid_getTx / paranoid_isNullifier
paranoid_getMiningInfo / paranoid_getPeerCount
paranoid_estimateFee / paranoid_estimateFeeDetailed
paranoid_validateAddress
paranoid_getSlotHints / paranoid_getSlotHintsSalted / paranoid_getEpochAnchor
paranoid_submitTxIntent
paranoid_getMempoolInfo / paranoid_getMempoolSize / paranoid_getMempoolEntry
paranoid_getRecursiveProof            (~86 KB hex for ~43 KB recursive chain proof)
paranoid_verifyReceipt
paranoid_walletStatus / paranoid_walletGetAddress / paranoid_walletGetBalance
paranoid_walletSend / paranoid_walletPlanSend / paranoid_walletHistory
paranoid_walletScan / paranoid_walletListUtxos / paranoid_walletConsolidate / paranoid_walletPlanConsolidate
paranoid_walletExportReceipt / paranoid_walletNextAddress / paranoid_walletListAddresses
paranoid_stop
paranoid_getBlockTemplate             (extminer mode only)
paranoid_submitBlock                  (extminer mode only; block, proof, auth sidecar)
```

---

## Documentation

| Document | Contents |
|----------|----------|
| [docs/protocol.md](docs/protocol.md) | System architecture: all layers, interfaces, data flow, block structure, transaction lifecycle |
| [docs/cryptography.md](docs/cryptography.md) | Proof stack: binary tower, Poseidon2b, FROST-GKR Kill-Shot, FRI-Binius, recursive STARK. Theorems and soundness proofs |
| [docs/security.md](docs/security.md) | Formal security analysis: claims, proofs, soundness budget, privacy model |
| [docs/network.md](docs/network.md) | P2P protocol: sync flows, gossip, peer discovery, validation pipeline, consensus parameters |
| [docs/cli.md](docs/cli.md) | CLI reference, JSON-RPC API, configuration, deployment recipes |

---

## Crate Map

```
Cryptographic primitives
  noid_core          Binary tower GF(2^128), CLMUL/AVX2, MLE, NTT
  noid_poseidon2b    Poseidon2b — GF(2^128) native, AIR-friendly sponge
  noid_fri           FRI proximity test (Reed-Solomon over binary towers)
  noid_fri_binius    FRI-Binius PCS: compact interleaved FRI, source-bound mixed openings
  noid_gkr           FROST-GKR Kill-Shot: SpineGKR (59 perms) + AuthGKR (20 perms)
  noid_air           AIR definitions: TxLogicAir, RecursiveBlockAir, gates and composition AIRs
  noid_stark         STARK prover/verifier: algebraic interleaved, per-tx deferred FRI
  noid_block         prove_block / verify_block, BlockProof, reconstruction helpers
  noid_recursive     O(1) recursive chain proof: ChainAccumulator, prove/verify_tip

Chain layer
  noid_tx            Transaction types, PublicInputs, wire formats (spend_secret never on wire)
  noid_chain         Consensus, UTXO state, MDBX storage, DA pruning, wire limits, NativeDelta state

Node layer
  noid_mempool       Async mempool: proof-verification admission gate (semaphore-bounded), fee floor
  noid_miner         Parallel PoW + BlockProof generation orchestrator
  noid_p2p           libp2p: BlockGossipMsg, RecursiveProofGossipMsg, snapshot sync
  noid_rpc           jsonrpsee JSON-RPC server
  noid_node          paranoid binary (relay / miner / extminer modes) + noid-cli binary
  noid_extminer      noid-extminer binary (external PoW worker)
```

---

## Building

**Requirements:** Rust stable ≥ 1.75, x86-64 with AVX2 + CLMUL.

```bash
cargo build --release
cargo test
```

AVX2 and PCLMULQDQ (CLMUL) are available on all Intel/AMD processors made after 2013.
The optimized production path targets x86-64 AVX2 + PCLMULQDQ.

---

## License

Apache 2.0
