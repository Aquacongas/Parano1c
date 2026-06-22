# PARANOID. The Proof-Native Transparent UTXO Statechain

> The proof of the entire chain history from genesis fits in **~38 KB**. Verification **~5 ms**.  
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
| Full sync | Replay N GB of history | State snapshot + ~38 KB recursive proof; proof verification ~5 ms |
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
2. The **RecursiveProof** (~38 KB)
3. Verifies the recursive proof in ~5 ms, then applies the authenticated snapshot segments

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
x^7 = x · x² · x⁴
        ↑    ↑    ↑
     1 mult  free  free   (squaring is linear over GF(2))
```

S-box evaluation requires only **3 multiplications** (+ 2 free squarings). This makes the S-box natively degree-7 — no auxiliary columns, no degree-2 decomposition needed. A single **unified sumcheck** (round polynomial degree 9: eq × selector × s_in⁷) runs over all 59 (or 20) permutations simultaneously. The MDS matrix transition is handled by a **Shift Gadget** — a bounded-degree polynomial over the permutation state that folds into the same sumcheck.

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
│  RecursiveProof  ·  ~38 KB ·  O(1) verify · ~5 ms (laptop) │
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

Your **spending secret** is any 32 bytes: random, a passphrase hash, anything. The wallet derives addresses:

```
Address_n = Poseidon2b(spend_secret, n)   // index n for multiple addresses
AuthTag   = Poseidon2b(spend_secret, tx_body_hash)   // per-tx replay protection
```

To spend, the wallet proves knowledge of the `spend_secret` whose hash equals the stored address. This is proven by the AuthGKR Kill-Shot. The spending secret never leaves the device — it is used to compute a proof, then zeroed from memory.

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

**Algorithm:** Blake3 over the 212-byte `header_core` PoW input. The full 276-byte header hash still commits `proof_transcript_hash` and `witness_root` for chain linking, while PoW and BlockProof generation can run in parallel. 128-bit nonce. CPU-friendly and cheap to verify.

**Why Blake3:** block withholding protection is built into the proof structure. The coinbase address is bound inside `witness_root → proof_transcript_hash → BlockProof`. An external miner cannot substitute their payout address without regenerating the entire block proof before PoW search can be valid.

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

Paranoid does not store block history. After FINALITY_DEPTH (18 blocks), full block data,
BlockProofs, and public Auth sidecars are pruned. Only block **headers** (276 bytes each) are kept permanently.

**Permanent storage:**
| Data | Size |
|---|---|
| Headers | ~553 MB/year (276 bytes × every block, forever) |
| UTXO set | ~3 MB per 65,536 unspent outputs (populated segments only) |
| Recursive proof | ~38 KB encoded (single entry, overwritten on each advance) |

**Temporary storage (pruned after 18 blocks):**
| Data | Size |
|---|---|
| Block bytes | 276-byte header (fixed) + tx bodies: ~530 B (coinbase-only) – ~192 KB (256 txs) |
| BlockProofs + public Auth sidecars | 0 (coinbase-only); user-tx proof size depends on shape mix and tx count |
| Undo logs | ~few KB per block |
| Nullifier window | ~few KB (last 144 blocks) |

At any given time the node holds at most 18 blocks' worth of block data + BlockProofs + public Auth sidecars. These bytes are retained only for the reorg/sync window, not permanent history. In the current `block_scaling` bench, 100 Standard4x8 transactions produce a 7.62 MB `BlockProof` and an 8.11 MB public Auth sidecar on a 2023 Intel Core i7-1365U laptop.

| RAM | ~60–120 MB (jemalloc, small-state node) |

---

## Performance

Measured on a 2023 Intel Core i7-1365U laptop, release/bench profile, production proof paths; no mock/native shortcuts.

Wallet proof benchmark (`cargo bench --bench alice_sends_bob`):

| Scenario | Prove median | Verify median | Wallet bundle | Logic proof | STARK | AuthGKR |
|---|---:|---:|---:|---:|---:|---:|
| Standard4x8, 1 input / 2 outputs | 92.61 ms | 24.68 ms | 236.24 KB | 234.53 KB | 151.94 KB | 82.59 KB |
| Standard4x8, 4 inputs / 8 outputs | 89.41 ms | 24.60 ms | 235.79 KB | 234.08 KB | 151.50 KB | 82.58 KB |
| Sweep25x2, 5 inputs / 2 outputs | 374.72 ms | 95.44 ms | 214.08 KB | 209.42 KB | 96.50 KB | 112.92 KB |
| Sweep25x2, 10 inputs / 2 outputs | 371.38 ms | 97.76 ms | 215.11 KB | 210.45 KB | 97.27 KB | 113.19 KB |
| Sweep25x2, 25 inputs / 2 outputs | 372.33 ms | 111.54 ms | 214.94 KB | 210.28 KB | 96.19 KB | 114.09 KB |
| Sweep25x2 consolidation, 25 inputs / 1 output | 394.71 ms | 109.60 ms | 216.63 KB | 211.97 KB | 96.89 KB | 115.08 KB |

Logical split compositions from the same run:

| Composition | Prove total | Verify total | Bundle total | Logic total |
|---|---:|---:|---:|---:|
| 26 inputs: Sweep25x2(25) + Standard4x8 tail | 464.93 ms | 136.22 ms | 451.18 KB | 444.81 KB |
| 50 inputs: Sweep25x2(25) + Sweep25x2(25) | 744.65 ms | 223.08 ms | 429.88 KB | 420.56 KB |

Selected block scaling rows (`cargo bench --bench block_scaling`, up to 100 transactions shown here). Wallet proofs are pre-built for block timing; wallet pre-proof time is reported separately by the bench and is not block-time work.

| Block proof path | Prove full block | Verify full block | BlockProof | Auth sidecar | BlockProof + sidecar |
|---|---:|---:|---:|---:|---:|
| 10 × Standard4x8 | 2.37 s | 542.39 ms | 2.24 MB | 828.17 KB | 3.04 MB |
| 20 × Standard4x8 | 3.95 s | 960.62 ms | 2.85 MB | 1.62 MB | 4.47 MB |
| 100 × Standard4x8 | 14.26 s | 4.10 s | 7.62 MB | 8.11 MB | 15.73 MB |
| 1 × Sweep25x2 | 810.01 ms | 224.44 ms | 656.85 KB | 113.84 KB | 770.69 KB |
| 4 × Sweep25x2 | 2.14 s | 509.76 ms | 1.96 MB | 452.74 KB | 2.40 MB |
| 10 × Sweep25x2 | 3.97 s | 1.06 s | 2.70 MB | 1.11 MB | 3.81 MB |
| 8 Standard4x8 + 2 Sweep25x2 | 3.53 s | 771.87 ms | 2.95 MB | 891.25 KB | 3.82 MB |
| 5 Standard4x8 + 5 Sweep25x2 | 4.05 s | 917.24 ms | 3.73 MB | 985.12 KB | 4.70 MB |

PoW search and BlockProof generation run **in parallel**. BlockProof bytes and public Auth sidecars are stored only for the **last 18 blocks** (reorg window), then pruned.

Full-block proofs do not accumulate on disk. What persists forever is the **RecursiveProof** (~38 KB encoded) — a single entry that is overwritten with each advance and proves the entire chain history from genesis.

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
3. Verifies the proof cryptographically (O(1), ~5 ms (laptop))
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
paranoid_getRecursiveProof            (~76 KB hex for ~38 KB recursive chain proof)
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
