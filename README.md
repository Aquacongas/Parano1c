# Paranoid — Proof-Native UTXO Statechain

> The entire history of the network from genesis fits in **6.5 KB**.  
> A new node verifies it cryptographically in **~5 ms**.  
> No archive nodes. No history replay. No signatures.

---

Blockchains have a fundamental architectural flaw: to validate the present, you must replay the past. Every major network inherits this property, full nodes download and re-execute every transaction back to genesis. This isn't a temporary limitation; it is baked into the model.

Paranoid removes this requirement entirely.

In Paranoid, validity is established once, locally, by the party with the most information — the wallet owner. The result is a cryptographic proof that the network verifies without re-executing. Recursive composition collapses the entire chain history into a single compact proof. The present can be verified without the past. **Truth is a function of mathematics, not time.**

---

*All timing figures measured on an Intel Core i7-1365U (laptop 10 cores, 2023).*

## The Fundamental Shift

| | Traditional Chain | Paranoid |
|---|---|---|
| Validation model | Re-execute everywhere | Verify proof once |
| Full sync | Replay N GB of history | State snapshot + 6.5 KB proof, ~5 ms |
| History required to validate | Yes. From genesis | No |
| Signatures | ECDSA / EdDSA | None. ZK ownership proof |
| Quantum safety | No (discrete log problem) | Yes. Hash-only primitives |
| 51% attack capability | Spend others' coins | Choose ordering only |
| State growth | Spent outputs accumulate forever | Spent outputs removed; slots freed and reused |
| Block proofs | None. Trust replays | `verify_block()` on every node |

A 51% miner in Paranoid can only choose the ordering of valid transitions. They cannot forge proofs. They cannot spend coins they do not own. The ZK layer is the security boundary; PoW is the ordering mechanism.

---

## How It Works

### Execution is Local

When you send NOID, your wallet builds a **LogicProof**. A ~26 KB STARK that proves:
- You know the secret behind the input address (`Address = Poseidon2b(spend_secret)`)
- Inputs equal outputs plus fee
- All values are in range
- The transaction body is cryptographically bound

This proof is **stateless**: no Merkle paths, no dependency on the current state root. It is valid across block boundaries until the epoch anchor expires (~28 minutes). You prove it once, on your device, ~140 ms for 4 inputs/8 outputs tx

### The Network Verifies, Not Executes

Every full node independently verifies the ZK proof of each block it receives. A `BlockProof` covers:
- All per-transaction LogicProofs (via interleaved STARK aggregation)
- State binding: that input slots held the claimed values and output slots were empty
- Correct computation of the new `state_root`
- A single unified FRI opening over all columns of all transactions

The full node never re-runs the wallet logic. It verifies the proof that the wallet already produced.

### History Collapses Recursively

Every block extends a rolling accumulator:

```
chain_hash_n = Poseidon2b_compress(chain_hash_{n-1}, H_BLOCK(header_n))
```

The recursive proof proves that this accumulator was correctly computed from genesis, and that the current `state_root` is the result. It is a single STARK over a 256-row trace — constant size regardless of chain length.

**Result:** A new node downloads:
1. The current **state snapshot**. Only populated FRI segments (~3 MB each,
   one per 65,536 UTXOs; scales with UTXO set size)
2. The **RecursiveProof** (6.5 KB)
3. Calls `verify_tip()` → cryptographic certainty over the full history in ~5 ms

No genesis replay. No archive nodes. No trust assumption.

---

## Cryptographic Architecture

*This section is aimed at ZK engineers. Skip to [Running Paranoid](#running-paranoid) if you just want to use it.*

### Field: Binary Tower GF(2^128)

All arithmetic runs over `GF(2^128)` in the **binary tower** representation. Multiplication is `CLMUL` on x86 (one instruction, ~1ns); addition is XOR. The field naturally supports the Frobenius endomorphism (`x → x²` is linear over GF(2) — free squaring, no multiplications).

Poseidon2b is a native GF(2^128) permutation: S-box is `x^7 = x · x² · x⁴` with the MDS matrix operating over the tower. The AIR and all proof systems operate over the same field — no field extension towers, no splitting.

### Polynomial Commitment: FRI-Binius

The PCS is **FRI-Binius** — Reed-Solomon over binary towers with compact interleaved FRI. Key properties:

- **COMPACT_TAU = 8** with `log_rows = 8`: the recursive RecursiveBlockAir has exactly **zero FRI Merkle paths**. The recursive proof is pure sumcheck algebra.
- **Interleaved commitment**: all columns across all transactions in a block are committed jointly in a single Merkle cap. One FRI opening covers all of them (the `mixed_multipoint_close`).
- **Segmented state PCS**: the UTXO state is divided into independent 2^16-slot segments, each with its own FRI commitment. Only dirty segments are re-committed per block.

### FROST-GKR Kill-Shot

This is Paranoid's core cryptographic innovation. Poseidon2b proving is the bottleneck in every ZK system using it. The standard approach decomposes S-box constraints into degree-2 layers:

```
Standard: 8 sumcheck rounds per permutation × (59 + 20) permutations = 632 rounds
          → 4,248 Fiat-Shamir challenges, >280 KB proof per transaction
```

FROST-GKR exploits the Frobenius endomorphism in GF(2^128):

```
x^7 = x · x² · x⁴
        ↑    ↑    ↑
     1 mult  free  free   (squaring is linear over GF(2))
```

S-box evaluation requires only **3 multiplications** (+ 2 free squarings). This makes it natively degree-7, eliminating all degree decomposition. A single **unified degree-7 sumcheck** runs over all 59 (or 20) permutations simultaneously. The MDS matrix transition is handled by a **Shift Gadget** — a bounded-degree polynomial over the permutation state that folds into the same sumcheck.

The result is a single Kill-Shot proof per GKR instance:

| | Legacy degree-2 GKR | FROST-GKR Kill-Shot |
|---|---|---|
| Fiat-Shamir rounds | 4,248 | **30** |
| Proof size (hash component) | >280 KB | **~5.1 KB** |
| Full GKR prover time\* | 1.63 s | **154 ms** |
| Full GKR verifier time\* | 1.06 s | **69 ms** |
| **Speedup** | — | **10.6× faster · 141× fewer rounds** |

\*Full GKR layer = SpineGKR (59 perms, block-side) + AuthGKR (20 perms, wallet-side).
The wallet `prove_logic` alone (AuthGKR + TxLogicAir STARK) runs in **~144 ms**.

**Two Kill-Shot instances per transaction:**
- **SpineGKR** (59 permutations) — computes `tx_body_hash` from the full transaction body. Binds every field of every input and output into a single 32-byte hash that the STARK pins.
- **AuthGKR** (20 permutations) — computes `Address[i]` and `AuthTag[i]` per input. Proves ownership and replay protection in one unified circuit.

Both are single-transcript, bound into the per-tx STARK via `extra_transcript`. Any byte-level tamper forks every subsequent Fiat-Shamir challenge.

### Three-Level Proof Stack

```
┌─────────────────────────────────────────────────────────────┐
│  RecursiveProof  ·  6.5 KB  ·  O(1) verify  ·  ~5 ms       │
│  RecursiveBlockAir: 8×8-row trace, COMPACT_TAU=8            │
│  Proves: accumulator continuity from genesis to h=N         │
└──────────────────────┬──────────────────────────────────────┘
                       │ each step wraps ↓
┌──────────────────────▼──────────────────────────────────────┐
│  BlockProof  ·  ~26 KB per tx  ·  O(txs) verify            │
│  = N × TxLogicAir STARKs (algebraic, no FRI per tx)        │
│  + SpineGKR Kill-Shot (unified over all txs in block)       │
│  + N × AuthGKR Kill-Shot (per-tx ownership)                 │
│  + BlockStateBindingAir (slot state transitions, per seg)   │
│  + single mixed FRI opening (all columns, all txs)          │
└──────────────────────┬──────────────────────────────────────┘
                       │ wallet produces ↓
┌──────────────────────▼──────────────────────────────────────┐
│  LogicProof  ·  ~26 KB  ·  stateless  ·  ~140 ms prove     │
│  TxLogicAir: balance + range + ownership binding            │
│  AuthGKR Kill-Shot: ZK proof of spending secret preimage          │
│  Stateless: no Merkle paths, no state_root dependency       │
└─────────────────────────────────────────────────────────────┘
```

**Stateless / stateful proof separation:** The LogicProof is created by the wallet — the only party that knows the spending secret. It is stateless and valid until the epoch anchor expires. The BlockStateBinding is created by the block producer from the public transaction body: it proves that the claimed slot values are consistent with the actual FRI state root. The `C_claimed` bridge commits the LogicProof's slot claims to the BlockStateBinding's slot openings, so neither layer can lie about the state.

### Deferred FRI Aggregation

All per-transaction STARK traces share a single Merkle commitment (the `InterleavedCommitment`). Instead of per-tx FRI openings, the block prover runs a **block-level multipoint sumcheck** that reduces all terminal claims to a single evaluation point `r_block`. One FRI-Binius mixed opening closes everything simultaneously.

Block proof size scales as `O(log N)` in the FRI layer and `O(N)` in the algebraic layer — not `O(N × per-tx FRI)`.

---

## State Model

The UTXO state is a flat array of `2^log_slots` slots:

```
slot[i] = { value: u64, owner_hi: [u8;16], owner_lo: [u8;16] }
```

An empty slot is canonical zero `(0, 0, 0)`. Spending a UTXO zeros its slot — **the slot is immediately available for reuse**. There are no stale entries — spent outputs leave no residue in the state. State size is proportional to the UTXO set, not transaction history.

### Segmented FRI Commitment

State is divided into independent **2^16-slot segments** (65,536 slots each), each with its own FRI Merkle root. The global `state_root = Poseidon2b_Merkle(seg_roots[])`. Only segments modified by a block are re-committed. The zone-based allocator places sequential outputs in the same segment, bounding the number of dirty segments per block.

Only **populated segments** are stored and transmitted. Each segment costs ~3 MB on disk (3 FRI-committed columns × 65,536 × 16 bytes). A node with 100,000 UTXOs holds ~2 populated segments ≈ 6 MB of state, regardless of `log_slots` capacity. Snapshot size grows with UTXO set size, not with total slot capacity.

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

There are no digital signatures in Paranoid. Ownership is proven entirely by ZK — a Poseidon2b hash preimage proof over GF(2^128).

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
| FRI-Binius PCS | 128 bits | **128 bits** | Information-theoretic (64q × log₂(rate-4)); quantum-invariant by proof |
| STARK / GKR sumcheck | ~128 bits | **~128 bits** | Schwartz–Zippel over GF(2¹²⁸); quantum-invariant by proof |
| Poseidon2b preimage | 256 bits | **128 bits** | Grover: O(√2²⁵⁶); **PQ < classical** |
| Blake3 / Poseidon2b collision | 128 bits | **~128 bits** | Grover on 2nd-preimage; BHT collision is O(2⁸⁵) but requires O(2⁸⁵) QRAM (impractical) |
| **System min** | **128 bits** | **128 bits** | |

The algebraic layers (FRI proximity, sumcheck, GKR) are **information-theoretic** — their
soundness bound holds against any prover, classical or quantum, by the Schwartz–Zippel lemma.
This is proven, not assumed.

For hash-based components: post-quantum security is indeed lower than classical for Poseidon2b
preimage (256 → 128 bits via Grover). The overall system minimum stays at 128 bits because the
algebraic layer already caps classical security at 128 bits by design (FRI parameter choice).

The 128-bit PQ claim holds under standard quantum circuit model (NIST assumption). The
theoretical BHT collision attack (O(2⁸⁵) quantum) requires O(2⁸⁵) QRAM cells — hardware that
does not exist and may never be physically realizable at that scale.

---

## Proof-of-Work: Ordering, Not Security

PoW in Paranoid has a single job: **ordering**. It picks the canonical sequence of valid state transitions. Block validity is already established by the proof system.

**Algorithm:** Blake3 over the 276-byte block header. 128-bit nonce. CPU-friendly (~1 GH/s on any laptop), nanosecond verification.

**Why Blake3:** block withholding protection is built into the proof structure. The coinbase address is bound inside `witness_root → proof_transcript_hash → BlockProof`. An external miner cannot substitute their payout address without regenerating the entire block proof (multi-second CPU operation — longer than the PoW at genesis difficulty).

**Difficulty:** ASERT algorithm (Bitcoin Cash variant), 6-block epoch, 72-second halflife. Responds to any hashrate change within ~6 minutes. Floor: difficulty never eases below genesis target — ASERT can only move harder.

| Parameter | Value |
|---|---|
| Block time target | 12 s |
| Genesis difficulty | 2^229 |
| ASERT halflife | 72 s (6 epochs × 12 s) |
| Finality depth | 18 blocks |
| Epoch anchor window | 144 blocks |
| Header size | 276 bytes |
| Nonce width | 128 bits |

---

## Security Model

**What ZK proofs guarantee:**
- Spender knows the Poseidon2b preimage of the input address (128-bit soundness, Schwartz–Zippel over GF(2¹²⁸))
- Balance is conserved; all values are in range
- State root is correctly computed from the claimed slot transitions
- `tx_body_hash` binding prevents cross-transaction replay of proof artifacts
- Every block received by a full node is ZK-verified before being applied

**What PoW guarantees:**
- Canonical ordering of valid transitions
- Sybil resistance for block proposal
- Reorg cost proportional to cumulative work (FINALITY_DEPTH = 18 blocks)

**What 51% hashpower cannot do:**
- Forge a valid proof for slots the attacker does not own
- Produce a `state_root` inconsistent with actual transitions
- Spend outputs without knowing the spending secret
- Fabricate a valid RecursiveProof (requires solving the underlying ZK hardness assumption)

**Snapshot sync security:** new nodes verify the RecursiveProof before accepting a snapshot. A malicious peer cannot serve a fabricated snapshot — the STARK verification would fail. Multiple peers are queried for Eclipse resistance; RecursiveProof STARK is unforgeable.

**Replay protection:** `epoch_anchor` — a recent block hash committed inside the tx body hash and therefore inside all ZK proofs. Transactions expire after ~144 blocks.

---

## No Block History

Paranoid does not store block history. After FINALITY_DEPTH (18 blocks), full block data
and BlockProofs are pruned. Only block **headers** (276 bytes each) are kept permanently.

**Permanent storage:**
| Data | Size |
|---|---|
| Headers | ~145 MB/year (276 bytes × every block, forever) |
| UTXO set | ~3 MB per 65,536 unspent outputs (populated segments only) |
| Recursive proof | 6.5 KB (single entry, overwritten on each advance) |

**Temporary storage (pruned after 18 blocks):**
| Data | Size |
|---|---|
| Block bytes | 276-byte header (fixed) + tx bodies: ~530 B (coinbase-only) – ~750 KB (1024 txs) |
| BlockProofs | 0 (coinbase-only) – ~19 MB per block at max capacity (1024 txs) |
| Undo logs | ~few KB per block |
| Nullifier window | ~few KB (last 144 blocks) |

At any given time the node holds at most 18 blocks’ worth of block data + BlockProofs.
A network at full capacity (1024 txs/block) peaks at ~18 × 20 MB ≈ 360 MB of temporary
storage before pruning (750 KB block + ~19 MB BlockProof per block).

| RAM | ~60–120 MB (jemalloc, small-state node) |

---

## Performance

**Per transaction (wallet, 2 inputs / 4 outputs):**

| Metric | Value |
|---|---|
| Wallet prove time | ~140 ms |
| Mempool verify time | ~76 ms |
| LogicProof size | ~26.3 KB |
| — STARK component | ~21.2 KB (81%) |
| — AuthGKR Kill-Shot | ~5.1 KB (19%) |

Proof size is **constant** regardless of input/output count (always 4 inputs, 8 outputs in the circuit; unused input/output positions are padded with dummy witnesses).

**Block production (laptop i7-1365U, 10 threads):**

| Block | Prove time | Verify time | BlockProof size |
|---|---|---|---|
| 10 txs | ~1.0 s | ~290 ms | ~213 KB |
| 20 txs | ~1.9 s | ~530 ms | ~410 KB |
| 100 txs | ~9.0 s | ~2.5 s | ~1.9 MB |
| 1024 txs (max) | ~90 s | ~25 s | ~19 MB |

PoW search and ZK proving run **in parallel**. BlockProof bytes are stored only for the **last 18 blocks** (reorg window), then pruned.

The ~19 MB full-block proof does not accumulate on disk. What persists forever is the
**RecursiveProof** (6.5 KB) — a single entry that is overwritten with each advance and
proves the entire chain history from genesis.

**Recursive proof:** ~2 s to prove one step (laptop i7-1365U), **~5 ms to verify the entire chain**.

---

## Running Paranoid

### Node Modes

```
--mode relay     Full node, no mining (default).
                 Verifies all blocks, serves snapshots, relays txs.
                 Suitable for: exchanges, explorers, infrastructure.

--mode miner     Internal PoW + ZK prover.
                 Mines blocks with the built-in wallet as coinbase.

--mode extminer  Serves block templates to noid-extminer clients.
                 Node does ZK proving; external processes do PoW.
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

# --- Mining pool (node does ZK proving; external miners do PoW) ---
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
3. Verifies the proof cryptographically (O(1), ~5 ms)
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
noid-cli send <addr> <μNOID>  # --fee 0 auto-computes minimum
noid-cli history         # confirmed TX history
noid-cli consolidate     # merge small UTXOs
noid-cli receipt <hash>  # export inclusion proof (Merkle + ZK)
noid-cli scan            # rescan state (after wallet restore)

# Node
noid-cli stop            # graceful shutdown
```

Connect to `http://127.0.0.1:9401` by default. Override with `--rpc <url>`.

**Fee formula:** `5000 μNOID base + 2000 μNOID × n_outputs`. Default `--fee 0` auto-computes the correct minimum.  
**1 NOID = 1,000,000 μNOID.**  
**Addresses:** bech32m, prefix `noid1`.

---

## JSON-RPC (port 9401)

```
paranoid_getChainInfo
paranoid_getHeaderByHeight / ByHash
paranoid_getBlock                     (last 18 blocks only)
paranoid_getSlot / getActiveSlotCount
paranoid_getSlotHints / getEpochAnchor
paranoid_submitTxIntent
paranoid_getMempoolInfo / getMempoolSize
paranoid_getRecursiveProof            (6.5 KB chain validity proof)
paranoid_verifyReceipt
paranoid_walletSend / walletBalance / walletHistory
paranoid_walletScan / walletListUtxos / walletConsolidate
paranoid_walletExportReceipt
paranoid_stop
paranoid_getBlockTemplate             (extminer mode only)
paranoid_submitBlock                  (extminer mode only)
```

---

## Crate Map

```
Cryptographic primitives
  noid_core          Binary tower GF(2^128), CLMUL/AVX2, MLE, NTT
  noid_poseidon2b    Poseidon2b — GF(2^128) native, AIR-friendly sponge
  noid_fri           FRI proximity test (Reed-Solomon over binary towers)
  noid_fri_binius    FRI-Binius PCS: compact interleaved FRI, COMPACT_TAU
  noid_gkr           FROST-GKR Kill-Shot: SpineGKR (59 perms) + AuthGKR (20 perms)
  noid_air           AIR definitions: TxLogicAir, BlockStateBindingAir, RecursiveBlockAir
  noid_stark         STARK prover/verifier: algebraic interleaved, per-tx deferred FRI
  noid_block         prove_block / verify_block, BlockProof, reconstruction helpers
  noid_recursive     O(1) recursive chain proof: ChainAccumulator, prove/verify_tip

Chain layer
  noid_tx            Transaction types, PublicInputs, wire formats (spend_secret never on wire)
  noid_chain         Consensus, UTXO state, MDBX storage, DA pruning, state binding

Node layer
  noid_mempool       Async mempool: ZK admission gate (semaphore-bounded), fee floor
  noid_miner         Parallel PoW + ZK prover orchestrator
  noid_p2p           libp2p: BlockGossipMsg, RecursiveProofGossipMsg, snapshot sync
  noid_rpc           jsonrpsee JSON-RPC server
  noid_node          paranoid binary (relay / miner / extminer modes)
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
Apple Silicon (AArch64) and Linux ARM support is planned.

---

## License

Apache 2.0
