# Paranoid. Proof-Native Statechain.

---

The term "blockchain" describes a data structure, not the underlying mechanism. Satoshi originally designated the Bitcoin ledger a *Timechain*, reflecting that truth in such systems is strictly a function of time. Every major network since has inherited this paradigm — the present state cannot be verified without the past. Validating a current balance requires re-executing the entire history from genesis. This dependency condemns traditional chains to perpetual data bloat and inevitable centralization.

**Paranoid decouples truth from time.** We define our architecture as a *Proof-Native Statechain*. In this model, validity is established by mathematics, not chronology. A transaction is not an event in time pending network execution, but a self-contained mathematical proof of a correct state transition. Recursion in Paranoid collapses the time dimension: the entire history of the network from genesis reduces to a single **6.5 KB proof**. It is no longer necessary to store the past to validate the present. We have transitioned the ledger from a chronicle of events into a system of verifiable mathematics.

---

## What makes this different

| | Traditional chain | Paranoid |
|---|---|---|
| Validation | Re-execute everywhere | Verify proof once |
| History required | Yes — from genesis | No — 6.5 KB suffices |
| Signatures | ECDSA / EdDSA | None — ZK ownership proof |
| Quantum safety | No (discrete log) | Yes — hash-based only |
| State on spend | Grows forever | Cell freed, reusable |
| 51% attack | Spend others' coins | Choose ordering only |
| Full node sync | Download & replay N GBs | State snapshot + recursive proof |
| Light node sync | Trust a server / SPV | 6.5 KB download, ~5 ms verify |

---

## Architecture

```
wallet ──► LogicProof ──► mempool ──► full node ──► BlockProof ──► RecursiveProof
(local) (stateless) │ (6.5 KB, O(1) sync)
├─ BlockStateBinding (state proofs)
├─ deferred-FRI aggregation
└─ PoW seal (ordering)
```

The network never re-executes transactions. It verifies proofs of computation already correctly performed. Execution is local, state binding is server-side, and history is recursively compressed.

### Two-layer proof split

**LogicProof** — built by the wallet, ~26 KB
- Balance: `Σ inputs == Σ outputs + fee`
- Ownership: `Poseidon2b(spend_secret) == address` for each input
- Range: all values fit in 64 bits
- Body binding: `tx_body_hash` pinned cryptographically

The LogicProof is **stateless** — no Merkle paths, no dependency on the state root. Valid across block boundaries until the epoch anchor expires.

**BlockStateBinding** — built by the full node at block assembly
- Proves all input slots match `prev_state_root`
- Proves all output slots are empty
- Proves the new `state_root` is correctly computed
- Bridges LogicProof claims to actual state openings

**BlockProof** = N×LogicProofs + BlockStateBinding + deferred-FRI aggregation

**RecursiveProof** = Entire chain history compressed into a single 6.5 KB proof. New nodes sync by verifying this proof in ~5 ms. No history download. No archive nodes.

### FROST-GKR Kill-Shot

Paranoid's core cryptographic innovation. Hash proving — the most expensive component of any ZK system — was the bottleneck.

The standard approach requires decomposing Poseidon2b S-boxes into degree-2 layers: 8 sumchecks per permutation × 59+20 permutations = **4,248 Fiat-Shamir rounds** and >280 KB proof per transaction.

FROST-GKR exploits the Frobenius endomorphism in GF(2^128): squaring is linear, so `x^7 = x · x² · x⁴` needs 3 multiplications and 2 free squarings. This eliminates degree decomposition entirely. A single **unified degree-7 sumcheck** over all 59 permutations simultaneously, plus a Shift Gadget for the MDS transition, replaces 472 per-slot sumchecks.

| | Legacy (degree-2) | FROST-GKR Kill-Shot |
|---|---|---|
| Fiat-Shamir rounds | 4,248 | 30 |
| Proof size (hash component) | >280 KB | ~5.4 KB |
| Prover time | 1.63 s | 154 ms |
| Verifier time | 1.06 s | 69 ms |
| **Speedup** | — | **10.5× prove · 141× fewer rounds** |

Two Kill-Shot instances per transaction:
- **SpineGKR** — 59 permutations computing `tx_body_hash` from the tx body
- **AuthGKR** — 20 permutations computing `Address` and `AuthTag` per input

Both are single-transcript, single-sumcheck, bound into the STARK via `extra_transcript`. Any byte-level tamper forks every subsequent STARK challenge.

### Recursive accumulator

Every block extends a rolling Poseidon2b chain hash:
```
chain_hash_n = compress(chain_hash_{n−1}, H_BLOCK(header_n))
```
`COMPACT_TAU=8`, `log_rows=8` → zero FRI Merkle paths in the recursive proof. The entire chain history collapses into pure tensor algebra.

A new node verifies the entire chain history:
1. Download `RecursiveBlockProof` (**6.5 KB**)
2. `verify_tip(proof, prev_state_root, tip_height, genesis_acc)`
3. Cryptographic certainty over all history in **~5 ms**

---

## State model

The ledger is a flat array of `2^log_slots` cells:
```
slot[i] = (value, owner_hi, owner_lo)
```
An empty cell is canonical zero `(0, 0, 0)`. A live cell holds a UTXO.

**When a UTXO is spent, its cell returns to zero — the slot is freed and available for reuse.** State does not accumulate dead entries. Memory grows proportionally to *active* UTXOs, not total historical transactions.

**Automatic expansion:** when active UTXOs reach 75% of capacity, `log_slots` increments by 1. The trigger is computed identically by all nodes from the median of the last 18 `active_slot_count` values — no governance, no hard fork.

**Anti-spam economics:** block reward halves with each expansion. Filling slots to force an expansion immediately halves the attacker's own mining income.

| log_slots | Capacity | Block reward |
|---|---|---|
| 24 (genesis) | 16,777,216 | 50 NOID |
| 25 | 33,554,432 | 25 NOID |
| 26 | 67,108,864 | 12.5 NOID |
| 27 | 134,217,728 | 6.25 NOID |
| 28+ | … | … |
| 32 (max) | 4,294,967,296 | 1 NOID (floor) |

**Global commitment:** Poseidon2b Merkle over segment FRI roots. State is divided into `2^(log_slots − 16)` segments of 65,536 slots each, each independently FRI-committed. Zone-based allocator: sequential UTXOs land in the same segment, bounding active RAM to `O(active_UTXOs / 65536)` segments rather than all 256+.

---

## Keys and post-quantum security

There are no signatures in Paranoid. Ownership is proven entirely by ZK — a Poseidon2b hash chain.

The `SpendSecret` is **any 32 bytes of your choice**: random bytes, a photo (stripped of metadata), a document hash, a passphrase hash. The wallet derives addresses from it:

```
Address = Poseidon2b(spend_secret, index)
```

Spending requires proving knowledge of the `spend_secret` whose hash equals the stored address. This is proven by the AuthGKR Kill-Shot — a ZK proof of Poseidon2b preimage. No elliptic curves. No discrete logarithm. **Post-quantum by construction.**

Multiple addresses from one secret:
```
address_0 = Poseidon2b(master_secret, 0)
address_1 = Poseidon2b(master_secret, 1)
...
```

---

## Proof-of-Work

**Algorithm:** Blake3 over the 276-byte block header. 128-bit nonce.

PoW in Paranoid serves exclusively as an ordering mechanism: it picks the canonical sequence of valid state transitions. Execution correctness is already established by the proof. A 51% miner can choose ordering — they cannot fake proofs.

**Why Blake3:** CPU-friendly (~1 GH/s on any laptop), nanosecond verification. Block withholding protection: coinbase is locked inside `witness_root → proof_transcript_hash → BlockProof`. An external miner cannot steal a block without regenerating the proof (~9s CPU — longer than PoW at target difficulty).

**Difficulty:** ASERT, 6-block epoch (360 s halflife). Adapts to any hashrate change within ~6 minutes.

| Parameter | Value |
|---|---|
| Block time target | 60 s |
| ASERT halflife | 360 s |
| Finality depth | 18 blocks |
| Epoch anchor window | 144 blocks |
| Header size | 276 bytes |
| Nonce width | 128 bits |

---

## Performance

**Per transaction (2 inputs / 4 outputs):**

| | Standard (2in/4out) | Max (4in/8out) |
|---|---|---|
| Wallet prove (median) | **135–141 ms** | **135–139 ms** |
| Wallet prove (cold) | ~135 ms | ~135 ms |
| Mempool verify | ~76 ms | ~77 ms |
| Proof size | 26.3 KB | 26.3 KB |
| — STARK | 21.2 KB (81%) | 21.2 KB |
| — AuthGKR Kill-Shot | 5.1 KB (19%) | 5.1 KB |

Proof size is **constant** regardless of input/output count.

**Block production (full node, 8 cores):**

| Block size | Prove time | Verify time | Proof size | Per-tx amortized |
|---|---|---|---|---|
| 10 txs | 994 ms | 286 ms | 213 KB | 99 ms / 29 ms |
| 20 txs | 1.94 s | 531 ms | 410 KB | 97 ms / 27 ms |
| 100 txs | **8.99 s** | 2.46 s | 1.92 MB | 90 ms / 25 ms |

Wallet-side TxIntent preparation (trace + AuthGKR, ~82 ms) is **not in the block-time budget** — it happens on the user's device before submission. The full node never re-does wallet work.

---

## No block history

Paranoid does not store block history. Blocks older than 18 are deleted immediately after finalization. Only the last 18 blocks are retained for reorg handling. All block headers (276 bytes each) are kept permanently as a lightweight chain proof — this is sufficient to reconstruct the recursive accumulator state at any point.

New nodes sync by downloading the **current state snapshot** from a peer, verified against the recursive proof. No genesis replay. No download of years of history.

**Storage per year (1 block/min, moderate TX volume):**
- Block headers (permanent): ~145 MB
- Active state (zone-based): 3 MB per 65,536 live UTXOs
- Recent blocks (last 18, rotating): ~18 KB constant
- Nullifier window (anti-replay, 144 blocks): ~few KB
- RAM: ~60–85 MB (jemalloc, small-state node)

---

## Node types

### Full node

```bash
# First node on a new network (genesis bootstrap)
paranoid --mine --genesis \
  --p2p-listen /ip4/0.0.0.0/tcp/9301 \
  --rpc-listen 127.0.0.1:9401

# Join an existing network, mine after sync
paranoid --mine \
  --seeds /ip4/<peer>/tcp/9301 \
  --p2p-listen /ip4/0.0.0.0/tcp/9301 \
  --rpc-listen 127.0.0.1:9401

# Full node without mining
paranoid \
  --seeds /ip4/<peer>/tcp/9301 \
  --rpc-listen 127.0.0.1:9401
```

Syncs automatically when connecting to peers: downloads state snapshot, catches up on recent blocks, then begins (if `--mine`) or validates.

### Light node (wallet)

Downloads the recursive proof (~6.5 KB) and latest header. Verifies the full chain in ~5 ms. Generates LogicProofs locally (~135 ms). Queries a full node for slot indices and epoch anchors only.

---

## CLI

```bash
noid-cli status                   # height, best hash, difficulty, active slots
noid-cli mempool                  # pending TXs, fee floor
noid-cli stop                     # graceful shutdown

noid-cli address                  # primary address
noid-cli balance                  # confirmed balance + UTXO count
noid-cli send <addr> <μNOID>      # fee=0 → auto-calculated
noid-cli history                  # confirmed TX history
noid-cli utxos                    # all owned UTXOs with slot indices
noid-cli scan                     # full rescan from state (after import/restore)
noid-cli receipt <txhash>         # export Merkle inclusion proof
noid-cli consolidate              # merge small UTXOs into fewer large ones
```

All commands connect to the daemon at `http://127.0.0.1:9401` by default. Override with `--rpc <url>`.

**Fee:** `MIN_FEE = 5000 μNOID + 2000 μNOID × n_outputs`. Default `--fee 0` auto-computes the correct minimum including the current dynamic mempool floor.

**1 NOID = 1,000,000 μNOID.**

---

## RPC (JSON-RPC 2.0, default port 9401)

```
paranoid_getChainInfo
paranoid_getHeaderByHeight / ByHash
paranoid_getBlock                       # last 18 blocks only
paranoid_getSlot / getActiveSlotCount
paranoid_getSlotHints / getEpochAnchor
paranoid_submitTxIntent
paranoid_getMempoolInfo / getMempoolSize
paranoid_getRecursiveProof              # 6.5 KB chain validity proof
paranoid_verifyReceipt
paranoid_walletSend / walletBalance / walletHistory
paranoid_walletScan / walletListUtxos / walletConsolidate
paranoid_walletExportReceipt
paranoid_stop
```

Full reference: [`API.md`](API.md)

---

## Security

**What ZK proofs establish:**
- Spender knows the preimage of the input address (AuthGKR, ~120-bit soundness)
- Balance conservation and range validity
- State root correctly computed from claimed slot transitions
- `tx_body_hash` binding prevents cross-transaction replay of proof artifacts

**What PoW establishes:**
- Canonical ordering of valid transitions
- Sybil resistance for block proposal
- Reorg cost proportional to cumulative work

**What 51% hashpower cannot do:**
- Forge a valid proof for slots the attacker does not own
- Produce a `state_root` inconsistent with actual transitions
- Spend UTXOs without knowing the spend secret

**Replay protection:** `epoch_anchor` — a recent block hash committed inside the tx body hash and therefore inside the ZK proof. Transactions expire after ~144 blocks.

**Block withholding:** coinbase address is bound inside `BlockProof`. An external miner cannot substitute their address without regenerating the entire block proof — a multi-second CPU operation they cannot perform faster than the PoW.

---

## Crate map

```
Cryptographic core:
  noid_poseidon2b    Poseidon2b — native GF(2^128), address / auth-tag derivation
  noid_core          Binary tower GF(2^128), MLE, CLMUL / AVX2 ops
  noid_fri           FRI proximity test
  noid_fri_binius    FRI-Binius: binary tower PCS, compact FRI (zero Merkle paths)
  noid_gkr           FROST-GKR Kill-Shot: SpineGKR + AuthGKR
  noid_air           AIR definitions: TxLogicAir, BlockStateBindingAir
  noid_stark         STARK prover/verifier, interleaved block aggregation
  noid_binius        Binius DA witness packing
  noid_block         prove_block / verify_block (BlockProof)
  noid_recursive     Recursive accumulator: O(1) chain verification

Chain:
  noid_tx            Transaction types, PublicInputs, wire formats
  noid_chain         Consensus rules, UTXO state, MDBX storage, DA pruning

Node:
  noid_mempool       Async mempool: ZK admission (semaphore-bounded), fee floor
  noid_miner         Parallel PoW + ZK prove orchestrator
  noid_p2p           libp2p: gossipsub block/TX relay, state snapshot sync
  noid_rpc           jsonrpsee JSON-RPC server
  noid_node          paranoid binary
```

---

## Building

**Requirements:** Rust stable ≥ 1.75, x86-64 with AVX2.

```bash
cargo build --release
cargo test --release
```

---

## License

Apache 2.0
