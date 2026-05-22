# PARANOID — ROADMAP

From current implementation state to public testnet.

---

## Current State (Baseline)

The cryptographic engine is complete and tested:

```
noid_core         GF(2^128) tower, CLMUL/AVX2, MLE, sumcheck, NTT, transcript.
noid_poseidon2b   Poseidon2b native + AIR (perm, sponge, domain tags, compress).
noid_fri          Generic FRI (legacy, used by IVC).
noid_fri_binius   Production PCS: interleaved commit, compact FRI, mixed opening.
noid_binius       Bit/byte packing for DA bandwidth reduction.
noid_gkr          Kill-Shot GKR: Spine (59-slot), Auth (20-slot), Merkle (32-slot).
noid_air          AIRs + gates + compositions. Production: tx_validity_with_spine.
noid_stark        STARK engine: prove_tx / verify_tx (Spine→Auth→STARK).
noid_ivc          Linear folding accumulator.
noid_tx           TxBody, PublicInputs, wire serialization.
noid_chain        State (FriState), block header, blocks, DA packing, wire encoding.
noid_block        Block aggregation via deferred-opening (prove_block / verify_block).
bench_prover      Performance harness.
```

Performance (per-tx, 8 thread, measured):
- Prove: 725 ms | Verify: 145 ms | Size: 55.5 KB

What exists: proof math, state machine, block aggregation, IVC, wire formats.
What does NOT exist: networking, mempool, RPC, wallet CLI, mining, difficulty adjustment, consensus validation, node binary.

---

## Phase 1 — Stateless Architecture (Stage S)

**Goal:** Separate wallet-side logic proof from full-node-side state binding.
Light Node (wallet) proves only math (balance, auth, body).
Full Node proves state (Merkle openings, BlockStateBinding) and assembles BlockProof.
External Miner receives 248-byte block template header and brute-forces nonce.

### S.1 Epoch Anchor

Replace `prev_state_root` with `epoch_anchor` in tx body hash.

- Change `noid_tx::TxBody.prev_state_root` → `epoch_anchor: Digest`
- Change `hash_tx_body()` first arg to `epoch_anchor`
- Define `ANCHOR_DEPTH = 6`; `epoch_anchor = H_BLOCK(header[height - 6])`
- Update `SpineInputs` in `noid_gkr`
- Update all downstream tests
- **Done when:** Spine GKR roundtrip passes with epoch_anchor

### S.2 Claims Commitment (C_claimed)

Wallet commits to claimed slot values without proving state.

- `compute_claims_commitment(inputs, outputs) -> Digest` in `noid_tx`
- Poseidon2b sponge over `(slot_index, value, owner_hi, owner_lo)` for each claim
- Add `claims_commitment: Digest` to `PublicInputs`
- LogicProof absorbs C_claimed into channel
- **Done when:** tamper any slot value → proof fails

### S.3 TxLogicAir

Extract pure-logic AIR (no FriStateOpen, no Merkle).

- Create `noid_air::composition::tx_logic` module
- Contains: balance_gate, range_gate, tx_body_spine pin, selector gates
- Does NOT contain: FriStateOpenAir, FriStateCombinerComposite
- Reduced `log_rows` (10-11 instead of 13)
- **Done when:** `air.check(trace)` passes for balance/range/auth/spine

### S.4 LogicProof Pipeline

New `prove_logic` / `verify_logic` in `noid_stark`.

- `prove_logic(LogicWitness) -> LogicProof`
- LogicWitness: TxLogicAir trace, SpineInputs (epoch_anchor), AuthInputs, C_claimed
- Same pipeline: SpineGKR → AuthGKR → STARK over TxLogicAir
- `verify_logic(proof, pi) -> Result<()>`
- **Done when:** end-to-end roundtrip with verify_logic

### S.5 BlockStateBindingAir

Block-level state opening AIR.

- Reuse FriStateOpenAir pattern at block scope
- All slots from all N txs (up to 12K)
- gamma-RLC accumulator batches openings into one FRI claim
- Bridge: opened slot values must match each tx's C_claimed
- Proves pre-state (inputs exist, outputs empty) and post-state (inputs zeroed, outputs filled)
- **Done when:** 3-tx block roundtrip, tamper detection on bridge

### S.6 Integrated BlockProof

Combine LogicProofs + BlockStateBinding.

- Modify `prove_block()` to accept `Vec<LogicProof>` + full state
- Full Node: verify LogicProofs → build BlockStateBinding → aggregate via deferred-opening
- State continuity: prev_block_state_root → apply all txs → new_block_state_root
- After BlockProof ready: form header, push to external miner via Block Template API
- **Done when:** 3-tx block roundtrip; each component tamper-tested

### S.7 Nullifier Set

Anti-double-inclusion rolling window.

- `NullifierSet` in `noid_chain::ChainState`
- Window = ANCHOR_DEPTH blocks of tx_body_hashes
- Reject at mempool if duplicate within window
- Prune on oldest block exit
- **Done when:** double-inclusion rejected at validation

### S.8 TxIntent Wire Format

Network payload for stateless transactions.

- `TxIntent { tx_body, logic_proof, claims_commitment, claimed_slots }`
- Wire serialization in `noid_tx::wire`
- No prev/new state_root in per-tx wire
- **Done when:** serialize/deserialize roundtrip

---

## Phase 2 — Consensus & PoW (Stage P)

**Goal:** Implement block validity rules so nodes can reach consensus.

### P.1 ASERT Difficulty Adjustment

- `noid_chain::difficulty` module
- `compute_target(anchor_header, current_height, current_timestamp) -> [u8; 32]`
- ASERT formula: `target = anchor_target * 2^((elapsed - ideal) / halflife)`
- Fixed-point 256-bit arithmetic (no floats, deterministic)
- EPOCH_LENGTH = 6, HALFLIFE = 360s, BLOCK_TIME = 60s
- GENESIS_TARGET = 2^240
- Anchor updates at each epoch boundary
- **Done when:** matches reference vectors, edge cases (negative exponent, overflow)

### P.2 PoW Validation

- `validate_pow(header: &BlockHeader) -> bool`
- `Blake3(header.to_bytes()) < header.difficulty_target` (LE comparison)
- `validate_difficulty(header, prev_epoch_anchor) -> bool` (ASERT check)
- **Done when:** rejects invalid nonces and wrong targets

### P.3 Timestamp Rules

- Median-time-past: `header.timestamp > median(last 11 timestamps)`
- Future limit: `header.timestamp <= now + MAX_FUTURE_DRIFT` (120s)
- **Done when:** rejects backward timestamps and far-future blocks

### P.4 Block Validation Pipeline

Full consensus validation combining all rules.

- `validate_block(block, chain_state) -> Result<(), ConsensusError>`
- Checks (in order): PoW valid, difficulty correct, timestamp valid, height sequential, prev_hash matches, tx_root matches, state_root matches, BlockProof verifies, nullifier clean, slot allocations valid
- All 16 invariants from Spec §16
- **Done when:** invalid blocks rejected for each rule independently

### P.5 Chain State Machine

- `ChainState::apply_validated_block(block) -> Result<ChainState>`
- Updates: state_root, active_slot_count, alloc_counter, log_slots, tip header
- Stores epoch anchors for ASERT
- Stores last 11 timestamps for median-time-past
- **Done when:** deterministic state evolution from genesis through 100 blocks

### P.6 Genesis

- `genesis() -> (Block, ChainState)` — hardcoded initial distribution
- All slots EMPTY except protocol alloc
- GENESIS_TARGET, height=0, timestamp=protocol-defined
- **Done when:** two independent nodes produce identical genesis state_root

---

## Phase 3 — Segmented State (Stage F)

**Goal:** Scale state beyond 2^16 slots per FRI.

### F.1 StateBackend Trait

- `trait StateBackend { get_slot, set_slot, load_segment, flush, segment_root }`
- Separates storage from logic
- **Done when:** FriState refactored to use trait

### F.2 RAM Backend

- `RamBackend`: Vec<Block128> per segment
- Implements full trait
- Default for testnet
- **Done when:** existing tests pass through backend abstraction

### F.3 Segmented FriState

- Split state into 2^16-slot segments
- Per-segment independent FRI commitment
- `state_root = Poseidon2b_Merkle(segment_roots)`
- TAG_SEGMENTTREE domain tag
- Zero-subtree optimization for empty segments
- **Done when:** state_root matches monolithic FRI at log_slots=16

### F.4 Segment Merkle Path in BlockStateBinding

- BlockStateBinding proves segment Merkle path (up to 16 levels)
- Merkle Kill-Shot GKR for in-circuit verification (~8 KB per path)
- **Done when:** block proves/verifies with segmented state + Merkle path

### F.5 Automatic Expansion

- Trigger: avg_occupancy > 0.90 over 7-day finalized window
- Action: append zero-subtree, increment log_slots
- One Poseidon2b compression per expansion
- **Done when:** expansion triggers correctly in multi-block test

---

## Phase 4 — Node Infrastructure (Stage N)

**Goal:** Working Full Node binary — validates, assembles blocks, mines, serves wallet requests.

### Node Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  FULL NODE (all-in-one: state + wallet + miner + API)           │
│                                                                 │
│  State layer:                                                   │
│    - Full segmented state (~768 MB+)                            │
│    - Block storage, mempool, nullifier set                      │
│    - Slot ownership tracking (built-in wallet)                  │
│                                                                 │
│  Block assembly:                                                │
│    - Validates incoming TxIntents (LogicProof check, ~3ms)      │
│    - Builds BlockStateBinding + BlockProof (1-3s CPU)           │
│    - Constructs 248-byte header                                 │
│                                                                 │
│  Mining:                                                        │
│    - Built-in multi-threaded Blake3 nonce search                │
│    - OR: serves Block Template API to external miners           │
│                                                                 │
│  Wallet:                                                        │
│    - Key management, slot tracking, balance                     │
│    - Builds LogicProof locally (~300-400ms)                     │
│    - Sends transactions (no RPC needed, direct mempool)         │
│                                                                 │
│  API server:                                                    │
│    - RPC for Light Nodes + explorers                            │
│    - Block Template API for external miners (solo/pool)         │
│                                                                 │
│  P2P:                                                           │
│    - Propagates blocks + TxIntents                              │
│    - Syncs chain from peers                                     │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  LIGHT NODE (wallet-only, connects to Full Node via RPC)        │
│                                                                 │
│  - Stores: keys, headers, receipts (minimal disk)               │
│  - Proves: LogicProof (~300-400ms, offline)                     │
│  - Queries: Full Node for slot hints + epoch_anchor             │
│  - Submits: TxIntent via RPC                                    │
│  - Verifies: chain tip via recursive proof (O(1), ~230ms)       │
│  - No state, no mining, no block assembly                       │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  EXTERNAL MINER (3rd party, solo or pool)                       │
│                                                                 │
│  - Input: 248-byte BlockHeader via Block Template API           │
│  - Operation: brute-force Blake3(header) < difficulty_target    │
│  - Output: valid 128-bit nonce                                  │
│  - Cannot: see transactions, modify coinbase, steal blocks      │
│  - Use case: GPU farms, ASICs, mining pools                     │
└─────────────────────────────────────────────────────────────────┘
```

### N.1 Node Binary Skeleton

- `noid-node` binary crate
- Config: data_dir, listen_addr, rpc_addr, template_api_addr, mining (on/off)
- Async runtime (tokio)
- State persistence (load/save ChainState)
- **Done when:** starts, loads genesis, shuts down cleanly

### N.2 Block Storage

- On-disk block index (height → header + proof location)
- Pruning: keep last N full blocks, headers-only beyond
- **Done when:** store/retrieve 1000 blocks

### N.3 Mempool

- `Mempool` struct: accepts TxIntents, validates LogicProof + epoch_anchor + nullifier
- Priority by fee/byte
- Eviction policy (size cap, TTL)
- Conflict detection (same input slot)
- **Done when:** accepts valid, rejects invalid, handles conflicts

### N.4 Block Assembly

- Select txs from mempool (max N, max bytes)
- Generate BlockStateBinding for selected set
- Produce BlockProof via `prove_block()` (1-3s CPU)
- Construct header (state_root, tx_root, da_root, difficulty_target, timestamp)
- Coinbase locked in da_root → header → BlockProof (withholding protection)
- **Done when:** produces valid block from mempool txs

### N.5 Built-in Miner

- Multi-threaded Blake3 nonce search (divide 128-bit space across cores)
- Interrupt on new block arrival from P2P
- Enabled via config flag
- **Done when:** finds valid nonce, Full Node assembles and propagates block

### N.6 Block Template API

- Minimal protocol: Full Node pushes 248-byte header to connected external miners
- External miner returns `(header_hash, nonce)` on solution
- Full Node validates PoW, assembles complete block, propagates
- Supports: multiple concurrent miners, work update on new txs/blocks
- Empty-block fallback: push empty template immediately, full template after assembly
- **Done when:** external miner process solves nonce, Full Node accepts and propagates

### N.7 RPC API

- JSON-RPC over HTTP
- Wallet-facing: `get_slot(idx)`, `get_epoch_anchor()`, `submit_tx_intent(TxIntent)`, `get_chain_info()`, `query_free_slots(count)`
- Explorer-facing: `get_block(height)`, `get_header(height)`, `get_tx(hash)`
- **Done when:** Light Node can query state and submit transactions

### N.8 P2P Networking

- libp2p or custom TCP protocol
- Message types: `NewBlock`, `NewTxIntent`, `GetBlock`, `GetHeaders`
- Peer discovery (static seeds + gossip)
- Block propagation (flood with seen-filter)
- TxIntent relay (mempool sharing)
- **Done when:** two Full Nodes sync a chain of 10 blocks

### N.9 Chain Sync

- Header-first sync (download headers, validate PoW + timestamps)
- Block download (request bodies for validated headers)
- State reconstruction (apply blocks from genesis)
- Fast-sync (future: download tip state + recursive proof)
- **Done when:** fresh Full Node syncs from peer to tip

---

## Phase 5 — Wallet Core (Stage W)

**Goal:** Wallet logic shared by both Full Node (built-in) and Light Node (standalone CLI).

### W.1 Key Management

- Generate SpendSecret, derive Address
- Encrypted keystore (argon2 + chacha20-poly1305)
- Shared library: `noid_wallet` crate (used by both node modes)
- **Done when:** generate, export, import keys

### W.2 Slot Tracking

- Track owned slots (slot_index, value, owner)
- Full Node mode: scan own state directly
- Light Node mode: subscribe to new block headers via RPC, detect incoming
- Mark spent slots
- **Done when:** balance updates on new blocks in both modes

### W.3 Transaction Construction

- Select inputs (coin selection: largest-first or random)
- Choose output slots: Full Node queries own state, Light Node queries via RPC
- Build TxBody, compute tx_body_hash, C_claimed
- **Done when:** produces valid TxBody from wallet state

### W.4 LogicProof Generation

- Build full witness (SpineInputs, AuthInputs, TxLogicAir trace)
- Call `prove_logic()` (~300-400ms)
- Package as TxIntent
- **Done when:** locally generated TxIntent verifies

### W.5 Submit & Confirm

- Full Node mode: inject directly into own mempool
- Light Node mode: submit TxIntent via RPC
- Poll for inclusion (watch blocks for tx_body_hash in tx_root)
- **Done when:** end-to-end send from wallet A to wallet B (both modes)

### W.6 Light Node CLI Binary

- `noid-light` binary crate (or `noid-node --light` flag)
- Connects to Full Node via RPC
- Stores: keys + headers + receipts only
- Commands: `balance`, `send <address> <amount>`, `receive`, `history`
- **Done when:** Light Node sends coins to Full Node and vice versa

---

## Phase 6 — Integration & Testnet (Stage T)

**Goal:** Multi-node network running real consensus.

### T.1 Multi-Node Test Harness

- Spawn 3-5 nodes locally (different ports)
- Seed peers, verify they sync
- One miner, others validate
- **Done when:** 3 nodes agree on 50-block chain

### T.2 Adversarial Testing

- Invalid PoW → rejected
- Invalid BlockProof → rejected
- Double-spend attempt → rejected
- Fork resolution (longest valid chain)
- Timestamp manipulation → rejected
- **Done when:** all attack vectors handled

### T.3 Performance Validation

- Block time targeting ~60s at genesis difficulty
- prove_block() < 3s for 100 txs
- verify_block() < 600ms
- P2P propagation < 2s
- **Done when:** sustained block production for 1 hour

### T.4 Reorg Handling

- Detect competing chains
- Switch to longest valid chain
- Revert mempool (return txs from orphaned blocks)
- **Done when:** handles 1-3 block reorgs gracefully

### T.5 Public Testnet Launch

- Docker image for node
- 3+ seed nodes on cloud (separate regions)
- Faucet (genesis allocation or low-difficulty coinbase)
- Block explorer (minimal: height, txs, difficulty, timestamps)
- Public RPC endpoint
- Wallet binary release
- **Done when:** external parties can run nodes and send transactions

---

## Phase 7 — Recursive Chain (Stage H)

**Goal:** O(1) historical verification. New node verifies entire history with one proof.

### H.1 Chain Accumulator

- `noid_recursive` crate
- `ChainAccumulator { acc: Digest, height, last_state_root }`
- `block_fri_digest(BlockProof) -> Digest`: canonical hash of FRI Merkle data
- `extend_chain(prev, block_proof) -> ChainAccumulator`: verify + fold `acc' = compress(acc, block_fri_digest)`
- `genesis_accumulator(initial_state_root) -> ChainAccumulator`
- **Done when:** 3-block chain accumulation + tamper detection

### H.2 Algebraic-Replay Witness

- Deterministic transcript-trace producer
- Takes BlockProof → emits field-element witness for recursive AIR
- Covers: sumcheck round polys, composition values, Fiat-Shamir squeezes
- **Done when:** witness generation deterministic and bit-identical across runs

### H.3 Fiat-Shamir Sponge AIR

- Composable AIR wrapping Poseidon2b absorb/squeeze
- Public-input bindings + transcript continuity
- Reused for ~300 in-circuit perms
- **Done when:** sponge AIR passes `check()` for arbitrary transcript

### H.4 Algebraic-Replay AIR

- Sumcheck round consistency constraints
- Composition terminal equation
- ~8K field muls over GF(2^128)
- **Done when:** replays full block verify algebraically

### H.5 RecursiveBlockAir

- Composes H.3 sponge + H.4 algebraic
- Deferred-Merkle accumulator gate: `acc' == compress(acc, fri_digest)`
- State-continuity gate: `prev_root == state_root_n`
- Proven with FRI-Binius PCS
- **Done when:** recursive proof of one-block verify

### H.6 Kill-Shot for In-Circuit Poseidon2b

- 300 FS perms → one unified degree-7 sumcheck over 18-var MLE
- Reduces circuit from ~2^18 to ~2^15 rows
- Expected recursive prove: ~3-5s
- **Done when:** recursive prove with Kill-Shot < 5s

### H.7 Tip Verifier

- `verify_tip(recursive_proof, tip_acc, tip_block_proof) -> Result<()>`
- Verifies recursive STARK + native FRI on tip + accumulator match
- O(1) regardless of chain length
- **Done when:** fresh node verifies 100-block chain in <300ms

---

## Phase 8 — Optimizations (Stage K)

### K.1 Reduced Inner Queries

- NUM_QUERIES=16 for block-internal proofs (nested inside recursive proof)
- Reduces Fiat-Shamir perms and proof size
- **Done when:** block prove time drops ~30%

### K.2 Parallel Recursive Prover

- Partition trace across 8 cores for commit + NTT phases
- **Done when:** recursive prove < 2s on 8-core

### K.3 MDBX Storage Backend

- `MdbxBackend` implementing StateBackend trait
- Memory-mapped, crash-safe copy-on-write
- Mandatory at log_slots > 26 (~4M+ slots)
- **Done when:** node runs with disk storage, survives crash

### K.4 Proof Compression

- Strip redundant data from block proofs for relay
- Delta-encode FRI paths within same Merkle tree
- **Done when:** BlockProof wire size < 100 KB for 100-tx blocks

---

## Phase 9 — GUI Wallet (Stage G)

**Goal:** Desktop application. User opens it, chooses Light or Full mode.

### G.1 GUI Framework

- Tauri or native Rust GUI (egui/iced)
- Cross-platform: Linux, macOS, Windows
- Embeds `noid_wallet` crate + node core
- **Done when:** window opens, mode selection screen renders

### G.2 Mode Selection

- Launch screen: "Light Node" or "Full Node"
- Light mode: connects to configured Full Node RPC, wallet-only
- Full mode: starts embedded Full Node (state, mining, P2P, everything)
- Config persistence between sessions
- **Done when:** both modes launch successfully from GUI

### G.3 Wallet UI

- Balance display, transaction history
- Send: address input, amount, fee selector, prove + submit
- Receive: show own address, QR code
- Slot viewer (own slots with values)
- LogicProof generation progress bar (~300-400ms)
- **Done when:** full send/receive cycle through GUI

### G.4 Full Node Controls (Full mode only)

- Mining toggle (on/off), hashrate display
- Mempool viewer (pending txs, fees)
- Chain status (height, difficulty, peers, sync progress)
- Block Template API status (connected external miners)
- **Done when:** user can monitor and control Full Node from GUI

---

## Dependency Graph

```
Phase 1 (Stateless)
    S.1 → S.2 → S.3 → S.4
                        S.5 → S.6
    S.7 (parallel to S.1-S.6)
    S.8 (after S.6)

Phase 2 (Consensus)
    P.1 → P.2 → P.4
    P.3 → P.4
    P.4 → P.5
    P.5 → P.6

Phase 3 (Segmented) [can start after S.6]
    F.1 → F.2 → F.3 → F.4
    F.5 (after F.3)

Phase 4 (Node) [can start after P.6]
    N.1 → N.2 → N.3 → N.4 → N.5 (built-in miner)
    N.6 (template API, parallel to N.5)
    N.7 (RPC, parallel to N.3+)
    N.8 → N.9

Phase 5 (Wallet) [W.1-W.5 start with N.1, W.6 after N.7]
    W.1 → W.2 → W.3 → W.4 → W.5 (built into Full Node)
    W.6 (Light Node CLI, after N.7)

Phase 6 (Integration) [requires N.9 + W.6]
    T.1 → T.2 → T.3 → T.4 → T.5

Phase 7 (Recursive) [can start after T.1, ship after T.5]
    H.1 → H.2 → H.3 → H.4 → H.5 → H.6 → H.7

Phase 8 (Optimizations) [incremental, any time after T.5]
    K.1, K.2, K.3, K.4 — independent

Phase 9 (GUI) [after T.5]
    G.1 → G.2 → G.3 → G.4
```

Critical path to testnet: **S → P → N/W → T** (Phases 1-2-4/5-6).
Phases 3 (Segmented) and 7 (Recursive) are parallel tracks — valuable but not blocking testnet.
Phase 9 (GUI) comes after testnet launch.

---

## Timeline Estimates

| Phase | Duration | Cumulative | Notes |
|-------|----------|------------|-------|
| Phase 1 (Stateless) | 4-6 weeks | 4-6 wk | Pure Rust, no external deps |
| Phase 2 (Consensus) | 2-3 weeks | 7-9 wk | Deterministic math + tests |
| Phase 3 (Segmented) | 3-4 weeks | parallel | Can overlap with Phase 4 |
| Phase 4 (Node) | 6-8 weeks | 13-17 wk | Networking is the long pole |
| Phase 5 (Wallet) | 2-3 weeks | 15-20 wk | Built into Full Node + Light CLI |
| Phase 6 (Testnet) | 3-4 weeks | 18-24 wk | Integration + hardening |
| Phase 7 (Recursive) | 8-12 weeks | post-testnet | Research-grade; ships as upgrade |
| Phase 8 (Optimizations) | ongoing | post-testnet | Incremental improvements |
| Phase 9 (GUI) | 4-6 weeks | post-testnet | Desktop app, last priority |

**Testnet ETA: ~5-6 months from start of Phase 1.**

---

## Design Invariants (Non-Negotiable)

1. **No trusted setup.** No elliptic curves. Post-quantum.
2. **Single algebraic universe.** Everything is GF(2^128) — from tx to recursion.
3. **Proof-native.** Network does not execute code. It verifies mathematics.
4. **Transparent.** All values on-chain. No zero-knowledge.
5. **PoW for ordering only.** Blake3 determines canonical chain. Proofs determine validity.
6. **Light Nodes prove logic, Full Nodes prove state.** External miners only provide PoW ordering.
7. **O(1) history.** Recursive chain compresses unbounded history into one proof.
8. **128-bit security.** Every component: FRI, GKR, Fiat-Shamir, PoW hash.
9. **Deterministic consensus.** Byte-identical state_root across all honest nodes.
10. **Fixed-slot UTXO.** No hash-map, no dynamic structures. Slots addressed by index.

---

## Proof Architecture (Target State)

```
  LogicProof generation (~300-400ms, runs on any node with wallet)
  ┌──────────────────────────────────────────┐
  │  SpineGKR Kill-Shot (59 perms, 15-var)   │
  │  AuthGKR Kill-Shot (20 perms, 14-var)    │
  │  STARK + FRI-Binius over TxLogicAir      │
  │  Output: LogicProof (~50-55 KB)          │
  │                                          │
  │  Runs on: Full Node (built-in wallet)    │
  │           Light Node (standalone wallet)  │
  └──────────────────────────────────────────┘
           │ TxIntent (to own mempool or via RPC)
           ▼
  Full Node — Block Assembly (1-3s CPU)
  ┌──────────────────────────────────────────┐
  │  Collect TxIntents from mempool          │
  │  Verify N LogicProofs                    │
  │  Build BlockStateBinding                 │
  │    - FRI state openings (gamma-RLC)      │
  │    - Segment Merkle paths                │
  │    - MerkleGKR Kill-Shot (32-slot, 14v)  │
  │    - Bridge check (C_claimed match)      │
  │  Deferred-opening aggregation            │
  │  Single FRI-Binius opening               │
  │  Output: BlockProof + 248-byte header    │
  └──────────────────────────────────────────┘
           │ PoW (built-in miner OR Block Template API)
           ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  Built-in miner          │  External Miner (3rd party)      │
  │  - Multi-thread Blake3   │  - Receives 248-byte header      │
  │  - Same process          │  - GPU/ASIC/pool                 │
  │  - Config: mining=on     │  - Returns valid nonce           │
  │                          │  - Cannot modify block content   │
  └─────────────────────────────────────────────────────────────┘
           │ Valid nonce found
           ▼
  Full Node — Propagation
  ┌──────────────────────────────────────────┐
  │  Attach nonce → complete block           │
  │  Propagate to P2P network                │
  │  Other Full Nodes validate + apply       │
  └──────────────────────────────────────────┘
           │ Block (P2P)
           ▼
  Recursive Accumulator (per-block, ~3-5s, Phase 7)
  ┌──────────────────────────────────────────┐
  │  Algebraic replay of BlockProof verify   │
  │  Fiat-Shamir sponge in-circuit           │
  │  FS Kill-Shot (300 perms, 18-var)        │
  │  Deferred-FRI Merkle commitment          │
  │  State continuity gate                   │
  │  Output: RecursiveProof (~55 KB)         │
  └──────────────────────────────────────────┘
           │
           ▼
  Tip Verification (Light Node or any verifier, ~230ms, O(1))
  ┌──────────────────────────────────────────┐
  │  Verify RecursiveProof (STARK)           │
  │  Check deferred Merkle at tip            │
  │  Result: entire history correct           │
  └──────────────────────────────────────────┘
```

---

## Soundness Summary

| Component | Security | Mechanism |
|---|---|---|
| FRI-Binius | 128-bit | 64 queries x 2-bit rate |
| Blake3 Merkle | 128-bit | collision resistance |
| Gamma batching | 128-bit | Horner RLC over GF(2^128) |
| SpineGKR | 128-bit | Schwartz-Zippel, 15-var |
| AuthGKR | 128-bit | Schwartz-Zippel, 14-var |
| MerkleGKR | 128-bit | Schwartz-Zippel, 14-var |
| Batch-eval | 128-bit | degree-2 sumcheck + RLC |
| Fiat-Shamir | collision-resistant | Poseidon2b sponge |
| PoW | ordering-only | Blake3 + ASERT DAA |
| Recursion | 128-bit | native field (no foreign-field penalty) |

No trusted setup. No elliptic curves. Post-quantum.
