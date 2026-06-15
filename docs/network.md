# Paranoid Network Protocol

## Core Principle: No History, Full Security

Paranoid nodes do not store transaction history. A node holds:

1. **Current UTXO state** -- the live balances right now. Overwritten every block.
2. **Block headers** -- 276 bytes each, kept forever (~553 MB/year). The only
   permanent growth.
3. **Last 18 blocks with full data** (block bodies + ZK proofs + undo logs) --
   for shallow reorgs and peer serving. Pruned after finality.
4. **One recursive proof** -- 6.5 KB. Proves the entire chain from genesis to
   near-tip in a single STARK verification (~5 ms).

**Why this works without history:**

- **State correctness**: The recursive proof mathematically guarantees that
  the current state is the honest result of every transaction since genesis.
  No replay needed. The proof IS the replay, compressed to 6.5 KB.
- **Past payments**: Users store their own receipts (~300 bytes). A receipt
  contains a Merkle path from the transaction to the block's `tx_root`.
  Any node verifies it against its permanent header chain. No block body needed.
- **Replay protection**: Transactions expire after 144 blocks (~36 min) via
  `epoch_anchor`. Nullifiers only need to cover this window, then self-prune.

A node that joins the network downloads the current state + recursive proof,
verifies the proof in 5 ms, and has full confidence. It never downloads or
processes historical blocks. Sync from zero takes 1-2 seconds.

The network does not execute transactions -- it verifies ZK proofs. Execution
is local (wallet), validity is global (ZK), ordering is PoW. Every node
independently verifies ZK validity of every block. No node trusts miners.

---

## Node Modes

A single binary, three mutually exclusive modes (`--mode`):

| Mode | Mining | Block Templates | ZK Verify | Serves State | P2P |
|------|--------|-----------------|-----------|--------------|-----|
| `relay` (default) | no | no | yes | yes | full gossip |
| `miner` | internal PoW + ZK | no | yes | yes | full gossip |
| `extminer` | ZK only (PoW external) | yes (requires `--mining-key`) | yes | yes | full gossip |

All modes are functionally identical in what they verify and store. The only
difference is block production.

**External PoW Miner (`noid-extminer`)** is a separate stateless binary. It
connects to an `--mode extminer` node via JSON-RPC, fetches templates, searches
for Blake3 nonces with rayon, and submits solved blocks. It has no P2P, no state,
no ZK proving.

---

## What a Node Stores

### Storage Layout (MDBX, 13 tables)

| Table | Key | Value | Retention | Approx Size |
|-------|-----|-------|-----------|-------------|
| `T_HEADERS` | height (u64) | BlockHeader (276 bytes) | **forever** | ~553 MB/year at 15s blocks |
| `T_HASH_TO_HEIGHT` | block_hash (32B) | height (u64) | **forever** | ~84 MB/year |
| `T_CHAIN_TIP` | single key | (height, hash) | latest only | 40 bytes |
| `T_SEGMENTS` | seg_id (u16) | SegmentColumns (3 x 64K x 16B) | current state | ~3 MB per materialized segment |
| `T_STATE_META` | single key | (log_slots, active_count, alloc_counter) | latest only | 20 bytes |
| `T_OWNER_INDEX` | owner_addr (32B) | packed Vec<(slot_u32, value_u64)> | current state | proportional to UTXO set |
| `T_RECURSIVE_PROOF` | single key | RecursiveBlockProof bytes | latest only | 6.5 KB |
| `T_RECENT_BLOCKS` | height (u64) | full Block bytes | last 18 blocks | ~4 MB |
| `T_BLOCK_PROOFS` | height (u64) | BlockProof bincode | last 18 blocks | ~35 MB at 100 txs/block; ~90 MB at max |
| `T_UNDO_LOGS` | height (u64) | BlockUndoLog | last 18 blocks | ~2 MB |
| `T_NULLIFIERS` | tx_body_hash (32B) | height (u64) | last 144 blocks | ~1.2 MB |
| `T_NULLIFIER_BLOCKS` | height (u64) | packed tx_body_hashes | last 144 blocks | ~1.2 MB |
| `T_TX_INDEX` | tx_body_hash (32B) | (height, position) | last 144 blocks | ~1.2 MB |

### Why These Retention Policies

**Headers forever (T_HEADERS, T_HASH_TO_HEIGHT):**
Headers are the chain's permanent anchor of truth. They enable receipt
verification at any time: a user presents a receipt containing a Merkle path
from their tx to a tx_root. The verifier checks that tx_root matches the
header at the claimed height. Headers are 276 bytes each; at 15-second blocks
this is ~553 MB per year. After 10 years: ~5.5 GB. Trivial by modern standards.

**State (T_SEGMENTS, T_STATE_META, T_OWNER_INDEX) -- current only:**
The node stores only the CURRENT UTXO state. No history.
- Spent slots are zeroed and recycled via the allocator.
- Past payments: proven by user-held receipts against permanent headers.
- State trust: guaranteed by the recursive proof, not by replay.

**Recent blocks and proofs (last 18 = FINALITY_DEPTH):**
Used for two purposes only:
1. **Shallow reorgs**: if a competing chain with more chainwork arrives for
   the last <=18 blocks, the node can undo and re-apply using undo logs.
2. **Peer serving**: a syncing node that is nearly caught up can request the
   last few blocks + proofs instead of a full snapshot.

After 18 blocks, a block is final. Its data is no longer needed because:
- Its state transitions are already reflected in the current state.
- Its ZK validity is already folded into the recursive proof.
- Its undo log is unreachable (no reorg past finality depth).

**Nullifiers (last 144 blocks = ANCHOR_DEPTH):**
A tx's epoch_anchor references a block header hash within the last 144 blocks.
Nullifiers (tx_body_hash values) are tracked for this window to prevent replay.
After ANCHOR_DEPTH blocks, the anchor expires and the tx cannot be replayed
even without the nullifier entry (the anchor check rejects it structurally).
The two mechanisms are redundant within the window and self-sufficient after:
- Within 144 blocks: nullifier prevents replay (fast, O(1) lookup)
- After 144 blocks: anchor expiry prevents replay (no storage needed)

### Storage Size Estimates

**Permanent growth (headers only):**
2,102,400 blocks/year * 276 bytes = ~553 MB/year. This is the ONLY component
that grows unboundedly. After 10 years: ~5.5 GB. After 100 years: ~55 GB.
Fits on any modern device indefinitely.

**State (unpredictable, bounded by capacity):**
Each materialized segment is ~3 MB. State auto-expands from 2^24 to 2^32 slots
as the network fills. Whether this takes 1 year or 50 years depends on adoption.
Only segments with live UTXOs are materialized (rest are virtual zero, no disk).
At full capacity (2^32 slots, all materialized): ~48 GB max theoretical ceiling.

**Volatile (fixed, independent of chain age):**
- Recent blocks + proofs + undo: ~40 MB at 100 txs/block; ~96 MB at max (always last 18 blocks)
- Nullifiers + tx_index: ~3.6 MB (always last 144 blocks)
- Recursive proof: 6.5 KB (single latest)

---

## State Model: Segmented FRI

The UTXO state is a flat array of slots. Each slot is 48 bytes:

```
SlotValue {
    value:    Block128  (16 bytes) -- amount in micronoid
    owner_hi: Block128  (16 bytes) -- owner address high 128 bits
    owner_lo: Block128  (16 bytes) -- owner address low 128 bits
}
```

A spent slot becomes `EMPTY = (0, 0, 0)`. Allocator reuses empty slots for new
outputs (PRNG-based allocation, deterministic from `alloc_counter`).

**Segmentation:**
- Total slots: 2^log_slots (genesis: 2^24 = 16.7M; max: 2^32 = 4.3B)
- Segment size: 2^16 = 65,536 slots each (~3 MB materialized)
- Segments with no live slots are virtual zero (no RAM, no disk)
- State root = Merkle tree over segment FRI roots (Poseidon2b compress)

**Expansion:**
- Triggered when median active_slot_count over last 18 finalized blocks >= 75%
  of current capacity
- Doubles num_segments by appending virtual-zero upper half
- State root update is O(1): `compress(old_root, precomputed_zero_subtree)`
- No data migration, no downtime

---

## Receipts: User-Stored Proof of Payment

The node does NOT store transaction history. Users store their own receipts.

### Receipt Structure

```rust
ParanoidReceipt {
    version: u8,                    // protocol version (1)
    tx_body_hash: [u8; 32],        // transaction identifier
    merkle_path: Vec<[u8; 32]>,    // sibling hashes, leaf to root (<=8 levels)
    merkle_dirs: u32,              // bitmask: bit k = 1 iff sibling on left at level k
    claimed_root: [u8; 32],        // tx_root from block header
    claimed_height: u64,           // block height
    summary: TxSummary,            // human-readable payment details
    summary_hash: [u8; 32],        // Blake3(bincode(summary)) -- integrity
    chain_cert: Option<Vec<u8>>,   // optional RecursiveProof for full standalone verification
}
```

### How Receipt Verification Works

Any wallet or node can verify a receipt against stored headers:

1. **Merkle check** (offline, instant):
   - Reconstruct tx_root from `tx_body_hash` + `merkle_path` + `merkle_dirs`
   - Uses Poseidon2b compress (same as in-circuit)
   - Compare reconstructed root with `claimed_root`

2. **Header check** (against stored headers):
   - Look up header at `claimed_height`
   - Verify `header.tx_root == claimed_root`

3. **What this proves**:
   - **Inclusion**: the tx was in block N (Merkle path to tx_root)
   - **Validity**: the tx was ZK-verified at inclusion (header's
     `proof_transcript_hash` commits to the BlockProof)
   - **Finality**: the block had real PoW cost (nonce + difficulty in header)

Unlike Bitcoin SPV (which proves inclusion but trusts miners for validity),
Paranoid receipts prove both inclusion AND validity. A forged transaction
cannot produce a valid BlockProof, so it cannot enter a block's tx_root.

---

## Synchronisation

Two sync modes only:
1. **Snapshot sync** (gap > 18 blocks or fresh node): download state + recursive proof, verify, done.
2. **Block-by-block** (gap <= 18 blocks): apply recent blocks with full ZK verification.

There is no third option. A node never "catches up" hundreds of blocks one
by one. If it's behind by more than 18 blocks, it gets a fresh snapshot.

### Flow A: Fresh Node Joins Network

```
New Node                         Peers (up to 3 queried)
   |
   | 1. Connect to seeds, discover peers via Kademlia DHT
   |
   |--- GetStateManifest -------> Peer 1, 2, 3  (eclipse mitigation)
   |<-- manifests (tip_height, segment_ids, headers, nullifiers)
   |
   | 2. Select best manifest (highest tip with valid PoW chainwork)
   |    Reject if chainwork < MIN_SNAPSHOT_CHAINWORK (prevents fake chains)
   |
   |--- GetRecursiveProof ------> Best peer
   |<-- RecursiveProof (6.5 KB)
   |
   | 3. Verify the ENTIRE chain history in one call:
   |    verify_tip(proof, prev_state_root, tip_height)
   |      - STARK verify: O(1), ~5 ms
   |      - proof.state_root == manifest state_root (from headers)
   |      - proof covers height == tip - 1
   |    If STARK fails: reject this peer, try next candidate.
   |    A forged RecursiveProof CANNOT pass STARK verification.
   |
   |--- GetStateSegment x N ----> Best peer (8 parallel, ~3 MB each)
   |<-- segments
   |
   | 4. Apply snapshot:
   |    - Load segments into MDBX
   |    - Load recent headers (for ASERT, median timestamps)
   |    - Load nullifiers (for ANCHOR_DEPTH window)
   |    - Store the peer's RecursiveProof (updater continues from here)
   |    - Wallet: background scan for owned UTXOs
   |
   |--- SyncBlocksFrom(tip+1) --> Any peer  (catch up finality window)
   |<-- blocks with proofs
   |
   | 5. Normal operation: gossip blocks and txs
```

**Total sync time: 1-2 seconds** for typical state sizes (tested: node syncs
from h=0 to h=21 in ~1s including ZK verification of all received blocks).

### Flow B: Node Restarts (Has State)

```
Node restarts. Reads MDBX. tip = h=N.
  - If tip timestamp within 3 block-times of wall clock:
      sync_ready immediately, wait for gossip
  - If slightly behind (<=18 blocks):
      SyncBlocksFrom(N+1) -- download and verify each block
  - If far behind (>18 blocks):
      same as Flow A (snapshot sync)
```

No special "recovery mode". Same logic as a fresh node with gap detection.

### Flow C: Node Behind > 18 Blocks

If a node was offline for 2 hours (~480 blocks), it does NOT replay them:

1. BlockProofs are only stored for the last 18 blocks -- replay is impossible.
2. The node requests a fresh state snapshot + RecursiveProof from peers.
3. Verifies the RecursiveProof (STARK, ~5 ms). Done.
4. Overwrites stale local state. Recursive updater continues from here.

This is safe because the RecursiveProof is unforgeable (~2^-120), the
state_root is committed in the proof, and snapshot headers have valid PoW
with cumulative chainwork above threshold.

### Flow D: Shallow Reorg (<=18 blocks)

```
Our tip: h=120. Competing block at h=115 (parent at h=114) arrives.
  1. FetchHeaders from peer to find common ancestor (h=114)
  2. Compare cumulative chainwork:
     - Competing chain must have STRICTLY MORE work to reorg
     - Equal work: keep current chain (tie-break: incumbent wins)
  3. If reorg:
     - Undo blocks h=120..115 using T_UNDO_LOGS
     - Apply competing blocks h=115..h=120+ with full ZK verification
     - Recursive proof updater catches up from h=114
```

### Flow E: Miner Starts Fresh Network

```
paranoid --mode miner --genesis
  - Creates genesis block (coinbase only, zero state)
  - sync_ready fires immediately (no peers needed)
  - Begins mining block 1, 2, 3...
  - Recursive updater: proves genesis, then h=1, h=2, ...
  - Other nodes connect, receive blocks + recursive proof updates
```

### Stale-Tip Recovery

If no new block is applied for 30 seconds but the node has seen higher block
announcements from peers, it re-requests missing blocks. This handles network
glitches where the initial request failed.

---

## Validation: What Gets Checked and When

### Block Reception from P2P (Full Pipeline)

When a node receives a block from the network, it runs these checks in order
(cheapest first -- fail fast):

**Stage 1: Wire Validation (instant)**
- Block size <= 512 KB
- BlockProof size <= 6 MB
- Deserialization succeeds
- Per-peer rate limit: 40 blocks / 10 seconds

**Stage 2: Native Consensus (`validate_block_checks`, O(txs))**

| Check | Error | Purpose |
|-------|-------|---------|
| `header.prev_hash == parent.hash` | BadParentHash | Chain integrity |
| `header.height == parent.height + 1` | HeightMismatch | Monotonicity |
| ASERT difficulty matches expected | BadDifficulty | PoW calibration |
| `header.timestamp > median_time_past(11)` | TimestampTooOld | Time ordering |
| `header.timestamp <= local_time + 120s` | TimestampTooFuture | Clock drift |
| Blake3(header_core, nonce) <= target | BadPoW | Proof of work |
| `block.transactions.len() <= 256` | TooManyTxs | Block size bound |
| No cross-tx slot conflicts (HashSet) | SlotConflict | Double-spend in block |
| Per-tx: fee fits u64 | BadFee | Overflow prevention |
| Per-tx: epoch_anchor != [0;32] (non-cb) | BadEpochAnchor | Anchor required |
| Per-tx: nullifier not in set | NullifierCollision | Replay prevention |
| Coinbase: first tx, 1 valid output | ShapeMismatch | Structure |
| Coinbase: value <= reward + fees | InflatedCoinbase | Inflation prevention |
| `header.log_slots` matches expansion rule | BadLogSlotsExpansion | State capacity |

**Stage 3: ZK Proof Verification (`verify_block`, O(txs x ~50ms))**

Only for blocks with user transactions (coinbase-only blocks skip this):

| Check | Error | Purpose |
|-------|-------|---------|
| proof.log_slots == header.log_slots per tx | LogSlotsInconsistent | Parameter binding |
| SpineGKR: tx_body_hash computation correct | StarkInvalid | TX body integrity |
| AuthGKR: Address = H_ADDR(secret), AuthTag = H_AUTH(secret, body) | StarkInvalid | Ownership proof |
| TxLogicAir STARK: balance, range, binding | StarkInvalid | TX validity |
| BlockStateBindingAir: slot openings vs state MLE | StarkInvalid | State consistency |
| FRI opening: all columns committed correctly | StarkInvalid | Commitment |

**Stage 4: State Transition (`apply_state_delta`)**

| Check | Error | Purpose |
|-------|-------|---------|
| Computed state_root == header.state_root | BadStateRoot | State binding |
| Computed tx_root == header.tx_root | BadTxRoot | TX binding |
| active_slot_count == header.active_slot_count | ShapeMismatch | Counter |
| alloc_counter == header.alloc_counter | ShapeMismatch | Allocator |

After all 4 stages pass: block is committed to MDBX, gossiped to peers.

### Coinbase-Only Blocks (No User TXs)

Most blocks at low TPS contain only a coinbase transaction. These:
- Have empty `block_proof_bytes` in gossip
- Skip ZK verification entirely (no user txs to prove)
- Are validated by native consensus + state transition only
- `header.proof_transcript_hash` = `STUB_MARKER [1u8; 32]` (prevents an
  adversary from omitting the proof on blocks that DO have user txs)

### Mempool TX Admission

When a transaction arrives via gossip, BEFORE entering the mempool:

| # | Check | Purpose |
|---|-------|---------|
| 0 | Wire size <= 1 MB | DoS prevention |
| 1 | Per-peer rate: 50 txs / 10 seconds | Flood prevention |
| 2 | Fee >= MIN_FEE_BASE + n_outputs x FEE_PER_OUTPUT | Spam prevention |
| 3 | Body hash binding (recompute and compare) | Integrity |
| 4 | Coinbase: must have exactly 1 valid output, fee = 0 | Structure |
| 5 | Epoch anchor references a known header in last 144 blocks | Freshness |
| 6 | Nullifier not in nullifier set | Replay prevention |
| 7 | No slot conflicts with existing mempool txs | Double-spend |
| 8 | Input slots exist in state with matching value + owner | Liveness |
| 9 | Output slots are EMPTY in state | Availability |

ZK proof verification (LogicProof) runs ASYNCHRONOUSLY after admission as a
background task. Invalid proofs are evicted when detected.

### Recursive Proof Verification (On Snapshot Sync)

When receiving a RecursiveProof from a peer during snapshot sync:

| Check | Purpose |
|-------|---------|
| STARK verify passes (RecursiveBlockAir, ~5ms) | Proof validity |
| proof.state_root == snapshot header state_root | State binding |
| proof.height == tip - 1 | Height consistency |
| Optional: chain_hash matches expected (if genesis in window) | Chain integrity |
| PoW chainwork of snapshot headers >= MIN_SNAPSHOT_CHAINWORK | Eclipse resistance |

---

## P2P Protocol Stack

Built on **libp2p 0.54**. Transport: TCP + Noise encryption + Yamux mux + DNS.

### Peer Discovery

| Mechanism | Purpose | Interval |
|-----------|---------|----------|
| Bootstrap seeds (CLI/config) | Initial connection | once at start |
| Kademlia DHT (server mode, replication=20) | Peer routing | 5-min random walks |
| mDNS | LAN discovery | 60s requery, immediate dial |
| Identify protocol | Address propagation, DHT seeding | on connect |
| Peer Store (disk-backed `peers.json`) | Cold-start resilience | 5-min persist |

### NAT Traversal

| Protocol | Purpose |
|----------|---------|
| AutoNAT | Detect public/private reachability (90s refresh) |
| Relay client | Circuit relay for nodes behind NAT |
| DCUtR | Direct connection upgrade via hole punching |

### Connection Limits

```
Max inbound:   128
Max outbound:   64
Pending in:     64
Pending out:    32
Reconnect:      exponential backoff 10s -> 600s, max 10 attempts
```

### GossipSub Configuration

```
Heartbeat:       700ms
Mesh:            n=4, n_low=2, n_high=8
Outbound min:    1 (critical for small networks)
Max transmit:    2 MB
Flood publish:   true (for txs)
Peer exchange:   enabled
Dedup:           blake3 content hash
```

### Gossipsub Topics

| Topic | Message Type | Size |
|-------|-------------|------|
| `/noid/{network}/blocks/1` | BlockGossipMsg | 310B compact or <1MB inline |
| `/noid/{network}/txs/1` | raw TxIntent bytes | ~1-2 KB |
| `/noid/{network}/recproofs/1` | RecursiveProofGossipMsg | ~6.5 KB |

### Block Gossip (Dual Mode)

```rust
enum BlockGossipMsg {
    Compact { height, hash, header_bytes },  // 310 bytes -- triggers pull
    Inline { height, hash, block_bytes, block_proof_bytes },  // full block
}
```

- Blocks < 1 MB total (block + proof): inlined in gossip message
- Blocks >= 1 MB: compact announcement, peers pull via request-response
- At 256 txs, block+proof is ~5.2 MB, so compact announcement + pull is used

### Request-Response Protocols

All use CBOR encoding. Network-isolated protocol IDs prevent cross-network pollution.

| Protocol | Request | Response | Timeout | Max Streams |
|----------|---------|----------|---------|-------------|
| `sync/headers/1` | start_height + count (max 512) | BlockHeader bytes | default | default |
| `sync/blocks/1` | height | block_bytes + block_proof_bytes | 30s | 64 |
| `sync/proof/1` | (unit) | proof_bytes + tip_header_bytes | 10s | default |
| `sync/manifest/1` | requester_height | manifest (tip, segments, headers, nullifiers) | 30s | 8 |
| `sync/segment/1` | segment_id + expected_tip | segment data (~3 MB) | 60s | 16 |
| `sync/mempool/1` | (unit) | up to 8192 pending txs | 10s | 4 |

### Wire Size Limits (Enforced, Hard Reject)

```
MAX_BLOCK_BYTES:           512 KB
MAX_BLOCK_PROOF_BYTES:       6 MB
MAX_SEGMENT_BYTES:           8 MB
MAX_RECURSIVE_PROOF_BYTES:  64 KB
MAX_HEADER_BYTES:          512 B
MAX_RECENT_HEADERS:        512
MAX_SYNC_TXS:            8,192
```

---

## Block Lifecycle

### Miner Produces Block

```
1. Build template:
   - Select txs from mempool (by fee, max 256)
   - Create coinbase (reward + fees -> miner_address)
   - Compute tx_root (Poseidon2b Merkle over tx_body_hashes)

2. Parallel execution:
   - Thread A: PoW search (Blake3, nonce space 2^128, ~15s target)
   - Thread B: prove_block (TxLogicAir x N + SpineGKR + AuthGKR + FRI)
     ZK proving takes ~10s for a full block

3. Both complete:
   - Seal header (embed proof_transcript_hash, witness_root)
   - Commit to MDBX (state transition applied)
   - Store BlockProof in T_BLOCK_PROOFS

4. Gossip immediately:
   - BlockGossipMsg (inline or compact depending on size)
   - Peers receive, verify, apply

5. Async (~2s later):
   - prove_recursive_step(block_proof) -> new RecursiveProof
   - Store in T_RECURSIVE_PROOF
   - Gossip RecursiveProofGossipMsg
```

### Node Receives Block

```
1. Receive BlockGossipMsg
   - Compact: request full block via sync/blocks/1
   - Inline: proceed directly

2. Rate limit check (40/peer/10s)

3. validate_block_full():
   - Native consensus (header chain, PoW, timestamps, fees, slots)
   - ZK verify (if has user txs)
   - State transition (apply, check roots)

4. Commit to MDBX:
   - Update state (segments, owner index)
   - Store header, recent block, block proof, undo log
   - Prune old entries beyond retention windows
   - Insert nullifiers, update tx_index

5. Post-commit:
   - Remove confirmed txs from mempool
   - Update wallet (check for owned outputs)
   - Notify subscribers
```

### Recursive Proof Advancement (Background, All Nodes)

Every node runs `run_recursive_proof_updater` (5-second poll):

```
Loop:
  current_proof = stored RecursiveProof at height M
  next = M + 1

  if next > tip - FINALITY_DEPTH:
    sleep (only prove finalized blocks)

  block_proof = load T_BLOCK_PROOFS[next]
  header = load T_HEADERS[next]

  if block has STUB_MARKER (coinbase-only):
    witness = null_block_replay_witness()
  else:
    witness = block_proof_to_replay_witness(block_proof)

  new_proof = prove_recursive_step(witness, header, current_proof.acc)
    -- ~2s on 8 cores

  store new_proof in T_RECURSIVE_PROOF
  gossip RecursiveProofGossipMsg { height: next, tip_hash, proof_bytes }
```

Every node eventually produces the same recursive proof as the miner, because
every node stores real BlockProof bytes received from gossip. The recursive
proof is NOT a miner privilege -- it is a network-wide property.

---

## Eclipse Resistance

Snapshot sync is the only "trust point". Defenses:

| Defense | How It Works |
|---------|-------------|
| Multi-peer manifest | Query up to 3 peers, select best by height |
| PoW chainwork threshold | Snapshot headers must have cumulative work >= MIN_SNAPSHOT_CHAINWORK |
| STARK unforgeable | RecursiveProof verification at ~2^-120 soundness |
| State root pinned in proof | proof.state_root must match snapshot headers |
| Header PoW verified | Each header in the snapshot has valid Blake3 PoW |

Even if ALL peers are adversarial, they cannot forge a valid snapshot: producing
a RecursiveProof for a fake state requires breaking ZK hardness; producing headers
with sufficient chainwork requires actually performing the PoW.

---

## Rate Limiting

| Resource | Limit | Window | Purpose |
|----------|-------|--------|---------|
| Blocks per peer | 40 | 10s | Prevent block flood |
| TXs per peer | 50 | 10s | Prevent tx spam |
| FetchHeaders | 1 outstanding | per peer | Prevent header flood |
| Orphan pool | 36 blocks max | evict lowest | Bound memory |
| Mempool | ANCHOR_DEPTH x BLOCK_MAX_TXS | rolling | Bound by design |

---

## Consensus Parameters

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `BLOCK_TIME` | 15 seconds | Target inter-block interval |
| `EPOCH_LENGTH` | 6 blocks | ASERT difficulty adjustment epoch |
| `FINALITY_DEPTH` | 18 blocks | Max reorg depth; undo/proof retention |
| `ANCHOR_DEPTH` | 144 blocks (~36 min) | TX validity window; nullifier retention |
| `BLOCK_MAX_TXS` | 256 | Max user transactions per block |
| `MAX_INPUTS` | 4 per tx | Input count limit |
| `MAX_OUTPUTS` | 8 per tx | Output count limit |
| `LOG_SLOTS_GENESIS` | 24 (16.7M slots) | Initial state capacity |
| `LOG_SLOTS_MAX` | 32 (4.3B slots) | Maximum state capacity |
| `LOG_SEGMENT_SIZE` | 16 (65,536 slots) | Slots per FRI segment |
| `EXPANSION_WINDOW` | 18 blocks | Median window for expansion trigger |
| `EXPAND threshold` | 75% occupancy | Trigger: median_active >= 75% capacity |
| `MAX_FUTURE_DRIFT` | 120 seconds | Max timestamp ahead of local clock |
| `MEDIAN_TIME_BLOCKS` | 11 | MTP calculation window |
| `MIN_FEE_BASE` | 5,000 uNOID (0.005) | Minimum relay fee per tx |
| `FEE_PER_OUTPUT` | 2,000 uNOID (0.002) | Additional fee per output |
| `BASE_REWARD` | 50 NOID | Starting block reward |
| `FLOOR_REWARD` | 1 NOID | Minimum reward (forever) |
| `MICRONOID_PER_NOID` | 1,000,000 | Precision unit |

---

## BlockHeader Wire Format (276 bytes)

```
Offset  Size  Field
  0      32   prev_block_hash        chain link
 32      32   state_root             Poseidon2b Merkle over segment FRI roots
 64      32   tx_root                Poseidon2b Merkle over tx_body_hashes
 96       8   timestamp              Unix seconds
104       8   height                 block number
112      32   miner_address          coinbase recipient
144      16   nonce                  Blake3 PoW nonce (128-bit)
160      32   difficulty_target      ASERT target (256-bit LE)
192      32   proof_transcript_hash  Fiat-Shamir hash of BlockProof
224      32   witness_root           Binius-packed DA payload root
256       4   log_slots              log2(state capacity)
260       8   active_slot_count      live UTXOs after this block
268       8   alloc_counter          allocator PRNG seed after this block
                                     Total: 276 bytes
```

`proof_transcript_hash` is non-zero for blocks with user txs (hash of the ZK
proof that validated them) and `STUB_MARKER = [1u8; 32]` for coinbase-only
blocks. This prevents an adversary from stripping the proof from a block that
has user transactions and claiming it was coinbase-only.
