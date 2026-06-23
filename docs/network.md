# Paranoid Network Protocol

## Core Principle: No History, Full Security

Paranoid nodes do not store transaction history. A node holds:

1. **Current UTXO state** -- the live balances right now. Overwritten every block.
2. **Block headers** -- 276 bytes each, kept forever (~553 MB/year). The only
   permanent growth.
3. **Recent block data** -- block bodies, public Auth sidecars, BlockProofs, and undo logs for shallow reorgs, peer serving, and recursive proof advancement. Bodies/undo/sidecars are pruned at finality; `BlockProof` bytes are retained until both finalized and folded into the recursive proof.
4. **One recursive proof** -- ~43 KB encoded. Proves the entire chain from genesis to
   near-tip in one STARK verification taking a few milliseconds.

**Why this works without history:**

- **State correctness**: The recursive proof mathematically guarantees that
  the current state is the honest result of every transaction since genesis.
  No replay needed. The proof IS the replay, compressed to ~43 KB encoded.
- **Past payments**: Users store their own receipts (~300 bytes). A receipt
  contains a Merkle path from the transaction to the block's `tx_root`.
  Any node verifies it against its permanent header chain. No block body needed.
- **Replay protection**: Transactions expire by `epoch_anchor` depth. With
  `ANCHOR_DEPTH = 144`, consensus accepts anchors in an inclusive window of up to
  145 past header heights; nullifiers cover this bounded window, then self-prune.

A node that joins the network downloads the current state + recursive proof,
verifies the proof in a few milliseconds, and has full confidence. It never downloads
or processes historical blocks. Sync from zero takes 1-2 seconds.

The network does not re-execute wallet logic as the acceptance rule -- it verifies validity proofs. Execution is local to the wallet, validity is global through proof verification, ordering is PoW. Every node independently verifies block validity. No node trusts miners.

---

## Node Modes

A single binary, three mutually exclusive modes (`--mode`):

| Mode | Mining | Block Templates | Proof Verify | Serves State | P2P |
|------|--------|-----------------|--------------|--------------|-----|
| `relay` (default) | no | no | yes | yes | full gossip |
| `miner` | internal PoW + BlockProof generation | no | yes | yes | full gossip |
| `extminer` | BlockProof generation only (PoW external) | yes (requires `--mining-key`) | yes | yes | full gossip |

All modes are functionally identical in what they verify and store. The only
difference is block production.

**External PoW Miner (`noid-extminer`)** is a separate stateless binary. It
connects to an `--mode extminer` node via JSON-RPC, fetches templates, searches
for Blake3 nonces with rayon, and submits solved blocks. It has no P2P, no state,
no proof generation.

---

## What a Node Stores

### Storage Layout (MDBX, 14 tables)

| Table | Key | Value | Retention | Approx Size |
|-------|-----|-------|-----------|-------------|
| `T_HEADERS` | height (u64) | BlockHeader (276 bytes) | **forever** | ~553 MB/year at 15s blocks |
| `T_HASH_TO_HEIGHT` | block_hash (32B) | height (u64) | **forever** | ~84 MB/year |
| `T_CHAIN_TIP` | single key | (height, hash) | latest only | 40 bytes |
| `T_SEGMENTS` | seg_id (u16) | SegmentColumns (3 x 64K x 16B) | current state | ~3 MB per materialized segment |
| `T_STATE_META` | single key | (log_slots, active_count, alloc_counter) | latest only | 20 bytes |
| `T_OWNER_INDEX` | owner_addr (32B) | packed Vec<(slot_u32, value_u64)> | current state | proportional to UTXO set |
| `T_RECURSIVE_PROOF` | single key | RecursiveBlockProof bytes | latest only | ~43 KB encoded |
| `T_RECENT_BLOCKS` | height (u64) | full Block bytes | last 18 blocks | ~4 MB |
| `T_BLOCK_PROOFS` | height (u64) | BlockProof bincode | finalized and recursive-consumed window | shape-mix dependent; bounded by proof caps |
| `T_BLOCK_AUTH_SIDECARS` | height (u64) | public BlockAuthSidecar bincode | last 18 blocks | shape-mix dependent; public Auth proofs only |
| `T_UNDO_LOGS` | height (u64) | BlockUndoLog | last 18 blocks | ~2 MB |
| `T_NULLIFIERS` | tx_body_hash (32B) | height (u64) | bounded anchor window | ~1.2 MB |
| `T_NULLIFIER_BLOCKS` | height (u64) | packed tx_body_hashes | bounded anchor window | ~1.2 MB |
| `T_TX_INDEX` | tx_body_hash (32B) | (height, position) | bounded anchor window | ~1.2 MB |

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

**Recent block data (FINALITY_DEPTH = 18):**
Used for three purposes:
1. **Shallow reorgs**: if a competing chain with more chainwork arrives for
   the last <=18 blocks, the node can undo and re-apply using undo logs.
2. **Peer serving**: a syncing node that is nearly caught up can request the
   last few blocks + proofs instead of a full snapshot.
3. **Recursive folding**: finalized user-transaction `BlockProof` bytes remain
   available until the background recursive updater has consumed that height.

After finality, block bodies, undo logs, and public Auth sidecars are pruned. `BlockProof` pruning is additionally gated by the stored recursive proof height to avoid racing the recursive updater.

**Nullifiers (`ANCHOR_DEPTH = 144`):**
A tx's `epoch_anchor` references a recent block header hash. For block consensus,
valid anchor heights are:

```text
[block_height - ANCHOR_DEPTH - 1, block_height - 1]
```

with saturation near genesis, so the window contains up to 145 possible anchor
heights. Mempool admission uses the analogous tip-inclusive recent-header window.
Nullifiers (`tx_body_hash` values) are tracked for this bounded window to prevent
replay while an anchor remains admissible. After the anchor expires, replay is
structurally impossible even without the nullifier entry.
The two mechanisms are redundant within the window and self-sufficient after:
- Within the anchor window: nullifier prevents replay (fast, O(1) lookup)
- After the anchor window: anchor expiry prevents replay (no storage needed)

### Storage Size Estimates

**Permanent growth (headers only):**
2,102,400 blocks/year * 276 bytes = ~553 MB/year. This is the ONLY component
that grows unboundedly. After 10 years: ~5.5 GB. After 100 years: ~55 GB.
Fits on any modern device indefinitely.

**State (unpredictable, bounded by capacity):**
Each materialized segment is ~3 MB. State auto-expands from 2^24 to 2^32 slots
as the network fills. Whether this takes 1 year or 50 years depends on adoption.
Only segments with live UTXOs are materialized (rest are virtual zero, no disk).
At full capacity (2^32 slots, all materialized): 2^32 × 48 bytes ≈ 192 GiB max theoretical ceiling.

**Volatile (fixed, independent of chain age):**
- Recent bodies + sidecars + undo: finality window only; shape-mix dependent
- BlockProof bytes: finality window plus recursive-consumption guard; bounded by wire caps
- Nullifiers + tx_index: bounded by the `ANCHOR_DEPTH = 144` recent-header window (up to 145 anchor heights)
- Recursive proof: ~43 KB encoded (single latest)

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
   - **Validity**: the tx's `LogicProof` was verified at inclusion (header's
     `proof_transcript_hash` commits to the BlockProof)
   - **Finality**: the block had real PoW cost (nonce + difficulty in header)

Unlike Bitcoin SPV (which proves inclusion but trusts miners for validity),
Paranoid receipts prove both inclusion AND validity. A forged transaction
cannot produce a valid BlockProof, so it cannot enter a block's tx_root.

---

## Synchronisation

Two sync modes only:
1. **Snapshot sync** (gap > 18 blocks or fresh node): download authenticated current state + recursive proof, verify, done.
2. **Block-by-block** (gap <= 18 blocks): apply recent blocks with full proof verification.

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
   |    Reject if chainwork does not strictly exceed MIN_SNAPSHOT_CHAINWORK
   |
   |--- GetRecursiveProof ------> Best peer
   |<-- RecursiveProof (~43 KB encoded)
   |
   | 3. Verify the recursive proof and header anchor:
   |    - STARK verify: O(1), a few milliseconds
   |    - proof height <= snapshot tip
   |    - proof lag <= FINALITY_DEPTH + 2
   |    - proof state root matches the corresponding stored header root
   |    - manifest segment-root table reconstructs the snapshot tip state_root
   |    If verification fails: reject this peer, try next candidate.
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
from h=0 to h=21 in ~1s including proof verification of all received blocks).

### Flow B: Node Restarts (Has State)

```
Node restarts. Reads MDBX. tip = h=N.
  - If tip timestamp is within 3 minutes of wall clock:
      sync_ready immediately, wait for gossip
  - If slightly behind (<=18 blocks):
      SyncBlocksFrom(N+1) -- download and verify each block
  - If far behind (>18 blocks):
      same as Flow A (snapshot sync)
```

No special "recovery mode". Same logic as a fresh node with gap detection.

### Flow C: Node Behind > 18 Blocks

If a node was offline for 2 hours (~480 blocks), it does NOT replay them:

1. Recent block bodies are retained only for the finality window; deep replay is not the sync path.
2. The node requests a fresh state snapshot + RecursiveProof from peers.
3. Verifies the RecursiveProof (STARK, a few milliseconds). Done.
4. Overwrites stale local state. Recursive updater continues from here.

This is safe because the RecursiveProof is unforgeable (~2^-120), the
state_root is committed in the proof, and snapshot headers have valid PoW
with cumulative chainwork above threshold.

### Flow D: Shallow Reorg (<=18 blocks)

```
Our tip: h=120. Competing block at h=115 (parent at h=114) arrives.
  1. FetchHeaders from peer to find common ancestor (h=114)
  2. Compare cumulative chainwork:
     - Reorg if competing extra work is strictly greater
     - If extra work is equal, reorg only if the competing tip height is greater
  3. If reorg:
     - Undo blocks h=120..115 using T_UNDO_LOGS
     - Apply competing blocks h=115..h=120+ with full proof verification
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
- Block bytes <= 1 MiB
- BlockProof bytes <= 32 MiB
- BlockAuthSidecar bytes <= 32 MiB
- BlockProof + BlockAuthSidecar <= 48 MiB
- Deserialization succeeds
- Per-peer rate limit: 40 blocks / 10 seconds

**Stage 2: Cheap Consensus Checks (`validate_block_checks`, O(txs))**

| Check | Error | Purpose |
|-------|-------|---------|
| `header.prev_hash == parent.hash` | BadParentHash | Chain integrity |
| `header.height == parent.height + 1` | HeightMismatch | Monotonicity |
| ASERT difficulty matches expected | BadDifficulty | PoW calibration |
| `header.timestamp > median_time_past(11)` | TimestampTooOld | Time ordering |
| `header.timestamp <= local_time + 120s` | TimestampTooFuture | Clock drift |
| `Blake3(header_core_bytes(header)) <= target` | BadPoW | Proof of work; `header_core` already includes nonce bytes `[144..160]` |
| `block.transactions.len() <= 256` | TooManyTxs | Block size bound |
| No cross-tx slot conflicts (HashSet) | SlotConflict | Double-spend in block |
| Per-tx: fee fits u64 | BadFee | Overflow prevention |
| Per-tx: epoch_anchor != [0;32] (non-cb) | BadEpochAnchor | Anchor required |
| Per-tx: nullifier not in set | NullifierCollision | Replay prevention |
| Coinbase: first tx, 1 valid output | ShapeMismatch | Structure |
| Coinbase: value <= reward + fees | InflatedCoinbase | Inflation prevention |
| `header.log_slots` matches expansion rule | BadLogSlotsExpansion | State capacity |

**Stage 3: Full BlockProof Verification (`validate_block_from_network`, proof-native)**

Only for blocks with user transactions (coinbase-only blocks skip this):

| Check | Error | Purpose |
|-------|-------|---------|
| proof/header transcript binding | BadProofTranscript | Header commits to the canonical `BlockProof` transcript |
| sidecar/header binding | AuthSidecarRootMismatch | `witness_root` commits to the public Auth sidecar in block order |
| bucket coverage: every non-coinbase tx appears once in the correct shape bucket | ShapeMismatch | Standard/Sweep binding |
| SpineGKR / sweep spine: tx_body_hash computation correct | StarkInvalid | TX body integrity |
| AuthGKR / sweep auth: Address = H_ADDR(secret), AuthTag = H_AUTH(secret, body) | StarkInvalid | Ownership proof |
| TxLogicAir / SweepTxLogicAir: balance, range, binding | StarkInvalid | TX validity |
| NativeDelta identity + pre/post segment MLE openings | StateMleOpeningFailed | State consistency under prev/new state roots |
| per-bucket source-bound FRI opening | StarkInvalid | Commitment/source binding |

**Stage 4: Commit Proven State Delta (`apply_state_delta`)**

NativeDelta verification reconstructs ordered per-segment claims from the canonical block body and pre-state, checks the random-point delta identity, and binds pre/post lane values to segment MLE openings under `prev_state_root` and `new_state_root`. `apply_state_delta` therefore commits the proven delta. It does not re-run wallet logic or create a second user-transaction acceptance path.

| Check | Error | Purpose |
|-------|-------|---------|
| `tx_root == header.tx_root` | BadTxRoot | TX binding |
| `active_slot_count == header.active_slot_count` | ShapeMismatch | Counter |
| `alloc_counter == header.alloc_counter` | ShapeMismatch | Allocator |
| `log_slots == header.log_slots` | BadLogSlotsExpansion | State capacity |

After all 4 stages pass: block is committed atomically to MDBX, then gossiped to peers.

### Coinbase-Only Blocks (No User TXs)

Most blocks at low TPS contain only a coinbase transaction. These:
- Have empty `block_proof_bytes` and empty `block_auth_sidecar_bytes` in gossip
- Skip user-transaction proof verification entirely (no user txs to prove)
- Are validated by proof/header stub binding, cheap consensus checks, and deterministic `apply_state_delta`
- `header.proof_transcript_hash` = `STUB_MARKER [1u8; 32]` (prevents an
  adversary from omitting the proof on blocks that DO have user txs)

### Mempool TX Admission

When a transaction arrives via gossip, BEFORE entering the mempool:

| # | Check | Purpose |
|---|-------|---------|
| 0 | Wire size <= 512 KiB global and <=384 KiB shape cap | DoS prevention |
| 1 | Per-peer rate: 50 txs / 10 seconds | Flood prevention |
| 2 | Fee minimum: base + I/O + occupancy-scaled net-new-state growth | Spam prevention |
| 3 | Body hash binding (recompute and compare) | Integrity |
| 4 | Coinbase: must have exactly 1 valid output, fee = 0 | Structure |
| 5 | Epoch anchor references a known header in the bounded anchor window | Freshness |
| 6 | Nullifier not in nullifier set | Replay prevention |
| 7 | No slot conflicts with existing mempool txs | Double-spend |
| 8 | Input slots exist in state with matching value + owner | Liveness |
| 9 | Output slots are EMPTY in state | Availability |
| 10 | LogicProof verification in a semaphore-bounded `spawn_blocking` worker | Proof validity without holding the mempool lock |

The implementation first runs checks 0–9 as a cheap pre-filter, then verifies the LogicProof outside the lock, then reacquires the lock and reruns the cheap checks against the current chain/mempool view before final insertion. `TxAdmitted`/gossip is emitted only after this final admission; invalid proofs never enter the admitted pool and are not gossiped as accepted transactions.

### Recursive Proof Verification (On Snapshot Sync)

When receiving a RecursiveProof from a peer during snapshot sync:

| Check | Purpose |
|-------|---------|
| proof bytes non-empty and <=64 KiB | DoS prevention |
| STARK verify passes (RecursiveBlockAir, ~5ms) | Proof validity |
| proof height <= snapshot tip and lag <= FINALITY_DEPTH + 2 | Freshness |
| proof state root matches the corresponding header root | State binding |
| manifest segment roots reconstruct the snapshot tip state root | Snapshot binding |
| chain_hash matches the header-derived chain hash | Chain integrity |
| PoW chainwork of snapshot headers strictly exceeds MIN_SNAPSHOT_CHAINWORK | Eclipse resistance |

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
Flood publish:   false
Peer exchange:   enabled
Dedup:           blake3 content hash
```

### Gossipsub Topics

| Topic | Message Type | Size |
|-------|-------------|------|
| `/noid/{network}/blocks/1` | BlockGossipMsg | 310B compact or <1MB inline |
| `/noid/{network}/txs/1` | raw TxIntent bytes | shape-capped at 384 KiB; current wallet bundles are ~284–291 KiB on the reference laptop |
| `/noid/{network}/recproofs/1` | RecursiveProofGossipMsg | ~43 KB encoded |

### Block Gossip (Dual Mode)

```rust
enum BlockGossipMsg {
    Compact { height, hash, header_bytes },  // header only -- triggers pull
    Inline { height, hash, block_bytes, block_proof_bytes, block_auth_sidecar_bytes },
}
```

- Blocks < 1 MiB total (block + proof + public sidecar): inlined in gossip message
- Blocks >= 1 MiB: compact announcement, peers pull via request-response
- Large proof-native user-tx blocks normally use compact announcement + pull

### Request-Response Protocols

All use CBOR encoding. Network-isolated protocol IDs prevent cross-network pollution.

| Protocol | Request | Response | Timeout | Max Streams |
|----------|---------|----------|---------|-------------|
| `sync/headers/1` | start_height + count (max 512) | BlockHeader bytes | default | default |
| `sync/block/1` | height | block_bytes + block_proof_bytes + block_auth_sidecar_bytes | 30s | 8 |
| `sync/proof/1` | (unit) | proof_bytes + tip_header_bytes | 10s | default |
| `sync/manifest/1` | requester_height | manifest (tip, segments, headers, nullifiers) | 30s | 8 |
| `sync/segment/1` | segment_id + expected_tip | segment data (~3 MB) | 60s | 8 client in-flight; 2 server encoders |
| `{protocol_id}/mempool/1` | (unit) | up to 128 pending txs / 16 MiB | 10s | 4 |

### Wire Size Limits (Enforced, Hard Reject)

```
MAX_TX_INTENT_BYTES_GLOBAL:          512 KiB
MAX_STANDARD_TX_INTENT_BYTES:        384 KiB
MAX_SWEEP_TX_INTENT_BYTES:           384 KiB
MAX_MEMPOOL_TXS:                     1024
MAX_MEMPOOL_BYTES:                   384 MiB
MAX_MEMPOOL_SYNC_TXS:                128
MAX_MEMPOOL_SYNC_BYTES:              16 MiB
MAX_BLOCK_BYTES:                     1 MiB
MAX_BLOCK_PROOF_BYTES:               32 MiB
MAX_BLOCK_AUTH_SIDECAR_BYTES:        32 MiB
MAX_BLOCK_PROOF_PLUS_SIDECAR_BYTES:  48 MiB
GOSSIP_MAX_TRANSMIT_BYTES:           2 MiB
INLINE_BLOCK_GOSSIP_THRESHOLD:       1 MiB
MAX_RECURSIVE_PROOF_BYTES:           64 KiB
MAX_HEADER_BYTES:                    512 B
MAX_SEGMENT_BYTES:                   8 MiB
MAX_SNAPSHOT_MANIFEST_SEGMENTS:      65,536
MAX_INFLIGHT_SEGMENTS:               8
MAX_ORPHAN_POOL:                     36
MAX_ORPHAN_POOL_BYTES:               128 MiB
```

Snapshot segment memory is bounded by `MAX_INFLIGHT_SEGMENTS × MAX_SEGMENT_BYTES = 64 MiB` on the requesting side. There is no separate 1 GiB snapshot-total cap: the authenticated manifest may describe any sparse subset up to `MAX_SNAPSHOT_MANIFEST_SEGMENTS = 65,536` segment IDs, and each accepted segment is independently size-limited, decoded exactly, root-checked, and applied to MDBX.

---

## Block Lifecycle

### Miner Produces Block

```
1. Build template:
   - Select txs from mempool (by fee, max 256)
   - Create coinbase (reward + fees -> miner_address)
   - Compute tx_root (Poseidon2b Merkle over tx_body_hashes)

2. Parallel execution:
   - Thread A: PoW search (`Blake3(header_core)`, patch nonce bytes `[144..160]`, nonce space 2^128, ~15s target)
   - Thread B: prove_block (shape buckets + NativeDelta state openings + per-bucket source-bound FRI)
     BlockProof generation time depends on tx count and shape mix. On the reference 2023 Intel Core i7-1365U laptop, the current `block_scaling` 100-transaction standard-only fixture mix proves in ~14.75s and verifies in ~4.91s; proof + sidecar is ~22.55 MB.

3. Both complete:
   - Seal header (embed proof_transcript_hash, witness_root)
   - Commit to MDBX (state transition applied)
   - Store BlockProof in T_BLOCK_PROOFS and public Auth sidecar in T_BLOCK_AUTH_SIDECARS

4. Gossip immediately:
   - BlockGossipMsg (inline or compact depending on size)
   - Peers receive, verify, apply

5. Background recursive updater:
   - when the block is finalized, prove_recursive_step(block_proof) -> new RecursiveProof
   - Store in T_RECURSIVE_PROOF
   - Gossip RecursiveProofGossipMsg
```

### Node Receives Block

```
1. Receive BlockGossipMsg
   - Compact: request full block via sync/block/1
   - Inline: proceed directly

2. Rate limit check (40/peer/10s)

3. Proof-native apply path (`MdbxChainContext::apply_next_block`):
   - Bind proof bytes to `header.proof_transcript_hash`
   - Run cheap consensus checks (header chain, PoW, timestamps, fees, slot conflicts)
   - For user-tx blocks, run `validate_block_from_network` over the full canonical `BlockProof`
   - For coinbase-only blocks, enforce the canonical stub marker and deterministic coinbase delta
   - Commit the proven state delta via `apply_state_delta`

4. Atomic MDBX commit:
   - Update state (segments, owner index)
   - Store header, recent block, block proof, public Auth sidecar, undo log
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

  store new_proof in T_RECURSIVE_PROOF
  gossip RecursiveProofGossipMsg { height: next, tip_hash, proof_bytes }
```

Every node eventually produces the same recursive proof as the miner for finalized history, because every node stores real BlockProof bytes received from gossip until recursive folding consumes them. The recursive proof is not a miner privilege; it is a network-wide property.

---

## Eclipse Resistance

Snapshot sync is the only "trust point". Defenses:

| Defense | How It Works |
|---------|-------------|
| Multi-peer manifest | Query up to 3 peers, select best by height |
| PoW chainwork threshold | Snapshot headers must have cumulative work strictly above MIN_SNAPSHOT_CHAINWORK |
| STARK unforgeable | RecursiveProof verification at ~2^-120 soundness |
| State root pinned in proof | proof state root must match the corresponding stored header root |
| Manifest state-root binding | Sparse segment-root table must reconstruct the snapshot tip state_root |
| Header PoW verified | Each header in the snapshot has valid Blake3 PoW |

Even if ALL peers are adversarial, they cannot forge a valid snapshot: producing
a RecursiveProof for a fake state requires breaking the transparent proof system's soundness; producing headers with sufficient chainwork requires actually performing the PoW.

---

## Rate Limiting

| Resource | Limit | Window | Purpose |
|----------|-------|--------|---------|
| Blocks per peer | 40 | 10s | Prevent block flood |
| TXs per peer | 50 | 10s | Prevent tx spam |
| FetchHeaders | 1 outstanding | per peer | Prevent header flood |
| Orphan pool | 36 blocks max | evict lowest | Bound memory |
| Mempool | 1024 tx / 384 MiB | rolling | Bound RAM and relay work |

---

## Consensus Parameters

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `BLOCK_TIME` | 15 seconds | Target inter-block interval |
| `EPOCH_LENGTH` | 6 blocks | ASERT difficulty adjustment epoch |
| `FINALITY_DEPTH` | 18 blocks | Max reorg depth; undo/proof retention |
| `ANCHOR_DEPTH` | 144 depth parameter (~36 min) | TX validity window; consensus anchor heights are inclusive up to 145 recent past headers |
| `BLOCK_MAX_TXS` | 256 | Max transactions per block, including coinbase when present |
| `Standard4x8` | 4 inputs / 8 outputs | Default payment shape |
| `Sweep25x2` | 25 inputs / 2 outputs | Sweep/consolidation shape |
| `LOG_SLOTS_GENESIS` | 24 (16.7M slots) | Initial state capacity |
| `LOG_SLOTS_MAX` | 32 (4.3B slots) | Maximum state capacity |
| `LOG_SEGMENT_SIZE` | 16 (65,536 slots) | Slots per FRI segment |
| `EXPANSION_WINDOW` | 18 blocks | Median window for expansion trigger |
| `EXPAND threshold` | 75% occupancy | Trigger: median_active >= 75% capacity |
| `MAX_FUTURE_DRIFT` | 120 seconds | Max timestamp ahead of local clock |
| `MEDIAN_TIME_BLOCKS` | 11 | MTP calculation window |
| `MIN_FEE_BASE` | 5,000 μNOID (0.005) | Base fee per non-coinbase tx |
| `FEE_PER_INPUT` | 100 μNOID (0.0001) | Small anti-DoS/prover-work fee per live input |
| `FEE_PER_OUTPUT` | 700 μNOID (0.0007) | Fee per live output |
| `STATE_GROWTH_FEE_BASE` | 2,500 μNOID (0.0025) | Base burned fee per net-new UTXO slot |
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
224      32   witness_root           BlockAuthSidecar root
256       4   log_slots              log2(state capacity)
260       8   active_slot_count      live UTXOs after this block
268       8   alloc_counter          allocator PRNG seed after this block
                                     Total: 276 bytes
```

For user-transaction blocks, `proof_transcript_hash = block_recursive_claim_hash(BlockProof)` and `witness_root = block_auth_sidecar_root(block, sidecar)`. Coinbase-only blocks use `proof_transcript_hash = STUB_MARKER = [1u8; 32]` with empty proof and sidecar bytes. This prevents an adversary from stripping the proof from a block that has user transactions and claiming it was coinbase-only.

PoW does not hash the full 276-byte header directly. It hashes the 212-byte `header_core`: fields `0..192` above, followed by `log_slots`, `active_slot_count`, and `alloc_counter`; `proof_transcript_hash` and `witness_root` are omitted. The nonce is included at byte offset 144 and patched by miners.
