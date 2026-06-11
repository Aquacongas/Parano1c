# Paranoid Network Infrastructure

## Philosophy

Paranoid is a **proof-native UTXO statechain**. The network does not execute
transactions — it verifies ZK proofs. Execution is local (wallet), validity is
global (ZK), ordering is PoW.

This has a concrete implication for every node type:

> A node that cannot verify ZK proofs is not a proof-native node.

Every full node independently verifies the ZK validity of every block it
receives. No node trusts miners to have done it correctly.

---

## Two Layers

```
Layer 1 — Ordering (PoW)
  Blake3 · ASERT difficulty · Block = header + transactions

Layer 2 — Validity (ZK)
  BlockProof  ~26 KB  per block  (TxLogicAir × N, BlockStateBindingAir, SpineGKR, AuthGKR)
  RecursiveProof  6.5 KB  O(1)   (proves entire chain history from genesis)
```

These layers are cleanly separated. `Block` (the wire struct) contains only
`header + transactions`. `BlockProof` and `RecursiveProof` are separate
structures propagated over their own channels.

---

## Node Types

### Full Node — `paranoid`

The backbone of the network. Three mutually exclusive operating modes selected
with `--mode`:

#### `--mode relay` *(default)*

```
Internal miner    : DISABLED
Block templates   : DISABLED (getBlockTemplate / submitBlock not exposed)
ZK block verify   : ENABLED  (validate_block_full on every received block with proof)
State snapshots   : SERVES   (to syncing peers)
RecursiveProof    : SERVES + GOSSIPS updates
P2P               : full gossip (blocks + txs + recursive proof updates)
RPC               : read-only public subset
```

Run by: exchanges, explorers, infrastructure operators, foundation.
Purpose: independent verification, snapshot serving, eclipse resistance.

#### `--mode miner`

```
Internal miner    : ENABLED  (PoW + ZK prove in parallel, ~15s target)
Block templates   : DISABLED (extminer cannot connect)
ZK block verify   : ENABLED
State snapshots   : SERVES
RecursiveProof    : SERVES + GOSSIPS updates (immediately after recursive step)
P2P               : full gossip
RPC               : local only (127.0.0.1 default)
```

Run by: miners. Requires heavy CPU (ZK proving ~10s per block).
The internal miner stores `BlockProof` bytes for every block it mines.
These enable real (non-null) recursive proof witnesses.

#### `--mode extminer`

```
Internal miner    : DISABLED
Block templates   : ENABLED  (getBlockTemplate / submitBlock)
Bearer auth       : REQUIRED (--mining-key TOKEN)
allow-custom-cb   : configurable (pool: off / permissionless: on)
ZK block verify   : ENABLED
State snapshots   : SERVES
RecursiveProof    : SERVES + GOSSIPS updates
P2P               : full gossip
RPC               : public mining endpoints + read-only
```

Run by: mining pools. The node does ZK proving; external `noid-extminer`
processes do only PoW hash search. Block rewards go to the extminer's coinbase
address when `--allow-custom-coinbase` is active.

---

### External PoW Miner — `noid-extminer`

```
Role              : PoW hash search only
ZK proving        : NONE (node does it)
P2P               : NONE
RPC               : JSON-RPC client → connects to --mode extminer node
State             : NONE
```

Fetches `getBlockTemplate`, searches for a valid Blake3 nonce using rayon,
submits the solved block via `submitBlock`. Completely stateless.

---

### Light Node — `paranoid-light` *(planned)*

```
Full UTXO state   : NONE
Block templates   : NONE
Snapshots         : NONE (does not serve)
ZK block verify   : via RecursiveProof only (no BlockProof verification)
RecursiveProof    : verifies every update  O(1) ~5ms
Mempool           : LogicProof verify + nullifier check + fee floor
                    (no slot-state check — no FRI state available)
Wallet            : block-tracking + RPC scan from full node
Headers           : last ~50 blocks only
P2P               : minimal (txs + block headers + RecursiveProof updates)
```

Security: equivalent to full node for chain validity via RecursiveProof.
Weaker only for: per-block ZK (needs full state) and slot-state mempool checks.

---

## P2P Wire Protocol

### Gossipsub Topics (per network)

| Topic | Message | Size |
|---|---|---|
| `/noid/mainnet/blocks/1` | `BlockGossipMsg` | ~276B + txs + ≤26KB proof |
| `/noid/mainnet/txs/1` | raw `TxIntent` bytes | ~1–2 KB |
| `/noid/mainnet/recproofs/1` | `RecursiveProofGossipMsg` | ~6.5 KB |

### Message Structures

```rust
// Block gossip — replaces bare block_bytes
struct BlockGossipMsg {
    block_bytes: Vec<u8>,       // Block::to_bytes() — header + transactions
    block_proof_bytes: Vec<u8>, // BlockProof bincode; EMPTY for coinbase-only blocks
}

// Recursive proof update — gossiped ~2s after block, once recursive step done
struct RecursiveProofGossipMsg {
    height: u64,
    tip_hash: [u8; 32],
    proof_bytes: Vec<u8>,  // RecursiveBlockProof bincode — 6.5 KB
}
```

### Request-Response (unchanged)

| Request | Response | Purpose |
|---|---|---|
| `GetHeadersRequest` | `GetHeadersResponse` | Reorg ancestor search |
| `GetRecentBlockRequest` | `GetRecentBlockResponse` | Block sync (last 18) |
| `GetRecursiveProofRequest` | `GetRecursiveProofResponse` | Snapshot verification |
| `GetStateSnapshotRequest` | `GetStateSnapshotResponse` | Initial sync |

---

## Block Lifecycle

```
Miner (--mode miner or --mode extminer):
  1. Build template (txs from mempool + coinbase)
  2. Parallel:
       PoW search (Blake3, ~15s target)
       ZK prove_block (~10s, TxLogicAir × N + SpineGKR + AuthGKR + FRI)
  3. Both done → seal block (embed proof_transcript_hash, witness_root)
  4. apply_found_block → commit to MDBX
  5. store.put_block_proof(h, block_proof_bytes)
  6. IMMEDIATELY gossip BlockGossipMsg { block_bytes, block_proof_bytes }
  7. Async (~2s): prove_recursive_step(block_proof_bytes) → new RecursiveProof
  8. store.put_recursive_proof(bytes)
  9. gossip RecursiveProofGossipMsg { height, tip_hash, proof_bytes }

Receiving Full Node (--mode relay / miner / extminer):
  1. Receive BlockGossipMsg
  2. Decode Block + block_proof_bytes
  3. If block_proof_bytes non-empty:
       validate_block_full(block, proof, ...) — PoW + ZK verify + apply_state_delta
  4. If block_proof_bytes empty (coinbase-only):
       apply_next_block(block, ...) — PoW + consensus only
  5. store.put_block_proof(h, block_proof_bytes)  ← enables real recursive witnesses
  6. Receive RecursiveProofGossipMsg (arrives ~2s later)
  7. Verify: proof.block_height > our stored height AND verify_tip/stark passes
  8. store.put_recursive_proof(bytes)
  9. run_recursive_proof_updater sees real BlockProof → uses real witness
```

### Coinbase-only blocks

Most blocks at low TPS contain only a coinbase transaction. No user ZK proofs
exist. These blocks:
- Have `block_proof_bytes = []` in `BlockGossipMsg`
- Are validated by native consensus only (PoW + state_root)
- The `STUB_MARKER [1u8;32]` in the header prevents fake "no proof" blocks that
  contain user transactions
- `run_recursive_proof_updater` uses `null_block_replay_witness` for them

---

## Synchronisation Flows

### A. Fresh Node → Existing Network

```
New Node                    Peer(s)
   |                           |
   |--- GetStateSnapshot ----→ |
   |--- GetRecursiveProof ---→ |   (to same peer)
   |                           |
   |←-- snapshot (h=N) ------  |   segments + recent_headers + nullifiers
   |←-- RecursiveProof (h=N) - |   6.5 KB
   |                           |
   verify_tip():               |
     STARK verify O(1)  ✅     |
     proof.acc.state_root      |
       == snapshot state_root  ✅
   apply_state_snapshot()      |
   store.put_recursive_proof() ← CRITICAL: saves peer's proof, updater starts here
   |                           |
   |--- SyncBlocksFrom(N+1) →  |   catch up missed blocks with BlockProof
   |←-- BlockGossipMsg × K --- |
   verify + apply each ✅      |
   |                           |
   Normal gossip ↔             |
```

**Multi-peer snapshot selection (Eclipse resistance):**
1. Connect to ≥3 peers, request snapshot from each
2. Collect candidates, pick snapshot with highest `tip_height`
3. Request `RecursiveProof` from the winning peer
4. `verify_tip()` — if STARK fails: reject snapshot, try next candidate
5. A forged RecursiveProof cannot pass STARK verification → safe from any peer

### B. Node Restart (has existing state)

```
Node restarts at h=N
  chain is current (tip_ts within 3 block-times) → sync_ready fires
  waits for peers → SyncBlocksFrom(N+1) → catches up via gossip
  run_recursive_proof_updater → reads stored proof at h=M → continues from M+1
```

### C. Miner Starts (`--mode miner`) on Fresh Network (`--genesis`)

```
paranoid --mode miner --genesis
  genesis flag → sync_ready fires immediately
  miner starts without waiting for peers
  mines block 1 → block 2 → ...
  recursive updater advances h=0 → h=1 → h=2 → ...
  peers join → receive blocks + RecursiveProofUpdates
```

### D. Node Behind by More than FINALITY_DEPTH (Deep Fork / Late Join)

```
Our tip: h=50   Peer's tip: h=200   Gap: 150 > FINALITY_DEPTH=18
  → deep fork detected → RequestStateSnapshot
  → Multi-peer snapshot selection (see Flow A)
  → verify_tip() with peer's RecursiveProof
  → apply snapshot at h=200
  → SyncBlocksFrom(201) → catch up
```

### E. Shallow Reorg (≤ FINALITY_DEPTH blocks)

```
Our tip: h=120   Competing block arrives for h=115 (parent in our chain at h=114)
  → BadParentHash → ancestor found at h=114 → FetchHeaders
  → apply_reorg_mdbx if competing chain has more chainwork
  → BlockProof witnesses for reorg blocks come with their BlockGossipMsg
  → run_recursive_proof_updater catches up from h=114 with real witnesses
```

### F. Extminer Submits Block

```
noid-extminer                paranoid (--mode extminer)
   |--- getBlockTemplate --→  |   template: header_core + block_hex + target
   |   PoW search (rayon)     |   meanwhile: prove_block running in background
   |← found nonce             |
   |--- submitBlock(hex) ---→ |
                              |   validate_block_consensus (PoW check)
                              |   apply block → commit
                              |   store.put_block_proof(h, proof_bytes)
                              |   gossip BlockGossipMsg { block_bytes, block_proof_bytes }
                              |   async: prove_recursive_step → gossip RecursiveProofGossipMsg
```

### G. RecursiveProof Advancement on Non-Miner Node

```
Full node receives BlockGossipMsg for h=N with block_proof_bytes
  → store.put_block_proof(N, bytes)

run_recursive_proof_updater (background, 5s poll):
  reads get_recursive_proof() → proof at h=M
  next_height = M+1 ≤ N - FINALITY_DEPTH
  reads get_block_proof(M+1) → REAL bytes (from gossip)
  block_proof_to_replay_witness(&bp) → real witness
  prove_recursive_step(real_witness, header, prev_acc) → new RecursiveProof at M+1
  put_recursive_proof(bytes)
  gossip RecursiveProofGossipMsg { height: M+1, ... }
```

Every node eventually produces the same quality recursive proof as the miner,
because every node stores real BlockProof bytes from gossip.

### H. RecursiveProof Update Received

```
Receive RecursiveProofGossipMsg { height: h, tip_hash, proof_bytes }
  deserialize RecursiveBlockProof
  if proof.block_height ≤ our stored rec_proof.block_height → ignore (stale)
  verify_step_stark_only(proof, prev_root, expected_root)  ← lightweight check
  if valid → store.put_recursive_proof(proof_bytes)
  (no re-gossip — gossipsub handles propagation)
```

---

## Security Model

### Full Node

| Guarantee | Mechanism |
|---|---|
| PoW validity per block | Blake3 + ASERT, verified independently |
| ZK tx validity per block | `verify_block(BlockProof)` ~50ms |
| State root correctness | ZK + native `apply_state_delta` |
| Chain history validity | RecursiveProof + `verify_tip` O(1) |
| Eclipse resistance | Multi-peer snapshot + STARK unforgeable |
| Tx validity at admission | `mempool.submit()` verifies LogicProof |

### Light Node

| Guarantee | Mechanism |
|---|---|
| PoW validity (recent) | Last ~50 headers checked directly |
| ZK chain validity (entire history) | `verify_tip(RecursiveProof)` O(1) ~5ms |
| ZK per-block validity | Indirect — via RecursiveProof chain |
| Tx validity at admission | LogicProof verify + nullifier check |
| My UTXOs | Block-tracking + RPC scan from full node |

The key distinction from Bitcoin SPV: a Paranoid light node verifying the
RecursiveProof has **cryptographic** guarantees for the entire chain history,
not just PoW-based probabilistic security. A forged chain cannot produce a
valid RecursiveProof without solving the underlying ZK hardness assumption.

### Why Miners Are Not Trusted Authorities

Every node independently enforces full ZK validity:

- Every node receives real `BlockProof` bytes in gossip
- Every node verifies `BlockProof` before applying a block
- Every node builds real RecursiveProofs from real witnesses
- No node needs to trust that the miner did ZK verification

The miner's role is: find PoW + create ZK proof. Once gossiped, every node
independently verifies both.

---

## Miner Template Protocol (extminer mode)

```
GET  paranoid_getBlockTemplate(coinbase_address)
  Returns:
    header_core_hex    : 212 bytes — PoW input (everything except nonce)
    block_hex          : full block with nonce=0 (to be patched by miner)
    nonce_offset       : byte offset of nonce in block_hex (always 144)
    difficulty_target_hex : 32-byte LE target
    height             : block height being mined
    n_txs              : number of transactions

POST paranoid_submitBlock(block_hex)
  The miner patches block_hex[nonce_offset..nonce_offset+16] with found nonce.
  Node validates PoW, applies block, stores proof, gossips.
  Returns: block hash hex on success.
```

`allow_custom_coinbase`: when enabled, the coinbase_address parameter in
`getBlockTemplate` is used as the miner's payout address. When disabled,
the node's configured address is always used (pool mode).

---

## Storage Layout (MDBX)

| Table | Key | Value | Retention |
|---|---|---|---|
| `T_HEADERS` | height (u64 LE) | BlockHeader bytes | forever |
| `T_BLOCKS` | height (u64 LE) | Block bytes | last 18 blocks |
| `T_BLOCK_PROOFS` | height (u64 LE) | BlockProof bincode | last 18 blocks |
| `T_SEGMENTS` | seg_id (u16) | SegmentColumns encoded | current state only |
| `T_RECURSIVE_PROOF` | `b"rec"` | RecursiveBlockProof bincode | forever (1 entry) |
| `T_NULLIFIERS` | tx_hash | block_height | last ANCHOR_DEPTH blocks |
| `T_UNDO_LOGS` | height | BlockUndoLog | last FINALITY_DEPTH blocks |
| `T_OWNER_INDEX` | owner_addr | slot_indices | current state |

`T_BLOCK_PROOFS` retention mirrors `T_BLOCKS` (18 blocks). This is sufficient
because:
- Reorgs are bounded by FINALITY_DEPTH=18
- `run_recursive_proof_updater` also needs at most FINALITY_DEPTH-old proofs
- New syncing nodes receive BlockProofs via `SyncBlocksFrom` gossip

---

## Configuration Flags Reference

```
paranoid [OPTIONS]

MODES (mutually exclusive):
  --mode relay     Default. Full node, no mining, no block templates.
  --mode miner     Internal PoW + ZK prover. Blocks extminer access.
  --mode extminer  Serves block templates. Requires --mining-key.

MINING:
  --mining-key TOKEN         Bearer token for extminer RPC auth (extminer mode).
  --allow-custom-coinbase    Allow extminers to set their own coinbase address.
                             Requires --mode extminer.
  --miner-address HEX        Coinbase address (miner mode). Default: wallet addr.
  --threads N                PoW threads. 0 = all cores.

NETWORK:
  --genesis                  Bootstrap a new network. Fires sync_ready immediately.
                             Use only for the very first node.
  --p2p-listen HOST:PORT     Default: 0.0.0.0:9400
  --rpc-listen HOST:PORT     Default: 127.0.0.1:9401
  --seed HOST:PORT           Seed peer (repeatable).

STORAGE:
  --data-dir PATH            Default: ~/.paranoid/data

OTHER:
  --config FILE              TOML config file.
  --log LEVEL                Log level (error/warn/info/debug). Default: info.
  --testnet                  Disable difficulty floor for fast local testing.
```

---

## Deployment Scenarios

### Solo Miner (single machine)

```bash
paranoid --mode miner --genesis  # first node, bootstraps network
paranoid --mode miner --seed node1.example.com:9400  # subsequent miners
```

### Mining Pool

```bash
# Pool node (heavy CPU for ZK proving + serving templates)
paranoid --mode extminer \
  --rpc-listen 0.0.0.0:9401 \
  --mining-key s3cr3t_pool_token \
  --allow-custom-coinbase

# Each rig connects to the pool node
noid-extminer --rpc http://pool.example.com:9401 \
  --key s3cr3t_pool_token \
  --coinbase noid1rig_payout_address
```

### Infrastructure / Relay Node

```bash
# Open relay (no mining, public RPC for explorers / light nodes)
paranoid --mode relay \
  --p2p-listen 0.0.0.0:9400 \
  --rpc-listen 0.0.0.0:9401 \
  --seed node1.noid.network
```

### Exchange Full Node

```bash
# Private relay (no external RPC, just P2P + local RPC for the exchange backend)
paranoid --mode relay \
  --p2p-listen 0.0.0.0:9400 \
  --rpc-listen 127.0.0.1:9401 \
  --seed node1.noid.network
```

### Local Dev / Testnet

```bash
# Node A: genesis miner
paranoid --mode miner --genesis --testnet \
  --p2p-listen 0.0.0.0:10000 --rpc-listen 127.0.0.1:10001

# Node B: relay (syncs from A)
paranoid --mode relay --testnet \
  --data-dir /tmp/nodeB \
  --p2p-listen 0.0.0.0:10002 --rpc-listen 127.0.0.1:10003 \
  --seed 127.0.0.1:10000

# Node C: relay (syncs from B — tests multi-hop sync)
paranoid --mode relay --testnet \
  --data-dir /tmp/nodeC \
  --p2p-listen 0.0.0.0:10004 --rpc-listen 127.0.0.1:10005 \
  --seed 127.0.0.1:10002
```

---

## Implementation Status

| Component | Status | Notes |
|---|---|---|
| `--mode` flag | ✅ DONE | Replaces `--mine`; miner/extminer/relay |
| `BlockGossipMsg` (block + proof bytes) | ✅ DONE | New gossip wire format with bincode |
| `RecursiveProofGossipMsg` | ✅ DONE | New gossip topic `/noid/mainnet/recproofs/1` |
| `validate_block_full` on block receive | ✅ DONE | `verify_block` under read lock before apply |
| Store received `BlockProof` | ✅ DONE | Stored in MDBX on P2P block receive |
| Miner: broadcast with proof | ✅ DONE | `block_proof_bytes` in `MinerEvent::BlockFound` |
| Any node: gossip `RecursiveProofUpdate` | ✅ DONE | `run_recursive_proof_updater` sends via p2p_cmd |
| Receive `RecursiveProofUpdate` | ✅ DONE | STARK-verified before storing |
| Save peer's RecursiveProof on snapshot apply | ✅ DONE | Fixed sync bug |
| Pre-genesis state_root fix in Mode A/B | ✅ DONE | Fixed `[0u8;32]` vs `genesis_state_root()` |
| `T_BLOCK_PROOFS` MDBX table | ✅ EXISTS | Already in `MdbxStore` |
| Multi-peer snapshot Eclipse resistance | ✅ EXISTS | `snapshot_candidates` |
