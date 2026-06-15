# Paranoid Infrastructure Audit — Findings and Fix Plan

Date: 2026-06-15

Scope:

- `noid_p2p`
- `noid_node`
- `noid_mempool`
- `noid_rpc`
- `noid_chain`
- `noid_miner`
- relevant protocol/security/network documentation

Context:

Paranoid is a proof-native UTXO statechain. Nodes must not execute transactions as the source of validity; they must verify mathematical validity proofs and only then commit state. The audit below is ordered by recommended fix priority, not by crate.

---

## Progress log

### 2026-06-15 — Iteration 1

Completed / partially completed:

- `PZ-01`: **DONE (initial)** — headers-only snapshot acceptance removed; non-empty `RecursiveProof` is now required for snapshot sync; `apply_state_snapshot()` now checks `tip_hash == full_block_hash(tip_header)`.
- `PZ-02`: **DONE (initial)** — added shared `validate_block_proof_binding()` helper and wired it into P2P block handling and RPC coinbase-only submit guard.
- `PZ-03`: **DONE (initial)** — `getBlockTemplate` returns `block_proof_hex`; `submitBlock(block_hex, block_proof_hex)` verifies proof/header binding, proof `log_slots` binding, cheap consensus, and ZK proof before native apply; extminer submits proof bytes with solved blocks.
- `PZ-06`: **DONE** — mempool now rejects non-coinbase transactions with empty logic proof and rejects oversized logic proofs.
- `PZ-07`: **PARTIAL** — mempool-sync response now enforces per-tx and total byte caps on the client side; per-peer cooldown still pending.
- `PZ-08`: **DONE** — inbound headers request count is server-capped to 512 with saturating arithmetic.
- `PZ-09`: **PARTIAL** — recursive proof gossip now enforces the 64KB proof-size cap; per-peer rate limit still pending.
- `PZ-16`: **DONE** — RPC template proving no longer silently falls back to stub proof on user-tx proof failure.

Validation run:

```bash
cargo check -p noid_chain -p noid_mempool -p noid_p2p -p noid_miner -p noid_rpc -p noid_node
cargo fmt
```

Result: `cargo check` passed.

### 2026-06-15 — Iteration 2

Completed / partially completed:

- `PZ-04`: **DONE (initial)** — P2P tip/orphan/reorg paths now run cheap consensus + proof/header binding + proof `log_slots`/header binding before ZK; fork/orphan ZK verification is postponed until the exact parent pre-state is current; reorg blocks are ZK-verified through a `MdbxChainContext` pre-apply hook after internal revert and before apply.
- `PZ-05`: **DONE (initial)** — orphan pool stores proof bytes, peer id, and receive time; chained orphans and reorg candidates preserve proof bytes; reorg-applied user-tx blocks are ZK-verified against fork pre-state and proof bytes are persisted to `T_BLOCK_PROOFS`. ZK validation now preloads evicted MDBX segments so state-binding does not see false virtual-zero slots.
- `PZ-07`: **DONE (initial)** — mempool sync has per-TX and total byte caps plus a per-peer outbound request cooldown before sending duplicate sync requests.
- `PZ-09`: **DONE (initial)** — recursive proof gossip now has both size cap and per-peer P2P-layer rate limit before `NetworkEvent` emission.
- `PZ-10`: **DONE (initial)** — tx gossip, block gossip/pull responses, and recursive proof gossip now enforce cheap size/rate filters inside `noid_p2p` before emitting into the bounded `NetworkEvent` channel. Separate priority channels remain an optional future scalability improvement.
- `PZ-14`: **PARTIAL** — node and P2P snapshot paths now enforce the documented 8MB segment cap, a 1GB total snapshot byte cap, and manifest segment-count sanity based on `log_slots/eff_log`. Streaming decode/write is still pending.
- `PZ-11`: **DONE** — Identify address ingestion is capped to 8 routable addresses per peer and filters localhost/private/link-local/multicast/unspecified IP addresses.
- `PZ-15`: **DONE** — mainnet gossipsub now uses mesh publish (`flood_publish(false)`) to avoid O(connected_peers) bandwidth amplification.

Validation run:

```bash
cargo check --release -p noid_node -p noid_p2p
cargo fmt
cargo test --release -p noid_p2p -p noid_node
cargo test --release -p noid_chain -p noid_mempool -p noid_p2p -p noid_miner -p noid_rpc -p noid_node
```

Result: all commands passed.

### 2026-06-15 — Iteration 3

Completed / partially completed:

- `PZ-12`: **DONE (initial)** — template construction now captures a `TemplateChainSnapshot` under the chain lock and drops the lock before awaiting mempool selection / doing template work. Snapshot capture preloads evicted segments before cloning state to preserve template correctness.
- `PZ-13`: **DONE (initial)** — state segment serving now clones columns in the swarm handler but performs segment encoding on a bounded `spawn_blocking` worker pool; encoded responses are sent back through an internal channel to the swarm task.
- `PZ-14`: **PARTIAL+** — snapshot caps remain in place; `apply_state_snapshot` now consumes decoded segment columns by value and writes MDBX / rebuilds owner index by reference from installed state, avoiding a second full segment clone. Full network-to-MDBX streaming remains future work.

Validation run:

```bash
cargo fmt
cargo check --release -p noid_miner -p noid_rpc -p noid_node
cargo check --release -p noid_p2p -p noid_node
cargo check --release -p noid_chain -p noid_node
cargo test --release -p noid_chain -p noid_p2p -p noid_miner -p noid_rpc -p noid_node
```

Result: all commands passed.

### 2026-06-15 — Iteration 4

Completed / partially completed:

- Added a real multi-node live-test harness at `scripts/live_multinode_scenarios.py`.
- Ran live scenarios on real `paranoid` daemon processes with isolated data dirs and ports:
  - genesis miner produced 18+ blocks and recursive proof;
  - relay node synced from genesis miner via proof-backed snapshot;
  - third relay synced using only the second relay as seed;
  - wallet send from node1 to node3 propagated through all three mempools with proof bytes and confirmed in a mined block;
  - node1 was stopped, node4 joined as a late miner, synced from relays, then mined;
  - node2 was stopped, node1 restarted as a second miner, two miners produced competing blocks and converged;
  - node2 restarted and caught up; all four nodes ended at the same exact tip.
- Minor UX/log cleanup: normal miner prover-busy backpressure messages were downgraded from `warn` to `debug` so user-tx proving does not look like an operational warning.

Validation run:

```bash
cargo fmt
cargo test --release -p noid_miner
cargo build --release -p noid_node
python3 scripts/live_multinode_scenarios.py
```

Result: all commands passed. Final live-test tip: height 27, same hash on all four nodes, empty mempools.

### 2026-06-15 — Iteration 5

Completed / partially completed:

- Added CLI-focused live-test harness at `scripts/live_cli_wallet_scenarios.py`.
- Ran user-facing `noid-cli` scenarios against real daemon nodes:
  - command output sanity for `status`, `mining`, `peers`, `proof`, `state`, `estimate-fee`;
  - wallet address display, fresh address generation, address listing, and address validation;
  - `scan`, `balance`, `utxos` before and after receiving funds;
  - sending NOID via `noid-cli send` to two fresh recipient addresses;
  - mempool display and `mempool-tx` proof visibility while pending;
  - confirmation checks through `tx`;
  - recipient `scan` discovers both received UTXOs, per-address `utxos-of` works, and `history` shows received entries;
  - sender `history` shows sent entries;
  - sender exports receipt with `receipt`, receipt verifies with `verify` on another node, and a tampered receipt is rejected.

Validation run:

```bash
cargo build --release -p noid_node --bin paranoid --bin noid-cli
python3 scripts/live_cli_wallet_scenarios.py
```

Result: all commands passed. Final CLI live-test tip: height 24, same hash on all three nodes, recipient balance 2.000000 NOID across two UTXOs, empty mempools.

---

## 0. Architectural invariants to preserve

Before fixing individual bugs, keep these invariants explicit:

1. **User-transaction blocks must always carry a valid `BlockProof`.**
   - Coinbase-only blocks may use the stub marker `[1u8; 32]` and empty proof bytes.
   - Any block containing at least one non-coinbase transaction must have non-empty proof bytes.

2. **The header must bind the exact proof bytes.**
   - `block.header.proof_transcript_hash == proof_transcript_hash(block_proof_bytes)` for user-tx blocks.
   - A non-zero random-looking hash is not enough.

3. **Snapshot sync must be proof-backed.**
   - A snapshot state root being committed by PoW headers is not equivalent to proof-native chain validity.
   - Fresh nodes must not accept state from headers-only verification, except possibly the hardcoded genesis state.

4. **Cheap validation must happen before expensive validation.**
   - Wire limits and native consensus checks must run before ZK proof verification.

5. **Orphans/reorg blocks must retain their proof bytes.**
   - A `Block` without its proof is insufficient for a proof-native fork/reorg path.

---

# Phase 1 — Critical consensus/proof-native safety fixes

## PZ-01 — Snapshot sync accepts state without `RecursiveProof`

**Severity:** Critical  
**Class:** Logical error / network attack surface / snapshot trust failure  
**Status:** DONE (initial) — headers-only acceptance removed; `tip_hash` binding added.

### Files

- `noid_node/src/main.rs:2132-2161`
- `noid_node/src/main.rs:758-840`
- `noid_chain/src/storage/mdbx_context.rs:859-1016`
- Docs:
  - `docs/network.md:404-418`
  - `docs/protocol.md:477-489`

### Current behavior

During snapshot sync, if a peer returns empty `proof_bytes`, the node can accept the manifest after checking only recent header PoW/chainwork:

```rust
if proof_bytes.is_empty() {
    match validate_snapshot_headers(...) {
        Ok(_) => tracing::info!("no recursive proof yet ... accepting manifest")
        ...
    }
}
```

`validate_snapshot_headers()` itself states that headers alone cannot reconstruct chain validity because `block_initial_claim` is unavailable:

```rust
// Replaying this from headers-only is no longer possible...
// We return None; the STARK in verify_tip provides the authoritative guarantee.
Ok((hdrs, None))
```

Then `apply_state_snapshot()` only verifies that downloaded segments match `tip_hdr.state_root`.

### Why this is wrong

PoW headers commit to a state root, but they do not prove that the state root resulted from valid proof-native transitions. In Paranoid, the network does not execute transactions for validity; it verifies proofs. Accepting a snapshot without a recursive proof violates the core design.

### Impact

A malicious peer can potentially serve a fabricated state snapshot with PoW-valid headers and matching segment data for the claimed root, but without proof that the state root is valid. This is a direct attack on fresh-node sync.

### Fix

1. Remove the headers-only acceptance path for non-genesis snapshots.
2. Require non-empty `RecursiveProof` for snapshot sync unless `tip_height == 0` and the state is exactly hardcoded genesis.
3. Require proof coverage:
   - preferred: `proof.height >= tip_height - FINALITY_DEPTH`;
   - if a stricter invariant is possible, require `proof.height == tip_height - FINALITY_DEPTH` or `tip_height - 1` depending on intended recursive lag.
4. Keep header PoW/chainwork checks as additional anti-eclipse checks, not as a replacement for proof verification.
5. In `apply_state_snapshot()`, additionally check:

```rust
tip_hash == full_block_hash(tip_hdr)
```

6. Consider changing `apply_state_snapshot()` signature so callers must pass an explicit `VerifiedSnapshotProof` marker rather than raw fields.

### Suggested tests

- Snapshot with empty proof and `tip_height > 0` is rejected.
- Genesis-only empty proof path is accepted only for exact hardcoded genesis.
- Snapshot with valid segment root but invalid/missing recursive proof is rejected.
- Snapshot `tip_hash` mismatch is rejected.

---

## PZ-02 — Header `proof_transcript_hash` is not checked against `block_proof_bytes`

**Severity:** Critical  
**Class:** Proof binding failure / consensus correctness  
**Status:** DONE (initial) — shared binding helper added and used in P2P/RPC guard paths.

### Files

- `noid_node/src/main.rs:1171-1191`
- `noid_chain/src/block.rs:95-116`
- `noid_chain/src/block.rs:361-365`
- `noid_chain/src/consensus/pow.rs:6-10`, `:60-98`

### Current behavior

P2P block handler deserializes proof and calls `verify_block()`, but does not check:

```rust
noid_chain::block::proof_transcript_hash(&block_proof_bytes)
    == block.header.proof_transcript_hash
```

`apply_block()` only rejects:

- zero `proof_transcript_hash`;
- stub marker `[1u8; 32]` when user transactions exist.

### Why this is wrong

`proof_transcript_hash` is a header field and should bind the exact proof bytes. PoW is computed over `header_core`, which excludes `proof_transcript_hash` and `witness_root`, so the proof field binding must be explicit in validation.

### Impact

A block may be accepted with a valid proof that is not the proof referenced by the header. This breaks the binding between:

- block header;
- block hash;
- recursive accumulator inputs;
- DA/witness commitment;
- actual proof bytes served over the network.

### Fix

Add block proof binding checks before ZK verification and before commit:

For coinbase-only blocks:

```rust
if !has_user_txs {
    require block_proof_bytes.is_empty();
    require block.header.proof_transcript_hash == [1u8; 32];
}
```

For user-tx blocks:

```rust
if has_user_txs {
    require !block_proof_bytes.is_empty();
    require block.header.proof_transcript_hash
        == noid_chain::block::proof_transcript_hash(&block_proof_bytes);
    require block.header.proof_transcript_hash != [1u8; 32];
}
```

When DA packing is fully wired, add analogous `witness_root` verification.

### Suggested tests

- User-tx block with valid proof but wrong `proof_transcript_hash` is rejected.
- User-tx block with empty proof is rejected.
- Coinbase-only block with non-empty proof is rejected or ignored according to final policy.
- Coinbase-only block with non-stub `proof_transcript_hash` is rejected.

---

## PZ-03 — RPC `submitBlock` applies user-tx blocks without ZK verification

**Severity:** Critical  
**Class:** External miner API consensus bypass  
**Status:** DONE (initial) — `submitBlock` is proof-aware and requires `block_proof_hex` for user-transaction blocks.

### Files

- `noid_rpc/src/server.rs:629-666`
- `noid_rpc/src/server.rs:546-622`
- `noid_rpc/src/types.rs:36-54`
- `noid_miner/src/lib.rs:51-56`
- `noid_chain/src/state.rs:125-209`

### Current behavior

`submitBlock` accepts only `block_hex`:

```rust
let block = Block::from_bytes(&bytes)?;
ctx.apply_next_block(&block, local_time)?;
```

`apply_next_block()` performs native consensus and native state transition, but it does not verify `BlockProof`.

`getBlockTemplate()` computes proof bytes but drops them:

```rust
let (proof_transcript_hash, witness_root, _proof_bytes) =
    noid_miner::run_prove_block_for_rpc(...);
```

`BlockTemplateResponse` claims that the ZK proof is already embedded, but `Block` does not contain proof bytes.

### Why this is wrong

For non-coinbase transactions, native state transition validates slot liveness and output emptiness, but it does not prove:

- ownership authorization;
- `AuthTag` correctness;
- balance/range constraints;
- full logic proof validity.

Those are proof-system responsibilities.

### Impact

An authenticated external miner or leaked mining key can submit a user-tx block that is locally applied without proof verification. Even if peers later reject it, the local node state is already corrupted.

### Fix options

#### Option A — Return proof bytes from template API

Change `BlockTemplateResponse` to include:

```rust
pub block_proof_hex: Option<String>
```

Then change `submitBlock` to accept both block and proof, either as:

- new object param `{ block_hex, block_proof_hex }`; or
- new method `paranoid_submitBlockWithProof`.

`submitBlock` must verify:

1. user-tx block has proof bytes;
2. proof hash matches header;
3. full ZK verification passes;
4. native apply succeeds.

#### Option B — Template proof cache

Node stores proof bytes keyed by a template id or deterministic header fields, then `submitBlock` looks up proof bytes before applying. This preserves external miner UX but requires cache invalidation.

### Immediate safe patch

Until API is redesigned:

- reject RPC-submitted user-tx blocks in `submitBlock`;
- allow only coinbase-only blocks through existing path.

### Suggested tests

- RPC `submitBlock` rejects user-tx block without proof.
- RPC `submitBlock` accepts coinbase-only stub block.
- New proof-aware submit path rejects wrong proof hash.
- New proof-aware submit path applies valid proved user-tx block.

---

## PZ-04 — P2P block validation performs ZK verification before cheap consensus checks

**Severity:** Critical/High  
**Class:** DoS / validation ordering bug  
**Status:** DONE (initial) — tip/orphan/reorg paths use cheap-first validation; reorg blocks are ZK-verified after internal revert and before apply.

### Files

- `noid_node/src/main.rs:1136-1226`
- `noid_node/src/main.rs:1228-1233`
- `noid_block/src/validate.rs:101-156`
- Docs: `docs/network.md:321-373`

### Current behavior

After block decode, P2P handler performs ZK verification before `apply_next_block()`. Native consensus checks such as parent hash, height, difficulty, PoW, timestamp, fees, slot conflicts, and expansion are inside `apply_next_block()` and therefore run after ZK.

### Why this is wrong

Docs specify fail-fast order:

1. wire validation;
2. native consensus;
3. ZK proof verification;
4. state transition.

Current order lets invalid blocks consume expensive verifier work.

### Impact

A malicious peer can send blocks with bad parent, bad height, invalid PoW, or invalid timestamp but with proof-shaped bytes. The node may spend CPU constructing AIRs and verifying ZK before cheap rejection.

### Fix

Refactor P2P block handling into a single explicit pipeline:

1. Decode block.
2. Check wire sizes.
3. If stale/duplicate, drop.
4. If parent is unknown, store as orphan with proof bytes and do not ZK verify yet.
5. If parent is known, run cheap native checks without mutating state:
   - `validate_block_checks(...)`;
   - proof presence/stub policy;
   - proof hash binding.
6. Run ZK verification.
7. Commit state.

Use or adapt `noid_block::validate_block_from_network()`, but ensure it does not mutate state before all proof checks pass unless the caller is prepared to rollback.

### Suggested tests

- Bad PoW user-tx block does not call ZK verifier.
- Bad parent user-tx block is orphaned without ZK verifier call.
- Valid block still applies.
- User-tx block with wrong proof hash rejected before ZK verifier.

---

## PZ-05 — Orphan/reorg path stores `Block` without `block_proof_bytes`

**Severity:** High  
**Class:** Reorg correctness / proof-native liveness / race  
**Status:** DONE (initial) — orphan/reorg candidates carry proof bytes; chained orphans and reorg blocks are ZK-verified against the correct pre-state before apply; proofs are stored for recursive replay.

### Files

- `noid_node/src/main.rs:917-923`
- `noid_node/src/main.rs:1276-1310`
- `noid_node/src/main.rs:1315-1471`
- `noid_node/src/main.rs:2671-2688`

### Current behavior

Orphan pool is:

```rust
HashMap<[u8; 32], noid_chain::block::Block>
```

It stores only block bodies, not proof bytes.

### Why this is wrong

In a proof-native chain, a user-tx block without proof bytes is incomplete. The orphan/reorg path must verify proofs against the correct parent pre-state and persist proof bytes for recursive proof advancement.

### Current failure modes

1. A valid fork block can be ZK-verified against the wrong pre-state when first received, then rejected incorrectly.
2. A buffered orphan later applied through `apply_block_offthread()` is applied without ZK verification.
3. Reorg blocks are applied as `Vec<Block>` without proof bytes.
4. `T_BLOCK_PROOFS` cannot be populated for reorg-applied user-tx blocks, breaking recursive proof updater.

### Fix

Introduce an orphan type:

```rust
struct OrphanBlock {
    block: noid_chain::block::Block,
    block_proof_bytes: Vec<u8>,
    from: libp2p::PeerId,
    received_at: Instant,
}
```

Change reorg candidate chain to carry proof bytes:

```rust
Vec<ProvedBlockCandidate>
```

where:

```rust
struct ProvedBlockCandidate {
    block: Block,
    block_proof_bytes: Vec<u8>,
}
```

For every applied user-tx block in orphan/reorg path:

1. verify proof with correct pre-state;
2. verify proof hash binding;
3. apply;
4. persist proof bytes to `T_BLOCK_PROOFS`.

### Suggested tests

- Shallow fork with user tx and valid proof reorgs successfully.
- Orphan with missing proof is rejected when parent arrives.
- Reorg-applied user-tx block stores proof in `T_BLOCK_PROOFS`.

---

# Phase 2 — Mempool and miner DoS fixes

## PZ-06 — Non-coinbase TX with empty proof can enter mempool

**Severity:** High  
**Class:** Mempool DoS / miner liveness  
**Status:** DONE — non-coinbase empty-proof and oversized-proof intents are rejected.

### Files

- `noid_mempool/src/pool.rs:170-208`
- `noid_mempool/src/pool.rs:255-271`
- `noid_miner/src/miner.rs:597-612`

### Current behavior

Mempool decides whether to verify ZK with:

```rust
let needs_zk = !intent.logic_proof_bytes.is_empty() && !intent.tx_body.is_coinbase;
```

So non-coinbase TX with empty proof skips ZK verification and can be admitted if cheap checks pass.

### Impact

Attacker can fill mempool with no-proof transactions. The miner selects them, then `run_prove_block()` fails due missing `WalletProofBundle`:

```rust
if bundles.len() != non_cb_count {
    return Err("missing WalletProofBundles...");
}
```

This wastes template/proving cycles and can block inclusion of valid transactions.

### Fix

In `AsyncMempool::submit()`:

```rust
if !intent.tx_body.is_coinbase && intent.logic_proof_bytes.is_empty() {
    return Err(SubmitError::MissingProof);
}
```

Also add a max proof size check before decode/verify, for example:

```rust
const MAX_TX_PROOF_BYTES: usize = 1024 * 1024;
```

or a tighter bound if actual wallet proof sizes are known.

### Suggested tests

- Non-coinbase intent with empty proof is rejected.
- Coinbase intent remains exempt where appropriate.
- Oversized proof rejected before `WalletProofBundle::from_bytes()`.

---

## PZ-07 — Mempool sync response lacks per-TX and total byte limits before processing

**Severity:** High  
**Class:** P2P DoS / memory pressure  
**Status:** DONE (initial) — per-tx and total response byte caps added; outbound request cooldown added.

### Files

- `noid_p2p/src/network.rs:1296-1343`
- `noid_node/src/main.rs:1548-1583`
- `noid_node/src/main.rs:1585-1595`

### Current behavior

`MempoolSyncResponse` truncates tx count to 8192, but does not enforce:

- max bytes per tx;
- max total response bytes;
- per-peer sync cooldown.

Normal gossip TX has a 1MB cap, but mempool sync does not apply the same cap before spawning processing.

### Impact

A malicious peer can send huge mempool sync responses causing allocation pressure and long async processing queues.

### Fix

At P2P layer before emitting `NetworkEvent::MempoolSyncResponse`:

```rust
const MAX_SYNC_TXS: usize = 8192;
const MAX_TX_WIRE_SIZE: usize = 1024 * 1024;
const MAX_MEMPOOL_SYNC_BYTES: usize = 16 * 1024 * 1024; // example
```

Reject or truncate entries exceeding per-TX size. Reject response if total bytes exceed cap.

Add per-peer request cooldown and ensure only one mempool sync request per peer per interval.

### Suggested tests

- Mempool sync response with oversized tx is dropped.
- Mempool sync response over total byte cap is dropped.
- Valid response still admits txs.

---

## PZ-08 — Inbound `GetHeadersRequest.count` is not server-capped

**Severity:** Medium/High  
**Class:** Request-response DoS  
**Status:** DONE — inbound count is capped to 512 server-side.

### File

- `noid_p2p/src/network.rs:966-990`

### Current behavior

Outbound requests cap `count` to 512. Inbound server does not:

```rust
for h in request.start_height..(request.start_height + request.count as u64)
```

`count` is `u16`, so a peer can request up to 65,535 headers.

### Impact

Unnecessary DB reads, memory allocation, and large CBOR responses.

### Fix

Server-side cap:

```rust
let count = request.count.min(512);
for h in request.start_height..request.start_height.saturating_add(count as u64) {
    ...
}
```

Also validate response size client-side before decoding/storing.

### Suggested tests

- Inbound request with count >512 returns at most 512 headers.
- Saturating arithmetic avoids overflow at high `start_height`.

---

## PZ-09 — Recursive proof gossip lacks size/rate limits

**Severity:** Medium/High  
**Class:** P2P DoS  
**Status:** DONE (initial) — gossip proof-size cap and per-peer P2P-layer rate limit added.

### Files

- `noid_p2p/src/network.rs:778-789`
- `noid_node/src/main.rs:2470-2564`

### Current behavior

Request-response recursive proof path enforces `MAX_RECURSIVE_PROOF_BYTES`, but gossip path does not check `msg.proof_bytes.len()` before emitting event.

Gossipsub max transmit is 2MB, while docs specify recursive proof max 64KB.

### Impact

Peers can flood large recursive proof gossip messages, causing allocation, bincode decode, and possible verification work.

### Fix

At P2P gossip handling:

```rust
if msg.proof_bytes.len() > MAX_RECURSIVE_PROOF_BYTES {
    drop;
}
```

Add per-peer recursive proof update rate limit, e.g. a small number per minute.

### Suggested tests

- Oversized recursive proof gossip is dropped before node event emission.
- Valid proof update still passes through.

---

# Phase 3 — P2P event-loop and network hardening

## PZ-10 — Rate limits happen after broadcast event channel

**Severity:** Medium  
**Class:** Event-channel DoS / liveness  
**Status:** DONE (initial) — tx/block/recursive-proof cheap filters now run in `noid_p2p` before event-channel emission; separate priority channels remain optional future work.

### Files

- `noid_p2p/src/network.rs:758-762`
- `noid_p2p/src/network.rs:773-777`
- `noid_node/src/main.rs:1114-1133`
- `noid_node/src/main.rs:1599-1620`

### Current behavior

`noid_p2p` receives gossip and immediately sends `NetworkEvent` through a broadcast channel. Per-peer rate limits are applied later in `handle_p2p_events()`.

The event channel capacity is 256.

### Impact

A noisy peer can fill the event channel before rate limits are applied. The receiver can lag and drop events, including valid block events from honest peers.

### Fix

Move cheap filters into `noid_p2p::handle_swarm_event`:

- per-peer block count;
- per-peer tx count;
- recursive proof count;
- wire size checks;
- stale/duplicate quick drops where possible.

Consider separate channels for high-priority block events and lower-priority tx/mempool sync events.

### Suggested tests

- Flooding tx gossip from one peer does not cause block event lag.
- Rate-limited events are dropped before broadcast channel.

---

## PZ-11 — `identify` blindly adds all advertised listen addresses

**Severity:** Low/Medium  
**Class:** Peer-store / address-book DoS  
**Status:** DONE — capped accepted Identify addresses and filtered unroutable IP addresses.

### File

- `noid_p2p/src/network.rs:804-824`

### Current behavior

For every Identify event, all advertised addresses are added to Kademlia and the swarm address book.

### Impact

A peer can advertise many or unsuitable addresses and bloat routing/address state.

### Fix

- Cap addresses accepted per peer, e.g. 8 or 16.
- Filter unroutable addresses from remote peers:
  - localhost;
  - private IP ranges unless peer is local/mDNS;
  - multicast/broadcast;
  - unsupported protocols.
- Avoid persisting low-quality addresses.

### Suggested tests

- Peer advertising >N addresses stores only N.
- Remote peer advertising localhost/private addresses is ignored unless explicitly allowed.

---

# Phase 4 — Performance bottlenecks and lock contention

## PZ-12 — Chain read lock is held across async template build

**Severity:** Medium  
**Class:** Performance / async lock contention  
**Status:** DONE (initial) — template build now uses a lock-captured `TemplateChainSnapshot`; mempool selection and template assembly happen after the chain lock is released.

### Files

- `noid_miner/src/miner.rs:291-303`
- `noid_miner/src/template.rs:114-221`
- `noid_rpc/src/server.rs:580-587`

### Current behavior

Miner does:

```rust
let ctx = self.chain.read().await;
let t = builder.build(&ctx, addr, now).await;
```

`builder.build()` awaits mempool selection and does state/template work while the chain read lock remains held.

RPC `getBlockTemplate` similarly holds chain read lock during template build and then spawns proving.

### Impact

Incoming P2P blocks, reorgs, and snapshots need the chain write lock. Long read-lock hold times delay block application and can cause stale mining.

### Fix

Create a lightweight immutable chain snapshot under read lock, then drop the lock before awaiting mempool or doing expensive work.

Example direction:

```rust
struct TemplateChainSnapshot {
    parent: BlockHeader,
    prev_active_counts: Vec<u64>,
    prev_timestamps: Vec<u64>,
    anchor: AnchorInfo,
    state: ChainState,
    // only what is needed for pre_segs / template build
}
```

Then:

1. acquire read lock;
2. clone/copy snapshot fields;
3. drop read lock;
4. await mempool selection;
5. build template from snapshot.

Also add RPC template concurrency limit or cached template reuse.

### Suggested tests/benchmarks

- Simulate template build while applying P2P block; verify block apply is not blocked by long read lock.
- Benchmark lock hold time before/after.

---

## PZ-13 — State segment serving performs heavy encoding in swarm event loop

**Severity:** Medium  
**Class:** P2P performance / event-loop blocking  
**Status:** DONE (initial) — segment encoding moved to bounded `spawn_blocking` workers; swarm task only sends completed responses.

### File

- `noid_p2p/src/network.rs:1213-1268`

### Current behavior

Segment server clones segment columns under lock, then calls `encode_segment()` directly in the swarm event handler.

### Impact

Encoding several MB of segment data can block the libp2p swarm loop, delaying gossip, request-response handling, ping, identify, and reconnect processing.

### Fix

Move segment encoding to `spawn_blocking` or a bounded worker pool. Also add:

- per-peer segment request limits;
- total concurrent segment encodes;
- optional encoded segment cache for current tip.

### Suggested tests/benchmarks

- Multiple concurrent segment requests do not delay block gossip handling.
- Segment encode concurrency cap is respected.

---

## PZ-14 — Snapshot segment memory cap mismatch and all-at-once assembly

**Severity:** Medium  
**Class:** Memory DoS / scalability  
**Status:** PARTIAL+ — 8MB segment cap, total snapshot byte cap, and impossible manifest segment-count checks added; `apply_state_snapshot` now moves decoded columns into state and avoids a second full clone before MDBX write. Full network-to-storage streaming is still pending.

### Files

- `docs/network.md:496-503`
- `noid_p2p/src/network.rs:31-33`
- `noid_node/src/main.rs:970-978`
- `noid_node/src/main.rs:1923-1925`
- `noid_p2p/src/network.rs:1190-1193`

### Current behavior

Docs and P2P define `MAX_SEGMENT_BYTES` as 8MB, but node snapshot handler allows 32MB per segment.

Node collects all segment bytes in memory:

```rust
HashMap<u16, (u8, Vec<u8>)>
```

P2P manifest allows up to 4096 segment IDs, while comment in node assumes 256 segments.

### Impact

A malicious or very large manifest can create huge memory pressure. Snapshot apply is not streaming.

### Fix

- Use one shared constant for segment byte cap, preferably 8MB as documented.
- Bound total snapshot bytes.
- Derive max segment count from `log_slots` and effective segment size.
- Prefer streaming decode/write to MDBX after proof verification instead of keeping all segment bytes in memory.

### Suggested tests

- Segment >8MB is rejected consistently in P2P and node layers.
- Manifest with impossible segment count for `log_slots` is rejected.
- Total snapshot byte cap is enforced.

---

## PZ-15 — `flood_publish(true)` may become bandwidth amplification at scale

**Severity:** Medium  
**Class:** Bandwidth bottleneck / amplification  
**Status:** DONE — mainnet gossipsub now uses mesh publish (`flood_publish(false)`).

### File

- `noid_p2p/src/behaviour.rs:210-217`

### Current behavior

Gossipsub is configured with:

```rust
.flood_publish(true)
```

Comment says TX flooding is acceptable because TXs are small and spam is filtered by mempool fee checks.

### Impact

At high peer counts, flood publishing is `O(connected_peers)` egress per admitted tx/block announcement. This can amplify inbound spam into outbound bandwidth usage.

### Fix

- Use mesh publish for public/mainnet networks.
- Optionally keep flood publish only for dev/small networks.
- Consider separate behavior or topic strategy for txs vs blocks.

### Suggested tests/benchmarks

- Measure egress with 64/128 peers under tx burst.
- Verify propagation remains acceptable with mesh-only publish.

---

# Phase 5 — Smaller correctness cleanups

## PZ-16 — `run_prove_block_for_rpc` silently falls back to stub proof on error

**Severity:** Medium  
**Class:** Error handling / hidden invalid template risk  
**Status:** DONE — RPC proving now returns an error instead of silent stub fallback.

### File

- `noid_miner/src/lib.rs:51-56`

### Current behavior

```rust
miner::run_prove_block(tmpl, prev_state_root).unwrap_or(([1u8; 32], [1u8; 32], vec![]))
```

For templates with user transactions, this returns the coinbase-only stub marker on proof failure. Later `apply_block()` rejects user-tx blocks with stub marker, but the RPC response may still hand an unusable template to external miners.

### Impact

External miners waste PoW on templates that cannot be accepted.

### Fix

Make `run_prove_block_for_rpc()` return `Result<..., String>` and surface the error to RPC. Do not silently substitute stub proof for user-tx templates.

### Suggested tests

- Proof failure in RPC template returns RPC error.
- Coinbase-only template still returns stub marker intentionally.

---

# Recommended implementation order

## Step 1 — Block proof policy helpers

Create shared helper functions, likely in `noid_block` or `noid_chain::block`:

```rust
pub enum ProofPolicyError {
    MissingProof,
    UnexpectedProofForCoinbaseOnly,
    BadProofTranscriptHash,
    StubProofWithUserTxs,
    BadCoinbaseStub,
}

pub fn validate_block_proof_binding(
    block: &Block,
    block_proof_bytes: &[u8],
) -> Result<(), ProofPolicyError>;
```

Use this helper in:

- P2P block handling;
- RPC submit path;
- tests;
- future block validation functions.

## Step 2 — Mempool proof admission

Reject non-coinbase TXs with empty or oversized proof bytes.

## Step 3 — P2P validation reorder

Refactor `NetworkEvent::NewBlock` handling:

1. decode;
2. stale check;
3. parent availability;
4. cheap consensus;
5. proof binding;
6. ZK verify;
7. apply.

## Step 4 — Orphan/reorg proof-carrying types

Store proof bytes in orphan pool and reorg candidate chains.

## Step 5 — RPC external miner proof path

Either:

- add proof bytes to template/submit API; or
- implement template proof cache.

Immediate safety fallback: reject RPC-submitted user-tx blocks until proof-aware path exists.

## Step 6 — Snapshot proof strictness

Remove headers-only snapshot acceptance. Require valid RecursiveProof for all non-genesis snapshots.

## Step 7 — Request-response and gossip limits

Add missing server-side and gossip-side limits:

- headers count cap;
- recursive proof gossip size/rate limit;
- mempool sync per-tx and total byte caps;
- earlier rate limits before event channel.

## Step 8 — Performance fixes

- Drop chain read lock before async template build work. ✅ initial
- Move segment encoding off the swarm event loop. ✅ initial
- Align snapshot segment caps and add total memory bounds. ✅ initial; full streaming still pending

---

# Validation plan after fixes

Run targeted tests first:

```bash
cargo test -p noid_mempool
cargo test -p noid_chain
cargo test -p noid_block
cargo test -p noid_p2p
cargo test -p noid_rpc
cargo test -p noid_node
```

Then run broader workspace tests:

```bash
cargo test --workspace
```

Add integration tests for:

1. P2P rejects user-tx block with missing proof.
2. P2P rejects user-tx block with mismatched `proof_transcript_hash`.
3. RPC `submitBlock` rejects user-tx block without proof.
4. Snapshot sync rejects empty proof for non-genesis tip.
5. Mempool rejects non-coinbase TX without proof.
6. Header request count capped server-side.
7. Oversized recursive proof gossip dropped.
8. Oversized mempool sync tx dropped.
9. Orphan user-tx block stores proof bytes and verifies after parent arrives.

---

# Summary table

| ID | Severity | Area | Short description | First fix |
|---|---:|---|---|---|
| PZ-01 | Critical | Snapshot sync | Headers-only snapshot acceptance | DONE initial: Require RecursiveProof |
| PZ-02 | Critical | Proof binding | Header proof hash not checked | DONE initial: proof binding helper + P2P/RPC guard |
| PZ-03 | Critical | RPC mining | `submitBlock` applies without ZK | PARTIAL: reject user-tx blocks until proof-aware path |
| PZ-04 | Critical/High | P2P validation | ZK before cheap checks | Reorder validation pipeline |
| PZ-05 | High | Reorg/orphans | Orphan pool loses proof bytes | Store proved block candidates |
| PZ-06 | High | Mempool | No-proof tx admitted | DONE: reject non-coinbase empty proof |
| PZ-07 | High | Mempool sync | No byte caps | PARTIAL: per-tx/total caps added |
| PZ-08 | Medium/High | Headers sync | Inbound count uncapped | DONE: server-side cap 512 |
| PZ-09 | Medium/High | RecProof gossip | No size/rate cap | PARTIAL: 64KB cap added |
| PZ-10 | Medium | Event channel | Rate limit after broadcast channel | Move filters into P2P layer |
| PZ-11 | Low/Medium | Peer discovery | Blind advertised addr insert | Cap/filter addrs |
| PZ-12 | Medium | Miner/RPC perf | Chain read lock across await | Snapshot then drop lock |
| PZ-13 | Medium | State sync perf | Segment encode in swarm loop | `spawn_blocking` / bounded workers |
| PZ-14 | Medium | Snapshot memory | 8MB vs 32MB cap; all-in-RAM | Align caps; stream apply |
| PZ-15 | Medium | Gossipsub | Flood publish amplification | Mesh/adaptive publish |
| PZ-16 | Medium | RPC template | Silent stub fallback on proof error | DONE: return RPC error |
