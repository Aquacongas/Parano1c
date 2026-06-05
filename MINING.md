# Paranoid Mining Guide

Mining in Paranoid means finding a Blake3 PoW nonce that satisfies the current
difficulty target. The full node handles everything except the hash search:
building block templates, generating ZK proofs, applying blocks to the chain,
and broadcasting to the network. Miners — built-in or external — only do PoW.

---

## Table of Contents

1. [How mining works](#1-how-mining-works)
2. [Built-in miner (solo)](#2-built-in-miner-solo)
3. [External miner (`noid-extminer`)](#3-external-miner-noid-extminer)
4. [Mining models comparison](#4-mining-models-comparison)
5. [Managed pool (node keeps rewards)](#5-managed-pool-node-keeps-rewards)
6. [Infrastructure pool (miner keeps rewards)](#6-infrastructure-pool-miner-keeps-rewards)
7. [Security model](#7-security-model)
8. [Difficulty and ASERT](#8-difficulty-and-asert)
9. [Block reward schedule](#9-block-reward-schedule)

---

## 1. How mining works

```
┌──────────────────────────────────────────────────────────┐
│  Full node                                               │
│                                                          │
│  1. Build block template                                 │
│     ├─ Select txs from mempool                           │
│     ├─ Compute state_root (post-tx state)                │
│     ├─ Create coinbase tx → payout address               │
│     └─ Generate ZK BlockProof (~instant for empty blocks)│
│                                                          │
│  2. Give template to miner (built-in or external):       │
│     header_core (212 bytes) + full sealed block          │
│                                                          │
│  3. Miner finds nonce N:                                 │
│     Blake3(header_core with N) < difficulty_target       │
│                                                          │
│  4. Submit block → node validates, applies, broadcasts   │
└──────────────────────────────────────────────────────────┘
```

**Key invariant:** The coinbase payout address is committed inside the ZK proof.
A miner cannot change who receives the reward after getting the template — the
hash would not match. Only the node operator decides the coinbase address
(unless `--allow-custom-coinbase` is configured).

---

## 2. Built-in miner (solo)

The simplest setup. One command, everything runs inside the daemon.

```bash
# Start a solo miner on a fresh network
paranoid --mine --genesis --data-dir ~/.paranoid

# Join an existing network
paranoid --mine \
  --seed seed1.noid.network:9400 \
  --data-dir ~/.paranoid
```

**What happens:**
- The node builds a block template with your wallet's primary address as coinbase
- Blake3 PoW runs in parallel with ZK proving (rayon, all CPU cores by default)
- Found blocks are applied immediately and broadcast to peers
- All rewards go to `wallet.key` in your `--data-dir`

**Tune CPU usage:**
```bash
# Use 4 cores for PoW (leave the rest for ZK proving and other tasks)
paranoid --mine --threads 4 --data-dir ~/.paranoid
```

**Custom payout address:**
```bash
# Rewards go to this address instead of the built-in wallet
paranoid --mine \
  --miner-address noid1your_address_here \
  --data-dir ~/.paranoid
```

> **RPC default:** `127.0.0.1:9401` — localhost only. No auth needed for solo.

---

## 3. External miner (`noid-extminer`)

A standalone binary that connects to any `paranoid` node via JSON-RPC,
fetches templates, searches for nonces using all CPU cores, and submits blocks.

**Build:**
```bash
cargo build --release -p noid-extminer
# Binary: target/release/noid-extminer
```

**Usage:**
```bash
noid-extminer [OPTIONS]

Options:
  --rpc <URL>          Node RPC endpoint  [default: http://127.0.0.1:9401]
  --key <TOKEN>        Bearer token (required when node uses --mining-key)
  --coinbase <ADDR>    Your own payout address (requires --allow-custom-coinbase on node)
  --threads <N>        PoW threads. 0 = all cores  [default: 0]
  --poll-ms <MS>       Template re-fetch interval  [default: 500]
```

**Examples:**
```bash
# Connect to a local node (no auth)
noid-extminer --rpc http://127.0.0.1:9401

# Connect to a pool with auth, collect rewards to pool address
noid-extminer --rpc http://pool.example.com:9401 --key my-token

# Connect to an infrastructure pool, collect rewards to YOUR OWN address
noid-extminer \
  --rpc http://pool.example.com:9401 \
  --key my-token \
  --coinbase noid1your_wallet_address

# Use 8 threads, faster template polling
noid-extminer --rpc http://127.0.0.1:9401 --threads 8 --poll-ms 200
```

**What `noid-extminer` does NOT do:**
- Does not generate ZK proofs (the node does that)
- Does not know about transactions or state
- Does not store any chain data
- Does not need a wallet or key file

---

## 4. Mining models comparison

| Model | Node flags | Who mines | Who gets reward | Auth needed |
|---|---|---|---|---|
| Solo (built-in) | `--mine` | Node | Node wallet | No |
| Solo + external | `--mine` | Both | Node wallet | No (localhost) |
| Managed pool | `--mine --mining-key K` | Node + external | **Pool operator** | Yes |
| Infrastructure pool | `--mining-key K --allow-custom-coinbase` | External miners | **Each miner** | Yes |

---

## 5. Managed pool (node keeps rewards)

The pool operator runs the full node. All miners contribute hashrate.
Block rewards accumulate in the pool wallet. The operator distributes
earnings to miners off-chain (e.g. proportional to shares submitted).

```
Pool node ──── ZK prove, chain, P2P
     │
     ├── noid-extminer (miner A, token required)
     ├── noid-extminer (miner B, token required)
     └── noid-extminer (miner C, token required)

Rewards: ALL go to pool node's wallet → operator distributes off-chain
```

**Node setup:**
```bash
# Generate a strong random token
MINING_KEY="$(openssl rand -hex 32)"
echo "Distribute this token to your miners: $MINING_KEY"

paranoid \
  --mine \
  --rpc-listen 0.0.0.0:9401 \
  --mining-key "$MINING_KEY" \
  --seed seed1.noid.network:9400 \
  --data-dir /var/lib/paranoid
```

**Miner setup:**
```bash
noid-extminer \
  --rpc http://pool.example.com:9401 \
  --key "$MINING_KEY"
# No --coinbase flag → rewards go to pool address
```

**Security:** Miners cannot redirect rewards. Even if a miner provides their
own address in `getBlockTemplate`, the server rejects it — coinbase is locked
to the pool's `--miner-address` (or wallet primary).

---

## 6. Infrastructure pool (miner keeps rewards)

The node operator provides infrastructure (ZK proving, P2P relay, chain state)
but does **not** take the block reward. Each miner specifies their own address
and receives rewards directly on-chain. The operator earns through an off-chain
service fee arrangement.

```
Infra node ──── ZK prove, chain, P2P (operator earns via service fee)
     │
     ├── noid-extminer --coinbase noid1miner_A  → rewards → miner A
     ├── noid-extminer --coinbase noid1miner_B  → rewards → miner B
     └── noid-extminer --coinbase noid1miner_C  → rewards → miner C

Rewards: each miner gets their blocks' rewards directly on-chain
```

**Node setup:**
```bash
# --allow-custom-coinbase REQUIRES --mining-key
# (prevents unauthenticated coinbase hijacking)
MINING_KEY="$(openssl rand -hex 32)"

paranoid \
  --rpc-listen 0.0.0.0:9401 \
  --mining-key "$MINING_KEY" \
  --allow-custom-coinbase \
  --seed seed1.noid.network:9400 \
  --data-dir /var/lib/paranoid
# Note: no --mine flag. The node provides infrastructure only.
# (You can add --mine if you also want the node itself to mine.)
```

**Miner setup:**
```bash
# Each miner provides their own wallet address
noid-extminer \
  --rpc http://infra.example.com:9401 \
  --key "$MINING_KEY" \
  --coinbase noid1my_own_wallet_address
```

**Verification:** After mining blocks, check your balance:
```bash
# On any synced node with your wallet key:
noid-cli balance
# Or check directly via getSlotsByOwner on any node:
curl ... paranoid_getSlotsByOwner ["noid1your_address"]
```

> **Startup guard:** `--allow-custom-coinbase` without `--mining-key` is rejected
> at startup with an error. This prevents accidentally exposing an
> unauthenticated endpoint where anyone could claim arbitrary coinbase addresses.

---

## 7. Security model

### Coinbase protection

The coinbase address is committed inside the ZK BlockProof generated by the
node. The proof covers the entire block state including `miner_address`.
An external miner who receives the template **cannot** change the payout
address without regenerating the entire ZK proof (1–3 CPU seconds per block),
which they cannot do without access to the transaction witnesses.

**Default (no `--allow-custom-coinbase`):**
- Any `miner_address` parameter other than the node's configured address → 400 error
- Node wallet address is always the coinbase

**With `--allow-custom-coinbase`:**
- Caller must be authenticated (bearer token checked by HTTP middleware)
- Any valid address is accepted
- Each template is proved with the caller's specified address

### Bearer token

When `--mining-key TOKEN` is set:
- All HTTP requests to the RPC endpoint require `Authorization: Bearer TOKEN`
- Requests without a valid token receive `HTTP 401 Unauthorized`
- The token is checked before any JSON-RPC parsing or ZK work

**Recommendation:** Use a minimum 32-character random token:
```bash
openssl rand -hex 32
```

### Network binding

By default `--rpc-listen 127.0.0.1:9401` — localhost only. External access
requires explicitly changing to `0.0.0.0:9401`. Always pair this with
`--mining-key` when exposing to external networks.

---

## 8. Difficulty and ASERT

Paranoid uses **ASERT** (Absolutely Scheduled Exponential Rise and Targeting),
the same algorithm used by Bitcoin Cash. It adjusts difficulty every block to
target a 60-second inter-block interval.

| Constant | Value |
|---|---|
| Target block time | 60 seconds |
| ASERT halflife | 360 seconds (6 blocks) |
| Genesis target | 2^248 (~256 hash attempts) |
| Minimum difficulty | ~1 hash attempt (MAX_TARGET) |
| Maximum difficulty | impossible target (MIN_TARGET) |

**How it works:**
- If blocks come faster than 60s → target decreases → harder
- If blocks come slower than 60s → target increases → easier
- Adjustment is smooth and continuous, not step-based

**At genesis:** Difficulty is very low (2^248). ASERT quickly raises it as
miners join. Within a few HALFLIFE periods (~30 minutes) difficulty stabilises
at a level matching the network hashrate.

**PoW algorithm:** Blake3 over 212-byte `header_core`:
```
valid when: Blake3(header_core_with_nonce) < difficulty_target
nonce:      16-byte little-endian u128 at offset 144 in header_core
```

---

## 9. Block reward schedule

The block reward **halves with every state expansion** (`log_slots` increases by 1).
Expansion is triggered automatically when active slot usage exceeds 75% of capacity.
This is Paranoid’s halving mechanism — driven by network growth, not by block count.

```
log_slots | expansion | reward/block
----------|-----------|-------------
    24    |     0     | 50.000000 NOID  ← genesis
    25    |     1     | 25.000000 NOID
    26    |     2     | 12.500000 NOID
    27    |     3     |  6.250000 NOID
    28    |     4     |  3.125000 NOID
    29    |     5     |  1.562500 NOID
    30+   |     6+    |  1.000000 NOID  ← floor forever
```

**Anti-spam property:** to trigger an expansion, someone must fill 75% of the
current slot space (16M UTXOs at genesis). Doing so immediately halves their
own mining income — a built-in economic penalty for spam.

Transaction fees are added on top:
```
total_coinbase = block_reward(log_slots) + sum(tx fees)
```

Check current reward:
```bash
noid-cli mining
# or
paranoid_getMiningInfo  # RPC
```

---

*For the full RPC reference see [RPC.md](RPC.md).*
*For the protocol specification see [SPECIFICATION.md](SPECIFICATION.md).*
