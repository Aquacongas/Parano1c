# Paranoid Node — Reference Manual

> **Version:** 0.1.0  
> **Protocol:** JSON-RPC 2.0 over HTTP  
> **Units:** 1 NOID = 1 000 000 μNOID (microNOID)

---

## Table of Contents

1. [Quick Start](#1-quick-start)
2. [Daemon (`paranoid`)](#2-daemon-paranoid)
   - 2.1 [CLI Flags](#21-cli-flags)
   - 2.2 [TOML Config File](#22-toml-config-file)
   - 2.3 [Network Defaults](#23-network-defaults)
   - 2.4 [Startup Scenarios](#24-startup-scenarios)
3. [CLI Client (`noid-cli`)](#3-cli-client-noid-cli)
   - 3.1 [Global Flags](#31-global-flags)
   - 3.2 [Chain Commands](#32-chain-commands)
   - 3.3 [Wallet Commands](#33-wallet-commands)
   - 3.4 [Node Commands](#34-node-commands)
   - 3.5 [Mining Commands](#35-mining-commands)
4. [JSON-RPC API](#4-json-rpc-api)
   - 4.1 [Transport](#41-transport)
   - 4.2 [Chain Methods](#42-chain-methods)
   - 4.3 [Mempool Methods](#43-mempool-methods)
   - 4.4 [Wallet Methods](#44-wallet-methods)
   - 4.5 [Mining Methods](#45-mining-methods)
   - 4.6 [Node Control](#46-node-control)
5. [Response Types](#5-response-types)
6. [Error Reference](#6-error-reference)
7. [Consensus Constants](#7-consensus-constants)

---

## 1. Quick Start

```bash
# Start the first node on a new network
paranoid --mine --genesis --data-dir ~/.paranoid

# Connect a second node to the first
paranoid --mine --seed 1.2.3.4:9400 --data-dir ~/.paranoid

# Check node status
noid-cli status

# Check wallet balance
noid-cli balance

# Send 10.5 NOID
noid-cli send f7845242ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1 10.5

# Scripting: raw JSON
noid-cli --json status | jq .height
```

---

## 2. Daemon (`paranoid`)

### 2.1 CLI Flags

```
paranoid [OPTIONS]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `--network` | `mainnet` \| `testnet` | `mainnet` | Network to join. Controls ports, genesis, P2P isolation. |
| `-c, --config <FILE>` | path | — | TOML config file (optional). CLI flags override file values. |
| `--mine` | flag | off | Enable built-in PoW miner. Uses all CPU cores unless `--threads` is set. |
| `--genesis` | flag | off | **Bootstrap only.** Start mining immediately without waiting for peers. Use only for the very first node on a new network. |
| `--data-dir <PATH>` | path | `~/.paranoid/data` | MDBX database directory and wallet key location. |
| `--p2p-listen <HOST:PORT>` | string | `0.0.0.0:9400` | P2P TCP listener. Converted to libp2p multiaddr internally. |
| `--rpc-listen <HOST:PORT>` | string | `127.0.0.1:9401` | JSON-RPC HTTP listener. |
| `--seed <HOST:PORT>` | string (repeatable) | — | Bootstrap peer. Repeat for multiple seeds: `--seed a:9400 --seed b:9400` |
| `--miner-address <HEX>` | 64-char hex | wallet address | Coinbase recipient. Defaults to built-in wallet primary address. |
| `--threads <N>` | integer | `0` | PoW rayon threads. `0` = all physical cores. |
| `--log <LEVEL>` | string | `info` | Log level: `error`, `warn`, `info`, `debug`, `trace`. |

> **Address format:** `HOST:PORT` (e.g. `0.0.0.0:9400`, `192.168.1.10:9400`). IPv6: `[::1]:9400`.  
> The daemon converts internally to libp2p multiaddr — users never see `/ip4/.../tcp/...`.

**Examples:**

```bash
# Minimal: solo miner on a fresh network
paranoid --mine --genesis

# Full: custom ports + two seeds + explicit address
paranoid \
  --network mainnet \
  --data-dir /var/lib/paranoid \
  --p2p-listen 0.0.0.0:9400 \
  --rpc-listen 127.0.0.1:9401 \
  --seed seed1.noid.network:9400 \
  --seed seed2.noid.network:9400 \
  --mine \
  --threads 8 \
  --log info

# Non-mining full node (relay + RPC only)
paranoid --data-dir /var/lib/paranoid --seed 1.2.3.4:9400

# Testnet with easy PoW
paranoid --network testnet --mine --genesis --data-dir ~/.paranoid-testnet

# RPC accessible from LAN (for external miners, monitoring)
paranoid --mine --rpc-listen 0.0.0.0:9401
```

### 2.2 TOML Config File

Default path: `~/.paranoid/paranoid.toml` (or `-c /path/to/config.toml`)

```toml
# paranoid.toml — full configuration example

[network]
# P2P listen address (HOST:PORT)
listen = "0.0.0.0:9400"

# Bootstrap seed peers (HOST:PORT)
seeds = [
    "seed1.noid.network:9400",
    "seed2.noid.network:9400",
]

# Maximum connected peers
max_peers = 50

[storage]
# Database backend: "mdbx" (disk) or "ram" (in-memory, lost on restart)
backend = "mdbx"

# Data directory. ~ is expanded to HOME.
path = "~/.paranoid/data"

[rpc]
# JSON-RPC listen address (HOST:PORT)
listen = "127.0.0.1:9401"

[mining]
# Enable built-in PoW miner
enabled = true

# PoW threads. 0 = all physical cores.
threads = 0

# Coinbase address (32-byte hex). Empty = use wallet primary address.
miner_address = ""
```

**Config precedence:** CLI flags > config file > built-in defaults.

**Minimal config** (everything else uses defaults):
```toml
[network]
seeds = ["1.2.3.4:9400"]

[mining]
enabled = true
```

### 2.3 Network Defaults

| Setting | Mainnet | Testnet |
|---|---|---|
| P2P port | `9400` | `19400` |
| RPC port | `9401` | `19401` |
| P2P protocol | `/noid/mainnet/1.0.0` | `/noid/testnet/1.0.0` |
| Magic bytes | `0x4E4F4944` ("NOID") | `0x544E4F49` ("TNOI") |
| DNS seeds | `seed1.noid.network`, `seed2.noid.network` | `testnet-seed.noid.network` |
| Genesis PoW target | `2^235` (~65K hashes) | `2^252` (trivial) |
| Block time | 60 s | 60 s |
| Block reward | 50 NOID | 50 NOID |

### 2.4 Startup Scenarios

**Scenario A — Bootstrap a new network (first node ever)**
```bash
paranoid --mine --genesis --data-dir ~/.paranoid
```
The `--genesis` flag fires `sync_ready` immediately so the miner starts without waiting for peers.
All subsequent nodes sync automatically when they connect.

**Scenario B — Join an existing network**
```bash
paranoid --mine \
  --seed seed1.noid.network:9400 \
  --data-dir ~/.paranoid
```
The node requests a state snapshot from the first peer it connects to (O(1) sync ~5ms proof verification), then starts mining.

**Scenario C — Full node without mining (relay / RPC only)**
```bash
paranoid --seed seed1.noid.network:9400 --data-dir ~/.paranoid
```

**Scenario D — Pool operator (expose RPC to miners)**
```bash
paranoid \
  --mine \
  --rpc-listen 0.0.0.0:9401 \
  --seed seed1.noid.network:9400 \
  --data-dir /var/lib/paranoid
```

**Scenario E — Testnet development**
```bash
paranoid \
  --network testnet \
  --mine --genesis \
  --data-dir ~/.paranoid-testnet \
  --p2p-listen 0.0.0.0:19400 \
  --rpc-listen 127.0.0.1:19401
```

---

## 3. CLI Client (`noid-cli`)

Connects to a running `paranoid` daemon via JSON-RPC. No keys or crypto happen here — everything runs in the daemon.

```
noid-cli [GLOBAL FLAGS] <COMMAND> [ARGS]
```

### 3.1 Global Flags

| Flag | Default | Description |
|---|---|---|
| `-r, --rpc <URL>` | `http://127.0.0.1:9401` | RPC endpoint. Also reads `NOID_RPC` env var. |
| `-j, --json` | off | Output raw JSON (for `\| jq`, scripts, CI). |

Hashes and addresses are **always shown in full**. They are security-critical identifiers — truncating them silently would be wrong.

```bash
# Use environment variable instead of --rpc every time
export NOID_RPC=http://192.168.1.10:9401
noid-cli status

# Raw JSON for scripting
noid-cli --json balance | jq .total_noid
```

### 3.2 All Commands — Quick Reference

| Command | Alias | Description | RPC method |
|---|---|---|---|
| `status` | | Chain tip: height, hash, difficulty | `getChainInfo` |
| `block-hash <H>` | `bh` | Block hash at height H | `getBlockHash` |
| `block-header <H>` | `bhead` | Decoded block header at height H | `getBlockHeader` |
| `block <H>` | `blk` | Raw block bytes at H (last 18 only) | `getBlock` |
| `header <H>` | | Raw 276-byte header hex (for devs) | `getHeaderByHeight` |
| `proof` | `rec` | Recursive chain proof info | `getRecursiveProof` |
| `slot <N>` | | UTXO slot by index | `getSlot` |
| `utxos-of <ADDR>` | | All UTXOs owned by address | `getSlotsByOwner` |
| `tx <HASH>` | | Confirmed tx info | `getTx` |
| `is-nullifier <HASH>` | | Check if tx is spent | `isNullifier` |
| `state` | | State dimensions, fill %, disk size | `getStateInfo` |
| `mining` | | Difficulty, reward, proof height | `getMiningInfo` |
| `peers` | | Connected peer count | `getPeerCount` |
| `estimate-fee [N]` | | Min fee for N outputs (default: 2) | `estimateFee` |
| `validate <ADDR>` | | Validate & normalise address | `validateAddress` |
| `epoch` | `anchor` | Epoch anchor hash | `getEpochAnchor` |
| `mempool` | | Pending txs list | `getMempoolInfo` |
| `mempool-tx <HASH>` | | Single pending tx | `getMempoolEntry` |
| `address [N]` | `addr` | Wallet address at key index N | `walletGetAddress` |
| `balance` | `bal` | Confirmed balance | `walletGetBalance` |
| `utxos` | `ls` | Own UTXO list | `walletListUtxos` |
| `send <ADDR> <NOID>` | | Send NOID | `walletSend` |
| `history` | `hist` `txs` | Tx history | `walletHistory` |
| `scan` | | Rescan chain state | `walletScan` |
| `consolidate` | `merge` | Merge small UTXOs | `walletConsolidate` |
| `receipt <HASH>` | | Export payment receipt | `walletExportReceipt` |
| `verify <HEX>` | `check` | Verify payment receipt | `verifyReceipt` |
| `block-template` | `template` | PoW template for external miner | `getBlockTemplate` |
| `submit-block <HEX>` | `submit` | Submit solved block | `submitBlock` |
| `stop` | | Stop the daemon | `stop` |

---

### 3.3 Chain Commands

#### `status`
Node health at a glance: height, best hash, difficulty, active UTXOs, mempool.

**Aliases:** (none)

```bash
noid-cli status
```

```
Paranoid node status
  Height             1337
  Best hash          f7845242ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1
  Difficulty         24 leading zeros (0xffffff0000000000000000000000000000000000000000000000000000000000)
  Active UTXOs       1042 (0% of 16777216 slots, log=24)
  Mempool            3 pending tx(s)
```

```bash
# JSON output
noid-cli --json status
```
```json
{
  "height": 1337,
  "best_hash": "f7845242ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1",
  "difficulty_target": "ffffff0000000000000000000000000000000000000000000000000000000000",
  "active_slot_count": 1042,
  "log_slots": 24
}
```

---

#### `block <HEIGHT>`
Block details at a given height (raw bytes hex).  
Only the last **18 blocks** are stored on-chain; older blocks are unavailable by design.

**Aliases:** `blk`

```bash
noid-cli block 1337
noid-cli --json block 1337
```

```
Block #1337
  Hex length         512 bytes (1024 hex chars)
  Header (276B)      f7845242ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1...

  Tip: Use --json to get the full raw hex.
```

---

#### `header <HEIGHT>`
Raw 276-byte block header as hex. For block explorers and developers.

```bash
noid-cli header 1337
noid-cli --json header 1337
```

```
Block header #1337
  Size               276 bytes (276)

  f7845242ea6c2b610a7d0c08f08ef16a2ff366148bd07541...
  ...
```

---

#### `proof`
Latest recursive chain proof: covers the entire chain history in ~6.6 KB.
Any node can verify the whole chain in ~5 ms using this proof.

**Aliases:** `rec`

```bash
noid-cli proof
```

```
Recursive chain proof  (O(1) sync)
  Size               6800 bytes (6.6 KB)  (full chain history in one tiny proof)
  Fingerprint        08000000…00000000

  Note: Any node can verify the ENTIRE chain history in ~5 ms using this proof.
```

---

#### `slot <INDEX>`
UTXO slot contents: whether it's occupied, owner address, and value.

```bash
noid-cli slot 12345678
noid-cli --json slot 12345678
```

```
Slot #12345678
  Status             live UTXO
  Value              50.000000 NOID  (50000000 μNOID)
  Owner              113e4a1c0300a5b09c8e09f4a402a38d83965c08a9c17cdd54756108d922d491
```

Empty slot:
```
Slot #9999
  Status             empty (unspent / available)
```

---

#### `block-hash <HEIGHT>`
Block hash at a given height. Stored forever.

**Aliases:** `bh`

```bash
noid-cli block-hash 100
noid-cli bh 1
```

```
Block #100 hash
  Hash               6e0ba7fbcce8f545468e0397e5cdd49178f62a33818c1d2a3ec1124f4bf93a50
```

---

#### `block-header <HEIGHT>`
Decoded block header at a given height — all fields as structured data. Stored forever.

**Aliases:** `bhead`

```bash
noid-cli block-header 1
noid-cli --json block-header 1
```

```
Block header #1
  hash               61ffb6fd9eaf7768531e61bda509dad589377d4b87634e5ec61e0cbf56e5aa6e
  prev_hash          a9919470fdea88430a733a81162a1e41a00c0e084dac890f8e4b1202a3ff9e70
  height             1
  timestamp          1780595891
  miner              noid18krueyqyq8um2f2ehca87hnzlpakr7z007wzl9vfgdn6ga5wt6asjkldtp
  state_root         2f4cef857cda723eafd5a5db69e733d3d46868998fe9f36872b051394eafd479
  tx_root            7b625c2ec238a9f4eeee2db4cd90a1eef0fecb47d10a77544bab6a07105bb15b
  difficulty_target  ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
  active_slot_count  1
  log_slots          24
  alloc_counter      1
```

---

#### `utxos-of <ADDRESS>`
All live UTXO slots owned by an address. Uses the persistent owner index — O(1) lookup.

```bash
noid-cli utxos-of noid18krueyqyq8um2f2ehca87hnzlpakr7z007wzl9vfgdn6ga5wt6asjkldtp
noid-cli --json utxos-of noid18krueyqyq8um...
```

```
UTXOs of noid18krueyqyq8um2f...
  ──────────────────────────────────────────────────
  slot                    NOID
  ──────────────────────────────────────────────────
  11468800           50.000000
  11468801           50.000000
  ──────────────────────────────────────────────────
  TOTAL             100.000000  (2 UTXOs)
```

---

#### `tx <TX_HASH>`
Confirmed transaction info by hash. Uses the permanent tx index (stored forever).

```bash
noid-cli tx c6278428ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1
```

```
Transaction
  tx_hash    c6278428ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1
  height     100
  block_hash f7845242ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1
  position   2
```

If not found: suggests checking `noid-cli mempool-tx <hash>` for pending txs.

---

#### `is-nullifier <TX_HASH>`
Returns whether a transaction is in the nullifier set (i.e., already spent and cannot be re-submitted).

```bash
noid-cli is-nullifier c6278428ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1
```

```
Nullifier check
  tx_hash    c6278428ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1
  status     not spent
```

---

#### `state`
UTXO state dimensions: slot space capacity, fill percentage, disk size, headroom until auto-expansion.

```bash
noid-cli state
noid-cli --json state
```

```
UTXO state
  Slot space       2^24 = 16777216 slots  (max 2^32)
  Active UTXOs     239  (0.00% full)
  Fill             [░░░░░░░░░░░░░░░░░░░░░░|░░░░░░] 0.00%  (| = expand at 75%)
  Until expand     12582913 slots  (74.99% headroom)
  State size       768.0 MB
```

At mainnet scale (log_slots=24, 16M slots): state is **768 MB** on disk.  
When `fill_pct ≥ 75%` the node automatically doubles the slot space (log_slots → 25).

---

#### `mining`
Mining and network state: difficulty, block reward, recursive proof height.

```bash
noid-cli mining
```

```
Mining info
  Height             239
  Difficulty         24 leading zeros  target: ffffff0000000000...
  Block reward       50.000000 NOID  (50000000 μNOID)
  Active UTXOs       239
  Recursive proof    height 221
```

---

#### `peers`
Number of currently connected P2P peers.

```bash
noid-cli peers
```

```
Connected peers
  Count              3
```

---

#### `estimate-fee [N_OUTPUTS]`
Minimum relay fee for a transaction with N outputs (default: 2).
Formula: `MIN_FEE_BASE(5000) + N × FEE_PER_OUTPUT(2000)` μNOID.

```bash
noid-cli estimate-fee      # default: 2 outputs
noid-cli estimate-fee 4   # 4 outputs
```

```
Fee estimate (2 outputs)
  Min fee            0.009000 NOID  (9000 μNOID)

  Formula: MIN_FEE_BASE(5000) + n_outputs × FEE_PER_OUTPUT(2000) μNOID
```

---

#### `validate <ADDRESS>`
Validate and normalise an address. Returns the canonical bech32m form.
Accepts both `noid1...` (bech32m) and 64-char hex.

```bash
noid-cli validate noid18krueyqyq8um2f2ehca87hnzlpakr7z007wzl9vfgdn6ga5wt6asjkldtp
noid-cli validate 3d87cc900401f9b52559be3a7f5e62f87b61f84f7f9c2f95894367a4768e5ebb
```

```
Address validation
✓ Valid address
  bech32m  noid18krueyqyq8um2f2ehca87hnzlpakr7z007wzl9vfgdn6ga5wt6asjkldtp
  hex      3d87cc900401f9b52559be3a7f5e62f87b61f84f7f9c2f95894367a4768e5ebb
```

---

#### `mempool-tx <TX_HASH>`
Single pending transaction in the mempool by hash.

```bash
noid-cli mempool-tx c6278428ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1
```

```
Mempool transaction
  tx_hash            c6278428ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1
  Fee                0.009000 NOID  (9000 μNOID)
  Inputs             1
  Outputs            2
  Admitted at height 237
  ZK proof           attached
```

---

#### `epoch`
Current epoch anchor hash. Wallets embed this in transactions to bind proofs to a point in time.

**Aliases:** `anchor`

```bash
noid-cli epoch
```

```
Epoch anchor
  Hash               61278f7c8d4a9e1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b

  Note: Wallets use this hash as epoch_anchor when building transaction proofs.
```

---

#### `mempool`
Pending transactions: count, fee floor, and list of up to 20 TXs.

```bash
noid-cli mempool
noid-cli --json mempool
```

```
Mempool
  Pending            3 transactions
  Fee floor          0.005000 NOID  (5000 μNOID minimum)

  ──────────────────────────────────────────────────────────────────────────────────────────
  tx hash                                                           fee (μNOID)  in→out   ZK
  ──────────────────────────────────────────────────────────────────────────────────────────
  c6278428ea6c2b610a7d0c08f08ef16a2ff366148bd07541         9000   1→2      ✓
  a1b2c3d412345678deadbeef00001111aabbccdd99887766         5000   0→1      ✓
  deadbeefcafebabe0102030405060708090a0b0c0d0e0f10         7000   2→3      ·
```

`ZK ✓` = wallet proof bundle attached (faster block inclusion).  
`ZK ·` = native consensus only (slower, waiting for re-submission with proof).

---

### 3.3 Wallet Commands

> **Amount format:** Always in **NOID** (e.g. `10.5`, `0.000001`).  
> The CLI converts to μNOID automatically before sending to the daemon.  
> 1 NOID = 1 000 000 μNOID.

---

#### `address [INDEX]`
Show your receiving address. Default index = 0 (primary address).

**Aliases:** `addr`

```bash
noid-cli address           # primary address (index 0)
noid-cli address 1         # second derived address
noid-cli address 0 --full-hash
```

```
Wallet address [index=0]
  ec7c7a9a4dfff02df4275b1debf5d8fdc336307d8e895108b73f059923afcdb2

  ↑ This is your primary receiving address. Share it to receive NOID.
```

---

#### `balance`
Confirmed wallet balance (NOID and μNOID) and UTXO count.

**Aliases:** `bal`

```bash
noid-cli balance
noid-cli --json balance
```

```
Wallet balance
  Balance:           3000.000000 NOID  (3000000000 μNOID)
  UTXOs              60
```

If no UTXOs found:
```
⚠ No UTXOs found in wallet cache.
       Run 'noid-cli scan' to discover UTXOs from chain state.
```

---

#### `utxos`
List all confirmed UTXOs: slot index, value, key derivation index, confirmation block, address.

**Aliases:** `ls`

```bash
noid-cli utxos
noid-cli utxos | head -20   # first 20 (no panic on pipe)
noid-cli --json utxos
```

```
Wallet UTXOs
  ────────────────────────────────────────────────────────────────────────────────────────────────────────
  slot         NOID          key   at block  address
  ────────────────────────────────────────────────────────────────────────────────────────────────────────
  11468858     50.000000       0         59  ec7c7a9a4dfff02df4275b1debf5d8fdc336307d8e895108b73f059923afcdb2
  11468877     50.000000       0         78  ec7c7a9a4dfff02df4275b1debf5d8fdc336307d8e895108b73f059923afcdb2
  ────────────────────────────────────────────────────────────────────────────────────────────────────────
  TOTAL        100.000000
```

---

#### `send <ADDRESS> <AMOUNT_NOID>`
Send NOID to a recipient address.

- Amount is in **NOID** (not μNOID). The CLI converts automatically.
- Fee is auto-computed (≥ 0.005 NOID) unless `--fee` is specified.
- Interactive confirmation prompt for amounts ≥ 1000 NOID.

```bash
# Send 10.5 NOID with automatic fee
noid-cli send f7845242ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1 10.5

# Send with explicit fee (0.01 NOID)
noid-cli send f7845242ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1 10.5 --fee 0.01

# Send smallest possible amount (1 μNOID = 0.000001 NOID)
noid-cli send f7845242ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1 0.000001

# Self-send (to own address)
MY_ADDR=$(noid-cli address | grep -v "^$\|index\|↑")
noid-cli send "$MY_ADDR" 1.0
```

```
Transaction submitted
✓ TX c6278428ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1

  To                 f7845242ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1
  Amount             10.500000 NOID  (10500000 μNOID)
  Fee                0.009000 NOID  (9000 μNOID) (auto)
  TX hash            c6278428ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1

  ⏳ The transaction is pending. It will confirm in the next block (~60s).
  Tip: Use 'noid-cli balance' to check your balance after confirmation.
```

**Error cases:**
```
Error: Insufficient funds.
       Requested: 999.000000 NOID  (999000000 μNOID)
       Run 'noid-cli balance' to check your current balance.

Error: Invalid address: expected 64 hex characters, got 8.
       Example: noid-cli send f7845242ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1 10.5
```

**Options:**

| Flag | Default | Description |
|---|---|---|
| `--fee <FEE_NOID>` | auto | Transaction fee in NOID. Auto = minimum + fee floor. |

---

#### `history`
Transaction history: all received and sent transactions, most recent last.

**Aliases:** `hist`, `txs`

```bash
noid-cli history
noid-cli --json history
```

```
Transaction history
  ──────────────────────────────────────────────────────────────────────────────────────────────
    #        block               NOID  tx hash
  ──────────────────────────────────────────────────────────────────────────────────────────────
  #1             1  + 50.000000 NOID  3ea1aad760d325630a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1
  #2             2  + 50.000000 NOID  faa0a9731a800dabdeadbeef00001111aabbccdd99887766112233445566778899
  #5           100  - 10.500000 NOID  c6278428ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1
  ──────────────────────────────────────────────────────────────────────────────────────────────
               + 100.000000 received  - 10.500000 NOID sent
```

Green `+` = received. Red `-` = sent.

---

#### `scan`
Rescan the full chain state to (re)discover your UTXOs.

Run this if:
- Your balance looks wrong
- You just started a fresh node and wallet balance shows 0
- You imported a new key / derivation path

```bash
noid-cli scan
```

```
  Scanning chain state for your UTXOs... done.
Wallet scan complete
✓ Found 60 UTXO(s)
  Balance            3000.000000 NOID  (3000000000 μNOID)
```

---

#### `consolidate`
Merge small UTXOs into fewer larger ones. Each round submits one TX and waits for confirmation. Useful before sending large amounts (fewer inputs = lower fees).

**Aliases:** `merge`

```bash
noid-cli consolidate               # auto fee, up to 100 rounds
noid-cli consolidate --fee 0.01    # explicit fee per round
noid-cli consolidate --rounds 3    # limit to 3 rounds
```

```
Wallet consolidate
  Merging small UTXOs to reduce UTXO count and lower future fees.
  Fee: auto (minimum per round)

✓ Round 1: TX a1b2c3d412345678deadbeef00001111aabbccdd99887766112233445566778899
  Waiting for confirmation............ confirmed.
  UTXOs remaining: 20  Balance: 2990.000000 NOID
✓ Round 2: TX deadbeefcafebabe0102030405060708090a0b0c0d0e0f10a1b2c3d412345678
  Waiting for confirmation............ confirmed.
✓ Consolidation complete — wallet has 1 UTXO.

  Total: 2 round(s) completed. TXs may still be pending.
  Next: Run 'noid-cli balance' after confirmation.
```

**Options:**

| Flag | Default | Description |
|---|---|---|
| `--fee <FEE_NOID>` | auto | Fee per consolidation TX in NOID. |
| `--rounds <N>` | `100` | Maximum consolidation rounds. |

---

#### `receipt <TX_HASH>`
Export a Merkle inclusion proof (payment receipt) for a confirmed transaction.

Outputs raw hex to stdout — redirect to a file.

```bash
# Export
noid-cli receipt c6278428ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1 > payment.hex

# Verify immediately
noid-cli verify $(noid-cli receipt c6278428ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1)

# Send receipt to payer
cat payment.hex | mail -s "Payment receipt" payee@example.com
```

```
3a9f7c8db61e0a7d1c2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c...
(full receipt hex to stdout, variable length ~1-4 KB)

Tip: Redirect to a file: noid-cli receipt <hash> > receipt.hex
Tip: Verify:              noid-cli verify $(cat receipt.hex)
```

---

#### `verify <RECEIPT_HEX>`
Verify a Merkle payment receipt against the canonical chain.

**Aliases:** `check`

```bash
# From a saved file (most common usage)
noid-cli verify $(cat payment.hex)

# Inline hex (receipt bytes, variable length)
noid-cli --json verify $(cat payment.hex)
```

Valid receipt:
```
Receipt verification
✓ Receipt is VALID and canonical.
  Merkle proof       ✓ valid
  On canonical chain ✓ yes
```

Invalid receipt (reorged block):
```
Error: Receipt INVALID: header at height 1337 not found
  Merkle proof       ✓ valid
  On canonical chain ✗ no (block may have been reorged)
```

---

### 3.4 Node Commands

#### `stop`
Gracefully stop the running `paranoid` daemon.

- Cancels the PoW miner (waits up to 2s for clean exit).
- Stops the RPC server.
- Flushes MDBX to disk.

```bash
noid-cli stop
```

```
✓ Daemon is shutting down.
```

---

### 3.5 Mining Commands

For operators running external GPU/ASIC miners via the Block Template API (analogous to Stratum in Bitcoin).

---

#### `block-template [--miner-addr <HEX>]`
Get a PoW block template for an external miner.

Returns the 212-byte `header_core` as hex — the input to Blake3 PoW search.

**Aliases:** `template`

```bash
noid-cli block-template
noid-cli block-template --miner-addr f7845242ea6c2b610a7d0c08f08ef16a2ff366148bd07541
noid-cli --json block-template
```

```
Block template
  Height             1338
  Txs in block       5
  Header core (212B) f7845242ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1...

  PoW: Compute Blake3(header_core || nonce_le_16bytes) < difficulty_target, then submit.
```

JSON response:
```json
{
  "header_core_hex": "f7845242ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1...",
  "height": 1338,
  "n_txs": 5
}
```

**PoW algorithm:**
```
nonce ∈ [0, 2^128)
Blake3(header_core_hex || nonce_le_16bytes) < difficulty_target
```

**Options:**

| Flag | Default | Description |
|---|---|---|
| `--miner-addr <HEX>` | wallet address | Coinbase reward address (64-char hex). |

---

#### `submit-block <BLOCK_HEX>`
Submit a solved block from an external miner.

**Aliases:** `submit`

```bash
# Miner found a valid nonce — submits full block bytes (header + txs)
# The block hex is built by sealing template_header_core + nonce
noid-cli submit-block <FULL_BLOCK_HEX>
```

```
✓ Block accepted: f7845242ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1
```

---

## 4. JSON-RPC API

### 4.1 Transport

**Protocol:** JSON-RPC 2.0 over HTTP POST  
**Content-Type:** `application/json`  
**Endpoint:** `http://127.0.0.1:9401` (default)

All method names are prefixed with `paranoid_`.

**Request format:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "paranoid_<method>",
  "params": [...]
}
```

**Success response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": <value>
}
```

**Error response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32000,
    "message": "description"
  }
}
```

**Shell example:**
```bash
curl -s http://127.0.0.1:9401 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"paranoid_getChainInfo","params":[]}'
```

---

### 4.2 Chain Methods

---

#### `paranoid_getChainInfo`
Returns the current chain tip summary.

```json
// Request
{"method": "paranoid_getChainInfo", "params": []}

// Response
{
  "height": 1337,
  "best_hash": "f7845242ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1",
  "difficulty_target": "ffffff0000000000000000000000000000000000000000000000000000000000",
  "active_slot_count": 1042,
  "log_slots": 24
}
```

| Field | Type | Description |
|---|---|---|
| `height` | `u64` | Current tip height (number of blocks since genesis). |
| `best_hash` | `hex` | Blake3 hash of the tip block header. |
| `difficulty_target` | `hex` | 256-bit PoW target (LE). Valid hash must be ≤ this value. |
| `active_slot_count` | `u64` | Number of live UTXOs in the current state. |
| `log_slots` | `u32` | `log₂` of total slot space capacity. Capacity = `2^log_slots`. |

---

#### `paranoid_blockCount`
Returns current tip height as a single integer.

```json
{"method": "paranoid_blockCount", "params": []}
// → 1337
```

---

#### `paranoid_getHeaderByHeight`
Returns the block header at a given height as 276-byte LE hex, or `null` if not found.

```json
{"method": "paranoid_getHeaderByHeight", "params": [1337]}
// → "f7845242ea6c2b610a7d0c08f08ef16a2ff366148bd07541..." (552 hex chars = 276 bytes)
// → null  (if height > tip or data pruned)
```

---

#### `paranoid_getHeaderByHash`
Returns the block header matching a 32-byte block hash, or `null`.

```json
{
  "method": "paranoid_getHeaderByHash",
  "params": ["f7845242ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1"]
}
// → "f7845242ea6c2b610a7d0c08f08ef16a2ff366148bd07541..." (header hex) or null
```

---

#### `paranoid_getBlock`
Returns the full block bytes as hex at a given height, or `null`.

> **Note:** Only the last **18 blocks** are retained. Older blocks are pruned by design.  
> For historical state, use the recursive proof and state snapshot instead.

```json
{"method": "paranoid_getBlock", "params": [1337]}
// → "f7845242ea6c2b610a7d0c08f08ef16a..." (full block hex) or null
```

---

#### `paranoid_getSlot`
Returns the contents of a UTXO state slot by index.

```json
{"method": "paranoid_getSlot", "params": [12345678]}
// →
{
  "slot_index": 12345678,
  "value": 50000000,
  "owner": "ec7c7a9a4dfff02df4275b1debf5d8fdc336307d8e895108b73f059923afcdb2",
  "empty": false
}
```

| Field | Type | Description |
|---|---|---|
| `slot_index` | `u32` | Index in the state array `[0, 2^log_slots)`. |
| `value` | `u64` | Balance in μNOID. 0 if empty. |
| `owner` | `hex` | 32-byte owner address. All-zeros if empty. |
| `empty` | `bool` | `true` = slot is unoccupied (zero). |

---

#### `paranoid_getActiveSlotCount`
Returns the number of live (non-zero) UTXOs.

```json
{"method": "paranoid_getActiveSlotCount", "params": []}
// → 1042
```

---

#### `paranoid_getBlockHash`
H_BLOCK hash of the block at `height`. Stored forever, fast O(1) lookup.

```json
{"method": "paranoid_getBlockHash", "params": [100]}
// → "6e0ba7fbcce8f545468e0397e5cdd49178f62a33818c1d2a3ec1124f4bf93a50"
// → null  (if height > tip)
```

---

#### `paranoid_getBlockHeader`
Decoded block header at `height`. All fields as typed values. Stored forever.

```json
{"method": "paranoid_getBlockHeader", "params": [1]}
```

```json
{
  "height": 1,
  "hash": "61ffb6fd9eaf7768531e61bda509dad589377d4b87634e5ec61e0cbf56e5aa6e",
  "prev_hash": "a9919470fdea88430a733a81162a1e41a00c0e084dac890f8e4b1202a3ff9e70",
  "state_root": "2f4cef857cda723eafd5a5db69e733d3d46868998fe9f36872b051394eafd479",
  "tx_root": "7b625c2ec238a9f4eeee2db4cd90a1eef0fecb47d10a77544bab6a07105bb15b",
  "timestamp": 1780595891,
  "miner": "noid18krueyqyq8um2f2ehca87hnzlpakr7z007wzl9vfgdn6ga5wt6asjkldtp",
  "difficulty_target": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "proof_transcript_hash": "0101010101010101010101010101010101010101010101010101010101010101",
  "log_slots": 24,
  "active_slot_count": 1,
  "alloc_counter": 1
}
```

---

#### `paranoid_getSlotsByOwner`
All live UTXO slots owned by `address` (bech32m or 64-char hex).
Uses the persistent `T_OWNER_INDEX` table — O(1) lookup.

```json
{
  "method": "paranoid_getSlotsByOwner",
  "params": ["noid18krueyqyq8um2f2ehca87hnzlpakr7z007wzl9vfgdn6ga5wt6asjkldtp"]
}
```

```json
[
  { "slot_index": 11468800, "value": 50000000, "owner": "noid18krueyqyq8um...", "empty": false },
  { "slot_index": 11468801, "value": 50000000, "owner": "noid18krueyqyq8um...", "empty": false }
]
```

---

#### `paranoid_getTx`
Confirmed transaction info by `tx_body_hash`. Uses the permanent `T_TX_INDEX` table.
Returns `null` if the hash is unknown (not confirmed or never submitted).

```json
{"method": "paranoid_getTx", "params": ["c6278428ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1"]}
```

```json
{
  "tx_hash": "c6278428ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1",
  "height": 100,
  "block_hash": "f7845242ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1",
  "tx_position": 2
}
```

---

#### `paranoid_isNullifier`
Returns `true` if `txhash` is in the nullifier set (tx was already spent and cannot be re-submitted).

```json
{"method": "paranoid_isNullifier", "params": ["c6278428ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1"]}
// → false
```

---

#### `paranoid_getStateInfo`
Full UTXO state dimensions, fill metrics, and disk size.

```json
{"method": "paranoid_getStateInfo", "params": []}
```

```json
{
  "log_slots": 24,
  "capacity": 16777216,
  "active_slots": 239,
  "fill_pct": 0.0,
  "slots_until_expand": 12582913,
  "expand_trigger_pct": 75,
  "log_slots_max": 32,
  "state_bytes": 805306368,
  "state_size_human": "768.0 MB"
}
```

| Field | Description |
|---|---|
| `log_slots` | log₂ of current slot space capacity |
| `capacity` | total UTXO slots = 2^log_slots |
| `active_slots` | live (non-empty) UTXO count |
| `fill_pct` | active / capacity × 100, rounded to 2dp |
| `slots_until_expand` | slots remaining before 75% trigger fires (negative = already fired) |
| `expand_trigger_pct` | always 75 (EXPAND_NUM/EXPAND_DENOM × 100) |
| `log_slots_max` | always 32 (max allowed slot depth) |
| `state_bytes` | capacity × 48 bytes/slot (value 16B + owner_hi 16B + owner_lo 16B) |
| `state_size_human` | human-readable size string (e.g. "768.0 MB") |

---

#### `paranoid_getMiningInfo`
Mining and network state.

```json
{"method": "paranoid_getMiningInfo", "params": []}
```

```json
{
  "height": 239,
  "difficulty_bits": 24,
  "difficulty_target": "ffffff0000000000000000000000000000000000000000000000000000000000",
  "block_reward_micronoid": 50000000,
  "block_reward_noid": 50.0,
  "active_slot_count": 239,
  "recursive_proof_height": 221
}
```

---

#### `paranoid_getPeerCount`
Number of currently connected P2P peers.

```json
{"method": "paranoid_getPeerCount", "params": []}
// → 3
```

---

#### `paranoid_estimateFee`
Minimum relay fee in μNOID for a transaction with `n_outputs` outputs.
Formula: `MIN_FEE_BASE(5000) + n_outputs × FEE_PER_OUTPUT(2000)` μNOID.

```json
{"method": "paranoid_estimateFee", "params": [2]}
// → 9000  (= 5000 + 2×2000 μNOID = 0.009 NOID)
```

---

#### `paranoid_validateAddress`
Validate and normalise an address. Accepts bech32m (`noid1…`) or 64-char hex.

```json
{
  "method": "paranoid_validateAddress",
  "params": ["noid18krueyqyq8um2f2ehca87hnzlpakr7z007wzl9vfgdn6ga5wt6asjkldtp"]
}
```

```json
{
  "valid": true,
  "bech32": "noid18krueyqyq8um2f2ehca87hnzlpakr7z007wzl9vfgdn6ga5wt6asjkldtp",
  "hex": "3d87cc900401f9b52559be3a7f5e62f87b61f84f7f9c2f95894367a4768e5ebb",
  "error": null
}
```

Invalid address:
```json
{ "valid": false, "bech32": null, "hex": null, "error": "invalid address format (...)" }
```

---

#### `paranoid_getMempoolEntry`
Single pending transaction by hash. Returns `null` if not in mempool.

```json
{
  "method": "paranoid_getMempoolEntry",
  "params": ["c6278428ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1"]
}
```

```json
{
  "tx_hash": "c6278428ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1",
  "fee_micronoid": 9000,
  "fee_rate": 3000,
  "n_inputs": 1,
  "n_outputs": 2,
  "admitted_height": 237,
  "has_proof": true
}
```

---

#### `paranoid_getSlotHints`
Returns N candidate empty slot indices for use as transaction outputs.

Wallets call this to find free slots before building a transaction proof.

```json
{"method": "paranoid_getSlotHints", "params": [8]}
// → [11468858, 11468877, 11468863, 11468845, ...]
```

| Param | Type | Description |
|---|---|---|
| `count` | `u32` | Number of candidate slots to return (max 256). |

---

#### `paranoid_getEpochAnchor`
Returns the hash of the current tip block header, which wallets use as `epoch_anchor` in transaction bodies.

```json
{"method": "paranoid_getEpochAnchor", "params": []}
// → "61278f7c8d4a9e1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b"
```

A transaction's `epoch_anchor` must refer to a block within the last `ANCHOR_DEPTH = 144` blocks (~144 minutes).

---

#### `paranoid_getRecursiveProof`
Returns the latest recursive chain proof as hex, or `null` if not yet generated.

The proof cryptographically covers the entire chain history in ~6.6 KB. Any node can verify the whole chain in ~5 ms.

```json
{"method": "paranoid_getRecursiveProof", "params": []}
// → "3a9f7c8d..." (hex bytes, ~13 600 hex chars = ~6.8 KB) or null
// Full hex omitted for brevity — actual response is ~6.8 KB of hex
```

> The proof lags behind the tip by `FINALITY_DEPTH = 18` blocks (only finalized blocks are proven).

---

### 4.3 Mempool Methods

---

#### `paranoid_getMempoolInfo`
Returns full mempool state: count, fee floor, and list of all pending transactions.

```json
{"method": "paranoid_getMempoolInfo", "params": []}
```

```json
{
  "size": 3,
  "fee_floor": 5000,
  "txs": [
    {
      "tx_hash": "c6278428ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1",
      "fee_micronoid": 9000,
      "fee_rate": 3000,
      "n_inputs": 1,
      "n_outputs": 2,
      "admitted_height": 1330,
      "has_proof": true
    }
  ]
}
```

| Field | Type | Description |
|---|---|---|
| `size` | `usize` | Total pending transaction count. |
| `fee_floor` | `u64` | Current dynamic minimum fee in μNOID. |
| `txs[].tx_hash` | `hex` | Transaction body hash. |
| `txs[].fee_micronoid` | `u64` | Absolute fee in μNOID. |
| `txs[].fee_rate` | `u64` | Fee per input+output (for fee estimation). |
| `txs[].n_inputs` | `usize` | Number of spent inputs. |
| `txs[].n_outputs` | `usize` | Number of created outputs. |
| `txs[].admitted_height` | `u64` | Chain height when the TX was admitted. |
| `txs[].has_proof` | `bool` | Whether a ZK proof bundle is cached (faster mining). |

---

#### `paranoid_getMempoolSize`
Returns pending TX count as a single integer. Lighter than `getMempoolInfo`.

```json
{"method": "paranoid_getMempoolSize", "params": []}
// → 3
```

---

#### `paranoid_submitTxIntent`
Submit a raw `TxIntent` (transaction + ZK proof) to the mempool.

```json
{
  "method": "paranoid_submitTxIntent",
  "params": ["f7845242ea6c2b610a7d0c08f08ef16a..."]
}
// → "c6278428ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1"  (tx_body_hash)
```

| Param | Type | Description |
|---|---|---|
| `hex` | `hex` | Wire-encoded `TxIntent` bytes (see §8.1 of API.md for format). |

Returns the `tx_body_hash` (32-byte hex) on success.

**Errors:** `InvalidProof`, `SlotConflict`, `BelowMinFee`, `BadEpochAnchor`, `Full`.

---

#### `paranoid_verifyReceipt`
Verify a Merkle payment receipt against the canonical chain.

```json
{
  "method": "paranoid_verifyReceipt",
  "params": ["3a9f7c8d..."]
}
```

```json
{
  "merkle_valid": true,
  "canonical": true,
  "confirmed": true,
  "error": null
}
```

| Field | Type | Description |
|---|---|---|
| `merkle_valid` | `bool` | Merkle inclusion proof is mathematically valid. |
| `canonical` | `bool` | The referenced block is on the current canonical chain. |
| `confirmed` | `bool` | `merkle_valid && canonical` — payment is confirmed. |
| `error` | `string?` | Human-readable error if not confirmed. |

---

### 4.4 Wallet Methods

All wallet methods operate on the daemon's built-in wallet (key stored in `data-dir/wallet.key`).

---

#### `paranoid_walletStatus`
Full wallet status including address, balance, and UTXO count.

```json
{"method": "paranoid_walletStatus", "params": []}
```

```json
{
  "exists": true,
  "address": "ec7c7a9a4dfff02df4275b1debf5d8fdc336307d8e895108b73f059923afcdb2",
  "balance_micronoid": 3000000000,
  "balance_noid": 3000.0,
  "utxo_count": 60,
  "address_count": 1
}
```

---

#### `paranoid_walletGetAddress`
Returns the derived address at key index N.

```json
{"method": "paranoid_walletGetAddress", "params": [0]}
// → "ec7c7a9a4dfff02df4275b1debf5d8fdc336307d8e895108b73f059923afcdb2"
```

---

#### `paranoid_walletGetBalance`
Returns confirmed balance breakdown.

```json
{"method": "paranoid_walletGetBalance", "params": []}
```

```json
{
  "total_micronoid": 3000000000,
  "total_noid": 3000.0,
  "utxo_count": 60
}
```

---

#### `paranoid_walletListUtxos`
Returns all confirmed UTXOs owned by the wallet.

```json
{"method": "paranoid_walletListUtxos", "params": []}
```

```json
[
  {
    "slot_index": 11468858,
    "value_micronoid": 50000000,
    "value_noid": 50.0,
    "address": "ec7c7a9a4dfff02df4275b1debf5d8fdc336307d8e895108b73f059923afcdb2",
    "key_index": 0,
    "confirmed_height": 59
  }
]
```

---

#### `paranoid_walletHistory`
Returns transaction history (most recent last).

```json
{"method": "paranoid_walletHistory", "params": []}
```

```json
[
  {
    "tx_hash": "c6278428ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1",
    "height": 100,
    "direction": "sent",
    "amount_micronoid": 10500000,
    "amount_noid": 10.5,
    "peer_address": "f7845242ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1",
    "timestamp": 1700000000
  },
  {
    "tx_hash": "3ea1aad760d325630a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1",
    "height": 1,
    "direction": "received",
    "amount_micronoid": 50000000,
    "amount_noid": 50.0,
    "peer_address": null,
    "timestamp": 1699999940
  }
]
```

| Field | Description |
|---|---|
| `direction` | `"sent"` or `"received"` |
| `peer_address` | Recipient (sent) or sender address (received). `null` for coinbase. |
| `timestamp` | Unix timestamp of the block (not the TX submission time). |

---

#### `paranoid_walletScan`
Rescan the full chain state to discover wallet UTXOs.

```json
{"method": "paranoid_walletScan", "params": []}
```

```json
{
  "found_utxos": 60,
  "balance_micronoid": 3000000000,
  "balance_noid": 3000.0
}
```

> This may take a few seconds on a fully-loaded node (16M+ slots).

---

#### `paranoid_walletSend`
Send NOID to a recipient address.

```json
{
  "method": "paranoid_walletSend",
  "params": [
    "f7845242ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1",
    10500000,
    0
  ]
}
```

| Param | Type | Description |
|---|---|---|
| `to_hex` | `hex` | Recipient address (32-byte hex = 64 chars). |
| `amount_micronoid` | `u64` | Amount in **μNOID**. Use `amount_noid × 1_000_000`. |
| `fee_micronoid` | `u64` | Fee in μNOID. `0` = auto (minimum + current fee floor). |

```json
{
  "tx_hash": "c6278428ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1",
  "fee_micronoid": 9000
}
```

**Errors:**
- `InsufficientFunds` — wallet balance < amount + fee
- `SlotConflict` — output slot occupied (retry in 1 block)
- `BadAddress` — invalid hex or wrong length

---

#### `paranoid_walletExportReceipt`
Export a Merkle inclusion proof for a confirmed transaction.

```json
{
  "method": "paranoid_walletExportReceipt",
  "params": ["c6278428ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1"]
}
// → "3a9f7c8d..."  (receipt bytes as hex, variable length)
```

---

#### `paranoid_walletConsolidate`
Merge up to 3 UTXOs into 1 (reduces UTXO count, lowers future fees).

```json
{
  "method": "paranoid_walletConsolidate",
  "params": [5000]
}
```

| Param | Type | Description |
|---|---|---|
| `fee_micronoid` | `u64` | Fee in μNOID. `0` = auto minimum. |

```json
{
  "tx_hash": "a1b2c3d412345678deadbeef00001111aabbccdd99887766112233445566778899",
  "fee_micronoid": 9000
}
```

Returns an error if wallet has ≤ 1 UTXO or insufficient funds.

---

### 4.5 Mining Methods

For external miners connecting via the Block Template API (Stratum-equivalent).

---

#### `paranoid_getBlockTemplate`
Returns the current PoW template for an external miner.

```json
{
  "method": "paranoid_getBlockTemplate",
  "params": ["f7845242ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1"]
}
```

| Param | Type | Description |
|---|---|---|
| `miner_address` | `hex` | Coinbase reward address (64-char hex). Empty string = wallet address. |

```json
{
  "header_core_hex": "f7845242ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1...",
  "height": 1338,
  "n_txs": 5
}
```

**PoW specification:**
```
header_core = first 212 bytes of the 276-byte block header
             (excludes proof_transcript_hash and witness_root)

valid nonce N satisfies:
  Blake3(header_core || N_as_16_byte_LE) ≤ difficulty_target
  where N ∈ [0, 2^128)

difficulty_target = 256-bit little-endian integer
```

**Block-withholding protection:** The `state_root` and `miner_address` are committed inside `header_core`. Changing the coinbase requires regenerating the ZK BlockProof (1–3 CPU seconds). External miners cannot steal blocks.

---

#### `paranoid_submitBlock`
Submit a solved block (full block bytes with valid nonce).

```json
{
  "method": "paranoid_submitBlock",
  "params": ["f7845242ea6c2b610a7d0c08f08ef16a..."]
}
// → "f7845242ea6c2b610a7d0c08f08ef16a2ff366148bd07541ec15a6f3e2b4c9d1"  (block hash)
```

---

### 4.6 Node Control

#### `paranoid_stop`
Gracefully stop the daemon.

```json
{"method": "paranoid_stop", "params": []}
// → "ok"
// (connection may close before response is received — that's expected)
```

---

## 5. Response Types

### `ChainInfo`
```typescript
{
  height:             u64,    // current tip block height
  best_hash:          hex,    // Blake3 hash of tip header (64 chars)
  difficulty_target:  hex,    // 256-bit PoW target LE (64 chars)
  active_slot_count:  u64,    // live UTXO count
  log_slots:          u32,    // log₂ of total slot capacity
}
```

### `SlotInfo`
```typescript
{
  slot_index: u32,     // index in [0, 2^log_slots)
  value:      u64,     // μNOID balance (0 if empty)
  owner:      hex,     // 32-byte owner address (all-zeros if empty)
  empty:      bool,    // true = slot is unoccupied
}
```

### `MempoolInfo`
```typescript
{
  size:       usize,          // pending TX count
  fee_floor:  u64,            // minimum relay fee in μNOID
  txs:        MempoolTxInfo[] // list of pending TXs
}
```

### `MempoolTxInfo`
```typescript
{
  tx_hash:         hex,    // transaction body hash
  fee_micronoid:   u64,    // absolute fee in μNOID
  fee_rate:        u64,    // fee per (n_inputs + n_outputs)
  n_inputs:        usize,  // number of spent inputs
  n_outputs:       usize,  // number of created outputs
  admitted_height: u64,    // chain height at admission
  has_proof:       bool,   // ZK bundle cached (faster block inclusion)
}
```

### `WalletBalance`
```typescript
{
  total_micronoid: u64,    // total confirmed balance in μNOID
  total_noid:      f64,    // total_micronoid / 1_000_000
  utxo_count:      usize,  // number of confirmed UTXOs
}
```

### `WalletUtxoInfo`
```typescript
{
  slot_index:        u32,   // UTXO slot index
  value_micronoid:   u64,   // value in μNOID
  value_noid:        f64,   // value_micronoid / 1_000_000
  address:           hex,   // 32-byte owner address
  key_index:         u32,   // wallet key derivation index
  confirmed_height:  u64,   // block height where this UTXO was created
}
```

### `WalletHistoryEntry`
```typescript
{
  tx_hash:           hex,     // transaction body hash
  height:            u64,     // block height
  direction:         string,  // "sent" | "received"
  amount_micronoid:  u64,     // amount in μNOID
  amount_noid:       f64,     // amount_micronoid / 1_000_000
  peer_address:      hex?,    // counterparty address (null for coinbase)
  timestamp:         u64,     // Unix timestamp (from block header)
}
```

### `WalletSendResult`
```typescript
{
  tx_hash:        hex,   // transaction body hash (32-byte hex)
  fee_micronoid:  u64,   // actual fee paid (useful when fee was 0 = auto)
}
```

### `WalletScanResult`
```typescript
{
  found_utxos:       usize,  // number of UTXOs found
  balance_micronoid: u64,    // total balance in μNOID
  balance_noid:      f64,    // balance_micronoid / 1_000_000
}
```

### `ReceiptVerifyResult`
```typescript
{
  merkle_valid: bool,    // Merkle inclusion proof is mathematically valid
  canonical:    bool,    // referenced block is on the canonical chain
  confirmed:    bool,    // merkle_valid && canonical
  error:        string?, // human-readable failure reason (null on success)
}
```

### `BlockTemplateResponse`
```typescript
{
  header_core_hex: hex,    // 212 bytes = 424 hex chars (PoW input)
  height:          u64,    // block height this template targets
  n_txs:           usize,  // total transaction count (including coinbase)
}
```

---

## 6. Error Reference

### RPC Errors

| Code | Name | Description |
|---|---|---|
| `-32700` | `ParseError` | Invalid JSON sent. |
| `-32600` | `InvalidRequest` | Request is not a valid JSON-RPC 2.0 object. |
| `-32601` | `MethodNotFound` | Method does not exist. |
| `-32602` | `InvalidParams` | Invalid parameters (wrong types or count). |
| `-32000` | `ServerError` | Application-level error (see `message` field). |

### Common Application Errors (`code: -32000`)

| Message | When | Action |
|---|---|---|
| `InsufficientFunds` | `walletSend` balance < amount + fee | Check balance, reduce amount, or wait for confirmation. |
| `SlotConflict` | Output slot already occupied | Retry in 1 block; node will suggest different slots. |
| `BelowMinFee` | Fee below dynamic fee floor | Increase fee or omit (auto will use floor). |
| `BadEpochAnchor` | TX anchor hash too old (> 144 blocks) | Re-prove the transaction with a fresh anchor. |
| `InvalidProof` | ZK proof verification failed | Wallet must regenerate the proof. |
| `Full` | Mempool capacity exceeded (8192 TXs) | Wait for the next block. |
| `AlreadyAdmitted` | TX already in mempool | TX was already submitted. |
| `MalformedIntent` | TxIntent bytes corrupt or wrong format | Check encoding. |
| `NullifierCollision` | TX attempts double-spend | Input UTXO already spent. |
| `nothing to consolidate` | `walletConsolidate` with ≤ 1 UTXO | Nothing to do; wallet already consolidated. |

### CLI Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Error (message printed to stderr) |

---

## 7. Consensus Constants

These values are consensus-critical. Any change requires a hard fork.

| Constant | Value | Description |
|---|---|---|
| `BLOCK_TIME` | 60 s | Target inter-block interval. |
| `HALFLIFE` | 360 s (6 blocks) | ASERT difficulty halflife. |
| `FINALITY_DEPTH` | 18 blocks | Reorgs deeper than this are rejected. |
| `ANCHOR_DEPTH` | 144 blocks | Maximum TX epoch anchor age (~144 min). |
| `BLOCK_MAX_TXS` | 1024 | Maximum non-coinbase TXs per block. |
| `MAX_INPUTS` | 4 | Maximum inputs per transaction. |
| `MAX_OUTPUTS` | 8 | Maximum outputs per transaction. |
| `BASE_REWARD` | 50 NOID | Block reward at genesis occupancy. |
| `FLOOR_REWARD` | 1 NOID | Minimum block reward (never halves below this). |
| `MIN_FEE_BASE` | 5 000 μNOID (0.005 NOID) | Minimum relay fee per transaction. |
| `FEE_PER_OUTPUT` | 2 000 μNOID (0.002 NOID) | Extra fee per output slot. |
| `LOG_SLOTS_GENESIS` | 24 (16 M slots) | Initial slot space depth. |
| `LOG_SLOTS_MAX` | 32 (4 B slots) | Maximum slot space depth. |
| `EXPAND_TRIGGER` | 75% occupancy | Slot space doubles when > 75% used (median over 18 blocks). |
| `1 NOID` | 1 000 000 μNOID | Base denomination. |

**Fee formula:**
```
min_fee = MIN_FEE_BASE + n_outputs × FEE_PER_OUTPUT
        = 5000 + n_outputs × 2000 μNOID

Example (2 outputs): 5000 + 2×2000 = 9000 μNOID = 0.009 NOID
```

**Block reward schedule:**
```
block_reward = BASE_REWARD × (1 - occupancy_fraction)
             = 50 NOID × (1 - active_slots / capacity)
             ≥ FLOOR_REWARD = 1 NOID

At genesis (0 UTXOs): 50 NOID
At 50% full:          25 NOID
At 90% full:           5 NOID
At 100% full:          1 NOID (floor)
```

---

*For the full cryptographic specification, see [SPECIFICATION.md](SPECIFICATION.md).*  
*For architecture details, see [ARCHITECTURE.md](ARCHITECTURE.md).*
