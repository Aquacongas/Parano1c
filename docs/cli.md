# Paranoid: CLI & JSON-RPC Reference

## 1. Node Daemon (`paranoid`)

### 1.1 Synopsis

```
paranoid [OPTIONS]
```

The daemon opens MDBX storage, starts P2P networking, JSON-RPC, and optionally the built-in miner.

### 1.2 Options

| Flag | Default | Description |
|------|---------|-------------|
| `--mode <MODE>` | `relay` | Operating mode: `relay`, `miner`, or `extminer` |
| `--data-dir <PATH>` | `~/.paranoid/data` | MDBX database and wallet key storage |
| `--p2p-listen <HOST:PORT>` | `0.0.0.0:9400` | P2P listen address |
| `--rpc-listen <HOST:PORT>` | `127.0.0.1:9401` | JSON-RPC listen address |
| `--seed <HOST:PORT>` | — | Bootstrap peer (repeatable) |
| `--miner-address <HEX>` | wallet addr | Coinbase recipient (32-byte hex) |
| `--mining-threads <N>` | balanced | Internal PoW threads for `--mode miner`; if omitted, uses roughly half of available cores and leaves the rest for node/prover work |
| `--mining-key <TOKEN>` | — | Bearer token for external mining API |
| `--allow-custom-coinbase` | off | Let external miners set their own coinbase (requires `--mining-key`) |
| `--genesis` | off | Bootstrap a fresh network (first node only) |
| `--purge-state` | off | Clear volatile state and re-sync from peers |
| `--log <LEVEL>` | `info` | Log filter: `debug`, `info`, `warn`, `error` |
| `-c <FILE>` | — | Path to TOML config file |

### 1.3 Operating Modes

**relay** — Full verification node. Validates all blocks (ZK + PoW), serves state and recursive proofs. No internal mining; all CPU remains available to node work.

**miner** — Internal PoW + ZK proving. Blocks external miner access. Produces blocks autonomously. `--mining-threads` controls only internal PoW threads; all remaining cores are left for node/prover work automatically.

**extminer** — Serves `getBlockTemplate`/`submitBlock` to external `noid-extminer` workers. Requires `--mining-key`. Internal PoW is disabled, so node CPU remains available for template/proof/RPC/P2P work.

### 1.4 Seed Formats

```
--seed 1.2.3.4:9400                       # HOST:PORT (IP)
--seed noid.example.com:9400              # HOST:PORT (DNS)
--seed /ip4/1.2.3.4/tcp/9400             # libp2p multiaddr
--seed dnsaddr:noid.network              # _dnsaddr DNS TXT lookup
```

### 1.5 Examples

```bash
# Solo miner (balanced internal PoW/prover CPU split)
paranoid --mode miner --data-dir ~/.paranoid

# Solo miner with explicit internal PoW threads; remaining cores stay with the node/prover
paranoid --mode miner --mining-threads 6 --data-dir ~/.paranoid

# Public relay node
paranoid --mode relay --p2p-listen 0.0.0.0:9400 --seed 1.2.3.4:9400

# Pool operator (external miners connect via RPC)
paranoid --mode extminer --rpc-listen 0.0.0.0:9401 --mining-key s3cr3t

# Pool operator allowing custom coinbase (miners get paid directly)
paranoid --mode extminer --rpc-listen 0.0.0.0:9401 \
         --mining-key s3cr3t --allow-custom-coinbase
```

---

## 2. CLI Client (`noid-cli`)

### 2.1 Synopsis

```
noid-cli [--rpc <URL>] [--json] <COMMAND> [ARGS...]
```

Thin terminal client. Connects to a running daemon via JSON-RPC. No local keys, no crypto.

### 2.2 Global Options

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `-r, --rpc <URL>` | `NOID_RPC` | `http://127.0.0.1:9401` | Daemon RPC endpoint |
| `-j, --json` | — | off | Output raw JSON (for scripting / piping to `jq`) |

### 2.3 Amount Format

All amounts are in **NOID** (human units). The CLI converts internally.

```
1 NOID = 1,000,000 μNOID

Examples:
  10.5       →  10,500,000 μNOID
  0.5        →     500,000 μNOID
  0.000001   →           1 μNOID (minimum)
```

---

## 3. Chain Commands

### `status`

Node health at a glance: height, tip hash, difficulty, UTXO count, mempool.

```
$ noid-cli status
Paranoid node status
  Height             30
  Best hash          6e7a8027180707317e2ba8fdc63af0d7828d3f7596ff4c6c30932c178d39a4c1
  Difficulty         160 leading zeros (0x0000000000000000)
  Active UTXOs       29 (0% of 16777216 slots, log=24)
  Mempool            0 pending tx(s)
```

RPC method: `paranoid_getChainInfo`

---

### `block-hash <HEIGHT>` (alias: `bh`)

Block hash at a given height.

```
$ noid-cli block-hash 5
Block #5 hash
  Hash               a41c9f0b237e...4d8f1e
```

RPC method: `paranoid_getBlockHash`

---

### `block-header <HEIGHT>` (alias: `bhead`)

Decoded block header with all fields.

```
$ noid-cli block-header 10
Block header #10
  hash               a41c9f0b237e...
  prev_hash          8b2d4e1f6c9a...
  height             10
  timestamp          1749648000
  miner              noid1qg7nxj...
  state_root         f3a4b1c2d5e6...
  tx_root            0000000000000000000000000000000000000000000000000000000000000000
  difficulty_target  0000000000000000ffffffffffffffffffffffffffffffffffffffffffffffff
  active_slot_count  10
  log_slots          24
  alloc_counter      10
```

RPC method: `paranoid_getBlockHeader`

Response fields:

| Field | Type | Description |
|-------|------|-------------|
| `height` | u64 | Block height |
| `hash` | hex(32) | H_BLOCK of this header |
| `prev_hash` | hex(32) | Parent block hash |
| `state_root` | hex(32) | Poseidon2b Merkle root of UTXO state |
| `tx_root` | hex(32) | Transaction Merkle root |
| `timestamp` | u64 | Unix seconds |
| `miner` | bech32m | Coinbase recipient |
| `difficulty_target` | hex(32) | PoW target (LE 256-bit) |
| `proof_transcript_hash` | hex(32) | ZK BlockProof Fiat-Shamir digest |
| `log_slots` | u32 | log2(UTXO slot capacity) |
| `active_slot_count` | u64 | Live UTXOs after this block |
| `alloc_counter` | u64 | Monotonic PRNG seed for slot allocation |

---

### `block <HEIGHT>` (alias: `blk`)

Full raw block at a given height. Only the last 18 blocks are retained; older blocks are pruned.

```
$ noid-cli block 15
Block #15
  Hex length         14892 bytes (29784 hex chars)
  Header (first 276B)  a41c9f0b237e6d1f8a9b4c2e3d5f7a01... (raw hex)

  Tip: Use --json to get the full raw hex.
```

RPC method: `paranoid_getBlock`

---

### `header <HEIGHT>`

Raw 276-byte block header as hex.

```
$ noid-cli header 10
Block header #10
  Size               276 bytes (276)

  a41c9f0b237e6d1f8a9b4c2e3d5f7a0182b3c4d5e6f7081920a1b2c3d4e5f607...
```

RPC method: `paranoid_getHeaderByHeight`

---

### `proof` (alias: `rec`)

Recursive chain proof: the entire chain history compressed into ~6.5 KB.

```
$ noid-cli proof
Recursive chain proof  (O(1) sync)
  Size               6432 bytes (6.3 KB) (full chain history in one tiny proof)
  Fingerprint        a1b2c3d4…e5f6g7h8

  Note: Any node can verify the ENTIRE chain history in ~5 ms using this proof.
```

RPC method: `paranoid_getRecursiveProof`

---

### `slot <INDEX>`

UTXO slot contents by index.

```
$ noid-cli slot 42
Slot #42
  Status             live UTXO
  Value              50.000000 NOID (50000000 μNOID)
  Owner              f784b2c1d3e5a6f7...
```

RPC method: `paranoid_getSlot`

Response fields:

| Field | Type | Description |
|-------|------|-------------|
| `slot_index` | u32 | Slot position |
| `value` | u64 | Value in μNOID |
| `owner` | bech32m | Owner address (empty if slot is empty) |
| `empty` | bool | Whether the slot is unoccupied |

---

### `utxos-of <ADDRESS>`

All live UTXOs owned by an address.

```
$ noid-cli utxos-of noid1qg7nxj...
UTXOs of noid1qg7nxj...
  ──────────────────────────────────────────────────
  slot            NOID
  ──────────────────────────────────────────────────
  14           50.000000
  3891          5.500000
  ──────────────────────────────────────────────────
  TOTAL        55.500000  (2 UTXOs)
```

RPC method: `paranoid_getSlotsByOwner`

---

### `tx <TX_HASH>`

Confirmed transaction by body hash.

```
$ noid-cli tx a1b2c3...
Transaction
  tx_hash            a1b2c3d4e5f6...
  height             25
  block_hash         6e7a802718...
  position           0
```

RPC method: `paranoid_getTx`

Response fields:

| Field | Type | Description |
|-------|------|-------------|
| `tx_hash` | hex(32) | Transaction body hash |
| `height` | u64 | Confirming block height |
| `block_hash` | hex(32) | Confirming block H_BLOCK |
| `tx_position` | u32 | Zero-based index within block |

---

### `is-nullifier <TX_HASH>`

Check if a transaction hash is in the nullifier set (spent).

```
$ noid-cli is-nullifier a1b2c3...
Nullifier check
  tx_hash            a1b2c3d4e5f6...
  status             spent (in nullifier set)
```

RPC method: `paranoid_isNullifier`

---

### `state`

UTXO state dimensions: capacity, fill %, memory footprint, expansion headroom.

```
$ noid-cli state
UTXO state
  Slot space         2^24 = 16777216 slots (max 2^32)
  Active UTXOs       29 (0.00% full)
  Fill               [░░░░░░░░░░░░░░░░░░░░░░|░░░░░░░░] 0.00%  (| = expand at 75%)
  Until expand       12582883 slots (75.00% headroom)
  State size         48.0 MB RAM  /  48.0 MB disk  /  768.0 MiB current capacity (192 GiB at 2^32)
```

RPC method: `paranoid_getStateInfo`

Response fields:

| Field | Type | Description |
|-------|------|-------------|
| `log_slots` | u32 | log2 of slot capacity |
| `capacity` | u64 | Total slot space (2^log_slots) |
| `active_slots` | u64 | Live UTXO count |
| `fill_pct` | f64 | Fill percentage |
| `slots_until_expand` | i64 | Slots remaining before 75% expansion trigger |
| `expand_trigger_pct` | u8 | Always 75 |
| `log_slots_max` | u32 | Maximum log_slots (32) |
| `state_bytes` | u64 | On-disk size in bytes |
| `state_size_human` | string | Human-readable size |

---

### `mining`

Mining and network status.

```
$ noid-cli mining
Mining info
  Height             30
  Difficulty         160 leading zeros target: 0000000000000000ffff...
  Block reward       50.000000 NOID/block (50000000 μNOID)
  Active UTXOs       29
  Recursive proof    height 12
```

RPC method: `paranoid_getMiningInfo`

Response fields:

| Field | Type | Description |
|-------|------|-------------|
| `height` | u64 | Current tip height |
| `difficulty_bits` | u32 | Leading zero bits in target |
| `difficulty_target` | hex(32) | PoW target (LE 256-bit) |
| `block_reward_micronoid` | u64 | Reward in μNOID |
| `block_reward_noid` | f64 | Reward in NOID |
| `active_slot_count` | u64 | Live UTXOs (determines reward) |
| `recursive_proof_height` | u64? | Latest recursive proof height (null if not ready) |

---

### `peers`

Connected P2P peer count.

```
$ noid-cli peers
Connected peers
  Count              4
```

RPC method: `paranoid_getPeerCount`

---

### `estimate-fee [N_OUTPUTS]`

Estimated minimum fee for N outputs (default: 2), assuming one input and current occupancy pressure.

```
$ noid-cli estimate-fee 3
Fee estimate (3 outputs)
  Min fee            0.011500 NOID (11500 μNOID)

  Formula: base(5000) + io_fee(500) × (inputs + outputs)
           + state_growth_fee(2500 × pressure) × max(0, outputs - inputs)
  estimate-fee assumes inputs = 1; pressure starts at 1× and rises with occupancy.
```

RPC method: `paranoid_estimateFee`

Fee formula charges base + I/O + occupancy-scaled net-new-state growth. The state-growth component is burned; miners can claim only the remainder plus any tip.

---

### `validate <ADDRESS>`

Validate and normalize an address.

```
$ noid-cli validate f784b2c1d3e5a6f708192a3b4c5d6e7f8091a2b3c4d5e6f7081920a1b2c3d4e5
✓ Valid address
  bech32m            noid1q7uyje...
  hex                f784b2c1d3e5a6f708192a3b4c5d6e7f8091a2b3c4d5e6f7081920a1b2c3d4e5
```

RPC method: `paranoid_validateAddress`

---

### `epoch` (alias: `anchor`)

Current epoch anchor hash (needed by wallets to build transactions).

```
$ noid-cli epoch
Epoch anchor
  Hash               6e7a8027180707317e2ba8fdc63af0d7828d3f7596ff4c6c30932c178d39a4c1

  Note: Wallets use this hash as epoch_anchor when building transaction proofs.
```

RPC method: `paranoid_getEpochAnchor`

---

### `mempool`

Pending transactions summary.

```
$ noid-cli mempool
Mempool
  Pending            3 transactions
  Fee floor          0.005000 NOID (5000 μNOID minimum)

  ──────────────────────────────────────────────────────────────────────────────────────────
  tx hash               fee (μNOID)   in→out  ZK
  ──────────────────────────────────────────────────────────────────────────────────────────
  a1b2c3d4e5f6g7h8...        9000    2→ 2   ✓
  b2c3d4e5f6g7h8i9...        7000    1→ 1   ✓
  c3d4e5f6g7h8i9j0...        9000    3→ 2   ·
```

RPC method: `paranoid_getMempoolInfo`

Response fields:

| Field | Type | Description |
|-------|------|-------------|
| `size` | usize | Pending transaction count |
| `fee_floor` | u64 | Current dynamic fee floor (μNOID) |
| `txs` | array | List of `MempoolTxInfo` objects |

Each `MempoolTxInfo`:

| Field | Type | Description |
|-------|------|-------------|
| `tx_hash` | hex(32) | Transaction body hash |
| `fee_micronoid` | u64 | Fee in μNOID |
| `fee_rate` | u64 | fee / weighted resource units (`inputs + outputs + 4 × net_new_slots`) |
| `n_inputs` | usize | Active input count |
| `n_outputs` | usize | Active output count |
| `admitted_height` | u64 | Chain height when admitted |
| `has_proof` | bool | Whether ZK proof is cached |

---

### `mempool-tx <TX_HASH>`

Single pending transaction details.

```
$ noid-cli mempool-tx a1b2c3...
Mempool transaction
  tx_hash            a1b2c3d4e5f6...
  Fee                0.009000 NOID (9000 μNOID)
  Inputs             2
  Outputs            2
  Admitted at height 28
  ZK proof           attached
```

RPC method: `paranoid_getMempoolEntry`

---

## 4. Wallet Commands

### `address` (alias: `addr`)

Show and manage wallet addresses.

```bash
noid-cli address             # primary address (index 0)
noid-cli address --new       # derive next fresh receiving address
noid-cli address --list      # all addresses with balances
noid-cli address --index 3   # address at key index 3
```

```
$ noid-cli address --list
Wallet addresses
    index              NOID   UTXOs  address
  ────────────────────────────────────────────────────────────────────────────
  ●     0        50.000000       1  f784b2c1d3e5...
  ○     1         0.000000       0  a2b3c4d5e6f7...
  ────────────────────────────────────────────────────────────────────────────
  Total: 50.000000 NOID  (1 UTXOs across 2 addresses)

  Tip: use 'noid-cli address --new' to generate a fresh receiving address.
```

```
$ noid-cli address --new
New receiving address [index=2]
  noid1qg7nxj0zwhqj9tm5sf...

  ↑ Share this address to receive NOID. Each payment should use a fresh address.
```

RPC methods: `paranoid_walletGetAddress`, `paranoid_walletNextAddress`, `paranoid_walletListAddresses`

---

### `balance` (alias: `bal`)

Confirmed wallet balance.

```
$ noid-cli balance
Wallet balance
  Balance: 155.500000 NOID (155500000 μNOID)  (3 UTXOs)
```

With pending outbound:

```
$ noid-cli balance
Wallet balance
  Balance: 155.500000 NOID (155500000 μNOID)  (3 UTXOs)
  Pending:  -10.509000 NOID outbound (10509000 μNOID locked)
  Spendable: 144.991000 NOID
```

RPC method: `paranoid_walletGetBalance`

Response fields:

| Field | Type | Description |
|-------|------|-------------|
| `total_micronoid` | u64 | Confirmed balance in μNOID |
| `total_noid` | f64 | Confirmed balance in NOID |
| `utxo_count` | usize | Number of confirmed UTXOs |
| `pending_outbound_micronoid` | u64 | Locked by pending sends |
| `spendable_micronoid` | u64 | total - pending_outbound |
| `spendable_noid` | f64 | Spendable in NOID |

---

### `utxos` (alias: `ls`)

All confirmed wallet UTXOs.

```
$ noid-cli utxos
Wallet UTXOs
  ────────────────────────────────────────────────────────────────────────────
  slot          NOID      key   at block  address
  ────────────────────────────────────────────────────────────────────────────
  14           50.000000       0        5  f784b2c1d3e5...
  3891          5.500000       0       18  f784b2c1d3e5...
  8204        100.000000       1       22  a2b3c4d5e6f7...
  ────────────────────────────────────────────────────────────────────────────
  TOTAL       155.500000
```

RPC method: `paranoid_walletListUtxos`

Response (array of):

| Field | Type | Description |
|-------|------|-------------|
| `slot_index` | u32 | Slot position in UTXO state |
| `value_micronoid` | u64 | Value in μNOID |
| `value_noid` | f64 | Value in NOID |
| `address` | bech32m | Owner address |
| `key_index` | u32 | HD derivation index |
| `confirmed_height` | u64 | Block height when confirmed |

---

### `send <ADDRESS> <AMOUNT> [--fee <FEE>]`

Send NOID to a recipient.

```bash
noid-cli send f784b2c1...64charhex 10.5          # auto fee
noid-cli send noid1qg7nxj... 10.5 --fee 0.01    # explicit fee
```

```
$ noid-cli send f784b2c1d3e5a6f708192a3b4c5d6e7f8091a2b3c4d5e6f7081920a1b2c3d4e5 10.5
Transaction submitted
✓ TX a1b2c3d4e5f6...

  To                 f784b2c1d3e5a6f708192a3b4c5d6e7f8091a2b3c4d5e6f7081920a1b2c3d4e5
  Amount             10.500000 NOID (10500000 μNOID)
  Fee                0.009000 NOID (9000 μNOID)(auto)
  TX hash            a1b2c3d4e5f6...

  ⏳ The transaction is pending. It will confirm in the next block (~60s).
  Tip: Use 'noid-cli balance' to check your balance after confirmation.
```

Amounts > 1000 NOID prompt interactive confirmation. Address accepts bech32m (`noid1...`) or 64-char hex.

RPC method: `paranoid_walletSend`

Parameters:

| Param | Type | Description |
|-------|------|-------------|
| `to_hex` | string | Recipient address (bech32m or hex) |
| `amount_micronoid` | u64 | Amount in μNOID |
| `fee_micronoid` | u64 | Fee in μNOID (0 = auto minimum) |

---

### `history` (alias: `hist`, `txs`)

Transaction history.

```bash
noid-cli history                        # all entries
noid-cli history --last 5               # last 5 entries
noid-cli history --address noid1qg7...  # filter by address
```

```
$ noid-cli history --last 3
Transaction history
  ────────────────────────────────────────────────────────────────────────────────────────────
     block  dir            NOID  own[idx]          counterparty
  ────────────────────────────────────────────────────────────────────────────────────────────
         5  ← recv    50.000000+ [0]f784b2c1d3  0000000000000000...
        18  → sent   -10.500000- [0]f784b2c1d3  a2b3c4d5e6f70819...
        22  ← recv   100.000000+ [1]a2b3c4d5e6  0000000000000000...
  ────────────────────────────────────────────────────────────────────────────────────────────
           + 150.000000 NOID received  - 10.500000 NOID sent
```

RPC method: `paranoid_walletHistory`

Response (array of):

| Field | Type | Description |
|-------|------|-------------|
| `tx_hash` | hex(32) | Transaction body hash |
| `height` | u64 | Confirming block height |
| `direction` | string | `"sent"` or `"received"` |
| `amount_micronoid` | u64 | Amount in μNOID |
| `amount_noid` | f64 | Amount in NOID |
| `peer_address` | string? | Counterparty address |
| `timestamp` | u64 | Unix seconds |
| `own_address` | string? | Our involved address |
| `own_key_index` | u32? | Key index of own address |

---

### `scan`

Rescan chain state to (re)discover owned UTXOs. Run after wallet import or if balance seems wrong.

```
$ noid-cli scan
  Scanning chain state for your UTXOs... done.
Wallet scan complete
  Scanned 5 addresses  •  Found 3 UTXO(s)  •  Balance: 155.500000 NOID
  Next available address: index 5 (use 'address --new' to generate)
```

RPC method: `paranoid_walletScan`

---

### `consolidate [--fee <FEE>] [--rounds <N>]`  (alias: `merge`)

Merge small UTXOs into fewer larger ones. Reduces future transaction fees.

```bash
noid-cli consolidate                 # auto fee, up to 100 rounds
noid-cli consolidate --fee 0.01     # explicit fee per round
noid-cli consolidate --rounds 5     # max 5 consolidation txs
```

```
$ noid-cli consolidate
Wallet consolidate
  Merging small UTXOs to reduce UTXO count and lower future fees.
  Fee: auto (minimum per round)

✓ Round 1: TX a1b2c3d4...
  Waiting for confirmation....... confirmed.
  UTXOs remaining: 2  Balance: 155.493000 NOID
✓ Round 2: TX b2c3d4e5...
  Waiting for confirmation....... confirmed.
  UTXOs remaining: 1  Balance: 155.486000 NOID
✓ Consolidation complete — wallet has 1 UTXO.

  Total: 2 round(s) completed. TXs may still be pending.
  Next: Run 'noid-cli balance' after confirmation.
```

RPC method: `paranoid_walletConsolidate`

---

### `receipt <TX_HASH>`

Export a Merkle payment receipt for a confirmed transaction. Pipe to file for storage.

```bash
noid-cli receipt a1b2c3... > receipt.hex
```

RPC method: `paranoid_walletExportReceipt`

---

### `verify <RECEIPT_HEX>` (alias: `check`)

Verify a Merkle payment receipt against the canonical chain.

```
$ noid-cli verify $(cat receipt.hex)
Receipt verification
✓ Receipt is VALID and canonical.
  Merkle proof       ✓ valid
  On canonical chain ✓ yes
```

RPC method: `paranoid_verifyReceipt`

Response fields:

| Field | Type | Description |
|-------|------|-------------|
| `merkle_valid` | bool | Merkle inclusion proof correct |
| `canonical` | bool | Block is on the canonical chain |
| `confirmed` | bool | Both valid and canonical |
| `error` | string? | Error description if invalid |

---

## 5. Mining Commands (External Miner API)

### `block-template [--miner-addr <HEX>]` (alias: `template`)

Get a PoW block template. The node performs ZK proving; the external miner only patches the nonce.

```
$ noid-cli block-template
Block template
  Height             31
  Txs in block       2
  Header core        a41c9f0b237e6d1f8a9b4c2e...… (212 bytes, PoW input)

  PoW: Compute Blake3(header_core || nonce) < difficulty_target, then submit.
  Full hex: a41c9f0b237e6d1f8a9b4c2e3d5f7a0182b3c4d5e6f7...
```

RPC method: `paranoid_getBlockTemplate`

Response fields:

| Field | Type | Description |
|-------|------|-------------|
| `header_core_hex` | hex | 212-byte PoW input buffer |
| `block_hex` | hex | Full sealed block (nonce=0); patch bytes [144..160] with found nonce |
| `block_proof_hex` | hex | Serialized BlockProof; empty for coinbase-only blocks |
| `nonce_offset` | usize | Byte offset of nonce in `block_hex` (always 144) |
| `difficulty_target_hex` | hex(32) | Target (LE); find N where `Blake3(patched_header_core) < target` |
| `height` | u64 | Block height being mined |
| `n_txs` | usize | Transaction count in template |

**PoW algorithm:**
1. Call `getBlockTemplate` to receive `header_core_hex` (212 bytes) and `difficulty_target_hex`
2. For each nonce attempt N (u128, LE):
   - Patch bytes [144..160] of `header_core_hex` with N
   - Compute `hash = Blake3(patched_212_bytes)`
   - If `hash < difficulty_target`: found a valid block
3. Patch bytes [144..160] of `block_hex` with the winning nonce
4. Submit via `submitBlock(block_hex, block_proof_hex)`

---

### `submit-block <BLOCK_HEX> <BLOCK_PROOF_HEX>` (alias: `submit`)

Submit a solved block plus its serialized BlockProof. Use `""` as `BLOCK_PROOF_HEX` for coinbase-only blocks.

```
$ noid-cli submit-block a41c9f0b237e... 9f1c02...
✓ Block accepted: 6e7a8027180707317e2ba8fdc63af0d7...
```

RPC method: `paranoid_submitBlock`

---

## 6. Node Control

### `stop`

Gracefully stop the daemon.

```
$ noid-cli stop
✓ Daemon is shutting down.
```

RPC method: `paranoid_stop`

---

## 7. JSON-RPC Protocol

### 7.1 Transport

- Protocol: JSON-RPC 2.0 over HTTP POST
- Default endpoint: `http://127.0.0.1:9401`
- Content-Type: `application/json`
- Namespace: `paranoid_` (all methods prefixed)

### 7.2 Authentication

When `--mining-key` is set, all requests require `Authorization: Bearer <TOKEN>` header.
Without `--mining-key`, RPC is bound to `127.0.0.1` (localhost only).

### 7.3 Request Format

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "paranoid_getChainInfo",
  "params": []
}
```

### 7.4 Response Format

Success:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "height": 30,
    "best_hash": "6e7a8027180707317e2ba8fdc63af0d7828d3f7596ff4c6c30932c178d39a4c1",
    "difficulty_target": "0000000000000000ffffffffffffffffffffffffffffffffffffffffffffffff",
    "active_slot_count": 29,
    "log_slots": 24
  }
}
```

Error:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32000,
    "message": "invalid txhash: expected 64-char hex"
  }
}
```

### 7.5 Complete Method Index

#### Chain

| Method | Params | Returns | Description |
|--------|--------|---------|-------------|
| `paranoid_blockCount` | — | `u64` | Tip height |
| `paranoid_getChainInfo` | — | `ChainInfo` | Height, hash, difficulty, slots |
| `paranoid_getBlockHash` | `height: u64` | `string?` | Block hash at height |
| `paranoid_getBlockHeader` | `height: u64` | `BlockHeaderInfo?` | Decoded header |
| `paranoid_getHeaderByHeight` | `height: u64` | `string?` | Raw 276-byte header hex |
| `paranoid_getHeaderByHash` | `hash: string` | `string?` | Raw header by hash |
| `paranoid_getBlock` | `height: u64` | `string?` | Full block hex (last 18 only) |
| `paranoid_getRecursiveProof` | — | `string?` | ~6.5 KB recursive proof hex |
| `paranoid_getSlot` | `slot_index: u32` | `SlotInfo` | Single UTXO slot |
| `paranoid_getSlotsByOwner` | `address: string` | `SlotInfo[]` | All UTXOs of an address |
| `paranoid_getActiveSlotCount` | — | `u64` | Live UTXO count |
| `paranoid_getStateInfo` | — | `StateInfo` | State dimensions and fill metrics |
| `paranoid_getTx` | `txhash: string` | `TxInfo?` | Confirmed tx by hash |
| `paranoid_isNullifier` | `txhash: string` | `bool` | Whether tx is spent |

#### Network & Mining

| Method | Params | Returns | Description |
|--------|--------|---------|-------------|
| `paranoid_getMiningInfo` | — | `MiningInfo` | Difficulty, reward, recursive height |
| `paranoid_getPeerCount` | — | `usize` | Connected peers |
| `paranoid_estimateFee` | `n_outputs: u32` | `u64` | Estimated min fee in μNOID |

#### Utilities

| Method | Params | Returns | Description |
|--------|--------|---------|-------------|
| `paranoid_validateAddress` | `address: string` | `AddressInfo` | Validate and normalize |
| `paranoid_getSlotHints` | `count: u32` | `u32[]` | Empty slot candidates for tx building |
| `paranoid_getEpochAnchor` | — | `string` | Current epoch anchor hash |
| `paranoid_submitTxIntent` | `hex: string` | `string` | Submit raw TxIntent to mempool |

#### Mempool

| Method | Params | Returns | Description |
|--------|--------|---------|-------------|
| `paranoid_getMempoolInfo` | — | `MempoolInfo` | Full mempool state with tx list |
| `paranoid_getMempoolSize` | — | `usize` | Pending tx count (lightweight) |
| `paranoid_getMempoolEntry` | `txhash: string` | `MempoolTxInfo?` | Single pending tx |

#### Receipt

| Method | Params | Returns | Description |
|--------|--------|---------|-------------|
| `paranoid_verifyReceipt` | `receipt_hex: string` | `ReceiptVerifyResult` | Verify Merkle receipt |

#### External Mining

| Method | Params | Returns | Description |
|--------|--------|---------|-------------|
| `paranoid_getBlockTemplate` | `miner_address: string` | `BlockTemplateResponse` | PoW template (ZK pre-proved) |
| `paranoid_submitBlock` | `block_hex: string, block_proof_hex: string` | `string` | Submit solved block, returns hash |

#### Node Control

| Method | Params | Returns | Description |
|--------|--------|---------|-------------|
| `paranoid_stop` | — | `string` | Graceful shutdown |

#### Wallet

| Method | Params | Returns | Description |
|--------|--------|---------|-------------|
| `paranoid_walletStatus` | — | `WalletStatus` | Address, balance, UTXO count |
| `paranoid_walletGetAddress` | `index: u32` | `string` | Address at derivation index |
| `paranoid_walletNextAddress` | — | `WalletAddressInfo` | Derive next fresh address |
| `paranoid_walletListAddresses` | — | `WalletAddressInfo[]` | All addresses with balances |
| `paranoid_walletGetBalance` | — | `WalletBalance` | Balance breakdown |
| `paranoid_walletListUtxos` | — | `WalletUtxoInfo[]` | All confirmed UTXOs |
| `paranoid_walletHistory` | — | `WalletHistoryEntry[]` | Transaction history |
| `paranoid_walletScan` | — | `WalletScanResult` | Full state rescan |
| `paranoid_walletSend` | `to: string, amount: u64, fee: u64` | `WalletSendResult` | Send NOID |
| `paranoid_walletConsolidate` | `fee: u64` | `WalletSendResult` | Merge UTXOs |
| `paranoid_walletExportReceipt` | `txhash: string` | `string` | Export receipt hex |

---

## 8. Configuration File

Optional TOML file (`-c config.toml`):

```toml
[network]
listen = "0.0.0.0:9400"
seeds = ["1.2.3.4:9400", "dnsaddr:noid.network"]
max_peers = 50

[storage]
backend = "mdbx"
path = "/data/paranoid"

[rpc]
listen = "127.0.0.1:9401"

[mining]
enabled = true
threads = 0
miner_address = "f784b2c1d3e5a6f708192a3b4c5d6e7f8091a2b3c4d5e6f7081920a1b2c3d4e5"
```

CLI flags override config file values.

---

## 9. Error Codes

| Code | Meaning |
|------|---------|
| `-32000` | Application error (message field contains details) |
| `-32600` | Invalid JSON-RPC request |
| `-32601` | Method not found |
| `-32602` | Invalid params |
| `-32603` | Internal error |

Common application errors:

| Message pattern | Cause |
|----------------|-------|
| `slot N out of range` | Slot index exceeds 2^log_slots |
| `invalid txhash: expected 64-char hex` | Bad transaction hash format |
| `invalid address` | Address not bech32m or valid hex |
| `InsufficientFunds` | Wallet balance too low for send |
| `no empty slot hints available` | UTXO state nearly full |
| `consensus: ...` | Submitted block fails validation |

---

## 10. Usage Examples (curl)

```bash
# Get chain info
curl -s http://127.0.0.1:9401 -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"paranoid_getChainInfo","params":[]}' | jq .result

# Get balance
curl -s http://127.0.0.1:9401 -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"paranoid_walletGetBalance","params":[]}' | jq .result

# Send NOID (10.5 NOID = 10500000 μNOID, auto fee = 0)
curl -s http://127.0.0.1:9401 -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"paranoid_walletSend","params":["f784b2c1d3e5a6f708192a3b4c5d6e7f8091a2b3c4d5e6f7081920a1b2c3d4e5",10500000,0]}' | jq .result

# Get block template (for external miners)
curl -s http://127.0.0.1:9401 -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer s3cr3t" \
  -d '{"jsonrpc":"2.0","id":1,"method":"paranoid_getBlockTemplate","params":[""]}' | jq .result

# Submit solved block
curl -s http://127.0.0.1:9401 -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"paranoid_submitBlock","params":["<block_hex>","<block_proof_hex>"]}' | jq .result

# Check if tx is spent (nullifier)
curl -s http://127.0.0.1:9401 -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"paranoid_isNullifier","params":["a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7081920a1b2c3d4"]}' | jq .result

# Validate address
curl -s http://127.0.0.1:9401 -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"paranoid_validateAddress","params":["noid1qg7nxj0zwhqj..."]}' | jq .result
```

---

*Source: `noid_node/src/bin/noid_cli.rs`, `noid_rpc/src/api.rs`, `noid_rpc/src/types.rs`, `noid_rpc/src/server.rs`.*
