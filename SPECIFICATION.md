# Paranoid Protocol Specification

This document is the **normative specification** of the Paranoid
chain — a slot-based transparent UTXO ledger with proof-native state
transitions. It describes the objects the protocol manipulates, the
rules under which those objects evolve, and the consensus-visible
algorithms that every conforming node MUST implement identically.

Companion documents:

- `ARCHITECTURE.md` — non-normative description of how the engine is
  implemented (crate map, proof-layer overview).
- `DESIGN_NOTES.md` — non-normative design rationale, philosophy, and
  open questions that are not yet part of the protocol.
- `noid_gkr/SPEC.md`, `noid_gkr/AUDIT.md` — GKR sub-protocol details.
- `ROADMAP2.md` — delivery status.

Keyword conventions (RFC 2119): **MUST**, **MUST NOT**, **SHALL**,
**SHOULD**, and **MAY** carry their usual normative meaning.

---

## 0. State model

### 0.1 Slot space

The ledger defines a fixed addressable slot space parameterised by an
integer `log_slots`. Each valid slot index is an unsigned integer in
the range:

```
  0 .. 2^log_slots − 1
```

The parameter `log_slots` is a **consensus-significant header field**
(see §0.4 and §15.3). Its initial value at genesis is:

```
  log_slots = 24             (2^24 slots ≈ 16 777 216)
```

It is monotonically non-decreasing, bounded above by:

```
  MAX_LOG_SLOTS = 32
```

### 0.2 Slot contents

Each slot stores a triple over GF(2^128)-packed field elements:

```
  slot[i] = (value, owner_hi, owner_lo)
```

where:

- `value` is the UTXO balance (64-bit semantic, canonically embedded
  in a `Block128` field element);
- `owner_hi`, `owner_lo` are the two 128-bit lanes of the transparent
  owner address.

A slot is **empty** iff it equals the canonical zero triple:

```
  EMPTY = (0, 0, 0)
```

Otherwise the slot is **live**.

### 0.3 Zero canonicalisation (load-bearing invariant)

`EMPTY` MUST be the unique valid encoding of an empty slot at every
level of commitment:

1. **Field level.** GF(2^128) has a unique zero element; any
   `Block128` value is compared against zero bit-for-bit.
2. **Leaf level.** `H_LEAF(0, 0, 0)` is a fixed Poseidon2b digest
   under `DomainTag::TAG_LEAF`, identical on every node.
3. **State-commitment level.** An empty sub-tree MUST be committed via
   the pre-computed constant `ZERO_SUBTREE_ROOT[k]` (one per depth
   `k`), never via a recomputed path.

Rationale: the invariant `is_mint ⇒ pre = 0` enforced by
`tx_validity` (§4) has exactly one canonical meaning for "zero", and
no alternative non-zero encoding exists that would open to the same
commitment. Without this canonicalisation the class of
"malformed witness, opening to zero" attacks would be open; with it,
it is closed by construction.

### 0.4 Block header fields (consensus-significant)

Every block header MUST carry at minimum the following fields that
participate in consensus:

- `prev_header_hash` — hash of the previous block header;
- `state_root` — Poseidon2b commitment to the full slot vector, taken
  after applying this block's transactions;
- `log_slots` — the slot-space parameter in effect for this block;
- `active_slot_count` — the number of live slots after this block
  (§15.3);
- `alloc_counter` — the monotonic PRNG seed for the allocator (§15.1);
- `block_proof_root` — commitment to the aggregated recursive proof
  for this block;
- `nonce` — 128-bit (16 bytes) PoW nonce (§18.2);
- `difficulty_target` — 256-bit target threshold for Blake3 PoW
  (§18.3);
- `height` — block height (used for epoch anchor and difficulty
  calculations).

`log_slots` is protocol versioning: AIR arithmetisation (state
commitment size, slot-index bit-decomposition in `BlockStateBindingAir`,
MLE eq-table size) is parameterised by `log_slots`. Every AIR builder
MUST read `log_slots` from the header of the block being verified.
There is no "off-header" configuration.

### 0.5 Global commitment

The global state commitment is the single Poseidon2b digest:

```
  state_root
```

computed as the root of a Poseidon2b Merkle tree over segment FRI
roots (§19). The state is divided into `2^(log_slots - 16)` segments
of `2^16` slots each. Each segment is independently FRI-committed
(three columns: value, owner_hi, owner_lo), and the segment roots
feed into a shallow Poseidon2b tree under `TAG_SEGMENTTREE`.

---

## 1. Genesis

At genesis:

- All slots are `EMPTY` except for a protocol-defined distribution of
  initial live slots.
- `log_slots = 24`, `active_slot_count` equals the number of
  distributed live slots, `alloc_counter = 0`.
- The resulting `state_root` is the genesis root.

Example:

```
  slot 101 = (100, Alice)
  slot 777 = ( 50,  Bob )
  every other slot = EMPTY
  ⇒ genesis_root
```

The genesis header is part of protocol constants and is identical on
every conforming node.

---

## 2. Wallet and keys

Each user holds a `SpendSecret`. The public `Address` is derived
deterministically:

```
  Address = derive_address(SpendSecret)
```

The address is public; the secret is private and never leaves the
wallet.

`derive_address` is implemented as a Poseidon2b compression of the
secret under `DomainTag::TAG_ADDRESS` (see
`noid_poseidon2b::native::domain`). Ownership is proven by:

- the `haddr` AIR — a Poseidon-permutation over the secret that
  recomputes the address and constrains `addr == owner` of the input
  slot;
- the `hauth` AIR — an authentication tag binding the spend to this
  specific transaction body (see §4).

---

## 3. Transaction construction

A transaction intent `tx_intent` has the form:

```
  tx_intent = (tx_body, logic_proof, claims_commitment, claimed_slots)
```

### 3.1 Selection of inputs

The wallet selects live slots owned by the spender (e.g., `slot 101 =
(100, Alice)`) and marks them as inputs.

### 3.2 Selection of output slots

The wallet obtains slot hints from a node:

```
  wallet → node:  request free slot indices
  node   → wallet: e.g., [200, 500]   (indices only, no Merkle paths)
```

The hint is **non-authoritative** — it matches the native allocator
(§15.1) but the authoritative correctness check is performed by the
miner in BlockStateBinding: the miner opens each output slot and
verifies it is EMPTY before including the transaction.

### 3.3 Outputs

Each output binds a chosen slot index to a `(value, owner)` pair:

```
  slot 200 → ( 90, Alice )       -- change
  slot 500 → ( 10, Bob   )       -- payment
```

### 3.4 Transaction body

`tx_body` contains:

```
  inputs:        list of (slot_index, claimed_value, claimed_owner)
  outputs:       list of (slot_index, value, owner_hi, owner_lo)
  fee:           non-negative amount (may be 0)
  epoch_anchor:  hash of block header at (current_height - ANCHOR_DEPTH)
  is_coinbase:   boolean
```

`tx_body_hash` is the Poseidon2b spine hash of `tx_body` (§A.3 of
`ARCHITECTURE.md`): 59 Poseidon2b permutations (4 input-leaf + 8
output-leaf + 15 compress + 1 wrap) under `DomainTag::TAG_TXBODY`.

### 3.5 Epoch anchor

The `epoch_anchor` replaces the former `prev_state_root` as the
time-binding field in `tx_body_hash`. It is defined as:

```
  epoch_anchor = H_BLOCK(block_header[height - ANCHOR_DEPTH])
```

where `ANCHOR_DEPTH = 6`. This provides:

- **Anti-replay across forks:** Different forks produce different
  headers at height-6, yielding different epoch_anchors and thus
  different tx_body_hashes.
- **Stability:** The epoch_anchor does not change when new blocks
  arrive (it refers to a header that is already 6-deep).
- **Expiry:** Consensus MUST reject transactions whose epoch_anchor
  does not match any header in the window
  `[current_height - ANCHOR_DEPTH, current_height]`.

### 3.6 Claims commitment

The wallet computes a binding commitment to all claimed slot values:

```
  C_claimed = Poseidon2b_sponge(
    for each input:  (slot_index, value, owner_hi, owner_lo)
    for each output: (slot_index, value, owner_hi, owner_lo)
  )
```

`C_claimed` is absorbed into the LogicProof Fiat-Shamir channel,
cryptographically binding the proof to these specific slot claims.
The miner's BlockStateBinding separately opens the same slots and
verifies equality with `C_claimed`.

---

## 4. Proof contents (Two-Layer Architecture)

The system uses a **two-layer proof architecture**:

- **Layer 1 — LogicProof** (wallet-side): proves transaction logic
  without any state dependency.
- **Layer 2 — BlockStateBinding** (miner-side): proves that claimed
  slot values match the actual Merkle-committed state.

### 4.1 LogicProof (wallet builds locally)

The wallet builds **one** cryptographic proof that attests:

#### 4.1.1 Ownership

For every input slot `i`, the prover knows `SpendSecret_i` such that
`derive_address(SpendSecret_i) == claimed_owner_i`. Enforced by
AuthGKR Kill-Shot (HAddr + HAuth sub-circuits).

#### 4.1.2 Balance and range

```
  Σ inputs.claimed_value == Σ outputs.value + fee
  ∀ v ∈ values:  v < 2^64
```

Enforced by `balance_gate` and `range_gate` within `TxLogicAir`.

#### 4.1.3 Transaction-body binding

`tx_body_hash` is computed by the SpineGKR Kill-Shot (59-perm Merkle
spine). Its two lanes are pinned into the AIR via `PublicColumn`.
`hauth` absorbs `tx_body_hash` so that the auth-tag is bound to this
specific body.

#### 4.1.4 Claims binding

`C_claimed` (§3.6) is absorbed into the Fiat-Shamir channel of the
LogicProof. The proof is therefore bound to the specific set of
claimed slot values. Any change to claimed slots forks the transcript
and invalidates the proof.

#### 4.1.5 What LogicProof does NOT prove

LogicProof does NOT prove:
- That claimed input values actually exist in the state tree.
- That claimed output slots are actually empty.
- Any Merkle-path opening against state_root.

These are deferred to BlockStateBinding (§4.2).

A LogicProof is **stateless**: it does not depend on `state_root` and
remains valid across new blocks, as long as the epoch_anchor is within
the ANCHOR_DEPTH window and the claimed slots have not been consumed.

### 4.2 BlockStateBinding (miner builds at block assembly)

The miner builds a block-level proof that attests, for all
transactions in the block:

#### 4.2.1 Pre-state correctness

Under `prev_block_state_root`:

- Every input slot `i` opens to its claimed `(value_i, owner_i)`.
- Every output slot `j` opens to `EMPTY`.

#### 4.2.2 Post-state correctness

Under `new_block_state_root`:

- Every input slot is `EMPTY`.
- Every output slot holds the claimed `(value, owner)` pair.

#### 4.2.3 Root consistency

`new_block_state_root` is computed correctly from the post-state
vector via Poseidon2b Merkle compression.

#### 4.2.4 Bridge to LogicProof

For each transaction `k`, the opened slot values MUST equal the
values committed in `C_claimed_k`. This is verified by the
block verifier checking `C_claimed` equality between the LogicProof
public inputs and the BlockStateBinding opened values.

### 4.3 Combined validity

A transaction is **cryptographically valid** within a block iff:

1. Its LogicProof verifies (balance, range, ownership, body binding).
2. The block's BlockStateBinding verifies (state openings, bridge).
3. `C_claimed` in the LogicProof equals `C_claimed` derived from
   BlockStateBinding openings.

Validity of a transaction within a block is a property of the combined
`(LogicProof, BlockStateBinding, C_claimed_match)` tuple.

---

## 5. Broadcast payload

The network payload (TxIntent) is:

```
  (tx_body, logic_proof, claims_commitment, claimed_slots)
```

The `SpendSecret` MUST NOT appear in the payload and MUST NOT be
recoverable from it. Neither `prev_state_root` nor `new_state_root`
appear in the per-tx broadcast — state binding is performed at block
level by the miner.

---

## 6. Node-side validation (per-tx, mempool admission)

On receiving a TxIntent a node MUST check:

```
  1. logic_proof verifies (STARK + SpineGKR + AuthGKR);
  2. epoch_anchor is within the valid window:
     epoch_anchor ∈ {H_BLOCK(header[h]) : h ∈ [tip - ANCHOR_DEPTH, tip]};
  3. claimed_slots match the node's current state natively:
        • each claimed input slot has the claimed (value, owner);
        • each claimed output slot is EMPTY;
  4. tx_body_hash is not in the nullifier set (§6.1);
  5. no conflicting slot usage versus the mempool-admitted set:
        • no input slot is spent twice,
        • no output slot is minted twice;
  6. fee is acceptable under the node's local policy (non-consensus).
```

Checks (1)–(5) are consensus-significant; check (6) is local policy.
Check (3) is a native pre-filter — the authoritative state proof is
generated by the miner in BlockStateBinding.

### 6.1 Nullifier set

A conforming node MUST maintain a rolling nullifier set containing
all `tx_body_hash` values from the last `ANCHOR_DEPTH` blocks.

A TxIntent is rejected if its `tx_body_hash` already appears in the
nullifier set. This prevents double-inclusion of the same transaction.

After a block exits the `ANCHOR_DEPTH` window, its nullifiers MAY be
pruned (the epoch_anchor will have expired anyway).

---

## 7. Block assembly (Full Node)

NOTE: Throughout this section, "the miner" refers to the block
assembly function of the Full Node. Mining (PoW search) may be
performed by a built-in miner or an external GPU/ASIC connected via
the Block Template API. The protocol has two node types: Light Node
(wallet) and Full Node (everything else). See `ARCHITECTURE.md` §8.

The Full Node aggregates a batch of admitted TxIntents:

```
  intent_1, intent_2, ..., intent_n
```

and MUST enforce:

- no input slot is consumed by more than one transaction in the
  block;
- no output slot is minted by more than one transaction in the block;
- no tx_body_hash appears in the nullifier set;
- conflicts between candidate transactions are resolved by the
  deterministic tie-break rule of §15.2.

The Full Node then:

1. orders the surviving transactions (deterministic order sealed by
   PoW; §15.2 tie-break fixes any remaining ambiguity);
2. generates **BlockStateBinding**: a STARK proving that all claimed
   slot values match the current state tree (Merkle openings against
   `prev_block_state_root`), that output slots are EMPTY, and that
   the post-state `new_block_state_root` is correctly computed;
3. aggregates all LogicProofs + BlockStateBinding into one
   `BlockProof` via deferred-opening (Stage G / Stage S architecture);
4. computes the resulting `state_root_next` and updates
   `active_slot_count`, `alloc_counter`, and (if the §15.3 trigger
   fires) `log_slots`;
5. forms the block header (including `da_root`, `block_proof_hash`,
   `coinbase_address`) and pushes it to the miner (built-in or
   external via Block Template API);
6. seals the block when a valid nonce is returned.

A block is **well-formed** iff every admitted transaction's LogicProof
verifies, no conflicts remain after §15.2, the aggregated `BlockProof`
(including BlockStateBinding) verifies, all C_claimed bridges match,
and the header fields are updated consistently with §8.

### 7.1 Mining pipeline (PoW integration)

The Full Node operates an asynchronous two-process pipeline:

- **Process 1 (Full Node CPU):** Collects TxIntents, generates
  BlockProof (1-3s on 8 cores), forms block header. On completion,
  pushes the 248-byte header to Process 2.
- **Process 2 (miner — built-in or external):** Continuously
  brute-forces nonce against `Blake3(header) < difficulty_target`.
  On valid nonce, returns it to Process 1 for block publication.

External miners connect via the Block Template API (analogous to
Bitcoin's getblocktemplate / Stratum). They receive only the 248-byte
header — no transaction data, no state, no proofs.

On finding a new block (own or received from network):
1. Immediately generate an empty-block template (coinbase only,
   trivial BlockStateBinding). Push to miner. No hash-rate downtime.
2. In background, build full template with transactions (1-3s).
3. When ready, push updated header to miner, replacing the empty
   template.

### 7.2 Block withholding protection

The coinbase address is embedded in the DA Payload, which determines
`da_root`, which is committed in the header, which is proven by the
BlockProof. An external miner receiving only the 248-byte header
CANNOT change the coinbase address without regenerating the entire
BlockProof — a CPU-intensive operation they do not perform.

This provides **cryptographic protection** against block withholding
attacks: external miners cannot steal blocks from the Full Node that
generated the proof.

---

## 8. Block application

A conforming verifier applies a well-formed block by updating the
header:

```
  state_root_next = BlockProof.output_state_root
  active_slot_count_{t+1} = active_slot_count_t
                          + Σ is_activation_k
                          − Σ is_deactivation_k
  log_slots_{t+1} = log_slots_t + Δ_expand  (see §15.3)
  alloc_counter_{t+1} = alloc_counter_t + (# successful mints)
```

where `is_activation` and `is_deactivation` are the per-tx boolean
columns defined in §15.3. The incremental update MUST NOT require a
re-scan of the state vector.

---

## 9. External observability

Any external observer sees, for every applied transaction:

```
  slot i spent   ⇒  slot i now EMPTY
  slot j minted  ⇒  slot j now = (value_j, owner_j)
```

Balances, owners and slot indices are transparent. The `SpendSecret`
is never observable.

---

## 10. Re-spend

A live slot `j` created by a previous transaction is spent by a
subsequent transaction in the usual way: the owner of `j` uses their
`SpendSecret` to prove ownership, the slot is consumed, and `j`
becomes `EMPTY` again. It then becomes eligible for reuse by the
allocator (§15.1).

---

## 11. Value conservation

The protocol guarantees that value flows are of exactly two types:

```
  occupied → EMPTY    (spend)
  EMPTY    → occupied (mint from spend outputs, or coinbase)
```

No value is created out of thin air. The sole exception is the
coinbase (§12).

---

## 12. Coinbase

Every block MAY contain exactly one coinbase transaction with zero
inputs:

```
  inputs:   ∅
  outputs:  slot 900 → ( reward_amount, Miner )
  fee:      0
```

The `reward_amount` is fixed by the protocol emission schedule. The
coinbase transaction:

- MUST be the first transaction of the block;
- MUST satisfy `is_mint ⇒ pre = 0` for its output slot(s), proven by
  BlockStateBinding (miner opens the coinbase slot and verifies EMPTY);
- does NOT require a LogicProof from a wallet (miner constructs it
  directly within BlockStateBinding);
- does NOT balance `Σ inputs == Σ outputs + fee`; instead it carries
  an explicit `is_coinbase` flag with `value = block_reward + sum(fees)`,
  enforced by consensus.

Example:

```
  slot 900 = (3.125, Miner)
```

---

## 13. Dust handling

Small-value outputs remain live slots with the same storage footprint
as larger outputs. Mitigations available to protocol and wallet
policy:

- **Fee floor** — minimum acceptable fee per transaction (local
  policy in the current specification).
- **Minimum output value** — protocol-level floor that transactions
  MUST respect (not enabled in the current specification).
- **Consolidation transactions** — wallets MAY sweep many small
  live slots into a single larger output.

None of the above is consensus-significant in the current protocol
version.

---

## 14. Mempool conflicts

If a transaction is rejected because one of its mint slots has been
taken (§15.2) or because one of its input slots is already consumed
in the mempool:

```
  reject tx
  wallet  → rebuild proof with fresh slot hints
  wallet  → resend
```

A rebuild requires the wallet to obtain new hints (e.g., `slot 913`),
construct a new proof, and broadcast again. The wallet is the only
actor that can produce the new proof — the node cannot.

---

## 15. Scaling

Fixed-slot state provides:

- fast state proofs;
- **parallel proving** across transactions with disjoint
  `input_slots ∪ output_slots`;
- deterministic structure;
- absence of a global hash-map UTXO set.

### 15.0 Parallel prove vs serialised apply

Parallel proving and serialised application live at different layers:

- **Prover side.** Multiple transactions MAY be proven in parallel if
  their input/output slot sets are disjoint. This is a prover
  optimisation.
- **Consensus side.** A block is applied by a deterministic
  serialised reducer: transactions in a block are ordered and applied
  one after the other; mint-slot conflicts are resolved by the
  tie-break of §15.2. This is NOT a concurrent state machine — it is
  serialised execution with parallelisable proving.

### 15.0.1 DA and packing (`noid_binius`)

- Bit-domain columns are packed 128× (`BitWitness`) into
  `Block128` field elements.
- Byte-domain columns are packed 16× (`ByteWitness`).
- Commitment is `PackedCommit` on top of FRI.
- DA payload commitment uses `Poseidon2bSponge` as a Merkle hash
  (`packed_witness_root`).

The test `bit_witness_commit_and_open` verifies a 2^10-bit column
packed into 1024 `Block128` words with opening at a random point
(128× DA saving).

### 15.0.2 Arithmetic (`noid_core`)

- Binary tower GF(2^128) over GF(2^8), with layers
  Bit / Block8 / 16 / 32 / 64.
- CLMUL flat-basis multiplication (GCM polynomial).
- Pre-computed matrices `TOWER_TO_FLAT` / `FLAT_TO_TOWER`.
- AVX2-SIMD squaring for `PackedBlock128`.
- MLE primitives: `evaluate`, `fold_highest_var`, eq-tables.
- Sumcheck: degree-2 round polynomial, three-point Lagrange.
- AdditiveNTT on the binary tower.
- Poseidon2b Fiat–Shamir transcript.

### 15.0.3 Block Aggregation (`noid_block`)

Stage G deferred-opening aggregation: single interleaved Merkle tree
over all N per-tx columns + block-level SpineGKR Kill-Shot + N algebraic
per-tx STARKs (no FRI per tx) + block-level multipoint sumcheck + one
FRI-Binius mixed opening. This is the current (Phase 1 / Stage S)
implementation.

IVC linear folding (`noid_ivc`) was a prototype that has been
removed. A recursive chain accumulator (`noid_recursive`) is planned
for Phase 7 (Stage H) to achieve O(1) historical verification.

---

### 15.1 Slot allocation

#### 15.1.1 Goals

The slot allocator MUST satisfy three properties simultaneously:

1. **Determinism.** Any two nodes applying the same block to the
   same prev-state MUST select identical output slots; otherwise
   their `state_root` diverges.
2. **Reuse efficiency.** When a UTXO is spent, its cell becomes
   `EMPTY` and MUST be preferred by subsequent mints. Otherwise the
   chain grows monotonically into never-written space and prematurely
   triggers the §15.3 expansion.
3. **Write uniformity.** Writes SHOULD spread across the full slot
   space rather than cluster in one region. This matters for
   prover-side parallelism (§15): FRI updates in disjoint Merkle
   sub-trees are independent.

A single rule does not deliver all three properties, so the allocator
is **two-tier**: it first consults a free-list of returned slots, and
only if that is empty probes the never-written region.

```
┌─────────────────────────────────────────────────────────────┐
│                Slot space [0 .. 2^log_slots)                │
│                                                             │
│   [live]  [empty*] [live]  [live]  [empty]  [empty]  ...    │
│           ↑         ↑      ↑                                │
│           was spent        still live                       │
│           → in free_slots (min-heap, "return bin")          │
│                                                             │
│   Never-written empties: scattered across the vector,       │
│   not contiguous at the right edge. Probed uniformly        │
│   by a deterministic PRNG.                                  │
└─────────────────────────────────────────────────────────────┘
```

#### 15.1.2 State variables

Every node MUST maintain on `ChainState` three consensus-significant
quantities:

```
  free_slots         -- min-heap of reusable (previously spent)
                        indices
  active_slot_count  -- number of live UTXOs (non-empty slots)
  alloc_counter      -- monotonic seed source for the PRNG
```

Invariants:

```
  0 ≤ active_slot_count ≤ 2^log_slots
  |free_slots| == (# empty slots that were once written)
  alloc_counter is strictly increasing on every successful mint,
      and is never modified by spends.
```

Nodes MAY also keep a local occupancy bitmap (≈ 2 MB at
`log_slots = 24`) to serve wallet hints; the bitmap itself is NOT
consensus-significant.

#### 15.1.3 Allocation policy (consensus-significant)

Upon a mint, the native allocator MUST execute:

```
  1. if free_slots is non-empty:
         return free_slots.pop_min()          -- primary: reuse

  2. if active_slot_count ≥ 2^log_slots:
         return StateFull                      -- triggers §15.3

  3. loop:
         alloc_counter += 1
         r   = splitmix64(alloc_counter)
         idx = r mod 2^log_slots
         if state[idx] == EMPTY: return idx    -- probe
```

The free-list is the primary tool; the random probe is the fallback
once the free-list is exhausted. `splitmix64` is a fixed-constant
deterministic mixer; the same seed yields the same output on every
node. Expected probe count is below 2 while
`active_slot_count < 0.5 · 2^log_slots`.

On spend:

```
  free_slots.push(input.slot_index)
  active_slot_count -= 1
```

`alloc_counter` MUST NOT be updated on spends: the deterministic seed
depends only on the history of successful mints so that two nodes
replaying the same transaction sequence obtain identical
`new_state_root`.

#### 15.1.4 Wallet hints (non-authoritative)

A wallet MAY request hints from a node:

```
  lowest empty slot                -- if free-list is non-empty
  next K empty slots
  random empty slot                -- via the same splitmix64
```

The hint matches the native allocator. The authoritative check is
strictly in-circuit:

```
  is_mint ⇒ pre_state == 0
```

A node cannot coerce a wallet into overwriting a live slot: the
proof simply fails to build. Parallel prover tie-breaks are handled
by §15.2, not by the allocator.

#### 15.1.5 Rationale: random probe over a monotonic frontier

A linear "bump the high-water mark" fallback would create a hot edge:
every mint before the first spend lands in consecutive low indices.
This:

- concentrates FRI-update work inside one Merkle sub-tree, defeating
  prover sharding;
- makes slot choice predictable to observers, revealing temporal
  signal: block `N` taking slot 17 implies the previous mint took
  slot 16, exposing timing.

Uniform probing spreads both properties. Prover shards receive
roughly equal workload; the slot index carries no temporal signal.

Determinism is preserved: `alloc_counter` is part of the state, lives
in snapshots, and replicates. `splitmix64` is a fixed-constant
algorithm without wall-clock dependence.

#### 15.1.6 `active_slot_count` vs `alloc_counter` — distinct roles

- `active_slot_count` is the **consensus occupancy signal**. It rises
  and falls. Only this quantity feeds the §15.3 expansion trigger and
  the aggregated public columns (§I.5 of the supporting design
  notes), where `is_activation` / `is_deactivation` sum over the block
  to `active_delta`.
- `alloc_counter` is the **PRNG technical variable**. It is
  monotonically increasing but does NOT feed the expansion trigger;
  otherwise the network would expand in response to lifetime
  throughput rather than peak occupancy.

The expansion trigger therefore watches
`active_slot_count / 2^log_slots` — and nothing else.

---

### 15.2 Conflict resolution

If two transactions within the same block attempt to mint the same
slot, they are resolved by a deterministic tie-break:

```
  winner = argmin_over_candidates (tx_body_hash)
```

The winner is included; the loser is dropped. The loser's wallet
rebuilds its proof with a fresh slot hint and re-broadcasts (§14).

#### 15.2.1 Boundary of responsibility (normative)

Slot uniqueness is an **economic** guarantee, not a cryptographic
one. The AIR proves only `is_mint ⇒ pre = 0` — "no overwriting a live
slot". It does NOT prove "two independent provers will never select
the same empty slot". That is handled by the tie-break at the
mempool / block-assembly layer. Chain safety does NOT depend on the
tie-break: only UX and throughput do.

---

### 15.3 Automatic slot-space expansion

Start:

```
  log_slots = 24
  MAX_LOG_SLOTS = 32
```

#### 15.3.1 Two composing allocation loops

1. **Loop 1 — within the current `log_slots`** (§15.1).
   The free-list reuses spent slots (lowest-first); the random probe
   fills never-written slots uniformly. `active_slot_count`
   oscillates. There is no protocol intervention at this layer — it
   is ordinary native bookkeeping.

2. **Loop 2 — protocol expansion** (this section).
   Triggered only when `active_slot_count` stays elevated. If spends
   keep pace and `active_slot_count` falls, the random probe finds
   empties quickly and no expansion is needed.

#### 15.3.2 Occupancy definition

```
  active_slot_count_{t+1} =
      active_slot_count_t
      − spent_to_zero_count(block_{t+1})
      + minted_from_zero_count(block_{t+1})

  occupancy_t = active_slot_count_t / 2^log_slots_t
```

Invariant: `0 ≤ active_slot_count ≤ 2^log_slots`.

The denominator MUST be `2^log_slots`; the numerator MUST be
`active_slot_count`. Any monotonic lifetime variable (total mints
ever, `alloc_counter`, etc.) would produce a false signal on
spike-then-drain traffic.

#### 15.3.3 Consensus semantics of size maintenance

State size MUST NOT be recomputed by scanning the state tree. It MUST
be maintained **incrementally** in the header. The per-block update
cost is `O(txs_in_block)`, not `O(2^log_slots)`. Any node MAY read
`active_slot_count` directly from the header without traversing the
state tree.

#### 15.3.4 Reorg safety

The accumulator is committed in every header. On a chain switch, a
node rolls back to the common ancestor and reads that ancestor's
`active_slot_count` — which is correct by construction because every
block carries a snapshot.

#### 15.3.5 AIR support

`tx_validity` exposes two boolean per-tx columns:

```
  is_activation   = (pre_value == 0)  AND (post_value != 0)
  is_deactivation = (pre_value != 0)  AND (post_value == 0)
```

Their block-wide sum is `active_delta`, which MUST equal
`header_{t+1}.active_slot_count − header_t.active_slot_count`.
Partial spends are disallowed: a slot is either live, or fully zeroed
(`value == 0 AND owner == 0`).

#### 15.3.6 Expansion rule (consensus)

Hysteresis is measured as a **7-day rolling average** over
**finalised** blocks (NOT mempool, NOT tip):

```
  if avg_occupancy_last_7d_finalized > 0.90
     AND log_slots < MAX_LOG_SLOTS:
       the next block MUST carry log_slots += 1
```

This is a consensus rule. A block that fails to increment under these
conditions is invalid. Anchoring the window to the finalised chain
eliminates reorg-induced disagreement: every node computes the same
trigger.

There is **no auto-shrink**. `log_slots` is monotonically
non-decreasing. Shrinking would introduce replay risks and AIR
versioning complexity. Surplus capacity after a demand drop is
cheap.

The rolling average (rather than instantaneous occupancy) removes
oscillation: a one-block spam spike does NOT trigger expansion.

#### 15.3.7 Expansion procedure (trigger block producer)

Expansion appends a zero sub-tree to the end of the state. The Merkle
root of an all-zero sub-tree is a pre-computed constant
`ZERO_SUBTREE_ROOT[k]` (one per depth `k`).

The new state root is computed with one Poseidon2b compression:

```
  new_state_root =
      Poseidon2b( old_state_root,
                  ZERO_SUBTREE_ROOT[old_log_slots] )
```

Plus `log_slots += 1` in the header. No state re-hashing.

Effect on the allocator on expansion:

```
  free_slots         -- unchanged (all existing freed slots remain
                        valid and keep priority — lowest-first)
  active_slot_count  -- unchanged (the new zero half adds no live
                        UTXOs)
  alloc_counter      -- unchanged (monotonic seed continues)
  fri.num_slots()    -- doubles to 2^new_log_slots; the probe mask
                        becomes (new_cap − 1), so the high bit of
                        splitmix64 is now live
```

After expansion, the allocator first drains the existing free-list
(msb = 0 slots in the old region), and then the random probe begins
sampling uniformly over the full doubled region — including the new
upper half (msb = 1). No prior `slot_index` is invalidated.

#### 15.3.8 Who performs the migration

The miner who first finds PoW for the trigger block. There is no
separate actor and no bounty.

- Cost: one Poseidon2b compression.
- Reward: standard coinbase + fees.

The `is_mint ⇒ pre = 0` invariant continues to hold: old
`slot_index` values remain valid (msb = 0); new mints may take msb =
1. AIR width parameterisation is redrawn from the new header's
`log_slots`. Soundness is preserved.

The trigger is deterministic. There is no voting, no signalling, and
no off-band coordination.

#### 15.3.9 `log_slots` as a protocol-versioning primitive

`log_slots` is not merely a state parameter. AIR arithmetisation
depends on it: the state commitment size, the bit-width of slot-index
decomposition in `BlockStateBindingAir`, and the size of MLE eq-tables are
all functions of `log_slots`. Expansion changes the interpretation of
the execution environment while preserving soundness (old
`slot_index` remain valid as msb = 0; new mints gain msb = 1 access).
Therefore `log_slots`:

- lives in the header;
- is committed in every block;
- is replicated in the Fiat–Shamir transcript;
- is read by every AIR builder as a circuit constant for the block
  being verified.

There is no off-header configuration.

---

## 16. Summary of block-level invariants

A conforming verifier MUST reject a block if any of the following
fails:

1. Every transaction's LogicProof verifies (STARK + SpineGKR +
   AuthGKR).
2. Every transaction's epoch_anchor is within the ANCHOR_DEPTH
   window.
3. No tx_body_hash appears in the nullifier set.
4. No input slot is consumed twice in the block.
5. No output slot is minted twice after tie-break resolution
   (§15.2).
6. Balance holds per transaction: `Σ inputs = Σ outputs + fee`
   (coinbase excepted, §12). (Proven in LogicProof.)
7. Range holds per value: `value < 2^64`. (Proven in LogicProof.)
8. BlockStateBinding verifies: all claimed slots match actual state,
   output slots were EMPTY, post-state root correctly computed.
9. Bridge: `C_claimed` from each LogicProof matches the values opened
   in BlockStateBinding.
10. `is_activation` / `is_deactivation` sums equal
    `header.active_slot_count` delta (§15.3.5).
11. `log_slots` is incremented iff the §15.3.6 trigger condition
    holds.
12. The aggregated `BlockProof` (LogicProofs + BlockStateBinding +
    deferred-opening FRI) verifies.
13. PoW satisfies the declared difficulty.
14. `header.da_root` matches the computed DA Payload root.
15. `header.state_root` matches `new_block_state_root` from
    BlockStateBinding.

---

## 17. Transaction validity vs chain validity (normative)

Per-tx LogicProof establishes **local correctness** of transaction
logic:

```
  (epoch_anchor, tx_body, C_claimed) → proof that balance, range,
  ownership, and body commitment are correct
```

covering ownership, balance, range, spine binding, and claims
commitment — without any state dependency.

BlockStateBinding establishes **state correctness**, i.e. that all
claimed slot values match the actual Merkle-committed state:

```
  (prev_block_state_root, claimed_slots, C_claimed) →
      proof that state matches claims, outputs empty, post-state correct
```

`BlockProof` establishes **chain correctness** by combining both
layers:

1. All LogicProofs are valid (algebraic).
2. BlockStateBinding is valid (state openings + bridge).
3. C_claimed equality holds for each transaction.
4. State transition is coherent: prev_block_state_root →
   (apply all txs) → new_block_state_root.

Consequently a `BlockProof` certifies:

```
  (a)  all transaction logic is valid (LogicProofs)
  (b)  all state claims are correct (BlockStateBinding)
  (c)  the bridge between (a) and (b) is sound (C_claimed match)
  (d)  the global state evolution is coherent
```

### 17.1 Recursive chain validity (overview)

When the recursive chain is active (Stage H), each `BlockProof_{n+1}`
additionally certifies the algebraic validity of `BlockProof_n`.
The recursive circuit verifies the prior block's sumcheck, GKR, and
composition claims in-circuit, while deferring FRI Merkle-path
verification to a running hash commitment checked natively at the tip.

A fresh node verifies the tip's recursive STARK proof plus one native
FRI Merkle check to gain cryptographic certainty over the entire chain
from genesis. Full specification of the recursive protocol will be
added after implementation (see `ROADMAP2.md` Part II).

---

## 18. Proof-of-Work and difficulty adjustment

### 18.1 PoW algorithm

The block hash for proof-of-work purposes is:

```
  pow_hash = Blake3(block_header_bytes)
```

where `block_header_bytes` is the canonical serialisation of the full
block header (§0.4, §8.4 of `ARCHITECTURE.md`) as a contiguous byte
sequence in field order, little-endian.

Blake3 was chosen for PoW because:

- The protocol does not rely on PoW for execution security (proofs
  handle that). PoW only provides ordering and Sybil resistance.
- Blake3 is CPU-friendly; any laptop can mine on a young network.
- Verification is nanoseconds, adding zero overhead to block validation.
- If ASIC dominance becomes problematic, the hash function can be
  changed via hard fork without affecting the proof system.

### 18.2 Nonce and header fields for PoW

The block header includes:

```
  nonce                [16B]  — 128-bit PoW nonce
  difficulty_target    [32B]  — 256-bit target threshold
  height              [ 8B]  — block height (used for anchor calculations)
```

A block satisfies PoW iff:

```
  Blake3(block_header_bytes) < difficulty_target
```

interpreted as a 256-bit unsigned little-endian integer.

### 18.3 ASERT difficulty adjustment

The protocol uses **ASERT** (Absolutely Scheduled Exponentially Rising
Targets), an exponential moving average that adjusts difficulty
continuously relative to a fixed anchor block.

#### 18.3.1 Parameters

```
  BLOCK_TIME     = 60 seconds      (target inter-block interval)
  EPOCH_LENGTH   = 6 blocks        (anchor update period)
  HALFLIFE       = 360 seconds     (= EPOCH_LENGTH × BLOCK_TIME)
```

The halflife means: if the last epoch took half the ideal time (miners
found 6 blocks in 180s instead of 360s), difficulty doubles. If it took
twice the ideal time (720s), difficulty halves.

#### 18.3.2 Anchor

The anchor is updated every `EPOCH_LENGTH` blocks at epoch boundaries:

```
  anchor_height    = largest h ≤ current_height where h % EPOCH_LENGTH == 0
  anchor_timestamp = block_header[anchor_height].timestamp
  anchor_target    = block_header[anchor_height].difficulty_target
```

At genesis, `anchor_height = 0`, `anchor_timestamp = genesis_timestamp`,
`anchor_target = GENESIS_TARGET`.

#### 18.3.3 Target calculation

For a block at height `H` with timestamp `T`:

```
  ideal_elapsed   = (H - anchor_height) × BLOCK_TIME
  actual_elapsed  = T - anchor_timestamp
  exponent        = (actual_elapsed - ideal_elapsed) / HALFLIFE

  new_target = anchor_target × 2^exponent
```

The exponential is computed using fixed-point arithmetic with sufficient
precision (at least 64 fractional bits) to avoid rounding-induced forks.
All nodes MUST use the same fixed-point implementation to produce
byte-identical targets.

The target is clamped:

```
  MIN_TARGET = 1          (maximum difficulty; hash must be < 1 is theoretical only)
  MAX_TARGET = 2^255 - 1  (minimum difficulty; trivially satisfied)
```

#### 18.3.4 Properties

- **Stateless calculation:** The target for any block depends only on
  the anchor block's fields plus the current block's height and
  timestamp. No scanning of intermediate blocks is required.
- **Fast adaptation:** 6-block epoch means the network adapts to
  hashrate changes within ~6 minutes.
- **No oscillation:** The exponential function is smooth — no DAA
  gaming via timestamp manipulation beyond clamping rules (§18.4).
- **Deterministic:** Given the same anchor + (height, timestamp), every
  node computes the identical target.

#### 18.3.5 Epoch anchor update rule (consensus)

When `height % EPOCH_LENGTH == 0`:

```
  anchor_height    ← height
  anchor_timestamp ← timestamp
  anchor_target    ← difficulty_target (as calculated for this block)
```

The anchor fields are NOT stored separately — they are read from the
block header at the relevant epoch boundary height. A node performing
a reorg recalculates the anchor from the new chain's epoch boundary.

### 18.4 Timestamp validation

A conforming node MUST reject a block if:

```
  block.timestamp ≤ median_time_past(last 11 blocks)
  block.timestamp > local_time + MAX_FUTURE_DRIFT
```

where:

```
  MAX_FUTURE_DRIFT = 120 seconds
```

This prevents timestamp manipulation that could game difficulty:
- Cannot go backwards (median-time-past rule).
- Cannot jump far forward (drift cap limits exponent depression).

### 18.5 Genesis difficulty

```
  GENESIS_TARGET = 2^240
```

This yields approximately 2^16 = 65536 expected hashes to find a block
at genesis. On a modern CPU doing ~1 GH/s Blake3, this takes ~65
microseconds — intentionally trivial so that the first miner can
bootstrap the chain immediately. Difficulty rises exponentially as
hashrate grows.

---

## 19. Segmented state commitment

### 19.1 Motivation

The original state commitment (a single FRI polynomial over all
`2^log_slots` elements) requires O(N) NTT recomputation per block.
At `log_slots = 24` this takes seconds; at `log_slots = 28` it becomes
impractical; at `log_slots = 32` it is impossible.

The segmented design splits the state into fixed-size segments, each
independently FRI-committed. Only segments modified by a block are
recomputed. The global `state_root` is a Poseidon2b Merkle tree over
segment roots.

### 19.2 Segment parameters

```
  LOG_SEGMENT_SIZE = 16                    (65 536 slots per segment)
  num_segments     = 2^(log_slots - LOG_SEGMENT_SIZE)
  segment_depth    = log_slots - LOG_SEGMENT_SIZE
```

At genesis (`log_slots = 24`): 256 segments, tree depth 8.
At maximum (`log_slots = 32`): 65 536 segments, tree depth 16.

`LOG_SEGMENT_SIZE` is a protocol constant. It does NOT change when
`log_slots` grows — expansion adds new segments, existing segments
retain their size.

### 19.3 Segment root

Each segment `s` is a FRI-committed vector of `2^LOG_SEGMENT_SIZE`
slots across three columns (value, owner_hi, owner_lo):

```
  seg_root[s] = combine_roots(
      LOG_SEGMENT_SIZE,
      fri_root(segment_s.values),
      fri_root(segment_s.owners_hi),
      fri_root(segment_s.owners_lo)
  )
```

This is the same `combine_roots` function (Poseidon2b sponge under
`TAG_FRISTATE`) used today, but scoped to `LOG_SEGMENT_SIZE` instead
of `log_slots`. The per-column FRI Merkle internals use Blake3.

### 19.4 Global state root

```
  state_root = poseidon2b_merkle_tree(
      seg_root[0], seg_root[1], ..., seg_root[num_segments - 1]
  )
```

The Merkle tree uses Poseidon2b compression with domain tag
`TAG_SEGMENTTREE`. Empty (all-zero) segments use pre-computed constants
`ZERO_SEGMENT_ROOT` (the FRI commitment of 2^16 zero-slots).

The tree has depth `segment_depth` (8 at genesis, grows with
`log_slots`). Internal nodes at depth `d` with two zero children use
`ZERO_SEGTREE_NODE[d]`.

### 19.5 Slot addressing

A slot at global index `idx` maps to:

```
  segment_id = idx >> LOG_SEGMENT_SIZE
  local_idx  = idx & ((1 << LOG_SEGMENT_SIZE) - 1)
```

### 19.6 Block production (state update)

Upon applying a block:

1. For each mutation `(idx, new_value)`: mark `segment_id` as dirty.
2. For each dirty segment:
   a. Apply mutations to the segment's column vectors.
   b. Recompute the segment's three FRI column roots (NTT over
      `2^LOG_SEGMENT_SIZE` elements — fixed-cost, independent of total
      state size).
   c. Compute `seg_root[s]` via `combine_roots`.
3. Update the Poseidon2b Merkle tree: for each dirty segment, update
   its leaf and propagate `segment_depth` hash compressions upward.
4. `state_root` = tree root.

Cost per block:

```
  FRI recomputation: K × O(2^LOG_SEGMENT_SIZE)  where K = # dirty segments
  Tree update:       K × segment_depth × O(1)   (Poseidon2b compressions)
```

Typical block with 100 transactions touching ~50 segments:
  - 50 × NTT(2^16) = 50 × ~0.5ms = ~25ms FRI work
  - 50 × 8 Poseidon2b = negligible

### 19.7 In-circuit proof (BlockStateBinding)

To prove `slot[idx] = V` against `state_root`:

```
  1. FRI opening of local_idx within segment_id:
     - Sumcheck over LOG_SEGMENT_SIZE variables (16 rounds)
     - Proves V against seg_root[segment_id]
     - This is the existing FRI opening mechanism, unchanged

  2. Segment Merkle path: seg_root[segment_id] → state_root
     - segment_depth Poseidon2b compressions (8 at genesis, up to 16)
     - Proved in-circuit within BlockStateBinding AIR
```

In-circuit cost breakdown:

```
  FRI opening (sumcheck):  16 rounds (was 24 with monolithic FRI)
  Merkle path (Poseidon):  8-16 permutations per unique segment

  Batching: slots in the same segment share the Merkle path.
  For 200 slots across 50 segments: 50 × 8 = 400 Poseidon2b perms.
```

Compared to monolithic FRI (24-round sumcheck, 0 Poseidon):
- Save 8 sumcheck rounds per slot (cheap binary field ops).
- Add 8 Poseidon perms per unique segment (moderate cost).
- Net with in-AIR Poseidon: ~+7-15% BlockProof overhead.

### 19.7.1 Merkle Kill-Shot optimisation

The segment Merkle path Poseidon2b permutations are NOT materialised in
the STARK AIR trace. Instead, they are proven via a dedicated
**Merkle Kill-Shot GKR** sub-protocol (`noid_gkr::merkle_killshot`),
using the same unified sumcheck + shift architecture as SpineGKR and
AuthGKR.

Structure: up to `MAX_MERKLE_DEPTH = 16` chained compressions (32
permutation slots) in a single 14-variable hypercube (2^14 = 16 384
cells). The Kill-Shot proves all Poseidon2b constraints simultaneously
via one degree-9 unified sumcheck (14 rounds) + one shift gadget
(14 rounds) + 3 batch-eval reductions.

When multiple segment paths are batched into a single block proof:

```
  50 unique segments × 8 compressions = 400 permutations
  → batched into a single Merkle Kill-Shot (18-var hypercube)
  → ~36 FS rounds, ~8 KB proof
  → ZERO additional STARK AIR rows
```

Compared to in-AIR materialisation:

| Approach | Trace overhead | Proof overhead | Net BlockProof impact |
|----------|---------------|---------------|-----------------------|
| In-AIR Poseidon | +107K rows | +10-15 KB | +15% |
| **Merkle Kill-Shot** | **0 rows** | **~8 KB sub-proof** | **+2-3%** |

The Merkle Kill-Shot is bound to the STARK via the same mechanism as
SpineGKR/AuthGKR: boundary MLE committed by FRI, `extra_transcript`
hook, and a single-point opening `(r_B, v_B)` discharged in the
multipoint-close.

Net impact on BlockProof with Kill-Shot: **+2-3%** (effectively zero).
Net impact on LogicProof: **still zero** (Merkle paths are block-only).

### 19.8 Expansion under segmentation (§15.3 interaction)

When `log_slots` increments by 1:

- `num_segments` doubles.
- The new upper half is all-zero segments (`ZERO_SEGMENT_ROOT`).
- The Merkle tree gains one level: new root = Poseidon2b(old_root,
  ZERO_SEGTREE_NODE[old_depth]).
- Existing segment indices remain valid (high bit = 0).
- New mints into the upper half create dirty segments in the new region.
- `LOG_SEGMENT_SIZE` remains 16 — segments never change size.

Cost of expansion: one Poseidon2b compression (same as before).

### 19.9 Segment root caching

Nodes MUST cache all `num_segments` segment roots (32 bytes each).
At `log_slots = 24`: 256 × 32 = 8 KB. At `log_slots = 32`: 65536 ×
32 = 2 MB. This is trivial.

The full Merkle tree of segment roots is also cached (internal nodes):
at most `2 × num_segments × 32` bytes = 4 MB at maximum scale.

---

## 20. State storage backends

### 20.1 Storage abstraction

The state layer MUST support two backend modes selectable at node
startup:

```
  --storage=ram    (default; entire state in process memory)
  --storage=disk   (MDBX-backed; mmap'd file on disk)
```

Both backends present the same interface to the chain layer:

```
  get_slot(segment_id, local_idx) → SlotValue
  set_slot(segment_id, local_idx, SlotValue)
  load_segment_columns(segment_id) → (Vec<Block128> × 3)
  flush()
```

The `load_segment_columns` method is used by the block producer to
obtain the full column vectors needed for FRI NTT recomputation of a
dirty segment. The disk backend loads (or maps) only the requested
segment into memory.

### 20.2 RAM backend (default)

All segments as contiguous `Vec<Block128>` arrays in process memory.
Optimal for development, testing, and nodes with sufficient RAM.

Memory budget:

```
  log_slots=24: 256 segments × 2^16 × 3 × 16B = 768 MB
  log_slots=26: 1024 segments × 2^16 × 3 × 16B = 3 GB
  log_slots=28: 4096 segments × 2^16 × 3 × 16B = 12 GB
```

Recommended for `log_slots ≤ 26` (up to ~3 GB).

### 20.3 Disk backend (MDBX)

Uses MDBX (libmdbx) as the storage engine. Each segment is a sub-range
within a single MDBX database, keyed by `(segment_id, local_idx)`.

MDBX properties relevant to our workload:

- **Memory-mapped reads:** Random slot lookups are mmap pointer
  dereferences — no deserialization overhead.
- **Copy-on-write:** Crash-safe by construction. No WAL replay needed.
- **Dynamic geometry:** Database file grows/shrinks automatically.
- **Proven at scale:** Used by Reth (Ethereum execution client) at
  multi-TB state sizes.

The disk backend loads dirty segment columns into a temporary RAM buffer
for NTT computation during block production, then releases the buffer
after computing the segment's FRI root.

Memory budget with disk backend:

```
  Hot buffer: K × 2^16 × 3 × 16B where K = dirty segments per block
  Typical (K=50): 50 × 64K × 48B = 150 MB temporary
  Segment root cache: ≤ 4 MB
  MDBX mmap: OS-managed, backed by file
```

### 20.4 Mandatory disk mode

A conforming node MUST use the disk backend when `log_slots > 26`.
Attempting to run in RAM mode at `log_slots > 26` requires > 12 GB
of state memory and is unsafe for typical hardware.

### 20.5 Backend selection is non-consensus

The storage backend is an implementation detail. Both backends produce
byte-identical `state_root` values and identical state transitions.
A node MAY switch backends between restarts (by importing a snapshot).
No on-chain state or proof depends on which backend is active.

---

## 21. Conformance

An implementation is **conforming** iff:

- it produces byte-identical `state_root`, `active_slot_count`,
  `alloc_counter`, and `log_slots` updates for every finalised block
  against the reference semantics of §0 through §20;
- it rejects every block that fails any invariant of §16;
- it uses the Fiat–Shamir transcript schedule specified by
  `ARCHITECTURE.md` §4.2 and `noid_gkr/SPEC.md` for the GKR boundary
  binding;
- it uses the ASERT difficulty calculation of §18.3 to validate PoW;
- it uses the segmented state commitment of §19 to compute
  `state_root`.

All other choices (mempool prioritisation, local fee policy, probe
caching, bitmap layout, storage backend) are implementation-defined.
