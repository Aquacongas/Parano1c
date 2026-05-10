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
- PoW nonce and difficulty parameters.

`log_slots` is protocol versioning: AIR arithmetisation (state
commitment size, slot-index bit-decomposition in `FriStateOpenAir`,
MLE eq-table size) is parameterised by `log_slots`. Every AIR builder
MUST read `log_slots` from the header of the block being verified.
There is no "off-header" configuration.

### 0.5 Global commitment

The global state commitment is the single Poseidon2b digest:

```
  state_root
```

computed over the `2^log_slots`-element slot vector using the fixed
domain-separated leaf hash and Poseidon2b Merkle compression with
`ZERO_SUBTREE_ROOT[k]` constants at empty sub-trees.

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

A transaction `tx` has the form:

```
  tx = (tx_body, proof, prev_root, new_root)
```

### 3.1 Selection of inputs

The wallet selects live slots owned by the spender (e.g., `slot 101 =
(100, Alice)`) and marks them as inputs.

### 3.2 Selection of output slots

The wallet obtains slot hints from a node:

```
  wallet → node:  request free slot hints
  node   → wallet: e.g., [200, 500, ...]
```

The hint is **non-authoritative** — it matches the native allocator
(§15.1) but the authoritative correctness check is in-circuit via
`is_mint ⇒ pre = 0`. A node cannot force the wallet to overwrite a
live slot; a proof that attempts to do so simply fails to build.

### 3.3 Outputs

Each output binds a chosen slot index to a `(value, owner)` pair:

```
  slot 200 → ( 90, Alice )       -- change
  slot 500 → ( 10, Bob   )       -- payment
```

### 3.4 Transaction body

`tx_body` contains:

```
  inputs:     list of slot indices (consumed slots)
  outputs:   list of (slot_index, value, owner_hi, owner_lo)
  fee:       non-negative amount (may be 0)
```

`tx_body_hash` is the Poseidon2b spine hash of `tx_body` (§A.3 of
`ARCHITECTURE.md`): 59 Poseidon2b permutations (4 input-leaf + 8
output-leaf + 15 compress + 1 wrap) under `DomainTag::TAG_TXBODY`.

---

## 4. Proof contents

The wallet builds **one** cryptographic proof locally that
simultaneously attests:

### 4.1 Ownership

For every input slot `i`, the prover knows `SpendSecret_i` such that
`derive_address(SpendSecret_i) == owner_i`. Enforced by `haddr` +
`hauth` + constraint `T1a` of `tx_validity` (see §A.2 of
`ARCHITECTURE.md`).

### 4.2 Balance and range

```
  Σ inputs.value == Σ outputs.value + fee
  ∀ v ∈ values:  v < 2^64
```

Enforced by `balance_gate` and `range_gate`.

### 4.3 Pre-state correctness

Under `prev_root`:

- Every input slot `i` opens to the claimed `(value_i, owner_i)`.
- Every mint output slot `j` opens to `EMPTY`.

Enforced by `fri_state_open` on the prev side plus the mint rule
`is_mint ⇒ pre == 0` (constraint `T3` of `tx_validity`).

### 4.4 Post-state correctness

Under `new_root`:

- Every input slot is `EMPTY`.
- Every output slot holds the claimed `(value, owner)` pair.

Enforced by `fri_state_open` on the new side.

### 4.5 Root consistency

`new_root` is the Poseidon2b state commitment of the post-state, and
it equals the value carried in the transaction and in the block
header. Enforced by the `FRI_STATE_COMBINER` compositions on both
sides (§A.4 of `ARCHITECTURE.md`).

### 4.6 Transaction-body binding

`tx_body_hash` is computed by the GKR spine sub-proof (§4.2 of
`ARCHITECTURE.md`); its two lanes are pinned into the AIR via
`PublicColumn`; `hauth` absorbs `tx_body_hash` so that the auth-tag
is bound to this specific body. Enforced by constraints `T2a` / `T2b`
of `tx_validity`.

A transaction is **cryptographically valid** iff all of the above
hold. Validity is a local property of the single object
`(prev_root, tx_body, new_root, proof)`.

---

## 5. Broadcast payload

The network payload is:

```
  (prev_root, tx_body, new_root, proof)
```

The `SpendSecret` MUST NOT appear in the payload and MUST NOT be
recoverable from it.

---

## 6. Node-side validation (per-tx)

On receiving a transaction a node MUST check:

```
  1. proof verifies under (prev_root, new_root, tx_body_hash);
  2. prev_root matches the current chain tip that the node is
     building on (or an explicitly allowed alternative tip during
     mempool handling — see §14);
  3. no conflicting slot usage versus the mempool-admitted set:
        • no input slot is spent twice,
        • no output slot is minted twice;
  4. fee is acceptable under the node's local policy (non-consensus).
```

Only if all four hold is the transaction admitted to the mempool.
Checks (1)–(3) are consensus-significant; check (4) is a local
policy.

---

## 7. Block assembly (miner)

A miner aggregates a batch of admitted transactions:

```
  tx_1, tx_2, ..., tx_n
```

and MUST enforce:

- no input slot is consumed by more than one transaction in the
  block;
- no output slot is minted by more than one transaction in the block;
- conflicts between candidate transactions are resolved by the
  deterministic tie-break rule of §15.2.

The miner then:

1. orders the surviving transactions (deterministic order sealed by
   PoW; §15.2 tie-break fixes any remaining ambiguity);
2. recursively folds every per-tx proof into the block's IVC
   accumulator (`noid_ivc::Accumulator`), producing one `BlockProof`;
3. computes the resulting `state_root_next` and updates
   `active_slot_count`, `alloc_counter`, and (if the §15.3 trigger
   fires) `log_slots`;
4. seals the block with PoW.

A block is **well-formed** iff every admitted transaction satisfies
§6, no conflicts remain after §15.2, the aggregated `BlockProof`
verifies, and the header fields are updated consistently with §8.

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
- MUST satisfy `is_mint ⇒ pre = 0` for its output slot(s), proven in
  the usual way via `tx_validity` and `fri_state_open`;
- does NOT balance `Σ inputs == Σ outputs + fee`; instead it carries
  an explicit `is_coinbase` flag that is consumed by the balance gate
  as a protocol-recognised mint.

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

### 15.0.3 IVC (`noid_ivc`)

Linear folding accumulator with state

```
  { log_len, z, y_acc, column_commitments,
    per_step_openings, per_step_proofs }
```

- `fold_step_prove` — commits the next column, opens it at the
  shared point `z`, absorbs a Fiat–Shamir challenge `α`, updates
  `y_acc += α · y`.
- `decide` — replays the transcript, verifies every FRI opening, and
  checks `y_acc == Σ α_k · y_k`.

Soundness: characteristic-2 XOR linearity plus Schwartz–Zippel in
`α`. The test `fold_three_decide_ok` exercises a three-step fold.

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
decomposition in `FriStateOpenAir`, and the size of MLE eq-tables are
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

1. Every transaction's proof verifies against
   `(prev_root, tx_body_hash, new_root)`.
2. `prev_root` of each transaction matches the state root on which
   that transaction is applied in serialised order.
3. No input slot is consumed twice in the block.
4. No output slot is minted twice after tie-break resolution
   (§15.2).
5. Balance holds per transaction: `Σ inputs = Σ outputs + fee`
   (coinbase excepted, §12).
6. Range holds per value: `value < 2^64`.
7. `is_mint ⇒ pre = 0` for every mint slot.
8. `is_activation` / `is_deactivation` sums equal
   `header.active_slot_count` delta (§15.3.5).
9. `log_slots` is incremented iff the §15.3.6 trigger condition
   holds.
10. The aggregated `BlockProof` verifies.
11. PoW satisfies the declared difficulty.

---

## 17. Transaction validity vs chain validity (normative)

Per-tx proof establishes **local correctness** of one state
transition:

```
  (prev_root_i, tx_i) → new_root_i
```

covering ownership, balance, state openings, post-state, and the
computation of `new_root_i`.

`BlockProof` establishes **chain correctness**, i.e. continuity of
the ordered transition sequence within the block:

```
  new_root_i == prev_root_{i+1}
```

The IVC fold additionally checks, at every step:

- validity of the next tx proof;
- continuity of state roots;
- absence of conflicting transitions;
- correctness of the accumulator state.

Consequently a `BlockProof` certifies both:

```
  (a)  all tx proofs are valid
  (b)  all tx proofs form one coherent global state evolution
```

---

## 18. Conformance

An implementation is **conforming** iff:

- it produces byte-identical `state_root`, `active_slot_count`,
  `alloc_counter`, and `log_slots` updates for every finalised block
  against the reference semantics of §0 through §17;
- it rejects every block that fails any invariant of §16;
- it uses the Fiat–Shamir transcript schedule specified by
  `ARCHITECTURE.md` §4.2 and `noid_gkr/SPEC.md` for the GKR boundary
  binding.

All other choices (mempool prioritisation, local fee policy, probe
caching, bitmap layout) are implementation-defined.
