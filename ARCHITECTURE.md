# Paranoid Engine — How It Works

This document describes the Paranoid chain engine end-to-end: from the
user pressing **Send** in a wallet to the block that settles the
transaction on chain. It is written so that both an engineer and a
reader without a cryptographic background can follow it. Components
are presented top-down — from UX down to the underlying mathematics.

---

## 1. One-line picture

```
  wallet  ──►  proof  ──►  mempool  ──►  miner  ──►  block proof  ──►  chain
                  ▲                        │
                  │                        ▼
              (GKR + STARK + FRI)     aggregated proof (IVC)
```

The user builds **a single cryptographic proof** locally that asserts
the transaction is correct. The network only **verifies** that proof —
it never "executes" the transaction. A miner aggregates many such
proofs into one recursive proof and seals it with a PoW block.

---

## 2. What the state looks like

State is a flat shelf of `2^log_slots` cells (initially 2^24 ≈ 16 M).
Each cell stores a triple:

```
  slot[i] = (value, owner_hi, owner_lo)
```

An empty cell is the canonical zero `(0, 0, 0)`. The root of all cells
is `state_root`, a single Poseidon2b commitment. It is written into
the block header.

```
┌─────────────────── state (2^24 cells) ───────────────────┐
│ [100, Alice] [ 0,0,0 ] [ 0,0,0 ] [ 50, Bob ] ...         │
│     slot 0      slot 1    slot 2     slot 3              │
└──────────────────────────────────────────────────────────┘
                        │
                        ▼
                   state_root (32 bytes)
```

Value can only **move from a live cell to an empty one**. Nothing is
created out of thin air, with one exception: the coinbase reward
minted to the miner.

---

## 3. The life of a transaction

### 3.1 The wallet assembles a `tx`

Alice holds a private `secret`. A public `address` is derived from it
deterministically. The wallet:

1. locates Alice's live slot (say `slot 101 = (100, Alice)`);
2. asks the node for free slots for change and for the recipient;
3. builds the **tx body**:

```
  inputs:   slot 101
  outputs:  slot 200 → 90  Alice   (change)
            slot 500 → 10  Bob     (payment)
  fee:      0
```

### 3.2 The wallet builds the proof

This is the heart of the system. The wallet assembles **one** proof
locally that simultaneously attests:

```
  ownership        │ Alice knows the secret for owner of slot 101
  balance          │ Σ inputs == Σ outputs + fee
  pre-state        │ slot 101 in prev_root really was (100, Alice);
                   │ slots 200 and 500 were empty
  post-state       │ slot 101 is now zero; slots 200 and 500 are full
  new_root         │ the resulting root is computed correctly
```

### 3.3 Broadcasting

```
  (prev_root, tx_body, new_root, proof)
```

**Without the secret.** The node verifies the proof → admits it to the
mempool.

### 3.4 The miner assembles a block

A miner in Paranoid is, simultaneously:

- block producer;
- recursive proof aggregator;
- PoW finalizer.

The network does not distinguish the separate roles of builder,
sequencer, prover, or aggregator. This is deliberate: every
transaction already carries a complete cryptographic proof of its
correctness, so the network does not need "executors". Execution
happens locally at the wallet/prover, well before `tx` is broadcast.

The miner's job is to construct the next **canonical recursive
validity checkpoint** for the network.

The miner:

- pulls tx proofs from the mempool;
- verifies each tx proof;
- resolves conflicts between competing transitions;
- orders the transactions;
- recursively folds all proofs into one `BlockProof`;
- computes the resulting `state_root`;
- seals the outcome with PoW.

```
  tx proofs
      │
      ▼
  validation
      │
      ▼
  ordering + conflict resolution
      │
      ▼
  recursive folding (IVC)
      │
      ▼
  BlockProof + state_root
      │
      ▼
  PoW finalization
      │
      ▼
  canonical block
```

Observe: PoW in Paranoid does not protect execution of transactions.
The correctness of execution is already established cryptographically.

PoW solves a different problem:

- it picks a canonical ordering of transitions;
- it makes reorgs expensive;
- it produces an objective history of the network;
- it anchors the recursive proof chain.

So the role of a Paranoid miner is not "transaction executor" but:

> recursive proof aggregator and PoW finalizer

---

## 4. What lives inside "one proof"

The proof is not a monolith. It is a layered composition of several
complementary primitives, each answering a different question and
doing what it does best.

```
  ┌──────────────────────────────────────────────────────────┐
  │                     Proof layers                         │
  │                                                          │
  │   AIR   ── algebraic model of the computation            │
  │    │                                                     │
  │    ├─► GKR   ── fast hash engine for the tx-body spine   │
  │    │                                                     │
  │    └─► STARK ── final non-interactive guarantee          │
  │          │                                               │
  │          └─► FRI  ── low-degree proximity test           │
  │                                                          │
  │   IVC   ── recursively aggregates all tx proofs of a block
  └──────────────────────────────────────────────────────────┘
```

### 4.1 AIR — the "computation table"

An AIR (Algebraic Intermediate Representation) is a table in which
each column is one intermediate quantity of the computation and each
row is one step. The rules of the computation become **algebraic
constraints**: "this cell must equal the sum of two others", "this
flag must be zero or one", "these two cells must be equal".

In Paranoid, AIRs are built for:

- value addition (`balance_gate`);
- range-validity of values (`range_gate`, ensuring `value < 2^64`);
- deriving an address from a secret (`haddr`);
- binding a signature to the tx body (`hauth`);
- opening state-tree cells out of the state Merkle tree
  (`fri_state_open`);
- S-box and MDS steps of Poseidon2b used by the remaining in-AIR
  hashes: HAddr, HAuth, FRI-state-combiner.

The 59-permutation Poseidon2b **spine** that compresses the tx body
into `tx_body_hash` is no materialised inside any STARK AIR.
It is proven end-to-end by GKR (see §4.2). On the STARK
side of the former merkle band is exactly two lanes — the two field
elements of `tx_body_hash` — row-pinned via `PublicColumn`.

Each AIR is a rigorous, verifiable table. Their composition, together
with the GKR sub-protocol, covers the whole transaction.

### 4.2 GKR — the "fast hash engine"

A Poseidon2b permutation is expensive: 66 rounds of S-box and MDS per
permutation, and a single transaction performs dozens of them. If the
STARK were to unroll every permutation row-by-row into its trace, the
proof would grow linearly in the number of hashes. That is exactly why
the 59-permutation tx-body spine has been lifted out of the STARK
trace and into a dedicated GKR sub-protocol. This is the
**production — and only — path**: there is no `gkr-spine` cargo
feature, and the former in-AIR spine has been retired from the default
build surface.

GKR (Goldwasser–Kalai–Rothblum) is a **separate sumcheck protocol**
optimised for repetitive arithmetic circuits. It proves both:

- the **59-permutation tx-body spine** (tx_body_hash derivation);
- the **20-slot auth circuit** (4 inputs × 5 Poseidon2b sponges each:
  HAddr + HAuth per input).

Both use the **Kill-Shot** protocol: a single unified degree-7
sumcheck over ALL slots simultaneously, followed by a shift argument
that links the cross-slot state→s_in transitions. This replaces the
former per-slot PermProof chain with two compact proof objects:
`SpineProofKillShot` and `AuthProofKillShot`.

```
    spine output (tx_body_hash)         auth outputs (Address, AuthTag)
              ▲                                   ▲
              │   unified sumcheck + shift         │   unified sumcheck + shift
              │                                   │
       ┌──────┴──────┐                     ┌──────┴──────┐
       │  59 slots   │                     │  20 slots   │
       │  15-var MLE │                     │  14-var MLE │
       └──────┬──────┘                     └──────┬──────┘
              │                                   │
    spine inputs (tx-body leaves)     auth inputs (secret, tx_body_hash)
```

The payoff:

- **proof size** of the hashing part becomes poly-logarithmic rather
  than linear in the number of hashes;
- **prover speed** — the prover works on multilinear extensions (MLEs)
  rather than a full trace;
- **binding to the STARK** — GKR does not live in a vacuum. Its input
  boundary (`59 × state_in`, concatenated into a 2^15-cell multilinear)
  is committed by the STARK as a dedicated boundary MLE and discharged
  via a single-point FRI opening `(r_B, v_B)`. Its output — two lanes
  of `tx_body_hash` — equals the `PublicColumn` pin in the AIR. A
  single Fiat–Shamir transcript: the flattened bytes of the GKR
  sub-proof are fed into the STARK transcript through the
  `extra_transcript` hook, positioned between column-root absorption
  and the draw of the zero-check point. Any byte-level tamper forks
  every subsequent STARK challenge.

Internal structure of the implementation (detailed specification:
`noid_gkr/SPEC.md` and `noid_gkr/AUDIT.md`):

```
  circuit.rs            Static 59-slot spine topology, read from
                        noid_air::airs::tx_body_merkle::layout.
  auth_circuit.rs       Static 20-slot auth topology (4 inputs ×
                        5 sponges: HAddr + HAuth per input).
  oracle.rs             Reference execution via noid_poseidon2b::native.
  auth_oracle.rs        Auth-side reference execution.
  layers.rs             Layered witness of a single permutation:
                        columns state / sin / x2 / x3 / x4 / sout.
  mle_layout.rs         MLE packing: 9 variables (spine), 512 cells/slot.
  spine_unified_v2.rs   Unified degree-7 sumcheck over all 59 spine
                        slots simultaneously (replaces per-slot PermProof).
  spine_shift.rs        Shift argument: proves state(x)→s_in(x⊕1)
                        linking across slots.
  spine_killshot.rs     Kill-Shot orchestrator (spine): unified + shift
                        + 3× batch-eval → SpineProofKillShot.
  auth_unified_v2.rs    Unified degree-7 sumcheck over all 20 auth slots.
  auth_shift.rs         Auth-side shift argument.
  auth_killshot.rs      Kill-Shot orchestrator (auth): unified + shift
                        + 3× batch-eval → AuthProofKillShot.
  batch_eval.rs         γ₂ primitive: RLC + degree-2 sumcheck,
                        collapses M point-value claims into (r_B, v_B).
  binding.rs            In-code contract for the STARK ↔ GKR cut.
```

### 4.3 STARK + FRI — the "final seal"

Once the AIR traces are filled and GKR has folded the 59-hash spine
into a single claim on its boundary MLE, the STARK performs the final
step:

1. Rolls all AIR constraints into one large polynomial.
2. Reed–Solomon-encodes it (oversampled on an extended domain).
3. Proves via **FRI** that the result really is a low-degree polynomial
   (which in turn guarantees that every constraint is satisfied).
4. Fiat–Shamir (Poseidon2b transcript) turns the entire interaction
   into a non-interactive proof.

FRI in Paranoid runs on top of the **binary tower GF(2^128)**, with
CLMUL-accelerated multiplication and AVX2-SIMD squaring. Commitments
are Poseidon2b Merkle trees over packed columns (128× bits, 16× bytes).

### 4.4 IVC — the "recursive block accumulator"

One `tx` produces one proof. A block contains hundreds of them. IVC
(Incrementally Verifiable Computation) linearly folds them into a
single final object:

```
  P1 ─┐
  P2 ─┤
  P3 ─┼─► fold_step ─► fold_step ─► ... ─► BlockProof
  ... ┤
  Pn ─┘
```

Each `fold_step`:

- commits to the column of the next `tx`;
- opens it at a shared point `z`;
- mixes in the Fiat–Shamir challenge `α`;
- updates the accumulator: `y_acc += α · y`.

`decide` at the end replays the entire transcript and checks that the
accumulator converges. Soundness is Schwartz–Zippel in `α`.

Consequence: **a fresh node synchronises with a single proof**. It
downloads the latest header and the latest recursive proof, and
obtains cryptographic certainty over the full chain history.

### 4.5 Recursive chain of proofs

A `BlockProof` does not live in isolation. Every new block verifies
the previous recursive accumulator:

```
  Proof_{n+1} verifies Proof_n
```

Consequence: the chain is not merely a sequence of blocks — it is a
recursive chain of correctness proofs.

The latest proof implicitly attests:

- every historical transaction;
- every state transition;
- every historical state_root;
- the correctness of the entire chain from genesis.

A fresh node synchronises as follows:

1. downloads the latest block header;
2. downloads the latest recursive proof;
3. runs a single verification procedure.

After that, the node has cryptographic certainty over the whole
history of the network.

Historical verification complexity in Paranoid is therefore:

```
  O(1)
```

relative to the length of the chain.

The network does not replay history and does not re-execute
transactions — it verifies a recursively accumulated correctness
proof.

### 4.6 Transaction validity vs chain validity

It matters to distinguish two levels of correctness in Paranoid.

#### Transaction validity

A per-`tx` proof guarantees the local correctness of one state
transition:

```
  (prev_root_i, tx_i) → new_root_i
```

The proof establishes:

- ownership;
- balance conservation;
- correctness of state openings;
- correctness of the post-state;
- correctness of the computation of `new_root_i`.

In short: an individual transaction is mathematically correct in
isolation.

#### Chain validity

Chain correctness, however, demands more.

It is not enough that every `tx` be individually valid. The
transitions must also form one continuous evolution of state.

A `BlockProof` guarantees, across the ordered transition sequence of
the block:

```
  new_root_i == prev_root_{i+1}
```

That is:

```
  root_0 --tx1--> root_1
  root_1 --tx2--> root_2
  root_2 --tx3--> root_3
```

forms one continuous state-evolution graph.

#### Stateful recursive accumulation

IVC in Paranoid does not merely aggregate a list of proofs. The
recursion operates over:

```
  validated state transitions
```

Each `fold_step` checks:

- correctness of the next `tx` proof;
- continuity of state roots;
- absence of conflicting transitions;
- correctness of the accumulator state.

Consequently a `BlockProof` certifies not only that

```
  all tx proofs are valid
```

but also that

```
  all tx proofs form one coherent global state evolution
```

---

## 5. What happens at every level, on one page

```
  ┌─────────────────────────────────────────────────────────────┐
  │ LEVEL 1 — USER                                              │
  │   "Send 10 to Bob"                                          │
  │   wallet picks slot 101; asks node for free slots 200, 500  │
  └────────────────────────┬────────────────────────────────────┘
                           ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ LEVEL 2 — TX ASSEMBLY                                       │
  │   tx_body = { inputs, outputs, fee }                        │
  │   tx_body_hash = Poseidon2b spine(tx_body)  (59 hashes)     │
  └────────────────────────┬────────────────────────────────────┘
                           ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ LEVEL 3 — WITNESS GENERATION (local to the wallet)          │
  │   AIR traces: balance, range, fri_state_open,               │
  │               tx_body_spine (2-lane pin), tx_validity       │
  │   GKR witness: 59 × spine perms + 20 × auth perms          │
  │   boundary MLEs: spine (2^15 cells) + auth (2^14 padded→2^15)│
  └────────────────────────┬────────────────────────────────────┘
                           ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ LEVEL 4 — PROVING  (noid_stark::prove_tx)                   │
  │   SpineGKR Kill-Shot: unified sumcheck + shift over 59 slots│
  │          → (SpineProofKillShot, (r_B, v_B))                 │
  │   AuthGKR Kill-Shot:  unified sumcheck + shift over 20 slots│
  │          → (AuthProofKillShot, (r_B, v_B))                  │
  │   STARK: AIR constraints → polynomial → FRI; both boundary  │
  │          MLEs ride as ExtraColumns in multipoint-close;      │
  │          both KS bytes feed extra_transcript before the      │
  │          zero-check draw (spine first, auth second)         │
  │   → per-tx TxProof                                          │
  └────────────────────────┬────────────────────────────────────┘
                           ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ LEVEL 5 — NETWORK                                           │
  │   (prev_root, tx_body, new_root, proof) → mempool           │
  │   node validates; resolves conflicts by tx_body_hash        │
  └────────────────────────┬────────────────────────────────────┘
                           ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ LEVEL 6 — BLOCK ASSEMBLY                                    │
  │   stateful IVC fold:                                        │
  │                                                             │
  │     (R0→R1), (R1→R2), ..., (Rn-1→Rn)                        │
  │                  ↓                                          │
  │               BlockProof                                    │
  │                                                             │
  │   continuity checks:                                        │
  │     new_root_i == prev_root_{i+1}                           │
  │                                                             │
  │   PoW: header + nonce                                       │
  │   broadcast block                                           │
  └────────────────────────┬────────────────────────────────────┘
                           ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ LEVEL 7 — VERIFICATION                                      │
  │   any node checks:                                          │
  │     • PoW                                                   │
  │     • BlockProof (one recursive verify)                     │
  │     • state_root_next matches the result of the transitions │
  └─────────────────────────────────────────────────────────────┘
```

---

## 6. Inputs / outputs of the key modules

| Module | Inputs | Outputs | Role |
|---|---|---|---|
| `noid_core` | — | GF(2^128), MLE, sumcheck, FS transcript, NTT | Algebraic foundation. |
| `noid_poseidon2b` | state `[B;4]` | permuted state, digest | Hash function used everywhere in the system. |
| `noid_fri` | polynomial over a domain | FRI proof, Merkle openings | Low-degree proximity test. |
| `noid_binius` | bit / byte columns | packed commitment | 128× DA savings via bit-packing. |
| `noid_air` | semantic inputs | tables + constraints | Per-`tx` logic encoded as AIRs. |
| `noid_gkr` | 59 × perm witness (spine) + 20 × perm witness (auth) | `SpineProofKillShot` + `AuthProofKillShot` + `(r_B, v_B)` reductions | Kill-Shot GKR: proves spine + auth outside the STARK trace. |
| `noid_stark` | AIR traces + GKR reductions | per-`tx` `TxProof` | Engine: STARK seal + `prove_tx` / `verify_tx` orchestrator. |
| `noid_ivc` | per-`tx` proofs | `BlockProof` | Recursive block accumulator. |
| `noid_tx` | high-level tx | `tx_body`, `tx_body_hash` | Transaction serialisation. |
| `noid_chain` | blocks + state | state transitions, DA, wire | Chain layer (state, blocks, DA). Does NOT depend on `noid_stark`. |

---

## 7. Why this architecture is not accidental

Seven properties follow directly from the design:

1. **Proof-native ledger.** The ledger stores not "intents to execute"
   (as an EVM chain does) but **already-proven transitions**. The
   validity of every `tx` is established before it enters a block.

2. **Miners aggregate proofs, they do not execute.** Miners verify
   `tx` proofs, resolve conflicts, recursively aggregate proofs into a
   `BlockProof`, and seal the result with PoW. There is no VM.
   Execution time no longer gates block production; verification stays
   permanently cheap.

3. **O(1) historical verification.** A fresh node verifies a single
   recursive proof and knows everything back to genesis. No "replay
   all blocks".

4. **Deterministic fixed-slot state.** The Patricia/trie is replaced by
   a vector with a canonical zero. This makes rolling updates
   algebraically clean and recursion tractable.

5. **Prover parallelism.** Transactions with disjoint input/output
   slots are proven independently. Consensus remains sequential —
   these are two separate planes.

6. **Recursive validity accumulation.** Every new `BlockProof` verifies
   the previous one. Network history is recursively compressed into a
   single accumulating proof. Verifying the latest proof attests the
   correctness of the whole chain since genesis.

7. **Execution separation.** Execution in Paranoid runs locally at the
   prover, before a `tx` ever reaches the network. The consensus layer
   never runs computation — it only:

   - verifies validity proofs;
   - orders transitions;
   - aggregates recursive state proofs;
   - anchors canonical history via PoW.

   That splits, radically,

   ```
   execution
   validity
   consensus
   ```

   into three independent layers of the system.

---

## 8. What is done, what is ahead

**Done:**

- Poseidon2b native + AIR encoding.
- AIRs: `balance_gate`, `range_gate`, `haddr`, `hauth`,
  `fri_state_open`, `tx_body_spine` (carrying only the 2-lane
  `tx_body_hash` pin), `tx_validity`, plus the composition layer.
- FRI over GF(2^128) with Poseidon2b Merkle commitments.
- STARK per-`tx` proof (stages 5–7 end-to-end roundtrip).
- IVC fold accumulator (3-step fold test passes).
- GKR spine Kill-Shot (production path): unified degree-7 sumcheck
  over all 59 slots + shift argument + 3× batch-eval →
  `SpineProofKillShot`. Bound to STARK via `extra_transcript` +
  boundary MLE FRI opening.
- GKR auth Kill-Shot: unified degree-7 sumcheck over all 20 auth
  slots (4 inputs × 5 sponges) + shift + 3× batch-eval →
  `AuthProofKillShot`. Same STARK binding pattern.
- Production orchestrator (`noid_stark::prove_tx`): single-transcript
  flow SpineGKR KS → AuthGKR KS → STARK with both boundary MLEs
  as `ExtraColumn`s in the mixed multipoint close.

**Ahead:**

- `BlockProof` pipeline (IVC composition over per-`tx` proofs).
- Recursive chain-of-proofs (`proof_{n+1}` verifies `proof_n`).
- Fee market and the final mempool conflict-resolution rules.

---

## 9. In one sentence

> Paranoid is a proof-native PoW chain in which every transaction
> arrives already proven. The network does not execute code — it
> verifies mathematics. Miners aggregate recursive proofs, PoW sets the
> canonical ordering, and recursion compresses the entire history of
> the network into one proof.

---

# Appendix A — AIR and GKR data flow

This appendix expands "LEVEL 3 — WITNESS GENERATION" from §5. It shows
how the **semantic inputs** of a transaction fan out through the
sub-AIRs, where the GKR spine sub-proof branches off, where the
intermediate witnesses arise, and how everything converges on the
final public inputs (`prev_root`, `new_root`, `tx_body_hash`, and
balance-OK).

Arrows represent flows of typed witness values (columns / cells).
"pin" edges are **boundary equality constraints**: two cells in
different sub-AIRs must contain the same value.

## A.1 Transaction inputs

```
                         ┌──────────────────────────────────┐
                         │         TX SEMANTIC INPUTS       │
                         │                                  │
                         │  prev_root       (public)        │
                         │  new_root        (public)        │
                         │  per-input:                      │
                         │     secret_i                     │
                         │     slot_index_i                 │
                         │     value_i, owner_hi/lo_i       │
                         │     merkle_path_i (prev)         │
                         │  per-output:                     │
                         │     slot_index_j                 │
                         │     value_j, owner_hi/lo_j       │
                         │     merkle_path_j (new)          │
                         │  fee                             │
                         └──────────────┬───────────────────┘
                                        │
              ┌─────────────────────────┼─────────────────────────┐
              ▼                         ▼                         ▼
        (ownership)              (state opening)             (balance)
```

## A.2 Fan-out across sub-AIRs

```
  ┌──────────────┐    ┌──────────────────┐    ┌──────────────────┐
  │   HADDR      │    │   FRI_STATE_OPEN │    │   BALANCE_GATE   │
  │              │    │                  │    │                  │
  │ in:          │    │ in:              │    │ in:              │
  │  secret_i    │    │  prev_root       │    │  value_i (ins)   │
  │              │    │  slot_index_i    │    │  value_j (outs) │
  │ Poseidon2b   │    │  merkle_path_i   │    │  fee             │
  │ sponge →     │    │                  │    │                  │
  │  addr_i =    │    │ per-level hash   │    │ Σ ins ==         │
  │  (oh_i,ol_i) │    │ reconstruction → │    │ Σ outs + fee     │
  │              │    │  (value, oh, ol) │    │                  │
  │              │    │  at slot         │    │ + range gate     │
  │ also checks  │    │                  │    │ (value < 2^64)   │
  │ addr==owner_i│    │                  │    │                  │
  └──────┬───────┘    └────────┬─────────┘    └────────┬─────────┘
         │                     │                       │
         │ owner_hi/lo         │ (value, oh, ol)       │ balance_ok
         │ per input           │ per input             │
         ▼                     ▼                       ▼
   ┌────────────────────────────────────────────────────────────┐
   │                    TX_VALIDITY  (composite)                │
   │                                                            │
   │   per-input row i:                                         │
   │     AuthTag_i, Value_i, OwnerHi_i, OwnerLo_i, SlotIndex_i  │
   │   per-output row k:                                        │
   │     Value_k, OwnerHi_k, OwnerLo_k                          │
   │                                                            │
   │   enforces:                                                │
   │     T1a  HADDR.addr    == TxValidity.owner  (per input)    │
   │     T1b  FriOpen.row   == TxValidity.row    (per input)    │
   │     T2a  HAUTH.tag     == TxValidity.AuthTag               │
   │     T2b  HAUTH.absorb2 == tx_body_hash                     │
   │     T3   is_mint ⇒ pre == 0                                │
   │     T4   balance_gate holds                                │
   └───────────────────────────┬────────────────────────────────┘
                               │
                               │  needs tx_body_hash
                               ▼
```

## A.3 `tx_body_hash` — lives entirely inside GKR

```
  ┌────────────────────────────────────────────────────────────┐
  │                 TX-BODY SPINE (GKR sub-proof)              │
  │                                                            │
  │   Structure (noid_gkr::circuit::SpineCircuit, 59 slots):   │
  │     4 input-leaf perms    (hash_input_leaf)                │
  │     8 output-leaf perms   (hash_output_leaf, A+B per out)  │
  │    15 compress perms      (Merkle fold)                    │
  │     1 wrap perm           (TAG_TXBODY)                     │
  │    ────────────────────                                    │
  │    59 Poseidon2b permutations total                        │
  │                                                            │
  │   SpineInputs (the cut's boundary):                        │
  │     prev_state_root, fee_leaf, 4 input-leaf payloads,      │
  │     8 output-leaf payloads, is_coinbase_leaf, pad_leaf     │
  │                                                            │
  │   Protocol (Kill-Shot):                                     │
  │     unified sumcheck  : one degree-7 sumcheck over ALL 59  │
  │                         slots simultaneously (15-var MLE). │
  │                         Squeezes ρ, β, γ; produces 12      │
  │                         final witness scalars.             │
  │     shift argument    : proves state(x) == s_in(x⊕1)      │
  │                         across slot boundaries (15 rounds).│
  │     3× batch-eval     : state claims, s_in claims,         │
  │                         s_out claims → (r_B, v_B) per col. │
  │     wrap pin          : wrap.state_out[0..1] ==            │
  │                         claimed_tx_body_hash               │
  │                                                            │
  │   Binding to the STARK (the only interface):               │
  │     • two lanes of tx_body_hash → `PublicColumn` in the    │
  │       AIR (noid_air::airs::tx_body_spine; columns          │
  │       TXBODY_MERKLE_LAYOUT.s and .s+1)                     │
  │     • boundary MLE committed by the STARK via FRI; its     │
  │       root is absorbed into the spine channel before the   │
  │       draw of r_B                                          │
  │     • flattened SpineProofKillShot bytes feed the STARK    │
  │       `extra_transcript` hook between column-root          │
  │       absorption and the zero-check point draw             │
  │     • the opening (r_B, v_B) is discharged by a FRI        │
  │       opening of the boundary MLE inside multipoint-close  │
  └───────────────────┬────────────────────────────────────────┘
                      │ tx_body_hash
                      ▼
  ┌────────────────────────────────────────────────────────────┐
  │              AUTH GKR (Kill-Shot sub-proof)                 │
  │                                                            │
  │   Structure (noid_gkr::auth_circuit::AuthCircuit):         │
  │     4 inputs × 5 Poseidon2b sponges each = 20 slots:      │
  │       HAddr: absorb(secret) → squeeze → Address            │
  │       HAuth: absorb(secret, tx_body_hash) → squeeze →      │
  │              AuthTag                                        │
  │                                                            │
  │   AuthInputs:                                              │
  │     spend_secret[i], tx_body_hash,                         │
  │     expected_address[i], expected_auth_tag[i]              │
  │                                                            │
  │   Protocol (Kill-Shot, same as spine):                     │
  │     unified sumcheck over ALL 20 slots (14-var MLE)        │
  │     + shift argument + 3× batch-eval                       │
  │     → AuthProofKillShot + (r_B, v_B)                       │
  │                                                            │
  │   Privacy: spend_secret is witness-only, never absorbed    │
  │   into the transcript. Verifier sees only the public       │
  │   expected_address and expected_auth_tag values.           │
  │                                                            │
  │   Binding: same pattern as spine — boundary MLE committed  │
  │   via FRI, (r_B, v_B) discharged by STARK multipoint-close │
  └──────────┬─────────────────────────────────────────────────┘
             │ Address_i, AuthTag_i
             ▼
       back to TX_VALIDITY (T1a: addr==owner, T2a: AuthTag)
```

## A.4 State commitments and final roots

```
       FRI_STATE_OPEN (prev)                 FRI_STATE_OPEN (new)
              │                                      │
              │ opened subtrees                      │ opened subtrees
              ▼                                      ▼
       ┌────────────────┐                    ┌────────────────┐
       │ FRI_STATE_     │                    │ FRI_STATE_     │
       │ COMBINER_COMP  │                    │ COMBINER_COMP  │
       │  (prev side)   │                    │  (new side)    │
       │                │                    │                │
       │ recombines     │                    │ recombines     │
       │ opened cells   │                    │ opened cells   │
       │ into digest →  │                    │ into digest →  │
       │ prev_root*     │                    │ new_root*      │
       └───────┬────────┘                    └───────┬────────┘
               │                                     │
               │  pin: prev_root* == prev_root       │
               │                                     │  pin: new_root* == new_root
               ▼                                     ▼
         PUBLIC INPUT                          PUBLIC INPUT
          prev_root                              new_root
```

## A.5 End-to-end path of one transaction (collapse view)

```
  semantic tx
      │
      ├──► HADDR ───────────────► owner pin ──┐
      │                                        │
      ├──► FRI_STATE_OPEN(prev) ─► value/owner ┤
      │                            / slot pins │
      │                                        ▼
      ├──► BALANCE_GATE ─────────► TX_VALIDITY ◄── AuthTag ──┐
      │                                 │                     │
      ├──► GKR spine sub-proof          │                     │
      │        │                        │                     │
      │        │ tx_body_hash (via the  │                     │
      │        │ PublicColumn pin in    │                     │
      │        │ the AIR)               │                     │
      │        │                        │                     │
      │        └──► HAUTH ──────────────┘─────────────────────┘
      │
      ├──► FRI_STATE_OPEN(new) ─► post-state cells
      │                                │
      │                                ▼
      │                    FRI_STATE_COMBINER(new) ──► new_root pin
      │
      └──► (all of the above folded into one STARK polynomial,
            committed via FRI over GF(2^128), Fiat–Shamir'd)
                                 │
                                 ▼
                           per-tx PROOF
                                 │
                                 ▼
                    IVC fold  →  BlockProof  →  PoW  →  CHAIN
```

## A.6 Legend

- **A named rectangle** — a sub-AIR (a table plus its constraints).
- **`→` arrow** — a flow of witness values (a column or a cell).
- **`pin: X == Y`** — a boundary equality constraint between two
  sub-AIRs; the composition `tx_validity_full` closes all such pins.
- **GKR sub-proof** — a separate sumcheck prover that does not live in
  the STARK trace. Its **only** outgoing surface is the two lanes of
  `tx_body_hash`, row-pinned as a `PublicColumn` in
  `noid_air::airs::tx_body_spine`. Its input boundary (59 ×
  `state_in`) is committed by the STARK as a boundary MLE and
  discharged by a FRI opening at a single point `(r_B, v_B)`. The
  flattened bytes of the sub-proof feed the STARK transcript via
  `extra_transcript`.
- **public input** — a value the verifier sees directly, without a
  witness.

## A.7 Where things live in the code

```
  HADDR                 noid_air::airs::haddr  (in-AIR only for
                        the PublicColumn pin; actual hash proven
                        by auth GKR Kill-Shot)
  HAUTH                 (proven by auth GKR Kill-Shot; no longer
                        a separate in-AIR sponge)
  BALANCE_GATE          noid_air::airs::balance_gate
  RANGE_GATE            noid_air::airs::range_gate
  FRI_STATE_OPEN        noid_air::airs::fri_state_open
  FRI_STATE_COMBINER    noid_air::airs::fri_state_combiner[_composite]
  TX-BODY SPINE pin     noid_air::airs::tx_body_spine
                        (the two PublicColumn lanes of tx_body_hash;
                         the topology layout lives in
                         noid_air::airs::tx_body_merkle::layout
                         and is consumed by the GKR crate)
  TX_VALIDITY           noid_air::airs::tx_validity
                        + noid_air::composition::tx_validity_full
                        + noid_air::composition::
                          tx_validity_with_spine
  POSEIDON (SBOX/MDS)   noid_air::airs::poseidon_{sbox,mds,perm}
  GKR spine Kill-Shot   noid_gkr::spine_killshot
                        (spine_unified_v2, spine_shift,
                         batch_eval, circuit, layers, mle_layout)
  GKR auth Kill-Shot    noid_gkr::auth_killshot
                        (auth_unified_v2, auth_shift,
                         auth_circuit, auth_oracle)
  prove_tx / verify_tx  noid_stark::prove_tx  (production
                        orchestrator: spine KS → auth KS → STARK)
  STARK engine          noid_stark  (prove_air, spine bridge,
                        auth bridge, multipoint close)
  FRI                   noid_fri
  Packing / DA          noid_binius
  IVC                   noid_ivc
  Chain state machine   noid_chain  (blocks, state, DA, wire;
                        does NOT depend on noid_stark or noid_gkr)
```

The registry of pinned columns through which the composition is held
together lives in `noid_air::composition::registry`: `HAddrCols`,
`HAuthCols`, `TxValidityCols`, `FriStateOpenCols`, `TxBodyMerkleCols`
(the map of the 2-lane `tx_body_hash` pin), and
`CombinerCompositeCols`.

---

# Architectural identity

Paranoid does not belong to any of the classes:

- smart-contract chains;
- zkEVMs;
- optimistic rollups.

Paranoid is:

```
  a recursively accumulated proof-native PoW ledger
  where:

    execution is local
    validity  is global
    ordering  is PoW
    history   is recursive
```

That is:

- execution runs locally at the prover;
- consensus only orders transitions;
- validity is proven before inclusion into a block;
- miners aggregate proofs instead of replaying execution;
- the entire history of the network is recursively compressed into a
  single validity object.

The network does not validate instructions to be executed — it
validates proofs of computation already correctly performed.

Ethereum-like systems store:

```
  what should be executed
```

Paranoid stores:

```
  proof that execution already happened correctly
```
