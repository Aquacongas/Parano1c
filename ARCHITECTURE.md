# Paranoid Engine — How It Works

This document describes the Paranoid chain engine end-to-end: from the
user pressing **Send** in a wallet to the block that settles the
transaction on chain. It is written so that both an engineer and a
reader without a cryptographic background can follow it. Components
are presented top-down — from UX down to the underlying mathematics.

---

## 1. One-line picture

```
  wallet  ──►  LogicProof  ──►  mempool  ──►  miner  ──►  BlockProof  ──►  chain
                   ▲                            │
                   │                            ├── BlockStateBinding (Merkle proofs)
               (GKR + STARK)                    ├── deferred-FRI aggregation
                                                └── PoW seal
```

The user builds a **LogicProof** locally that asserts the transaction's
math is correct (balance, ownership, range). The miner adds a
**BlockStateBinding** proving that claimed slot values exist in the
state tree. Together they form the **BlockProof**. The network never
"executes" transactions — it verifies mathematics.

---

## 2. What the state looks like

State is a flat shelf of `2^log_slots` cells (initially 2^24 ≈ 16 M).
Each cell stores a triple:

```
  slot[i] = (value, owner_hi, owner_lo)
```

An empty cell is the canonical zero `(0, 0, 0)`. The root of all cells
is `state_root` — a Poseidon2b Merkle tree over segment FRI roots
(§11). It is written into the block header.

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

### 3.2 The wallet builds the LogicProof

This is the heart of the system. The wallet assembles a **LogicProof**
locally that attests only to the MATHEMATICAL correctness of the
transaction:

```
  ownership        │ Alice knows the secret for owner of slot 101
  balance          │ Σ inputs == Σ outputs + fee
  range            │ all values < 2^64
  body binding     │ tx_body_hash correctly computed (SpineGKR)
  claims binding   │ C_claimed commits to specific slot values
```

The LogicProof does NOT prove:
- That slot 101 actually contains (100, Alice) in the state tree.
- That slots 200 and 500 are actually empty.
- Any Merkle-path computation.

This separation means the LogicProof is **stateless**: it remains valid
across new blocks as long as the epoch_anchor hasn't expired and
nobody has spent the same input slots.

### 3.3 Broadcasting

```
  (tx_body, logic_proof, claims_commitment, claimed_slots)
```

**Without the secret. Without state roots.** The node verifies the
LogicProof and checks claimed slots against native state → admits to
the mempool. State binding is done by the miner at block assembly.

### 3.4 The Full Node assembles a block

Block assembly is a core function of the Full Node (not a separate
actor). The Full Node performs three sub-roles during block production:

- **state prover** (generates BlockStateBinding);
- **proof aggregator** (combines LogicProofs + state binding);
- **PoW coordinator** (pushes header to built-in or external miner).

The Full Node:

- pulls TxIntents (LogicProofs) from the mempool;
- verifies each LogicProof;
- resolves conflicts between competing slot claims;
- orders the transactions;
- generates BlockStateBinding (proves Merkle openings for all slots);
- aggregates LogicProofs + BlockStateBinding into one `BlockProof`;
- computes the resulting `state_root` and `da_root`;
- forms the 248-byte header and pushes it to the miner (built-in or
  external via Block Template API).

```
  TxIntents (LogicProofs)
      │
      ▼
  validation + conflict resolution
      │
      ▼
  ordering (deterministic)
      │
      ▼
  BlockStateBinding (Full Node proves state)
      │
      ▼
  aggregation (deferred-FRI)
      │
      ▼
  BlockProof + state_root + da_root
      │
      ▼
  form header (248 bytes)
      │
      ├──► built-in miner (CPU/GPU)
      │         OR
      └──► Block Template API → external miner (GPU/ASIC)
              │
              ▼
         valid nonce returned
              │
              ▼
         seal + broadcast block
```

PoW in Paranoid does not protect execution of transactions.
The correctness of execution is already established cryptographically.

PoW solves a different problem:

- it picks a canonical ordering of transitions;
- it makes reorgs expensive;
- it produces an objective history of the network;
- it anchors the recursive proof chain.

The Full Node is: **state prover + proof aggregator + PoW coordinator.**

The mining pipeline is asynchronous: CPU generates BlockProof (1-3s),
then pushes the header to the miner (built-in or external) who
brute-forces the nonce. The external miner cannot modify block content
(coinbase is locked in the proof). See `SPECIFICATION.md` §7.1-7.2.

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
  (`fri_state_open` — block-level in the new design);
- S-box and MDS steps of Poseidon2b used by the remaining in-AIR
  hashes.

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

### 4.3 STARK + FRI-Binius — the "final seal"

Once the AIR traces are filled and GKR has folded the 59-hash spine
into a single claim on its boundary MLE, the STARK performs the final
step:

1. Rolls all AIR constraints into one large polynomial.
2. Reed–Solomon-encodes it (oversampled on an extended domain).
3. Proves via **FRI-Binius** that the result really is a low-degree
   polynomial (which in turn guarantees that every constraint is
   satisfied).
4. Fiat–Shamir (Poseidon2b transcript) turns the entire interaction
   into a non-interactive proof.

FRI-Binius runs on top of the **binary tower GF(2^128)**, with
CLMUL-accelerated multiplication and AVX2-SIMD squaring. Commitments
are Poseidon2b Merkle trees over interleaved packed columns. The PCS
supports mixed-length columns (log_len=13 for the AIR trace, log_len=15
for boundary MLEs) batched into a single multipoint-close opening.

**Measured performance (per-tx, 2in/4out, single-thread):**
- Prove: ~725 ms
- Verify: ~145 ms
- Proof size: ~55 KB

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

#### Transaction validity (LogicProof)

A per-tx LogicProof guarantees the local correctness of transaction
logic:

```
  (epoch_anchor, tx_body, C_claimed) → proof that math is correct
```

The proof establishes:

- ownership (AuthGKR);
- balance conservation;
- range validity;
- body commitment (SpineGKR);
- claims binding (C_claimed in Fiat-Shamir).

A LogicProof does NOT establish state correctness — that is deferred
to BlockStateBinding.

#### State validity (BlockStateBinding)

The miner's BlockStateBinding proves:

```
  (prev_block_state_root, claimed_slots, C_claimed) →
      all openings match, outputs empty, post-state correct
```

#### Chain validity (BlockProof)

A `BlockProof` combines both layers plus IVC accumulation:

1. All LogicProofs are valid (algebraic correctness).
2. BlockStateBinding is valid (state correctness).
3. C_claimed bridge holds (LogicProof claims == state openings).
4. Global state evolution is coherent:
   `prev_block_state_root → apply txs → new_block_state_root`.

Consequently a `BlockProof` certifies:

```
  (a)  all transaction logic is valid
  (b)  all state claims are correct
  (c)  the bridge between (a) and (b) is sound
  (d)  the global state evolution is coherent
```

---

## 5. What happens at every level, on one page

```
  ┌─────────────────────────────────────────────────────────────┐
  │ LEVEL 1 — USER                                              │
  │   "Send 10 to Bob"                                          │
  │   wallet picks slot 101; asks node for free slots 200, 500  │
  │   wallet gets epoch_anchor from node (hash of block at h-6) │
  └────────────────────────┬────────────────────────────────────┘
                           ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ LEVEL 2 — TX ASSEMBLY                                       │
  │   tx_body = { inputs, outputs, fee, epoch_anchor }          │
  │   tx_body_hash = Poseidon2b spine(tx_body)  (59 hashes)     │
  │   C_claimed = Poseidon2b_sponge(all claimed slot data)      │
  └────────────────────────┬────────────────────────────────────┘
                           ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ LEVEL 3 — WITNESS GENERATION (local to the wallet)          │
  │   AIR traces: balance, range, tx_body_spine (2-lane pin),   │
  │               tx_logic (no fri_state_open!)                 │
  │   GKR witness: 59 × spine perms + 20 × auth perms          │
  │   boundary MLEs: spine (2^15) + auth (2^14 padded→2^15)     │
  │   C_claimed absorbed into Fiat-Shamir channel               │
  └────────────────────────┬────────────────────────────────────┘
                           ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ LEVEL 4 — PROVING  (noid_stark::prove_logic)                │
  │   SpineGKR Kill-Shot: unified sumcheck + shift over 59 slots│
  │          → (SpineProofKillShot, (r_B, v_B))                 │
  │   AuthGKR Kill-Shot:  unified sumcheck + shift over 20 slots│
  │          → (AuthProofKillShot, (r_B, v_B))                  │
  │   STARK: TxLogicAir → polynomial → FRI; both boundary       │
  │          MLEs ride as ExtraColumns in multipoint-close       │
  │   → per-tx LogicProof (~300-400ms, ~45 KB)                  │
  └────────────────────────┬────────────────────────────────────┘
                           ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ LEVEL 5 — NETWORK                                           │
  │   TxIntent = (tx_body, logic_proof, C_claimed, claimed_slots)│
  │   NO state roots in broadcast payload                        │
  │   node validates: verify LogicProof (~3ms), check           │
  │   epoch_anchor, check nullifier, native slot verify         │
  │   → admit to mempool                                        │
  └────────────────────────┬────────────────────────────────────┘
                           ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ LEVEL 6 — BLOCK ASSEMBLY (miner, CPU, 1-3s)                 │
  │                                                             │
  │   BlockStateBinding: miner opens Merkle paths for all       │
  │   touched slots, proves pre-state + post-state + bridge     │
  │                                                             │
  │   Aggregation: LogicProofs + BlockStateBinding via           │
  │   deferred-FRI → single opening → BlockProof                │
  │                                                             │
  │   State: prev_block_state_root → apply all → new_state_root │
  │   DA: coinbase + tx_bodies → da_root                        │
  │                                                             │
  │   PoW: push 248-byte header to GPU/ASIC                     │
  │   On valid nonce: broadcast block                           │
  └────────────────────────┬────────────────────────────────────┘
                           ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ LEVEL 7 — VERIFICATION                                      │
  │   any node checks:                                          │
  │     • PoW valid                                             │
  │     • All LogicProofs verify                                │
  │     • BlockStateBinding verifies                            │
  │     • C_claimed bridge matches (per tx)                     │
  │     • Epoch anchors within window                           │
  │     • No nullifier conflicts                                │
  │     • state_root matches, da_root matches                   │
  │     • BlockProof (IVC decide)                               │
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
| `noid_stark` | AIR traces + GKR reductions | per-tx `LogicProof` | Engine: STARK seal + `prove_logic` / `verify_logic` orchestrator. |
| `noid_block` | N LogicProofs + state witness | `BlockProof` | Block assembly: BlockStateBinding + deferred-FRI aggregation. |
| `noid_ivc` | per-proof columns | folded accumulator | Linear folding accumulator (primitive). |
| `noid_tx` | high-level tx | `tx_body`, `tx_body_hash`, `C_claimed` | Transaction serialisation + claims commitment. |
| `noid_chain` | blocks + state | state transitions, DA, wire, nullifier | Chain layer (state, blocks, DA, nullifier set). Does NOT depend on `noid_stark`. |

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

## 8. Node types

Two node types exist in the network (same model as Bitcoin):

### 8.1 Light Node (Wallet)

The minimal client. Runs on a phone, IoT device, or browser.

```
  Stores:  last block header + recursive proof (~55 KB) + own keys + receipts
  Does:    verifies chain in ~230ms (recursive proof)
           generates LogicProof (~300-400ms)
           queries full node for slot indices and epoch_anchor
  Does NOT: store state, compute Merkle paths, validate blocks from scratch
```

### 8.2 Full Node (Everything)

The backbone. Stores state, validates, assembles blocks, and mines.

```
  Stores:  segmented state (256 segments × 2^16 slots × 48B = ~768 MB at log_slots=24)
           segment root cache (8 KB) + Merkle tree cache (8 KB)
           all block headers (~180 MB/year)
           DA payload (prunable after application)
           nullifier set (rolling ~20 KB)
           mempool of pending TxIntents
           Storage backend: RAM (default) or MDBX disk (§12)

  Does:
    [Wallet]        can generate LogicProofs (built-in wallet, optional)
    [Validation]    validates incoming LogicProofs (~3ms each)
                    validates incoming blocks (PoW + BlockProof + state)
    [State]         maintains full state vector + nullifier set
                    serves slot hints (free indices, epoch_anchor)
    [Block Assembly]
                    collects TxIntents from mempool
                    resolves slot conflicts
                    generates BlockStateBinding (Merkle openings)
                    aggregates LogicProofs + BlockStateBinding -> BlockProof
                    computes da_root, forms 248-byte block header
    [Mining]
                    built-in miner (CPU/GPU, optional)
                    OR exposes Block Template API for external miners
                    accepts valid nonce from miner, seals + broadcasts block
    [P2P]           propagates blocks and TxIntents to peers

  Mining modes:
    • Solo (built-in):  Full Node mines with local CPU/GPU.
    • Solo (external):  Full Node exposes Block Template; user connects
                        separate GPU/ASIC process.
    • Pool:             Full Node is the pool operator. Pushes headers to
                        N connected external miners. Distributes reward
                        offchain. Protocol does not know about pools.
```

### 8.3 External Miner (3rd-party process, NOT a node)

Not a node type — it is a dumb hash device that connects to a Full
Node via the Block Template API (analogous to Stratum in Bitcoin).

```
  Receives: 248-byte block header from Full Node
  Does:     brute-forces nonce: Blake3(header) < difficulty_target
  Returns:  valid nonce
  Cannot:   modify block content, change coinbase, see transactions
```

Block withholding protection: coinbase is locked inside da_root which
is locked inside the header which is locked inside BlockProof.
Changing coinbase requires regenerating BlockProof (1-3s CPU). The
external miner has no CPU proof capability — it cannot steal blocks.

### 8.4 Block structure

```
  BlockHeader (328 bytes):
    prev_block_hash         [32B]
    state_root              [32B]   -- Poseidon2b Merkle over segment FRI roots
    tx_root                 [32B]   -- Merkle of tx_body_hashes in block
    da_root                 [32B]   -- Merkle of DA payload (binds coinbase)
    timestamp               [8B]
    height                  [8B]
    miner_address           [32B]
    nonce                   [16B]   -- 128-bit PoW nonce (Blake3)
    difficulty_target       [32B]   -- 256-bit ASERT target
    proof_transcript_hash   [32B]
    witness_root            [32B]   -- Binius-packed witness on DA
    log_slots               [4B]
    active_slot_count       [8B]
    alloc_counter           [8B]
```

`da_root` is the Poseidon2b Merkle root of the Data Availability
payload (ordered tx_bodies + coinbase_address + coinbase_slot). It
provides cryptographic protection against block withholding: changing
the coinbase requires regenerating `da_root` → header → BlockProof.

---

## 9. What is done, what is ahead

**Done (Phase 1 — per-tx proof engine, pre-Stage-S baseline):**

- Poseidon2b native + AIR encoding.
- AIRs: `balance_gate`, `range_gate`, `haddr`, `hauth`,
  `fri_state_open` (moves to block scope in Stage S), `tx_body_spine`
  (2-lane `tx_body_hash` pin), `tx_validity`, plus composition layer.
- FRI-Binius over GF(2^128) with Poseidon2b Merkle commitments,
  interleaved packing (`noid_fri_binius`), and mixed-length
  multipoint-close for batching columns of different log_len.
- STARK per-`tx` proof (stages 5–7 end-to-end roundtrip).
  Measured: prove ~725 ms, verify ~145 ms, proof ~55 KB.
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

**Done (Stage G — block folding, deferred-opening):**

- `noid_block` crate: N per-tx algebraic STARKs on shared block
  channel + block-level multipoint sumcheck + single FRI opening.
- State continuity enforcement (root chaining).
- 852 lib tests + 3 integration tests pass.

**Next (Stage S — Stateless LogicProof + BlockStateBinding):**

- Epoch anchor replaces prev_state_root in tx_body_hash (anti-replay).
- TxLogicAir: extract pure-logic constraints (no FriStateOpen).
- LogicProof pipeline (prove_logic / verify_logic).
- BlockStateBinding: block-level Merkle opening AIR.
- C_claimed bridge between LogicProof and BlockStateBinding.
- Nullifier set for anti-double-inclusion.
- Updated wallet API (slot indices only, no Merkle paths).

**After Stage S:**

- Stage H: Recursive chain-of-proofs with deferred-FRI strategy
  (algebraic verification in-circuit, Merkle binding deferred to tip).
- Stage K: Kill-Shot for in-circuit Poseidon2b, reduced inner queries,
  parallel recursive prover.

See `ROADMAP2.md` Part II for the detailed plan and performance
targets derived from measured data.

---

## 10. Proof-of-Work subsystem

### 10.1 Algorithm

PoW uses Blake3 over the serialised block header. The miner searches
for a 128-bit nonce such that `Blake3(header) < difficulty_target`
(interpreted as a 256-bit LE integer).

Blake3 is chosen because PoW in Paranoid does not protect execution
correctness (proofs do that). PoW only orders blocks and provides Sybil
resistance. A CPU-friendly hash ensures any laptop can mine on a young
network.

### 10.2 ASERT difficulty

Difficulty adjusts every 6 blocks (epoch) using ASERT:

```
  target = anchor_target × 2^((actual - ideal) / halflife)

  BLOCK_TIME = 60s
  EPOCH      = 6 blocks
  HALFLIFE   = 360s (one epoch)
```

If the last epoch ran 2x fast, difficulty doubles. If 2x slow, it
halves. The exponential is smooth — no oscillation, no DAA gaming.

The anchor updates at every epoch boundary. The calculation is
stateless: only the anchor block's (height, timestamp, target) plus
the current block's (height, timestamp) are needed.

### 10.3 Timestamp rules

```
  block.timestamp > median_time_past(last 11 blocks)
  block.timestamp ≤ local_time + 120 seconds
```

Prevents both backward manipulation (median-time-past) and forward
leaps (drift cap limits how much an attacker can depress difficulty).

### 10.4 Implementation location

```
  noid_chain/src/difficulty.rs    (ASERT calculation, to be created)
  noid_chain/src/pow.rs           (Blake3 PoW check, to be created)
  noid_chain/src/block_header.rs  (header with nonce/target fields)
```

---

## 11. Segmented state commitment

### 11.1 Why segmentation

The original design commits the entire state via a single FRI
polynomial. This is O(N) per block — impractical at scale. Segmentation
splits state into 2^16-slot segments, each independently FRI-committed.
Only dirty segments are recomputed per block.

### 11.2 Structure

```
  ┌────────────────── State (2^24 slots at genesis) ──────────────────┐
  │                                                                    │
  │  Segment 0          Segment 1          ...        Segment 255      │
  │  [slot 0..65535]    [slot 65536..131071]           [slot ...]      │
  │       │                  │                             │           │
  │  FRI commit          FRI commit                    FRI commit      │
  │       │                  │                             │           │
  │  seg_root[0]         seg_root[1]        ...       seg_root[255]   │
  └───────┬──────────────────┬──────────────────────────────┬─────────┘
          │                  │                              │
          └──────────────────┼──────────────────────────────┘
                             │
                    Poseidon2b Merkle tree (depth 8)
                             │
                        state_root
```

### 11.3 Cost model

| Operation | Monolithic FRI | Segmented FRI |
|-----------|---------------|---------------|
| NTT per block | O(2^24) | K × O(2^16) |
| Merkle update | 0 | K × 8 hashes |
| In-circuit per slot | 24-round sumcheck | 16-round sumcheck + 8 Poseidon |
| LogicProof impact | — | ZERO |
| BlockProof overhead | — | +7-15% |

K = number of dirty segments per block (typically 30-80 for 100 txs).

### 11.4 In-circuit integration

BlockStateBinding proves a slot opening in two steps:

1. **FRI opening** (sumcheck, 16 rounds) — proves slot value against
   the segment's FRI root. Same mechanism as today, over a smaller
   polynomial.

2. **Segment Merkle path** (Merkle Kill-Shot GKR) — proves
   the segment root is a leaf of `state_root`. Uses the same unified
   sumcheck + shift architecture as SpineGKR/AuthGKR. The Poseidon2b
   compressions are NOT materialised in the STARK trace — they live
   entirely in a GKR sub-proof (~8 KB for 50 paths).

Slots in the same segment share the Merkle path (batching optimisation).

### 11.5 Merkle Kill-Shot GKR

```
  noid_gkr/src/merkle_circuit.rs      32-slot linear chain topology
  noid_gkr/src/merkle_oracle.rs       Native reference execution
  noid_gkr/src/merkle_mle.rs          14-var hypercube MLE layout
  noid_gkr/src/merkle_shift.rs        Shift helpers + schedule tables
  noid_gkr/src/merkle_killshot.rs     Kill-Shot orchestrator (prove/verify)
```

The Merkle Kill-Shot proves up to 16 chained Poseidon2b compressions
(a segment-to-root Merkle path) in a single 14-variable unified
sumcheck. Architecture:

```
  1. Unified sumcheck (14 rounds, degree 9)
     → proves all S-box + MDS constraints across 32 perm slots
  2. Shift gadget (14 rounds, degree 2)
     → proves round-to-round state consistency
  3. Batch-eval (3 × ~14 rounds)
     → reduces witness claims to (r_B, v_B) openings

  Output pin: state[(last_PermB, N_ROUNDS, lane)] == expected_root
  Binding: boundary MLE → FRI commitment → STARK multipoint-close
```

Proof size: ~5.9 KB per individual path. When batched (multiple
paths in a larger hypercube): ~8 KB total for typical blocks.

---

## 12. State storage backends

### 12.1 Architecture

```
  ┌─────────────────────────────────────────────────┐
  │              Chain Layer (noid_chain)            │
  │                                                 │
  │  ChainState { segments, seg_roots, tree_cache } │
  │         │                                       │
  │         ▼                                       │
  │  ┌─────────────────────────────────────┐        │
  │  │        StateBackend (trait)          │        │
  │  │                                     │        │
  │  │  get_slot(seg, idx) → SlotValue     │        │
  │  │  set_slot(seg, idx, val)            │        │
  │  │  load_segment(seg) → columns        │        │
  │  │  flush()                            │        │
  │  └────────────┬────────────────┬───────┘        │
  │               │                │                │
  │    ┌──────────┴──┐    ┌───────┴────────┐       │
  │    │  InMemory   │    │   MdbxBackend  │       │
  │    │ Vec<Block128>│    │  libmdbx mmap │       │
  │    │ (default)   │    │ (--storage=disk)│       │
  │    └─────────────┘    └────────────────┘       │
  └─────────────────────────────────────────────────┘
```

### 12.2 RAM backend (default)

All segment columns in `Vec<Block128>`. Maximum performance. Suitable
when the full state fits in available RAM (up to ~3 GB at log_slots=26).

### 12.3 Disk backend (MDBX)

Uses libmdbx (the same engine as Reth/Erigon). Key-value store where:
- Key: `(segment_id: u16, column: u8, local_idx: u16)` — 5 bytes
- Value: `Block128` — 16 bytes

Properties:
- Memory-mapped reads: slot lookups are pointer dereferences
- Copy-on-write: crash-safe without WAL
- OS manages page cache: hot segments stay in memory
- Scales to terabytes (proven by Ethereum archive nodes)

During block production, dirty segment columns are loaded into a
temporary buffer for NTT. The buffer is released after computing
the segment FRI root.

### 12.4 When to use which

```
  log_slots ≤ 26  (~3 GB):    RAM recommended, disk optional
  log_slots  = 27  (~6 GB):    Disk recommended
  log_slots  > 27  (12+ GB):   Disk mandatory
```

### 12.5 Snapshot format

Both backends can export/import state as a flat binary snapshot:
- Header: magic, version, log_slots, active_slot_count, alloc_counter
- Body: all segment columns in order (segment 0 values, segment 0
  owners_hi, segment 0 owners_lo, segment 1 values, ...)
- Footer: state_root for integrity check

A node can switch backends by exporting a snapshot and re-importing.

### 12.6 Implementation location

```
  noid_chain/src/storage/mod.rs        StateBackend trait
  noid_chain/src/storage/memory.rs     InMemory backend
  noid_chain/src/storage/mdbx.rs       MDBX backend
  noid_chain/src/segmented_state.rs    SegmentedFriState (replaces FriState)
```

---

## 13. In one sentence

> Paranoid is a proof-native PoW chain where wallets prove logic and
> miners prove state. The network does not execute code — it verifies
> mathematics. Blake3 PoW with ASERT difficulty sets the canonical
> ordering, segmented FRI state scales to billions of slots, and
> recursion compresses the entire history of the network into one proof.

---

# Appendix A — AIR and GKR data flow (Stateless Design)

This appendix expands "LEVEL 3 — WITNESS GENERATION" from §5. It shows
how the semantic inputs of a transaction fan out through the sub-AIRs
and GKR sub-proofs. In the stateless design, the wallet proves only
LOGIC (no Merkle paths); state binding is done at block level by the
miner.

Arrows represent flows of typed witness values (columns / cells).
"pin" edges are boundary equality constraints.

## A.1 LogicProof inputs (wallet-side)

```
                         ┌──────────────────────────────────┐
                         │     LOGICPROOF SEMANTIC INPUTS   │
                         │                                  │
                         │  epoch_anchor     (public)       │
                         │  tx_body_hash     (public)       │
                         │  C_claimed        (public)       │
                         │  per-input:                      │
                         │     secret_i      (witness only) │
                         │     slot_index_i  (claimed)      │
                         │     value_i       (claimed)      │
                         │     owner_hi/lo_i (claimed)      │
                         │  per-output:                     │
                         │     slot_index_j  (claimed)      │
                         │     value_j       (claimed)      │
                         │     owner_hi/lo_j (claimed)      │
                         │  fee                             │
                         │                                  │
                         │  NO merkle_paths!                │
                         │  NO prev_state_root!             │
                         │  NO new_state_root!              │
                         └──────────────┬───────────────────┘
                                        │
              ┌─────────────────────────┼──────────────────┐
              ▼                         ▼                   ▼
        (ownership)              (body binding)        (balance)
```

## A.2 Fan-out across sub-AIRs (LogicProof)

```
  ┌──────────────┐                          ┌──────────────────┐
  │   AUTH GKR   │                          │   BALANCE_GATE   │
  │  Kill-Shot   │                          │                  │
  │              │                          │ in:              │
  │ in:          │                          │  value_i (ins)   │
  │  secret_i    │                          │  value_j (outs) │
  │  tx_body_hash│                          │  fee             │
  │              │                          │                  │
  │ proves:      │                          │ Σ ins ==         │
  │  addr_i =   │                          │ Σ outs + fee     │
  │  H(secret_i)│                          │                  │
  │  auth_tag_i =│                          │ + range gate     │
  │  H(secret_i,│                          │ (value < 2^64)   │
  │   tx_body_h)│                          │                  │
  └──────┬───────┘                          └────────┬─────────┘
         │                                           │
         │ Address_i, AuthTag_i                      │ balance_ok
         ▼                                           ▼
   ┌────────────────────────────────────────────────────────────┐
   │                    TX_LOGIC_AIR  (composite)               │
   │                                                            │
   │   per-input row i:                                         │
   │     AuthTag_i, Value_i, OwnerHi_i, OwnerLo_i, SlotIndex_i  │
   │   per-output row k:                                        │
   │     Value_k, OwnerHi_k, OwnerLo_k, SlotIndex_k             │
   │                                                            │
   │   enforces:                                                │
   │     T1   AuthGKR.addr  == claimed owner  (per input)       │
   │     T2   AuthGKR.tag   == expected auth_tag                │
   │     T3   balance_gate holds                                │
   │     T4   range_gate holds for all values                   │
   │     T5   C_claimed absorbed into FS channel                │
   │                                                            │
   │   does NOT contain:                                         │
   │     FRI_STATE_OPEN (moved to BlockStateBinding)            │
   │     FRI_STATE_COMBINER (moved to BlockStateBinding)        │
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
  │     epoch_anchor, fee_leaf, 4 input-leaf payloads,         │
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

## A.4 BlockStateBinding (miner-side, block-level)

```
  ┌────────────────────────────────────────────────────────────┐
  │            BLOCK STATE BINDING AIR (miner generates)        │
  │                                                            │
  │   For ALL slots from ALL txs in the block:                 │
  │                                                            │
  │   FRI_STATE_OPEN (block scope):                            │
  │     prev_block_state_root                                  │
  │     slot_index_k (for each touched slot)                   │
  │     merkle_path_k (miner has these)                        │
  │     → gamma-RLC accumulator over all openings              │
  │                                                            │
  │   Constraints:                                             │
  │     • input slots open to claimed (value, owner)           │
  │     • output slots open to EMPTY (0, 0, 0)                 │
  │     • post-state: inputs zeroed, outputs filled            │
  │     • new_block_state_root correctly computed              │
  │     • C_claimed per tx matches opened values (bridge)      │
  │                                                            │
  │   Public outputs:                                          │
  │     prev_block_state_root                                  │
  │     new_block_state_root                                   │
  │     C_claimed[0..N] (one per tx, for bridge verification)  │
  └────────────────────────────────────────────────────────────┘
```

## A.5 End-to-end path of one transaction (collapse view, new design)

```
  semantic tx (wallet)
      │
      ├──► SpineGKR Kill-Shot ──► tx_body_hash (PublicColumn pin)
      │       (59 perms, epoch_anchor at L0)
      │
      ├──► AuthGKR Kill-Shot ──► Address_i, AuthTag_i
      │       (20 perms, secret never in transcript)
      │
      ├──► BALANCE_GATE ──┐
      │                    ├──► TX_LOGIC_AIR
      ├──► RANGE_GATE ────┘       │
      │                           │ C_claimed in FS channel
      │                           ▼
      └──► STARK over TxLogicAir (FRI-Binius, no state columns)
                                 │
                                 ▼
                           LogicProof (~45 KB)
                                 │
                                 ▼  (broadcast as TxIntent)
                           mempool admission
                                 │
                                 ▼  (miner collects N TxIntents)
      ┌──────────────────────────┴──────────────────────────┐
      │  BLOCK ASSEMBLY (miner)                             │
      │                                                     │
      │  BlockStateBinding: FRI_STATE_OPEN at block scope   │
      │  + Bridge check: C_claimed matches opened values    │
      │  + Aggregation: LogicProofs + BlockStateBinding      │
      │  + Single FRI opening (deferred-FRI)                │
      │  + IVC fold → BlockProof                            │
      │  + PoW seal                                         │
      └──────────────────────────┬──────────────────────────┘
                                 │
                                 ▼
                               CHAIN
```

## A.6 Legend

- **A named rectangle** — a sub-AIR (a table plus its constraints).
- **`→` arrow** — a flow of witness values (a column or a cell).
- **GKR sub-proof** — a separate sumcheck prover that does not live in
  the STARK trace. Its **only** outgoing surface is the two lanes of
  `tx_body_hash`, row-pinned as a `PublicColumn` in
  `noid_air::airs::tx_body_spine`. Its input boundary (59 ×
  `state_in`) is committed by the STARK as a boundary MLE and
  discharged by a FRI opening at a single point `(r_B, v_B)`.
- **public input** — a value the verifier sees directly.
- **C_claimed** — the bridge commitment (Poseidon2b sponge over all
  claimed slot data) that links LogicProof to BlockStateBinding.

## A.7 Where things live in the code

```
  --- WALLET (LogicProof) ---

  BALANCE_GATE          noid_air::airs::balance_gate
  RANGE_GATE            noid_air::airs::range_gate
  TX-BODY SPINE pin     noid_air::airs::tx_body_spine
                        (two PublicColumn lanes of tx_body_hash;
                         layout: noid_air::airs::tx_body_merkle::layout)
  TX_LOGIC_AIR          noid_air::composition::tx_logic (Stage S)
                        (balance + range + auth pins; NO state columns)
  GKR spine Kill-Shot   noid_gkr::spine_killshot
                        (spine_unified_v2, spine_shift,
                         batch_eval, circuit, layers, mle_layout)
  GKR auth Kill-Shot    noid_gkr::auth_killshot
                        (auth_unified_v2, auth_shift,
                         auth_circuit, auth_oracle)
  prove_logic           noid_stark::prove_tx (will become prove_logic
                        in Stage S; spine KS → auth KS → STARK)
  STARK engine          noid_stark  (prove_air, spine bridge,
                        auth bridge, multipoint close)

  --- MINER (BlockStateBinding) ---

  FRI_STATE_OPEN        noid_air::airs::fri_state_open
                        (moved to block scope in Stage S)
  FRI_STATE_COMBINER    noid_air::airs::fri_state_combiner[_composite]
  BLOCK_STATE_AIR       (Stage S.5: block-level state opening AIR)
  prove_block           noid_block  (Stage G: deferred-FRI aggregation;
                        Stage S: + BlockStateBinding)

  --- SHARED ---

  FRI                   noid_fri / noid_fri_binius
  Packing / DA          noid_binius
  IVC                   noid_ivc
  Chain state machine   noid_chain  (blocks, state, DA, wire, nullifier;
                        does NOT depend on noid_stark or noid_gkr)
  POSEIDON (native)     noid_poseidon2b
```

The registry of pinned columns lives in `noid_air::composition::registry`.
In Stage S, `FriStateOpenCols` and `CombinerCompositeCols` move from
the per-tx composition to the block-level `BlockStateBindingAir`.

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
