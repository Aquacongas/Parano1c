# Paranoid Design Notes

This document collects the **non-normative** rationale, philosophy,
UX outlook, and open questions that back the Paranoid protocol. It is
not a specification. The authoritative rules live in
`SPECIFICATION.md`; the implementation overview lives in
`ARCHITECTURE.md`.

Everything below is descriptive: design intent, trade-offs, future
deliverables, and commentary. Where a statement describes a
consensus-significant rule, this document defers to
`SPECIFICATION.md`.

Contents:

1. The proof-native ledger (philosophy).
2. What "O(1) history verification" really means.
3. User-facing UX outlook.
4. The ideal-form summary.
5. Architectural verdict.
6. Open questions for future specification work.
7. Honest status line.
8. Implementation status — what is in code today.

---

## 1. The proof-native ledger

This section is a **conceptual frame**, not a specification. It
describes the kind of system that falls out of the layers defined in
`SPECIFICATION.md` §0–§15, and how it differs from a classical UTXO
chain or an account-based chain. Some of the properties below are
already realised in the code; others are architectural future
deliverables. See §8 for the line-by-line status.

### 1.1 Transaction = self-contained state-transition proof

Each transaction is the tuple

```
  (prev_root, tx_body, new_root, proof)
```

that proves **everything** about the transition in a single
cryptographic object:

- ownership (`tx_validity_hauth` → secret-to-owner);
- balance (`balance_gate`: Σ inputs = Σ outputs + fee);
- pre-state correctness (`fri_state_open` on `prev`: inputs exist,
  mint slots are empty);
- post-state correctness (`fri_state_open` on `new`: inputs zeroed,
  outputs materialised);
- the resulting `new_root`.

A transaction is a **completed cryptographic state-transition
object**. The network does not execute it — the network verifies it.

### 1.2 Miners do not execute transactions

This is an explicit design principle, not a consequence of
optimisation. A miner:

- does NOT execute a VM;
- does NOT recompute state;
- does NOT simulate transactions.

A miner:

- verifies per-tx proofs;
- resolves conflicts (§15.2 of `SPECIFICATION.md`);
- aggregates proofs into the block proof;
- produces canonical ordering;
- anchors history via PoW.

```
  PoW secures ordering, NOT execution.
```

### 1.3 Block = aggregated proof checkpoint

Raw inclusion of per-tx proofs (≈ hundreds of KB each) does not
scale. The block producer MUST:

- recursively fold tx proofs through IVC
  (`noid_ivc::Accumulator`);
- build **one** block proof.

A block contains:

- the ordered tx list;
- `tx_body_root`;
- `witness_root`;
- the **aggregated recursive proof**;
- the resulting `state_root`;
- the PoW header.

The folded block proof attests:

- all tx proofs are valid;
- the ordering is fixed;
- the composition of state transitions is correct;
- the final `state_root` is the result of that composition.

### 1.4 Recursive chain of proofs

The next step is where the design acquires its distinguishing
property:

```
  Proof_{n+1}  verifies  Proof_n
```

`BlockProof_{n+1}` includes, in its verification portion, a check of
`BlockProof_n`. The chain becomes not a sequence of blocks but a
recursive chain of proofs.

Consequence: to synchronise, a fresh node needs only to

1. download the latest header,
2. download the latest recursive proof,
3. verify **one** proof.

After that the node knows the correctness of every state transition
from genesis to tip.

### 1.5 Full-chain verification collapses to O(1)

It is not "verify all N historical blocks" but "verify the latest
recursive accumulator". Historical verification complexity:

```
  O(chain_length)  →  O(1)
```

The proof size does not depend on the length of the history. This is
a fundamental property, not a micro-optimisation.

**Caveat.** "O(1)" is about proof verification, not about state
storage. To *spend* a UTXO a wallet still needs Merkle witnesses for
its own slots (a tree kept locally by a wallet indexer) and sync up
to the tip. The claim here is about **history verification**, not
about ledger state maintenance.

### 1.6 Consensus and execution are fully decoupled

| Layer     | Where it runs               | What it does                       |
|-----------|-----------------------------|------------------------------------|
| Execution | Prover-side, off-chain      | Building proofs                    |
| Consensus | On-chain (PoW + ordering)   | Ordering, anti-conflict, finality  |

There is no VM in the consensus layer. There is no Sybil resistance
in the execution layer. A clean separation.

### 1.7 Proof-native ledger

The ledger stores not **executable intents** (as an EVM or Bitcoin
Script chain does) but **cryptographically proven state
transitions**. This is a different class of system: the validity of
every ledger element is established before inclusion.

### 1.8 Thin PoW blockchain

Because execution is externalised:

- blocks are not bounded by VM execution time;
- verification is tiny (one recursive proof);
- state replay is not required for verification.

The PoW layer becomes thin, deterministic, and almost purely a
data-ordering system.

### 1.9 Canonical global state = cryptographic accumulation

The network does not "trust miners". The network verifies a recursive
validity object accumulated over the entire history. Trust moves out
of execution and into cryptographic recursion.

### 1.10 Stateless (or near-stateless) sync

Because the latest proof attests the entire chain:

- archival replay is not required for verification;
- historical execution is not required;
- bootstrap is radically simplified: header + latest proof.

A full node that wants to **actively participate** (wallet, mining)
still needs state, but a **light client** can verify everything with
a single proof.

### 1.11 PoW retains its role

PoW is not decorative. It:

- secures ordering (which chain is canonical on a fork);
- makes reorgs economically costly;
- provides Sybil resistance;
- defines canonical history.

What has been removed from PoW is the **execution trace**. What is
retained is its intrinsic role: ordering + finality + anti-Sybil.

### 1.12 Fixed-slot state makes recursion tractable

Slot architecture (§0, §15.1 of `SPECIFICATION.md`) is not an
arbitrary choice. It yields:

- deterministic addressing (`slot_index` is an explicit field of each
  tx);
- an explicit "touched set" (inputs/outputs per tx are known up front);
- simple conflict detection (intersection of sets);
- algebraically clean transitions (an update is a pointwise write,
  not a walk over a Patricia trie).

This is radically friendlier to recursive accumulation than arbitrary
VM execution: every shift / fold operates on a fixed algebraic
structure rather than on opcode semantics.

### 1.13 Mempool = proof market

The mempool stores **candidate proven transitions**, not intents to
execute. A miner does not pick "which transactions to profitably
execute"; a miner picks "which already-proven transitions to include
in a batch". The semantics differ in kind, and a fee market built on
top of this operates on a different primitive — proof producers pay
for inclusion of ready transitions.

### 1.14 Miners = proof aggregators

The miner's role is:

```
  sequencer + aggregator + recursive prover + PoW finalizer
```

— not an execution worker. Fees pay for (a) inclusion,
(b) aggregation work, (c) PoW security — not for compute.

---

## 2. End-user UX outlook

From the user's vantage point the system collapses to a single
action:

```
  Send 10 to Bob
```

Everything else is hidden:

- proof generation;
- slot allocation;
- retry on conflict (rebuild proof with a fresh slot hint);
- state update.

The wallet handles proof building, hinting, and rebroadcast. The
protocol never demands human intervention for algorithmic
bookkeeping.

---

## 3. The ideal-form summary

In a single formula:

```
  inputs consume occupied slots
  outputs occupy empty slots
  spent slots become zero
  proof guarantees correctness
```

This is the entire ledger semantics. Everything else — Poseidon2b
hashing, GKR, FRI, STARK, IVC — is the machinery that makes the
single word "proof" meaningful.

---

## 4. Architectural verdict

The model is a tight composition of four well-known ingredients:

```
  Bitcoin-style UTXO
  + fixed indexed state
  + zk validity engine
  + transparent balances
```

Each ingredient is chosen for a specific reason:

- **UTXO over accounts.** Input/output is an explicit set of slot
  indices; conflicts are set intersections; the transition function
  is pointwise.
- **Fixed indexed state.** Addressing by slot index eliminates a
  hash-map UTXO set and makes state proofs constant-depth Merkle
  paths.
- **zk validity engine.** Execution moves off-chain; the network
  verifies proofs rather than replaying them.
- **Transparent balances.** No hidden state — observers can read
  balances and owners directly. Privacy is not the goal; succinct
  verifiability is.

---

## 5. Open questions (for future specification work)

Two large questions remain outside the current specification:

1. **Fee market.** How fee bids are expressed, how the miner
   prioritises inclusion, and how fee dynamics respond to
   mempool pressure. This is a consensus-adjacent question and will
   become normative in a future revision of `SPECIFICATION.md`.

2. **Mempool conflict resolution at scale.** The tie-break rule of
   §15.2 resolves mint collisions inside a single block. The
   cross-node mempool policy — how nodes propagate, deduplicate, and
   prioritise competing proven transitions — is still a local-policy
   matter. A future revision should tighten this into a protocol
   rule so that different clients do not interpret conflicts
   differently.

Both items are tracked in `ROADMAP2.md`.

---

## 6. Honest status line

Fully delivered: the design is realistic. If the remaining stages
(block-level IVC composition, recursive chain of proofs, fee market,
mempool rules) are carried through, the resulting system is a
plausible **more-proof-efficient backend** for the classical Bitcoin
UTXO model. The interesting half is not the ledger shape — which is
deliberately conservative — but the proof stack underneath it.

---

## 7. Implementation status

This is a snapshot of what is realised in the codebase as of the
current revision. For the authoritative per-stage breakdown see
`ROADMAP2.md`.

| Design principle (§1)                         | Status                                                    |
|-----------------------------------------------|-----------------------------------------------------------|
| 1.1 Transaction as state-transition proof     | Implemented (`noid_air`, `noid_stark`, `noid_tx`).        |
| 1.2 Miners do not execute                     | Implemented (the engine has no VM by construction).       |
| 1.3 Block = aggregated proof checkpoint       | IVC primitive ready (`noid_ivc::Accumulator`: `fold_step_prove` + `decide`); BlockProof pipeline pending (Stage G). |
| 1.4 Recursive chain of proofs                 | Future deliverable (Stage J).                             |
| 1.5 O(1) historical verification              | Follows from 1.4 once delivered.                          |
| 1.6 Consensus / execution decoupled           | Implemented by architecture.                              |
| 1.7 Proof-native ledger                       | Implemented (slot-based state in `noid_chain`).           |
| 1.8 Thin PoW blockchain                       | Follows from 1.3 + 1.4.                                   |
| 1.9 Canonical state = cryptographic accumulation | Follows from 1.4.                                       |
| 1.10 Stateless / near-stateless sync          | Follows from 1.4.                                         |
| 1.11 PoW retains ordering/Sybil role          | By design; PoW wiring is out-of-scope for the proof stack.|
| 1.12 Fixed-slot state                         | Implemented (§0 of `SPECIFICATION.md`).                   |
| 1.13 Mempool as proof market                  | Future deliverable (§5 above).                            |
| 1.14 Miners as proof aggregators              | Follows from 1.3 + fee market.                            |

Items 1.1–1.2, 1.6–1.7, 1.12 are already reflected by the engine
architecture (`noid_air`, `noid_stark`, `noid_tx`, `noid_chain` with
slot-based state). Item 1.3 has its IVC primitive in place; the
remaining integration into a `BlockProof` is Stage G. Items 1.4, 1.5,
1.8–1.11, 1.13, 1.14 are future deliverables — Stage J for recursive
chain plus out-of-scope consensus-layer work. This is a roadmap, not
vapourware: every consequence is anchored in a concrete stage.

---

## 8. Cross-references

- `SPECIFICATION.md` — normative rules. Read this first if you care
  about what a conforming node MUST do.
- `ARCHITECTURE.md` — implementation overview, crate map, proof
  layering, data flow.
- `noid_gkr/SPEC.md`, `noid_gkr/AUDIT.md` — GKR sub-protocol spec and
  audit notes.
- `ROADMAP2.md` — stage-by-stage delivery tracker.
