# Paranoid Zero — current engineering roadmap

Last updated: 2026-06-17

This document replaces the old `roadmapmininext.md` and describes what remains **from the current code state**, not from the beginning of the `Sweep25x2` work.

The main goal is no longer “make `Sweep25x2` exist”. It already exists across wallet proof generation, mempool admission, miner/block inclusion, block verification, recursive replay, and live multi-node smoke paths.

The current goal is to harden the product path:

```text
automatic wallet planning
→ cheap consolidation
→ measured performance
→ restart/reorg correctness
→ shape-aware fee policy
→ external miner/template stability
→ clean UX and observability
```

---

## Status legend

- `[x]` done and covered enough to treat as current baseline
- `[~]` partially done / works but not final
- `[ ]` not done
- `[!]` invariant, safety requirement, or design constraint

---

## 0. Current reality

### 0.1 Done baseline

- `[x]` `TxShape::{Standard4x8, Sweep25x2}` exists.
- `[x]` `TxBody.shape` is explicit.
- `[x]` Shape-aware tx-body hashing is implemented through `hash_tx_body_for_shape(...)`.
- `[x]` Public inputs carry a shape id.
- `[x]` Wallet proof bundles are shape-dispatched.
- `[x]` `Sweep25x2` has wallet proof generation.
- `[x]` Mempool verifies and admits valid `Sweep25x2` intents.
- `[x]` Mempool rejects malformed/wrong-shape/tampered sweep bundles.
- `[x]` Miner can select `Sweep25x2` transactions.
- `[x]` Block proof format has standard and sweep bucket support.
- `[x]` Sweep bucket has real aggregation transcript coverage, not a placeholder.
- `[x]` Chain state applies confirmed `Sweep25x2` transactions.
- `[x]` Wallet sees confirmed `Sweep25x2` outputs.
- `[x]` Recursive replay supports standard/sweep/mixed blocks.
- `[x]` Late-join snapshot smoke path works after recursive proof readiness.
- `[x]` Live quick `Sweep25x2` scenarios use 20 funding blocks and 5 inputs by default.

### 0.2 Wallet send automation already present

For normal sends, the wallet is intended to hide shape selection from the user:

```text
1..4 inputs   -> Standard4x8
5..25 inputs  -> Sweep25x2
>25 inputs    -> automatic split into multiple transactions
```

Current code state:

- `[x]` `walletSend` plans split chunks automatically.
- `[x]` `walletSend` chooses the smallest shape that can carry selected inputs.
- `[x]` CLI sends use auto fee by default.
- `[x]` RPC `walletSend(..., fee_micronoid = 0)` computes an automatic fee.
- `[~]` Auto fee is conservative, not final shape-aware policy.
- `[~]` Split UX exists but needs hardening for partial success and per-chunk reporting.

### 0.3 Consolidation is now shape-aware

`walletConsolidate` now uses the same shape-aware model as normal sends:

```text
<=4 UTXOs selected   -> Standard4x8 consolidation
5..25 UTXOs selected -> Sweep25x2 consolidation
```

Current code reality:

- `[x]` Consolidation selects the smallest pending-free UTXOs up to `Sweep25x2` capacity.
- `[x]` Auto-fee uses the actual planned consolidation input count and one output.
- `[x]` RPC/CLI report consolidation shape and input/output counts.
- `[x]` Failed consolidation mempool submits clean temporary output reservations before retry.
- `[x]` Fast live smoke confirms a `Sweep25x2` consolidation with >4 inputs.
- `[x]` Restart/reorg hardening for confirmed consolidation is covered by Workstreams C/D.

### 0.4 Fee policy is shape-aware

Current behavior:

- `walletSend fee=0` plans the logical payment first and computes automatic fee per actual chunk.
- Fee policy is output-centric and deterministic: base + small input anti-DoS + output fee + burned net-new-state growth.
- `Sweep25x2` has no separate proof-cost premium; it pays for actual live inputs/outputs and remains cheap for consolidation/state cleanup.
- `estimateFeeDetailed` exposes shape-aware fee breakdown; legacy `estimateFee` remains for compatibility.

### 0.5 Retained checkpoint / expected chain hash hardening is optional production hardening

The retained checkpoint / expected chain-hash work is **not a blocker for basic O(1) snapshot smoke**.

Correct framing:

- `[x]` Basic recursive proof and late-join snapshot smoke work.
- `[x]` Genesis-contained snapshot windows can replay/check expected recursive chain hash.
- `[~]` Long-running suffix-only manifests can be further hardened with retained checkpoints or wire-visible per-block claims.
- `[!]` This is production trust-minimization/diagnostic hardening, not a blocker for the current basic `Sweep25x2` path.

---

## 1. Global invariants

These must remain true through all following work.

### 1.1 User-facing wallet invariants

- `[!]` The user must not manually choose transaction shape for normal sends.
- `[!]` The wallet must automatically choose `Standard4x8`, `Sweep25x2`, or split based on selected inputs.
- `[!]` Fee omission in CLI/RPC must mean automatic minimum/safe fee.
- `[!]` A split payment must expose enough information to the user: tx hashes, shapes, total fee, and any partial success.
- `[!]` Failed sends must not leave permanent pending input/output locks.
- `[!]` Restart must not lose confirmed wallet balance, history, or known recipient outputs.

### 1.2 Shape-binding invariants

- `[!]` `TxBody.shape` must be cryptographically bound into the tx-body hash.
- `[!]` `PublicInputs.shape_id` must match `TxBody.shape.id()`.
- `[!]` Wallet proof bundle shape must match `TxBody.shape`.
- `[!]` Mempool proof verification and block proof verification must agree on shape semantics.
- `[!]` A `Standard4x8` proof must never verify as `Sweep25x2`, and vice versa.
- `[!]` Unknown or unsupported future shapes must fail closed.

### 1.3 Block/state invariants

- `[!]` Every non-coinbase transaction in a block must be covered by exactly one shape bucket.
- `[!]` Bucket tx indices must match canonical block transaction order.
- `[!]` Standard and sweep transactions must not be able to spend the same slot in one block.
- `[!]` Nullifier and slot conflicts must remain rejected.
- `[!]` Common state transition must include claims from all shapes.
- `[!]` Coinbase fee claim must include all included txs and must respect burned state-growth fees.
- `[!]` Reorg/undo must exactly restore spent inputs and remove created outputs.

### 1.4 Proof soundness invariants

- `[!]` Fiat-Shamir transcripts must be domain-separated across:
  - wallet logic proofs;
  - standard bucket;
  - sweep bucket;
  - state binding;
  - recursive accumulator.
- `[!]` Bucket commitments must not be swappable without verifier detection.
- `[!]` Per-tx public inputs must be bound to the exact tx body in the block.
- `[!]` Recursive accumulator claims must bind all present buckets and state-binding mode.
- `[!]` Do not replace a missing cryptographic relation with native validation, dummy claims, unchecked hashes, or zero proofs.

### 1.5 Standard-path regression invariants

- `[!]` `Standard4x8` must remain the cheap default path.
- `[!]` Standard-only block proving must not pay sweep-sized padding cost.
- `[!]` Existing standard wallet/mempool/live scenarios must remain green.
- `[!]` New sweep functionality must not silently increase normal small-payment fee or proof cost without measurement and explicit policy.

### 1.6 Benchmark integrity invariants

- `[!]` Benchmarks must measure real prover/verifier paths, not mock/native shortcuts.
- `[!]` Bench labels must state shape, input count, output count, and split composition.
- `[!]` Any fee/policy decision must cite bench results or an explicit conservative rationale.
- `[!]` Do not optimize by weakening proof coverage or removing verifier checks.

---

## 2. Workstream A — `Sweep25x2` consolidation

Priority: highest.

Reason: consolidation is the obvious user-visible win from `Sweep25x2`. It also affects fee economics and benchmark scenarios.

### Tasks

- `[x]` Update consolidation coin selection to select the smallest pending-free UTXOs up to `TxShape::Sweep25x2.max_inputs()`.
- `[x]` Choose consolidation shape by selected input count:
  - `1..4` -> `Standard4x8`
  - `5..25` -> `Sweep25x2`
- `[x]` Keep consolidation output count at exactly 1, to the wallet's own address.
- `[x]` Compute auto fee from actual selected input count and 1 output, with mempool floor applied.
- `[x]` Ensure pending input/output locks are handled like send locks:
  - output slots reserved after build;
  - input slots marked pending only after mempool admission;
  - failed submit cleans temporary output reservations.
- `[x]` Update CLI output for consolidation to show shape, inputs, outputs, and fee.

### Tests

- `[x]` Unit: 4 selected UTXOs -> `Standard4x8` consolidation.
- `[x]` Unit: 5 selected UTXOs -> `Sweep25x2` consolidation.
- `[x]` Unit: 25 selected UTXOs -> `Sweep25x2` consolidation.
- `[x]` Unit: pending input slots are skipped.
- `[x]` Unit: insufficient funds / one-UTXO no-op fails cleanly.
- `[x]` RPC/integration: `walletConsolidate` returns `shape`, `tx_shapes`, and input/output counts correctly.
- `[x]` Live: fragmented coinbase UTXOs -> one `Sweep25x2` consolidation -> confirmed -> wallet UTXO count drops sharply.

### Acceptance

- `[x]` A wallet with many small UTXOs can consolidate them in one confirmed `Sweep25x2` transaction.
- `[x]` Consolidation fee is automatic when omitted.
- `[x]` Restart after confirmed consolidation preserves the resulting UTXO.

---

## 3. Workstream B — benchmark suite for optimization and fees

Priority: high, before final fee policy.

Reason: fee policy and optimization need real numbers for wallet proofs, block proving, bucket composition, and recursive update cost.

### 3.1 `alice_sends_bob` wallet benchmark

Add/refresh scenarios:

- `[x]` `Standard4x8`: 1 input / 2 outputs.
- `[x]` `Standard4x8`: 4 inputs / 8 outputs.
- `[x]` `Sweep25x2`: 5 inputs / 2 outputs.
- `[x]` `Sweep25x2`: 10 inputs / 2 outputs.
- `[x]` `Sweep25x2`: 25 inputs / 2 outputs.
- `[x]` Sweep consolidation: 25 inputs / 1 output.
- `[x]` Logical split: 26 inputs -> `Sweep25x2 + Standard4x8` composition.
- `[x]` Logical split: 50 inputs -> two sweep-sized chunks.

Report at minimum:

- prove cold/median/best;
- verify cold/median/best;
- proof bytes;
- STARK bytes;
- AuthGKR bytes;
- shape;
- live input/output counts.

### 3.2 `block_scaling` benchmark

Current gap: standard-only fixtures are not enough.

Add block compositions:

- `[x]` 100% `Standard4x8`.
- `[x]` 100% `Sweep25x2` bucket aggregation.
- `[x]` Mixed 80/20 standard/sweep composition.
- `[x]` Mixed 50/50 standard/sweep composition.
- `[x]` Realistic block composition: many standard sends plus a few sweeps/consolidations.
- `[~]` Split chunks in the same block are represented by mixed/sweep chunk composition, not a wallet-planner-driven block fixture yet.
- `[ ]` Split chunks across blocks if bench harness can model it cleanly.

Report:

- block prove time;
- block verify time;
- proof bytes;
- standard bucket contribution;
- sweep bucket contribution;
- state-binding contribution;
- recursive update time if included.

### 3.3 `stark_report`

Update the report with current transaction classes:

- `[x]` wallet `Standard4x8` proof;
- `[x]` wallet `Sweep25x2` proof;
- `[x]` wallet `Sweep25x2` consolidation proof;
- `[x]` block standard bucket;
- `[x]` block sweep bucket;
- `[x]` mixed bucket composition;
- `[x]` recursive update after standard block;
- `[x]` recursive update after sweep block;
- `[x]` recursive update after mixed block.

### Acceptance

- `[x]` Bench output makes it possible to compare standard vs sweep vs mixed block costs.
- `[~]` Fee policy can now start from actual measured costs; final policy still needs a deliberate decision.
- `[x]` Bench code does not use dummy proof paths for reported production numbers.

---

## 4. Workstream C — restart hardening after confirmed `Sweep25x2`

Priority: high.

Reason: confirmed wallet state must survive process restart for sender, recipient, and relays.

### Tasks

- `[x]` Promote/extend live restart scenario for recipient after confirmed `Sweep25x2` (`NOID_LIVE_MULTI_SWEEP_RESTART_RECIPIENT=1`).
- `[x]` Add sender restart after confirmed `Sweep25x2` (`NOID_LIVE_MULTI_SWEEP_RESTART_SENDER=1`).
- `[x]` Add restart after confirmed split payment (`NOID_LIVE_SWEEP_RESTART=1` with split enabled).
- `[x]` Add restart after confirmed consolidation (`NOID_LIVE_SWEEP_RESTART=1`).
- `[x]` Verify wallet history, UTXO set, pending locks, and chain tip after restart in live harness.

### Acceptance

- `[x]` Recipient balance remains at least the confirmed received amount after restart.
- `[x]` Sender spent inputs do not reappear after restart.
- `[x]` Pending outbound amount is zero after confirmed tx and restart.
- `[x]` Node reconverges to the network tip after restart.

---

## 5. Workstream D — reorg/undo after confirmed `Sweep25x2`

Priority: high, but after consolidation and initial benches.

Reason: state transition correctness is only production-grade if undo/reorg is correct for all shapes.

### Scenarios

- `[x]` Reorg after confirmed single `Sweep25x2` covered by `noid_chain::consensus::reorg` regression.
- `[x]` Reorg after mixed block containing standard + sweep txs covered by regression.
- `[x]` Reorg after split payment chunks (`Sweep25x2` + `Standard4x8`) covered by regression.
- `[x]` Reorg after sweep consolidation covered by regression.

### Required checks

- `[x]` Spent inputs are restored on disconnect.
- `[x]` Created outputs are removed on disconnect.
- `[x]` Recipient balance rolls back via wallet full rescan after reorg.
- `[x]` Sender balance rolls back via wallet full rescan after reorg.
- `[x]` Wallet history does not claim reverted txs as final; reorged entries are removed.
- `[x]` Pending/mempool policy is explicit for reverted txs:
  - full proof-bearing tx bytes are not persisted for automatic readmission;
  - reclaimed hashes are logged and duplicate pool entries are evicted;
  - wallets can resubmit after scan if still desired.
- `[~]` Recursive proof state follows the active chain at block verification level; explicit live reorg proof-state assertion still pending.

### Acceptance

- `[x]` Reorg tests pass for standard-only, sweep-only, and mixed blocks.
- `[x]` No double-spend or ghost-output remains after undo in regression coverage.

---

## 6. Workstream E — shape-aware fees and policy

Priority: after benchmark data.

Reason: current auto fee is safe but conservative. Final policy should be fair, predictable, and miner-compatible.

### Current behavior

- `[x]` `walletSend fee=0` uses a shape-aware dry-run plan and computes automatic fee per actual chunk.
- `[x]` `estimateFeeDetailed` RPC is shape-aware by explicit live input/output counts.
- `[x]` Split payments use per-chunk fees and report total fee.
- `[x]` Consolidation fee is shape-aware for the selected consolidation input count.
- `[x]` Policy deliberately does not add a `Sweep25x2` proof-cost premium: sweeps/consolidations are beneficial when they reduce live slots.

### Tasks

- `[x]` Define deterministic fee formula by actual live inputs/outputs and state growth:
  - base;
  - small input anti-DoS component;
  - output component;
  - burned occupancy-scaled net-new-state growth.
- `[x]` Decide whether proof-cost premium is needed for `Sweep25x2`: no separate shape premium for current production policy.
- `[x]` Add shape-aware fee estimation API.
- `[x]` Add wallet dry-run/plan API returning:
  - selected inputs count;
  - planned chunks;
  - shapes;
  - per-chunk fee;
  - total fee;
  - expected change.
- `[x]` Make `walletSend` compute fee per actual chunk, not only one conservative global fee.
- `[x]` Make `walletConsolidate` compute fee from selected consolidation shape/input count.
- `[x]` Expose fee breakdown in RPC/CLI where useful:
  - base;
  - input/output IO;
  - state growth;
  - burned;
  - miner claimable.

### Acceptance

- `[x]` A small standard send does not pay sweep worst-case.
- `[x]` A 5-input sweep send pays enough and reports why.
- `[x]` Split payments report total and per-tx fees.
- `[x]` Miner fee accounting and burned fee accounting match consensus validation.

---

## 7. Workstream F — miner template and external miner path

Priority: after fee policy shape is clear.

Reason: internal miner path is not enough; external mining/template APIs must be stable for mixed shapes.

### Tasks

- `[ ]` Test `getBlockTemplate` with standard-only mempool.
- `[ ]` Test `getBlockTemplate` with sweep-only mempool.
- `[ ]` Test `getBlockTemplate` with mixed standard+sweep mempool.
- `[ ]` Test template with split chunks present.
- `[ ]` Test external `submitBlock` for mixed block.
- `[ ]` Verify coinbase fee claim for mixed template.
- `[ ]` Verify invalid/mismatched bucket proofs are rejected on submit.

### Acceptance

- `[ ]` External miner can mine a block containing `Sweep25x2` txs.
- `[ ]` Template serialization exposes enough shape/proof data for external miner workflow.
- `[ ]` Mixed templates remain deterministic and consensus-valid.

---

## 8. Workstream G — wallet UX and operator observability

Priority: ongoing after core correctness.

### CLI/RPC UX tasks

- `[ ]` `send` output shows:
  - shape for single tx;
  - split count;
  - tx hashes;
  - tx shapes;
  - total fee;
  - per-chunk fee if available.
- `[ ]` `consolidate` output shows:
  - selected input count;
  - output count;
  - shape;
  - fee;
  - expected UTXO reduction.
- `[ ]` Add `--dry-run` or equivalent planning command for send/consolidate.
- `[ ]` Make partial split success explicit and actionable.
- `[ ]` Improve errors for:
  - insufficient fragmented funds;
  - too few empty slots;
  - proof generation failure;
  - mempool fee floor rejection;
  - slot conflict retry exhaustion.

### Observability tasks

- `[ ]` Add `shape` to mempool entry RPC output.
- `[ ]` Add proof/bucket info to block/template debug output.
- `[ ]` Add concise logs for:
  - shape selected;
  - split planned;
  - consolidation planned;
  - recursive proof updated;
  - snapshot proof accepted/rejected.

### Acceptance

- `[ ]` A normal user can send and consolidate without understanding tx shapes.
- `[ ]` A developer/operator can diagnose shape/fee/proof issues from RPC/logs without reading binary data.

---

## 9. Workstream H — optional retained checkpoint / snapshot hardening

Priority: after product-critical wallet/reorg/fee work, unless a new snapshot bug appears.

This is production hardening, not a blocker for the current basic O(1) sync path.

### Tasks

- `[ ]` Define retained recursive checkpoint format for long suffix-only manifests.
- `[ ]` Decide whether checkpoint claims are stored in headers, sidecar manifests, or node DB only.
- `[ ]` Ensure expected chain-hash verification can operate without full historical block bodies.
- `[ ]` Add diagnostics for snapshot rejection:
  - bad recursive proof;
  - bad chain hash;
  - missing retained checkpoint;
  - state root mismatch.

### Acceptance

- `[ ]` Late-join snapshot verification can check accumulated recursive claim continuity for long-running suffix-only histories.
- `[ ]` The normal recursive proof remains constant-size.
- `[ ]` No full-history requirement is reintroduced into the steady-state design.

---

## 10. Validation matrix

### Unit / crate tests

Run targeted tests as work changes:

```sh
cargo test -p noid_node wallet
cargo test -p noid_chain consensus
cargo test -p noid_mempool sweep
cargo test -p noid_block sweep
cargo test -p noid_recursive
```

### Live smoke tests

Fast default smoke tests should remain short:

```sh
python3 scripts/live_sweep_shape_scenarios.py
python3 scripts/live_multinode_sweep_shape_scenarios.py
NOID_LIVE_MULTI_SWEEP_LATE_JOIN=1 python3 scripts/live_multinode_sweep_shape_scenarios.py
```

Heavy split/full-fragmentation tests remain opt-in:

```sh
NOID_LIVE_SWEEP_SKIP_SPLIT=0 python3 scripts/live_sweep_shape_scenarios.py
NOID_LIVE_MULTI_SWEEP_SKIP_SPLIT=0 python3 scripts/live_multinode_sweep_shape_scenarios.py
```

### Benchmarks

After benchmark workstream updates:

```sh
cargo bench --bench alice_sends_bob
cargo bench --bench block_scaling
cargo bench --bench stark_report
```

---

## 11. Definition of done for this roadmap

This roadmap is complete when:

- `[ ]` Normal send automatically uses standard/sweep/split with accurate reporting.
- `[x]` Consolidation uses `Sweep25x2` for 5..25 inputs and is live-tested.
- `[x]` Benchmark suite covers standard, sweep, mixed, split, and consolidation-relevant cases.
- `[x]` Restart after confirmed sweep/split/consolidation is covered.
- `[~]` Reorg/undo after sweep/mixed/split/consolidation is covered by unit regressions; live reorg smoke remains useful.
- `[ ]` Shape-aware fee policy is benchmark-informed and exposed cleanly.
- `[ ]` External miner/template path works for mixed shapes.
- `[ ]` Wallet UX hides shape complexity from normal users.
- `[ ]` Optional retained checkpoint hardening is either implemented or explicitly deferred with documented tradeoffs.

---

## 12. Non-goals / do-not-do list

- `[!]` Do not make users choose transaction shapes manually for normal wallet operations.
- `[!]` Do not pad all standard transactions to `Sweep25x2` just to simplify proving.
- `[!]` Do not weaken proof checks to make benchmarks look better.
- `[!]` Do not describe retained checkpoint hardening as a blocker for basic O(1) snapshot smoke.
- `[!]` Do not finalize fee policy before collecting updated mixed-shape benchmark data.
- `[!]` Do not treat live smoke success as reorg/undo correctness.
