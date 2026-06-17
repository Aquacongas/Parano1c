# Tx Shape Plurality — next roadmap

Last updated: 2026-06-17

Purpose: describe the remaining work from the **current code state** to fully confirmed mixed-shape transaction support.

Current high-level state:

```text
Standard4x8  — full wallet + mempool + block inclusion path works
Sweep25x2    — wallet proof + mempool + miner/block inclusion path works
Mixed blocks — standard bucket + sweep bucket proof packaging/verification works
Live confirm — single-node and multi-node Sweep25x2 + mixed split scenarios pass
Recursive   — standard/sweep/mixed bucket replay and late-join snapshot smoke pass; retained-claim hardening remains
```

The next milestone is not “make Sweep25x2 proofs exist”. They already exist at wallet/mempool level.

The next milestone is:

```text
Sweep25x2 tx admitted to mempool
→ miner selects it
→ block prover includes it in a shape bucket
→ block verifies
→ chain state applies it
→ wallet sees it confirmed
```

---

## Status legend

- `[x]` done and covered by tests
- `[~]` partially done / design or infrastructure exists
- `[ ]` not done
- `[!]` important invariant, risk, or decision point

---

## 0. Current code reality

### Already done

- `[x]` `TxShape::{Standard4x8, Sweep25x2}` exists.
- `[x]` `TxBody` carries explicit `shape`.
- `[x]` tx-body hashing dispatches by shape via `hash_tx_body_for_shape(...)`.
- `[x]` `PublicInputs.shape_id` exists.
- `[x]` STARK transcript absorbs shape/public inputs.
- `[x]` `WalletProofBundle` is shape-dispatched.
- `[x]` `Sweep25x2` native 32-leaf tx-body hash exists.
- `[x]` `Sweep25x2` balance AIR exists.
- `[x]` `Sweep25x2` AuthGKR exists.
- `[x]` `Sweep25x2` tx-body SpineGKR exists.
- `[x]` `Sweep25x2` full wallet proof exists.
- `[x]` Mempool verifies and admits valid `Sweep25x2` bundles.
- `[x]` Mempool rejects malformed/wrong-shape/tampered sweep proofs.
- `[x]` Wallet planner/builder chooses:
  - `Standard4x8` for up to 4 inputs;
  - `Sweep25x2` for 5–25 inputs;
  - split planning for larger fragmented sends.
- `[x]` RPC/CLI expose shape information for sends.

### Still not done

- `[x]` Block proof has bucketized standard fields plus a concrete sweep bucket container/coverage verifier.
- `[x]` Block witness builder supports constructing `Sweep25x2` owned witnesses.
- `[x]` Miner includes `Sweep25x2` in templates.
- `[x]` Sweep bucket uses a real aggregation transcript: per-bucket `InterleavedCommitment`, per-tx algebraic STARKs, bucket multipoint sumcheck, and FRI mixed opening over sweep balance AIR columns + sweep AuthGKR `state` slices.
- `[x]` Single-node `Sweep25x2` send confirms through wallet → mempool → miner/block → chain → wallet history.
- `[x]` Mixed Standard/Sweep block proof packaging/verifier path is wired.
- `[x]` Multi-node live mixed-shape scenario passes for relays started before funding blocks.
- `[x]` Late-join relays snapshot-sync after funding blocks and then confirm a Sweep25x2 tx.
- `[~]` Production-final retained per-block claim / expected-chain-hash verification is hardened:
  - `[x]` genesis-contained snapshot windows replay expected `chain_hash` from header-committed `proof_transcript_hash` and check it in snapshot step mode;
  - `[ ]` long-running suffix-only snapshot manifests still need retained checkpoint/wire support.
- `[ ]` Final shape-aware fees are decided from real bench data.
- `[ ]` Final docs are updated.

### Important current blockers in code

The block inclusion path is shape-aware for `Standard4x8` and `Sweep25x2`. Remaining blockers are retained-claim/finality and policy hardening, not basic block inclusion, normal multi-node propagation, or late-join snapshot smoke.

Known blockers:

- `noid_miner/src/template.rs`
  - `is_current_block_provable_shape(...)` now accepts both `TxShape::Standard4x8` and `TxShape::Sweep25x2`.

- `noid_block/src/witness_builder.rs`
  - `build_tx_witness(...)` is now shape-dispatched and can construct `OwnedSweepTxWitness` from public body + sweep wallet bundle.
  - `OwnedTxWitness::as_block_witness()` remains standard-only because the current heavy block prover still consumes `TxBlockWitness` for the standard bucket path.

- `noid_block/src/lib.rs`
  - `BlockProof` now has `standard_bucket` and `sweep_bucket` fields.
  - `SweepBucketProof` exists and carries tx indices, public inputs, public sweep auth/spine data, wallet sweep logic proofs, and the real sweep bucket aggregation transcript.
  - The heavy `prove_block(...)` / `verify_block(...)` path still proves the standard bucket commitment/state-binding aggregation; extracting it into dedicated bucket functions remains pending.
  - Sweep-only blocks use standalone full STARKs in `state_binding_starks` for `BlockStateBindingAir`, preserving the state-integrity requirement from `docs/security.md` SC-3.

The remaining Phase G work is now mostly retained-claim/finality validation and policy hardening rather than basic inclusion plumbing.

---

## 1. Target architecture

### Goal

Support blocks containing any valid combination of:

```text
Standard4x8 only
Sweep25x2 only
Standard4x8 + Sweep25x2 mixed
```

without making normal standard-only blocks pay for sweep-sized proof padding.

### Preferred design: shape buckets

Use one proof bucket per tx shape.

Conceptually:

```rust
pub struct BlockProof {
    pub meta: BlockPublicMeta,
    pub standard_bucket: Option<ShapeBucketProof>,
    pub sweep_bucket: Option<ShapeBucketProof>,
    pub state_binding_proof: StateBindingProof,
}
```

Each bucket proves tx logic for txs of exactly one shape:

```text
standard txs -> Standard4x8 bucket
sweep txs    -> Sweep25x2 bucket
all txs      -> one common state binding
```

### Why buckets, not universal max padding?

Do **not** pad every tx to `Sweep25x2` size.

Reason:

- `Standard4x8` is the fast default path.
- Most blocks should remain cheap for small payments.
- Universal padding would make ordinary standard payments pay for sweep capacity.
- Buckets preserve fast standard-only blocks and only pay sweep cost when sweep txs are present.

### Bucket ordering model

Block transaction order must remain canonical.

Recommended representation:

```rust
pub struct ShapeBucketProof {
    pub shape: TxShape,
    pub tx_indices: Vec<u32>,
    pub tx_pis: Vec<PublicInputs>,
    // shape-specific proof fields
}
```

Example:

```text
block.transactions:
  0 coinbase
  1 Standard4x8
  2 Sweep25x2
  3 Standard4x8

standard_bucket.tx_indices = [1, 3]
sweep_bucket.tx_indices    = [2]
```

Verifier must check that every non-coinbase tx appears in exactly one bucket and that bucket indices match the block transaction order.

---

## 2. Global invariants

These must remain true through all stages.

### 2.1 Shape binding invariants

- `[!]` `TxBody.shape` must be cryptographically bound into the tx-body hash.
- `[!]` `PublicInputs.shape_id` must match `TxBody.shape.id()`.
- `[!]` Wallet proof bundle shape must match `TxBody.shape`.
- `[!]` Block bucket shape must match every tx in the bucket.
- `[!]` A `Standard4x8` proof must never verify as `Sweep25x2` and vice versa.
- `[!]` Unknown/future shape ids must be rejected unless explicitly supported.

### 2.2 Mempool/block consistency invariants

- `[!]` Anything admitted to mempool must either be block-provable now or explicitly filtered by miner policy.
- `[!]` Once miner policy includes `Sweep25x2`, block proof must support it fully.
- `[!]` Mempool proof verification and block proof verification must agree on shape semantics.
- `[!]` Cached proof bytes must decode to the same `WalletProofBundle` shape used during admission.

### 2.3 State transition invariants

- `[!]` There must be one common state transition for the whole block.
- `[x]` State binding covers claims from all txs across all buckets:
  - standard/mixed-with-standard: aggregated through the standard bucket commitment;
  - sweep-only: standalone `state_binding_starks` plus pre/post state MLE openings.
- `[!]` Standard and sweep txs must not be able to spend the same slot in one block.
- `[!]` Nullifier/slot conflicts must remain rejected.
- `[!]` Coinbase fee claim must include fees from all shapes.
- `[!]` Burn component must be computed consistently across all shapes.
- `[!]` Reorg/undo must restore state for mixed blocks exactly.

### 2.4 Proof soundness invariants

- `[!]` Fiat-Shamir channels must be domain-separated between:
  - standard bucket;
  - sweep bucket;
  - block-level state binding;
  - recursive proof step.
- `[!]` Bucket transcript roots must be bound into the block proof.
- `[!]` Bucket order and `tx_indices` must be committed or otherwise verifier-bound.
- `[!]` Per-bucket commitments must not be swappable without detection.
- `[!]` Per-tx public inputs must be bound to the exact transaction body in the block.

### 2.5 Security-model alignment after Sweep integration

- `[x]` `docs/security.md` SC-1 remains satisfied for sweep txs by `verify_sweep_logic(...)` (`SweepAuthGKR`, `SweepSpineGKR`, sweep balance AIR).
- `[x]` `docs/security.md` SC-3 remains satisfied for sweep-only blocks by standalone `BlockStateBindingAir` full STARKs in `BlockProof.state_binding_starks` plus pre/post state MLE openings.
- `[!]` No-imitation rule: do not replace a missing cryptographic relation with native validation, zero claims, dummy witnesses, or unchecked hashes. Temporary development states may be fail-closed or explicitly degraded, but production-ready means the relevant relation is actually proven or verifier-bound.
- `[x]` `docs/security.md` SC-2 sweep bucket closure is implemented and documented: `SweepBucketProof` carries a per-bucket `InterleavedCommitment`, per-tx algebraic STARKs, bucket-level multipoint sumcheck, FRI mixed opening, and verifier checks over sweep balance AIR columns + wallet-provided sweep AuthGKR `state` slices.
- `[~]` `docs/security.md` SC-4 recursive chain proof supports standard-only, sweep-only, and mixed bucket replay:
  - `[x]` standard-only and sweep-only recursive replay use real bucket multipoint transcripts;
  - `[x]` mixed recursive replay uses separate primary/secondary bucket lanes, so it does not bind only one bucket when both standard and sweep buckets are present;
  - `[x]` the accumulator input is a canonical, domain-separated block-proof claim that covers all present buckets and state-binding mode;
  - `[!]` snapshot/finality verification must be able to check accumulated claims against header-committed data or stored per-block claims; passing `None` for expected chain hash is not production-final for mixed/sweep chains.

### 2.6 Standard-path regression invariants

- `[!]` Existing `Standard4x8` tests must remain green.
- `[!]` Standard-only block proof size/prove time should not regress materially.
- `[!]` RPC `walletSend` should continue returning the existing useful send data while also exposing shape/chunk fields.
- `[!]` Existing standard live scenarios must continue passing.

---

## 3. Phase N1 — design lock

Status: `[x] done`

Purpose: make the bucket design unambiguous before touching the high-risk block prover.

### Tasks

- `[x]` Write a short design note for shape buckets in `docs/tx-shapes.md`.
- `[x]` Decide public serialization direction for future `BlockProof` buckets: explicit optional `standard_bucket` / `sweep_bucket` fields for the current two-shape rollout.
- `[x]` Decide proof-format policy: use one target bucketized `BlockProof` format for all block shapes.

### Acceptance

- `[x]` Bucket design is explicit enough to implement without guessing.

---

## 4. Phase N2 — extract current Standard block proof into a bucket

Status: `[~] public standard path bucketized; extraction into dedicated functions pending`

Risk: `[!] high but localized`

Purpose: refactor without behavior change.

Before adding sweep, isolate the current standard-only block proof path into a reusable bucket prover/verifier.

### Current problem

`prove_block(...)` currently mixes several responsibilities:

```text
per-tx standard logic proof aggregation
block spine proof
auth proof verification/reduction
algebraic STARK transcript aggregation
block multipoint opening
state binding proof
state MLE openings
BlockProof assembly
```

This makes mixed shapes hard because the tx part assumes uniform layout.

### Target internal shape

Introduce internal structures similar to:

```rust
pub struct StandardBucketWitness<'a> {
    pub tx_indices: Vec<usize>,
    pub witnesses: Vec<TxBlockWitness<'a>>,
}

pub struct StandardBucketProof {
    pub tx_indices: Vec<u32>,
    pub tx_pis: Vec<PublicInputs>,
    pub commitment: InterleavedCommitment,
    pub block_spine_proof: BlockSpineProof,
    pub tx_auth_proofs: Vec<AuthProofKillShot>,
    pub tx_algebraic: Vec<AlgebraicStarkProof>,
    pub block_col_openings: Vec<Block128>,
    pub block_multipoint_rounds: Vec<Vec<Block128>>,
    pub mixed_opening: MixedOpeningProof,
    pub block_initial_claim: Block128,
    pub meta: ShapeBucketMeta,
}
```

Names can differ, but the separation should be real.

### Tasks

- `[x]` Introduce `ShapeBucketMeta` and `StandardBucketProof` in `noid_block/src/lib.rs`.
- `[x]` Move public standard block proof fields into `BlockProof.standard_bucket`.
- `[x]` Update block verifier, validation, recursive replay extraction, P2P/RPC verification, benches, and tests to read standard bucket fields.
- `[x]` Carry canonical block transaction indices through `TxBlockWitness` into `ShapeBucketMeta.tx_indices`.
- `[x]` Add block/proof coverage checks binding standard bucket indices and public inputs to actual `Block.transactions`.
- `[ ]` Move standard tx aggregation logic out of `prove_block(...)` into `prove_standard_bucket(...)`.
- `[ ]` Move standard tx verification logic out of `verify_block(...)` into `verify_standard_bucket(...)`.
- `[x]` Keep state binding path unchanged during this phase.
- `[x]` Add/adjust tests proving standard-only behavior remains green after bucketization.

### Invariants

- `[!]` Do not change consensus behavior in this phase.
- `[!]` Do not enable sweep miner inclusion yet.
- `[!]` Do not modify wallet/mempool sweep logic unless required by compilation.
- `[!]` Standard-only block proof semantics must remain correct; preserving the old flat proof layout is not required because the network is not launched yet.

### Validation

Run:

```bash
cargo test -p noid_block --release
cargo test -p noid_miner --release
cargo test -p noid_chain --release
cargo test -p noid_recursive --release
```

---

## 5. Phase N3 — introduce bucket-aware `BlockProof`

Status: `[~] bucketized public format, coverage validation, and mixed recursive replay landed; dedicated bucket prover/verifier refactors still pending`

Risk: `[!] high`

Purpose: allow more than one tx proof family in a block.

### Target model

Replace one uniform tx proof section with shape buckets.

Possible model:

```rust
pub struct BlockProof {
    pub meta: BlockPublicMeta,
    pub standard_bucket: Option<StandardBucketProof>,
    pub sweep_bucket: Option<SweepBucketProof>,
    pub state_binding: BlockStateBindingProof,
}
```

Alternatively:

```rust
pub enum ShapeBucketProof {
    Standard4x8(StandardBucketProof),
    Sweep25x2(SweepBucketProof),
}

pub struct BlockProof {
    pub meta: BlockPublicMeta,
    pub buckets: Vec<ShapeBucketProof>,
    pub state_binding: BlockStateBindingProof,
}
```

Recommended for explicitness with only two shapes today:

```text
standard_bucket: Option<...>
sweep_bucket: Option<...>
```

Recommended if future shapes are likely soon:

```text
buckets: Vec<ShapeBucketProof>
```

### Required metadata

Bucket metadata should include:

- shape id;
- tx count;
- tx indices in block order;
- per-shape AIR column count;
- per-shape boundary slice count;
- log rows;
- number of block spine slices or equivalent;
- commitment column count;
- transcript/bucket digest if recursive proof needs compact binding.

### Verifier checks

Verifier must reject:

- duplicate tx index across buckets;
- missing non-coinbase tx index;
- coinbase tx index inside a tx logic bucket;
- out-of-range tx index;
- bucket tx index not matching block tx shape;
- bucket `PublicInputs.tx_body_hash` not matching block tx body hash;
- bucket `PublicInputs.shape_id` not matching bucket shape;
- bucket order tampering;
- swapped standard/sweep buckets;
- empty buckets if the chosen encoding forbids them.

### Tasks

- `[x]` Define bucket proof structs (`StandardBucketProof`, `SweepBucketProof`).
- `[x]` Define bucket metadata structs (`ShapeBucketMeta`).
- `[x]` Adjust serialization/deserialization via the new `BlockProof` fields.
- `[x]` Adjust `BlockProof::byte_len()`.
- `[x]` Adjust `validate_block_full(...)` to pass bucket-aware proof data:
  - standard-only path remains fully verified;
  - sweep bucket wallet proofs are verified and coverage-checked;
  - sweep-only state binding is verified through standalone full STARK proofs.
- `[x]` Adjust recursive proof extraction in `noid_block/src/block_chain_context.rs` for the standard bucket.
- `[x]` Adjust recursive replay extraction/proving for bucketized proofs: standard-only, sweep-only, and mixed Standard/Sweep proofs map to real bucket transcript lanes.

### Invariants

- `[!]` The verifier must derive expected tx hashes from actual block transactions, not trust bucket metadata blindly.
- `[!]` Bucket metadata must be treated as claimed data and validated.
- `[!]` A block with no non-coinbase txs should remain legal only if the existing protocol allows it; do not accidentally require a tx bucket for empty blocks.

### Validation

Run:

```bash
cargo test -p noid_block --release
cargo test -p noid_chain --release
cargo test -p noid_recursive --release
```

---

## 6. Phase N4 — make block witness builder shape-aware

Status: `[x] shape-dispatched witnesses consumed by block proof assembly`

Risk: `[!] medium-high`

Purpose: build block-time witnesses from both standard and sweep wallet bundles.

### Current problem

`noid_block/src/witness_builder.rs` currently has a standard-only model:

```rust
pub struct OwnedTxWitness {
    pub air: TxLogicAir,
    pub trace: Trace,
    pub pi: PublicInputs,
    pub spine_inputs: SpineInputs,
    pub auth_public: AuthPublicInputs,
    pub auth_proof: AuthProofKillShot,
    pub auth_slices: Vec<Vec<Block128>>,
}
```

This cannot represent `Sweep25x2` because sweep uses different AIR/GKR families.

### Target model

Introduce variants:

```rust
pub enum OwnedTxWitness {
    Standard4x8(OwnedStandardTxWitness),
    Sweep25x2(OwnedSweepTxWitness),
}
```

Standard witness keeps current fields.

Sweep witness now contains enough data for the current sweep bucket container and the next real aggregation step:

```rust
pub struct OwnedSweepTxWitness {
    pub air: Sweep25x2BalanceGateAir,
    pub trace: Trace,
    pub pi: PublicInputs,
    pub spine_inputs: SweepSpineInputs,
    pub auth_public: SweepAuthPublicInputs,
    pub auth_slices: Vec<Vec<Block128>>,
    pub logic_proof: SweepLogicProof,
}
```

### Key design decision: sweep auth slices

Current standard bundle includes AuthGKR `state` slices:

```rust
pub auth_slices: Vec<Vec<Block128>>
```

Sweep now mirrors this exact block-friendly artifact surface:

```rust
pub logic_proof: SweepLogicProof
pub auth_slices: Vec<Vec<Block128>>
pub auth_public: SweepAuthPublicInputs
```

Only AuthGKR `state` slices are serialized. Sweep `auth.s_in`, `auth.s_out`, and tx-body SpineGKR helper columns remain internal to wallet proving.

### Tasks

- `[x]` Add `OwnedStandardTxWitness` and `OwnedSweepTxWitness`.
- `[x]` Make `build_tx_witness(...)` dispatch by `WalletProofBundle` shape.
- `[x]` Remove standard-only assert in `build_public_inputs(...)`.
- `[x]` Add shape-aware public input builder that respects shape capacity:
  - standard activation/deactivation arrays remain existing size;
  - sweep leaves the fixed standard activation/deactivation arrays empty and relies on `claims_commitment`, live counts, shape id, and sweep proof internals instead of truncating 25 inputs.
- `[~]` Add tests:
  - `[ ]` standard witness still builds;
  - `[x]` sweep witness builds and feeds `SweepBucketProof` assembly;
  - `[x]` bucket index/shape/spine tampering rejects;
  - `[ ]` unsupported future shape rejected.
- `[x]` Teach the block bucket assembly path to consume `OwnedSweepTxWitness` via the concrete `SweepBucketProof` fields, including sweep `auth_slices`.
- `[x]` Teach block proof assembly to bind sweep bucket data and state binding:
  - sweep logic through `SweepLogicProof` entries;
  - sweep AuthGKR state slices through bucket `auth_slices`;
  - sweep-only state binding through standalone `state_binding_starks`.

### Invariants

- `[!]` Spend secrets must never enter block witness builder.
- `[!]` Sweep block witness must be derived from public body + wallet proof bundle only.
- `[!]` Public inputs must match exactly what mempool verified.
- `[!]` Do not silently truncate sweep inputs/outputs into standard-sized arrays.

### Validation

Run:

```bash
cargo test -p noid_block --release
cargo test -p noid_stark --release
cargo test -p noid_gkr --release
```

---

## 7. Phase N5 — implement `Sweep25x2` bucket proving

Status: `[~] real sweep aggregation transcript plus sweep-only/mixed recursive replay implemented/tested; NOT production-complete until live/snapshot hardening is closed`

Risk: `[!] high`

Purpose: prove and verify blocks containing only sweep txs.

### Target

A block with one or more `Sweep25x2` user txs must prove and verify without any standard tx bucket.

### Required components

Sweep bucket needs shape-specific equivalents of the standard bucket logic:

- sweep AIR:
  - `Sweep25x2BalanceGateAir`
- sweep trace:
  - from `sweep25x2_balance_witness_from_body(...)`
- sweep auth:
  - `SweepAuthCircuit`
  - `SweepAuthProofKillShot`
  - `SweepAuthPublicInputs`
- sweep spine:
  - `SweepSpineCircuit`
  - `SweepSpineInputs`
  - `SweepSpineProofKillShot`
- sweep public inputs:
  - `shape_id == TxShape::Sweep25x2.id()`
  - live inputs <= 25
  - live outputs <= 2
  - tx-body hash from sweep 32-leaf layout

### Tasks

#### N5-A — functional self-contained sweep bucket layer

This was the initial layer for carrying wallet-produced sweep proofs through block packaging. It is now complemented by the real SC-2 aggregation transcript in N5-B.

- `[x]` Add concrete `SweepBucketProof` target struct carrying tx indices, public inputs, sweep auth public inputs, sweep spine inputs, and wallet sweep logic proofs.
- `[x]` Add bucket assembly from `OwnedSweepTxWitness` (`assemble_sweep_bucket_proof(...)`).
- `[x]` Add sweep bucket public verifier for wallet logic proofs and block-body binding (`verify_sweep_bucket_from_block(...)`).
- `[x]` Implement sweep bucket commitment/binding model for integration by carrying self-contained wallet `SweepLogicProof` objects inside `SweepBucketProof` and binding them to block tx indices/public inputs.
- `[x]` Implement canonical transcript/header binding through `block_recursive_claim_hash(...)` and `proof_transcript_hash`.
- `[x]` Implement sweep bucket slice/reduction verification by delegating to `verify_sweep_logic(...)` for each carried wallet proof.
- `[x]` Implement standalone sweep-only block state binding via `state_binding_starks` and pre/post state MLE openings.
- `[x]` Implement sweep bucket tamper tests for tx index/shape/spine binding (`noid_block/tests/sweep_bucket.rs`).
- `[x]` Implement standalone state-binding proof regression test for the sweep-only path (`standalone_state_binding_proves_and_verifies_for_sweep_only_path`).

#### N5-B — real Sweep25x2 aggregation bucket transcript (SC-2 implemented; sweep-only/mixed SC-4 replay implemented)

Sweep now has a real verifier-bound bucket transcript using the same wallet-artifact model as Standard4x8: wallet proof plus AuthGKR `state` slices, not a hash-only shortcut. Recursive replay consumes sweep-only bucket transcripts directly, and mixed blocks replay standard and sweep bucket transcripts in separate primary/secondary recursive lanes.

##### N5-B.0 — design lock

- `[x]` Follow the Standard4x8 pattern for sweep: serialize only AuthGKR `state` slices as `auth_slices`.
- `[x]` Do **not** serialize sweep `auth.s_in`, `auth.s_out`, or tx-body SpineGKR helper columns. Those extra columns are internal to `prove_sweep_logic(...)`.
- `[x]` `SweepWalletProofBundle` now carries `logic_proof`, `auth_slices`, and `auth_public`.

##### N5-B.1 — pass sweep auth slices through wallet/block witness

- `[x]` Add `build_sweep_auth_slices(...)` in `noid_stark/src/prove_logic_sweep.rs`.
- `[x]` Extend `SweepWalletProofBundle` with `auth_slices`.
- `[x]` Extend `OwnedSweepTxWitness` with `auth_slices`.
- `[x]` Add basic mempool shape checks for sweep `auth_slices`.

##### N5-B.2 — real sweep bucket aggregation design

- `[x]` Build sweep bucket aggregation over sweep balance AIR columns + wallet-provided sweep `auth_slices`, mirroring the standard bucket path.
- `[x]` Use sweep-specific AuthGKR/SpineGKR verification and bridge checks; never call standard auth verifier for sweep.
- `[x]` Bind every sweep tx proof to the block transaction body and bucket order.

##### N5-B.3 — implement real sweep bucket verifier/prover

- `[ ]` Add dedicated `noid_block/src/sweep_bucket.rs` (refactor only; current implementation lives in `noid_block/src/lib.rs`).
- `[x]` Build a real bucket transcript over the verified sweep wallet proofs, their commitments/openings, tx indices, public inputs, and block header context.
- `[x]` Produce and verify a non-null `block_initial_claim` / bucket transcript claim for recursion.
- `[x]` Reject tampering of sweep public data, tx index, bucket order, AuthGKR slices, `block_col_openings`, `block_initial_claim`, or `mixed_opening`.
- `[x]` Swapped sweep bucket between otherwise valid blocks rejects in mixed coverage/body binding tests.
- `[x]` Sweep-only block without real aggregation transcript rejects in production mode.

### Acceptance tests

- `[x]` one sweep tx block proves/verifies through real sweep aggregation bucket transcript.
- `[ ]` many sweep tx block proves/verifies through real sweep aggregation bucket transcript.
- `[ ]` sweep tx with tampered body hash rejects.
- `[ ]` sweep tx with tampered auth proof rejects.
- `[x]` sweep tx with tampered spine data rejects.
- `[x]` sweep bucket with tampered AuthGKR `state` slice contents rejects.
- `[x]` sweep bucket with wrong shape rejects.
- `[x]` sweep bucket with wrong tx index rejects.
- `[x]` sweep bucket with tampered aggregation transcript rejects.

### Invariants

- `[!]` Sweep bucket verifier must not call standard `verify_auth_killshot(...)`.
- `[!]` Sweep bucket verifier must use sweep-specific AuthGKR and SpineGKR.
- `[!]` Sweep bucket AIR columns must not be interpreted as standard `TxLogicAir` columns.
- `[!]` Sweep tx-body hash must come from the sweep 32-leaf layout with explicit shape leaf.
- `[x]` Production `SweepBucketProof` contains a real aggregation transcript, not only self-contained wallet proofs plus a header hash.
- `[x]` Recursive replay for sweep-only blocks consumes the canonical block claim plus the real sweep bucket multipoint rounds/challenges/opening transcript; null block-sumcheck replay is forbidden for non-stub user-tx blocks.
- `[x]` Mixed recursive replay uses separate primary/secondary lanes so recursion does not drop either bucket.

### Validation

Run:

```bash
cargo test -p noid_block --release
cargo test -p noid_stark --release
cargo test -p noid_mempool --release
```

---

## 8. Phase N6 — mixed Standard/Sweep block verification

Status: `[~] wired functionally with mixed recursive replay; NOT production-complete until live/heavy scenarios pass`

Risk: `[!] high`

Purpose: prove and verify a block with both shapes.

### Target examples

```text
1 Standard + 1 Sweep
many Standard + 1 Sweep
1 Standard + many Sweep
many Standard + many Sweep
```

### Tasks

- `[x]` Group non-coinbase txs by shape while preserving original block order via `tx_indices`.
- `[x]` Prove standard bucket if standard txs exist.
- `[x]` Prove sweep bucket if sweep txs exist.
- `[x]` Verify all buckets.
- `[x]` Verify exact coverage of all non-coinbase txs.
- `[x]` Verify no duplicate indices via exact per-shape expected-index matching.
- `[x]` Verify state binding over all txs.
- `[x]` Verify coinbase fee claim over all tx fees through existing consensus checks.

### Coverage algorithm

Verifier should derive:

```text
expected_non_coinbase_indices = all block tx indices except coinbase
proved_indices = standard_bucket.tx_indices ∪ sweep_bucket.tx_indices
```

Then check:

```text
proved_indices == expected_non_coinbase_indices
proved_indices has no duplicates
for each proved index:
    bucket.shape == block.transactions[index].body.shape
```

### State binding rule

Do not split state binding by bucket unless there is a formal design for composing state transitions.

Preferred:

```text
all tx claims across all shapes -> one common BlockStateBinding proof
```

### Acceptance tests

- `[x]` mixed block: `1 standard + 1 sweep` replay witness extracts both bucket lanes and recursive step verifies.
- `[x]` mixed block: `many standard + one sweep` replay witness extracts both bucket lanes.
- `[x]` mixed block: `one standard + many sweep` replay witness extracts both bucket lanes.
- `[x]` mixed block: duplicate bucket tx index rejected.
- `[x]` mixed block: missing tx index rejected.
- `[x]` mixed block: sweep bucket swapped to another valid sweep tx body rejected by tx-body binding.
- `[x]` mixed block: sweep tx placed in standard bucket rejected.
- `[x]` mixed block: standard tx placed in sweep bucket rejected.
- `[x]` mixed block: bucket order tampering rejected.
- `[x]` mixed block: state/proof metadata tamper changes canonical transcript and header binding rejects.

### Validation

Run:

```bash
cargo test -p noid_block --release
cargo test -p noid_chain --release
cargo test -p noid_miner --release
cargo test -p noid_recursive --release
```

---

## 9. Phase N7 — recursive proof integration

Status: `[~] standard/sweep/mixed bucket replay works; late-join snapshot smoke passes; retained-claim hardening remains`

Risk: `[!] high`

Purpose: keep O(1) chain proof valid with bucketized block proofs without weakening `docs/security.md` SC-4.

### Current concern

The recursive relation must not fold a shape-local bucket claim as the chain claim or silently omit a bucket. The current implementation separates bucket-local `block_initial_claim` values from the canonical `chain_claim`, and mixed blocks replay the standard and sweep bucket multipoint transcripts in separate recursive lanes.

### Production target

Introduce a canonical recursive block claim:

```text
BlockRecursiveClaim = H_to_field(
  domain = "NOID_BLOCK_RECURSIVE_CLAIM_V1",
  BlockPublicMeta,
  standard_bucket_summary?,
  sweep_bucket_summary?,
  state_binding_mode,
  state_binding_summary,
  bucket_coverage_summary
)
```

Required summaries:

- `standard_bucket_summary` binds the existing standard bucket commitment cap, `tx_indices`, `tx_pis`, block-spine/auth transcript data, bucket multipoint rounds, mixed opening transcript, and `block_initial_claim`.
- `sweep_bucket_summary` binds the implemented sweep aggregation transcript: bucket commitment cap, `tx_indices`, `tx_pis`, `auth_public`, `auth_slices`, `spine_inputs`, wallet `logic_proofs`, per-tx algebraic STARKs, bucket multipoint rounds, FRI mixed opening transcript, and `block_initial_claim`.
- `state_binding_summary` binds the exact mode:
  - `algebraic` state bindings aggregated into the standard bucket; or
  - `standalone` `state_binding_starks` for sweep-only blocks;
  and includes pre/post state MLE openings.
- `bucket_coverage_summary` binds the canonical non-coinbase transaction coverage checked by `validate_block_bucket_tx_indices(...)`.

The recursive accumulator must fold `BlockRecursiveClaim`, not a shape-local partial claim, for all bucketized proofs. Pure standard blocks may continue deriving an equivalent claim from the legacy standard transcript only if the value is exactly mapped into the canonical claim and regression tests prove compatibility.

### Tasks

- `[x]` Audit `noid_recursive/src/prove.rs` assumptions about current `BlockProof` layout: current `BlockReplayWitness` maps to standard bucket data.
- `[x]` Strengthen `RecursiveBlockAir` sumcheck replay: active block/recursive rows now enforce both `claim_in = p0 + p1` and `claim_out = Lagrange([p0,p1,p2], r)` for degree-2 round polynomials, and `docs/security.md` / `docs/cryptography.md` are updated accordingly.
- `[x]` Store and verifier-check real bucket `block_multipoint_challenges`, then feed those challenges into recursive replay instead of synthetic fresh-channel values.
- `[x]` Recursive extraction does not silently replay only one bucket for mixed blocks, and does not fabricate zero/null witnesses for real sweep blocks.
- `[x]` Add canonical, domain-separated block recursive claim computation in `noid_block`:
  - `[x]` deterministic serialization/hash for `BlockPublicMeta`;
  - `[x]` deterministic standard bucket summary;
  - `[x]` deterministic sweep bucket summary;
  - `[x]` deterministic state-binding summary including proof mode;
  - `[x]` deterministic bucket coverage summary.
- `[~]` Header / proof binding:
  - `[x]` define `proof_transcript_hash` as the hash of the canonical recursive claim transcript for every non-stub block;
  - `[x]` make miner/header assembly populate it from the actual `BlockProof`;
  - `[x]` make full validation reject mismatch between header and canonical proof transcript hash;
  - `[x]` add explicit header mismatch regression test.
- `[~]` Recursive witness/model update:
  - `[x]` separate bucket-local `block_initial_claim` from canonical `chain_claim` for the standard path;
  - `[x]` preserve pure-standard compatibility while deriving `chain_claim` from `block_recursive_claim_field(proof)`;
  - `[x]` ensure `ChainAccumulator::extend(...)` folds the canonical `chain_claim` bytes, not the bucket-local sumcheck claim;
  - `[x]` sweep-only recursion extracts the real sweep bucket transcript and verifies a recursive step over it; a null block-sumcheck plus canonical hash is explicitly not accepted;
  - `[x]` mixed recursion extracts standard and sweep transcripts into separate primary/secondary lanes and verifies a recursive step over both;
  - `[~]` ensure recursive verifier and snapshot verifier can check accumulated claims against header-committed data or stored per-block claims: `verify_recursive_step` checks non-stub header projection; snapshot verification now replays expected `chain_hash` when headers include genesis through `proof_h`; long-running suffix-only manifests still need retained checkpoint/wire support.
- `[x]` SC-2 closure dependency:
  - `[x]` implement aggregated sweep bucket commitment/multipoint/FRI path equivalent to the standard bucket path;
  - `[x]` update recursive extraction to replay/verify the real sweep-only bucket transcript;
  - `[x]` add docs/security proof for the aggregated sweep bucket model and tests that cover transcript tampering.
- `[~]` Add recursive tests for:
  - `[x]` standard-only block;
  - `[x]` sweep-only block;
  - `[x]` mixed block secondary-lane replay and recursive step;
  - `[x]` mixed block where sweep bucket is swapped after validation/body binding (must reject);
  - `[x]` mixed state/proof metadata tamper changes the canonical transcript and header binding rejects;
  - `[x]` header `proof_transcript_hash` mismatch (covered by `verify_recursive_step` / transcript hash tests).

### Invariants

- `[!]` Recursive proof must not accept a block proof whose bucket contents were swapped after block validation.
- `[!]` Recursive witness must include enough data to replay or verify bucketized block proof binding.
- `[!]` Recursive proof must bind all bucket summaries, not just one shape-local claim.
- `[!]` Header `proof_transcript_hash` must be verifier-derived from the same canonical transcript used by recursion.
- `[!]` Standard-only recursive path must remain green.

### Validation

Run:

```bash
cargo test -p noid_recursive --release
cargo test -p noid_block --release
cargo test -p noid_chain --release
```

---

## 10. Phase N8 — enable miner inclusion for `Sweep25x2`

Status: `[~] code enabled; production gate now depends on snapshot/finality hardening and policy tests`

Risk: `[!] high`

Purpose: allow confirmed sweep txs without violating `docs/security.md`.

Miner policy is currently wired to accept `Sweep25x2`, and the SC-2/SC-4 bucket transcript blockers are structurally closed for standard, sweep-only, and mixed blocks. Single-node and normal multi-node live scenarios pass; production readiness still requires snapshot/finality retained-claim hardening plus final policy tests.

### Tasks

- `[x]` Change miner policy in `noid_miner/src/template.rs`:

```rust
fn is_current_block_provable_shape(shape: TxShape) -> bool {
    matches!(shape, TxShape::Standard4x8 | TxShape::Sweep25x2)
}
```

- `[x]` Update test formerly locking standard-only behavior.
- `[ ]` Add template tests:
  - sweep tx selected when block prover supports sweep;
  - standard tx not starved by high-fee sweep txs;
  - mixed template created when both shapes are in mempool;
  - stale epoch anchors still filtered for both shapes.
- `[x]` Ensure block template proof bytes include bucketized proof.
- `[~]` Ensure RPC `getBlockTemplate` still works for external miners: compile path is green; live external-miner scenario still pending.

### Invariants

- `[!]` Do not treat miner inclusion as production-ready before snapshot/finality checks and final policy tests are closed.
- `[!]` Miner must not select a tx shape unsupported by the current block prover.
- `[!]` Template ordering/fee sorting must remain deterministic.
- `[!]` Coinbase fee must include selected sweep tx fees.

### Validation

Run:

```bash
cargo test -p noid_miner --release
cargo test -p noid_rpc --release
cargo test -p noid_chain --release
```

---

## 11. Phase N9 — single-node live confirmation

Status: `[x] done for Sweep25x2 single tx and fragmented split send`

Risk: `[!] medium`

Purpose: prove the complete local lifecycle.

### Scenario A — one sweep send confirms

Steps:

```text
start single node
create/fund wallet with ~20 fragmented UTXOs
walletSend amount requiring 5–25 inputs
assert RPC result shape == Sweep25x2
assert tx enters mempool
mine/prove block
assert tx confirmed
assert mempool drains
assert wallet balance/history update
```

### Scenario B — split send confirms

Steps:

```text
create/fund wallet with >25 fragmented UTXOs
walletSend large amount
assert multiple chunks
assert chunk shapes are Sweep25x2 and/or Standard4x8
mine blocks
assert all chunks confirmed
```

### Tasks

- `[x]` Add `scripts/live_sweep_shape_scenarios.py`.
- `[x]` Add single-node sweep confirm test.
- `[x]` Add split confirm test.
- `[~]` Add failure diagnostics for:
  - `[x]` tx stuck in mempool / confirmation timeout reports last state;
  - `[x]` miner/block failure exposes node log tail;
  - `[x]` wallet pending-lock/history failures report balance/history snapshots;
  - `[ ]` chain rejected block should get more structured RPC/log extraction if it appears in multi-node runs.

### Invariants

- `[!]` A sweep tx must not remain indefinitely in mempool when miner is enabled and block capacity allows it.
- `[!]` Wallet pending-input locks must clear correctly after confirmation.
- `[!]` Retry behavior must not double-spend pending inputs.

### Validation

Run the new script plus existing live standard scenarios.

Latest local validation:

```bash
NOID_LIVE_SWEEP_START_BLOCKS=28 python3 scripts/live_sweep_shape_scenarios.py
```

Result: passed. It confirmed one `Sweep25x2` tx (`n_inputs = 5`) and one fragmented split send (`Sweep25x2` + `Standard4x8` chunks), with mempool drain, confirmation, wallet scan/history, and pending-lock clearing.

---

## 12. Phase N10 — multi-node propagation and convergence

Status: `[x] normal propagation/convergence done; restart/reorg hardening remains`

Risk: `[!] medium`

Purpose: verify network behavior.

### Scenarios

- `[x]` 3-node propagation/confirmation of one `Sweep25x2` tx.
- `[x]` 3-node mixed split send confirms as `Sweep25x2` + `Standard4x8` chunks.
- `[x]` All nodes verify bucketized block proof.
- `[x]` Mempools drain on all nodes after block acceptance.
- `[x]` Nodes converge to same tip/state root.
- `[x]` Recipient wallet balances increase by the sent amounts without explicit post-confirmation rescan.
- `[x]` Late-join snapshot sync after many blocks.
- `[~]` Production-final retained per-block claim / expected-chain-hash replay for headers-only snapshots (separate N7 hardening): genesis-contained windows are checked; suffix-only long-chain manifests still need retained checkpoints.
- `[ ]` Restart after confirmed sweep tx.
- `[ ]` Reorg/undo after confirmed sweep tx.

### Invariants

- `[!]` P2P tx propagation must preserve proof bundle bytes exactly.
- `[!]` Block serialization must preserve bucket metadata exactly.
- `[!]` Nodes without mixed-shape support must reject mixed blocks deterministically if protocol version requires it.
- `[!]` Reorg must restore spent sweep inputs and remove sweep outputs like standard txs.

### Validation

Run:

```bash
cargo test -p noid_p2p --release
cargo test -p noid_node --bins --release
```

plus live multi-node scenario script.

Latest local validation:

```bash
python3 scripts/live_multinode_sweep_shape_scenarios.py
```

Result: passed with 32 funding blocks. It confirmed one `Sweep25x2` tx to node2 and a fragmented split send to node3 (`Sweep25x2` + `Standard4x8` chunks), all txs confirmed on all nodes, mempools drained, tips converged, and recipient balances increased by exactly the requested sent amounts (`recipient_received_delta >= amount`).

Late-join validation:

```bash
NOID_LIVE_MULTI_SWEEP_LATE_JOIN=1 NOID_LIVE_MULTI_SWEEP_SKIP_SPLIT=1 \
  python3 scripts/live_multinode_sweep_shape_scenarios.py
```

Result: passed. Relays started after funding blocks, snapshot-synced from the miner, converged to the miner tip, confirmed a `Sweep25x2` tx on all nodes, and node2 received exactly `200000001` μNOID without explicit post-confirmation rescan. Latest run also exercised genesis-contained snapshot `expected_chain_hash` replay/check in the partial recursive-proof path.

---

## 13. Phase N11 — fees and policy finalization

Status: `[ ] not done`

Risk: `[!] medium`

Purpose: finalize economics after real proof costs are known.

### Current state

- Minimum fee logic exists through `required_fee_for_tx_body(...)`.
- Mempool rejects below-min-fee non-coinbase txs.
- RPC auto-fee uses a conservative estimate that covers both standard and sweep sends.
- Final shape-aware fee policy is not locked.

### Decisions needed

- `[ ]` Is current `base + io_fee * (inputs + outputs) + growth_fee` enough?
- `[ ]` Do we need `proof_weight_fee(shape)`?
- `[ ]` What is the minimum acceptable fee for `Sweep25x2 25/2`?
- `[ ]` Should sweep be cheaper than 5–7 standard splits?
- `[ ]` How to prevent spam if sweep is too cheap?

### Candidate formula

Current base:

```text
base + io_fee * (inputs + outputs) + growth_fee * max(0, outputs - inputs)
```

Optional final addition:

```text
+ proof_weight_fee(shape)
```

Possible shape weights:

```text
Standard4x8: 1.0
Sweep25x2:  k, based on prove/verify/bytes vs standard
```

### Tasks

- `[ ]` Add shape-aware fee estimate API.
- `[ ]` Expose fee estimate over RPC/CLI if needed.
- `[ ]` Add underpriced sweep rejection test.
- `[ ]` Add coinbase fee claim test including sweep fees.
- `[ ]` Add burn component test including sweep fees.
- `[ ]` Update wallet auto-fee to use final policy.
- `[ ]` Update docs.

### Invariants

- `[!]` Standard fees must not regress unexpectedly.
- `[!]` Sweep should be economically better than many standard splits for fragmented wallets.
- `[!]` Sweep must not be so cheap that it becomes the default spam vector.
- `[!]` Fee policy must be deterministic consensus logic where required.

### Validation

Run:

```bash
cargo test -p noid_chain --release
cargo test -p noid_mempool --release
cargo test -p noid_rpc --release
cargo test -p noid_node --bins --release
```

---

## 14. Phase N12 — benchmarks

Status: `[ ] not done`

Risk: `[!] low-medium`

Purpose: collect data for performance and fees.

### Add benches

Recommended files:

```text
bench_prover/benches/wallet_tx_shapes.rs
bench_prover/benches/block_mixed_shapes.rs
```

### Wallet scenarios

- `[ ]` Standard 1 input / 2 outputs.
- `[ ]` Standard 2 inputs / 4 outputs.
- `[ ]` Standard 4 inputs / 8 outputs.
- `[ ]` Sweep 5 inputs / 2 outputs.
- `[ ]` Sweep 12 inputs / 2 outputs.
- `[ ]` Sweep 21 inputs / 2 outputs.
- `[ ]` Sweep 25 inputs / 2 outputs.
- `[ ]` Auto-split equivalent, e.g. 5 × Standard4x8.

### Block scenarios

- `[ ]` 10 Standard.
- `[ ]` 10 Sweep.
- `[ ]` 9 Standard + 1 Sweep.
- `[ ]` 50 Standard + 5 Sweep.

### Metrics

For each relevant scenario:

- prove cold;
- prove median;
- prove best;
- verify cold;
- verify median;
- verify best;
- total proof bytes;
- STARK bytes;
- AuthGKR bytes;
- SpineGKR bytes;
- bucket overhead bytes;
- memory peak if measurable.

### Initial targets

Adjust after real data.

```text
Standard4x8 regression:
  prove <= +10–15%
  verify <= +10–15%
  proof size <= +10–15%

Sweep25x2 target:
  better total cost than 5–7 Standard splits
  proof size ideally <= 90 KB for wallet proof
  block inclusion should not degrade standard-only blocks
```

### Optimizations to consider after data

- Reuse fixed columns per shape bucket.
- Avoid cloning large selector/fixed columns.
- Parallelize per-tx algebraic STARKs inside each bucket.
- Parallelize buckets where safe.
- Cache shape-specific circuits:
  - `AuthCircuit`;
  - `SweepAuthCircuit`;
  - `SpineCircuit`;
  - `SweepSpineCircuit`.
- Avoid recomputing body hash/spine inputs where mempool already cached them.
- Keep standard-only bucket path as close as possible to the current optimized path.
- Consider compact bucket metadata encoding.

### Validation

Run benches in release mode and record results in docs.

---

## 15. Phase N13 — documentation and UX

Status: `[ ] not done`

Purpose: explain what shipped and how users/operators should reason about it.

### Docs to update

- `[ ]` `README.md`
- `[ ]` `docs/tx-shapes.md`
- `[ ]` `docs/network.md`
- `[ ]` `docs/cli.md`
- `[ ]` `docs/security.md`
- `[ ]` `docs/cryptography.md`

### Topics to document

- `[ ]` Shape model:
  - `Standard4x8` fast default;
  - `Sweep25x2` fragmented-wallet path.
- `[ ]` Wallet planner policy.
- `[ ]` RPC `walletSend` response fields:
  - `shape`;
  - `tx_shapes`;
  - `tx_hashes`;
  - `split_count`.
- `[ ]` CLI output examples.
- `[ ]` Fee policy.
- `[ ]` Mempool and block inclusion behavior.
- `[ ]` Security model:
  - shape binding;
  - proof bundle shape mismatch rejection;
  - bucket shape/order binding;
  - no spend secrets in block witness builder.
- `[ ]` Bench results.
- `[ ]` Manual consolidation is optional hygiene, not required for normal large sends.

---

## 16. Suggested implementation order

### Step 1 — design

- Lock bucket design.

### Step 2 — standard bucket refactor

- Extract current block proof tx part into standard bucket.
- No behavior changes.
- Keep all standard tests green.

### Step 3 — bucketized `BlockProof`

- Add bucket-aware proof structs and verifier coverage checks.
- Standard-only still passes.

### Step 4 — sweep witness support

- Make `witness_builder` shape-aware.
- Decide and implement sweep boundary slice strategy.

### Step 5 — sweep-only block proof

- Implement `SweepBucketProof`.
- Prove/verify only-sweep blocks.

### Step 6 — mixed block proof

- Prove/verify standard+sweep mixed blocks.
- Verify bucket coverage and state binding across all txs.

### Step 7 — recursive integration

- Update recursive proof extraction/binding.
- Add standard/sweep/mixed recursive tests.

### Step 8 — miner inclusion

- Enable `Sweep25x2` in block template selection.
- Add template tests.

### Step 9 — live scenarios

- Single-node sweep confirm.
- Multi-node propagation/convergence.
- Restart/reorg.

### Step 10 — fees, benches, docs

- Collect final numbers.
- Decide final fee policy.
- Update docs/UX.

---

## 17. Do not do these shortcuts

- `[!]` Do not enable miner inclusion for `Sweep25x2` before block proof supports it.
- `[!]` Do not make every tx use sweep-sized universal padding.
- `[!]` Do not silently treat sweep auth proofs as standard auth proofs.
- `[!]` Do not truncate sweep inputs to standard `MAX_INPUTS` arrays in block public inputs.
- `[!]` Do not split state binding per bucket without a formal composition design.
- `[!]` Do not mark live sweep done just because mempool accepted the tx.
- `[!]` Do not mark mixed block support done until a real mixed block proves and verifies.
- `[!]` Do not simplify proof verification to make tests pass; preserve cryptographic binding.

---

## 18. Definition of done for this next roadmap

All must be true:

- `[ ]` `walletSend` from 5–25 fragmented UTXOs creates one `Sweep25x2` tx.
- `[ ]` That tx enters mempool.
- `[ ]` Miner includes it in a block.
- `[ ]` Block proof verifies.
- `[ ]` Chain applies the block.
- `[ ]` Wallet sees the tx confirmed.
- `[ ]` `walletSend` from 30+ fragmented UTXOs creates multiple chunks automatically.
- `[ ]` Split chunks confirm.
- `[ ]` Standard payments still use `Standard4x8`.
- `[ ]` Standard-only blocks still prove/verify with no material regression.
- `[ ]` Sweep-only blocks prove/verify.
- `[ ]` Mixed Standard/Sweep blocks prove/verify.
- `[ ]` Mempool rejects malformed/wrong-shape proofs.
- `[ ]` Block verifier rejects bucket tampering/order/shape mismatches.
- `[ ]` Reorg/undo works with sweep and mixed blocks.
- `[ ]` 3-node live sweep/mixed scenario passes.
- `[ ]` Bench numbers are recorded.
- `[ ]` Final fee policy is implemented and documented.
- `[ ]` Docs explain shapes, policy, fees, UX, and security model.
