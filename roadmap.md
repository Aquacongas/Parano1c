# Public O(1) Roadmap

This document is the working implementation roadmap for public O(1) snapshot
sync. It starts from the current repository state and defines the selected
architecture, the security target, and the exact implementation phases. The
normative production security document remains `docs/security.md`; every phase
that changes the accepted language or a theorem must update that file in the
same patch.

## 1. Current State

The current production block-validation path is live and concrete:

```text
semantic block body
+ BlockProof
+ BlockAuthSidecar
+ parent/state context
-> timeless AcceptBlock
```

What works today:

- block identity and PoW use Poseidon2b domains `BLOCKHDR` and `POWHDR__`;
- strict `pow_digest < target`, MTP, ASERT, chainwork, and log-slot expansion
  have native/proof-facing relations and release tests;
- exact UTXO and ReuseGuard state transitions are proven by the current
  `BlockProof`;
- every non-coinbase transaction carries a wallet-produced
  `OwnerAuthProofKillShot`;
- wallet secrets stay with wallets; block producers and history provers verify
  wallet proofs, they do not know `spend_secret`;
- retained batch replay derives component statements only after timeless
  `AcceptBlock` succeeds;
- public arbitrary-peer snapshot sync is fail-closed.

The remaining public O(1) problem is not the semantic block proof. The measured
max-block payload is dominated by authorization sidecars:

```text
255 Standard4x8:
    BlockProof         about 160 KB
    BlockAuthSidecar   about 14-16 MB

40 full Sweep25x2:
    consensus max under the 1020 live-input semantic budget
```

The current `OwnerAuthProofKillShot` is itself sound, but its serialized size is
dominated by the private-column PCS opening:

```text
Standard4x8:
    proof              about 63 KB
    PCS opening        about 58-60 KB

Sweep25x2:
    proof              about 116-119 KB
    PCS opening        about 112-113 KB
```

The current laboratory benchmark is:

```text
cargo bench -p bench_prover --bench o1_auth_accumulator_lite
```

It builds real `OwnerAuthProofKillShot` objects, verifies them to the existing
production verifier claims, then measures a streaming binary-field accumulator
kernel. Current standard-only data:

```text
Standard4x8 x1:
    core_accum         about 0.37 ms
    full_scan          about 0.44 ms
    wallet             about 63 KB
    pcs_pending        about 58 KB

Standard4x8 x64:
    core_accum         about 22.9 ms
    full_scan          about 27.3 ms
    wallet             about 3.98 MB
    pcs_pending        about 3.64 MB
```

This shows that the binary-field accumulation kernel is not the bottleneck. The
remaining work is a proof-native batch decider for the current Auth PCS
FRI/source/Merkle opening relation.

## 2. Selected Architecture

The selected architecture keeps the current wallet authorization model:

```text
wallet:
    TxBody + OwnerAuthProofKillShot

mempool/full node:
    direct VerifyAuthorization(statement, proof)

block producer / history prover:
    use wallet proofs as private validation witness

public snapshot verifier:
    verify HistoryProof and compare cumulative_chainwork
```

The public O(1) authority is:

```text
HistoryProof
```

The public O(1) authority is not:

```text
BlockAuthSidecar bytes
local cache entries
retained replay output
transport checksums
component statements supplied without their derivation relation
```

### 2.1 Recursive Consensus State

The public history state is the minimal timeless consensus state:

```rust
pub struct RecursiveConsensusState {
    pub height: u64,
    pub block_id: [u8; 32],

    pub state_root: [u8; 32],
    pub utxo_root: [u8; 32],
    pub guard_root: [u8; 32],

    pub cumulative_chainwork: [u8; 32],
    pub log_slots: u32,
    pub active_slot_count: u64,
    pub alloc_counter: u64,
    pub asert_anchor: AsertAnchor,
    pub mtp_window: MtpWindow,
    pub expansion_window: ExpansionWindow,
}
```

`state_root` remains:

```text
H_STATE_ROOT(log_slots, utxo_root, guard_root)
```

`utxo_root` and `guard_root` are explicit public state fields so snapshot
manifest verification does not depend on an opaque root alone.

### 2.2 Digest Graph

The final statement graph is acyclic:

```text
BatchContextDigest =
    H(start_state, end_state, batch_len, ordered headers, semantic counts)

HeaderBatchStatementDigest =
    H(BatchContextDigest, header-specific public inputs)

TxBodyBatchStatementDigest =
    H(BatchContextDigest, ordered tx-body commitments)

ExactActionStatementDigest =
    H(BatchContextDigest, exact action surfaces)

ExactStateBatchStatementDigest =
    H(BatchContextDigest, state transition public inputs)

AuthorizationBatchStatementDigest =
    H(BatchContextDigest, ordered authorization statements, layout counts)

ExecutionBatchStatementDigest =
    H(
      BatchContextDigest,
      TxBodyBatchStatementDigest,
      ExactActionStatementDigest,
      ExactStateBatchStatementDigest,
      AuthorizationBatchStatementDigest
    )

HistoryStepStatementDigest =
    H(previous_state_digest, end_state_digest,
      HeaderBatchStatementDigest, ExecutionBatchStatementDigest)
```

No digest may include itself through another module digest. `ACCBLK__` may be
used only as an internal semantic claim schedule derived inside the proved batch
relation. It is not a standalone public acceptance object.

### 2.3 Authorization Accumulation

The final authorization proof object is:

```rust
pub struct OwnerAuthAccumulationProof {
    pub statement_digest: [u8; 32],
    pub layout_groups: Vec<AuthLayoutGroupDigest>,
    pub core: CoreAuthAccumulatorProof,
    pub pcs: PcsFriSourceBatchDeciderProof,
}
```

The private witness contains the existing wallet proofs:

```rust
pub struct OwnerAuthAccumulationWitness {
    pub canonical_statements: Vec<CanonicalAuthorizationStatement>,
    pub wallet_proofs: Vec<OwnerAuthProofKillShot>,
}
```

`CoreAuthAccumulatorProof` covers:

- canonical statement binding;
- Fiat-Shamir transcript order for the non-PCS verifier surface;
- main/shift/boundary sumcheck verifier equations;
- batch-eval terminal reduction;
- continuity between verifier reductions and PCS opening claims.

`PcsFriSourceBatchDeciderProof` covers:

- arithmetic PCS commitment metadata and cap binding;
- compact FRI root absorption and query derivation;
- FRI fold equations;
- batched Merkle path equations;
- source TensorFold equations;
- source cap and folded-root binding;
- equality between the final PCS opening value and the batch-eval terminal
  state claim.

Large wallet proof objects become witness data. The public O(1) proof carries
only the accumulated authorization proof.

### 2.4 History IVC

The final history step relation is:

```text
Verify(prev_history_proof) OR genesis base
Verify(HeaderBatchProof)
Verify(ExecutionBatchProof)
Verify(OwnerAuthAccumulationProof)
Check exact start/end RecursiveConsensusState equality
Check one batch statement digest graph
=> new HistoryProof
```

Fork choice remains outside `HistoryProof`:

```text
verify candidate HistoryProof objects
choose highest cumulative_chainwork
```

## 3. Security Target

This section defines the target the implementation must reach before public
O(1) activation. Until then, snapshot sync remains fail-closed.

### 3.1 Authorization Accumulation Soundness

Let `B` be an ordered batch of semantic blocks. Let `Stmt_i` be the canonical
authorization statement for non-coinbase transaction `i`, derived from:

```text
ordered TxBody
authenticated pre-state owners
ordered live input slots
input_to_owner mapping
owner_count and layout
protocol domains
the arithmetic Auth PCS commitment
```

Target theorem:

```text
VerifyOwnerAuthAccumulation(B, proof) accepts

=> exists wallet proofs pi_i such that
   VerifyAuthorization(Stmt_i, pi_i) accepts
   for every non-coinbase transaction i in B
```

except with:

```text
epsilon_auth_accum
+ sum_i epsilon_owner_auth_i
+ epsilon_pcs_batch_decider
+ epsilon_hash_binding
```

The theorem is existential over wallet proof bytes. It does not say that a node
previously saw the proof; it says the proof relation accepts for some witness
that is bound to the canonical statement.

By the existing Authorization Knowledge Theorem in `docs/security.md`:

```text
VerifyAuthorization(Stmt_i, pi_i) accepts
=> an extractor obtains spend_secret for every claimed owner
```

except with the owner-auth knowledge-soundness error. Therefore accepted
accumulated authorization implies every consumed owner is authorized, under the
same wallet-secret model as today.

### 3.2 History Soundness

Target theorem:

```text
VerifyHistoryProof(S_0, S_n, proof) accepts

=> exists a canonical sequence of semantic blocks B_1..B_n
   and validation witnesses W_1..W_n such that
   S_i = AcceptBlockTimeless(S_{i-1}, B_i, W_i)
   for every i
```

except with the union of:

- Poseidon2b commitment assumptions;
- binary-field IVC soundness;
- header integer relation soundness;
- execution relation soundness;
- OwnerAuth accumulation soundness;
- exact-state Merkle and ReuseGuard binding failures.

The theorem must be proven in `docs/security.md` at activation time with exact
module names and error accounting from the implemented backend.

### 3.3 Current Proven Facts

The following are current facts, not future claims:

- direct `VerifyAuthorization(statement, OwnerAuthProofKillShot)` is the
  production authorization verifier;
- `OwnerAuthProofKillShot` knowledge soundness is the production theft-security
  claim;
- the bench-only accumulator shows the binary-field folding kernel is cheap on
  real proof material;
- the bench-only accumulator is not consensus authority and does not prove PCS
  source binding.

## 4. Implementation Plan

Every phase must end with:

- focused tests;
- a benchmark gate where performance risk exists;
- a `docs/security.md` update if the phase changes the security language;
- no production path accepting a partial O(1) proof as authority.

### Phase 0: Freeze Current Lab and Documentation

Status: completed.

Tasks:

- keep only `bench_prover/benches/o1_auth_accumulator_lite.rs` for the current
  authorization accumulator lab;
- keep default benches small and require explicit env vars for large runs;
- add this roadmap;
- update `docs/security.md` so the selected public O(1) target is
  `HistoryProof` over `RecursiveConsensusState`, not a rolling accumulator.

Exit gate:

```text
cargo fmt --check
cargo check -p bench_prover --benches
cargo bench -p bench_prover --bench o1_auth_accumulator_lite
```

### Phase 1: OwnerAuth Verify Claim Shape

Goal: define the exact typed claim language that the accumulator will prove.

New module target:

```text
noid_gkr::owner_auth_accum
```

Core types:

```rust
pub struct OwnerAuthVerifyClaim {
    pub statement_digest: [u8; 32],
    pub layout_key: AuthLayoutKey,
    pub transcript_digest: [u8; 32],
    pub gkr: OwnerAuthGkrVerifierClaim,
    pub batch_eval: OwnerAuthBatchEvalClaim,
    pub pcs: OwnerAuthPcsOpeningClaim,
}

pub struct AuthLayoutKey {
    pub owner_count: u8,
    pub live_slots: u8,
    pub slot_bits: u8,
    pub num_vars: u8,
    pub hash_backend: u8,
}
```

Implementation:

- build claims from the existing production verifier boundary;
- bind `block_index` and `tx_index` into each authorization statement digest;
- enforce canonical layout counts: sorted layout groups, no duplicate layout
  keys, sum of group counts equals `user_tx_count`;
- keep this claim builder as witness construction, not public authority.

Tests:

- direct verifier accepts iff claim construction succeeds;
- wrong tx hash rejects;
- swapped transaction position changes statement digest;
- wrong owner mapping rejects;
- wrong PCS backend rejects.

Bench gate:

```text
255 Standard4x8 claim construction <= direct verify time + 10%
40 full Sweep25x2 claim construction <= direct verify time + 10%
```

### Phase 2: CoreAuthAccumulatorProof

Goal: implement the proof for the non-PCS authorization verifier surface.

New proof object:

```rust
pub struct CoreAuthAccumulatorProof {
    pub layout_groups: Vec<AuthLayoutGroupDigest>,
    pub accumulator_commitment: [u8; 32],
    pub terminal_claim: [Block128; 2],
}
```

Implementation:

- use a Poseidon2b transcript to bind batch context, ordered statements, layout
  groups, and Auth PCS commitments before drawing accumulator challenges;
- use streaming CLMUL for binary-field RLC inside the prover/decider relation;
- prove main/shift/boundary sumcheck verifier equations and batch-eval terminal
  continuity;
- keep PCS opening checks as explicit unresolved inputs to the next phase, not
  as accepted authority.

Tests:

- mutation of any non-PCS proof message rejects;
- mutation of any returned verifier claim rejects;
- removing, duplicating, or reordering an authorization proof rejects;
- layout count mismatch rejects.

Bench gate:

```text
255 Standard4x8:
    core proof public bytes <= 150 KB
    verify <= 150 ms
    prover HWM <= 1 GB

40 full Sweep25x2:
    core proof public bytes <= 200 KB
    verify <= 250 ms
    prover HWM <= 1 GB
```

Security update:

- add a `CoreAuthAccumulatorSoundness` lemma to `docs/security.md`;
- explicitly state that this phase alone is not public authorization authority.

### Phase 3: PcsFriSourceBatchDeciderProof

Goal: remove the linear public PCS opening payload from public history.

New proof object:

```rust
pub struct PcsFriSourceBatchDeciderProof {
    pub layout_groups: Vec<AuthPcsLayoutGroupDigest>,
    pub fri_decider: FriBatchDeciderProof,
    pub source_decider: SourceTensorFoldBatchDeciderProof,
    pub terminal_opening_claim: [Block128; 2],
}
```

Implementation:

- group proofs by canonical Auth PCS layout;
- prove compact FRI query derivation and fold equations for all openings in one
  grouped decider;
- prove source TensorFold and source-cap Merkle equations in one grouped
  decider;
- prove equality between PCS terminal opening values and the batch-eval
  reductions produced by Phase 2;
- keep all FRI symbols, source symbols, Merkle siblings, and folded-layer data
  as private witness.

Tests:

- tamper FRI root rejects;
- tamper FRI queried symbol rejects;
- tamper FRI sibling rejects;
- tamper source cap node rejects;
- tamper source symbol rejects;
- tamper folded root rejects;
- tamper folded query symbol rejects;
- tamper terminal opening rejects;
- wrong query schedule rejects;
- extra or missing PCS opening rejects.

Bench gate:

```text
1 Standard4x8:
    auth accumulation proof <= 200 KB
    verify <= 250 ms
    HWM <= 1 GB

255 Standard4x8:
    auth accumulation proof <= 1 MB
    verify <= 500 ms
    HWM <= 1 GB

40 full Sweep25x2:
    auth accumulation proof <= 2 MB
    verify <= 1 s
    HWM <= 1.5 GB
```

Security update:

- add `PcsFriSourceBatchDeciderSoundness`;
- compose it with `CoreAuthAccumulatorSoundness`;
- upgrade the target authorization theorem to a concrete theorem using the
  implemented module names.

### Phase 4: OwnerAuthAccumulationProof Integration

Goal: replace public authorization sidecar authority in the public O(1) path.

Implementation:

- add `OwnerAuthAccumulationProof` verifier;
- add witness builder that consumes retained wallet proofs;
- update retained batch construction to produce the new proof as a component;
- keep direct wallet proof verification for mempool/full-node validation and
  differential tests;
- do not remove live block sidecars from propagation until networking policy is
  separately changed.

Tests:

- direct batch authorization and accumulated authorization agree on corpus
  blocks;
- missing, duplicated, swapped, or cross-transaction wallet proofs reject;
- coinbase-only batch has one canonical empty authorization proof shape.

Bench gate:

```text
255 Standard4x8 full block auth public payload <= 1 MB
40 full Sweep25x2 full block auth public payload <= 2 MB
```

### Phase 5: ExecutionBatchProof

Goal: make execution proof-native instead of relying on retained replay.

Implementation:

- prove tx-root over ordered bodies;
- prove tx body hash spines;
- prove exact action table;
- prove exact UTXO and ReuseGuard transition;
- prove fees, reward, supply, shape, and semantic resource bounds;
- bind execution and authorization to the same `BatchContextDigest`.

Tests:

- differential native `AcceptBlock` vs `ExecutionBatchProof`;
- action reorder rejects;
- state root mismatch rejects;
- fee/reward/supply mutation rejects;
- semantic bounds mutation rejects.

Security update:

- add `ExecutionBatchSoundness` and compose with authorization theorem.

### Phase 6: HeaderBatchProof

Goal: make header consensus proof-native for the final IVC step.

Implementation:

- prove `POWHDR__` and `BLOCKHDR` schedules;
- prove parent linkage;
- prove strict target comparison;
- prove ASERT, MTP, chainwork, and log-slot expansion;
- remove any dependence on host equality shortcuts.

Tests:

- strict equality target reject;
- parent mismatch reject;
- ASERT mutation reject;
- MTP mutation reject;
- chainwork mutation reject;
- expansion-window mutation reject.

Bench gate:

```text
255 headers absorbed into IVC relation without shipping a linear header wrapper
```

### Phase 7: Binary-Field History IVC

Goal: implement the public recursive history verifier.

Implementation:

```text
base case:
    fixed genesis RecursiveConsensusState

step:
    verify previous HistoryProof
    verify HeaderBatchProof
    verify ExecutionBatchProof
    check BatchContextDigest graph
    check exact start/end RecursiveConsensusState equality
    output new HistoryProof
```

Target API:

```rust
pub struct HistoryProof {
    pub proof_bytes: Vec<u8>,
    pub start: RecursiveConsensusState,
    pub end: RecursiveConsensusState,
    pub statement_digest: [u8; 32],
}

pub fn verify_history_proof(
    genesis: &RecursiveConsensusState,
    claimed_tip: &RecursiveConsensusState,
    proof: &HistoryProof,
) -> Result<(), HistoryProofError>;
```

Tests:

- genesis base accepts only the fixed genesis state;
- wrong previous proof rejects;
- wrong start/end state rejects;
- wrong module digest rejects;
- fork-choice test verifies two proofs and picks higher chainwork outside the
  proof verifier.

Bench gate:

```text
HistoryProof verify <= 1 s on target laptop for current max block sizes
HistoryProof public size <= 2 MB before final tuning
peak verifier RSS <= 1 GB
```

Security update:

- replace target theorem text with the concrete `HistoryProof` theorem;
- define exact soundness error accounting for the implemented IVC backend.

### Phase 8: Public Snapshot Activation

Goal: enable public arbitrary-peer snapshot sync.

Implementation:

- snapshot manifest carries `RecursiveConsensusState`, state roots, and
  `HistoryProof`;
- public verifier checks `HistoryProof`;
- public verifier checks snapshot `utxo_root`, `guard_root`, and composite
  `state_root`;
- public verifier compares cumulative chainwork across candidate proofs;
- retained replay remains only a local/test/witness-builder path.

Activation matrix:

- differential native vs proof corpus;
- malformed witness and tamper matrix;
- 1, 2, 16, 100, 255 Standard4x8 benches;
- 1, 2, 16, 40 full Sweep25x2 benches;
- auth-heavy mixed blocks;
- coinbase-only ranges;
- proof size, verify time, prover time, and peak RSS caps;
- full `docs/security.md` audit pass.

## 5. Current Next Step

The immediate next implementation task is Phase 1:

```text
OwnerAuthVerifyClaim shape
+ canonical statement digest with block_index and tx_index
+ canonical layout grouping
+ differential tests against direct VerifyAuthorization
```

Do not start the PCS batch decider until the claim language is frozen and tested.
That prevents reworking the decider around changing statement shapes.
