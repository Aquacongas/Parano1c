# O(1) Sync Roadmap

This roadmap tracks the path from the current O(1) checkpoint scaffold to the
complete cryptographic implementation.

## 1. Current Architecture

The current tree is wired as an end-to-end O(1) sync scaffold:

- Headers are stored forever from genesis. Header consensus stays native:
  PoW, chainwork, ASERT, MTP, log slots, state counters.
- Full block bytes, `BlockProof` bytes, `BlockAuthSidecar` bytes, and accepted
  history claim witnesses are transient. After finalized history coverage they
  are pruned outside the last 18-block suffix, but only after an accepted-block
  certificate record exists for that height.
- Accepted-block certificate records are produced at block acceptance time and
  stored as raw bytes in MDBX. They currently contain the hash-only certificate
  proof scaffold and act as a per-height pruning guard.
- Full accepted-block checkpoint batch packages can now be built from retained
  blocks, serialized, stored as raw bytes in MDBX, and verified later without
  retained `Block`/`BlockProof`/`BlockAuthSidecar` witnesses. They contain the
  checkpoint step statement, certificate batch statement, full proof-facing
  components, retained component proof, and checkpoint step proof.
- The background updater builds fixed 16-block checkpoint packages while their
  full witnesses are still inside the 18-block retained suffix, then promotes
  `CheckpointCoverage.history_proof_covered_to` only after the package is
  finalized and still matches canonical header anchors.
- P2P and RPC history proof serving use a public `HistoryCheckpointProofV1`
  exported from the latest promoted checkpoint package. The public proof is
  light and does not include retained blocks. There is no local-cache public
  proof fallback.
- P2P state manifests are served at the locally servable public proof height,
  not at the live tip. The peer reconstructs that finalized state from retained
  undo logs and exports segment roots/data for that exact height.
- Scaffold serving refuses to advertise a public proof if
  `local_tip - proof_height > RECENT_BLOCK_RETENTION_DEPTH`, because the peer
  can no longer provide the retained suffix after the snapshot boundary.
- After a snapshot proof is accepted, the client decodes the peer live tip from
  the proof response and prefetches `F+1..peer_tip` into a bounded in-memory
  suffix buffer before downloading state segments. The snapshot is applied at
  `F`, then the prefetched suffix is replayed with normal full block/proof/auth
  validation.
- Current protocol V1 overloads `GetStateManifestResponse.tip_height`,
  `tip_hash`, and `cumulative_chainwork` with the snapshot height `F` fields.
  It does not yet carry the peer's live tip separately, so manifest candidate
  selection currently compares snapshot chainwork rather than live-tip
  chainwork.
- Because `tip_height` is `F` in Manifest V1, the client treats every non-empty
  ahead manifest as a snapshot candidate. Shallow `<=18` sync is selected from
  block/header announcements, not from `F - local_tip`.
- If a retained suffix block is already unavailable, the client requests a fresh
  snapshot manifest instead of expecting the peer to keep a 19th block.
- Snapshot verification checks the manifest against locally verified headers
  through persisted `HeaderChainAnchor` records and a constant-size public
  proof envelope. Production snapshot sync accepts `HistoryCheckpointProofV1`
  only; the old `HistoryProof`/`NativeFoldV1` path is no longer a public
  authority.
- After applying the finalized snapshot, the node replays the retained suffix
  with normal full block validation.

Current sync mode selection:

Terminology below uses the final/live-tip wording. In the current scaffold,
block/header gossip discovers the deep gap, while manifest V1 advertises the
snapshot boundary `F` under the legacy `tip_height` field name.

```text
peer_tip <= local_tip:
  no sync

peer_tip - local_tip <= CONSENSUS_FINALITY_DEPTH:
  shallow sync
  -> request retained full blocks from local_tip + 1
  -> verify each block/proof/auth sidecar normally
  -> apply blocks one by one

peer_tip - local_tip > CONSENSUS_FINALITY_DEPTH:
  O(1) checkpoint snapshot sync
  -> sync/verify headers
  -> verify checkpoint/history proof at finalized snapshot height F
  -> download/apply state snapshot at F
  -> replay retained suffix blocks after F
```

O(1) is only the deep-sync path. The normal path for gaps up to 18 blocks is
still ordinary full-block replay.

Important current files:

- `noid_node/src/main.rs`
  - `verify_snapshot_history_proof_headers_anchored`
  - `run_checkpoint_package_worker`
- `noid_p2p/src/network.rs`
  - state manifest export at servable public proof height
  - checkpoint package proof serving
- `noid_block/src/accepted_block_batch.rs`
  - full accepted-block checkpoint package build/verify/export
- `noid_chain/src/storage/mdbx_store.rs`
  - persistent `T_HEADER_ANCHORS`
  - pruning by `RECENT_BLOCK_RETENTION_DEPTH` and history/checkpoint coverage
- `noid_recursive/src/checkpoint_proof.rs`
  - `verify_history_checkpoint_proof_v1_checkpoint`
- `noid_recursive/src/block_certificate.rs`
  - `verify_accepted_block_certificate_proof_v1_checkpoint`

Current scaffold limitations:

- `NativeFoldV1` still exists in `noid_recursive` library/tests as a scaffold
  type, but node/P2P/RPC snapshot authority no longer accepts it.
- Digest/hash-only accepted-block certificate paths still exist as scaffold
  per-height inputs.
- `HistoryCheckpointProofV1` verifies the envelope/head shape, but the final
  recursive backend proof still needs real previous-head and certificate-validity
  verification.
- Full accepted-block checkpoint batch package generation, MDBX raw-byte
  storage, background finalized chunk building, sequential coverage promotion,
  and P2P proof serving are wired. The public checkpoint proof still carries a
  scaffold recursive backend payload until Phase 4 closes previous-head
  recursion.
- Manifest V1 does not bind `snapshot_height` and `peer_tip_height` separately.
  The suffix is requested after applying the snapshot, but the manifest itself
  cannot yet state the exact `F+1..peer_tip` range.
- Pruning uses proven checkpoint coverage only and also requires an
  accepted-block certificate record at each pruned height.

Current crypto backend / verifier status:

What already exists:

- Low-level crypto/proof infrastructure:
  `noid_gkr`, `noid_ivc_core`, `noid_ivc_prover`, Poseidon2b hash schedules,
  fixed-field hash KillShot proofs, transcript proofs, and PCS/IVC components.
- Full native accepted-block batch boundary:
  `noid_block/src/accepted_block_batch.rs` re-verifies retained full blocks and
  reconstructs accepted claims/certificate material.
- Accepted-block certificate statement/receipt/handle types:
  `noid_recursive/src/block_certificate.rs`.
- Certificate receipt-projection IVC subrelation:
  `noid_recursive/src/block_certificate_ivc.rs`.
- Checkpoint chunk continuity IVC core:
  `noid_recursive/src/checkpoint_ivc_backend.rs`.
- Current scaffold verifier entrypoint names are temporary:

```rust
verify_accepted_block_certificate_proof_v1_checkpoint(...)
verify_history_checkpoint_step_proof_v1_checkpoint(...)
verify_history_checkpoint_proof_v1_checkpoint(...)
```

Before first public launch these names must be flattened to one clean API
without `_v1`, `V1`, `V2`, `version`, backend-kind, or compatibility wrappers.
There is no deployed compatibility contract yet, so final code should not carry
legacy branches.

What is still scaffold:

- `NativeFoldV1` remains as non-authoritative recursive/library scaffold, not
  as production snapshot authority.
- `prove_accepted_block_certificate_proof_v1_hash_only` still appears in
  scaffold paths. It proves statement/digest shape, not the full block-validity
  relation.
- `verify_history_checkpoint_proof_v1_checkpoint` checks the public checkpoint
  envelope and recursive head shape, but the recursive `backend_proof` is not
  yet the final previous-head-validity proof.
- The checkpoint IVC core currently consumes certificate handles/receipts; the
  final backend must verify certificate proof validity inside the recursive
  path.
- `verify_checkpoint_step_certificate_validity_backend_v1` still treats empty
  certificate statement/proof sidecars as acceptable scaffold shape.
- `checkpoint_ivc_backend.rs` can still derive receipt/handle pairs from
  certificate statements by building hash-only certificate proofs internally.
  Final code must consume persisted certificate proofs produced before pruning
  instead.

So the answer is: the crypto building blocks mostly exist, but the final public
recursive verifier is not fully assembled yet. The roadmap work is integration
and replacement of scaffold subrelations, not inventing the whole crypto stack
from zero.

Final crypto design decision:

- Do not introduce a new public primitive stack for the first launch. The
  existing stack is sufficient:
  - Poseidon2b over `Block128` for block ids, state roots, transcript binding,
    statement digests, proof digests, and Fiat-Shamir.
  - `noid_gkr` KillShot proofs for fixed-field hashes, tx-body spines, tx-root
    Merkle checks, authorization transcript checks, exact-state slot/path/root
    checks, and ReUseGuard checks.
  - `noid_ivc_core` / `noid_ivc_prover` Boolean R1CS + sumcheck/zerocheck +
    multilinear PCS/Ligerito for fixed certificate and checkpoint proof cores.
  - Native header verification for PoW, chainwork, ASERT, MTP, and log slots.
- The final proof stack is two-layered:
  1. Accepted-block certificate issuance proves the tx-dependent block-validity
     relation while full block/proof/auth bytes are still retained.
  2. Checkpoint recursion folds only fixed-size certificate statements,
     receipts, validity proofs/handles, header anchors, and accumulator
     transitions.
- `noid_recursive/src/block_certificate_backend.rs` is the verifier-language
  boundary for final certificate validity. It already names the components that
  must be proven: accepted claim hash, tx body hash/spine, tx root, auth
  statements/transcripts, checkpoint Poseidon transition, exact state paths, and
  ReUseGuard paths.
- `noid_recursive/src/block_certificate_ivc.rs` remains a subrelation for
  receipt projection. It is not full certificate validity by itself.
- `noid_recursive/src/checkpoint_ivc_backend.rs` remains the fixed 16-slot
  checkpoint core. Its final form must prove certificate validity and previous
  recursive-head validity inside the backend, not only receipt/handle shape.
- The checkpoint backend must not synthesize certificate handles from statements
  during proof generation or verification. Handles come from already-verified
  certificate proofs stored at block acceptance time.
- The history/checkpoint layer must never replay transaction-shaped component
  lists. Tx-count-dependent work ends at certificate issuance; checkpoint
  proving consumes fixed certificate outputs.
- Keep one field/hash/transcript family end to end. Avoid Groth16/STARK/foreign
  field adapters/new hash functions/new PCS unless profiling later proves an
  unavoidable bottleneck. Those would add complexity without changing the core
  O(1) architecture.
- Before first launch there is one clean proof shape and one clean verifier API.
  Remove public `version`, backend-kind dispatch, `_v1`, `V1`/`V2`, and
  compatibility branches instead of carrying dormant legacy code.

## 2. Final Architecture And Invariants

Final sync cost:

```text
O(headers) native header sync
+ O(1) execution/history proof verification
+ O(live state) snapshot download
+ O(18) suffix replay
```

Hard invariants:

- Headers are stored forever and are the only source of header consensus truth.
- Header work, ASERT, MTP, and log-slot consensus are not inside history
  aggregation.
- Full block bytes, `BlockProof` bytes, `BlockAuthSidecar` bytes, and local
  accepted-claim witnesses are stored only for the retained suffix.
- `18` is finality/suffix/retention depth. It is not the recursive batch size.
- Recursive checkpoint batch size stays independent, currently `16`.
- The miner/block layer handles tx-size-dependent work:
  tx body binding, authorization proof, tx root, exact UTXO/ReUseGuard state
  transition, and accepted-block certificate issuance.
- The history/checkpoint layer consumes only fixed-size accepted-block
  receipts/certificates.
- Snapshot manifest height is a finalized proof-covered height `F`.
- `F` must be serveable with the retained suffix invariant:
  `F <= peer_tip - CONSENSUS_FINALITY_DEPTH` and
  `peer_tip - F <= RECENT_BLOCK_RETENTION_DEPTH`. With both constants currently
  equal to `18`, a fully up-to-date peer advertises `F = peer_tip - 18`.
- Live mining can move the retained suffix while a snapshot is downloading. The
  node must never solve that by storing block `tip - 18` as a 19th retained
  block. The final client should prefetch the manifest suffix `F+1..peer_tip`
  into a bounded pending buffer before downloading the state snapshot. If
  `F+1` is already unavailable, restart from a fresh manifest at the newer
  finalized boundary.
- Any retention slack must be explicit protocol configuration, not hidden
  behavior. If the design ever changes to keep more than 18 full blocks, it
  must be represented as `RECENT_BLOCK_RETENTION_DEPTH > CONSENSUS_FINALITY_DEPTH`
  and tested as a new invariant. The current target remains exactly 18.
- `MIN_SNAPSHOT_CHAINWORK` is an admission/resource floor for a header-verified
  snapshot boundary. It is not fork choice. Fork choice remains exact cumulative
  PoW chainwork over natively verified headers.
- Snapshot state root must equal the locally verified header `state_root` at
  `F`.
- Suffix blocks `F+1..tip` are always replayed with normal validation.

Final sync mode selection remains the same:

```text
gap <= 18:
  block replay only

gap > 18:
  checkpoint snapshot at finalized proof-covered F
  then bounded suffix prefetch
  then snapshot apply
  then suffix replay
```

Final data flow:

```text
Block accepted
  -> emit accepted-block certificate statement/proof/receipt
  -> fold finalized receipts in 16-block checkpoint chunks
  -> update recursive checkpoint head
  -> mark checkpoint coverage height F
  -> advertise snapshot only if peer_tip - F <= 18
  -> prune payload witnesses older than tip - 18 and <= F

Joining node
  -> sync/verify headers
  -> request checkpoint snapshot manifest with F and peer live tip
  -> verify O(1) checkpoint proof at F
  -> prefetch full suffix blocks F+1..peer_tip into a bounded <=18 buffer
  -> download/verify state segments for F
  -> apply snapshot at F
  -> replay prefetched suffix blocks F+1..peer_tip
  -> shallow-sync any blocks mined after peer_tip
```

Final manifest shape:

```rust
pub struct CheckpointSnapshotManifest {
    pub snapshot_height: u64,
    pub snapshot_block_id: [u8; 32],
    pub snapshot_state_root: [u8; 32],
    pub snapshot_chainwork: [u8; 32],

    pub peer_tip_height: u64,
    pub peer_tip_block_id: [u8; 32],
    pub peer_tip_chainwork: [u8; 32],

    pub checkpoint_proof_bytes: Vec<u8>,

    pub eff_log: u8,
    pub segment_ids: Vec<u16>,
    pub segment_roots: Vec<[u8; 32]>,
    pub reuse_guard_buckets: Vec<noid_chain::reuse_guard::GuardBucket>,

    pub suffix_start: u64,
    pub suffix_end: u64,
}
```

## 3. Concrete Phases To Full O(1)

### Phase 0: Scaffold Wiring

Status: implemented in this branch.

Done:

- Manifest export is finalized-height based.
- Snapshot apply treats the manifest height as finalized.
- Manifest V1 still names that finalized snapshot height `tip_height`; the final
  manifest removes this naming/semantics overload.
- Manifest V1 handling no longer downgrades to shallow block sync from
  `manifest.tip_height - local_tip`, because that value is `F - local_tip`, not
  `peer_tip - local_tip`.
- Missing retained next-block responses trigger fresh snapshot manifest retry.
- Snapshot verification rejects boundaries below `MIN_SNAPSHOT_CHAINWORK` after
  matching manifest chainwork to locally verified headers.
- Snapshot verification accepts `HistoryCheckpointProofV1` against local header
  anchors and rejects old `HistoryProof`/`NativeFoldV1` public authority bytes.
- P2P and RPC proof serving use checkpoint package proofs only.
- Snapshot client prefetches the bounded retained suffix before segment
  download and replays it after applying the snapshot.
- Pruning of retained payloads is back and coverage-gated.
- Old disabled/public-blocker wording was replaced by checkpoint scaffold
  wording.

Acceptance:

```text
cargo fmt --all
cargo check -p noid_node -p noid_p2p --release
cargo test -p noid_block --release full_batch_checkpoint_package_serializes_and_verifies_without_blocks
cargo test -p noid_node --release snapshot_history_boundary_checks_local_header_chainwork
cargo test -p noid_chain --release block_payloads_prune_after_checkpoint_history_coverage
cargo test -p noid_recursive --release --lib checkpoint_scaffold
```

### Phase 1: Persistent Header Anchor Table

Status: implemented in this branch.

Done:

- Added persistent `T_HEADER_ANCHORS` in MDBX.
- Added fixed storage encoding for `HeaderChainAnchor`.
- `commit_block` stores a header anchor atomically with canonical header and
  cumulative chainwork.
- `put_verified_header_only` stores a header anchor for header-only sync.
- Snapshot history proof verification now reads local start/end anchors from
  MDBX and rejects proof-supplied projection-root tampering.
- `local_header_boundary_anchor_scaffold` was removed.

Original goal: remove `local_header_boundary_anchor_scaffold`.

Implemented MDBX table:

```rust
const T_HEADER_ANCHORS: &str = "header_anchors";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredHeaderAnchor {
    pub height: u64,
    pub anchor: noid_chain::HeaderChainAnchor,
}
```

Canonical header inserts now compute the anchor in the same MDBX transaction as
the header and cumulative chainwork:

```rust
let previous = store.get_header_anchor(header.height - 1)?;
let anchor = extend_header_chain_anchor(&previous, header, cumulative_chainwork)?;
txn.put(T_HEADER_ANCHORS, header.height, encode_header_chain_anchor(&anchor))?;
```

For genesis:

```rust
let genesis_anchor = compute_header_chain_anchor([&genesis_header], genesis_work)?;
txn.put(T_HEADER_ANCHORS, 0, encode_header_chain_anchor(&genesis_anchor))?;
```

Snapshot verification now resolves local anchors through storage:

```rust
store.get_header_anchor(height)?
```

Tests:

- Restart preserves anchors.
- Header-only sync persists anchors.
- Tampered proof `projection_root` is rejected.
- Fresh node snapshot verification does not scan `0..height`.

Acceptance:

```text
cargo test -p noid_chain --release verified_headers_persist_header_chain_anchors
cargo test -p noid_chain --release open_fresh_database
cargo test -p noid_chain --release apply_one_block_and_reopen
cargo test -p noid_node --release snapshot_history_boundary_checks_local_header_chainwork
cargo check -p noid_node -p noid_p2p --release
```

### Phase 2: Accepted-Block Certificate Issuance And Full Batch Package

Status: implemented for Phase 2 scope. Per-height pruning guard and
component-backed batch package storage are wired; replacing the scaffold
certificate-validity backend is Phase 4/7 crypto work, not a Phase 2 carryover.

Done:

- Added persistent raw `accepted_block_certificates` table in MDBX.
- Added `AcceptedBlockCertificateRecord` in `noid_block`.
- P2P block acceptance and reorg application now build and store certificate
  records before old payload witnesses are eligible for pruning.
- Current records use the existing hash-only certificate proof scaffold.
- Payload pruning now requires both history/checkpoint coverage and an
  accepted-block certificate record for that height.
- Snapshot install/restart cleanup clears transient certificate records with
  other payload witness tables.
- Added `FullAcceptedBlockBatchCheckpointPackageV1` in `noid_block`.
- The package builder replays retained blocks once, proves
  `FullAcceptedBlockBatchProofComponents`, builds the checkpoint step statement,
  and proves the checkpoint step from the full components.
- The package verifier checks the decoded component proof and checkpoint step
  without retained block bodies/proofs/auth sidecars.
- Added persistent raw `accepted_block_batch_certificate_packages` table in
  MDBX, keyed by checkpoint package end height.
- Added serde/wire support for the proof-facing component structs needed by the
  package.

Goal: every block has fixed certificate material before it leaves the 18-block
window, and every finalized chunk can be represented by a persistent proof-side
package before payload witnesses are pruned.

Implemented persistent certificate table:

```rust
const T_ACCEPTED_BLOCK_CERTIFICATES: &str = "accepted_block_certificates";
const T_ACCEPTED_BLOCK_BATCH_CERTIFICATE_PACKAGES: &str =
    "accepted_block_batch_certificate_packages";

pub struct AcceptedBlockCertificateRecord {
    pub height: u64,
    pub statement: AcceptedBlockCertificateStatement,
    pub proof: AcceptedBlockCertificateProof,
    pub receipt: AcceptedBlockCertificateReceipt,
    pub validity_handle: AcceptedBlockCertificateValidityHandle,
}

pub struct FullAcceptedBlockBatchCheckpointPackage {
    pub step_statement: HistoryCheckpointStepStatement,
    pub certificate_batch_statement: AcceptedBlockCertificateBatchStatement,
    pub components: FullAcceptedBlockBatchProofComponents,
    pub proof: RetainedFullAcceptedBlockBatchProof,
    pub checkpoint_step_proof: HistoryCheckpointStepProof,
}
```

Block acceptance must do:

```rust
let statement = accepted_block_certificate_statement(...)?;
let proof = prove_accepted_block_certificate_proof_hash_only_scaffold(&statement)?;
let receipt = accepted_block_certificate_receipt(&statement);
let handle = accepted_block_certificate_validity_handle(&proof)?;
store.put_accepted_block_certificate(height, record)?;
```

Full batch package path:

```rust
let package = prove_full_accepted_block_batch_checkpoint_package_from_boundary(
    start_anchor,
    start_consensus,
    start_accumulator,
    start_parent,
    start_state,
    retained_witness,
)?;
verify_full_accepted_block_batch_checkpoint_package(&package)?;
store.put_accepted_block_batch_certificate_package(package.end_height(), bytes)?;
```

Remaining cryptographic replacement:

```rust
prove_accepted_block_certificate_proof_hash_only
```

The hash-only per-height proof remains temporary. The full batch package already
proves accepted-block components, but the final public recursive backend must
make certificate validity part of the recursive proof rather than relying on
digest-only certificate handles.

Tests:

- A block cannot be pruned unless certificate record exists.
- Tampered tx root, auth sidecar digest, exact transition digest, or claim digest
  makes certificate verification fail.
- Tampered certificate component proof is rejected by
  `verify_accepted_block_batch_components`.
- Coinbase-only blocks still produce a fixed certificate/receipt.

Acceptance:

```text
cargo test -p noid_block --release certificate_record_hash_only_scaffold_binds_statement_receipt_and_handle
cargo test -p noid_chain --release accepted_block_certificate_roundtrip
cargo test -p noid_chain --release accepted_block_batch_certificate_package_roundtrip
cargo test -p noid_block --release full_batch_checkpoint_package_serializes_and_verifies_without_blocks
cargo test -p noid_chain --release block_payloads_prune_after_checkpoint_history_coverage
cargo test -p noid_chain --release block_payloads_do_not_prune_without_certificate_record
cargo test -p noid_node --release snapshot_history_boundary_checks_local_header_chainwork
cargo check -p noid_node -p noid_p2p --release
```

### Phase 3: 16-Block Checkpoint Chunk Worker

Status: implemented in this branch. Package build/store, sequential finalized
coverage promotion, public checkpoint proof export, P2P/RPC proof serving,
manifest selection by servable public proof height, checkpoint-only pruning, and
local-cache storage removal are complete for this milestone.

Goal: automatically fold finalized accepted-block packages in fixed chunks and
advance local proven checkpoint coverage.

The raw package table already exists:

```rust
const T_ACCEPTED_BLOCK_BATCH_CERTIFICATE_PACKAGES: &str =
    "accepted_block_batch_certificate_packages";

pub struct FullAcceptedBlockBatchCheckpointPackage {
    pub start_height: u64,
    pub end_height: u64,
    pub statement: HistoryCheckpointStepStatement,
    pub certificate_batch_statement: AcceptedBlockCertificateBatchStatement,
    pub components: FullAcceptedBlockBatchProofComponents,
    pub proof: RetainedFullAcceptedBlockBatchProof,
    pub checkpoint_step_proof: HistoryCheckpointStepProof,
}
```

Worker loop:

```rust
let start = previous_head.checkpoint_height + 1;
let end = start + HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS - 1;
// Build while still retained, before finality promotion.
let retained = store.get_retained_full_batch_witness(start..=end)?;
let package = prove_full_accepted_block_batch_checkpoint_package(
    previous_head,
    start_anchor,
    start_consensus,
    start_accumulator,
    start_parent,
    start_state,
    retained,
)?;
verify_full_accepted_block_batch_checkpoint_package(&package)?;
store.put_accepted_block_batch_certificate_package(package.end_height(), bytes)?;
// Promote later, only after end <= tip - 18 and anchors still match canonical headers.
store.put_checkpoint_coverage(history_proof_covered_to = Some(package.end_height()))?;
```

Implemented worker behavior:

- Builds the next 16-block package as soon as `end <= tip` and the package
  start state is still reconstructable from at most 18 undo logs.
- Deletes stale/corrupt latest packages if their decoded end height or boundary
  anchors no longer match canonical stored header anchors.
- Promotes coverage sequentially (`covered + 16`), so an unfinalized later
  package cannot block promotion of an earlier finalized package.
- Re-verifies the package and re-checks canonical anchors immediately before
  `CheckpointCoverage.history_proof_covered_to` advances.
- Exports a public `HistoryCheckpointProofV1` from the latest promoted package
  without retained blocks and serves it as the only public proof authority.
- Refuses to serve checkpoint proof bytes for snapshot sync when
  `tip - proof_height` exceeds `RECENT_BLOCK_RETENTION_DEPTH`; this prevents
  fast-mining bursts from producing stale manifest/proof pairs that cannot be
  completed with the retained suffix.
- Client-side scaffold now uses the proof response peer tip header to prefetch
  the retained suffix before state segments. If the suffix length is greater
  than `RECENT_BLOCK_RETENTION_DEPTH`, or a suffix block is unavailable, the
  session is discarded and a fresh manifest is requested.

The chunk backend receives fixed certificate data only:

```rust
certificate_statements: [AcceptedBlockCertificateStatement; 16]
certificate_receipts: [AcceptedBlockCertificateReceipt; 16]
certificate_validity: [AcceptedBlockCertificateProof; 16]
accepted_claim_batch_digest
start/end header anchors
start/end chain accumulators
```

It must not receive block bodies, transaction bodies, authorization sidecars, or
exact-state path lists.

Tests:

- Missing certificate blocks chunk generation.
- Bad receipt order fails.
- Chunk `end_height` must equal previous height + batch len.
- Chunk size remains independent from tx count.
- Restart resumes from the latest stored package/head.
- Checkpoint coverage advances only after package verification succeeds.
- Pruning uses proven package coverage only and never uses local-cache height as
  coverage.
- The worker never asks storage for height `tip - 18 - 1`; if the chunk cannot
  be built from retained witnesses, it waits for or fetches a newer manifest
  instead of expanding the full-block retention invariant.

### Phase 4: Recursive Checkpoint Head

Goal: `HistoryCheckpointProof` verifies previous-head validity, not just final
head shape.

Add table:

```rust
const T_HISTORY_CHECKPOINT_HEADS: &str = "history_checkpoint_heads";

pub struct HistoryCheckpointHeadRecord {
    pub height: u64,
    pub head: HistoryCheckpointHead,
    pub recursive_proof: HistoryCheckpointProof,
}
```

Final verifier must check:

```rust
verify_previous_recursive_head(previous_head, previous_proof)?;
verify_checkpoint_step(statement, certificate_batch, step_proof)?;
verify_head_transition(previous_head, batch_summary, next_head)?;
```

Replace `HistoryCheckpointRecursivePayload.backend_proof` scaffold bytes with
the actual recursive backend proof.

The final public checkpoint proof is constant-size with respect to chain height:
it verifies one recursive head, not a linear list of historical chunks.

Tests:

- Swapping previous head fails.
- Swapping backend proof fails.
- Empty backend proof fails.
- Proof size stays constant across 1, 2, 10 chunks.

### Phase 5: Final Manifest And Suffix Tip Binding

Goal: manifest advertises both snapshot height `F` and peer live tip.

Add protocol:

```rust
GetCheckpointSnapshotManifest
GetCheckpointSnapshotSegment
GetCheckpointProof
```

Serving rule:

```rust
let peer_tip = store.tip_height();
let f = store.latest_checkpoint_coverage_height()?;
require(f <= peer_tip - CONSENSUS_FINALITY_DEPTH);
require(peer_tip - f <= RECENT_BLOCK_RETENTION_DEPTH);
manifest.snapshot_height = f;
manifest.suffix_start = f + 1;
manifest.suffix_end = peer_tip;
```

Client rule:

```rust
verify headers through manifest.peer_tip_height;
verify checkpoint proof at manifest.snapshot_height;
reject if manifest.suffix_end - manifest.snapshot_height > RECENT_BLOCK_RETENTION_DEPTH;
select candidate by manifest.peer_tip_chainwork, then manifest.peer_tip_height;
require snapshot_chainwork >= MIN_SNAPSHOT_CHAINWORK;
prefetch full blocks manifest.suffix_start..=manifest.suffix_end into a bounded pending buffer;
verify each prefetched suffix block header/proof/auth sidecar shape before committing snapshot;
if manifest.suffix_start is unavailable, discard the session and request a fresh manifest;
download and verify snapshot segments for manifest.snapshot_height;
apply snapshot at F;
replay the prefetched suffix;
shallow-sync blocks after manifest.peer_tip_height if new blocks appeared;
```

Tests:

- Manifest with suffix longer than 18 is rejected.
- Peer refuses to advertise a snapshot when checkpoint coverage lags beyond the
  retained suffix window.
- Live miner advances during snapshot download; if the first replay block falls
  out of the retained suffix before suffix prefetch, the client retries from a
  fresh manifest.
- Live miner advances during snapshot download after suffix prefetch; the
  prefetched bounded suffix still replays to the manifest peer tip, then the
  node continues with ordinary shallow sync.
- Pending suffix buffer never exceeds `RECENT_BLOCK_RETENTION_DEPTH`.
- No hidden 19th/20th block retention is required or accepted by tests.
- Snapshot below `MIN_SNAPSHOT_CHAINWORK` is rejected, but this floor is never
  used to choose between competing chains.
- Manifest snapshot root must match local header at `F`.
- Peer tip chainwork tie-break uses header-verified chainwork.

### Phase 6: Final Pruning Gate

Status: completed early in Phase 3.

Final pruning authority is already checkpoint coverage only:

```rust
coverage_height = real_checkpoint_coverage
    .and_then(|c| c.history_proof_covered_to);
```

Pruning rule:

```rust
let cutoff = min(tip - RECENT_BLOCK_RETENTION_DEPTH, coverage_height);
delete from recent/block_proofs/auth_sidecars/history_claims where height <= cutoff;
```

Tests:

- No recursive checkpoint coverage means no payload pruning.
- Coverage to `F` prunes exactly `<= min(tip-18, F)`.
- Last 18 full blocks always remain serveable.

### Phase 7: Remove Scaffold Backends

Goal: final clean names stay, scaffold internals disappear.

Remove production use of:

- `NativeFoldV1` as snapshot authority.
- `ArcPcdV1` / backend-kind dispatch as public authority.
- local claim sidecars as pruning coverage.
- `prove_accepted_block_certificate_proof_v1_hash_only`.
- digest-only certificate backend in checkpoint paths.
- proof-supplied header projection root.
- `version` fields, `V1`/`V2` type suffixes, and compatibility wrappers.

Keep only:

```rust
verify_history_proof_checkpoint
verify_history_checkpoint_proof
verify_history_checkpoint_step_proof
verify_accepted_block_certificate_proof
```

The implementations behind those names are fully recursive.

## 4. Placeholder And TODO Closure Order

Close these in order:

1. Completed: persistent header anchors
   - `noid_node/src/main.rs::local_header_boundary_anchor_scaffold` was
     removed.
   - Snapshot proof verification now uses stored `HeaderChainAnchor` records.

2. Completed: `noid_node/src/main.rs::run_checkpoint_package_worker`
   - Accepted-block certificate storage is now produced at block acceptance.
   - Build retained `FullAcceptedBlockBatchWitness` for finalized 16-block
     chunks while those blocks are still inside the 18-block window.
   - Call `prove_full_accepted_block_batch_checkpoint_package`.
   - Store the serialized package in
     `accepted_block_batch_certificate_packages`.
   - Advance `CheckpointCoverage.history_proof_covered_to` only after package
     verification succeeds.
   - Old local-cache coverage production was removed from the node worker.

3. Completed: public proof serving
   - `noid_block::public_history_checkpoint_proof_from_package_v1` exports a
     `HistoryCheckpointProofV1` from a promoted package without retained blocks.
   - `noid_p2p` and `noid_rpc` serve checkpoint package proofs only.
   - Snapshot verification accepts checkpoint proof bytes only.
   - Local-cache public proof serving, local-cache pruning authority, and
     local-cache MDBX storage were removed from the runtime/storage path.

4. `noid_block/src/accepted_block_certificate.rs` and
   `noid_block/src/accepted_block_batch.rs`
   - Keep `FullAcceptedBlockBatchCheckpointPackage` as the persisted
     proof-side package.
   - Replace `accepted_block_certificate_record_hash_only_scaffold` and
     `prove_accepted_block_certificate_proof_hash_only` with the final
     certificate-validity proof once `checkpoint_ivc_backend` consumes full
     certificate proofs instead of digest-only handles.

5. `noid_recursive/src/block_certificate.rs`
   - Remove digest-only backend from checkpoint verifier.

6. `noid_recursive/src/block_certificate_ivc.rs`
   - Keep receipt projection IVC as a subrelation, but do not treat it as full
     certificate validity.

7. `noid_recursive/src/checkpoint_ivc_backend.rs`
   - Replace validity handles-only logic with actual certificate proof
     verification inside the recursive backend.
   - Remove internal hash-only certificate proof synthesis from certificate
     statements.

8. `noid_recursive/src/checkpoint_proof.rs`
   - Make `verify_history_checkpoint_proof` verify backend proof
     recursion, previous head validity, and step proof validity.
   - Remove the empty-certificate-sidecar success path from
     `verify_checkpoint_step_certificate_validity_backend`.

9. `noid_recursive/src/verify.rs::accept_public_snapshot_authority_scaffold`
   - Remove the exported scaffold authority hook, or make it a thin wrapper over
     the real checkpoint verifier.

10. Completed: `noid_chain/src/storage/mdbx_store.rs`
   - Pruning now uses only
     `CheckpointCoverage.history_proof_covered_to`.
   - Header bytes, header anchors, hash-to-height indexes, and chainwork are
     preserved by local recovery cleanup.
   - Checkpoint coverage is cleared together with checkpoint package bytes if
     local state recovery resets volatile state.

11. `noid_chain/src/storage/mdbx_context.rs::generate_immutable_checkpoint_at`
   - Replace prefix rebuild of payload roots with rolling payload roots, because
     full block payloads are retained only for the suffix.

12. `noid_p2p/src/protocol.rs`
    - Replace the scaffold manifest with the final manifest carrying separate
      `snapshot_height` and `peer_tip_height`.

13. `noid_p2p/src/network.rs`
    - Stop overloading manifest `tip_height` as snapshot height; serve a final
      manifest only when `F` is finalized and
      `peer_tip - F <= RECENT_BLOCK_RETENTION_DEPTH`.
    - Import or request checkpoint packages/public checkpoint heads after a
      remote snapshot is accepted, so a node that was offline during local
      package construction can become a proof-serving peer without replaying
      pruned retained witnesses.

14. Global cleanup before first public launch
    - Delete `_v1` functions, `V1`/`V2` type suffixes, `version` fields,
      backend-kind enums, unused wrappers, and all compatibility-only branches.
      Do not leave dead legacy paths in production code.

15. `docs/security.md`
    - Move scaffold caveats into an archived section when phases 1-7 are done.

## 5. Final Acceptance Checklist

- Fresh node syncs by headers + O(1) checkpoint proof + state snapshot + 18
  suffix blocks.
- Verification time for history proof is independent of chain height.
- Snapshot state bytes scale only with live state, not history.
- Full block/proof/auth storage stays bounded to 18 blocks after coverage.
- Snapshot serving is refused when checkpoint coverage is older than the
  retained 18-block suffix.
- Manifest candidate selection uses live peer-tip chainwork, not snapshot
  chainwork.
- Tampering any certificate, receipt, checkpoint step, recursive head, state
  segment, reuse guard bucket, or suffix block fails deterministically.
- Removing transaction bodies older than 18 does not prevent future checkpoint
  proof serving.
