# Final O(1) History Roadmap

This document is the production target for trustless O(1) snapshot sync. It is
intentionally narrow: it describes the final architecture, the proof
obligations, what is already implemented, and the concrete path from the
current code to the final verifier.

## Final Goal

A new node must be able to sync from arbitrary peers without replaying old
block bodies:

```text
headers from genesis to tip
+ one constant-size finalized-history proof at checkpoint F
+ snapshot state whose root equals header[F].state_root
+ normally verified suffix blocks F+1..tip
= accepted local tip state
```

The retained data window is 18 blocks. The checkpoint batch target is 16
accepted blocks. There is no larger history batch target in this protocol path.

The old finalized body data may be pruned only after the recursive history
proof covers it.

## Prefix Proof vs Retained Window

The O(1) history proof covers a monotonic finalized prefix. It is not a proof
of the moving last-18-block window.

```text
height H:

[ finalized prefix already covered by Proof_C ] [ unaggregated retained suffix ]
0 ......................................... C   C+1 ....................... H

public sync checks:
  Proof_C verifies the prefix up to C
  suffix blocks C+1..H are replayed normally
```

When enough finalized suffix blocks accumulate, the worker folds the next
checkpoint chunk:

```text
Proof_C + blocks C+1..C+16 + BlockProof/AuthSidecar witnesses
    -> Proof_{C+16}
```

After that, the coverage height advances:

```text
[ finalized prefix covered by Proof_{C+16} ] [ fresh retained suffix ]
0 .................................... C+16   C+17 ...................... H
```

The retained window is only the local safety buffer for recent block bodies,
reorg/finality handling, and worker lag. The batch target is 16 so the worker
can fold finalized data before the 18-block retention boundary is reached. The
node must never prune block bodies that are older than the retained suffix
unless `history_proof_covered_to` has already passed them.

## Trust Model

The sync peer is untrusted. The peer may send headers, snapshot chunks, block
proofs, sidecars, and the history proof, but none of those objects are trusted
without verification.

The node accepts a snapshot only if all checks below pass:

```text
             headers[0..tip]
                  |
                  v
       native PoW + chainwork verification
                  |
                  v
       local HeaderChainAnchor at F
                  |
                  +------------------------------+
                                                 |
HistoryCheckpointProofV1                         |
  recursive_proof                                |
  end_anchor ------------------------------------+
  end_accumulator.state_root
                  |
                  v
       O(1) recursive verifier
                  |
                  v
       proven checkpoint state root
                  |
                  v
       must equal header[F].state_root
                  |
                  v
       verify snapshot chunks against that root
                  |
                  v
       replay suffix blocks F+1..tip normally
```

Headers protect ordering and work. The recursive history proof protects the
validity of the old block transitions. The snapshot root binds the state bytes
to the proven checkpoint. The retained suffix is checked by the normal block
acceptance path.

## Non-Negotiable Design

- The public recursive path uses Poseidon2b/KillShot-compatible hashing only.
- Non-production hash/comparator experiments cannot become public recursive
  authority.
- The final proof derives accepted claims from verified block certificates.
  Peer-provided accepted-claim sidecars are cache hints only.
- History aggregation never re-proves transaction internals as its public
  surface. Transaction-dependent work belongs to the existing block proof
  layer.
- The final public proof size and public verification time do not depend on the
  number of transactions in historical blocks.
- P2P/RPC snapshot acceptance stays fail-closed until the multi-step recursive
  backend verifies real proofs.

There are two verifier layers and they must not be conflated:

```text
production block verifier in noid_block:
  block body + BlockProof + BlockAuthSidecar + state/auth witnesses
  -> accepted block artifacts

history aggregation verifier in noid_recursive:
  canonical components derived from those accepted artifacts
  -> accepted-claim batch + checkpoint step
```

`noid_recursive` must not become the owner of block parsing, transaction
application, or serialized `BlockProof` replay. Those stay in `noid_block` and
are still measured by `block_scaling`.

## Final Objects

### Existing block layer

This layer already exists and remains owned by block production and normal
block validation.

Objects:

- `BlockProof`
- `BlockAuthSidecar`
- block body
- state witnesses
- authorization witnesses
- exact-state witnesses

This layer may have prover cost and proof component sizes that depend on the
transaction shape, within protocol block limits. That is expected. It is not
the O(1) history proof.

The required statement is:

```text
VerifyBlockCertificate(parent_state, block, BlockProof, BlockAuthSidecar)
  -> child_state
  -> AcceptedStateTransitionClaim
```

The final history prover may use these objects as private witnesses, but the
network-facing history proof exposes only a constant-size recursive proof and
fixed checkpoint boundary data.

### Accepted-claim certificate layer

This is the bridge between full block validation and history folding.

For each historical block:

```text
full block certificate is verified
accepted claim is derived inside the proof
accepted claim is folded into the history accumulator
```

The peer must not be able to choose accepted claim fields directly. A bad claim
must require forging either the block certificate verifier or the recursive
proof.

Current code already has the native digest boundary:

- `noid_recursive::accepted_claim_batch_digest_v1`
- `noid_block::accepted_claim_batch_digest_v1` as a thin wrapper over the
  recursive schedule
- `noid_block::history_checkpoint_batch_summary_from_full_accepted_output_v1`

Important: `accepted_claim_batch_digest_v1` uses a fixed 16-slot
Poseidon2b/KillShot-compatible schedule over header witnesses, accepted claims,
end consensus state, and end accumulator. It does not absorb tx-body,
exact-state, authorization, or tx-root statement lists. Those details are
verified by the block certificate layer and are private to the history prover.

### Checkpoint step layer

A checkpoint step folds up to 16 accepted blocks:

```text
previous HistoryCheckpointHeadV1
+ HistoryCheckpointBatchSummaryV1
= next HistoryCheckpointHeadV1
```

Public step statement:

```text
HistoryCheckpointStepStatementV1 {
    previous_head,
    batch_summary,
    next_head,
}
```

Batch summary:

```text
HistoryCheckpointBatchSummaryV1 {
    batch_len <= 16,
    start_anchor,
    end_anchor,
    start_accumulator,
    end_accumulator,
    start_consensus,
    end_consensus,
    accepted_claim_batch_digest,
}
```

The summary is fixed-shape for a batch. It binds only the information needed by
the recursive head:

```text
start boundary
  (anchor, accumulator, consensus)
accepted-claim batch digest
end boundary
  (anchor, accumulator, consensus)
```

It is not a list of transaction proofs.

### Recursive checkpoint proof

Network proof object:

```text
HistoryCheckpointProofV1 {
    version,
    engine_id,
    checkpoint_height,
    start_anchor,
    end_anchor,
    start_accumulator,
    end_accumulator,
    recursive_proof,
}
```

Recursive payload:

```text
HistoryCheckpointRecursivePayloadV1 {
    version,
    engine_id,
    head: HistoryCheckpointHeadV1,
    backend_proof,
}
```

The final verifier must check:

```text
payload.head.checkpoint_height == proof.checkpoint_height
payload.head.anchor_digest == Digest(proof.end_anchor)
payload.head.accumulator_digest == Digest(proof.end_accumulator)
VerifyRecursiveBackend(payload.backend_proof, payload.head) == true
```

Today the public shape checks exist and the untrusted verifier still returns
`BackendVerifierMissing`. That is intentional fail-closed behavior until the
recursive/IVC backend is connected.

The real retained accepted-block component verifier now exists below that
public boundary: `noid_block` first uses the production block verifier to
replay existing `BlockProof`/`BlockAuthSidecar` objects and derive canonical
components, and `noid_recursive::block_certificate_backend` verifies those
components without depending on `noid_block`.

## Final Proof Relation

For one 16-block step, the recursive backend must prove the following relation:

```text
input:
  previous_head
  batch_summary
  next_head

private witnesses:
  previous recursive proof, unless this is the base step
  block bodies B_1..B_k
  BlockProof_1..BlockProof_k
  BlockAuthSidecar_1..BlockAuthSidecar_k
  state/auth/tx witnesses needed by the existing block certificate verifier

constraints:
  1. k == batch_summary.batch_len and 1 <= k <= 16

  2. previous_head matches batch_summary.start_*:
       previous_head.checkpoint_height == start_anchor.height
       previous_head.anchor_digest == Digest(start_anchor)
       previous_head.accumulator_digest == Digest(start_accumulator)
       previous_head.consensus_digest == Digest(start_consensus)

  3. for each block i in order:
       VerifyHeaderPoWAndParent(header_i, anchor_{i-1}, consensus_{i-1})
       VerifyBlockCertificate(B_i, BlockProof_i, BlockAuthSidecar_i)
       claim_i = DeriveAcceptedStateTransitionClaim(B_i, verified_artifacts_i)
       accumulator_i = FoldAcceptedClaim(accumulator_{i-1}, claim_i)
       anchor_i, consensus_i = ExtendHeaderAnchor(anchor_{i-1}, consensus_{i-1}, header_i)

  4. accepted_claim_batch_digest ==
       Digest(header_witnesses_1..k, claim_1..k, end_consensus, end_accumulator)

  5. batch_summary.end_* equals the computed end boundary

  6. next_head ==
       AdvanceHistoryCheckpointHead(previous_head, batch_summary)

  7. if previous_head.batch_count > 0:
       VerifyRecursiveBackend(previous_proof, previous_head)
```

The public verifier sees one constant-size proof for the final head. The heavy
per-block witnesses are private to the prover and do not travel with the final
snapshot package.

## Why This Is Trustless

Invalid headers are rejected by native PoW and chainwork verification before
the snapshot proof is trusted.

Invalid old block transitions are rejected because the recursive backend must
verify the existing block certificate path and derive the accepted claims
inside the proof.

Fake accepted claims are rejected because the history step folds only claims
that come from verified block certificates. A sidecar claim from a peer is not
authority.

Fake snapshots are rejected because the snapshot root must equal
`header[F].state_root`, and the recursive proof must end at the same checkpoint
anchor and accumulator.

Data withholding can still stop sync from that peer, but it cannot make an
invalid snapshot accepted.

## Current Code Map

### `noid_block::accepted_block_batch`

Status: native authority boundary and benchmark harness.

What it does now:

- replays retained full `AcceptBlock` data;
- keeps the production block verifier for `BlockProof`, transaction bodies,
  authorization sidecars, exact state, and consensus checks;
- reconstructs accepted claims after full validation;
- verifies component proofs for accepted claim hash, tx body, tx root,
  checkpoint Poseidon, exact state, and authorization transcripts;
- builds `HistoryCheckpointBatchSummaryV1` from a real accepted batch;
- builds and verifies checkpoint step proofs from full accepted components via
  `noid_recursive`;
- exposes a wrapper for `noid_recursive::accepted_claim_batch_digest_v1`.

What it is not:

- it is not the final public O(1) recursive verifier;
- it is not supposed to make history aggregation depend on tx count.

### `noid_recursive`

Status: final public envelope, native checkpoint step, certificate statement
digest proofs, certificate-batch digest proofs, accepted-claim digest proof,
real retained accepted-block component verification, and the first
Poseidon2b-backed checkpoint IVC core exist. The final IVC encoding of the full
accepted-block component verifier and the multi-step fold verifier are still
missing.

What it does now:

- defines `HistoryCheckpointProofV1`;
- defines `HistoryCheckpointRecursivePayloadV1`;
- defines `HistoryCheckpointHeadV1`;
- defines `HistoryCheckpointBatchSummaryV1`;
- defines `HistoryCheckpointStepStatementV1`;
- checks version, engine, anchors, accumulators, checkpoint height, and payload
  shape;
- verifies the native checkpoint step relation;
- proves and verifies the fixed-schedule Poseidon2b digest of
  `AcceptedBlockCertificateStatementV1`;
- proves and verifies the fixed-schedule Poseidon2b digest of
  `AcceptedBlockCertificateBatchStatementV1`;
- proves and verifies the fixed 16-slot accepted-claim batch digest;
- proves and verifies the fixed-schedule Poseidon2b digest of
  `HistoryCheckpointStepStatementV1`;
- verifies existing `BlockProof`/`BlockAuthSidecar`-derived retained batch
  components in `noid_recursive::block_certificate_backend`;
- verifies a checkpoint step against full accepted components through
  `verify_history_checkpoint_step_proof_v1_private_block_components_native`;
- decodes the checkpoint-step backend proof and checks the certificate-batch
  digest and step-statement digest components before failing closed;
- exposes `checkpoint_ivc_backend`, which proves a fixed 16-slot R1CS chunk
  core over checkpoint boundary, certificate statement digests, accepted-claim
  digest witnesses, state roots, heights, and block-id continuity;
- fails closed at `BackendVerifierMissing`.

What must be added:

- encode `verify_accepted_block_batch_components_v1` inside the
  Poseidon2b-backed IVC backend instead of prechecking it natively;
- proof of previous head validity inside the next step;
- replace the checkpoint-step `BackendVerifierMissing` with public IVC
  verification so the component witnesses remain private and only a constant
  public proof is sent over the network.

### Removed Lab Crate

Status: removed.

The useful proof-core ideas have been promoted into `noid_ivc_core`,
`noid_ivc_prover`, and `noid_recursive::checkpoint_ivc_backend`. The benchmark
coverage that matters now lives in production-path crates:

- `noid_recursive --bench checkpoint_ivc` for the Poseidon2b IVC chunk core;
- `bench_prover --bench full_accepted_batch` for the retained full
  `AcceptBlock` authority boundary;
- `bench_prover --bench history_accumulator_lite` for the older local
  accumulator shape checks until the final worker replaces them.

There is no second production history-proof API.

## Performance Budget

The block interval target is 15 seconds. The history worker must stay ahead of
the retained window.

Targets:

- prove one 16-block checkpoint step in less than 2 seconds on the benchmark
  machine;
- verify the final public proof in less than 1 second;
- keep the final public proof below 64 KiB;
- keep public proof size independent of historical transaction count;
- stop pruning if `history_proof_covered_to` falls behind retained data.

Current useful measurements:

```text
noid_recursive checkpoint_ivc chunk core, 16 slots:
  proof core Poseidon2b BaseFold/R1CS, pcs_log_inv_rate=4,
  pcs_log_batch_size=5
  fixture 4.71 ms, prove 46.98 ms, verify 52.32 ms
  proof 97.59 KiB, core proof 97.57 KiB
  current scope: checkpoint/certificate/claim continuity core, not yet the full
  accepted-block component verifier

noid_recursive n=18 older local shape:
  public_proof 9.71 KiB
  recursive_head_history_proof 10.12 KiB
  recursive_chunk_head_history_proof 16.42 KiB
  promising shape, but multi-step untrusted verifier still fails closed

full accepted batch, 1 user block:
  build fixture 85.37 ms, prove 170.52 ms, verify 146.13 ms, proof 46.61 KiB
  checkpoint step statement 1.70 KiB, certificate batch statement 552 B
  accepted-claim batch digest proof 5.68 KiB, prove 103.52 ms, verify 31.17 ms
  checkpoint step proof from full accepted components 14.63 KiB, prove 200.24 ms,
    private full-component verify 134.42 ms, public verify-to-fail-closed 10.05 ms

full accepted batch, 16 no-user blocks:
  build fixture 19.01 ms, prove 396.48 ms, verify 143.26 ms, proof 16.33 KiB
  checkpoint step statement 1.70 KiB, certificate batch statement 552 B
  accepted-claim batch digest proof 5.68 KiB, prove 94.25 ms, verify 28.36 ms
  checkpoint step proof from full accepted components 14.63 KiB, prove 212.79 ms,
    private full-component verify 156.28 ms, public verify-to-fail-closed 10.09 ms
```

The full accepted batch bench uses saved valid PoW nonces, so the 16-block
measurement is proof cost rather than deterministic fixture mining cost.

## Milestones To Final O(1)

### M0. Cleanup and safety rails

Status: done.

Delivered:

- removed the legacy long-history target from docs, tests, and bench defaults;
- kept the retained window at 18 and checkpoint batch target at 16;
- clarified that SHA proof-core paths are diagnostic only;
- kept incomplete public verification fail-closed.

Exit condition:

- there is one visible final architecture and no competing long-history
  plan.

### M1. Final public envelope

Status: done.

Delivered:

- `HistoryCheckpointProofV1`;
- `HistoryCheckpointRecursivePayloadV1`;
- `HistoryCheckpointHeadV1`;
- `HistoryCheckpointBatchSummaryV1`;
- `HistoryCheckpointStepStatementV1`;
- deterministic Poseidon2b digests for anchors, accumulators, consensus state,
  batch summaries, heads, and step statements;
- fixed 12-field Poseidon2b/KillShot hash schedule for the checkpoint step
  statement digest;
- negative tests for bad versions, engines, anchors, accumulators, payloads,
  and head mismatches.

Exit condition:

- P2P/RPC can carry the final proof type without accepting incomplete proofs.

### M2. Native accepted-batch handoff

Status: done for the native boundary.

Delivered:

- `noid_block::accepted_block_batch` verifies full retained `AcceptBlock`
  batches natively;
- accepted claims are reconstructed after full validation;
- `accepted_claim_batch_digest_v1` binds fixed per-block header witnesses and
  accepted claims;
- `accepted_claim_batch_digest_v1` now lives in `noid_recursive` as a fixed
  440-field Poseidon2b/KillShot schedule with a proof component;
- `history_checkpoint_batch_summary_from_full_accepted_output_v1` builds the
  checkpoint summary from real batch output;
- release tests cover summary construction and tampering.

Delivered in the certificate handoff:

- `AcceptedBlockCertificateStatementV1`;
- `accepted_block_certificate_statement_v1`;
- `accepted_block_certificate_statement_digest_v1`;
- `accepted_block_certificate_chain_claim_v1`;
- fixed 35-field statement projection in `noid_recursive`;
- fixed 38-field Poseidon2b/KillShot hash schedule for the certificate
  statement digest;
- fixed 40-field Poseidon2b/KillShot hash schedule for the certificate batch
  statement digest;
- native statement verification against an accepted block and its artifacts;
- full accepted batches now carry one certificate statement per block and derive
  the folded chain claim from that statement.

Exit condition:

- the recursive backend has a precise target statement instead of relying on
  native helper output.

### M3. One-block certificate verifier inside the recursive backend

Status: done for the dependency-clean retained component verifier. The public
one-block recursive proof wrapper is still fail-closed.

Goal:

```text
BlockProof + BlockAuthSidecar + block body + witnesses
  -> verified accepted block
  -> derived AcceptedStateTransitionClaim
```

Tasks:

- done: define `AcceptedBlockCertificateStatementV1`;
- done: bind block body digest, proof digest, auth sidecar digest, folded
  accepted-block claim digest, semantic state-transition claim digest, roots,
  counts, and witness lengths;
- done: make `noid_block::accepted_block_batch` derive the folded claim from
  the certificate statement instead of from a parallel free claim path;
- done: move the data-only certificate statement and digest schedule into
  `noid_recursive` so the final verifier does not depend on `noid_block`;
- done: add `AcceptedBlockCertificateProofV1` as a fail-closed recursive proof
  shape;
- done: add `AcceptedBlockCertificateBackendProofV1`, which proves the
  fixed-schedule statement digest with `FixedFieldHashProofKillShot`;
- done: make malformed certificate backend bytes reject before the final
  fail-closed verifier boundary;
- done: add `noid_recursive::block_certificate_backend`, the real verifier
  relation for canonical components derived by `noid_block` after it verifies
  existing `BlockProof`/`BlockAuthSidecar` bytes:
  accepted-claim hash, tx body hash, tx root, owner authorization,
  authorization transcript, header trace, checkpoint Poseidon, exact-state
  KillShot, certificate statement projection, consensus state, and accumulator;
- done: keep `noid_block` as the extractor/builder for canonical components
  from actual blocks, block proofs, and sidecars; the production block verifier
  and `block_scaling` benchmark stay there;
- wrap this component verifier in the public recursive proof backend;
- make the final public proof shape fixed under protocol block caps;
- extend tamper tests across block body bytes, proof bytes, auth sidecar bytes,
  parent root, child root, tx root, owner auth, and claim fields.

Exit condition:

- one block certificate can be proved recursively and verified publicly without
  trusting a peer-provided accepted claim.

### M4. Sixteen-block checkpoint step

Status: fixed certificate batch statement, fixed digest proof components,
accepted-claim digest component, full accepted component native verifier,
fail-closed step proof shape, extracted Poseidon2b IVC core/prover crates, and
the first checkpoint IVC chunk-core proof are done. The full accepted-block
component verifier is not yet encoded inside the public IVC backend.

Goal:

```text
previous HistoryCheckpointHeadV1
+ up to 16 verified block certificates
+ derived accepted claims
= next HistoryCheckpointHeadV1
```

Tasks:

- done: add `AcceptedBlockCertificateBatchStatementV1`, a fixed 16-slot
  statement over certificate statement digests;
- done: bind certificate batch length and accepted-claim batch digest to
  `HistoryCheckpointStepStatementV1`;
- done: add `HistoryCheckpointStepProofV1`, a fail-closed proof shape for the
  checkpoint step backend;
- done: add `HistoryCheckpointStepDigestProofV1`, which proves the fixed
  `HistoryCheckpointStepStatementV1` digest with `FixedFieldHashProofKillShot`;
- done: add `AcceptedBlockCertificateBatchDigestProofV1`, which proves the
  fixed 16-slot certificate-batch statement digest with
  `FixedFieldHashProofKillShot`;
- done: add `AcceptedClaimBatchDigestProofV1`, which proves the fixed 16-slot
  accepted-claim batch digest with `FixedFieldHashProofKillShot`;
- done: add `HistoryCheckpointStepBackendProofV1`, decode it in the untrusted
  step verifier, verify the public step-statement digest proof and
  certificate-batch digest proof, then fail closed at the missing recursive
  fold verifier;
- done: connect `AcceptedClaimBatchDigestProofV1` to the checkpoint step
  backend as a private component and add a native private-component verifier
  for benches;
- done: add `prove_history_checkpoint_step_proof_v1_from_certificate_statements`,
  which rebuilds `AcceptedBlockCertificateBatchStatementV1` from certificate
  statements and accepted-claim witness projection before proving the step;
- done: add `prove_history_checkpoint_step_proof_v1_from_block_components`,
  which first verifies the real accepted-block components and then builds the
  checkpoint step proof from the derived accepted-claim output;
- done: add
  `verify_history_checkpoint_step_proof_v1_private_block_components_native`,
  which verifies public step/certificate digest components and the real
  accepted-block component verifier before accepting the step privately;
- done: add `noid_block` bridge helpers that build and verify checkpoint step
  proofs from retained full accepted components;
- done: bench the accepted-claim batch digest proof shape:
  5.68 KiB, prove about 94-104 ms, verify about 28-31 ms;
- done: bench the checkpoint step proof built from full accepted components:
  14.63 KiB, prove about 200-213 ms, private full-component verify about
  134-156 ms, public verify-to-fail-closed about 10 ms;
- done: batch 1..16 real accepted-block component verifications through
  `noid_recursive`;
- done: derive the accepted-claim batch digest in the native step from
  certificate-derived claims;
- done: fold the chain accumulator and header anchor in the native component
  verifier via accepted-claim batch/header trace checks;
- done: extract the useful proof-core technology into `noid_ivc_core` and
  `noid_ivc_prover`, with Poseidon2b as the mandatory proof-core boundary;
- done: add `noid_recursive::checkpoint_ivc_backend`, a fixed 16-slot IVC
  chunk-core proof for checkpoint/certificate/claim continuity;
- encode `verify_accepted_block_batch_components_v1` inside the public
  recursive/IVC backend;
- connect `HistoryCheckpointStepStatementV1` to that backend and remove the
  fail-closed placeholder;
- reject wrong order, skipped height, wrong parent, wrong PoW target, wrong
  state root, wrong accumulator, and wrong accepted-claim digest;
- benchmark no-user, one-user, and mixed 16-block fixtures.

Exit condition:

- one retained 16-block batch verifies as a public recursive step, not only as
  a native/private component statement.

### M5. Recursive head chaining

Status: not done. It starts after the full 16-block component verifier is
inside the IVC backend.

Goal:

```text
base head
  -> step 1 proof
  -> step 2 proof verifies step 1
  -> ...
  -> final constant-size checkpoint proof
```

Tasks:

- verify previous recursive proof inside the next step;
- fold `recursive_digest` deterministically;
- serialize only the latest recursive proof as public proof bytes;
- replace `BackendVerifierMissing` with real backend verification;
- keep worker caches separate from network proof bytes.

Exit condition:

- many checkpoint batches verify with one constant-size public proof.

### M6. History worker and pruning gate

Status: not done.

Goal:

```text
while history_proof_covered_to + 16 <= finalized_height:
    load retained blocks, BlockProofs, BlockAuthSidecars
    prove one checkpoint step
    persist new head and recursive proof
    advance history_proof_covered_to
```

Tasks:

- persist proof head, coverage height, proof digest, and pending suffix count;
- resume safely after restart;
- expose metrics for prove time, verify time, proof size, and coverage lag;
- block pruning if proof coverage lags behind retained data;
- keep the latest 18 blocks available for normal validation and reorg safety.

Exit condition:

- old data cannot be deleted before the O(1) proof covers it.

### M7. Snapshot sync package

Status: not done.

Goal:

```text
SnapshotPackage {
    headers,
    checkpoint_height F,
    HistoryCheckpointProofV1,
    snapshot chunks,
    suffix blocks F+1..tip,
}
```

Verification order:

1. Verify headers from genesis.
2. Compute local `HeaderChainAnchor` at checkpoint `F`.
3. Verify `HistoryCheckpointProofV1`.
4. Verify snapshot chunks against the snapshot root.
5. Require snapshot root equals `header[F].state_root`.
6. Replay suffix blocks `F+1..tip` normally.

Exit condition:

- a fresh node can sync from arbitrary peers without trusting peer-local
  history caches.

### M8. Performance hardening

Status: not done.

Tasks:

- keep `block_scaling` as the separate block-proof benchmark;
- keep `full_accepted_batch` for the retained-batch authority boundary;
- add final recursive-step benches for 1, 16, and mixed blocks;
- add final public verifier benches for repeated checkpoint depth;
- enforce public proof size and verify-time budgets in release CI;
- replace older local accumulator shape benches with final worker benches once
  recursive head chaining is implemented.

Exit condition:

- the worker comfortably covers the 18-block retained window under a 15-second
  block interval.

## Work Completed In This Pass

- Removed the legacy long-history target from the history accumulator bench
  defaults.
- Removed legacy long-history checks from `noid_recursive` size tests.
- Clarified that `noid_recursive` multi-step recursive heads are not public
  authority while they fail closed.
- Clarified docs/security: public recursive path must be Poseidon2b-compatible.
- Added `bench_prover --bench full_accepted_batch` for the full retained
  `AcceptBlock` authority boundary.
- Added saved valid PoW nonces for the deterministic full accepted batch bench.
- Measured the 16-block no-user full accepted batch:
  build 16.80 ms, prove 360.54 ms, verify 117.88 ms, proof 16.33 KiB.
- Added `HistoryCheckpointProofV1` and fail-closed untrusted verifier skeleton
  in `noid_recursive`.
- Added `HistoryCheckpointHeadV1`, `HistoryCheckpointBatchSummaryV1`, and
  `HistoryCheckpointStepStatementV1`.
- Added Poseidon2b digests for checkpoint anchors, accumulators, consensus
  state, batch summary, head, step relation, and step statement.
- Added native checkpoint step verification.
- Added the accepted-claim batch digest boundary: the fixed 16-slot,
  440-field Poseidon2b schedule lives in `noid_recursive`, while `noid_block`
  exposes a wrapper over full accepted batch output.
- Added `AcceptedClaimBatchDigestProofV1`.
- Added `AcceptedBlockCertificateStatementV1`, its Poseidon2b digest, native
  verifier, and chain-claim projection.
- Moved the data-only certificate statement/digest/projection into
  `noid_recursive` and left `noid_block` as the full-`AcceptBlock` builder.
- Added `AcceptedBlockCertificateProofV1`, fail-closed one-block proof
  skeleton.
- Added `AcceptedBlockCertificateBatchStatementV1`, fixed 16-slot certificate
  batch statement, and `HistoryCheckpointStepProofV1`, fail-closed checkpoint
  step proof skeleton.
- Changed certificate statement and certificate-batch digests to fixed
  no-padding Poseidon2b schedules that can be proven by
  `FixedFieldHashProofKillShot`.
- Added certificate statement digest proof and certificate-batch digest proof
  components.
- Added checkpoint step statement digest proof and included it in
  `HistoryCheckpointStepBackendProofV1`.
- Added `HistoryCheckpointStepBackendProofV1`; the untrusted checkpoint step
  verifier now decodes backend bytes, verifies public step-statement and
  certificate-batch digest proofs, and returns `BackendVerifierMissing`.
- Wired `AcceptedClaimBatchDigestProofV1` into the checkpoint step backend as a
  private component and added a native private-component verifier for benches.
- Added a checkpoint-step prover helper that derives the certificate batch
  statement from `AcceptedBlockCertificateStatementV1` values and their
  projected accepted claims before building the bundled step proof.
- Added `noid_recursive::block_certificate_backend`, a dependency-clean real
  verifier for retained accepted-block components derived from existing
  `BlockProof`/`BlockAuthSidecar`.
- Rewired `noid_block::verify_full_accepted_block_batch_components` to call the
  `noid_recursive` component verifier instead of a local verifier clone.
- Added
  `verify_history_checkpoint_step_proof_v1_private_block_components_native`
  and `prove_history_checkpoint_step_proof_v1_from_block_components`, so a
  checkpoint step can be proved and privately verified from real accepted-block
  components rather than from accepted-claim-only data.
- Added `noid_block` bridge helpers for checkpoint steps over retained full
  accepted batch output/proofs.
- Connected full accepted batches so each folded chain claim is derived from the
  accepted block certificate statement.
- Connected `noid_block::accepted_block_batch` output to
  `HistoryCheckpointBatchSummaryV1`.
- Updated the full accepted batch bench to build and verify the checkpoint step
  statement over real bench fixtures.
- Updated the full accepted batch bench to prove and verify-to-fail-closed the
  bundled checkpoint-step component backend.
- Updated the full accepted batch bench to prove and verify the accepted-claim
  batch digest component.
- Updated the full accepted batch bench to build checkpoint step proofs from
  full accepted components, not from a prebuilt trusted certificate-batch
  digest.
- Extracted the history proof-core technology into `noid_ivc_core` and
  `noid_ivc_prover`.
- Made the new IVC proof-core boundary Poseidon2b-only: statement digests,
  Merkle commitments, Fiat-Shamir grinding, and proof serialization no longer
  expose the old comparator/hash-chain APIs.
- Removed the old `r1cs_hashes`, `chain`, and `merkle_path` modules from
  `noid_ivc_prover`.
- Added small-outer fallback support in lincheck byte-stripe packing/folding so
  fixed chunk-core relations with `m == k_log` can be proven without padding
  the relation by dummy outer blocks.
- Added `noid_recursive::checkpoint_ivc_backend`, proving and verifying a
  fixed 16-slot checkpoint chunk core over boundary continuity, certificate
  statement digests, accepted-claim digest witnesses, heights, state roots, and
  block ids.
- Added `noid_recursive --bench checkpoint_ivc` for the production-path
  Poseidon2b checkpoint IVC chunk core.
- Removed the deprecated history workbench crate after moving the relevant
  proof-core measurement into `noid_recursive`.
- Optimized checkpoint IVC chunk-core statement binding so the prover/verifier
  hash a compact Poseidon2b statement digest instead of re-hashing sparse R1CS
  matrices in the hot path.
- Tuned the BaseFold PCS chunk-core profile to `pcs_log_inv_rate=4` and
  `pcs_log_batch_size=5`, with explicit rate-aware query counts.
- Bound PCS parameters into the IVC Fiat-Shamir transcript alongside the R1CS
  statement digest and Merkle root.
- Moved release R1CS self-checking behind debug builds or
  `CHECKPOINT_IVC_ASSERT_R1CS=1`; normal release proving keeps native private
  input validation and lets the proof system enforce the relation.
- Current clean checkpoint IVC chunk-core bench:
  fixture 4.71 ms, prove 46.98 ms, verify 52.32 ms, proof 97.59 KiB.
- Current clean release bench:
  16 no-user blocks prove 396.48 ms, verify 143.26 ms, checkpoint step from
  full components prove 212.79 ms and private verify 156.28 ms;
  1 user block prove 170.52 ms, verify 146.13 ms, checkpoint step from full
  components prove 200.24 ms and private verify 134.42 ms.

## Required Commands

Use release/bench optimized mode only:

```bash
cargo test --workspace --release
cargo test -p noid_recursive --release
cargo test -p noid-ivc-core --release
cargo test -p noid-ivc-prover --release
cargo test -p noid_recursive --release checkpoint_ivc
cargo test -p noid_block --release

NOID_RECURSIVE_CHECKPOINT_IVC_SAMPLES=3 \
  cargo bench -p noid_recursive --bench checkpoint_ivc -- --nocapture

NOID_FULL_ACCEPTED_BATCH_SAMPLES=1 \
NOID_FULL_ACCEPTED_BATCH_BLOCKS=16 \
  cargo bench -p bench_prover --bench full_accepted_batch -- --nocapture

NOID_HISTORY_ACCUM_NS=1,18 \
NOID_HISTORY_ACCUM_SAMPLES=3 \
  cargo bench -p bench_prover --bench history_accumulator_lite -- --nocapture

```

## Immediate Next Step

Encode the real retained accepted-block component verifier in the public
recursive/IVC backend and replace the checkpoint-step `BackendVerifierMissing`
boundary:

```text
HistoryCheckpointStepProofV1
  verifies previous recursive head/proof
  verifies current step statement
  proves verify_accepted_block_batch_components_v1 privately
  exposes one constant public proof for the new head
```

Then chain those steps so the public network object proves:

```text
base head -> step_1 -> ... -> final checkpoint head
```
