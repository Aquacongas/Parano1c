# Implementation Log

This log records production design decisions, implemented changes, and measured
results. It intentionally omits removed prototypes and inactive alternatives.

## Production O(1) Activation Plan

Goal: public `HistoryProof` becomes the only trustless O(1) snapshot authority.
No local cache, component proof, retained claim, or peer-provided byte blob is
accepted as a shortcut.

The activation sequence is:

1. Keep snapshot sync fail-closed while proving partial components.
2. Finish the accepted-block batch relation:
   - Poseidon2b header hash and block id;
   - exact header integer semantics;
   - fixed accepted-claim schedule;
   - transaction root and public transaction rules;
   - authorization verification;
   - exact UTXO and ReuseGuard transition;
   - state-root and chainwork continuity.
3. Wrap batches into `HistoryProof`:
   - genesis base case;
   - previous proof verifier;
   - new accepted-block batch proof;
   - exact start/end equality;
   - chain accumulator over the same block ids and claims.
4. Optimize before activation:
   - keep Poseidon-heavy relations on KillShot/FROST-style GKR paths;
   - remove host-only header traces once the integer proof component replaces
     them;
   - benchmark batch sizes and memory before fixing public proof parameters;
   - reduce authorization PCS bytes only with a replacement witness-binding
     argument, never by dropping the binding.
5. Enable public snapshot sync only after:
   - release differential tests prove native `AcceptBlock` equals the recursive
     batch relation;
   - mixed live/restart/reorg/checkpoint tests pass;
   - max-block and sweep-heavy benches stay within wire, time, and RSS caps;
   - `docs/security.md` contains the complete soundness and invariant theorem.

## Poseidon2b Consensus PoW

### Design

The consensus mining algorithm is Poseidon2b over a fixed semantic header field
schedule:

```text
pow_digest = Poseidon2b(POWHDR__, pow_header_fields)
accept iff pow_digest < difficulty_target
```

The field schedule has 16 `Block128` elements and includes only semantic header
fields. Detached validation witness metadata does not affect mining work or
semantic block identity.

The chain link remains a separate Poseidon2b digest:

```text
block_id = Poseidon2b(BLOCKHDR, semantic_header_fields)
```

`POWHDR__` and `BLOCKHDR` are distinct capacity-IV domains.

### Implementation

- Added `TAG_POWHDR`.
- Replaced consensus PoW validation with fixed-field Poseidon2b hashing.
- Added canonical `pow_header_fields` and nonce index `10`.
- Added RPC template `pow_fields_hex` for the fixed PoW field schedule.
- Updated internal miner and external miner to patch nonce field 10.
- Removed obsolete recursive header-work modules and their benches.
- Kept public snapshot sync fail-closed until real recursive authority verifies
  the full block relation.

### Genesis Difficulty

The genesis target is:

```text
GENESIS_TARGET = 2^237
```

With the current batched Poseidon2b miner on the 12-core laptop:

```text
parallel rate        about 186 KH/s
expected attempts    2^19 = 524288
expected solve time  about 2.8 seconds
```

The hardcoded genesis nonce is:

```text
GENESIS_NONCE = 482250
```

### Chainwork Formula

Consensus chainwork now matches strict `< target` acceptance exactly:

```text
Work(T) = floor((2^256 - 1) / T) + 1
```

`block_work`, cumulative chainwork addition, fork choice, retained header
replay, and the recursive header-integer boundary all use the same little-endian
u256 semantics. This replaced the earlier leading-zero bucket approximation,
where different targets inside the same bit-length bucket could contribute the
same work. `GENESIS_TARGET = 2^237` remains unchanged; it contributes `2^19`
work, matching the expected nonce count for strict target search.

Focused release checks:

```text
cargo test -p noid_chain consensus::difficulty --release
cargo test -p noid_chain consensus::fork_choice --release
cargo test -p noid_recursive header_integer --release
cargo test -p noid_recursive pow_header --release
```

### Detached Witness Liveness Guard

Coinbase-only blocks are semantic blocks with no detached witness. The direct
storage apply path now rejects both unexpected `BlockProof` bytes and unexpected
`BlockAuthSidecar` bytes before applying a coinbase-only block. This closes the
same boundary that P2P orphan precheck already enforced for non-tip candidates.

Added a liveness regression: the same semantic coinbase-only block is first
submitted with invalid detached witness bytes and rejected without advancing the
tip or storing proof bytes, then submitted again with the correct empty witness
and accepted under the same `block_id`.

Focused release checks:

```text
cargo test -p noid_chain invalid_detached_witness_does_not_poison_semantic_block --release
cargo test -p noid_chain storage::mdbx_context --release
```

## Packed Miner Optimization

### Design

Mining can evaluate consecutive nonce candidates in batches:

```text
poseidon_pow_digest_nonce_batch(fields, start_nonce, out)
```

The batch function uses `PackedBlock128` and `packed_poseidon2b_permute`. On this
machine the active packed lane count is 2. Consensus safety does not depend on
the miner optimization: validators recompute the canonical digest from the
submitted header.

### Implementation

- Added batch nonce hashing in `noid_chain::consensus::pow`.
- Changed `search_pow` to use the same batch helper.
- Changed `noid_miner` to search thread-local contiguous ranges in nonce
  batches.
- Changed `noid-extminer` to use the same packed batch strategy without adding
  a heavy chain dependency.
- Broadcast static header fields into packed lanes and fill only the nonce
  field lane-by-lane inside the hot batch loop.
- Materialized the fixed PoW field schedule once per internal-miner template
  instead of rebuilding it inside each Rayon worker.
- Added release test coverage proving packed batch digests match scalar
  canonical digests for full and partial chunks.

### Result

Production mining benchmark after the accepted-claim cleanup:

```text
sequential attempts: 20000
sequential time:     0.505 s
sequential rate:     39.57 KH/s
parallel attempts:   200000
parallel time:       1.025 s
parallel rate:       195.06 KH/s
threads:             12
packed lanes:        2
```

Expected average solve time at the configured target:

```text
target 2^237 -> about 2.69 s
```

The variation is expected on the laptop test machine. The invariant is that
the configured genesis target remains in the same wall-clock solve class as
the previous BLAKE path.

This is a CPU/Rayon miner. On x86, field multiplication uses CLMUL; packed
builds use AVX2 or AVX512 lane widths when the target features are enabled.

## Full Accepted-Block Batch Boundary

### Design

The public O(1) proof must prove the full timeless `AcceptBlock` relation, not
trust stored local coverage claims. The native boundary is now:

```text
VerifyFullAcceptedBlockBatchNative(
    start recursive consensus state,
    start chain accumulator,
    start parent header,
    start ChainState,
    retained semantic blocks and detached witnesses
) -> end recursive state, end accumulator, end ChainState
```

For every block, the boundary derives the MTP window, active-count expansion
window, and ASERT anchor from the rolling recursive consensus state, then
verifies the full timeless `AcceptBlock` predicate over retained block body,
`BlockProof`, `BlockAuthSidecar`, parent header, and pre-state.

Coinbase-only blocks carry no detached proof but still verify header consensus, tx root,
coinbase structure, and exact state delta. User-transaction blocks still
require detached proof and sidecar bytes.

### Implementation

- Split live timestamp admission from timeless historical consensus:
  `validate_header` keeps local future-drift policy; `validate_header_timeless`
  excludes only that local clock rule.
- Added `validate_block_checks_timeless`, `validate_block_full_timeless`, and
  `accept_block_timeless`.
- Fixed `accept_block` so coinbase-only blocks with no detached proof are handled by the
  same named predicate instead of storage bypass semantics.
- Added `verify_full_accepted_block_batch_native` in `noid_block`.
- Full batch component proofs now carry and verify one
  `OwnerAuthProofKillShot` per non-coinbase transaction. The verifier rebuilds
  the canonical authorization statement from block order and authenticated
  state-derived owners, checks `tx_body_hash` equality, and rejects tampered
  authorization proof bytes.
- Removed the old `validate_block_from_network` wrapper so the production
  predicate has one name: `accept_block`.

### Security Result

The accepted-claim batch relation is no longer treated as public authority by
itself. A public proof must first prove full timeless `AcceptBlock` for every
block, reconstruct claims after validation, then fold those claims into the
chain accumulator.

## Production Hash Surface Cleanup

Consensus and recursive-authority byte hashing now use Poseidon2b domains. The
chain checkpoint package, receipt summaries, and P2P message IDs depend only on
the current Poseidon2b hashing surface. The removed test-only Blake3 commitment
helper and dev-dependency are not part of the current workspace.

Security consequence: there is no mixed BLAKE/Poseidon consensus binding left
for block identity, PoW, checkpoint authority, Fiat-Shamir, PCS roots, or
accepted-claim accumulation.

## Accepted-Claim Witness Separation

### Design

Accepted-block claims no longer hash `BlockProof` or `BlockAuthSidecar` bytes.
Detached witnesses are mandatory validation inputs, but their serialized bytes
are not semantic block identity and should not dominate local coverage updates.

The claim still records witness byte lengths as resource accounting. The full
accepted-block batch relation verifies witness contents before reconstructing
the claim.

### Implementation

- Removed `block_proof_digest` from `AcceptedBlockClaimTranscript`.
- Removed `auth_sidecar_root` from `AcceptedBlockClaimTranscript`.
- Removed the expensive sidecar Poseidon root over proof bytes.
- Removed reserved zero fields from `BlockPublicMeta`; the production block
  proof metadata now carries only previous state root, new state root, and
  non-coinbase transaction count.
- Removed stale disconnected GKR exports (`binding`, `spine_degree7`).
- Removed stale `validate_block_from_network` naming and old GKR/STARK bridge
  comments.

## KillShot Component Snapshot

The `state`, `s_in`, and `s_out` terminal openings now use one multi-column
batch-evaluation proof. This removes two independent batch-eval transcripts
from each Poseidon2b-heavy KillShot proof without changing the algebraic
relation.

Merkle path KillShot pins compression-chain continuity. The old single-path
debug proof was removed from production code; the only remaining Merkle proof
path is batched. It proves a public linear relation over the committed `state`
column:

```text
PermA(level).state[0]       = MDS(leaf_or_previous_digest, TAG_COMPRESS)
PermB(level).state[0]       = MDS(PermA(level).out + sibling[level])
last PermB(level).out[0..2] = expected_root
```

This closes the gap where transcript binding alone rejected old-proof sibling
tampering but did not algebraically force a freshly generated proof to use the
public leaf/sibling path.

Many Merkle paths now use `BatchedMerkleProofKillShot`: one dynamic
Poseidon2b permutation trace over all active path slots, one shared
multi-column terminal proof, and one linear chain-continuity proof. The chain
relation is deterministic from the already absorbed public path statement, so
it uses a prebound relation tag and shape binding rather than serializing every
linear term into the transcript. Boolean W-table construction still scatters
hypercube-vertex terms directly into the dense table.

Current component measurements on the laptop after multi-column batch opening,
linear Merkle chain-continuity proof, Boolean W-table scatter, and prebound
transcript:

```text
Merkle depth 16:               prove 44.99 ms, verify 24.77 ms,  proof 5.28 KB
255 Merkle paths independent:  prove 10.90 s,  verify 5.99 s,   proof 1.32 MB
255 Merkle paths batched:      prove 2.53 s,   verify 454.33 ms, proof 6.83 KB
OwnerAuth Standard4x8:         prove 163.43 ms, verify 38.04 ms, proof 64.39 KB
OwnerAuth Sweep25x2:           prove 863.21 ms, verify 78.78 ms, proof 117.20 KB
BlockSpine 64 standard:        prove 1.01 s,   verify 3.15 ms,  proof 5.53 KB
SweepSpine 16 sweep:           prove 995.88 ms, verify 2.73 ms, proof 5.53 KB
```

Block-spine KillShot is already small and verifier-cheap at max block size.
Batched Merkle proof size is now independent of the number of paths up to the
logarithmic trace domain size. Remaining time is prover-side witness/table work
plus one linear sumcheck over all path-chain constraints; there is no linear
boundary proof payload.

### Rejected Exact-State Merkle Fusion

A mixed-domain tagged Merkle batch was implemented and benchmarked as an
exact-state optimization. It fused UTXO paths and ReuseGuard paths into one
larger Merkle trace and reduced exact-state proof bytes:

```text
separate production proofs: 29.69 KB
fused tagged proof:         23.75 KB
```

The release benchmark showed a clear time regression:

```text
separate production proofs: prove 2.68 s, verify 450.82 ms
fused tagged proof:         prove 4.50 s, verify 612.96 ms
```

The cause is structural: one larger MLE increases sumcheck work and loses the
parallelism of two smaller domain-specific proofs. The tagged fusion code was
removed after measurement. Production exact-state therefore keeps separate
UTXO-node and ReuseGuard-node Merkle proofs; this is faster and still domain
separated.

### Current O(1) Bottleneck

The remaining large proof object is authorization PCS opening data:

```text
OwnerAuth Standard1x2: proof 41.73 KB, PCS opening 38.80 KB
OwnerAuth Standard4x8: proof 63.14 KB, PCS opening 59.58 KB
OwnerAuth Sweep25x2:   proof 116.42 KB, PCS opening 111.92 KB
255 Standard4x8 proofs: sidecar 15.98 MB, verify 1.43-1.58 s total
```

The Poseidon2b/FROST relation itself is small. The next size/verify big win
must replace or aggregate the private-witness PCS discharge while preserving
the authorization knowledge theorem in `security.md`.

## Owner-Count-Sized Auth Layout

### Design

Authorization traces are now sized by the actual unique owner count with no
fixed four-slot minimum:

```text
owner_count = 1  -> slot_bits 0, num_vars 9,  cells 512
owner_count = 2  -> slot_bits 1, num_vars 10, cells 1024
owner_count = 3+ -> next_power_of_two(owner_count)
```

The canonical authorization statement already binds owner count, layout,
capacity, tx hash, input order, and input-to-owner mapping before any
Fiat-Shamir challenge. Removing the old minimum padding therefore only shrinks
the private MLE and PCS opening; it does not change which owners must be proven
or how a proof is bound to the transaction.

### Result

Wallet proof benchmark:

```text
Standard 1 input / 2 outputs:
  prove median     52.84 ms
  verify median    23.28 ms
  wallet bundle    42.21 KB
  authorization    41.86 KB

Standard 4 inputs / 8 outputs:
  prove median    136.09 ms
  verify median    33.94 ms
  wallet bundle    62.95 KB
  authorization    62.55 KB

Sweep 25 inputs / 2 outputs:
  prove median    812.85 ms
  verify median    81.46 ms
  wallet bundle   116.80 KB
  authorization   116.33 KB
```

The common one-owner payment path is now roughly 42 KB instead of the previous
four-slot-sized authorization proof class. Worst-case multi-owner proofs remain
bounded by the existing owner cap.

### Rejected PCS Cap Tuning

FRI-Binius Merkle cap depths 6 and 7 were benchmarked against the current cap
depth 5. They did not produce a production win:

```text
cap 5 baseline:
  Standard4x8 auth proof 63.14 KB
  Sweep25x2 auth proof   116.42 KB
  255 Standard4x8 sidecar 15.98 MB

cap 6:
  Standard4x8 auth proof 66.11 KB
  Sweep25x2 auth proof   120.86 KB

cap 7:
  Standard4x8 auth proof 70.11 KB
  Sweep25x2 auth proof   123.17 KB
  255 Standard4x8 sidecar 17.02 MB
```

The cap-depth experiments were removed. Cap depth 5 remains the production
format.

The single-path Merkle GKR modules and tests were deleted after the batched
path passed release tests:

```text
noid_gkr release: 146 unit tests + integration tests passed
```

## Local History Cache Cleanup

The old local recursive accumulator naming was removed from the production
surface. The object is now `LocalHistoryCache`: it is not a public proof and
not snapshot authority. RPC/CLI text presents it as a local finalized-history
cache only. Public O(1) remains disabled until `HistoryProof` verifies the
full accepted-block batch relation.

Live snapshot/deep-sync scripts that still required public snapshot authority
were removed, and the optional late-join mode was removed from the multi-node
sweep script. Current live scripts only cover direct/live convergence paths;
deep 18+ catch-up remains fail-closed until real `HistoryProof` exists.

Release check after the rename:

```text
noid_chain, noid_recursive, noid_block, noid_rpc, noid_node: release check passed
```

## Legacy AIR Removal

`noid_air` was removed from the workspace. Benchmark fixtures now derive
Standard4x8 spine statements through `noid_gkr::spine_inputs_from_body`, the
same way Sweep25x2 already used `sweep_spine_inputs_from_body`. Fixture sanity
checks use current native public-logic validation and native tx-body hash
equivalence, not retired transaction AIRs.

Implemented:

- added canonical Standard4x8 `spine_inputs_from_body` in `noid_gkr`;
- added release test comparing the derived GKR spine hash to native
  `hash_tx_body`;
- removed `noid_air` from `bench_prover` and from the workspace.

Verification:

```text
noid_gkr release: 147 unit tests + integration tests passed
workspace release check: passed
```

## Authorization Batch Boundary

`validate_block_authorizations_with_output` now exposes the native batch
authorization boundary:

```text
VerifyAuthorizationBatchNative(block, BlockAuthSidecar)
    -> user_tx_count, owner_count_total, live_input_count_total
```

The relation derives each canonical authorization statement from the ordered
block body, verifies exactly one `OwnerAuthProofKillShot` per non-coinbase
transaction in block order, and rejects zero-owner or zero-live-input proofs.
This is the relation the future `HistoryProof` must prove; it is not a host
certificate.

Release test:

```text
noid_block release: 15 tests passed
```

Current verifier baseline from the focused KillShot bench:

```text
255 Standard4x8 authorization proofs:
    verify total:          1.55 s
    verify per proof:      6.10 ms
    sidecar logical total: 15.82 MB
    sidecar logical each:  63.55 KB
```

This is fine for parallel live validation but too large to become the final
recursive payload. The next O(1) big win must aggregate or replace recursive
verification of `OwnerAuthProofKillShot` while preserving the same canonical
authorization statement and knowledge-soundness theorem.

## ParanO(1)d Production Plan

The remaining production path is:

1. Keep consensus identity and PoW fully Poseidon2b-native:
   `BLOCKHDR` for semantic block id and `POWHDR__` for mining.
2. Finish Poseidon2b-heavy proof optimization before enabling public authority:
   multi-column terminal openings and batched Merkle paths are done; the next
   required win is authorization/state batching so `HistoryProof` does not
   linearly replay every detached wallet proof.
3. Replace local coverage authority with the real accepted-block batch proof
   around the native boundary:
   every block in the batch must prove timeless `AcceptBlock`, exact state
   transition, ReuseGuard, authorization verification, header work, ASERT, MTP,
   chainwork, and expansion-window semantics.
4. Compose finalized batches into `HistoryProof`; the recursive verifier checks
   the previous proof, the new batch proof, and exact start/end state equality.
   Local coverage is not accepted as a substitute.
5. Run max-block and live-node acceptance matrices before any public O(1)
   switch: 255 tx, sweep-heavy, mixed, restart, reorg boundary, checkpoint
   package, and snapshot root verification.
6. Enable pruning and trustless public snapshot sync only after recursive
   checkpoint coverage proves the exact retained range.

## Security Specification Update

`docs/security.md` now reflects the implemented kernel:

- Poseidon2b PoW under `POWHDR__`;
- Poseidon2b semantic block id under `BLOCKHDR`;
- strict `< target` comparison;
- Poseidon2b as the sole consensus PoW authority;
- no retired transaction AIR crate in the production workspace;
- exact sparse-Merkle state transition plus ReuseGuard root;
- explicit authorization knowledge-soundness assumption;
- conservative authorization soundness budget;
- retention until real checkpoint proof coverage;
- packed miner equivalence invariant.

## Current Verification

Release tests run after the PoW switch:

```text
noid_chain:     322 passed, 1 ignored
noid_recursive: 23 lib passed, 10 integration passed, 2 ignored
noid_miner:     6 passed
noid_rpc:       2 passed
noid-extminer:  3 passed
```

Focused PoW tests:

- fixed field schedule and nonce index;
- detached witness exclusion;
- `POWHDR__`/`BLOCKHDR` domain separation;
- nonce mutation changes digest;
- packed batch equals scalar digest;
- zero target rejects;
- easy target accepts;
- genesis nonce satisfies configured target.

## Exact-State KillShot Boundary

The Merkle proof component is now domain-aware and direction-aware:

- `MerkleCircuit::build_with_tag(tag)` fixes the Poseidon2b node domain in the
  verifier relation;
- public path inputs include one direction bit per active level;
- unused path levels must have zero siblings and `direction = 0`;
- the transcript absorbs the node domain and all direction bits before
  challenges;
- verifying a proof under the wrong domain fails closed.

`noid_chain::sparse_merkle` can deterministically expand the canonical implicit
multiproof into directed full paths. This is not a second proof format; it is
the verifier-side projection that the history proof circuit consumes.

`noid_block` now derives proof inputs for both exact state components:

- UTXO old/new paths under `EXSTNOD_`, up to depth 32;
- ReuseGuard old/new bucket paths under `RGDNODE`, fixed depth 8.

The hash leaves and composite root are also proved through dedicated
Poseidon2b/KillShot components:

- `EXSTSLT_`: slot amount/owner to exact UTXO leaf hash;
- `RGDBUCK_`: empty or occupied ReuseGuard bucket to bucket leaf hash;
- `EXSTROT_`: `(log_slots, utxo_root, guard_root)` to composite state root.

Targeted release tests cover:

- directed sparse-Merkle path expansion with non-zero direction bits;
- `EXSTNOD_` KillShot verification for old and new UTXO roots;
- `RGDNODE` KillShot verification for old and new ReuseGuard roots;
- `EXSTSLT_` slot-leaf hash proofs derived from exact state surfaces;
- `RGDBUCK_` guard-bucket hash proofs derived from exact guard updates;
- `EXSTROT_` parent/child composite state-root proofs derived from verified
  transitions;
- domain mismatch rejection.
- full accepted-block batch replay for a real user transaction with wallet
  authorization, fee policy, exact state proof, ReuseGuard update, and tampered
  sidecar rejection:
  `cargo test -p noid_block accepted_block_batch --release
cargo check -p bench_prover --bench killshot_components --release`.

This closes the Poseidon2b hash-binding part of exact state transition
proofing. The remaining exact-state proof obligations are action/counter
semantics and their composition with authorization and header work.

## Chain Accumulator KillShot

Added `ChainAccumulatorProofKillShot` for the rolling recursive history
accumulator:

```text
inner_i = COMPRESS(block_id_i, accepted_block_claim_i)
acc_i   = COMPRESS(acc_{i-1}, inner_i)
```

The public statement is `(start_acc, ordered block_id/claim items, end_acc)`.
Intermediate `inner_i` and `acc_i` values are witness state and are linked by
linear constraints over the unified Poseidon2b permutation trace. This component
does not make local coverage public authority by itself; it is the accumulator
subrelation that the full checkpoint/history proof will compose with header,
authorization, and exact-state proofs.

Release tests:

```text
cargo test -p noid_gkr chain_accumulator --release
cargo test -p noid_recursive accepted_claim_batch_feeds_chain_accumulator_killshot --release
```

The `noid_recursive::chain_accumulator_proof_inputs` helper derives the
KillShot public statement directly from `AcceptedClaimBatchWitness`,
`start_accumulator`, and the verified native batch output. This keeps the
block-id/claim encoding single-sourced for the later checkpoint builder.

Measured component result:

```text
ChainAccumulatorProof KillShot, 32 accepted claims:
  prove  54.53 ms
  verify 12.65 ms
  proof   5.05 KB
  vars   16
  slots  128
```

## Header Hash KillShot

Added `HeaderHashProofKillShot` for the two Poseidon2b header digests derived
from one canonical 16-field schedule:

```text
pow_digest = Poseidon2b(POWHDR__, fields[0..16]) no-pad
block_id   = Poseidon2b(BLOCKHDR, fields[0..16]) padded
```

`noid_recursive::header_hash_proof_inputs` derives the proof statement from
`HeaderWitness`, so the same `pow_fields`, `pow_digest`, and `block_id` values
used by the native header boundary feed the optimized component.

Release tests:

```text
cargo test -p noid_gkr header_hash --release
cargo test -p noid_recursive header_witness_feeds_header_hash_killshot --release
```

Measured component result:

```text
HeaderHashProof KillShot, 32 headers:
  prove  254.47 ms
  verify  28.91 ms
  proof    5.94 KB
  vars    19
  slots   544
```

## Checkpoint Poseidon Proof

Added `CheckpointPoseidonProof`, the first composed checkpoint proof object for
the production O(1) path. It combines:

```text
HeaderHashProofKillShot
ChainAccumulatorProofKillShot
```

The verifier does not recompute native Poseidon2b header hashes. It checks that
the supplied header witness uses the canonical field schedule, then verifies:

```text
pow_digest = Poseidon2b(POWHDR__, header_fields)
block_id   = Poseidon2b(BLOCKHDR, header_fields)
acc_i      = COMPRESS(acc_{i-1}, COMPRESS(block_id_i, accepted_claim_i))
```

This object is not public snapshot authority by itself. It intentionally does
not claim header integer consensus or full `AcceptBlock`; those remain separate
proof obligations before `HistoryProof` can be enabled.

Release tests:

```text
cargo test -p noid_recursive checkpoint_poseidon --release
cargo test -p noid_recursive --release
```

Result:

```text
noid_recursive: 32 unit tests + 6 integration tests passed
```

Focused benchmark after parallel component prove/verify:

```text
CheckpointPoseidonProof composed, 32 headers/claims:
  prove       263.65 ms
  verify       31.35 ms
  proof        10.98 KB
```

## Exact State KillShot Composition

Added `ExactStateKillShotProof`, the composed proof object for exact-state
hash/Merkle subrelations. It proves the derived production statements for:

```text
EXSTSLT_  old/new slot leaves
EXSTNOD_  old/new UTXO Merkle paths
RGDBUCK_  old/new ReuseGuard bucket hashes, when the block spends
RGDNODE   old/new ReuseGuard Merkle paths, when the block spends
EXSTROT_  parent/child composite state roots
```

The verifier consumes derived `ExactStateKillShotInputs` and checks only the
KillShot proofs; it does not recompute native Poseidon2b hashes. The derivation
helper still uses the native exact transition verifier to construct honest test
inputs and to keep the current full-node validation path single-sourced.

This composition closes the state hash/Merkle part of the checkpoint proof
pipeline. It still does not prove action ordering, counter updates, or full
transaction semantics by itself.

Release test:

```text
cargo test -p noid_block exact_state_killshot --release
```

Result:

```text
2 tests passed
```

Focused component benchmark after parallel component prove/verify:

```text
NOID_KILLSHOT_STATE_N=32
cargo bench -p bench_prover --bench killshot_components

ExactStateKillShotProof composed, 32 transition-shaped items:
  prove          1.28 s
  verify       212.35 ms
  proof         28.20 KB
  slot leaves       64
  state paths       64
  guard buckets     64
  guard paths       64
  state roots       64
```

Before parallelizing independent component verifiers the same row was about
`1.53 s` prove and `298 ms` verify. The proof format did not change.

## KillShot Component Measurements

Short release sanity run:

```text
NOID_KILLSHOT_STANDARD_NS=1
NOID_KILLSHOT_SWEEP_NS=1
NOID_KILLSHOT_MERKLE_MANY=4
NOID_KILLSHOT_AUTH_VERIFY_N=4
NOID_KILLSHOT_STATE_N=8
cargo bench -p bench_prover --bench killshot_components
```

Observed component sizes/times on the current laptop:

```text
Batched Merkle, 4 depth-32 paths:
  prove 81.30 ms, verify 13.57 ms, proof 5.34 KB

Exact-state components, N=8:
  EXSTSLT_ slot leaves:        prove  9.52 ms, verify 2.89 ms, proof 4.16 KB
  RGDBUCK_ guard buckets:      prove 14.86 ms, verify 3.16 ms, proof 4.45 KB
  EXSTROT_ composite roots:    prove 13.64 ms, verify 3.76 ms, proof 4.45 KB

OwnerAuthProofKillShot:
  Standard4x8: prove 128.58 ms, verify 31.23 ms, proof 64.39 KB
    FROST/GKR 3.03 KB, batch eval 544 B, PCS opening 60.83 KB
  Sweep25x2:  prove 733.86 ms, verify 71.13 ms, proof 117.20 KB
    FROST/GKR 3.83 KB, batch eval 688 B, PCS opening 112.70 KB
```

Conclusion: the Poseidon2b/KillShot hash components are already small and
fast. The remaining authorization bottleneck is the FRI-Binius private-column
PCS opening inside each wallet proof, not the FROST/GKR relation itself.

Added a source-cap optimization to the Auth PCS commitment: the source cap is
absorbed as part of the commitment and source Merkle paths are verified to that
cap instead of to a single source root. This keeps the same source-binding
relation and moves upper Merkle levels into the commitment.

Short-bench result:

```text
OwnerAuth Standard4x8: 64.39 KB -> 63.14 KB
  PCS opening:          60.83 KB -> 59.58 KB

OwnerAuth Sweep25x2:   117.20 KB -> 116.42 KB
  PCS opening:          112.70 KB -> 111.92 KB
```

This is a safe small win, not the O(1) authorization big win. The serialized
Auth bottleneck remains the private-column PCS discharge.

The wallet benchmark output was simplified to report only the real serialized
authorization capsule. Current release run:

```text
Standard4x8 1x2:       prove 166.94 ms, verify 54.41 ms, authorization 63.52 KB
Standard4x8 4x8:       prove 150.03 ms, verify 33.15 ms, authorization 62.55 KB
Sweep25x2 5x2:         prove 254.34 ms, verify 41.06 ms, authorization 79.30 KB
Sweep25x2 10x2:        prove 464.80 ms, verify 56.64 ms, authorization 99.30 KB
Sweep25x2 25x2:        prove 863.22 ms, verify 75.83 ms, authorization 116.33 KB
Sweep25x2 25x1:        prove 796.72 ms, verify 78.89 ms, authorization 117.27 KB
Split 50 inputs:       prove 1.73 s, verify 151.65 ms, auth total 232.66 KB
```

Checked a deeper source cap (`SOURCE_CAP_DEPTH = 7`) and rejected it:

```text
Standard4x8: 63.14 KB -> 64.73 KB
Sweep25x2:   116.42 KB -> 120.61 KB
```

The added commitment cap bytes outweighed the path reduction for the current
Auth trace sizes, so the production parameter remains cap depth 5.

Checked and rejected the direct source-expansion alternative for Auth PCS:

```text
Standard4x8 PCS: 60.83 KB -> 136.48 KB, verify 31.48 ms -> 134.66 ms
Sweep25x2 PCS:   112.70 KB -> 608.77 KB, verify 73.47 ms -> 376.20 ms
```

The current folded source-binding path is the better implementation until the
Auth discharge protocol itself is replaced.

Checked compact-FRI `TAU` retuning for the Auth PCS:

```text
TAU=6: Standard4x8 65.33 KB, Sweep25x2 117.36 KB
TAU=7: Standard4x8 63.67 KB, Sweep25x2 114.05 KB, standard batch verify worse
TAU=8: Standard4x8 63.14 KB, Sweep25x2 116.42 KB
TAU=9: Standard4x8 69.45 KB, Sweep25x2 122.05 KB
```

The production parameter remains `TAU=8`: it is the best standard/batch
balance and avoids optimizing for rare sweep-heavy blocks at the cost of the
common path.

Checked and rejected folded-layer Merkle caps for source binding:

```text
folded cap depth 2: Standard4x8 64.70 KB, Sweep25x2 119.55 KB
folded cap depth 1: Standard4x8 63.39 KB, Sweep25x2 117.14 KB
```

The extra cap nodes outweighed path savings for the current trace dimensions,
so the simpler folded-root path remains production. This was reverted; no
alternate folded-cap wire format remains.

`noid_binius` was removed from the workspace because it was an unused
FRI-packing experiment. Its bit/byte packing idea may inform a future
production commitment redesign, but the crate was not part of the O(1)
authority path and only added audit noise.

Removed the public history-proof gossip topic entirely. The P2P request-response
endpoint remains as the future `HistoryProof` transport surface, but production
peers return an empty proof until the real accepted-block recursive verifier is
active. Local finalized coverage is not broadcast and is not accepted from peers
as trustless snapshot authority.

## Remaining Production Work

The concrete activation path to ParanO(1)d is:

1. Compose the existing Poseidon-heavy checkpoint components:
   header hash, exact-state Merkle/hash components, and chain accumulator.
2. Replace the remaining native header integer boundary with a proof relation:
   strict target comparison, MTP, ASERT, chainwork, epoch anchors, and exact
   log-slot expansion.
3. Replace the remaining native exact-state action/counter boundary with a
   proof relation over touched slots, spends/mints, resource counters, and
   ReuseGuard events.
4. Aggregate or replace authorization proof verification so recursive
   checkpoints do not replay detached wallet proofs linearly. The replacement
   must remain knowledge-sound and must not expose wallet secrets.
5. Build `HistoryProof` over fixed-size finalized checkpoint batches. Public
   state stays O(1): height, block id, state/UTXO/guard roots, chainwork,
   ASERT context, MTP window, expansion window, and accumulator.
6. Enable pruning and trustless public snapshot sync only after `HistoryProof`
   verifies the full frozen block relation.

Optimization is part of each step, not a final cleanup pass. Each new component
must be benched for prove time, verify time, proof bytes, and peak memory before
the next layer is frozen.

## Consensus Helper Cleanup

`log_slots` expansion is now a single consensus helper:

```text
expected_child_log_slots(parent_log_slots,
                         parent_active_slot_count,
                         previous_active_counts_window)
```

The old monotone-only header validation path was removed from the public API.
`validate_header`, `validate_block_checks`, miner template construction, network
header precheck, and the recursive header-batch relation all use the same exact
predicate. Release checks:

```text
cargo test -p noid_chain consensus::header --release
cargo test -p noid_chain consensus::slot_expansion --release
cargo test -p noid_recursive pow_header --release
cargo check -p noid_node --release
```

## Authorization O(1) Direction

Current `OwnerAuthProofKillShot` benchmark:

```text
Standard4x8: prove 121.94 ms, verify 30.55 ms, proof 63.14 KB
  FROST/GKR 3.03 KB, batch eval 544 B, PCS opening 59.58 KB

Sweep25x2: prove 723.56 ms, verify 69.56 ms, proof 116.42 KB
  FROST/GKR 3.83 KB, batch eval 688 B, PCS opening 111.92 KB
```

The bottleneck is the private trace-MLE PCS opening, not the Poseidon2b
KillShot relation. The production O(1) path should replace that discharge with
an input-terminal, knowledge-sound authorization proof committing only the
private owner secrets, or else prove a full extractor theorem for the current
PCS composition. A block-level proof over raw secrets is invalid because miners
and checkpoint provers do not know wallet secrets.

Closed the theft-soundness proof obligation for the current path in
`security.md`: under the Fiat-Shamir, source-bound PCS extraction, and
Poseidon2b assumptions, an accepting `OwnerAuthProofKillShot` yields the
committed private `state` MLE; the boundary constraints recover the round-zero
preimage lanes through `MDS_FULL^{-1}`; and the transition constraints prove
those lanes hash to the claimed owner under `TAG_ADDRFIX`.

Added an implementation guard test that extracts spend-secret fields from the
committed owner-auth state layout and checks final owner-address lanes. Release
test:

```text
cargo test -p noid_gkr owner_auth --release
```

The remaining Auth work is now optimization, not an unresolved theft-security
P0: the PCS opening still dominates wallet proof bytes and verify time.

## Header Integer Split Boundary

Implemented the explicit split between Poseidon2b header hashing and exact
integer consensus semantics:

```text
HeaderHashProofKillShot:
  canonical 16-field schedule -> pow_digest and block_id

HeaderIntegerTrace:
  parent link, height, strict pow_digest < target, ASERT, MTP,
  chainwork, epoch anchors, and exact log-slot expansion
```

The split is intentionally not a shortcut: `HeaderIntegerTrace` does not
recompute Poseidon2b and is valid only when paired with the hash proof over the
same header witnesses. The accepted-claim batch has a verifier entry point for
this split boundary, so the recursive wrapper can compose hash, integer,
and accumulator relations without host-level equality.

Release tests now cover:

```text
positive accepted-claim split-batch roundtrip
pow_digest == target rejection
untriggered log-slot jump rejection
header integer trace roundtrip without native hashing
```

The important security point is exactness: the recursive relation rejects PoW
equality, uses the same `expected_child_log_slots` helper as live validation,
and advances chainwork/ASERT windows from the rolling recursive state.

## Full Accepted-Block Component Extraction

The raw timeless `AcceptBlock` path now has an artifacts-returning variant for
recursive proof construction. Existing callers still receive the same
`state_root` result; the new path keeps the same wire caps, resource-weight
checks, deserialization, public tx checks, authorization verification, and exact
state transition validation.

After successful validation, user-transaction blocks return:

```text
VerifiedAuthorizationBatch
ExactStateTransitionInputs
ExactActionSurface
VerifiedStateTransition
ExactStateKillShotInputs
```

Proofless coinbase-only blocks return no authorization or exact-state proof
components. The full accepted-block batch now packages:

```text
AcceptedClaimBatchWitness
HeaderIntegerBatchTrace
ExactStateKillShotInputs[]
VerifiedAuthorizationBatch[]
```

The accepted-claim batch is verified through the split header boundary
(`HeaderHashProofKillShot` + `HeaderIntegerTrace`) instead of a host-only native
header hash path. Release tests cover coinbase-only blocks without detached
proofs, user blocks, tampered sidecars, split header traces, and an
ExactStateKillShot proof roundtrip over the extracted exact-state inputs.

Added `RetainedFullAcceptedBlockBatchProof`, which proves the implemented
component layer over extracted full-batch components:

```text
AcceptedClaimHashProofKillShot
TxBodyStandardBlockSpineProof
TxBodySweepBlockSpineProof
TxRootBatchedMerkleProofKillShot
CheckpointPoseidonProof
ExactStateKillShotProof[]
```

Verification checks the fixed `ACCBLK__` claim schedule, the accepted-claim
batch through `HeaderIntegerTrace`, shape-specific tx-body hash proofs, the
Poseidon header/accumulator proof, the ordered tx-root Merkle proof including
zero padding leaves, and each exact-state proof against extracted inputs. This
is still not public snapshot authority because final `HistoryProof` must prove
component reconstruction from block bodies, authorization proofs, resource
rules, and pre-state context inside one accepted block relation.

## Tx-Body Hash Component Pinning

### Design

`tx_body_hash` is not accepted by transcript binding alone. The shape-specific
tx-body spine proof must prove that the final wrap permutation output equals
the claimed transaction hash:

```text
state[wrap_slot, final_round, 0..2] == tx_body_hash
```

The proof groups transactions by production shape:

- `Standard4x8` uses the 59-permutation standard spine.
- `Sweep25x2` uses the 142-permutation sweep spine.

### Implementation

Added a linear hash-pin proof to both block-spine proof formats and included
the pin terminal claim in the shared multi-column terminal discharge. The full
accepted-block component proof now carries optional standard and sweep tx-body
spine components, derived from retained block bodies after timeless
`AcceptBlock` validation.

### Result

Changing a component statement's claimed `tx_body_hash` while keeping the same
proof now rejects at `TxBodyHashComponent`. Release tests cover standard block
spine, sweep block spine, and full accepted-block component verification with
the new pin relation.

## Component Reduction Discharge

### Design

Every Poseidon2b/KillShot component returns terminal reductions for the
committed trace columns. A component is accepted only if those terminal claims
are discharged against the canonical trace implied by the public component
statement. The verifier must not accept a sumcheck transcript while ignoring
its returned terminal openings.

### Implementation

Added native discharge checks to the production component verifier path for:

- accepted-block claim hashing;
- semantic header/hash and chain-accumulator checkpoint components;
- transaction-root Merkle paths;
- exact-state slot leaves, UTXO Merkle paths, guard bucket hashes, guard
  Merkle paths, and composite state roots.

Owner authorization remains different by design: its terminal reduction is
already checked against the source-bound private PCS opening, because validators
and recursive provers do not know wallet spend secrets.

### Result

The component proof layer is now fail-closed on terminal reduction mismatch.
Release tests for `noid_gkr`, full accepted-block batch extraction, and
recursive checkpoint components pass with the new discharge requirements.

### Current Bench Result

Release component bench after terminal-discharge wiring:

```text
ChainAccumulatorProof, 32 claims:
    prove 49.48 ms, verify 7.70 ms, proof 5.05 KB

HeaderHashProof, 32 headers:
    prove 258.12 ms, verify 31.05 ms, proof 5.94 KB

CheckpointPoseidonProof, 32 headers/claims:
    prove 258.34 ms, verify 62.12 ms, proof 10.98 KB

BatchedMerkleProof, 32 depth-32 paths:
    prove 523.73 ms, verify 103.51 ms, proof 6.23 KB

ExactStateKillShotProof, 64 transition-shaped items:
    prove 2.56 s, verify 965.48 ms, proof 29.69 KB

OwnerAuthProofKillShot, 255 Standard4x8 proofs:
    verify 1.49 s total, sidecar 15.98 MB
```

Optimization conclusion:

- Poseidon2b/KillShot header and accumulator components are already small.
- Exact-state composition is dominated by repeated Merkle-path component
  verification and terminal discharge.
- OwnerAuth remains dominated by the private-column PCS opening. Shrinking it
  requires a replacement private-witness binding argument, not a cache or
  digest shortcut.
- A streaming direct-discharge evaluator avoids full MLE reconstruction, but
  did not materially change the composed exact-state bench on this machine.
  The next optimization must reduce component count or PCS/opening work rather
  than only moving allocations.

## Accepted-Block Claim Field Schedule

Replaced the accepted-block claim hash from a bincode byte transcript under the
Fiat-Shamir domain with a fixed 80-field Poseidon2b schedule under `ACCBLK__`.
The schedule absorbs:

```text
predicate version
semantic block header claim
parent header claim
MTP window as len + padded u64 fields
active-count expansion window as len + padded u64 fields
ASERT anchor
resource counters
```

This removes a byte-serialization island from the recursive relation.

The accepted-block claim folded into the chain accumulator is now the full
32-byte Poseidon2b digest, represented as two `Block128` lanes. The previous
truncated accumulator input was removed. `AcceptedClaimHashProofKillShot`
pins both output lanes, and `ChainAccumulatorProofKillShot` compresses the
full claim bytes:

```text
accepted_claim_i = Poseidon2b(ACCBLK__, fixed_80_field_schedule_i)
inner_i          = COMPRESS(block_id_i, accepted_claim_i)
acc_i            = COMPRESS(acc_{i-1}, inner_i)
```

This avoids carrying a truncated accepted-claim binding into the final history
proof. Release tests cover accepted-claim high-lane tamper rejection and
chain-accumulator tamper rejection.
The claim still records witness byte lengths for resource accounting but does
not hash detached proof or sidecar bytes into semantic identity. Release tests:

```text
cargo test -p noid_block --release
cargo test -p noid_poseidon2b native::domain --release
```

Added `AcceptedClaimHashProofKillShot`, proving:

```text
accepted_claim = Poseidon2b(ACCBLK__, fields[0..80])
```

Release test:

```text
cargo test -p noid_gkr accepted_claim_hash --release
```

## Local History Cache / Public HistoryProof Split

Renamed the locally persisted finalized-history accumulator from a proof-shaped
API into `LocalHistoryCache`. The object still stores the rolling
`ChainAccumulator` for finalized blocks, but it is now explicitly local
diagnostic/cache state:

```text
LocalHistoryCache:
    acc
    block_height
    chain_claim
```

Storage methods, RPC mining diagnostics, node logs, and in-memory utility
contexts now use cache terminology. The public `HistoryProof` RPC/P2P endpoint
remains separate and returns no proof until the full accepted-block history
verifier becomes authority.

Design result:

- local cache bytes cannot be accidentally decoded as public `HistoryProof`;
- peer-provided history bytes are not stored in the local-cache slot;
- snapshot sync remains fail-closed until the proof verifies the full
  `AcceptBlock` relation;
- the release workspace still checks after the rename.

## Exact-State Seeding and Deferred Slot Writes

Fixed the deferred-root transaction path: internal spend/mint slot writes now
use the crate-private unrooted delta writer instead of `set_slot`, which was
recomputing the raw segmented root per slot. The public `apply_tx` API still
computes and returns the exact composite state root, and block validation still
binds the exact-state verifier result atomically.

Added `ChainState::from_sparse_utxos` for loaded sparse states. It writes unique
live UTXO slots without computing the old raw segment root, then computes
the exact sparse UTXO root directly from the same leaves. Duplicate,
out-of-range, or empty slots are rejected.

Bench result for the standard max-block path:

```text
100 standard user tx:
    before: assemble 32.03 s, RSS 134 MB
    after:  assemble 2.21 s cold profile, 367 ms warm row, RSS 72.6 MB

255 standard user tx:
    before: assemble 76.36 s
    after:  assemble 2.82 s cold profile, 914 ms warm row
    verify: 1.54 s
    proof + sidecar: 14.09 MB
```

The heavy time was not the exact proof itself; it was fixture/raw-state seeding
through the old segmented-root path. The exact transition proof phase for 255
standard tx is about 10 ms in the profiler.

## Poseidon2b PoW Calibration

The production mining loop now benchmarks the actual Poseidon2b PoW header hash.
Current local result on the 12-thread laptop:

```text
sequential rate: 41.07 KH/s
parallel rate:   211.60 KH/s
packed lanes:    2
```

With `GENESIS_TARGET = 2^237`, the expected average genesis solve is:

```text
2^19 attempts / 185.67 KH/s ~= 2.82 s
```

The target remains unchanged; only the explanatory calibration comment was
updated. BLAKE3 is not in the workspace dependency graph and is not a mining or
consensus primitive.

## OwnerAuth Public Table Cache

Verifier/prover code now caches deterministic OwnerAuth public layout tables
(`sigma`, round constants, and MDS lane tables after the fixed dec/project
transforms) by canonical `owner_count`. These tables contain no witness data and
are derived only from protocol constants and layout, so the cache does not alter
the Auth relation.

Measured effect is small and not a big win:

```text
Standard1x2 verify:  about 21 ms
Standard4x8 verify:  about 33 ms
Sweep25x2 verify:    about 78 ms
255 Standard verify: about 1.54 s total
```

Conclusion: Auth sidecar size/verification cannot be solved by this micro-cache.
The production path needs finality-level recursive absorption of per-transaction
Auth proofs, while live blocks keep per-tx wallet proofs for mempool/miner
compatibility.

## OwnerAuth PCS Profiling

### Result

The dominant serialized Auth proof cost is the source-binding portion of the
private-column PCS opening, not the Poseidon2b/FROST relation:

```text
Standard1x2 PCS:
    cap 2.00 KB, FRI 4.38 KB, source 32.41 KB

Standard4x8 PCS:
    cap 2.00 KB, FRI 7.31 KB, source 50-51 KB

Sweep25x2 PCS:
    cap 2.00 KB, FRI 18.69 KB, source 91.22 KB
```

Tuning `COMPACT_TAU` was measured and not kept:

```text
tau=6:
    improves the 255 Standard4x8 batch slightly
    but worsens individual Standard4x8/Sweep sizes and exact-state timing.

tau=7:
    worsens the overall component mix.

tau=8:
    remains the best measured production-wide setting.
```

Source-cap depth was also tested by moving one more source Merkle level from
proof paths into the PCS commitment. It increased individual OwnerAuth proof
size and slightly worsened verification, so the change was reverted. The source
cap remains aligned with the normal Merkle cap depth.

The old packed bit/byte helper from the removed `noid_binius` crate does not
directly reduce this PCS surface. It packs boolean/byte traces, while Auth binds
a private `Block128` state-column MLE. It remains a useful implementation idea
for future bit-oriented witnesses, but it is not part of the production code.

### Consequence

The next Auth big win must be one of:

- a knowledge-sound block/history aggregation proof that verifies wallet Auth
  proofs and outputs a compact aggregate relation; or
- a replacement source-bound private-column PCS opening with a strictly smaller
  source-binding proof.

Reducing query count, accepting digest-only wallet proof markers, or removing
the private-column binding is not allowed.

## Full Batch Verifier Parallelism

The full accepted-block component verifier now checks independent authorization
proofs and independent exact-state component proofs in parallel. The verified
language is unchanged:

```text
for every non-coinbase tx:
    VerifyAuthorization(canonical_statement_i, proof_i)

for every exact-state component:
    VerifyExactStateKillShot(inputs_i, proof_i)
```

This is a verifier/runtime optimization only. The same ordered counts are still
checked after verification:

```text
user_tx_count
owner_count_total
live_input_count_total
```

Release `accepted_block_batch` tests pass with the parallel verifier path.

## Retained Full-Batch Proof API

The public `noid_block` API no longer exposes raw component prove/verify
functions. Those helpers are crate-internal so external callers cannot submit a
component statement as if it were a complete accepted-block batch proof.

The exported retained proof API now has one shape:

```text
retained semantic blocks
+ detached block proofs
+ detached authorization sidecars
+ start parent
+ start state
    -> replay timeless AcceptBlock
    -> derive component statements from the accepted replay
    -> prove or verify the derived component proofs
```

This closes the accidental authority gap between component proofs and full
batch proofs. It still does not enable public O(1) sync: the verifier receives
retained block bytes and witnesses, so a future `HistoryProof` must replace
this host replay with in-proof derivation and recursive composition.

Test coverage now checks:

- retained proof generation equals the native accepted batch output;
- retained proof verification succeeds from the retained block witness;
- mutating an authorization witness is rejected by the internal component
  verifier;
- mutating the retained sidecar is rejected through the retained wrapper before
  component verification.

The component proof object no longer duplicates authorization sidecar proof
bytes. Authorization proofs are retained/private validation witnesses, not the
compressed proof object itself. This removes a linear-size duplicate and makes
the boundary to the future public `HistoryProof` explicit.

## Retained Batch Prover Parallelization

The retained full-batch prover now builds independent proof components in
parallel:

- accepted-claim Poseidon2b hash;
- Standard transaction-body hash component;
- Sweep transaction-body hash component;
- transaction Merkle-root component;
- checkpoint Poseidon2b header/accumulator component;
- exact-state KillShot components.

This is a local prover optimization only. It does not change the accepted
language, public statement, proof format, or soundness assumptions. Every
component statement is still derived only after the retained `AcceptBlock`
replay succeeds.

Release checks:

```text
cargo fmt --all --check
cargo check --workspace --release
cargo test -p noid_block accepted_block_batch --release
cargo test -p noid_chain genesis_nonce_satisfies_pow --release
cargo test -p noid_chain block_work_genesis_target --release
```

## Retained Authorization Totals Cleanup

`FullAcceptedBlockBatchProofComponents` now stores one accumulated
`authorization_totals` value instead of a vector of per-block authorization
batches. The verifier only needs the totals to prove that the number of checked
authorization proofs, unique owners, and live inputs equals the counts produced
by the accepted-block replay.

This removes unused internal shape surface and makes the boundary clearer:
block-local authorization batches are validation artifacts, not independent
component-proof statements.

Release checks:

```text
cargo test -p noid_block accepted_block_batch --release
cargo check --workspace --release
```

## Authorization Verifier Batch Boundary

The retained full-batch component verifier now routes all authorization checks
through a single native batch relation:

```text
VerifyAuthorizationBatchNative(
    canonical_statement_i[],
    retained_wallet_auth_proof_i[],
    expected_authorization_totals
)
```

The relation verifies one `OwnerAuthProofKillShot` per non-coinbase transaction
against the statement derived by accepted-block replay, then recomputes:

```text
user_tx_count
owner_count_total
live_input_count_total
```

and rejects if those totals do not match the accepted-block validation
artifacts. This is the exact boundary the future authorization-verifier proof
component must replace. It is not public O(1) authority yet: the wallet proofs
are still retained/private witnesses and native verification still runs on the
host.

Added test coverage:

- tampered authorization proof is rejected;
- tampered retained sidecar is rejected by full replay before component proof
  verification;
- tampered authorization totals are rejected even when proof bytes are valid.

`docs/security.md` now contains the corresponding production proof-component
requirements. The future component must prove the complete
`VerifyAuthorization(statement, proof)` verifier relation: OwnerAuth sumchecks,
Fiat-Shamir transcript, batch-eval reduction, arithmetic mixed-opening PCS,
compact FRI, and source-binding Merkle/cap checks. Digest-only proof IDs,
acceptance caches, and miner-side re-proving from spend secrets are explicitly
outside the consensus language.

## Recursive Header/Consensus Gate Evidence

Release tests confirm the current recursive boundary matches the timeless header
consensus rules:

```text
cargo test -p noid_recursive --release
cargo test -p noid_chain consensus::pow --release
cargo test -p noid_chain consensus::slot_expansion --release
```

Coverage includes:

- strict `pow_digest < target`, including equality rejection;
- canonical PoW field schedule and packed nonce-batch equivalence;
- `POWHDR__` and `BLOCKHDR` domain separation;
- exact MTP window;
- exact 18-block active-count expansion window;
- triggered/missing/untriggered `log_slots` expansion;
- ASERT anchor update at epoch boundary;
- cumulative chainwork update and saturation behavior;
- header hash KillShot input binding;
- checkpoint Poseidon component tamper rejection.

## Authorization Aggregation Decision

I checked the tempting batch-OwnerAuth idea: combine many transactions with the
same layout into one larger owner-auth MLE and prove all address preimages at
once. That is safe only if the prover knows every spend secret in the batch.
For normal blocks the miner/HistoryProof prover has only wallet proof bytes, not
wallet secrets. Therefore this is not a valid block-level aggregation strategy.

The production path is:

- wallets keep producing authorization proofs without revealing secrets;
- block/HistoryProof provers treat those proof bytes as private validation
  witnesses;
- the final public `HistoryProof` proves the verifier relation
  `VerifyAuthorization(statement_i, proof_i)` for every non-coinbase
  transaction;
- public verifiers receive only the recursive history proof and public terminal
  state, not per-transaction authorization proof lists.

This means sidecar bytes are a live propagation cost, but they must not become a
public O(1) proof-size cost. The next real aggregation work is an
authorization-verifier proof component, not a miner-side proof-of-secret batch.

## Auth PCS API Cleanup

Removed unused exported multi-column Auth PCS helpers:

- `AuthMleMultiOpeningProof`;
- `commit_auth_mle_columns`;
- `open_auth_mle_columns_committed`;
- `verify_auth_mle_multi_opening`;
- the public convenience `prove_auth_mle_opening`.

The production Auth capsule commits exactly one private `state` MLE column, then
opens the single reduced batch-eval claim bound to that column. Keeping the
unused multi-column surface made audit scope larger without serving the current
protocol. The remaining Auth PCS API is the one used by
`OwnerAuthProofKillShot`:

```text
commit_auth_mle_column
absorb_auth_mle_commitment
open_auth_mle_committed
verify_auth_mle_opening
```

Release check:

```text
cargo test -p noid_gkr auth_pcs --release
```

## Authorization Verifier Boundary Move

Moved the proof-facing authorization statement and verified-count output from
`noid_block` into `noid_gkr`:

```text
CanonicalAuthorizationStatement
VerifiedAuthorization
VerifiedAuthorizationBatch
canonical_authorization_statement_from_body
verify_authorization_statement_proof
```

This removes a future dependency cycle for public history proofs. The block
validator still orchestrates sidecar shape and block ordering, but the exact
`VerifyAuthorization(statement, proof)` boundary now lives in the cryptographic
crate that owns the OwnerAuth proof format.

Added a focused test that a split statement is rejected when
`statement.tx_body_hash` differs from the hash already absorbed inside the
canonical OwnerAuth public input.

Added `noid_recursive::verify_authorization_batch_native`, a dependency-cycle
free native relation for:

```text
ordered block transaction bodies
+ ordered retained wallet authorization proofs
-> VerifiedAuthorizationBatch totals
```

This function is not public snapshot authority. It is the recursive crate's
specification boundary for the future in-proof authorization verifier component,
so the final `HistoryProof` does not need to depend on `noid_block`. The native
batch verifier checks proofs in parallel; statement ordering is still fixed by
transaction index and the output totals are deterministic sums.

Retained full-batch verification now uses the same
`verify_authorization_statement_proof` boundary instead of rebuilding
`OwnerAuthCircuit + channel` locally. There is one native authorization verifier
language shared by wallet verification, block validation, retained batch replay,
and the future history proof relation.

Release checks:

```text
cargo check -p noid_block --release
cargo test -p noid_gkr wallet_authorization --release
cargo test -p noid_recursive authorization --release
cargo test -p noid_block accepted_block_batch --release
```

## Folded Source-Cap Experiment Rejected

Rechecked folded-layer Merkle caps for Auth PCS source binding on the current
Poseidon2b source-binding implementation. A depth-5 cap per intermediate
TensorFold layer increased proof sizes:

```text
Standard4x8: 63.00 KB -> 71.19 KB wallet bundle
Sweep25x2:   116.86 KB -> 124.54 KB wallet bundle
```

It also changed Fiat-Shamir query scheduling when encoded differently, and the
source-binding tamper test correctly exposed that risk. The experiment was not
kept. Production remains the single folded-root format with byte-identical
root/depth transcript binding and source paths proven to those roots.

Release checks:

```text
cargo test -p noid_fri_binius mixed_open --release
cargo test -p noid_gkr auth_pcs --release
NOID_AUTH_PCS_PROFILE=1 NOID_SOURCE_BINDING_PROFILE=1 \
  cargo bench -p bench_prover --bench alice_sends_bob
```

## Poseidon2b PoW Mining Baseline

Current production PoW is `H_POSEIDON_POW(header fields with patched nonce)`.
The focused mining bench on the laptop measured:

```text
sequential: 20,000 attempts in 0.505 s  = 39.63 KH/s
parallel:   200,000 attempts in 1.077 s = 185.67 KH/s
threads:    12
packed lanes: 2
```

At that measured parallel rate, expected average solve time is about:

```text
target 2^237: 2.82 s
target 2^238: 1.41 s
target 2^239: 0.71 s
target 2^240: 0.35 s
```

This is a CPU baseline, not a final optimized miner. The current implementation
already uses limited packed lanes, but it is not yet a wide AVX/GPU mining
kernel. Difficulty/genesis target selection must use this measured Poseidon2b
rate, not the removed pre-Poseidon PoW rate.

## Standard Max-Block Minimal Path Bench

Release standard-only block scaling after the retained batch and Auth PCS API
cleanup:

```text
NOID_BLOCK_SCALING_STANDARD_ONLY=1 cargo bench -p bench_prover --bench block_scaling

10 user tx:
    first measured row previously included cold-start noise

20 user tx:
    assemble proof 90.63 ms, verify 133.55 ms, total bytes 1.11 MB

100 user tx:
    assemble proof 378.62 ms, verify 621.85 ms, total bytes 5.53 MB

255 user tx + 1 coinbase:
    assemble proof 936.58 ms, verify 1.56 s, total bytes 14.09 MB
    block proof 160.81 KB, auth sidecar 13.93 MB
```

The initial 10-tx row was later confirmed to be a cold-start artifact: whichever
row ran first absorbed lazy proof-stack initialization. The bench now performs
an unreported warmup before printing rows. The important max-block conclusion is
unchanged: live block size is dominated by per-tx wallet authorization sidecars,
not the exact-state block proof. Public O(1) history must recursively absorb
those sidecar verifier relations so they do not remain linear public snapshot
payload.

Re-run after moving the authorization verifier boundary into `noid_gkr` and
adding the recursive native auth-batch boundary:

```text
NOID_BLOCK_SCALING_STANDARD_ONLY=1 cargo bench -p bench_prover --bench block_scaling

10 user tx:
    assemble proof 59.06-71.68 ms, verify 66.05-88.92 ms, total bytes 573.73 KB

20 user tx:
    assemble proof 102.52 ms, verify 134.58 ms, total bytes 1.11 MB

100 user tx:
    assemble proof 383.74 ms, verify 630.02 ms, total bytes 5.53 MB

255 user tx + 1 coinbase:
    assemble proof 927.54 ms, verify 1.59 s, total bytes 14.09 MB
    block proof 160.81 KB, auth sidecar 13.93 MB
```

## Authorization Verifier Trace Boundary

The recursive crate now exposes a traced authorization-batch boundary:

```text
verify_authorization_batch_native_with_traces(block, wallet_auth_proofs)
```

It runs the same production `verify_owner_auth_killshot` verifier through a
tracing Poseidon2b Fiat-Shamir channel. The trace records the exact ordered
absorbs and squeezes for each accepted wallet proof; it is not a new verifier
and not public authority.

Design consequences:

- the canonical statement and arithmetic PCS commitment are visibly absorbed
  before the first challenge;
- split `tx_body_hash` statements reject before a trace can be used;
- future `HistoryProof` authorization work has a concrete proof target:
  prove this transcript and the OwnerAuth verifier equations in-proof, not a
  digest or host acceptance flag.

Release checks:

```text
cargo test -p noid_recursive authorization --release
cargo test -p noid_gkr wallet_authorization --release
cargo check -p noid_recursive --release
cargo check -p noid_gkr --release
```

## Fiat-Shamir Transcript Batch KillShot

Added `noid_recursive::FiatShamirTranscriptProofKillShot` and
`FiatShamirTranscriptBatchProofKillShot`, Poseidon2b KillShot proofs for
ordered production Fiat-Shamir traces. It models the exact
`Poseidon2bChannel` state machine:

- two absorbed fields fill a rate block and trigger a permutation;
- a squeeze with one buffered field applies the canonical padding field first;
- the first squeeze outputs lane 0, buffers lane 1, then advances the sponge;
- the second consecutive squeeze consumes the buffered lane without a
  permutation;
- any absorb invalidates the buffered lane.

The proof uses BlockSpine KillShot plus linear chain claims over the sponge
state. It has been integrated into `RetainedFullAcceptedBlockBatchProof` for
authorization verifier traces. Retained block proofs split authorization traces
into chunks of at most 16 traces, so a 255-transaction block cannot create one
giant transcript MLE. Tampering any chunk rejects during retained batch
verification.

Measured component data before chunking was fixed:

- 1 Standard4x8 auth verifier trace: prove 166.15 ms, verify 20.56 ms, proof
  5.64 KB, 302 Poseidon2b permutations.
- 16 Standard4x8 auth verifier traces: prove 2.38 s, verify 367.11 ms, proof
  6.83 KB, 4832 Poseidon2b permutations.

Direct monolithic 255-trace proving is forbidden by API caps. It would pad about
77000 permutations to a 2^26-row MLE and can exhaust laptop memory; production
retained proofs use bounded chunks instead. A fail-safe bench run with
NOID_KILLSHOT_AUTH_TRACE_N=255 and all unrelated component sizes set to 1 now
prints skip for the direct transcript batch instead of proving it, and the
process exits normally.

Optimization notes:

- Direct source expansion for small single-column Auth PCS was tested and
  rejected: Standard4x8 grew from about 63 KB to about 141 KB and verify from
  about 33 ms to about 156 ms.
- COMPACT_TAU=6 was tested and rejected for the production mix: Standard4x8 and
  Sweep became larger than the current setting.
- COMPACT_TAU=7 reduced Sweep by about 2.4 KB but increased the common
  Standard4x8 proof by about 0.5 KB, so COMPACT_TAU=8 remains the production
  setting until a real source-binding redesign replaces this PCS path.

This closes the Poseidon2b transcript subclaim for future recursive
authorization verification and makes the OwnerAuth verifier reductions explicit:
main, shift, boundary, the three state-column batch-eval claims, and the final
PCS opening reduction are now returned by the production verifier boundary. It
does not yet prove the full OwnerAuth verifier arithmetic; the remaining auth
work is to prove those field equations directly inside the HistoryProof
component.

Release checks:

```text
cargo test -p noid_recursive fs_transcript --release
cargo test -p noid_block accepted_block_batch --release
```

## Full Workspace Release Test

Full release test after the current O(1) cleanup and retained-boundary work:

```text
cargo test --workspace --release
```

Result: passed.

Notable long-path coverage included:

- max 255 authorization sidecar cap;
- accepted full-batch replay and retained component proof checks;
- recursive header, chain, and checkpoint tests;
- FRI-Binius source-binding tamper tests;
- OwnerAuth statement, boundary, and PCS tamper tests;
- mempool Sweep25x2 admission and tamper/replay tests;
- miner standard, sweep, mixed, and split sweep+standard proof serialization;
- wallet proof serialization secrecy tests.
