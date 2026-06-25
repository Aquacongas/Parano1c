# Security Specification

This document describes the current production consensus kernel. It is
normative for the code in this repository and intentionally does not describe
removed proof systems or inactive design variants.

## 1. Consensus Surface

### 1.1 Semantic Block

A semantic block consists of:

- a canonical 212-byte `BlockHeader`;
- the ordered transaction bodies committed by `tx_root`;
- the detached validation witness required to verify the block:
  `BlockProof` and `BlockAuthSidecar`.

The detached witness is mandatory for block acceptance, but its serialized
bytes are not part of semantic block identity or mining work. Different valid
encodings of the same validation witness cannot create different consensus
blocks.

### 1.2 Block ID

The chain link is:

```text
block_id = Poseidon2b(BLOCKHDR, semantic_header_fields)
```

The block header is semantic-only. Proof bytes and authorization sidecar bytes
are detached validation witnesses and have no header fields.

The next block must set:

```text
next.prev_block_hash == block_id(parent)
```

### 1.3 Proof-of-Work Digest

The mining digest is:

```text
pow_digest = Poseidon2b(POWHDR__, pow_header_fields)
```

The fixed field schedule has exactly 16 `Block128` elements:

```text
prev_block_hash       2 fields
state_root            2 fields
tx_root               2 fields
timestamp             1 field, zero-extended LE u64
height                1 field, zero-extended LE u64
miner_address         2 fields
nonce                 1 field, LE u128
difficulty_target     2 fields
log_slots             1 field, zero-extended LE u32
active_slot_count     1 field, zero-extended LE u64
alloc_counter         1 field, zero-extended LE u64
```

With Poseidon2b rate 2, this is exactly eight rate blocks. The digest uses
`finalize_no_pad`; length binding comes from the fixed 16-field schedule and
domain separation from the `POWHDR__` capacity IV.

Consensus accepts PoW only when:

```text
pow_digest < difficulty_target
```

as little-endian 256-bit integers. Equality is rejected.

### 1.4 Difficulty and Work

The ASERT target function, median-time-past rule, cumulative chainwork, and
finalized-prefix fork choice are deterministic integer consensus rules. The PoW
hash primitive changed; the target arithmetic did not.

For strict target acceptance, exactly `difficulty_target` digest values are
valid. Consensus chainwork for one block is therefore:

```text
Work(T) = floor((2^256 - 1) / T) + 1, for T > 0
Work(0) = 0 for defensive accounting only; target 0 cannot satisfy PoW
```

The value is stored as a little-endian unsigned 256-bit integer and cumulative
chainwork is saturating u256 addition. This same formula is used by live fork
choice, retained batch replay, and the recursive header-integer relation.

The local wall-clock future-drift check is node admission policy, not timeless
history consensus. Live nodes still enforce it before accepting or relaying a
fresh block. Recursive history proofs verify median-time-past, ASERT, PoW,
chainwork, and state validity, but do not try to prove what a specific node's
wall clock was at historical acceptance time.

The current genesis floor is:

```text
GENESIS_TARGET = 2^237
```

This calibrates the first block to the same wall-clock solve class as the
previous floor on the current production miner path. The measured parallel
Poseidon2b miner on the current 12-core laptop is about 186 KH/s, so:

```text
expected attempts at 2^237 = 2^19 = 524288
expected time              = about 2.8 seconds
```

## 2. Cryptographic Domains

All consensus hash domains are fixed byte tags mapped into Poseidon2b capacity
IVs. The important separation for block validity is:

```text
BLOCKHDR != POWHDR__
```

Therefore a PoW digest cannot be replayed as a chain-link block id, and a block
id cannot be replayed as mining work.

BLAKE3 is not a consensus PoW primitive and is not Fiat-Shamir authority. It is
absent from the workspace dependency graph. A byte-native checksum or object id
is not sufficient for accepting a block, accepting a snapshot, or extending
recursive history.

Consensus PCS and source-binding commitments use only the arithmetic Poseidon2b
backend. Source caps, folded roots, authorization PCS roots, exact sparse-state
Merkle roots, and ReuseGuard roots are field-element commitments under
Poseidon2b domains. There is no byte-native or BLAKE3 commitment backend in the
consensus verifier.

The source-binding commitment stores a Poseidon2b source cap, not merely a
single source root. Source Merkle openings are checked up to the absorbed cap
nodes. This is the same binding relation as a root opening, with the upper
Merkle levels moved into the commitment so the verifier does not accept any
prover-supplied source cap.

## 3. Authorization Security

For every non-coinbase transaction, the verifier derives a canonical
authorization statement from the transaction body and authenticated state view:

```text
statement =
    tx_hash
    ordered input slots
    actual unique owners
    input_to_owner mapping
    owner_count and capacity
    protocol/domain identifiers
    one-column arithmetic Poseidon2b PCS commitment binding
```

The statement is absorbed before the first Fiat-Shamir challenge.

The owner-auth layout is sized by the actual unique owner count, not by the
transaction shape or by a fixed four-slot minimum. For one unique owner the
committed trace has `slot_bits = 0` and `num_vars = 9`; for 25 unique owners it
has `slot_bits = 5` and `num_vars = 14`. The layout fields and owner capacity
are part of the canonical statement absorbed before challenges, so shrinking
padding changes only the committed table size, not the authorization relation.

The authorization relation is:

```text
exists spend_secret:
    H_ADDR_fixed(spend_secret) = owner
```

The proof is accepted only if the owner-batched authorization proof verifies
against the canonical statement.

### Authorization Knowledge Theorem

Security claim for production theft resistance:

```text
If VerifyAuthorization(statement, proof) accepts, then an extractor for the
Fiat-Shamir IOP/PCS obtains spend_secret for every claimed owner, except with
the stated authorization proof soundness error.
```

This is the property needed for theft resistance. Plain algebraic soundness is
not enough, because an address preimage statement can be true even for a prover
that does not know the preimage.

The current `OwnerAuthProofKillShot` implementation satisfies this theorem
under the Fiat-Shamir, source-bound PCS extraction, and Poseidon2b assumptions
listed below.

For each owner slot, the proof commits to one private `state` MLE before any
authorization challenge is squeezed. The transcript absorbs:

- the canonical authorization statement;
- owner count, layout, input mapping, slot positions, and `tx_hash`;
- expected owner addresses; and
- the arithmetic PCS commitment to the private state column.

The FROST/KillShot sumchecks then prove, over that committed column:

- every active Poseidon2b round transition for
  `H_ADDR_fixed(spend_secret)`;
- fixed capacity lanes for the `TAG_ADDRFIX` domain at round zero; and
- expected output lanes equal to the public owner address at the final round.

The boundary relation uses the inverse first-round MDS matrix to express the
pre-round input lanes as linear constraints on committed round-zero state
cells. Therefore, from an accepting proof, a forking extractor obtains the
committed state MLE and reads:

```text
spend_secret_i =
    MDS_FULL^{-1}(state[owner_slot_i, round=0])[0..2]
```

for every owner slot. The transition and boundary equations imply:

```text
Poseidon2b(TAG_ADDRFIX, spend_secret_i) = owner_i
```

except with the authorization sumcheck/PCS soundness error and the configured
hash-binding assumptions.

The PCS opening is the dominant proof-size and verification cost:

```text
Standard1x2, one owner: about 38.8 KB of a 41.7 KB proof
Standard4x8, four owners: about 59.6 KB of a 63.1 KB proof
Sweep25x2, twenty-five owners: about 111.9 KB of a 116.4 KB proof
```

This is an optimization issue, not a theft-soundness gap. A future replacement
may use an input-terminal private-witness commitment to reduce proof size, but
it must preserve the theorem above. A block-level proof over raw secrets is
invalid: block producers and recursive provers only have detached wallet
proofs, not spend secrets.

Forbidden authorization replacements:

```text
- digest-only acceptance of wallet proofs;
- native cache markers;
- revealing the private trace or raw spend secrets;
- block-producer proofs that require miners to know wallet secrets;
- removing the private-state PCS/opening without an equivalent
  knowledge-sound commitment/opening relation.
```

## 4. Exact State Transition

The accepted block relation applies transactions atomically over:

```text
state_root = H_STATE_ROOT(log_slots, utxo_root, guard_root)
```

The UTXO update is exact sparse-Merkle transition checking. The ReuseGuard root
is part of the same state root and prevents spend-to-remint ABA reuse until the
consensus delay expires.

The old random-point native delta term is not part of current security. The
state transition is hash binding plus exact authenticated update logic.

### Directed Merkle Path Binding

The recursive state-transition proof boundary uses directed Poseidon2b Merkle
paths derived from the same canonical multiproof accepted by native
`AcceptBlock`.

For the UTXO frontier:

```text
leaf domain:  EXSTSLT_
node domain:  EXSTNOD_
root:         utxo_root
max depth:    32
```

For ReuseGuard:

```text
leaf domain:  RGDBUCK_
node domain:  RGDNODE
root:         guard_root
fixed depth:  8
```

The leaf/root hash relations are also explicit proof relations:

```text
SlotLeafProof:
    proves EXSTSLT_(amount_u64, owner_hi, owner_lo) = slot_leaf

GuardBucketProof:
    proves RGDBUCK_(empty | height, sorted spent_slots) = bucket_leaf

CompositeStateRootProof:
    proves EXSTROT_(log_slots, utxo_root, guard_root) = state_root
```

Empty ReuseGuard buckets have one canonical encoding. Occupied buckets require
a non-empty strictly sorted slot list. Non-canonical bucket encodings are
outside the recursive language.

Each path level includes a public direction bit:

```text
direction = 0: parent = H_NODE(current, sibling)
direction = 1: parent = H_NODE(sibling, current)
```

Unused levels must have zero siblings and `direction = 0`. The Merkle
KillShot relation absorbs the node-domain tag and all direction bits before
Fiat-Shamir challenges, then proves the exact two-permutation Poseidon2b
compression chain for those public path values. A proof built under `COMPRESS`
cannot verify as `EXSTNOD_` or `RGDNODE`.

The UTXO old-root paths and new-root paths are both derived from the same
canonical multiproof topology. Explicit proof siblings are reused, while
touched sibling subtrees are recomputed from the old or new touched leaves.
Together with `SlotLeafProof`, one canonical sparse-Merkle proof fixes both:

```text
old_leaves -> parent/frontier utxo_root
new_leaves -> child utxo_root
```

The composite state root proof is accepted only after:

```text
H_STATE_ROOT(log_slots, child_utxo_root, child_guard_root)
    == header.state_root
```

### Atomicity Theorem

For any block:

```text
AcceptBlock(parent_state, block, witness) = true
```

implies there exists an ordered transaction execution from `parent_state` to
`header.state_root`, with all input spends, output mints, fee accounting,
coinbase accounting, expansion counters, and ReuseGuard updates applied in
that order.

If any transaction, authorization proof, state opening, ReuseGuard update, fee
rule, or public predicate fails, the block is rejected and no partial state is
committed.

## 5. Aggregate Soundness Budget

The conservative per-authorization proof bound used for production accounting is:

```text
epsilon_auth <= 512 / 2^128
```

For a maximum user block of 255 non-coinbase transactions:

```text
epsilon_auth_block <= 255 * 512 / 2^128
                   = 130560 / 2^128
                   ~= 2^-111.0
```

The system therefore claims:

```text
about 119-bit soundness per authorization proof
about 111-bit authorization union bound for a full 255-user-tx block
```

It does not claim a global 120-bit lifetime bound. For an adversary making
`Q_auth` authorization verification attempts:

```text
epsilon_total(Q_auth) <= Q_auth * (512 / 2^128) + epsilon_hash + epsilon_state
```

where `epsilon_hash` covers the configured hash assumptions and
`epsilon_state` covers sparse-Merkle and ReuseGuard hash-binding failures.

## 6. Recursive and Snapshot Authority

Public arbitrary-peer snapshot sync remains fail-closed until real recursive
history proof verification is active.

Retention is fail-safe:

```text
block body
BlockProof
BlockAuthSidecar
consensus context objects
```

may be pruned only after the corresponding finalized block range is covered by
a real checkpoint proof that verifies the full frozen block relation.

### Finalized Prefix Safety

The fork-choice rule rejects a candidate chain that conflicts with the persisted
finalized prefix. Within the non-finalized window, the chain with greater exact
cumulative work wins, with deterministic tie-breaking by block id.

### Snapshot Safety

A public snapshot is acceptable only if:

```text
snapshot.height     == HistoryProof.height
snapshot.state_root == HistoryProof.state_root
snapshot.utxo_root  == HistoryProof.utxo_root
snapshot.guard_root == HistoryProof.guard_root

H_STATE_ROOT(snapshot.log_slots, snapshot.utxo_root, snapshot.guard_root)
    == snapshot.state_root
```

Blocks after the checkpoint height are then verified by normal `AcceptBlock`.

### Production O(1) Closure

Public O(1) history authority is enabled only after the verifier checks the
following recursive statement:

```text
HistoryProof(S_n) accepts
    => there exists a canonical block sequence B_0..B_{n-1}
       and validation witnesses W_0..W_{n-1}
       such that S_{i+1} = AcceptBlock(S_i, B_i, W_i)
       for every i from genesis to n-1.
```

The recursive step must prove, not assume:

- Poseidon2b `POWHDR__` digest and strict target comparison;
- Poseidon2b `BLOCKHDR` block id and parent linkage;
- Poseidon2b `ACCBLK__` accepted-block claim reconstruction from its fixed
  field schedule;
- exact MTP, ASERT, target floor, and cumulative chainwork integer semantics;
- exact log-slot expansion trigger from the 18-block active-count window;
- transaction root binding to the ordered block body;
- coinbase, fee, supply, shape, and resource-weight rules;
- owner-batched authorization verification for every non-coinbase transaction;
- exact sparse-Merkle UTXO transition;
- exact ReuseGuard transition;
- state-root continuity across every block in the batch;
- previous history proof verification and start/end state equality.

The history proof may use optimized Poseidon2b/KillShot relations, but those
relations must be proven equivalent to the native `AcceptBlock` predicate on a
differential corpus before they become authority.

Public O(1) activation has a single accepted verifier shape:

```text
VerifyHistoryProof(
    genesis_consensus_state,
    claimed_tip_consensus_state,
    claimed_tip_accumulator,
    proof
) = true
```

Acceptance requires all of the following in one composed relation:

- the previous `HistoryProof` verifier relation, or the fixed genesis base case;
- the full accepted-block batch relation over finalized blocks;
- exact start/end equality between the previous proof state and the new batch;
- exact chain-accumulator transition over the same ordered block ids and
  accepted-block claims;
- exact final `state_root = H_STATE_ROOT(log_slots, utxo_root, guard_root)`;
- exact cumulative chainwork and finalized-prefix state;
- no host-supplied accepted claims, local cache entries, header traces, or
  component inputs accepted as authority without the relation that derives them.

Until that verifier exists and passes the acceptance matrix, public snapshot
sync is fail-closed even when peers send non-empty proof bytes. The local
history cache and component proofs are useful for construction and testing,
but they are not a substitute for `VerifyHistoryProof`.

History proof soundness theorem:

```text
VerifyHistoryProof(S_0, S_n, A_n, Π_n) = true
    => there exists a canonical sequence of finalized semantic blocks
       B_1..B_n and detached validation witnesses W_1..W_n such that
       S_i = AcceptBlockTimeless(S_{i-1}, B_i, W_i) for every i,
       and A_n is the deterministic Poseidon2b chain accumulator over exactly
       those ordered block ids and accepted-block claims,
```

except with the union of:

- Poseidon2b collision/preimage failure for consensus commitments;
- KillShot/GKR/sumcheck/PCS soundness failure in the active components;
- authorization knowledge-soundness failure;
- exact-state Merkle binding failure; and
- recursive verifier soundness failure.

### Checkpoint Poseidon Component

The implemented `CheckpointPoseidonProof` is the composed proof for the
Poseidon-heavy checkpoint subrelation:

```text
pow_digest_i = Poseidon2b(POWHDR__, header_fields_i)
block_id_i   = Poseidon2b(BLOCKHDR, header_fields_i)

inner_i      = COMPRESS(block_id_i, accepted_claim_i)
acc_i        = COMPRESS(acc_{i-1}, inner_i)
```

The verifier checks that `header_fields_i` are the canonical field schedule of
the supplied semantic header. It does not recompute native Poseidon2b digests.
It discharges the header-hash and accumulator terminal reductions against the
deterministic MLE traces reconstructed from the public headers, claims, and
accumulator boundary. A component transcript whose terminal claims are not
openings of those canonical traces is rejected.
Soundness of this component says:

```text
VerifyCheckpointPoseidon(start_acc, end_acc, headers, claims, proof) accepts
    => the supplied pow_digest/block_id values and end accumulator are
       consistent with the stated Poseidon2b relations,
```

except for the Poseidon2b/KillShot/sumcheck soundness errors.

This component is intentionally insufficient for public snapshot authority. It
does not prove:

- `pow_digest < difficulty_target`;
- ASERT, MTP, chainwork, epoch anchor, or expansion-window integer semantics;
- transaction root, coinbase, fee, supply, or resource rules;
- authorization proof verification;
- exact UTXO/ReuseGuard action semantics.

Those relations must be included in `HistoryProof` before public O(1) sync can
be enabled.

### Full Batch Component Proof

The implemented full-batch component proof composes the currently proven
subrelations after the raw retained `AcceptBlock` batch has extracted
components:

```text
RetainedFullAcceptedBlockBatchProof =
    AcceptedClaimHashProofKillShot
    TxBodyStandardBlockSpineProof
    TxBodySweepBlockSpineProof
    TxRootBatchedMerkleProofKillShot
    CheckpointPoseidonProof
    + ExactStateKillShotProof for each user-transaction block
```

Verification also checks:

- the fixed `ACCBLK__` accepted-claim field schedule;
- the `AcceptedClaimHashProofKillShot` terminal reductions against the
  canonical accepted-claim trace reconstructed from that field schedule;
- every `tx_body_hash` against the canonical `TxBody` via the shape-specific
  Poseidon2b spine relation;
- standard and sweep tx-body spine terminal reductions against canonical traces
  reconstructed from ordered block bodies;
- the ordered transaction-root Merkle relation, including canonical zero
  padding up to the block's Merkle width;
- the transaction-root Merkle terminal reductions against the canonical Merkle
  trace reconstructed from ordered transaction body hashes and zero padding
  leaves;
- the accepted-claim batch through `HeaderIntegerTrace`;
- the Poseidon2b header-hash component and its terminal reduction discharge;
- the Poseidon2b chain-accumulator component and its terminal reduction
  discharge; and
- every owner-batched authorization proof against the exact canonical
  statement derived from the retained block body and authenticated state view;
  and
- every exact-state KillShot component against the extracted exact-state
  inputs.

This is a production component proof, but it is still not sufficient public
snapshot authority by itself. It proves the implemented claim-hash,
hash/Merkle/accumulator subrelations over supplied components. The final
`HistoryProof` must additionally prove that the supplied components are
reconstructed from canonical block bodies, canonical transaction body hashes,
public transaction logic, authorization proofs, resource rules, and retained
pre-state context.

The tx-body component groups transactions by shape and proves the matching
canonical Poseidon2b schedule. Standard transactions use the 59-permutation
`Standard4x8` spine. Sweep transactions use the 142-permutation `Sweep25x2`
spine. Both relations include a dedicated linear terminal pin:

```text
state[tx_i.wrap_slot, final_round, 0..2] == tx_body_hash_i
```

The claimed hashes are absorbed before challenges and also appear as the
right-hand side of this linear relation. Transcript binding alone is not a
valid replacement for the wrap-output pin.

The transaction-root component uses one batched Poseidon2b Merkle KillShot over
all leaves in the padded block tree:

```text
leaves[0..tx_count)      = ordered tx_body_hashes
leaves[tx_count..width)  = ZERO_DIGEST
tx_root                 = MerkleRoot_COMPRESS(leaves)
```

Every padding leaf is included in the component inputs. Therefore a block with
`tx_count = n` cannot prove a root that hides additional non-zero leaves beyond
the declared body length.

### Exact-State KillShot Component

The implemented `ExactStateKillShotProof` composes the Poseidon2b hash/Merkle
subrelations of exact state transition:

```text
EXSTSLT_  slot leaf hashing for old and new touched slots
EXSTNOD_  old and new UTXO Merkle paths
RGDBUCK_  old and new ReuseGuard bucket hashes, when spends exist
RGDNODE   old and new ReuseGuard Merkle paths, when spends exist
EXSTROT_  parent and child composite state roots
```

The UTXO Merkle paths and ReuseGuard Merkle paths are proven as separate
domain-specific batched Merkle relations. This is the production relation: each
batch absorbs its own node-domain tag before Fiat-Shamir challenges and proves
only paths from that domain. Mixing the domains into one larger trace is not a
security requirement and is not used by the verifier.

Soundness of this component says that accepted proof bytes bind the supplied
derived inputs to the stated Poseidon2b relations, except for the stated
KillShot/sumcheck/PCS errors. The verifier discharges each subcomponent's
terminal reductions against the canonical trace reconstructed from the supplied
slot-leaf, state-path, guard-bucket, guard-path, and composite-root inputs. It
does not by itself prove:

- that the touched-slot set is the canonical action surface of the block body;
- spend/mint ordering and same-block exclusion;
- active-slot and allocation-counter updates;
- ReuseGuard event semantics beyond the supplied old/new bucket/path hashes;
- equality between this state component and authorization or transaction-root
  components.

Those constraints remain part of the full `AcceptBlock` proof relation.

The authorization subrelation is the native batch relation:

```text
VerifyAuthorizationBatchNative(block, BlockAuthSidecar)
    -> user_tx_count, owner_count_total, live_input_count_total
```

It derives every canonical authorization statement from ordered block bodies,
checks exactly one `OwnerAuthProofKillShot` per non-coinbase transaction in
block order, and rejects empty-owner or empty-live-input authorizations. A
future optimized recursive implementation may aggregate this relation, but it
must prove the same statement/proof binding and cannot replace it with a host
acceptance certificate.

The block producer does not know wallet `spend_secret` values. Therefore a
block-level authorization proof over raw secrets is not a valid production
replacement for per-transaction wallet authorization. Any aggregation used by
`HistoryProof` must either:

- prove verification of the wallet-provided authorization proofs; or
- replace the wallet proof format with an equally binding proof produced by the
  wallet before mempool admission.

It must not require miners to learn secrets and must not replace authorization
verification with a digest, cache marker, or local acceptance flag.

Current implementation note: `OwnerAuthProofKillShot` already makes the
Poseidon2b/FROST relation small. The dominant serialized size is the
private-column PCS opening used to bind the Auth witness MLE. Replacing that
PCS discharge is a production optimization target, but until it is replaced,
the native authorization verifier remains the authority.

The current PCS uses a source-cap optimization: the source cap is part of the
absorbed commitment, and source paths prove queried leaves to that cap. This
reduces upper Merkle path bytes but does not change the proof relation or the
authorization knowledge assumption.

The Auth witness MLE must remain cryptographically bound. Removing the PCS
opening without a replacement commitment is forbidden: otherwise a prover can
answer terminal sumcheck claims adaptively without binding them to one private
witness. Revealing the private trace is also forbidden because it can reveal or
linearly expose spend secrets for reused owners. A replacement must be either a
knowledge-sound private-witness commitment/opening protocol or an in-proof
verifier aggregation of the wallet-provided authorization proofs.

The current Auth PCS size is dominated by source-binding data, not by the
FROST/KillShot relation. Optimizing this surface is valid only if the
replacement still proves:

```text
terminal state claim == evaluation of the committed private Auth state MLE
```

for the commitment absorbed before authorization challenges. The following are
not valid optimizations:

- reducing FRI/source query count below the stated soundness budget;
- accepting a hash of an Auth proof instead of verifying the proof;
- trusting mempool/miner acceptance caches;
- dropping source-binding Merkle/Fold data without another source-bound
  opening argument;
- moving proof of raw spend secrets to the miner or block producer.

The native production boundary for this proof is the full accepted-block batch
relation:

```text
VerifyFullAcceptedBlockBatchNative(
    start_recursive_consensus_state,
    start_chain_accumulator,
    start_parent_header,
    start_state,
    retained semantic blocks and detached witnesses
) -> (end_recursive_consensus_state, end_chain_accumulator, end_state)
```

For each block in order this relation:

- derives the exact MTP window, 18-block active-count window, and ASERT anchor
  from the rolling recursive consensus state;
- verifies the full timeless `AcceptBlock` predicate from the retained block
  body, `BlockProof`, `BlockAuthSidecar`, parent header, and pre-state;
- treats coinbase-only blocks as carrying no detached proof while still verifying header, tx root,
  coinbase structure, and exact state delta;
- reconstructs the canonical accepted-block claim only after full validation;
- feeds the reconstructed claims into the accepted-claim batch relation.

The implementation also exposes proof-facing components from this same
validation path. For user-transaction blocks the raw `AcceptBlock` path returns:

- the verified authorization batch counts;
- exact-state transition inputs;
- the canonical exact action surface;
- the sealed verified transition; and
- derived exact-state KillShot inputs.

Coinbase-only blocks with no detached proof return no exact-state or
authorization proof components. This distinction is consensus-significant:
component inputs are not accepted from peers or storage, and are useful only
because they are derived after `AcceptBlock` succeeds on retained block bodies
and detached witnesses.

Therefore stored accepted claims or local history-cache updates are never
accepted as substitutes for re-verifying `AcceptBlock` in the public O(1)
authority.

Native transaction application uses deferred raw-slot writes internally: the
crate-private slot update path marks dirty raw state but does not publish a
root. The public `apply_tx` API computes the exact composite state root before
returning, and block acceptance binds the sealed exact-state verifier result
atomically. Thus the deferred write helper is a performance implementation
detail, not an externally callable consensus shortcut.

Loaded sparse state, such as genesis/snapshot/bench fixtures, may be
constructed from unique live UTXO leaves by writing raw slots without computing
the old raw segment root and then computing the exact sparse UTXO root directly
from the same leaves. This constructor rejects duplicate, empty, or out-of-range
slots. It does not apply transactions and does not bypass `AcceptBlock`; it only
constructs a state object whose `state_root` is still
`H_STATE_ROOT(log_slots, utxo_root, guard_root)`.

### Accepted-Block Claim Binding

The stored local history cache does not fold raw proof bytes or a
proof-only digest. Each non-genesis step folds a domain-separated
`AcceptedBlockClaimTranscript`:

```text
AcceptedBlockClaim =
    Poseidon2b(ACCBLK__,
        ACCEPT_BLOCK_PREDICATE_VERSION,
        semantic block header and block_id,
        parent header and parent block_id,
        MTP timestamp window,
        18-block active-count expansion window,
        ASERT anchor height/timestamp/target,
        block resource-count inputs
    )
```

This is a fixed field schedule, not bincode or byte-stream serialization. The
MTP and active-count windows are encoded as `len || values || zero padding` up
to their consensus maximum lengths. This keeps the final recursive claim
relation arithmetizable with the same Poseidon2b/KillShot machinery used for
headers and accumulators.

For user-transaction blocks the claim constructor is fail-closed unless a
canonical `BlockProof` is present. For coinbase-only blocks it is fail-closed
if proof or authorization-sidecar bytes are present. The claim records witness
byte lengths for resource accounting, but does not hash `BlockProof` or
`BlockAuthSidecar` bytes. Those detached witnesses are verified by the full
accepted-block batch relation before the claim is reconstructed. Detached
checkpoint/package checksums are transport corruption checks only and are not
recursive authority.

This local cache object is not itself the O(1) public authority and is not
accepted from arbitrary peers as a trustless proof. It is stored under a
separate local-cache storage key and is not deserialized as `HistoryProof`.
Public snapshot sync still requires an in-proof verification of the full
`AcceptBlock` predicate listed above.

The local cache is not gossiped. The P2P `HistoryProof` request-response method
is retained only as the public transport endpoint and returns no proof until
the accepted-block recursive verifier is active.

### Accepted-Claim Batch Relation

The native specification boundary for checkpoint batching is:

```text
VerifyAcceptedClaimBatchNative(
    start_recursive_consensus_state,
    start_chain_accumulator,
    header_witnesses[0..k),
    accepted_block_claims[0..k)
) -> (end_recursive_consensus_state, end_chain_accumulator)
```

It is valid only if:

- the batch is non-empty;
- each header witness verifies the exact Poseidon2b `POWHDR__` digest,
  strict target comparison, Poseidon2b `BLOCKHDR` id, parent link, MTP, ASERT,
  chainwork, and log-slot expansion relation;
- there is exactly one accepted-block claim per header;
- the start accumulator height and state root equal the start recursive
  consensus state;
- the output accumulator is obtained by folding each
  `(block_id_i, accepted_block_claim_i, state_root_i, height_i)` in order.

The optimized recursive implementation may replace this native verifier, but
must prove the same relation. A batch proof that only checks headers, or only
checks accepted claims, is insufficient.

The current production decomposition has an explicit split boundary:

```text
HeaderHashProofKillShot:
    proves pow_digest_i and block_id_i from the canonical 16-field header
    schedule under the `POWHDR__` and `BLOCKHDR` Poseidon2b domains.

HeaderIntegerTrace:
    consumes the same header witnesses and proves the non-hash consensus
    semantics exactly.
```

`HeaderIntegerTrace` does not recompute Poseidon2b. It is valid only when
paired with `HeaderHashProofKillShot` over the same header witnesses. It checks:

- the header field schedule equals `pow_header_fields(header)`;
- the target field equals `header.difficulty_target`;
- parent linkage and height increment from the rolling recursive state;
- exact ASERT target from the rolling epoch anchor;
- exact median-time-past using the rolling timestamp window;
- strict little-endian `pow_digest < difficulty_target`, with equality
  rejected;
- exact `expected_child_log_slots` from the 18-block active-count window;
- exact block work and cumulative chainwork addition;
- exact epoch-anchor rollover;
- state advancement to the supplied `block_id`, `state_root`,
  `active_slot_count`, and `alloc_counter`.

The accepted-claim split verifier advances the chain accumulator only after
`HeaderIntegerTrace` accepts and the accumulator start height/state root match
the rolling recursive consensus state. This closes the earlier weak boundary
where independent hash and integer components could otherwise be connected by
host-level equality rather than an explicit relation. The component-level tests
include a positive split-batch roundtrip and rejection of `pow_digest == target`.

### Chain-Accumulator KillShot Relation

The recursive history accumulator is Poseidon2b-only:

```text
inner_i = COMPRESS(block_id_i, accepted_block_claim_i)
acc_i   = COMPRESS(acc_{i-1}, inner_i)
```

where `accepted_block_claim_i` is the full 32-byte Poseidon2b `ACCBLK__`
digest encoded as two little-endian `Block128` lanes before `COMPRESS`. The
production KillShot component for this subrelation proves:

```text
ChainAccumulatorBatch(
    start_acc,
    ordered (block_id_i, accepted_block_claim_i)[0..k),
    end_acc
) = true
```

It binds:

- the batch length;
- the `COMPRESS` domain;
- the starting accumulator digest;
- every ordered block id and accepted-block claim;
- the final accumulator digest;
- every intermediate inner digest and rolling accumulator transition through
  the same Poseidon2b permutation relation and linear chain constraints.

Soundness theorem for this component:

```text
VerifyChainAccumulatorKillShot(P, start_acc, items, end_acc) = true
    => end_acc is exactly the result of applying the accumulator transition
       to `items` in order from `start_acc`,
       except with probability bounded by the KillShot sumcheck/batch-eval
       soundness error and Poseidon2b collision resistance.
```

This relation is necessary but not sufficient for public O(1) history
authority. The accepted claims fed into it must still be reconstructed only
after full `AcceptBlock` verification inside the same checkpoint/history proof.

### Header-Hash KillShot Relation

The consensus header has one canonical 16-field schedule. The recursive
header-hash component proves both hash domains from that same schedule:

```text
pow_digest_i = Poseidon2b(POWHDR__, fields_i[0..16]) no-pad
block_id_i   = Poseidon2b(BLOCKHDR, fields_i[0..16]) padded
```

The component binds:

- the ordered 16-field header schedule;
- the `POWHDR__` and `BLOCKHDR` domains;
- the no-pad PoW squeeze after exactly eight rate blocks;
- the padded semantic block-id squeeze after the extra padding block;
- the claimed `pow_digest` and `block_id` outputs.

Soundness theorem for this component:

```text
VerifyHeaderHashKillShot(P, fields, pow_digest, block_id) = true
    => each accepted output is exactly the Poseidon2b digest of the same
       canonical header field schedule under its declared domain,
       except with probability bounded by KillShot sumcheck/batch-eval
       soundness and Poseidon2b collision resistance.
```

This component proves only the hash computations. Header-work authority also
requires exact strict target comparison, MTP, ASERT, chainwork, parent linkage,
and log-slot expansion semantics from the same header witness.

The production header validator has no monotone-only `log_slots` acceptance
path. The child value must equal:

```text
expected_child_log_slots(parent.log_slots, parent.active_slot_count,
                         previous_active_counts_window)
```

where the active-count window is the deterministic oldest-first consensus
window ending at the parent. The same helper is used by live block checks,
miner template construction, network header precheck, and the native
checkpoint-relation boundary. A recursive implementation must prove this exact
predicate.

### Multi-Column Batch-Evaluation Binding

Poseidon2b-heavy KillShot components may discharge several committed MLE
columns through one multi-column batch-evaluation sumcheck:

```text
columns: B_0, ..., B_{m-1}
claims_j: (r_{j,k}, v_{j,k})

V = Σ_j Σ_k α_{j,k} · v_{j,k}
W_j(x) = Σ_k α_{j,k} · eq(r_{j,k}, x)

prove V = Σ_x Σ_j W_j(x) · B_j(x)
```

The transcript absorbs the ordered column index, claim count, every claim point,
and every claim value before sampling the `α_{j,k}` coefficients. The sumcheck
returns one shared terminal point `r_B` and one terminal value per column:

```text
v_j = B_j(r_B)
```

The verifier recomputes each `W_j(r_B)` and checks:

```text
final_claim = Σ_j W_j(r_B) · v_j
```

Every returned `(r_B, v_j)` must still be discharged against the corresponding
committed column. Therefore replacing three independent terminal proofs
(`state`, `s_in`, `s_out`) with one multi-column proof does not remove any
column binding condition; it only shares the terminal point and transcript.

The current component verifiers enforce this by native reconstruction of the
canonical MLE from the public component statement and by checking:

```text
evaluate(canonical_column_j, r_B) == v_j
```

for every returned terminal column. This native discharge is not public O(1)
authority by itself; it is the exact relation that `HistoryProof` must replace
with an in-proof PCS or recursive discharge before trustless snapshot sync can
be enabled. Ignoring terminal reductions, accepting only a sumcheck transcript,
or trusting host-supplied terminal values is forbidden.

### Merkle Path Boundary Binding

A Poseidon2b Merkle path proof is valid only if public path values are bound to
the committed permutation trace, not merely absorbed into the transcript.

The batched production proof proves chain continuity by a public linear
relation over the committed `state` column. For every active level:

```text
PermA(level).state[0]
    = MDS(leaf, TAG_COMPRESS)                         when level = 0
    = MDS(PermB(level-1).state_out[0..2], TAG_COMPRESS) otherwise

PermB(level).state[0]
    = MDS(PermA(level).state_out + sibling[level])

PermB(active_depth-1).state_out[0..2]
    = expected_root
```

The relation is reduced by `LinearEvalProof`:

```text
for every public linear equation i:
    L_i(state) == value_i

sample α_i from Fiat-Shamir
prove Σ_i α_i · L_i(state) == Σ_i α_i · value_i
```

This sumcheck outputs one terminal `state(r)` claim. That terminal claim is then
included in the shared multi-column terminal proof, so it is bound to the same
committed `state` MLE as the Poseidon2b permutation trace.

The constraint set is deterministic from the already absorbed public Merkle
statement:

```text
path_count, every leaf, every sibling, every expected root, every depth,
live_slots, dynamic variable count
```

The linear-chain proof therefore uses a dedicated prebound relation tag and
shape binding rather than serializing every Boolean term. This is sound because
the verifier reconstructs the exact same constraint set from the public
statement before checking the proof; no prover-supplied boundary values are
trusted.

The prover may optimize W-table construction for terms at Boolean
hypercube vertices. This is a prover-only acceleration:

```text
eq(b, x) over x in {0,1}^n is 1 exactly at x = b and 0 elsewhere.
```

Therefore a Boolean term contributes one field element to the dense `W` table.
Non-Boolean terms continue through the general equality-table path, and the
verifier still checks the same linear sumcheck relation.

The multi-column terminal transcript uses a canonical compact encoding for the
same Boolean terminal claim points:

```text
Boolean point:
    BOOL_TAG || dimension || hypercube_index || claimed_value

Dense point:
    DENSE_TAG || dimension || point[0] || ... || point[dimension-1]
              || claimed_value
```

`BOOL_TAG` and `DENSE_TAG` are disjoint. A Boolean point is compact-encoded
only when every coordinate is exactly `0` or `1`; otherwise the dense encoding
is mandatory. This keeps Fiat-Shamir binding injective while avoiding linear
coordinate serialization for terminal claims at hypercube vertices.

The following are forbidden in the public O(1) authority path:

- marker or stub proofs for user-transaction blocks;
- special digest values that stand in for a proof object;
- native host acceptance as a substitute for an in-proof relation;
- detached witness byte hashes as semantic block identity;
- non-consensus BLAKE3 checksums as recursive authority;
- local history-cache accumulators as public snapshot authority;
- pruning before finalized checkpoint proof coverage.

Coinbase-only blocks carry no block proof and zero detached witness metadata.
User-transaction blocks are accepted only with non-empty `BlockProof` bytes that
verify against the canonical block statement. No header field value can upgrade
an absent proof into a valid proof.

### HistoryProof Activation Gate

Public O(1) snapshot sync can be enabled only for a `HistoryProof` verifier
whose accepted language is exactly the timeless accepted-block batch relation:

```text
exists retained semantic blocks and detached validation witnesses:
    VerifyFullAcceptedBlockBatchNative(start, witness) = end
```

with native verification replaced by in-proof relations, not by host cache
markers. In particular, the verifier must prove all of the following inside the
accepted language:

- canonical semantic-header field schedule;
- Poseidon2b `POWHDR__` digest and strict `< target` comparison;
- Poseidon2b `BLOCKHDR` id and parent linkage;
- exact MTP, ASERT, chainwork, finalized-prefix, and log-slot expansion
  integer semantics;
- canonical transaction root and shape-specific transaction-body hash
  relation;
- one ordered authorization proof per non-coinbase transaction, verified
  against the canonical statement;
- exact sparse-Merkle UTXO update and ReuseGuard transition;
- accepted-block claim reconstruction only after full block validation;
- chain-accumulator update over the same ordered block ids and accepted claims;
- previous recursive proof verification and exact start/end state continuity.

The current native terminal-discharge helpers for KillShot components are
allowed only as local verification of component witnesses while the final
recursive composition is being implemented. They are not a public authority
interface. A `HistoryProof` that proves only header work, only the chain
accumulator, only component markers, or only cached terminal values is outside
the production consensus language and must be rejected.

### Retained Full-Batch Proof Boundary

The retained full-batch proof API accepts retained semantic block bodies,
detached block proofs, detached authorization sidecars, the start parent, and
the start state. It first replays the timeless `AcceptBlock` predicate and only
then derives component statements from the accepted replay. The caller cannot
provide arbitrary component statements as authority.

Soundness of the retained proof is therefore:

```text
VerifyRetainedFullAcceptedBlockBatch(
    start_parent,
    start_state,
    retained_blocks_and_witnesses,
    retained_batch_proof
) = accept

=> AcceptBlockBatchNative(start, retained_blocks_and_witnesses) = end
   and every derived component proof verifies against that accepted replay,
   except with the stated authorization, KillShot/GKR, PCS, Poseidon2b, and
   integer-relation failure probabilities.
```

This API is useful for retained history packaging and local verification while
the recursive composition is being completed. It is not the public O(1)
snapshot authority because the retained block bodies and detached witnesses are
still inputs to the verifier. Public O(1) requires `HistoryProof` to prove the
same accepted-block batch relation without trusting locally retained bytes or
host-level component reconstruction.

The retained component proof object does not duplicate authorization sidecar
proof bytes. Authorization proofs are part of the retained validation witness
and are verified against the statements derived by accepted-block replay. This
prevents a component-proof byte string from being confused with a compressed
public history proof.

The retained authorization verifier boundary is:

```text
VerifyAuthorizationBatchNative(
    canonical_statement_i[],
    retained_wallet_auth_proof_i[],
    expected_authorization_totals
)
```

It checks every retained wallet authorization proof against its derived
statement, then recomputes `user_tx_count`, `owner_count_total`, and
`live_input_count_total`. A batch with valid proof bytes but mismatched totals
is rejected. The future public `HistoryProof` must prove this verifier relation
inside the accepted-block batch relation; it must not replace it with a proof
digest, cache marker, or precomputed acceptance flag.

### Authorization Aggregation Boundary

Block-level authorization aggregation must not re-prove ownership from spend
secrets. Miners and validators do not know spend secrets, and requiring them
would either leak wallet witnesses or change the ownership model. Therefore the
safe public O(1) design is:

```text
wallet:
    proves VerifyAuthorization(statement_i, proof_i)
    without revealing spend_secret_i

block HistoryProof prover:
    uses retained proof_i bytes as private validation witness
    proves the verifier relation VerifyAuthorization(statement_i, proof_i)
    inside the accepted-block batch relation

public verifier:
    checks only HistoryProof public state/accumulator output
```

The forbidden alternative is:

```text
miner aggregates transactions by constructing a new proof from spend secrets
```

because the miner does not possess those secrets and must never receive them.
Any authorization proof-size reduction must preserve this split. It may
optimize wallet proof format, recursively verify wallet proofs, or batch
verifier equations, but it may not move private owner witnesses from wallets to
block producers.

### Authorization Verifier Proof Component

The production `HistoryProof` authorization component must prove the verifier
relation for retained wallet authorization proofs. Its private witness is the
ordered sidecar proof list; its public inputs are only the statements derived
inside the accepted-block batch relation and the expected aggregate counts.

The canonical statement type is part of the authorization proof layer, not a
separate block-specific language. The block validator derives ordered
statements from transaction bodies and sidecar order, then calls the same
`VerifyAuthorization(statement, proof)` boundary that the recursive history
relation must prove.

The recursive crate exposes the same boundary as a native batch relation over
ordered semantic block transactions and retained wallet authorization proofs.
That native function is a specification/test oracle only; public O(1) sync
remains disabled until `HistoryProof` proves the verifier relation inside the
proof.

The native boundary also emits an ordered verifier transcript trace for each
accepted authorization proof. The trace is produced by running the production
`VerifyAuthorization` function over a tracing Poseidon2b Fiat-Shamir channel;
there is no second verifier implementation. This trace is not accepted as
authority. It fixes the exact sequence of absorbed field elements and squeezed
challenges that the recursive authorization component must prove.

For every non-coinbase transaction `i`, the component must prove:

```text
VerifyAuthorization(statement_i, wallet_auth_proof_i) = accept
```

with all verifier subrelations linked to the same canonical statement and proof
object:

- absorb the complete canonical authorization statement before the first
  challenge;
- absorb the arithmetic Poseidon2b PCS commitment before GKR challenges;
- verify the OwnerAuth main, shift, boundary, and batch-eval sumchecks with the
  exact Fiat-Shamir transcript;
- verify the arithmetic mixed-opening PCS, including compact FRI and
  source-binding Merkle/cap checks, against the same commitment;
- enforce that the returned opening value equals the reduced batch-eval claim;
- recompute and bind `owner_count_total` and `live_input_count_total` from the
  same verified statements.

The first recursive authorization subclaim is therefore:

```text
TraceAuthorizationVerifier(statement_i, wallet_auth_proof_i) = transcript_i
```

where the first challenge in `transcript_i` appears only after the complete
canonical statement and the arithmetic PCS commitment have been absorbed. Any
split between the transaction-body hash inside the statement and the hash
inside the OwnerAuth public input is rejected before a trace can be accepted as
well-formed input to the recursive component.

The implemented Fiat-Shamir transcript component proves this subclaim for bounded
ordered trace batches by reconstructing the production `Poseidon2bChannel` state
machine independently for each trace:

- two field absorbs fill one rate block and trigger one Poseidon2b
  permutation;
- a squeeze with one buffered field first applies the canonical sponge padding
  field and triggers one permutation;
- the first squeeze from a ready state outputs lane 0, buffers lane 1, and
  advances the sponge by one permutation;
- a second consecutive squeeze consumes the buffered lane without another
  permutation;
- any absorb invalidates the buffered lane exactly as the production channel
  does.

The transcript proof uses the same BlockSpine KillShot permutation language as
the other Poseidon2b-heavy recursive components. Its public traces are not
standalone authorization proofs: the final `HistoryProof` must still prove the
OwnerAuth verifier algebraic checks that consume the transcript challenges.

No transcript proof batch may exceed 16 authorization traces, 2048 operations
per trace, or 8192 Poseidon2b permutations. Larger accepted blocks are proved
as independent transcript chunks. This is a production resource invariant: it
prevents one maximum block from becoming one giant multilinear table while
preserving the exact per-trace Fiat-Shamir language above.

The authorization verifier boundary also exposes the exact terminal claims that
the verifier derives from the accepted OwnerAuth proof: main GKR reduction, shift
reduction, boundary reduction, the three state-column claims consumed by
batch-eval, and the final PCS opening reduction. A future recursive arithmetic
component must prove these field equations directly; it may not replace them
with a host-provided boolean or digest of native verifier success.

The component may optimize by batching verifier arithmetic, grouping equal
layouts, or proving many Poseidon2b transcript/Merkle/hash evaluations through
KillShot/FROST-style relations. These optimizations are valid only if they keep
the exact verifier language above.

The following are explicitly outside the consensus language:

- proving only a digest of a wallet authorization proof;
- trusting mempool/miner acceptance of the wallet proof;
- using a separate statement for PCS verification and GKR verification;
- replacing the arithmetic source-bound PCS with an unbound FRI oracle;
- exposing spend secrets to the block producer so the producer can re-prove
  authorization from secrets.

## 7. Mining Optimization Invariant

The miner may compute many nonce candidates in parallel or through packed
Poseidon2b lanes. This is an implementation optimization only.

For every nonce `n`:

```text
packed_batch_digest(fields, n) == poseidon_pow_digest_from_fields(fields[n])
```

Consensus validation still recomputes the scalar canonical digest from the
submitted header and rejects the block if the digest does not satisfy the
target.

## 8. Assumptions

### A1. Poseidon2b Permutation and Sponge Security

Poseidon2b with the configured field, state width, round constants, MDS
matrices, round counts, capacity IV derivation, and fixed-length sponge mode is
modeled as providing 128-bit collision and target-preimage security for the
domain-separated consensus uses in this repository.

For PoW specifically, the fixed-prefix variable-nonce search is assumed to have
no shortcut materially better than random trial:

```text
Pr[Poseidon2b(POWHDR__, fixed_prefix || nonce) < target]
    = target / 2^256
```

up to the stated 128-bit primitive security target.

### A2. Domain Separation

All Poseidon2b capacity IV tags used by consensus are distinct. In particular:

```text
POWHDR__ != BLOCKHDR
```

### A3. Fiat-Shamir Random Oracle

Poseidon2b Fiat-Shamir channels are modeled as random-oracle challenges after
complete absorb-before-squeeze binding of the canonical statement.

### A4. Sparse-Merkle Binding

Sparse-Merkle roots using the configured Poseidon2b node/leaf domains are
collision resistant at the 128-bit target.

### A5. Exact Integer Semantics

ASERT target arithmetic, median-time-past, target comparison, and chainwork use
the implemented Rust integer semantics exactly. Recursive implementations must
prove the same integer relation, not an approximation.

### A6. Authorization Knowledge Soundness

`OwnerAuthProofKillShot` is treated as a knowledge-sound non-interactive
argument for the canonical authorization statement in the random-oracle model.
The extractor is the standard Fiat-Shamir/forking extractor for the sumcheck
IOPs plus the source-bound arithmetic PCS extractor for the committed private
state MLE.

The extracted MLE is tied to the proof because the PCS commitment is absorbed
before the first authorization challenge. The boundary constraints recover the
round-zero preimage lanes with `MDS_FULL^{-1}`, and the transition constraints
prove that those lanes hash to the public owner address under `TAG_ADDRFIX`.
Thus any accepted proof yields spend secrets for all claimed unique owners,
except with the stated authorization proof error and hash/PCS binding failures.

### A7. Arithmetic PCS and FRI Source Binding

The arithmetic FRI-Binius PCS binds every opened field value to the committed
source matrix under the Poseidon2b source root, folded roots, and Fiat-Shamir
challenges. A proof using a byte-native or BLAKE3 source commitment is outside
the consensus language and is rejected by construction.

## 9. Tests and Evidence

The release test suite covers the current invariants with:

- fixed Poseidon2b PoW field schedule and nonce index;
- `POWHDR__` vs `BLOCKHDR` domain separation;
- physical removal of obsolete header witness fields: block headers are 212
  semantic bytes and detached witnesses live outside the header;
- no marker/stub proof path: coinbase-only blocks have no proof, and
  user-transaction blocks require detached `BlockProof` bytes;
- production `BlockProof` metadata has no reserved bucket/AIR fields; removed
  fields cannot be set to re-enable old proof paths;
- accepted-block claim binding to semantic header, parent/context windows,
  and resource-count inputs; it does not hash detached proof or sidecar bytes;
- consensus PCS and FRI source commitments use the arithmetic Poseidon2b
  backend only; the removed BLAKE3 commitment backend is not a selectable
  consensus verifier mode;
- the retired transaction AIR crate is not part of the production workspace;
  transaction-body statements are derived by canonical native/GKR statement
  builders and checked against the same Poseidon2b tx-body hash;
- accepted-claim batch relation rejects claim/header count mismatch and bad
  parent linkage, and folds claims in exact header order;
- full accepted-block batch native relation re-verifies timeless `AcceptBlock`
  before reconstructing accepted claims, including coinbase-only blocks with no
  detached proof;
- invalid detached witness bytes for a semantic block do not mark that block id
  as permanently invalid; the same semantic block can still be accepted later
  with the correct detached witness;
- directed Merkle path expansion from canonical exact-state multiproofs,
  including non-zero direction bits and proof-level `EXSTNOD_`/`RGDNODE`
  KillShot verification;
- `EXSTSLT_` slot-leaf, `RGDBUCK_` guard-bucket, and `EXSTROT_`
  composite-root KillShot proof components;
- live node admission keeps the local future-drift timestamp policy outside the
  timeless recursive history predicate;
- the obsolete local recursive STARK step is removed from production crates;
  stored coverage is a small accumulator only, and peer-provided coverage bytes
  are ignored for snapshot authority;
- strict `< target` comparison and zero-target rejection;
- packed nonce-batch digest equivalence with scalar digest;
- genesis nonce satisfying `GENESIS_TARGET = 2^237`;
- exact chainwork for the genesis target and snapshot work floor;
- ReuseGuard active boundary, ring wrap, and root reconstruction;
- atomic state application and crash/restart persistence;
- finalized-prefix fork-choice restriction;
- disabled public snapshot authority without a recursive accepted-block proof.

The mining benchmark records the production batched Poseidon2b nonce-search
path and prints the active packed lane count.
