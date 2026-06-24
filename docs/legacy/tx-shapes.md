# Transaction shapes

Paranoid transactions are fixed-shape proof objects. Every transaction carries an explicit `TxShape` so wallets, mempools, miners, block provers, verifiers, and recursive replay all dispatch to the same circuit shape.

The production block format is singular: shape-specific transaction buckets plus common NativeDelta state openings for the whole user-transaction block, with public Auth proofs carried in a header-bound `BlockAuthSidecar`.

## Current production status

`Standard4x8` is the default payment shape and is supported end-to-end by wallet proving, mempool admission, miner selection, block proving/verification, recursive replay, P2P/RPC submission, and live node application.

`Sweep25x2` is the large-input payment/consolidation shape and is also supported end-to-end: wallet proof generation, mempool admission, miner selection, bucketized block inclusion, mixed Standard/Sweep blocks, recursive replay, restart, reorg, and external template/submit flows.

Live validation covers Standard-only, Sweep-only, and mixed Standard/Sweep blocks on release nodes.

## Shapes

| Shape | ID | Max inputs | Max outputs | Status | Use case |
|---|---:|---:|---:|---|---|
| `Standard4x8` | `0` | 4 | 8 | production | default wallet payments, fanout, mobile-fast proofs |
| `Sweep25x2` | `1` | 25 | 2 | production | fragmented payments, sweeps, consolidation |

## Wallet policy

Wallet sending chooses:

1. `Standard4x8` when the payment fits in at most 4 inputs.
2. `Sweep25x2` when the payment needs 5–25 inputs and at most 2 outputs (`recipient + change`).
3. Multiple chunks when the payment needs more than 25 inputs.

The user-facing command remains one logical payment:

```text
noid-cli send noid1... 1000
```

The wallet decides whether that logical payment is one standard transaction, one sweep transaction, or several chunks.

## Fee policy

Fees are deterministic and output-centric:

```text
required_fee = base
             + input_fee  * live_inputs
             + output_fee * live_outputs
             + state_growth_fee(active occupancy) * max(0, live_outputs - live_inputs)
```

Current constants:

| Component | Value |
|---|---:|
| `MIN_FEE_BASE` | 5,000 μNOID |
| `FEE_PER_INPUT` | 100 μNOID |
| `FEE_PER_OUTPUT` | 700 μNOID |
| `STATE_GROWTH_FEE_BASE` | 2,500 μNOID per net-new slot at low occupancy |

The state-growth component is burned. Miners may claim `fee - burned`, including any user tip above the minimum.

There is no shape premium for `Sweep25x2`. A sweep pays for actual live inputs and outputs only. This keeps consolidation and fragmented-wallet cleanup cheap when they reduce live slot count, while the small input fee and mempool resource-weight ordering keep large-input spam from being free.

`walletSend` computes automatic fees per actual planned chunk. Split sends report per-chunk fee and total fee. `walletConsolidate` computes its fee from the selected consolidation input count and one output.

## Sweep25x2 tx-body layout

`Sweep25x2` uses a distinct 32-leaf tx-body hash layout. It does not reuse the `Standard4x8` 16-leaf layout.

```text
L0          epoch_anchor
L1          fee
L2          shape_leaf(Sweep25x2)
L3..L27     input_leaves[0..25]
L28..L29    output_leaves[0..2]
L30         is_coinbase
L31         reserved/pad
```

The shape leaf is consensus-critical: a proof for `Standard4x8` cannot be replayed as `Sweep25x2`, and a sweep proof cannot be accepted in a standard bucket.

Implemented crypto pieces:

- shape-aware tx-body hash dispatch;
- sweep balance AIR;
- AuthGKR over `25 × 5 = 125` auth permutation slots;
- tx-body spine over the 32-leaf layout;
- shape-specific wallet proof bundle and mempool verifier dispatch.

Implemented block/recursive pieces:

- block proof bucket dispatch by `TxShape` for standard, sweep-only, and mixed Standard/Sweep blocks;
- real sweep bucket aggregation transcript: per-bucket commitment, per-tx algebraic STARKs, bucket multipoint sumcheck, column-axis terminal compression, and source-bound mixed FRI opening;
- common NativeDelta state binding: verifier-reconstructed state claims plus pre/post segment MLE openings;
- public `BlockAuthSidecar` binding through `header.witness_root`;
- recursive replay witness extraction for standard-only, sweep-only, and mixed blocks, with separate primary/secondary bucket lanes for mixed replay.

## Canonical BlockProof format

The production-valid `BlockProof` surface is bucketized:

```rust
pub struct BlockProof {
    pub meta: BlockPublicMeta,
    pub standard_bucket: Option<StandardBucketProof>,
    pub sweep_bucket: Option<SweepBucketProof>,
    pub pre_state_openings: Vec<SegmentMleOpening>,
    pub post_state_openings: Vec<SegmentMleOpening>,
}

pub struct BlockAuthSidecar {
    pub tx_auth: Vec<BlockTxAuthProof>,
}
```

The optional bucket fields mean “bucket absent because this shape has no transactions in this block”. They do not mean “optional validation”. For every non-coinbase transaction in the block, exactly one matching shape bucket must be present and valid. For every dirty state segment in a user-transaction block, matching pre/post `SegmentMleOpening`s are mandatory. The public Auth sidecar has one entry per non-coinbase transaction in canonical block order and is bound by `header.witness_root`.

Standard-only blocks are represented as:

```text
standard_bucket      = Some(...)
sweep_bucket         = None
pre_state_openings   = one per dirty segment
post_state_openings  = one per dirty segment
BlockAuthSidecar     = one Standard auth proof per non-coinbase tx
```

Sweep-only blocks are represented as:

```text
standard_bucket      = None
sweep_bucket         = Some(...)
pre_state_openings   = one per dirty segment
post_state_openings  = one per dirty segment
BlockAuthSidecar     = one Sweep auth proof per non-coinbase tx
```

Mixed blocks have both buckets present, one common NativeDelta state-binding surface, and one block-order Auth sidecar containing Standard and Sweep entries.

Coinbase-only blocks are the only no-user-proof exception: there are no user slot claims to bind, so they use empty proof/sidecar bytes, the canonical stub proof marker/header binding, cheap consensus checks, and deterministic coinbase `apply_state_delta`.

## Bucket public format

Each bucket serializes enough metadata for independent verification:

- `shape: TxShape` or a bucket type that implies the shape;
- `tx_indices: Vec<u32>` in canonical block transaction order;
- `tx_pis: Vec<PublicInputs>` for the bucket's non-coinbase transactions;
- shape-specific proof artifacts;
- shape-specific metadata such as AIR column count, boundary slice count, log rows, and committed column count;
- transcript/commitment summary needed by recursive replay.

`tx_indices` are block transaction indices, not indices within the filtered non-coinbase list. Coinbase transactions must not appear in a shape bucket.

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

## Verification rules

The verifier derives expected coverage from the actual block transactions and rejects:

- missing non-coinbase tx indices;
- duplicate tx indices across buckets;
- out-of-range tx indices;
- coinbase txs inside a shape bucket;
- a bucket whose shape does not match every indexed transaction body;
- `PublicInputs.shape_id` mismatches;
- `PublicInputs.tx_body_hash` mismatches;
- swapped standard/sweep buckets;
- bucket order or index tampering;
- missing or mismatched pre/post `SegmentMleOpening`s for dirty state segments;
- missing or mismatched public Auth sidecar entries.

## State-binding rule

State binding is common across the full block:

```text
standard bucket proves standard tx logic
sweep bucket proves sweep tx logic
NativeDelta reconstructs all spend/mint claims together from the canonical block body
pre/post segment MLE openings bind the delta to prev_state_root and new_state_root
```

Do not split state binding per bucket. The common NativeDelta state surface prevents cross-shape double spends and keeps one canonical state transition for the whole block.

## Design rationale

A single large payment circuit would make every ordinary small payment pay the large proof cost. Shape variants preserve fast standard payments while still allowing fragmented-wallet sends without manual pre-consolidation.

Bucketized block proofs preserve that performance model at block level: standard-only blocks keep the standard proof shape, while sweep cost is paid only by blocks that actually include sweep transactions.
