# Transaction shapes

Paranoid transactions are fixed-shape proof objects. Every transaction carries an explicit `TxShape` so wallets, mempools, miners, block provers, verifiers, and recursive replay all dispatch to the same circuit shape.

The production block format is singular: shape-specific transaction buckets plus one common `BlockStateBindingAir` proof for the whole user-transaction block.

## Current production status

`Standard4x8` is the default payment shape and is supported end-to-end by wallet proving, mempool admission, miner selection, block proving/verification, recursive replay, P2P/RPC submission, and live node application.

`Sweep25x2` is the large-input payment/consolidation shape and is also supported end-to-end: wallet proof generation, mempool admission, miner selection, bucketized block inclusion, mixed Standard/Sweep blocks, recursive replay, restart, reorg, and external template/submit flows.

Live validation has covered Standard-only, Sweep-only, and mixed Standard/Sweep blocks on real release nodes. The next phase is optimization and cap tuning, not a second production validation path.

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
- real sweep bucket aggregation transcript: per-bucket commitment, per-tx algebraic STARKs, bucket multipoint sumcheck, and mixed FRI opening;
- recursive replay witness extraction for standard-only, sweep-only, and mixed blocks, with separate primary/secondary bucket lanes for mixed replay.

## Canonical BlockProof format

The production block proof format is bucketized `BlockProof`:

```rust
pub struct BlockProof {
    pub meta: BlockPublicMeta,
    pub standard_bucket: Option<StandardBucketProof>,
    pub sweep_bucket: Option<SweepBucketProof>,
    pub state_binding: BlockStateBindingProof,
}
```

The optional fields mean “bucket absent because this shape has no transactions in this block”. They do not mean “optional validation”. For every non-coinbase transaction in the block, exactly one matching shape bucket must be present and valid. For every user-transaction block, `state_binding` is mandatory.

Standard-only blocks are represented as:

```text
standard_bucket = Some(...)
sweep_bucket    = None
state_binding   = present
```

Sweep-only blocks are represented as:

```text
standard_bucket = None
sweep_bucket    = Some(...)
state_binding   = present
```

Mixed blocks have both buckets present and one common state-binding proof.

Coinbase-only blocks are the only no-user-proof exception: there are no user slot claims to bind, so they use the canonical stub proof marker/header binding, cheap consensus checks, and deterministic coinbase `apply_state_delta`.

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
- missing `BlockStateBindingAir` on a user-transaction block.

## State-binding rule

State binding is common across the full block:

```text
standard bucket proves standard tx logic
sweep bucket proves sweep tx logic
common state binding proves all spend/mint claims together
```

Do not split state binding per bucket. The common state binding is what prevents cross-shape double spends and keeps one canonical state transition for the whole block.

## Design rationale

A single large payment circuit would make every ordinary small payment pay the large proof cost. Shape variants preserve fast standard payments while still allowing fragmented-wallet sends without manual pre-consolidation.

Bucketized block proofs preserve that performance model at block level: standard-only blocks keep the standard proof shape, while sweep cost is paid only by blocks that actually include sweep transactions.
