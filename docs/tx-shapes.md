# Transaction shapes

Paranoid transactions are fixed-shape proof objects. A transaction carries an explicit `TxShape` so wallets, mempools, block provers, and verifiers can dispatch to the right proof circuit without forcing every small payment to pay for the largest shape.

## Current milestone

`Standard4x8` has the full wallet, mempool, and block-inclusion path.

`Sweep25x2` has wallet proof generation, mempool admission, miner selection, bucketized block inclusion, and recursive replay support. The wallet can build a real sweep proof bundle, mempool verifies it by shape, malformed/wrong-shape sweep bundles are rejected, and block proofs carry a real sweep bucket aggregation transcript.

The remaining gaps are external miner/template hardening and continuing UX/observability polish, not basic block inclusion: restart and reorg paths are covered, and fee policy is now shape-aware without charging a separate `Sweep25x2` premium.

## Shapes

| Shape | ID | Max inputs | Max outputs | Status | Use case |
|---|---:|---:|---:|---|---|
| `Standard4x8` | `0` | 4 | 8 | wallet + mempool + block supported | default wallet payments, fanout, mobile-fast proofs |
| `Sweep25x2` | `1` | 25 | 2 | wallet + mempool + miner/block + recursive replay supported | large fragmented payments, sweeps, consolidation |

## Wallet policy target

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

The state-growth component is burned. Miners may claim `fee - burned`, including any user tip above the minimum.

There is no shape premium for `Sweep25x2`. A sweep pays for actual live inputs and outputs only. This keeps consolidation and fragmented-wallet cleanup cheap when they reduce live slot count, while the small input fee and mempool resource-weight ordering keep large-input spam from being free.

`walletSend` computes automatic fees per actual planned chunk. Split sends report per-chunk fee and total fee. `walletConsolidate` computes its fee from the selected consolidation input count and one output.

## Sweep25x2 implementation notes

`Sweep25x2` should not reuse the current 16-leaf tx-body hash layout. It needs a distinct 32-leaf layout, for example:

```text
L0          epoch_anchor
L1          fee
L2          shape_leaf(Sweep25x2)
L3..L27     input_leaves[0..25]
L28..L29    output_leaves[0..2]
L30         is_coinbase
L31         reserved/pad
```

Implemented crypto pieces:

- shape-aware tx-body hash dispatch;
- sweep balance AIR;
- AuthGKR over `25 × 5 = 125` auth permutation slots;
- tx-body spine over the 32-leaf layout;
- shape-specific wallet proof bundle and mempool verifier dispatch.

Implemented block/recursive pieces:

- block proof bucket dispatch by `TxShape` for standard, sweep-only, and mixed Standard/Sweep blocks;
- real sweep bucket aggregation transcript: per-bucket commitment, per-tx algebraic STARKs, bucket multipoint sumcheck, and one mixed FRI opening;
- recursive replay witness extraction for standard-only, sweep-only, and mixed blocks, with separate primary/secondary bucket lanes for mixed replay.

## Block proof bucket design lock

The selected design for block inclusion is **shape buckets**.

A block proof should contain one proof bucket per transaction shape present in the block. Each bucket proves tx logic for transactions of exactly one shape, while the block keeps one common state-binding proof over all spend/mint claims.

Conceptual layout:

```rust
pub struct BlockProof {
    pub meta: BlockPublicMeta,
    pub standard_bucket: Option<StandardBucketProof>,
    pub sweep_bucket: Option<SweepBucketProof>,
    pub state_binding: BlockStateBindingProof,
}
```

A generic enum form is also acceptable if future shapes are expected soon:

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

For the current two-shape rollout, explicit optional fields are preferred because they make serialization, verifier coverage checks, and tests easier to audit.

### Bucket public format

Each bucket must serialize enough metadata for independent verification:

- `shape: TxShape` or an enum variant that implies the shape;
- `tx_indices: Vec<u32>` in canonical block transaction order;
- `tx_pis: Vec<PublicInputs>` for the bucket's non-coinbase transactions;
- shape-specific proof artifacts;
- shape-specific metadata such as AIR column count, boundary slice count, log rows, and committed column count;
- a transcript or commitment summary if recursive proof integration needs compact binding.

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

### Verification rules

The verifier must derive expected coverage from the actual block transactions and reject:

- missing non-coinbase tx indices;
- duplicate tx indices across buckets;
- out-of-range tx indices;
- coinbase txs inside a shape bucket;
- a bucket whose shape does not match every indexed transaction body;
- `PublicInputs.shape_id` mismatches;
- `PublicInputs.tx_body_hash` mismatches;
- swapped standard/sweep buckets;
- bucket order or index tampering.

### State-binding rule

State binding remains common across the full block:

```text
standard bucket proves standard tx logic
sweep bucket proves sweep tx logic
common state binding proves all spend/mint claims together
```

Do not split state binding per bucket unless a separate composition proof is designed. The common state binding is what prevents cross-shape double spends and keeps one canonical state transition for the whole block.

### Proof-format decision

Use one target block proof format: bucketized `BlockProof`.

Standard-only blocks are represented as:

```text
standard_bucket = Some(...)
sweep_bucket    = None
```

Sweep-only blocks are represented as:

```text
standard_bucket = None
sweep_bucket    = Some(...)
```

Mixed blocks have both buckets present.

Because the network has not launched yet, the migration should move directly to the bucketized public format for every block, including standard-only blocks.

## Design rationale

A single global `MAX_INPUTS = 25` would make every ordinary small payment pay the large proof cost. Shape variants preserve fast standard payments while still allowing large fragmented sends without manual consolidation.

Bucketized block proofs preserve that performance model at block level: standard-only blocks keep the standard proof shape, while sweep cost is paid only by blocks that actually include sweep transactions.
