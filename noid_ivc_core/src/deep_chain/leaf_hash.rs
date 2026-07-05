//! Flat-basis replays of the wallet-capsule query-leaf hash schedules.
//!
//! Each FRI/source query opens a LEAF whose hash is a fixed chain of
//! `hash_pair`/`compress` over the queried symbols plus class-constant
//! metadata (domain tag, `log_rows`, `n_cols`, leaf index). The region layer
//! proves these chains with a deep-chain family (the item-3 clone of
//! `MerklePathFamily`); this module is the native flat-basis replay the
//! family and its gate are built against — the same single-basis convention
//! as [`super::source_tree`] (φ only at the symbol/digest boundary, every
//! interior lane a plain flat wire).

use crate::deep_chain::source_tree::{compress_iv_flat, flat_compress, flat_hash_pair};
use crate::deep_chain::schedule::flat_of_tower_u128;
use crate::field::F128;

/// Domain tag for encoded-source leaf hashes — the flat image of
/// `noid_fri_binius::interleaved_commit::SOURCE_LEAF_DOMAIN`. Kept in sync
/// with the native constant; a mismatch only yields honest-rejected proofs.
pub const SOURCE_LEAF_DOMAIN: u128 = 0xF21B_1D50_0000_0001u128;

/// Flat lane of a tower `u128` bit pattern (class-constant metadata and
/// queried symbols cross the region boundary through this linear map).
#[inline]
pub fn flat_lane(v: u128) -> F128 {
    flat_of_tower_u128(v)
}

/// Flat-basis replay of `source_leaf_hash(log_rows, n_cols, leaf_index,
/// symbols)`:
///
/// ```text
///   acc  = hash_pair(DOMAIN, log_rows)
///   meta = hash_pair(n_cols, leaf_index)
///   acc  = compress(acc, meta)
///   for k in 0..n_cols:  acc = compress(acc, hash_pair(sym[2k], sym[2k+1]))
/// ```
///
/// `symbols` are the `2·n_cols` queried codeword lanes already in the flat
/// basis. `log_rows`, `n_cols`, `leaf_index` are class/query metadata (their
/// flat images are formed here). Matches the native tower `source_leaf_hash`
/// under φ. Returns the leaf digest's two flat lanes.
pub fn flat_source_leaf_hash(
    log_rows: usize,
    n_cols: usize,
    leaf_index: usize,
    symbols: &[F128],
) -> [F128; 2] {
    assert_eq!(symbols.len(), n_cols * 2, "source leaf symbol count");
    let iv = compress_iv_flat();

    let acc = flat_hash_pair(flat_lane(SOURCE_LEAF_DOMAIN), flat_lane(log_rows as u128));
    let meta = flat_hash_pair(flat_lane(n_cols as u128), flat_lane(leaf_index as u128));
    let mut acc = flat_compress(iv, acc, meta);
    for k in 0..n_cols {
        let ph = flat_hash_pair(symbols[2 * k], symbols[2 * k + 1]);
        acc = flat_compress(iv, acc, ph);
    }
    acc
}
