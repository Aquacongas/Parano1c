// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Release-pack pin emitter: hashes the nine compressed canonical matrix
//! leaves in canonical identity order (genesis T, Link B8/B32/B64/B255,
//! Block B8/B32/B64/B255) and prints the concatenated hex value expected in
//! `NOID_SELECTED_RECURSIVE_PACK_LEAF_DIGESTS` at node build time.
//!
//! Usage: `noid_pack_pins <artifact-root>`

use noid_miner::{
    selected_recursive_matrix_relative_path, SelectedRecursiveMatrixKind as Kind,
    SelectedRecursiveTier as Tier,
};

const PACK_LEAF_HASH_DOMAIN: &[u8] = b"NOID/SELECTED-RECURSIVE/PACK-LEAF";

fn main() {
    let root = std::env::args()
        .nth(1)
        .expect("usage: noid_pack_pins <artifact-root>");
    let kinds = [
        Kind::GenesisLink,
        Kind::PreviousLink(Tier::B8),
        Kind::PreviousLink(Tier::B32),
        Kind::PreviousLink(Tier::B64),
        Kind::PreviousLink(Tier::B255),
        Kind::CurrentBlock(Tier::B8),
        Kind::CurrentBlock(Tier::B32),
        Kind::CurrentBlock(Tier::B64),
        Kind::CurrentBlock(Tier::B255),
    ];
    let mut concatenated = String::new();
    for kind in kinds {
        let leaf = std::path::Path::new(&root)
            .join(selected_recursive_matrix_relative_path(kind))
            .with_extension("field-r1cs.zst");
        let bytes =
            std::fs::read(&leaf).unwrap_or_else(|error| panic!("read {}: {error}", leaf.display()));
        let digest =
            noid_poseidon2b::native::poseidon2b_hash_byte_slices(PACK_LEAF_HASH_DOMAIN, &[&bytes]);
        let encoded = hex::encode(digest);
        println!(
            "{encoded}  {}  ({:.1} MiB)",
            leaf.file_name().expect("leaf name").to_string_lossy(),
            bytes.len() as f64 / (1024.0 * 1024.0)
        );
        concatenated.push_str(&encoded);
    }
    println!("\nNOID_SELECTED_RECURSIVE_PACK_LEAF_DIGESTS={concatenated}");
}
