// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Emit release pins for one canonical `HistoryStep` v1 pack.
//!
//! Usage: `noid_pack_pins <pack-root>`

use noid_miner::history_step_artifacts::{
    decode_history_step_runtime_metadata_pinned, history_step_matrix_file_name,
    HISTORY_STEP_PACK_LEAF_COUNT, HISTORY_STEP_PACK_LEAF_HASH_DOMAIN,
    HISTORY_STEP_PACK_VERSION_DIRECTORY, HISTORY_STEP_RUNTIME_METADATA_FILE,
    HISTORY_STEP_RUNTIME_METADATA_MAX_BYTES,
};
use noid_poseidon2b::native::poseidon2b_hash_byte_slices;
use noid_recursive::acceptance::history_step_bank::CanonicalHistoryStepClassId;

fn main() {
    let root = std::env::args()
        .nth(1)
        .expect("usage: noid_pack_pins <pack-root>");
    let root = std::path::Path::new(&root);
    let version = root.join(HISTORY_STEP_PACK_VERSION_DIRECTORY);

    let metadata_path = version.join(HISTORY_STEP_RUNTIME_METADATA_FILE);
    let metadata_file = std::fs::metadata(&metadata_path)
        .unwrap_or_else(|error| panic!("inspect {}: {error}", metadata_path.display()));
    assert!(
        metadata_file.is_file()
            && metadata_file.len() <= HISTORY_STEP_RUNTIME_METADATA_MAX_BYTES as u64,
        "runtime metadata is not a bounded regular file"
    );
    let metadata = std::fs::read(&metadata_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", metadata_path.display()));
    let metadata_digest: [u8; 32] = metadata[metadata.len() - 32..]
        .try_into()
        .expect("fixed metadata trailer");
    decode_history_step_runtime_metadata_pinned(&metadata, metadata_digest)
        .expect("canonical HistoryStep runtime metadata");
    println!(
        "{}  {}",
        hex::encode(metadata_digest),
        metadata_path
            .file_name()
            .expect("metadata file name")
            .to_string_lossy()
    );

    let mut leaf_pins = String::with_capacity(HISTORY_STEP_PACK_LEAF_COUNT * 64);
    for index in 0..HISTORY_STEP_PACK_LEAF_COUNT {
        let class = CanonicalHistoryStepClassId::from_index(index).expect("canonical class");
        let leaf_path = version.join(history_step_matrix_file_name(class));
        let bytes = std::fs::read(&leaf_path)
            .unwrap_or_else(|error| panic!("read {}: {error}", leaf_path.display()));
        let digest = poseidon2b_hash_byte_slices(HISTORY_STEP_PACK_LEAF_HASH_DOMAIN, &[&bytes]);
        let encoded = hex::encode(digest);
        println!(
            "{encoded}  {}  ({:.1} MiB)",
            leaf_path
                .file_name()
                .expect("matrix file name")
                .to_string_lossy(),
            bytes.len() as f64 / (1024.0 * 1024.0)
        );
        leaf_pins.push_str(&encoded);
    }

    println!(
        "\nNOID_HISTORY_STEP_RUNTIME_METADATA_RELEASE_DIGEST={}",
        hex::encode(metadata_digest)
    );
    println!("NOID_HISTORY_STEP_PACK_LEAF_DIGESTS={leaf_pins}");
}
