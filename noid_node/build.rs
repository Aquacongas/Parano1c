// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Build-time authority for the canonical embedded `HistoryStep` v1 pack.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use noid_ivc_core::field_r1cs::CompactFieldR1cs;
use noid_ivc_core::proof::FieldShape;
use noid_miner::history_step_artifacts::{
    decode_history_step_runtime_metadata_pinned, history_step_matrix_file_name,
    HISTORY_STEP_PACK_LEAF_COUNT, HISTORY_STEP_PACK_LEAF_HASH_DOMAIN,
    HISTORY_STEP_PACK_VERSION_DIRECTORY, HISTORY_STEP_RUNTIME_METADATA_FILE,
    HISTORY_STEP_RUNTIME_METADATA_MAX_BYTES,
};
use noid_poseidon2b::native::poseidon2b_hash_byte_slices;
use noid_recursive::acceptance::history_step_bank::CanonicalHistoryStepClassId;

const PACK_DIRECTORY_ENV: &str = "NOID_HISTORY_STEP_PACK_DIR";
const METADATA_DIGEST_ENV: &str = "NOID_HISTORY_STEP_RUNTIME_METADATA_RELEASE_DIGEST";
const LEAF_DIGESTS_ENV: &str = "NOID_HISTORY_STEP_PACK_LEAF_DIGESTS";

const GENERATED_FILE: &str = "history_step_pack.rs";
const STAGED_DIRECTORY: &str = "embedded-history-step";
const MAX_COMPRESSED_LEAF_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_CANONICAL_LEAF_BYTES: usize = 1024 * 1024 * 1024;
const ZSTD_WINDOW_LOG_MAX: u32 = 27;

#[derive(Clone, Copy)]
struct BuildAuthenticatedLeafSeal {
    shape: FieldShape,
    statement_digest: [u8; 32],
    canonical_bytes: usize,
}

struct BuildAuthenticatedLeaf {
    seal: BuildAuthenticatedLeafSeal,
}

fn main() {
    for variable in [PACK_DIRECTORY_ENV, METADATA_DIGEST_ENV, LEAF_DIGESTS_ENV] {
        println!("cargo:rerun-if-env-changed={variable}");
    }

    let pack_directory = env::var_os(PACK_DIRECTORY_ENV);
    let metadata_digest = env::var_os(METADATA_DIGEST_ENV);
    let leaf_digests = env::var_os(LEAF_DIGESTS_ENV);
    let out_directory = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    let generated_path = out_directory.join(GENERATED_FILE);

    match (pack_directory, metadata_digest, leaf_digests) {
        (None, None, None) => {
            assert_ne!(
                env::var("PROFILE").as_deref(),
                Ok("release"),
                "release node builds require {PACK_DIRECTORY_ENV}, {METADATA_DIGEST_ENV}, and \
                 {LEAF_DIGESTS_ENV}"
            );
            write_if_changed(
                &generated_path,
                b"static GENERATED_HISTORY_STEP_PACK: Option<EmbeddedHistoryStepPack> = None;\n",
            );
        }
        (Some(pack_directory), Some(metadata_digest), Some(leaf_digests)) => {
            let metadata_digest = parse_hex_digest(
                &metadata_digest
                    .into_string()
                    .unwrap_or_else(|_| panic!("{METADATA_DIGEST_ENV} is not UTF-8")),
                METADATA_DIGEST_ENV,
            );
            let leaf_digests = parse_leaf_digests(
                &leaf_digests
                    .into_string()
                    .unwrap_or_else(|_| panic!("{LEAF_DIGESTS_ENV} is not UTF-8")),
            );
            embed_release_pack(
                &PathBuf::from(pack_directory),
                metadata_digest,
                leaf_digests,
                &out_directory,
                &generated_path,
            );
        }
        _ => panic!(
            "{PACK_DIRECTORY_ENV}, {METADATA_DIGEST_ENV}, and {LEAF_DIGESTS_ENV} must be set together"
        ),
    }
}

fn embed_release_pack(
    pack_root: &Path,
    metadata_digest: [u8; 32],
    leaf_digests: [[u8; 32]; HISTORY_STEP_PACK_LEAF_COUNT],
    out_directory: &Path,
    generated_path: &Path,
) {
    let version_directory = pack_root.join(HISTORY_STEP_PACK_VERSION_DIRECTORY);
    let metadata_path = version_directory.join(HISTORY_STEP_RUNTIME_METADATA_FILE);
    let metadata = read_bounded(
        &metadata_path,
        HISTORY_STEP_RUNTIME_METADATA_MAX_BYTES as u64,
    );
    let runtime_metadata = decode_history_step_runtime_metadata_pinned(&metadata, metadata_digest)
        .unwrap_or_else(|error| {
            panic!(
                "authenticate HistoryStep runtime metadata {}: {error}",
                metadata_path.display()
            )
        });
    println!("cargo:rerun-if-changed={}", metadata_path.display());

    let staged_directory = out_directory.join(STAGED_DIRECTORY);
    fs::create_dir_all(&staged_directory).unwrap_or_else(|error| {
        panic!(
            "create embedded HistoryStep staging directory {}: {error}",
            staged_directory.display()
        )
    });
    write_if_changed(
        &staged_directory.join(HISTORY_STEP_RUNTIME_METADATA_FILE),
        &metadata,
    );

    let mut build_leaves = Vec::with_capacity(HISTORY_STEP_PACK_LEAF_COUNT);
    for index in 0..HISTORY_STEP_PACK_LEAF_COUNT {
        let class = CanonicalHistoryStepClassId::from_index(index).expect("canonical class");
        let leaf_path = version_directory.join(history_step_matrix_file_name(class));
        let compressed = read_bounded(&leaf_path, MAX_COMPRESSED_LEAF_BYTES);
        let actual =
            poseidon2b_hash_byte_slices(HISTORY_STEP_PACK_LEAF_HASH_DOMAIN, &[&compressed]);
        assert_digest_eq(
            actual,
            leaf_digests[index],
            &format!("HistoryStep matrix leaf {}", leaf_path.display()),
        );
        let entry = runtime_metadata.bank().entry(class);
        let built = authenticate_leaf(class, &compressed, entry.shape(), entry.matrix_digest());
        write_if_changed(
            &staged_directory.join(history_step_matrix_file_name(class)),
            &compressed,
        );
        build_leaves.push(built);
        println!("cargo:rerun-if-changed={}", leaf_path.display());
    }
    let build_leaves: [BuildAuthenticatedLeaf; HISTORY_STEP_PACK_LEAF_COUNT] = build_leaves
        .try_into()
        .unwrap_or_else(|_| unreachable!("one build result per HistoryStep class"));
    let generated = render_generated_pack(metadata_digest, &build_leaves);
    write_if_changed(generated_path, generated.as_bytes());
}

fn authenticate_leaf(
    class: CanonicalHistoryStepClassId,
    compressed: &[u8],
    shape: FieldShape,
    statement_digest: [u8; 32],
) -> BuildAuthenticatedLeaf {
    let label = history_step_matrix_file_name(class);
    let mut decoder = zstd::stream::read::Decoder::new(compressed)
        .unwrap_or_else(|error| panic!("open compressed HistoryStep matrix {label}: {error}"));
    decoder
        .window_log_max(ZSTD_WINDOW_LOG_MAX)
        .unwrap_or_else(|error| panic!("bound zstd window for {label}: {error}"));
    let mut canonical = Vec::new();
    decoder
        .take(MAX_CANONICAL_LEAF_BYTES as u64 + 1)
        .read_to_end(&mut canonical)
        .unwrap_or_else(|error| panic!("decode HistoryStep matrix {label}: {error}"));
    assert!(
        canonical.len() <= MAX_CANONICAL_LEAF_BYTES,
        "HistoryStep matrix {label} exceeds the canonical size bound"
    );
    let canonical_bytes = canonical.len();
    // Full authentication of the exact embedded bytes. The packed runtime
    // layout is deliberately not built here: the node derives it once per
    // release into its local runtime cache.
    let _relation = CompactFieldR1cs::open(canonical.into_boxed_slice(), shape, statement_digest)
        .unwrap_or_else(|error| panic!("authenticate HistoryStep matrix {label}: {error}"));
    BuildAuthenticatedLeaf {
        seal: BuildAuthenticatedLeafSeal {
            shape,
            statement_digest,
            canonical_bytes,
        },
    }
}

fn read_bounded(path: &Path, max_bytes: u64) -> Vec<u8> {
    let metadata = fs::metadata(path)
        .unwrap_or_else(|error| panic!("inspect release artifact {}: {error}", path.display()));
    assert!(
        metadata.is_file() && metadata.len() <= max_bytes,
        "release artifact {} is not a bounded regular file",
        path.display()
    );
    fs::read(path)
        .unwrap_or_else(|error| panic!("read release artifact {}: {error}", path.display()))
}

fn parse_leaf_digests(encoded: &str) -> [[u8; 32]; HISTORY_STEP_PACK_LEAF_COUNT] {
    let expected_length = HISTORY_STEP_PACK_LEAF_COUNT * 64;
    assert_eq!(
        encoded.len(),
        expected_length,
        "{LEAF_DIGESTS_ENV} must contain exactly {HISTORY_STEP_PACK_LEAF_COUNT} lowercase hex digests"
    );
    std::array::from_fn(|index| {
        parse_hex_digest(&encoded[index * 64..(index + 1) * 64], LEAF_DIGESTS_ENV)
    })
}

fn parse_hex_digest(encoded: &str, variable: &str) -> [u8; 32] {
    assert_eq!(
        encoded.len(),
        64,
        "{variable} must be exactly 64 lowercase hexadecimal characters"
    );
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        let high = decode_lower_hex(encoded.as_bytes()[index * 2])
            .unwrap_or_else(|| panic!("{variable} is not lowercase hexadecimal"));
        let low = decode_lower_hex(encoded.as_bytes()[index * 2 + 1])
            .unwrap_or_else(|| panic!("{variable} is not lowercase hexadecimal"));
        *byte = (high << 4) | low;
    }
    digest
}

const fn decode_lower_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn assert_digest_eq(actual: [u8; 32], expected: [u8; 32], label: &str) {
    assert!(
        actual == expected,
        "{label} digest mismatch: expected {}, actual {}",
        encode_hex(&expected),
        encode_hex(&actual)
    );
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn render_generated_pack(
    metadata_digest: [u8; 32],
    leaves: &[BuildAuthenticatedLeaf; HISTORY_STEP_PACK_LEAF_COUNT],
) -> String {
    let mut generated = String::from(
        "static GENERATED_HISTORY_STEP_PACK: Option<EmbeddedHistoryStepPack> =\n\
         Some(EmbeddedHistoryStepPack {\n",
    );
    writeln!(
        &mut generated,
        "    runtime_metadata: include_bytes!(concat!(env!(\"OUT_DIR\"), \"/{STAGED_DIRECTORY}/{HISTORY_STEP_RUNTIME_METADATA_FILE}\")),"
    )
    .expect("writing to String cannot fail");
    writeln!(
        &mut generated,
        "    runtime_metadata_digest: {},",
        render_digest(metadata_digest)
    )
    .expect("writing to String cannot fail");
    generated.push_str("    leaves: [\n");
    for (index, leaf) in leaves.iter().enumerate() {
        let class = CanonicalHistoryStepClassId::from_index(index).expect("canonical class");
        let seal = leaf.seal;
        writeln!(
            &mut generated,
            "        unsafe {{ noid_miner::EmbeddedHistoryStepMatrixLeaf::from_release_build(\n            noid_recursive::acceptance::history_step_bank::CanonicalHistoryStepClassId::from_index({index}).unwrap(),\n            include_bytes!(concat!(env!(\"OUT_DIR\"), \"/{STAGED_DIRECTORY}/{}\")),\n            noid_ivc_core::field_r1cs::BuildAuthenticatedFieldR1csSeal::from_release_build(\n                noid_ivc_core::proof::FieldShape {{ m: {}, k_log: {}, k_skip: {}, const_pin: {} }},\n                {},\n                {},\n            ),\n        ) }},",
            history_step_matrix_file_name(class),
            seal.shape.m,
            seal.shape.k_log,
            seal.shape.k_skip,
            render_const_pin(seal.shape.const_pin),
            render_digest(seal.statement_digest),
            seal.canonical_bytes,
        )
        .expect("writing to String cannot fail");
    }
    generated.push_str("    ],\n});\n");
    generated
}

fn render_const_pin(pin: Option<usize>) -> String {
    pin.map_or_else(|| "None".to_owned(), |column| format!("Some({column})"))
}

fn render_digest(digest: [u8; 32]) -> String {
    let mut rendered = String::from("[");
    for (index, byte) in digest.iter().enumerate() {
        if index != 0 {
            rendered.push_str(", ");
        }
        write!(&mut rendered, "0x{byte:02x}").expect("writing to String cannot fail");
    }
    rendered.push(']');
    rendered
}

fn write_if_changed(path: &Path, bytes: &[u8]) {
    if matches!(fs::read(path), Ok(existing) if existing == bytes) {
        return;
    }
    fs::write(path, bytes)
        .unwrap_or_else(|error| panic!("write generated artifact {}: {error}", path.display()));
}
