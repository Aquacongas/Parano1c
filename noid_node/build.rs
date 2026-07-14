// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Build-time authority for the self-contained selected-recursive release pack.
//!
//! Development builds with no release-pack environment are intentionally
//! pack-free. Once any pack setting is supplied, all three settings become
//! mandatory and every embedded byte is authenticated before rustc sees it.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use noid_ivc_core::field_r1cs::CompactFieldR1cs;
use noid_ivc_core::proof::FieldShape;
use noid_poseidon2b::native::poseidon2b_hash_byte_slices;
use noid_recursive::class_registry::{
    decode_selected_recursive_class_registry_pinned,
    decode_selected_recursive_terminal_registry_pinned,
};

const PACK_DIRECTORY_ENV: &str = "NOID_SELECTED_RECURSIVE_PACK_DIR";
const REGISTRY_DIGEST_ENV: &str = "NOID_SELECTED_RECURSIVE_REGISTRY_RELEASE_DIGEST";
const LEAF_DIGESTS_ENV: &str = "NOID_SELECTED_RECURSIVE_PACK_LEAF_DIGESTS";

const PACK_LEAF_HASH_DOMAIN: &[u8] = b"NOID/SELECTED-RECURSIVE/PACK-LEAF";
const REGISTRY_DIGEST_DOMAIN: &[u8] = b"NOID/SELECTED-RECURSIVE-CLASS-REGISTRY/V1";
const REGISTRY_MAGIC: &[u8; 16] = b"NOID/SRCLASS/V2\0";
const REGISTRY_VERSION: u16 = 2;
const REGISTRY_HEADER_BYTES: usize = REGISTRY_MAGIC.len() + 2 + 8;
const REGISTRY_TRAILER_BYTES: usize = 32;
const MAX_REGISTRY_BYTES: u64 = 4 * 1024 * 1024;
const MAX_COMPRESSED_LEAF_BYTES: u64 = 512 * 1024 * 1024;
const MIB: usize = 1024 * 1024;
const EMBEDDED_MATRIX_ZSTD_WINDOW_LOG_MAX: u32 = 23;
const CANONICAL_LEAF_LIMITS: [usize; 9] = [
    32 * MIB,
    32 * MIB,
    32 * MIB,
    32 * MIB,
    32 * MIB,
    32 * MIB,
    64 * MIB,
    96 * MIB,
    320 * MIB,
];

const GENERATED_FILE: &str = "selected_recursive_pack.rs";
const STAGED_DIRECTORY: &str = "embedded-selected-recursive";
const REGISTRY_FILE: &str = "selected-recursive.classes";

#[derive(Clone, Copy)]
struct LeafSpec {
    file_name: &'static str,
    runtime_file_name: &'static str,
    rust_kind: &'static str,
}

#[derive(Clone, Copy)]
struct BuildAuthenticatedLeafSeal {
    shape: FieldShape,
    statement_digest: [u8; 32],
    canonical_bytes: usize,
}

struct BuildAuthenticatedLeaf {
    seal: BuildAuthenticatedLeafSeal,
    compressed_runtime_image: Vec<u8>,
}

/// Consensus order: genesis T, Link B8/B32/B64/B255, then Block
/// B8/B32/B64/B255. It must remain identical to `noid_pack_pins`.
const LEAVES: [LeafSpec; 9] = [
    LeafSpec {
        file_name: "genesis-link.field-r1cs.zst",
        runtime_file_name: "genesis-link.packed-r1cs.zst",
        rust_kind: "SelectedRecursiveMatrixKind::GenesisLink",
    },
    LeafSpec {
        file_name: "link-b8.field-r1cs.zst",
        runtime_file_name: "link-b8.packed-r1cs.zst",
        rust_kind:
            "SelectedRecursiveMatrixKind::PreviousLink(noid_miner::SelectedRecursiveTier::B8)",
    },
    LeafSpec {
        file_name: "link-b32.field-r1cs.zst",
        runtime_file_name: "link-b32.packed-r1cs.zst",
        rust_kind:
            "SelectedRecursiveMatrixKind::PreviousLink(noid_miner::SelectedRecursiveTier::B32)",
    },
    LeafSpec {
        file_name: "link-b64.field-r1cs.zst",
        runtime_file_name: "link-b64.packed-r1cs.zst",
        rust_kind:
            "SelectedRecursiveMatrixKind::PreviousLink(noid_miner::SelectedRecursiveTier::B64)",
    },
    LeafSpec {
        file_name: "link-b255.field-r1cs.zst",
        runtime_file_name: "link-b255.packed-r1cs.zst",
        rust_kind:
            "SelectedRecursiveMatrixKind::PreviousLink(noid_miner::SelectedRecursiveTier::B255)",
    },
    LeafSpec {
        file_name: "block-b8.field-r1cs.zst",
        runtime_file_name: "block-b8.packed-r1cs.zst",
        rust_kind:
            "SelectedRecursiveMatrixKind::CurrentBlock(noid_miner::SelectedRecursiveTier::B8)",
    },
    LeafSpec {
        file_name: "block-b32.field-r1cs.zst",
        runtime_file_name: "block-b32.packed-r1cs.zst",
        rust_kind:
            "SelectedRecursiveMatrixKind::CurrentBlock(noid_miner::SelectedRecursiveTier::B32)",
    },
    LeafSpec {
        file_name: "block-b64.field-r1cs.zst",
        runtime_file_name: "block-b64.packed-r1cs.zst",
        rust_kind:
            "SelectedRecursiveMatrixKind::CurrentBlock(noid_miner::SelectedRecursiveTier::B64)",
    },
    LeafSpec {
        file_name: "block-b255.field-r1cs.zst",
        runtime_file_name: "block-b255.packed-r1cs.zst",
        rust_kind:
            "SelectedRecursiveMatrixKind::CurrentBlock(noid_miner::SelectedRecursiveTier::B255)",
    },
];

fn main() {
    for name in [PACK_DIRECTORY_ENV, REGISTRY_DIGEST_ENV, LEAF_DIGESTS_ENV] {
        println!("cargo:rerun-if-env-changed={name}");
    }

    let pack_directory = env::var_os(PACK_DIRECTORY_ENV);
    let registry_digest = env::var_os(REGISTRY_DIGEST_ENV);
    let leaf_digests = env::var_os(LEAF_DIGESTS_ENV);
    let out_directory = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    let generated_path = out_directory.join(GENERATED_FILE);

    match (pack_directory, registry_digest, leaf_digests) {
        (None, None, None) => {
            assert_ne!(
                env::var("PROFILE").as_deref(),
                Ok("release"),
                "release node builds must embed the selected-recursive pack; set \
                 {PACK_DIRECTORY_ENV}, {REGISTRY_DIGEST_ENV}, and {LEAF_DIGESTS_ENV}"
            );
            write_if_changed(
                &generated_path,
                b"static GENERATED_SELECTED_RECURSIVE_PACK: Option<EmbeddedSelectedRecursivePack> = None;\n",
            );
        }
        (Some(pack_directory), Some(registry_digest), Some(leaf_digests)) => {
            let registry_digest = parse_hex_digest(
                &registry_digest
                    .into_string()
                    .unwrap_or_else(|_| panic!("{REGISTRY_DIGEST_ENV} is not UTF-8")),
                REGISTRY_DIGEST_ENV,
            );
            let leaf_digests = parse_leaf_digests(
                &leaf_digests
                    .into_string()
                    .unwrap_or_else(|_| panic!("{LEAF_DIGESTS_ENV} is not UTF-8")),
            );
            let pack_directory = PathBuf::from(pack_directory);
            embed_release_pack(
                &pack_directory,
                registry_digest,
                leaf_digests,
                &out_directory,
                &generated_path,
            );
        }
        _ => panic!(
            "selected-recursive release embedding is fail-closed: {PACK_DIRECTORY_ENV}, \
             {REGISTRY_DIGEST_ENV}, and {LEAF_DIGESTS_ENV} must be either all set or all unset"
        ),
    }
}

fn embed_release_pack(
    pack_directory: &Path,
    registry_digest: [u8; 32],
    leaf_digests: [[u8; 32]; LEAVES.len()],
    out_directory: &Path,
    generated_path: &Path,
) {
    let version_directory = resolve_version_directory(pack_directory);
    reject_symlink_or_non_directory(&version_directory, "selected-recursive pack directory");

    let registry_path = version_directory.join(REGISTRY_FILE);
    let registry_bytes = read_regular_file(&registry_path, MAX_REGISTRY_BYTES);
    authenticate_registry(&registry_bytes, registry_digest, &registry_path);

    let mut authenticated_leaves = Vec::with_capacity(LEAVES.len());
    for (index, spec) in LEAVES.iter().enumerate() {
        let path = version_directory.join(spec.file_name);
        let bytes = read_regular_file(&path, MAX_COMPRESSED_LEAF_BYTES);
        let actual = poseidon2b_hash_byte_slices(PACK_LEAF_HASH_DOMAIN, &[&bytes]);
        assert_digest_eq(
            actual,
            leaf_digests[index],
            &format!("compressed pack leaf {}", path.display()),
        );
        authenticated_leaves.push(bytes);
        println!("cargo:rerun-if-changed={}", path.display());
    }
    println!("cargo:rerun-if-changed={}", registry_path.display());

    // Move the expensive semantic trust boundary and runtime layout transform
    // into the release build.
    // The registry pin supplies every matrix shape/statement identity and the
    // compressed pins bind the exact canonical inputs. Each leaf is fully
    // decoded and structurally Poseidon-authenticated here before a seal can
    // be emitted, transformed into the fixed-width runtime layout, and
    // compressed for embedding. Runtime performs no canonical parse, layout
    // validation, structural hash, or repack.
    let build_leaves = authenticate_canonical_leaf_semantics(
        &registry_bytes,
        registry_digest,
        &authenticated_leaves,
    );

    // Stage only the build-produced runtime images. The canonical compressed
    // leaves are release-build inputs and never ship inside the executable;
    // `include_bytes!` sees immutable output with no runtime parse/repack path.
    let staged_directory = out_directory.join(STAGED_DIRECTORY);
    fs::create_dir_all(&staged_directory).unwrap_or_else(|error| {
        panic!(
            "create embedded pack staging directory {}: {error}",
            staged_directory.display()
        )
    });
    write_if_changed(&staged_directory.join(REGISTRY_FILE), &registry_bytes);
    for (spec, leaf) in LEAVES.iter().zip(&build_leaves) {
        write_if_changed(
            &staged_directory.join(spec.runtime_file_name),
            &leaf.compressed_runtime_image,
        );
    }

    let generated = render_generated_pack(registry_digest, &build_leaves);
    write_if_changed(generated_path, generated.as_bytes());
}

fn authenticate_canonical_leaf_semantics(
    registry_bytes: &[u8],
    registry_digest: [u8; 32],
    compressed_leaves: &[Vec<u8>],
) -> [BuildAuthenticatedLeaf; LEAVES.len()] {
    assert_eq!(compressed_leaves.len(), LEAVES.len());
    // Both runtime materializations are authorized here. Proving roles use
    // the full registry; relays use the terminal-only representation. Neither
    // executable path is allowed to defer its semantic gate to node startup.
    drop(
        decode_selected_recursive_class_registry_pinned(registry_bytes, registry_digest)
            .unwrap_or_else(|error| {
                panic!("full pinned selected-recursive registry is invalid: {error}")
            }),
    );
    let registry =
        decode_selected_recursive_terminal_registry_pinned(registry_bytes, registry_digest)
            .unwrap_or_else(|error| {
                panic!("pinned selected-recursive registry is invalid: {error}")
            });
    let descriptor = registry.descriptor();
    let terminal = registry.selected_history_registry();
    let mut identities = [(
        descriptor.link_shape(),
        registry.genesis_link_matrix_digest(),
    ); LEAVES.len()];
    for slot in 0..descriptor.slots().len() {
        identities[1 + slot] = (
            descriptor.link_shape(),
            terminal
                .link_class_digest(slot)
                .expect("validated terminal registry covers every Link tier"),
        );
        identities[5 + slot] = (
            descriptor.slots()[slot].b_shape,
            descriptor.slots()[slot].b_digest,
        );
    }

    // The nine leaves are independent and the documented release/prover host
    // has at least 16 GiB RAM. Authenticate them concurrently so this one-time
    // build gate uses the machine instead of serializing nine Poseidon scans.
    // Their aggregate canonical payload is only about 553 MiB.
    let seals = std::thread::scope(|scope| {
        let mut workers = Vec::with_capacity(LEAVES.len());
        for index in 0..LEAVES.len() {
            let compressed = &compressed_leaves[index];
            let identity = identities[index];
            workers.push(
                scope.spawn(move || authenticate_one_canonical_leaf(index, compressed, identity)),
            );
        }
        workers
            .into_iter()
            .map(|worker| {
                worker
                    .join()
                    .unwrap_or_else(|payload| std::panic::resume_unwind(payload))
            })
            .collect::<Vec<_>>()
    });
    seals
        .try_into()
        .unwrap_or_else(|_| unreachable!("one build seal per canonical leaf"))
}

fn authenticate_one_canonical_leaf(
    index: usize,
    compressed: &[u8],
    identity: (FieldShape, [u8; 32]),
) -> BuildAuthenticatedLeaf {
    let canonical = decompress_canonical_leaf_for_build(
        compressed,
        CANONICAL_LEAF_LIMITS[index],
        LEAVES[index].file_name,
    );
    let canonical_bytes = canonical.len();
    let (shape, statement_digest) = identity;
    let relation =
        CompactFieldR1cs::open(canonical, shape, statement_digest).unwrap_or_else(|error| {
            panic!(
                "release matrix {} disagrees with the pinned registry: {error}",
                LEAVES[index].file_name
            )
        });
    assert_eq!(relation.shape(), shape);
    assert_eq!(relation.statement_digest(), statement_digest);
    assert_eq!(relation.encoded_len(), canonical_bytes);
    let packed = relation.into_startup_packed().unwrap_or_else(|error| {
        panic!(
            "release matrix {} cannot be transformed to the runtime layout: {error}",
            LEAVES[index].file_name
        )
    });
    let runtime_image = packed
        .encode_startup_packed_image()
        .unwrap_or_else(|error| {
            panic!(
                "release matrix {} runtime image cannot be encoded: {error}",
                LEAVES[index].file_name
            )
        });
    let compressed_runtime_image = zstd::stream::encode_all(runtime_image.as_ref(), 9)
        .unwrap_or_else(|error| {
            panic!(
                "release matrix {} runtime image cannot be compressed: {error}",
                LEAVES[index].file_name
            )
        });
    BuildAuthenticatedLeaf {
        seal: BuildAuthenticatedLeafSeal {
            shape,
            statement_digest,
            canonical_bytes,
        },
        compressed_runtime_image,
    }
}

fn decompress_canonical_leaf_for_build(
    compressed: &[u8],
    max_canonical_bytes: usize,
    label: &str,
) -> Box<[u8]> {
    let mut decoder = zstd::stream::read::Decoder::new(compressed)
        .unwrap_or_else(|error| panic!("open compressed release matrix {label}: {error}"));
    decoder
        .window_log_max(EMBEDDED_MATRIX_ZSTD_WINDOW_LOG_MAX)
        .unwrap_or_else(|error| panic!("bound zstd window for release matrix {label}: {error}"));
    let mut canonical = Vec::new();
    decoder
        .take(max_canonical_bytes.saturating_add(1) as u64)
        .read_to_end(&mut canonical)
        .unwrap_or_else(|error| panic!("decode release matrix {label}: {error}"));
    assert!(
        canonical.len() <= max_canonical_bytes,
        "release matrix {label} expands beyond its {}-byte canonical limit",
        max_canonical_bytes,
    );
    canonical.into_boxed_slice()
}

fn resolve_version_directory(pack_directory: &Path) -> PathBuf {
    let nested = pack_directory.join("v1");
    if nested.join(REGISTRY_FILE).is_file() {
        nested
    } else {
        pack_directory.to_path_buf()
    }
}

fn reject_symlink_or_non_directory(path: &Path, label: &str) {
    let metadata = fs::symlink_metadata(path)
        .unwrap_or_else(|error| panic!("inspect {label} {}: {error}", path.display()));
    assert!(
        !metadata.file_type().is_symlink(),
        "{label} {} must not be a symlink",
        path.display()
    );
    assert!(
        metadata.is_dir(),
        "{label} {} is not a directory",
        path.display()
    );
}

fn read_regular_file(path: &Path, max_bytes: u64) -> Vec<u8> {
    let path_metadata = fs::symlink_metadata(path)
        .unwrap_or_else(|error| panic!("inspect release artifact {}: {error}", path.display()));
    assert!(
        !path_metadata.file_type().is_symlink(),
        "release artifact {} must not be a symlink",
        path.display()
    );
    assert!(
        path_metadata.is_file(),
        "release artifact {} is not a regular file",
        path.display()
    );
    // Read through one opened handle and enforce the cap on bytes actually
    // consumed. A path can be resized or replaced between metadata and read;
    // trusting its earlier length would let a same-UID build perturbation make
    // `fs::read` allocate without the advertised bound. The pinned digest
    // below still rejects any path substitution, while `take(max + 1)` keeps
    // even a hostile replacement allocation-bounded.
    let mut file = fs::File::open(path)
        .unwrap_or_else(|error| panic!("open release artifact {}: {error}", path.display()));
    let metadata = file
        .metadata()
        .unwrap_or_else(|error| panic!("inspect opened artifact {}: {error}", path.display()));
    assert!(
        metadata.is_file(),
        "opened release artifact {} is not a regular file",
        path.display()
    );
    assert!(
        metadata.len() <= max_bytes,
        "release artifact {} is too large: {} bytes exceeds {}",
        path.display(),
        metadata.len(),
        max_bytes
    );
    let capacity = usize::try_from(metadata.len().min(max_bytes)).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .unwrap_or_else(|error| panic!("read release artifact {}: {error}", path.display()));
    assert!(
        bytes.len() as u64 <= max_bytes,
        "release artifact {} grew beyond {} bytes while being read",
        path.display(),
        max_bytes
    );
    bytes
}

fn authenticate_registry(bytes: &[u8], expected: [u8; 32], path: &Path) {
    assert!(
        bytes.len() >= REGISTRY_HEADER_BYTES + REGISTRY_TRAILER_BYTES,
        "registry {} is truncated",
        path.display()
    );
    assert_eq!(
        &bytes[..REGISTRY_MAGIC.len()],
        REGISTRY_MAGIC,
        "registry {} has bad magic",
        path.display()
    );
    let version_offset = REGISTRY_MAGIC.len();
    let version = u16::from_le_bytes(
        bytes[version_offset..version_offset + 2]
            .try_into()
            .expect("two-byte registry version"),
    );
    assert_eq!(
        version,
        REGISTRY_VERSION,
        "registry {} has unsupported version {version}",
        path.display()
    );
    let body_length_offset = version_offset + 2;
    let body_length = u64::from_le_bytes(
        bytes[body_length_offset..body_length_offset + 8]
            .try_into()
            .expect("eight-byte registry body length"),
    );
    let body_length = usize::try_from(body_length)
        .unwrap_or_else(|_| panic!("registry {} body length overflows usize", path.display()));
    let expected_length = REGISTRY_HEADER_BYTES
        .checked_add(body_length)
        .and_then(|length| length.checked_add(REGISTRY_TRAILER_BYTES))
        .unwrap_or_else(|| panic!("registry {} length overflows usize", path.display()));
    assert_eq!(
        bytes.len(),
        expected_length,
        "registry {} encoded length does not match its header",
        path.display()
    );
    let body = &bytes[REGISTRY_HEADER_BYTES..REGISTRY_HEADER_BYTES + body_length];
    let advertised: [u8; 32] = bytes[REGISTRY_HEADER_BYTES + body_length..]
        .try_into()
        .expect("32-byte registry trailer");
    let actual = poseidon2b_hash_byte_slices(REGISTRY_DIGEST_DOMAIN, &[body]);
    assert_digest_eq(
        actual,
        advertised,
        &format!("registry trailer in {}", path.display()),
    );
    assert_digest_eq(
        actual,
        expected,
        &format!("release registry pin for {}", path.display()),
    );
}

fn parse_leaf_digests(encoded: &str) -> [[u8; 32]; LEAVES.len()] {
    let expected_length = LEAVES.len() * 64;
    assert_eq!(
        encoded.len(),
        expected_length,
        "{LEAF_DIGESTS_ENV} must contain exactly {} lowercase hex digests ({} characters)",
        LEAVES.len(),
        expected_length
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
        let high = decode_lower_hex(encoded.as_bytes()[index * 2]).unwrap_or_else(|| {
            panic!(
                "{variable} contains non-lowercase-hex at byte {}",
                index * 2
            )
        });
        let low = decode_lower_hex(encoded.as_bytes()[index * 2 + 1]).unwrap_or_else(|| {
            panic!(
                "{variable} contains non-lowercase-hex at byte {}",
                index * 2 + 1
            )
        });
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
    registry_digest: [u8; 32],
    build_leaves: &[BuildAuthenticatedLeaf; LEAVES.len()],
) -> String {
    let mut generated = String::from(
        "static GENERATED_SELECTED_RECURSIVE_PACK: Option<EmbeddedSelectedRecursivePack> =\n\
         Some(EmbeddedSelectedRecursivePack {\n",
    );
    writeln!(
        &mut generated,
        "    registry_bytes: include_bytes!(concat!(env!(\"OUT_DIR\"), \"/{STAGED_DIRECTORY}/{REGISTRY_FILE}\")),"
    )
    .expect("writing to String cannot fail");
    writeln!(
        &mut generated,
        "    registry_digest: {},",
        render_digest(registry_digest)
    )
    .expect("writing to String cannot fail");
    generated.push_str("    leaves: [\n");
    for (index, spec) in LEAVES.iter().enumerate() {
        let seal = build_leaves[index].seal;
        writeln!(
            &mut generated,
            "        EmbeddedSelectedRecursiveLeaf {{\n            kind: {},\n            compressed_runtime_image: include_bytes!(concat!(env!(\"OUT_DIR\"), \"/{STAGED_DIRECTORY}/{}\")),\n            build_seal: unsafe {{ noid_ivc_core::field_r1cs::BuildAuthenticatedFieldR1csSeal::from_release_build(\n                noid_ivc_core::proof::FieldShape {{ m: {}, k_log: {}, k_skip: {}, const_pin: {} }},\n                {},\n                {},\n            ) }},\n        }},",
            spec.rust_kind,
            spec.runtime_file_name,
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
