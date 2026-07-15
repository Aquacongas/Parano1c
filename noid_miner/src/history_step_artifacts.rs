// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Executable-embedded artifacts for the canonical `HistoryStep` class bank.
//!
//! An official node contains one pinned runtime-metadata artifact and sixteen
//! build-authenticated matrix images.  This module owns only the matrix-image
//! boundary. Every [`HistoryStepMatrixSource`] call returns an authenticated
//! compact lease. A fixed-size cache retains only the most recently used
//! packed relations; no runtime path decodes resident CSR arrays.

use std::collections::VecDeque;
use std::io::Read as _;
use std::sync::{Arc, Mutex};

use noid_ivc_core::field_r1cs::{
    BuildAuthenticatedFieldR1csSeal, CompactFieldR1cs, FieldR1csArtifactError,
};
use noid_poseidon2b::native::poseidon2b_hash_byte_slices;
use noid_recursive::acceptance::history_step::{
    HistoryStepMatrixLease, HistoryStepMatrixSource, HistoryStepMatrixSourceError,
};
use noid_recursive::acceptance::history_step_bank::{
    canonical_history_step_shape, CanonicalHistoryStepClassId, PinnedHistoryStepClassBank,
    HISTORY_STEP_CLASS_COUNT,
};
use noid_recursive::{
    pin_history_step_class_bank, HistoryStepError, HistoryStepRuntimeParts,
    HISTORY_STEP_RUNTIME_PARTS_COMPACT_MAX_BYTES,
};
use thiserror::Error;

pub const HISTORY_STEP_PACK_VERSION_DIRECTORY: &str = "v1";
pub const HISTORY_STEP_RUNTIME_METADATA_FILE: &str = "history-step.runtime";
pub const HISTORY_STEP_PACK_LEAF_COUNT: usize = HISTORY_STEP_CLASS_COUNT;
pub const HISTORY_STEP_PACK_LEAF_HASH_DOMAIN: &[u8] = b"NOID/HISTORY-STEP/PACK-LEAF/V1";
pub const HISTORY_STEP_RUNTIME_METADATA_DIGEST_DOMAIN: &[u8] =
    b"NOID/HISTORY-STEP/RUNTIME-METADATA/V1";

pub const HISTORY_STEP_RUNTIME_METADATA_VERSION: u16 = 1;
pub const HISTORY_STEP_RUNTIME_METADATA_MAX_BYTES: usize = 16
    + 2
    + 8
    + 32 * HISTORY_STEP_PACK_LEAF_COUNT
    + HISTORY_STEP_RUNTIME_PARTS_COMPACT_MAX_BYTES
    + 32;

const HISTORY_STEP_RUNTIME_METADATA_MAGIC: [u8; 16] = *b"NOID/HSTEP/V1\0\0\0";
const HISTORY_STEP_RUNTIME_METADATA_HEADER_BYTES: usize =
    HISTORY_STEP_RUNTIME_METADATA_MAGIC.len() + 2 + 8;
const HISTORY_STEP_RUNTIME_METADATA_MATRIX_DIGEST_BYTES: usize = 32 * HISTORY_STEP_PACK_LEAF_COUNT;
const HISTORY_STEP_RUNTIME_METADATA_TRAILER_BYTES: usize = 32;
const HISTORY_STEP_RUNTIME_METADATA_MIN_BYTES: usize = HISTORY_STEP_RUNTIME_METADATA_HEADER_BYTES
    + HISTORY_STEP_RUNTIME_METADATA_MATRIX_DIGEST_BYTES
    + 1
    + HISTORY_STEP_RUNTIME_METADATA_TRAILER_BYTES;

/// Keep the hot parent and one concurrent/terminal class without retaining
/// the complete four-class bank in memory.
const HISTORY_STEP_COMPACT_MATRIX_CACHE_CAPACITY: usize = 2;

const HISTORY_STEP_MATRIX_FILE_NAMES: [&str; HISTORY_STEP_PACK_LEAF_COUNT] = [
    "history-step-c00.field-r1cs.zst",
    "history-step-c01.field-r1cs.zst",
    "history-step-c02.field-r1cs.zst",
    "history-step-c03.field-r1cs.zst",
];

const HISTORY_STEP_RUNTIME_IMAGE_FILE_NAMES: [&str; HISTORY_STEP_PACK_LEAF_COUNT] = [
    "history-step-c00.packed-r1cs.zst",
    "history-step-c01.packed-r1cs.zst",
    "history-step-c02.packed-r1cs.zst",
    "history-step-c03.packed-r1cs.zst",
];

pub fn history_step_matrix_file_name(class: CanonicalHistoryStepClassId) -> &'static str {
    HISTORY_STEP_MATRIX_FILE_NAMES[class.index()]
}

/// Fully validated release material for the canonical runtime.
pub struct HistoryStepRuntimeMetadata {
    bank: PinnedHistoryStepClassBank,
    runtime_parts: HistoryStepRuntimeParts,
}

impl HistoryStepRuntimeMetadata {
    pub fn bank(&self) -> &PinnedHistoryStepClassBank {
        &self.bank
    }

    pub fn runtime_parts(&self) -> &HistoryStepRuntimeParts {
        &self.runtime_parts
    }

    pub fn into_parts(self) -> (PinnedHistoryStepClassBank, HistoryStepRuntimeParts) {
        (self.bank, self.runtime_parts)
    }

    pub fn encode(&self) -> Result<Vec<u8>, HistoryStepRuntimeMetadataError> {
        encode_history_step_runtime_metadata(&self.bank, &self.runtime_parts)
    }
}

#[derive(Debug, Error)]
pub enum HistoryStepRuntimeMetadataError {
    #[error(
        "HistoryStep runtime metadata has {actual} bytes, canonical bounds are {minimum}..={maximum}"
    )]
    Length {
        minimum: usize,
        maximum: usize,
        actual: usize,
    },
    #[error("HistoryStep runtime metadata magic mismatch")]
    Magic,
    #[error("unsupported HistoryStep runtime metadata version {actual}")]
    Version { actual: u16 },
    #[error("HistoryStep runtime metadata body length mismatch")]
    BodyLength,
    #[error("HistoryStep runtime metadata digest mismatch")]
    Digest,
    #[error("HistoryStep runtime metadata does not match the release pin")]
    ReleasePin,
    #[error("HistoryStep runtime metadata bank and verifier material disagree")]
    BankMismatch,
    #[error("HistoryStep runtime verifier material is invalid: {0}")]
    Recursive(#[from] HistoryStepError),
}

pub fn encode_history_step_runtime_metadata(
    bank: &PinnedHistoryStepClassBank,
    runtime_parts: &HistoryStepRuntimeParts,
) -> Result<Vec<u8>, HistoryStepRuntimeMetadataError> {
    let matrix_digests = std::array::from_fn(|index| bank.entries()[index].matrix_digest());
    let rebuilt = pin_history_step_class_bank(matrix_digests, runtime_parts)?;
    if rebuilt.digest() != bank.digest() {
        return Err(HistoryStepRuntimeMetadataError::BankMismatch);
    }
    let runtime_parts = runtime_parts.encode_compact()?;
    let mut body =
        Vec::with_capacity(HISTORY_STEP_RUNTIME_METADATA_MATRIX_DIGEST_BYTES + runtime_parts.len());
    for entry in bank.entries() {
        body.extend_from_slice(&entry.matrix_digest());
    }
    body.extend_from_slice(&runtime_parts);
    Ok(frame_history_step_runtime_metadata(&body))
}

fn frame_history_step_runtime_metadata(body: &[u8]) -> Vec<u8> {
    let digest = poseidon2b_hash_byte_slices(HISTORY_STEP_RUNTIME_METADATA_DIGEST_DOMAIN, &[&body]);
    let mut encoded = Vec::with_capacity(
        HISTORY_STEP_RUNTIME_METADATA_HEADER_BYTES
            + body.len()
            + HISTORY_STEP_RUNTIME_METADATA_TRAILER_BYTES,
    );
    encoded.extend_from_slice(&HISTORY_STEP_RUNTIME_METADATA_MAGIC);
    encoded.extend_from_slice(&HISTORY_STEP_RUNTIME_METADATA_VERSION.to_le_bytes());
    encoded.extend_from_slice(&(body.len() as u64).to_le_bytes());
    encoded.extend_from_slice(&body);
    encoded.extend_from_slice(&digest);
    encoded
}

pub fn decode_history_step_runtime_metadata_pinned(
    encoded: &[u8],
    expected_digest: [u8; 32],
) -> Result<HistoryStepRuntimeMetadata, HistoryStepRuntimeMetadataError> {
    if !(HISTORY_STEP_RUNTIME_METADATA_MIN_BYTES..=HISTORY_STEP_RUNTIME_METADATA_MAX_BYTES)
        .contains(&encoded.len())
    {
        return Err(HistoryStepRuntimeMetadataError::Length {
            minimum: HISTORY_STEP_RUNTIME_METADATA_MIN_BYTES,
            maximum: HISTORY_STEP_RUNTIME_METADATA_MAX_BYTES,
            actual: encoded.len(),
        });
    }
    if encoded[..HISTORY_STEP_RUNTIME_METADATA_MAGIC.len()] != HISTORY_STEP_RUNTIME_METADATA_MAGIC {
        return Err(HistoryStepRuntimeMetadataError::Magic);
    }
    let mut cursor = HISTORY_STEP_RUNTIME_METADATA_MAGIC.len();
    let version = u16::from_le_bytes(
        encoded[cursor..cursor + 2]
            .try_into()
            .expect("fixed version width"),
    );
    cursor += 2;
    if version != HISTORY_STEP_RUNTIME_METADATA_VERSION {
        return Err(HistoryStepRuntimeMetadataError::Version { actual: version });
    }
    let body_bytes = usize::try_from(u64::from_le_bytes(
        encoded[cursor..cursor + 8]
            .try_into()
            .expect("fixed body-length width"),
    ))
    .map_err(|_| HistoryStepRuntimeMetadataError::BodyLength)?;
    cursor += 8;
    let expected = HISTORY_STEP_RUNTIME_METADATA_HEADER_BYTES
        .checked_add(body_bytes)
        .and_then(|bytes| bytes.checked_add(HISTORY_STEP_RUNTIME_METADATA_TRAILER_BYTES))
        .ok_or(HistoryStepRuntimeMetadataError::BodyLength)?;
    if expected != encoded.len()
        || body_bytes <= HISTORY_STEP_RUNTIME_METADATA_MATRIX_DIGEST_BYTES
        || body_bytes
            > HISTORY_STEP_RUNTIME_METADATA_MATRIX_DIGEST_BYTES
                + HISTORY_STEP_RUNTIME_PARTS_COMPACT_MAX_BYTES
    {
        return Err(HistoryStepRuntimeMetadataError::BodyLength);
    }
    debug_assert_eq!(cursor, HISTORY_STEP_RUNTIME_METADATA_HEADER_BYTES);
    let body_end = cursor + body_bytes;
    let body = &encoded[cursor..body_end];
    let advertised: [u8; 32] = encoded[body_end..]
        .try_into()
        .expect("fixed metadata trailer width");
    let actual = poseidon2b_hash_byte_slices(HISTORY_STEP_RUNTIME_METADATA_DIGEST_DOMAIN, &[body]);
    if advertised != actual {
        return Err(HistoryStepRuntimeMetadataError::Digest);
    }
    if actual != expected_digest {
        return Err(HistoryStepRuntimeMetadataError::ReleasePin);
    }

    let matrix_digests: [[u8; 32]; HISTORY_STEP_PACK_LEAF_COUNT] = std::array::from_fn(|index| {
        let start = index * 32;
        body[start..start + 32]
            .try_into()
            .expect("fixed matrix digest width")
    });
    let runtime_parts = HistoryStepRuntimeParts::decode_compact(
        &body[HISTORY_STEP_RUNTIME_METADATA_MATRIX_DIGEST_BYTES..],
    )?;
    let bank = pin_history_step_class_bank(matrix_digests, &runtime_parts)?;
    Ok(HistoryStepRuntimeMetadata {
        bank,
        runtime_parts,
    })
}

#[doc(hidden)]
pub fn history_step_runtime_image_file_name(class: CanonicalHistoryStepClassId) -> &'static str {
    HISTORY_STEP_RUNTIME_IMAGE_FILE_NAMES[class.index()]
}

/// One immutable matrix image paired with the authority minted by the release
/// build after it authenticated the corresponding canonical leaf.
#[derive(Clone, Copy)]
pub struct EmbeddedHistoryStepMatrixLeaf {
    class: CanonicalHistoryStepClassId,
    compressed_runtime_image: &'static [u8],
    runtime_image_bytes: usize,
    build_seal: BuildAuthenticatedFieldR1csSeal,
}

impl EmbeddedHistoryStepMatrixLeaf {
    /// # Safety
    ///
    /// The image, exact decoded length, and seal must be emitted together by
    /// the release build after authenticating the pinned canonical matrix.
    #[doc(hidden)]
    pub const unsafe fn from_release_build(
        class: CanonicalHistoryStepClassId,
        compressed_runtime_image: &'static [u8],
        runtime_image_bytes: usize,
        build_seal: BuildAuthenticatedFieldR1csSeal,
    ) -> Self {
        Self {
            class,
            compressed_runtime_image,
            runtime_image_bytes,
            build_seal,
        }
    }

    pub const fn class(&self) -> CanonicalHistoryStepClassId {
        self.class
    }

    pub const fn compressed_runtime_image(&self) -> &'static [u8] {
        self.compressed_runtime_image
    }

    pub const fn runtime_image_bytes(&self) -> usize {
        self.runtime_image_bytes
    }

    pub const fn build_seal(&self) -> BuildAuthenticatedFieldR1csSeal {
        self.build_seal
    }
}

#[derive(Debug, Error)]
pub enum EmbeddedHistoryStepMatrixError {
    #[error("HistoryStep matrix leaf {index} is not canonical class {index}")]
    ClassOrder { index: usize },
    #[error("HistoryStep matrix leaf {index} is empty")]
    EmptyLeaf { index: usize },
    #[error("HistoryStep matrix class {class} has a non-canonical build shape")]
    Shape { class: usize },
    #[error("HistoryStep matrix class {class} runtime image length overflow")]
    ImageLength { class: usize },
    #[error("HistoryStep matrix class {class} runtime image cannot be decoded: {source}")]
    Compression {
        class: usize,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "HistoryStep matrix class {class} runtime image has {actual} bytes, expected {expected}"
    )]
    DecodedLength {
        class: usize,
        expected: usize,
        actual: usize,
    },
    #[error("HistoryStep matrix class {class} runtime image is invalid: {source}")]
    Matrix {
        class: usize,
        #[source]
        source: FieldR1csArtifactError,
    },
    #[error("HistoryStep compact matrix cache is unavailable")]
    Cache,
}

struct CachedHistoryStepMatrix {
    class: CanonicalHistoryStepClassId,
    matrix: Arc<CompactFieldR1cs>,
}

/// Embedded source for the complete sixteen-class matrix bank. Only two
/// authenticated compact relations are retained by the source at a time.
pub struct EmbeddedHistoryStepMatrixSource {
    leaves: [EmbeddedHistoryStepMatrixLeaf; HISTORY_STEP_PACK_LEAF_COUNT],
    cache: Mutex<VecDeque<CachedHistoryStepMatrix>>,
}

impl EmbeddedHistoryStepMatrixSource {
    /// # Safety
    ///
    /// Every leaf must be the exact immutable image/seal tuple emitted by the
    /// successful release build.  Runtime or filesystem bytes must not enter
    /// this constructor.
    pub unsafe fn from_release_build(
        leaves: [EmbeddedHistoryStepMatrixLeaf; HISTORY_STEP_PACK_LEAF_COUNT],
    ) -> Result<Self, EmbeddedHistoryStepMatrixError> {
        for (index, leaf) in leaves.iter().enumerate() {
            let expected = CanonicalHistoryStepClassId::from_index(index)
                .expect("fixed HistoryStep bank index is canonical");
            if leaf.class != expected {
                return Err(EmbeddedHistoryStepMatrixError::ClassOrder { index });
            }
            if leaf.compressed_runtime_image.is_empty() || leaf.runtime_image_bytes == 0 {
                return Err(EmbeddedHistoryStepMatrixError::EmptyLeaf { index });
            }
            if leaf.build_seal.shape() != canonical_history_step_shape(expected) {
                return Err(EmbeddedHistoryStepMatrixError::Shape { class: index });
            }
        }
        Ok(Self {
            leaves,
            cache: Mutex::new(VecDeque::with_capacity(
                HISTORY_STEP_COMPACT_MATRIX_CACHE_CAPACITY,
            )),
        })
    }

    fn materialize(
        &self,
        class: CanonicalHistoryStepClassId,
    ) -> Result<Arc<CompactFieldR1cs>, EmbeddedHistoryStepMatrixError> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| EmbeddedHistoryStepMatrixError::Cache)?;
        if let Some(position) = cache.iter().position(|entry| entry.class == class) {
            let entry = cache
                .remove(position)
                .expect("located compact HistoryStep cache entry exists");
            let matrix = Arc::clone(&entry.matrix);
            cache.push_back(entry);
            return Ok(matrix);
        }

        let leaf = &self.leaves[class.index()];
        let read_limit = leaf.runtime_image_bytes.checked_add(1).ok_or(
            EmbeddedHistoryStepMatrixError::ImageLength {
                class: class.index(),
            },
        )?;
        let decoder =
            zstd::stream::read::Decoder::new(leaf.compressed_runtime_image).map_err(|source| {
                EmbeddedHistoryStepMatrixError::Compression {
                    class: class.index(),
                    source,
                }
            })?;
        let mut image = Vec::new();
        decoder
            .take(read_limit as u64)
            .read_to_end(&mut image)
            .map_err(|source| EmbeddedHistoryStepMatrixError::Compression {
                class: class.index(),
                source,
            })?;
        if image.len() != leaf.runtime_image_bytes {
            return Err(EmbeddedHistoryStepMatrixError::DecodedLength {
                class: class.index(),
                expected: leaf.runtime_image_bytes,
                actual: image.len(),
            });
        }
        // SAFETY: the private source can be constructed only from tuples
        // emitted by the release build, which produced this packed image from
        // the exact canonical relation authenticated under `build_seal`.
        let compact = Arc::new(
            unsafe {
                CompactFieldR1cs::open_build_authenticated_packed_image(&image, leaf.build_seal)
            }
            .map_err(|source| EmbeddedHistoryStepMatrixError::Matrix {
                class: class.index(),
                source,
            })?,
        );
        cache.push_back(CachedHistoryStepMatrix {
            class,
            matrix: Arc::clone(&compact),
        });
        while cache.len() > HISTORY_STEP_COMPACT_MATRIX_CACHE_CAPACITY {
            cache.pop_front();
        }
        Ok(compact)
    }
}

impl HistoryStepMatrixSource for EmbeddedHistoryStepMatrixSource {
    fn load(
        &self,
        class: CanonicalHistoryStepClassId,
    ) -> Result<HistoryStepMatrixLease, HistoryStepMatrixSourceError> {
        self.materialize(class)
            .map(HistoryStepMatrixLease::Compact)
            .map_err(|_| HistoryStepMatrixSourceError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_matrix_names_are_dense_and_unique() {
        let mut canonical = std::collections::BTreeSet::new();
        let mut runtime = std::collections::BTreeSet::new();
        for index in 0..HISTORY_STEP_PACK_LEAF_COUNT {
            let class = CanonicalHistoryStepClassId::from_index(index).unwrap();
            let name = history_step_matrix_file_name(class);
            assert_eq!(name, format!("history-step-c{index:02}.field-r1cs.zst"));
            assert!(canonical.insert(name));
            let runtime_name = history_step_runtime_image_file_name(class);
            assert_eq!(
                runtime_name,
                format!("history-step-c{index:02}.packed-r1cs.zst")
            );
            assert!(runtime.insert(runtime_name));
        }
    }

    #[test]
    fn runtime_metadata_checks_digest_and_release_pin_before_materialization() {
        let mut body = vec![0u8; HISTORY_STEP_RUNTIME_METADATA_MATRIX_DIGEST_BYTES + 1];
        body[HISTORY_STEP_RUNTIME_METADATA_MATRIX_DIGEST_BYTES] =
            noid_recursive::HISTORY_STEP_RUNTIME_PARTS_COMPACT_VERSION;
        let encoded = frame_history_step_runtime_metadata(&body);
        let body_start = HISTORY_STEP_RUNTIME_METADATA_HEADER_BYTES;
        let body_end = encoded.len() - HISTORY_STEP_RUNTIME_METADATA_TRAILER_BYTES;
        let digest = poseidon2b_hash_byte_slices(
            HISTORY_STEP_RUNTIME_METADATA_DIGEST_DOMAIN,
            &[&encoded[body_start..body_end]],
        );
        assert!(matches!(
            decode_history_step_runtime_metadata_pinned(&encoded, [0xA5; 32]),
            Err(HistoryStepRuntimeMetadataError::ReleasePin)
        ));

        let mut tampered = encoded;
        tampered[body_start] ^= 1;
        assert!(matches!(
            decode_history_step_runtime_metadata_pinned(&tampered, digest),
            Err(HistoryStepRuntimeMetadataError::Digest)
        ));
    }
}
