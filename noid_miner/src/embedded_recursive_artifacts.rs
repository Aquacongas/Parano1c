// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Executable-embedded selected-recursive registry and matrix bank.
//!
//! The production daemon supplies immutable `include_bytes!` slices. The
//! release build authenticates the registry and all nine canonical matrix
//! leaves, converts them to fixed-width runtime images, and embeds those
//! images. Runtime only decompresses and copies trusted ready arrays. A
//! materialized matrix is shared between Link proving and terminal
//! verification without canonical parsing, repacking, a filesystem trust
//! record, or a second semantic scan.

use std::array;
use std::io::Cursor;
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;

use noid_ivc_core::field_r1cs::{
    BuildAuthenticatedFieldR1csSeal, CompactFieldR1cs, FieldR1csArtifactError,
};
use noid_ivc_core::matrix_claim::{
    AuthenticatedMatrixClaimEvaluations, FreshLincheckClaim, MatrixAccClaim, MatrixClaimEvaluator,
};
use noid_ivc_core::proof::FieldShape;
use noid_recursive::class_registry::SelectedRecursiveClassRegistryError;
use noid_recursive::{
    SelectedHistoryMatrixFamily, SelectedHistoryMatrixLease, SelectedHistoryMatrixRequest,
    SelectedHistoryMatrixSource,
};
use thiserror::Error;

use crate::recursive_class_registry_store::{
    LoadedSelectedRecursiveClassRegistry, LoadedSelectedRecursiveTerminalRegistry,
    PinnedSelectedRecursiveClassRegistrySource,
};
use crate::recursive_matrix_store::SelectedRecursiveMatrixArtifactIdentity;
use crate::recursive_prover::{
    LoadedSelectedRecursiveMatrix, SelectedRecursiveMatrixKind, SelectedRecursiveMatrixRequest,
    SelectedRecursiveMatrixSource, SelectedRecursiveTier,
};

pub const EMBEDDED_SELECTED_RECURSIVE_LEAF_COUNT: usize = 9;
const MIB: usize = 1024 * 1024;

/// Natural matrix lifetime selected from the node role.
///
/// A relay owns no matrix after its current verification leases disappear.
/// Proving roles keep each of the fixed nine embedded matrices after first
/// use. There is no byte budget, LRU, eviction threshold, or fallback path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmbeddedSelectedRecursiveRetention {
    Ephemeral,
    RetainAll,
}

#[derive(Debug, Error)]
pub enum EmbeddedSelectedRecursiveArtifactError {
    #[error("embedded selected-recursive registry is empty")]
    EmptyRegistry,
    #[error("embedded selected-recursive matrix leaf {index} is empty")]
    EmptyMatrixLeaf { index: usize },
    #[error("embedded selected-recursive matrix leaf {index} has non-canonical kind {actual:?}")]
    LeafKindMismatch {
        index: usize,
        actual: SelectedRecursiveMatrixKind,
    },
    #[error("embedded selected-recursive registry rejected: {0}")]
    Registry(#[from] SelectedRecursiveClassRegistryError),
    #[error(
        "embedded selected-recursive registry was requested with a different release identity"
    )]
    RegistryIdentityMismatch,
    #[error("embedded selected-recursive registry residency mutex is poisoned")]
    RegistryResidencyPoisoned,
    #[error("unsupported embedded selected-recursive matrix tier {tier}")]
    UnsupportedTier { tier: usize },
    #[error("embedded selected-recursive matrix residency mutex is poisoned")]
    CachePoisoned,
    #[error("embedded selected-recursive matrix leaf {index} was requested with two identities")]
    CachedIdentityMismatch { index: usize },
    #[error("embedded selected-recursive build seal {index} does not match the requested matrix identity")]
    BuildSealIdentityMismatch { index: usize },
    #[error("cannot open embedded selected-recursive runtime image: {0}")]
    Zstd(#[source] std::io::Error),
    #[error("embedded selected-recursive matrix rejected: {0}")]
    Matrix(#[from] FieldR1csArtifactError),
}

struct EmbeddedSelectedRecursiveRegistryBank {
    bytes: &'static [u8],
    digest: [u8; 32],
    residency: Mutex<EmbeddedSelectedRecursiveRegistryResidency>,
}

struct EmbeddedSelectedRecursiveRegistryResidency {
    full: Option<LoadedSelectedRecursiveClassRegistry>,
    terminal: Option<LoadedSelectedRecursiveTerminalRegistry>,
}

/// Shared runtime materialization of registry bytes authenticated by the
/// release build. Full and terminal views are each built at most once; when a
/// proving role already owns the full registry, terminal verification borrows
/// that same authority instead of rebuilding a relay-only copy.
#[derive(Clone)]
pub struct EmbeddedSelectedRecursiveClassRegistrySource {
    bank: Arc<EmbeddedSelectedRecursiveRegistryBank>,
}

impl EmbeddedSelectedRecursiveClassRegistrySource {
    fn new(bytes: &'static [u8], digest: [u8; 32]) -> Self {
        Self {
            bank: Arc::new(EmbeddedSelectedRecursiveRegistryBank {
                bytes,
                digest,
                residency: Mutex::new(EmbeddedSelectedRecursiveRegistryResidency {
                    full: None,
                    terminal: None,
                }),
            }),
        }
    }

    fn require_identity(
        &self,
        expected_registry_digest: [u8; 32],
    ) -> Result<(), EmbeddedSelectedRecursiveArtifactError> {
        if expected_registry_digest != self.bank.digest {
            return Err(EmbeddedSelectedRecursiveArtifactError::RegistryIdentityMismatch);
        }
        Ok(())
    }

    pub fn load_terminal_pinned(
        &self,
        expected_registry_digest: [u8; 32],
    ) -> Result<LoadedSelectedRecursiveTerminalRegistry, EmbeddedSelectedRecursiveArtifactError>
    {
        self.require_identity(expected_registry_digest)?;
        let mut residency = self
            .bank
            .residency
            .lock()
            .map_err(|_| EmbeddedSelectedRecursiveArtifactError::RegistryResidencyPoisoned)?;
        if let Some(full) = residency.full.as_ref() {
            return Ok(LoadedSelectedRecursiveTerminalRegistry::from_full(full));
        }
        if let Some(terminal) = residency.terminal.as_ref() {
            return Ok(terminal.clone());
        }
        // SAFETY: this bank is constructed only by the unsafe embedded
        // release authority after build.rs accepted the exact bytes with the
        // terminal pinned decoder.
        let loaded = unsafe {
            LoadedSelectedRecursiveTerminalRegistry::decode_build_authenticated_bytes(
                self.bank.bytes,
            )?
        };
        residency.terminal = Some(loaded.clone());
        Ok(loaded)
    }
}

impl PinnedSelectedRecursiveClassRegistrySource for EmbeddedSelectedRecursiveClassRegistrySource {
    type Error = EmbeddedSelectedRecursiveArtifactError;

    fn load_pinned_registry(
        &self,
        expected_registry_digest: [u8; 32],
    ) -> Result<LoadedSelectedRecursiveClassRegistry, Self::Error> {
        self.require_identity(expected_registry_digest)?;
        let mut residency = self
            .bank
            .residency
            .lock()
            .map_err(|_| EmbeddedSelectedRecursiveArtifactError::RegistryResidencyPoisoned)?;
        if let Some(full) = residency.full.as_ref() {
            return Ok(full.clone());
        }
        // SAFETY: this bank is constructed only by the unsafe embedded
        // release authority after build.rs accepted the exact bytes with the
        // full pinned decoder.
        let loaded = unsafe {
            LoadedSelectedRecursiveClassRegistry::decode_build_authenticated_bytes(self.bank.bytes)?
        };
        residency.full = Some(loaded.clone());
        // The full authority supplies the same terminal view, so a previous
        // relay-only materialization is no longer needed in a proving role.
        residency.terminal = None;
        Ok(loaded)
    }
}

struct MatrixSlot {
    shape: FieldShape,
    digest: [u8; 32],
    active: Weak<CompactFieldR1cs>,
    _retained: Option<Arc<CompactFieldR1cs>>,
}

struct MatrixResidency {
    entries: [Option<MatrixSlot>; EMBEDDED_SELECTED_RECURSIVE_LEAF_COUNT],
}

impl MatrixResidency {
    fn new() -> Self {
        Self {
            entries: array::from_fn(|_| None),
        }
    }
}

struct EmbeddedSelectedRecursiveMatrixBank {
    compressed_runtime_images: [&'static [u8]; EMBEDDED_SELECTED_RECURSIVE_LEAF_COUNT],
    build_seals: [BuildAuthenticatedFieldR1csSeal; EMBEDDED_SELECTED_RECURSIVE_LEAF_COUNT],
    retention: EmbeddedSelectedRecursiveRetention,
    residency: Mutex<MatrixResidency>,
}

impl EmbeddedSelectedRecursiveMatrixBank {
    fn load(
        &self,
        kind: SelectedRecursiveMatrixKind,
        shape: FieldShape,
        digest: [u8; 32],
    ) -> Result<Arc<CompactFieldR1cs>, EmbeddedSelectedRecursiveArtifactError> {
        let index = matrix_leaf_index(kind);
        // Decode is deliberately inside this short-lived global bank lock so
        // Link and Verify cannot duplicate one first materialization. No
        // proof or matrix evaluation runs under the lock.
        let mut residency = self
            .residency
            .lock()
            .map_err(|_| EmbeddedSelectedRecursiveArtifactError::CachePoisoned)?;
        if let Some(entry) = residency.entries[index].as_ref() {
            if entry.shape == shape && entry.digest == digest {
                if let Some(matrix) = entry.active.upgrade() {
                    return Ok(matrix);
                }
            } else {
                // One embedded leaf has one immutable protocol identity. A
                // conflicting request cannot replace an established slot.
                return Err(
                    EmbeddedSelectedRecursiveArtifactError::CachedIdentityMismatch { index },
                );
            }
        }

        let load_started = Instant::now();
        let decompress_started = Instant::now();
        let decoded = decompress_embedded_runtime_image(self.compressed_runtime_images[index])?;
        let decompress_ms = decompress_started.elapsed().as_millis() as u64;
        let seal = self.build_seals[index];
        if seal.shape() != shape || seal.statement_digest() != digest {
            return Err(
                EmbeddedSelectedRecursiveArtifactError::BuildSealIdentityMismatch { index },
            );
        }
        // SAFETY: `build_seals` can enter this private bank only through the
        // unsafe release-build constructor, which requires the exact staged
        // `include_bytes!` leaf paired by `noid_node/build.rs`.
        let open_started = Instant::now();
        let matrix = Arc::new(unsafe {
            CompactFieldR1cs::open_build_authenticated_packed_image(&decoded, seal)?
        });
        let open_ms = open_started.elapsed().as_millis() as u64;
        let canonical_bytes = matrix.encoded_len();
        let artifact_bytes = matrix.resident_artifact_len();
        let payload_bytes = matrix.resident_heap_payload_len();
        // Arc stores two usize counters alongside T. This is telemetry only:
        // residency follows role and ownership, never an estimated byte cap.
        let resident_bytes = payload_bytes
            .saturating_add(std::mem::size_of::<CompactFieldR1cs>())
            .saturating_add(2 * std::mem::size_of::<usize>());
        let retained = matches!(
            self.retention,
            EmbeddedSelectedRecursiveRetention::RetainAll
        );
        residency.entries[index] = Some(MatrixSlot {
            shape,
            digest,
            active: Arc::downgrade(&matrix),
            _retained: retained.then(|| Arc::clone(&matrix)),
        });
        tracing::info!(
            ?kind,
            ?self.retention,
            retained,
            matrix_storage = matrix.storage_name(),
            matrix_authentication = matrix.authentication_name(),
            decompress_ms,
            open_ms,
            total_ms = load_started.elapsed().as_millis() as u64,
            canonical_bytes,
            artifact_bytes,
            payload_bytes,
            resident_bytes,
            canonical_mib = canonical_bytes / MIB,
            artifact_mib = artifact_bytes / MIB,
            payload_mib = payload_bytes / MIB,
            resident_mib = resident_bytes / MIB,
            "build-prepared embedded selected-recursive matrix loaded"
        );
        Ok(matrix)
    }
}

/// Cloneable matrix-source handle over one shared authenticated bank.
#[derive(Clone)]
pub struct EmbeddedSelectedRecursiveMatrixSource {
    bank: Arc<EmbeddedSelectedRecursiveMatrixBank>,
}

impl EmbeddedSelectedRecursiveMatrixSource {
    pub fn retention(&self) -> EmbeddedSelectedRecursiveRetention {
        self.bank.retention
    }

    /// Materialize and retain one compact matrix before the proving pipeline
    /// starts. The identity comes from the build-authenticated registry; this
    /// operation does not materialize the much larger CSR representation.
    pub fn prewarm_compact(
        &self,
        identity: SelectedRecursiveMatrixArtifactIdentity,
    ) -> Result<(), EmbeddedSelectedRecursiveArtifactError> {
        drop(self.bank.load(
            identity.kind(),
            identity.shape(),
            identity.statement_digest(),
        )?);
        Ok(())
    }
}

impl SelectedRecursiveMatrixSource for EmbeddedSelectedRecursiveMatrixSource {
    type Error = EmbeddedSelectedRecursiveArtifactError;

    fn load_compact_matrix(
        &mut self,
        request: SelectedRecursiveMatrixRequest,
    ) -> Result<Option<Arc<CompactFieldR1cs>>, Self::Error> {
        self.bank
            .load(request.kind(), request.shape(), request.statement_digest())
            .map(Some)
    }

    fn load_matrix(
        &mut self,
        request: SelectedRecursiveMatrixRequest,
    ) -> Result<LoadedSelectedRecursiveMatrix, Self::Error> {
        let matrix = self
            .bank
            .load(request.kind(), request.shape(), request.statement_digest())?;
        // Link folding still consumes the mature CSR kernel. Decode it from
        // the already-authenticated immutable bytes without rehashing, and
        // drop it after this one matrix phase. The compact bank remains the
        // sole resident authority and terminal verification reads it directly.
        let resident = matrix.decode_resident_authenticated()?;
        Ok(LoadedSelectedRecursiveMatrix::from_authenticated_owned(
            resident,
            request.statement_digest(),
        ))
    }
}

/// Terminal evaluator borrowing the same immutable matrix allocation as the
/// Link lane. The authenticated digest lives inside the opaque compact value
/// minted by the bank's full canonical decode; no parallel metadata can drift.
pub struct EmbeddedSelectedRecursiveMatrixEvaluator {
    matrix: Arc<CompactFieldR1cs>,
}

impl MatrixClaimEvaluator for EmbeddedSelectedRecursiveMatrixEvaluator {
    fn field_shape(&self) -> FieldShape {
        self.matrix.shape()
    }

    fn evaluate_matrix_claims(
        &mut self,
        fresh: Option<&FreshLincheckClaim>,
        accumulated: Option<&MatrixAccClaim>,
    ) -> Result<AuthenticatedMatrixClaimEvaluations, FieldR1csArtifactError> {
        self.matrix
            .evaluate_matrix_claims_authenticated(fresh, accumulated)
    }
}

impl SelectedHistoryMatrixLease for EmbeddedSelectedRecursiveMatrixEvaluator {
    fn evaluator(&mut self) -> &mut dyn MatrixClaimEvaluator {
        self
    }
}

impl SelectedHistoryMatrixSource for EmbeddedSelectedRecursiveMatrixSource {
    type Lease = EmbeddedSelectedRecursiveMatrixEvaluator;
    type Error = EmbeddedSelectedRecursiveArtifactError;

    fn load_matrix(
        &mut self,
        request: SelectedHistoryMatrixRequest,
    ) -> Result<Self::Lease, Self::Error> {
        let kind = history_matrix_kind(request.family, request.tier)?;
        let matrix = self
            .bank
            .load(kind, request.shape(), request.statement_digest())?;
        Ok(EmbeddedSelectedRecursiveMatrixEvaluator { matrix })
    }
}

/// One self-contained release authority. Cloning either source never clones
/// registry bytes, compressed runtime images, or decoded matrices.
pub struct EmbeddedSelectedRecursiveArtifacts {
    registry: EmbeddedSelectedRecursiveClassRegistrySource,
    matrices: EmbeddedSelectedRecursiveMatrixSource,
}

impl EmbeddedSelectedRecursiveArtifacts {
    /// Construct from immutable bytes already authenticated and staged by
    /// `build.rs` for `include_bytes!`.
    ///
    /// The release build checked the canonical compressed pins, decoded the
    /// pinned registry, fully structural-Poseidon-authenticated all nine
    /// canonical leaves, and emitted their runtime-ready packed images.
    /// Runtime therefore only decompresses and copies fixed-width arrays.
    /// Arbitrary runtime bytes cannot enter this path because the opaque seals
    /// and images are created together only in generated code.
    /// # Safety
    ///
    /// Every leaf and seal must be the exact pair emitted together by the
    /// successful release build. Callers must not construct this authority
    /// from runtime or filesystem bytes.
    pub unsafe fn from_build_authenticated(
        registry: &'static [u8],
        registry_digest: [u8; 32],
        leaves: [(
            SelectedRecursiveMatrixKind,
            &'static [u8],
            BuildAuthenticatedFieldR1csSeal,
        ); EMBEDDED_SELECTED_RECURSIVE_LEAF_COUNT],
        retention: EmbeddedSelectedRecursiveRetention,
    ) -> Result<Self, EmbeddedSelectedRecursiveArtifactError> {
        let build_seals = leaves.map(|(_, _, seal)| seal);
        let runtime_images = leaves.map(|(kind, bytes, _)| (kind, bytes));
        Self::construct(
            registry,
            registry_digest,
            runtime_images,
            build_seals,
            retention,
        )
    }

    fn construct(
        registry: &'static [u8],
        registry_digest: [u8; 32],
        leaves: [(SelectedRecursiveMatrixKind, &'static [u8]);
            EMBEDDED_SELECTED_RECURSIVE_LEAF_COUNT],
        build_seals: [BuildAuthenticatedFieldR1csSeal; EMBEDDED_SELECTED_RECURSIVE_LEAF_COUNT],
        retention: EmbeddedSelectedRecursiveRetention,
    ) -> Result<Self, EmbeddedSelectedRecursiveArtifactError> {
        if registry.is_empty() {
            return Err(EmbeddedSelectedRecursiveArtifactError::EmptyRegistry);
        }
        for (index, (kind, leaf)) in leaves.iter().enumerate() {
            if matrix_leaf_index(*kind) != index {
                return Err(EmbeddedSelectedRecursiveArtifactError::LeafKindMismatch {
                    index,
                    actual: *kind,
                });
            }
            if leaf.is_empty() {
                return Err(EmbeddedSelectedRecursiveArtifactError::EmptyMatrixLeaf { index });
            }
        }
        let compressed_runtime_images = leaves.map(|(_, bytes)| bytes);
        let bank = EmbeddedSelectedRecursiveMatrixBank {
            compressed_runtime_images,
            build_seals,
            retention,
            residency: Mutex::new(MatrixResidency::new()),
        };
        Ok(Self {
            registry: EmbeddedSelectedRecursiveClassRegistrySource::new(registry, registry_digest),
            matrices: EmbeddedSelectedRecursiveMatrixSource {
                bank: Arc::new(bank),
            },
        })
    }

    pub fn registry_source(&self) -> EmbeddedSelectedRecursiveClassRegistrySource {
        self.registry.clone()
    }

    pub fn matrix_source(&self) -> EmbeddedSelectedRecursiveMatrixSource {
        self.matrices.clone()
    }
}

fn matrix_leaf_index(kind: SelectedRecursiveMatrixKind) -> usize {
    match kind {
        SelectedRecursiveMatrixKind::GenesisLink => 0,
        SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B8) => 1,
        SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B32) => 2,
        SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B64) => 3,
        SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B255) => 4,
        SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B8) => 5,
        SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B32) => 6,
        SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B64) => 7,
        SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B255) => 8,
    }
}

fn decompress_embedded_runtime_image(
    compressed: &[u8],
) -> Result<Box<[u8]>, EmbeddedSelectedRecursiveArtifactError> {
    zstd::stream::decode_all(Cursor::new(compressed))
        .map(Vec::into_boxed_slice)
        .map_err(EmbeddedSelectedRecursiveArtifactError::Zstd)
}

fn history_matrix_kind(
    family: SelectedHistoryMatrixFamily,
    tier: usize,
) -> Result<SelectedRecursiveMatrixKind, EmbeddedSelectedRecursiveArtifactError> {
    let tier = match tier {
        8 => SelectedRecursiveTier::B8,
        32 => SelectedRecursiveTier::B32,
        64 => SelectedRecursiveTier::B64,
        255 => SelectedRecursiveTier::B255,
        _ => return Err(EmbeddedSelectedRecursiveArtifactError::UnsupportedTier { tier }),
    };
    Ok(match family {
        SelectedHistoryMatrixFamily::Link => SelectedRecursiveMatrixKind::PreviousLink(tier),
        SelectedHistoryMatrixFamily::Block => SelectedRecursiveMatrixKind::CurrentBlock(tier),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANONICAL_MATRIX_KINDS: [SelectedRecursiveMatrixKind;
        EMBEDDED_SELECTED_RECURSIVE_LEAF_COUNT] = [
        SelectedRecursiveMatrixKind::GenesisLink,
        SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B8),
        SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B32),
        SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B64),
        SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B255),
        SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B8),
        SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B32),
        SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B64),
        SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B255),
    ];

    fn placeholder_build_leaves() -> [(
        SelectedRecursiveMatrixKind,
        &'static [u8],
        BuildAuthenticatedFieldR1csSeal,
    ); EMBEDDED_SELECTED_RECURSIVE_LEAF_COUNT] {
        let seal = unsafe {
            BuildAuthenticatedFieldR1csSeal::from_release_build(
                FieldShape {
                    m: 8,
                    k_log: 8,
                    k_skip: 0,
                    const_pin: None,
                },
                [0u8; 32],
                4,
            )
        };
        CANONICAL_MATRIX_KINDS.map(|kind| (kind, b"leaf" as &'static [u8], seal))
    }

    fn compact_fixture(seed: u64) -> Arc<CompactFieldR1cs> {
        let (r1cs, _) = noid_ivc_core::field_r1cs::synthetic_satisfiable(8, 8, seed);
        let shape = FieldShape::of(&r1cs);
        let digest = r1cs.structural_statement_digest();
        let mut artifact = Vec::new();
        r1cs.write_artifact(&mut artifact).unwrap();
        Arc::new(CompactFieldR1cs::open(artifact.into_boxed_slice(), shape, digest).unwrap())
    }

    fn fixture_bank(
        seed: u64,
        retention: EmbeddedSelectedRecursiveRetention,
    ) -> (EmbeddedSelectedRecursiveMatrixBank, FieldShape, [u8; 32]) {
        let compact = compact_fixture(seed);
        let shape = compact.shape();
        let digest = compact.statement_digest();
        let canonical = compact.artifact_bytes().into_owned();
        let seal = unsafe {
            BuildAuthenticatedFieldR1csSeal::from_release_build(shape, digest, canonical.len())
        };
        let packed = CompactFieldR1cs::open_packed(canonical.into_boxed_slice(), shape, digest)
            .expect("fixture packs");
        let runtime_image = packed
            .encode_startup_packed_image()
            .expect("fixture runtime image encodes");
        let compressed = zstd::stream::encode_all(Cursor::new(runtime_image.as_ref()), 1)
            .expect("fixture compresses");
        let compressed: &'static [u8] = Box::leak(compressed.into_boxed_slice());
        (
            EmbeddedSelectedRecursiveMatrixBank {
                compressed_runtime_images: [compressed; EMBEDDED_SELECTED_RECURSIVE_LEAF_COUNT],
                build_seals: [seal; EMBEDDED_SELECTED_RECURSIVE_LEAF_COUNT],
                retention,
                residency: Mutex::new(MatrixResidency::new()),
            },
            shape,
            digest,
        )
    }

    #[test]
    fn canonical_leaf_order_is_total_and_distinct() {
        let mut seen = [false; EMBEDDED_SELECTED_RECURSIVE_LEAF_COUNT];
        for kind in CANONICAL_MATRIX_KINDS {
            let index = matrix_leaf_index(kind);
            assert!(!seen[index]);
            seen[index] = true;
        }
        assert!(seen.into_iter().all(|value| value));
    }

    #[test]
    fn build_authenticated_constructor_preserves_structural_input_checks() {
        assert!(matches!(
            unsafe {
                EmbeddedSelectedRecursiveArtifacts::from_build_authenticated(
                    b"",
                    [0u8; 32],
                    placeholder_build_leaves(),
                    EmbeddedSelectedRecursiveRetention::Ephemeral,
                )
            },
            Err(EmbeddedSelectedRecursiveArtifactError::EmptyRegistry)
        ));

        let mut noncanonical = placeholder_build_leaves();
        noncanonical.swap(0, 1);
        assert!(matches!(
            unsafe {
                EmbeddedSelectedRecursiveArtifacts::from_build_authenticated(
                    b"registry",
                    [0u8; 32],
                    noncanonical,
                    EmbeddedSelectedRecursiveRetention::Ephemeral,
                )
            },
            Err(EmbeddedSelectedRecursiveArtifactError::LeafKindMismatch { index: 0, .. })
        ));

        let mut empty = placeholder_build_leaves();
        empty[4].1 = b"";
        assert!(matches!(
            unsafe {
                EmbeddedSelectedRecursiveArtifacts::from_build_authenticated(
                    b"registry",
                    [0u8; 32],
                    empty,
                    EmbeddedSelectedRecursiveRetention::Ephemeral,
                )
            },
            Err(EmbeddedSelectedRecursiveArtifactError::EmptyMatrixLeaf { index: 4 })
        ));

        assert!(unsafe {
            EmbeddedSelectedRecursiveArtifacts::from_build_authenticated(
                b"registry",
                [0u8; 32],
                placeholder_build_leaves(),
                EmbeddedSelectedRecursiveRetention::RetainAll,
            )
        }
        .is_ok());
    }

    #[test]
    fn history_requests_never_map_to_genesis() {
        for (tier, expected) in [
            (8, SelectedRecursiveTier::B8),
            (32, SelectedRecursiveTier::B32),
            (64, SelectedRecursiveTier::B64),
            (255, SelectedRecursiveTier::B255),
        ] {
            assert_eq!(
                history_matrix_kind(SelectedHistoryMatrixFamily::Link, tier).unwrap(),
                SelectedRecursiveMatrixKind::PreviousLink(expected)
            );
            assert_eq!(
                history_matrix_kind(SelectedHistoryMatrixFamily::Block, tier).unwrap(),
                SelectedRecursiveMatrixKind::CurrentBlock(expected)
            );
        }
        assert!(matches!(
            history_matrix_kind(SelectedHistoryMatrixFamily::Link, 9),
            Err(EmbeddedSelectedRecursiveArtifactError::UnsupportedTier { tier: 9 })
        ));
    }

    #[test]
    fn embedded_runtime_decompression_is_exactly_the_trusted_frame_payload() {
        let payload = b"trusted build output";
        let compressed = zstd::stream::encode_all(Cursor::new(payload), 1).unwrap();
        assert_eq!(
            decompress_embedded_runtime_image(&compressed)
                .unwrap()
                .as_ref(),
            payload
        );
    }

    #[test]
    fn established_leaf_rejects_a_conflicting_identity() {
        let (bank, shape, digest) =
            fixture_bank(0x1DE7_1717, EmbeddedSelectedRecursiveRetention::Ephemeral);
        drop(
            bank.load(SelectedRecursiveMatrixKind::GenesisLink, shape, digest)
                .expect("canonical identity loads"),
        );

        let mut conflicting = digest;
        conflicting[0] ^= 1;
        assert!(matches!(
            bank.load(SelectedRecursiveMatrixKind::GenesisLink, shape, conflicting,),
            Err(EmbeddedSelectedRecursiveArtifactError::CachedIdentityMismatch { index: 0 })
        ));
        let residency = bank.residency.lock().unwrap();
        assert_eq!(
            residency.entries[0].as_ref().map(|entry| entry.digest),
            Some(digest)
        );
    }

    #[test]
    fn embedded_b8_has_only_its_exact_packed_payload() {
        let (bank, shape, digest) =
            fixture_bank(0xB8A8_CACE, EmbeddedSelectedRecursiveRetention::Ephemeral);
        let loaded = bank
            .load(
                SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B8),
                shape,
                digest,
            )
            .expect("B8 leaf loads");
        assert!(loaded.is_packed());
        assert_eq!(loaded.resident_artifact_len(), 0);
        let payload_before_export = loaded.resident_heap_payload_len();
        drop(loaded.artifact_bytes());
        assert_eq!(loaded.resident_heap_payload_len(), payload_before_export);
        let residency = bank.residency.lock().unwrap();
        let slot = residency.entries[1].as_ref().unwrap();
        assert!(slot.active.upgrade().is_some());
        assert!(slot._retained.is_none());
    }

    #[test]
    fn build_sealed_leaf_skips_runtime_scan_but_preserves_request_identity() {
        let (bank, shape, digest) =
            fixture_bank(0x5EA1_B8A8, EmbeddedSelectedRecursiveRetention::RetainAll);
        let loaded = bank
            .load(
                SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B8),
                shape,
                digest,
            )
            .expect("build-sealed B8 leaf loads");
        assert_eq!(loaded.authentication_name(), "release-build-sealed");
        assert!(loaded.is_packed());

        let mut wrong_digest = digest;
        wrong_digest[0] ^= 1;
        assert!(matches!(
            bank.load(
                SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B8),
                shape,
                wrong_digest,
            ),
            Err(EmbeddedSelectedRecursiveArtifactError::BuildSealIdentityMismatch { index: 5 })
        ));
    }

    #[test]
    fn ephemeral_reuses_only_an_active_matrix_and_releases_the_last_lease() {
        let (bank, shape, digest) =
            fixture_bank(0x1EA5_ED00, EmbeddedSelectedRecursiveRetention::Ephemeral);
        let kind = SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B8);
        let first = bank.load(kind, shape, digest).expect("first lease");
        let second = bank.load(kind, shape, digest).expect("shared lease");
        assert!(Arc::ptr_eq(&first, &second));
        let released = Arc::downgrade(&first);
        drop(second);
        drop(first);
        assert!(released.upgrade().is_none());
        let residency = bank.residency.lock().unwrap();
        let slot = residency.entries[1].as_ref().unwrap();
        assert!(slot.active.upgrade().is_none());
        assert!(slot._retained.is_none());
    }

    #[test]
    fn retain_all_keeps_the_fixed_matrix_without_a_capacity_gate() {
        let (bank, shape, digest) =
            fixture_bank(0xA11C_A11C, EmbeddedSelectedRecursiveRetention::RetainAll);
        let kind = SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B8);
        let first = bank.load(kind, shape, digest).expect("first lease");
        let retained = Arc::downgrade(&first);
        drop(first);
        let retained = retained.upgrade().expect("proving role retains matrix");
        let again = bank.load(kind, shape, digest).expect("retained lease");
        assert!(Arc::ptr_eq(&retained, &again));
        let residency = bank.residency.lock().unwrap();
        assert!(residency.entries[1].as_ref().unwrap()._retained.is_some());
    }
}
