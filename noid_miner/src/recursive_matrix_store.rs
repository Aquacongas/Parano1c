// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Bounded local storage for the canonical selected-recursive matrices.
//!
//! The history prover requests matrices by frozen shape and structural digest.
//! This source maps that request to one of nine fixed local paths, streams the
//! artifact through the canonical `FieldR1cs` codec, and holds a one-matrix
//! lease until the returned value is dropped. It never caches a matrix or a
//! complete serialized artifact.

use std::fs::{self, File, Metadata};
use std::io::{self, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use noid_ivc_core::field_r1cs::{
    FieldR1cs, FieldR1csArtifactError, PreflightSeekableFieldR1csArtifact,
};
use noid_ivc_core::matrix_claim::{
    AuthenticatedMatrixClaimEvaluations, FreshLincheckClaim, MatrixAccClaim, MatrixClaimEvaluator,
};
use noid_ivc_core::proof::FieldShape;
use thiserror::Error;

#[cfg(unix)]
use crate::anchored_artifact_fs;
use crate::recursive_prover::{
    LoadedSelectedRecursiveMatrix, SelectedRecursiveMatrixKind, SelectedRecursiveMatrixRequest,
    SelectedRecursiveMatrixSource, SelectedRecursiveTier,
};

/// Maximum accepted size of one canonical matrix artifact on disk.
///
/// The decoder additionally clamps this to the platform `usize` address
/// space. The cap applies before opening/allocating matrix vectors and the
/// source admits only one decoded matrix at a time.
pub const MAX_SELECTED_RECURSIVE_MATRIX_ARTIFACT_BYTES: u64 = 6 * 1024 * 1024 * 1024;

const ARTIFACT_VERSION_DIRECTORY: &str = "v1";
const ARTIFACT_READ_BUFFER_BYTES: usize = 64 * 1024;
const TEMP_CREATE_ATTEMPTS: usize = 32;
static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(0);
static PROCESS_MATRIX_RESIDENT: OnceLock<Arc<AtomicBool>> = OnceLock::new();

fn process_matrix_residency() -> Arc<AtomicBool> {
    Arc::clone(PROCESS_MATRIX_RESIDENT.get_or_init(|| Arc::new(AtomicBool::new(false))))
}

/// Declared identity used by the offline matrix materializer/exporter.
///
/// Runtime proof authority still comes only from the coordinator's private
/// [`SelectedRecursiveMatrixRequest`]. Exporting a matrix under a wrong local
/// identity is rejected before the target path is mutated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectedRecursiveMatrixArtifactIdentity {
    kind: SelectedRecursiveMatrixKind,
    shape: FieldShape,
    statement_digest: [u8; 32],
}

impl SelectedRecursiveMatrixArtifactIdentity {
    pub const fn new(
        kind: SelectedRecursiveMatrixKind,
        shape: FieldShape,
        statement_digest: [u8; 32],
    ) -> Self {
        Self {
            kind,
            shape,
            statement_digest,
        }
    }

    pub const fn kind(&self) -> SelectedRecursiveMatrixKind {
        self.kind
    }

    pub const fn shape(&self) -> FieldShape {
        self.shape
    }

    pub const fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }
}

impl From<SelectedRecursiveMatrixRequest> for SelectedRecursiveMatrixArtifactIdentity {
    fn from(request: SelectedRecursiveMatrixRequest) -> Self {
        Self::new(request.kind(), request.shape(), request.statement_digest())
    }
}

/// Fixed path below a local selected-recursive matrix root.
pub fn selected_recursive_matrix_relative_path(kind: SelectedRecursiveMatrixKind) -> &'static Path {
    let path = match kind {
        SelectedRecursiveMatrixKind::GenesisLink => "v1/genesis-link.field-r1cs",
        SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B8) => {
            "v1/link-b8.field-r1cs"
        }
        SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B32) => {
            "v1/link-b32.field-r1cs"
        }
        SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B64) => {
            "v1/link-b64.field-r1cs"
        }
        SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B255) => {
            "v1/link-b255.field-r1cs"
        }
        SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B8) => {
            "v1/block-b8.field-r1cs"
        }
        SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B32) => {
            "v1/block-b32.field-r1cs"
        }
        SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B64) => {
            "v1/block-b64.field-r1cs"
        }
        SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B255) => {
            "v1/block-b255.field-r1cs"
        }
    };
    Path::new(path)
}

/// Fail-closed local matrix artifact error.
#[derive(Debug, Error)]
pub enum LocalSelectedRecursiveMatrixError {
    #[error("unsupported selected-recursive matrix tier {tier}")]
    UnsupportedTier { tier: usize },
    #[error("another selected-recursive matrix is still resident")]
    MatrixAlreadyResident,
    #[error("matrix artifact path is a symlink: {path}")]
    Symlink { path: PathBuf },
    #[error("matrix artifact directory is not a directory: {path}")]
    NotDirectory { path: PathBuf },
    #[error("matrix artifact is not a regular file: {path}")]
    NotRegularFile { path: PathBuf },
    #[error("matrix artifact is too large: {actual} bytes exceeds cap {max}")]
    ArtifactTooLarge { actual: u64, max: u64 },
    #[error("matrix artifact changed while its opened file was being consumed: {path}")]
    ArtifactChanged { path: PathBuf },
    #[error("secure descriptor-relative matrix storage is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("matrix export shape does not match the requested canonical identity")]
    ExportShapeMismatch {
        expected: FieldShape,
        actual: FieldShape,
    },
    #[error("matrix export digest does not match the requested canonical identity")]
    ExportDigestMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    #[error("canonical matrix artifact rejected: {0}")]
    Codec(#[source] FieldR1csArtifactError),
    #[error("cannot {operation} matrix artifact {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// Local disk-backed matrix source and atomic exporter.
///
/// Every root and version-directory component is opened with `O_NOFOLLOW`, and
/// all leaf I/O is relative to the held version-directory descriptor. Paths
/// are fixed by [`SelectedRecursiveMatrixKind`]. The artifact's shape and
/// digest remain the cryptographic authority even if local files are
/// substituted.
pub struct LocalSelectedRecursiveMatrixSource {
    root: PathBuf,
    max_artifact_bytes: u64,
    resident: Arc<AtomicBool>,
    resident_evaluation: bool,
}

impl LocalSelectedRecursiveMatrixSource {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self::with_max_artifact_bytes(root, MAX_SELECTED_RECURSIVE_MATRIX_ARTIFACT_BYTES)
    }

    pub fn with_max_artifact_bytes(root: impl Into<PathBuf>, max_artifact_bytes: u64) -> Self {
        Self {
            root: root.into(),
            max_artifact_bytes,
            resident: process_matrix_residency(),
            resident_evaluation: false,
        }
    }

    /// Choose the terminal claim-evaluation strategy for
    /// [`Self::open_artifact_evaluator`]. Callers enable residency only under
    /// an admission that covers one decoded CSR matrix
    /// (`SELECTED_HISTORY_TERMINAL_RESIDENT_MATRIX_PEAK_MIB`); the default is
    /// the bounded-memory streaming scanner.
    pub fn set_resident_evaluation(&mut self, resident_evaluation: bool) {
        self.resident_evaluation = resident_evaluation;
    }

    #[cfg(test)]
    fn with_isolated_residency(root: impl Into<PathBuf>, max_artifact_bytes: u64) -> Self {
        Self {
            root: root.into(),
            max_artifact_bytes,
            resident: Arc::new(AtomicBool::new(false)),
            resident_evaluation: false,
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub const fn max_artifact_bytes(&self) -> u64 {
        self.max_artifact_bytes
    }

    pub fn artifact_path(&self, kind: SelectedRecursiveMatrixKind) -> PathBuf {
        self.root
            .join(selected_recursive_matrix_relative_path(kind))
    }

    /// Load one locally declared artifact while retaining the source's
    /// one-matrix lease in the returned RAII wrapper.
    ///
    /// Terminal verifiers should borrow the matrix through
    /// [`LoadedSelectedRecursiveMatrix::matrix`] for each verification phase
    /// and drop the wrapper before loading the next identity. There is no
    /// consuming unwrap: the matrix cannot outlive its admission lease.
    pub fn load_artifact(
        &self,
        identity: SelectedRecursiveMatrixArtifactIdentity,
    ) -> Result<LoadedSelectedRecursiveMatrix, LocalSelectedRecursiveMatrixError> {
        self.load_requested(
            identity.kind(),
            identity.shape(),
            identity.statement_digest(),
        )
    }

    /// Preflight one artifact as a bounded-memory, one-shot seekable evaluator.
    /// No CSR index, offset, or coefficient array proportional to matrix size
    /// is retained. The returned lease owns the opened inode and process-wide
    /// matrix admission until its file view is dropped.
    pub fn open_artifact_view(
        &self,
        identity: SelectedRecursiveMatrixArtifactIdentity,
    ) -> Result<LoadedSelectedRecursiveMatrixView, LocalSelectedRecursiveMatrixError> {
        self.open_requested_view(
            identity.kind(),
            identity.shape(),
            identity.statement_digest(),
        )
    }

    /// Open one artifact for terminal claim evaluation under the source's
    /// residency policy. Both variants recompute and authenticate the same
    /// structural statement digest from the exact rows they evaluate;
    /// residency changes only where those rows live — a decoded CSR with
    /// parallel span hashing versus bounded single-pass streaming windows —
    /// never the trust boundary.
    pub fn open_artifact_evaluator(
        &self,
        identity: SelectedRecursiveMatrixArtifactIdentity,
    ) -> Result<LoadedSelectedRecursiveMatrixEvaluator, LocalSelectedRecursiveMatrixError> {
        if self.resident_evaluation {
            Ok(LoadedSelectedRecursiveMatrixEvaluator::Resident(
                self.load_artifact(identity)?,
            ))
        } else {
            Ok(LoadedSelectedRecursiveMatrixEvaluator::Streamed(
                self.open_artifact_view(identity)?,
            ))
        }
    }

    /// Atomically stream one canonical matrix to its fixed local path.
    ///
    /// The matrix is checked against the request before any target mutation.
    /// A same-directory `create_new` temporary file is synced and renamed,
    /// then the containing directory is synced. Failed writes remove only the
    /// temporary file and leave an existing target intact.
    pub fn export_matrix(
        &self,
        identity: SelectedRecursiveMatrixArtifactIdentity,
        matrix: &FieldR1cs,
    ) -> Result<(), LocalSelectedRecursiveMatrixError> {
        validate_export_identity(identity, matrix)?;

        #[cfg(not(unix))]
        {
            let _ = (identity, matrix);
            Err(LocalSelectedRecursiveMatrixError::UnsupportedPlatform)
        }
        #[cfg(unix)]
        {
            let parent = self.open_version_directory(true)?;
            self.export_matrix_anchored(&parent, identity.kind(), matrix)
        }
    }

    fn load_requested(
        &self,
        kind: SelectedRecursiveMatrixKind,
        shape: FieldShape,
        statement_digest: [u8; 32],
    ) -> Result<LoadedSelectedRecursiveMatrix, LocalSelectedRecursiveMatrixError> {
        #[cfg(not(unix))]
        {
            let _ = (kind, shape, statement_digest);
            Err(LocalSelectedRecursiveMatrixError::UnsupportedPlatform)
        }
        #[cfg(unix)]
        {
            let lease = ResidentMatrixLease::acquire(Arc::clone(&self.resident))?;
            let parent = self.open_version_directory(false)?;
            self.load_requested_anchored(&parent, kind, shape, statement_digest, lease)
        }
    }

    fn open_requested_view(
        &self,
        kind: SelectedRecursiveMatrixKind,
        shape: FieldShape,
        statement_digest: [u8; 32],
    ) -> Result<LoadedSelectedRecursiveMatrixView, LocalSelectedRecursiveMatrixError> {
        #[cfg(not(unix))]
        {
            let _ = (kind, shape, statement_digest);
            Err(LocalSelectedRecursiveMatrixError::UnsupportedPlatform)
        }
        #[cfg(unix)]
        {
            let lease = ResidentMatrixLease::acquire(Arc::clone(&self.resident))?;
            let parent = self.open_version_directory(false)?;
            self.open_requested_view_anchored(&parent, kind, shape, statement_digest, lease)
        }
    }

    #[cfg(unix)]
    fn load_requested_anchored(
        &self,
        parent: &anchored_artifact_fs::AnchoredDirectory,
        kind: SelectedRecursiveMatrixKind,
        shape: FieldShape,
        statement_digest: [u8; 32],
        lease: ResidentMatrixLease,
    ) -> Result<LoadedSelectedRecursiveMatrix, LocalSelectedRecursiveMatrixError> {
        let (file, opened, path) = self.open_anchored_artifact(parent, kind)?;
        let decoder_cap = usize::try_from(self.effective_max_bytes()).unwrap_or(usize::MAX);
        let mut reader = BufReader::with_capacity(ARTIFACT_READ_BUFFER_BYTES, file);
        let matrix = FieldR1cs::read_artifact(&mut reader, shape, statement_digest, decoder_cap)
            .map_err(LocalSelectedRecursiveMatrixError::Codec)?;
        let after = reader
            .get_ref()
            .metadata()
            .map_err(|source| io_error("inspect decoded", &path, source))?;
        if !same_file_and_length(&opened, &after) {
            return Err(LocalSelectedRecursiveMatrixError::ArtifactChanged { path });
        }
        drop(reader);

        let resident = lease.transfer();
        Ok(LoadedSelectedRecursiveMatrix::with_release_callback(
            matrix,
            move || resident.store(false, Ordering::Release),
        ))
    }

    #[cfg(unix)]
    fn open_requested_view_anchored(
        &self,
        parent: &anchored_artifact_fs::AnchoredDirectory,
        kind: SelectedRecursiveMatrixKind,
        shape: FieldShape,
        statement_digest: [u8; 32],
        lease: ResidentMatrixLease,
    ) -> Result<LoadedSelectedRecursiveMatrixView, LocalSelectedRecursiveMatrixError> {
        let (file, opened, path) = self.open_anchored_artifact(parent, kind)?;
        let view = PreflightSeekableFieldR1csArtifact::open(
            file,
            shape,
            statement_digest,
            self.effective_max_bytes(),
        )
        .map_err(LocalSelectedRecursiveMatrixError::Codec)?;
        let after = view
            .reader()
            .metadata()
            .map_err(|source| io_error("inspect preflighted", &path, source))?;
        if !same_file_and_length(&opened, &after) {
            return Err(LocalSelectedRecursiveMatrixError::ArtifactChanged { path });
        }

        let resident = lease.transfer();
        Ok(LoadedSelectedRecursiveMatrixView {
            view: Some(view),
            opened,
            release_callback: Some(Box::new(move || resident.store(false, Ordering::Release))),
        })
    }

    #[cfg(unix)]
    fn open_anchored_artifact(
        &self,
        parent: &anchored_artifact_fs::AnchoredDirectory,
        kind: SelectedRecursiveMatrixKind,
    ) -> Result<(File, Metadata, PathBuf), LocalSelectedRecursiveMatrixError> {
        let path = self.artifact_path(kind);
        let leaf = selected_recursive_matrix_leaf(kind);
        match parent
            .leaf_kind(leaf)
            .map_err(|source| io_error("inspect anchored leaf", &path, source))?
        {
            anchored_artifact_fs::LeafKind::Regular => {}
            anchored_artifact_fs::LeafKind::Symlink => {
                return Err(LocalSelectedRecursiveMatrixError::Symlink { path });
            }
            anchored_artifact_fs::LeafKind::Other => {
                return Err(LocalSelectedRecursiveMatrixError::NotRegularFile { path });
            }
            anchored_artifact_fs::LeafKind::Missing => {
                return Err(io_error(
                    "open anchored leaf",
                    &path,
                    io::Error::new(io::ErrorKind::NotFound, "matrix artifact is missing"),
                ));
            }
        }

        let file = parent
            .open_read_only(leaf)
            .map_err(|source| io_error("open anchored leaf", &path, source))?;
        let opened = file
            .metadata()
            .map_err(|source| io_error("inspect opened", &path, source))?;
        validate_regular_file_metadata(&path, &opened)?;
        reject_oversize(opened.len(), self.effective_max_bytes())?;
        Ok((file, opened, path))
    }

    #[cfg(unix)]
    fn export_matrix_anchored(
        &self,
        parent: &anchored_artifact_fs::AnchoredDirectory,
        kind: SelectedRecursiveMatrixKind,
        matrix: &FieldR1cs,
    ) -> Result<(), LocalSelectedRecursiveMatrixError> {
        let target = self.artifact_path(kind);
        let leaf = selected_recursive_matrix_leaf(kind);
        match parent
            .leaf_kind(leaf)
            .map_err(|source| io_error("inspect anchored target", &target, source))?
        {
            anchored_artifact_fs::LeafKind::Missing | anchored_artifact_fs::LeafKind::Regular => {}
            anchored_artifact_fs::LeafKind::Symlink => {
                return Err(LocalSelectedRecursiveMatrixError::Symlink { path: target });
            }
            anchored_artifact_fs::LeafKind::Other => {
                return Err(LocalSelectedRecursiveMatrixError::NotRegularFile { path: target });
            }
        }

        let (temporary_name, file) = create_temporary_file(parent, &target)?;
        let temporary_path = target
            .parent()
            .expect("fixed matrix path has parent")
            .join(&temporary_name);
        let mut cleanup = TemporaryCleanup::new(parent, temporary_name.clone(), target.clone())?;
        let mut writer = CappedWriter::new(file, self.effective_max_bytes());
        let write_result = matrix.write_artifact(&mut writer);
        if let Some(actual) = writer.exceeded_at() {
            return Err(LocalSelectedRecursiveMatrixError::ArtifactTooLarge {
                actual,
                max: self.effective_max_bytes(),
            });
        }
        write_result.map_err(LocalSelectedRecursiveMatrixError::Codec)?;
        writer
            .flush()
            .map_err(|source| io_error("flush", &temporary_path, source))?;
        writer
            .inner()
            .sync_all()
            .map_err(|source| io_error("sync", &temporary_path, source))?;
        drop(writer);

        parent
            .rename(&temporary_name, leaf)
            .map_err(|source| io_error("rename anchored artifact", &target, source))?;
        cleanup.disarm();
        parent
            .sync_all()
            .map_err(|source| io_error("sync anchored directory", &target, source))?;
        Ok(())
    }

    #[cfg(unix)]
    fn open_version_directory(
        &self,
        create: bool,
    ) -> Result<anchored_artifact_fs::AnchoredDirectory, LocalSelectedRecursiveMatrixError> {
        let root = anchored_artifact_fs::AnchoredDirectory::open_tree(&self.root, create)
            .map_err(|source| directory_open_error(&self.root, source))?;
        let version_path = self.root.join(ARTIFACT_VERSION_DIRECTORY);
        root.open_child_directory(ARTIFACT_VERSION_DIRECTORY, create)
            .map_err(|source| directory_open_error(&version_path, source))
    }

    fn effective_max_bytes(&self) -> u64 {
        self.max_artifact_bytes.min(usize::MAX as u64)
    }
}

impl SelectedRecursiveMatrixSource for LocalSelectedRecursiveMatrixSource {
    type Error = LocalSelectedRecursiveMatrixError;

    fn load_matrix(
        &mut self,
        request: SelectedRecursiveMatrixRequest,
    ) -> Result<LoadedSelectedRecursiveMatrix, Self::Error> {
        self.load_requested(request.kind(), request.shape(), request.statement_digest())
    }
}

/// RAII lease over a preflighted one-shot seekable evaluator. Authentication
/// and claim evaluation happen together on first use; the opened file is
/// destroyed before process-global residency is released, matching the
/// decoded-matrix lease's ordering while retaining only bounded scratch.
pub struct LoadedSelectedRecursiveMatrixView {
    view: Option<PreflightSeekableFieldR1csArtifact<File>>,
    opened: Metadata,
    release_callback: Option<Box<dyn FnOnce() + Send + 'static>>,
}

impl LoadedSelectedRecursiveMatrixView {
    fn ensure_opened_file_identity(&self) -> Result<(), FieldR1csArtifactError> {
        let current = self
            .view
            .as_ref()
            .expect("matrix view exists until lease drop")
            .reader()
            .metadata()
            .map_err(FieldR1csArtifactError::Io)?;
        if !same_file_and_length(&self.opened, &current) {
            return Err(FieldR1csArtifactError::BackingFileChanged);
        }
        Ok(())
    }
}

impl MatrixClaimEvaluator for LoadedSelectedRecursiveMatrixView {
    fn field_shape(&self) -> FieldShape {
        self.view
            .as_ref()
            .expect("matrix view exists until lease drop")
            .field_shape()
    }

    fn evaluate_matrix_claims(
        &mut self,
        fresh: Option<&FreshLincheckClaim>,
        accumulated: Option<&MatrixAccClaim>,
    ) -> Result<AuthenticatedMatrixClaimEvaluations, FieldR1csArtifactError> {
        self.ensure_opened_file_identity()?;
        let evaluated = self
            .view
            .as_mut()
            .expect("matrix view exists until lease drop")
            .evaluate_matrix_claims(fresh, accumulated)?;
        self.ensure_opened_file_identity()?;
        Ok(evaluated)
    }
}

impl Drop for LoadedSelectedRecursiveMatrixView {
    fn drop(&mut self) {
        drop(self.view.take());
        if let Some(release_callback) = self.release_callback.take() {
            release_callback();
        }
    }
}

/// One terminal claim-evaluation lease under the source's residency policy.
/// Both variants hold the process-wide one-matrix admission until drop and
/// recompute the structural statement digest from the exact rows they
/// evaluate. Resident evaluation decodes the authenticated CSR once and
/// hashes its spans in parallel; streamed evaluation keeps only bounded
/// windows and re-scans the artifact per evaluation.
pub enum LoadedSelectedRecursiveMatrixEvaluator {
    Resident(crate::recursive_prover::LoadedSelectedRecursiveMatrix),
    Streamed(LoadedSelectedRecursiveMatrixView),
}

impl MatrixClaimEvaluator for LoadedSelectedRecursiveMatrixEvaluator {
    fn field_shape(&self) -> FieldShape {
        match self {
            Self::Resident(loaded) => FieldShape::of(loaded.matrix()),
            Self::Streamed(view) => view.field_shape(),
        }
    }

    fn evaluate_matrix_claims(
        &mut self,
        fresh: Option<&FreshLincheckClaim>,
        accumulated: Option<&MatrixAccClaim>,
    ) -> Result<AuthenticatedMatrixClaimEvaluations, FieldR1csArtifactError> {
        match self {
            Self::Resident(loaded) => loaded.matrix_mut().evaluate_matrix_claims(fresh, accumulated),
            Self::Streamed(view) => view.evaluate_matrix_claims(fresh, accumulated),
        }
    }
}

fn validate_export_identity(
    identity: SelectedRecursiveMatrixArtifactIdentity,
    matrix: &FieldR1cs,
) -> Result<(), LocalSelectedRecursiveMatrixError> {
    let actual_shape = FieldShape::of(matrix);
    if actual_shape != identity.shape() {
        return Err(LocalSelectedRecursiveMatrixError::ExportShapeMismatch {
            expected: identity.shape(),
            actual: actual_shape,
        });
    }
    let actual_digest = matrix.structural_statement_digest();
    if actual_digest != identity.statement_digest() {
        return Err(LocalSelectedRecursiveMatrixError::ExportDigestMismatch {
            expected: identity.statement_digest(),
            actual: actual_digest,
        });
    }
    Ok(())
}

fn selected_recursive_matrix_leaf(kind: SelectedRecursiveMatrixKind) -> &'static str {
    selected_recursive_matrix_relative_path(kind)
        .file_name()
        .and_then(|value| value.to_str())
        .expect("fixed ASCII matrix path has a file name")
}

#[cfg(unix)]
fn directory_open_error(path: &Path, source: io::Error) -> LocalSelectedRecursiveMatrixError {
    // This path lookup is diagnostic only. Security comes from the held
    // descriptor and its component-wise O_NOFOLLOW walk.
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return LocalSelectedRecursiveMatrixError::Symlink {
                path: path.to_path_buf(),
            };
        }
        if !metadata.is_dir() {
            return LocalSelectedRecursiveMatrixError::NotDirectory {
                path: path.to_path_buf(),
            };
        }
    }
    io_error("open anchored directory", path, source)
}

fn validate_regular_file_metadata(
    path: &Path,
    metadata: &Metadata,
) -> Result<(), LocalSelectedRecursiveMatrixError> {
    if metadata.file_type().is_symlink() {
        return Err(LocalSelectedRecursiveMatrixError::Symlink {
            path: path.to_path_buf(),
        });
    }
    if !metadata.is_file() {
        return Err(LocalSelectedRecursiveMatrixError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn reject_oversize(actual: u64, max: u64) -> Result<(), LocalSelectedRecursiveMatrixError> {
    if actual > max {
        return Err(LocalSelectedRecursiveMatrixError::ArtifactTooLarge { actual, max });
    }
    Ok(())
}

#[cfg(unix)]
fn same_file_and_length(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(not(unix))]
fn same_file_and_length(left: &Metadata, right: &Metadata) -> bool {
    left.len() == right.len() && left.is_file() == right.is_file()
}

#[cfg(unix)]
fn create_temporary_file(
    parent: &anchored_artifact_fs::AnchoredDirectory,
    target: &Path,
) -> Result<(String, File), LocalSelectedRecursiveMatrixError> {
    let leaf = target
        .file_name()
        .and_then(|value| value.to_str())
        .expect("fixed ASCII matrix artifact has a file name");
    let mut last_error = None;
    for _ in 0..TEMP_CREATE_ATTEMPTS {
        let sequence = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
        let temporary = format!(".{leaf}.tmp-{}-{sequence}", std::process::id());
        match parent.create_new(&temporary) {
            Ok(file) => return Ok((temporary, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                last_error = Some(error);
            }
            Err(source) => return Err(io_error("create anchored temporary", target, source)),
        }
    }
    Err(io_error(
        "create anchored temporary",
        target,
        last_error.unwrap_or_else(|| io::Error::new(io::ErrorKind::AlreadyExists, "collision")),
    ))
}

fn io_error(
    operation: &'static str,
    path: &Path,
    source: io::Error,
) -> LocalSelectedRecursiveMatrixError {
    LocalSelectedRecursiveMatrixError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

struct ResidentMatrixLease {
    resident: Arc<AtomicBool>,
    armed: bool,
}

impl ResidentMatrixLease {
    fn acquire(resident: Arc<AtomicBool>) -> Result<Self, LocalSelectedRecursiveMatrixError> {
        resident
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| LocalSelectedRecursiveMatrixError::MatrixAlreadyResident)?;
        Ok(Self {
            resident,
            armed: true,
        })
    }

    fn transfer(mut self) -> Arc<AtomicBool> {
        self.armed = false;
        Arc::clone(&self.resident)
    }
}

impl Drop for ResidentMatrixLease {
    fn drop(&mut self) {
        if self.armed {
            self.resident.store(false, Ordering::Release);
        }
    }
}

#[cfg(unix)]
struct TemporaryCleanup {
    parent: anchored_artifact_fs::AnchoredDirectory,
    name: String,
    display_path: PathBuf,
    armed: bool,
}

#[cfg(unix)]
impl TemporaryCleanup {
    fn new(
        parent: &anchored_artifact_fs::AnchoredDirectory,
        name: String,
        display_path: PathBuf,
    ) -> Result<Self, LocalSelectedRecursiveMatrixError> {
        Ok(Self {
            parent: parent
                .try_clone()
                .map_err(|source| io_error("clone anchored directory", &display_path, source))?,
            name,
            display_path,
            armed: true,
        })
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(unix)]
impl Drop for TemporaryCleanup {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.parent.unlink(&self.name);
            let _ = &self.display_path;
        }
    }
}

struct CappedWriter<W> {
    inner: W,
    written: u64,
    max: u64,
    exceeded_at: Option<u64>,
}

impl<W> CappedWriter<W> {
    fn new(inner: W, max: u64) -> Self {
        Self {
            inner,
            written: 0,
            max,
            exceeded_at: None,
        }
    }

    fn exceeded_at(&self) -> Option<u64> {
        self.exceeded_at
    }

    fn inner(&self) -> &W {
        &self.inner
    }
}

impl<W: Write> Write for CappedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let attempted = self
            .written
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        if attempted > self.max {
            self.exceeded_at = Some(attempted);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "matrix artifact byte cap exceeded",
            ));
        }
        let count = self.inner.write(bytes)?;
        self.written = self
            .written
            .saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::ffi::OsString;
    use std::fs::OpenOptions;

    use noid_ivc_core::field::F128;
    use noid_ivc_core::field_circuit::FieldR1csBuilder;
    use noid_ivc_core::field_r1cs::FieldR1csArtifactError;
    use tempfile::tempdir;

    use super::*;

    fn tiny_matrix(tag: u64) -> FieldR1cs {
        let mut builder = FieldR1csBuilder::new();
        builder.alloc_public_f128(F128::new(tag, 0));
        builder.build().0
    }

    fn identity(
        kind: SelectedRecursiveMatrixKind,
        matrix: &FieldR1cs,
    ) -> SelectedRecursiveMatrixArtifactIdentity {
        SelectedRecursiveMatrixArtifactIdentity::new(
            kind,
            FieldShape::of(matrix),
            matrix.structural_statement_digest(),
        )
    }

    fn all_kinds() -> [SelectedRecursiveMatrixKind; 9] {
        [
            SelectedRecursiveMatrixKind::GenesisLink,
            SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B8),
            SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B32),
            SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B64),
            SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B255),
            SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B8),
            SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B32),
            SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B64),
            SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B255),
        ]
    }

    fn isolated_source(root: &Path) -> LocalSelectedRecursiveMatrixSource {
        LocalSelectedRecursiveMatrixSource::with_isolated_residency(
            root,
            MAX_SELECTED_RECURSIVE_MATRIX_ARTIFACT_BYTES,
        )
    }

    fn isolated_source_with_cap(root: &Path, cap: u64) -> LocalSelectedRecursiveMatrixSource {
        LocalSelectedRecursiveMatrixSource::with_isolated_residency(root, cap)
    }

    #[test]
    fn fixed_mapping_covers_nine_distinct_versioned_paths() {
        let actual = all_kinds()
            .into_iter()
            .map(|kind| {
                selected_recursive_matrix_relative_path(kind)
                    .to_str()
                    .unwrap()
            })
            .collect::<BTreeSet<_>>();
        let expected = BTreeSet::from([
            "v1/genesis-link.field-r1cs",
            "v1/link-b8.field-r1cs",
            "v1/link-b32.field-r1cs",
            "v1/link-b64.field-r1cs",
            "v1/link-b255.field-r1cs",
            "v1/block-b8.field-r1cs",
            "v1/block-b32.field-r1cs",
            "v1/block-b64.field-r1cs",
            "v1/block-b255.field-r1cs",
        ]);
        assert_eq!(actual, expected);
    }

    #[test]
    fn atomic_export_roundtrips_without_serialized_vec_or_temp_residue() {
        let directory = tempdir().unwrap();
        let source = isolated_source(directory.path());
        let matrix = tiny_matrix(7);
        let identity = identity(SelectedRecursiveMatrixKind::GenesisLink, &matrix);
        source.export_matrix(identity, &matrix).unwrap();

        let loaded = source.load_artifact(identity).unwrap();
        assert_eq!(
            loaded.matrix().structural_statement_digest(),
            identity.statement_digest()
        );
        drop(loaded);
        let version_entries = fs::read_dir(directory.path().join("v1"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(
            version_entries,
            vec![OsString::from("genesis-link.field-r1cs")]
        );
    }

    #[test]
    fn seekable_view_matches_in_memory_claim_and_holds_admission() {
        use noid_ivc_core::matrix_claim::{stacked_matrix_mle_eval, MatrixAccClaim};

        let directory = tempdir().unwrap();
        let source = isolated_source(directory.path());
        let matrix = tiny_matrix(0x51EA);
        let matrix_identity = identity(SelectedRecursiveMatrixKind::GenesisLink, &matrix);
        source.export_matrix(matrix_identity, &matrix).unwrap();
        let mut claim = MatrixAccClaim {
            point: vec![F128::new(7, 11); 2 * matrix.k_log + 1],
            value: F128::ZERO,
        };
        claim.value = stacked_matrix_mle_eval(&matrix, &claim);

        let mut view = source.open_artifact_view(matrix_identity).unwrap();
        assert!(matches!(
            source.load_artifact(matrix_identity),
            Err(LocalSelectedRecursiveMatrixError::MatrixAlreadyResident)
        ));
        let evaluated = view.evaluate_matrix_claims(None, Some(&claim)).unwrap();
        assert_eq!(
            evaluated.structural_digest(),
            matrix_identity.statement_digest()
        );
        assert_eq!(evaluated.accumulated_value(), Some(claim.value));
        assert!(matches!(
            view.evaluate_matrix_claims(None, Some(&claim)),
            Err(FieldR1csArtifactError::MatrixEvaluatorAlreadyConsumed)
        ));
        drop(view);
        drop(source.load_artifact(matrix_identity).unwrap());
    }

    #[test]
    fn resident_evaluator_matches_streamed_claims_and_holds_admission() {
        use noid_ivc_core::matrix_claim::{stacked_matrix_mle_eval, MatrixAccClaim};

        let directory = tempdir().unwrap();
        let mut source = isolated_source(directory.path());
        let matrix = tiny_matrix(0x9E51);
        let matrix_identity = identity(SelectedRecursiveMatrixKind::GenesisLink, &matrix);
        source.export_matrix(matrix_identity, &matrix).unwrap();
        let mut claim = MatrixAccClaim {
            point: vec![F128::new(3, 5); 2 * matrix.k_log + 1],
            value: F128::ZERO,
        };
        claim.value = stacked_matrix_mle_eval(&matrix, &claim);

        // The default policy serves the bounded streaming scanner.
        let mut streamed = source.open_artifact_evaluator(matrix_identity).unwrap();
        assert!(matches!(
            streamed,
            LoadedSelectedRecursiveMatrixEvaluator::Streamed(_)
        ));
        let streamed_eval = streamed.evaluate_matrix_claims(None, Some(&claim)).unwrap();
        drop(streamed);

        source.set_resident_evaluation(true);
        let mut resident = source.open_artifact_evaluator(matrix_identity).unwrap();
        assert!(matches!(
            resident,
            LoadedSelectedRecursiveMatrixEvaluator::Resident(_)
        ));
        // Both evaluator variants hold the same one-matrix admission.
        assert!(matches!(
            source.load_artifact(matrix_identity),
            Err(LocalSelectedRecursiveMatrixError::MatrixAlreadyResident)
        ));
        let resident_eval = resident.evaluate_matrix_claims(None, Some(&claim)).unwrap();
        assert_eq!(
            resident_eval.structural_digest(),
            matrix_identity.statement_digest()
        );
        assert_eq!(
            resident_eval.structural_digest(),
            streamed_eval.structural_digest()
        );
        assert_eq!(resident_eval.accumulated_value(), Some(claim.value));
        assert_eq!(streamed_eval.accumulated_value(), Some(claim.value));
        drop(resident);
        drop(source.load_artifact(matrix_identity).unwrap());
    }

    #[test]
    fn terminal_streaming_arm_never_invokes_full_csr_decoder() {
        let store = include_str!("recursive_matrix_store.rs");
        let view_entry = store
            .split("fn open_requested_view(")
            .nth(1)
            .expect("seekable view loader")
            .split("fn load_requested_anchored")
            .next()
            .expect("view entry boundary");
        let view_loader = store
            .split("fn open_requested_view_anchored(")
            .nth(1)
            .expect("anchored seekable view loader")
            .split("fn open_anchored_artifact")
            .next()
            .expect("anchored view boundary");
        assert!(view_entry.contains("open_requested_view_anchored"));
        assert!(view_loader.contains("PreflightSeekableFieldR1csArtifact::open"));
        assert!(!view_entry.contains("FieldR1cs::read_artifact"));
        assert!(!view_loader.contains("FieldR1cs::read_artifact"));

        // Terminal claim evaluation dispatches on the residency policy: the
        // resident arm is admitted only under the resident envelope, and the
        // default remains the bounded streaming scanner.
        let evaluator_entry = store
            .split("pub fn open_artifact_evaluator(")
            .nth(1)
            .expect("terminal evaluator dispatch")
            .split("fn load_requested(")
            .next()
            .expect("evaluator dispatch boundary");
        assert!(evaluator_entry.contains("if self.resident_evaluation"));
        assert!(evaluator_entry.contains("self.open_artifact_view(identity)"));

        let verifier = include_str!("selected_history_verifier.rs");
        let source_impl = verifier
            .split("impl SelectedHistoryMatrixSource for LocalSelectedRecursiveMatrixSource")
            .nth(1)
            .expect("selected-history source implementation")
            .split("/// Production terminal-verification failure")
            .next()
            .expect("source implementation boundary");
        assert!(source_impl.contains("self.open_artifact_evaluator("));
        assert!(!source_impl.contains("load_artifact("));
    }

    #[cfg(unix)]
    #[test]
    fn opened_file_identity_includes_content_change_timestamps() {
        let source = include_str!("recursive_matrix_store.rs");
        let identity = source
            .split("fn same_file_and_length(left: &Metadata, right: &Metadata) -> bool {")
            .nth(1)
            .expect("Unix opened-file identity")
            .split("#[cfg(not(unix))]")
            .next()
            .expect("Unix identity boundary");
        for field in ["mtime()", "mtime_nsec()", "ctime()", "ctime_nsec()"] {
            assert!(identity.contains(field), "missing metadata field {field}");
        }
    }

    #[test]
    fn truncated_artifact_is_rejected_by_canonical_decoder() {
        let directory = tempdir().unwrap();
        let source = isolated_source(directory.path());
        let matrix = tiny_matrix(8);
        let identity = identity(
            SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B8),
            &matrix,
        );
        source.export_matrix(identity, &matrix).unwrap();
        let path = source.artifact_path(identity.kind());
        let length = fs::metadata(&path).unwrap().len();
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(length - 1)
            .unwrap();

        assert!(matches!(
            source.load_requested(
                identity.kind(),
                identity.shape(),
                identity.statement_digest()
            ),
            Err(LocalSelectedRecursiveMatrixError::Codec(
                FieldR1csArtifactError::Truncated { .. }
            ))
        ));
    }

    #[test]
    fn path_substitution_is_rejected_by_request_digest() {
        let directory = tempdir().unwrap();
        let source = isolated_source(directory.path());
        let expected = tiny_matrix(11);
        let substitute = tiny_matrix(22);
        let expected_identity = identity(
            SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B8),
            &expected,
        );
        let substitute_identity = identity(
            SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B32),
            &substitute,
        );
        source.export_matrix(expected_identity, &expected).unwrap();
        source
            .export_matrix(substitute_identity, &substitute)
            .unwrap();
        fs::copy(
            source.artifact_path(substitute_identity.kind()),
            source.artifact_path(expected_identity.kind()),
        )
        .unwrap();

        assert!(matches!(
            source.load_requested(
                expected_identity.kind(),
                expected_identity.shape(),
                expected_identity.statement_digest()
            ),
            Err(LocalSelectedRecursiveMatrixError::Codec(
                FieldR1csArtifactError::StructuralDigestMismatch { .. }
            ))
        ));
    }

    #[test]
    fn file_size_cap_rejects_before_decode() {
        let directory = tempdir().unwrap();
        let writer = isolated_source(directory.path());
        let matrix = tiny_matrix(33);
        let identity = identity(
            SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B64),
            &matrix,
        );
        writer.export_matrix(identity, &matrix).unwrap();
        let actual = fs::metadata(writer.artifact_path(identity.kind()))
            .unwrap()
            .len();
        let reader = isolated_source_with_cap(directory.path(), actual - 1);

        assert!(matches!(
            reader.load_requested(
                identity.kind(),
                identity.shape(),
                identity.statement_digest()
            ),
            Err(LocalSelectedRecursiveMatrixError::ArtifactTooLarge {
                actual: seen,
                max
            }) if seen == actual && max == actual - 1
        ));
    }

    #[test]
    fn export_cap_removes_temporary_and_never_creates_target() {
        let directory = tempdir().unwrap();
        let source = isolated_source_with_cap(directory.path(), 127);
        let matrix = tiny_matrix(44);
        let identity = identity(
            SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B255),
            &matrix,
        );

        assert!(matches!(
            source.export_matrix(identity, &matrix),
            Err(LocalSelectedRecursiveMatrixError::ArtifactTooLarge { max: 127, .. })
        ));
        assert!(!source.artifact_path(identity.kind()).exists());
        assert_eq!(
            fs::read_dir(directory.path().join("v1")).unwrap().count(),
            0
        );
    }

    #[test]
    fn second_load_waits_for_first_matrix_drop() {
        let directory = tempdir().unwrap();
        let source = isolated_source(directory.path());
        let previous = tiny_matrix(55);
        let block = tiny_matrix(66);
        let previous_identity = identity(
            SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B255),
            &previous,
        );
        let block_identity = identity(
            SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B64),
            &block,
        );
        source.export_matrix(previous_identity, &previous).unwrap();
        source.export_matrix(block_identity, &block).unwrap();

        let first = source.load_artifact(previous_identity).unwrap();
        let borrowed = first.matrix();
        assert_eq!(
            borrowed.structural_statement_digest(),
            previous_identity.statement_digest()
        );
        assert!(matches!(
            source.load_artifact(block_identity),
            Err(LocalSelectedRecursiveMatrixError::MatrixAlreadyResident)
        ));
        let _ = borrowed;
        drop(first);
        let second = source.load_artifact(block_identity).unwrap();
        drop(second);
    }

    #[test]
    fn independent_production_sources_share_process_matrix_admission() {
        let directory = tempdir().unwrap();
        let writer = isolated_source(directory.path());
        let first_matrix = tiny_matrix(101);
        let second_matrix = tiny_matrix(102);
        let first_identity = identity(
            SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B8),
            &first_matrix,
        );
        let second_identity = identity(
            SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B8),
            &second_matrix,
        );
        writer.export_matrix(first_identity, &first_matrix).unwrap();
        writer
            .export_matrix(second_identity, &second_matrix)
            .unwrap();

        let first_source = LocalSelectedRecursiveMatrixSource::new(directory.path());
        let second_source = LocalSelectedRecursiveMatrixSource::new(directory.path());
        let first = first_source.load_artifact(first_identity).unwrap();
        assert!(matches!(
            second_source.load_artifact(second_identity),
            Err(LocalSelectedRecursiveMatrixError::MatrixAlreadyResident)
        ));
        drop(first);
        drop(second_source.load_artifact(second_identity).unwrap());
    }

    #[test]
    fn loaded_wrapper_releases_admission_after_matrix_storage_drop() {
        let source = include_str!("recursive_prover.rs");
        let drop_body = source
            .split("impl Drop for LoadedSelectedRecursiveMatrix")
            .nth(1)
            .expect("loaded matrix Drop implementation")
            .split("/// On-demand local matrix provider")
            .next()
            .expect("loaded matrix Drop boundary");
        let matrix_drop = drop_body
            .find("drop(self.matrix.take())")
            .expect("matrix storage is explicitly dropped");
        let callback = drop_body
            .find("self.release_callback.take()")
            .expect("release callback exists");
        assert!(matrix_drop < callback);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_leaf_is_rejected_without_following_it() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().unwrap();
        let source = isolated_source(directory.path());
        let expected = tiny_matrix(77);
        let target = tiny_matrix(88);
        let expected_identity = identity(
            SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B8),
            &expected,
        );
        let target_identity = identity(
            SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B32),
            &target,
        );
        source.export_matrix(expected_identity, &expected).unwrap();
        source.export_matrix(target_identity, &target).unwrap();
        let expected_path = source.artifact_path(expected_identity.kind());
        fs::remove_file(&expected_path).unwrap();
        symlink("block-b32.field-r1cs", &expected_path).unwrap();

        assert!(matches!(
            source.load_requested(
                expected_identity.kind(),
                expected_identity.shape(),
                expected_identity.statement_digest()
            ),
            Err(LocalSelectedRecursiveMatrixError::Symlink { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn anchored_read_cannot_be_redirected_by_parent_symlink_swap() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().unwrap();
        let root = directory.path().join("root");
        let source = isolated_source(&root);
        let expected = tiny_matrix(0xA11CE);
        let substitute = tiny_matrix(0xBAD);
        let expected_identity = identity(
            SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B32),
            &expected,
        );
        source.export_matrix(expected_identity, &expected).unwrap();

        let anchored = source.open_version_directory(false).unwrap();
        let held_parent = root.join("held-v1");
        let outside = directory.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::rename(root.join(ARTIFACT_VERSION_DIRECTORY), &held_parent).unwrap();
        symlink(&outside, root.join(ARTIFACT_VERSION_DIRECTORY)).unwrap();

        let outside_path = outside.join(selected_recursive_matrix_leaf(expected_identity.kind()));
        let mut outside_file = File::create(&outside_path).unwrap();
        substitute.write_artifact(&mut outside_file).unwrap();
        outside_file.sync_all().unwrap();
        drop(outside_file);

        let lease = ResidentMatrixLease::acquire(Arc::clone(&source.resident)).unwrap();
        let loaded = source
            .load_requested_anchored(
                &anchored,
                expected_identity.kind(),
                expected_identity.shape(),
                expected_identity.statement_digest(),
                lease,
            )
            .unwrap();
        assert_eq!(
            loaded.matrix().structural_statement_digest(),
            expected_identity.statement_digest()
        );
        assert_ne!(
            loaded.matrix().structural_statement_digest(),
            substitute.structural_statement_digest()
        );
    }

    #[cfg(unix)]
    #[test]
    fn anchored_export_cannot_be_redirected_by_parent_symlink_swap() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().unwrap();
        let root = directory.path().join("root");
        let source = isolated_source(&root);
        let anchored = source.open_version_directory(true).unwrap();
        let held_parent = root.join("held-v1");
        let outside = directory.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::rename(root.join(ARTIFACT_VERSION_DIRECTORY), &held_parent).unwrap();
        symlink(&outside, root.join(ARTIFACT_VERSION_DIRECTORY)).unwrap();

        let matrix = tiny_matrix(0xE77047);
        let matrix_identity = identity(
            SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B64),
            &matrix,
        );
        validate_export_identity(matrix_identity, &matrix).unwrap();
        source
            .export_matrix_anchored(&anchored, matrix_identity.kind(), &matrix)
            .unwrap();

        let leaf = selected_recursive_matrix_leaf(matrix_identity.kind());
        assert!(held_parent.join(leaf).is_file());
        assert!(!outside.join(leaf).exists());
        assert_eq!(fs::read_dir(&held_parent).unwrap().count(), 1);

        let mut reader = BufReader::new(File::open(held_parent.join(leaf)).unwrap());
        let decoded = FieldR1cs::read_artifact(
            &mut reader,
            matrix_identity.shape(),
            matrix_identity.statement_digest(),
            usize::MAX,
        )
        .unwrap();
        assert_eq!(
            decoded.structural_statement_digest(),
            matrix_identity.statement_digest()
        );
    }
}
