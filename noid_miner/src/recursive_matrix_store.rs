// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Bounded local storage for the canonical selected-recursive matrices.
//!
//! The history prover requests matrices by frozen shape and structural digest.
//! This source maps that request to one of nine fixed local paths, streams the
//! artifact through the canonical `FieldR1cs` codec, and holds a one-matrix
//! lease until the returned value is dropped. It never caches a matrix or a
//! complete serialized artifact.

use std::ffi::OsString;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use noid_ivc_core::field_r1cs::{FieldR1cs, FieldR1csArtifactError, SeekableFieldR1csArtifact};
use noid_ivc_core::matrix_claim::{
    AuthenticatedMatrixClaimEvaluations, FreshLincheckClaim, MatrixAccClaim, MatrixClaimEvaluator,
};
use noid_ivc_core::proof::FieldShape;
use thiserror::Error;

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
    #[error("matrix artifact changed between path preflight and file open: {path}")]
    ArtifactChanged { path: PathBuf },
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
/// `root` is a trusted node-local directory boundary. Every path below it is
/// fixed by [`SelectedRecursiveMatrixKind`]; the `v1` directory and artifact
/// leaf are checked against symlinks. The artifact's shape and digest remain
/// the cryptographic authority even if local files are substituted.
pub struct LocalSelectedRecursiveMatrixSource {
    root: PathBuf,
    max_artifact_bytes: u64,
    resident: Arc<AtomicBool>,
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
        }
    }

    #[cfg(test)]
    fn with_isolated_residency(root: impl Into<PathBuf>, max_artifact_bytes: u64) -> Self {
        Self {
            root: root.into(),
            max_artifact_bytes,
            resident: Arc::new(AtomicBool::new(false)),
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

    /// Open one canonical artifact as a bounded-memory seekable evaluator.
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

        self.prepare_write_layout()?;
        let target = self.artifact_path(identity.kind());
        match fs::symlink_metadata(&target) {
            Ok(metadata) => validate_regular_file_metadata(&target, &metadata)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(io_error("stat", &target, source)),
        }
        let parent = target.parent().expect("fixed matrix path has parent");
        validate_directory(parent)?;

        let (temporary, file) = create_temporary_file(parent, &target)?;
        let mut cleanup = TemporaryCleanup::new(temporary.clone());
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
            .map_err(|source| io_error("flush", &temporary, source))?;
        writer
            .inner()
            .sync_all()
            .map_err(|source| io_error("sync", &temporary, source))?;
        drop(writer);

        fs::rename(&temporary, &target).map_err(|source| io_error("rename", &target, source))?;
        cleanup.disarm();
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| io_error("sync directory", parent, source))?;
        Ok(())
    }

    fn load_requested(
        &self,
        kind: SelectedRecursiveMatrixKind,
        shape: FieldShape,
        statement_digest: [u8; 32],
    ) -> Result<LoadedSelectedRecursiveMatrix, LocalSelectedRecursiveMatrixError> {
        let lease = ResidentMatrixLease::acquire(Arc::clone(&self.resident))?;
        let path = self.artifact_path(kind);
        let parent = path.parent().expect("fixed matrix path has parent");
        validate_directory(&self.root)?;
        validate_directory(parent)?;

        let before =
            fs::symlink_metadata(&path).map_err(|source| io_error("stat", &path, source))?;
        validate_regular_file_metadata(&path, &before)?;
        let cap = self.effective_max_bytes();
        reject_oversize(before.len(), cap)?;

        let file = open_artifact_read_only(&path)?;
        let opened = file
            .metadata()
            .map_err(|source| io_error("inspect opened", &path, source))?;
        validate_regular_file_metadata(&path, &opened)?;
        if !same_file_and_length(&before, &opened) {
            return Err(LocalSelectedRecursiveMatrixError::ArtifactChanged { path });
        }
        reject_oversize(opened.len(), cap)?;

        let decoder_cap = usize::try_from(cap).unwrap_or(usize::MAX);
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

    fn open_requested_view(
        &self,
        kind: SelectedRecursiveMatrixKind,
        shape: FieldShape,
        statement_digest: [u8; 32],
    ) -> Result<LoadedSelectedRecursiveMatrixView, LocalSelectedRecursiveMatrixError> {
        let lease = ResidentMatrixLease::acquire(Arc::clone(&self.resident))?;
        let path = self.artifact_path(kind);
        let parent = path.parent().expect("fixed matrix path has parent");
        validate_directory(&self.root)?;
        validate_directory(parent)?;

        let before =
            fs::symlink_metadata(&path).map_err(|source| io_error("stat", &path, source))?;
        validate_regular_file_metadata(&path, &before)?;
        let cap = self.effective_max_bytes();
        reject_oversize(before.len(), cap)?;

        let file = open_artifact_read_only(&path)?;
        let opened = file
            .metadata()
            .map_err(|source| io_error("inspect opened", &path, source))?;
        validate_regular_file_metadata(&path, &opened)?;
        if !same_file_and_length(&before, &opened) {
            return Err(LocalSelectedRecursiveMatrixError::ArtifactChanged { path });
        }
        let view = SeekableFieldR1csArtifact::open(file, shape, statement_digest, cap)
            .map_err(LocalSelectedRecursiveMatrixError::Codec)?;
        let after = view
            .reader()
            .metadata()
            .map_err(|source| io_error("inspect validated", &path, source))?;
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

    fn effective_max_bytes(&self) -> u64 {
        self.max_artifact_bytes.min(usize::MAX as u64)
    }

    fn prepare_write_layout(&self) -> Result<(), LocalSelectedRecursiveMatrixError> {
        if !self.root.exists() {
            fs::create_dir_all(&self.root)
                .map_err(|source| io_error("create directory", &self.root, source))?;
        }
        validate_directory(&self.root)?;
        let version = self.root.join(ARTIFACT_VERSION_DIRECTORY);
        match fs::create_dir(&version) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(source) => return Err(io_error("create directory", &version, source)),
        }
        validate_directory(&version)
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

/// RAII lease over an authenticated seekable artifact.  The opened file is
/// destroyed before process-global residency is released, matching the
/// decoded-matrix lease's ordering while retaining only bounded scratch.
pub struct LoadedSelectedRecursiveMatrixView {
    view: Option<SeekableFieldR1csArtifact<File>>,
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

fn validate_directory(path: &Path) -> Result<(), LocalSelectedRecursiveMatrixError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error("stat", path, source))?;
    if metadata.file_type().is_symlink() {
        return Err(LocalSelectedRecursiveMatrixError::Symlink {
            path: path.to_path_buf(),
        });
    }
    if !metadata.is_dir() {
        return Err(LocalSelectedRecursiveMatrixError::NotDirectory {
            path: path.to_path_buf(),
        });
    }
    Ok(())
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
    left.dev() == right.dev() && left.ino() == right.ino() && left.len() == right.len()
}

#[cfg(not(unix))]
fn same_file_and_length(left: &Metadata, right: &Metadata) -> bool {
    left.len() == right.len() && left.is_file() == right.is_file()
}

fn open_artifact_read_only(path: &Path) -> Result<File, LocalSelectedRecursiveMatrixError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    options
        .open(path)
        .map_err(|source| io_error("open", path, source))
}

fn create_temporary_file(
    parent: &Path,
    target: &Path,
) -> Result<(PathBuf, File), LocalSelectedRecursiveMatrixError> {
    let leaf = target
        .file_name()
        .expect("fixed matrix artifact path has a file name");
    let mut last_error = None;
    for _ in 0..TEMP_CREATE_ATTEMPTS {
        let sequence = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
        let mut temporary_name = OsString::from(".");
        temporary_name.push(leaf);
        temporary_name.push(format!(".tmp-{}-{sequence}", std::process::id()));
        let temporary = parent.join(temporary_name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        match options.open(&temporary) {
            Ok(file) => return Ok((temporary, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                last_error = Some(error);
            }
            Err(source) => return Err(io_error("create temporary", &temporary, source)),
        }
    }
    Err(io_error(
        "create temporary",
        parent,
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

struct TemporaryCleanup {
    path: PathBuf,
    armed: bool,
}

impl TemporaryCleanup {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TemporaryCleanup {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
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
            evaluated.structural_digest,
            matrix_identity.statement_digest()
        );
        assert_eq!(evaluated.accumulated_value, Some(claim.value));
        drop(view);
        drop(source.load_artifact(matrix_identity).unwrap());
    }

    #[test]
    fn terminal_view_source_never_invokes_full_csr_decoder() {
        let store = include_str!("recursive_matrix_store.rs");
        let view_loader = store
            .split("fn open_requested_view(")
            .nth(1)
            .expect("seekable view loader")
            .split("fn effective_max_bytes")
            .next()
            .expect("view loader boundary");
        assert!(view_loader.contains("SeekableFieldR1csArtifact::open"));
        assert!(!view_loader.contains("FieldR1cs::read_artifact"));

        let verifier = include_str!("selected_history_verifier.rs");
        let source_impl = verifier
            .split("impl SelectedHistoryMatrixSource for LocalSelectedRecursiveMatrixSource")
            .nth(1)
            .expect("selected-history source implementation")
            .split("/// Production terminal-verification failure")
            .next()
            .expect("source implementation boundary");
        assert!(source_impl.contains("self.open_artifact_view("));
        assert!(!source_impl.contains("load_artifact("));
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
}
