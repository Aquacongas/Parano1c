// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Atomic local store for the compact selected-recursive class registry.

use std::ffi::OsString;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use noid_recursive::acceptance::block_class::BlockClass;
use noid_recursive::acceptance::split_link::{CanonicalSplitLinkLadder, SplitLinkClass};
use noid_recursive::class_registry::{
    decode_selected_recursive_class_registry, encode_selected_recursive_class_registry,
    OwnedSelectedRecursiveClassRegistry, SelectedRecursiveClassRegistryError,
    MAX_SELECTED_RECURSIVE_CLASS_REGISTRY_BYTES,
};
use noid_recursive::{CanonicalSelectedHistoryRegistry, SelectedHistoryRegistryError};
use thiserror::Error;

use crate::recursive_prover::{
    SelectedRecursiveBlockClasses, SelectedRecursiveLinkClasses, SelectedRecursiveProverError,
};

const REGISTRY_VERSION_DIRECTORY: &str = "v1";
const REGISTRY_ARTIFACT_FILE: &str = "selected-recursive.classes";
const TEMP_CREATE_ATTEMPTS: usize = 32;
static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Error)]
pub enum LocalSelectedRecursiveClassRegistryError {
    #[error("class registry path is a symlink: {path}")]
    Symlink { path: PathBuf },
    #[error("class registry directory is not a directory: {path}")]
    NotDirectory { path: PathBuf },
    #[error("class registry artifact is not a regular file: {path}")]
    NotRegularFile { path: PathBuf },
    #[error("class registry artifact is too large: {actual} bytes exceeds cap {max}")]
    ArtifactTooLarge { actual: u64, max: u64 },
    #[error("class registry artifact changed between path preflight and decode: {path}")]
    ArtifactChanged { path: PathBuf },
    #[error("class registry artifact rejected: {0}")]
    Registry(#[from] SelectedRecursiveClassRegistryError),
    #[error("cannot {operation} class registry {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// Loaded ownership plus checked borrowed views for the prover and terminal
/// verifier.  No view clones a class or retained genesis proof.
pub struct LoadedSelectedRecursiveClassRegistry {
    registry: OwnedSelectedRecursiveClassRegistry,
}

impl LoadedSelectedRecursiveClassRegistry {
    pub fn owned(&self) -> &OwnedSelectedRecursiveClassRegistry {
        &self.registry
    }

    pub fn block_classes(
        &self,
    ) -> Result<SelectedRecursiveBlockClasses<'_>, SelectedRecursiveProverError> {
        let [b8, b32, b64, b255] = self.registry.block_classes();
        SelectedRecursiveBlockClasses::try_new(b8, b32, b64, b255)
    }

    pub fn link_classes(
        &self,
    ) -> Result<SelectedRecursiveLinkClasses<'_>, SelectedRecursiveProverError> {
        SelectedRecursiveLinkClasses::try_new(
            self.registry.descriptor(),
            self.registry.link_classes(),
        )
    }

    pub fn terminal_registry(
        &self,
    ) -> Result<CanonicalSelectedHistoryRegistry<'_>, SelectedHistoryRegistryError> {
        CanonicalSelectedHistoryRegistry::try_new(
            self.registry.descriptor(),
            self.registry.link_classes(),
        )
    }
}

/// Fixed-path, fail-closed registry source.  The root is trusted local
/// configuration; both the `v1` directory and leaf reject symlinks.
pub struct LocalSelectedRecursiveClassRegistryStore {
    root: PathBuf,
    max_artifact_bytes: u64,
}

impl LocalSelectedRecursiveClassRegistryStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self::with_max_artifact_bytes(root, MAX_SELECTED_RECURSIVE_CLASS_REGISTRY_BYTES as u64)
    }

    pub fn with_max_artifact_bytes(root: impl Into<PathBuf>, max_artifact_bytes: u64) -> Self {
        Self {
            root: root.into(),
            max_artifact_bytes: max_artifact_bytes
                .min(MAX_SELECTED_RECURSIVE_CLASS_REGISTRY_BYTES as u64),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn artifact_path(&self) -> PathBuf {
        self.root
            .join(REGISTRY_VERSION_DIRECTORY)
            .join(REGISTRY_ARTIFACT_FILE)
    }

    pub fn load(
        &self,
    ) -> Result<LoadedSelectedRecursiveClassRegistry, LocalSelectedRecursiveClassRegistryError>
    {
        let path = self.artifact_path();
        let parent = path.parent().expect("fixed registry artifact has parent");
        validate_directory(&self.root)?;
        validate_directory(parent)?;

        let before =
            fs::symlink_metadata(&path).map_err(|source| io_error("stat", &path, source))?;
        validate_regular_file(&path, &before)?;
        reject_oversize(before.len(), self.effective_max_bytes())?;

        let mut file = open_read_only(&path)?;
        let opened = file
            .metadata()
            .map_err(|source| io_error("inspect opened", &path, source))?;
        validate_regular_file(&path, &opened)?;
        if !same_file_and_length(&before, &opened) {
            return Err(LocalSelectedRecursiveClassRegistryError::ArtifactChanged { path });
        }
        reject_oversize(opened.len(), self.effective_max_bytes())?;

        let len = usize::try_from(opened.len()).map_err(|_| {
            LocalSelectedRecursiveClassRegistryError::ArtifactTooLarge {
                actual: opened.len(),
                max: self.effective_max_bytes(),
            }
        })?;
        let mut bytes = Vec::with_capacity(len);
        file.read_to_end(&mut bytes)
            .map_err(|source| io_error("read", &path, source))?;
        if bytes.len() != len {
            return Err(LocalSelectedRecursiveClassRegistryError::ArtifactChanged { path });
        }
        let after = file
            .metadata()
            .map_err(|source| io_error("inspect decoded", &path, source))?;
        if !same_file_and_length(&opened, &after) {
            return Err(LocalSelectedRecursiveClassRegistryError::ArtifactChanged { path });
        }
        drop(file);

        let registry = decode_selected_recursive_class_registry(&bytes)?;
        Ok(LoadedSelectedRecursiveClassRegistry { registry })
    }

    pub fn export(
        &self,
        blocks: &[BlockClass; 4],
        descriptor: &CanonicalSplitLinkLadder,
        links: &[SplitLinkClass; 4],
    ) -> Result<(), LocalSelectedRecursiveClassRegistryError> {
        let bytes = encode_selected_recursive_class_registry(blocks, descriptor, links)?;
        self.export_encoded(&bytes)
    }

    fn export_encoded(&self, bytes: &[u8]) -> Result<(), LocalSelectedRecursiveClassRegistryError> {
        reject_oversize(bytes.len() as u64, self.effective_max_bytes())?;
        self.prepare_layout()?;
        let target = self.artifact_path();
        match fs::symlink_metadata(&target) {
            Ok(metadata) => validate_regular_file(&target, &metadata)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(io_error("stat", &target, source)),
        }
        let parent = target.parent().expect("fixed registry artifact has parent");
        validate_directory(parent)?;

        let (temporary, mut file) = create_temporary_file(parent, &target)?;
        let mut cleanup = TemporaryCleanup::new(temporary.clone());
        file.write_all(bytes)
            .map_err(|source| io_error("write", &temporary, source))?;
        file.flush()
            .map_err(|source| io_error("flush", &temporary, source))?;
        file.sync_all()
            .map_err(|source| io_error("sync", &temporary, source))?;
        drop(file);
        fs::rename(&temporary, &target).map_err(|source| io_error("rename", &target, source))?;
        cleanup.disarm();
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| io_error("sync directory", parent, source))?;
        Ok(())
    }

    fn effective_max_bytes(&self) -> u64 {
        self.max_artifact_bytes
            .min(MAX_SELECTED_RECURSIVE_CLASS_REGISTRY_BYTES as u64)
            .min(usize::MAX as u64)
    }

    fn prepare_layout(&self) -> Result<(), LocalSelectedRecursiveClassRegistryError> {
        if !self.root.exists() {
            fs::create_dir_all(&self.root)
                .map_err(|source| io_error("create directory", &self.root, source))?;
        }
        validate_directory(&self.root)?;
        let version = self.root.join(REGISTRY_VERSION_DIRECTORY);
        match fs::create_dir(&version) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(source) => return Err(io_error("create directory", &version, source)),
        }
        validate_directory(&version)
    }
}

fn validate_directory(path: &Path) -> Result<(), LocalSelectedRecursiveClassRegistryError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error("stat", path, source))?;
    if metadata.file_type().is_symlink() {
        return Err(LocalSelectedRecursiveClassRegistryError::Symlink {
            path: path.to_path_buf(),
        });
    }
    if !metadata.is_dir() {
        return Err(LocalSelectedRecursiveClassRegistryError::NotDirectory {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn validate_regular_file(
    path: &Path,
    metadata: &Metadata,
) -> Result<(), LocalSelectedRecursiveClassRegistryError> {
    if metadata.file_type().is_symlink() {
        return Err(LocalSelectedRecursiveClassRegistryError::Symlink {
            path: path.to_path_buf(),
        });
    }
    if !metadata.is_file() {
        return Err(LocalSelectedRecursiveClassRegistryError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn reject_oversize(actual: u64, max: u64) -> Result<(), LocalSelectedRecursiveClassRegistryError> {
    if actual > max {
        return Err(LocalSelectedRecursiveClassRegistryError::ArtifactTooLarge { actual, max });
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

fn open_read_only(path: &Path) -> Result<File, LocalSelectedRecursiveClassRegistryError> {
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
) -> Result<(PathBuf, File), LocalSelectedRecursiveClassRegistryError> {
    let leaf = target
        .file_name()
        .expect("fixed registry artifact has a file name");
    let mut last_error = None;
    for _ in 0..TEMP_CREATE_ATTEMPTS {
        let sequence = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
        let mut name = OsString::from(".");
        name.push(leaf);
        name.push(format!(".tmp-{}-{sequence}", std::process::id()));
        let temporary = parent.join(name);
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
) -> LocalSelectedRecursiveClassRegistryError {
    LocalSelectedRecursiveClassRegistryError::Io {
        operation,
        path: path.to_path_buf(),
        source,
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn fixed_path_and_size_cap_precede_decode() {
        let directory = tempdir().unwrap();
        let store =
            LocalSelectedRecursiveClassRegistryStore::with_max_artifact_bytes(directory.path(), 8);
        store.prepare_layout().unwrap();
        fs::write(store.artifact_path(), [0u8; 9]).unwrap();
        assert!(matches!(
            store.load(),
            Err(LocalSelectedRecursiveClassRegistryError::ArtifactTooLarge { actual: 9, max: 8 })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn registry_leaf_symlink_is_rejected() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().unwrap();
        let store = LocalSelectedRecursiveClassRegistryStore::new(directory.path());
        store.prepare_layout().unwrap();
        let target = directory.path().join("target");
        fs::write(&target, [0u8; 64]).unwrap();
        symlink(&target, store.artifact_path()).unwrap();
        assert!(matches!(
            store.load(),
            Err(LocalSelectedRecursiveClassRegistryError::Symlink { .. })
        ));
    }

    #[test]
    fn failed_export_does_not_replace_existing_target() {
        let directory = tempdir().unwrap();
        let store =
            LocalSelectedRecursiveClassRegistryStore::with_max_artifact_bytes(directory.path(), 4);
        store.prepare_layout().unwrap();
        fs::write(store.artifact_path(), b"old").unwrap();
        assert!(matches!(
            store.export_encoded(b"too large"),
            Err(LocalSelectedRecursiveClassRegistryError::ArtifactTooLarge { .. })
        ));
        assert_eq!(fs::read(store.artifact_path()).unwrap(), b"old");
    }
}
