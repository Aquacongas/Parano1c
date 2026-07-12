// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Atomic local store for the compact selected-recursive class registry.

use std::fs::{self, File, Metadata};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

#[cfg(test)]
use std::fs::OpenOptions;

use noid_recursive::acceptance::block_class::BlockClass;
use noid_recursive::acceptance::split_link::{CanonicalSplitLinkLadder, SplitLinkClass};
use noid_recursive::class_registry::{
    decode_selected_recursive_class_registry_pinned, encode_selected_recursive_class_registry,
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
    #[error("secure descriptor-relative class registry storage is unsupported on this platform")]
    UnsupportedPlatform,
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

    /// Load only under an externally provisioned release pin.  The expected
    /// digest must not be derived from the artifact being opened.
    pub fn load_pinned(
        &self,
        expected_registry_digest: [u8; 32],
    ) -> Result<LoadedSelectedRecursiveClassRegistry, LocalSelectedRecursiveClassRegistryError>
    {
        #[cfg(not(unix))]
        {
            let _ = expected_registry_digest;
            return Err(LocalSelectedRecursiveClassRegistryError::UnsupportedPlatform);
        }
        #[cfg(unix)]
        {
            let path = self.artifact_path();
            let parent = self.open_version_directory(false)?;
            match parent
                .leaf_kind(REGISTRY_ARTIFACT_FILE)
                .map_err(|source| io_error("inspect anchored leaf", &path, source))?
            {
                anchored_artifact_fs::LeafKind::Regular => {}
                anchored_artifact_fs::LeafKind::Symlink => {
                    return Err(LocalSelectedRecursiveClassRegistryError::Symlink { path });
                }
                anchored_artifact_fs::LeafKind::Other => {
                    return Err(LocalSelectedRecursiveClassRegistryError::NotRegularFile { path });
                }
                anchored_artifact_fs::LeafKind::Missing => {
                    return Err(io_error(
                        "open anchored leaf",
                        &path,
                        io::Error::new(io::ErrorKind::NotFound, "registry artifact is missing"),
                    ));
                }
            }

            let mut file = parent
                .open_read_only(REGISTRY_ARTIFACT_FILE)
                .map_err(|source| io_error("open anchored leaf", &path, source))?;
            let opened = file
                .metadata()
                .map_err(|source| io_error("inspect opened", &path, source))?;
            validate_regular_file(&path, &opened)?;
            reject_oversize(opened.len(), self.effective_max_bytes())?;

            let len = usize::try_from(opened.len()).map_err(|_| {
                LocalSelectedRecursiveClassRegistryError::ArtifactTooLarge {
                    actual: opened.len(),
                    max: self.effective_max_bytes(),
                }
            })?;
            let bytes = read_exact_artifact_bytes(&mut file, len, &path)?;
            let after = file
                .metadata()
                .map_err(|source| io_error("inspect decoded", &path, source))?;
            if !same_file_and_length(&opened, &after) {
                return Err(LocalSelectedRecursiveClassRegistryError::ArtifactChanged { path });
            }
            drop(file);

            let registry =
                decode_selected_recursive_class_registry_pinned(&bytes, expected_registry_digest)?;
            Ok(LoadedSelectedRecursiveClassRegistry { registry })
        }
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
        #[cfg(not(unix))]
        {
            let _ = bytes;
            return Err(LocalSelectedRecursiveClassRegistryError::UnsupportedPlatform);
        }
        #[cfg(unix)]
        {
            reject_oversize(bytes.len() as u64, self.effective_max_bytes())?;
            let target = self.artifact_path();
            let parent = self.open_version_directory(true)?;
            match parent
                .leaf_kind(REGISTRY_ARTIFACT_FILE)
                .map_err(|source| io_error("inspect anchored target", &target, source))?
            {
                anchored_artifact_fs::LeafKind::Missing
                | anchored_artifact_fs::LeafKind::Regular => {}
                anchored_artifact_fs::LeafKind::Symlink => {
                    return Err(LocalSelectedRecursiveClassRegistryError::Symlink { path: target });
                }
                anchored_artifact_fs::LeafKind::Other => {
                    return Err(LocalSelectedRecursiveClassRegistryError::NotRegularFile {
                        path: target,
                    });
                }
            }

            let (temporary_name, mut file) = create_temporary_file(&parent, &target)?;
            let mut cleanup =
                TemporaryCleanup::new(&parent, temporary_name.clone(), target.clone())?;
            file.write_all(bytes)
                .map_err(|source| io_error("write", &target, source))?;
            file.flush()
                .map_err(|source| io_error("flush", &target, source))?;
            file.sync_all()
                .map_err(|source| io_error("sync", &target, source))?;
            drop(file);
            parent
                .rename(&temporary_name, REGISTRY_ARTIFACT_FILE)
                .map_err(|source| io_error("rename anchored artifact", &target, source))?;
            cleanup.disarm();
            parent
                .sync_all()
                .map_err(|source| io_error("sync anchored directory", &target, source))?;
            Ok(())
        }
    }

    fn effective_max_bytes(&self) -> u64 {
        self.max_artifact_bytes
            .min(MAX_SELECTED_RECURSIVE_CLASS_REGISTRY_BYTES as u64)
            .min(usize::MAX as u64)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn prepare_layout(&self) -> Result<(), LocalSelectedRecursiveClassRegistryError> {
        #[cfg(not(unix))]
        {
            return Err(LocalSelectedRecursiveClassRegistryError::UnsupportedPlatform);
        }
        #[cfg(unix)]
        {
            self.open_version_directory(true).map(|_| ())
        }
    }

    #[cfg(unix)]
    fn open_version_directory(
        &self,
        create: bool,
    ) -> Result<anchored_artifact_fs::AnchoredDirectory, LocalSelectedRecursiveClassRegistryError>
    {
        let root = anchored_artifact_fs::AnchoredDirectory::open_tree(&self.root, create)
            .map_err(|source| directory_open_error(&self.root, source))?;
        let version_path = self.root.join(REGISTRY_VERSION_DIRECTORY);
        root.open_child_directory(REGISTRY_VERSION_DIRECTORY, create)
            .map_err(|source| directory_open_error(&version_path, source))
    }
}

/// Read exactly the stat-preflighted regular-file length, then prove EOF with
/// one bounded byte.  `read_to_end` is deliberately forbidden here: an
/// in-place appender could otherwise grow the Vec without the 4 MiB cap even
/// though the post-read metadata check eventually rejects the file.
fn read_exact_artifact_bytes(
    file: &mut File,
    len: usize,
    path: &Path,
) -> Result<Vec<u8>, LocalSelectedRecursiveClassRegistryError> {
    let mut bytes = vec![0u8; len];
    file.read_exact(&mut bytes)
        .map_err(|source| io_error("read exact", path, source))?;
    let mut extra = [0u8; 1];
    match file.read(&mut extra) {
        Ok(0) => Ok(bytes),
        Ok(_) => Err(LocalSelectedRecursiveClassRegistryError::ArtifactChanged {
            path: path.to_path_buf(),
        }),
        Err(source) => Err(io_error("probe artifact EOF", path, source)),
    }
}

#[cfg(unix)]
fn directory_open_error(
    path: &Path,
    source: io::Error,
) -> LocalSelectedRecursiveClassRegistryError {
    // Classification is diagnostic only. Security comes from the descriptor-
    // relative O_NOFOLLOW walk below, so a race in this best-effort path stat
    // can change the error variant but cannot redirect an operation.
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return LocalSelectedRecursiveClassRegistryError::Symlink {
                path: path.to_path_buf(),
            };
        }
        if !metadata.is_dir() {
            return LocalSelectedRecursiveClassRegistryError::NotDirectory {
                path: path.to_path_buf(),
            };
        }
    }
    io_error("open anchored directory", path, source)
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

#[cfg(unix)]
fn create_temporary_file(
    parent: &anchored_artifact_fs::AnchoredDirectory,
    target: &Path,
) -> Result<(String, File), LocalSelectedRecursiveClassRegistryError> {
    let leaf = target
        .file_name()
        .and_then(|value| value.to_str())
        .expect("fixed ASCII registry artifact has a file name");
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
) -> LocalSelectedRecursiveClassRegistryError {
    LocalSelectedRecursiveClassRegistryError::Io {
        operation,
        path: path.to_path_buf(),
        source,
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
    ) -> Result<Self, LocalSelectedRecursiveClassRegistryError> {
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

/// Reusable Unix descriptor-relative filesystem boundary for large local
/// protocol artifacts. Every directory component is opened with O_NOFOLLOW;
/// leaf open/create/rename/unlink operations are relative to the held parent
/// descriptor, so path replacement cannot redirect I/O outside the root.
#[cfg(unix)]
pub(crate) mod anchored_artifact_fs {
    use std::ffi::{CStr, CString};
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::mem::MaybeUninit;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::{Component, Path};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum LeafKind {
        Missing,
        Regular,
        Symlink,
        Other,
    }

    pub(crate) struct AnchoredDirectory {
        file: File,
    }

    impl AnchoredDirectory {
        pub(crate) fn open_tree(path: &Path, create: bool) -> io::Result<Self> {
            let mut current = open_start(path.is_absolute())?;
            for component in path.components() {
                match component {
                    Component::RootDir | Component::CurDir => {}
                    Component::Normal(name) => {
                        current = current.open_child_directory_os(name.as_bytes(), create)?;
                    }
                    Component::ParentDir | Component::Prefix(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "anchored artifact root cannot contain parent/prefix components",
                        ));
                    }
                }
            }
            Ok(current)
        }

        pub(crate) fn open_child_directory(&self, name: &str, create: bool) -> io::Result<Self> {
            self.open_child_directory_os(name.as_bytes(), create)
        }

        fn open_child_directory_os(&self, name: &[u8], create: bool) -> io::Result<Self> {
            let name = cstring(name)?;
            match open_directory_at(self.file.as_raw_fd(), &name) {
                Ok(file) => Ok(Self { file }),
                Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
                    let result = unsafe {
                        libc::mkdirat(self.file.as_raw_fd(), name.as_ptr(), 0o755 as libc::mode_t)
                    };
                    if result != 0 {
                        let mkdir_error = io::Error::last_os_error();
                        if mkdir_error.kind() != io::ErrorKind::AlreadyExists {
                            return Err(mkdir_error);
                        }
                    }
                    open_directory_at(self.file.as_raw_fd(), &name).map(|file| Self { file })
                }
                Err(error) => Err(error),
            }
        }

        pub(crate) fn leaf_kind(&self, name: &str) -> io::Result<LeafKind> {
            let name = cstring(name.as_bytes())?;
            let mut stat = MaybeUninit::<libc::stat>::uninit();
            let result = unsafe {
                libc::fstatat(
                    self.file.as_raw_fd(),
                    name.as_ptr(),
                    stat.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if result != 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::NotFound {
                    return Ok(LeafKind::Missing);
                }
                return Err(error);
            }
            let mode = unsafe { stat.assume_init() }.st_mode & libc::S_IFMT;
            Ok(if mode == libc::S_IFREG {
                LeafKind::Regular
            } else if mode == libc::S_IFLNK {
                LeafKind::Symlink
            } else {
                LeafKind::Other
            })
        }

        pub(crate) fn open_read_only(&self, name: &str) -> io::Result<File> {
            open_file_at(
                self.file.as_raw_fd(),
                &cstring(name.as_bytes())?,
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0,
            )
        }

        pub(crate) fn create_new(&self, name: &str) -> io::Result<File> {
            open_file_at(
                self.file.as_raw_fd(),
                &cstring(name.as_bytes())?,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        }

        pub(crate) fn rename(&self, from: &str, to: &str) -> io::Result<()> {
            let from = cstring(from.as_bytes())?;
            let to = cstring(to.as_bytes())?;
            let result = unsafe {
                libc::renameat(
                    self.file.as_raw_fd(),
                    from.as_ptr(),
                    self.file.as_raw_fd(),
                    to.as_ptr(),
                )
            };
            cvt(result)
        }

        pub(crate) fn unlink(&self, name: &str) -> io::Result<()> {
            let name = cstring(name.as_bytes())?;
            let result = unsafe { libc::unlinkat(self.file.as_raw_fd(), name.as_ptr(), 0) };
            cvt(result)
        }

        pub(crate) fn sync_all(&self) -> io::Result<()> {
            self.file.sync_all()
        }

        pub(crate) fn try_clone(&self) -> io::Result<Self> {
            self.file.try_clone().map(|file| Self { file })
        }
    }

    fn open_start(absolute: bool) -> io::Result<AnchoredDirectory> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW);
        options
            .open(if absolute {
                Path::new("/")
            } else {
                Path::new(".")
            })
            .map(|file| AnchoredDirectory { file })
    }

    fn open_directory_at(parent: libc::c_int, name: &CStr) -> io::Result<File> {
        open_file_at(
            parent,
            name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        )
    }

    fn open_file_at(
        parent: libc::c_int,
        name: &CStr,
        flags: libc::c_int,
        mode: libc::mode_t,
    ) -> io::Result<File> {
        let fd = unsafe { libc::openat(parent, name.as_ptr(), flags, mode) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn cstring(bytes: &[u8]) -> io::Result<CString> {
        CString::new(bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "artifact path component contains NUL",
            )
        })
    }

    fn cvt(result: libc::c_int) -> io::Result<()> {
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
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
            store.load_pinned([0u8; 32]),
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
            store.load_pinned([0u8; 32]),
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

    #[test]
    fn exact_reader_rejects_growth_without_reading_past_preflight_length() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("artifact");
        fs::write(&path, b"bounded").unwrap();
        let mut opened = File::open(&path).unwrap();
        let preflight_len = usize::try_from(opened.metadata().unwrap().len()).unwrap();

        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"growth")
            .unwrap();

        assert!(matches!(
            read_exact_artifact_bytes(&mut opened, preflight_len, &path),
            Err(LocalSelectedRecursiveClassRegistryError::ArtifactChanged { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn held_directory_descriptor_cannot_be_redirected_by_symlink_swap() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().unwrap();
        let store = LocalSelectedRecursiveClassRegistryStore::new(directory.path().join("root"));
        store.prepare_layout().unwrap();
        let anchored = store.open_version_directory(false).unwrap();
        let held = directory.path().join("root/held-v1");
        let outside = directory.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::rename(directory.path().join("root/v1"), &held).unwrap();
        symlink(&outside, directory.path().join("root/v1")).unwrap();

        let mut file = anchored.create_new("probe").unwrap();
        file.write_all(b"anchored").unwrap();
        file.sync_all().unwrap();
        assert_eq!(fs::read(held.join("probe")).unwrap(), b"anchored");
        assert!(!outside.join("probe").exists());
    }
}
