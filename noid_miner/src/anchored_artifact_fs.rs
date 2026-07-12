// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Descriptor-relative filesystem boundary for local protocol artifacts.
//!
//! Every directory component is opened with `O_NOFOLLOW`. Leaf open/create,
//! rename, unlink, and directory sync operations are relative to a held parent
//! descriptor, so replacing a configured path cannot redirect an in-flight
//! operation outside the directory that was actually opened.

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
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
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
