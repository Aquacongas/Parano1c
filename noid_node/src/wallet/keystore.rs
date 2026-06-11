// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Plaintext key file: master_secret → disk.
//!
//! Format: `noid_plain_key_1` (16 bytes magic) + secret (32 bytes) = 48 bytes.
//!
//! Security model: the file is stored at `~/.paranoid/data/wallet.key` with
//! permissions 0o600 (owner-only). No encryption — the OS filesystem is the
//! security boundary during development. Future versions will derive the
//! master secret from a user-chosen file (photo, document, etc.) instead of
//! generating random bytes.

use std::path::{Path, PathBuf};

use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use noid_poseidon2b::primitives::{Address, SpendSecret};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("wallet already exists at {0}")]
    AlreadyExists(PathBuf),
    #[error("wallet file not found at {0}")]
    NotFound(PathBuf),
    #[error("invalid wallet file format")]
    InvalidFormat,
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// On-disk format (plaintext)
// ---------------------------------------------------------------------------

const PLAIN_MAGIC: &[u8; 16] = b"noid_plain_key_1";
const SECRET_LEN: usize = 32;
const PLAIN_FILE_LEN: usize = 16 + SECRET_LEN; // 48 bytes

// ---------------------------------------------------------------------------
// MasterSecret
// ---------------------------------------------------------------------------

/// The decrypted master secret (zeroized on drop).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterSecret(pub [u8; SECRET_LEN]);

impl MasterSecret {
    /// Derive the spending secret for address index `n`.
    ///
    /// `spend_secret_n = Poseidon2b(master_secret, n, domain_tag)`
    ///
    /// The derived secret is used by `prove_logic` to generate auth proofs.
    /// It NEVER leaves the daemon.
    pub fn derive_spend_secret(&self, index: u32) -> SpendSecret {
        use noid_core::{Block128, TowerField};
        use noid_poseidon2b::native::compression::Poseidon2bSponge;

        let mut sponge = Poseidon2bSponge::with_iv([Block128::ZERO; 2]);
        let lo = u128::from_le_bytes(self.0[..16].try_into().unwrap());
        let hi = u128::from_le_bytes(self.0[16..].try_into().unwrap());
        sponge.absorb(Block128::from(lo));
        sponge.absorb(Block128::from(hi));
        sponge.absorb(Block128::from(index as u128));
        sponge.absorb(Block128::from(0x6E6F69642D64657269_u128)); // "noid-deri"
        let digest = sponge.finalize();
        SpendSecret(digest)
    }

    /// Derive the public address for index `n` (safe to share).
    pub fn derive_address(&self, index: u32) -> Address {
        let secret = self.derive_spend_secret(index);
        noid_poseidon2b::primitives::derive_address(&secret)
    }
}

// ---------------------------------------------------------------------------
// Keystore
// ---------------------------------------------------------------------------

/// Manages the plaintext wallet key file on disk.
pub struct Keystore {
    path: PathBuf,
}

impl Keystore {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Create a new wallet with a randomly generated secret.
    /// Writes `magic[16] + secret[32]` = 48 bytes with mode 0o600.
    /// Fails if the file already exists.
    pub fn create_plain(&self) -> Result<MasterSecret, KeystoreError> {
        if self.exists() {
            return Err(KeystoreError::AlreadyExists(self.path.clone()));
        }
        let mut secret = [0u8; SECRET_LEN];
        rand::thread_rng().fill_bytes(&mut secret);

        let mut buf = Vec::with_capacity(PLAIN_FILE_LEN);
        buf.extend_from_slice(PLAIN_MAGIC);
        buf.extend_from_slice(&secret);

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Atomic write: write to .tmp then rename.
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &buf)?;
        std::fs::rename(&tmp, &self.path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(MasterSecret(secret))
    }

    /// Load a plaintext wallet key file.
    pub fn load_plain(&self) -> Result<MasterSecret, KeystoreError> {
        if !self.exists() {
            return Err(KeystoreError::NotFound(self.path.clone()));
        }
        let data = std::fs::read(&self.path)?;
        if data.len() != PLAIN_FILE_LEN {
            return Err(KeystoreError::InvalidFormat);
        }
        if &data[..16] != PLAIN_MAGIC.as_ref() {
            return Err(KeystoreError::InvalidFormat);
        }
        let mut secret = [0u8; SECRET_LEN];
        secret.copy_from_slice(&data[16..]);
        Ok(MasterSecret(secret))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn create_and_load_plain() {
        let dir = TempDir::new().unwrap();
        let ks = Keystore::new(dir.path().join("wallet.key"));
        let secret = ks.create_plain().unwrap();
        let loaded = ks.load_plain().unwrap();
        assert_eq!(secret.0, loaded.0);
    }

    #[test]
    fn double_create_fails() {
        let dir = TempDir::new().unwrap();
        let ks = Keystore::new(dir.path().join("wallet.key"));
        ks.create_plain().unwrap();
        assert!(matches!(
            ks.create_plain(),
            Err(KeystoreError::AlreadyExists(_))
        ));
    }

    #[test]
    fn load_missing_fails() {
        let dir = TempDir::new().unwrap();
        let ks = Keystore::new(dir.path().join("wallet.key"));
        assert!(matches!(ks.load_plain(), Err(KeystoreError::NotFound(_))));
    }

    #[test]
    fn address_derivation_deterministic() {
        let dir = TempDir::new().unwrap();
        let ks = Keystore::new(dir.path().join("wallet.key"));
        let secret = ks.create_plain().unwrap();
        assert_eq!(secret.derive_address(0), secret.derive_address(0));
        assert_ne!(secret.derive_address(0), secret.derive_address(1));
    }

    #[test]
    fn spend_secret_differs_per_index() {
        let dir = TempDir::new().unwrap();
        let ks = Keystore::new(dir.path().join("wallet.key"));
        let master = ks.create_plain().unwrap();
        assert_ne!(
            master.derive_spend_secret(0).0,
            master.derive_spend_secret(1).0
        );
    }
}
