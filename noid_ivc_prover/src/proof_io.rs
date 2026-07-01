//! Minimal serialization for IVC R1CS proof bundles.
//!
//! The production recursive path only needs to carry a witness commitment plus
//! the R1CS proof. Comparator/hash-chain bundles belonged to the old laboratory
//! harness and are intentionally absent here.

use serde::{Deserialize, Serialize};

use noid_ivc_core::pcs::Commitment;
use noid_ivc_core::proof::R1csProof;

pub const MAGIC: [u8; 5] = *b"NOIDI";
pub const VERSION: u8 = 1;

const FLAVOR_R1CS: u8 = 0;
const HEADER_LEN: usize = 7;

#[derive(Debug)]
pub enum DeserializeError {
    BadMagic,
    UnsupportedVersion(u8),
    UnknownFlavor(u8),
    Truncated,
    FlavorMismatch { expected: u8, found: u8 },
    Bincode(bincode::Error),
}

impl std::fmt::Display for DeserializeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "bad magic: not a NOIDI IVC proof bundle"),
            Self::UnsupportedVersion(v) => {
                write!(f, "unsupported IVC proof bundle version {v}")
            }
            Self::UnknownFlavor(v) => write!(f, "unknown IVC proof bundle flavor {v}"),
            Self::Truncated => write!(f, "IVC proof bundle shorter than header"),
            Self::FlavorMismatch { expected, found } => {
                write!(
                    f,
                    "IVC proof bundle flavor mismatch: expected {expected}, found {found}"
                )
            }
            Self::Bincode(error) => write!(f, "IVC proof bundle bincode error: {error}"),
        }
    }
}

impl std::error::Error for DeserializeError {}

impl From<bincode::Error> for DeserializeError {
    fn from(error: bincode::Error) -> Self {
        Self::Bincode(error)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct R1csProofBundle {
    pub commitment: Commitment,
    pub proof: R1csProof,
}

impl R1csProofBundle {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + 1024);
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(FLAVOR_R1CS);
        bincode::serialize_into(&mut out, self).expect("R1csProofBundle serializes");
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DeserializeError> {
        let payload = parse_header(bytes, FLAVOR_R1CS)?;
        Ok(bincode::deserialize(payload)?)
    }
}

fn parse_header(bytes: &[u8], expected_flavor: u8) -> Result<&[u8], DeserializeError> {
    if bytes.len() < HEADER_LEN {
        return Err(DeserializeError::Truncated);
    }
    if bytes[0..5] != MAGIC {
        return Err(DeserializeError::BadMagic);
    }
    let version = bytes[5];
    if version != VERSION {
        return Err(DeserializeError::UnsupportedVersion(version));
    }
    let flavor = bytes[6];
    if flavor != FLAVOR_R1CS {
        return Err(DeserializeError::UnknownFlavor(flavor));
    }
    if flavor != expected_flavor {
        return Err(DeserializeError::FlavorMismatch {
            expected: expected_flavor,
            found: flavor,
        });
    }
    Ok(&bytes[HEADER_LEN..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_truncated() {
        assert!(matches!(
            R1csProofBundle::from_bytes(&[0u8; 3]),
            Err(DeserializeError::Truncated)
        ));
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"NOIDH");
        bytes.push(VERSION);
        bytes.push(FLAVOR_R1CS);
        assert!(matches!(
            R1csProofBundle::from_bytes(&bytes),
            Err(DeserializeError::BadMagic)
        ));
    }
}
