// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical chain-level metadata prefix for HistoryStep terminals.
//!
//! The recursive layer owns and verifies the proof envelope after this prefix.
//! Chain, storage and transport share this exact pre-launch codec.

use core::fmt;

pub const HISTORY_STEP_TERMINAL_VERSION: u8 = 1;
pub const HISTORY_STEP_TERMINAL_BINDING_BYTES: usize = 1 + 8 + 32 + 1;
pub const HISTORY_STEP_TIER_SLOT_COUNT: u8 = 4;
pub const HISTORY_STEP_CLASS_COUNT: u8 =
    HISTORY_STEP_TIER_SLOT_COUNT * HISTORY_STEP_TIER_SLOT_COUNT;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryStepTerminalMetadata {
    terminal_height: u64,
    terminal_hash: [u8; 32],
    class_id: u8,
}

impl HistoryStepTerminalMetadata {
    pub fn new(
        terminal_height: u64,
        terminal_hash: [u8; 32],
        class_id: u8,
    ) -> Result<Self, HistoryStepTerminalMetadataError> {
        if class_id >= HISTORY_STEP_CLASS_COUNT {
            return Err(HistoryStepTerminalMetadataError::InvalidClassId { actual: class_id });
        }
        Ok(Self {
            terminal_height,
            terminal_hash,
            class_id,
        })
    }

    pub fn decode_prefix(bytes: &[u8]) -> Result<Self, HistoryStepTerminalMetadataError> {
        if bytes.len() < HISTORY_STEP_TERMINAL_BINDING_BYTES {
            return Err(HistoryStepTerminalMetadataError::Truncated);
        }
        let version = bytes[0];
        if version != HISTORY_STEP_TERMINAL_VERSION {
            return Err(HistoryStepTerminalMetadataError::UnsupportedVersion { actual: version });
        }
        let terminal_height = u64::from_le_bytes(bytes[1..9].try_into().unwrap());
        let terminal_hash = bytes[9..41].try_into().unwrap();
        Self::new(terminal_height, terminal_hash, bytes[41])
    }

    pub fn encode_prefix(self) -> [u8; HISTORY_STEP_TERMINAL_BINDING_BYTES] {
        let mut encoded = [0u8; HISTORY_STEP_TERMINAL_BINDING_BYTES];
        encoded[0] = HISTORY_STEP_TERMINAL_VERSION;
        encoded[1..9].copy_from_slice(&self.terminal_height.to_le_bytes());
        encoded[9..41].copy_from_slice(&self.terminal_hash);
        encoded[41] = self.class_id;
        encoded
    }

    pub const fn terminal_height(self) -> u64 {
        self.terminal_height
    }

    pub const fn terminal_hash(self) -> [u8; 32] {
        self.terminal_hash
    }

    pub const fn class_id(self) -> u8 {
        self.class_id
    }

    pub const fn current_class_slot(self) -> usize {
        (self.class_id / HISTORY_STEP_TIER_SLOT_COUNT) as usize
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HistoryStepTerminalMetadataError {
    Truncated,
    UnsupportedVersion { actual: u8 },
    InvalidClassId { actual: u8 },
}

impl fmt::Display for HistoryStepTerminalMetadataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => formatter.write_str("HistoryStep terminal metadata is truncated"),
            Self::UnsupportedVersion { actual } => {
                write!(formatter, "unsupported HistoryStep version {actual}")
            }
            Self::InvalidClassId { actual } => {
                write!(formatter, "HistoryStep class id {actual} is not canonical")
            }
        }
    }
}

impl std::error::Error for HistoryStepTerminalMetadataError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_canonical_classes_roundtrip() {
        for class_id in 0..HISTORY_STEP_CLASS_COUNT {
            let metadata = HistoryStepTerminalMetadata::new(9, [class_id; 32], class_id)
                .expect("canonical class");
            assert_eq!(
                HistoryStepTerminalMetadata::decode_prefix(&metadata.encode_prefix()),
                Ok(metadata)
            );
        }
    }

    #[test]
    fn noncanonical_class_is_rejected() {
        let mut encoded = HistoryStepTerminalMetadata::new(9, [0xA5; 32], 15)
            .unwrap()
            .encode_prefix();
        encoded[41] = HISTORY_STEP_CLASS_COUNT;
        assert_eq!(
            HistoryStepTerminalMetadata::decode_prefix(&encoded),
            Err(HistoryStepTerminalMetadataError::InvalidClassId {
                actual: HISTORY_STEP_CLASS_COUNT,
            })
        );
    }
}
