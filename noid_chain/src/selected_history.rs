// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical chain-level metadata prefix for selected-history terminals.
//!
//! The recursive layer owns and verifies the opaque Link proof envelope.  The
//! chain/storage layer owns the fixed metadata that binds those bytes to one
//! canonical job.  Keeping this codec below both layers prevents release,
//! storage, P2P, and scheduler tests from independently spelling consensus
//! slot/tier bytes.

use core::fmt;

use crate::consensus::params::USER_TX_CLASS_TIERS;

/// First and only pre-launch selected-history terminal wire version.
pub const SELECTED_HISTORY_TERMINAL_VERSION: u16 = 1;

/// version + height + block hash + canonical class slot + canonical tier.
pub const SELECTED_HISTORY_TERMINAL_METADATA_BYTES: usize = 2 + 8 + 32 + 1 + 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectedHistoryTerminalMetadata {
    terminal_height: u64,
    terminal_hash: [u8; 32],
    canonical_tip_slot: u8,
    canonical_tip_tier: u16,
}

impl SelectedHistoryTerminalMetadata {
    /// Construct metadata from the consensus slot table.  Callers never
    /// supply the tier independently, so a slot/tier mismatch cannot be
    /// authored through the typed API.
    pub fn new(
        terminal_height: u64,
        terminal_hash: [u8; 32],
        canonical_tip_slot: usize,
    ) -> Result<Self, SelectedHistoryTerminalMetadataError> {
        let tier = USER_TX_CLASS_TIERS.get(canonical_tip_slot).copied().ok_or(
            SelectedHistoryTerminalMetadataError::InvalidTipSlot {
                actual: canonical_tip_slot,
            },
        )?;
        let canonical_tip_slot = u8::try_from(canonical_tip_slot).map_err(|_| {
            SelectedHistoryTerminalMetadataError::InvalidTipSlot {
                actual: canonical_tip_slot,
            }
        })?;
        let canonical_tip_tier = u16::try_from(tier).expect("canonical transaction tier fits u16");
        Ok(Self {
            terminal_height,
            terminal_hash,
            canonical_tip_slot,
            canonical_tip_tier,
        })
    }

    /// Decode and validate the fixed prefix of a complete terminal package.
    /// The recursive layer remains responsible for the following envelope.
    pub fn decode_prefix(bytes: &[u8]) -> Result<Self, SelectedHistoryTerminalMetadataError> {
        if bytes.len() < SELECTED_HISTORY_TERMINAL_METADATA_BYTES {
            return Err(SelectedHistoryTerminalMetadataError::Truncated);
        }
        let version = u16::from_le_bytes(bytes[0..2].try_into().unwrap());
        if version != SELECTED_HISTORY_TERMINAL_VERSION {
            return Err(SelectedHistoryTerminalMetadataError::UnsupportedVersion {
                actual: version,
            });
        }
        let terminal_height = u64::from_le_bytes(bytes[2..10].try_into().unwrap());
        let terminal_hash = bytes[10..42].try_into().unwrap();
        let slot = usize::from(bytes[42]);
        let actual_tier = usize::from(u16::from_le_bytes(bytes[43..45].try_into().unwrap()));
        let expected_tier = USER_TX_CLASS_TIERS
            .get(slot)
            .copied()
            .ok_or(SelectedHistoryTerminalMetadataError::InvalidTipSlot { actual: slot })?;
        if actual_tier != expected_tier {
            return Err(SelectedHistoryTerminalMetadataError::TipTierMismatch {
                slot,
                expected: expected_tier,
                actual: actual_tier,
            });
        }
        Self::new(terminal_height, terminal_hash, slot)
    }

    pub fn encode_prefix(self) -> [u8; SELECTED_HISTORY_TERMINAL_METADATA_BYTES] {
        let mut encoded = [0u8; SELECTED_HISTORY_TERMINAL_METADATA_BYTES];
        encoded[0..2].copy_from_slice(&SELECTED_HISTORY_TERMINAL_VERSION.to_le_bytes());
        encoded[2..10].copy_from_slice(&self.terminal_height.to_le_bytes());
        encoded[10..42].copy_from_slice(&self.terminal_hash);
        encoded[42] = self.canonical_tip_slot;
        encoded[43..45].copy_from_slice(&self.canonical_tip_tier.to_le_bytes());
        encoded
    }

    pub const fn terminal_height(self) -> u64 {
        self.terminal_height
    }

    pub const fn terminal_hash(self) -> [u8; 32] {
        self.terminal_hash
    }

    pub const fn canonical_tip_slot(self) -> usize {
        self.canonical_tip_slot as usize
    }

    pub const fn canonical_tip_tier(self) -> usize {
        self.canonical_tip_tier as usize
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelectedHistoryTerminalMetadataError {
    Truncated,
    UnsupportedVersion {
        actual: u16,
    },
    InvalidTipSlot {
        actual: usize,
    },
    TipTierMismatch {
        slot: usize,
        expected: usize,
        actual: usize,
    },
}

impl fmt::Display for SelectedHistoryTerminalMetadataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => {
                formatter.write_str("selected-history terminal metadata is truncated")
            }
            Self::UnsupportedVersion { actual } => {
                write!(formatter, "unsupported selected-history version {actual}")
            }
            Self::InvalidTipSlot { actual } => {
                write!(
                    formatter,
                    "selected-history tip slot {actual} is not canonical"
                )
            }
            Self::TipTierMismatch {
                slot,
                expected,
                actual,
            } => write!(
                formatter,
                "selected-history tip slot {slot} requires tier {expected}, got {actual}"
            ),
        }
    }
}

impl std::error::Error for SelectedHistoryTerminalMetadataError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_consensus_slots_roundtrip_without_an_independent_tier_input() {
        for (slot, tier) in USER_TX_CLASS_TIERS.into_iter().enumerate() {
            let metadata = SelectedHistoryTerminalMetadata::new(9, [slot as u8; 32], slot)
                .expect("canonical slot");
            assert_eq!(metadata.canonical_tip_tier(), tier);
            assert_eq!(
                SelectedHistoryTerminalMetadata::decode_prefix(&metadata.encode_prefix()),
                Ok(metadata)
            );
        }
    }

    #[test]
    fn decode_rejects_every_noncanonical_slot_tier_pair() {
        let mut encoded = SelectedHistoryTerminalMetadata::new(9, [0xA5; 32], 3)
            .unwrap()
            .encode_prefix();
        encoded[43..45].copy_from_slice(&8u16.to_le_bytes());
        assert_eq!(
            SelectedHistoryTerminalMetadata::decode_prefix(&encoded),
            Err(SelectedHistoryTerminalMetadataError::TipTierMismatch {
                slot: 3,
                expected: 255,
                actual: 8,
            })
        );
    }
}
