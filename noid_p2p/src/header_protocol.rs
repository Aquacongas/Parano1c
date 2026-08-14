// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Fixed header-first announcement for network v2.

use noid_chain::{
    block::BLOCK_WIRE_HEADER_OFFSET,
    block_header::{block_id, semantic_header_id},
    consensus::wire_limits::{MAX_BLOCK_BYTES, MAX_HISTORY_STEP_TERMINAL_BYTES},
    history_step::{HistoryStepTerminalMetadata, HISTORY_STEP_CLASS_COUNT},
    AcceptedBlockBundle, BlockHeader, BLOCK_HEADER_WIRE_SIZE,
};
use thiserror::Error;

use crate::object_protocol::{
    BlockBodyClaimId, BlockBodyObjectId, TerminalClaimId, TerminalObjectId,
};

const HEADER_ANNOUNCE_MAGIC: [u8; 4] = *b"NHA2";
const RESERVED_BYTES: usize = 2;
pub const HEADER_ANNOUNCE_BYTES: usize =
    4 + BLOCK_HEADER_WIRE_SIZE + 32 + 4 + 32 + 4 + 1 + 1 + RESERVED_BYTES;
pub const MAX_HEADER_ANNOUNCE_BYTES: usize = 512;

const _: () = assert!(HEADER_ANNOUNCE_BYTES <= MAX_HEADER_ANNOUNCE_BYTES);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderFlags(u8);

impl ProviderFlags {
    pub const BODY: u8 = 1 << 0;
    pub const TERMINAL: u8 = 1 << 1;
    pub const SNAPSHOT: u8 = 1 << 2;
    const KNOWN: u8 = Self::BODY | Self::TERMINAL | Self::SNAPSHOT;

    pub const fn new(body: bool, terminal: bool, snapshot: bool) -> Self {
        Self(
            (body as u8) * Self::BODY
                | (terminal as u8) * Self::TERMINAL
                | (snapshot as u8) * Self::SNAPSHOT,
        )
    }

    pub const fn serves_body(self) -> bool {
        self.0 & Self::BODY != 0
    }

    pub const fn serves_terminal(self) -> bool {
        self.0 & Self::TERMINAL != 0
    }

    pub const fn serves_snapshot(self) -> bool {
        self.0 & Self::SNAPSHOT != 0
    }

    fn decode(bits: u8) -> Result<Self, HeaderAnnounceError> {
        if bits & !Self::KNOWN != 0 {
            return Err(HeaderAnnounceError::UnknownProviderFlags(bits));
        }
        Ok(Self(bits))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderAnnouncement {
    pub header: BlockHeader,
    pub body: BlockBodyObjectId,
    pub terminal: TerminalObjectId,
    pub providers: ProviderFlags,
}

impl HeaderAnnouncement {
    pub fn from_accepted_bundle(
        bundle: &AcceptedBlockBundle,
        providers: ProviderFlags,
    ) -> Result<Self, HeaderAnnounceError> {
        let header_end = BLOCK_WIRE_HEADER_OFFSET
            .checked_add(BLOCK_HEADER_WIRE_SIZE)
            .ok_or(HeaderAnnounceError::InvalidBundleHeader)?;
        let header = BlockHeader::from_bytes(
            bundle
                .block_bytes()
                .get(BLOCK_WIRE_HEADER_OFFSET..header_end)
                .ok_or(HeaderAnnounceError::InvalidBundleHeader)?,
        )
        .map_err(|_| HeaderAnnounceError::InvalidBundleHeader)?;
        let metadata =
            HistoryStepTerminalMetadata::decode_prefix(bundle.history_step_terminal_bytes())
                .map_err(|_| HeaderAnnounceError::InvalidTerminalMetadata)?;
        let body_claim = BlockBodyClaimId {
            height: header.height,
            block_hash: block_id(&header),
        };
        let terminal_claim = TerminalClaimId {
            height: header.height,
            semantic_header_id: semantic_header_id(&header),
            proof_class: metadata.class_id(),
        };
        let body = BlockBodyObjectId::from_bytes(body_claim, bundle.block_bytes())
            .ok_or(HeaderAnnounceError::ObjectLengthOverflow)?;
        let terminal =
            TerminalObjectId::from_bytes(terminal_claim, bundle.history_step_terminal_bytes())
                .ok_or(HeaderAnnounceError::ObjectLengthOverflow)?;
        let announcement = Self {
            header,
            body,
            terminal,
            providers,
        };
        announcement.validate()?;
        Ok(announcement)
    }

    pub fn encode(self) -> Result<[u8; HEADER_ANNOUNCE_BYTES], HeaderAnnounceError> {
        self.validate()?;
        let mut encoded = [0u8; HEADER_ANNOUNCE_BYTES];
        encoded[..4].copy_from_slice(&HEADER_ANNOUNCE_MAGIC);
        let mut cursor = 4;
        encoded[cursor..cursor + BLOCK_HEADER_WIRE_SIZE].copy_from_slice(&self.header.to_bytes());
        cursor += BLOCK_HEADER_WIRE_SIZE;
        encoded[cursor..cursor + 32].copy_from_slice(&self.body.byte_digest);
        cursor += 32;
        encoded[cursor..cursor + 4].copy_from_slice(&self.body.encoded_len.to_le_bytes());
        cursor += 4;
        encoded[cursor..cursor + 32].copy_from_slice(&self.terminal.byte_digest);
        cursor += 32;
        encoded[cursor..cursor + 4].copy_from_slice(&self.terminal.encoded_len.to_le_bytes());
        cursor += 4;
        encoded[cursor] = self.terminal.claim.proof_class;
        cursor += 1;
        encoded[cursor] = self.providers.0;
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, HeaderAnnounceError> {
        if encoded.len() != HEADER_ANNOUNCE_BYTES {
            return Err(HeaderAnnounceError::NonCanonicalLength(encoded.len()));
        }
        if encoded[..4] != HEADER_ANNOUNCE_MAGIC {
            return Err(HeaderAnnounceError::BadMagic);
        }
        if encoded[HEADER_ANNOUNCE_BYTES - RESERVED_BYTES..] != [0; RESERVED_BYTES] {
            return Err(HeaderAnnounceError::NonZeroReserved);
        }
        let mut cursor = 4;
        let header = BlockHeader::from_bytes(&encoded[cursor..cursor + BLOCK_HEADER_WIRE_SIZE])
            .map_err(|_| HeaderAnnounceError::InvalidHeader)?;
        cursor += BLOCK_HEADER_WIRE_SIZE;
        let body_digest = encoded[cursor..cursor + 32].try_into().unwrap();
        cursor += 32;
        let body_len = u32::from_le_bytes(encoded[cursor..cursor + 4].try_into().unwrap());
        cursor += 4;
        let terminal_digest = encoded[cursor..cursor + 32].try_into().unwrap();
        cursor += 32;
        let terminal_len = u32::from_le_bytes(encoded[cursor..cursor + 4].try_into().unwrap());
        cursor += 4;
        let proof_class = encoded[cursor];
        cursor += 1;
        let providers = ProviderFlags::decode(encoded[cursor])?;

        let announcement = Self {
            header,
            body: BlockBodyObjectId {
                claim: BlockBodyClaimId {
                    height: header.height,
                    block_hash: block_id(&header),
                },
                byte_digest: body_digest,
                encoded_len: body_len,
            },
            terminal: TerminalObjectId {
                claim: TerminalClaimId {
                    height: header.height,
                    semantic_header_id: semantic_header_id(&header),
                    proof_class,
                },
                byte_digest: terminal_digest,
                encoded_len: terminal_len,
            },
            providers,
        };
        announcement.validate()?;
        Ok(announcement)
    }

    pub fn validate(&self) -> Result<(), HeaderAnnounceError> {
        let expected_hash = block_id(&self.header);
        if self.body.claim.height != self.header.height
            || self.body.claim.block_hash != expected_hash
        {
            return Err(HeaderAnnounceError::BodyClaimMismatch);
        }
        if self.terminal.claim.height != self.header.height
            || self.terminal.claim.semantic_header_id != semantic_header_id(&self.header)
        {
            return Err(HeaderAnnounceError::TerminalClaimMismatch);
        }
        if self.terminal.claim.proof_class >= HISTORY_STEP_CLASS_COUNT {
            return Err(HeaderAnnounceError::InvalidProofClass(
                self.terminal.claim.proof_class,
            ));
        }
        if self.body.encoded_len == 0 || self.body.encoded_len as usize > MAX_BLOCK_BYTES {
            return Err(HeaderAnnounceError::BodyLength(self.body.encoded_len));
        }
        if self.terminal.encoded_len == 0
            || self.terminal.encoded_len as usize > MAX_HISTORY_STEP_TERMINAL_BYTES
        {
            return Err(HeaderAnnounceError::TerminalLength(
                self.terminal.encoded_len,
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum HeaderAnnounceError {
    #[error("header announcement has non-canonical length {0}")]
    NonCanonicalLength(usize),
    #[error("header announcement magic/version is invalid")]
    BadMagic,
    #[error("header announcement reserved bytes are non-zero")]
    NonZeroReserved,
    #[error("canonical block header decode failed")]
    InvalidHeader,
    #[error("accepted bundle does not contain a canonical header")]
    InvalidBundleHeader,
    #[error("accepted bundle terminal metadata is invalid")]
    InvalidTerminalMetadata,
    #[error("object length does not fit the fixed wire field")]
    ObjectLengthOverflow,
    #[error("body object claim does not match the announced header")]
    BodyClaimMismatch,
    #[error("terminal object claim does not match the announced semantic header")]
    TerminalClaimMismatch,
    #[error("proof class {0} is not part of the active class bank")]
    InvalidProofClass(u8),
    #[error("block body length {0} is outside the fixed wire cap")]
    BodyLength(u32),
    #[error("HistoryStep terminal length {0} is outside the active profile cap")]
    TerminalLength(u32),
    #[error("provider flag byte contains unknown bits: {0:#04x}")]
    UnknownProviderFlags(u8),
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::{history_step::HISTORY_STEP_TERMINAL_VERSION, Block};

    fn bundle() -> AcceptedBlockBundle {
        let mut header = noid_chain::consensus::genesis_header();
        header.height = 1;
        header.prev_block_hash = block_id(&noid_chain::consensus::genesis_header());
        let block = Block {
            header,
            transactions: Vec::new(),
        };
        let mut terminal = Vec::new();
        terminal.push(HISTORY_STEP_TERMINAL_VERSION);
        terminal.extend_from_slice(&header.height.to_le_bytes());
        terminal.extend_from_slice(&semantic_header_id(&header));
        terminal.push(0);
        terminal.push(0xA5);
        AcceptedBlockBundle::try_from_parts(block.to_bytes(), terminal).unwrap()
    }

    #[test]
    fn announcement_round_trip_binds_header_and_exact_objects() {
        let announcement = HeaderAnnouncement::from_accepted_bundle(
            &bundle(),
            ProviderFlags::new(true, true, false),
        )
        .unwrap();
        let decoded = HeaderAnnouncement::decode(&announcement.encode().unwrap()).unwrap();
        assert_eq!(decoded, announcement);
        assert!(decoded.providers.serves_body());
        assert!(decoded.providers.serves_terminal());
        assert!(decoded.body.matches_bytes(bundle().block_bytes()));
        assert!(decoded
            .terminal
            .matches_bytes(bundle().history_step_terminal_bytes()));
    }

    #[test]
    fn malformed_lengths_flags_and_reserved_bytes_fail_closed() {
        let announcement = HeaderAnnouncement::from_accepted_bundle(
            &bundle(),
            ProviderFlags::new(true, true, false),
        )
        .unwrap();
        let encoded = announcement.encode().unwrap();
        assert!(matches!(
            HeaderAnnouncement::decode(&encoded[..encoded.len() - 1]),
            Err(HeaderAnnounceError::NonCanonicalLength(_))
        ));

        let mut bad_flags = encoded;
        bad_flags[HEADER_ANNOUNCE_BYTES - RESERVED_BYTES - 1] = 0x80;
        assert_eq!(
            HeaderAnnouncement::decode(&bad_flags),
            Err(HeaderAnnounceError::UnknownProviderFlags(0x80))
        );

        let mut bad_reserved = encoded;
        bad_reserved[HEADER_ANNOUNCE_BYTES - 1] = 1;
        assert_eq!(
            HeaderAnnouncement::decode(&bad_reserved),
            Err(HeaderAnnounceError::NonZeroReserved)
        );
    }

    #[test]
    fn object_claim_substitution_is_rejected_before_encoding() {
        let mut announcement = HeaderAnnouncement::from_accepted_bundle(
            &bundle(),
            ProviderFlags::new(true, true, false),
        )
        .unwrap();
        announcement.body.claim.block_hash[0] ^= 1;
        assert_eq!(
            announcement.encode(),
            Err(HeaderAnnounceError::BodyClaimMismatch)
        );
    }
}
