// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Allocation-bounded codec for one retained accepted-block bundle.

use std::{io, sync::Arc};

use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{request_response, swarm::StreamProtocol};
use noid_chain::{AcceptedBlockBundle, MAX_ACCEPTED_BLOCK_BUNDLE_BYTES};

use crate::inbound_budget::process_global_inbound_budget;
use crate::outbound_budget::OutboundResponseBudget;
use crate::protocol::{GetRecentBlockRequest, GetRecentBlockResponse};

const REQUEST_MAGIC: [u8; 4] = *b"NBR1";
const RESPONSE_MAGIC: [u8; 4] = *b"NBS1";
const REQUEST_HEADER_BYTES: usize = 12;
const RESPONSE_HEADER_BYTES: usize = 16;
const NONE_LEN: u32 = u32::MAX;

#[derive(Debug, Clone)]
pub struct BlockSyncCodec {
    inbound_budget: Arc<tokio::sync::Semaphore>,
    outbound_budget: OutboundResponseBudget,
}

impl Default for BlockSyncCodec {
    fn default() -> Self {
        Self {
            inbound_budget: process_global_inbound_budget(),
            outbound_budget: OutboundResponseBudget::process_global(),
        }
    }
}

impl BlockSyncCodec {
    #[cfg(test)]
    fn with_inbound_budget(bytes: usize) -> Self {
        Self {
            inbound_budget: Arc::new(tokio::sync::Semaphore::new(bytes)),
            outbound_budget: OutboundResponseBudget::process_global(),
        }
    }

    async fn acquire_inbound(
        &self,
        bytes: usize,
    ) -> io::Result<Option<Arc<tokio::sync::OwnedSemaphorePermit>>> {
        if bytes == 0 {
            return Ok(None);
        }
        let permits = u32::try_from(bytes)
            .map_err(|_| invalid_data("accepted-block bundle byte budget overflow"))?;
        let permit = self
            .inbound_budget
            .clone()
            .acquire_many_owned(permits)
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "block-sync byte budget closed")
            })?;
        Ok(Some(Arc::new(permit)))
    }
}

#[async_trait]
impl request_response::Codec for BlockSyncCodec {
    type Protocol = StreamProtocol;
    type Request = GetRecentBlockRequest;
    type Response = GetRecentBlockResponse;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut header = [0u8; REQUEST_HEADER_BYTES];
        io.read_exact(&mut header).await?;
        if header[..4] != REQUEST_MAGIC {
            return Err(invalid_data("invalid block-sync request magic/version"));
        }
        ensure_eof(io).await?;
        Ok(GetRecentBlockRequest {
            height: u64::from_le_bytes(header[4..12].try_into().unwrap()),
        })
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut header = [0u8; RESPONSE_HEADER_BYTES];
        io.read_exact(&mut header).await?;
        if header[..4] != RESPONSE_MAGIC {
            return Err(invalid_data("invalid block-sync response magic/version"));
        }
        let height = u64::from_le_bytes(header[4..12].try_into().unwrap());
        let encoded_len = u32::from_le_bytes(header[12..16].try_into().unwrap());
        let bundle_len = validate_encoded_len(encoded_len)?;
        let inbound_memory_permit = self.acquire_inbound(bundle_len).await?;
        let bundle = if encoded_len == NONE_LEN {
            None
        } else {
            let mut encoded = allocate_payload(bundle_len)?;
            io.read_exact(&mut encoded).await?;
            let bundle = AcceptedBlockBundle::decode(&encoded)
                .map_err(|error| invalid_data(&format!("accepted-block bundle: {error}")))?;
            if bundle.height() != height {
                return Err(invalid_data(
                    "accepted-block bundle height does not match response",
                ));
            }
            Some(bundle)
        };
        ensure_eof(io).await?;
        Ok(GetRecentBlockResponse {
            height,
            bundle,
            inbound_memory_permit,
            outbound_memory_permit: None,
        })
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let mut header = [0u8; REQUEST_HEADER_BYTES];
        header[..4].copy_from_slice(&REQUEST_MAGIC);
        header[4..12].copy_from_slice(&request.height.to_le_bytes());
        io.write_all(&header).await
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let GetRecentBlockResponse {
            height,
            bundle,
            inbound_memory_permit,
            outbound_memory_permit,
        } = response;
        if bundle
            .as_ref()
            .is_some_and(|bundle| bundle.height() != height)
        {
            return Err(invalid_data(
                "accepted-block bundle height does not match response",
            ));
        }
        let encoded = bundle.as_ref().map(AcceptedBlockBundle::encode);
        let encoded_len = match encoded.as_ref() {
            Some(encoded) => u32::try_from(encoded.len())
                .map_err(|_| invalid_data("accepted-block bundle length does not fit u32"))?,
            None => NONE_LEN,
        };
        let payload_len = validate_encoded_len(encoded_len)?;
        let outbound_memory_permit = match outbound_memory_permit {
            Some(permit) => Some(permit),
            None => self.outbound_budget.acquire(payload_len).await?,
        };
        let _memory_permits = (inbound_memory_permit, outbound_memory_permit);

        let mut header = [0u8; RESPONSE_HEADER_BYTES];
        header[..4].copy_from_slice(&RESPONSE_MAGIC);
        header[4..12].copy_from_slice(&height.to_le_bytes());
        header[12..16].copy_from_slice(&encoded_len.to_le_bytes());
        io.write_all(&header).await?;
        if let Some(encoded) = encoded {
            io.write_all(&encoded).await?;
        }
        Ok(())
    }
}

fn validate_encoded_len(encoded_len: u32) -> io::Result<usize> {
    if encoded_len == NONE_LEN {
        return Ok(0);
    }
    let len = encoded_len as usize;
    if len == 0 {
        return Err(invalid_data("present accepted-block bundle is empty"));
    }
    if len > MAX_ACCEPTED_BLOCK_BUNDLE_BYTES {
        return Err(invalid_data(
            "declared accepted-block bundle exceeds wire cap",
        ));
    }
    Ok(len)
}

fn allocate_payload(len: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(len).map_err(|_| {
        io::Error::new(
            io::ErrorKind::OutOfMemory,
            "accepted-block bundle allocation failed",
        )
    })?;
    bytes.resize(len, 0);
    Ok(bytes)
}

async fn ensure_eof<T: AsyncRead + Unpin + Send>(io: &mut T) -> io::Result<()> {
    let mut trailing = [0u8; 1];
    if io.read(&mut trailing).await? != 0 {
        return Err(invalid_data("trailing bytes in block-sync message"));
    }
    Ok(())
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}

#[cfg(test)]
mod tests {
    use futures::io::Cursor;
    use libp2p::request_response::Codec;
    use noid_chain::{AcceptedBlockBundle, Block, BlockHeader, HISTORY_STEP_TERMINAL_VERSION};
    use noid_poseidon2b::primitives::Address;

    use super::*;

    fn protocol() -> StreamProtocol {
        StreamProtocol::new("/noid/test/sync/block/1")
    }

    fn bundle(height: u64) -> AcceptedBlockBundle {
        let block = Block {
            header: BlockHeader {
                prev_block_hash: [1; 32],
                state_root: [2; 32],
                tx_root: [3; 32],
                timestamp: 1_700_000_000,
                height,
                miner_address: Address([4; 32]),
                nonce: 5,
                difficulty_target: [0xff; 32],
                log_slots: 24,
                active_slot_count: 0,
                alloc_counter: 0,
            },
            transactions: Vec::new(),
        };
        let mut terminal = Vec::new();
        terminal.extend_from_slice(&HISTORY_STEP_TERMINAL_VERSION.to_le_bytes());
        terminal.extend_from_slice(&height.to_le_bytes());
        terminal.extend_from_slice(&noid_chain::block_header::semantic_header_id(&block.header));
        terminal.push(1);
        terminal.push(0xA5);
        AcceptedBlockBundle::try_from_parts(block.to_bytes(), terminal).unwrap()
    }

    fn response_wire(bundle: &AcceptedBlockBundle) -> Vec<u8> {
        let encoded = bundle.encode();
        let mut wire = Vec::with_capacity(RESPONSE_HEADER_BYTES + encoded.len());
        wire.extend_from_slice(&RESPONSE_MAGIC);
        wire.extend_from_slice(&bundle.height().to_le_bytes());
        wire.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        wire.extend_from_slice(&encoded);
        wire
    }

    #[tokio::test]
    async fn request_round_trip_is_exact() {
        let mut wire = Cursor::new(Vec::new());
        BlockSyncCodec::default()
            .write_request(&protocol(), &mut wire, GetRecentBlockRequest { height: 42 })
            .await
            .unwrap();
        wire.set_position(0);
        assert_eq!(
            BlockSyncCodec::default()
                .read_request(&protocol(), &mut wire)
                .await
                .unwrap()
                .height,
            42
        );
    }

    #[tokio::test]
    async fn complete_bundle_round_trips_as_one_object() {
        let bundle = bundle(42);
        let response = GetRecentBlockResponse {
            height: 42,
            bundle: Some(bundle.clone()),
            inbound_memory_permit: None,
            outbound_memory_permit: None,
        };
        let mut wire = Cursor::new(Vec::new());
        BlockSyncCodec::default()
            .write_response(&protocol(), &mut wire, response)
            .await
            .unwrap();
        wire.set_position(0);
        let decoded = BlockSyncCodec::default()
            .read_response(&protocol(), &mut wire)
            .await
            .unwrap();
        assert_eq!(decoded.height, 42);
        assert_eq!(decoded.bundle, Some(bundle));
    }

    #[tokio::test]
    async fn unavailable_response_has_no_partial_payload_shape() {
        let response = GetRecentBlockResponse {
            height: 42,
            bundle: None,
            inbound_memory_permit: None,
            outbound_memory_permit: None,
        };
        let mut wire = Cursor::new(Vec::new());
        BlockSyncCodec::default()
            .write_response(&protocol(), &mut wire, response)
            .await
            .unwrap();
        assert_eq!(wire.get_ref().len(), RESPONSE_HEADER_BYTES);
        wire.set_position(0);
        assert!(BlockSyncCodec::default()
            .read_response(&protocol(), &mut wire)
            .await
            .unwrap()
            .bundle
            .is_none());
    }

    #[tokio::test]
    async fn declared_length_is_bounded_before_payload_allocation() {
        let mut header = vec![0u8; RESPONSE_HEADER_BYTES];
        header[..4].copy_from_slice(&RESPONSE_MAGIC);
        header[4..12].copy_from_slice(&42u64.to_le_bytes());
        header[12..16]
            .copy_from_slice(&((MAX_ACCEPTED_BLOCK_BUNDLE_BYTES + 1) as u32).to_le_bytes());
        let error = BlockSyncCodec::default()
            .read_response(&protocol(), &mut Cursor::new(header))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn response_height_must_match_bundle() {
        let bundle = bundle(42);
        let mut wire = response_wire(&bundle);
        wire[4..12].copy_from_slice(&41u64.to_le_bytes());
        assert_eq!(
            BlockSyncCodec::default()
                .read_response(&protocol(), &mut Cursor::new(wire))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn inbound_budget_follows_bundle_until_consumption() {
        let bundle = bundle(42);
        let wire = response_wire(&bundle);
        let payload_len = bundle.encode().len();
        let codec = BlockSyncCodec::with_inbound_budget(payload_len);
        let first = codec
            .clone()
            .read_response(&protocol(), &mut Cursor::new(wire.clone()))
            .await
            .unwrap();
        let mut second_codec = codec.clone();
        let second = tokio::spawn(async move {
            second_codec
                .read_response(&protocol(), &mut Cursor::new(wire))
                .await
        });
        tokio::task::yield_now().await;
        assert!(!second.is_finished());
        drop(first);
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), second)
                .await
                .unwrap()
                .unwrap()
                .unwrap()
                .bundle
                .is_some()
        );
    }

    #[test]
    fn production_codecs_share_one_inbound_budget() {
        let first = BlockSyncCodec::default();
        let second = BlockSyncCodec::default();
        assert!(Arc::ptr_eq(&first.inbound_budget, &second.inbound_budget));
        assert!(Arc::ptr_eq(
            &first.inbound_budget,
            &process_global_inbound_budget()
        ));
    }
}
