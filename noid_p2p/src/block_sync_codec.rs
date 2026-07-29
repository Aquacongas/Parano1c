// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Allocation-bounded codec for one retained accepted-block bundle or one
//! retention-bounded range of canonical block bodies.

use std::{io, sync::Arc};

use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{request_response, swarm::StreamProtocol};
use noid_chain::{
    consensus::wire_limits::MAX_BLOCK_BYTES, AcceptedBlockBundle, Block,
    MAX_ACCEPTED_BLOCK_BUNDLE_BYTES,
};

use crate::inbound_budget::process_global_inbound_budget;
use crate::outbound_budget::OutboundResponseBudget;
use crate::protocol::{
    GetRecentBlockRequest, GetRecentBlockResponse, RecentBlockPayload, RecentBlockPayloadKind,
    MAX_BLOCK_BODY_BATCH,
};

const REQUEST_MAGIC: [u8; 4] = *b"NBR3";
const RESPONSE_MAGIC: [u8; 4] = *b"NBS3";
const REQUEST_HEADER_BYTES: usize = 15;
const RESPONSE_HEADER_BYTES: usize = 19;
const PAYLOAD_COMPLETE: u8 = 0;
const PAYLOAD_BLOCK_BODY: u8 = 1;
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
        let count = u16::from_le_bytes(header[12..14].try_into().unwrap());
        let payload_kind = decode_payload_kind(header[14])?;
        let height = u64::from_le_bytes(header[4..12].try_into().unwrap());
        validate_request_shape(height, count, payload_kind)?;
        ensure_eof(io).await?;
        Ok(GetRecentBlockRequest {
            height,
            count,
            payload_kind,
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
        let count = u16::from_le_bytes(header[12..14].try_into().unwrap());
        let payload_kind = decode_payload_kind(header[14])?;
        validate_request_shape(height, count, payload_kind)?;
        let encoded_len = u32::from_le_bytes(header[15..19].try_into().unwrap());
        let payload_len = validate_encoded_len(encoded_len, count, payload_kind)?;
        let inbound_memory_permit = self.acquire_inbound(payload_len).await?;
        let payload = if encoded_len == NONE_LEN {
            None
        } else {
            match payload_kind {
                RecentBlockPayloadKind::Complete => {
                    let mut encoded = allocate_payload(payload_len)?;
                    io.read_exact(&mut encoded).await?;
                    let bundle = AcceptedBlockBundle::decode(&encoded).map_err(|error| {
                        invalid_data(&format!("accepted-block bundle: {error}"))
                    })?;
                    if bundle.height() != height {
                        return Err(invalid_data(
                            "accepted-block bundle height does not match response",
                        ));
                    }
                    Some(RecentBlockPayload::Complete(bundle))
                }
                RecentBlockPayloadKind::BlockBody => {
                    let mut bodies = Vec::new();
                    bodies
                        .try_reserve_exact(count as usize)
                        .map_err(|_| invalid_data("block-body batch allocation failed"))?;
                    let mut consumed = 0usize;
                    for index in 0..count {
                        let mut length_bytes = [0u8; 4];
                        io.read_exact(&mut length_bytes).await?;
                        consumed = consumed
                            .checked_add(length_bytes.len())
                            .ok_or_else(|| invalid_data("block-body batch length overflow"))?;
                        let body_len = u32::from_le_bytes(length_bytes) as usize;
                        if body_len == 0 || body_len > MAX_BLOCK_BYTES {
                            return Err(invalid_data(
                                "block body length exceeds its per-item wire cap",
                            ));
                        }
                        consumed = consumed
                            .checked_add(body_len)
                            .ok_or_else(|| invalid_data("block-body batch length overflow"))?;
                        if consumed > payload_len {
                            return Err(invalid_data(
                                "block-body batch exceeds its declared payload length",
                            ));
                        }
                        let mut encoded = allocate_payload(body_len)?;
                        io.read_exact(&mut encoded).await?;
                        let block = Block::from_bytes(&encoded).map_err(|error| {
                            invalid_data(&format!("canonical block body: {error:?}"))
                        })?;
                        let expected_height = height.saturating_add(index as u64);
                        if block.header.height != expected_height {
                            return Err(invalid_data("block-body batch is not height-contiguous"));
                        }
                        bodies.push(encoded);
                    }
                    if consumed != payload_len {
                        return Err(invalid_data(
                            "block-body batch payload length does not close exactly",
                        ));
                    }
                    Some(RecentBlockPayload::BlockBodies(bodies))
                }
            }
        };
        ensure_eof(io).await?;
        Ok(GetRecentBlockResponse {
            height,
            count,
            payload_kind,
            payload,
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
        validate_request_shape(request.height, request.count, request.payload_kind)?;
        header[12..14].copy_from_slice(&request.count.to_le_bytes());
        header[14] = encode_payload_kind(request.payload_kind);
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
            count,
            payload_kind,
            payload,
            inbound_memory_permit,
            outbound_memory_permit,
        } = response;
        validate_request_shape(height, count, payload_kind)?;
        match payload.as_ref() {
            Some(RecentBlockPayload::Complete(bundle)) => {
                if payload_kind != RecentBlockPayloadKind::Complete {
                    return Err(invalid_data(
                        "complete payload does not match declared response kind",
                    ));
                }
                if bundle.height() != height {
                    return Err(invalid_data(
                        "accepted-block bundle height does not match response",
                    ));
                }
            }
            Some(RecentBlockPayload::BlockBodies(block_bodies)) => {
                if payload_kind != RecentBlockPayloadKind::BlockBody {
                    return Err(invalid_data(
                        "block bodies do not match declared response kind",
                    ));
                }
                if block_bodies.len() != count as usize {
                    return Err(invalid_data(
                        "block-body batch count does not match response",
                    ));
                }
                for (index, block_bytes) in block_bodies.iter().enumerate() {
                    if block_bytes.is_empty() || block_bytes.len() > MAX_BLOCK_BYTES {
                        return Err(invalid_data(
                            "block body length exceeds its per-item wire cap",
                        ));
                    }
                    let block = Block::from_bytes(block_bytes).map_err(|error| {
                        invalid_data(&format!("canonical block body: {error:?}"))
                    })?;
                    if block.header.height != height.saturating_add(index as u64) {
                        return Err(invalid_data("block-body batch is not height-contiguous"));
                    }
                }
            }
            None => {}
        }
        let complete_encoded = match payload.as_ref() {
            Some(RecentBlockPayload::Complete(bundle)) => Some(bundle.encode()),
            _ => None,
        };
        let encoded_len = match payload.as_ref() {
            Some(RecentBlockPayload::Complete(_)) => u32::try_from(
                complete_encoded
                    .as_ref()
                    .expect("complete payload was encoded")
                    .len(),
            )
            .map_err(|_| invalid_data("block-sync payload length does not fit u32"))?,
            Some(RecentBlockPayload::BlockBodies(block_bodies)) => {
                let total = block_bodies.iter().try_fold(0usize, |total, block| {
                    total
                        .checked_add(4)
                        .and_then(|value| value.checked_add(block.len()))
                });
                u32::try_from(
                    total.ok_or_else(|| invalid_data("block-body batch length overflow"))?,
                )
                .map_err(|_| invalid_data("block-body batch length does not fit u32"))?
            }
            None => NONE_LEN,
        };
        let payload_len = validate_encoded_len(encoded_len, count, payload_kind)?;
        let outbound_memory_permit = match outbound_memory_permit {
            Some(permit) => Some(permit),
            None => self.outbound_budget.acquire(payload_len).await?,
        };
        let _memory_permits = (inbound_memory_permit, outbound_memory_permit);

        let mut header = [0u8; RESPONSE_HEADER_BYTES];
        header[..4].copy_from_slice(&RESPONSE_MAGIC);
        header[4..12].copy_from_slice(&height.to_le_bytes());
        header[12..14].copy_from_slice(&count.to_le_bytes());
        header[14] = encode_payload_kind(payload_kind);
        header[15..19].copy_from_slice(&encoded_len.to_le_bytes());
        io.write_all(&header).await?;
        match payload {
            Some(RecentBlockPayload::Complete(_)) => {
                io.write_all(
                    complete_encoded
                        .as_ref()
                        .expect("complete payload was encoded"),
                )
                .await?;
            }
            Some(RecentBlockPayload::BlockBodies(block_bodies)) => {
                for block_bytes in block_bodies {
                    let body_len = u32::try_from(block_bytes.len())
                        .map_err(|_| invalid_data("block body length does not fit u32"))?;
                    io.write_all(&body_len.to_le_bytes()).await?;
                    io.write_all(&block_bytes).await?;
                }
            }
            None => {}
        }
        Ok(())
    }
}

fn validate_encoded_len(
    encoded_len: u32,
    count: u16,
    payload_kind: RecentBlockPayloadKind,
) -> io::Result<usize> {
    if encoded_len == NONE_LEN {
        return Ok(0);
    }
    let len = encoded_len as usize;
    if len == 0 {
        return Err(invalid_data("present block-sync payload is empty"));
    }
    let maximum = match payload_kind {
        RecentBlockPayloadKind::Complete => MAX_ACCEPTED_BLOCK_BUNDLE_BYTES,
        RecentBlockPayloadKind::BlockBody => (MAX_BLOCK_BYTES + 4)
            .checked_mul(count as usize)
            .ok_or_else(|| invalid_data("block-body batch wire cap overflow"))?,
    };
    if len > maximum {
        return Err(invalid_data("declared block-sync payload exceeds wire cap"));
    }
    if payload_kind == RecentBlockPayloadKind::BlockBody && len < count as usize * 4 {
        return Err(invalid_data(
            "declared block-body batch is shorter than its item framing",
        ));
    }
    Ok(len)
}

fn validate_request_shape(
    height: u64,
    count: u16,
    payload_kind: RecentBlockPayloadKind,
) -> io::Result<()> {
    if count == 0 {
        return Err(invalid_data("block-sync request count is zero"));
    }
    if height.checked_add(count.saturating_sub(1) as u64).is_none() {
        return Err(invalid_data("block-sync request height range overflows"));
    }
    match payload_kind {
        RecentBlockPayloadKind::Complete if count != 1 => Err(invalid_data(
            "complete retained-block requests must contain exactly one block",
        )),
        RecentBlockPayloadKind::BlockBody if count > MAX_BLOCK_BODY_BATCH => {
            Err(invalid_data("block-body request exceeds retention window"))
        }
        _ => Ok(()),
    }
}

fn encode_payload_kind(kind: RecentBlockPayloadKind) -> u8 {
    match kind {
        RecentBlockPayloadKind::Complete => PAYLOAD_COMPLETE,
        RecentBlockPayloadKind::BlockBody => PAYLOAD_BLOCK_BODY,
    }
}

fn decode_payload_kind(encoded: u8) -> io::Result<RecentBlockPayloadKind> {
    match encoded {
        PAYLOAD_COMPLETE => Ok(RecentBlockPayloadKind::Complete),
        PAYLOAD_BLOCK_BODY => Ok(RecentBlockPayloadKind::BlockBody),
        _ => Err(invalid_data("unknown block-sync payload kind")),
    }
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
        StreamProtocol::new("/noid/test/sync/block/3")
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
        wire.extend_from_slice(&1u16.to_le_bytes());
        wire.push(PAYLOAD_COMPLETE);
        wire.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        wire.extend_from_slice(&encoded);
        wire
    }

    #[tokio::test]
    async fn request_round_trip_is_exact() {
        let mut wire = Cursor::new(Vec::new());
        BlockSyncCodec::default()
            .write_request(
                &protocol(),
                &mut wire,
                GetRecentBlockRequest {
                    height: 42,
                    count: 2,
                    payload_kind: RecentBlockPayloadKind::BlockBody,
                },
            )
            .await
            .unwrap();
        wire.set_position(0);
        let decoded = BlockSyncCodec::default()
            .read_request(&protocol(), &mut wire)
            .await
            .unwrap();
        assert_eq!(decoded.height, 42);
        assert_eq!(decoded.count, 2);
        assert_eq!(decoded.payload_kind, RecentBlockPayloadKind::BlockBody);
    }

    #[tokio::test]
    async fn request_rejects_zero_and_oversized_ranges() {
        for request in [
            GetRecentBlockRequest {
                height: 42,
                count: 0,
                payload_kind: RecentBlockPayloadKind::BlockBody,
            },
            GetRecentBlockRequest {
                height: 42,
                count: MAX_BLOCK_BODY_BATCH + 1,
                payload_kind: RecentBlockPayloadKind::BlockBody,
            },
            GetRecentBlockRequest {
                height: 42,
                count: 2,
                payload_kind: RecentBlockPayloadKind::Complete,
            },
        ] {
            let error = BlockSyncCodec::default()
                .write_request(&protocol(), &mut Cursor::new(Vec::new()), request)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[tokio::test]
    async fn complete_bundle_round_trips_as_one_object() {
        let bundle = bundle(42);
        let response = GetRecentBlockResponse {
            height: 42,
            count: 1,
            payload_kind: RecentBlockPayloadKind::Complete,
            payload: Some(RecentBlockPayload::Complete(bundle.clone())),
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
        assert_eq!(decoded.count, 1);
        assert_eq!(decoded.payload_kind, RecentBlockPayloadKind::Complete);
        assert_eq!(decoded.payload, Some(RecentBlockPayload::Complete(bundle)));
    }

    #[tokio::test]
    async fn body_batch_round_trips_without_terminals() {
        let first = bundle(42).block_bytes().to_vec();
        let second = bundle(43).block_bytes().to_vec();
        let bodies = vec![first, second];
        let response = GetRecentBlockResponse {
            height: 42,
            count: 2,
            payload_kind: RecentBlockPayloadKind::BlockBody,
            payload: Some(RecentBlockPayload::BlockBodies(bodies.clone())),
            inbound_memory_permit: None,
            outbound_memory_permit: None,
        };
        let mut wire = Cursor::new(Vec::new());
        BlockSyncCodec::default()
            .write_response(&protocol(), &mut wire, response)
            .await
            .unwrap();
        let repeated_bundle_bytes = bundle(42).encode().len() + bundle(43).encode().len();
        assert!(wire.get_ref().len() < repeated_bundle_bytes);
        wire.set_position(0);
        let decoded = BlockSyncCodec::default()
            .read_response(&protocol(), &mut wire)
            .await
            .unwrap();
        assert_eq!(decoded.payload_kind, RecentBlockPayloadKind::BlockBody);
        assert_eq!(decoded.count, 2);
        assert_eq!(
            decoded.payload,
            Some(RecentBlockPayload::BlockBodies(bodies))
        );
    }

    #[tokio::test]
    async fn body_batch_rejects_non_contiguous_heights() {
        let response = GetRecentBlockResponse {
            height: 42,
            count: 2,
            payload_kind: RecentBlockPayloadKind::BlockBody,
            payload: Some(RecentBlockPayload::BlockBodies(vec![
                bundle(42).block_bytes().to_vec(),
                bundle(44).block_bytes().to_vec(),
            ])),
            inbound_memory_permit: None,
            outbound_memory_permit: None,
        };
        let error = BlockSyncCodec::default()
            .write_response(&protocol(), &mut Cursor::new(Vec::new()), response)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn body_batch_rejects_payload_that_does_not_close_exactly() {
        let body = bundle(42).block_bytes().to_vec();
        let response = GetRecentBlockResponse {
            height: 42,
            count: 1,
            payload_kind: RecentBlockPayloadKind::BlockBody,
            payload: Some(RecentBlockPayload::BlockBodies(vec![body])),
            inbound_memory_permit: None,
            outbound_memory_permit: None,
        };
        let mut wire = Cursor::new(Vec::new());
        BlockSyncCodec::default()
            .write_response(&protocol(), &mut wire, response)
            .await
            .unwrap();
        let bytes = wire.get_mut();
        let declared = u32::from_le_bytes(bytes[15..19].try_into().unwrap());
        bytes[15..19].copy_from_slice(&(declared + 1).to_le_bytes());
        bytes.push(0);
        wire.set_position(0);
        let error = BlockSyncCodec::default()
            .read_response(&protocol(), &mut wire)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn unavailable_response_has_no_partial_payload_shape() {
        let response = GetRecentBlockResponse {
            height: 42,
            count: 2,
            payload_kind: RecentBlockPayloadKind::BlockBody,
            payload: None,
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
        let decoded = BlockSyncCodec::default()
            .read_response(&protocol(), &mut wire)
            .await
            .unwrap();
        assert_eq!(decoded.payload_kind, RecentBlockPayloadKind::BlockBody);
        assert!(decoded.payload.is_none());
    }

    #[tokio::test]
    async fn response_payload_must_match_its_declared_kind() {
        let body = bundle(42).block_bytes().to_vec();
        let response = GetRecentBlockResponse {
            height: 42,
            count: 1,
            payload_kind: RecentBlockPayloadKind::Complete,
            payload: Some(RecentBlockPayload::BlockBodies(vec![body])),
            inbound_memory_permit: None,
            outbound_memory_permit: None,
        };
        assert!(BlockSyncCodec::default()
            .write_response(&protocol(), &mut Cursor::new(Vec::new()), response)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn declared_length_is_bounded_before_payload_allocation() {
        let mut header = vec![0u8; RESPONSE_HEADER_BYTES];
        header[..4].copy_from_slice(&RESPONSE_MAGIC);
        header[4..12].copy_from_slice(&42u64.to_le_bytes());
        header[12..14].copy_from_slice(&1u16.to_le_bytes());
        header[14] = PAYLOAD_COMPLETE;
        header[15..19]
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
                .payload
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
