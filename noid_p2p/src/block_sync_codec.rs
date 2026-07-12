// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Allocation-bounded wire codec for retained proof-native blocks.
//!
//! The generic libp2p CBOR codec first buffers the complete encoded response,
//! is capped at 10 MiB, and then allocates the decoded byte vectors.  A valid
//! Paranoid block may carry up to 48 MiB of proof and authorization data, so
//! block sync uses a small fixed header followed by the three payloads.  Every
//! declared length is checked before any payload allocation and payload bytes
//! are read directly into the vectors delivered to the node.

use std::{
    io,
    sync::{Arc, OnceLock},
};

use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{request_response, swarm::StreamProtocol};
use noid_chain::consensus::wire_limits::{
    proof_sidecar_combined_len_ok, MAX_BLOCK_AUTH_SIDECAR_BYTES, MAX_BLOCK_BYTES,
    MAX_BLOCK_PROOF_BYTES,
};

use crate::outbound_budget::OutboundResponseBudget;
use crate::protocol::{GetRecentBlockRequest, GetRecentBlockResponse};

const REQUEST_MAGIC: [u8; 4] = *b"NBR2";
const RESPONSE_MAGIC: [u8; 4] = *b"NBS2";
const REQUEST_HEADER_BYTES: usize = 12;
const RESPONSE_HEADER_BYTES: usize = 24;
const NONE_LEN: u32 = u32::MAX;
/// Maximum aggregate bytes held by decoded inbound block-sync responses.
/// One maximum proof-native block fits, while a second peer must wait until
/// the node releases the first response.
pub const INBOUND_BLOCK_SYNC_BUDGET_BYTES: usize = 64 * 1024 * 1024;

/// Block-sync codec with a canonical, allocation-bounded wire format.
#[derive(Debug, Clone)]
pub struct BlockSyncCodec {
    inbound_budget: Arc<tokio::sync::Semaphore>,
    outbound_budget: OutboundResponseBudget,
}

impl Default for BlockSyncCodec {
    fn default() -> Self {
        static INBOUND_BUDGET: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
        Self {
            inbound_budget: Arc::clone(INBOUND_BUDGET.get_or_init(|| {
                Arc::new(tokio::sync::Semaphore::new(INBOUND_BLOCK_SYNC_BUDGET_BYTES))
            })),
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
            height: u64::from_le_bytes(header[4..12].try_into().expect("fixed request header")),
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
        let lengths = parse_response_header(&header)?;

        // `parse_response_header` validates all individual and combined caps
        // before the first payload Vec is reserved. The shared codec budget is
        // acquired before reading payload bytes and follows the decoded event
        // until the node finishes consuming it.
        let inbound_memory_permit = self.acquire_inbound_permit(lengths).await?;
        let block_bytes = read_optional_payload(io, lengths.block_len).await?;
        let block_proof_bytes = read_optional_payload(io, lengths.proof_len).await?;
        let block_auth_sidecar_bytes = read_optional_payload(io, lengths.sidecar_len).await?;
        ensure_eof(io).await?;

        Ok(GetRecentBlockResponse {
            height: lengths.height,
            block_bytes,
            block_proof_bytes,
            block_auth_sidecar_bytes,
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
            block_bytes,
            block_proof_bytes,
            block_auth_sidecar_bytes,
            inbound_memory_permit,
            outbound_memory_permit,
        } = response;
        let block_len = optional_len(&block_bytes, "block")?;
        let proof_len = optional_len(&block_proof_bytes, "block proof")?;
        let sidecar_len = optional_len(&block_auth_sidecar_bytes, "block authorization sidecar")?;
        validate_response_lengths(block_len, proof_len, sidecar_len)?;

        let payload_len = decoded_optional_len(block_len)
            .checked_add(decoded_optional_len(proof_len))
            .and_then(|sum| sum.checked_add(decoded_optional_len(sidecar_len)))
            .ok_or_else(|| invalid_data("block-sync response length overflow"))?;
        // Production response workers acquire this before touching storage.
        // The codec fallback preserves the process-wide write bound for any
        // future call site that constructs an already-resident response.
        let outbound_memory_permit = match outbound_memory_permit {
            Some(permit) => Some(permit),
            None => self.outbound_budget.acquire(payload_len).await?,
        };
        let _memory_permits = (inbound_memory_permit, outbound_memory_permit);

        let mut header = [0u8; RESPONSE_HEADER_BYTES];
        header[..4].copy_from_slice(&RESPONSE_MAGIC);
        header[4..12].copy_from_slice(&height.to_le_bytes());
        header[12..16].copy_from_slice(&block_len.to_le_bytes());
        header[16..20].copy_from_slice(&proof_len.to_le_bytes());
        header[20..24].copy_from_slice(&sidecar_len.to_le_bytes());
        io.write_all(&header).await?;

        // Write directly from the owned response fields.  Unlike CBOR, this
        // does not construct a second response-sized serialization buffer.
        if let Some(bytes) = block_bytes {
            io.write_all(&bytes).await?;
        }
        if let Some(bytes) = block_proof_bytes {
            io.write_all(&bytes).await?;
        }
        if let Some(bytes) = block_auth_sidecar_bytes {
            io.write_all(&bytes).await?;
        }
        Ok(())
    }
}

impl BlockSyncCodec {
    async fn acquire_inbound_permit(
        &self,
        lengths: ResponseLengths,
    ) -> io::Result<Option<Arc<tokio::sync::OwnedSemaphorePermit>>> {
        let bytes = if lengths.block_len == NONE_LEN {
            0
        } else {
            (lengths.block_len as usize)
                .checked_add(decoded_optional_len(lengths.proof_len))
                .and_then(|sum| sum.checked_add(decoded_optional_len(lengths.sidecar_len)))
                .ok_or_else(|| invalid_data("block-sync response length overflow"))?
        };
        if bytes == 0 {
            return Ok(None);
        }
        let permits = u32::try_from(bytes)
            .map_err(|_| invalid_data("block-sync response byte budget overflow"))?;
        let permit = self
            .inbound_budget
            .clone()
            .acquire_many_owned(permits)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "block-sync budget closed"))?;
        Ok(Some(Arc::new(permit)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResponseLengths {
    height: u64,
    block_len: u32,
    proof_len: u32,
    sidecar_len: u32,
}

fn parse_response_header(header: &[u8; RESPONSE_HEADER_BYTES]) -> io::Result<ResponseLengths> {
    if header[..4] != RESPONSE_MAGIC {
        return Err(invalid_data("invalid block-sync response magic/version"));
    }
    let lengths = ResponseLengths {
        height: u64::from_le_bytes(header[4..12].try_into().expect("fixed response header")),
        block_len: u32::from_le_bytes(header[12..16].try_into().expect("fixed block length field")),
        proof_len: u32::from_le_bytes(header[16..20].try_into().expect("fixed proof length field")),
        sidecar_len: u32::from_le_bytes(
            header[20..24]
                .try_into()
                .expect("fixed sidecar length field"),
        ),
    };
    validate_response_lengths(lengths.block_len, lengths.proof_len, lengths.sidecar_len)?;
    Ok(lengths)
}

fn validate_response_lengths(block_len: u32, proof_len: u32, sidecar_len: u32) -> io::Result<()> {
    if block_len == NONE_LEN {
        if proof_len != NONE_LEN || sidecar_len != NONE_LEN {
            return Err(invalid_data(
                "unavailable block response carries proof or sidecar bytes",
            ));
        }
        return Ok(());
    }

    let block_len = block_len as usize;
    let proof_len = decoded_optional_len(proof_len);
    let sidecar_len = decoded_optional_len(sidecar_len);
    if block_len > MAX_BLOCK_BYTES {
        return Err(invalid_data("declared block length exceeds consensus cap"));
    }
    if proof_len > MAX_BLOCK_PROOF_BYTES {
        return Err(invalid_data(
            "declared block proof length exceeds consensus cap",
        ));
    }
    if sidecar_len > MAX_BLOCK_AUTH_SIDECAR_BYTES {
        return Err(invalid_data(
            "declared block authorization sidecar length exceeds consensus cap",
        ));
    }
    if (proof_len == 0) != (sidecar_len == 0) {
        return Err(invalid_data(
            "block proof and authorization sidecar presence must match",
        ));
    }
    if !proof_sidecar_combined_len_ok(proof_len, sidecar_len) {
        return Err(invalid_data(
            "declared block proof and sidecar exceed combined consensus cap",
        ));
    }
    Ok(())
}

fn optional_len(bytes: &Option<Vec<u8>>, field: &'static str) -> io::Result<u32> {
    match bytes {
        Some(bytes) => u32::try_from(bytes.len())
            .map_err(|_| invalid_data(&format!("{field} length does not fit u32"))),
        None => Ok(NONE_LEN),
    }
}

#[inline]
fn decoded_optional_len(encoded: u32) -> usize {
    if encoded == NONE_LEN {
        0
    } else {
        encoded as usize
    }
}

async fn read_optional_payload<T>(io: &mut T, encoded_len: u32) -> io::Result<Option<Vec<u8>>>
where
    T: AsyncRead + Unpin + Send,
{
    if encoded_len == NONE_LEN {
        return Ok(None);
    }
    let len = encoded_len as usize;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len)
        .map_err(|_| io::Error::new(io::ErrorKind::OutOfMemory, "payload allocation failed"))?;
    bytes.resize(len, 0);
    io.read_exact(&mut bytes).await?;
    Ok(Some(bytes))
}

async fn ensure_eof<T>(io: &mut T) -> io::Result<()>
where
    T: AsyncRead + Unpin + Send,
{
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
    use std::sync::Arc;

    use futures::io::Cursor;
    use libp2p::request_response::Codec;

    use super::*;

    fn protocol() -> StreamProtocol {
        StreamProtocol::new("/noid/test/sync/block/2")
    }

    fn response_header(block_len: u32, proof_len: u32, sidecar_len: u32) -> Vec<u8> {
        let mut header = vec![0u8; RESPONSE_HEADER_BYTES];
        header[..4].copy_from_slice(&RESPONSE_MAGIC);
        header[4..12].copy_from_slice(&7u64.to_le_bytes());
        header[12..16].copy_from_slice(&block_len.to_le_bytes());
        header[16..20].copy_from_slice(&proof_len.to_le_bytes());
        header[20..24].copy_from_slice(&sidecar_len.to_le_bytes());
        header
    }

    #[test]
    fn production_codecs_share_one_process_inbound_budget() {
        let first = BlockSyncCodec::default();
        let second = BlockSyncCodec::default();
        assert!(Arc::ptr_eq(&first.inbound_budget, &second.inbound_budget));
    }

    #[tokio::test]
    async fn round_trip_supports_valid_response_above_old_ten_mib_cap() {
        let response = GetRecentBlockResponse {
            height: 19,
            block_bytes: Some(vec![0x11; 128]),
            block_proof_bytes: Some(vec![0x22; 11 * 1024 * 1024]),
            block_auth_sidecar_bytes: Some(vec![0x33; 1024]),
            inbound_memory_permit: None,
            outbound_memory_permit: None,
        };
        let mut encoded = Cursor::new(Vec::new());
        BlockSyncCodec::default()
            .write_response(&protocol(), &mut encoded, response)
            .await
            .unwrap();
        assert!(encoded.get_ref().len() > 10 * 1024 * 1024);

        encoded.set_position(0);
        let decoded = BlockSyncCodec::default()
            .read_response(&protocol(), &mut encoded)
            .await
            .unwrap();
        assert_eq!(decoded.height, 19);
        assert_eq!(decoded.block_bytes.unwrap().len(), 128);
        assert_eq!(decoded.block_proof_bytes.unwrap().len(), 11 * 1024 * 1024);
        assert_eq!(decoded.block_auth_sidecar_bytes.unwrap().len(), 1024);
    }

    #[tokio::test]
    async fn malicious_oversized_length_is_rejected_before_payload_read() {
        let encoded = response_header(
            1,
            u32::try_from(MAX_BLOCK_PROOF_BYTES + 1).unwrap(),
            NONE_LEN,
        );
        let error = BlockSyncCodec::default()
            .read_response(&protocol(), &mut Cursor::new(encoded))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("proof length"));
    }

    #[tokio::test]
    async fn malicious_combined_lengths_are_rejected_before_payload_read() {
        let encoded = response_header(
            1,
            u32::try_from(MAX_BLOCK_PROOF_BYTES).unwrap(),
            u32::try_from(
                noid_chain::consensus::wire_limits::MAX_BLOCK_PROOF_PLUS_SIDECAR_BYTES
                    - MAX_BLOCK_PROOF_BYTES
                    + 1,
            )
            .unwrap(),
        );
        let error = BlockSyncCodec::default()
            .read_response(&protocol(), &mut Cursor::new(encoded))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("combined"));
    }

    #[tokio::test]
    async fn unavailable_response_cannot_smuggle_payload_or_trailing_bytes() {
        let mut inconsistent = response_header(NONE_LEN, 0, NONE_LEN);
        inconsistent.push(0xaa);
        let error = BlockSyncCodec::default()
            .read_response(&protocol(), &mut Cursor::new(inconsistent))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("unavailable"));

        let mut trailing = response_header(0, NONE_LEN, NONE_LEN);
        trailing.push(0xaa);
        let error = BlockSyncCodec::default()
            .read_response(&protocol(), &mut Cursor::new(trailing))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("trailing"));
    }

    #[tokio::test]
    async fn request_codec_is_fixed_size_and_exact() {
        let mut encoded = Cursor::new(Vec::new());
        BlockSyncCodec::default()
            .write_request(
                &protocol(),
                &mut encoded,
                GetRecentBlockRequest { height: 42 },
            )
            .await
            .unwrap();
        assert_eq!(encoded.get_ref().len(), REQUEST_HEADER_BYTES);
        encoded.set_position(0);
        let decoded = BlockSyncCodec::default()
            .read_request(&protocol(), &mut encoded)
            .await
            .unwrap();
        assert_eq!(decoded.height, 42);

        let mut malicious = encoded.into_inner();
        malicious.push(0);
        let error = BlockSyncCodec::default()
            .read_request(&protocol(), &mut Cursor::new(malicious))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn global_budget_blocks_second_payload_until_first_is_consumed() {
        let codec = BlockSyncCodec::with_inbound_budget(16);
        let mut first_wire = response_header(12, NONE_LEN, NONE_LEN);
        first_wire.extend_from_slice(&[0x11; 12]);
        let first = codec
            .clone()
            .read_response(&protocol(), &mut Cursor::new(first_wire))
            .await
            .unwrap();
        assert_eq!(codec.inbound_budget.available_permits(), 4);

        let mut second_wire = response_header(12, NONE_LEN, NONE_LEN);
        second_wire.extend_from_slice(&[0x22; 12]);
        let mut second_codec = codec.clone();
        let second = tokio::spawn(async move {
            second_codec
                .read_response(&protocol(), &mut Cursor::new(second_wire))
                .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(!second.is_finished());
        // Tokio reserves the four currently-free permits for the fair queued
        // waiter, but cannot grant its requested twelve until `first` drops.
        assert_eq!(codec.inbound_budget.available_permits(), 0);

        drop(first);
        let decoded = tokio::time::timeout(std::time::Duration::from_secs(1), second)
            .await
            .expect("second response must proceed after permit release")
            .unwrap()
            .unwrap();
        assert_eq!(decoded.block_bytes.unwrap(), vec![0x22; 12]);
    }
}
