// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Fixed-framing codec for the constant-size public history proof endpoint.

use std::io;
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{request_response, swarm::StreamProtocol};
use noid_chain::consensus::wire_limits::{MAX_HEADER_BYTES, MAX_HISTORY_PROOF_BYTES};

use crate::{
    outbound_budget::OutboundResponseBudget,
    protocol::{GetHistoryProofRequest, GetHistoryProofResponse},
};

const REQUEST_MAGIC: [u8; 4] = *b"NHR2";
const REQUEST_BYTES: usize = 4 + 8 + 32;
const RESPONSE_MAGIC: [u8; 4] = *b"NHS2";
const RESPONSE_HEADER_BYTES: usize = 4 + 4 + 4 + 8 + 32;
const NONE_LEN: u32 = u32::MAX;
pub const INBOUND_HISTORY_PROOF_BUDGET_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct HistoryProofCodec {
    inbound_budget: std::sync::Arc<tokio::sync::Semaphore>,
    outbound_budget: OutboundResponseBudget,
}

impl Default for HistoryProofCodec {
    fn default() -> Self {
        static INBOUND_BUDGET: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
        Self {
            inbound_budget: Arc::clone(INBOUND_BUDGET.get_or_init(|| {
                Arc::new(tokio::sync::Semaphore::new(
                    INBOUND_HISTORY_PROOF_BUDGET_BYTES,
                ))
            })),
            outbound_budget: OutboundResponseBudget::process_global(),
        }
    }
}

#[async_trait]
impl request_response::Codec for HistoryProofCodec {
    type Protocol = StreamProtocol;
    type Request = GetHistoryProofRequest;
    type Response = GetHistoryProofResponse;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut request = [0u8; REQUEST_BYTES];
        io.read_exact(&mut request).await?;
        if request[..4] != REQUEST_MAGIC {
            return Err(invalid_data("invalid history-proof request magic/version"));
        }
        ensure_eof(io).await?;
        Ok(GetHistoryProofRequest {
            height: u64::from_le_bytes(request[4..12].try_into().expect("fixed height")),
            block_hash: request[12..44].try_into().expect("fixed block hash"),
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
        let (proof_len, tip_len, height, block_hash) = parse_response_header(&header)?;
        let payload_len = decoded_len(proof_len)
            .checked_add(decoded_len(tip_len))
            .ok_or_else(|| invalid_data("history-proof response length overflow"))?;
        let inbound_memory_permit = self.acquire_inbound(payload_len).await?;
        let proof_bytes = read_optional(io, proof_len).await?;
        let tip_header_bytes = read_optional(io, tip_len).await?;
        ensure_eof(io).await?;
        Ok(GetHistoryProofResponse {
            height,
            block_hash,
            proof_bytes,
            tip_header_bytes,
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
        let mut encoded = [0u8; REQUEST_BYTES];
        encoded[..4].copy_from_slice(&REQUEST_MAGIC);
        encoded[4..12].copy_from_slice(&request.height.to_le_bytes());
        encoded[12..44].copy_from_slice(&request.block_hash);
        io.write_all(&encoded).await
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
        let GetHistoryProofResponse {
            height,
            block_hash,
            proof_bytes,
            tip_header_bytes,
            inbound_memory_permit,
            outbound_memory_permit,
        } = response;
        let proof_len = optional_len(proof_bytes.as_deref(), "history proof")?;
        let tip_len = optional_len(tip_header_bytes.as_deref(), "tip header")?;
        validate_lengths(proof_len, tip_len)?;
        let payload_len = decoded_len(proof_len)
            .checked_add(decoded_len(tip_len))
            .ok_or_else(|| invalid_data("history-proof response length overflow"))?;
        let outbound_memory_permit = match outbound_memory_permit {
            Some(permit) => Some(permit),
            None => self.outbound_budget.acquire(payload_len).await?,
        };
        let _memory_permits = (inbound_memory_permit, outbound_memory_permit);

        let mut header = [0u8; RESPONSE_HEADER_BYTES];
        header[..4].copy_from_slice(&RESPONSE_MAGIC);
        header[4..8].copy_from_slice(&proof_len.to_le_bytes());
        header[8..12].copy_from_slice(&tip_len.to_le_bytes());
        header[12..20].copy_from_slice(&height.to_le_bytes());
        header[20..52].copy_from_slice(&block_hash);
        io.write_all(&header).await?;
        if let Some(bytes) = proof_bytes {
            io.write_all(&bytes).await?;
        }
        if let Some(bytes) = tip_header_bytes {
            io.write_all(&bytes).await?;
        }
        Ok(())
    }
}

impl HistoryProofCodec {
    #[cfg(test)]
    fn with_inbound_budget(bytes: usize) -> Self {
        Self {
            inbound_budget: std::sync::Arc::new(tokio::sync::Semaphore::new(bytes)),
            outbound_budget: OutboundResponseBudget::process_global(),
        }
    }

    async fn acquire_inbound(
        &self,
        bytes: usize,
    ) -> io::Result<Option<std::sync::Arc<tokio::sync::OwnedSemaphorePermit>>> {
        if bytes == 0 {
            return Ok(None);
        }
        let permits =
            u32::try_from(bytes).map_err(|_| invalid_data("history-proof byte budget overflow"))?;
        let permit = self
            .inbound_budget
            .clone()
            .acquire_many_owned(permits)
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "history-proof budget closed")
            })?;
        Ok(Some(std::sync::Arc::new(permit)))
    }
}

fn parse_response_header(
    header: &[u8; RESPONSE_HEADER_BYTES],
) -> io::Result<(u32, u32, u64, [u8; 32])> {
    if header[..4] != RESPONSE_MAGIC {
        return Err(invalid_data("invalid history-proof response magic/version"));
    }
    let proof_len = u32::from_le_bytes(header[4..8].try_into().expect("fixed proof length"));
    let tip_len = u32::from_le_bytes(header[8..12].try_into().expect("fixed tip length"));
    validate_lengths(proof_len, tip_len)?;
    let height = u64::from_le_bytes(header[12..20].try_into().expect("fixed height"));
    let block_hash = header[20..52].try_into().expect("fixed block hash");
    Ok((proof_len, tip_len, height, block_hash))
}

fn validate_lengths(proof_len: u32, tip_len: u32) -> io::Result<()> {
    if decoded_len(proof_len) > MAX_HISTORY_PROOF_BYTES {
        return Err(invalid_data("declared history proof exceeds wire cap"));
    }
    if decoded_len(tip_len) > MAX_HEADER_BYTES {
        return Err(invalid_data("declared history tip header exceeds wire cap"));
    }
    Ok(())
}

async fn read_optional<T: AsyncRead + Unpin + Send>(
    io: &mut T,
    encoded_len: u32,
) -> io::Result<Option<Vec<u8>>> {
    if encoded_len == NONE_LEN {
        return Ok(None);
    }
    let len = encoded_len as usize;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(len).map_err(|_| {
        io::Error::new(
            io::ErrorKind::OutOfMemory,
            "history payload allocation failed",
        )
    })?;
    bytes.resize(len, 0);
    io.read_exact(&mut bytes).await?;
    Ok(Some(bytes))
}

fn optional_len(bytes: Option<&[u8]>, field: &'static str) -> io::Result<u32> {
    match bytes {
        Some(bytes) => u32::try_from(bytes.len())
            .map_err(|_| invalid_data(&format!("{field} length does not fit u32"))),
        None => Ok(NONE_LEN),
    }
}

#[inline]
fn decoded_len(encoded_len: u32) -> usize {
    if encoded_len == NONE_LEN {
        0
    } else {
        encoded_len as usize
    }
}

async fn ensure_eof<T: AsyncRead + Unpin + Send>(io: &mut T) -> io::Result<()> {
    let mut trailing = [0u8; 1];
    if io.read(&mut trailing).await? != 0 {
        return Err(invalid_data("trailing bytes in history-proof message"));
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

    use super::*;

    fn protocol() -> StreamProtocol {
        StreamProtocol::new("/noid/test/sync/proof/2")
    }

    fn response_wire(proof_len: usize, fill: u8) -> Vec<u8> {
        let mut wire = vec![0u8; RESPONSE_HEADER_BYTES];
        wire[..4].copy_from_slice(&RESPONSE_MAGIC);
        wire[4..8].copy_from_slice(&(proof_len as u32).to_le_bytes());
        wire[8..12].copy_from_slice(&NONE_LEN.to_le_bytes());
        wire[12..20].copy_from_slice(&77u64.to_le_bytes());
        wire[20..52].copy_from_slice(&[0xA5; 32]);
        wire.extend(std::iter::repeat_n(fill, proof_len));
        wire
    }

    #[tokio::test]
    async fn request_round_trip_binds_exact_manifest_boundary() {
        let request = GetHistoryProofRequest {
            height: 77,
            block_hash: [0xA5; 32],
        };
        let mut wire = Cursor::new(Vec::new());
        HistoryProofCodec::default()
            .write_request(&protocol(), &mut wire, request.clone())
            .await
            .unwrap();
        assert_eq!(wire.get_ref().len(), REQUEST_BYTES);
        wire.set_position(0);
        let decoded = HistoryProofCodec::default()
            .read_request(&protocol(), &mut wire)
            .await
            .unwrap();
        assert_eq!(decoded.height, request.height);
        assert_eq!(decoded.block_hash, request.block_hash);

        let mut trailing = wire.into_inner();
        trailing.push(0);
        assert_eq!(
            HistoryProofCodec::default()
                .read_request(&protocol(), &mut Cursor::new(trailing))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData,
        );
    }

    #[test]
    fn production_codecs_share_one_history_inbound_budget() {
        let first = HistoryProofCodec::default();
        let second = HistoryProofCodec::default();
        assert!(Arc::ptr_eq(&first.inbound_budget, &second.inbound_budget));
    }

    #[tokio::test]
    async fn round_trip_has_no_duplicate_serialization_envelope() {
        let response = GetHistoryProofResponse {
            height: 77,
            block_hash: [0xA5; 32],
            proof_bytes: Some(vec![1; 4096]),
            tip_header_bytes: Some(vec![2; 276]),
            inbound_memory_permit: None,
            outbound_memory_permit: None,
        };
        let mut wire = Cursor::new(Vec::new());
        HistoryProofCodec::default()
            .write_response(&protocol(), &mut wire, response)
            .await
            .unwrap();
        assert_eq!(wire.get_ref().len(), RESPONSE_HEADER_BYTES + 4096 + 276);
        wire.set_position(0);
        let decoded = HistoryProofCodec::default()
            .read_response(&protocol(), &mut wire)
            .await
            .unwrap();
        assert_eq!(decoded.height, 77);
        assert_eq!(decoded.block_hash, [0xA5; 32]);
        assert_eq!(decoded.proof_bytes.unwrap(), vec![1; 4096]);
        assert_eq!(decoded.tip_header_bytes.unwrap(), vec![2; 276]);
    }

    #[tokio::test]
    async fn malicious_length_is_rejected_before_payload_read() {
        let mut header = vec![0u8; RESPONSE_HEADER_BYTES];
        header[..4].copy_from_slice(&RESPONSE_MAGIC);
        header[4..8].copy_from_slice(&((MAX_HISTORY_PROOF_BYTES + 1) as u32).to_le_bytes());
        header[8..12].copy_from_slice(&NONE_LEN.to_le_bytes());
        let error = HistoryProofCodec::default()
            .read_response(&protocol(), &mut Cursor::new(header))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("history proof"));
    }

    #[tokio::test]
    async fn inbound_budget_follows_proof_until_node_consumption() {
        let len = 4096;
        let codec = HistoryProofCodec::with_inbound_budget(len);
        let first = codec
            .clone()
            .read_response(&protocol(), &mut Cursor::new(response_wire(len, 1)))
            .await
            .unwrap();
        let mut second_codec = codec.clone();
        let second = tokio::spawn(async move {
            second_codec
                .read_response(&protocol(), &mut Cursor::new(response_wire(len, 2)))
                .await
        });
        tokio::task::yield_now().await;
        assert!(!second.is_finished());
        drop(first);
        let second = tokio::time::timeout(std::time::Duration::from_secs(1), second)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(second.proof_bytes.unwrap()[0], 2);
    }
}
