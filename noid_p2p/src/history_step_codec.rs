// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Fixed-framing codec for the HistoryStep terminal used by O(1) sync.

use std::{io, sync::Arc};

use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{request_response, swarm::StreamProtocol};
use noid_chain::{
    consensus::wire_limits::MAX_HISTORY_STEP_TERMINAL_BYTES, HISTORY_STEP_TERMINAL_BINDING_BYTES,
    HISTORY_STEP_TERMINAL_VERSION,
};

use crate::{
    inbound_budget::process_global_inbound_budget,
    outbound_budget::OutboundResponseBudget,
    protocol::{GetHistoryStepTerminalRequest, GetHistoryStepTerminalResponse},
};

const REQUEST_MAGIC: [u8; 4] = *b"NTR1";
const REQUEST_BYTES: usize = 4 + 8 + 32;
const RESPONSE_MAGIC: [u8; 4] = *b"NTS1";
const RESPONSE_HEADER_BYTES: usize = 4 + 4 + 8 + 32;
const NONE_LEN: u32 = u32::MAX;

#[derive(Debug, Clone)]
pub struct HistoryStepTerminalCodec {
    inbound_budget: Arc<tokio::sync::Semaphore>,
    outbound_budget: OutboundResponseBudget,
}

impl Default for HistoryStepTerminalCodec {
    fn default() -> Self {
        Self {
            inbound_budget: process_global_inbound_budget(),
            outbound_budget: OutboundResponseBudget::process_global(),
        }
    }
}

#[async_trait]
impl request_response::Codec for HistoryStepTerminalCodec {
    type Protocol = StreamProtocol;
    type Request = GetHistoryStepTerminalRequest;
    type Response = GetHistoryStepTerminalResponse;

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
            return Err(invalid_data(
                "invalid HistoryStep terminal request magic/version",
            ));
        }
        ensure_eof(io).await?;
        Ok(GetHistoryStepTerminalRequest {
            height: u64::from_le_bytes(request[4..12].try_into().unwrap()),
            block_hash: request[12..44].try_into().unwrap(),
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
        let (terminal_len, height, block_hash) = parse_response_header(&header)?;
        let payload_len = decoded_len(terminal_len);
        let inbound_memory_permit = self.acquire_inbound(payload_len).await?;
        let terminal_bytes = read_optional(io, terminal_len).await?;
        ensure_eof(io).await?;
        if let Some(terminal) = terminal_bytes.as_deref() {
            validate_terminal_binding(terminal, height, block_hash)?;
        }
        Ok(GetHistoryStepTerminalResponse {
            height,
            block_hash,
            terminal_bytes,
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
        let GetHistoryStepTerminalResponse {
            height,
            block_hash,
            terminal_bytes,
            inbound_memory_permit,
            outbound_memory_permit,
        } = response;
        if let Some(terminal) = terminal_bytes.as_deref() {
            validate_terminal_binding(terminal, height, block_hash)?;
        }
        let terminal_len = optional_len(terminal_bytes.as_deref(), "HistoryStep terminal")?;
        validate_length(terminal_len)?;
        let payload_len = decoded_len(terminal_len);
        let outbound_memory_permit = match outbound_memory_permit {
            Some(permit) => Some(permit),
            None => self.outbound_budget.acquire(payload_len).await?,
        };
        let _memory_permits = (inbound_memory_permit, outbound_memory_permit);

        let mut header = [0u8; RESPONSE_HEADER_BYTES];
        header[..4].copy_from_slice(&RESPONSE_MAGIC);
        header[4..8].copy_from_slice(&terminal_len.to_le_bytes());
        header[8..16].copy_from_slice(&height.to_le_bytes());
        header[16..48].copy_from_slice(&block_hash);
        io.write_all(&header).await?;
        if let Some(bytes) = terminal_bytes {
            io.write_all(&bytes).await?;
        }
        Ok(())
    }
}

impl HistoryStepTerminalCodec {
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
            .map_err(|_| invalid_data("HistoryStep response byte budget overflow"))?;
        let permit = self
            .inbound_budget
            .clone()
            .acquire_many_owned(permits)
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "HistoryStep byte budget closed")
            })?;
        Ok(Some(Arc::new(permit)))
    }
}

fn parse_response_header(header: &[u8; RESPONSE_HEADER_BYTES]) -> io::Result<(u32, u64, [u8; 32])> {
    if header[..4] != RESPONSE_MAGIC {
        return Err(invalid_data(
            "invalid HistoryStep terminal response magic/version",
        ));
    }
    let terminal_len = u32::from_le_bytes(header[4..8].try_into().unwrap());
    validate_length(terminal_len)?;
    let height = u64::from_le_bytes(header[8..16].try_into().unwrap());
    let block_hash = header[16..48].try_into().unwrap();
    Ok((terminal_len, height, block_hash))
}

fn validate_length(terminal_len: u32) -> io::Result<()> {
    let terminal_is_present = terminal_len != NONE_LEN;
    let terminal_len = decoded_len(terminal_len);
    if terminal_is_present && terminal_len <= HISTORY_STEP_TERMINAL_BINDING_BYTES {
        return Err(invalid_data("declared HistoryStep terminal is truncated"));
    }
    if terminal_len > MAX_HISTORY_STEP_TERMINAL_BYTES {
        return Err(invalid_data(
            "declared HistoryStep terminal exceeds wire cap",
        ));
    }
    Ok(())
}

fn validate_terminal_binding(
    terminal: &[u8],
    expected_height: u64,
    expected_hash: [u8; 32],
) -> io::Result<()> {
    if terminal.len() <= HISTORY_STEP_TERMINAL_BINDING_BYTES {
        return Err(invalid_data("HistoryStep terminal is truncated"));
    }
    let version = terminal[0];
    let height = u64::from_le_bytes(terminal[1..9].try_into().unwrap());
    let block_hash: [u8; 32] = terminal[9..41].try_into().unwrap();
    let class_id = terminal[41];
    if version != HISTORY_STEP_TERMINAL_VERSION
        || height != expected_height
        || block_hash != expected_hash
        || class_id >= noid_chain::HISTORY_STEP_CLASS_COUNT
    {
        return Err(invalid_data(
            "HistoryStep terminal does not bind its response boundary",
        ));
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
            "HistoryStep response allocation failed",
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
        return Err(invalid_data("trailing bytes in HistoryStep message"));
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
        StreamProtocol::new("/noid/test/sync/history-step/1")
    }

    fn terminal(height: u64, block_hash: [u8; 32], fill: u8) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(HISTORY_STEP_TERMINAL_VERSION);
        bytes.extend_from_slice(&height.to_le_bytes());
        bytes.extend_from_slice(&block_hash);
        bytes.push(1);
        bytes.push(fill);
        bytes
    }

    fn response_wire(height: u64, hash: [u8; 32], fill: u8) -> Vec<u8> {
        let terminal = terminal(height, hash, fill);
        let mut wire = vec![0u8; RESPONSE_HEADER_BYTES];
        wire[..4].copy_from_slice(&RESPONSE_MAGIC);
        wire[4..8].copy_from_slice(&(terminal.len() as u32).to_le_bytes());
        wire[8..16].copy_from_slice(&height.to_le_bytes());
        wire[16..48].copy_from_slice(&hash);
        wire.extend_from_slice(&terminal);
        wire
    }

    #[tokio::test]
    async fn request_round_trip_binds_exact_snapshot_boundary() {
        let request = GetHistoryStepTerminalRequest {
            height: 77,
            block_hash: [0xA5; 32],
        };
        let mut wire = Cursor::new(Vec::new());
        HistoryStepTerminalCodec::default()
            .write_request(&protocol(), &mut wire, request.clone())
            .await
            .unwrap();
        wire.set_position(0);
        let decoded = HistoryStepTerminalCodec::default()
            .read_request(&protocol(), &mut wire)
            .await
            .unwrap();
        assert_eq!(decoded.height, request.height);
        assert_eq!(decoded.block_hash, request.block_hash);
    }

    #[tokio::test]
    async fn terminal_round_trip_preserves_exact_binding() {
        let response = GetHistoryStepTerminalResponse {
            height: 77,
            block_hash: [0xA5; 32],
            terminal_bytes: Some(terminal(77, [0xA5; 32], 1)),
            inbound_memory_permit: None,
            outbound_memory_permit: None,
        };
        let mut wire = Cursor::new(Vec::new());
        HistoryStepTerminalCodec::default()
            .write_response(&protocol(), &mut wire, response)
            .await
            .unwrap();
        wire.set_position(0);
        let decoded = HistoryStepTerminalCodec::default()
            .read_response(&protocol(), &mut wire)
            .await
            .unwrap();
        assert_eq!(decoded.height, 77);
        assert_eq!(decoded.block_hash, [0xA5; 32]);
        assert_eq!(decoded.terminal_bytes.unwrap()[42], 1);
    }

    #[tokio::test]
    async fn forged_terminal_binding_is_rejected() {
        let mut wire = response_wire(77, [0xA5; 32], 1);
        wire[RESPONSE_HEADER_BYTES + 9] ^= 1;
        assert_eq!(
            HistoryStepTerminalCodec::default()
                .read_response(&protocol(), &mut Cursor::new(wire))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn out_of_bank_class_is_rejected() {
        let mut wire = response_wire(77, [0xA5; 32], 1);
        wire[RESPONSE_HEADER_BYTES + 41] = noid_chain::HISTORY_STEP_CLASS_COUNT;
        assert_eq!(
            HistoryStepTerminalCodec::default()
                .read_response(&protocol(), &mut Cursor::new(wire))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn malicious_length_is_rejected_before_payload_read() {
        let mut header = vec![0u8; RESPONSE_HEADER_BYTES];
        header[..4].copy_from_slice(&RESPONSE_MAGIC);
        header[4..8].copy_from_slice(&((MAX_HISTORY_STEP_TERMINAL_BYTES + 1) as u32).to_le_bytes());
        assert_eq!(
            HistoryStepTerminalCodec::default()
                .read_response(&protocol(), &mut Cursor::new(header))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn inbound_budget_follows_terminal_until_consumption() {
        let wire = response_wire(77, [0xA5; 32], 1);
        let terminal_len = HISTORY_STEP_TERMINAL_BINDING_BYTES + 1;
        let codec = HistoryStepTerminalCodec::with_inbound_budget(terminal_len);
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
                .terminal_bytes
                .is_some()
        );
    }
}
