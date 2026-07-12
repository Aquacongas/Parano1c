// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Allocation-bounded snapshot-segment wire codec.
//!
//! The fixed header authenticates all lengths before allocation. Payload bytes
//! are streamed directly from/to the response Vec, avoiding the second full
//! serialization buffer used by the generic CBOR codec.

use std::{io, sync::Arc};

use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{request_response, swarm::StreamProtocol};
use noid_chain::{
    consensus::wire_limits::MAX_SEGMENT_BYTES, storage::encoded_segment_len_for_eff_log,
};

use crate::{
    inbound_budget::process_global_inbound_budget,
    outbound_budget::OutboundResponseBudget,
    protocol::{GetStateSegmentRequest, GetStateSegmentResponse},
};

const REQUEST_MAGIC: [u8; 4] = *b"NSR2";
const RESPONSE_MAGIC: [u8; 4] = *b"NSS2";
const REQUEST_HEADER_BYTES: usize = 48;
const RESPONSE_HEADER_BYTES: usize = 12;
const NONE_LEN: u32 = u32::MAX;
#[derive(Debug, Clone)]
pub struct StateSegmentCodec {
    inbound_budget: Arc<tokio::sync::Semaphore>,
    outbound_budget: OutboundResponseBudget,
}

impl Default for StateSegmentCodec {
    fn default() -> Self {
        Self {
            inbound_budget: process_global_inbound_budget(),
            outbound_budget: OutboundResponseBudget::process_global(),
        }
    }
}

impl StateSegmentCodec {
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
        let permits =
            u32::try_from(bytes).map_err(|_| invalid_data("state-segment byte budget overflow"))?;
        let permit = self
            .inbound_budget
            .clone()
            .acquire_many_owned(permits)
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "state-segment budget closed")
            })?;
        Ok(Some(Arc::new(permit)))
    }
}

#[async_trait]
impl request_response::Codec for StateSegmentCodec {
    type Protocol = StreamProtocol;
    type Request = GetStateSegmentRequest;
    type Response = GetStateSegmentResponse;

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
            return Err(invalid_data("invalid state-segment request magic/version"));
        }
        if header[6..8] != [0, 0] {
            return Err(invalid_data(
                "non-zero state-segment request reserved bytes",
            ));
        }
        ensure_eof(io).await?;
        Ok(GetStateSegmentRequest {
            segment_id: u16::from_le_bytes(header[4..6].try_into().expect("fixed segment id")),
            expected_tip_height: u64::from_le_bytes(
                header[8..16].try_into().expect("fixed tip height"),
            ),
            expected_tip_hash: header[16..48].try_into().expect("fixed tip hash"),
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
        let (segment_id, eff_log, encoded_len) = parse_response_header(&header)?;
        let payload_len = decoded_len(encoded_len);
        let inbound_memory_permit = self.acquire_inbound(payload_len).await?;
        let data = if encoded_len == NONE_LEN {
            None
        } else {
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(payload_len).map_err(|_| {
                io::Error::new(io::ErrorKind::OutOfMemory, "segment allocation failed")
            })?;
            bytes.resize(payload_len, 0);
            io.read_exact(&mut bytes).await?;
            Some(bytes)
        };
        ensure_eof(io).await?;
        Ok(GetStateSegmentResponse {
            segment_id,
            eff_log,
            data,
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
        header[4..6].copy_from_slice(&request.segment_id.to_le_bytes());
        header[8..16].copy_from_slice(&request.expected_tip_height.to_le_bytes());
        header[16..48].copy_from_slice(&request.expected_tip_hash);
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
        let GetStateSegmentResponse {
            segment_id,
            eff_log,
            data,
            inbound_memory_permit,
            outbound_memory_permit,
        } = response;
        let encoded_len = optional_len(data.as_deref())?;
        validate_response_length(eff_log, encoded_len)?;
        let payload_len = decoded_len(encoded_len);
        let outbound_memory_permit = match outbound_memory_permit {
            Some(permit) => Some(permit),
            None => self.outbound_budget.acquire(payload_len).await?,
        };
        // Both permits (the latter normally only exists for locally-served
        // responses) remain in scope until the final write resolves.
        let _memory_permits = (inbound_memory_permit, outbound_memory_permit);

        let mut header = [0u8; RESPONSE_HEADER_BYTES];
        header[..4].copy_from_slice(&RESPONSE_MAGIC);
        header[4..6].copy_from_slice(&segment_id.to_le_bytes());
        header[6] = eff_log;
        header[8..12].copy_from_slice(&encoded_len.to_le_bytes());
        io.write_all(&header).await?;
        if let Some(bytes) = data {
            io.write_all(&bytes).await?;
        }
        Ok(())
    }
}

fn parse_response_header(header: &[u8; RESPONSE_HEADER_BYTES]) -> io::Result<(u16, u8, u32)> {
    if header[..4] != RESPONSE_MAGIC {
        return Err(invalid_data("invalid state-segment response magic/version"));
    }
    if header[7] != 0 {
        return Err(invalid_data(
            "non-zero state-segment response reserved byte",
        ));
    }
    let segment_id = u16::from_le_bytes(header[4..6].try_into().expect("fixed segment id"));
    let eff_log = header[6];
    let encoded_len = u32::from_le_bytes(header[8..12].try_into().expect("fixed length"));
    validate_response_length(eff_log, encoded_len)?;
    Ok((segment_id, eff_log, encoded_len))
}

fn validate_response_length(eff_log: u8, encoded_len: u32) -> io::Result<()> {
    if encoded_len == NONE_LEN {
        return if eff_log == 0 {
            Ok(())
        } else {
            Err(invalid_data(
                "unavailable segment has non-zero effective log",
            ))
        };
    }
    let len = encoded_len as usize;
    if len > MAX_SEGMENT_BYTES {
        return Err(invalid_data("declared state segment exceeds wire cap"));
    }
    let expected = encoded_segment_len_for_eff_log(eff_log)
        .ok_or_else(|| invalid_data("invalid state-segment effective log"))?;
    if len != expected {
        return Err(invalid_data(
            "declared state-segment length is not canonical",
        ));
    }
    Ok(())
}

fn optional_len(data: Option<&[u8]>) -> io::Result<u32> {
    match data {
        Some(bytes) => u32::try_from(bytes.len())
            .map_err(|_| invalid_data("state-segment length does not fit u32")),
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
        return Err(invalid_data("trailing bytes in state-segment message"));
    }
    Ok(())
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        },
        task::{Context, Poll, Waker},
    };

    use futures::io::Cursor;
    use libp2p::request_response::Codec;

    use super::*;

    fn protocol() -> StreamProtocol {
        StreamProtocol::new("/noid/test/sync/segment/2")
    }

    fn response_header(eff_log: u8, encoded_len: u32) -> Vec<u8> {
        let mut header = vec![0u8; RESPONSE_HEADER_BYTES];
        header[..4].copy_from_slice(&RESPONSE_MAGIC);
        header[4..6].copy_from_slice(&7u16.to_le_bytes());
        header[6] = eff_log;
        header[8..12].copy_from_slice(&encoded_len.to_le_bytes());
        header
    }

    #[test]
    fn production_codecs_share_one_process_inbound_budget() {
        let first = StateSegmentCodec::default();
        let second = StateSegmentCodec::default();
        let shared = process_global_inbound_budget();
        assert!(Arc::ptr_eq(&first.inbound_budget, &second.inbound_budget));
        assert!(Arc::ptr_eq(&first.inbound_budget, &shared));
    }

    struct GatedWriter {
        started: Arc<AtomicBool>,
        released: Arc<AtomicBool>,
        waker: Arc<Mutex<Option<Waker>>>,
    }

    impl AsyncWrite for GatedWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.started.store(true, Ordering::SeqCst);
            if !self.released.load(Ordering::SeqCst) {
                *self.waker.lock().unwrap() = Some(cx.waker().clone());
                return Poll::Pending;
            }
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn round_trip_streams_one_canonical_segment() {
        let len = encoded_segment_len_for_eff_log(10).unwrap();
        let response = GetStateSegmentResponse {
            segment_id: 7,
            eff_log: 10,
            data: Some(vec![0x5a; len]),
            inbound_memory_permit: None,
            outbound_memory_permit: None,
        };
        let mut wire = Cursor::new(Vec::new());
        StateSegmentCodec::default()
            .write_response(&protocol(), &mut wire, response)
            .await
            .unwrap();
        assert_eq!(wire.get_ref().len(), RESPONSE_HEADER_BYTES + len);
        wire.set_position(0);
        let decoded = StateSegmentCodec::default()
            .read_response(&protocol(), &mut wire)
            .await
            .unwrap();
        assert_eq!(decoded.segment_id, 7);
        assert_eq!(decoded.data.unwrap(), vec![0x5a; len]);
    }

    #[tokio::test]
    async fn malicious_length_is_rejected_before_payload_read_or_allocation() {
        let declared = encoded_segment_len_for_eff_log(16).unwrap() + 1;
        let error = StateSegmentCodec::default()
            .read_response(
                &protocol(),
                &mut Cursor::new(response_header(16, declared as u32)),
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("not canonical"));
    }

    #[tokio::test]
    async fn inbound_budget_blocks_second_segment_until_first_is_consumed() {
        let len = encoded_segment_len_for_eff_log(6).unwrap();
        let codec = StateSegmentCodec::with_inbound_budget(len);
        let mut first_wire = response_header(6, len as u32);
        first_wire.extend(std::iter::repeat_n(1u8, len));
        let first = codec
            .clone()
            .read_response(&protocol(), &mut Cursor::new(first_wire))
            .await
            .unwrap();

        let mut second_wire = response_header(6, len as u32);
        second_wire.extend(std::iter::repeat_n(2u8, len));
        let mut second_codec = codec.clone();
        let second = tokio::spawn(async move {
            second_codec
                .read_response(&protocol(), &mut Cursor::new(second_wire))
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
        assert_eq!(second.data.unwrap()[0], 2);
    }

    #[tokio::test]
    async fn outbound_permit_lives_until_codec_write_completes() {
        let len = encoded_segment_len_for_eff_log(6).unwrap();
        let budget = OutboundResponseBudget::with_capacity(len);
        let permit = budget.acquire(len).await.unwrap().unwrap();
        let response = GetStateSegmentResponse {
            segment_id: 3,
            eff_log: 6,
            data: Some(vec![0x33; len]),
            inbound_memory_permit: None,
            outbound_memory_permit: Some(permit),
        };
        let started = Arc::new(AtomicBool::new(false));
        let released = Arc::new(AtomicBool::new(false));
        let waker = Arc::new(Mutex::new(None));
        let writer = GatedWriter {
            started: started.clone(),
            released: released.clone(),
            waker: waker.clone(),
        };
        let write = tokio::spawn(async move {
            let mut writer = writer;
            StateSegmentCodec::default()
                .write_response(&protocol(), &mut writer, response)
                .await
        });
        while !started.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
        assert_eq!(budget.available_bytes(), 0);
        assert!(!write.is_finished());

        let waiter_budget = budget.clone();
        let waiter = tokio::spawn(async move { waiter_budget.acquire(len).await.unwrap() });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());

        released.store(true, Ordering::SeqCst);
        if let Some(waker) = waker.lock().unwrap().take() {
            waker.wake();
        }
        write.await.unwrap().unwrap();
        let second_permit = tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(budget.available_bytes(), 0);
        drop(second_permit);
        assert_eq!(budget.available_bytes(), len);
    }
}
