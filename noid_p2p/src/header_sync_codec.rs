// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Allocation-bounded framing for canonical header batches.
//!
//! The generic libp2p CBOR codec buffers as many as ten MiB before decoding
//! attacker-controlled sequence lengths.  Header sync has a much smaller
//! consensus surface: at most 512 headers, each exactly
//! [`noid_chain::BLOCK_HEADER_WIRE_SIZE`] bytes.  This codec checks that count
//! in its fixed header before reserving the response vectors.

use std::io;

use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{request_response, swarm::StreamProtocol};
use noid_chain::BLOCK_HEADER_WIRE_SIZE;

use crate::protocol::{GetHeadersRequest, GetHeadersResponse};

const REQUEST_MAGIC: [u8; 4] = *b"NHQ2";
const RESPONSE_MAGIC: [u8; 4] = *b"NHB2";
const REQUEST_BYTES: usize = 4 + 8 + 2 + 2;
const RESPONSE_HEADER_BYTES: usize = 4 + 2 + 2;
const MAX_HEADERS: usize = 512;

/// Fixed-framing header request/response codec.
#[derive(Debug, Clone, Copy, Default)]
pub struct HeaderSyncCodec;

#[async_trait]
impl request_response::Codec for HeaderSyncCodec {
    type Protocol = StreamProtocol;
    type Request = GetHeadersRequest;
    type Response = GetHeadersResponse;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut encoded = [0u8; REQUEST_BYTES];
        io.read_exact(&mut encoded).await?;
        if encoded[..4] != REQUEST_MAGIC {
            return Err(invalid_data("invalid header-sync request magic/version"));
        }
        if encoded[14..16] != [0, 0] {
            return Err(invalid_data("non-zero header-sync request reserved bytes"));
        }
        let count = u16::from_le_bytes(encoded[12..14].try_into().expect("fixed count"));
        validate_count(count)?;
        ensure_eof(io).await?;
        Ok(GetHeadersRequest {
            start_height: u64::from_le_bytes(
                encoded[4..12].try_into().expect("fixed start height"),
            ),
            count,
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
            return Err(invalid_data("invalid header-sync response magic/version"));
        }
        if header[6..8] != [0, 0] {
            return Err(invalid_data("non-zero header-sync response reserved bytes"));
        }
        let count = u16::from_le_bytes(header[4..6].try_into().expect("fixed count"));
        validate_count(count)?;

        // The attacker-controlled count has now passed its hard cap.  Only at
        // this point may the outer and per-header vectors be reserved.
        let count = usize::from(count);
        let mut headers = Vec::new();
        headers.try_reserve_exact(count).map_err(|_| {
            io::Error::new(io::ErrorKind::OutOfMemory, "header batch allocation failed")
        })?;
        for _ in 0..count {
            let mut encoded = vec![0u8; BLOCK_HEADER_WIRE_SIZE];
            io.read_exact(&mut encoded).await?;
            headers.push(encoded);
        }
        ensure_eof(io).await?;
        Ok(GetHeadersResponse { headers })
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
        validate_count(request.count)?;
        let mut encoded = [0u8; REQUEST_BYTES];
        encoded[..4].copy_from_slice(&REQUEST_MAGIC);
        encoded[4..12].copy_from_slice(&request.start_height.to_le_bytes());
        encoded[12..14].copy_from_slice(&request.count.to_le_bytes());
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
        let count = u16::try_from(response.headers.len())
            .map_err(|_| invalid_data("header batch count does not fit u16"))?;
        validate_count(count)?;
        if response
            .headers
            .iter()
            .any(|encoded| encoded.len() != BLOCK_HEADER_WIRE_SIZE)
        {
            return Err(invalid_data(
                "header batch contains a noncanonical header length",
            ));
        }

        let mut header = [0u8; RESPONSE_HEADER_BYTES];
        header[..4].copy_from_slice(&RESPONSE_MAGIC);
        header[4..6].copy_from_slice(&count.to_le_bytes());
        io.write_all(&header).await?;
        for encoded in response.headers {
            io.write_all(&encoded).await?;
        }
        Ok(())
    }
}

fn validate_count(count: u16) -> io::Result<()> {
    if usize::from(count) > MAX_HEADERS {
        return Err(invalid_data("declared header batch count exceeds 512"));
    }
    Ok(())
}

async fn ensure_eof<T: AsyncRead + Unpin + Send>(io: &mut T) -> io::Result<()> {
    let mut trailing = [0u8; 1];
    if io.read(&mut trailing).await? != 0 {
        return Err(invalid_data("trailing bytes in header-sync message"));
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
        StreamProtocol::new("/noid/test/sync/headers/2")
    }

    fn response_header(count: u16) -> Vec<u8> {
        let mut encoded = vec![0u8; RESPONSE_HEADER_BYTES];
        encoded[..4].copy_from_slice(&RESPONSE_MAGIC);
        encoded[4..6].copy_from_slice(&count.to_le_bytes());
        encoded
    }

    #[tokio::test]
    async fn request_is_exact_and_caps_count() {
        let request = GetHeadersRequest {
            start_height: 41,
            count: 512,
        };
        let mut wire = Cursor::new(Vec::new());
        HeaderSyncCodec
            .write_request(&protocol(), &mut wire, request)
            .await
            .unwrap();
        assert_eq!(wire.get_ref().len(), REQUEST_BYTES);
        wire.set_position(0);
        let decoded = HeaderSyncCodec
            .read_request(&protocol(), &mut wire)
            .await
            .unwrap();
        assert_eq!(decoded.start_height, 41);
        assert_eq!(decoded.count, 512);

        let mut oversized = wire.into_inner();
        oversized[12..14].copy_from_slice(&513u16.to_le_bytes());
        let error = HeaderSyncCodec
            .read_request(&protocol(), &mut Cursor::new(oversized))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn malicious_count_rejects_before_any_header_payload_read_or_reserve() {
        // Only the fixed header is supplied. InvalidData (rather than EOF)
        // demonstrates that the count gate fires before a payload read.
        let error = HeaderSyncCodec
            .read_response(&protocol(), &mut Cursor::new(response_header(u16::MAX)))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("count"));
    }

    #[tokio::test]
    async fn response_round_trip_has_exact_canonical_framing() {
        let response = GetHeadersResponse {
            headers: vec![
                vec![0x11; BLOCK_HEADER_WIRE_SIZE],
                vec![0x22; BLOCK_HEADER_WIRE_SIZE],
            ],
        };
        let mut wire = Cursor::new(Vec::new());
        HeaderSyncCodec
            .write_response(&protocol(), &mut wire, response)
            .await
            .unwrap();
        assert_eq!(
            wire.get_ref().len(),
            RESPONSE_HEADER_BYTES + 2 * BLOCK_HEADER_WIRE_SIZE
        );
        wire.set_position(0);
        let decoded = HeaderSyncCodec
            .read_response(&protocol(), &mut wire)
            .await
            .unwrap();
        assert_eq!(decoded.headers[0], vec![0x11; BLOCK_HEADER_WIRE_SIZE]);
        assert_eq!(decoded.headers[1], vec![0x22; BLOCK_HEADER_WIRE_SIZE]);
    }

    #[tokio::test]
    async fn writer_rejects_noncanonical_header_before_partial_output() {
        let mut wire = Cursor::new(Vec::new());
        let error = HeaderSyncCodec
            .write_response(
                &protocol(),
                &mut wire,
                GetHeadersResponse {
                    headers: vec![vec![0; BLOCK_HEADER_WIRE_SIZE - 1]],
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(wire.get_ref().is_empty());
    }

    #[tokio::test]
    async fn response_rejects_trailing_bytes() {
        let mut wire = response_header(0);
        wire.push(0xAA);
        let error = HeaderSyncCodec
            .read_response(&protocol(), &mut Cursor::new(wire))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
