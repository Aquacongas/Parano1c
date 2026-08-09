// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Allocation-bounded compressed framing for canonical header batches.
//!
//! The generic libp2p CBOR codec buffers as many as ten MiB before decoding
//! attacker-controlled sequence lengths.  Header sync has a much smaller
//! consensus surface: at most 4,096 headers, each exactly
//! [`noid_chain::BLOCK_HEADER_WIRE_SIZE`] bytes. This codec checks the count,
//! compressed length, frame length, declared content size and zstd window
//! before decompression. The decompressed payload is the unchanged canonical
//! header stream consumed by the existing validation and storage path.

use std::io;

use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{request_response, swarm::StreamProtocol};
use noid_chain::BLOCK_HEADER_WIRE_SIZE;

use crate::protocol::{GetHeadersRequest, GetHeadersResponse};

const REQUEST_MAGIC: [u8; 4] = *b"NHQ3";
const RESPONSE_MAGIC: [u8; 4] = *b"NHB3";
const REQUEST_BYTES: usize = 4 + 8 + 2 + 2;
const RESPONSE_HEADER_BYTES: usize = 4 + 2 + 2 + 4;
const HEADER_COMPRESSION_LEVEL: i32 = 1;
const HEADER_ZSTD_WINDOW_LOG_MAX: u32 = 20;
/// Fixed bytes preceding the canonical header payload in one response.
pub const HEADER_RESPONSE_PREFIX_BYTES: usize = RESPONSE_HEADER_BYTES;
/// Maximum compressed-framing header batch.
///
/// At the canonical 212-byte header size this keeps the decompressed payload
/// below 0.83 MiB while avoiding a network round trip for every 512 headers.
pub const MAX_HEADERS_PER_BATCH: usize = 4_096;
/// Maximum canonical bytes produced by one compressed response.
pub const MAX_UNCOMPRESSED_HEADER_BYTES: usize = MAX_HEADERS_PER_BATCH * BLOCK_HEADER_WIRE_SIZE;

const _: () = assert!(
    MAX_UNCOMPRESSED_HEADER_BYTES <= (1usize << HEADER_ZSTD_WINDOW_LOG_MAX),
    "header batch must fit inside the bounded zstd window"
);

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
        let compressed_len =
            u32::from_le_bytes(header[8..12].try_into().expect("fixed compressed length")) as usize;
        let canonical_len = canonical_payload_len(count)?;
        validate_compressed_len(canonical_len, compressed_len)?;

        // Both attacker-controlled lengths have passed count-relative hard
        // caps. Read exactly one bounded frame before invoking zstd.
        let mut compressed = Vec::new();
        compressed.try_reserve_exact(compressed_len).map_err(|_| {
            io::Error::new(io::ErrorKind::OutOfMemory, "header batch allocation failed")
        })?;
        compressed.resize(compressed_len, 0);
        io.read_exact(&mut compressed).await?;
        ensure_eof(io).await?;

        validate_zstd_frame(&compressed, canonical_len)?;
        let payload = decompress_canonical_headers(&compressed, canonical_len)?;

        let count = usize::from(count);
        let mut headers = Vec::new();
        headers.try_reserve_exact(count).map_err(|_| {
            io::Error::new(io::ErrorKind::OutOfMemory, "header batch allocation failed")
        })?;
        for encoded in payload.chunks_exact(BLOCK_HEADER_WIRE_SIZE) {
            headers.push(encoded.to_vec());
        }
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

        let canonical_len = canonical_payload_len(count)?;
        let mut canonical = Vec::new();
        canonical.try_reserve_exact(canonical_len).map_err(|_| {
            io::Error::new(io::ErrorKind::OutOfMemory, "header batch allocation failed")
        })?;
        for encoded in response.headers {
            canonical.extend_from_slice(&encoded);
        }
        let compressed =
            zstd::bulk::compress(&canonical, HEADER_COMPRESSION_LEVEL).map_err(|error| {
                io::Error::other(format!("header zstd compression failed: {error}"))
            })?;
        validate_compressed_len(canonical_len, compressed.len()).map_err(|_| {
            io::Error::other("header zstd encoder exceeded its deterministic bound")
        })?;
        let compressed_len = u32::try_from(compressed.len())
            .map_err(|_| io::Error::other("compressed header batch length does not fit u32"))?;

        let mut response_header = [0u8; RESPONSE_HEADER_BYTES];
        response_header[..4].copy_from_slice(&RESPONSE_MAGIC);
        response_header[4..6].copy_from_slice(&count.to_le_bytes());
        response_header[8..12].copy_from_slice(&compressed_len.to_le_bytes());
        io.write_all(&response_header).await?;
        io.write_all(&compressed).await
    }
}

fn validate_count(count: u16) -> io::Result<()> {
    if usize::from(count) > MAX_HEADERS_PER_BATCH {
        return Err(invalid_data(
            "declared header batch count exceeds the fixed cap",
        ));
    }
    Ok(())
}

fn canonical_payload_len(count: u16) -> io::Result<usize> {
    usize::from(count)
        .checked_mul(BLOCK_HEADER_WIRE_SIZE)
        .filter(|len| *len <= MAX_UNCOMPRESSED_HEADER_BYTES)
        .ok_or_else(|| invalid_data("header batch canonical length exceeds the fixed cap"))
}

fn validate_compressed_len(canonical_len: usize, compressed_len: usize) -> io::Result<()> {
    let maximum = zstd::zstd_safe::compress_bound(canonical_len);
    if compressed_len == 0 || compressed_len > maximum {
        return Err(invalid_data(
            "compressed header batch length exceeds its count-relative bound",
        ));
    }
    Ok(())
}

fn validate_zstd_frame(compressed: &[u8], canonical_len: usize) -> io::Result<()> {
    let frame_len = zstd::zstd_safe::find_frame_compressed_size(compressed)
        .map_err(|_| invalid_data("invalid header zstd frame"))?;
    if frame_len != compressed.len() {
        return Err(invalid_data(
            "header response must contain exactly one zstd frame",
        ));
    }
    let content_size = zstd::zstd_safe::get_frame_content_size(compressed)
        .map_err(|_| invalid_data("invalid header zstd content size"))?;
    if content_size != Some(canonical_len as u64) {
        return Err(invalid_data(
            "header zstd content size does not match the declared count",
        ));
    }
    Ok(())
}

fn decompress_canonical_headers(compressed: &[u8], canonical_len: usize) -> io::Result<Vec<u8>> {
    let mut decoder = zstd::bulk::Decompressor::new()
        .map_err(|error| io::Error::other(format!("header zstd decoder init failed: {error}")))?;
    decoder
        .window_log_max(HEADER_ZSTD_WINDOW_LOG_MAX)
        .map_err(|error| io::Error::other(format!("header zstd window setup failed: {error}")))?;
    let decoded = decoder
        .decompress(compressed, canonical_len)
        .map_err(|_| invalid_data("header zstd decompression failed"))?;
    if decoded.len() != canonical_len {
        return Err(invalid_data(
            "decompressed header payload has the wrong canonical length",
        ));
    }
    Ok(decoded)
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
        StreamProtocol::new("/noid/test/sync/headers/3")
    }

    fn response_header(count: u16, compressed_len: usize) -> Vec<u8> {
        let mut encoded = vec![0u8; RESPONSE_HEADER_BYTES];
        encoded[..4].copy_from_slice(&RESPONSE_MAGIC);
        encoded[4..6].copy_from_slice(&count.to_le_bytes());
        encoded[8..12].copy_from_slice(&(compressed_len as u32).to_le_bytes());
        encoded
    }

    fn compress(payload: &[u8]) -> Vec<u8> {
        zstd::bulk::compress(payload, HEADER_COMPRESSION_LEVEL).unwrap()
    }

    fn framed_response(count: u16, canonical: &[u8]) -> Vec<u8> {
        let compressed = compress(canonical);
        let mut encoded = response_header(count, compressed.len());
        encoded.extend_from_slice(&compressed);
        encoded
    }

    #[tokio::test]
    async fn request_is_exact_and_caps_count() {
        let request = GetHeadersRequest {
            start_height: 41,
            count: MAX_HEADERS_PER_BATCH as u16,
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
        assert_eq!(decoded.count, MAX_HEADERS_PER_BATCH as u16);

        let mut oversized = wire.into_inner();
        oversized[12..14].copy_from_slice(&((MAX_HEADERS_PER_BATCH as u16) + 1).to_le_bytes());
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
            .read_response(&protocol(), &mut Cursor::new(response_header(u16::MAX, 1)))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("count"));
    }

    #[tokio::test]
    async fn response_round_trip_restores_exact_canonical_headers() {
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
        assert_eq!(&wire.get_ref()[..4], &RESPONSE_MAGIC);
        let compressed_len = u32::from_le_bytes(wire.get_ref()[8..12].try_into().unwrap());
        assert_eq!(
            wire.get_ref().len(),
            RESPONSE_HEADER_BYTES + compressed_len as usize
        );
        assert!(wire.get_ref().len() < RESPONSE_HEADER_BYTES + 2 * BLOCK_HEADER_WIRE_SIZE);
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
    async fn compressed_length_cap_fires_before_payload_read_or_reserve() {
        let canonical_len = BLOCK_HEADER_WIRE_SIZE;
        let oversized = zstd::zstd_safe::compress_bound(canonical_len) + 1;
        let error = HeaderSyncCodec
            .read_response(&protocol(), &mut Cursor::new(response_header(1, oversized)))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("compressed"));
    }

    #[tokio::test]
    async fn response_rejects_zstd_content_size_that_disagrees_with_count() {
        let one_header = vec![0x33; BLOCK_HEADER_WIRE_SIZE];
        let error = HeaderSyncCodec
            .read_response(
                &protocol(),
                &mut Cursor::new(framed_response(2, &one_header)),
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("content size"));
    }

    #[tokio::test]
    async fn response_rejects_multiple_zstd_frames_inside_declared_payload() {
        let canonical = vec![0x44; BLOCK_HEADER_WIRE_SIZE];
        let mut compressed = compress(&canonical);
        compressed.extend_from_slice(&compress(&[]));
        assert!(compressed.len() <= zstd::zstd_safe::compress_bound(canonical.len()));
        let mut wire = response_header(1, compressed.len());
        wire.extend_from_slice(&compressed);

        let error = HeaderSyncCodec
            .read_response(&protocol(), &mut Cursor::new(wire))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("exactly one"));
    }

    #[tokio::test]
    async fn maximum_batch_round_trip_stays_exact_and_bounded() {
        let mut state = 0xD1B5_4A32_D192_ED03u64;
        let headers = (0..MAX_HEADERS_PER_BATCH)
            .map(|_| {
                (0..BLOCK_HEADER_WIRE_SIZE)
                    .map(|_| {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        state as u8
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let expected = headers.clone();
        let mut wire = Cursor::new(Vec::new());
        HeaderSyncCodec
            .write_response(&protocol(), &mut wire, GetHeadersResponse { headers })
            .await
            .unwrap();
        assert!(
            wire.get_ref().len()
                <= RESPONSE_HEADER_BYTES
                    + zstd::zstd_safe::compress_bound(MAX_UNCOMPRESSED_HEADER_BYTES)
        );
        wire.set_position(0);
        let decoded = HeaderSyncCodec
            .read_response(&protocol(), &mut wire)
            .await
            .unwrap();
        assert_eq!(decoded.headers, expected);
    }

    #[tokio::test]
    async fn response_rejects_trailing_bytes() {
        let mut wire = framed_response(0, &[]);
        wire.push(0xAA);
        let error = HeaderSyncCodec
            .read_response(&protocol(), &mut Cursor::new(wire))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
