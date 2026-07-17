// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Allocation-bounded framing for authenticated snapshot manifests.
//!
//! A manifest can legitimately describe the complete `u16` segment namespace,
//! so it cannot use a decoder that first buffers a generic ten-MiB envelope.
//! This codec authenticates the fixed metadata and validates both declared
//! sequence counts plus their canonical geometry before reserving any vector.

use std::io;

use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{request_response, swarm::StreamProtocol};
use noid_chain::{
    consensus::wire_limits::{MAX_SEGMENT_BYTES, MAX_SNAPSHOT_MANIFEST_SEGMENTS},
    storage::{encoded_segment_live_count_from_len, max_encoded_segment_len_for_eff_log},
    LOG_SEGMENT_SIZE,
};

use crate::protocol::{GetStateManifestRequest, GetStateManifestResponse};

const REQUEST_MAGIC: [u8; 4] = *b"NMQ3";
const RESPONSE_MAGIC: [u8; 4] = *b"NMF3";
const REQUEST_BYTES: usize = 4 + 8;
const RESPONSE_HEADER_BYTES: usize = 4 + 8 + 32 + 32 + 4 + 8 + 8 + 1 + 4;
const SEGMENT_DESCRIPTOR_BYTES: usize = 2 + 32 + 4;

/// Fixed-framing state-manifest request/response codec.
#[derive(Debug, Clone, Copy, Default)]
pub struct StateManifestCodec;

#[async_trait]
impl request_response::Codec for StateManifestCodec {
    type Protocol = StreamProtocol;
    type Request = GetStateManifestRequest;
    type Response = GetStateManifestResponse;

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
            return Err(invalid_data("invalid state-manifest request magic/version"));
        }
        ensure_eof(io).await?;
        Ok(GetStateManifestRequest {
            requester_height: u64::from_le_bytes(
                encoded[4..12].try_into().expect("fixed requester height"),
            ),
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
        let fields = parse_response_header(&header)?;

        // Counts and geometry are now bounded. No attacker-controlled Vec is
        // reserved before this point.
        let segment_count = fields.segment_count as usize;
        let mut segment_ids = Vec::new();
        segment_ids.try_reserve_exact(segment_count).map_err(|_| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                "manifest segment-id allocation failed",
            )
        })?;
        let mut segment_roots = Vec::new();
        segment_roots
            .try_reserve_exact(segment_count)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "manifest segment-root allocation failed",
                )
            })?;
        let mut segment_lengths = Vec::new();
        segment_lengths
            .try_reserve_exact(segment_count)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "manifest segment-length allocation failed",
                )
            })?;

        let mut previous = None;
        let mut declared_live_count = 0u64;
        for _ in 0..segment_count {
            let mut descriptor = [0u8; SEGMENT_DESCRIPTOR_BYTES];
            io.read_exact(&mut descriptor).await?;
            let segment_id =
                u16::from_le_bytes(descriptor[..2].try_into().expect("fixed segment id"));
            if previous.is_some_and(|previous| segment_id <= previous) {
                return Err(invalid_data(
                    "manifest segment ids are not strictly increasing",
                ));
            }
            if u32::from(segment_id) >= fields.maximum_segments {
                return Err(invalid_data(
                    "manifest segment id lies outside snapshot domain",
                ));
            }
            previous = Some(segment_id);
            let encoded_len =
                u32::from_le_bytes(descriptor[34..38].try_into().expect("fixed segment length"));
            let live_count = validate_descriptor_length(fields.eff_log, encoded_len)?;
            declared_live_count = declared_live_count
                .checked_add(u64::from(live_count))
                .ok_or_else(|| invalid_data("manifest live-entry count overflows"))?;
            segment_ids.push(segment_id);
            segment_roots.push(descriptor[2..34].try_into().expect("fixed segment root"));
            segment_lengths.push(encoded_len);
        }
        if declared_live_count != fields.active_slot_count {
            return Err(invalid_data(
                "manifest sparse lengths do not match active slot count",
            ));
        }

        ensure_eof(io).await?;

        Ok(GetStateManifestResponse {
            tip_height: fields.tip_height,
            tip_hash: fields.tip_hash,
            cumulative_chainwork: fields.cumulative_chainwork,
            log_slots: fields.log_slots,
            active_slot_count: fields.active_slot_count,
            alloc_counter: fields.alloc_counter,
            eff_log: fields.eff_log,
            segment_ids,
            segment_roots,
            segment_lengths,
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
        encoded[4..12].copy_from_slice(&request.requester_height.to_le_bytes());
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
        let mut fields = ResponseFields::from_response(&response)?;
        validate_response_fields(&mut fields)?;
        if response.segment_ids.len() != response.segment_roots.len()
            || response.segment_ids.len() != response.segment_lengths.len()
        {
            return Err(invalid_data(
                "manifest segment descriptor vector counts differ",
            ));
        }
        let mut previous = None;
        let mut declared_live_count = 0u64;
        for (&segment_id, &encoded_len) in response
            .segment_ids
            .iter()
            .zip(response.segment_lengths.iter())
        {
            if previous.is_some_and(|previous| segment_id <= previous) {
                return Err(invalid_data(
                    "manifest segment ids are not strictly increasing",
                ));
            }
            if u32::from(segment_id) >= fields.maximum_segments {
                return Err(invalid_data(
                    "manifest segment id lies outside snapshot domain",
                ));
            }
            previous = Some(segment_id);
            let live_count = validate_descriptor_length(fields.eff_log, encoded_len)?;
            declared_live_count = declared_live_count
                .checked_add(u64::from(live_count))
                .ok_or_else(|| invalid_data("manifest live-entry count overflows"))?;
        }
        if declared_live_count != fields.active_slot_count {
            return Err(invalid_data(
                "manifest sparse lengths do not match active slot count",
            ));
        }
        // Validate every variable field before emitting the fixed header so an
        // invalid local response cannot create an ambiguous partial frame.
        let header = encode_response_header(&fields);
        io.write_all(&header).await?;
        for ((segment_id, segment_root), encoded_len) in response
            .segment_ids
            .into_iter()
            .zip(response.segment_roots)
            .zip(response.segment_lengths)
        {
            io.write_all(&segment_id.to_le_bytes()).await?;
            io.write_all(&segment_root).await?;
            io.write_all(&encoded_len.to_le_bytes()).await?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct ResponseFields {
    tip_height: u64,
    tip_hash: [u8; 32],
    cumulative_chainwork: [u8; 32],
    log_slots: u32,
    active_slot_count: u64,
    alloc_counter: u64,
    eff_log: u8,
    segment_count: u32,
    maximum_segments: u32,
}

impl ResponseFields {
    fn from_response(response: &GetStateManifestResponse) -> io::Result<Self> {
        Ok(Self {
            tip_height: response.tip_height,
            tip_hash: response.tip_hash,
            cumulative_chainwork: response.cumulative_chainwork,
            log_slots: response.log_slots,
            active_slot_count: response.active_slot_count,
            alloc_counter: response.alloc_counter,
            eff_log: response.eff_log,
            segment_count: u32::try_from(response.segment_ids.len())
                .map_err(|_| invalid_data("manifest segment count does not fit u32"))?,
            maximum_segments: 0,
        })
    }
}

fn parse_response_header(header: &[u8; RESPONSE_HEADER_BYTES]) -> io::Result<ResponseFields> {
    if header[..4] != RESPONSE_MAGIC {
        return Err(invalid_data(
            "invalid state-manifest response magic/version",
        ));
    }
    let mut fields = ResponseFields {
        tip_height: u64::from_le_bytes(header[4..12].try_into().expect("fixed tip height")),
        tip_hash: header[12..44].try_into().expect("fixed tip hash"),
        cumulative_chainwork: header[44..76].try_into().expect("fixed chainwork"),
        log_slots: u32::from_le_bytes(header[76..80].try_into().expect("fixed log slots")),
        active_slot_count: u64::from_le_bytes(
            header[80..88].try_into().expect("fixed active count"),
        ),
        alloc_counter: u64::from_le_bytes(
            header[88..96].try_into().expect("fixed allocation counter"),
        ),
        eff_log: header[96],
        segment_count: u32::from_le_bytes(header[97..101].try_into().expect("fixed segment count")),
        maximum_segments: 0,
    };
    validate_response_fields(&mut fields)?;
    Ok(fields)
}

fn validate_response_fields(fields: &mut ResponseFields) -> io::Result<()> {
    if fields.tip_height == 0 {
        if fields.tip_hash != [0; 32]
            || fields.cumulative_chainwork != [0; 32]
            || fields.log_slots != 0
            || fields.active_slot_count != 0
            || fields.alloc_counter != 0
            || fields.eff_log != 0
            || fields.segment_count != 0
        {
            return Err(invalid_data(
                "empty state manifest carries non-zero metadata",
            ));
        }
        fields.maximum_segments = 0;
        return Ok(());
    }

    if !(1..=32).contains(&fields.log_slots) {
        return Err(invalid_data("manifest log_slots is outside 1..=32"));
    }
    let total_slots = 1u64
        .checked_shl(fields.log_slots)
        .ok_or_else(|| invalid_data("manifest slot domain overflows"))?;
    if fields.active_slot_count > total_slots {
        return Err(invalid_data(
            "manifest active slot count exceeds snapshot domain",
        ));
    }
    if fields.active_slot_count > fields.alloc_counter {
        return Err(invalid_data(
            "manifest active slot count exceeds allocation counter",
        ));
    }
    let expected_eff_log = fields.log_slots.min(LOG_SEGMENT_SIZE as u32) as u8;
    if fields.eff_log != expected_eff_log {
        return Err(invalid_data(
            "manifest effective segment log is noncanonical",
        ));
    }
    let Some(maximum_encoded_segment_len) = max_encoded_segment_len_for_eff_log(fields.eff_log)
    else {
        return Err(invalid_data("manifest effective segment log is invalid"));
    };
    if maximum_encoded_segment_len > MAX_SEGMENT_BYTES {
        return Err(invalid_data("manifest segment geometry exceeds wire cap"));
    }
    let segment_bits = fields.log_slots - u32::from(fields.eff_log);
    let maximum_segments = 1u32
        .checked_shl(segment_bits)
        .ok_or_else(|| invalid_data("manifest segment namespace overflows"))?;
    fields.maximum_segments = maximum_segments;
    let segment_count = fields.segment_count as usize;
    if segment_count > MAX_SNAPSHOT_MANIFEST_SEGMENTS {
        return Err(invalid_data("declared manifest segment count exceeds cap"));
    }
    if fields.segment_count > maximum_segments {
        return Err(invalid_data(
            "declared manifest segment count exceeds snapshot domain",
        ));
    }
    if u64::from(fields.segment_count) > fields.active_slot_count {
        return Err(invalid_data(
            "declared non-empty segment count exceeds active slot count",
        ));
    }
    segment_count
        .checked_mul(SEGMENT_DESCRIPTOR_BYTES)
        .ok_or_else(|| invalid_data("manifest payload length overflows"))?;
    Ok(())
}

fn validate_descriptor_length(eff_log: u8, encoded_len: u32) -> io::Result<u32> {
    let encoded_len = encoded_len as usize;
    if encoded_len > MAX_SEGMENT_BYTES {
        return Err(invalid_data("manifest segment length exceeds wire cap"));
    }
    let live_count = encoded_segment_live_count_from_len(eff_log, encoded_len)
        .ok_or_else(|| invalid_data("manifest segment length is not canonical sparse framing"))?;
    if live_count == 0 {
        return Err(invalid_data(
            "manifest advertises an empty segment descriptor",
        ));
    }
    Ok(live_count)
}

fn encode_response_header(fields: &ResponseFields) -> [u8; RESPONSE_HEADER_BYTES] {
    let mut header = [0u8; RESPONSE_HEADER_BYTES];
    header[..4].copy_from_slice(&RESPONSE_MAGIC);
    header[4..12].copy_from_slice(&fields.tip_height.to_le_bytes());
    header[12..44].copy_from_slice(&fields.tip_hash);
    header[44..76].copy_from_slice(&fields.cumulative_chainwork);
    header[76..80].copy_from_slice(&fields.log_slots.to_le_bytes());
    header[80..88].copy_from_slice(&fields.active_slot_count.to_le_bytes());
    header[88..96].copy_from_slice(&fields.alloc_counter.to_le_bytes());
    header[96] = fields.eff_log;
    header[97..101].copy_from_slice(&fields.segment_count.to_le_bytes());
    header
}

async fn ensure_eof<T: AsyncRead + Unpin + Send>(io: &mut T) -> io::Result<()> {
    let mut trailing = [0u8; 1];
    if io.read(&mut trailing).await? != 0 {
        return Err(invalid_data("trailing bytes in state-manifest message"));
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
        StreamProtocol::new("/noid/test/sync/manifest/3")
    }

    fn populated_response() -> GetStateManifestResponse {
        GetStateManifestResponse {
            tip_height: 77,
            tip_hash: [0x11; 32],
            cumulative_chainwork: [0x22; 32],
            log_slots: 17,
            active_slot_count: 9,
            alloc_counter: 12,
            eff_log: 16,
            segment_ids: vec![0, 1],
            segment_roots: vec![[0x33; 32], [0x44; 32]],
            segment_lengths: vec![209, 259],
        }
    }

    fn response_header(mut fields: ResponseFields) -> Vec<u8> {
        fields.maximum_segments = 0;
        encode_response_header(&fields).to_vec()
    }

    fn valid_fields() -> ResponseFields {
        ResponseFields {
            tip_height: 77,
            tip_hash: [0x11; 32],
            cumulative_chainwork: [0x22; 32],
            log_slots: 17,
            active_slot_count: 9,
            alloc_counter: 12,
            eff_log: 16,
            segment_count: 2,
            maximum_segments: 0,
        }
    }

    #[tokio::test]
    async fn request_round_trip_is_fixed_and_exact() {
        let mut wire = Cursor::new(Vec::new());
        StateManifestCodec
            .write_request(
                &protocol(),
                &mut wire,
                GetStateManifestRequest {
                    requester_height: 123,
                },
            )
            .await
            .unwrap();
        assert_eq!(wire.get_ref().len(), REQUEST_BYTES);
        wire.set_position(0);
        let decoded = StateManifestCodec
            .read_request(&protocol(), &mut wire)
            .await
            .unwrap();
        assert_eq!(decoded.requester_height, 123);

        let mut trailing = wire.into_inner();
        trailing.push(0);
        assert_eq!(
            StateManifestCodec
                .read_request(&protocol(), &mut Cursor::new(trailing))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn populated_manifest_round_trip_preserves_exact_boundary_and_order() {
        let mut wire = Cursor::new(Vec::new());
        StateManifestCodec
            .write_response(&protocol(), &mut wire, populated_response())
            .await
            .unwrap();
        assert_eq!(
            wire.get_ref().len(),
            RESPONSE_HEADER_BYTES + 2 * SEGMENT_DESCRIPTOR_BYTES
        );
        wire.set_position(0);
        let decoded = StateManifestCodec
            .read_response(&protocol(), &mut wire)
            .await
            .unwrap();
        assert_eq!(decoded.tip_height, 77);
        assert_eq!(decoded.tip_hash, [0x11; 32]);
        assert_eq!(decoded.cumulative_chainwork, [0x22; 32]);
        assert_eq!(decoded.segment_ids, vec![0, 1]);
        assert_eq!(decoded.segment_roots, vec![[0x33; 32], [0x44; 32]]);
        assert_eq!(decoded.segment_lengths, vec![209, 259]);
    }

    #[tokio::test]
    async fn malicious_counts_reject_from_fixed_header_before_payload_allocation() {
        let mut segment_bomb = valid_fields();
        segment_bomb.segment_count = u32::MAX;
        let error = StateManifestCodec
            .read_response(&protocol(), &mut Cursor::new(response_header(segment_bomb)))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("segment count"));
    }

    #[tokio::test]
    async fn impossible_geometry_rejects_before_descriptor_read() {
        let mut fields = valid_fields();
        fields.log_slots = 16;
        fields.eff_log = 16;
        fields.segment_count = 2;
        let error = StateManifestCodec
            .read_response(&protocol(), &mut Cursor::new(response_header(fields)))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("snapshot domain"));

        let mut impossible_active_count = valid_fields();
        impossible_active_count.active_slot_count = (1u64 << 17) + 1;
        let error = StateManifestCodec
            .read_response(
                &protocol(),
                &mut Cursor::new(response_header(impossible_active_count)),
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("active slot count"));

        let mut impossible_nonempty_segments = valid_fields();
        impossible_nonempty_segments.active_slot_count = 1;
        let error = StateManifestCodec
            .read_response(
                &protocol(),
                &mut Cursor::new(response_header(impossible_nonempty_segments)),
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("non-empty segment count"));
    }

    #[tokio::test]
    async fn descriptor_ids_must_be_sorted_and_in_domain() {
        let fields = valid_fields();
        let mut wire = response_header(fields);
        for (id, root, encoded_len) in [(1u16, [1u8; 32], 209u32), (0, [2u8; 32], 259u32)] {
            wire.extend_from_slice(&id.to_le_bytes());
            wire.extend_from_slice(&root);
            wire.extend_from_slice(&encoded_len.to_le_bytes());
        }
        let error = StateManifestCodec
            .read_response(&protocol(), &mut Cursor::new(wire))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("strictly increasing"));
    }

    #[tokio::test]
    async fn empty_manifest_is_one_canonical_frame() {
        let response = GetStateManifestResponse::default();
        let mut wire = Cursor::new(Vec::new());
        StateManifestCodec
            .write_response(&protocol(), &mut wire, response)
            .await
            .unwrap();
        assert_eq!(wire.get_ref().len(), RESPONSE_HEADER_BYTES);

        let mut noncanonical = valid_fields();
        noncanonical.tip_height = 0;
        noncanonical.segment_count = 0;
        let error = StateManifestCodec
            .read_response(&protocol(), &mut Cursor::new(response_header(noncanonical)))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("empty state manifest"));
    }

    #[tokio::test]
    async fn writer_validates_all_vectors_before_partial_output() {
        let mut response = populated_response();
        response.segment_ids.swap(0, 1);
        let mut wire = Cursor::new(Vec::new());
        let error = StateManifestCodec
            .write_response(&protocol(), &mut wire, response)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(wire.get_ref().is_empty());

        let mut response = populated_response();
        response.segment_lengths[0] += 1;
        let mut wire = Cursor::new(Vec::new());
        let error = StateManifestCodec
            .write_response(&protocol(), &mut wire, response)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(wire.get_ref().is_empty());

        let mut response = populated_response();
        response.segment_lengths.pop();
        let mut wire = Cursor::new(Vec::new());
        let error = StateManifestCodec
            .write_response(&protocol(), &mut wire, response)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(wire.get_ref().is_empty());
    }
}
