// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! DA / bandwidth layer: ship trace columns in their Binius-packed form.
//!
//! A block carries its witness columns tagged with a [`ColumnDomain`]. On the
//! wire, `Bit` columns are shipped at 128x density, `Byte` columns at 16x, and
//! `Block128` columns unchanged. The encoder packs; the decoder reconstructs
//! the full `Block128` column vector before handing it to AIR / STARK. The
//! logical witness — and therefore every commitment root and every hash — is
//! identical across the packed and unpacked wire forms.
//!
//! This module is transport-only. Soundness of any downstream proof is
//! unaffected: the AIR / STARK layer commits the packed column for
//! `Byte` and `Block128` directly (the packed MLE *is* the polynomial),
//! and expands `Bit` columns to Block128 before FRI-committing.

use noid_air::{ColumnDomain, Trace};
use noid_binius::{BitWitness, ByteWitness};
use noid_core::{Block128, TowerField};
use noid_poseidon2b::native::domain::TAG_DAWTNSS;
use noid_poseidon2b::primitives::Digest;

/// A single column as it travels on the wire. The payload length depends on
/// the domain:
///   * `Bit`      — `n_rows / 8` bytes (128 bits per Block128, 8 bits per byte)
///   * `Byte`     — `n_rows` bytes
///   * `Block128` — `n_rows * 16` bytes (little-endian Block128 encoding)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackedWitnessColumn {
    pub domain: ColumnDomain,
    pub log_rows: u8,
    pub payload: Vec<u8>,
}

/// All trace columns packed for DA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackedWitness {
    pub log_rows: u8,
    pub columns: Vec<PackedWitnessColumn>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaError {
    LogRowsMismatch,
    PayloadLenMismatch,
    RowCountNotPowerOfTwo,
}

/// Encode a [`Trace`] into its packed DA form.
pub fn pack_trace(trace: &Trace) -> PackedWitness {
    let log_rows = trace.log_rows as u8;
    let n_rows = trace.n_rows();
    let columns = trace
        .columns
        .iter()
        .zip(trace.domains.iter())
        .map(|(col, dom)| pack_column(col, *dom, n_rows))
        .collect();
    PackedWitness { log_rows, columns }
}

/// Decode a [`PackedWitness`] back into a [`Trace`].
pub fn unpack_trace(pw: &PackedWitness) -> Result<Trace, DaError> {
    if !(1usize << pw.log_rows).is_power_of_two() {
        return Err(DaError::RowCountNotPowerOfTwo);
    }
    let n_rows = 1usize << pw.log_rows;
    let mut columns = Vec::with_capacity(pw.columns.len());
    let mut domains = Vec::with_capacity(pw.columns.len());
    for pc in &pw.columns {
        if pc.log_rows != pw.log_rows {
            return Err(DaError::LogRowsMismatch);
        }
        let col = unpack_column(pc, n_rows)?;
        columns.push(col);
        domains.push(pc.domain);
    }
    Ok(Trace::new_with_domains(columns, domains))
}

fn pack_column(col: &[Block128], domain: ColumnDomain, n_rows: usize) -> PackedWitnessColumn {
    let log_rows = n_rows.trailing_zeros() as u8;
    let payload = match domain {
        ColumnDomain::Bit => {
            // One bit per row, expanded form -> BitWitness -> packed Block128 -> LE bytes.
            // BitWitness requires at least 128 bits, so zero-pad small columns.
            let mut bits: Vec<u8> = col
                .iter()
                .map(|v| if *v == Block128::ZERO { 0u8 } else { 1u8 })
                .collect();
            if bits.len() < 128 {
                bits.resize(128, 0u8);
            }
            let w = BitWitness::from_bits(&bits);
            block128s_to_bytes(w.as_packed())
        }
        ColumnDomain::Byte => {
            // ByteWitness requires at least 16 bytes, so zero-pad small columns.
            let mut bytes: Vec<u8> = col.iter().map(|v| v.to_u128() as u8).collect();
            if bytes.len() < 16 {
                bytes.resize(16, 0u8);
            }
            let w = ByteWitness::from_bytes(&bytes);
            block128s_to_bytes(w.as_packed())
        }
        ColumnDomain::Block128 => block128s_to_bytes(col),
    };
    PackedWitnessColumn {
        domain,
        log_rows,
        payload,
    }
}

fn unpack_column(pc: &PackedWitnessColumn, n_rows: usize) -> Result<Vec<Block128>, DaError> {
    match pc.domain {
        ColumnDomain::Bit => {
            // Packed payload is at least one Block128 (128 bits); small columns were
            // zero-padded during packing, so payload may be larger than n_rows / 8.
            let padded_bits = 128usize.max(n_rows);
            let want = padded_bits / 8;
            if pc.payload.len() != want {
                return Err(DaError::PayloadLenMismatch);
            }
            let packed = bytes_to_block128s(&pc.payload);
            let w = BitWitness::from_packed(packed);
            // Truncate the expanded vector back to the logical n_rows.
            Ok(w.as_expanded_field().into_iter().take(n_rows).collect())
        }
        ColumnDomain::Byte => {
            // Packed payload is at least one Block128 (16 bytes); small columns were
            // zero-padded during packing, so payload may be larger than n_rows.
            let padded_bytes = 16usize.max(n_rows);
            let want = padded_bytes; // ByteWitness stores one byte per entry
            if pc.payload.len() != want {
                return Err(DaError::PayloadLenMismatch);
            }
            let packed = bytes_to_block128s(&pc.payload);
            let w = ByteWitness::from_packed(packed);
            // Truncate the expanded vector back to the logical n_rows.
            Ok(w.as_expanded_field().into_iter().take(n_rows).collect())
        }
        ColumnDomain::Block128 => {
            if pc.payload.len() != n_rows * 16 {
                return Err(DaError::PayloadLenMismatch);
            }
            Ok(bytes_to_block128s(&pc.payload))
        }
    }
}

fn block128s_to_bytes(xs: &[Block128]) -> Vec<u8> {
    let mut out = Vec::with_capacity(xs.len() * 16);
    for x in xs {
        out.extend_from_slice(&x.to_u128().to_le_bytes());
    }
    out
}

fn bytes_to_block128s(bytes: &[u8]) -> Vec<Block128> {
    assert_eq!(bytes.len() % 16, 0, "bytes must be a multiple of 16");
    let mut out = Vec::with_capacity(bytes.len() / 16);
    for chunk in bytes.chunks_exact(16) {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(chunk);
        out.push(Block128::from(u128::from_le_bytes(buf)));
    }
    out
}

/// Canonical digest of a packed witness, computed over the packed form
/// itself. This is the identity any full node recomputes after
/// downloading the DA blob and binds into the block header so that the
/// 128x / 16x savings carry all the way to on-chain state.
///
/// Implementation: Blake3, byte-native, multi-GB/s. DA verification runs
/// off the critical path of any circuit, so there is no reason to burn
/// it on a ZK-friendly hash. The resulting 32-byte digest is absorbed
/// into `H_BLOCK` (CRYPTO.md §8.1) as an opaque field, so downstream
/// consensus is unchanged.
///
/// Absorption order is fully deterministic and length-prefixed at every
/// boundary:
///
/// 1. 8-byte domain tag = `DAWTNSS_` (disjoint from every other Blake3
///    use in the codebase).
/// 2. `log_rows` as a little-endian `u64`.
/// 3. Number of columns as a little-endian `u64`.
/// 4. For each column in order:
///    a. Domain tag byte (0 = Bit, 1 = Byte, 2 = Block128).
///    b. Payload length as a little-endian `u64`.
///    c. Payload bytes.
pub fn packed_witness_root(pw: &PackedWitness) -> Digest {
    let mut h = blake3::Hasher::new();
    h.update(&TAG_DAWTNSS.0);
    h.update(&(pw.log_rows as u64).to_le_bytes());
    h.update(&(pw.columns.len() as u64).to_le_bytes());
    for col in &pw.columns {
        let tag: u8 = match col.domain {
            ColumnDomain::Bit => 0,
            ColumnDomain::Byte => 1,
            ColumnDomain::Block128 => 2,
        };
        h.update(&[tag]);
        h.update(&(col.payload.len() as u64).to_le_bytes());
        h.update(&col.payload);
    }
    *h.finalize().as_bytes()
}

/// Shortcut: pack the trace and hash it. The returned digest is the
/// `witness_root` a block header should bind (CRYPTO.md §9.1).
pub fn trace_witness_root(trace: &Trace) -> Digest {
    packed_witness_root(&pack_trace(trace))
}

/// Wire-size in bytes that a packed column occupies, excluding metadata.
pub fn payload_bytes(domain: ColumnDomain, n_rows: usize) -> usize {
    match domain {
        ColumnDomain::Bit => n_rows / 8,
        ColumnDomain::Byte => n_rows,
        ColumnDomain::Block128 => n_rows * 16,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bit_col(n: usize, pattern: u64) -> Vec<Block128> {
        (0..n)
            .map(|i| {
                if (pattern >> (i % 64)) & 1 == 1 {
                    Block128::ONE
                } else {
                    Block128::ZERO
                }
            })
            .collect()
    }

    fn byte_col(n: usize) -> Vec<Block128> {
        (0..n).map(|i| Block128::from((i as u128) & 0xff)).collect()
    }

    fn block_col(n: usize) -> Vec<Block128> {
        (0..n)
            .map(|i| Block128::from((i as u128).wrapping_mul(0x9e3779b97f4a7c15)))
            .collect()
    }

    #[test]
    fn roundtrip_bit_column() {
        let n = 256;
        let trace = Trace::new_with_domains(vec![bit_col(n, 0xa5a5_5a5a_deadbeef)], vec![ColumnDomain::Bit]);
        let pw = pack_trace(&trace);
        assert_eq!(pw.columns[0].payload.len(), n / 8);
        let back = unpack_trace(&pw).unwrap();
        assert_eq!(back.columns, trace.columns);
        assert_eq!(back.domains, trace.domains);
    }

    #[test]
    fn roundtrip_byte_column() {
        let n = 128;
        let trace = Trace::new_with_domains(vec![byte_col(n)], vec![ColumnDomain::Byte]);
        let pw = pack_trace(&trace);
        assert_eq!(pw.columns[0].payload.len(), n);
        let back = unpack_trace(&pw).unwrap();
        assert_eq!(back.columns, trace.columns);
    }

    #[test]
    fn roundtrip_block_column() {
        let n = 32;
        let trace = Trace::new_with_domains(vec![block_col(n)], vec![ColumnDomain::Block128]);
        let pw = pack_trace(&trace);
        assert_eq!(pw.columns[0].payload.len(), n * 16);
        let back = unpack_trace(&pw).unwrap();
        assert_eq!(back.columns, trace.columns);
    }

    #[test]
    fn roundtrip_mixed_trace() {
        let n = 256;
        let trace = Trace::new_with_domains(
            vec![bit_col(n, 0x1234_5678), byte_col(n), block_col(n)],
            vec![ColumnDomain::Bit, ColumnDomain::Byte, ColumnDomain::Block128],
        );
        let pw = pack_trace(&trace);
        let back = unpack_trace(&pw).unwrap();
        assert_eq!(back.columns, trace.columns);
        assert_eq!(back.domains, trace.domains);
    }

    #[test]
    fn da_savings_are_real() {
        let n = 4096;
        let bit = payload_bytes(ColumnDomain::Bit, n);
        let byt = payload_bytes(ColumnDomain::Byte, n);
        let blk = payload_bytes(ColumnDomain::Block128, n);
        assert_eq!(blk / bit, 128);
        assert_eq!(blk / byt, 16);
    }

    #[test]
    fn witness_root_determinism() {
        let n = 256;
        let trace = Trace::new_with_domains(
            vec![bit_col(n, 0x1234), byte_col(n), block_col(n)],
            vec![ColumnDomain::Bit, ColumnDomain::Byte, ColumnDomain::Block128],
        );
        assert_eq!(trace_witness_root(&trace), trace_witness_root(&trace));
    }

    #[test]
    fn witness_root_changes_per_column() {
        let n = 256;
        let t1 = Trace::new_with_domains(vec![byte_col(n)], vec![ColumnDomain::Byte]);
        let t2 = Trace::new_with_domains(
            vec![byte_col(n), byte_col(n)],
            vec![ColumnDomain::Byte, ColumnDomain::Byte],
        );
        assert_ne!(trace_witness_root(&t1), trace_witness_root(&t2));
    }

    #[test]
    fn witness_root_sensitive_to_payload() {
        let n = 256;
        let mut pw = pack_trace(&Trace::new_with_domains(
            vec![byte_col(n)],
            vec![ColumnDomain::Byte],
        ));
        let baseline = packed_witness_root(&pw);
        pw.columns[0].payload[0] ^= 0xFF;
        assert_ne!(packed_witness_root(&pw), baseline);
    }

    #[test]
    fn witness_root_sensitive_to_domain_tag() {
        // Same payload bytes, different domain tag, different root.
        let n = 128;
        let bit_payload = pack_trace(&Trace::new_with_domains(
            vec![bit_col(n, 0x0f0f)],
            vec![ColumnDomain::Bit],
        ));
        let mut impostor = bit_payload.clone();
        impostor.columns[0].domain = ColumnDomain::Byte;
        assert_ne!(packed_witness_root(&bit_payload), packed_witness_root(&impostor));
    }

    #[test]
    fn payload_len_mismatch_rejected() {
        let n = 256;
        let trace = Trace::new_with_domains(vec![bit_col(n, 0)], vec![ColumnDomain::Bit]);
        let mut pw = pack_trace(&trace);
        pw.columns[0].payload.pop();
        assert!(matches!(
            unpack_trace(&pw),
            Err(DaError::PayloadLenMismatch)
        ));
    }
}
