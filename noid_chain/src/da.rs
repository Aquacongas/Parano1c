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
//! unaffected: the AIR / STARK layer still commits and opens on the expanded
//! column today. The bit-packed commit path lands in Phase 4 once the
//! ring-switching opening is in place.

use noid_air::{ColumnDomain, Trace};
use noid_binius::{BitWitness, ByteWitness};
use noid_core::{Block128, TowerField};

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
    BitDomainTooSmall,
    ByteDomainTooSmall,
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
            let bits: Vec<u8> = col
                .iter()
                .map(|v| if *v == Block128::ZERO { 0u8 } else { 1u8 })
                .collect();
            let w = BitWitness::from_bits(&bits);
            block128s_to_bytes(w.as_packed())
        }
        ColumnDomain::Byte => {
            let bytes: Vec<u8> = col.iter().map(|v| v.to_u128() as u8).collect();
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
            if n_rows < 128 {
                return Err(DaError::BitDomainTooSmall);
            }
            // payload = (n_rows / 128) Block128s = n_rows / 8 bytes
            let want = n_rows / 8;
            if pc.payload.len() != want {
                return Err(DaError::PayloadLenMismatch);
            }
            let packed = bytes_to_block128s(&pc.payload);
            let w = BitWitness::from_packed(packed);
            Ok(w.as_expanded_field())
        }
        ColumnDomain::Byte => {
            if n_rows < 16 {
                return Err(DaError::ByteDomainTooSmall);
            }
            // payload = (n_rows / 16) Block128s = n_rows bytes
            if pc.payload.len() != n_rows {
                return Err(DaError::PayloadLenMismatch);
            }
            let packed = bytes_to_block128s(&pc.payload);
            let w = ByteWitness::from_packed(packed);
            Ok(w.as_expanded_field())
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
