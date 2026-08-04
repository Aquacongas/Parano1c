// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Artifact format-v2 sizing analysis: measures whether shift-invariant
//! re-serialization (per-row entry counts, zigzag column deltas, varint
//! value indices, planar streams) lets zstd reach the gadget repetition
//! that absolute `u32` column indices currently break.
//!
//! Usage: `noid_matrix_stats <artifact.field-r1cs.zst>...`

use std::time::Instant;

use noid_ivc_prover::field_r1cs::{FieldR1cs, SparseFieldMatrix};
use noid_ivc_prover::proof::FieldShape;

fn varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}

fn zigzag(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

struct PlanarStreams {
    counts: Vec<u8>,
    firsts: Vec<u8>,
    deltas: Vec<u8>,
    values: Vec<u8>,
}

fn encode_planar(matrix: &SparseFieldMatrix) -> PlanarStreams {
    let mut streams = PlanarStreams {
        counts: Vec::new(),
        firsts: Vec::new(),
        deltas: Vec::new(),
        values: Vec::new(),
    };
    let mut previous_first: i64 = 0;
    for row in 0..matrix.num_rows {
        let start = matrix.row_offsets[row];
        let end = matrix.row_offsets[row + 1];
        varint(&mut streams.counts, (end - start) as u64);
        if start == end {
            continue;
        }
        let first = matrix.col_indices[start] as i64;
        varint(&mut streams.firsts, zigzag(first - previous_first));
        previous_first = first;
        let mut previous = first;
        for entry in start + 1..end {
            let col = matrix.col_indices[entry] as i64;
            varint(&mut streams.deltas, zigzag(col - previous));
            previous = col;
        }
        for entry in start..end {
            varint(&mut streams.values, matrix.value_indices[entry] as u64);
        }
    }
    streams
}

fn compress(bytes: &[u8], level: i32) -> usize {
    let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), level).expect("encoder");
    encoder
        .multithread(rayon::current_num_threads() as u32)
        .expect("multithread");
    std::io::Write::write_all(&mut encoder, bytes).expect("compress write");
    encoder.finish().expect("compress finish").len()
}

fn header_u32(raw: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(raw[at..at + 4].try_into().expect("header u32"))
}

fn header_u64(raw: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(raw[at..at + 8].try_into().expect("header u64"))
}

fn mib(bytes: usize) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

fn main() {
    for path in std::env::args().skip(1) {
        let shipped = std::fs::read(&path).expect("read artifact");
        let t = Instant::now();
        let raw = zstd::stream::decode_all(&shipped[..]).expect("zstd decode");
        let decode_s = t.elapsed().as_secs_f64();

        assert_eq!(&raw[..8], b"NOIDR1CS", "artifact magic");
        let m = header_u32(&raw, 20) as usize;
        let k_log = header_u32(&raw, 24) as usize;
        let k_skip = header_u32(&raw, 28) as usize;
        let const_pin_plus_one = header_u64(&raw, 40) as usize;
        assert!(m <= 64 && k_log <= 32, "implausible header (endianness?)");
        let shape = FieldShape {
            m,
            k_log,
            k_skip,
            const_pin: const_pin_plus_one.checked_sub(1),
        };

        let t = Instant::now();
        let r1cs = FieldR1cs::read_artifact_unbound(&mut &raw[..], shape, usize::MAX)
            .expect("parse artifact");
        let parse_s = t.elapsed().as_secs_f64();

        let name = std::path::Path::new(&path)
            .file_name()
            .expect("file name")
            .to_string_lossy()
            .into_owned();
        println!("{name}");
        println!(
            "  shape m{m} k{k_log}  raw {:.1} MiB  shipped zst {:.1} MiB  (decode {decode_s:.2} s, parse {parse_s:.2} s)",
            mib(raw.len()),
            mib(shipped.len())
        );

        let mut planar_raw = 0usize;
        let mut planar_zst = 0usize;
        for (label, matrix) in [("a0", &r1cs.a_0), ("b0", &r1cs.b_0)] {
            let sorted = (0..matrix.num_rows).all(|row| {
                matrix.col_indices[matrix.row_offsets[row]..matrix.row_offsets[row + 1]]
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
            });
            let streams = encode_planar(matrix);
            let sizes = [
                compress(&streams.counts, 19),
                compress(&streams.firsts, 19),
                compress(&streams.deltas, 19),
                compress(&streams.values, 19),
            ];
            let stream_raw = streams.counts.len()
                + streams.firsts.len()
                + streams.deltas.len()
                + streams.values.len();
            planar_raw += stream_raw;
            planar_zst += sizes.iter().sum::<usize>();
            println!(
                "  {label}: nnz {}  dict {}  sorted {sorted}  planar raw {:.1} MiB  planar zst19 {:.1} MiB (counts {:.1} + firsts {:.1} + deltas {:.1} + values {:.1})",
                matrix.col_indices.len(),
                matrix.value_table.len(),
                mib(stream_raw),
                mib(sizes.iter().sum()),
                mib(sizes[0]),
                mib(sizes[1]),
                mib(sizes[2]),
                mib(sizes[3]),
            );
        }
        drop(r1cs);

        let t = Instant::now();
        let baseline19 = compress(&raw, 19);
        let baseline_s = t.elapsed().as_secs_f64();
        println!(
            "  v1@zst19 {:.1} MiB ({baseline_s:.1} s)   v2 planar total: raw {:.1} MiB -> zst19 {:.1} MiB",
            mib(baseline19),
            mib(planar_raw),
            mib(planar_zst)
        );
        println!();
    }
}
