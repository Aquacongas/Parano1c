// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! End-to-end release report for the Paranoid workspace.
//!
//! Exercises the full pipeline that is actually implemented:
//!
//! 1. Poseidon2b native permutation + sponge (ZK-friendly hash).
//! 2. FRI PCS commit / prove / verify over GF(2^128) with the additive NTT.
//! 3. Binius small-field packing (bits 128x, bytes 16x) and the packed
//!    commitment on top of the FRI PCS.
//! 4. AIR trace construction + native constraint check.
//! 5. Zero-check STARK prove_air / verify_air on the transaction-validity AIR.
//! 6. Chain-level state transition, block apply, header hash,
//!    packed-witness DA root.
//! 7. Wire codecs (tx body, block header) — the transport path.
//!
//! Each group reports timings plus the quantities a prover / verifier /
//! block producer actually cares about: proof bytes, commitment bytes,
//! DA bytes saved by packing, tx-body / header wire sizes, FRI query
//! count, zero-check round count, per-round polynomial length.

use std::time::{Duration, Instant};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use noid_air::{Air, ColumnDomain, TxValidityAir};
use noid_binius::{pack_bits, pack_bytes, BitWitness, ByteWitness};
use noid_chain::{
    apply_block, apply_tx, compute_tx_root, hash_block_header, pack_trace, packed_witness_root,
    payload_bytes, proof_transcript_hash, unpack_trace, Block, BlockHeader, ChainState,
    BLOCK_HEADER_WIRE_SIZE, BLOCK_VERSION,
};
use noid_core::{AdditiveNTT, Block128, TowerField};
use noid_fri::channel::{NUM_QUERIES, TAU};
use noid_fri::prover::{commit as fri_commit, prove as fri_prove};
use noid_fri::verifier::verify as fri_verify;
use noid_fri::Channel;
use noid_poseidon2b::native::compression::Poseidon2bSponge;
use noid_poseidon2b::native::permutation::Poseidon2bPermutation;
use noid_poseidon2b::primitives::{Address, AuthTag, SpendSecret};
use noid_stark::{prove_air, verify_air, StarkProof};
use noid_tx::{
    hash_tx_body, PublicInputs, Transaction, TxBody, TxInput, TxOutput, PUBLIC_INPUTS_WIRE_SIZE,
};

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

fn mk_input(seed: u8) -> TxInput {
    TxInput {
        slot_index: seed as u32,
        value: seed as u64,
        owner: Address([seed; 32]),
        spend_secret: SpendSecret([seed ^ 0xAA; 32]),
        auth_tag: AuthTag([seed ^ 0x55; 32]),
        valid: true,
    }
}

fn mk_output(seed: u8) -> TxOutput {
    TxOutput {
        value: seed as u64,
        owner: Address([seed; 32]),
        valid: true,
    }
}

fn mk_tx_body(state_root: [u8; 32], new_root: [u8; 32]) -> TxBody {
    TxBody {
        prev_state_root: state_root,
        new_state_root: new_root,
        fee: 7,
        inputs: vec![mk_input(1), mk_input(2), TxInput::dummy(), TxInput::dummy()],
        outputs: vec![
            mk_output(3),
            mk_output(4),
            mk_output(5),
            TxOutput::dummy(),
            TxOutput::dummy(),
            TxOutput::dummy(),
            TxOutput::dummy(),
            TxOutput::dummy(),
        ],
    }
}

fn mk_public_inputs(body: &TxBody) -> PublicInputs {
    let tx_body_hash = hash_tx_body(
        &body.prev_state_root,
        body.fee,
        &body.inputs,
        &body.outputs,
    );
    PublicInputs {
        prev_state_root: body.prev_state_root,
        new_state_root: body.new_state_root,
        tx_body_hash,
        fee: body.fee,
    }
}

/// Encoded size of a `StarkProof`, counting every byte the verifier
/// actually needs to consume. Commitments contribute their Merkle root +
/// metadata (depth, packing factor); FRI opening proofs contribute the
/// full authentication path bytes; round polys contribute 16 bytes per
/// `Block128` sample.
fn stark_proof_size(proof: &StarkProof) -> usize {
    let mut n = 0;
    for _c in &proof.column_commitments {
        n += 32 + 8 + 8; // root + depth + packing_factor
    }
    n += proof.base_openings.len() * 16;
    n += proof.multipoint_batch.column_openings.len() * 16;
    n += std::mem::size_of_val(&proof.multipoint_batch.batch_proof);
    n += 32 + 8 + 8; // multipoint batch commitment metadata
    for rp in &proof.zero_check_rounds {
        n += rp.len() * 16;
    }
    for rp in &proof.multipoint_rounds {
        n += rp.len() * 16;
    }
    for slot in &proof.ladder_batch_rounds {
        for rp in slot {
            n += rp.len() * 16;
        }
    }
    for partials in &proof.shift_partials {
        n += partials.len() * 16;
    }
    n += proof.ladder_batch_openings.len() * 16;
    n
}

// ---------------------------------------------------------------------------
// 1. Poseidon2b
// ---------------------------------------------------------------------------

fn bench_poseidon(c: &mut Criterion) {
    let mut g = c.benchmark_group("01_poseidon2b");

    // Native permutation — the primitive every other hash lives on top of.
    g.bench_function("permutation_4x128b", |b| {
        let mut state = [Block128::from(1u128), Block128::from(2u128), Block128::from(3u128), Block128::from(4u128)];
        b.iter(|| {
            Poseidon2bPermutation.permute_mut(&mut state);
            state
        });
    });

    // Sponge absorb + squeeze at 1 KiB — the Fiat-Shamir workhorse.
    g.throughput(Throughput::Bytes(1024));
    g.bench_function("sponge_absorb_1KiB_then_squeeze", |b| {
        let data = vec![0xA5u8; 1024];
        b.iter(|| {
            let mut s = Poseidon2bSponge::new();
            s.update(&data);
            s.finalize()
        });
    });

    // TxBodyHash under TAG_TXBODY with 4 inputs + 8 outputs (max shape).
    g.bench_function("hash_tx_body_full_4in_8out", |b| {
        let inputs = vec![mk_input(1), mk_input(2), mk_input(3), mk_input(4)];
        let outputs = vec![
            mk_output(10), mk_output(11), mk_output(12), mk_output(13),
            mk_output(14), mk_output(15), mk_output(16), mk_output(17),
        ];
        let prev = [0xABu8; 32];
        b.iter(|| hash_tx_body(&prev, 42, &inputs, &outputs));
    });

    g.finish();
}

// ---------------------------------------------------------------------------
// 2. FRI PCS
// ---------------------------------------------------------------------------

fn bench_fri(c: &mut Criterion) {
    let mut g = c.benchmark_group("02_fri_pcs");
    let hasher = Poseidon2bSponge::new();

    // Report fixed protocol parameters so operators can see them in the
    // report header (criterion prints the group name + params).
    println!(
        "# FRI parameters: NUM_QUERIES={} TAU={} (target 128-bit proven soundness at rate 1/4)",
        NUM_QUERIES, TAU
    );

    for &log_len in &[10usize, 14, 18] {
        let ntt = AdditiveNTT::<Block128>::new(log_len + noid_fri::code::LOG_RATE);
        let n = 1usize << log_len;
        let col: Vec<Block128> = (0..n)
            .map(|i| Block128::from((i as u128).wrapping_mul(0x9e3779b97f4a7c15)))
            .collect();
        let point: Vec<Block128> = (0..log_len)
            .map(|i| Block128::from((i as u128) * 17 + 3))
            .collect();

        g.throughput(Throughput::Elements(n as u64));
        g.bench_with_input(
            BenchmarkId::new("commit", log_len),
            &log_len,
            |b, _| {
                b.iter(|| fri_commit(&col, &ntt, &hasher));
            },
        );

        // One-shot prove/verify — measured separately so operators can
        // size prover hardware vs. verifier hardware independently.
        let (commitment, _tree, _code) = fri_commit(&col, &ntt, &hasher);

        g.bench_with_input(BenchmarkId::new("prove", log_len), &log_len, |b, _| {
            b.iter(|| {
                let mut ch = Channel::new();
                ch.observe_fri_commitment(&commitment);
                fri_prove(&col, &point, &ntt, &mut ch, &hasher)
            });
        });

        let mut ch = Channel::new();
        ch.observe_fri_commitment(&commitment);
        let proof = fri_prove(&col, &point, &ntt, &mut ch, &hasher);
        // Evaluate the opening locally so verify has a claim to check.
        let opening = mle_eval(&col, &point);

        g.bench_with_input(BenchmarkId::new("verify", log_len), &log_len, |b, _| {
            b.iter(|| {
                let mut ch = Channel::new();
                ch.observe_fri_commitment(&commitment);
                fri_verify(
                    &point,
                    opening,
                    proof.clone(),
                    &ntt,
                    &mut ch,
                    &hasher,
                )
                .expect("fri verify")
            });
        });
    }

    g.finish();
}

fn mle_eval(evals: &[Block128], point: &[Block128]) -> Block128 {
    let mut buf = evals.to_vec();
    for &r in point.iter().rev() {
        let half = buf.len() / 2;
        for i in 0..half {
            buf[i] = buf[i] + r * (buf[i + half] + buf[i]);
        }
        buf.truncate(half);
    }
    buf[0]
}

// ---------------------------------------------------------------------------
// 3. Binius packing (DA-layer compression)
// ---------------------------------------------------------------------------

fn bench_packing(c: &mut Criterion) {
    let mut g = c.benchmark_group("03_binius_packing");

    // Fixed DA shapes: 2^14 rows. A chain of realistic width ships many
    // such columns; each is independent, so benchmarking one is enough
    // to size the packer.
    let n = 1 << 14;

    // Bit column: 128x compression.
    g.throughput(Throughput::Bytes(n as u64));
    g.bench_function("pack_bits_16384", |b| {
        let bits: Vec<u8> = (0..n).map(|i| (i & 1) as u8).collect();
        b.iter(|| pack_bits(&bits));
    });

    // Byte column: 16x compression.
    g.throughput(Throughput::Bytes(n as u64));
    g.bench_function("pack_bytes_16384", |b| {
        let bytes: Vec<u8> = (0..n).map(|i| (i & 0xff) as u8).collect();
        b.iter(|| pack_bytes(&bytes));
    });

    // DA savings summary. Operators care about this ratio — it is what
    // makes the chain Binius-native.
    let n_rows = 1 << 14;
    let raw = payload_bytes(ColumnDomain::Block128, n_rows);
    let byte_p = payload_bytes(ColumnDomain::Byte, n_rows);
    let bit_p = payload_bytes(ColumnDomain::Bit, n_rows);
    println!(
        "# DA payload for {} rows: Block128={}B  Byte={}B ({}x saving)  Bit={}B ({}x saving)",
        n_rows,
        raw,
        byte_p,
        raw / byte_p,
        bit_p,
        raw / bit_p
    );

    // BitWitness / ByteWitness roundtrip — they are what the chain
    // serialises and what `packed_witness_root` hashes.
    g.bench_function("bitwitness_roundtrip_16384", |b| {
        let bits: Vec<u8> = (0..n).map(|i| (i & 1) as u8).collect();
        b.iter(|| {
            let w = BitWitness::from_bits(&bits);
            let packed = w.as_packed().to_vec();
            BitWitness::from_packed(packed).as_expanded()
        });
    });

    g.bench_function("bytewitness_roundtrip_16384", |b| {
        let bytes: Vec<u8> = (0..n).map(|i| (i & 0xff) as u8).collect();
        b.iter(|| {
            let w = ByteWitness::from_bytes(&bytes);
            let packed = w.as_packed().to_vec();
            ByteWitness::from_packed(packed).as_expanded()
        });
    });

    g.finish();
}

// ---------------------------------------------------------------------------
// 4. AIR trace + native check
// ---------------------------------------------------------------------------

fn bench_air(c: &mut Criterion) {
    let mut g = c.benchmark_group("04_air_trace");

    g.bench_function("tx_validity_build_trace", |b| {
        let body = mk_tx_body([0u8; 32], [0u8; 32]);
        b.iter(|| TxValidityAir::build_trace(&body));
    });

    g.bench_function("tx_validity_native_check", |b| {
        let air = TxValidityAir::new();
        let trace = TxValidityAir::build_trace(&mk_tx_body([0u8; 32], [0u8; 32]));
        b.iter(|| assert!(air.check(&trace)));
    });

    g.finish();
}

// ---------------------------------------------------------------------------
// 5. STARK: full prove + verify on TxValidityAir
// ---------------------------------------------------------------------------

fn bench_stark(c: &mut Criterion) {
    let mut g = c.benchmark_group("05_stark_tx_validity");
    g.measurement_time(Duration::from_secs(10));

    let air = TxValidityAir::new();
    let body = mk_tx_body([0u8; 32], [0u8; 32]);
    let trace = TxValidityAir::build_trace(&body);
    let pi = mk_public_inputs(&body);

    // One-shot prove — reports the time to produce the full zero-check
    // + FRI opening for every column.
    g.bench_function("prove_air", |b| {
        b.iter(|| prove_air(&air, &trace, &pi).expect("prove"));
    });

    // One-shot verify — what a full node executes per tx.
    let proof = prove_air(&air, &trace, &pi).expect("prove");
    g.bench_function("verify_air", |b| {
        b.iter(|| verify_air(&air, &pi, &proof).expect("verify"));
    });

    // Print the proof shape so report readers can size storage.
    let proof_bytes = stark_proof_size(&proof);
    println!(
        "# StarkProof shape: log_rows={} cols={} zero_check_rounds={} round_poly_len={} approx_bytes={}",
        proof.log_rows,
        proof.column_commitments.len(),
        proof.zero_check_rounds.len(),
        proof.zero_check_rounds.first().map(|r| r.len()).unwrap_or(0),
        proof_bytes
    );

    g.finish();
}

// ---------------------------------------------------------------------------
// 6. Chain: state transition + block apply + header hash + DA root
// ---------------------------------------------------------------------------

fn bench_chain(c: &mut Criterion) {
    let mut g = c.benchmark_group("06_chain");

    // apply_tx: mint-only body exercises the state-tree append path.
    g.bench_function("apply_tx_mint_8out", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let mut state = ChainState::with_log_slots(10);
                let prev = state.state_root();
                let mut body = mint_only_body(prev);
                let mut shadow = state.clone();
                let st = apply_tx(&mut shadow, &body).expect("shadow apply");
                body.new_state_root = st.new_state_root;
                let t = Instant::now();
                let _ = apply_tx(&mut state, &body).expect("apply_tx");
                total += t.elapsed();
            }
            total
        });
    });

    // Block apply: 8 mint-only txs chained end-to-end.
    g.bench_function("apply_block_8_txs", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let mut reference = ChainState::with_log_slots(10);
                let mut txs: Vec<Transaction> = Vec::with_capacity(8);
                let mut cur_root = reference.state_root();
                for k in 0..8u8 {
                    let mut body = mk_tx_body_unique(cur_root, k);
                    let mut shadow = reference.clone();
                    let st = apply_tx(&mut shadow, &body).expect("shadow apply");
                    body.new_state_root = st.new_state_root;
                    let _ = apply_tx(&mut reference, &body).expect("ref apply");
                    let body_hash = hash_tx_body(
                        &body.prev_state_root,
                        body.fee,
                        &body.inputs,
                        &body.outputs,
                    );
                    txs.push(Transaction {
                        body,
                        tx_body_hash: body_hash,
                    });
                    cur_root = st.new_state_root;
                }

                let tx_root = compute_tx_root(&txs);
                let header = BlockHeader {
                    prev_block_hash: [0u8; 32],
                    state_root: reference.state_root(),
                    tx_root,
                    timestamp: 1_700_000_000,
                    miner_address: Address([0u8; 32]),
                    nonce: 0,
                    proof_transcript_hash: [1u8; 32],
                    witness_root: [2u8; 32],
                };
                let block = Block {
                    header,
                    transactions: txs,
                };

                let mut fresh = ChainState::with_log_slots(10);
                let t = Instant::now();
                let _ = apply_block(&mut fresh, &block).expect("apply_block");
                total += t.elapsed();
            }
            total
        });
    });

    // Header hash — the PoW inner loop.
    g.bench_function("hash_block_header", |b| {
        let h = BlockHeader {
            prev_block_hash: [0x11u8; 32],
            state_root: [0x22u8; 32],
            tx_root: [0x33u8; 32],
            timestamp: 1_700_000_000,
            miner_address: Address([0x44u8; 32]),
            nonce: 0xDEAD_BEEFu64,
            proof_transcript_hash: [0x55u8; 32],
            witness_root: [0x66u8; 32],
        };
        b.iter(|| hash_block_header(&h));
    });

    // proof_transcript_hash — the binding from a STARK transcript to
    // the block header.
    g.bench_function("proof_transcript_hash_4KiB", |b| {
        let data = vec![0u8; 4096];
        b.iter(|| proof_transcript_hash(&data));
    });

    // DA: pack trace + hash root (blake3, byte-native).
    g.bench_function("da_pack_and_root_validity_trace", |b| {
        let trace = TxValidityAir::build_trace(&mk_tx_body([0u8; 32], [0u8; 32]));
        b.iter(|| {
            let pw = pack_trace(&trace);
            packed_witness_root(&pw)
        });
    });

    // DA roundtrip to prove full-node invariance.
    g.bench_function("da_roundtrip_validity_trace", |b| {
        let trace = TxValidityAir::build_trace(&mk_tx_body([0u8; 32], [0u8; 32]));
        b.iter(|| {
            let pw = pack_trace(&trace);
            let back = unpack_trace(&pw).expect("unpack");
            back.n_rows()
        });
    });

    g.finish();
}

fn mk_tx_body_unique(prev_state_root: [u8; 32], seed: u8) -> TxBody {
    TxBody {
        prev_state_root,
        new_state_root: [0u8; 32],
        fee: seed as u128,
        inputs: vec![
            TxInput::dummy(),
            TxInput::dummy(),
            TxInput::dummy(),
            TxInput::dummy(),
        ],
        outputs: vec![
            mk_output(0x30 | seed),
            mk_output(0x40 | seed),
            TxOutput::dummy(),
            TxOutput::dummy(),
            TxOutput::dummy(),
            TxOutput::dummy(),
            TxOutput::dummy(),
            TxOutput::dummy(),
        ],
    }
}

fn mint_only_body(prev: [u8; 32]) -> TxBody {
    TxBody {
        prev_state_root: prev,
        new_state_root: [0u8; 32],
        fee: 0,
        inputs: vec![
            TxInput::dummy(),
            TxInput::dummy(),
            TxInput::dummy(),
            TxInput::dummy(),
        ],
        outputs: vec![
            mk_output(1),
            mk_output(2),
            mk_output(3),
            mk_output(4),
            mk_output(5),
            mk_output(6),
            mk_output(7),
            mk_output(8),
        ],
    }
}

// ---------------------------------------------------------------------------
// 7. Wire codecs
// ---------------------------------------------------------------------------

fn bench_wire(c: &mut Criterion) {
    let mut g = c.benchmark_group("07_wire");

    let body = mk_tx_body([1u8; 32], [2u8; 32]);
    let bytes = body.to_bytes();
    println!(
        "# wire sizes: TxBody(4in 8out)={}B  BlockHeader={}B  PublicInputs={}B  BLOCK_VERSION={}",
        bytes.len(),
        BLOCK_HEADER_WIRE_SIZE,
        PUBLIC_INPUTS_WIRE_SIZE,
        BLOCK_VERSION
    );

    g.throughput(Throughput::Bytes(bytes.len() as u64));
    g.bench_function("tx_body_encode", |b| {
        b.iter(|| body.to_bytes());
    });
    g.bench_function("tx_body_decode", |b| {
        b.iter(|| TxBody::from_bytes(&bytes).expect("decode"));
    });

    let header = BlockHeader {
        prev_block_hash: [0u8; 32],
        state_root: [1u8; 32],
        tx_root: [2u8; 32],
        timestamp: 1_700_000_000,
        miner_address: Address([3u8; 32]),
        nonce: 0,
        proof_transcript_hash: [4u8; 32],
        witness_root: [5u8; 32],
    };
    let hbytes = header.to_bytes();
    g.throughput(Throughput::Bytes(hbytes.len() as u64));
    g.bench_function("block_header_encode", |b| {
        b.iter(|| header.to_bytes());
    });
    g.bench_function("block_header_decode", |b| {
        b.iter(|| BlockHeader::from_bytes(&hbytes).expect("decode"));
    });

    g.finish();
}

// ---------------------------------------------------------------------------
// Criterion entry
// ---------------------------------------------------------------------------

criterion_group!(
    blockchain_report,
    bench_poseidon,
    bench_fri,
    bench_packing,
    bench_air,
    bench_stark,
    bench_chain,
    bench_wire,
);
criterion_main!(blockchain_report);
