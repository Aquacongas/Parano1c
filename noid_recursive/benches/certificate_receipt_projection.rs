// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Bench for the fixed accepted-block certificate receipt-projection backend.
//! This is a receipt adapter, not the production tx/auth/state block proof.

use std::env;

use noid_poseidon2b::primitives::Digest;
use noid_recursive::{
    accepted_block_receipt_projection_handle,
    prove_accepted_block_certificate_receipt_projection_proof,
    verify_accepted_block_certificate_proof_checkpoint, AcceptedBlockCertificateStatement,
    ACCEPTED_BLOCK_RECEIPT_PROJECTION_K_LOG, ACCEPTED_BLOCK_RECEIPT_PROJECTION_LOG_BATCH_SIZE,
    ACCEPTED_BLOCK_RECEIPT_PROJECTION_LOG_INV_RATE, ACCEPTED_BLOCK_RECEIPT_PROJECTION_M,
};

fn env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|&value| value > 0)
        .unwrap_or(default)
}

fn time_once<T>(f: impl FnOnce() -> T) -> (std::time::Duration, T) {
    let start = std::time::Instant::now();
    let out = f();
    (start.elapsed(), out)
}

fn median(mut values: Vec<std::time::Duration>) -> std::time::Duration {
    values.sort_unstable();
    values[values.len() / 2]
}

fn fmt_ms(duration: std::time::Duration) -> String {
    format!("{:>8.2} ms", duration.as_secs_f64() * 1000.0)
}

fn fmt_bytes(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:>8.2} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:>8.2} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes:>8} B ")
    }
}

fn digest(byte: u8) -> Digest {
    [byte; 32]
}

fn statement() -> AcceptedBlockCertificateStatement {
    AcceptedBlockCertificateStatement {
        height: 42,
        block_id: digest(1),
        parent_block_id: digest(2),
        parent_state_root: digest(3),
        child_state_root: digest(4),
        tx_root: digest(5),
        block_body_digest: digest(6),
        block_proof_digest: digest(7),
        auth_sidecar_digest: digest(8),
        accepted_block_claim_digest: digest(9),
        accepted_state_transition_claim_digest: digest(10),
        exact_transition_digest: digest(11),
        tx_count: 2,
        user_tx_count: 1,
        live_input_count: 1,
        live_output_count: 2,
        state_frontier_node_count: 8,
        touched_slot_count: 2,
        action_count: 3,
        block_body_len: 512,
        block_proof_len: 4096,
        auth_sidecar_len: 2048,
    }
}

fn main() {
    let samples = env_usize("NOID_CERTIFICATE_RECEIPT_PROJECTION_SAMPLES", 3);
    let statement = statement();

    println!("noid_recursive certificate_receipt_projection");
    println!("  backend=accepted_block_receipt_projection");
    println!("  m={ACCEPTED_BLOCK_RECEIPT_PROJECTION_M}");
    println!("  k_log={ACCEPTED_BLOCK_RECEIPT_PROJECTION_K_LOG}");
    println!("  pcs_log_inv_rate={ACCEPTED_BLOCK_RECEIPT_PROJECTION_LOG_INV_RATE}");
    println!("  pcs_log_batch_size={ACCEPTED_BLOCK_RECEIPT_PROJECTION_LOG_BATCH_SIZE}");
    println!("  tx_count_dependent=false");
    println!("  final_accept_block_validity=false");
    println!("  samples={samples}");

    let mut prove_times = Vec::with_capacity(samples);
    let mut verify_times = Vec::with_capacity(samples);
    let mut proof = None;
    for _ in 0..samples {
        let (prove_time, built) = time_once(|| {
            prove_accepted_block_certificate_receipt_projection_proof(&statement)
                .expect("certificate receipt-projection proof builds")
        });
        let (verify_time, ()) = time_once(|| {
            verify_accepted_block_certificate_proof_checkpoint(&statement, &built)
                .expect("certificate receipt-projection proof verifies")
        });
        prove_times.push(prove_time);
        verify_times.push(verify_time);
        proof = Some(built);
    }
    let proof = proof.expect("at least one sample");
    let handle = accepted_block_receipt_projection_handle(&proof)
        .expect("certificate receipt-projection handle builds");

    println!("  proof={}", fmt_bytes(proof.byte_len()));
    println!("  backend_proof={}", fmt_bytes(proof.backend_proof.len()));
    println!("  handle={}", fmt_bytes(handle.byte_len()));
    println!("  prove_median={}", fmt_ms(median(prove_times)));
    println!("  verify_median={}", fmt_ms(median(verify_times)));
}
