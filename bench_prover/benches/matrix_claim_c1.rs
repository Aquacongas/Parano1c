// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Direct production C1 matrix-fold benchmark.
//!
//! This loads and authenticates the B64 matrix from a completed HistoryStep
//! pack, constructs deterministic valid claims, and times only the native
//! fold and its matrix-free verifier. It deliberately avoids building the
//! multi-block HistoryStep fixture backbone.

use std::fs::File;
use std::io::{BufReader, Read as _};
use std::path::PathBuf;
use std::time::Instant;

use noid_ivc_core::challenger::{Challenger, FsLaneChallenger};
use noid_ivc_core::field::{F128, F256};
use noid_ivc_core::field_r1cs::CompactFieldR1cs;
use noid_ivc_core::matrix_claim::c1::{
    prove_matrix_claim_fold_compact_c1, verify_matrix_claim_fold_c1, C1FreshLincheckClaim,
    C1MatrixAccClaim, C1MatrixClaimEvaluator,
};
use noid_miner::history_step_artifacts::{
    history_step_matrix_file_name, HISTORY_STEP_PACK_VERSION_DIRECTORY,
    HISTORY_STEP_RUNTIME_METADATA_FILE, HISTORY_STEP_RUNTIME_METADATA_MAX_BYTES,
};
use noid_recursive::{canonical_history_step_shape, CanonicalHistoryStepClassId};

const PACK_DIRECTORY_ENV: &str = "NOID_HISTORY_STEP_PACK_DIR";
const SAMPLE_COUNT_ENV: &str = "NOID_MATRIX_FOLD_SAMPLES";
const NODE_CPU_POOL_ENV: &str = "NOID_HISTORY_STEP_NODE_CPU_POOL";
const MAX_COMPRESSED_MATRIX_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_CANONICAL_MATRIX_BYTES: usize = 1024 * 1024 * 1024;
const ZSTD_WINDOW_LOG_MAX: u32 = 27;
const TRANSCRIPT_DOMAIN: &[u8] = b"NOID/BENCH/MATRIX-CLAIM-C1/V1";

fn read_regular_bounded(path: &std::path::Path, max_bytes: u64) -> Result<Vec<u8>, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > max_bytes {
        return Err(format!("{} is not a bounded regular file", path.display()));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .map_err(|error| format!("open {}: {error}", path.display()))?
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!("{} exceeds its byte bound", path.display()));
    }
    Ok(bytes)
}

fn load_b64_matrix() -> Result<CompactFieldR1cs, String> {
    let root = PathBuf::from(
        std::env::var_os(PACK_DIRECTORY_ENV)
            .ok_or_else(|| format!("{PACK_DIRECTORY_ENV} is required"))?,
    );
    let version = root.join(HISTORY_STEP_PACK_VERSION_DIRECTORY);
    let metadata_path = version.join(HISTORY_STEP_RUNTIME_METADATA_FILE);
    let metadata = read_regular_bounded(
        &metadata_path,
        HISTORY_STEP_RUNTIME_METADATA_MAX_BYTES as u64,
    )?;
    let trailer = metadata
        .len()
        .checked_sub(32)
        .ok_or_else(|| "runtime metadata has no digest trailer".to_owned())?;
    let digest = metadata[trailer..]
        .try_into()
        .map_err(|_| "runtime metadata digest width".to_owned())?;
    let runtime = noid_miner::decode_history_step_runtime_metadata_pinned(&metadata, digest)
        .map_err(|error| format!("authenticate {}: {error}", metadata_path.display()))?;
    let class = CanonicalHistoryStepClassId::new(0).expect("B64 class is canonical");
    let matrix_path = version.join(history_step_matrix_file_name(class));
    let compressed = read_regular_bounded(&matrix_path, MAX_COMPRESSED_MATRIX_BYTES)?;
    let mut decoder = zstd::stream::read::Decoder::new(BufReader::new(compressed.as_slice()))
        .map_err(|error| format!("open zstd {}: {error}", matrix_path.display()))?;
    decoder
        .window_log_max(ZSTD_WINDOW_LOG_MAX)
        .map_err(|error| format!("bound zstd window {}: {error}", matrix_path.display()))?;
    let mut canonical = Vec::new();
    decoder
        .take((MAX_CANONICAL_MATRIX_BYTES + 1) as u64)
        .read_to_end(&mut canonical)
        .map_err(|error| format!("decode {}: {error}", matrix_path.display()))?;
    if canonical.len() > MAX_CANONICAL_MATRIX_BYTES {
        return Err(format!(
            "{} exceeds the canonical size bound",
            matrix_path.display()
        ));
    }
    CompactFieldR1cs::open(
        canonical.into_boxed_slice(),
        canonical_history_step_shape(class),
        runtime.bank().entry(class).matrix_digest(),
    )
    .and_then(CompactFieldR1cs::into_startup_packed)
    .map_err(|error| format!("authenticate {}: {error}", matrix_path.display()))
}

fn field(seed: u64) -> F256 {
    F256::new(
        F128::new(
            seed.wrapping_mul(0x9e37_79b9_7f4a_7c15),
            seed.rotate_left(23) ^ 0xbf58_476d_1ce4_e5b9,
        ),
        F128::new(
            !seed.wrapping_mul(0x94d0_49bb_1331_11eb),
            seed.rotate_right(17) ^ 0xd6e8_feb8_6659_fd93,
        ),
    )
}

fn valid_claims(
    matrix: &mut CompactFieldR1cs,
) -> Result<(C1FreshLincheckClaim, C1MatrixAccClaim), String> {
    let shape = matrix.shape();
    let rest = shape.k_log - shape.k_skip;
    let mut fresh = C1FreshLincheckClaim {
        alpha: field(1),
        z_skip: field(2),
        x_inner_rest: (0..rest).map(|index| field(10 + index as u64)).collect(),
        r_inner_rest: (0..rest).map(|index| field(50 + index as u64)).collect(),
        z_partial: (0..1usize << shape.k_skip)
            .map(|index| field(100 + index as u64))
            .collect(),
        value: F256::ZERO,
    };
    let mut incoming = C1MatrixAccClaim {
        point: (0..2 * shape.k_log + 1)
            .map(|index| field(1000 + index as u64))
            .collect(),
        value: F256::ZERO,
    };
    let evaluated = matrix
        .evaluate_matrix_claims_c1(Some(&fresh), Some(&incoming))
        .map_err(|error| format!("evaluate benchmark claims: {error}"))?;
    fresh.value = evaluated
        .fresh_value()
        .ok_or_else(|| "fresh matrix value is absent".to_owned())?;
    incoming.value = evaluated
        .accumulated_value()
        .ok_or_else(|| "accumulated matrix value is absent".to_owned())?;
    Ok((fresh, incoming))
}

fn sample_count() -> Result<usize, String> {
    let samples = std::env::var(SAMPLE_COUNT_ENV)
        .unwrap_or_else(|_| "1".to_owned())
        .parse::<usize>()
        .map_err(|_| format!("{SAMPLE_COUNT_ENV} must be an integer"))?;
    if !(1..=100).contains(&samples) {
        return Err(format!("{SAMPLE_COUNT_ENV} must be in 1..=100"));
    }
    Ok(samples)
}

fn run() -> Result<(), String> {
    if std::env::var_os(NODE_CPU_POOL_ENV).is_some() {
        noid_miner::configure_process_cpu_budget(noid_miner::ProcessCpuBudgetMode::ProofOnly)
            .map_err(|error| format!("configure production CPU pool: {error}"))?;
    } else {
        noid_ivc_prover::init_perf_thread_pool();
    }
    let mut matrix = load_b64_matrix()?;
    let (fresh, incoming) = valid_claims(&mut matrix)?;
    let shape = matrix.shape();
    for sample in 1..=sample_count()? {
        let mut prover = FsLaneChallenger::new_c1(TRANSCRIPT_DOMAIN);
        let prove_started = Instant::now();
        let (proof, outgoing) =
            prove_matrix_claim_fold_compact_c1(&matrix, &fresh, &incoming, true, &mut prover);
        let prove_ms = prove_started.elapsed().as_millis();
        let mut verifier = FsLaneChallenger::new_c1(TRANSCRIPT_DOMAIN);
        let verify_started = Instant::now();
        let verified = verify_matrix_claim_fold_c1(
            shape.k_log,
            shape.k_skip,
            &fresh,
            &incoming,
            F256::ONE,
            &proof,
            &mut verifier,
        )
        .map_err(|error| format!("verify benchmark fold: {error}"))?;
        let verify_us = verify_started.elapsed().as_micros();
        if verified != outgoing || prover.sample_f256() != verifier.sample_f256() {
            return Err("matrix-fold prover/verifier transcript drift".to_owned());
        }
        println!(
            "B64 matrix-fold-c1 sample={sample} k_log={} prove_ms={prove_ms} verify_us={verify_us}",
            shape.k_log
        );
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        panic!("C1 matrix-fold benchmark: {error}");
    }
}
