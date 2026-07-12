// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Terminal-decider matrix roofline: streamed versus resident claim
//! evaluation of one synthetic canonical artifact.
//!
//! The streamed path is the pre-existing bounded-memory scanner (single
//! sequential authenticated pass per open and per evaluation); the resident
//! path decodes the CSR once under admission, authenticates with parallel
//! span hashing, and evaluates in memory. `NOID_DECIDER_K_LOG` selects the
//! instance size (default 22; production Link/Block classes are k24).

use std::time::Instant;

use noid_ivc_core::field::F128;
use noid_ivc_core::field_r1cs::synthetic_satisfiable_bounded_dictionary;
use noid_ivc_core::matrix_claim::{stacked_matrix_mle_eval, MatrixAccClaim, MatrixClaimEvaluator};
use noid_ivc_core::proof::FieldShape;
use noid_miner::{
    LoadedSelectedRecursiveMatrixEvaluator, LocalSelectedRecursiveMatrixSource,
    SelectedRecursiveMatrixArtifactIdentity, SelectedRecursiveMatrixKind,
};

fn main() {
    let k_log: usize = std::env::var("NOID_DECIDER_K_LOG")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(22);
    println!("PARANOID terminal-decider matrix roofline (k_log={k_log})");
    println!("  rayon threads: {}", rayon::current_num_threads());

    let t = Instant::now();
    // 512 distinct coefficients: the production verifier-trace profile the
    // streaming evaluator's dictionary cap is sized for.
    let (matrix, z) = synthetic_satisfiable_bounded_dictionary(k_log, k_log, 0xDEC1DE, 512);
    drop(z);
    println!(
        "  synth build      {:>8.3} s  ({} rows)",
        t.elapsed().as_secs_f64(),
        matrix.useful_rows
    );

    let t = Instant::now();
    let digest = matrix.structural_statement_digest();
    println!(
        "  parallel hash    {:>8.3} s  (resident span digest)",
        t.elapsed().as_secs_f64()
    );

    let directory = tempfile::tempdir().expect("tempdir");
    let mut source = LocalSelectedRecursiveMatrixSource::new(directory.path());
    let identity = SelectedRecursiveMatrixArtifactIdentity::new(
        SelectedRecursiveMatrixKind::GenesisLink,
        FieldShape::of(&matrix),
        digest,
    );
    let t = Instant::now();
    // Streamed evaluation needs the seekable plaintext; the compressed form
    // serves the resident/trusted arms below.
    source
        .export_matrix_uncompressed(identity, &matrix)
        .expect("export uncompressed");
    source.export_matrix(identity, &matrix).expect("export");
    let bytes = std::fs::metadata(
        source
            .artifact_path(SelectedRecursiveMatrixKind::GenesisLink)
            .with_extension("field-r1cs.zst"),
    )
    .expect("artifact metadata")
    .len();
    println!(
        "  export           {:>8.3} s  ({:.1} MiB compressed artifact)",
        t.elapsed().as_secs_f64(),
        bytes as f64 / (1024.0 * 1024.0)
    );

    let mut claim = MatrixAccClaim {
        point: vec![F128::new(7, 9); 2 * matrix.k_log + 1],
        value: F128::ZERO,
    };
    let t = Instant::now();
    claim.value = stacked_matrix_mle_eval(&matrix, &claim);
    println!(
        "  in-memory eval   {:>8.3} s  (claim reference)",
        t.elapsed().as_secs_f64()
    );
    drop(matrix);

    // Streamed decider path (default policy): one preflight scan at open plus
    // one authenticated evaluation scan.
    let t = Instant::now();
    let mut streamed = source.open_artifact_evaluator(identity).expect("streamed open");
    let open_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let evaluated = streamed
        .evaluate_matrix_claims(None, Some(&claim))
        .expect("streamed evaluation");
    assert_eq!(evaluated.accumulated_value(), Some(claim.value));
    let eval_s = t.elapsed().as_secs_f64();
    drop(streamed);
    println!(
        "  streamed         open {open_s:>8.3} s + eval {eval_s:>8.3} s = {:>8.3} s",
        open_s + eval_s
    );

    // Resident decider path with paranoid rehash forced (export already
    // wrote a trust record): decode + parallel span authentication, then
    // in-memory evaluation.
    source.set_resident_evaluation(true);
    source.set_artifact_trust(false);
    let t = Instant::now();
    let mut resident = source.open_artifact_evaluator(identity).expect("resident open");
    let open_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let evaluated = resident
        .evaluate_matrix_claims(None, Some(&claim))
        .expect("resident evaluation");
    assert_eq!(evaluated.accumulated_value(), Some(claim.value));
    let eval_s = t.elapsed().as_secs_f64();
    drop(resident);
    println!(
        "  resident         load {open_s:>8.3} s + eval {eval_s:>8.3} s = {:>8.3} s",
        open_s + eval_s
    );

    // Trusted-resident decider path: the install-time record (written at
    // export) admits decode with no Poseidon pass at all; evaluation
    // authenticates against the established digest.
    source.set_artifact_trust(true);
    let t = Instant::now();
    let mut trusted = source
        .open_artifact_evaluator(identity)
        .expect("trusted open");
    assert!(matches!(
        trusted,
        LoadedSelectedRecursiveMatrixEvaluator::TrustedResident(_)
    ));
    let open_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let evaluated = trusted
        .evaluate_matrix_claims(None, Some(&claim))
        .expect("trusted evaluation");
    assert_eq!(evaluated.accumulated_value(), Some(claim.value));
    assert_eq!(evaluated.structural_digest(), digest);
    let eval_s = t.elapsed().as_secs_f64();
    drop(trusted);
    println!(
        "  trusted          load {open_s:>8.3} s + eval {eval_s:>8.3} s = {:>8.3} s",
        open_s + eval_s
    );
}
