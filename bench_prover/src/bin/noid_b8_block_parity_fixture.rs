// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Export the honest native-input fixture consumed by the exact B8
//! legacy-versus-locally-authored Block parity gate.
//!
//! This is release/test tooling only. It builds one canonical single-user B8
//! block through the retained component prover, re-verifies that component
//! proof, preserves authorization proofs in their allocation-bounded wire
//! format, and atomically writes the exact bincode DTO expected by
//! `release_b8_locally_authored_block_envelope_and_sidecar_are_legacy_identical`.
//!
//! Usage:
//!
//! ```text
//! noid_b8_block_parity_fixture <output-file>
//! ```

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use bench_prover::accepted_single_user_fixture;
use noid_recursive::block_certificate_backend::{
    verify_accepted_block_batch_components, AcceptedBlockBatchComponentInputs,
    AcceptedBlockBatchComponentProof,
};
use noid_recursive::ChainAccumulator;

const FIXTURE_SEED: u128 = 0xB8_B10C_C1A5_5001;
const B8_TIER: usize = 8;

/// Keep field order and types byte-for-byte aligned with the private reader
/// DTO in `noid_recursive::acceptance::block_class::tests`.
#[derive(serde::Serialize, serde::Deserialize)]
struct ReleaseB8BlockParityFixture {
    start_accumulator: ChainAccumulator,
    end_accumulator: ChainAccumulator,
    inputs: AcceptedBlockBatchComponentInputs,
    component_proof: AcceptedBlockBatchComponentProof,
    live_authorization_proof_bytes: Vec<Vec<u8>>,
    ghost_authorization_proof_bytes: Vec<u8>,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn output_path() -> Result<PathBuf, io::Error> {
    let mut args = std::env::args_os();
    let program = args
        .next()
        .unwrap_or_else(|| OsString::from("noid_b8_block_parity_fixture"));
    let output = args.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("usage: {} <output-file>", Path::new(&program).display()),
        )
    })?;
    if args.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("usage: {} <output-file>", Path::new(&program).display()),
        ));
    }
    Ok(PathBuf::from(output))
}

fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), io::Error> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let parent = parent.unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("output directory does not exist: {}", parent.display()),
        ));
    }
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "output has no file name"))?;
    let temporary = parent.join(format!(
        ".{}.tmp-{}",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output_path = output_path()?;
    let fixture = accepted_single_user_fixture(FIXTURE_SEED);
    let end_accumulator = fixture.output.accepted_claim_batch.accumulator.clone();
    let component_inputs = &fixture.output.proof_components.component_inputs;
    let live_proofs = &fixture
        .output
        .proof_components
        .selected_authorization_proofs;
    let live_count = component_inputs.authorization_inputs.len();

    if noid_chain::consensus::params::user_tx_class_tier(live_count) != Some(B8_TIER) {
        return Err(invalid(format!(
            "single-user fixture selected non-B8 class for {live_count} authorizations"
        ))
        .into());
    }
    if live_proofs.len() != live_count {
        return Err(invalid(format!(
            "selected authorization proof cardinality {} != {live_count}",
            live_proofs.len()
        ))
        .into());
    }

    let verified = verify_accepted_block_batch_components(
        &fixture.start_consensus,
        &fixture.start_accumulator,
        &end_accumulator,
        component_inputs,
        &fixture.component_proof,
    )
    .map_err(|error| invalid(format!("retained component proof rejected: {error:?}")))?;
    if verified != fixture.output.accepted_claim_batch {
        return Err(invalid("component verifier changed the accepted B8 output").into());
    }

    let live_authorization_proof_bytes = live_proofs
        .iter()
        .map(|proof| {
            proof
                .to_bytes()
                .map_err(|error| invalid(format!("encode live authorization proof: {error:?}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let ghost_authorization_proof_bytes = noid_gkr::ghost_tx::prove_selected_ghost_authorization()
        .map_err(|error| invalid(format!("prove canonical ghost authorization: {error:?}")))?
        .to_bytes()
        .map_err(|error| invalid(format!("encode ghost authorization proof: {error:?}")))?;

    let encoded = bincode::serialize(&ReleaseB8BlockParityFixture {
        start_accumulator: fixture.start_accumulator,
        end_accumulator,
        inputs: fixture.output.proof_components.component_inputs,
        component_proof: fixture.component_proof,
        live_authorization_proof_bytes,
        ghost_authorization_proof_bytes,
    })?;
    let decoded: ReleaseB8BlockParityFixture = bincode::deserialize(&encoded)?;
    if decoded.inputs.authorization_inputs.len() != live_count
        || decoded.live_authorization_proof_bytes.len() != live_count
        || noid_chain::consensus::params::user_tx_class_tier(live_count) != Some(B8_TIER)
    {
        return Err(invalid("serialized B8 parity fixture failed its DTO roundtrip").into());
    }

    write_atomically(&output_path, &encoded)?;
    println!(
        "wrote canonical B8 Block parity fixture: {} bytes -> {}",
        encoded.len(),
        output_path.display()
    );
    Ok(())
}
