// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Release-pinned HistoryStep verifier initialization for the mobile full node.
//!
//! This mirrors the ordinary desktop-node verifier path but contains no mining
//! code. Development builds may intentionally contain no embedded pack.
//! Official release builds must embed the pinned metadata and both canonical
//! matrix leaves.

use std::path::{Path, PathBuf};
use std::sync::Arc;

pub type HistoryStepRuntime = noid_recursive::acceptance::history_step::HistoryStepRuntime;

fn history_step_cache_directory(data_dir: &Path, metadata_digest: [u8; 32]) -> PathBuf {
    let mut digest_hex = String::with_capacity(64);

    for byte in metadata_digest {
        use std::fmt::Write as _;

        write!(&mut digest_hex, "{byte:02x}").expect("writing to String cannot fail");
    }

    data_dir.join("history-step-cache").join(digest_hex)
}

/// Exact release bank identifier advertised to P2P.
///
/// `[0; 32]` is used only by pack-free development builds, matching the
/// desktop node.
pub fn history_proof_bank_id() -> [u8; 32] {
    crate::embedded_history_step_pack::embedded_history_step_pack()
        .map(|pack| pack.runtime_metadata_digest())
        .unwrap_or([0; 32])
}

/// Construct the executable-embedded release-pinned HistoryStep verifier.
///
/// This is deliberately fail-closed:
///
/// - malformed pinned metadata -> error;
/// - wrong release digest -> error;
/// - malformed canonical matrix pack -> error;
/// - runtime bank/parts disagreement -> error.
///
/// `Ok(None)` is valid only for a pack-free development build.
pub fn embedded_history_step_runtime(
    data_dir: &Path,
) -> Result<Option<Arc<HistoryStepRuntime>>, String> {
    let Some(pack) = crate::embedded_history_step_pack::embedded_history_step_pack() else {
        return Ok(None);
    };

    let metadata = noid_history_runtime::decode_history_step_runtime_metadata_pinned(
        pack.runtime_metadata(),
        pack.runtime_metadata_digest(),
    )
    .map_err(|error| format!("embedded HistoryStep metadata rejected: {error}"))?;

    // Same cache identity as desktop:
    // pinned metadata digest -> runtime packed matrix cache.
    let cache_directory = history_step_cache_directory(data_dir, pack.runtime_metadata_digest());

    let matrix_source = pack
        .matrix_source(Some(cache_directory))
        .map_err(|error| format!("embedded HistoryStep matrices rejected: {error}"))?;

    let (bank, runtime_parts) = metadata.into_parts();

    let runtime = HistoryStepRuntime::new(bank, Box::new(matrix_source), runtime_parts)
        .map_err(|error| format!("embedded HistoryStep runtime rejected: {error}"))?;

    tracing::debug!(
        embedded_matrix_mib = pack.embedded_bytes_total() / (1024 * 1024),
        "mobile HistoryStep runtime loaded from executable release pack"
    );

    Ok(Some(Arc::new(runtime)))
}

/// Mobile full-node startup requires a verifier in an official release build.
///
/// Debug/development builds can remain pack-free so ordinary `cargo check`
/// does not require release artifacts.
pub fn require_embedded_history_step_runtime(
    data_dir: &Path,
) -> Result<Arc<HistoryStepRuntime>, String> {
    embedded_history_step_runtime(data_dir)?.ok_or_else(|| {
        "HistoryStep verifier unavailable: this is a pack-free development build".to_string()
    })
}
