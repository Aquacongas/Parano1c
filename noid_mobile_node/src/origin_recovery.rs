// SPDX-License-Identifier: Apache-2.0

//! Authenticated fork-origin recovery shared with the desktop policy.

use std::{sync::Arc, time::Duration};

#[derive(Debug)]
pub(super) enum OriginRecoveryError {
    InvalidTerminal(String),
    Unavailable(String),
}

impl std::fmt::Display for OriginRecoveryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTerminal(error) | Self::Unavailable(error) => formatter.write_str(error),
        }
    }
}

/// Authenticate the terminal's origin, upgrading an unusable local certificate
/// from the peer when needed. A local legacy-only file must not prevent a
/// retired-history build from fetching its matrix-free replacement.
pub(super) async fn ensure_terminal_origin(
    runtime: &Arc<noid_miner::HistoryProtocolRuntime>,
    terminal: &[u8],
    peer: libp2p::PeerId,
    commands: &noid_p2p::NetworkCommandSender,
) -> Result<(), OriginRecoveryError> {
    let Some(requested) = runtime
        .requested_origin(terminal)
        .map_err(OriginRecoveryError::InvalidTerminal)?
    else {
        return Ok(());
    };
    ensure_requested_origin(runtime, requested, peer, commands)
        .await
        .map_err(OriginRecoveryError::Unavailable)
}

async fn ensure_requested_origin(
    runtime: &Arc<noid_miner::HistoryProtocolRuntime>,
    requested: noid_recursive::acceptance::history_step::v2::banked::Origin,
    peer: libp2p::PeerId,
    commands: &noid_p2p::NetworkCommandSender,
) -> Result<(), String> {
    if runtime.has_verified_origin(&requested)? {
        return Ok(());
    }
    let local = match runtime.origin_bytes(requested.request_binding()) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(%error, "local fork-origin file unavailable; requesting a checked replacement");
            None
        }
    };
    if let Some(bytes) = local {
        let local_runtime = Arc::clone(runtime);
        let local_requested = requested.clone();
        let checked: Result<(), String> = tokio::task::spawn_blocking(move || {
            noid_miner::install_inbound_verifier_cpu(|| {
                let checked = local_runtime.install_origin_bytes(&bytes)?;
                if checked.origin() != &local_requested {
                    return Err("local fork-origin certificate does not match the terminal".into());
                }
                Ok(())
            })
            .map_err(|e| e.to_string())?
        })
        .await
        .map_err(|e| e.to_string())?;
        match checked {
            Ok(()) => return Ok(()),
            Err(error) => {
                tracing::warn!(%error, "local fork-origin certificate could not be verified; requesting a checked replacement")
            }
        }
    }
    // The local bytes have been dropped before acquiring a network allocation.
    // Fetch failure cannot grant verification or replace the retained file.
    let (reply, response) = tokio::sync::oneshot::channel();
    commands
        .send(noid_p2p::NetworkCommand::FetchForkOrigin {
            peer,
            request: requested.request_binding(),
            reply,
        })
        .await
        .map_err(|e| e.to_string())?;
    let response = tokio::time::timeout(Duration::from_secs(50), response)
        .await
        .map_err(|_| "fork-origin request timed out")?
        .map_err(|_| "fork-origin response channel closed")??;
    let runtime = Arc::clone(runtime);
    tokio::task::spawn_blocking(move || {
        noid_miner::install_inbound_verifier_cpu(|| {
            // Keep the network allocation permit until certificate checking
            // finishes. Local files have the same strict decoder and proof path.
            let encoded = response
                .bytes
                .as_deref()
                .ok_or("peer does not retain the requested fork origin")?;
            let checked = runtime.install_origin_bytes(encoded)?;
            if checked.origin() != &requested {
                return Err("fork-origin certificate does not match the terminal".into());
            }
            Ok(())
        })
        .map_err(|e| e.to_string())?
    })
    .await
    .map_err(|e| e.to_string())?
}
