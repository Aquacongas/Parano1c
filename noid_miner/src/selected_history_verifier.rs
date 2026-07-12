// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Memory-governed selected-history terminal verification.
//!
//! The recursive verifier owns cryptographic policy and the dependency-clean
//! matrix lease contract.  This node/miner layer connects that contract to the
//! disk-backed production matrix source and the same process-global m24
//! governor used by native and recursive proving.

use std::fmt;

use noid_chain::BlockHeader;
use noid_recursive::{
    verify_selected_history_terminal, CanonicalSelectedHistoryRegistry, ChainAccumulator,
    SelectedHistoryMatrixFamily, SelectedHistoryMatrixLease, SelectedHistoryMatrixRequest,
    SelectedHistoryMatrixSource, SelectedHistoryTerminalPackage, SelectedHistoryVerificationError,
};

use crate::memory_governor::{ProofMemoryGovernor, ProofMemoryPressure, ProofMemoryReservation};
use crate::recursive_matrix_store::{
    LocalSelectedRecursiveMatrixError, LocalSelectedRecursiveMatrixSource,
    SelectedRecursiveMatrixArtifactIdentity,
};
use crate::recursive_prover::{
    LoadedSelectedRecursiveMatrix, SelectedRecursiveMatrixKind, SelectedRecursiveTier,
};

impl SelectedHistoryMatrixLease for LoadedSelectedRecursiveMatrix {
    fn matrix(&self) -> &noid_ivc_core::field_r1cs::FieldR1cs {
        self.matrix()
    }
}

fn history_matrix_identity(
    request: SelectedHistoryMatrixRequest,
) -> Result<SelectedRecursiveMatrixArtifactIdentity, LocalSelectedRecursiveMatrixError> {
    let kind = history_matrix_kind(request.family, request.tier)?;
    Ok(SelectedRecursiveMatrixArtifactIdentity::new(
        kind,
        request.shape(),
        request.statement_digest(),
    ))
}

fn history_matrix_kind(
    family: SelectedHistoryMatrixFamily,
    tier: usize,
) -> Result<SelectedRecursiveMatrixKind, LocalSelectedRecursiveMatrixError> {
    let tier = match tier {
        8 => SelectedRecursiveTier::B8,
        32 => SelectedRecursiveTier::B32,
        64 => SelectedRecursiveTier::B64,
        255 => SelectedRecursiveTier::B255,
        _ => return Err(LocalSelectedRecursiveMatrixError::UnsupportedTier { tier }),
    };
    Ok(match family {
        SelectedHistoryMatrixFamily::Link => SelectedRecursiveMatrixKind::PreviousLink(tier),
        SelectedHistoryMatrixFamily::Block => SelectedRecursiveMatrixKind::CurrentBlock(tier),
    })
}

impl SelectedHistoryMatrixSource for LocalSelectedRecursiveMatrixSource {
    type Lease = LoadedSelectedRecursiveMatrix;
    type Error = LocalSelectedRecursiveMatrixError;

    fn load_matrix(
        &mut self,
        request: SelectedHistoryMatrixRequest,
    ) -> Result<Self::Lease, Self::Error> {
        self.load_artifact(history_matrix_identity(request)?)
    }
}

/// Production terminal-verification failure.  Memory pressure is reported
/// before any matrix artifact is opened.
#[derive(Debug)]
pub enum SelectedHistoryTerminalVerifierError {
    MemoryPressure {
        required_mib: usize,
        available_mib: usize,
    },
    Verification(SelectedHistoryVerificationError),
}

impl fmt::Display for SelectedHistoryTerminalVerifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MemoryPressure {
                required_mib,
                available_mib,
            } => write!(
                f,
                "selected-history verification needs {required_mib} MiB; {available_mib} MiB is available"
            ),
            Self::Verification(error) => write!(f, "selected-history verification: {error}"),
        }
    }
}

impl std::error::Error for SelectedHistoryTerminalVerifierError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MemoryPressure { .. } => None,
            Self::Verification(error) => Some(error),
        }
    }
}

impl From<ProofMemoryPressure> for SelectedHistoryTerminalVerifierError {
    fn from(value: ProofMemoryPressure) -> Self {
        Self::MemoryPressure {
            required_mib: value.required_mib,
            available_mib: value.available_mib,
        }
    }
}

impl From<SelectedHistoryVerificationError> for SelectedHistoryTerminalVerifierError {
    fn from(value: SelectedHistoryVerificationError) -> Self {
        Self::Verification(value)
    }
}

/// One process-global m24 admission held throughout terminal proof replay,
/// every sequential matrix lease, all live-lane checks, and the final local
/// accumulator boundary decision.
#[must_use = "dropping the session releases selected-history verification admission"]
pub struct SelectedHistoryTerminalVerificationSession {
    _reservation: ProofMemoryReservation,
}

impl SelectedHistoryTerminalVerificationSession {
    pub fn verify<S: SelectedHistoryMatrixSource>(
        &mut self,
        package: &SelectedHistoryTerminalPackage,
        registry: &CanonicalSelectedHistoryRegistry<'_>,
        local_tip_header: &BlockHeader,
        local_epoch_anchor_header: &BlockHeader,
        matrix_source: &mut S,
    ) -> Result<ChainAccumulator, SelectedHistoryTerminalVerifierError> {
        verify_selected_history_terminal(
            package,
            registry,
            local_tip_header,
            local_epoch_anchor_header,
            matrix_source,
        )
        .map_err(Into::into)
    }
}

/// Acquire production terminal-verification admission before any matrix load.
pub fn begin_selected_history_terminal_verification_session(
) -> Result<SelectedHistoryTerminalVerificationSession, SelectedHistoryTerminalVerifierError> {
    begin_terminal_verification_with_governor(&ProofMemoryGovernor::global(0))
}

fn begin_terminal_verification_with_governor(
    governor: &ProofMemoryGovernor,
) -> Result<SelectedHistoryTerminalVerificationSession, SelectedHistoryTerminalVerifierError> {
    Ok(SelectedHistoryTerminalVerificationSession {
        _reservation: governor.try_reserve_for_selected_history_session()?,
    })
}

/// Production one-shot entrypoint.  The shared m24 reservation is acquired
/// before the recursive verifier can request its first disk matrix and is
/// released only after the accumulator/tip decision returns.
pub fn verify_selected_history_terminal_governed<S: SelectedHistoryMatrixSource>(
    package: &SelectedHistoryTerminalPackage,
    registry: &CanonicalSelectedHistoryRegistry<'_>,
    local_tip_header: &BlockHeader,
    local_epoch_anchor_header: &BlockHeader,
    matrix_source: &mut S,
) -> Result<ChainAccumulator, SelectedHistoryTerminalVerifierError> {
    let mut session = begin_selected_history_terminal_verification_session()?;
    session.verify(
        package,
        registry,
        local_tip_header,
        local_epoch_anchor_header,
        matrix_source,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_requests_map_only_to_fixed_non_genesis_artifact_paths() {
        for (tier, selected) in [
            (8, SelectedRecursiveTier::B8),
            (32, SelectedRecursiveTier::B32),
            (64, SelectedRecursiveTier::B64),
            (255, SelectedRecursiveTier::B255),
        ] {
            assert_eq!(
                history_matrix_kind(SelectedHistoryMatrixFamily::Link, tier).unwrap(),
                SelectedRecursiveMatrixKind::PreviousLink(selected)
            );
            assert_eq!(
                history_matrix_kind(SelectedHistoryMatrixFamily::Block, tier).unwrap(),
                SelectedRecursiveMatrixKind::CurrentBlock(selected)
            );
        }
        assert!(matches!(
            history_matrix_kind(SelectedHistoryMatrixFamily::Link, 9),
            Err(LocalSelectedRecursiveMatrixError::UnsupportedTier { tier: 9 })
        ));
    }

    #[test]
    fn terminal_verification_session_serializes_with_all_proof_work() {
        let governor = ProofMemoryGovernor::new(8 * 1024);
        let session = SelectedHistoryTerminalVerificationSession {
            _reservation: governor
                .try_reserve_selected_history_with_available(Some(16 * 1024))
                .expect("first terminal verification admission"),
        };

        assert!(governor
            .try_reserve_selected_history_with_available(Some(16 * 1024))
            .is_err());
        assert!(governor.try_reserve_for_recursive_tier(8).is_err());

        drop(session);
        governor
            .try_reserve_selected_history_with_available(Some(16 * 1024))
            .expect("dropping terminal session releases shared admission");
    }

    #[test]
    fn governed_entrypoint_acquires_before_recursive_verifier_can_load() {
        let source = include_str!("selected_history_verifier.rs");
        let entrypoint = source
            .split("pub fn verify_selected_history_terminal_governed<")
            .nth(1)
            .expect("governed terminal entrypoint")
            .split("#[cfg(test)]")
            .next()
            .expect("entrypoint boundary");
        let reserve = entrypoint
            .find("begin_selected_history_terminal_verification_session()")
            .expect("terminal reservation");
        let verify = entrypoint.find("session.verify(").expect("terminal verify");
        assert!(reserve < verify);
    }
}
