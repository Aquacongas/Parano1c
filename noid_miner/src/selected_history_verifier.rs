// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Memory-governed selected-history terminal verification.
//!
//! The recursive verifier owns cryptographic policy and the dependency-clean
//! matrix lease contract.  This node/miner layer connects that contract to the
//! disk-backed production matrix source and the same process-global exclusion
//! ledger used by native and recursive proving. Its byte reservation covers
//! the hard-cap-derived compact-registry materialization envelope plus bounded
//! streaming scratch; it does not pretend to allocate an m24 CSR.

use std::fmt;

use noid_chain::BlockHeader;
use noid_recursive::{
    verify_selected_history_terminal, CanonicalSelectedHistoryRegistry, ChainAccumulator,
    SelectedHistoryMatrixFamily, SelectedHistoryMatrixLease, SelectedHistoryMatrixRequest,
    SelectedHistoryMatrixSource, SelectedHistoryRegistryError, SelectedHistoryTerminalPackage,
    SelectedHistoryVerificationError,
};

use crate::memory_governor::{ProofMemoryGovernor, ProofMemoryPressure, ProofMemoryReservation};
use crate::recursive_class_registry_store::{
    LoadedSelectedRecursiveTerminalRegistry, LocalSelectedRecursiveClassRegistryError,
    LocalSelectedRecursiveClassRegistryStore,
};
use crate::recursive_matrix_store::{
    LoadedSelectedRecursiveMatrixView, LocalSelectedRecursiveMatrixError,
    LocalSelectedRecursiveMatrixSource, SelectedRecursiveMatrixArtifactIdentity,
};
use crate::recursive_prover::{SelectedRecursiveMatrixKind, SelectedRecursiveTier};

impl SelectedHistoryMatrixLease for LoadedSelectedRecursiveMatrixView {
    fn evaluator(&mut self) -> &mut dyn noid_ivc_core::matrix_claim::MatrixClaimEvaluator {
        self
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
    type Lease = LoadedSelectedRecursiveMatrixView;
    type Error = LocalSelectedRecursiveMatrixError;

    fn load_matrix(
        &mut self,
        request: SelectedHistoryMatrixRequest,
    ) -> Result<Self::Lease, Self::Error> {
        self.open_artifact_view(history_matrix_identity(request)?)
    }
}

/// Production terminal-verification failure.  The pinned production entrypoint
/// reports memory pressure before the registry or any matrix artifact opens.
#[derive(Debug)]
pub enum SelectedHistoryTerminalVerifierError {
    MemoryPressure {
        required_mib: usize,
        available_mib: usize,
    },
    RegistryLoad(LocalSelectedRecursiveClassRegistryError),
    RegistryPolicy(SelectedHistoryRegistryError),
    RegistryNotLoaded,
    RegistryAlreadyLoaded,
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
            Self::RegistryLoad(error) => {
                write!(f, "selected-history pinned registry load: {error}")
            }
            Self::RegistryPolicy(error) => {
                write!(f, "selected-history terminal registry policy: {error}")
            }
            Self::RegistryNotLoaded => {
                f.write_str("selected-history pinned registry was not loaded in this session")
            }
            Self::RegistryAlreadyLoaded => {
                f.write_str("selected-history session already owns a pinned registry")
            }
            Self::Verification(error) => write!(f, "selected-history verification: {error}"),
        }
    }
}

impl std::error::Error for SelectedHistoryTerminalVerifierError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MemoryPressure { .. } => None,
            Self::RegistryLoad(error) => Some(error),
            Self::RegistryPolicy(error) => Some(error),
            Self::RegistryNotLoaded => None,
            Self::RegistryAlreadyLoaded => None,
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

impl From<LocalSelectedRecursiveClassRegistryError> for SelectedHistoryTerminalVerifierError {
    fn from(value: LocalSelectedRecursiveClassRegistryError) -> Self {
        Self::RegistryLoad(value)
    }
}

impl From<SelectedHistoryRegistryError> for SelectedHistoryTerminalVerifierError {
    fn from(value: SelectedHistoryRegistryError) -> Self {
        Self::RegistryPolicy(value)
    }
}

/// One process-global admission held throughout pinned-registry
/// materialization, terminal proof replay, every sequential matrix lease, all
/// live-lane checks, and the final local accumulator boundary decision.
#[must_use = "dropping the session releases selected-history verification admission"]
pub struct SelectedHistoryTerminalVerificationSession {
    _reservation: ProofMemoryReservation,
    // Keeping the registry inside the session makes it impossible for the
    // pinned materialization performed through this API to outlive admission.
    loaded_registry: Option<LoadedSelectedRecursiveTerminalRegistry>,
}

impl SelectedHistoryTerminalVerificationSession {
    /// Read, authenticate, preflight, and materialize the compact registry
    /// after this session has acquired the process-global 64 MiB envelope.
    /// The session admits exactly one load so two materialized registries can
    /// never overlap inside the single-registry envelope. The loaded value is
    /// never returned detached from its owning admission guard.
    pub fn load_pinned_registry(
        &mut self,
        store: &LocalSelectedRecursiveClassRegistryStore,
        expected_registry_digest: [u8; 32],
    ) -> Result<(), SelectedHistoryTerminalVerifierError> {
        if self.loaded_registry.is_some() {
            return Err(SelectedHistoryTerminalVerifierError::RegistryAlreadyLoaded);
        }
        let loaded = store.load_terminal_pinned(expected_registry_digest)?;
        // The pinned decoder publishes only an already-validated owned
        // terminal registry. Reborrowing its view below is allocation-free
        // and cannot repeat the shared-genesis proof replay.
        self.loaded_registry = Some(loaded);
        Ok(())
    }

    /// Verify with the pinned registry materialized by this same admission
    /// session. Registry ownership, the process-global proof exclusion and all
    /// sequential matrix leases therefore share one lexical lifetime.
    pub fn verify_with_loaded_registry<S: SelectedHistoryMatrixSource>(
        &self,
        package: &SelectedHistoryTerminalPackage,
        local_tip_header: &BlockHeader,
        local_epoch_anchor_header: &BlockHeader,
        matrix_source: &mut S,
    ) -> Result<ChainAccumulator, SelectedHistoryTerminalVerifierError> {
        let loaded = self
            .loaded_registry
            .as_ref()
            .ok_or(SelectedHistoryTerminalVerifierError::RegistryNotLoaded)?;
        let registry = loaded.terminal_registry();
        self.verify(
            package,
            &registry,
            local_tip_header,
            local_epoch_anchor_header,
            matrix_source,
        )
    }

    pub fn verify<S: SelectedHistoryMatrixSource>(
        &self,
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

/// Acquire the complete production terminal-verification admission before
/// pinned-registry materialization or any matrix load.
pub fn begin_selected_history_terminal_verification_session(
) -> Result<SelectedHistoryTerminalVerificationSession, SelectedHistoryTerminalVerifierError> {
    begin_terminal_verification_with_governor(&ProofMemoryGovernor::global(0))
}

fn begin_terminal_verification_with_governor(
    governor: &ProofMemoryGovernor,
) -> Result<SelectedHistoryTerminalVerificationSession, SelectedHistoryTerminalVerifierError> {
    Ok(SelectedHistoryTerminalVerificationSession {
        _reservation: governor.try_reserve_for_selected_history_terminal_verification()?,
        loaded_registry: None,
    })
}

/// One-shot verifier for a registry that the caller already materialized under
/// an equal or larger owning admission. The terminal reservation is acquired
/// before the recursive verifier can request its first disk matrix and is
/// released only after the accumulator/tip decision returns. New runtime code
/// should prefer [`verify_selected_history_terminal_pinned_governed`].
pub fn verify_selected_history_terminal_governed<S: SelectedHistoryMatrixSource>(
    package: &SelectedHistoryTerminalPackage,
    registry: &CanonicalSelectedHistoryRegistry<'_>,
    local_tip_header: &BlockHeader,
    local_epoch_anchor_header: &BlockHeader,
    matrix_source: &mut S,
) -> Result<ChainAccumulator, SelectedHistoryTerminalVerifierError> {
    let session = begin_selected_history_terminal_verification_session()?;
    session.verify(
        package,
        registry,
        local_tip_header,
        local_epoch_anchor_header,
        matrix_source,
    )
}

/// Production pinned-registry entrypoint. Admission is acquired before the
/// registry artifact is opened, and the same owning session retains both the
/// registry and the process-global exclusion through terminal verification.
pub fn verify_selected_history_terminal_pinned_governed<S: SelectedHistoryMatrixSource>(
    package: &SelectedHistoryTerminalPackage,
    registry_store: &LocalSelectedRecursiveClassRegistryStore,
    expected_registry_digest: [u8; 32],
    local_tip_header: &BlockHeader,
    local_epoch_anchor_header: &BlockHeader,
    matrix_source: &mut S,
) -> Result<ChainAccumulator, SelectedHistoryTerminalVerifierError> {
    let mut session = begin_selected_history_terminal_verification_session()?;
    session.load_pinned_registry(registry_store, expected_registry_digest)?;
    session.verify_with_loaded_registry(
        package,
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
                .try_reserve_selected_history_terminal_with_available(Some(2 * 1024))
                .expect("first terminal verification admission"),
            loaded_registry: None,
        };

        assert!(governor
            .try_reserve_selected_history_terminal_with_available(Some(2 * 1024))
            .is_err());
        assert!(governor.try_reserve_for_recursive_tier(8).is_err());

        drop(session);
        governor
            .try_reserve_selected_history_terminal_with_available(Some(2 * 1024))
            .expect("dropping terminal session releases shared admission");
    }

    #[test]
    fn pinned_registry_load_stays_inside_terminal_admission() {
        let directory = tempfile::tempdir().unwrap();
        let store = LocalSelectedRecursiveClassRegistryStore::new(directory.path());
        let governor = ProofMemoryGovernor::new(8 * 1024);
        let mut session = begin_terminal_verification_with_governor(&governor)
            .expect("terminal admission before registry I/O");

        assert!(session.load_pinned_registry(&store, [0u8; 32]).is_err());
        assert!(
            governor.try_reserve_for_recursive_tier(8).is_err(),
            "a failed registry load must not release the owning session"
        );

        drop(session);
        drop(
            governor
                .try_reserve_for_recursive_tier(8)
                .expect("session drop releases process-global proof exclusion"),
        );
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

    #[test]
    fn pinned_entrypoint_reserves_before_loading_registry() {
        let source = include_str!("selected_history_verifier.rs");
        let entrypoint = source
            .split("pub fn verify_selected_history_terminal_pinned_governed<")
            .nth(1)
            .expect("pinned governed entrypoint")
            .split("#[cfg(test)]")
            .next()
            .expect("entrypoint boundary");
        let reserve = entrypoint
            .find("begin_selected_history_terminal_verification_session()")
            .expect("terminal reservation");
        let load = entrypoint
            .find("session.load_pinned_registry(")
            .expect("pinned registry load");
        let verify = entrypoint
            .find("session.verify_with_loaded_registry(")
            .expect("terminal verification");
        assert!(reserve < load && load < verify);
    }

    #[test]
    fn terminal_session_cannot_materialize_prover_block_classes() {
        let source = include_str!("selected_history_verifier.rs");
        let load = source
            .split("pub fn load_pinned_registry(")
            .nth(1)
            .expect("terminal session registry loader")
            .split("/// Verify with the pinned registry")
            .next()
            .expect("terminal loader boundary");
        assert!(load.contains("store.load_terminal_pinned("));
        assert!(!load.contains("store.load_pinned("));
        let session = source
            .split("pub struct SelectedHistoryTerminalVerificationSession {")
            .nth(1)
            .expect("terminal session declaration")
            .split("impl SelectedHistoryTerminalVerificationSession")
            .next()
            .expect("terminal session fields");
        assert!(session.contains("Option<LoadedSelectedRecursiveTerminalRegistry>"));
        assert!(!session.contains("LoadedSelectedRecursiveClassRegistry"));
    }

    #[test]
    fn loaded_terminal_verification_reborrows_without_registry_revalidation() {
        let source = include_str!("selected_history_verifier.rs");
        let load = source
            .split("pub fn load_pinned_registry(")
            .nth(1)
            .expect("terminal session registry loader")
            .split("/// Verify with the pinned registry")
            .next()
            .expect("terminal loader boundary");
        assert!(load.contains("store.load_terminal_pinned("));
        assert!(!load.contains(".terminal_registry("));
        assert!(!load.contains("CanonicalSelectedHistoryRegistry::try_new("));

        let verify = source
            .split("pub fn verify_with_loaded_registry<")
            .nth(1)
            .expect("loaded terminal verifier")
            .split("pub fn verify<")
            .next()
            .expect("loaded verifier boundary");
        assert_eq!(verify.matches("loaded.terminal_registry()").count(), 1);
        assert!(!verify.contains("CanonicalSelectedHistoryRegistry::try_new("));
        assert!(!verify.contains("validate_materialized("));
    }
}
