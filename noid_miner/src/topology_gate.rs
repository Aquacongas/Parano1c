// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Process-local topology control for concurrent proof stages.
//!
//! This gate represents ownership conflicts between proof kernels. It is not a
//! memory estimator: allocation sizes, host-memory readings, cache capacities,
//! and user-configured byte ceilings never participate in admission. The only
//! approved overlap is one native B8 proof with one selected-history B8-B64
//! session; every other heavy proof shape is process-exclusive.

use std::sync::{Arc, Mutex, OnceLock};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExclusiveProofStage {
    NativeWide,
    NativeB255,
    StandaloneRecursive,
    SelectedB255,
    TerminalVerification,
    StartupPrewarm,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProofTopologyProfile {
    NativeB8,
    SelectedSmall,
    Exclusive(ExclusiveProofStage),
}

#[derive(Debug, Default)]
struct AdmissionState {
    native_b8: bool,
    selected_small: bool,
    exclusive: Option<ExclusiveProofStage>,
}

#[derive(Debug)]
struct Inner {
    admission: Mutex<AdmissionState>,
}

static GLOBAL_PROOF_TOPOLOGY_GATE: OnceLock<ProofTopologyGate> = OnceLock::new();

/// Shared ownership gate for heavy proof kernels in one node process.
///
/// Admission is non-blocking. A successful reservation owns its topology slot
/// until drop, including error and unwind paths; a busy result tells the caller
/// to apply backpressure before queueing more blocking work.
#[derive(Clone, Debug)]
pub(crate) struct ProofTopologyGate {
    inner: Arc<Inner>,
}

/// Owning proof-stage slot. Dropping it releases the exact admitted profile.
#[derive(Debug)]
pub(crate) struct ProofTopologyReservation {
    inner: Arc<Inner>,
    profile: ProofTopologyProfile,
}

/// Admission failure is either transient topology contention or an internal
/// attempt to request a non-canonical proof class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProofTopologyAdmissionError {
    Busy,
    NonCanonicalNativeUserTxCount { user_txs: usize },
    NonCanonicalRecursiveTier { tier: usize },
}

impl core::fmt::Display for ProofTopologyAdmissionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Busy => f.write_str("another incompatible proof stage is active"),
            Self::NonCanonicalNativeUserTxCount { user_txs } => write!(
                f,
                "native proof requested for non-canonical user transaction count {user_txs}"
            ),
            Self::NonCanonicalRecursiveTier { tier } => {
                write!(
                    f,
                    "recursive proof requested for non-canonical B{tier} tier"
                )
            }
        }
    }
}

impl std::error::Error for ProofTopologyAdmissionError {}

impl ProofTopologyGate {
    #[cfg(test)]
    pub(crate) fn for_tests() -> Self {
        Self::isolated()
    }

    fn isolated() -> Self {
        Self {
            inner: Arc::new(Inner {
                admission: Mutex::new(AdmissionState::default()),
            }),
        }
    }

    /// Join the process-wide proof-stage ownership ledger shared by the native
    /// miner, selected-history prover, verifier, and external-mining RPC.
    pub(crate) fn global() -> Self {
        GLOBAL_PROOF_TOPOLOGY_GATE
            .get_or_init(Self::isolated)
            .clone()
    }

    /// Largest canonical native transaction tier compatible with the active
    /// proof topology. Zero means a new native template must wait.
    pub(crate) fn max_user_txs_now(&self) -> usize {
        let state = self
            .inner
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.exclusive.is_some() || state.native_b8 {
            0
        } else if state.selected_small {
            8
        } else {
            255
        }
    }

    /// Admit a native block proof before template work is queued. A
    /// coinbase-only template needs no reservation.
    pub(crate) fn try_admit_native_user_txs(
        &self,
        user_txs: usize,
    ) -> Result<Option<ProofTopologyReservation>, ProofTopologyAdmissionError> {
        let profile = match user_txs {
            0 => return Ok(None),
            1..=8 => ProofTopologyProfile::NativeB8,
            9..=64 => ProofTopologyProfile::Exclusive(ExclusiveProofStage::NativeWide),
            65..=255 => ProofTopologyProfile::Exclusive(ExclusiveProofStage::NativeB255),
            _ => {
                return Err(ProofTopologyAdmissionError::NonCanonicalNativeUserTxCount { user_txs })
            }
        };
        self.try_admit_profile(profile).map(Some)
    }

    /// Standalone selected Block proving is exclusive. Pipeline sessions use
    /// [`Self::try_admit_selected_history_session`] instead.
    pub(crate) fn try_admit_recursive_tier(
        &self,
        tier: usize,
    ) -> Result<ProofTopologyReservation, ProofTopologyAdmissionError> {
        match tier {
            8 | 32 | 64 | 255 => self.try_admit_profile(ProofTopologyProfile::Exclusive(
                ExclusiveProofStage::StandaloneRecursive,
            )),
            _ => Err(ProofTopologyAdmissionError::NonCanonicalRecursiveTier { tier }),
        }
    }

    /// Standalone m22 Link proving is exclusive.
    pub(crate) fn try_admit_recursive_link(
        &self,
    ) -> Result<ProofTopologyReservation, ProofTopologyAdmissionError> {
        self.try_admit_profile(ProofTopologyProfile::Exclusive(
            ExclusiveProofStage::StandaloneRecursive,
        ))
    }

    /// Admit one selected-history Block/Link session. B8-B64 may overlap one
    /// native B8 proof; B255 remains exclusive.
    pub(crate) fn try_admit_selected_history_session(
        &self,
        tier: usize,
    ) -> Result<ProofTopologyReservation, ProofTopologyAdmissionError> {
        match tier {
            8 | 32 | 64 => self.try_admit_profile(ProofTopologyProfile::SelectedSmall),
            255 => self.try_admit_profile(ProofTopologyProfile::Exclusive(
                ExclusiveProofStage::SelectedB255,
            )),
            _ => Err(ProofTopologyAdmissionError::NonCanonicalRecursiveTier { tier }),
        }
    }

    /// Startup registry/matrix prewarm is serialized with all proof kernels.
    pub(crate) fn try_admit_selected_history_prewarm(
        &self,
    ) -> Result<ProofTopologyReservation, ProofTopologyAdmissionError> {
        self.try_admit_profile(ProofTopologyProfile::Exclusive(
            ExclusiveProofStage::StartupPrewarm,
        ))
    }

    /// Terminal verification is serialized with every proving lane. Matrix
    /// storage strategy is independent of this topology decision.
    pub(crate) fn try_admit_selected_history_terminal_verification(
        &self,
    ) -> Result<ProofTopologyReservation, ProofTopologyAdmissionError> {
        self.try_admit_profile(ProofTopologyProfile::Exclusive(
            ExclusiveProofStage::TerminalVerification,
        ))
    }

    fn try_admit_profile(
        &self,
        profile: ProofTopologyProfile,
    ) -> Result<ProofTopologyReservation, ProofTopologyAdmissionError> {
        let mut state = self
            .inner
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !profile_compatible(&state, profile) {
            return Err(ProofTopologyAdmissionError::Busy);
        }
        activate_profile(&mut state, profile);
        Ok(ProofTopologyReservation {
            inner: Arc::clone(&self.inner),
            profile,
        })
    }
}

impl Drop for ProofTopologyReservation {
    fn drop(&mut self) {
        let mut state = self
            .inner
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        deactivate_profile(&mut state, self.profile);
    }
}

impl ProofTopologyReservation {
    /// Reclassify a native template reservation after transaction selection.
    /// The transition may only narrow the admitted native class; it can never
    /// upgrade or retype a reservation owned by another proof stage.
    pub(crate) fn narrow_for_native_user_txs(
        mut self,
        user_txs: usize,
    ) -> Result<Option<Self>, &'static str> {
        if user_txs == 0 {
            return Ok(None);
        }
        let target = native_profile(user_txs)
            .ok_or("native template has a non-canonical transaction count")?;
        let current_rank = native_profile_rank(self.profile)
            .ok_or("native template reservation cannot be retyped")?;
        let target_rank = native_profile_rank(target)
            .expect("native_profile always returns a native topology profile");
        if target_rank > current_rank {
            return Err("native template reservation cannot be upgraded");
        }
        if target == self.profile {
            return Ok(Some(self));
        }

        let mut state = self
            .inner
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        deactivate_profile(&mut state, self.profile);
        activate_profile(&mut state, target);
        self.profile = target;
        drop(state);
        Ok(Some(self))
    }
}

fn native_profile(user_txs: usize) -> Option<ProofTopologyProfile> {
    match user_txs {
        1..=8 => Some(ProofTopologyProfile::NativeB8),
        9..=64 => Some(ProofTopologyProfile::Exclusive(
            ExclusiveProofStage::NativeWide,
        )),
        65..=255 => Some(ProofTopologyProfile::Exclusive(
            ExclusiveProofStage::NativeB255,
        )),
        _ => None,
    }
}

fn native_profile_rank(profile: ProofTopologyProfile) -> Option<u8> {
    match profile {
        ProofTopologyProfile::NativeB8 => Some(0),
        ProofTopologyProfile::Exclusive(ExclusiveProofStage::NativeWide) => Some(1),
        ProofTopologyProfile::Exclusive(ExclusiveProofStage::NativeB255) => Some(2),
        _ => None,
    }
}

fn profile_compatible(state: &AdmissionState, profile: ProofTopologyProfile) -> bool {
    if state.exclusive.is_some() {
        return false;
    }
    match profile {
        ProofTopologyProfile::NativeB8 => !state.native_b8,
        ProofTopologyProfile::SelectedSmall => !state.selected_small,
        ProofTopologyProfile::Exclusive(_) => !state.native_b8 && !state.selected_small,
    }
}

fn activate_profile(state: &mut AdmissionState, profile: ProofTopologyProfile) {
    match profile {
        ProofTopologyProfile::NativeB8 => {
            debug_assert!(!state.native_b8);
            state.native_b8 = true;
        }
        ProofTopologyProfile::SelectedSmall => {
            debug_assert!(!state.selected_small);
            state.selected_small = true;
        }
        ProofTopologyProfile::Exclusive(stage) => {
            debug_assert!(state.exclusive.is_none());
            state.exclusive = Some(stage);
        }
    }
}

fn deactivate_profile(state: &mut AdmissionState, profile: ProofTopologyProfile) {
    match profile {
        ProofTopologyProfile::NativeB8 => {
            debug_assert!(state.native_b8);
            state.native_b8 = false;
        }
        ProofTopologyProfile::SelectedSmall => {
            debug_assert!(state.selected_small);
            state.selected_small = false;
        }
        ProofTopologyProfile::Exclusive(stage) => {
            debug_assert_eq!(state.exclusive, Some(stage));
            state.exclusive = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_gate_exposes_the_full_native_ladder() {
        let gate = ProofTopologyGate::for_tests();
        assert_eq!(gate.max_user_txs_now(), 255);
        assert!(gate
            .try_admit_native_user_txs(0)
            .expect("coinbase-only admission")
            .is_none());
    }

    #[test]
    fn only_native_b8_and_selected_small_overlap_in_both_orders() {
        let gate = ProofTopologyGate::for_tests();
        let native = gate
            .try_admit_native_user_txs(8)
            .expect("native B8 admission")
            .expect("native reservation");
        let selected = gate
            .try_admit_selected_history_session(64)
            .expect("selected-small admission");
        assert_eq!(gate.max_user_txs_now(), 0);
        assert!(matches!(
            gate.try_admit_native_user_txs(1),
            Err(ProofTopologyAdmissionError::Busy)
        ));
        assert!(matches!(
            gate.try_admit_selected_history_session(8),
            Err(ProofTopologyAdmissionError::Busy)
        ));
        drop(selected);
        drop(native);

        let selected = gate
            .try_admit_selected_history_session(8)
            .expect("selected-small first");
        assert_eq!(gate.max_user_txs_now(), 8);
        let native = gate
            .try_admit_native_user_txs(1)
            .expect("native B8 second")
            .expect("native reservation");
        drop(native);
        drop(selected);
    }

    #[test]
    fn wide_native_and_selected_b255_profiles_are_exclusive() {
        let gate = ProofTopologyGate::for_tests();
        for user_txs in [9, 65] {
            let native = gate
                .try_admit_native_user_txs(user_txs)
                .expect("exclusive native admission")
                .expect("native reservation");
            assert!(matches!(
                gate.try_admit_selected_history_session(8),
                Err(ProofTopologyAdmissionError::Busy)
            ));
            drop(native);
        }

        let selected = gate
            .try_admit_selected_history_session(255)
            .expect("selected B255 admission");
        assert!(matches!(
            gate.try_admit_native_user_txs(1),
            Err(ProofTopologyAdmissionError::Busy)
        ));
        drop(selected);
    }

    #[test]
    fn standalone_terminal_and_prewarm_stages_exclude_every_lane() {
        let gate = ProofTopologyGate::for_tests();
        for stage in [
            ExclusiveProofStage::StandaloneRecursive,
            ExclusiveProofStage::TerminalVerification,
            ExclusiveProofStage::StartupPrewarm,
        ] {
            let exclusive = gate
                .try_admit_profile(ProofTopologyProfile::Exclusive(stage))
                .expect("exclusive admission");
            assert!(matches!(
                gate.try_admit_native_user_txs(1),
                Err(ProofTopologyAdmissionError::Busy)
            ));
            assert!(matches!(
                gate.try_admit_selected_history_session(8),
                Err(ProofTopologyAdmissionError::Busy)
            ));
            drop(exclusive);
        }
    }

    #[test]
    fn native_reservation_narrowing_is_atomic_and_never_upgrades() {
        let gate = ProofTopologyGate::for_tests();
        let native_b255 = gate
            .try_admit_native_user_txs(255)
            .expect("native B255 admission")
            .expect("native reservation");
        let native_b8 = native_b255
            .narrow_for_native_user_txs(1)
            .expect("safe narrowing")
            .expect("tx-bearing reservation");
        let selected = gate
            .try_admit_selected_history_session(64)
            .expect("narrowing opens the approved overlap");
        assert!(native_b8.narrow_for_native_user_txs(255).is_err());
        drop(selected);
    }

    #[test]
    fn reservations_release_on_drop_and_unwind() {
        let gate = ProofTopologyGate::for_tests();
        let unwind_gate = gate.clone();
        let unwound = std::panic::catch_unwind(move || {
            let _selected = unwind_gate
                .try_admit_selected_history_session(64)
                .expect("selected-small before panic");
            panic!("synthetic proof worker panic");
        });
        assert!(unwound.is_err());
        drop(
            gate.try_admit_selected_history_session(255)
                .expect("unwind released the selected lane"),
        );
    }

    #[test]
    fn noncanonical_requests_are_not_reported_as_contention() {
        let gate = ProofTopologyGate::for_tests();
        assert!(matches!(
            gate.try_admit_native_user_txs(256),
            Err(ProofTopologyAdmissionError::NonCanonicalNativeUserTxCount { user_txs: 256 })
        ));
        assert!(matches!(
            gate.try_admit_recursive_tier(16),
            Err(ProofTopologyAdmissionError::NonCanonicalRecursiveTier { tier: 16 })
        ));
        assert!(matches!(
            gate.try_admit_selected_history_session(16),
            Err(ProofTopologyAdmissionError::NonCanonicalRecursiveTier { tier: 16 })
        ));
    }
}
