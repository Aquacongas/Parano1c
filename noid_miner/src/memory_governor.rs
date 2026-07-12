// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Process-local admission control for memory-heavy block proof jobs.
//!
//! The prover is deliberately admitted before a template enters the blocking
//! worker pool.  This keeps memory pressure out of Tokio's unbounded blocking
//! queue and makes a low-memory node mine a smaller canonical block class (or
//! a coinbase-only block) instead of starting a proof that will swap or OOM.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, OnceLock,
};

/// Conservative process-HWM envelopes for the frozen proof classes.
///
/// These are scheduler parameters, not consensus constants.  They round the
/// measured m22/m23/m24 process peaks upward to leave allocator and template
/// headroom.  A new measured proof shape must update this table before it is
/// enabled in the production miner.
const B8_PEAK_MIB: usize = 2 * 1024;
const B32_B64_PEAK_MIB: usize = 4 * 1024;
const B255_PEAK_MIB: usize = 8 * 1024;
/// Every production Split-Link class is m24.  The phased coordinator keeps
/// only one transient fold matrix resident, but trace assembly/proving still
/// requires the measured m24 admission envelope.
const RECURSIVE_LINK_PEAK_MIB: usize = B255_PEAK_MIB;
/// A selected-history session spans artifact reconstruction, one selected
/// Block proof, and its following Link proof.  Its admission must therefore
/// cover the largest phase for the entire sequence, regardless of Block tier.
const SELECTED_HISTORY_SESSION_PEAK_MIB: usize = RECURSIVE_LINK_PEAK_MIB;
/// Hard-cap-derived envelope for materializing one pinned compact recursive
/// class registry.  This is deliberately much larger than the <=4 MiB wire
/// artifact because Rust's checked in-memory representation expands fixed
/// tables and transcript schedules:
///
/// - 4 MiB for the exact artifact bytes;
/// - 16 MiB for at most 64 * 8192 `Option<u128>` schedule lanes;
/// - 28 MiB for seven 64 * 4096 combined-duplex fixed tables;
/// - 256 MiB for the largest permitted Merkle-key validation phase: two
///   2^22-cell F128 fixed-table sets plus the digest encoder's conservatively
///   rounded 128 MiB capacity;
/// - 64 MiB for the bounded genesis envelope, canonical Block keys, decoded
///   wire carriers, vector metadata, and allocator rounding.
///
/// Every multiplicand above is fixed by a codec or region-VK preflight cap.
/// The final 64 MiB is larger than the complete 1 MiB genesis wire budget and
/// all four canonical Block-key fixed tables combined.  Full registry loading
/// is a prover-only operation and must remain inside the owning 8 GiB proof
/// session; ordinary terminal verification uses the separate bound below.
pub const SELECTED_RECURSIVE_REGISTRY_MATERIALIZATION_PEAK_MIB: usize = 368;
/// Hard bound for the terminal-only registry loader.  Its allocation-free
/// preflight admits only the frozen four-subchannel/four-family Link topology,
/// and its materializer never constructs a Block VK:
///
/// - 4 MiB exact pinned artifact cap;
/// - 4 MiB decoded compact carriers while the artifact bytes are still live;
/// - 1 MiB canonical Link VK fixed tables and digest encoders (the exact
///   topology has 448 combined-duplex and 3,072 Merkle F128 fixed cells);
/// - 32 MiB for the allocation-safe <=1 MiB serialized genesis envelope and
///   its bounded proof representation;
/// - 7 MiB allocator/vector-metadata rounding.
///
/// The full 368 MiB loader remains unchanged for prover roles.
pub const SELECTED_RECURSIVE_TERMINAL_REGISTRY_MATERIALIZATION_PEAK_MIB: usize = 48;
/// Matrix replay itself is streaming: two bounded coefficient/scratch buffers
/// and factorized equality tables remain within this independent allowance.
pub const SELECTED_HISTORY_TERMINAL_STREAMING_PEAK_MIB: usize = 16;
/// Complete ordinary-node terminal-verification admission.  A node reserves
/// this before reading/materializing the pinned registry and retains it through
/// sequential disk-backed matrix replay; no CSR matrix is charged or resident.
pub const SELECTED_HISTORY_TERMINAL_VERIFY_PEAK_MIB: usize =
    SELECTED_RECURSIVE_TERMINAL_REGISTRY_MATERIALIZATION_PEAK_MIB
        + SELECTED_HISTORY_TERMINAL_STREAMING_PEAK_MIB;

/// Never let proof admission consume the complete host-visible allowance.
const MIN_NODE_RESERVE_MIB: usize = 1024;
const NODE_RESERVE_DIVISOR: usize = 4;

#[derive(Debug)]
struct Inner {
    configured_budget_mib: usize,
    reserved_mib: AtomicUsize,
    active_jobs: AtomicUsize,
}

static GLOBAL_PROOF_MEMORY_GOVERNOR: OnceLock<ProofMemoryGovernor> = OnceLock::new();

/// Shared byte-budget gate for every block-proof worker in the node process.
///
/// Clones share one atomic reservation ledger. Admission is non-blocking:
/// callers either receive an owning reservation or apply backpressure before
/// submitting work to a blocking executor.
#[derive(Clone, Debug)]
pub(crate) struct ProofMemoryGovernor {
    inner: Arc<Inner>,
}

/// Owning proof-memory reservation. Dropping it releases the budget even when
/// the proof returns an error or its async join handle is abandoned.
#[derive(Debug)]
pub(crate) struct ProofMemoryReservation {
    inner: Arc<Inner>,
    reserved_mib: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProofMemoryPressure {
    pub required_mib: usize,
    pub available_mib: usize,
}

impl ProofMemoryGovernor {
    /// `configured_budget_mib == 0` selects an automatic host-aware ceiling.
    pub(crate) fn new(configured_budget_mib: usize) -> Self {
        let configured_budget_mib = if configured_budget_mib == 0 {
            automatic_budget_mib(system_available_memory_mib())
        } else {
            configured_budget_mib.min(B255_PEAK_MIB)
        };
        Self {
            inner: Arc::new(Inner {
                configured_budget_mib,
                reserved_mib: AtomicUsize::new(0),
                active_jobs: AtomicUsize::new(0),
            }),
        }
    }

    /// Process-wide proof admission ledger shared by the internal miner and
    /// external-mining RPC. The first production entrypoint fixes the local
    /// ceiling; subsequent callers join the same ledger.
    pub(crate) fn global(configured_budget_mib: usize) -> Self {
        GLOBAL_PROOF_MEMORY_GOVERNOR
            .get_or_init(|| Self::new(configured_budget_mib))
            .clone()
    }

    pub(crate) fn configured_budget_mib(&self) -> usize {
        self.inner.configured_budget_mib
    }

    /// Largest canonical transaction tier admissible under current host
    /// pressure. Zero means that only a coinbase-only template may start.
    pub(crate) fn max_user_txs_now(&self) -> usize {
        self.max_user_txs_with_available(system_available_memory_mib())
    }

    fn max_user_txs_with_available(&self, available_mib: Option<usize>) -> usize {
        if self.inner.active_jobs.load(Ordering::Acquire) != 0 {
            return 0;
        }
        let free_budget = self
            .effective_budget_mib(available_mib)
            .saturating_sub(self.inner.reserved_mib.load(Ordering::Acquire));
        [
            (255, B255_PEAK_MIB),
            (64, B32_B64_PEAK_MIB),
            (32, B32_B64_PEAK_MIB),
            (8, B8_PEAK_MIB),
        ]
        .into_iter()
        .find_map(|(tier, required)| (required <= free_budget).then_some(tier))
        .unwrap_or(0)
    }

    /// Reserve the complete class envelope before queueing a proof job.
    pub(crate) fn try_reserve_for_user_txs(
        &self,
        user_txs: usize,
    ) -> Result<Option<ProofMemoryReservation>, ProofMemoryPressure> {
        self.try_reserve_with_available(user_txs, system_available_memory_mib())
    }

    /// Reserve one recursive selected Block class by its canonical tier.
    ///
    /// This is deliberately separate from native block-certificate admission:
    /// a coinbase-only native block needs no expensive proof, while its
    /// recursive representation is still B8/m22 and must reserve the complete
    /// B8 envelope before entering the blocking worker pool.
    pub(crate) fn try_reserve_for_recursive_tier(
        &self,
        tier: usize,
    ) -> Result<ProofMemoryReservation, ProofMemoryPressure> {
        let required_mib = recursive_proof_peak_mib(tier).unwrap_or(usize::MAX);
        self.try_reserve_required_mib(required_mib, system_available_memory_mib())
    }

    /// Reserve one universal m24 Split-Link proof. Matrix residency inside the
    /// job is sequential, but Link trace construction remains an m24 worker
    /// and therefore shares the process-wide single-proof ledger.
    pub(crate) fn try_reserve_for_recursive_link(
        &self,
    ) -> Result<ProofMemoryReservation, ProofMemoryPressure> {
        self.try_reserve_required_mib(RECURSIVE_LINK_PEAK_MIB, system_available_memory_mib())
    }

    /// Reserve the complete m24/8 GiB envelope for one sequential selected
    /// history session.  The owning session acquires this before reconstructing
    /// accepted-block artifacts and retains it through both Block and Link.
    pub(crate) fn try_reserve_for_selected_history_session(
        &self,
    ) -> Result<ProofMemoryReservation, ProofMemoryPressure> {
        self.try_reserve_required_mib(
            SELECTED_HISTORY_SESSION_PEAK_MIB,
            system_available_memory_mib(),
        )
    }

    /// Admit bounded-memory terminal verification while excluding all native
    /// and recursive proof workers process-wide. This is intentionally not an
    /// m24 proving reservation: requiring 8 GiB here would prevent a low-RAM
    /// non-mining node from synchronizing even though matrices remain on disk.
    pub(crate) fn try_reserve_for_selected_history_terminal_verification(
        &self,
    ) -> Result<ProofMemoryReservation, ProofMemoryPressure> {
        self.try_reserve_required_mib(
            SELECTED_HISTORY_TERMINAL_VERIFY_PEAK_MIB,
            system_available_memory_mib(),
        )
    }

    fn try_reserve_with_available(
        &self,
        user_txs: usize,
        available_mib: Option<usize>,
    ) -> Result<Option<ProofMemoryReservation>, ProofMemoryPressure> {
        let Some(required_mib) = proof_peak_mib(user_txs) else {
            return Ok(None);
        };
        self.try_reserve_required_mib(required_mib, available_mib)
            .map(Some)
    }

    #[cfg(test)]
    fn try_reserve_recursive_with_available(
        &self,
        tier: usize,
        available_mib: Option<usize>,
    ) -> Result<ProofMemoryReservation, ProofMemoryPressure> {
        let required_mib = recursive_proof_peak_mib(tier).unwrap_or(usize::MAX);
        self.try_reserve_required_mib(required_mib, available_mib)
    }

    #[cfg(test)]
    pub(crate) fn try_reserve_selected_history_with_available(
        &self,
        available_mib: Option<usize>,
    ) -> Result<ProofMemoryReservation, ProofMemoryPressure> {
        self.try_reserve_required_mib(SELECTED_HISTORY_SESSION_PEAK_MIB, available_mib)
    }

    #[cfg(test)]
    pub(crate) fn try_reserve_selected_history_terminal_with_available(
        &self,
        available_mib: Option<usize>,
    ) -> Result<ProofMemoryReservation, ProofMemoryPressure> {
        self.try_reserve_required_mib(SELECTED_HISTORY_TERMINAL_VERIFY_PEAK_MIB, available_mib)
    }

    fn try_reserve_required_mib(
        &self,
        required_mib: usize,
        available_mib: Option<usize>,
    ) -> Result<ProofMemoryReservation, ProofMemoryPressure> {
        // Only single-proof HWM envelopes are currently measured. Do not infer
        // that two proofs whose estimates add up are safe to overlap: allocator
        // fragmentation and shared matrix caches make that a separate gate.
        if self
            .inner
            .active_jobs
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(ProofMemoryPressure {
                required_mib,
                available_mib: 0,
            });
        }
        let effective_budget = self.effective_budget_mib(available_mib);

        let mut reserved = self.inner.reserved_mib.load(Ordering::Acquire);
        loop {
            let available = effective_budget.saturating_sub(reserved);
            if required_mib > available {
                self.inner.active_jobs.store(0, Ordering::Release);
                return Err(ProofMemoryPressure {
                    required_mib,
                    available_mib: available,
                });
            }
            match self.inner.reserved_mib.compare_exchange_weak(
                reserved,
                reserved + required_mib,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(ProofMemoryReservation {
                        inner: Arc::clone(&self.inner),
                        reserved_mib: required_mib,
                    });
                }
                Err(actual) => reserved = actual,
            }
        }
    }

    fn effective_budget_mib(&self, available_mib: Option<usize>) -> usize {
        let pressure_ceiling = available_mib
            .map(host_safe_budget_mib)
            .unwrap_or(self.inner.configured_budget_mib);
        self.inner.configured_budget_mib.min(pressure_ceiling)
    }
}

impl Drop for ProofMemoryReservation {
    fn drop(&mut self) {
        let previous = self
            .inner
            .reserved_mib
            .fetch_sub(self.reserved_mib, Ordering::AcqRel);
        debug_assert!(previous >= self.reserved_mib);
        let previous_jobs = self.inner.active_jobs.swap(0, Ordering::AcqRel);
        debug_assert_eq!(previous_jobs, 1);
    }
}

fn proof_peak_mib(user_txs: usize) -> Option<usize> {
    match user_txs {
        0 => None,
        1..=8 => Some(B8_PEAK_MIB),
        9..=64 => Some(B32_B64_PEAK_MIB),
        65..=255 => Some(B255_PEAK_MIB),
        _ => Some(usize::MAX),
    }
}

fn recursive_proof_peak_mib(tier: usize) -> Option<usize> {
    match tier {
        8 => Some(B8_PEAK_MIB),
        32 | 64 => Some(B32_B64_PEAK_MIB),
        255 => Some(B255_PEAK_MIB),
        _ => None,
    }
}

fn automatic_budget_mib(available_mib: Option<usize>) -> usize {
    available_mib
        .map(host_safe_budget_mib)
        .unwrap_or(B8_PEAK_MIB)
        .min(B255_PEAK_MIB)
}

fn host_safe_budget_mib(available_mib: usize) -> usize {
    let reserve = MIN_NODE_RESERVE_MIB.max(available_mib / NODE_RESERVE_DIVISOR);
    available_mib.saturating_sub(reserve)
}

/// Linux exposes the amount allocatable without swapping as `MemAvailable`.
/// Restricted/non-Linux hosts fall back to the configured conservative gate.
fn system_available_memory_mib() -> Option<usize> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let kib = meminfo.lines().find_map(|line| {
        line.strip_prefix("MemAvailable:")?
            .split_whitespace()
            .next()?
            .parse::<usize>()
            .ok()
    })?;
    Some(kib / 1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_cap_steps_down_before_large_allocation() {
        let governor = ProofMemoryGovernor::new(B255_PEAK_MIB);
        assert_eq!(governor.max_user_txs_with_available(Some(16 * 1024)), 255);
        assert_eq!(governor.max_user_txs_with_available(Some(8 * 1024)), 64);
        assert_eq!(governor.max_user_txs_with_available(Some(4 * 1024)), 8);
        assert_eq!(governor.max_user_txs_with_available(Some(2 * 1024)), 0);
    }

    #[test]
    fn reservations_apply_backpressure_and_release_on_drop() {
        let governor = ProofMemoryGovernor::new(B32_B64_PEAK_MIB);
        let first = governor
            .try_reserve_with_available(8, None)
            .expect("first B8 reservation")
            .expect("non-empty proof reservation");
        assert_eq!(
            governor
                .try_reserve_with_available(1, None)
                .expect_err("overlapping proof must be rejected"),
            ProofMemoryPressure {
                required_mib: B8_PEAK_MIB,
                available_mib: 0,
            }
        );
        drop(first);
        assert!(governor.try_reserve_with_available(1, None).is_ok());
    }

    #[test]
    fn runtime_pressure_can_reject_below_configured_ceiling() {
        let governor = ProofMemoryGovernor::new(B255_PEAK_MIB);
        assert_eq!(
            governor
                .try_reserve_with_available(65, Some(8 * 1024))
                .expect_err("runtime pressure must reject B255"),
            ProofMemoryPressure {
                required_mib: B255_PEAK_MIB,
                available_mib: 6 * 1024,
            }
        );
    }

    #[test]
    fn coinbase_only_jobs_reserve_nothing() {
        let governor = ProofMemoryGovernor::new(0);
        assert!(governor
            .try_reserve_with_available(0, Some(0))
            .expect("coinbase admission")
            .is_none());
    }

    #[test]
    fn coinbase_recursive_block_still_reserves_b8() {
        let governor = ProofMemoryGovernor::new(B8_PEAK_MIB);
        let reservation = governor
            .try_reserve_recursive_with_available(8, None)
            .expect("coinbase recursive B8 admission");
        assert_eq!(
            governor
                .try_reserve_recursive_with_available(8, None)
                .expect_err("recursive proof jobs share the single-proof ledger"),
            ProofMemoryPressure {
                required_mib: B8_PEAK_MIB,
                available_mib: 0,
            }
        );
        drop(reservation);
        assert!(governor
            .try_reserve_recursive_with_available(8, None)
            .is_ok());
    }

    #[test]
    fn recursive_link_reserves_the_m24_envelope_and_excludes_overlap() {
        let governor = ProofMemoryGovernor::new(RECURSIVE_LINK_PEAK_MIB);
        let reservation = governor
            .try_reserve_required_mib(RECURSIVE_LINK_PEAK_MIB, None)
            .expect("m24 Link admission");
        assert_eq!(
            governor
                .try_reserve_for_recursive_link()
                .expect_err("Link cannot overlap another proof worker"),
            ProofMemoryPressure {
                required_mib: RECURSIVE_LINK_PEAK_MIB,
                available_mib: 0,
            }
        );
        drop(reservation);
    }

    #[test]
    fn selected_history_session_excludes_all_proof_workers_until_drop() {
        let governor = ProofMemoryGovernor::new(SELECTED_HISTORY_SESSION_PEAK_MIB);
        let session = governor
            .try_reserve_selected_history_with_available(None)
            .expect("full selected-history session admission");

        assert_eq!(
            governor
                .try_reserve_with_available(1, None)
                .expect_err("native proof cannot overlap selected history"),
            ProofMemoryPressure {
                required_mib: B8_PEAK_MIB,
                available_mib: 0,
            }
        );
        assert_eq!(
            governor
                .try_reserve_recursive_with_available(8, None)
                .expect_err("standalone Block cannot overlap selected history"),
            ProofMemoryPressure {
                required_mib: B8_PEAK_MIB,
                available_mib: 0,
            }
        );
        assert_eq!(
            governor
                .try_reserve_required_mib(RECURSIVE_LINK_PEAK_MIB, None)
                .expect_err("standalone Link cannot overlap selected history"),
            ProofMemoryPressure {
                required_mib: RECURSIVE_LINK_PEAK_MIB,
                available_mib: 0,
            }
        );

        drop(session);
        assert!(governor
            .try_reserve_recursive_with_available(8, None)
            .is_ok());
    }

    #[test]
    fn selected_history_reservation_releases_during_unwind() {
        let governor = ProofMemoryGovernor::new(SELECTED_HISTORY_SESSION_PEAK_MIB);
        let unwind_governor = governor.clone();
        let unwound = std::panic::catch_unwind(move || {
            let _session = unwind_governor
                .try_reserve_selected_history_with_available(None)
                .expect("selected-history reservation before panic");
            panic!("synthetic selected-history worker panic");
        });
        assert!(unwound.is_err());
        assert!(governor
            .try_reserve_selected_history_with_available(None)
            .is_ok());
    }

    #[test]
    fn low_memory_admits_streaming_terminal_but_not_a_prover() {
        let governor = ProofMemoryGovernor::new(B255_PEAK_MIB);
        // host_safe_budget_mib(2048) = 1024 MiB: ample for the complete
        // 64-MiB terminal-only pinned-registry + streaming verifier session,
        // but below even the smallest B8 proof envelope.
        let terminal = governor
            .try_reserve_selected_history_terminal_with_available(Some(2048))
            .expect("low-memory node must still verify terminal history");
        assert_eq!(
            governor
                .try_reserve_recursive_with_available(8, Some(2048))
                .expect_err("terminal verification excludes proof overlap"),
            ProofMemoryPressure {
                required_mib: B8_PEAK_MIB,
                available_mib: 0,
            }
        );
        drop(terminal);
        assert_eq!(
            governor
                .try_reserve_recursive_with_available(8, Some(2048))
                .expect_err("host pressure still rejects a B8 prover"),
            ProofMemoryPressure {
                required_mib: B8_PEAK_MIB,
                available_mib: 1024,
            }
        );
        drop(
            governor
                .try_reserve_selected_history_terminal_with_available(Some(2048))
                .expect("terminal RAII drop releases process-wide exclusion"),
        );
    }

    #[test]
    fn terminal_verification_reservation_releases_during_unwind() {
        let governor = ProofMemoryGovernor::new(B255_PEAK_MIB);
        let unwind_governor = governor.clone();
        let unwound = std::panic::catch_unwind(move || {
            let _terminal = unwind_governor
                .try_reserve_selected_history_terminal_with_available(Some(2048))
                .expect("streaming terminal admission before panic");
            panic!("synthetic terminal verifier panic");
        });
        assert!(unwound.is_err());
        drop(
            governor
                .try_reserve_selected_history_terminal_with_available(Some(2048))
                .expect("unwind releases terminal verification admission"),
        );
    }

    #[test]
    fn terminal_envelope_accounts_for_registry_before_streaming_scratch() {
        assert_eq!(
            SELECTED_RECURSIVE_REGISTRY_MATERIALIZATION_PEAK_MIB,
            4 + 16 + 28 + 256 + 64
        );
        assert_eq!(SELECTED_HISTORY_TERMINAL_STREAMING_PEAK_MIB, 16);
        assert_eq!(
            SELECTED_RECURSIVE_TERMINAL_REGISTRY_MATERIALIZATION_PEAK_MIB,
            4 + 4 + 1 + 32 + 7
        );
        assert_eq!(SELECTED_HISTORY_TERMINAL_VERIFY_PEAK_MIB, 64);

        let governor = ProofMemoryGovernor::new(B255_PEAK_MIB);
        assert_eq!(
            governor
                .try_reserve_selected_history_terminal_with_available(Some(1080))
                .expect_err("host reserve leaves only 56 MiB")
                .required_mib,
            SELECTED_HISTORY_TERMINAL_VERIFY_PEAK_MIB
        );
        drop(
            governor
                .try_reserve_selected_history_terminal_with_available(Some(1088))
                .expect("host reserve leaves the exact 64-MiB envelope"),
        );
    }

    #[test]
    fn recursive_reservation_rejects_noncanonical_tier() {
        let governor = ProofMemoryGovernor::new(B255_PEAK_MIB);
        assert_eq!(
            governor
                .try_reserve_recursive_with_available(16, None)
                .expect_err("noncanonical recursive class"),
            ProofMemoryPressure {
                required_mib: usize::MAX,
                available_mib: B255_PEAK_MIB,
            }
        );
    }
}
