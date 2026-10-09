// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Single-writer commit admission for immutable synchronization plans.

use std::fmt;

use super::{
    sync_plan::{SyncPlan, SyncPlanKind},
    types::{ChainPoint, PlanId},
};

/// Non-cloneable ticket tying a future atomic write to the chain generation
/// that was observed when admission began.
#[derive(Debug)]
pub struct CommitTicket {
    plan_id: PlanId,
    kind: SyncPlanKind,
    base: ChainPoint,
    old_tip: Option<ChainPoint>,
    target: ChainPoint,
    generation: u64,
}

impl CommitTicket {
    pub const fn plan_id(&self) -> PlanId {
        self.plan_id
    }

    pub const fn target(&self) -> ChainPoint {
        self.target
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitAdmissionError {
    Busy,
    StaleBase,
    CandidateNoLongerWins,
    WrongTicket,
}

#[derive(Debug)]
pub enum CommitError<E> {
    Admission(CommitAdmissionError),
    AtomicWrite(E),
}

impl<E: fmt::Display> fmt::Display for CommitError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admission(error) => write!(formatter, "commit admission failed: {error:?}"),
            Self::AtomicWrite(error) => write!(formatter, "atomic chain write failed: {error}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for CommitError<E> {}

/// Serializes the final recheck and database mutation. Consensus verification
/// remains in `noid_chain`; this state machine prevents stale verified work
/// from being committed after the base view changes.
pub struct ChainCommitter {
    committed_tip: ChainPoint,
    generation: u64,
    active_plan: Option<PlanId>,
}

impl ChainCommitter {
    pub const fn new(committed_tip: ChainPoint) -> Self {
        Self {
            committed_tip,
            generation: 0,
            active_plan: None,
        }
    }

    pub fn begin(&mut self, plan: &SyncPlan) -> Result<CommitTicket, CommitAdmissionError> {
        if self.active_plan.is_some() {
            return Err(CommitAdmissionError::Busy);
        }
        let base_matches = match plan.kind() {
            SyncPlanKind::LiveSuffix => plan.base() == self.committed_tip,
            SyncPlanKind::Reorg => plan.old_tip() == Some(self.committed_tip),
            // Snapshot installation replaces a pre-authenticated state view;
            // its storage path performs the exact boundary/genesis recheck.
            SyncPlanKind::Snapshot => true,
        };
        if !base_matches {
            return Err(CommitAdmissionError::StaleBase);
        }
        self.active_plan = Some(plan.id());
        Ok(CommitTicket {
            plan_id: plan.id(),
            kind: plan.kind(),
            base: plan.base(),
            old_tip: plan.old_tip(),
            target: plan.target(),
            generation: self.generation,
        })
    }

    /// Execute the storage layer's one atomic transaction only after all
    /// mutable admission facts have been rechecked under the writer boundary.
    pub fn commit<T, E>(
        &mut self,
        ticket: CommitTicket,
        candidate_still_wins: bool,
        atomic_write: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, CommitError<E>> {
        if self.active_plan != Some(ticket.plan_id) {
            return Err(CommitError::Admission(CommitAdmissionError::WrongTicket));
        }
        let base_matches = ticket.generation == self.generation
            && match ticket.kind {
                SyncPlanKind::LiveSuffix => ticket.base == self.committed_tip,
                SyncPlanKind::Reorg => ticket.old_tip == Some(self.committed_tip),
                SyncPlanKind::Snapshot => true,
            };
        if !base_matches {
            self.active_plan = None;
            return Err(CommitError::Admission(CommitAdmissionError::StaleBase));
        }
        if !candidate_still_wins {
            self.active_plan = None;
            return Err(CommitError::Admission(
                CommitAdmissionError::CandidateNoLongerWins,
            ));
        }

        let result = match atomic_write() {
            Ok(result) => result,
            Err(error) => {
                self.active_plan = None;
                return Err(CommitError::AtomicWrite(error));
            }
        };
        self.committed_tip = ticket.target;
        self.generation = self.generation.saturating_add(1);
        self.active_plan = None;
        Ok(result)
    }

    pub fn abort(&mut self, ticket: CommitTicket) -> Result<(), CommitAdmissionError> {
        if self.active_plan != Some(ticket.plan_id) {
            return Err(CommitAdmissionError::WrongTicket);
        }
        self.active_plan = None;
        Ok(())
    }

    /// Shadow mode and external database recovery use this when another
    /// authoritative writer commits before a prepared plan reaches admission.
    pub fn observe_committed_tip(&mut self, tip: ChainPoint) {
        if tip != self.committed_tip {
            self.committed_tip = tip;
            self.generation = self.generation.saturating_add(1);
        }
    }

    pub const fn committed_tip(&self) -> ChainPoint {
        self.committed_tip
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header_dag::ValidatedHeader;
    use noid_chain::{
        block_header::{block_id, BlockHeader},
        consensus::genesis_header,
    };

    fn child(parent: BlockHeader, nonce: u128, work: u8) -> ValidatedHeader {
        let mut header = parent;
        header.prev_block_hash = block_id(&parent);
        header.height += 1;
        header.timestamp += 1;
        header.nonce = nonce;
        ValidatedHeader::new_after_consensus_checks(header, [work; 32])
    }

    #[test]
    fn stale_base_cannot_reach_atomic_write() {
        let genesis = genesis_header();
        let base = ChainPoint::new(0, block_id(&genesis));
        let first = child(genesis, 1, 2);
        let plan = SyncPlan::live_suffix(base, vec![first], 0).unwrap();
        let mut committer = ChainCommitter::new(base);
        let ticket = committer.begin(&plan).unwrap();
        committer.observe_committed_tip(ChainPoint::new(1, [9; 32]));
        let mut called = false;
        let result = committer.commit(ticket, true, || {
            called = true;
            Ok::<_, ()>(())
        });
        assert!(matches!(
            result,
            Err(CommitError::Admission(CommitAdmissionError::StaleBase))
        ));
        assert!(!called);
    }

    #[test]
    fn failed_atomic_write_preserves_the_old_tip() {
        let genesis = genesis_header();
        let base = ChainPoint::new(0, block_id(&genesis));
        let first = child(genesis, 1, 2);
        let plan = SyncPlan::live_suffix(base, vec![first], 0).unwrap();
        let mut committer = ChainCommitter::new(base);
        let ticket = committer.begin(&plan).unwrap();
        let result = committer.commit(ticket, true, || Err::<(), _>("disk failure"));
        assert!(matches!(
            result,
            Err(CommitError::AtomicWrite("disk failure"))
        ));
        assert_eq!(committer.committed_tip(), base);
    }

    #[test]
    fn successful_atomic_write_advances_once() {
        let genesis = genesis_header();
        let base = ChainPoint::new(0, block_id(&genesis));
        let first = child(genesis, 1, 2);
        let target = first.point();
        let plan = SyncPlan::live_suffix(base, vec![first], 0).unwrap();
        let mut committer = ChainCommitter::new(base);
        let ticket = committer.begin(&plan).unwrap();
        assert_eq!(
            committer.commit(ticket, true, || Ok::<_, ()>(7)).unwrap(),
            7
        );
        assert_eq!(committer.committed_tip(), target);
        assert_eq!(committer.generation(), 1);
    }
}
