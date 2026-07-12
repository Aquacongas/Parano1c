// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical selected-ZK Block input boundary shared by Block and split-Link.
//!
//! The former monolithic recursive Link implementation lived in this module.
//! Production recursion is [`super::split_link`]; retaining the old Link class
//! would also retain the rejected transparent authorization builder.  Only the
//! direct accumulator layout and the consuming selected Block input remain.

use noid_chain::consensus::params::user_tx_class_tier;
use noid_gkr::zk_authorization::ZkAuthorizationProof;
use noid_ivc_core::field::F128;

use super::trace::flat_of;
use super::trace::zk_authorization_candidate::SelectedZkAuthorizationProofBundle;
use crate::accumulator::{ChainAccumulator, CHAIN_ACCUMULATOR_LANES};
use crate::block_certificate_backend::{
    AcceptedBlockBatchComponentInputs, AcceptedBlockBatchComponentProof,
};

/// The canonical direct accumulator-boundary lane count.
pub const ACC_LANES: usize = CHAIN_ACCUMULATOR_LANES;

/// The block chain accumulator as flat IO lanes, in consensus layout order.
pub(crate) fn block_acc_lanes(accumulator: &ChainAccumulator) -> [F128; ACC_LANES] {
    accumulator.to_lanes().map(flat_of)
}

/// Borrowed native inputs consumed by the canonical selected Block builder.
///
/// This carrier is private to the acceptance implementation.  Callers can
/// construct it only through [`SelectedZkBlockInput::try_new`], which fixes
/// the class tier and requires ownership of the complete ZK proof bundle.
pub(in crate::acceptance) struct LinkBlock<'a> {
    pub(in crate::acceptance) start_accumulator: &'a ChainAccumulator,
    pub(in crate::acceptance) end_accumulator: &'a ChainAccumulator,
    pub(in crate::acceptance) inputs: &'a AcceptedBlockBatchComponentInputs,
    pub(in crate::acceptance) proof: &'a AcceptedBlockBatchComponentProof,
}

/// Owned, consuming authorization carrier for one canonical Block class.
///
/// It has no transparent proof field, optional backend, serde form, clone, default,
/// setter, or raw proof extractor.  The bundle is consumed exactly once by
/// matrix freeze or witness assembly.
#[must_use = "selected input must be consumed by a production Block build"]
pub struct SelectedZkBlockInput<'a, const TIER: usize> {
    block: LinkBlock<'a>,
    authorization: SelectedZkAuthorizationProofBundle,
}

/// Structural rejection at the canonical production input boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectedZkBlockInputError {
    NonCanonicalTier {
        tier: usize,
    },
    AuthorizationProofCardinality {
        expected: usize,
        actual: usize,
    },
    WrongTier {
        expected_tier: usize,
        live_authorizations: usize,
        actual_tier: Option<usize>,
    },
}

impl core::fmt::Display for SelectedZkBlockInputError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NonCanonicalTier { tier } => {
                write!(formatter, "selected input tier B{tier} is not canonical")
            }
            Self::AuthorizationProofCardinality { expected, actual } => write!(
                formatter,
                "selected authorization proof count {actual} does not match canonical live count {expected}"
            ),
            Self::WrongTier {
                expected_tier,
                live_authorizations,
                actual_tier,
            } => write!(
                formatter,
                "selected B{expected_tier} input has {live_authorizations} live authorizations (tier {actual_tier:?})"
            ),
        }
    }
}

impl std::error::Error for SelectedZkBlockInputError {}

impl<'a, const TIER: usize> SelectedZkBlockInput<'a, TIER> {
    /// Bind the canonical retained component to one complete selected-ZK proof
    /// set.  The Block builder subsequently verifies all live proofs and the
    /// one canonical ghost proof before minting its private capability.
    pub fn try_new(
        start_accumulator: &'a ChainAccumulator,
        end_accumulator: &'a ChainAccumulator,
        inputs: &'a AcceptedBlockBatchComponentInputs,
        proof: &'a AcceptedBlockBatchComponentProof,
        live_proofs: Vec<ZkAuthorizationProof>,
        ghost_proof: ZkAuthorizationProof,
    ) -> Result<Self, SelectedZkBlockInputError> {
        if crate::region_sidecar::selected_zk_block_geometry(TIER).is_none() {
            return Err(SelectedZkBlockInputError::NonCanonicalTier { tier: TIER });
        }
        let live_authorizations = inputs.authorization_inputs.len();
        if live_proofs.len() != live_authorizations {
            return Err(SelectedZkBlockInputError::AuthorizationProofCardinality {
                expected: live_authorizations,
                actual: live_proofs.len(),
            });
        }
        let actual_tier = user_tx_class_tier(live_authorizations);
        if actual_tier != Some(TIER) {
            return Err(SelectedZkBlockInputError::WrongTier {
                expected_tier: TIER,
                live_authorizations,
                actual_tier,
            });
        }

        Ok(Self {
            block: LinkBlock {
                start_accumulator,
                end_accumulator,
                inputs,
                proof,
            },
            authorization: SelectedZkAuthorizationProofBundle::new(live_proofs, ghost_proof),
        })
    }

    pub(in crate::acceptance) fn into_parts(
        self,
    ) -> (LinkBlock<'a>, SelectedZkAuthorizationProofBundle) {
        (self.block, self.authorization)
    }
}

pub type SelectedZkB8BlockInput<'a> = SelectedZkBlockInput<'a, 8>;
pub type SelectedZkB32BlockInput<'a> = SelectedZkBlockInput<'a, 32>;
pub type SelectedZkB64BlockInput<'a> = SelectedZkBlockInput<'a, 64>;
pub type SelectedZkB255BlockInput<'a> = SelectedZkBlockInput<'a, 255>;
pub type SelectedZkB255BlockInputError = SelectedZkBlockInputError;

#[cfg(feature = "selected-zk-measurement")]
pub type SelectedZkB255MeasurementInput<'a> = SelectedZkB255BlockInput<'a>;

#[cfg(feature = "selected-zk-measurement")]
pub type SelectedZkB255MeasurementInputError = SelectedZkBlockInputError;
