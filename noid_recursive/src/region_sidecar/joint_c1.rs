// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! One genuine C1 History sidecar transcript shared by Link and Block.
//!
//! Link's three prefixes are derived on the outer post-commit channel. That
//! channel then samples the seed of Block's child channel. The child proves
//! one ordered nine-instance walk over Link followed by Block and completes
//! Block's six suffixes. Its terminal digest is absorbed back into the outer
//! channel before Link's three suffixes. Thus every algebraic challenge and
//! proof message lives in GF(2^256), while the nine committed Poseidon state
//! tables remain in GF(2^128).

use noid_ivc_core::challenger::{Challenger, FsLaneChallenger};
use noid_ivc_core::deep_chain::c1::{
    prove_ragged_deep_chain_walk, verify_ragged_deep_chain_walk, C1LaneClaimGroup,
    C1MultiDeepChainWalkProof,
};
use noid_ivc_core::field::F128;
use noid_ivc_core::pcs::C1QuirkyDirectClaim;
use serde::{Deserialize, Serialize};

use super::block::{
    verify_c1_block_region_walk_deferred_prefix, BlockRegionProverPlan, BlockRegionSidecarVk,
    C1BlockRegionWalkDeferredProof, BLOCK_SIDECAR_CHILD_DOMAIN, BLOCK_SIDECAR_RECORDED_LABEL,
};
use super::link::{
    verify_c1_link_region_walk_deferred_prefix, C1LinkRegionWalkDeferredProof,
    LinkRegionProverPlan, LinkRegionSidecarVk,
};
use super::RegionSidecarError;

pub(crate) const JOINT_C1_SIDECAR_VERSION: u8 = 1;
const JOINT_C1_TRANSCRIPT_LABEL: &[u8] = b"history-region-sidecar-joint-c1-v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct JointC1RegionSidecarProof {
    version: u8,
    link: C1LinkRegionWalkDeferredProof,
    block: C1BlockRegionWalkDeferredProof,
    walk: C1MultiDeepChainWalkProof,
}

impl JointC1RegionSidecarProof {
    pub(crate) fn byte_len(&self) -> usize {
        bincode::serialized_size(self).expect("joint C1 sidecar serialized length") as usize
    }
}

pub(crate) fn prove_joint_c1_region_sidecar<Ch: Challenger>(
    link_plan: &LinkRegionProverPlan<'_>,
    block_plan: &BlockRegionProverPlan<'_>,
    witness: &[F128],
    outer: &mut Ch,
) -> Result<(JointC1RegionSidecarProof, Vec<C1QuirkyDirectClaim>), RegionSidecarError> {
    let timing = std::env::var_os("NOIDH_C1_JOINT_TIMING").is_some();
    let mut stage = std::time::Instant::now();
    let lap = |label: &str, stage: &mut std::time::Instant| {
        if timing {
            eprintln!(
                "[joint-c1-sidecar] {label}: {:.1} ms",
                stage.elapsed().as_secs_f64() * 1e3
            );
        }
        *stage = std::time::Instant::now();
    };
    outer.observe_label(JOINT_C1_TRANSCRIPT_LABEL);

    let link_prefix = link_plan.prove_c1_walk_deferred_prefix(witness, outer)?;
    let link_groups = link_prefix.groups();
    let link_states = link_prefix.states();
    lap("Link prefixes", &mut stage);

    outer.observe_label(BLOCK_SIDECAR_RECORDED_LABEL);
    let seed = outer.sample_f256();
    let mut child = FsLaneChallenger::new_c1(BLOCK_SIDECAR_CHILD_DOMAIN);
    child.observe_f256(seed);

    let block_prefix = block_plan.prove_c1_walk_deferred_prefix(witness, &mut child)?;
    let block_groups = block_prefix.groups();
    let block_states = block_prefix.states();
    lap("Block prefixes", &mut stage);

    let groups = link_groups
        .iter()
        .chain(&block_groups)
        .cloned()
        .collect::<Vec<_>>();
    let states = link_states
        .into_iter()
        .chain(block_states)
        .collect::<Vec<_>>();
    let (walk, terminals) = prove_ragged_deep_chain_walk(&states, &groups, &mut child);
    lap("nine-child walk", &mut stage);
    let mut terminals = terminals.into_iter();
    let link_terminals: [C1LaneClaimGroup; 3] =
        std::array::from_fn(|_| terminals.next().expect("three Link walk terminals"));
    let block_terminals: [C1LaneClaimGroup; 6] =
        std::array::from_fn(|_| terminals.next().expect("six Block walk terminals"));
    assert!(terminals.next().is_none(), "nine joint walk terminals");

    let (block, mut claims) = block_prefix.finish(&block_terminals, &mut child)?;
    lap("Block suffixes", &mut stage);
    let tail = child.sample_f256();
    outer.observe_f256(tail);
    let (link, link_claims) = link_prefix.finish(&link_terminals, outer)?;
    claims.extend(link_claims);
    lap("Link suffixes", &mut stage);

    Ok((
        JointC1RegionSidecarProof {
            version: JOINT_C1_SIDECAR_VERSION,
            link,
            block,
            walk,
        },
        claims,
    ))
}

pub(crate) fn verify_joint_c1_region_sidecar<Ch: Challenger>(
    link_vk: &LinkRegionSidecarVk,
    block_vk: &BlockRegionSidecarVk,
    total_vars: usize,
    proof: &JointC1RegionSidecarProof,
    outer: &mut Ch,
) -> Result<Vec<C1QuirkyDirectClaim>, RegionSidecarError> {
    let timing = std::env::var_os("NOIDH_C1_VERIFY_TIMING").is_some();
    let total_started = std::time::Instant::now();
    if proof.version != JOINT_C1_SIDECAR_VERSION {
        return Err(RegionSidecarError::UnsupportedVersion);
    }
    outer.observe_label(JOINT_C1_TRANSCRIPT_LABEL);

    let link_prefix =
        verify_c1_link_region_walk_deferred_prefix(link_vk, total_vars, &proof.link, outer)?;
    let link_micros = total_started.elapsed().as_micros();
    let link_groups = link_prefix.groups();

    outer.observe_label(BLOCK_SIDECAR_RECORDED_LABEL);
    let seed = outer.sample_f256();
    let mut child = FsLaneChallenger::new_c1(BLOCK_SIDECAR_CHILD_DOMAIN);
    child.observe_f256(seed);

    let block_started = std::time::Instant::now();
    let block_prefix = verify_c1_block_region_walk_deferred_prefix(
        block_vk,
        total_vars,
        &proof.block,
        &mut child,
    )?;
    let block_micros = block_started.elapsed().as_micros();
    let block_groups = block_prefix.groups();
    let groups = link_groups
        .iter()
        .chain(&block_groups)
        .cloned()
        .collect::<Vec<_>>();
    let w_logs = groups
        .iter()
        .map(|group| group.point.len())
        .collect::<Vec<_>>();
    let walk_started = std::time::Instant::now();
    let terminals = verify_ragged_deep_chain_walk(&w_logs, &groups, &proof.walk, &mut child)
        .map_err(|_| RegionSidecarError::InvalidProof)?;
    let walk_micros = walk_started.elapsed().as_micros();
    let mut terminals = terminals.into_iter();
    let link_terminals: [C1LaneClaimGroup; 3] =
        std::array::from_fn(|_| terminals.next().expect("three Link walk terminals"));
    let block_terminals: [C1LaneClaimGroup; 6] =
        std::array::from_fn(|_| terminals.next().expect("six Block walk terminals"));
    if terminals.next().is_some() {
        return Err(RegionSidecarError::InvalidProof);
    }

    let block_finish_started = std::time::Instant::now();
    let mut claims = block_prefix.finish(&block_terminals, &mut child)?;
    let block_finish_micros = block_finish_started.elapsed().as_micros();
    let handoff_started = std::time::Instant::now();
    let tail = child.sample_f256();
    outer.observe_f256(tail);
    let handoff_micros = handoff_started.elapsed().as_micros();
    let link_finish_started = std::time::Instant::now();
    claims.extend(link_prefix.finish(&link_terminals, outer)?);
    let link_finish_micros = link_finish_started.elapsed().as_micros();
    if timing {
        eprintln!(
            "[joint-c1 verify] link_us={link_micros} block_us={block_micros} walk_us={walk_micros} block_finish_us={block_finish_micros} handoff_us={handoff_micros} link_finish_us={link_finish_micros} total_us={}",
            total_started.elapsed().as_micros(),
        );
    }
    Ok(claims)
}
