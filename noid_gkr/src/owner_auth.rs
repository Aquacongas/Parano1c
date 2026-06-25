// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

#![allow(clippy::needless_range_loop)]
#![allow(clippy::too_many_arguments)]

//! Dynamic owner-batched AuthGKR.
//!
//! One transaction gets one AuthGKR capsule sized by canonical unique owner
//! count `k`, not by live input count `m` and not by the transaction shape.

use std::sync::OnceLock;

use noid_core::hardware::{clmul_gcm, flat_to_tower_u128, square_flat_u128, tower_to_flat_u128};
use noid_core::mle::eq::eq_ind_partial_eval;
use noid_core::mle::evaluate::{evaluate_flat, evaluate_slice};
use noid_core::packed::pow7::pow7_block128;
use noid_core::sumcheck::RoundPolynomial;
use noid_core::transcript::FiatShamir;
use noid_core::{Block128, TowerField};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_poseidon2b::native::domain::{capacity_iv, TAG_ADDRFIX};
use noid_poseidon2b::native::permutation::{
    F_ROUNDS, MDS_FULL, MDS_PARTIAL, N_ROUNDS, P_ROUNDS, ROUND_CONSTANTS, STATE_SIZE,
};
use noid_poseidon2b::primitives::{derive_address, SpendSecret};
use noid_tx::{canonical_owner_auth, CanonicalOwnerAuth, OwnerAuthError, TxBody};
use zeroize::Zeroize;

use crate::auth_pcs::{
    absorb_auth_mle_commitment, commit_auth_mle_column, open_auth_mle_committed,
    verify_auth_mle_opening, AuthMleOpeningProof,
};
use crate::batch_eval::{
    prove_batch_eval, verify_batch_eval, BatchEvalProof, BatchEvalReduction, BatchEvalRound,
    EvalClaim,
};
use crate::layers::{evaluate_permutation, PermLayerWitness, RoundKind};

pub const OWNER_AUTH_SLOTS_PER_OWNER: usize = 1;
pub const OWNER_AUTH_PIN_LANES: usize = 2;
pub const OWNER_AUTH_ROUND_VARS: usize = 7;
pub const OWNER_AUTH_ELEM_VARS: usize = 2;
pub const OWNER_AUTH_MIN_SLOT_BITS: usize = 0;
pub const OWNER_AUTH_MIN_OWNERS: usize = 1;
pub const OWNER_AUTH_MAX_OWNERS: usize = 25;

const ELEM_LO: usize = 0;
const ELEM_HI: usize = ELEM_LO + OWNER_AUTH_ELEM_VARS;
const ROUND_LO: usize = ELEM_HI;
const ROUND_HI: usize = ROUND_LO + OWNER_AUTH_ROUND_VARS;
const SLOT_LO: usize = ROUND_HI;

const ROUND_LIMIT: usize = 1 << OWNER_AUTH_ROUND_VARS;
const ELEM_LIMIT: usize = 1 << OWNER_AUTH_ELEM_VARS;
const _: () = assert!(N_ROUNDS == 66);
const _: () = assert!(STATE_SIZE == 4);
const _: () = assert!(OWNER_AUTH_ROUND_VARS == 7);
const _: () = assert!(OWNER_AUTH_ELEM_VARS == 2);

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OwnerAuthLayout {
    pub owner_count: usize,
    pub live_slots: usize,
    pub slot_bits: usize,
    pub num_vars: usize,
    pub padded_slots: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerAuthLayoutError {
    OwnerCountOutOfRange {
        actual: usize,
        min: usize,
        max: usize,
    },
}

impl std::fmt::Display for OwnerAuthLayoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for OwnerAuthLayoutError {}

impl OwnerAuthLayout {
    pub fn for_owner_count(owner_count: usize) -> Result<Self, OwnerAuthLayoutError> {
        if !(OWNER_AUTH_MIN_OWNERS..=OWNER_AUTH_MAX_OWNERS).contains(&owner_count) {
            return Err(OwnerAuthLayoutError::OwnerCountOutOfRange {
                actual: owner_count,
                min: OWNER_AUTH_MIN_OWNERS,
                max: OWNER_AUTH_MAX_OWNERS,
            });
        }
        let live_slots = owner_count * OWNER_AUTH_SLOTS_PER_OWNER;
        let slot_bits = (live_slots.next_power_of_two().trailing_zeros() as usize)
            .max(OWNER_AUTH_MIN_SLOT_BITS);
        let num_vars = slot_bits + OWNER_AUTH_ROUND_VARS + OWNER_AUTH_ELEM_VARS;
        let padded_slots = 1usize << slot_bits;
        Ok(Self {
            owner_count,
            live_slots,
            slot_bits,
            num_vars,
            padded_slots,
        })
    }

    #[inline]
    pub fn cells(self) -> usize {
        1usize << self.num_vars
    }

    #[inline]
    pub fn index(self, slot: usize, round: usize, elem: usize) -> usize {
        debug_assert!(slot < self.padded_slots);
        debug_assert!(round < ROUND_LIMIT);
        debug_assert!(elem < ELEM_LIMIT);
        (slot << (OWNER_AUTH_ROUND_VARS + OWNER_AUTH_ELEM_VARS))
            | (round << OWNER_AUTH_ELEM_VARS)
            | elem
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerAuthSlotRole {
    HAddrPerm { owner_idx: u8 },
}

impl OwnerAuthSlotRole {
    #[inline]
    pub fn owner_idx(self) -> usize {
        match self {
            OwnerAuthSlotRole::HAddrPerm { owner_idx } => owner_idx as usize,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct OwnerAuthSlotDescriptor {
    pub id: usize,
    pub role: OwnerAuthSlotRole,
    pub capacity_iv: [Block128; 2],
    pub is_head: bool,
    pub prev_output_src: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct OwnerAuthCircuit {
    pub layout: OwnerAuthLayout,
    pub slots: Vec<OwnerAuthSlotDescriptor>,
}

impl OwnerAuthCircuit {
    pub fn build(layout: OwnerAuthLayout) -> Self {
        let iv_addr = capacity_iv(TAG_ADDRFIX);
        let mut slots = Vec::with_capacity(layout.live_slots);

        for owner_idx_usize in 0..layout.owner_count {
            let owner_idx = owner_idx_usize as u8;
            let base = slots.len();
            slots.push(OwnerAuthSlotDescriptor {
                id: base,
                role: OwnerAuthSlotRole::HAddrPerm { owner_idx },
                capacity_iv: iv_addr,
                is_head: true,
                prev_output_src: None,
            });
        }
        debug_assert_eq!(slots.len(), layout.live_slots);
        Self { layout, slots }
    }

    #[inline]
    pub fn haddr_output_slot(owner_idx: usize) -> usize {
        owner_idx * OWNER_AUTH_SLOTS_PER_OWNER
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OwnerAuthPublicInputs {
    pub layout: OwnerAuthLayout,
    pub tx_body_hash: [Block128; 2],
    pub live_input_positions: Vec<usize>,
    pub live_slot_indices: Vec<u32>,
    pub input_to_group: Vec<usize>,
    pub expected_address: Vec<[Block128; 2]>,
}

impl OwnerAuthPublicInputs {
    pub fn new(
        layout: OwnerAuthLayout,
        tx_body_hash: [Block128; 2],
        live_input_positions: Vec<usize>,
        live_slot_indices: Vec<u32>,
        input_to_group: Vec<usize>,
        expected_address: Vec<[Block128; 2]>,
    ) -> Option<Self> {
        if expected_address.len() != layout.owner_count
            || live_input_positions.is_empty()
            || live_slot_indices.len() != live_input_positions.len()
            || input_to_group.len() != live_input_positions.len()
            || input_to_group
                .iter()
                .any(|&group_idx| group_idx >= layout.owner_count)
        {
            return None;
        }
        Some(Self {
            layout,
            tx_body_hash,
            live_input_positions,
            live_slot_indices,
            input_to_group,
            expected_address,
        })
    }
}

#[derive(Clone)]
pub struct OwnerAuthInputs {
    pub layout: OwnerAuthLayout,
    pub spend_secret: Vec<[Block128; 2]>,
    pub tx_body_hash: [Block128; 2],
    pub live_input_positions: Vec<usize>,
    pub live_slot_indices: Vec<u32>,
    pub input_to_group: Vec<usize>,
    pub expected_address: Vec<[Block128; 2]>,
}

impl Drop for OwnerAuthInputs {
    fn drop(&mut self) {
        self.spend_secret.zeroize();
    }
}

impl OwnerAuthInputs {
    pub fn to_public(&self) -> OwnerAuthPublicInputs {
        OwnerAuthPublicInputs {
            layout: self.layout,
            tx_body_hash: self.tx_body_hash,
            live_input_positions: self.live_input_positions.clone(),
            live_slot_indices: self.live_slot_indices.clone(),
            input_to_group: self.input_to_group.clone(),
            expected_address: self.expected_address.clone(),
        }
    }

    pub fn from_parts(public: &OwnerAuthPublicInputs, spend_secret: Vec<[Block128; 2]>) -> Self {
        Self {
            layout: public.layout,
            spend_secret,
            tx_body_hash: public.tx_body_hash,
            live_input_positions: public.live_input_positions.clone(),
            live_slot_indices: public.live_slot_indices.clone(),
            input_to_group: public.input_to_group.clone(),
            expected_address: public.expected_address.clone(),
        }
    }
}

impl std::fmt::Debug for OwnerAuthInputs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnerAuthInputs")
            .field("layout", &self.layout)
            .field("spend_secret", &"[REDACTED]")
            .field("tx_body_hash", &self.tx_body_hash)
            .field("live_input_positions", &self.live_input_positions)
            .field("live_slot_indices", &self.live_slot_indices)
            .field("input_to_group", &self.input_to_group)
            .field("expected_address", &self.expected_address)
            .finish()
    }
}

#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct OwnerAuthSlotState {
    pub state_in: [Block128; 4],
    pub state_out: [Block128; 4],
}

impl OwnerAuthSlotState {
    #[inline]
    pub fn digest(&self) -> [Block128; 2] {
        [self.state_out[0], self.state_out[1]]
    }
}

#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct OwnerAuthWitness {
    pub slots: Vec<OwnerAuthSlotState>,
    pub derived_address: Vec<[Block128; 2]>,
}

pub fn evaluate_owner_auth(
    circuit: &OwnerAuthCircuit,
    inputs: &OwnerAuthInputs,
) -> OwnerAuthWitness {
    assert_eq!(inputs.layout, circuit.layout);
    assert_eq!(inputs.spend_secret.len(), circuit.layout.owner_count);
    let perm = noid_poseidon2b::native::permutation::Poseidon2bPermutation;
    let mut slots: Vec<OwnerAuthSlotState> = Vec::with_capacity(circuit.slots.len());

    for slot in &circuit.slots {
        let state_in = build_owner_auth_state_in(slot, inputs, &slots);
        let mut state_out = state_in;
        perm.permute_mut(&mut state_out);
        slots.push(OwnerAuthSlotState {
            state_in,
            state_out,
        });
    }

    let mut derived_address = vec![[Block128::ZERO; 2]; circuit.layout.owner_count];
    for i in 0..circuit.layout.owner_count {
        derived_address[i] = slots[OwnerAuthCircuit::haddr_output_slot(i)].digest();
    }

    OwnerAuthWitness {
        slots,
        derived_address,
    }
}

#[inline]
fn build_owner_auth_state_in(
    slot: &OwnerAuthSlotDescriptor,
    inputs: &OwnerAuthInputs,
    _prev: &[OwnerAuthSlotState],
) -> [Block128; 4] {
    let [iv_hi, iv_lo] = slot.capacity_iv;
    match slot.role {
        OwnerAuthSlotRole::HAddrPerm { owner_idx } => {
            let [a, b] = inputs.spend_secret[owner_idx as usize];
            [a, b, iv_hi, iv_lo]
        }
    }
}

pub fn compute_owner_auth_boundary(
    circuit: &OwnerAuthCircuit,
    spend_secret: Vec<[Block128; 2]>,
    tx_body_hash: [Block128; 2],
) -> Vec<[Block128; 2]> {
    let inputs = OwnerAuthInputs {
        layout: circuit.layout,
        spend_secret,
        tx_body_hash,
        live_input_positions: (0..circuit.layout.owner_count).collect(),
        live_slot_indices: (0..circuit.layout.owner_count).map(|i| i as u32).collect(),
        input_to_group: (0..circuit.layout.owner_count).collect(),
        expected_address: vec![[Block128::ZERO; 2]; circuit.layout.owner_count],
    };
    let w = evaluate_owner_auth(circuit, &inputs);
    w.derived_address.clone()
}

#[derive(Debug, Clone)]
pub struct OwnerAuthUnifiedMle {
    pub layout: OwnerAuthLayout,
    pub s_in: Vec<Block128>,
    pub s_out: Vec<Block128>,
    pub sigma: Vec<Block128>,
    pub state: Vec<Block128>,
}

impl Drop for OwnerAuthUnifiedMle {
    fn drop(&mut self) {
        self.s_in.zeroize();
        self.s_out.zeroize();
        self.sigma.zeroize();
        self.state.zeroize();
    }
}

impl OwnerAuthUnifiedMle {
    pub fn zero(layout: OwnerAuthLayout) -> Self {
        let cells = layout.cells();
        Self {
            layout,
            s_in: vec![Block128::ZERO; cells],
            s_out: vec![Block128::ZERO; cells],
            sigma: vec![Block128::ZERO; cells],
            state: vec![Block128::ZERO; cells],
        }
    }

    #[inline]
    pub fn index(&self, slot: usize, round: usize, elem: usize) -> usize {
        self.layout.index(slot, round, elem)
    }

    pub fn populate_slot(&mut self, slot: usize, witness: &PermLayerWitness) {
        assert!(slot < self.layout.live_slots, "slot out of range");
        for r in 0..N_ROUNDS {
            let active_mask = match witness.kind[r] {
                RoundKind::Full => [true; STATE_SIZE],
                RoundKind::Partial => {
                    let mut m = [false; STATE_SIZE];
                    m[0] = true;
                    m
                }
            };
            for elem in 0..STATE_SIZE {
                let idx = self.index(slot, r, elem);
                self.s_in[idx] = witness.sin[r][elem];
                self.s_out[idx] = witness.sout[r][elem];
                self.sigma[idx] = if active_mask[elem] {
                    Block128::ONE
                } else {
                    Block128::ZERO
                };
            }
        }
        for r in 0..=N_ROUNDS {
            for elem in 0..STATE_SIZE {
                let idx = self.index(slot, r, elem);
                self.state[idx] = witness.state[r][elem];
            }
        }
    }
}

pub fn owner_auth_sigma_at(round: usize, elem: usize) -> Block128 {
    if round >= N_ROUNDS || elem >= STATE_SIZE {
        return Block128::ZERO;
    }
    let is_partial = (F_ROUNDS / 2..F_ROUNDS / 2 + P_ROUNDS).contains(&round);
    if !is_partial || elem == 0 {
        Block128::ONE
    } else {
        Block128::ZERO
    }
}

pub fn build_owner_auth_unified_mle(
    layout: OwnerAuthLayout,
    slot_state_ins: &[[Block128; STATE_SIZE]],
) -> (OwnerAuthUnifiedMle, Vec<PermLayerWitness>) {
    assert_eq!(
        slot_state_ins.len(),
        layout.live_slots,
        "expected one state input per live owner-auth slot"
    );
    let mut mle = OwnerAuthUnifiedMle::zero(layout);
    let mut witnesses = Vec::with_capacity(layout.live_slots);
    for (slot, state_in) in slot_state_ins.iter().enumerate() {
        let w = evaluate_permutation(*state_in);
        mle.populate_slot(slot, &w);
        witnesses.push(w);
    }
    (mle, witnesses)
}

#[inline]
fn owner_auth_round_of(layout: OwnerAuthLayout, idx: usize) -> usize {
    let _ = layout;
    (idx >> ROUND_LO) & ((1 << OWNER_AUTH_ROUND_VARS) - 1)
}

#[inline]
fn owner_auth_elem_of(idx: usize) -> usize {
    idx & ((1 << OWNER_AUTH_ELEM_VARS) - 1)
}

#[inline]
fn owner_auth_slot_of(layout: OwnerAuthLayout, idx: usize) -> usize {
    (idx >> SLOT_LO) & ((1 << layout.slot_bits) - 1)
}

#[inline]
fn owner_auth_dec_round_index(layout: OwnerAuthLayout, idx: usize) -> usize {
    let round = owner_auth_round_of(layout, idx);
    let prev = (round + ROUND_LIMIT - 1) & (ROUND_LIMIT - 1);
    (idx & !(((1 << OWNER_AUTH_ROUND_VARS) - 1) << ROUND_LO)) | (prev << ROUND_LO)
}

#[inline]
fn owner_auth_pack_index(layout: OwnerAuthLayout, slot: usize, round: usize, elem: usize) -> usize {
    layout.index(slot, round, elem)
}

#[inline]
fn owner_auth_mds_coeff(round: usize, i: usize, j: usize) -> Block128 {
    let is_partial = (F_ROUNDS / 2..F_ROUNDS / 2 + P_ROUNDS).contains(&round);
    let raw = if is_partial {
        MDS_PARTIAL[i][j]
    } else {
        MDS_FULL[i][j]
    };
    Block128::from(raw)
}

fn build_owner_auth_mu_table(layout: OwnerAuthLayout) -> Vec<Block128> {
    let mut tab = vec![Block128::ZERO; layout.cells()];
    for slot in 0..layout.live_slots {
        for round in 0..N_ROUNDS {
            for elem in 0..STATE_SIZE {
                let idx = owner_auth_pack_index(layout, slot, round, elem);
                tab[idx] = Block128::ONE;
            }
        }
    }
    tab
}

fn build_owner_auth_sigma_table(layout: OwnerAuthLayout) -> Vec<Block128> {
    let mut tab = vec![Block128::ZERO; layout.cells()];
    for slot in 0..layout.live_slots {
        for round in 0..N_ROUNDS {
            for elem in 0..STATE_SIZE {
                let idx = owner_auth_pack_index(layout, slot, round, elem);
                tab[idx] = owner_auth_sigma_at(round, elem);
            }
        }
    }
    tab
}

fn build_owner_auth_rc_table(layout: OwnerAuthLayout) -> Vec<Block128> {
    let mut tab = vec![Block128::ZERO; layout.cells()];
    for slot in 0..layout.live_slots {
        for round in 0..N_ROUNDS {
            let is_partial = (F_ROUNDS / 2..F_ROUNDS / 2 + P_ROUNDS).contains(&round);
            for elem in 0..STATE_SIZE {
                if is_partial && elem != 0 {
                    continue;
                }
                let idx = owner_auth_pack_index(layout, slot, round, elem);
                tab[idx] = Block128::from(ROUND_CONSTANTS[elem][round]);
            }
        }
    }
    tab
}

fn build_owner_auth_mds_lane_table(layout: OwnerAuthLayout, lane: usize) -> Vec<Block128> {
    let mut out = vec![Block128::ZERO; layout.cells()];
    for y in 0..layout.cells() {
        let slot = owner_auth_slot_of(layout, y);
        if slot >= layout.live_slots {
            continue;
        }
        let dec_round = owner_auth_round_of(layout, owner_auth_dec_round_index(layout, y));
        if dec_round >= N_ROUNDS {
            continue;
        }
        let elem = owner_auth_elem_of(y);
        out[y] = owner_auth_mds_coeff(dec_round, elem, lane);
    }
    out
}

fn build_owner_auth_mds_lane_tables(layout: OwnerAuthLayout) -> [Vec<Block128>; STATE_SIZE] {
    std::array::from_fn(|j| build_owner_auth_mds_lane_table(layout, j))
}

struct OwnerAuthPublicTables {
    mds_lane_dec: [Vec<Block128>; STATE_SIZE],
    sigma_lane_dec: [Vec<Block128>; STATE_SIZE],
    rc_lane_dec: [Vec<Block128>; STATE_SIZE],
}

fn build_owner_auth_public_tables(layout: OwnerAuthLayout) -> OwnerAuthPublicTables {
    let sigma_full = build_owner_auth_sigma_table(layout);
    let sigma_dec = owner_auth_permute_by_dec(layout, &sigma_full);
    let rc_table = build_owner_auth_rc_table(layout);
    let rc_dec = owner_auth_permute_by_dec(layout, &rc_table);
    let mds_lane_dec = build_owner_auth_mds_lane_tables(layout);
    let sigma_lane_dec: [Vec<Block128>; STATE_SIZE] =
        std::array::from_fn(|j| owner_auth_project_lane(layout, &sigma_dec, j));
    let rc_lane_dec: [Vec<Block128>; STATE_SIZE] =
        std::array::from_fn(|j| owner_auth_project_lane(layout, &rc_dec, j));
    OwnerAuthPublicTables {
        mds_lane_dec,
        sigma_lane_dec,
        rc_lane_dec,
    }
}

fn owner_auth_public_tables(layout: OwnerAuthLayout) -> &'static OwnerAuthPublicTables {
    static TABLES: OnceLock<Vec<OnceLock<OwnerAuthPublicTables>>> = OnceLock::new();
    let tables = TABLES.get_or_init(|| {
        (0..=OWNER_AUTH_MAX_OWNERS)
            .map(|_| OnceLock::new())
            .collect()
    });
    tables[layout.owner_count].get_or_init(|| build_owner_auth_public_tables(layout))
}

fn owner_auth_permute_by_dec(layout: OwnerAuthLayout, src: &[Block128]) -> Vec<Block128> {
    debug_assert_eq!(src.len(), layout.cells());
    let mut out = vec![Block128::ZERO; layout.cells()];
    for y in 0..layout.cells() {
        out[y] = src[owner_auth_dec_round_index(layout, y)];
    }
    out
}

fn owner_auth_build_u_table(layout: OwnerAuthLayout, rho: &[Block128]) -> Vec<Block128> {
    debug_assert_eq!(rho.len(), layout.num_vars);
    let eq_tab = eq_ind_partial_eval::<Block128>(rho);
    let mu_tab = build_owner_auth_mu_table(layout);
    let mut out = vec![Block128::ZERO; layout.cells()];
    for y in 0..layout.cells() {
        let x = owner_auth_dec_round_index(layout, y);
        out[y] = eq_tab[x] * mu_tab[x];
    }
    out
}

fn owner_auth_project_lane(
    layout: OwnerAuthLayout,
    src: &[Block128],
    lane: usize,
) -> Vec<Block128> {
    debug_assert!(lane < STATE_SIZE);
    debug_assert_eq!(src.len(), layout.cells());
    let elem_mask = (1 << OWNER_AUTH_ELEM_VARS) - 1;
    let mut out = vec![Block128::ZERO; layout.cells()];
    for y in 0..layout.cells() {
        let row_base = y & !elem_mask;
        out[y] = src[row_base | lane];
    }
    out
}

pub const OWNER_AUTH_STATE_ROUND_DEGREE: usize = 10;
pub const OWNER_AUTH_UNIFIED_ROUND_DEGREE: usize = OWNER_AUTH_STATE_ROUND_DEGREE;
pub const OWNER_AUTH_SHIFT_ROUND_DEGREE: usize = 2;
pub const OWNER_AUTH_BOUNDARY_ROUND_DEGREE: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OwnerAuthUnifiedProof {
    pub round_polys: Vec<RoundPolynomial<Block128>>,
    pub state_at_r: Block128,
    pub state_lane_dec_at_r: [Block128; STATE_SIZE],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerAuthUnifiedReduction {
    pub r_prime: Vec<Block128>,
    pub state_at_r: Block128,
    pub state_lane_dec_at_r: [Block128; STATE_SIZE],
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OwnerAuthShiftProof {
    pub round_polys: Vec<BatchEvalRound>,
    pub state_at_r2: Block128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerAuthShiftReduction {
    pub r_double_prime: Vec<Block128>,
    pub state_at_r2: Block128,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OwnerAuthBoundaryProof {
    pub round_polys: Vec<BatchEvalRound>,
    pub state_at_r: Block128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerAuthBoundaryReduction {
    pub point: Vec<Block128>,
    pub state_at_r: Block128,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OwnerAuthKillShotProof {
    pub main: OwnerAuthUnifiedProof,
    pub shift: OwnerAuthShiftProof,
}

#[derive(Debug)]
struct OwnerStateTables {
    u: Vec<Block128>,
    mds_lane_dec: [Vec<Block128>; STATE_SIZE],
    sigma_lane_dec: [Vec<Block128>; STATE_SIZE],
    rc_lane_dec: [Vec<Block128>; STATE_SIZE],
    state: Vec<Block128>,
    state_lane_dec: [Vec<Block128>; STATE_SIZE],
}

struct OwnerStateFinalClaims {
    state: Block128,
    state_lane_dec: [Block128; STATE_SIZE],
}

fn build_owner_state_tables(mle: &OwnerAuthUnifiedMle, rho: &[Block128]) -> OwnerStateTables {
    let layout = mle.layout;
    let public = owner_auth_public_tables(layout);
    let state_dec = owner_auth_permute_by_dec(layout, &mle.state);
    let state_lane_dec: [Vec<Block128>; STATE_SIZE] =
        std::array::from_fn(|j| owner_auth_project_lane(layout, &state_dec, j));

    OwnerStateTables {
        u: owner_auth_build_u_table(layout, rho),
        mds_lane_dec: public.mds_lane_dec.clone(),
        sigma_lane_dec: public.sigma_lane_dec.clone(),
        rc_lane_dec: public.rc_lane_dec.clone(),
        state: mle.state.clone(),
        state_lane_dec,
    }
}

#[derive(Debug)]
struct OwnerStateFlatTables {
    u: Vec<u128>,
    mds_lane_dec: [Vec<u128>; STATE_SIZE],
    sigma_lane_dec: [Vec<u128>; STATE_SIZE],
    rc_lane_dec: [Vec<u128>; STATE_SIZE],
    state: Vec<u128>,
    state_lane_dec: [Vec<u128>; STATE_SIZE],
}

#[inline]
fn vec_tower_to_flat(mut v: Vec<Block128>) -> Vec<u128> {
    let out = v.iter().map(|b| tower_to_flat_u128(b.to_u128())).collect();
    v.zeroize();
    out
}

impl Drop for OwnerStateFlatTables {
    fn drop(&mut self) {
        self.state.zeroize();
        for j in 0..STATE_SIZE {
            self.state_lane_dec[j].zeroize();
        }
    }
}

impl OwnerStateFlatTables {
    fn from_tower(t: OwnerStateTables) -> Self {
        Self {
            u: vec_tower_to_flat(t.u),
            mds_lane_dec: t.mds_lane_dec.map(vec_tower_to_flat),
            sigma_lane_dec: t.sigma_lane_dec.map(vec_tower_to_flat),
            rc_lane_dec: t.rc_lane_dec.map(vec_tower_to_flat),
            state: vec_tower_to_flat(t.state),
            state_lane_dec: t.state_lane_dec.map(vec_tower_to_flat),
        }
    }

    fn fold_flat(&mut self, r_flat: u128) {
        fold_highest_var_inplace_flat(&mut self.u, r_flat);
        fold_secret_highest_var_inplace_flat(&mut self.state, r_flat);
        for j in 0..STATE_SIZE {
            fold_highest_var_inplace_flat(&mut self.mds_lane_dec[j], r_flat);
            fold_highest_var_inplace_flat(&mut self.sigma_lane_dec[j], r_flat);
            fold_highest_var_inplace_flat(&mut self.rc_lane_dec[j], r_flat);
            fold_secret_highest_var_inplace_flat(&mut self.state_lane_dec[j], r_flat);
        }
    }

    fn final_claims_tower(&self) -> OwnerStateFinalClaims {
        let f = |x: u128| Block128::from(flat_to_tower_u128(x));
        OwnerStateFinalClaims {
            state: f(self.state[0]),
            state_lane_dec: std::array::from_fn(|j| f(self.state_lane_dec[j][0])),
        }
    }
}

#[inline]
fn fold_highest_var_inplace_flat(evals: &mut Vec<u128>, r_flat: u128) {
    fold_highest_var_inplace_flat_inner(evals, r_flat, false);
}

#[inline]
fn fold_secret_highest_var_inplace_flat(evals: &mut Vec<u128>, r_flat: u128) {
    fold_highest_var_inplace_flat_inner(evals, r_flat, true);
}

fn fold_highest_var_inplace_flat_inner(
    evals: &mut Vec<u128>,
    r_flat: u128,
    zeroize_truncated: bool,
) {
    let half = evals.len() / 2;
    debug_assert!(half > 0);
    if half >= 1024 {
        use rayon::prelude::*;
        let (lo, hi) = evals.split_at_mut(half);
        lo.par_iter_mut().zip(hi.par_iter()).for_each(|(l, &h)| {
            *l ^= clmul_gcm(r_flat, *l ^ h);
        });
    } else {
        for j in 0..half {
            let delta = evals[j] ^ evals[j + half];
            evals[j] ^= clmul_gcm(r_flat, delta);
        }
    }
    if zeroize_truncated {
        evals[half..].zeroize();
    }
    evals.truncate(half);
}

#[inline(always)]
fn poly_mul_t<const NA: usize, const NB: usize, const NR: usize>(
    a: &[u128; NA],
    b: &[u128; NB],
) -> [u128; NR] {
    debug_assert_eq!(NR, NA + NB - 1);
    let mut out = [0u128; NR];
    for i in 0..NA {
        for j in 0..NB {
            out[i + j] ^= clmul_gcm(a[i], b[j]);
        }
    }
    out
}

#[inline(always)]
fn pow7_poly_t(a: u128, b: u128) -> [u128; 8] {
    let a2 = square_flat_u128(a);
    let a3 = clmul_gcm(a2, a);
    let a4 = square_flat_u128(a2);
    let a5 = clmul_gcm(a4, a);
    let a6 = clmul_gcm(a4, a2);
    let a7 = clmul_gcm(a4, a3);

    let b2 = square_flat_u128(b);
    let b3 = clmul_gcm(b2, b);
    let b4 = square_flat_u128(b2);
    let b5 = clmul_gcm(b4, b);
    let b6 = clmul_gcm(b4, b2);
    let b7 = clmul_gcm(b4, b3);

    [
        a7,
        clmul_gcm(a6, b),
        clmul_gcm(a5, b2),
        clmul_gcm(a4, b3),
        clmul_gcm(a3, b4),
        clmul_gcm(a2, b5),
        clmul_gcm(a, b6),
        b7,
    ]
}

fn compute_owner_state_round_polynomial_flat(
    tabs: &OwnerStateFlatTables,
) -> RoundPolynomial<Block128> {
    use rayon::prelude::*;
    let half = tabs.u.len() / 2;
    const ONE_FLAT: u128 = 1u128;

    let acc: [u128; OWNER_AUTH_STATE_ROUND_DEGREE + 1] = if half >= 4096 {
        (0..half)
            .into_par_iter()
            .fold(
                || [0u128; OWNER_AUTH_STATE_ROUND_DEGREE + 1],
                |mut local_acc, i| {
                    accumulate_owner_state_round_at(&mut local_acc, tabs, ONE_FLAT, half, i);
                    local_acc
                },
            )
            .reduce(
                || [0u128; OWNER_AUTH_STATE_ROUND_DEGREE + 1],
                |mut a, b| {
                    for k in 0..=OWNER_AUTH_STATE_ROUND_DEGREE {
                        a[k] ^= b[k];
                    }
                    a
                },
            )
    } else {
        let mut acc = [0u128; OWNER_AUTH_STATE_ROUND_DEGREE + 1];
        for i in 0..half {
            accumulate_owner_state_round_at(&mut acc, tabs, ONE_FLAT, half, i);
        }
        acc
    };

    let coeffs_tower: Vec<Block128> = acc
        .iter()
        .map(|&c| Block128::from(flat_to_tower_u128(c)))
        .collect();
    RoundPolynomial::from_coeffs(coeffs_tower)
}

fn accumulate_owner_state_round_at(
    acc: &mut [u128; OWNER_AUTH_STATE_ROUND_DEGREE + 1],
    tabs: &OwnerStateFlatTables,
    one_flat: u128,
    half: usize,
    i: usize,
) {
    let u_p: [u128; 2] = [tabs.u[i], tabs.u[i] ^ tabs.u[i + half]];
    let stmain_p: [u128; 2] = [tabs.state[i], tabs.state[i] ^ tabs.state[i + half]];

    let mut q_p = [0u128; OWNER_AUTH_STATE_ROUND_DEGREE];
    q_p[0] ^= stmain_p[0];
    q_p[1] ^= stmain_p[1];
    for j in 0..STATE_SIZE {
        let m_p: [u128; 2] = [
            tabs.mds_lane_dec[j][i],
            tabs.mds_lane_dec[j][i] ^ tabs.mds_lane_dec[j][i + half],
        ];
        let sgl_p: [u128; 2] = [
            tabs.sigma_lane_dec[j][i],
            tabs.sigma_lane_dec[j][i] ^ tabs.sigma_lane_dec[j][i + half],
        ];
        let rc_p: [u128; 2] = [
            tabs.rc_lane_dec[j][i],
            tabs.rc_lane_dec[j][i] ^ tabs.rc_lane_dec[j][i + half],
        ];
        let stl_p: [u128; 2] = [
            tabs.state_lane_dec[j][i],
            tabs.state_lane_dec[j][i] ^ tabs.state_lane_dec[j][i + half],
        ];
        let one_plus_sgl_p: [u128; 2] = [one_flat ^ sgl_p[0], sgl_p[1]];

        let x_p = [stl_p[0] ^ rc_p[0], stl_p[1] ^ rc_p[1]];
        let x7_p: [u128; 8] = pow7_poly_t(x_p[0], x_p[1]);
        let sgl_x7_p: [u128; 9] = poly_mul_t::<2, 8, 9>(&sgl_p, &x7_p);
        let onep_stl_p: [u128; 3] = poly_mul_t::<2, 2, 3>(&one_plus_sgl_p, &stl_p);
        let mut pi_p = [0u128; 9];
        pi_p.copy_from_slice(&sgl_x7_p);
        for k in 0..3 {
            pi_p[k] ^= onep_stl_p[k];
        }
        let m_pi_p: [u128; 10] = poly_mul_t::<2, 9, 10>(&m_p, &pi_p);
        for k in 0..OWNER_AUTH_STATE_ROUND_DEGREE {
            q_p[k] ^= m_pi_p[k];
        }
    }

    let f_p: [u128; 11] = poly_mul_t::<2, 10, 11>(&u_p, &q_p);
    for k in 0..=OWNER_AUTH_STATE_ROUND_DEGREE {
        acc[k] ^= f_p[k];
    }
}

pub fn prove_owner_auth_unified<T: FiatShamir<Block128>>(
    mle: &OwnerAuthUnifiedMle,
    channel: &mut T,
) -> (OwnerAuthUnifiedProof, Vec<Block128>) {
    let layout = mle.layout;
    let cells = layout.cells();
    assert_eq!(mle.s_in.len(), cells);
    assert_eq!(mle.s_out.len(), cells);
    assert_eq!(mle.sigma.len(), cells);
    assert_eq!(mle.state.len(), cells);

    let rho: Vec<Block128> = (0..layout.num_vars).map(|_| channel.squeeze()).collect();
    let tabs = build_owner_state_tables(mle, &rho);
    let mut tabs = OwnerStateFlatTables::from_tower(tabs);

    let mut round_polys = Vec::with_capacity(layout.num_vars);
    let mut r_prime = vec![Block128::ZERO; layout.num_vars];
    for round in 0..layout.num_vars {
        let poly = compute_owner_state_round_polynomial_flat(&tabs);
        for &c in &poly.coeffs {
            channel.absorb(c);
        }
        let challenge = channel.squeeze();
        let challenge_flat = tower_to_flat_u128(challenge.to_u128());
        tabs.fold_flat(challenge_flat);
        r_prime[layout.num_vars - 1 - round] = challenge;
        round_polys.push(poly);
    }

    let final_claims = tabs.final_claims_tower();
    channel.absorb(final_claims.state);
    for v in &final_claims.state_lane_dec {
        channel.absorb(*v);
    }

    let proof = OwnerAuthUnifiedProof {
        round_polys,
        state_at_r: final_claims.state,
        state_lane_dec_at_r: final_claims.state_lane_dec,
    };
    (proof, r_prime)
}

pub fn verify_owner_auth_unified<T: FiatShamir<Block128>>(
    proof: &OwnerAuthUnifiedProof,
    layout: OwnerAuthLayout,
    channel: &mut T,
) -> Option<OwnerAuthUnifiedReduction> {
    if proof.round_polys.len() != layout.num_vars {
        return None;
    }
    for p in &proof.round_polys {
        if p.degree() > OWNER_AUTH_STATE_ROUND_DEGREE {
            return None;
        }
    }

    let rho: Vec<Block128> = (0..layout.num_vars).map(|_| channel.squeeze()).collect();

    let mut expected = Block128::ZERO;
    let mut r_prime = vec![Block128::ZERO; layout.num_vars];
    for (round, poly) in proof.round_polys.iter().enumerate() {
        let s = poly.evaluate(Block128::ZERO) + poly.evaluate(Block128::ONE);
        if s != expected {
            return None;
        }
        for &c in &poly.coeffs {
            channel.absorb(c);
        }
        let challenge = channel.squeeze();
        expected = poly.evaluate(challenge);
        r_prime[layout.num_vars - 1 - round] = challenge;
    }

    let u_at_r = evaluate_flat(&owner_auth_build_u_table(layout, &rho), &r_prime);
    let public = owner_auth_public_tables(layout);
    let mut mds_lane_dec_at_r = [Block128::ZERO; STATE_SIZE];
    let mut sigma_lane_dec_at_r = [Block128::ZERO; STATE_SIZE];
    let mut rc_lane_dec_at_r = [Block128::ZERO; STATE_SIZE];
    for j in 0..STATE_SIZE {
        mds_lane_dec_at_r[j] = evaluate_slice(&public.mds_lane_dec[j], &r_prime);
        sigma_lane_dec_at_r[j] = evaluate_slice(&public.sigma_lane_dec[j], &r_prime);
        rc_lane_dec_at_r[j] = evaluate_slice(&public.rc_lane_dec[j], &r_prime);
    }

    let mut q_at_r = proof.state_at_r;
    for j in 0..STATE_SIZE {
        let x_j = proof.state_lane_dec_at_r[j] + rc_lane_dec_at_r[j];
        let pi_j = sigma_lane_dec_at_r[j] * pow7_block128(x_j)
            + (Block128::ONE + sigma_lane_dec_at_r[j]) * proof.state_lane_dec_at_r[j];
        q_at_r += mds_lane_dec_at_r[j] * pi_j;
    }
    if expected != u_at_r * q_at_r {
        return None;
    }

    channel.absorb(proof.state_at_r);
    for v in &proof.state_lane_dec_at_r {
        channel.absorb(*v);
    }

    Some(OwnerAuthUnifiedReduction {
        r_prime,
        state_at_r: proof.state_at_r,
        state_lane_dec_at_r: proof.state_lane_dec_at_r,
    })
}

struct OwnerCombinedWeights {
    w_state: Vec<Block128>,
}

fn build_owner_combined_weights(
    layout: OwnerAuthLayout,
    r_prime: &[Block128],
    delta: Block128,
) -> OwnerCombinedWeights {
    let r_slot = &r_prime[SLOT_LO..SLOT_LO + layout.slot_bits];
    let r_round = &r_prime[ROUND_LO..ROUND_HI];
    let r_elem = &r_prime[ELEM_LO..ELEM_HI];

    let eq_slot_tab = eq_ind_partial_eval::<Block128>(r_slot);
    let eq_round_tab = eq_ind_partial_eval::<Block128>(r_round);
    let eq_elem_tab = eq_ind_partial_eval::<Block128>(r_elem);
    let mut eq_round_at_inc = vec![Block128::ZERO; ROUND_LIMIT];
    for round_x in 0..ROUND_LIMIT {
        let inc = (round_x + 1) & (ROUND_LIMIT - 1);
        eq_round_at_inc[round_x] = eq_round_tab[inc];
    }

    let d0 = Block128::ONE;
    let d1 = delta;
    let d2 = d1 * delta;
    let d3 = d2 * delta;
    let d4 = d3 * delta;
    let lane_state = [d1, d2, d3, d4];

    let mut w_state = vec![Block128::ZERO; layout.cells()];
    for x in 0..layout.cells() {
        let slot = owner_auth_slot_of(layout, x);
        let round = owner_auth_round_of(layout, x);
        let elem = owner_auth_elem_of(x);
        let w_direct = eq_slot_tab[slot] * eq_round_tab[round] * eq_elem_tab[elem];
        let es_er = eq_slot_tab[slot] * eq_round_at_inc[round];
        w_state[x] = d0 * w_direct + lane_state[elem] * es_er;
    }

    OwnerCombinedWeights { w_state }
}

fn owner_combined_target(red: &OwnerAuthUnifiedReduction, delta: Block128) -> Block128 {
    let d0 = Block128::ONE;
    let d1 = delta;
    let d2 = d1 * delta;
    let d3 = d2 * delta;
    let d4 = d3 * delta;
    let lane = [d1, d2, d3, d4];
    let mut acc = d0 * red.state_at_r;
    for j in 0..STATE_SIZE {
        acc += lane[j] * red.state_lane_dec_at_r[j];
    }
    acc
}

fn compute_weighted_state_round_polynomial_flat(
    state: &[u128],
    w_state: &[u128],
) -> BatchEvalRound {
    let half = state.len() / 2;
    let mut evals = [0u128; OWNER_AUTH_SHIFT_ROUND_DEGREE + 1];
    let t_flat: [u128; OWNER_AUTH_SHIFT_ROUND_DEGREE + 1] =
        std::array::from_fn(|k| tower_to_flat_u128(k as u128));

    for i in 0..half {
        let (st0, st1) = (state[i], state[i + half]);
        let (wst0, wst1) = (w_state[i], w_state[i + half]);

        let dst = st0 ^ st1;
        let dwst = wst0 ^ wst1;

        for k in 0..=OWNER_AUTH_SHIFT_ROUND_DEGREE {
            let t = t_flat[k];
            let st = st0 ^ clmul_gcm(t, dst);
            let wst = wst0 ^ clmul_gcm(t, dwst);
            evals[k] ^= clmul_gcm(wst, st);
        }
    }

    let evals_tower: [Block128; OWNER_AUTH_SHIFT_ROUND_DEGREE + 1] =
        std::array::from_fn(|k| Block128::from(flat_to_tower_u128(evals[k])));
    BatchEvalRound { evals: evals_tower }
}

fn prove_weighted_state_sumcheck<T: FiatShamir<Block128>>(
    state: &[Block128],
    weights: Vec<Block128>,
    target: Block128,
    channel: &mut T,
) -> (Vec<BatchEvalRound>, Vec<Block128>, Block128) {
    assert_eq!(state.len(), weights.len());
    let n = state.len().trailing_zeros() as usize;
    assert_eq!(state.len(), 1usize << n);
    let mut state = vec_tower_to_flat(state.to_vec());
    let mut weights = vec_tower_to_flat(weights);
    let mut expected = target;
    let mut round_polys = Vec::with_capacity(n);
    let mut r = vec![Block128::ZERO; n];
    for round in 0..n {
        let poly = compute_weighted_state_round_polynomial_flat(&state, &weights);
        debug_assert_eq!(poly.sum_at_0_plus_1(), expected);
        for &e in &poly.evals {
            channel.absorb(e);
        }
        let challenge = channel.squeeze();
        let challenge_flat = tower_to_flat_u128(challenge.to_u128());
        expected = poly.evaluate(challenge);
        fold_secret_highest_var_inplace_flat(&mut state, challenge_flat);
        fold_highest_var_inplace_flat(&mut weights, challenge_flat);
        r[n - 1 - round] = challenge;
        round_polys.push(poly);
    }
    let state_at_r = Block128::from(flat_to_tower_u128(state[0]));
    (round_polys, r, state_at_r)
}

fn verify_weighted_state_sumcheck<T: FiatShamir<Block128>>(
    round_polys: &[BatchEvalRound],
    state_at_r: Block128,
    n: usize,
    weights: &[Block128],
    target: Block128,
    channel: &mut T,
) -> Option<Vec<Block128>> {
    if round_polys.len() != n || weights.len() != (1usize << n) {
        return None;
    }
    let mut expected = target;
    let mut r = Vec::with_capacity(n);
    for poly in round_polys {
        if poly.sum_at_0_plus_1() != expected {
            return None;
        }
        for &e in &poly.evals {
            channel.absorb(e);
        }
        let challenge = channel.squeeze();
        expected = poly.evaluate(challenge);
        r.push(challenge);
    }
    r.reverse();
    let w_at_r = evaluate_slice(weights, &r);
    if expected != w_at_r * state_at_r {
        return None;
    }
    Some(r)
}

pub fn prove_owner_auth_shift<T: FiatShamir<Block128>>(
    mle: &OwnerAuthUnifiedMle,
    main_red: &OwnerAuthUnifiedReduction,
    channel: &mut T,
) -> (OwnerAuthShiftProof, Vec<Block128>) {
    let layout = mle.layout;
    assert_eq!(main_red.r_prime.len(), layout.num_vars);
    let delta = channel.squeeze();
    let weights = build_owner_combined_weights(layout, &main_red.r_prime, delta);
    let target = owner_combined_target(main_red, delta);
    let (round_polys, r_double_prime, state_at_r2) =
        prove_weighted_state_sumcheck(&mle.state, weights.w_state, target, channel);
    channel.absorb(state_at_r2);

    (
        OwnerAuthShiftProof {
            round_polys,
            state_at_r2,
        },
        r_double_prime,
    )
}

pub fn verify_owner_auth_shift<T: FiatShamir<Block128>>(
    proof: &OwnerAuthShiftProof,
    layout: OwnerAuthLayout,
    main_red: &OwnerAuthUnifiedReduction,
    channel: &mut T,
) -> Option<OwnerAuthShiftReduction> {
    if proof.round_polys.len() != layout.num_vars {
        return None;
    }
    for p in &proof.round_polys {
        let _ = p;
    }
    let delta = channel.squeeze();
    let target = owner_combined_target(main_red, delta);
    let weights = build_owner_combined_weights(layout, &main_red.r_prime, delta);
    let r_double_prime = verify_weighted_state_sumcheck(
        &proof.round_polys,
        proof.state_at_r2,
        layout.num_vars,
        &weights.w_state,
        target,
        channel,
    )?;

    channel.absorb(proof.state_at_r2);

    Some(OwnerAuthShiftReduction {
        r_double_prime,
        state_at_r2: proof.state_at_r2,
    })
}

#[derive(Debug, Clone)]
struct OwnerBoundaryTerm {
    cell: usize,
    coeff: Block128,
}

#[derive(Debug, Clone)]
struct OwnerBoundaryConstraint {
    terms: Vec<OwnerBoundaryTerm>,
    constant: Block128,
}

fn mds_full_inverse() -> &'static [[Block128; STATE_SIZE]; STATE_SIZE] {
    static INV: OnceLock<[[Block128; STATE_SIZE]; STATE_SIZE]> = OnceLock::new();
    INV.get_or_init(|| {
        let mut aug = [[Block128::ZERO; STATE_SIZE * 2]; STATE_SIZE];
        for row in 0..STATE_SIZE {
            for col in 0..STATE_SIZE {
                aug[row][col] = Block128::from(MDS_FULL[row][col]);
            }
            aug[row][STATE_SIZE + row] = Block128::ONE;
        }

        for col in 0..STATE_SIZE {
            let pivot = (col..STATE_SIZE)
                .find(|&row| aug[row][col] != Block128::ZERO)
                .expect("MDS_FULL must be invertible");
            if pivot != col {
                aug.swap(col, pivot);
            }
            let inv = aug[col][col].invert();
            for j in 0..STATE_SIZE * 2 {
                aug[col][j] *= inv;
            }
            for row in 0..STATE_SIZE {
                if row == col {
                    continue;
                }
                let factor = aug[row][col];
                if factor == Block128::ZERO {
                    continue;
                }
                for j in 0..STATE_SIZE * 2 {
                    aug[row][j] += factor * aug[col][j];
                }
            }
        }

        std::array::from_fn(|row| std::array::from_fn(|col| aug[row][STATE_SIZE + col]))
    })
}

fn owner_boundary_state_cell(
    layout: OwnerAuthLayout,
    slot: usize,
    round: usize,
    lane: usize,
) -> usize {
    layout.index(slot, round, lane)
}

fn owner_boundary_push_pre_lane(
    terms: &mut Vec<OwnerBoundaryTerm>,
    layout: OwnerAuthLayout,
    slot: usize,
    pre_lane: usize,
    coeff: Block128,
) {
    let inv = mds_full_inverse();
    for post_lane in 0..STATE_SIZE {
        terms.push(OwnerBoundaryTerm {
            cell: owner_boundary_state_cell(layout, slot, 0, post_lane),
            coeff: coeff * inv[pre_lane][post_lane],
        });
    }
}

fn owner_boundary_push_pre_equals_const(
    constraints: &mut Vec<OwnerBoundaryConstraint>,
    layout: OwnerAuthLayout,
    slot: usize,
    pre_lane: usize,
    constant: Block128,
) {
    let mut terms = Vec::with_capacity(STATE_SIZE);
    owner_boundary_push_pre_lane(&mut terms, layout, slot, pre_lane, Block128::ONE);
    constraints.push(OwnerBoundaryConstraint { terms, constant });
}

fn owner_boundary_push_output_equals_const(
    constraints: &mut Vec<OwnerBoundaryConstraint>,
    layout: OwnerAuthLayout,
    slot: usize,
    lane: usize,
    constant: Block128,
) {
    constraints.push(OwnerBoundaryConstraint {
        terms: vec![OwnerBoundaryTerm {
            cell: owner_boundary_state_cell(layout, slot, N_ROUNDS, lane),
            coeff: Block128::ONE,
        }],
        constant,
    });
}

fn owner_auth_boundary_constraints(
    circuit: &OwnerAuthCircuit,
    public: &OwnerAuthPublicInputs,
) -> Vec<OwnerBoundaryConstraint> {
    let layout = public.layout;
    debug_assert_eq!(circuit.layout, layout);
    let iv_addr = capacity_iv(TAG_ADDRFIX);
    let mut constraints = Vec::with_capacity(layout.owner_count * 4);

    for owner_idx in 0..layout.owner_count {
        let base = owner_idx * OWNER_AUTH_SLOTS_PER_OWNER;
        let haddr = base;

        owner_boundary_push_pre_equals_const(&mut constraints, layout, haddr, 2, iv_addr[0]);
        owner_boundary_push_pre_equals_const(&mut constraints, layout, haddr, 3, iv_addr[1]);

        for lane in 0..OWNER_AUTH_PIN_LANES {
            owner_boundary_push_output_equals_const(
                &mut constraints,
                layout,
                haddr,
                lane,
                public.expected_address[owner_idx][lane],
            );
        }
    }

    constraints
}

fn owner_boundary_weights_and_target(
    layout: OwnerAuthLayout,
    constraints: &[OwnerBoundaryConstraint],
    alphas: &[Block128],
) -> (Vec<Block128>, Block128) {
    debug_assert_eq!(constraints.len(), alphas.len());
    let mut weights = vec![Block128::ZERO; layout.cells()];
    let mut target = Block128::ZERO;
    for (constraint, &alpha) in constraints.iter().zip(alphas.iter()) {
        target += alpha * constraint.constant;
        for term in &constraint.terms {
            weights[term.cell] += alpha * term.coeff;
        }
    }
    (weights, target)
}

const OWNER_AUTH_BOUNDARY_DOMAIN_TAG: u128 = 0xA07D_0B47_B0A0_0001;

pub fn prove_owner_auth_boundary<T: FiatShamir<Block128>>(
    circuit: &OwnerAuthCircuit,
    public: &OwnerAuthPublicInputs,
    mle: &OwnerAuthUnifiedMle,
    channel: &mut T,
) -> (OwnerAuthBoundaryProof, OwnerAuthBoundaryReduction) {
    let constraints = owner_auth_boundary_constraints(circuit, public);
    channel.absorb(Block128::from(OWNER_AUTH_BOUNDARY_DOMAIN_TAG));
    channel.absorb(Block128::from(constraints.len() as u128));
    let alphas: Vec<Block128> = (0..constraints.len()).map(|_| channel.squeeze()).collect();
    let (weights, target) = owner_boundary_weights_and_target(public.layout, &constraints, &alphas);
    let (round_polys, point, state_at_r) =
        prove_weighted_state_sumcheck(&mle.state, weights, target, channel);
    channel.absorb(state_at_r);
    (
        OwnerAuthBoundaryProof {
            round_polys,
            state_at_r,
        },
        OwnerAuthBoundaryReduction { point, state_at_r },
    )
}

pub fn verify_owner_auth_boundary<T: FiatShamir<Block128>>(
    proof: &OwnerAuthBoundaryProof,
    circuit: &OwnerAuthCircuit,
    public: &OwnerAuthPublicInputs,
    channel: &mut T,
) -> Option<OwnerAuthBoundaryReduction> {
    if circuit.layout != public.layout {
        return None;
    }
    let constraints = owner_auth_boundary_constraints(circuit, public);
    channel.absorb(Block128::from(OWNER_AUTH_BOUNDARY_DOMAIN_TAG));
    channel.absorb(Block128::from(constraints.len() as u128));
    let alphas: Vec<Block128> = (0..constraints.len()).map(|_| channel.squeeze()).collect();
    let (weights, target) = owner_boundary_weights_and_target(public.layout, &constraints, &alphas);
    let point = verify_weighted_state_sumcheck(
        &proof.round_polys,
        proof.state_at_r,
        public.layout.num_vars,
        &weights,
        target,
        channel,
    )?;
    channel.absorb(proof.state_at_r);
    Some(OwnerAuthBoundaryReduction {
        point,
        state_at_r: proof.state_at_r,
    })
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OwnerAuthProofKillShot {
    pub kill_shot: OwnerAuthKillShotProof,
    pub boundary: OwnerAuthBoundaryProof,
    pub batch: BatchEvalProof,
    pub pcs: AuthMleOpeningProof,
}

impl OwnerAuthProofKillShot {
    pub fn byte_len(&self) -> usize {
        let main_polys: usize = self
            .kill_shot
            .main
            .round_polys
            .iter()
            .map(|p| p.coeffs.len() * 16)
            .sum();
        let shift_polys: usize = self
            .kill_shot
            .shift
            .round_polys
            .iter()
            .map(|p| p.evals.len() * 16)
            .sum();
        let boundary_polys: usize = self
            .boundary
            .round_polys
            .iter()
            .map(|p| p.evals.len() * 16)
            .sum();
        let main_finals = (1 + STATE_SIZE) * 16;
        let shift_finals = 16;
        let boundary_finals = 16;
        main_polys
            + shift_polys
            + boundary_polys
            + main_finals
            + shift_finals
            + boundary_finals
            + self.batch.byte_len()
            + self.pcs.byte_len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerAuthVerifierClaims {
    pub main: OwnerAuthUnifiedReduction,
    pub shift: OwnerAuthShiftReduction,
    pub boundary: OwnerAuthBoundaryReduction,
    pub state_claims: Vec<EvalClaim>,
    pub state: BatchEvalReduction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerAuthKillShotReductions {
    pub state: BatchEvalReduction,
}

const OWNER_AUTH_GKR_DOMAIN_TAG: u128 = 0xA07D_0B47_CAFE_0003;

pub fn init_owner_auth_gkr_channel<T: FiatShamir<Block128>>(channel: &mut T) {
    channel.absorb(Block128::from(OWNER_AUTH_GKR_DOMAIN_TAG));
}

pub fn owner_auth_gkr_channel() -> Poseidon2bChannel {
    let mut ch = Poseidon2bChannel::new();
    init_owner_auth_gkr_channel(&mut ch);
    ch
}

#[inline]
fn absorb_pair<T: FiatShamir<Block128>>(channel: &mut T, pair: &[Block128; 2]) {
    channel.absorb(pair[0]);
    channel.absorb(pair[1]);
}

fn absorb_owner_public_boundary<T: FiatShamir<Block128>>(
    channel: &mut T,
    inputs: &OwnerAuthPublicInputs,
) {
    channel.absorb(Block128::from(inputs.layout.owner_count as u128));
    channel.absorb(Block128::from(inputs.layout.live_slots as u128));
    channel.absorb(Block128::from(inputs.layout.slot_bits as u128));
    channel.absorb(Block128::from(inputs.layout.num_vars as u128));
    channel.absorb(Block128::from(inputs.layout.padded_slots as u128));
    absorb_pair(channel, &inputs.tx_body_hash);
    channel.absorb(Block128::from(inputs.live_input_positions.len() as u128));
    for &position in &inputs.live_input_positions {
        channel.absorb(Block128::from(position as u128));
    }
    channel.absorb(Block128::from(inputs.live_slot_indices.len() as u128));
    for &slot_index in &inputs.live_slot_indices {
        channel.absorb(Block128::from(slot_index as u128));
    }
    channel.absorb(Block128::from(inputs.input_to_group.len() as u128));
    for &group_idx in &inputs.input_to_group {
        channel.absorb(Block128::from(group_idx as u128));
    }
    for pair in &inputs.expected_address {
        absorb_pair(channel, pair);
    }
}

pub fn build_owner_auth_unified_from_inputs(
    circuit: &OwnerAuthCircuit,
    inputs: &OwnerAuthInputs,
) -> OwnerAuthUnifiedMle {
    let w = evaluate_owner_auth(circuit, inputs);
    debug_assert_eq!(w.slots.len(), circuit.layout.live_slots);
    let mut state_ins: Vec<[Block128; STATE_SIZE]> = w.slots.iter().map(|s| s.state_in).collect();
    let (mle, _) = build_owner_auth_unified_mle(circuit.layout, &state_ins);
    state_ins.zeroize();
    mle
}

pub fn prove_owner_auth_killshot<T: FiatShamir<Block128>>(
    circuit: &OwnerAuthCircuit,
    inputs: &OwnerAuthInputs,
    channel: &mut T,
) -> (OwnerAuthProofKillShot, OwnerAuthKillShotReductions) {
    let witness = evaluate_owner_auth(circuit, inputs);
    for i in 0..circuit.layout.owner_count {
        debug_assert_eq!(witness.derived_address[i], inputs.expected_address[i]);
    }
    let mut state_ins: Vec<[Block128; STATE_SIZE]> =
        witness.slots.iter().map(|s| s.state_in).collect();
    let (mle, _) = build_owner_auth_unified_mle(circuit.layout, &state_ins);
    state_ins.zeroize();
    prove_owner_auth_killshot_from_mle(circuit, &inputs.to_public(), &mle, channel)
}

pub fn prove_owner_auth_killshot_from_mle<T: FiatShamir<Block128>>(
    circuit: &OwnerAuthCircuit,
    public: &OwnerAuthPublicInputs,
    mle: &OwnerAuthUnifiedMle,
    channel: &mut T,
) -> (OwnerAuthProofKillShot, OwnerAuthKillShotReductions) {
    let layout = public.layout;
    assert_eq!(circuit.layout, layout);
    assert_eq!(mle.layout, layout);
    let committed = commit_auth_mle_column(mle.state.as_slice(), layout.num_vars);

    absorb_owner_public_boundary(channel, public);
    absorb_auth_mle_commitment(channel, &committed.commitment);

    let (main, r_prime) = prove_owner_auth_unified(mle, channel);
    let main_red = OwnerAuthUnifiedReduction {
        r_prime: r_prime.clone(),
        state_at_r: main.state_at_r,
        state_lane_dec_at_r: main.state_lane_dec_at_r,
    };
    let (shift, r_double_prime) = prove_owner_auth_shift(mle, &main_red, channel);
    let (boundary, boundary_red) = prove_owner_auth_boundary(circuit, public, mle, channel);

    let state_claims = vec![
        EvalClaim {
            point: r_prime.clone(),
            value: main.state_at_r,
        },
        EvalClaim {
            point: r_double_prime.clone(),
            value: shift.state_at_r2,
        },
        EvalClaim {
            point: boundary_red.point.clone(),
            value: boundary_red.state_at_r,
        },
    ];

    let (batch, red) = prove_batch_eval(mle.state.as_slice(), &state_claims, channel);
    let pcs = open_auth_mle_committed(&committed, layout.num_vars, &red);
    let proof = OwnerAuthProofKillShot {
        kill_shot: OwnerAuthKillShotProof { main, shift },
        boundary,
        batch,
        pcs,
    };
    let reductions = OwnerAuthKillShotReductions { state: red };
    (proof, reductions)
}

pub fn verify_owner_auth_killshot_with_claims<T: FiatShamir<Block128>>(
    proof: &OwnerAuthProofKillShot,
    circuit: &OwnerAuthCircuit,
    inputs: &OwnerAuthPublicInputs,
    channel: &mut T,
) -> Option<OwnerAuthVerifierClaims> {
    if circuit.layout != inputs.layout
        || inputs.expected_address.len() != inputs.layout.owner_count
        || inputs.live_input_positions.is_empty()
        || inputs.live_slot_indices.len() != inputs.live_input_positions.len()
        || inputs.input_to_group.len() != inputs.live_input_positions.len()
        || inputs
            .input_to_group
            .iter()
            .any(|&group_idx| group_idx >= inputs.layout.owner_count)
    {
        return None;
    }
    let layout = inputs.layout;

    absorb_owner_public_boundary(channel, inputs);
    absorb_auth_mle_commitment(channel, &proof.pcs.commitment);

    let main_red = verify_owner_auth_unified(&proof.kill_shot.main, layout, channel)?;
    let shift_red = verify_owner_auth_shift(&proof.kill_shot.shift, layout, &main_red, channel)?;
    let boundary_red = verify_owner_auth_boundary(&proof.boundary, circuit, inputs, channel)?;

    let state_claims = vec![
        EvalClaim {
            point: main_red.r_prime.clone(),
            value: main_red.state_at_r,
        },
        EvalClaim {
            point: shift_red.r_double_prime.clone(),
            value: shift_red.state_at_r2,
        },
        EvalClaim {
            point: boundary_red.point.clone(),
            value: boundary_red.state_at_r,
        },
    ];

    let red = verify_batch_eval(&proof.batch, &state_claims, layout.num_vars, channel)?;
    if !verify_auth_mle_opening(&proof.pcs, layout.num_vars, &red) {
        return None;
    }

    Some(OwnerAuthVerifierClaims {
        main: main_red,
        shift: shift_red,
        boundary: boundary_red,
        state_claims,
        state: red,
    })
}

pub fn verify_owner_auth_killshot<T: FiatShamir<Block128>>(
    proof: &OwnerAuthProofKillShot,
    circuit: &OwnerAuthCircuit,
    inputs: &OwnerAuthPublicInputs,
    channel: &mut T,
) -> Option<OwnerAuthKillShotReductions> {
    let claims = verify_owner_auth_killshot_with_claims(proof, circuit, inputs, channel)?;
    Some(OwnerAuthKillShotReductions {
        state: claims.state,
    })
}

pub fn discharge_owner_auth_reductions_native(
    circuit: &OwnerAuthCircuit,
    inputs: &OwnerAuthInputs,
    reductions: &OwnerAuthKillShotReductions,
) -> bool {
    let mle = build_owner_auth_unified_from_inputs(circuit, inputs);
    evaluate_slice(&mle.state, &reductions.state.point) == reductions.state.value
}

#[derive(Debug)]
pub enum OwnerAuthStatementError {
    Canonical(OwnerAuthError),
    Layout(OwnerAuthLayoutError),
    SecretCountMismatch { expected: usize, actual: usize },
    SecretMismatch { input_position: usize },
    RepeatedOwnerSecretMismatch { input_position: usize },
}

impl From<OwnerAuthError> for OwnerAuthStatementError {
    fn from(value: OwnerAuthError) -> Self {
        Self::Canonical(value)
    }
}

impl From<OwnerAuthLayoutError> for OwnerAuthStatementError {
    fn from(value: OwnerAuthLayoutError) -> Self {
        Self::Layout(value)
    }
}

impl std::fmt::Display for OwnerAuthStatementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Canonical(e) => write!(f, "canonical owner auth failed: {e}"),
            Self::Layout(e) => write!(f, "owner auth layout failed: {e}"),
            Self::SecretCountMismatch { expected, actual } => {
                write!(
                    f,
                    "secret count mismatch: expected {expected}, actual {actual}"
                )
            }
            Self::SecretMismatch { input_position } => {
                write!(f, "secret mismatch at live input position {input_position}")
            }
            Self::RepeatedOwnerSecretMismatch { input_position } => write!(
                f,
                "repeated owner provided different secret at live input position {input_position}"
            ),
        }
    }
}

impl std::error::Error for OwnerAuthStatementError {}

pub fn owner_auth_public_from_statement(
    statement: &CanonicalOwnerAuth,
) -> Result<OwnerAuthPublicInputs, OwnerAuthStatementError> {
    let layout = OwnerAuthLayout::for_owner_count(statement.groups.len())?;
    let expected_address = statement
        .groups
        .iter()
        .map(|group| group.owner.as_fields())
        .collect::<Vec<_>>();
    Ok(OwnerAuthPublicInputs {
        layout,
        tx_body_hash: statement.tx_body_hash.as_fields(),
        live_input_positions: statement.live_input_positions.clone(),
        live_slot_indices: statement.live_slot_indices.clone(),
        input_to_group: statement.input_to_group.clone(),
        expected_address,
    })
}

pub fn owner_auth_public_from_body(
    body: &TxBody,
) -> Result<OwnerAuthPublicInputs, OwnerAuthStatementError> {
    let statement = canonical_owner_auth(body)?;
    owner_auth_public_from_statement(&statement)
}

pub fn owner_auth_inputs_from_body_and_live_secrets(
    body: &TxBody,
    spend_secrets: &[SpendSecret],
) -> Result<OwnerAuthInputs, OwnerAuthStatementError> {
    let statement = canonical_owner_auth(body)?;
    if spend_secrets.len() != statement.live_input_positions.len() {
        return Err(OwnerAuthStatementError::SecretCountMismatch {
            expected: statement.live_input_positions.len(),
            actual: spend_secrets.len(),
        });
    }

    let public = owner_auth_public_from_statement(&statement)?;
    let mut group_secrets: Vec<Option<[Block128; 2]>> = vec![None; statement.groups.len()];
    for (live_idx, &input_position) in statement.live_input_positions.iter().enumerate() {
        let secret = &spend_secrets[live_idx];
        let owner = derive_address(secret);
        let group_idx = statement.input_to_group[live_idx];
        if owner != statement.groups[group_idx].owner {
            return Err(OwnerAuthStatementError::SecretMismatch { input_position });
        }
        let fields = secret.as_fields();
        match group_secrets[group_idx] {
            Some(existing) if existing != fields => {
                return Err(OwnerAuthStatementError::RepeatedOwnerSecretMismatch {
                    input_position,
                });
            }
            Some(_) => {}
            None => group_secrets[group_idx] = Some(fields),
        }
    }

    let spend_secret = group_secrets
        .into_iter()
        .map(|slot| slot.expect("each canonical group has a first live input"))
        .collect();
    Ok(OwnerAuthInputs::from_parts(&public, spend_secret))
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{TxInput, TxOutput, TxShape};

    fn secret(seed: u8) -> SpendSecret {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = seed.wrapping_mul(17).wrapping_add(i as u8);
        }
        SpendSecret(bytes)
    }

    fn body_from_secrets(shape: TxShape, secrets: &[SpendSecret], repeated_first: bool) -> TxBody {
        let mut inputs = Vec::new();
        for (i, s) in secrets.iter().enumerate() {
            inputs.push(TxInput {
                slot_index: i as u32,
                value: 10,
                owner: derive_address(s),
                spend_secret: s.clone(),
                valid: true,
            });
        }
        if repeated_first {
            let s = secrets[0].clone();
            inputs.push(TxInput {
                slot_index: 100,
                value: 10,
                owner: derive_address(&s),
                spend_secret: s,
                valid: true,
            });
        }
        let total = inputs.iter().map(|i| i.value).sum::<u64>();
        TxBody {
            shape,
            epoch_anchor: [0xA5; 32],
            fee: 1,
            inputs,
            outputs: vec![TxOutput {
                slot_index: 1_000,
                value: total - 1,
                owner: Address([0xB0; 32]),
                valid: true,
            }],
            is_coinbase: false,
        }
    }

    #[test]
    fn owner_auth_layout_table_matches_spec() {
        let cases = [
            (1, 1, 0, 9, 512),
            (2, 2, 1, 10, 1024),
            (3, 3, 2, 11, 2048),
            (4, 4, 2, 11, 2048),
            (6, 6, 3, 12, 4096),
            (7, 7, 3, 12, 4096),
            (12, 12, 4, 13, 8192),
            (13, 13, 4, 13, 8192),
            (25, 25, 5, 14, 16384),
        ];
        for (k, live, bits, vars, cells) in cases {
            let layout = OwnerAuthLayout::for_owner_count(k).unwrap();
            assert_eq!(layout.live_slots, live);
            assert_eq!(layout.slot_bits, bits);
            assert_eq!(layout.num_vars, vars);
            assert_eq!(layout.cells(), cells);
        }
    }

    #[test]
    fn owner_auth_oracle_matches_native_hashes() {
        for k in [1usize, 3, 6, 12, 25] {
            let layout = OwnerAuthLayout::for_owner_count(k).unwrap();
            let circuit = OwnerAuthCircuit::build(layout);
            let secrets: Vec<_> = (0..k).map(|i| secret(i as u8 + 1)).collect();
            let tx_hash = noid_poseidon2b::primitives::TxBodyHash([0x55; 32]);
            let public_hash = tx_hash.as_fields();
            let spend_secret: Vec<_> = secrets.iter().map(SpendSecret::as_fields).collect();
            let addr = compute_owner_auth_boundary(&circuit, spend_secret.clone(), public_hash);
            for i in 0..k {
                assert_eq!(addr[i], derive_address(&secrets[i]).as_fields());
            }
        }
    }

    #[test]
    fn owner_auth_state_mle_round_zero_extracts_spend_secret() {
        for k in [1usize, 4, 13] {
            let secrets: Vec<_> = (0..k).map(|i| secret(i as u8 + 70)).collect();
            let shape = if k <= 4 {
                TxShape::Standard4x8
            } else {
                TxShape::Sweep25x2
            };
            let body = body_from_secrets(shape, &secrets, false);
            let inputs =
                owner_auth_inputs_from_body_and_live_secrets(&body, &secrets).expect("inputs");
            let circuit = OwnerAuthCircuit::build(inputs.layout);
            let mle = build_owner_auth_unified_from_inputs(&circuit, &inputs);
            let inv = mds_full_inverse();

            for owner_idx in 0..inputs.layout.owner_count {
                let slot = OwnerAuthCircuit::haddr_output_slot(owner_idx);
                let row0: [Block128; STATE_SIZE] =
                    std::array::from_fn(|lane| mle.state[inputs.layout.index(slot, 0, lane)]);
                let pre: [Block128; 2] = std::array::from_fn(|lane| {
                    let mut acc = Block128::ZERO;
                    for post_lane in 0..STATE_SIZE {
                        acc += inv[lane][post_lane] * row0[post_lane];
                    }
                    acc
                });
                assert_eq!(pre, inputs.spend_secret[owner_idx]);
                assert_eq!(
                    [
                        mle.state[inputs.layout.index(slot, N_ROUNDS, 0)],
                        mle.state[inputs.layout.index(slot, N_ROUNDS, 1)],
                    ],
                    inputs.expected_address[owner_idx]
                );
            }
        }
    }

    #[test]
    fn owner_auth_mle_roundtrip_all_layout_classes() {
        for k in [1usize, 3, 6, 12, 25] {
            let layout = OwnerAuthLayout::for_owner_count(k).unwrap();
            let state_ins: Vec<_> = (0..layout.live_slots)
                .map(|i| {
                    [
                        Block128::from(i as u128 + 1),
                        Block128::from(i as u128 + 2),
                        Block128::from(i as u128 + 3),
                        Block128::from(i as u128 + 4),
                    ]
                })
                .collect();
            let (mle, witnesses) = build_owner_auth_unified_mle(layout, &state_ins);
            assert_eq!(witnesses.len(), layout.live_slots);
            assert_eq!(mle.state.len(), layout.cells());
            for slot in layout.live_slots..layout.padded_slots {
                for round in 0..ROUND_LIMIT {
                    for elem in 0..STATE_SIZE {
                        let idx = layout.index(slot, round, elem);
                        assert_eq!(mle.state[idx], Block128::ZERO);
                        assert_eq!(mle.s_in[idx], Block128::ZERO);
                        assert_eq!(mle.s_out[idx], Block128::ZERO);
                    }
                }
            }
        }
    }

    #[test]
    fn owner_auth_killshot_roundtrip_repeated_owner_k1() {
        let s = secret(9);
        let body = body_from_secrets(TxShape::Sweep25x2, std::slice::from_ref(&s), true);
        let live_secrets: Vec<_> = body
            .inputs
            .iter()
            .filter(|i| i.valid)
            .map(|i| i.spend_secret.clone())
            .collect();
        let inputs =
            owner_auth_inputs_from_body_and_live_secrets(&body, &live_secrets).expect("inputs");
        assert_eq!(inputs.layout.owner_count, 1);
        let circuit = OwnerAuthCircuit::build(inputs.layout);
        let mut ch = owner_auth_gkr_channel();
        let (proof, reductions) = prove_owner_auth_killshot(&circuit, &inputs, &mut ch);
        assert!(discharge_owner_auth_reductions_native(
            &circuit,
            &inputs,
            &reductions
        ));

        let mut ch_v = owner_auth_gkr_channel();
        let verified = verify_owner_auth_killshot(&proof, &circuit, &inputs.to_public(), &mut ch_v)
            .expect("verify");
        assert_eq!(verified.state.point.len(), inputs.layout.num_vars);
    }

    #[test]
    fn owner_auth_killshot_roundtrip_layout_classes() {
        for k in [1usize, 2, 4, 7, 13] {
            let secrets: Vec<_> = (0..k).map(|i| secret(i as u8 + 20)).collect();
            let shape = if k <= 4 {
                TxShape::Standard4x8
            } else {
                TxShape::Sweep25x2
            };
            let body = body_from_secrets(shape, &secrets, false);
            let inputs =
                owner_auth_inputs_from_body_and_live_secrets(&body, &secrets).expect("inputs");
            assert_eq!(inputs.layout.owner_count, k);
            let circuit = OwnerAuthCircuit::build(inputs.layout);
            let mut ch = owner_auth_gkr_channel();
            let (proof, _reductions) = prove_owner_auth_killshot(&circuit, &inputs, &mut ch);
            let mut ch_v = owner_auth_gkr_channel();
            verify_owner_auth_killshot(&proof, &circuit, &inputs.to_public(), &mut ch_v)
                .expect("verify owner auth");
        }
    }

    #[test]
    fn owner_auth_killshot_rejects_tamper() {
        let secrets = [secret(41), secret(42)];
        let body = body_from_secrets(TxShape::Standard4x8, &secrets, false);
        let inputs = owner_auth_inputs_from_body_and_live_secrets(&body, &secrets).expect("inputs");
        let circuit = OwnerAuthCircuit::build(inputs.layout);
        let mut ch = owner_auth_gkr_channel();
        let (mut proof, _) = prove_owner_auth_killshot(&circuit, &inputs, &mut ch);
        proof.kill_shot.main.state_at_r += Block128::ONE;

        let mut ch_v = owner_auth_gkr_channel();
        assert!(
            verify_owner_auth_killshot(&proof, &circuit, &inputs.to_public(), &mut ch_v).is_none()
        );
    }

    #[test]
    fn owner_auth_rejects_canonical_statement_tamper() {
        let secrets = [secret(51), secret(52)];
        let body = body_from_secrets(TxShape::Standard4x8, &secrets, false);
        let inputs = owner_auth_inputs_from_body_and_live_secrets(&body, &secrets).expect("inputs");
        let circuit = OwnerAuthCircuit::build(inputs.layout);
        let mut ch = owner_auth_gkr_channel();
        let (proof, _) = prove_owner_auth_killshot(&circuit, &inputs, &mut ch);

        let mut wrong_hash = inputs.to_public();
        wrong_hash.tx_body_hash[0] += Block128::ONE;
        let mut ch_v = owner_auth_gkr_channel();
        assert!(verify_owner_auth_killshot(&proof, &circuit, &wrong_hash, &mut ch_v).is_none());

        let mut wrong_slot = inputs.to_public();
        wrong_slot.live_slot_indices[0] ^= 1;
        let mut ch_v = owner_auth_gkr_channel();
        assert!(verify_owner_auth_killshot(&proof, &circuit, &wrong_slot, &mut ch_v).is_none());

        let mut wrong_mapping = inputs.to_public();
        wrong_mapping.input_to_group[0] = 1;
        let mut ch_v = owner_auth_gkr_channel();
        assert!(verify_owner_auth_killshot(&proof, &circuit, &wrong_mapping, &mut ch_v).is_none());
    }

    #[test]
    fn owner_auth_rejects_boundary_batch_and_pcs_tamper() {
        let secrets = [secret(61), secret(62)];
        let body = body_from_secrets(TxShape::Standard4x8, &secrets, false);
        let inputs = owner_auth_inputs_from_body_and_live_secrets(&body, &secrets).expect("inputs");
        let circuit = OwnerAuthCircuit::build(inputs.layout);
        let mut ch = owner_auth_gkr_channel();
        let (proof, _) = prove_owner_auth_killshot(&circuit, &inputs, &mut ch);

        let mut bad_boundary = proof.clone();
        bad_boundary.boundary.state_at_r += Block128::ONE;
        let mut ch_v = owner_auth_gkr_channel();
        assert!(verify_owner_auth_killshot(
            &bad_boundary,
            &circuit,
            &inputs.to_public(),
            &mut ch_v
        )
        .is_none());

        let mut bad_batch = proof.clone();
        bad_batch.batch.b_final += Block128::ONE;
        let mut ch_v = owner_auth_gkr_channel();
        assert!(
            verify_owner_auth_killshot(&bad_batch, &circuit, &inputs.to_public(), &mut ch_v)
                .is_none()
        );

        let mut bad_pcs = proof;
        bad_pcs.pcs.opening.all_openings[0] += Block128::ONE;
        let mut ch_v = owner_auth_gkr_channel();
        assert!(
            verify_owner_auth_killshot(&bad_pcs, &circuit, &inputs.to_public(), &mut ch_v)
                .is_none()
        );
    }
}
