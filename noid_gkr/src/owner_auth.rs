// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

#![allow(clippy::needless_range_loop)]
#![allow(clippy::too_many_arguments)]

//! Owner-authorization AuthGKR.
//!
//! Production statements have exactly one owner and one secret, independent
//! of live-input count. Layout-parameterized circuit tests remain internal.

use std::sync::OnceLock;

use noid_core::hardware::{clmul_gcm, flat_to_tower_u128, square_flat_u128, tower_to_flat_u128};
use noid_core::mle::eq::eq_ind_partial_eval;
use noid_core::mle::evaluate::{evaluate_flat, evaluate_preflat};
use noid_core::packed::pow7::pow7_block128;
use noid_core::sumcheck::{CompressedRoundPolynomial, RoundPolynomial};
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

pub const OWNER_AUTH_PIN_LANES: usize = 2;
pub const OWNER_AUTH_ROUND_VARS: usize = 7;
pub const OWNER_AUTH_ELEM_VARS: usize = 2;
pub const OWNER_AUTH_LIVE_SLOTS: usize = 1;
pub const OWNER_AUTH_SLOT_BITS: usize = 0;
pub const OWNER_AUTH_NUM_VARS: usize = OWNER_AUTH_ROUND_VARS + OWNER_AUTH_ELEM_VARS;
pub const OWNER_AUTH_PADDED_SLOTS: usize = 1;
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

/// The single protocol owner-auth geometry.
///
/// This zero-sized marker deliberately has no owner-count constructor or
/// variable fields: every transaction proves exactly one `H_ADDR(secret)`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OwnerAuthLayout;

impl OwnerAuthLayout {
    pub const FIXED: Self = Self;

    #[inline]
    pub fn cells(self) -> usize {
        1usize << OWNER_AUTH_NUM_VARS
    }

    #[inline]
    pub fn index(self, slot: usize, round: usize, elem: usize) -> usize {
        debug_assert!(slot < OWNER_AUTH_PADDED_SLOTS);
        debug_assert!(round < ROUND_LIMIT);
        debug_assert!(elem < ELEM_LIMIT);
        (slot << (OWNER_AUTH_ROUND_VARS + OWNER_AUTH_ELEM_VARS))
            | (round << OWNER_AUTH_ELEM_VARS)
            | elem
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerAuthSlotRole {
    HAddrPerm,
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
    pub fn build() -> Self {
        let layout = OwnerAuthLayout::FIXED;
        let iv_addr = capacity_iv(TAG_ADDRFIX);
        let slots = vec![OwnerAuthSlotDescriptor {
            id: 0,
            role: OwnerAuthSlotRole::HAddrPerm,
            capacity_iv: iv_addr,
            is_head: true,
            prev_output_src: None,
        }];
        Self { layout, slots }
    }

    #[inline]
    pub fn haddr_output_slot() -> usize {
        0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OwnerAuthPublicInputs {
    pub layout: OwnerAuthLayout,
    pub tx_body_hash: [Block128; 2],
    pub expected_address: [Block128; 2],
}

impl OwnerAuthPublicInputs {
    pub fn new(tx_body_hash: [Block128; 2], expected_address: [Block128; 2]) -> Self {
        Self {
            layout: OwnerAuthLayout::FIXED,
            tx_body_hash,
            expected_address,
        }
    }
}

pub struct OwnerAuthInputs {
    pub layout: OwnerAuthLayout,
    spend_secret: [Block128; 2],
    pub tx_body_hash: [Block128; 2],
    pub expected_address: [Block128; 2],
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
            expected_address: self.expected_address,
        }
    }

    pub fn from_parts(public: &OwnerAuthPublicInputs, spend_secret: [Block128; 2]) -> Self {
        Self {
            layout: public.layout,
            spend_secret,
            tx_body_hash: public.tx_body_hash,
            expected_address: public.expected_address,
        }
    }
}

impl std::fmt::Debug for OwnerAuthInputs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnerAuthInputs")
            .field("layout", &self.layout)
            .field("spend_secret", &"[REDACTED]")
            .field("tx_body_hash", &self.tx_body_hash)
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

/// Evaluated permutation states used internally while constructing an
/// owner-authorization proof.
///
/// This is deliberately named a *trace* witness so it cannot be confused
/// with [`crate::OwnerAuthWitness`], the wallet-facing one-secret capability.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct OwnerAuthTraceWitness {
    pub slots: Vec<OwnerAuthSlotState>,
    pub derived_address: [Block128; 2],
}

pub fn evaluate_owner_auth(
    circuit: &OwnerAuthCircuit,
    inputs: &OwnerAuthInputs,
) -> OwnerAuthTraceWitness {
    assert_eq!(inputs.layout, circuit.layout);
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

    let derived_address = slots[OwnerAuthCircuit::haddr_output_slot()].digest();

    OwnerAuthTraceWitness {
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
        OwnerAuthSlotRole::HAddrPerm => {
            let [a, b] = inputs.spend_secret;
            [a, b, iv_hi, iv_lo]
        }
    }
}

pub fn compute_owner_auth_boundary(
    circuit: &OwnerAuthCircuit,
    spend_secret: [Block128; 2],
    tx_body_hash: [Block128; 2],
) -> [Block128; 2] {
    let inputs = OwnerAuthInputs {
        layout: circuit.layout,
        spend_secret,
        tx_body_hash,
        expected_address: [Block128::ZERO; 2],
    };
    let w = evaluate_owner_auth(circuit, &inputs);
    w.derived_address
}

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
        assert!(slot < OWNER_AUTH_LIVE_SLOTS, "slot out of range");
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
        OWNER_AUTH_LIVE_SLOTS,
        "expected one state input per live owner-auth slot"
    );
    let mut mle = OwnerAuthUnifiedMle::zero(layout);
    let mut witnesses = Vec::with_capacity(OWNER_AUTH_LIVE_SLOTS);
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
    let _ = layout;
    (idx >> SLOT_LO) & ((1 << OWNER_AUTH_SLOT_BITS) - 1)
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
    for slot in 0..OWNER_AUTH_LIVE_SLOTS {
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
    for slot in 0..OWNER_AUTH_LIVE_SLOTS {
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
    for slot in 0..OWNER_AUTH_LIVE_SLOTS {
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
        if slot >= OWNER_AUTH_LIVE_SLOTS {
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
    /// Flat (GCM-basis) copies of the same tables for the verifier's final
    /// MLE evaluations (`evaluate_preflat` folds with clmul instead of tower
    /// multiplication). Built once per layout alongside the tower tables.
    mds_lane_dec_flat: [Vec<u128>; STATE_SIZE],
    sigma_lane_dec_flat: [Vec<u128>; STATE_SIZE],
    rc_lane_dec_flat: [Vec<u128>; STATE_SIZE],
}

fn owner_auth_table_to_flat(table: &[Block128]) -> Vec<u128> {
    use noid_core::hardware::tower_to_flat_u128;
    table.iter().map(|v| tower_to_flat_u128(v.0)).collect()
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
    let mds_lane_dec_flat = std::array::from_fn(|j| owner_auth_table_to_flat(&mds_lane_dec[j]));
    let sigma_lane_dec_flat = std::array::from_fn(|j| owner_auth_table_to_flat(&sigma_lane_dec[j]));
    let rc_lane_dec_flat = std::array::from_fn(|j| owner_auth_table_to_flat(&rc_lane_dec[j]));
    OwnerAuthPublicTables {
        mds_lane_dec,
        sigma_lane_dec,
        rc_lane_dec,
        mds_lane_dec_flat,
        sigma_lane_dec_flat,
        rc_lane_dec_flat,
    }
}

fn owner_auth_public_tables(layout: OwnerAuthLayout) -> &'static OwnerAuthPublicTables {
    static TABLES: OnceLock<OwnerAuthPublicTables> = OnceLock::new();
    TABLES.get_or_init(|| build_owner_auth_public_tables(layout))
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
    debug_assert_eq!(rho.len(), OWNER_AUTH_NUM_VARS);
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
    pub round_polys: Vec<CompressedRoundPolynomial<Block128>>,
    pub state_at_r: Block128,
    pub state_lane_dec_at_r: [Block128; STATE_SIZE],
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OwnerAuthShiftReduction {
    pub r_double_prime: Vec<Block128>,
    pub state_at_r2: Block128,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OwnerAuthBoundaryProof {
    pub round_polys: Vec<BatchEvalRound>,
    pub state_at_r: Block128,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

    let rho: Vec<Block128> = (0..OWNER_AUTH_NUM_VARS)
        .map(|_| channel.squeeze())
        .collect();
    let tabs = build_owner_state_tables(mle, &rho);
    let mut tabs = OwnerStateFlatTables::from_tower(tabs);

    let mut round_polys = Vec::with_capacity(OWNER_AUTH_NUM_VARS);
    let mut r_prime = vec![Block128::ZERO; OWNER_AUTH_NUM_VARS];
    for round in 0..OWNER_AUTH_NUM_VARS {
        let poly = compute_owner_state_round_polynomial_flat(&tabs);
        let wire = CompressedRoundPolynomial::compress(&poly);
        for &c in &wire.coeffs_no_linear {
            channel.absorb(c);
        }
        let challenge = channel.squeeze();
        let challenge_flat = tower_to_flat_u128(challenge.to_u128());
        tabs.fold_flat(challenge_flat);
        r_prime[OWNER_AUTH_NUM_VARS - 1 - round] = challenge;
        round_polys.push(wire);
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
    if proof.round_polys.len() != OWNER_AUTH_NUM_VARS {
        return None;
    }
    for p in &proof.round_polys {
        if p.degree() != OWNER_AUTH_STATE_ROUND_DEGREE {
            return None;
        }
    }

    let rho: Vec<Block128> = (0..OWNER_AUTH_NUM_VARS)
        .map(|_| channel.squeeze())
        .collect();

    let mut expected = Block128::ZERO;
    let mut r_prime = vec![Block128::ZERO; OWNER_AUTH_NUM_VARS];
    for (round, wire) in proof.round_polys.iter().enumerate() {
        // Linear coefficient reconstructed from the running claim — the
        // per-round sum check holds by construction.
        let poly = wire.reconstruct(expected);
        for &c in &wire.coeffs_no_linear {
            channel.absorb(c);
        }
        let challenge = channel.squeeze();
        expected = poly.evaluate(challenge);
        r_prime[OWNER_AUTH_NUM_VARS - 1 - round] = challenge;
    }

    let u_at_r = evaluate_flat(&owner_auth_build_u_table(layout, &rho), &r_prime);
    let public = owner_auth_public_tables(layout);
    let mut mds_lane_dec_at_r = [Block128::ZERO; STATE_SIZE];
    let mut sigma_lane_dec_at_r = [Block128::ZERO; STATE_SIZE];
    let mut rc_lane_dec_at_r = [Block128::ZERO; STATE_SIZE];
    for j in 0..STATE_SIZE {
        mds_lane_dec_at_r[j] = evaluate_preflat(&public.mds_lane_dec_flat[j], &r_prime);
        sigma_lane_dec_at_r[j] = evaluate_preflat(&public.sigma_lane_dec_flat[j], &r_prime);
        rc_lane_dec_at_r[j] = evaluate_preflat(&public.rc_lane_dec_flat[j], &r_prime);
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
    let r_slot = &r_prime[SLOT_LO..SLOT_LO + OWNER_AUTH_SLOT_BITS];
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

    use rayon::prelude::*;
    let fill = |(x, w_out): (usize, &mut Block128)| {
        let slot = owner_auth_slot_of(layout, x);
        let round = owner_auth_round_of(layout, x);
        let elem = owner_auth_elem_of(x);
        let w_direct = eq_slot_tab[slot] * eq_round_tab[round] * eq_elem_tab[elem];
        let es_er = eq_slot_tab[slot] * eq_round_at_inc[round];
        *w_out = d0 * w_direct + lane_state[elem] * es_er;
    };
    let mut w_state = vec![Block128::ZERO; layout.cells()];
    if layout.cells() >= 4096 {
        w_state.par_iter_mut().enumerate().for_each(fill);
    } else {
        w_state.iter_mut().enumerate().for_each(fill);
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
    debug_assert_eq!(evals_tower.len(), 3);
    BatchEvalRound {
        evals_at_1_2: [evals_tower[1], evals_tower[2]],
    }
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
        for &e in &poly.evals_at_1_2 {
            channel.absorb(e);
        }
        let challenge = channel.squeeze();
        let challenge_flat = tower_to_flat_u128(challenge.to_u128());
        expected = poly.evaluate(expected, challenge);
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
        for &e in &poly.evals_at_1_2 {
            channel.absorb(e);
        }
        let challenge = channel.squeeze();
        expected = poly.evaluate(expected, challenge);
        r.push(challenge);
    }
    r.reverse();
    let w_at_r = evaluate_flat(weights, &r);
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
    assert_eq!(main_red.r_prime.len(), OWNER_AUTH_NUM_VARS);
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
    if proof.round_polys.len() != OWNER_AUTH_NUM_VARS {
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
        OWNER_AUTH_NUM_VARS,
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
    let mut constraints = Vec::with_capacity(4);
    let haddr = OwnerAuthCircuit::haddr_output_slot();
    owner_boundary_push_pre_equals_const(&mut constraints, layout, haddr, 2, iv_addr[0]);
    owner_boundary_push_pre_equals_const(&mut constraints, layout, haddr, 3, iv_addr[1]);
    for lane in 0..OWNER_AUTH_PIN_LANES {
        owner_boundary_push_output_equals_const(
            &mut constraints,
            layout,
            haddr,
            lane,
            public.expected_address[lane],
        );
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

pub const OWNER_AUTH_BOUNDARY_DOMAIN_TAG: u128 = 0xA07D_0B47_B0A0_0001;

pub fn prove_owner_auth_boundary<T: FiatShamir<Block128>>(
    circuit: &OwnerAuthCircuit,
    public: &OwnerAuthPublicInputs,
    mle: &OwnerAuthUnifiedMle,
    channel: &mut T,
) -> (OwnerAuthBoundaryProof, OwnerAuthBoundaryReduction) {
    let constraints = owner_auth_boundary_constraints(circuit, public);
    channel.absorb(Block128::from(OWNER_AUTH_BOUNDARY_DOMAIN_TAG));
    channel.absorb(Block128::from(constraints.len() as u128));
    // Squeeze-diet RLC weights (powers of one challenge) — see
    // `batch_eval::squeeze_alphas` for the soundness note.
    let alphas = crate::batch_eval::squeeze_alphas(channel, constraints.len());
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
    // Squeeze-diet RLC weights (powers of one challenge) — see
    // `batch_eval::squeeze_alphas` for the soundness note.
    let alphas = crate::batch_eval::squeeze_alphas(channel, constraints.len());
    let (weights, target) = owner_boundary_weights_and_target(public.layout, &constraints, &alphas);
    let point = verify_weighted_state_sumcheck(
        &proof.round_polys,
        proof.state_at_r,
        OWNER_AUTH_NUM_VARS,
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
            .map(|p| p.coeffs_no_linear.len() * 16)
            .sum();
        let shift_polys: usize = self
            .kill_shot
            .shift
            .round_polys
            .iter()
            .map(|p| p.evals_at_1_2.len() * 16)
            .sum();
        let boundary_polys: usize = self
            .boundary
            .round_polys
            .iter()
            .map(|p| p.evals_at_1_2.len() * 16)
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

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

/// Domain tag for the minimal one-owner public statement.
pub const OWNER_AUTH_GKR_DOMAIN_TAG: u128 = 0xA07D_0B47_CAFE_0004;

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
    // Keep the fixed geometry explicitly domain-separated in the transcript.
    channel.absorb(Block128::from(1u128));
    channel.absorb(Block128::from(OWNER_AUTH_LIVE_SLOTS as u128));
    channel.absorb(Block128::from(OWNER_AUTH_SLOT_BITS as u128));
    channel.absorb(Block128::from(OWNER_AUTH_NUM_VARS as u128));
    channel.absorb(Block128::from(OWNER_AUTH_PADDED_SLOTS as u128));
    absorb_pair(channel, &inputs.tx_body_hash);
    absorb_pair(channel, &inputs.expected_address);
}

pub fn build_owner_auth_unified_from_inputs(
    circuit: &OwnerAuthCircuit,
    inputs: &OwnerAuthInputs,
) -> OwnerAuthUnifiedMle {
    let w = evaluate_owner_auth(circuit, inputs);
    debug_assert_eq!(w.slots.len(), OWNER_AUTH_LIVE_SLOTS);
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
    debug_assert_eq!(witness.derived_address, inputs.expected_address);
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
    let mut committed = commit_auth_mle_column(mle.state.as_slice(), OWNER_AUTH_NUM_VARS);

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
    let pcs = open_auth_mle_committed(&mut committed, OWNER_AUTH_NUM_VARS, &red);
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
    if circuit.layout != inputs.layout {
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

    let red = verify_batch_eval(&proof.batch, &state_claims, OWNER_AUTH_NUM_VARS, channel)?;
    if !verify_auth_mle_opening(&proof.pcs, OWNER_AUTH_NUM_VARS, &red) {
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
    evaluate_flat(&mle.state, &reductions.state.point) == reductions.state.value
}

#[derive(Debug)]
pub enum OwnerAuthStatementError {
    Canonical(OwnerAuthError),
    LiveInputCountOutOfRange { actual: usize, max: usize },
    SecretMismatch { input_position: usize },
}

impl From<OwnerAuthError> for OwnerAuthStatementError {
    fn from(value: OwnerAuthError) -> Self {
        Self::Canonical(value)
    }
}

impl std::fmt::Display for OwnerAuthStatementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Canonical(e) => write!(f, "canonical owner auth failed: {e}"),
            Self::LiveInputCountOutOfRange { actual, max } => {
                write!(
                    f,
                    "live input count out of range: actual {actual}, max {max}"
                )
            }
            Self::SecretMismatch { input_position } => {
                write!(f, "secret mismatch at live input position {input_position}")
            }
        }
    }
}

impl std::error::Error for OwnerAuthStatementError {}

pub fn owner_auth_public_from_statement(
    statement: &CanonicalOwnerAuth,
) -> Result<OwnerAuthPublicInputs, OwnerAuthStatementError> {
    Ok(OwnerAuthPublicInputs::new(
        statement.tx_body_hash.as_fields(),
        statement.input_owner.as_fields(),
    ))
}

pub fn owner_auth_public_from_body(
    body: &TxBody,
) -> Result<OwnerAuthPublicInputs, OwnerAuthStatementError> {
    let statement = canonical_owner_auth(body)?;
    owner_auth_public_from_statement(&statement)
}

/// One-secret trace boundary used by owner-auth proving and proof ledgers.
///
/// The secret is borrowed only long enough to validate the body's sole owner
/// and copy its two field limbs into zeroizing prover inputs.  It is never
/// returned, serialized, or repeated once per live input. Production wallets
/// should pass [`crate::OwnerAuthWitness`] to
/// [`crate::prove_wallet_authorization`] instead of constructing trace inputs.
pub fn owner_auth_trace_inputs_from_body_and_secret(
    body: &TxBody,
    spend_secret: &SpendSecret,
) -> Result<OwnerAuthInputs, OwnerAuthStatementError> {
    let statement = canonical_owner_auth(body)?;

    let input_position = body
        .live_inputs()
        .next()
        .map(|(index, _)| index)
        .expect("canonical user transaction has a live input");
    if derive_address(spend_secret) != statement.input_owner {
        return Err(OwnerAuthStatementError::SecretMismatch { input_position });
    }

    let public = owner_auth_public_from_statement(&statement)?;
    Ok(OwnerAuthInputs::from_parts(
        &public,
        spend_secret.as_fields(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{output_bitmap_bit, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS};

    fn secret(seed: u8) -> SpendSecret {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = seed.wrapping_mul(17).wrapping_add(i as u8);
        }
        SpendSecret(bytes)
    }

    fn body_from_secret(spend_secret: &SpendSecret, input_count: usize) -> TxBody {
        let owner = derive_address(spend_secret);
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        for (i, input) in inputs.iter_mut().enumerate().take(input_count) {
            *input = TxInput {
                slot_index: i as u32,
                amount: 10,
                creation_id: 0,
            };
        }
        let total = (input_count as u64) * 10;
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: 1_000,
            amount: total - 1,
            owner: Address([0xB0; 32]),
        };
        TxBody {
            epoch_anchor: [0xA5; 32],
            fee: 1,
            input_owner: owner,
            inputs,
            outputs,
            validity_bitmap: ((1u16 << input_count) - 1) | output_bitmap_bit(0),
            is_coinbase: false,
        }
    }

    fn trace_inputs(secret: &SpendSecret, hash_seed: u8) -> OwnerAuthInputs {
        let public = OwnerAuthPublicInputs::new(
            noid_poseidon2b::primitives::TxBodyHash([hash_seed; 32]).as_fields(),
            derive_address(secret).as_fields(),
        );
        OwnerAuthInputs::from_parts(&public, secret.as_fields())
    }

    #[test]
    fn owner_auth_layout_is_fixed_one_owner() {
        assert_eq!(OWNER_AUTH_LIVE_SLOTS, 1);
        assert_eq!(OWNER_AUTH_SLOT_BITS, 0);
        assert_eq!(OWNER_AUTH_NUM_VARS, 9);
        assert_eq!(OwnerAuthLayout::FIXED.cells(), 512);
    }

    #[test]
    fn owner_auth_oracle_matches_native_hash() {
        let circuit = OwnerAuthCircuit::build();
        let secret = secret(1);
        let tx_hash = noid_poseidon2b::primitives::TxBodyHash([0x55; 32]);
        let addr = compute_owner_auth_boundary(&circuit, secret.as_fields(), tx_hash.as_fields());
        assert_eq!(addr, derive_address(&secret).as_fields());
    }

    #[test]
    fn owner_auth_state_mle_round_zero_extracts_spend_secret() {
        let secret = secret(70);
        let inputs = trace_inputs(&secret, 0x71);
        let circuit = OwnerAuthCircuit::build();
        let mle = build_owner_auth_unified_from_inputs(&circuit, &inputs);
        let inv = mds_full_inverse();
        let slot = OwnerAuthCircuit::haddr_output_slot();
        let row0: [Block128; STATE_SIZE] =
            std::array::from_fn(|lane| mle.state[inputs.layout.index(slot, 0, lane)]);
        let pre: [Block128; 2] = std::array::from_fn(|lane| {
            let mut acc = Block128::ZERO;
            for post_lane in 0..STATE_SIZE {
                acc += inv[lane][post_lane] * row0[post_lane];
            }
            acc
        });
        assert_eq!(pre, inputs.spend_secret);
        assert_eq!(
            [
                mle.state[inputs.layout.index(slot, N_ROUNDS, 0)],
                mle.state[inputs.layout.index(slot, N_ROUNDS, 1)],
            ],
            inputs.expected_address
        );
    }

    #[test]
    fn owner_auth_mle_has_fixed_geometry() {
        let layout = OwnerAuthLayout::FIXED;
        let state_ins = [[
            Block128::from(1u128),
            Block128::from(2u128),
            Block128::from(3u128),
            Block128::from(4u128),
        ]];
        let (mle, witnesses) = build_owner_auth_unified_mle(layout, &state_ins);
        assert_eq!(witnesses.len(), OWNER_AUTH_LIVE_SLOTS);
        assert_eq!(mle.state.len(), layout.cells());
    }

    #[test]
    fn owner_auth_killshot_roundtrip_repeated_inputs_fixed_owner() {
        let s = secret(9);
        let body = body_from_secret(&s, 2);
        let inputs = owner_auth_trace_inputs_from_body_and_secret(&body, &s).expect("inputs");
        let circuit = OwnerAuthCircuit::build();
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
        assert_eq!(verified.state.point.len(), OWNER_AUTH_NUM_VARS);
    }

    #[test]
    fn owner_auth_killshot_roundtrip_fixed_layout() {
        let s = secret(20);
        let inputs = trace_inputs(&s, 0x72);
        let circuit = OwnerAuthCircuit::build();
        let mut ch = owner_auth_gkr_channel();
        let (proof, _reductions) = prove_owner_auth_killshot(&circuit, &inputs, &mut ch);
        let mut ch_v = owner_auth_gkr_channel();
        verify_owner_auth_killshot(&proof, &circuit, &inputs.to_public(), &mut ch_v)
            .expect("verify owner auth");
    }

    #[test]
    fn owner_auth_v3_transcript_rejects_v4_proof() {
        const OWNER_AUTH_GKR_V3_DOMAIN_TAG: u128 = 0xA07D_0B47_CAFE_0003;
        let spend_secret = secret(33);
        let body = body_from_secret(&spend_secret, 1);
        let inputs =
            owner_auth_trace_inputs_from_body_and_secret(&body, &spend_secret).expect("inputs");
        let circuit = OwnerAuthCircuit::build();
        let mut prover_channel = owner_auth_gkr_channel();
        let (proof, _) = prove_owner_auth_killshot(&circuit, &inputs, &mut prover_channel);

        let mut old_channel = Poseidon2bChannel::new();
        old_channel.absorb(Block128::from(OWNER_AUTH_GKR_V3_DOMAIN_TAG));
        assert!(
            verify_owner_auth_killshot(&proof, &circuit, &inputs.to_public(), &mut old_channel,)
                .is_none(),
            "a v4 proof must not verify under the retired v3 transcript"
        );
    }

    #[test]
    fn owner_auth_killshot_rejects_tamper() {
        let secret = secret(41);
        let inputs = trace_inputs(&secret, 0x73);
        let circuit = OwnerAuthCircuit::build();
        let mut ch = owner_auth_gkr_channel();
        let (mut proof, _) = prove_owner_auth_killshot(&circuit, &inputs, &mut ch);
        proof.kill_shot.main.state_at_r += Block128::ONE;

        let mut ch_v = owner_auth_gkr_channel();
        assert!(
            verify_owner_auth_killshot(&proof, &circuit, &inputs.to_public(), &mut ch_v).is_none()
        );
    }

    #[test]
    fn owner_auth_rejects_tampered_or_off_shape_round_polys() {
        let secret = secret(71);
        let inputs = trace_inputs(&secret, 0x74);
        let circuit = OwnerAuthCircuit::build();
        let prove = || {
            let mut ch = owner_auth_gkr_channel();
            prove_owner_auth_killshot(&circuit, &inputs, &mut ch).0
        };

        // Compressed rounds have no per-round sum check; a flipped
        // coefficient must still die at the final constraint check.
        for (poly_idx, coeff_idx) in [(0usize, 0usize), (2, 7)] {
            let mut proof = prove();
            proof.kill_shot.main.round_polys[poly_idx].coeffs_no_linear[coeff_idx] += Block128::ONE;
            let mut ch_v = owner_auth_gkr_channel();
            assert!(
                verify_owner_auth_killshot(&proof, &circuit, &inputs.to_public(), &mut ch_v)
                    .is_none()
            );
        }

        // Wire length is an exact shape check in both directions.
        let mut proof = prove();
        proof.kill_shot.main.round_polys[1].coeffs_no_linear.pop();
        let mut ch_v = owner_auth_gkr_channel();
        assert!(
            verify_owner_auth_killshot(&proof, &circuit, &inputs.to_public(), &mut ch_v).is_none()
        );

        let mut proof = prove();
        proof.kill_shot.main.round_polys[1]
            .coeffs_no_linear
            .push(Block128::ZERO);
        let mut ch_v = owner_auth_gkr_channel();
        assert!(
            verify_owner_auth_killshot(&proof, &circuit, &inputs.to_public(), &mut ch_v).is_none()
        );
    }

    #[test]
    fn owner_auth_rejects_canonical_statement_tamper() {
        let secret = secret(51);
        let inputs = trace_inputs(&secret, 0x75);
        let circuit = OwnerAuthCircuit::build();
        let mut ch = owner_auth_gkr_channel();
        let (proof, _) = prove_owner_auth_killshot(&circuit, &inputs, &mut ch);

        let mut wrong_hash = inputs.to_public();
        wrong_hash.tx_body_hash[0] += Block128::ONE;
        let mut ch_v = owner_auth_gkr_channel();
        assert!(verify_owner_auth_killshot(&proof, &circuit, &wrong_hash, &mut ch_v).is_none());

        let mut wrong_address = inputs.to_public();
        wrong_address.expected_address[0] += Block128::ONE;
        let mut ch_v = owner_auth_gkr_channel();
        assert!(verify_owner_auth_killshot(&proof, &circuit, &wrong_address, &mut ch_v).is_none());
    }

    #[test]
    fn owner_auth_rejects_boundary_batch_and_pcs_tamper() {
        let secret = secret(61);
        let inputs = trace_inputs(&secret, 0x76);
        let circuit = OwnerAuthCircuit::build();
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
        bad_pcs.pcs.opening.value += Block128::ONE;
        let mut ch_v = owner_auth_gkr_channel();
        assert!(
            verify_owner_auth_killshot(&bad_pcs, &circuit, &inputs.to_public(), &mut ch_v)
                .is_none()
        );
    }
}
