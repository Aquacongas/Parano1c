// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage G — Block Folding (Deferred-Opening).
//!
//! See `DESIGN.md` in this crate for the full specification.
//!
//! # Protocol summary
//!
//! 1. One interleaved Merkle cap covering all N*n_per_tx columns.
//! 2. N per-tx Spine/Auth Kill-Shot proofs.
//! 3. N per-tx *algebraic* STARK transcripts (no FRI per tx).
//! 4. One block-level multipoint sumcheck reducing N per-tx terminal
//!    claims to a single `(r_block, h_block)`.
//! 5. One single FRI-Binius mixed opening at r_block.

#![allow(clippy::too_many_arguments)]

pub mod channel;
pub mod full_node;

use crate::channel::{
    block_multipoint_channel, compute_tx_transcript_digest, merkle_reduce,
    per_tx_algebraic_channel, state_binding_channel,
};
use noid_air::airs::block_state_binding::BlockStateBindingAir;
use noid_air::{Air, FixedColumns};
use noid_core::mle::{eq::eq_ind_partial_eval, split::split_mle_into_slices};
use noid_core::transcript::FiatShamir;
use noid_core::{AdditiveNTT, Block128, TowerField};
use noid_fri::hasher::Blake3Hasher;
use noid_fri_binius::{
    interleaved_commit, prove_mixed_opening, verify_mixed_opening, InterleavedCommitment,
    MixedOpeningProof, COMPACT_NUM_QUERIES,
};
use noid_gkr::{
    auth_gkr_channel, prove_block_spine_killshot, reconstruct_slot_states, verify_auth_killshot,
    verify_block_spine_killshot, AuthCircuit, AuthProofKillShot, AuthPublicInputs, BlockSpineProof,
    SpineCircuit, SpineInputs,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_poseidon2b::primitives::TxBodyHash;
use noid_stark::interleaved::{
    prove_air_interleaved_algebraic, verify_air_interleaved_algebraic, AlgebraicStarkProof,
};
use noid_stark::{SliceClaim, VerifyError};
use noid_tx::PublicInputs;
use rayon::prelude::*;

const BASE_LOG: usize = 13;
const BLOCK_MULTIPOINT_TAG: u128 = 0xFFFB_0000_0000_0000;

// ---------------------------------------------------------------------------
// Public metadata
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockPublicMeta {
    pub prev_block_state_root: [u8; 32],
    pub n_tx: u32,
    pub n_air_per_tx: u32,
    pub n_auth_slices_per_tx: u32,
    pub log_rows: u32,
    /// Number of block-level spine state slices committed to FRI.
    pub n_block_spine_slices: u32,
    /// Number of state binding AIR instances (one per touched segment; 0 = no state binding).
    pub n_state_bindings: u32,
    /// Number of columns per state binding AIR instance (0 if none).
    pub state_binding_n_cols: u32,
    /// Log-rows of each state binding AIR instance.
    pub state_binding_log_rows: u32,
}

// ---------------------------------------------------------------------------
// BlockProof
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct BlockProof {
    pub meta: BlockPublicMeta,
    /// Single interleaved commitment covering all columns (per-tx + block spine + state binding).
    pub commitment: InterleavedCommitment,
    /// Public inputs for every transaction in order.
    pub tx_pis: Vec<PublicInputs>,
    /// Unified block spine Kill-Shot proof (covers all txs in one shot).
    pub block_spine_proof: BlockSpineProof,
    /// AuthGKR Kill-Shot proofs (one per tx).
    pub tx_auth_proofs: Vec<AuthProofKillShot>,
    /// Algebraic STARK transcripts — no FRI, one per tx.
    pub tx_algebraic: Vec<AlgebraicStarkProof>,
    /// Algebraic STARK transcripts for state binding AIRs (one per touched segment).
    /// Empty when there is no state binding.
    pub state_binding_algebraics: Vec<AlgebraicStarkProof>,
    /// Per-tx column openings at the per-tx terminal points r''_k.
    /// Flat layout: `block_col_openings[k*n_per_tx .. (k+1)*n_per_tx]`.
    /// Block spine slices follow, then state binding.
    pub block_col_openings: Vec<Block128>,
    /// Block-level degree-2 multipoint sumcheck rounds (log_rows of them).
    pub block_multipoint_rounds: Vec<Vec<Block128>>,
    /// Single FRI-Binius mixed opening at r_block.
    pub mixed_opening: MixedOpeningProof,
}

impl BlockProof {
    pub fn byte_len(&self) -> usize {
        let cap = self.commitment.cap.hashes.len() * 32;
        let alg: usize = self.tx_algebraic.iter().map(|a| a.byte_len()).sum();
        let sb_alg: usize = self
            .state_binding_algebraics
            .iter()
            .map(|a| a.byte_len())
            .sum();
        let spine = self.block_spine_proof.byte_len();
        let auth: usize = self.tx_auth_proofs.iter().map(|a| a.byte_len()).sum();
        let col_open = self.block_col_openings.len() * 16;
        let mp: usize = self
            .block_multipoint_rounds
            .iter()
            .map(|r| r.len() * 16)
            .sum();
        let mixed = self.mixed_opening.byte_len();
        cap + alg + sb_alg + spine + auth + col_open + mp + mixed
    }
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum ProveBlockError {
    EmptyBlock,
}

#[derive(Debug)]
pub enum VerifyBlockError {
    ShapeMismatch,
    BlockSpineKillShot,
    BlockSpineSliceReconstruction,
    AuthKillShot(usize),
    AuthSpineBridge(usize),
    AuthSliceReconstruction(usize),
    AlgebraicStark(usize, VerifyError),
    BlockMultipoint,
    FriFailed(String),
}

// ---------------------------------------------------------------------------
// Per-tx witness bundle
// ---------------------------------------------------------------------------

pub struct TxBlockWitness<'a> {
    pub air: &'a dyn Air,
    pub trace: &'a noid_air::Trace,
    pub pi: &'a PublicInputs,
    pub spine_inputs: &'a SpineInputs,
    /// Public-only auth boundary (no spend_secret). The block prover
    /// never sees private keys.
    pub auth_public: &'a AuthPublicInputs,
    /// Pre-built auth proof from the wallet. The block prover includes
    /// this as-is without re-proving.
    pub auth_proof: &'a AuthProofKillShot,
    /// Pre-built auth MLE slices from the wallet (2 slices, each
    /// length 2^BASE_LOG). Needed for the interleaved commitment.
    pub auth_slices: &'a [Vec<Block128>],
}

// ---------------------------------------------------------------------------
// Block-level state binding witness bundle
// ---------------------------------------------------------------------------

/// Optional state binding witness for prove_block.
/// When present, the BlockStateBindingAir columns are committed alongside
/// per-tx columns and proven via the shared block channel.
pub struct StateBindingBlockWitness<'a> {
    pub air: &'a BlockStateBindingAir,
    pub columns: Vec<Vec<Block128>>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hash_to_fields(h: &[u8; 32]) -> [Block128; 2] {
    let lo = u128::from_le_bytes(h[..16].try_into().unwrap());
    let hi = u128::from_le_bytes(h[16..].try_into().unwrap());
    [Block128::from(lo), Block128::from(hi)]
}

fn absorb_cap_into_p2b(ch: &mut Poseidon2bChannel, cap: &noid_fri_binius::MerkleCap) {
    for hash in &cap.hashes {
        let [h0, h1] = hash_to_fields(hash);
        ch.absorb(h0);
        ch.absorb(h1);
    }
}

fn reduction_to_transcript(point: &[Block128], value: Block128) -> Vec<Block128> {
    let mut out = Vec::with_capacity(point.len() + 1);
    out.extend_from_slice(point);
    out.push(value);
    out
}

fn build_auth_slice_claims(
    n_air_cols: usize,
    auth_r_low: &[Block128],
    auth_vals: &[Block128],
) -> Vec<SliceClaim> {
    let mut claims = Vec::with_capacity(2);
    for (i, &val) in auth_vals.iter().enumerate() {
        claims.push(SliceClaim {
            col_index: n_air_cols + i,
            eval_point: auth_r_low.to_vec(),
            value: val,
        });
    }
    claims
}

// ---------------------------------------------------------------------------
// prove_block
// ---------------------------------------------------------------------------

pub fn prove_block(
    prev_block_state_root: [u8; 32],
    witnesses: &[TxBlockWitness<'_>],
    state_bindings: &[StateBindingBlockWitness<'_>],
) -> Result<BlockProof, ProveBlockError> {
    let n_tx = witnesses.len();
    assert!(n_tx >= 1, "block must have at least one transaction");

    let spine_circuit = SpineCircuit::build();
    let auth_circuit = AuthCircuit::build();

    let n_air_cols = witnesses[0].air.n_columns();
    let n_auth_slices: usize = 2;
    let n_per_tx = n_air_cols + n_auth_slices;
    let log_len = noid_stark::padded_log_len(witnesses[0].trace.log_rows);

    // -------------------------------------------------------------------------
    // Stage 1: State continuity is now enforced by BlockStateBinding (S.5).
    // -------------------------------------------------------------------------

    // -------------------------------------------------------------------------
    // Stage 2: Build per-tx column pools + block spine MLE.
    // -------------------------------------------------------------------------
    // Per-tx: AIR columns (padded) + 2 auth slices.
    // Block-level: unified spine state MLE split into slices.

    // Build fixed columns once from the first witness AIR (all txs share the
    // same AIR shape).  Fixed columns (selectors / masks) are padded once and
    // reused across all N transactions via zero-copy refs, avoiding N-1 extra
    // copies of ~65 MB of selector data per block.
    let shared_fixed = FixedColumns::from_air(witnesses[0].air, witnesses[0].trace, log_len);

    struct TxPrep {
        /// Non-fixed AIR witness columns in ascending original column-index order.
        witness_cols: Vec<Vec<Block128>>,
        /// Per-tx auth slices (2 slices of length 2^BASE_LOG).
        auth_slices: Vec<Vec<Block128>>,
    }

    // Q.2b: Parallel prep loop.
    // Each tx's spine-state reconstruction and witness column padding are
    // fully independent; parallelize across txs with rayon.
    struct TxPrepBundle {
        slot_state_ins: Vec<[Block128; 4]>,
        prep: TxPrep,
    }
    let bundles: Vec<TxPrepBundle> = (0..n_tx)
        .into_par_iter()
        .map(|k| {
            let w = &witnesses[k];
            let spine_states = reconstruct_slot_states(&spine_circuit, w.spine_inputs);
            let slot_state_ins: Vec<[Block128; 4]> = spine_states.iter().map(|(s, _)| *s).collect();
            let witness_cols: Vec<Vec<Block128>> = w
                .trace
                .columns
                .iter()
                .enumerate()
                .filter(|(i, _)| !shared_fixed.is_fixed(*i))
                .map(|(_, col)| noid_stark::pad_column(col, log_len))
                .collect();
            TxPrepBundle {
                slot_state_ins,
                prep: TxPrep {
                    witness_cols,
                    auth_slices: w.auth_slices.to_vec(),
                },
            }
        })
        .collect();

    let mut all_slot_state_ins: Vec<[Block128; 4]> = Vec::with_capacity(n_tx * 59);
    let mut preps: Vec<TxPrep> = Vec::with_capacity(n_tx);
    for bundle in bundles {
        all_slot_state_ins.extend_from_slice(&bundle.slot_state_ins);
        preps.push(bundle.prep);
    }

    // Build unified block spine MLE and split state column into FRI slices.
    let block_spine_mle = noid_gkr::BlockSpineMle::build(n_tx, &all_slot_state_ins);
    let block_spine_num_vars = block_spine_mle.num_vars;
    let block_spine_slices =
        split_mle_into_slices(&block_spine_mle.state, block_spine_num_vars, BASE_LOG);
    let n_block_spine_slices = block_spine_slices.len();

    // -------------------------------------------------------------------------
    // Stage 3: Single block-wide interleaved commit.
    // Layout: [per-tx columns | block spine slices | state binding columns…].
    // Multiple state binding AIRs (one per dirty segment) are flattened.
    // -------------------------------------------------------------------------
    let n_state_bindings = state_bindings.len();
    let sb_n_cols_per_seg = state_bindings.first().map_or(0, |sb| sb.air.n_columns());
    let sb_log_rows = state_bindings.first().map_or(0, |sb| sb.air.log_rows());
    let sb_n_cols_total = sb_n_cols_per_seg * n_state_bindings;

    // Pad all state binding columns (flat across all AIR instances).
    let sb_padded_columns: Vec<Vec<Block128>> = state_bindings
        .iter()
        .flat_map(|sb| {
            sb.columns
                .iter()
                .map(|c| noid_stark::pad_column(c, log_len))
        })
        .collect();
    // Backward compat: use `sb_n_cols` as the total column count for existing calculations.
    let sb_n_cols = sb_n_cols_total;

    // Pad block spine slices to log_len (they may be shorter if num_vars < BASE_LOG).
    let spine_padded_slices: Vec<Vec<Block128>> = block_spine_slices
        .iter()
        .map(|s| noid_stark::pad_column(s, log_len))
        .collect();

    // Build the flat column-ref list for the interleaved commitment.
    // For each tx: fixed columns (zero-copy from shared_fixed) then witness then auth slices.
    let mut flat_refs: Vec<&[Block128]> =
        Vec::with_capacity(n_tx * n_per_tx + n_block_spine_slices + sb_n_cols);
    for p in &preps {
        let air_refs = shared_fixed.build_full_col_refs(n_air_cols, &p.witness_cols);
        flat_refs.extend_from_slice(&air_refs);
        for s in &p.auth_slices {
            flat_refs.push(s.as_slice());
        }
    }
    for s in &spine_padded_slices {
        flat_refs.push(s.as_slice());
    }
    for c in &sb_padded_columns {
        flat_refs.push(c.as_slice());
    }

    let ntt = AdditiveNTT::<Block128>::new(log_len + noid_fri::code::LOG_RATE);
    let hasher = Blake3Hasher::new();
    let (commitment, prover_state) = interleaved_commit(&flat_refs, &ntt, &hasher);
    let cap = &commitment.cap;

    // -------------------------------------------------------------------------
    // Stage 4: GKR Kill-Shots.
    //   (a) Unified block spine Kill-Shot (all txs in one shot).
    //   (b) Per-tx auth Kill-Shots (wallet pre-built, replayed for reductions).
    // -------------------------------------------------------------------------
    let tx_body_hashes: Vec<[Block128; 2]> = witnesses
        .iter()
        .map(|w| w.pi.tx_body_hash.as_fields())
        .collect();
    let auth_public_refs: Vec<&AuthPublicInputs> =
        witnesses.iter().map(|w| w.auth_public).collect();
    let auth_proof_refs: Vec<&AuthProofKillShot> = witnesses.iter().map(|w| w.auth_proof).collect();

    // (a) Unified block spine.
    let mut spine_channel = Poseidon2bChannel::new();
    absorb_cap_into_p2b(&mut spine_channel, cap);
    let (block_spine_proof, block_spine_reductions) = prove_block_spine_killshot(
        n_tx,
        &all_slot_state_ins,
        &tx_body_hashes,
        &mut spine_channel,
    );

    // Spine reduction -> slice bridge.
    // spine_r_low is the BASE_LOG-dimensional opening point for the spine slices.
    // For the multipoint sumcheck, all participants must share the same hypercube
    // dimension (log_len). When log_len > BASE_LOG, extend with zeros — the
    // zero-padded slices evaluate identically at (r_low, 0..0) as at r_low.
    let spine_r = &block_spine_reductions.state.point;
    let spine_r_low_base = &spine_r[..BASE_LOG];
    let spine_r_low: Vec<Block128> = {
        let mut v = spine_r_low_base.to_vec();
        v.resize(log_len, Block128::ZERO);
        v
    };
    let spine_extras = reduction_to_transcript(spine_r, block_spine_reductions.state.value);

    // (b) Per-tx auth Kill-Shots (parallel).
    struct AuthResult {
        auth_r_low: Vec<Block128>,
        auth_slice_vals: Vec<Block128>,
        extras_transcript: Vec<Block128>,
    }

    let auth_results: Vec<AuthResult> = (0..n_tx)
        .into_par_iter()
        .map(|k| {
            let prep = &preps[k];
            let mut ch = auth_gkr_channel();
            let auth_reductions = verify_auth_killshot(
                auth_proof_refs[k],
                &auth_circuit,
                auth_public_refs[k],
                &mut ch,
            )
            .expect("wallet-supplied auth proof must verify");

            let r_auth = auth_reductions.state.point.clone();
            let auth_r_low = r_auth[..BASE_LOG].to_vec();

            let auth_slice_vals: Vec<Block128> = prep
                .auth_slices
                .iter()
                .map(|s| noid_core::mle::evaluate::evaluate_slice(s, &auth_r_low))
                .collect();

            let auth_tr = reduction_to_transcript(&r_auth, auth_reductions.state.value);
            let mut extras = Vec::with_capacity(spine_extras.len() + auth_tr.len());
            extras.extend_from_slice(&spine_extras);
            extras.extend_from_slice(&auth_tr);

            AuthResult {
                auth_r_low,
                auth_slice_vals,
                extras_transcript: extras,
            }
        })
        .collect();

    // -------------------------------------------------------------------------
    // Stage 5: Q.2c — Parallel per-tx algebraic STARK proofs.

    //
    // Each tx uses an independent Fiat-Shamir channel seeded from:
    //   DOMAIN_TAG_TX_ALGEBRAIC || PROTOCOL_VERSION || state_root || cap || tx_index
    // This is safe because the cap already commits ALL columns (committed before
    // any challenge is drawn). The block-level binding happens in Stage 6 via
    // the Merkle reduction of all per-tx transcripts (Q.4a).
    // -------------------------------------------------------------------------
    struct TxAlgResult {
        alg: AlgebraicStarkProof,
        r_pp: Vec<Block128>,
        final_claim: Block128,
        lambdas: Vec<Block128>,
    }

    let tx_alg_results: Vec<TxAlgResult> = (0..n_tx)
        .into_par_iter()
        .map(|k| {
            let w = &witnesses[k];
            let prep = &preps[k];
            let auth_res = &auth_results[k];

            let slice_claims = build_auth_slice_claims(
                n_air_cols,
                &auth_res.auth_r_low,
                &auth_res.auth_slice_vals,
            );

            // Per-tx independent Fiat-Shamir channel (Q.2c / Q.1).
            let mut ch = per_tx_algebraic_channel(&prev_block_state_root, cap, k as u32);

            // Build full ordered column refs (fixed zero-copy + witness).
            let mut all_col_refs = shared_fixed.build_full_col_refs(n_air_cols, &prep.witness_cols);
            for s in &prep.auth_slices {
                all_col_refs.push(s.as_slice());
            }

            let (alg, r_pp, final_claim, lambdas) = prove_air_interleaved_algebraic(
                w.air,
                &all_col_refs,
                w.pi,
                &auth_res.extras_transcript,
                &slice_claims,
                log_len,
                &mut ch,
            );
            TxAlgResult {
                alg,
                r_pp,
                final_claim,
                lambdas,
            }
        })
        .collect();

    let mut tx_algebraic: Vec<AlgebraicStarkProof> = Vec::with_capacity(n_tx);
    let mut tx_r_pp: Vec<Vec<Block128>> = Vec::with_capacity(n_tx);
    let mut tx_claims: Vec<Block128> = Vec::with_capacity(n_tx);
    let mut tx_lambdas: Vec<Vec<Block128>> = Vec::with_capacity(n_tx);
    for r in tx_alg_results {
        tx_algebraic.push(r.alg);
        tx_r_pp.push(r.r_pp);
        tx_claims.push(r.final_claim);
        tx_lambdas.push(r.lambdas);
    }

    // -------------------------------------------------------------------------
    // Stage 5b: BlockStateBindingAir algebraic STARKs — one per segment AIR.
    //   Q.4: each gets a dedicated channel seeded with (prev_state_root, cap,
    //   n_tx, segment_index) to avoid sharing with per-tx channels.
    // -------------------------------------------------------------------------
    let empty_pi = PublicInputs {
        epoch_anchor: [0u8; 32],
        tx_body_hash: TxBodyHash([0u8; 32]),
        fee: 0,
        n_live_inputs: 0,
        n_live_outputs: 0,
        coinbase_credit: 0,
        log_slots: 0,
        claims_commitment: [0u8; 32],
        is_activation: [false; 8],
        is_deactivation: [false; 4],
    };

    // One algebraic proof + r_pp per state-binding AIR.
    struct SbResult {
        alg: AlgebraicStarkProof,
        r_pp: Vec<Block128>,
    }
    let sb_results: Vec<SbResult> = state_bindings
        .iter()
        .enumerate()
        .map(|(sb_idx, sb)| {
            // Channel seed: n_tx + sb_idx distinguishes each segment's channel.
            let mut sb_ch =
                state_binding_channel(&prev_block_state_root, cap, (n_tx + sb_idx) as u32);
            let col_offset = sb_idx * sb_n_cols_per_seg;
            let sb_col_refs: Vec<&[Block128]> = sb_padded_columns
                [col_offset..col_offset + sb_n_cols_per_seg]
                .iter()
                .map(|c| c.as_slice())
                .collect();
            let (alg, r_pp_sb, _, _) = prove_air_interleaved_algebraic(
                sb.air,
                &sb_col_refs,
                &empty_pi,
                &[],
                &[],
                log_len,
                &mut sb_ch,
            );
            SbResult { alg, r_pp: r_pp_sb }
        })
        .collect();

    let sb_algebraics: Vec<AlgebraicStarkProof> =
        sb_results.iter().map(|r| r.alg.clone()).collect();
    // r_pp per state-binding AIR — used in the multipoint sumcheck below.
    let sb_r_pp_list: Vec<Vec<Block128>> = sb_results.into_iter().map(|r| r.r_pp).collect();

    // -------------------------------------------------------------------------
    // Q.4a: Segmented Transcript Absorption.
    //
    // Each per-tx algebraic STARK produced an independent Fiat-Shamir transcript.
    // We summarise all transcripts into a single 32-byte Merkle root that the
    // block channel absorbs, providing soundness-equivalent binding to the
    // sequential approach while enabling parallel proving.
    // -------------------------------------------------------------------------
    let tx_digests: Vec<[u8; 32]> = (0..n_tx)
        .into_par_iter()
        .map(|k| {
            compute_tx_transcript_digest(
                k as u32,
                &tx_r_pp[k],
                &tx_algebraic[k].base_openings,
                &tx_lambdas[k],
                tx_claims[k],
            )
        })
        .collect();
    let transcript_root = merkle_reduce(&tx_digests);

    // -------------------------------------------------------------------------
    // Q.4: Block multipoint channel — fresh, domain-separated from per-tx channels.
    // -------------------------------------------------------------------------
    let mut block_channel = block_multipoint_channel(&prev_block_state_root, cap);
    let [tr0, tr1] = hash_to_fields(&transcript_root);
    block_channel.observe_field_elem(tr0);
    block_channel.observe_field_elem(tr1);

    // -------------------------------------------------------------------------
    // Stage 6 (§6): Block-level multipoint sumcheck.
    //
    // Participants:
    //   0..n_tx: per-tx (AIR + auth slices), each with n_per_tx columns
    //   n_tx: block spine slices participant (opened at spine_r_low)
    //   n_tx+1: state binding (if present)
    // -------------------------------------------------------------------------
    // One participant per state binding AIR (segment), plus spine and per-tx.
    let n_participants = n_tx + 1 + n_state_bindings; // +1 for spine
    let spine_participant_idx = n_tx;
    // State binding participants are at indices n_tx+1 .. n_tx+1+n_state_bindings.
    let sb_participant_base = n_tx + 1;

    // M2: Parallel per-tx column openings with thread-local scratch.
    // Eliminates ~n_tx * n_per_tx * 128 KB = ~1 GB of allocations for 100 txs.
    let total_cols = n_tx * n_per_tx + n_block_spine_slices + sb_n_cols;

    // M2 + flat-basis: evaluate_flat_with_scratch uses clmul_gcm (~4 ns/mul)
    // instead of tower-basis Karatsuba (~30 ns/mul) — 7-8x faster per column.
    thread_local! {
        static FLAT_SCRATCH: std::cell::RefCell<Vec<u128>> =
            std::cell::RefCell::new(Vec::new());
        static PT_SCRATCH: std::cell::RefCell<Vec<u128>> =
            std::cell::RefCell::new(Vec::new());
    }

    let tx_openings: Vec<Vec<Block128>> = (0..n_tx)
        .into_par_iter()
        .map(|k| {
            let r_pp_k = &tx_r_pp[k];
            let air_refs = shared_fixed.build_full_col_refs(n_air_cols, &preps[k].witness_cols);
            let mut cols_k = Vec::with_capacity(n_per_tx);
            FLAT_SCRATCH.with(|fs| {
                PT_SCRATCH.with(|ps| {
                    let mut flat = fs.borrow_mut();
                    let mut pt = ps.borrow_mut();
                    for col in &air_refs {
                        cols_k.push(noid_core::mle::evaluate::evaluate_flat_with_scratch(
                            col, r_pp_k, &mut flat, &mut pt,
                        ));
                    }
                    for auth_s in &preps[k].auth_slices {
                        cols_k.push(noid_core::mle::evaluate::evaluate_flat_with_scratch(
                            auth_s, r_pp_k, &mut flat, &mut pt,
                        ));
                    }
                })
            });
            cols_k
        })
        .collect();

    let mut block_col_openings: Vec<Block128> = Vec::with_capacity(total_cols);
    for openings_k in tx_openings {
        block_col_openings.extend_from_slice(&openings_k);
    }
    // Block spine slice openings at spine_r_low.
    FLAT_SCRATCH.with(|fs| {
        PT_SCRATCH.with(|ps| {
            let mut flat = fs.borrow_mut();
            let mut pt = ps.borrow_mut();
            for sp in &spine_padded_slices {
                block_col_openings.push(noid_core::mle::evaluate::evaluate_flat_with_scratch(
                    sp,
                    &spine_r_low,
                    &mut flat,
                    &mut pt,
                ));
            }
            // State binding columns: one block per AIR instance.
            for sb_idx in 0..n_state_bindings {
                let col_offset = sb_idx * sb_n_cols_per_seg;
                let r_pp = &sb_r_pp_list[sb_idx];
                for i in 0..sb_n_cols_per_seg {
                    block_col_openings.push(noid_core::mle::evaluate::evaluate_flat_with_scratch(
                        &sb_padded_columns[col_offset + i],
                        r_pp,
                        &mut flat,
                        &mut pt,
                    ));
                }
            }
        })
    });

    block_channel.observe_field_elem(Block128::from(BLOCK_MULTIPOINT_TAG));
    block_channel.observe_field_elems(&block_col_openings);
    let mu = block_channel.get_random_point();
    let beta_block = block_channel.get_random_point();

    let mu_powers: Vec<Block128> = {
        let mut v = Vec::with_capacity(n_participants);
        let mut cur = Block128::ONE;
        for _ in 0..n_participants {
            v.push(cur);
            cur *= mu;
        }
        v
    };

    let max_cols = n_per_tx.max(n_block_spine_slices).max(sb_n_cols_per_seg);
    let beta_powers: Vec<Block128> = {
        let mut v = Vec::with_capacity(max_cols);
        let mut cur = Block128::ONE;
        for _ in 0..max_cols {
            v.push(cur);
            cur *= beta_block;
        }
        v
    };

    // Block sumcheck target = sum over all participants.
    let block_target: Block128 = {
        let mut target = Block128::ZERO;
        for k in 0..n_tx {
            let inner: Block128 = (0..n_per_tx)
                .map(|i| beta_powers[i] * block_col_openings[k * n_per_tx + i])
                .fold(Block128::ZERO, |a, b| a + b);
            target += mu_powers[k] * inner;
        }
        // Block spine participant.
        let spine_offset = n_tx * n_per_tx;
        let inner_spine: Block128 = (0..n_block_spine_slices)
            .map(|i| beta_powers[i] * block_col_openings[spine_offset + i])
            .fold(Block128::ZERO, |a, b| a + b);
        target += mu_powers[spine_participant_idx] * inner_spine;
        // State binding participants (one per dirty segment).
        if sb_n_cols_per_seg > 0 {
            let sb_base_offset = spine_offset + n_block_spine_slices;
            for sb_idx in 0..n_state_bindings {
                let col_offset = sb_base_offset + sb_idx * sb_n_cols_per_seg;
                let inner: Block128 = (0..sb_n_cols_per_seg)
                    .map(|i| beta_powers[i] * block_col_openings[col_offset + i])
                    .fold(Block128::ZERO, |a, b| a + b);
                target += mu_powers[sb_participant_base + sb_idx] * inner;
            }
        }
        target
    };

    // Collect all r_pp points for all participants.
    let all_r_pp: Vec<&[Block128]> = {
        let mut v: Vec<&[Block128]> = tx_r_pp.iter().map(|r| r.as_slice()).collect();
        v.push(&spine_r_low); // block spine
        for r in &sb_r_pp_list {
            v.push(r.as_slice()); // one per state binding AIR
        }
        v
    };

    // A-side: A_k[j] = mu^k * eq_ind(r''_k)[j].
    let pairs_a: Vec<Vec<Block128>> = (0..n_participants)
        .into_par_iter()
        .map(|k| {
            let eq_k = eq_ind_partial_eval(all_r_pp[k]);
            eq_k.into_iter().map(|v| v * mu_powers[k]).collect()
        })
        .collect();

    // B-side: B_k[j] = sum_i beta^i * cols_k[i][j].
    let hyper_len = 1usize << log_len;

    // Column-outer accumulation: process one column at a time so both
    // b_k (128 KB) and the current column (128 KB) stay in L2 cache.
    // This avoids the L3/DRAM cache-miss storm of the row-outer layout.
    let pairs_b_owned: Vec<Vec<Block128>> = (0..n_participants)
        .into_par_iter()
        .map(|k| {
            if k < n_tx {
                let air_refs = shared_fixed.build_full_col_refs(n_air_cols, &preps[k].witness_cols);
                let mut b_k = vec![Block128::ZERO; hyper_len];
                for i in 0..n_air_cols {
                    let lam = beta_powers[i];
                    let col = air_refs[i];
                    b_k.iter_mut()
                        .zip(col.iter())
                        .for_each(|(acc, &v)| *acc += lam * v);
                }
                for (off, s) in preps[k].auth_slices.iter().enumerate() {
                    let lam = beta_powers[n_air_cols + off];
                    b_k.iter_mut()
                        .zip(s.iter())
                        .for_each(|(acc, &v)| *acc += lam * v);
                }
                b_k
            } else if k == spine_participant_idx {
                let mut b_k = vec![Block128::ZERO; hyper_len];
                for i in 0..n_block_spine_slices {
                    let lam = beta_powers[i];
                    let col = spine_padded_slices[i].as_slice();
                    b_k.iter_mut()
                        .zip(col.iter())
                        .for_each(|(acc, &v)| *acc += lam * v);
                }
                b_k
            } else {
                // State binding participant k → segment index sb_idx.
                let sb_idx = k - sb_participant_base;
                let col_offset = sb_idx * sb_n_cols_per_seg;
                let mut b_k = vec![Block128::ZERO; hyper_len];
                for i in 0..sb_n_cols_per_seg {
                    let lam = beta_powers[i];
                    let col = sb_padded_columns[col_offset + i].as_slice();
                    b_k.iter_mut()
                        .zip(col.iter())
                        .for_each(|(acc, &v)| *acc += lam * v);
                }
                b_k
            }
        })
        .collect();
    let pairs_b: Vec<&[Block128]> = pairs_b_owned.iter().map(|v| v.as_slice()).collect();

    let _ = &tx_lambdas;
    let _ = &tx_claims;

    let (block_mp_rounds, block_mp_challenges) =
        noid_stark::multipoint_batch::prove_multipoint_sumcheck(
            pairs_a,
            pairs_b,
            block_target,
            &mut block_channel,
        );
    let r_block: Vec<Block128> = block_mp_challenges.iter().rev().cloned().collect();
    debug_assert_eq!(r_block.len(), log_len);

    // -------------------------------------------------------------------------
    // Stage 7: Single FRI-Binius mixed opening at r_block.
    // -------------------------------------------------------------------------
    let mixed_opening = prove_mixed_opening(
        &prover_state,
        &r_block,
        &[],
        &ntt,
        &mut block_channel,
        &hasher,
        COMPACT_NUM_QUERIES,
    );

    let tx_pis: Vec<PublicInputs> = witnesses.iter().map(|w| w.pi.clone()).collect();
    let tx_auth_proofs: Vec<AuthProofKillShot> =
        witnesses.iter().map(|w| w.auth_proof.clone()).collect();

    Ok(BlockProof {
        meta: BlockPublicMeta {
            prev_block_state_root,
            n_tx: n_tx as u32,
            n_air_per_tx: n_air_cols as u32,
            n_auth_slices_per_tx: n_auth_slices as u32,
            log_rows: witnesses[0].trace.log_rows as u32,
            n_block_spine_slices: n_block_spine_slices as u32,
            n_state_bindings: n_state_bindings as u32,
            state_binding_n_cols: sb_n_cols_per_seg as u32,
            state_binding_log_rows: sb_log_rows as u32,
        },
        commitment,
        tx_pis,
        block_spine_proof,
        tx_auth_proofs,
        tx_algebraic,
        state_binding_algebraics: sb_algebraics,
        block_col_openings,
        block_multipoint_rounds: block_mp_rounds,
        mixed_opening,
    })
}

// ---------------------------------------------------------------------------
// verify_block
// ---------------------------------------------------------------------------

/// Verify a `BlockProof`.
pub fn verify_block(
    airs: &[&dyn Air],
    proof: &BlockProof,
    spine_inputs_list: &[SpineInputs],
    auth_public_list: &[AuthPublicInputs],
    state_binding_airs: &[&BlockStateBindingAir],
) -> Result<(), VerifyBlockError> {
    let meta = &proof.meta;
    let n_tx = meta.n_tx as usize;
    let n_air_cols = meta.n_air_per_tx as usize;
    let n_auth_slices = meta.n_auth_slices_per_tx as usize;
    let n_per_tx = n_air_cols + n_auth_slices;
    let n_block_spine_slices = meta.n_block_spine_slices as usize;
    let n_state_bindings = meta.n_state_bindings as usize;
    let sb_n_cols_per_seg = meta.state_binding_n_cols as usize;
    let sb_n_cols_total = sb_n_cols_per_seg * n_state_bindings;
    let log_len = noid_stark::padded_log_len(meta.log_rows as usize);
    let has_state_binding = n_state_bindings > 0;
    let n_participants = n_tx + 1 + n_state_bindings;
    let spine_participant_idx = n_tx;
    let sb_participant_base = n_tx + 1;
    let total_committed_cols = n_tx * n_per_tx + n_block_spine_slices + sb_n_cols_total;

    if airs.len() != n_tx {
        return Err(VerifyBlockError::ShapeMismatch);
    }
    if airs[0].n_columns() != n_air_cols {
        return Err(VerifyBlockError::ShapeMismatch);
    }
    if proof.tx_pis.len() != n_tx
        || proof.tx_auth_proofs.len() != n_tx
        || proof.tx_algebraic.len() != n_tx
        || proof.state_binding_algebraics.len() != n_state_bindings
        || proof.block_col_openings.len() != total_committed_cols
        || spine_inputs_list.len() != n_tx
        || auth_public_list.len() != n_tx
    {
        return Err(VerifyBlockError::ShapeMismatch);
    }
    if proof.commitment.n_cols != total_committed_cols {
        return Err(VerifyBlockError::ShapeMismatch);
    }
    if has_state_binding && state_binding_airs.len() != n_state_bindings {
        return Err(VerifyBlockError::ShapeMismatch);
    }
    if has_state_binding {
        for sb_air in state_binding_airs {
            if sb_air.n_columns() != sb_n_cols_per_seg {
                return Err(VerifyBlockError::ShapeMismatch);
            }
        }
    }

    let auth_circuit = AuthCircuit::build();
    let cap = &proof.commitment.cap;

    // -------------------------------------------------------------------------
    // Stage 2: Unified block spine Kill-Shot + per-tx parallel verification.
    // -------------------------------------------------------------------------

    // (a) Unified block spine Kill-Shot — self-seeded, independent of per-tx channels.
    let tx_body_hashes: Vec<[Block128; 2]> = proof
        .tx_pis
        .iter()
        .map(|pi| pi.tx_body_hash.as_fields())
        .collect();

    let block_spine_reductions = {
        let mut ch = Poseidon2bChannel::new();
        absorb_cap_into_p2b(&mut ch, cap);
        verify_block_spine_killshot(&proof.block_spine_proof, n_tx, &tx_body_hashes, &mut ch)
            .ok_or(VerifyBlockError::BlockSpineKillShot)?
    };

    let spine_r = &block_spine_reductions.state.point;
    let spine_r_low: Vec<Block128> = {
        let mut v = spine_r[..BASE_LOG].to_vec();
        v.resize(log_len, Block128::ZERO);
        v
    };
    let spine_r_high = &spine_r[BASE_LOG..];
    let spine_offset = n_tx * n_per_tx;
    let spine_slice_vals: Vec<Block128> = (0..n_block_spine_slices)
        .map(|i| proof.block_col_openings[spine_offset + i])
        .collect();
    let recon_spine =
        noid_core::mle::split::reconstruct_from_slices(&spine_slice_vals, spine_r_high);
    if recon_spine != block_spine_reductions.state.value {
        return Err(VerifyBlockError::BlockSpineSliceReconstruction);
    }
    let spine_extras = reduction_to_transcript(spine_r, block_spine_reductions.state.value);

    // (b) Q.3/Q.5 — Parallel per-tx auth Kill-Shots + algebraic STARK.
    //
    // Each tx uses an independent per_tx_algebraic_channel, mirroring the prover.
    // Results are collected in order; any error short-circuits the whole block.
    struct TxVerifyResult {
        r_pp: Vec<Block128>,
        final_claim: Block128,
        lambdas: Vec<Block128>,
    }

    let tx_verify_results: Vec<Result<TxVerifyResult, VerifyBlockError>> = (0..n_tx)
        .into_par_iter()
        .map(|k| {
            let pi = &proof.tx_pis[k];
            let alg = &proof.tx_algebraic[k];
            let spine_inputs = &spine_inputs_list[k];
            let auth_public = &auth_public_list[k];
            let claimed = pi.tx_body_hash.as_fields();

            // Auth Kill-Shot (self-seeded, parallel-safe).
            let auth_reductions = {
                let mut ch = auth_gkr_channel();
                verify_auth_killshot(
                    &proof.tx_auth_proofs[k],
                    &auth_circuit,
                    auth_public,
                    &mut ch,
                )
                .ok_or(VerifyBlockError::AuthKillShot(k))?
            };

            if auth_public.tx_body_hash != claimed {
                return Err(VerifyBlockError::AuthSpineBridge(k));
            }
            let n_live = pi.n_live_inputs as usize;
            for i in 0..n_live {
                let owner_hi = spine_inputs.input_leaves[i][2];
                let owner_lo = spine_inputs.input_leaves[i][3];
                if auth_public.expected_address[i] != [owner_hi, owner_lo] {
                    return Err(VerifyBlockError::AuthSpineBridge(k));
                }
            }

            let r_auth = &auth_reductions.state.point;
            let auth_r_low = &r_auth[..BASE_LOG];
            let auth_r_high = &r_auth[BASE_LOG..];
            let auth_slice_vals = &alg.slice_claimed_values[..n_auth_slices];

            let recon_auth =
                noid_core::mle::split::reconstruct_from_slices(auth_slice_vals, auth_r_high);
            if recon_auth != auth_reductions.state.value {
                return Err(VerifyBlockError::AuthSliceReconstruction(k));
            }

            let auth_tr = reduction_to_transcript(r_auth, auth_reductions.state.value);
            let mut extras = Vec::with_capacity(spine_extras.len() + auth_tr.len());
            extras.extend_from_slice(&spine_extras);
            extras.extend_from_slice(&auth_tr);

            let slice_claims = build_auth_slice_claims(n_air_cols, auth_r_low, auth_slice_vals);

            // Q.3: per-tx channel mirrors the prover's channel.
            let mut ch = per_tx_algebraic_channel(&meta.prev_block_state_root, cap, k as u32);

            let (r_pp_k, final_claim_k, lambdas_k) =
                verify_air_interleaved_algebraic(airs[k], pi, alg, &extras, &slice_claims, &mut ch)
                    .map_err(|e| VerifyBlockError::AlgebraicStark(k, e))?;

            Ok(TxVerifyResult {
                r_pp: r_pp_k,
                final_claim: final_claim_k,
                lambdas: lambdas_k,
            })
        })
        .collect();

    let mut tx_r_pp: Vec<Vec<Block128>> = Vec::with_capacity(n_tx);
    let mut tx_final_claims: Vec<Block128> = Vec::with_capacity(n_tx);
    let mut tx_lambdas: Vec<Vec<Block128>> = Vec::with_capacity(n_tx);
    for result in tx_verify_results {
        let r = result?;
        tx_r_pp.push(r.r_pp);
        tx_final_claims.push(r.final_claim);
        tx_lambdas.push(r.lambdas);
    }

    // -------------------------------------------------------------------------
    // Stage 2b: State binding algebraic STARKs — one per segment AIR.
    // -------------------------------------------------------------------------
    let empty_pi_sb = PublicInputs {
        epoch_anchor: [0u8; 32],
        tx_body_hash: TxBodyHash([0u8; 32]),
        fee: 0,
        n_live_inputs: 0,
        n_live_outputs: 0,
        coinbase_credit: 0,
        log_slots: 0,
        claims_commitment: [0u8; 32],
        is_activation: [false; 8],
        is_deactivation: [false; 4],
    };
    let mut sb_r_pp_list: Vec<Vec<Block128>> = Vec::with_capacity(n_state_bindings);
    for sb_idx in 0..n_state_bindings {
        let sb_air = state_binding_airs[sb_idx];
        let sb_alg = &proof.state_binding_algebraics[sb_idx];
        let mut sb_ch =
            state_binding_channel(&meta.prev_block_state_root, cap, (n_tx + sb_idx) as u32);
        let (r_pp_sb, _, _) =
            verify_air_interleaved_algebraic(sb_air, &empty_pi_sb, sb_alg, &[], &[], &mut sb_ch)
                .map_err(|e| VerifyBlockError::AlgebraicStark(n_tx + sb_idx, e))?;
        sb_r_pp_list.push(r_pp_sb);
    }

    // -------------------------------------------------------------------------
    // Q.4a: Reconstruct Merkle root of per-tx transcript digests.
    // The block channel absorbs this root instead of N sequential transcripts.
    // -------------------------------------------------------------------------
    let tx_digests: Vec<[u8; 32]> = (0..n_tx)
        .into_par_iter()
        .map(|k| {
            compute_tx_transcript_digest(
                k as u32,
                &tx_r_pp[k],
                &proof.tx_algebraic[k].base_openings,
                &tx_lambdas[k],
                tx_final_claims[k],
            )
        })
        .collect();
    let transcript_root = merkle_reduce(&tx_digests);

    // Q.4: Block multipoint channel — mirrors the prover's block_multipoint_channel.
    let mut block_channel = block_multipoint_channel(&meta.prev_block_state_root, cap);
    let [tr0, tr1] = hash_to_fields(&transcript_root);
    block_channel.observe_field_elem(tr0);
    block_channel.observe_field_elem(tr1);

    // -------------------------------------------------------------------------
    // Stage 3: Block-level multipoint sumcheck.
    // -------------------------------------------------------------------------

    block_channel.observe_field_elem(Block128::from(BLOCK_MULTIPOINT_TAG));
    block_channel.observe_field_elems(&proof.block_col_openings);
    let mu = block_channel.get_random_point();
    let beta_block = block_channel.get_random_point();

    let mu_powers: Vec<Block128> = {
        let mut v = Vec::with_capacity(n_participants);
        let mut cur = Block128::ONE;
        for _ in 0..n_participants {
            v.push(cur);
            cur *= mu;
        }
        v
    };

    let max_cols = n_per_tx.max(n_block_spine_slices).max(sb_n_cols_per_seg);
    let beta_powers: Vec<Block128> = {
        let mut v = Vec::with_capacity(max_cols);
        let mut cur = Block128::ONE;
        for _ in 0..max_cols {
            v.push(cur);
            cur *= beta_block;
        }
        v
    };

    let block_target: Block128 = {
        let mut target = Block128::ZERO;
        for k in 0..n_tx {
            let inner: Block128 = (0..n_per_tx)
                .map(|i| beta_powers[i] * proof.block_col_openings[k * n_per_tx + i])
                .fold(Block128::ZERO, |a, b| a + b);
            target += mu_powers[k] * inner;
        }
        let inner_spine: Block128 = (0..n_block_spine_slices)
            .map(|i| beta_powers[i] * proof.block_col_openings[spine_offset + i])
            .fold(Block128::ZERO, |a, b| a + b);
        target += mu_powers[spine_participant_idx] * inner_spine;
        if has_state_binding {
            let sb_base_off = spine_offset + n_block_spine_slices;
            for sb_idx in 0..n_state_bindings {
                let col_off = sb_base_off + sb_idx * sb_n_cols_per_seg;
                let inner: Block128 = (0..sb_n_cols_per_seg)
                    .map(|i| beta_powers[i] * proof.block_col_openings[col_off + i])
                    .fold(Block128::ZERO, |a, b| a + b);
                target += mu_powers[sb_participant_base + sb_idx] * inner;
            }
        }
        target
    };

    let _ = &tx_final_claims;

    let (block_sc_challenges, block_final_claim) =
        noid_stark::multipoint_batch::verify_multipoint_sumcheck(
            &proof.block_multipoint_rounds,
            block_target,
            &mut block_channel,
        )
        .map_err(|_| VerifyBlockError::BlockMultipoint)?;

    let r_block: Vec<Block128> = block_sc_challenges.iter().rev().cloned().collect();
    if r_block.len() != log_len {
        return Err(VerifyBlockError::ShapeMismatch);
    }

    // -------------------------------------------------------------------------
    // Stage 4: FRI-Binius mixed opening verify.
    // -------------------------------------------------------------------------
    let ntt = AdditiveNTT::<Block128>::new(log_len + noid_fri::code::LOG_RATE);
    let hasher = Blake3Hasher::new();

    verify_mixed_opening(
        &proof.commitment,
        &r_block,
        &[],
        &proof.mixed_opening,
        &ntt,
        &mut block_channel,
        &hasher,
        COMPACT_NUM_QUERIES,
    )
    .map_err(VerifyBlockError::FriFailed)?;

    // -------------------------------------------------------------------------
    // Stage 5: Block sumcheck terminal identity.
    // -------------------------------------------------------------------------
    let m = &proof.mixed_opening.all_openings;
    if m.len() < total_committed_cols {
        return Err(VerifyBlockError::ShapeMismatch);
    }
    let mut expected = Block128::ZERO;
    for k in 0..n_tx {
        let eq_k = noid_core::mle::eq::eq_ind(&tx_r_pp[k], &r_block);
        let mut inner = Block128::ZERO;
        for i in 0..n_per_tx {
            inner += beta_powers[i] * m[k * n_per_tx + i];
        }
        expected += mu_powers[k] * eq_k * inner;
    }
    // Block spine participant
    let eq_spine = noid_core::mle::eq::eq_ind(&spine_r_low, &r_block);
    let mut inner_spine = Block128::ZERO;
    for i in 0..n_block_spine_slices {
        inner_spine += beta_powers[i] * m[spine_offset + i];
    }
    expected += mu_powers[spine_participant_idx] * eq_spine * inner_spine;
    // State binding participants (one per segment).
    if has_state_binding {
        let sb_base_off = spine_offset + n_block_spine_slices;
        for sb_idx in 0..n_state_bindings {
            let eq_sb = noid_core::mle::eq::eq_ind(&sb_r_pp_list[sb_idx], &r_block);
            let col_off = sb_base_off + sb_idx * sb_n_cols_per_seg;
            let mut inner = Block128::ZERO;
            for i in 0..sb_n_cols_per_seg {
                inner += beta_powers[i] * m[col_off + i];
            }
            expected += mu_powers[sb_participant_base + sb_idx] * eq_sb * inner;
        }
    }
    if expected != block_final_claim {
        return Err(VerifyBlockError::BlockMultipoint);
    }

    Ok(())
}
