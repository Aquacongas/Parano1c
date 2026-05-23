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
//! 5. One single FRI-Binius mixed opening at `r_block`.

#![allow(clippy::too_many_arguments)]

pub mod full_node;

use noid_core::mle::{
    eq::eq_ind_partial_eval,
    split::split_mle_into_slices,
};
use noid_core::transcript::FiatShamir;
use noid_core::{AdditiveNTT, Block128, TowerField};
use noid_fri::hasher::Blake3Hasher;
use noid_fri::Channel;
use noid_fri_binius::{
    absorb_cap, interleaved_commit, prove_mixed_opening, verify_mixed_opening,
    InterleavedCommitment, MixedOpeningProof, COMPACT_NUM_QUERIES,
};
use noid_gkr::{
    auth_gkr_channel, build_boundary_mle, prove_spine_killshot_with_states,
    reconstruct_slot_states, verify_auth_killshot, verify_spine_killshot, AuthCircuit,
    AuthProofKillShot, AuthPublicInputs, SpineCircuit, SpineInputs, SpineProofKillShot,
    N_BOUNDARY_VARS,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_stark::interleaved::{
    prove_air_interleaved_algebraic, verify_air_interleaved_algebraic, AlgebraicStarkProof,
};
use noid_stark::{SliceClaim, VerifyError};
use noid_poseidon2b::primitives::TxBodyHash;
use noid_tx::PublicInputs;
use noid_air::airs::block_state_binding::BlockStateBindingAir;
use noid_air::Air;
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
    pub n_slice_per_tx: u32,
    pub log_rows: u32,
    /// Number of state binding AIR columns (0 if no state binding).
    pub state_binding_n_cols: u32,
    /// Log-rows of the state binding AIR (may differ from per-tx log_rows).
    pub state_binding_log_rows: u32,
}

// ---------------------------------------------------------------------------
// BlockProof
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct BlockProof {
    pub meta: BlockPublicMeta,
    /// Single interleaved commitment covering all columns (per-tx + state binding).
    pub commitment: InterleavedCommitment,
    /// Public inputs for every transaction in order.
    pub tx_pis: Vec<PublicInputs>,
    /// SpineGKR Kill-Shot proofs (one per tx).
    pub tx_spine_proofs: Vec<SpineProofKillShot>,
    /// AuthGKR Kill-Shot proofs (one per tx).
    pub tx_auth_proofs: Vec<AuthProofKillShot>,
    /// Algebraic STARK transcripts — no FRI, one per tx.
    pub tx_algebraic: Vec<AlgebraicStarkProof>,
    /// Algebraic STARK transcript for BlockStateBindingAir (None if no state binding).
    pub state_binding_algebraic: Option<AlgebraicStarkProof>,
    /// Number of columns in the state binding AIR (0 if absent).
    pub state_binding_n_cols: u32,
    /// Per-tx column openings at the per-tx terminal points r''_k.
    /// Flat layout: `block_col_openings[k*n_per_tx .. (k+1)*n_per_tx]`.
    /// If state binding present, appended at the end: `[n_tx*n_per_tx .. n_tx*n_per_tx + sb_n_cols]`.
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
        let spine: usize = self.tx_spine_proofs.iter().map(|s| s.byte_len()).sum();
        let auth: usize = self.tx_auth_proofs.iter().map(|a| a.byte_len()).sum();
        let col_open = self.block_col_openings.len() * 16;
        let mp: usize = self.block_multipoint_rounds.iter().map(|r| r.len() * 16).sum();
        let mixed = self.mixed_opening.byte_len();
        cap + alg + spine + auth + col_open + mp + mixed
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
    SpineKillShot(usize),
    AuthKillShot(usize),
    AuthSpineBridge(usize),
    SliceReconstruction(usize),
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

fn build_slice_claims(
    n_air_cols: usize,
    spine_r_low: &[Block128],
    spine_vals: &[Block128],
    auth_r_low: &[Block128],
    auth_vals: &[Block128],
) -> Vec<SliceClaim> {
    let mut claims = Vec::with_capacity(6);
    for (i, &val) in spine_vals.iter().enumerate() {
        claims.push(SliceClaim {
            col_index: n_air_cols + i,
            eval_point: spine_r_low.to_vec(),
            value: val,
        });
    }
    for (i, &val) in auth_vals.iter().enumerate() {
        claims.push(SliceClaim {
            col_index: n_air_cols + 4 + i,
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
    state_binding: Option<&StateBindingBlockWitness<'_>>,
) -> Result<BlockProof, ProveBlockError> {
    let n_tx = witnesses.len();
    assert!(n_tx >= 1, "block must have at least one transaction");

    let spine_circuit = SpineCircuit::build();
    let auth_circuit = AuthCircuit::build();

    let n_air_cols = witnesses[0].air.n_columns();
    let n_slice_per_tx: usize = 6; // 4 spine + 2 auth
    let n_per_tx = n_air_cols + n_slice_per_tx;
    let log_len = noid_stark::padded_log_len(witnesses[0].trace.log_rows);

    // -------------------------------------------------------------------------
    // Stage 1: State continuity is now enforced by BlockStateBinding (S.5).
    // -------------------------------------------------------------------------

    // -------------------------------------------------------------------------
    // Stage 2: Build per-tx extended column pools.
    // -------------------------------------------------------------------------
    // For each tx: AIR columns (padded) + 4 spine slices + 2 auth slices.
    // All columns for all txs are laid out flat for the single block-wide commit.

    struct TxPrep {
        columns: Vec<Vec<Block128>>,           // length n_per_tx
        spine_slices: Vec<Vec<Block128>>,      // length 4
        auth_slices: Vec<Vec<Block128>>,       // length 2
        spine_r_low: Vec<Block128>,
        spine_r_high: Vec<Block128>,
        auth_r_low: Vec<Block128>,
        auth_r_high: Vec<Block128>,
        spine_slice_vals: Vec<Block128>,
        auth_slice_vals: Vec<Block128>,
        extras_transcript: Vec<Block128>,
        spine_proof: Option<SpineProofKillShot>,
        auth_proof: Option<AuthProofKillShot>,
    }

    // Pre-build boundary MLEs (needed before commit for slice derivation).
    let mut preps: Vec<TxPrep> = Vec::with_capacity(n_tx);

    for w in witnesses.iter() {
        let spine_states = reconstruct_slot_states(&spine_circuit, w.spine_inputs);
        let spine_boundary = build_boundary_mle(&spine_states);

        let spine_slices = split_mle_into_slices(&spine_boundary, N_BOUNDARY_VARS, BASE_LOG);

        let mut columns: Vec<Vec<Block128>> = Vec::with_capacity(n_per_tx);
        for col in &w.trace.columns {
            columns.push(noid_stark::pad_column(col, log_len));
        }
        for s in &spine_slices {
            columns.push(s.clone());
        }
        // Auth slices are pre-built by the wallet (no secret needed).
        for s in w.auth_slices {
            columns.push(s.clone());
        }

        preps.push(TxPrep {
            columns,
            spine_slices,
            auth_slices: w.auth_slices.to_vec(),
            spine_r_low: Vec::new(),
            spine_r_high: Vec::new(),
            auth_r_low: Vec::new(),
            auth_r_high: Vec::new(),
            spine_slice_vals: Vec::new(),
            auth_slice_vals: Vec::new(),
            extras_transcript: Vec::new(),
            spine_proof: None,
            auth_proof: None,
        });
    }

    // -------------------------------------------------------------------------
    // Stage 3: Single block-wide interleaved commit.
    // Includes per-tx columns AND (optionally) state binding columns.
    // -------------------------------------------------------------------------
    let sb_n_cols = state_binding.map_or(0, |sb| sb.air.n_columns());
    let sb_log_rows = state_binding.map_or(0, |sb| sb.air.log_rows());

    // Pad state binding columns to log_len if present and shorter.
    let sb_padded_columns: Vec<Vec<Block128>> = if let Some(sb) = state_binding {
        sb.columns
            .iter()
            .map(|c| noid_stark::pad_column(c, log_len))
            .collect()
    } else {
        Vec::new()
    };

    let mut flat_refs: Vec<&[Block128]> = preps
        .iter()
        .flat_map(|p| p.columns.iter().map(|c| c.as_slice()))
        .collect();
    for c in &sb_padded_columns {
        flat_refs.push(c.as_slice());
    }

    let ntt = AdditiveNTT::<Block128>::new(log_len + noid_fri::code::LOG_RATE);
    let hasher = Blake3Hasher::new();
    let (commitment, prover_state) = interleaved_commit(&flat_refs, &ntt, &hasher);
    let cap = &commitment.cap;

    // -------------------------------------------------------------------------
    // Stage 4: Per-tx GKR Kill-Shots (seeded with the block-wide cap).
    // Fully parallel: each tx has independent channels seeded from cap.
    // -------------------------------------------------------------------------
    struct GkrResult {
        spine_r_low: Vec<Block128>,
        spine_r_high: Vec<Block128>,
        auth_r_low: Vec<Block128>,
        auth_r_high: Vec<Block128>,
        spine_slice_vals: Vec<Block128>,
        auth_slice_vals: Vec<Block128>,
        extras_transcript: Vec<Block128>,
        spine_proof: SpineProofKillShot,
        auth_proof: AuthProofKillShot,
    }

    let tx_body_hashes: Vec<[Block128; 2]> = witnesses
        .iter()
        .map(|w| w.pi.tx_body_hash.as_fields())
        .collect();
    let spine_inputs_refs: Vec<&SpineInputs> = witnesses
        .iter()
        .map(|w| w.spine_inputs)
        .collect();
    let auth_public_refs: Vec<&AuthPublicInputs> = witnesses
        .iter()
        .map(|w| w.auth_public)
        .collect();
    let auth_proof_refs: Vec<&AuthProofKillShot> = witnesses
        .iter()
        .map(|w| w.auth_proof)
        .collect();

    let gkr_results: Vec<GkrResult> = (0..n_tx)
        .into_par_iter()
        .map(|k| {
            let claimed = tx_body_hashes[k];
            let prep = &preps[k];
            let spine_states = reconstruct_slot_states(&spine_circuit, spine_inputs_refs[k]);

            // Spine: block prover generates fresh (only needs public SpineInputs).
            // Auth: wallet pre-built; block prover replays verify to get reductions.
            let ((spine_proof, spine_reductions), auth_reductions) = rayon::join(
                || {
                    let mut ch = Poseidon2bChannel::new();
                    absorb_cap_into_p2b(&mut ch, cap);
                    prove_spine_killshot_with_states(&spine_states, claimed, &mut ch)
                },
                || {
                    let mut ch = auth_gkr_channel();
                    verify_auth_killshot(
                        auth_proof_refs[k],
                        &auth_circuit,
                        auth_public_refs[k],
                        &mut ch,
                    )
                    .expect("wallet-supplied auth proof must verify")
                },
            );

            let r_spine = spine_reductions.state.point.clone();
            let r_auth = auth_reductions.state.point.clone();
            let spine_r_low = r_spine[..BASE_LOG].to_vec();
            let spine_r_high = r_spine[BASE_LOG..].to_vec();
            let auth_r_low = r_auth[..BASE_LOG].to_vec();
            let auth_r_high = r_auth[BASE_LOG..].to_vec();

            let spine_slice_vals: Vec<Block128> = prep
                .spine_slices
                .iter()
                .map(|s| noid_core::mle::evaluate::evaluate_slice(s, &spine_r_low))
                .collect();
            let auth_slice_vals: Vec<Block128> = prep
                .auth_slices
                .iter()
                .map(|s| noid_core::mle::evaluate::evaluate_slice(s, &auth_r_low))
                .collect();

            let spine_tr = reduction_to_transcript(&r_spine, spine_reductions.state.value);
            let auth_tr = reduction_to_transcript(&r_auth, auth_reductions.state.value);
            let mut extras = Vec::with_capacity(spine_tr.len() + auth_tr.len());
            extras.extend_from_slice(&spine_tr);
            extras.extend_from_slice(&auth_tr);

            GkrResult {
                spine_r_low,
                spine_r_high,
                auth_r_low,
                auth_r_high,
                spine_slice_vals,
                auth_slice_vals,
                extras_transcript: extras,
                spine_proof,
                auth_proof: auth_proof_refs[k].clone(),
            }
        })
        .collect();

    for (k, res) in gkr_results.into_iter().enumerate() {
        let prep = &mut preps[k];
        prep.spine_r_low = res.spine_r_low;
        prep.spine_r_high = res.spine_r_high;
        prep.auth_r_low = res.auth_r_low;
        prep.auth_r_high = res.auth_r_high;
        prep.spine_slice_vals = res.spine_slice_vals;
        prep.auth_slice_vals = res.auth_slice_vals;
        prep.extras_transcript = res.extras_transcript;
        prep.spine_proof = Some(res.spine_proof);
        prep.auth_proof = Some(res.auth_proof);
    }

    // -------------------------------------------------------------------------
    // Stage 5: Per-tx algebraic STARK proofs on shared block channel.
    // -------------------------------------------------------------------------
    let mut block_channel = Channel::new();
    let [sr0, sr1] = hash_to_fields(&prev_block_state_root);
    block_channel.observe_field_elem(sr0);
    block_channel.observe_field_elem(sr1);
    absorb_cap(&mut block_channel, cap);

    let mut tx_algebraic: Vec<AlgebraicStarkProof> = Vec::with_capacity(n_tx);
    let mut tx_r_pp: Vec<Vec<Block128>> = Vec::with_capacity(n_tx);
    let mut tx_claims: Vec<Block128> = Vec::with_capacity(n_tx);
    let mut tx_lambdas: Vec<Vec<Block128>> = Vec::with_capacity(n_tx);

    for (k, w) in witnesses.iter().enumerate() {
        let prep = &preps[k];
        let slice_claims = build_slice_claims(
            n_air_cols,
            &prep.spine_r_low,
            &prep.spine_slice_vals,
            &prep.auth_r_low,
            &prep.auth_slice_vals,
        );

        let (alg, r_pp_k, claim_k, lambdas_k) = prove_air_interleaved_algebraic(
            w.air,
            &prep.columns,
            w.pi,
            &prep.extras_transcript,
            &slice_claims,
            log_len,
            &mut block_channel,
        );

        tx_r_pp.push(r_pp_k);
        tx_claims.push(claim_k);
        tx_lambdas.push(lambdas_k);
        tx_algebraic.push(alg);
    }

    // -------------------------------------------------------------------------
    // Stage 5b: BlockStateBindingAir algebraic STARK on the shared channel.
    // -------------------------------------------------------------------------
    let mut sb_algebraic: Option<AlgebraicStarkProof> = None;
    let mut sb_r_pp: Vec<Block128> = Vec::new();

    if let Some(sb) = state_binding {
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
        let (alg, r_pp_sb, _claim_sb, _lambdas_sb) = prove_air_interleaved_algebraic(
            sb.air,
            &sb_padded_columns,
            &empty_pi,
            &[],        // no extras transcript for state binding
            &[],        // no slice claims (Kill-Shots handle Merkle paths)
            log_len,
            &mut block_channel,
        );
        sb_r_pp = r_pp_sb;
        sb_algebraic = Some(alg);
    }

    // -------------------------------------------------------------------------
    // Stage 6 (§6): Block-level multipoint sumcheck.
    //
    // Absorb BLOCK_MULTIPOINT_TAG + flat(M_k[i]) then squeeze mu.
    // Build pairs:
    //   A_k(x) = mu^k * eq_ind(r''_k, x)
    //   B_k(x) = sum_i beta^i * BLOCK_COLS[k*n_per_tx + i](x)
    // Run degree-2 sumcheck to get r_block.
    //
    // If state binding present: it participates as participant index n_tx
    // with its own r_pp and column openings.
    // -------------------------------------------------------------------------
    // Total participants: n_tx per-tx + (1 if state binding)
    let n_participants = n_tx + if state_binding.is_some() { 1 } else { 0 };

    // Collect per-tx column openings M_k[i] = MLE(col)(r''_k).
    let mut block_col_openings: Vec<Block128> = Vec::with_capacity(n_tx * n_per_tx + sb_n_cols);
    for k in 0..n_tx {
        let r_pp_k = &tx_r_pp[k];
        for i in 0..n_per_tx {
            block_col_openings.push(noid_stark::mle_eval(&preps[k].columns[i], r_pp_k));
        }
    }
    // State binding column openings at sb_r_pp.
    if state_binding.is_some() {
        for i in 0..sb_n_cols {
            block_col_openings.push(noid_stark::mle_eval(&sb_padded_columns[i], &sb_r_pp));
        }
    }

    block_channel.observe_field_elem(Block128::from(BLOCK_MULTIPOINT_TAG));
    block_channel.observe_field_elems(&block_col_openings);
    let mu = block_channel.get_random_point();
    let beta_block = block_channel.get_random_point();

    // Horner weights mu^k for all participants (n_tx + optional state binding).
    let mu_powers: Vec<Block128> = {
        let mut v = Vec::with_capacity(n_participants);
        let mut cur = Block128::ONE;
        for _ in 0..n_participants {
            v.push(cur);
            cur *= mu;
        }
        v
    };

    // Inner Horner weights beta_block^i. We need enough for the widest
    // participant (max of n_per_tx and sb_n_cols).
    let max_cols_per_participant = n_per_tx.max(sb_n_cols);
    let beta_powers: Vec<Block128> = {
        let mut v = Vec::with_capacity(max_cols_per_participant);
        let mut cur = Block128::ONE;
        for _ in 0..max_cols_per_participant {
            v.push(cur);
            cur *= beta_block;
        }
        v
    };

    // Block sumcheck target = sum_k mu^k * sum_i beta^i * M_k[i].
    let block_target: Block128 = {
        let mut target = Block128::ZERO;
        // Per-tx participants
        for k in 0..n_tx {
            let inner: Block128 = (0..n_per_tx)
                .map(|i| beta_powers[i] * block_col_openings[k * n_per_tx + i])
                .fold(Block128::ZERO, |a, b| a + b);
            target += mu_powers[k] * inner;
        }
        // State binding participant
        if sb_n_cols > 0 {
            let sb_offset = n_tx * n_per_tx;
            let inner: Block128 = (0..sb_n_cols)
                .map(|i| beta_powers[i] * block_col_openings[sb_offset + i])
                .fold(Block128::ZERO, |a, b| a + b);
            target += mu_powers[n_tx] * inner;
        }
        target
    };

    // Collect all r_pp points: per-tx plus optional state binding.
    let all_r_pp: Vec<&[Block128]> = {
        let mut v: Vec<&[Block128]> = tx_r_pp.iter().map(|r| r.as_slice()).collect();
        if sb_n_cols > 0 {
            v.push(&sb_r_pp);
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
    let pairs_b: Vec<Vec<Block128>> = (0..n_participants)
        .into_par_iter()
        .map(|k| {
            if k < n_tx {
                // Per-tx participant
                (0..hyper_len)
                    .map(|j| {
                        let mut acc = Block128::ZERO;
                        for i in 0..n_per_tx {
                            acc += beta_powers[i] * preps[k].columns[i][j];
                        }
                        acc
                    })
                    .collect()
            } else {
                // State binding participant
                (0..hyper_len)
                    .map(|j| {
                        let mut acc = Block128::ZERO;
                        for i in 0..sb_n_cols {
                            acc += beta_powers[i] * sb_padded_columns[i][j];
                        }
                        acc
                    })
                    .collect()
            }
        })
        .collect();

    let _ = &tx_lambdas; // unused now; kept for future stage K refinements
    let _ = &tx_claims;

    let pairs_b_refs: Vec<&[Block128]> = pairs_b.iter().map(|v| v.as_slice()).collect();

    let (block_mp_rounds, block_mp_challenges) =
        noid_stark::multipoint_batch::prove_multipoint_sumcheck(
            pairs_a,
            pairs_b_refs,
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
    let tx_spine_proofs: Vec<SpineProofKillShot> =
        preps.iter_mut().map(|p| p.spine_proof.take().expect("spine_proof set")).collect();
    let tx_auth_proofs: Vec<AuthProofKillShot> =
        preps.iter_mut().map(|p| p.auth_proof.take().expect("auth_proof set")).collect();

    Ok(BlockProof {
        meta: BlockPublicMeta {
            prev_block_state_root,
            n_tx: n_tx as u32,
            n_air_per_tx: n_air_cols as u32,
            n_slice_per_tx: n_slice_per_tx as u32,
            log_rows: witnesses[0].trace.log_rows as u32,
            state_binding_n_cols: sb_n_cols as u32,
            state_binding_log_rows: sb_log_rows as u32,
        },
        commitment,
        tx_pis,
        tx_spine_proofs,
        tx_auth_proofs,
        tx_algebraic,
        state_binding_algebraic: sb_algebraic,
        state_binding_n_cols: sb_n_cols as u32,
        block_col_openings,
        block_multipoint_rounds: block_mp_rounds,
        mixed_opening,
    })
}

// ---------------------------------------------------------------------------
// verify_block
// ---------------------------------------------------------------------------

/// Verify a `BlockProof`.
///
/// `airs` must contain one AIR per transaction, each instantiated with the
/// correct boundary pins for that transaction. All AIRs must share the same
/// `n_columns()` and `log_rows()`.
///
/// The caller must supply `spine_inputs` and `auth_public_list` slices
/// (length N) corresponding to the N transactions; these are needed to
/// re-verify the GKR Kill-Shots and to reconstruct the `extras_transcript`
/// for the algebraic STARK replay.
///
/// PRIVACY: `auth_public_list` contains only public fields (address, tag,
/// tx_body_hash). The verifier never sees `spend_secret`.
///
/// `state_binding_air` is required if the proof contains a state binding
/// algebraic transcript (i.e. `proof.state_binding_n_cols > 0`).
pub fn verify_block(
    airs: &[&dyn Air],
    proof: &BlockProof,
    spine_inputs_list: &[SpineInputs],
    auth_public_list: &[AuthPublicInputs],
    state_binding_air: Option<&BlockStateBindingAir>,
) -> Result<(), VerifyBlockError> {
    let meta = &proof.meta;
    let n_tx = meta.n_tx as usize;
    let n_air_cols = meta.n_air_per_tx as usize;
    let n_slice_per_tx = meta.n_slice_per_tx as usize;
    let n_per_tx = n_air_cols + n_slice_per_tx;
    let sb_n_cols = meta.state_binding_n_cols as usize;
    let log_len = noid_stark::padded_log_len(meta.log_rows as usize);
    let has_state_binding = sb_n_cols > 0;
    let n_participants = n_tx + if has_state_binding { 1 } else { 0 };
    let total_committed_cols = n_tx * n_per_tx + sb_n_cols;

    if airs.len() != n_tx {
        return Err(VerifyBlockError::ShapeMismatch);
    }
    if airs[0].n_columns() != n_air_cols {
        return Err(VerifyBlockError::ShapeMismatch);
    }
    if proof.tx_pis.len() != n_tx
        || proof.tx_spine_proofs.len() != n_tx
        || proof.tx_auth_proofs.len() != n_tx
        || proof.tx_algebraic.len() != n_tx
        || proof.block_col_openings.len() != total_committed_cols
        || spine_inputs_list.len() != n_tx
        || auth_public_list.len() != n_tx
    {
        return Err(VerifyBlockError::ShapeMismatch);
    }
    if proof.commitment.n_cols != total_committed_cols {
        return Err(VerifyBlockError::ShapeMismatch);
    }
    if has_state_binding && state_binding_air.is_none() {
        return Err(VerifyBlockError::ShapeMismatch);
    }
    if has_state_binding {
        if proof.state_binding_algebraic.is_none() {
            return Err(VerifyBlockError::ShapeMismatch);
        }
        if state_binding_air.unwrap().n_columns() != sb_n_cols {
            return Err(VerifyBlockError::ShapeMismatch);
        }
    }

    let spine_circuit = SpineCircuit::build();
    let auth_circuit = AuthCircuit::build();
    let cap = &proof.commitment.cap;

    // -------------------------------------------------------------------------
    // Stage 1: State continuity is now enforced by BlockStateBinding (S.5).
    // -------------------------------------------------------------------------

    // -------------------------------------------------------------------------
    // Stage 2: Per-tx GKR Kill-Shots + slice reconstruction + algebraic STARK.
    // -------------------------------------------------------------------------
    let mut block_channel = Channel::new();
    let [sr0, sr1] = hash_to_fields(&meta.prev_block_state_root);
    block_channel.observe_field_elem(sr0);
    block_channel.observe_field_elem(sr1);
    absorb_cap(&mut block_channel, cap);

    let mut tx_r_pp: Vec<Vec<Block128>> = Vec::with_capacity(n_tx);
    let mut tx_final_claims: Vec<Block128> = Vec::with_capacity(n_tx);

    for k in 0..n_tx {
        let pi = &proof.tx_pis[k];
        let alg = &proof.tx_algebraic[k];
        let spine_inputs = &spine_inputs_list[k];
        let auth_public = &auth_public_list[k];
        let claimed = pi.tx_body_hash.as_fields();

        // GKR Kill-Shots.
        let spine_reductions = {
            let mut ch = Poseidon2bChannel::new();
            absorb_cap_into_p2b(&mut ch, cap);
            verify_spine_killshot(
                &proof.tx_spine_proofs[k],
                &spine_circuit,
                spine_inputs,
                claimed,
                &mut ch,
            )
            .ok_or(VerifyBlockError::SpineKillShot(k))?
        };
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

        // Auth/Spine bridge: tx_body_hash must agree unconditionally.
        if auth_public.tx_body_hash != claimed {
            return Err(VerifyBlockError::AuthSpineBridge(k));
        }
        // Address check: only live inputs. Dummy inputs carry zero-address
        // in spine but derive_address(zero_secret) in auth — intentionally
        // different. Dummy slots have is_deactivation=false so they cannot
        // authorize any spend.
        let n_live = pi.n_live_inputs as usize;
        for i in 0..n_live {
            let owner_hi = spine_inputs.input_leaves[i][2];
            let owner_lo = spine_inputs.input_leaves[i][3];
            if auth_public.expected_address[i] != [owner_hi, owner_lo] {
                return Err(VerifyBlockError::AuthSpineBridge(k));
            }
        }

        // Slice reconstruction.
        let r_spine = &spine_reductions.state.point;
        let r_auth = &auth_reductions.state.point;
        let spine_r_low = &r_spine[..BASE_LOG];
        let spine_r_high = &r_spine[BASE_LOG..];
        let auth_r_low = &r_auth[..BASE_LOG];
        let auth_r_high = &r_auth[BASE_LOG..];

        let spine_slice_vals = &alg.slice_claimed_values[..4];
        let auth_slice_vals = &alg.slice_claimed_values[4..6];

        let recon_spine =
            noid_core::mle::split::reconstruct_from_slices(spine_slice_vals, spine_r_high);
        if recon_spine != spine_reductions.state.value {
            return Err(VerifyBlockError::SliceReconstruction(k));
        }
        let recon_auth =
            noid_core::mle::split::reconstruct_from_slices(auth_slice_vals, auth_r_high);
        if recon_auth != auth_reductions.state.value {
            return Err(VerifyBlockError::SliceReconstruction(k));
        }

        // Rebuild extras_transcript and slice_claims.
        let spine_tr = reduction_to_transcript(r_spine, spine_reductions.state.value);
        let auth_tr = reduction_to_transcript(r_auth, auth_reductions.state.value);
        let mut extras = Vec::with_capacity(spine_tr.len() + auth_tr.len());
        extras.extend_from_slice(&spine_tr);
        extras.extend_from_slice(&auth_tr);

        let slice_claims = build_slice_claims(
            n_air_cols,
            spine_r_low,
            spine_slice_vals,
            auth_r_low,
            auth_slice_vals,
        );

        // Algebraic STARK replay on the shared block channel.
        let (r_pp_k, final_claim_k) =
            verify_air_interleaved_algebraic(airs[k], pi, alg, &extras, &slice_claims, &mut block_channel)
                .map_err(|e| VerifyBlockError::AlgebraicStark(k, e))?;

        tx_r_pp.push(r_pp_k);
        tx_final_claims.push(final_claim_k);
    }

    // -------------------------------------------------------------------------
    // Stage 2b: State binding algebraic STARK replay on the shared channel.
    // -------------------------------------------------------------------------
    let mut sb_r_pp: Vec<Block128> = Vec::new();

    if has_state_binding {
        let sb_air = state_binding_air.unwrap();
        let sb_alg = proof.state_binding_algebraic.as_ref().unwrap();
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

        let (r_pp_sb, _final_claim_sb) = verify_air_interleaved_algebraic(
            sb_air,
            &empty_pi,
            sb_alg,
            &[],
            &[],
            &mut block_channel,
        )
        .map_err(|e| VerifyBlockError::AlgebraicStark(n_tx, e))?;

        sb_r_pp = r_pp_sb;
    }

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

    let max_cols_per_participant = n_per_tx.max(sb_n_cols);
    let beta_powers: Vec<Block128> = {
        let mut v = Vec::with_capacity(max_cols_per_participant);
        let mut cur = Block128::ONE;
        for _ in 0..max_cols_per_participant {
            v.push(cur);
            cur *= beta_block;
        }
        v
    };

    // target = sum_k mu^k * sum_i beta^i * M_k[i].
    let block_target: Block128 = {
        let mut target = Block128::ZERO;
        for k in 0..n_tx {
            let inner: Block128 = (0..n_per_tx)
                .map(|i| beta_powers[i] * proof.block_col_openings[k * n_per_tx + i])
                .fold(Block128::ZERO, |a, b| a + b);
            target += mu_powers[k] * inner;
        }
        if has_state_binding {
            let sb_offset = n_tx * n_per_tx;
            let inner: Block128 = (0..sb_n_cols)
                .map(|i| beta_powers[i] * proof.block_col_openings[sb_offset + i])
                .fold(Block128::ZERO, |a, b| a + b);
            target += mu_powers[n_tx] * inner;
        }
        target
    };

    let _ = &tx_final_claims; // not used in target — block_col_openings is authoritative

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
    //
    //   block_final_claim == Σ_k mu^k · eq(r''_k, r_block) ·
    //                         Σ_i beta^i · m[k*n_per_tx + i]
    //
    // where m[..] = proof.mixed_opening.all_openings (FRI openings at r_block).
    // Binds the FRI-supplied openings to the block sumcheck's randomness.
    // Includes state binding participant (index n_tx) if present.
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
    if has_state_binding {
        let eq_sb = noid_core::mle::eq::eq_ind(&sb_r_pp, &r_block);
        let sb_offset = n_tx * n_per_tx;
        let mut inner = Block128::ZERO;
        for i in 0..sb_n_cols {
            inner += beta_powers[i] * m[sb_offset + i];
        }
        expected += mu_powers[n_tx] * eq_sb * inner;
    }
    if expected != block_final_claim {
        return Err(VerifyBlockError::BlockMultipoint);
    }

    Ok(())
}
