// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage G3.γ — GKR spine bridge (default STARK path).
//!
//! # Binding model (post-γ₄)
//!
//! Two Fiat–Shamir runs stapled by *one* shared commitment and *two*
//! shared scalars:
//!
//! 1. `pi.tx_body_hash` — the public claim. Cross-checked inside
//!    `verify_spine` against the wrap output; also pinned into the
//!    STARK as the composite's
//!    `TxBodyMerkleBoundaryPins::tx_body_hash` `PublicColumn`. One
//!    cell, two views.
//! 2. The boundary FRI commitment — seeds the spine Poseidon2b
//!    channel (so every spine challenge depends on the committed `B`)
//!    and is carried into the STARK mixed-close as an
//!    [`ExtraColumn`]. The mixed close runs a single FRI opening that
//!    discharges the spine's `(r_B, v_B)` reduction against the same
//!    commitment.
//! 3. The reduction scalars `(r_B, v_B)` — absorbed into the STARK
//!    parent channel via `spine_reduction_transcript`, forking every
//!    STARK challenge after column-root absorption on any spine
//!    tamper that survives the Poseidon2b FS.
//!
//! γ₄ deleted the raw `absorb_inputs` in spine-sumcheck, the per-slot
//! `absorb_boundary(state_in)` in perm-sumcheck, and the full
//! flattened-SpineProof extras digest. All three were γ₂-era belt-
//! and-braces that now rely on the boundary commitment and the
//! mixed-close FRI opening instead.

use noid_air::Air;
use noid_air::Trace;
use noid_core::transcript::FiatShamir;
use noid_core::{AdditiveNTT, Block128};
use noid_fri::code::LOG_RATE;
use noid_fri::hasher::Blake3Hasher;
use noid_fri::prover::{commit as fri_commit, FriCommitment};
use noid_gkr::{
    build_boundary_mle, prove_spine, reconstruct_slot_states, verify_spine,
    BatchEvalReduction, SpineCircuit, SpineInputs, SpineProof, N_BOUNDARY_VARS,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_tx::PublicInputs;

use crate::{
    prove_air_unchecked_with_extra_columns, verify_air_with_extra_columns, ExtraColumn,
    ProveError, StarkProof, VerifyError,
};

/// Composite proof: a normal STARK proof plus an independent GKR spine
/// proof, both written against the same `PublicInputs`.
///
/// γ₃b: the boundary MLE `B` is now opened **inside** the STARK's
/// mixed-length multipoint close as an [`ExtraColumn`], so there's no
/// standalone `boundary_open` field and no dedicated FRI channel for
/// it. The boundary FRI commitment still rides along — the spine
/// channel is seeded with it before `r_B` is drawn, so a tampered
/// commitment forks the spine transcript. The opening is then
/// discharged in the mixed close at `reduction.point`.
#[derive(Debug, Clone)]
pub struct StarkProofWithSpine {
    pub stark: StarkProof,
    pub spine: SpineProof,
    pub boundary_commitment: FriCommitment,
}

/// Verifier-side failures specific to the with-spine path.
#[derive(Debug)]
pub enum VerifyWithSpineError {
    /// Inner STARK verification failed.
    Stark(VerifyError),
    /// Inner GKR spine verification failed. Covers every failure mode
    /// inside `verify_spine`: slot count mismatch, any per-slot
    /// permutation sumcheck rejection, or wrap-digest != claimed hash.
    Spine,
}

impl From<VerifyError> for VerifyWithSpineError {
    fn from(e: VerifyError) -> Self {
        VerifyWithSpineError::Stark(e)
    }
}

/// Little-endian 32-byte `tx_body_hash` (as it lives on `PublicInputs`)
/// parsed into the two `Block128` lanes the GKR spine expects. Mirrors
/// the lane ordering `TxBodyHash::as_fields` uses everywhere else.
pub fn tx_body_hash_as_lanes(pi: &PublicInputs) -> [Block128; 2] {
    pi.tx_body_hash.as_fields()
}

/// Flatten a full `SpineProof` into the field-element stream the STARK
/// parent channel absorbs. Every `ProductProof`'s round evaluations
/// (4 per round) and its `(a_final, b_final)` pair contribute; every
/// per-slot `PermProof` contributes all eight of its `ProductProof`s
/// in the same order they're written by `prove_perm`. Order is fixed
/// and deterministic so prover and verifier produce byte-identical
/// streams.
/// γ₄: the extras-transcript shrinks from a full SpineProof flattening
/// to exactly the `(r_B, v_B)` reduction scalars. Soundness argument:
///
/// 1. `r_B` and `v_B` are the only scalars the spine actually commits
///    the STARK to. Everything else in the `SpineProof` is bound
///    transitively:
///    - the spine Poseidon2b channel is seeded with the boundary FRI
///      commitment root, so any tamper to `B` forks every spine
///      challenge (including `r_B`);
///    - every product/batch-eval round poly is absorbed into the spine
///      channel by `prove_perm` / `prove_batch_eval`; any scalar flip
///      forks later spine challenges → spine verify rejects OR the
///      surviving `reduction` disagrees;
///    - `v_B` is itself cross-checked against the committed `B` by the
///      mixed-close FRI opening, which uses the same commitment the
///      spine channel was seeded with.
/// 2. Feeding `(r_B, v_B)` into the STARK's `extra_transcript` hook
///    forks every STARK challenge drawn after column-root absorption.
///    Any change to `reduction` therefore breaks the STARK zero-check
///    in addition to the FRI opening.
///
/// The net effect is that the STARK transcript now depends on the
/// *meaning* of the spine (its final claim) rather than its byte
/// layout. Any spine tamper that the spine accepts must still produce
/// the same `(r_B, v_B)` — which is impossible unless the tamper is
/// semantically equivalent.
pub fn spine_reduction_transcript(reduction_point: &[Block128], reduction_value: Block128) -> Vec<Block128> {
    let mut out = Vec::with_capacity(reduction_point.len() + 1);
    out.extend_from_slice(reduction_point);
    out.push(reduction_value);
    out
}

/// Split a 32-byte hash into two `Block128` lanes + depth/packing/
/// log_len tail — the shape the spine Poseidon2b channel expects.
/// Deterministic across prover/verifier.
fn hash_to_fields(h: &[u8; 32]) -> [Block128; 2] {
    let mut a = [0u8; 16];
    let mut b = [0u8; 16];
    a.copy_from_slice(&h[..16]);
    b.copy_from_slice(&h[16..]);
    [
        Block128::from(u128::from_le_bytes(a)),
        Block128::from(u128::from_le_bytes(b)),
    ]
}

/// Bind a FRI commitment root into a `Poseidon2bChannel`.
fn absorb_fri_commitment_into_spine_channel(
    channel: &mut Poseidon2bChannel,
    commitment: &FriCommitment,
) {
    let [h0, h1] = hash_to_fields(&commitment.vector_commitment.root);
    channel.absorb(h0);
    channel.absorb(h1);
    channel.absorb(Block128::from(commitment.vector_commitment.depth as u128));
    channel.absorb(Block128::from(commitment.packing_factor as u128));
    channel.absorb(Block128::from(commitment.log_len as u128));
}

/// Run a GKR spine proof first, then digest it into the STARK's parent
/// channel as `extra_transcript`. A tamper in the spine proof forks
/// every STARK challenge drawn after column-root absorption.
///
/// γ₃a: commit the concatenated boundary MLE `B` via `noid_fri`, bind
/// the commitment root into the spine Fiat-Shamir channel, run the
/// spine sumcheck, then open `B` at the batch-eval reduction point
/// `r_B` and ship both with the proof.
pub fn prove_air_with_spine<A: Air>(
    air: &A,
    trace: &Trace,
    pi: &PublicInputs,
    spine_inputs: &SpineInputs,
) -> Result<StarkProofWithSpine, ProveError> {
    if !air.check(trace) {
        return Err(ProveError::TraceRejectedByAir);
    }

    let claimed = tx_body_hash_as_lanes(pi);
    let circuit = SpineCircuit::build();

    // Build and commit the boundary MLE `B` before opening the spine
    // transcript. The commitment root is folded into the spine channel
    // so the γ₂ batch-eval reduction point `r_B` depends on it — any
    // tamper to `B`'s bytes forks the spine challenge sequence.
    let states = reconstruct_slot_states(&circuit, spine_inputs);
    let boundary_mle = build_boundary_mle(&states);
    let ntt = AdditiveNTT::<Block128>::new(N_BOUNDARY_VARS + LOG_RATE);
    let hasher = Blake3Hasher::new();
    let (boundary_commitment, _tree, _code) = fri_commit(&boundary_mle, &ntt, &hasher);

    let mut spine_channel = Poseidon2bChannel::new();
    absorb_fri_commitment_into_spine_channel(&mut spine_channel, &boundary_commitment);
    let (spine, reduction) = prove_spine(&circuit, spine_inputs, claimed, &mut spine_channel);

    // γ₃b: the boundary opening now rides inside the STARK's
    // mixed-length multipoint close as an `ExtraColumn`. No separate
    // FRI channel or `boundary_open` field.
    let extras = vec![ExtraColumn {
        evals: boundary_mle,
        commitment: boundary_commitment.clone(),
        eval_point: reduction.point.clone(),
        value: reduction.value,
    }];
    let extras_transcript =
        spine_reduction_transcript(&reduction.point, reduction.value);
    let stark = prove_air_unchecked_with_extra_columns(
        air,
        trace,
        pi,
        &extras_transcript,
        &extras,
    );

    Ok(StarkProofWithSpine {
        stark,
        spine,
        boundary_commitment,
    })
}

/// Verify the GKR spine first (to confirm it's well-formed before
/// using its bytes as a transcript seed), then replay the STARK
/// transcript with the spine digest absorbed at the matching position.
pub fn verify_air_with_spine<A: Air>(
    air: &A,
    pi: &PublicInputs,
    spine_inputs: &SpineInputs,
    proof: &StarkProofWithSpine,
) -> Result<(), VerifyWithSpineError> {
    let claimed = tx_body_hash_as_lanes(pi);
    let circuit = SpineCircuit::build();

    // The commitment's log_len must match the boundary MLE the spine
    // is proving over. Anything else is a malformed proof.
    if proof.boundary_commitment.log_len != N_BOUNDARY_VARS {
        return Err(VerifyWithSpineError::Spine);
    }

    let mut spine_channel = Poseidon2bChannel::new();
    absorb_fri_commitment_into_spine_channel(&mut spine_channel, &proof.boundary_commitment);
    let reduction: BatchEvalReduction =
        verify_spine(&proof.spine, &circuit, spine_inputs, claimed, &mut spine_channel)
            .ok_or(VerifyWithSpineError::Spine)?;

    // γ₃b: the spine's `(r_B, v_B)` reduction is discharged by the
    // STARK's mixed multipoint close, which opens `B` against the
    // same commitment the spine channel was seeded with. The verifier
    // just hands `ExtraColumn { commitment, eval_point, value }` to
    // `verify_air_with_extra_columns`; the mixed FRI verify inside
    // the STARK is what proves `B(r_B) = v_B`.
    //
    // No `evals` needed on the verifier side — it's a prover-only
    // field. We use a zero-length placeholder since
    // `verify_air_with_extra_columns` never dereferences it.
    let extras = vec![ExtraColumn {
        evals: Vec::new(),
        commitment: proof.boundary_commitment.clone(),
        eval_point: reduction.point.clone(),
        value: reduction.value,
    }];
    let extras_transcript =
        spine_reduction_transcript(&reduction.point, reduction.value);
    verify_air_with_extra_columns(air, pi, &proof.stark, &extras_transcript, &extras)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_air::airs::linear_combination::LinearCombinationAir;
    use noid_core::TowerField;
    use noid_gkr::compute_tx_body_hash;
    use noid_poseidon2b::primitives::TxBodyHash;

    fn tiny_air() -> LinearCombinationAir {
        LinearCombinationAir::new(3, 8)
    }

    fn demo_spine_inputs() -> SpineInputs {
        SpineInputs {
            prev_state_root: [Block128::from(11u128), Block128::from(22u128)],
            fee_leaf: [Block128::from(33u128), Block128::from(44u128)],
            input_leaves: [[Block128::from(1u128); 4]; 4],
            output_leaves: [[Block128::from(2u128); 4]; 8],
            is_coinbase_leaf: [Block128::from(55u128), Block128::from(66u128)],
            pad_leaf: [Block128::ZERO; 2],
        }
    }

    fn demo_public_inputs(spine_inputs: &SpineInputs) -> PublicInputs {
        let circuit = SpineCircuit::build();
        let [hi, lo] = compute_tx_body_hash(&circuit, spine_inputs);
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(&hi.0.to_le_bytes());
        bytes[16..].copy_from_slice(&lo.0.to_le_bytes());
        PublicInputs {
            prev_state_root: [0u8; 32],
            new_state_root: [0u8; 32],
            tx_body_hash: TxBodyHash(bytes),
            fee: 0,
            n_live_inputs: 0,
            n_live_outputs: 0,
            coinbase_credit: 0,
            log_slots: 0,
            is_activation: [false; noid_tx::MAX_OUTPUTS],
            is_deactivation: [false; noid_tx::MAX_INPUTS],
        }
    }

    fn demo_trace() -> Trace {
        let log_rows = 8;
        let n = 1usize << log_rows;
        // Row-by-row XOR-to-zero with non-trivial entries: any challenge
        // drift in the zero-check phase now actually flips round-poly
        // consistency, so the β₂ fork test has teeth.
        let col0: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 * 7 + 1)).collect();
        let col1: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 * 11 + 3)).collect();
        let col2: Vec<Block128> = col0.iter().zip(col1.iter()).map(|(a, b)| *a + *b).collect();
        Trace::new(vec![col0, col1, col2])
    }

    #[test]
    fn honest_with_spine_roundtrip() {
        let spine_inputs = demo_spine_inputs();
        let pi = demo_public_inputs(&spine_inputs);
        let air = tiny_air();
        let trace = demo_trace();
        let proof = prove_air_with_spine(&air, &trace, &pi, &spine_inputs).unwrap();
        verify_air_with_spine(&air, &pi, &spine_inputs, &proof).unwrap();
    }

    #[test]
    fn forged_spine_proof_rejected() {
        // Prove honestly, then swap in a proof built against *different*
        // inputs. verify_spine must reject.
        let spine_inputs_a = demo_spine_inputs();
        let mut spine_inputs_b = demo_spine_inputs();
        spine_inputs_b.fee_leaf[0] = Block128::from(99u128);

        let pi_a = demo_public_inputs(&spine_inputs_a);
        let air = tiny_air();
        let trace = demo_trace();

        let proof_a = prove_air_with_spine(&air, &trace, &pi_a, &spine_inputs_a).unwrap();
        let proof_b = prove_air_with_spine(&air, &trace, &demo_public_inputs(&spine_inputs_b), &spine_inputs_b).unwrap();

        // Splice B's spine proof into A's container. Verifier replays
        // the spine transcript against A's (pi_a, spine_inputs_a) and
        // rejects because the wrap digest no longer matches.
        let forged = StarkProofWithSpine {
            stark: proof_a.stark.clone(),
            spine: proof_b.spine.clone(),
            boundary_commitment: proof_b.boundary_commitment.clone(),
        };
        let err = verify_air_with_spine(&air, &pi_a, &spine_inputs_a, &forged);
        assert!(matches!(err, Err(VerifyWithSpineError::Spine)));
    }

    #[test]
    fn tampered_pi_tx_body_hash_rejected() {
        let spine_inputs = demo_spine_inputs();
        let pi = demo_public_inputs(&spine_inputs);
        let air = tiny_air();
        let trace = demo_trace();

        let proof = prove_air_with_spine(&air, &trace, &pi, &spine_inputs).unwrap();

        // Flip one byte in tx_body_hash so the verifier's claim no
        // longer matches the spine's honest wrap output.
        let mut bad_pi = demo_public_inputs(&spine_inputs);
        bad_pi.tx_body_hash.0[0] ^= 0x01;
        let err = verify_air_with_spine(&air, &bad_pi, &spine_inputs, &proof);
        // Either the STARK rejects (PI forks its channel) or the spine
        // rejects (claimed hash != wrap output). Both are acceptable.
        assert!(err.is_err());
    }

    #[test]
    fn mismatched_spine_inputs_rejected() {
        let spine_inputs = demo_spine_inputs();
        let pi = demo_public_inputs(&spine_inputs);
        let air = tiny_air();
        let trace = demo_trace();

        let proof = prove_air_with_spine(&air, &trace, &pi, &spine_inputs).unwrap();

        let mut bad_inputs = spine_inputs.clone();
        bad_inputs.input_leaves[0][0] = bad_inputs.input_leaves[0][0] + Block128::from(1u128);
        let err = verify_air_with_spine(&air, &pi, &bad_inputs, &proof);
        assert!(matches!(err, Err(VerifyWithSpineError::Spine)));
    }

    #[test]
    fn transcript_determinism() {
        let spine_inputs = demo_spine_inputs();
        let pi = demo_public_inputs(&spine_inputs);
        let air = tiny_air();
        let trace = demo_trace();

        let p1 = prove_air_with_spine(&air, &trace, &pi, &spine_inputs).unwrap();
        let p2 = prove_air_with_spine(&air, &trace, &pi, &spine_inputs).unwrap();
        assert_eq!(p1.spine, p2.spine);
    }

    /// γ₄ guard. The extras-transcript now carries only `(r_B, v_B)`
    /// scalars; if spine FS missed a scalar, a tamper could survive.
    /// Pound ten distinct per-slot scalars and verify every one
    /// rejects — if any slipped through we'd see a false accept.
    #[test]
    fn gamma4_spine_scalar_tamper_surface_is_fully_bound() {
        let spine_inputs = demo_spine_inputs();
        let pi = demo_public_inputs(&spine_inputs);
        let air = tiny_air();
        let trace = demo_trace();
        let base = prove_air_with_spine(&air, &trace, &pi, &spine_inputs).unwrap();

        let targets = [0usize, 1, 2, 10, 20, 30, 40, 50, 55, 58];
        for &slot in &targets {
            let mut t = base.clone();
            t.spine.slots[slot].sout_x4x3.a_final =
                t.spine.slots[slot].sout_x4x3.a_final + Block128::from(1u128);
            let err = verify_air_with_spine(&air, &pi, &spine_inputs, &t);
            assert!(
                err.is_err(),
                "γ₄ binding slipped on slot {slot}: a tampered spine scalar accepted"
            );
        }
    }

    #[test]
    fn tampered_spine_scalar_rejected_by_spine_check() {
        // A single-field flip in the SpineProof must be caught. In β₂
        // it can fail either at verify_spine (its own FS transcript
        // drifts) or at verify_air (the STARK extras hash changes so
        // zero-check/multipoint challenges drift). Both are acceptable.
        let spine_inputs = demo_spine_inputs();
        let pi = demo_public_inputs(&spine_inputs);
        let air = tiny_air();
        let trace = demo_trace();

        let mut proof = prove_air_with_spine(&air, &trace, &pi, &spine_inputs).unwrap();
        proof.spine.slots[0].sout_x4x3.a_final =
            proof.spine.slots[0].sout_x4x3.a_final + Block128::from(1u128);

        let err = verify_air_with_spine(&air, &pi, &spine_inputs, &proof);
        assert!(err.is_err());
    }

    #[test]
    fn stark_extras_actually_fork_transcript() {
        // Isolate the β₂ binding by bypassing verify_spine: rebuild
        // the extras the STARK verifier would see and replay it with
        // an intact vs. perturbed extras-transcript. If the verifier
        // accepted regardless, the extras hook would be
        // soundness-neutral.
        let spine_inputs = demo_spine_inputs();
        let pi = demo_public_inputs(&spine_inputs);
        let air = tiny_air();
        let trace = demo_trace();

        let proof = prove_air_with_spine(&air, &trace, &pi, &spine_inputs).unwrap();

        // Re-derive the reduction point the way verify_air_with_spine
        // does, so the ExtraColumn claim matches what the prover used.
        let claimed = tx_body_hash_as_lanes(&pi);
        let circuit = SpineCircuit::build();
        let mut spine_channel = Poseidon2bChannel::new();
        absorb_fri_commitment_into_spine_channel(
            &mut spine_channel,
            &proof.boundary_commitment,
        );
        let reduction = verify_spine(
            &proof.spine,
            &circuit,
            &spine_inputs,
            claimed,
            &mut spine_channel,
        )
        .expect("honest spine must verify here");
        let honest =
            spine_reduction_transcript(&reduction.point, reduction.value);
        let extras = vec![ExtraColumn {
            evals: Vec::new(),
            commitment: proof.boundary_commitment.clone(),
            eval_point: reduction.point.clone(),
            value: reduction.value,
        }];

        // Honest extras replay → accepts.
        verify_air_with_extra_columns(&air, &pi, &proof.stark, &honest, &extras).unwrap();

        // Perturbed extras-transcript → zero-check challenge drifts, verify rejects.
        let mut forged = honest.clone();
        forged[0] = forged[0] + Block128::from(1u128);
        let err = verify_air_with_extra_columns(&air, &pi, &proof.stark, &forged, &extras);
        assert!(
            err.is_err(),
            "spine-digest drift must fork STARK channel and break zero-check"
        );
    }
}
