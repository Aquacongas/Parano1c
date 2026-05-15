// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! STARK bridge for the auth GKR (Address/AuthTag) reduction.
//!
//! Mirror of [`crate::spine`]: two Fiat–Shamir runs stapled by one
//! shared FRI commitment and one shared `(r_B, v_B)` reduction.
//!
//! # Why an auth-specific wrapper?
//!
//! The spine wrapper proves the Merkle path folds down to
//! `pi.tx_body_hash`. The auth wrapper proves that every live input's
//! `(Address, AuthTag)` was produced by honest `HAddr`/`HAuth` chains
//! driven by the spender's secret, **without exposing the secret to the
//! verifier**. The secret is witness-only; the verifier sees only the
//! committed 2^14-cell unified state MLE and the
//! `(r_B, v_B)` reduction scalars.
//!
//! # Binding
//!
//! 1. The auth boundary FRI commitment seeds the auth Poseidon2b
//!    channel — any tamper to `B_auth` forks every auth challenge,
//!    including the per-slot `r0` draws feeding `prove_perm`.
//! 2. The STARK parent channel absorbs `(r_B, v_B)` via
//!    [`auth_reduction_transcript`]; any change to the reduction forks
//!    every STARK challenge drawn after column-root absorption.
//! 3. The STARK's mixed-length multipoint close carries `B_auth` as an
//!    [`ExtraColumn`] and opens it at `r_B`. The same FRI root that
//!    seeded the auth channel is now proved against the committed
//!    polynomial — no daylight between the two transcripts.

use noid_air::{Air, Trace};
use noid_core::transcript::FiatShamir;
use noid_core::{AdditiveNTT, Block128};
use noid_fri::code::LOG_RATE;
use noid_fri::hasher::Blake3Hasher;
use noid_fri::prover::{commit as fri_commit, FriCommitment};
use noid_gkr::{
    build_auth_unified_from_inputs, prove_auth_killshot,
    verify_auth_killshot, AuthCircuit, AuthInputs, AuthProofKillShot,
    N_AUTH_UNIFIED_VARS,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_tx::PublicInputs;

use crate::{
    prove_air_unchecked_with_extra_columns, verify_air_with_extra_columns, ExtraColumn,
    ProveError, StarkProof, VerifyError,
};

/// Composite proof: a normal STARK proof plus the AuthGKR Kill-Shot
/// proof, both written against the same `PublicInputs`. Byte layout
/// mirrors [`crate::spine::StarkProofWithSpine`].
///
/// Step 3 Phase 1 flip: the legacy per-perm `AuthProof` is replaced by
/// `AuthProofKillShot` (unified sumcheck + shift). The STARK bridge now
/// uses the kill-shot entry point exclusively.
#[derive(Debug, Clone)]
pub struct StarkProofWithAuth {
    pub stark: StarkProof,
    pub auth: AuthProofKillShot,
    pub boundary_commitment: FriCommitment,
}

/// Verifier-side failures specific to the with-auth path.
#[derive(Debug)]
pub enum VerifyWithAuthError {
    /// Inner STARK verification failed.
    Stark(VerifyError),
    /// Inner AuthGKR verification failed. Covers slot-count mismatch,
    /// any per-slot permutation sumcheck rejection, a lying
    /// `slot_v0`, or a boundary pin (`expected_address` /
    /// `expected_auth_tag`) mismatch.
    Auth,
}

impl From<VerifyError> for VerifyWithAuthError {
    fn from(e: VerifyError) -> Self {
        VerifyWithAuthError::Stark(e)
    }
}

/// Flatten `(r_B, v_B)` into the field-element stream the STARK parent
/// channel absorbs at the extras-transcript hook. Same shape as
/// [`crate::spine::spine_reduction_transcript`].
pub fn auth_reduction_transcript(
    reduction_point: &[Block128],
    reduction_value: Block128,
) -> Vec<Block128> {
    let mut out = Vec::with_capacity(reduction_point.len() + 1);
    out.extend_from_slice(reduction_point);
    out.push(reduction_value);
    out
}

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

fn absorb_fri_commitment_into_auth_channel(
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

/// Commit the 2^14-cell unified state MLE, run the AuthGKR Kill-Shot
/// against a channel seeded with the commitment root, and fold the
/// reduction `(r_B, v_B)` into the STARK parent via the
/// extras-transcript hook. The state MLE rides along as an
/// [`ExtraColumn`] so the STARK's mixed-close FRI opening discharges
/// `state(r_B) = v_B`.
///
/// Step 3 Phase 1: uses `prove_auth_killshot` (unified sumcheck +
/// shift) instead of the legacy per-perm `prove_auth`.
pub fn prove_air_with_auth<A: Air>(
    air: &A,
    trace: &Trace,
    pi: &PublicInputs,
    auth_inputs: &AuthInputs,
) -> Result<StarkProofWithAuth, ProveError> {
    if !air.check(trace) {
        return Err(ProveError::TraceRejectedByAir);
    }

    let circuit = AuthCircuit::build();

    // Build and commit the unified state MLE (14 vars).
    let unified_mle = build_auth_unified_from_inputs(&circuit, auth_inputs);
    let state_mle = unified_mle.state;
    let ntt = AdditiveNTT::<Block128>::new(N_AUTH_UNIFIED_VARS + LOG_RATE);
    let hasher = Blake3Hasher::new();
    let (boundary_commitment, _tree, _code) = fri_commit(&state_mle, &ntt, &hasher);

    // Seed auth channel with boundary commitment, run Kill-Shot.
    let mut auth_channel = Poseidon2bChannel::new();
    absorb_fri_commitment_into_auth_channel(&mut auth_channel, &boundary_commitment);
    let (auth_proof, reductions) = prove_auth_killshot(&circuit, auth_inputs, &mut auth_channel);

    let reduction = &reductions.state;
    let extras = vec![ExtraColumn {
        evals: state_mle,
        commitment: boundary_commitment.clone(),
        eval_point: reduction.point.clone(),
        value: reduction.value,
    }];
    let extras_transcript = auth_reduction_transcript(&reduction.point, reduction.value);
    let stark = prove_air_unchecked_with_extra_columns(
        air,
        trace,
        pi,
        &extras_transcript,
        &extras,
    );

    Ok(StarkProofWithAuth {
        stark,
        auth: auth_proof,
        boundary_commitment,
    })
}

/// Verify the AuthGKR Kill-Shot first, then replay the STARK with the
/// same extras-transcript and boundary commitment.
///
/// Step 3 Phase 1: uses `verify_auth_killshot` instead of the legacy
/// per-perm `verify_auth`.
pub fn verify_air_with_auth<A: Air>(
    air: &A,
    pi: &PublicInputs,
    auth_inputs: &AuthInputs,
    proof: &StarkProofWithAuth,
) -> Result<(), VerifyWithAuthError> {
    let circuit = AuthCircuit::build();

    if proof.boundary_commitment.log_len != N_AUTH_UNIFIED_VARS {
        return Err(VerifyWithAuthError::Auth);
    }

    let mut auth_channel = Poseidon2bChannel::new();
    absorb_fri_commitment_into_auth_channel(&mut auth_channel, &proof.boundary_commitment);
    let reductions =
        verify_auth_killshot(&proof.auth, &circuit, auth_inputs, &mut auth_channel)
            .ok_or(VerifyWithAuthError::Auth)?;

    let reduction = &reductions.state;
    let extras = vec![ExtraColumn {
        evals: Vec::new(),
        commitment: proof.boundary_commitment.clone(),
        eval_point: reduction.point.clone(),
        value: reduction.value,
    }];
    let extras_transcript = auth_reduction_transcript(&reduction.point, reduction.value);
    verify_air_with_extra_columns(air, pi, &proof.stark, &extras_transcript, &extras)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_air::airs::linear_combination::LinearCombinationAir;
    use noid_core::TowerField;
    use noid_gkr::{compute_auth_boundary, N_AUTH_INPUTS};
    use noid_poseidon2b::primitives::{SpendSecret, TxBodyHash};

    fn tiny_air() -> LinearCombinationAir {
        LinearCombinationAir::new(3, 8)
    }

    fn digest_to_fields(d: &[u8; 32]) -> [Block128; 2] {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        a.copy_from_slice(&d[..16]);
        b.copy_from_slice(&d[16..]);
        [
            Block128::from(u128::from_le_bytes(a)),
            Block128::from(u128::from_le_bytes(b)),
        ]
    }

    fn demo_auth_inputs() -> AuthInputs {
        let circuit = AuthCircuit::build();
        let secrets = [
            SpendSecret([1u8; 32]),
            SpendSecret([2u8; 32]),
            SpendSecret([3u8; 32]),
            SpendSecret([4u8; 32]),
        ];
        let tbh = TxBodyHash([0x5Au8; 32]);

        let mut spend_secret = [[Block128::ZERO; 2]; N_AUTH_INPUTS];
        for i in 0..N_AUTH_INPUTS {
            spend_secret[i] = secrets[i].as_fields();
        }
        let tx_body_hash = digest_to_fields(tbh.as_bytes());
        let (expected_address, expected_auth_tag) =
            compute_auth_boundary(&circuit, spend_secret, tx_body_hash);

        AuthInputs {
            spend_secret,
            tx_body_hash,
            expected_address,
            expected_auth_tag,
        }
    }

    fn demo_pi() -> PublicInputs {
        PublicInputs {
            prev_state_root: [0u8; 32],
            new_state_root: [0u8; 32],
            tx_body_hash: TxBodyHash([0u8; 32]),
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
        let col0: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 * 7 + 1)).collect();
        let col1: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 * 11 + 3)).collect();
        let col2: Vec<Block128> = col0.iter().zip(col1.iter()).map(|(a, b)| *a + *b).collect();
        Trace::new(vec![col0, col1, col2])
    }

    #[test]
    fn honest_with_auth_roundtrip() {
        let inputs = demo_auth_inputs();
        let pi = demo_pi();
        let air = tiny_air();
        let trace = demo_trace();
        let proof = prove_air_with_auth(&air, &trace, &pi, &inputs).unwrap();
        verify_air_with_auth(&air, &pi, &inputs, &proof).unwrap();
    }

    #[test]
    fn tampered_expected_address_rejected() {
        let inputs = demo_auth_inputs();
        let pi = demo_pi();
        let air = tiny_air();
        let trace = demo_trace();
        let proof = prove_air_with_auth(&air, &trace, &pi, &inputs).unwrap();

        let mut bad = inputs.clone();
        bad.expected_address[1][0] = bad.expected_address[1][0] + Block128::from(1u128);
        let err = verify_air_with_auth(&air, &pi, &bad, &proof);
        assert!(matches!(err, Err(VerifyWithAuthError::Auth)));
    }

    #[test]
    fn tampered_state_batch_rejected() {
        // Kill-Shot equivalent of the legacy `tampered_slot_v0` test:
        // flip a scalar in the state batch-eval proof. The kill-shot
        // verifier must reject before we reach the STARK.
        let inputs = demo_auth_inputs();
        let pi = demo_pi();
        let air = tiny_air();
        let trace = demo_trace();
        let mut proof = prove_air_with_auth(&air, &trace, &pi, &inputs).unwrap();
        proof.auth.state_batch.b_final =
            proof.auth.state_batch.b_final + Block128::from(1u128);
        let err = verify_air_with_auth(&air, &pi, &inputs, &proof);
        assert!(matches!(err, Err(VerifyWithAuthError::Auth)));
    }

    #[test]
    fn tampered_auth_killshot_scalar_rejected() {
        // Flip a scalar in the unified proof's round polys.
        let inputs = demo_auth_inputs();
        let pi = demo_pi();
        let air = tiny_air();
        let trace = demo_trace();
        let mut proof = prove_air_with_auth(&air, &trace, &pi, &inputs).unwrap();
        proof.auth.kill_shot.main.state_at_r =
            proof.auth.kill_shot.main.state_at_r + Block128::from(1u128);
        let err = verify_air_with_auth(&air, &pi, &inputs, &proof);
        assert!(err.is_err());
    }

    #[test]
    fn transcript_determinism() {
        let inputs = demo_auth_inputs();
        let pi = demo_pi();
        let air = tiny_air();
        let trace = demo_trace();

        let p1 = prove_air_with_auth(&air, &trace, &pi, &inputs).unwrap();
        let p2 = prove_air_with_auth(&air, &trace, &pi, &inputs).unwrap();
        assert_eq!(p1.auth, p2.auth);
    }

    #[test]
    fn auth_extras_actually_fork_transcript() {
        // Bypass verify_auth_killshot, rebuild the extras the STARK
        // verifier sees, and confirm a perturbed extras-transcript
        // is rejected.
        let inputs = demo_auth_inputs();
        let pi = demo_pi();
        let air = tiny_air();
        let trace = demo_trace();
        let proof = prove_air_with_auth(&air, &trace, &pi, &inputs).unwrap();

        let circuit = AuthCircuit::build();
        let mut auth_channel = Poseidon2bChannel::new();
        absorb_fri_commitment_into_auth_channel(&mut auth_channel, &proof.boundary_commitment);
        let reductions =
            verify_auth_killshot(&proof.auth, &circuit, &inputs, &mut auth_channel)
                .expect("honest auth must verify here");
        let reduction = &reductions.state;
        let honest = auth_reduction_transcript(&reduction.point, reduction.value);
        let extras = vec![ExtraColumn {
            evals: Vec::new(),
            commitment: proof.boundary_commitment.clone(),
            eval_point: reduction.point.clone(),
            value: reduction.value,
        }];
        verify_air_with_extra_columns(&air, &pi, &proof.stark, &honest, &extras).unwrap();

        let mut forged = honest.clone();
        forged[0] = forged[0] + Block128::from(1u128);
        let err = verify_air_with_extra_columns(&air, &pi, &proof.stark, &forged, &extras);
        assert!(
            err.is_err(),
            "auth-reduction drift must fork STARK channel and break zero-check"
        );
    }
}
