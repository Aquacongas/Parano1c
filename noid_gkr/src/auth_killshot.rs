// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! AuthGKR Kill-Shot orchestrator (retargeted
//! onto the dedicated 14-variable AuthGKR hypercube).
//!
//! Runs the unified AuthGKR Kill-Shot instead of a per-permutation chain:
//! a single `prove_auth_unified` + `prove_auth_shift` pair, then
//! collapses the four resulting witness claims into three column
//! batch-eval reductions:
//!
//! ```text
//!         column           claims at points
//!     ────────────  ─────────────────────────────────
//!     state           state(r')   state(r'')   + per-input output pins
//!     s_in            s_in(r'')
//!     s_out           s_out(r'')
//! ```
//!
//! The output digests `Address[i]` / `AuthTag[i]` are lifted as
//! additional `EvalClaim`s on the `state` column at boolean hypercube
//! points corresponding to `state[(slot, N_ROUNDS, lane)]` for
//! `lane ∈ {0, 1}`. The batch-eval reduction therefore enforces all
//! public boundary equalities through a single mixed-close opening.
//!
//! Privacy invariant: `spend_secret` is never absorbed. Only public
//! inputs (`tx_body_hash`, `expected_address`, `expected_auth_tag`)
//! seed the channel before the sumchecks run.
//!
//! Transcript order
//! ----------------
//! 1. Absorb `tx_body_hash`.
//! 2. For each `i ∈ 0..N_AUTH_INPUTS`: absorb `expected_address[i]`
//!    then `expected_auth_tag[i]`.
//! 3. Run `prove_auth_unified` (squeezes ρ, β, γ; 14 round polys; 12
//!    final witness scalars).
//! 4. Run `prove_auth_shift` (squeezes δ; 14 round polys; 3 final
//!    witness scalars).
//! 5. Run `prove_batch_eval` on `state` with claims `(r', state_at_r)`,
//!    `(r'', state_at_r2)`, plus the per-input `(Address, AuthTag)`
//!    pins.
//! 6. Run `prove_batch_eval` on `s_in` with claim `(r'', s_in_at_r2)`.
//! 7. Run `prove_batch_eval` on `s_out` with claim `(r'', s_out_at_r2)`.

use noid_core::transcript::FiatShamir;
use noid_core::{Block128, TowerField};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_poseidon2b::native::permutation::{N_ROUNDS, STATE_SIZE};

use crate::auth_circuit::{AuthCircuit, AuthInputs, AuthPublicInputs, N_AUTH_INPUTS};
use crate::auth_mle_v2::{
    build_auth_unified_mle_v2, AuthUnifiedMle, N_AUTH_LIVE_SLOTS, N_AUTH_UNIFIED_VARS,
};
use crate::auth_oracle::evaluate_auth;
use crate::auth_unified_v2::{
    prove_auth_shift, prove_auth_unified, verify_auth_shift, verify_auth_unified,
    AuthKillShotProof, AuthShiftReduction, AuthUnifiedReduction,
};
use crate::batch_eval::{
    prove_batch_eval, verify_batch_eval, BatchEvalProof, BatchEvalReduction, EvalClaim,
};

/// Number of digest lanes pinned at the boundary per output (Address
/// and AuthTag are each 2 lanes).
pub const AUTH_PIN_LANES: usize = 2;

/// Composite proof for an AuthGKR boundary in the Kill-Shot flow.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuthProofKillShot {
    pub kill_shot: AuthKillShotProof,
    /// Discharges `state(r')`, `state(r'')`, plus all output digest
    /// pins against the committed `state` MLE.
    pub state_batch: BatchEvalProof,
    /// Discharges `s_in(r'')` against the committed `s_in` MLE.
    pub sin_batch: BatchEvalProof,
    /// Discharges `s_out(r'')` against the committed `s_out` MLE.
    pub sout_batch: BatchEvalProof,
}

impl AuthProofKillShot {
    pub fn byte_len(&self) -> usize {
        let main_polys = self.kill_shot.main.round_polys.len() * 10 * 16;
        let shift_polys = self.kill_shot.shift.round_polys.len() * 3 * 16;
        let main_finals = 12 * 16;
        let shift_finals = 3 * 16;
        main_polys
            + shift_polys
            + main_finals
            + shift_finals
            + self.state_batch.byte_len()
            + self.sin_batch.byte_len()
            + self.sout_batch.byte_len()
    }
}

/// Reductions delivered to the FRI / STARK bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthKillShotReductions {
    pub state: BatchEvalReduction,
    pub sin: BatchEvalReduction,
    pub sout: BatchEvalReduction,
}

/// Domain separator for the self-seeded auth GKR channel. Ensures no
/// collision with other protocol sub-channels.
const AUTH_GKR_DOMAIN_TAG: u128 = 0xA07D_6B12_0000_0000;

#[inline]
fn absorb_pair<T: FiatShamir<Block128>>(channel: &mut T, pair: &[Block128; 2]) {
    channel.absorb(pair[0]);
    channel.absorb(pair[1]);
}

/// Absorb the public boundary into the channel — never touches
/// `spend_secret`.
fn absorb_public_boundary<T: FiatShamir<Block128>>(channel: &mut T, inputs: &AuthPublicInputs) {
    absorb_pair(channel, &inputs.tx_body_hash);
    for i in 0..N_AUTH_INPUTS {
        absorb_pair(channel, &inputs.expected_address[i]);
        absorb_pair(channel, &inputs.expected_auth_tag[i]);
    }
}

/// Create a deterministically-seeded Poseidon2b channel for AuthGKR.
///
/// Seeded with a domain tag only. The prove/verify functions absorb the
/// public boundary internally. This makes the auth proof portable: it
/// does NOT depend on any commitment cap, so the same proof works in
/// both LogicProof and BlockProof contexts.
///
/// PRIVACY: By decoupling the auth channel from the Merkle commitment
/// cap, the wallet can generate the auth proof locally (with
/// `spend_secret`) and the block prover can include it as-is without
/// re-proving.
pub fn auth_gkr_channel() -> Poseidon2bChannel {
    let mut ch = Poseidon2bChannel::new();
    ch.absorb(Block128::from(AUTH_GKR_DOMAIN_TAG));
    ch
}

/// Hypercube coords of the `state` cell that holds output lane
/// `(slot, lane)` — `state[(slot, N_ROUNDS, lane)]` on the 14-var
/// AuthGKR hypercube.
fn state_output_point(slot: usize, lane: usize) -> Vec<Block128> {
    debug_assert!(slot < N_AUTH_LIVE_SLOTS);
    debug_assert!(lane < AUTH_PIN_LANES);
    let cell = AuthUnifiedMle::index(slot, N_ROUNDS, lane);
    (0..N_AUTH_UNIFIED_VARS)
        .map(|b| {
            if (cell >> b) & 1 == 1 {
                Block128::ONE
            } else {
                Block128::ZERO
            }
        })
        .collect()
}

/// Build the public-pin claim list — Address inputs 0..N then AuthTag
/// inputs 0..N, two lanes each. Identical order on prover and verifier.
fn public_pin_claims(_circuit: &AuthCircuit, inputs: &AuthPublicInputs) -> Vec<EvalClaim> {
    let mut out = Vec::with_capacity(2 * AUTH_PIN_LANES * N_AUTH_INPUTS);
    for i in 0..N_AUTH_INPUTS {
        let slot = AuthCircuit::haddr_output_slot(i);
        for lane in 0..AUTH_PIN_LANES {
            out.push(EvalClaim {
                point: state_output_point(slot, lane),
                value: inputs.expected_address[i][lane],
            });
        }
    }
    for i in 0..N_AUTH_INPUTS {
        let slot = AuthCircuit::hauth_output_slot(i);
        for lane in 0..AUTH_PIN_LANES {
            out.push(EvalClaim {
                point: state_output_point(slot, lane),
                value: inputs.expected_auth_tag[i][lane],
            });
        }
    }
    out
}

/// Materialise the auth unified MLE bundle from `AuthInputs`.
pub fn build_auth_unified_from_inputs(
    circuit: &AuthCircuit,
    inputs: &AuthInputs,
) -> AuthUnifiedMle {
    let w = evaluate_auth(circuit, inputs);
    debug_assert_eq!(w.slots.len(), N_AUTH_LIVE_SLOTS);
    let state_ins: Vec<[Block128; STATE_SIZE]> = w.slots.iter().map(|s| s.state_in).collect();
    let (mle, _) = build_auth_unified_mle_v2(&state_ins);
    mle
}

/// Honest prover.
pub fn prove_auth_killshot<T: FiatShamir<Block128>>(
    circuit: &AuthCircuit,
    inputs: &AuthInputs,
    channel: &mut T,
) -> (AuthProofKillShot, AuthKillShotReductions) {
    let witness = evaluate_auth(circuit, inputs);
    for i in 0..N_AUTH_INPUTS {
        debug_assert_eq!(
            witness.derived_address[i], inputs.expected_address[i],
            "prover asked to prove a mismatching Address at input {i}",
        );
        debug_assert_eq!(
            witness.derived_auth_tag[i], inputs.expected_auth_tag[i],
            "prover asked to prove a mismatching AuthTag at input {i}",
        );
    }

    let public = inputs.to_public();
    absorb_public_boundary(channel, &public);

    let state_ins: Vec<[Block128; STATE_SIZE]> = witness.slots.iter().map(|s| s.state_in).collect();
    let (mle, _) = build_auth_unified_mle_v2(&state_ins);

    let (main, r_prime) = prove_auth_unified(&mle, channel);
    let (shift, r_double_prime) = prove_auth_shift(&mle, &r_prime, channel);

    let mut state_claims = vec![
        EvalClaim {
            point: r_prime.clone(),
            value: main.state_at_r,
        },
        EvalClaim {
            point: r_double_prime.clone(),
            value: shift.state_at_r2,
        },
    ];
    state_claims.extend(public_pin_claims(circuit, &public));
    let (state_batch, state_red) = prove_batch_eval(&mle.state, &state_claims, channel);

    let sin_claims = vec![EvalClaim {
        point: r_double_prime.clone(),
        value: shift.s_in_at_r2,
    }];
    let (sin_batch, sin_red) = prove_batch_eval(&mle.s_in, &sin_claims, channel);

    let sout_claims = vec![EvalClaim {
        point: r_double_prime,
        value: shift.s_out_at_r2,
    }];
    let (sout_batch, sout_red) = prove_batch_eval(&mle.s_out, &sout_claims, channel);

    let proof = AuthProofKillShot {
        kill_shot: AuthKillShotProof { main, shift },
        state_batch,
        sin_batch,
        sout_batch,
    };
    let reductions = AuthKillShotReductions {
        state: state_red,
        sin: sin_red,
        sout: sout_red,
    };
    (proof, reductions)
}

/// Verifier. Accepts only the public fields; `spend_secret` is
/// structurally excluded at the type level.
pub fn verify_auth_killshot<T: FiatShamir<Block128>>(
    proof: &AuthProofKillShot,
    circuit: &AuthCircuit,
    inputs: &AuthPublicInputs,
    channel: &mut T,
) -> Option<AuthKillShotReductions> {
    if circuit.slots.len() != N_AUTH_LIVE_SLOTS {
        return None;
    }

    absorb_public_boundary(channel, inputs);

    let main_red: AuthUnifiedReduction = verify_auth_unified(&proof.kill_shot.main, channel)?;
    let shift_red: AuthShiftReduction =
        verify_auth_shift(&proof.kill_shot.shift, &main_red, channel)?;

    let mut state_claims = vec![
        EvalClaim {
            point: main_red.r_prime.clone(),
            value: main_red.state_at_r,
        },
        EvalClaim {
            point: shift_red.r_double_prime.clone(),
            value: shift_red.state_at_r2,
        },
    ];
    state_claims.extend(public_pin_claims(circuit, inputs));
    let state_red = verify_batch_eval(
        &proof.state_batch,
        &state_claims,
        N_AUTH_UNIFIED_VARS,
        channel,
    )?;

    let sin_claims = vec![EvalClaim {
        point: shift_red.r_double_prime.clone(),
        value: shift_red.s_in_at_r2,
    }];
    let sin_red = verify_batch_eval(&proof.sin_batch, &sin_claims, N_AUTH_UNIFIED_VARS, channel)?;

    let sout_claims = vec![EvalClaim {
        point: shift_red.r_double_prime,
        value: shift_red.s_out_at_r2,
    }];
    let sout_red = verify_batch_eval(
        &proof.sout_batch,
        &sout_claims,
        N_AUTH_UNIFIED_VARS,
        channel,
    )?;

    Some(AuthKillShotReductions {
        state: state_red,
        sin: sin_red,
        sout: sout_red,
    })
}

/// Discharge all three reductions against the natively reconstructed
/// MLE bundle. Test harness; production path uses FRI commitments.
pub fn discharge_auth_reductions_native(
    circuit: &AuthCircuit,
    inputs: &AuthInputs,
    reductions: &AuthKillShotReductions,
) -> bool {
    use noid_core::mle::evaluate::evaluate_slice;
    let mle = build_auth_unified_from_inputs(circuit, inputs);
    evaluate_slice(&mle.state, &reductions.state.point) == reductions.state.value
        && evaluate_slice(&mle.s_in, &reductions.sin.point) == reductions.sin.value
        && evaluate_slice(&mle.s_out, &reductions.sout.point) == reductions.sout.value
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::primitives::{SpendSecret, TxBodyHash};

    fn fixture_inputs() -> AuthInputs {
        let circuit = AuthCircuit::build();
        let secrets: [SpendSecret; N_AUTH_INPUTS] = std::array::from_fn(|i| {
            let mut bytes = [0u8; 32];
            for (j, b) in bytes.iter_mut().enumerate() {
                *b = ((i + 1) as u8).wrapping_mul((j + 7) as u8);
            }
            SpendSecret(bytes)
        });
        let tbh = TxBodyHash([0x5Au8; 32]);

        let mut spend_secret = [[Block128::ZERO; 2]; N_AUTH_INPUTS];
        for (i, s) in secrets.iter().enumerate() {
            spend_secret[i] = s.as_fields();
        }
        let mut tx_body_hash = [Block128::ZERO; 2];
        let bytes = tbh.into_bytes();
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        a.copy_from_slice(&bytes[..16]);
        b.copy_from_slice(&bytes[16..]);
        tx_body_hash[0] = Block128::from(u128::from_le_bytes(a));
        tx_body_hash[1] = Block128::from(u128::from_le_bytes(b));

        let (expected_address, expected_auth_tag) =
            crate::auth_oracle::compute_auth_boundary(&circuit, spend_secret, tx_body_hash);

        AuthInputs {
            spend_secret,
            tx_body_hash,
            expected_address,
            expected_auth_tag,
        }
    }

    #[test]
    fn auth_killshot_round_trip_native_discharge() {
        let circuit = AuthCircuit::build();
        let inputs = fixture_inputs();
        let public = inputs.to_public();

        let mut ch_p = auth_gkr_channel();
        let (proof, reductions) = prove_auth_killshot(&circuit, &inputs, &mut ch_p);

        let mut ch_v = auth_gkr_channel();
        let v_red = verify_auth_killshot(&proof, &circuit, &public, &mut ch_v)
            .expect("verifier accepts honest proof");

        assert_eq!(v_red, reductions);
        assert!(discharge_auth_reductions_native(&circuit, &inputs, &v_red));
    }

    #[test]
    fn auth_killshot_rejects_tampered_state_at_r() {
        let circuit = AuthCircuit::build();
        let inputs = fixture_inputs();
        let public = inputs.to_public();

        let mut ch_p = auth_gkr_channel();
        let (mut proof, _) = prove_auth_killshot(&circuit, &inputs, &mut ch_p);
        proof.kill_shot.main.state_at_r += Block128::ONE;

        let mut ch_v = auth_gkr_channel();
        assert!(verify_auth_killshot(&proof, &circuit, &public, &mut ch_v).is_none());
    }

    #[test]
    fn auth_killshot_rejects_tampered_shift_claim() {
        let circuit = AuthCircuit::build();
        let inputs = fixture_inputs();
        let public = inputs.to_public();

        let mut ch_p = auth_gkr_channel();
        let (mut proof, _) = prove_auth_killshot(&circuit, &inputs, &mut ch_p);
        proof.kill_shot.shift.s_in_at_r2 += Block128::ONE;

        let mut ch_v = auth_gkr_channel();
        assert!(verify_auth_killshot(&proof, &circuit, &public, &mut ch_v).is_none());
    }

    #[test]
    fn auth_killshot_rejects_wrong_expected_address() {
        let circuit = AuthCircuit::build();
        let inputs = fixture_inputs();
        let mut public = inputs.to_public();

        let mut ch_p = auth_gkr_channel();
        let (proof, _) = prove_auth_killshot(&circuit, &inputs, &mut ch_p);

        public.expected_address[0][0] += Block128::ONE;
        let mut ch_v = auth_gkr_channel();
        assert!(verify_auth_killshot(&proof, &circuit, &public, &mut ch_v).is_none());
    }

    #[test]
    fn auth_killshot_rejects_tampered_state_batch() {
        let circuit = AuthCircuit::build();
        let inputs = fixture_inputs();
        let public = inputs.to_public();

        let mut ch_p = auth_gkr_channel();
        let (mut proof, _) = prove_auth_killshot(&circuit, &inputs, &mut ch_p);
        proof.state_batch.b_final += Block128::ONE;

        let mut ch_v = auth_gkr_channel();
        assert!(verify_auth_killshot(&proof, &circuit, &public, &mut ch_v).is_none());
    }
}
