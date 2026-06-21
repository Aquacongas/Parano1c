// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Sweep AuthGKR Kill-Shot orchestrator (retargeted
//! onto the dedicated 16-variable Sweep AuthGKR hypercube).
//!
//! Runs the unified AuthGKR Kill-Shot instead of a per-permutation chain:
//! a single `prove_sweep_auth_unified` + `prove_sweep_auth_shift` pair, then
//! collapses the resulting witness claims for `state`, `s_in`, and `s_out`
//! through one multi-column batch-eval reduction:
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
//! Privacy invariant: raw `spend_secret` is never serialized and never
//! absorbed into Fiat-Shamir. The channel is seeded by the public boundary
//! plus the Auth MLE PCS commitment before GKR challenges. This is a compact
//! non-ZK authorization capsule: it removes raw-secret/raw-slice leakage, but
//! still exposes deterministic random-point side information about the private
//! AuthGKR trace.
//!
//! Transcript order
//! ----------------
//! 1. Absorb `tx_body_hash`.
//! 2. For each `i ∈ 0..N_SWEEP_AUTH_INPUTS`: absorb `expected_address[i]`
//!    then `expected_auth_tag[i]`.
//! 3. Absorb the Auth MLE PCS commitment (`state`, `s_in`, `s_out`).
//! 4. Run `prove_sweep_auth_unified` (squeezes ρ, β, γ; 16 round polys; 12
//!    final witness scalars).
//! 5. Run `prove_sweep_auth_shift` (squeezes δ; 16 round polys; 3 final
//!    witness scalars).
//! 6. Run one `prove_multi_batch_eval` over `state`, `s_in`, `s_out`.
//! 7. Open the three committed Sweep AuthGKR MLE columns with one mixed PCS
//!    opening at the shared terminal batch-eval point.

use noid_core::transcript::FiatShamir;
use noid_core::{Block128, TowerField};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_poseidon2b::native::permutation::{N_ROUNDS, STATE_SIZE};
use zeroize::Zeroize;

use crate::auth_circuit_sweep::{
    SweepAuthCircuit, SweepAuthInputs, SweepAuthPublicInputs, N_SWEEP_AUTH_INPUTS,
};
use crate::auth_mle_sweep::{
    build_sweep_auth_unified_mle, SweepAuthUnifiedMle, N_SWEEP_AUTH_LIVE_SLOTS,
    N_SWEEP_AUTH_UNIFIED_VARS,
};
use crate::auth_oracle_sweep::evaluate_sweep_auth;
use crate::auth_pcs::{
    absorb_auth_mle_commitment, commit_auth_mle_columns, open_auth_mle_columns_committed,
    verify_auth_mle_multi_opening, AuthMleMultiOpeningProof,
};
use crate::auth_unified_sweep::{
    prove_sweep_auth_shift, prove_sweep_auth_unified, verify_sweep_auth_shift,
    verify_sweep_auth_unified, SweepAuthKillShotProof, SweepAuthShiftReduction,
    SweepAuthUnifiedReduction,
};
use crate::batch_eval::{
    prove_multi_batch_eval, verify_multi_batch_eval, BatchEvalReduction, EvalClaim,
    MultiBatchEvalProof,
};

/// Number of digest lanes pinned at the boundary per output (Address
/// and AuthTag are each 2 lanes).
pub const SWEEP_AUTH_PIN_LANES: usize = 2;

/// Composite proof for an AuthGKR boundary in the Kill-Shot flow.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SweepAuthProofKillShot {
    pub kill_shot: SweepAuthKillShotProof,
    /// Reduces `state`, `s_in`, and `s_out` claims to one shared terminal point
    /// with one terminal value per logical Sweep AuthGKR MLE column.
    pub batch: MultiBatchEvalProof,
    /// Capsule-local PCS discharge for the three reduced claims. The commitment
    /// contains column-major slices for `state`, `s_in`, then `s_out`.
    pub pcs: AuthMleMultiOpeningProof,
}

impl SweepAuthProofKillShot {
    pub fn byte_len(&self) -> usize {
        let main_polys = self.kill_shot.main.round_polys.len() * 10 * 16;
        let shift_polys = self.kill_shot.shift.round_polys.len() * 3 * 16;
        let main_finals = 12 * 16;
        let shift_finals = 3 * 16;
        main_polys
            + shift_polys
            + main_finals
            + shift_finals
            + self.batch.byte_len()
            + self.pcs.byte_len()
    }
}

/// Reductions delivered to the FRI / STARK bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepAuthKillShotReductions {
    pub state: BatchEvalReduction,
    pub sin: BatchEvalReduction,
    pub sout: BatchEvalReduction,
}

/// Domain separator for the self-seeded sweep auth GKR channel. Distinct
/// from the standard AuthGKR domain so cross-shape transcripts cannot alias.
const SWEEP_AUTH_GKR_DOMAIN_TAG: u128 = 0xA07D_6B12_2500_0000;

#[inline]
fn absorb_pair<T: FiatShamir<Block128>>(channel: &mut T, pair: &[Block128; 2]) {
    channel.absorb(pair[0]);
    channel.absorb(pair[1]);
}

/// Absorb the public boundary into the channel — never touches
/// `spend_secret`.
fn absorb_public_boundary<T: FiatShamir<Block128>>(
    channel: &mut T,
    inputs: &SweepAuthPublicInputs,
) {
    absorb_pair(channel, &inputs.tx_body_hash);
    for i in 0..N_SWEEP_AUTH_INPUTS {
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
pub fn sweep_auth_gkr_channel() -> Poseidon2bChannel {
    let mut ch = Poseidon2bChannel::new();
    ch.absorb(Block128::from(SWEEP_AUTH_GKR_DOMAIN_TAG));
    ch
}

/// Hypercube coords of the `state` cell that holds output lane
/// `(slot, lane)` — `state[(slot, N_ROUNDS, lane)]` on the 16-var
/// Sweep AuthGKR hypercube.
fn state_output_point(slot: usize, lane: usize) -> Vec<Block128> {
    debug_assert!(slot < N_SWEEP_AUTH_LIVE_SLOTS);
    debug_assert!(lane < SWEEP_AUTH_PIN_LANES);
    let cell = SweepAuthUnifiedMle::index(slot, N_ROUNDS, lane);
    (0..N_SWEEP_AUTH_UNIFIED_VARS)
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
fn public_pin_claims(
    _circuit: &SweepAuthCircuit,
    inputs: &SweepAuthPublicInputs,
) -> Vec<EvalClaim> {
    let mut out = Vec::with_capacity(2 * SWEEP_AUTH_PIN_LANES * N_SWEEP_AUTH_INPUTS);
    for i in 0..N_SWEEP_AUTH_INPUTS {
        let slot = SweepAuthCircuit::haddr_output_slot(i);
        for lane in 0..SWEEP_AUTH_PIN_LANES {
            out.push(EvalClaim {
                point: state_output_point(slot, lane),
                value: inputs.expected_address[i][lane],
            });
        }
    }
    for i in 0..N_SWEEP_AUTH_INPUTS {
        let slot = SweepAuthCircuit::hauth_output_slot(i);
        for lane in 0..SWEEP_AUTH_PIN_LANES {
            out.push(EvalClaim {
                point: state_output_point(slot, lane),
                value: inputs.expected_auth_tag[i][lane],
            });
        }
    }
    out
}

/// Materialise the auth unified MLE bundle from `SweepAuthInputs`.
pub fn build_sweep_auth_unified_from_inputs(
    circuit: &SweepAuthCircuit,
    inputs: &SweepAuthInputs,
) -> SweepAuthUnifiedMle {
    let w = evaluate_sweep_auth(circuit, inputs);
    debug_assert_eq!(w.slots.len(), N_SWEEP_AUTH_LIVE_SLOTS);
    let mut state_ins: Vec<[Block128; STATE_SIZE]> = w.slots.iter().map(|s| s.state_in).collect();
    let (mle, _) = build_sweep_auth_unified_mle(&state_ins);
    state_ins.zeroize();
    mle
}

/// Honest prover.
pub fn prove_sweep_auth_killshot<T: FiatShamir<Block128>>(
    circuit: &SweepAuthCircuit,
    inputs: &SweepAuthInputs,
    channel: &mut T,
) -> (SweepAuthProofKillShot, SweepAuthKillShotReductions) {
    let witness = evaluate_sweep_auth(circuit, inputs);
    for i in 0..N_SWEEP_AUTH_INPUTS {
        debug_assert_eq!(
            witness.derived_address[i], inputs.expected_address[i],
            "prover asked to prove a mismatching Address at input {i}",
        );
        debug_assert_eq!(
            witness.derived_auth_tag[i], inputs.expected_auth_tag[i],
            "prover asked to prove a mismatching AuthTag at input {i}",
        );
    }

    let mut state_ins: Vec<[Block128; STATE_SIZE]> =
        witness.slots.iter().map(|s| s.state_in).collect();
    let (mle, _) = build_sweep_auth_unified_mle(&state_ins);
    state_ins.zeroize();
    prove_sweep_auth_killshot_from_mle(circuit, &inputs.to_public(), &mle, channel)
}

/// Honest prover variant for callers that already materialised the auth MLE.
pub fn prove_sweep_auth_killshot_with_mle<T: FiatShamir<Block128>>(
    circuit: &SweepAuthCircuit,
    inputs: &SweepAuthInputs,
    mle: &SweepAuthUnifiedMle,
    channel: &mut T,
) -> (SweepAuthProofKillShot, SweepAuthKillShotReductions) {
    #[cfg(debug_assertions)]
    {
        let witness = evaluate_sweep_auth(circuit, inputs);
        for i in 0..N_SWEEP_AUTH_INPUTS {
            debug_assert_eq!(
                witness.derived_address[i], inputs.expected_address[i],
                "prover asked to prove a mismatching Address at input {i}",
            );
            debug_assert_eq!(
                witness.derived_auth_tag[i], inputs.expected_auth_tag[i],
                "prover asked to prove a mismatching AuthTag at input {i}",
            );
        }
    }

    prove_sweep_auth_killshot_from_mle(circuit, &inputs.to_public(), mle, channel)
}

fn prove_sweep_auth_killshot_from_mle<T: FiatShamir<Block128>>(
    circuit: &SweepAuthCircuit,
    public: &SweepAuthPublicInputs,
    mle: &SweepAuthUnifiedMle,
    channel: &mut T,
) -> (SweepAuthProofKillShot, SweepAuthKillShotReductions) {
    let committed = commit_auth_mle_columns(
        &[
            mle.state.as_slice(),
            mle.s_in.as_slice(),
            mle.s_out.as_slice(),
        ],
        N_SWEEP_AUTH_UNIFIED_VARS,
    );

    absorb_public_boundary(channel, public);
    absorb_auth_mle_commitment(channel, &committed.commitment);

    let (main, r_prime) = prove_sweep_auth_unified(mle, channel);
    let (shift, r_double_prime) = prove_sweep_auth_shift(mle, &r_prime, channel);

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
    state_claims.extend(public_pin_claims(circuit, public));

    let sin_claims = vec![EvalClaim {
        point: r_double_prime.clone(),
        value: shift.s_in_at_r2,
    }];

    let sout_claims = vec![EvalClaim {
        point: r_double_prime,
        value: shift.s_out_at_r2,
    }];

    let (batch, reds) = prove_multi_batch_eval(
        &[
            mle.state.as_slice(),
            mle.s_in.as_slice(),
            mle.s_out.as_slice(),
        ],
        &[
            state_claims.as_slice(),
            sin_claims.as_slice(),
            sout_claims.as_slice(),
        ],
        channel,
    );
    debug_assert_eq!(reds.len(), 3);
    let pcs = open_auth_mle_columns_committed(&committed, N_SWEEP_AUTH_UNIFIED_VARS, &reds);

    let proof = SweepAuthProofKillShot {
        kill_shot: SweepAuthKillShotProof { main, shift },
        batch,
        pcs,
    };
    let reductions = SweepAuthKillShotReductions {
        state: reds[0].clone(),
        sin: reds[1].clone(),
        sout: reds[2].clone(),
    };
    (proof, reductions)
}

/// Verifier. Accepts only the public fields; `spend_secret` is
/// structurally excluded at the type level.
pub fn verify_sweep_auth_killshot<T: FiatShamir<Block128>>(
    proof: &SweepAuthProofKillShot,
    circuit: &SweepAuthCircuit,
    inputs: &SweepAuthPublicInputs,
    channel: &mut T,
) -> Option<SweepAuthKillShotReductions> {
    if circuit.slots.len() != N_SWEEP_AUTH_LIVE_SLOTS {
        return None;
    }

    absorb_public_boundary(channel, inputs);
    absorb_auth_mle_commitment(channel, &proof.pcs.commitment);

    let main_red: SweepAuthUnifiedReduction =
        verify_sweep_auth_unified(&proof.kill_shot.main, channel)?;
    let shift_red: SweepAuthShiftReduction =
        verify_sweep_auth_shift(&proof.kill_shot.shift, &main_red, channel)?;

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

    let sin_claims = vec![EvalClaim {
        point: shift_red.r_double_prime.clone(),
        value: shift_red.s_in_at_r2,
    }];

    let sout_claims = vec![EvalClaim {
        point: shift_red.r_double_prime,
        value: shift_red.s_out_at_r2,
    }];

    let reds = verify_multi_batch_eval(
        &proof.batch,
        &[
            state_claims.as_slice(),
            sin_claims.as_slice(),
            sout_claims.as_slice(),
        ],
        N_SWEEP_AUTH_UNIFIED_VARS,
        channel,
    )?;
    if reds.len() != 3
        || !verify_auth_mle_multi_opening(&proof.pcs, N_SWEEP_AUTH_UNIFIED_VARS, &reds)
    {
        return None;
    }

    Some(SweepAuthKillShotReductions {
        state: reds[0].clone(),
        sin: reds[1].clone(),
        sout: reds[2].clone(),
    })
}

/// Discharge all three reductions against the natively reconstructed
/// MLE bundle. Test harness; production path uses FRI commitments.
pub fn discharge_sweep_auth_reductions_native(
    circuit: &SweepAuthCircuit,
    inputs: &SweepAuthInputs,
    reductions: &SweepAuthKillShotReductions,
) -> bool {
    use noid_core::mle::evaluate::evaluate_slice;
    let mle = build_sweep_auth_unified_from_inputs(circuit, inputs);
    evaluate_slice(&mle.state, &reductions.state.point) == reductions.state.value
        && evaluate_slice(&mle.s_in, &reductions.sin.point) == reductions.sin.value
        && evaluate_slice(&mle.s_out, &reductions.sout.point) == reductions.sout.value
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::primitives::{SpendSecret, TxBodyHash};

    struct RecordingChannel {
        inner: Poseidon2bChannel,
        absorbed: Vec<Block128>,
    }

    impl RecordingChannel {
        fn sweep_auth_domain() -> Self {
            let mut ch = Self {
                inner: Poseidon2bChannel::new(),
                absorbed: Vec::new(),
            };
            ch.absorb(Block128::from(SWEEP_AUTH_GKR_DOMAIN_TAG));
            ch
        }
    }

    impl FiatShamir<Block128> for RecordingChannel {
        fn absorb(&mut self, elem: Block128) {
            self.absorbed.push(elem);
            self.inner.absorb(elem);
        }

        fn squeeze(&mut self) -> Block128 {
            self.inner.squeeze()
        }
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    fn secret_bytes_from_fields(fields: &[Block128; 2]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&fields[0].to_u128().to_le_bytes());
        out[16..].copy_from_slice(&fields[1].to_u128().to_le_bytes());
        out
    }

    fn fixture_inputs() -> SweepAuthInputs {
        let circuit = SweepAuthCircuit::build();
        let secrets: [SpendSecret; N_SWEEP_AUTH_INPUTS] = std::array::from_fn(|i| {
            let mut bytes = [0u8; 32];
            for (j, b) in bytes.iter_mut().enumerate() {
                *b = ((i + 1) as u8).wrapping_mul((j + 7) as u8);
            }
            SpendSecret(bytes)
        });
        let tbh = TxBodyHash([0x5Au8; 32]);

        let mut spend_secret = [[Block128::ZERO; 2]; N_SWEEP_AUTH_INPUTS];
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
            crate::auth_oracle_sweep::compute_sweep_auth_boundary(
                &circuit,
                spend_secret,
                tx_body_hash,
            );

        SweepAuthInputs {
            spend_secret,
            tx_body_hash,
            expected_address,
            expected_auth_tag,
        }
    }

    #[test]
    fn auth_killshot_round_trip_native_discharge() {
        let circuit = SweepAuthCircuit::build();
        let inputs = fixture_inputs();
        let public = inputs.to_public();

        let mut ch_p = sweep_auth_gkr_channel();
        let (proof, reductions) = prove_sweep_auth_killshot(&circuit, &inputs, &mut ch_p);

        let mut ch_v = sweep_auth_gkr_channel();
        let v_red = verify_sweep_auth_killshot(&proof, &circuit, &public, &mut ch_v)
            .expect("verifier accepts honest proof");

        assert_eq!(v_red, reductions);
        assert!(discharge_sweep_auth_reductions_native(
            &circuit, &inputs, &v_red
        ));
    }

    #[test]
    fn auth_killshot_serialization_does_not_contain_raw_spend_secret_limbs() {
        let circuit = SweepAuthCircuit::build();
        let inputs = fixture_inputs();
        let raw_secrets: Vec<[u8; 32]> = inputs
            .spend_secret
            .iter()
            .map(secret_bytes_from_fields)
            .collect();

        let mut ch_p = sweep_auth_gkr_channel();
        let (proof, _) = prove_sweep_auth_killshot(&circuit, &inputs, &mut ch_p);
        let bytes = bincode::serialize(&proof).expect("SweepAuthProofKillShot serializes");

        for secret in raw_secrets {
            assert!(
                !contains_bytes(&bytes, &secret),
                "Sweep Auth capsule serialized raw 32-byte spend_secret"
            );
            assert!(
                !contains_bytes(&bytes, &secret[..16]),
                "Sweep Auth capsule serialized spend_secret low limb"
            );
            assert!(
                !contains_bytes(&bytes, &secret[16..]),
                "Sweep Auth capsule serialized spend_secret high limb"
            );
        }
    }

    #[test]
    fn auth_killshot_transcript_never_absorbs_raw_spend_secret_limbs() {
        let circuit = SweepAuthCircuit::build();
        let inputs = fixture_inputs();
        let secret_limbs: Vec<Block128> = inputs
            .spend_secret
            .iter()
            .flat_map(|fields| fields.iter().copied())
            .collect();

        let mut ch = RecordingChannel::sweep_auth_domain();
        let _ = prove_sweep_auth_killshot(&circuit, &inputs, &mut ch);

        for limb in secret_limbs {
            assert!(
                !ch.absorbed.contains(&limb),
                "Sweep Auth transcript absorbed a raw spend_secret limb"
            );
        }
    }

    #[test]
    fn auth_killshot_rejects_tampered_state_at_r() {
        let circuit = SweepAuthCircuit::build();
        let inputs = fixture_inputs();
        let public = inputs.to_public();

        let mut ch_p = sweep_auth_gkr_channel();
        let (mut proof, _) = prove_sweep_auth_killshot(&circuit, &inputs, &mut ch_p);
        proof.kill_shot.main.state_at_r += Block128::ONE;

        let mut ch_v = sweep_auth_gkr_channel();
        assert!(verify_sweep_auth_killshot(&proof, &circuit, &public, &mut ch_v).is_none());
    }

    #[test]
    fn auth_killshot_rejects_tampered_shift_claim() {
        let circuit = SweepAuthCircuit::build();
        let inputs = fixture_inputs();
        let public = inputs.to_public();

        let mut ch_p = sweep_auth_gkr_channel();
        let (mut proof, _) = prove_sweep_auth_killshot(&circuit, &inputs, &mut ch_p);
        proof.kill_shot.shift.s_in_at_r2 += Block128::ONE;

        let mut ch_v = sweep_auth_gkr_channel();
        assert!(verify_sweep_auth_killshot(&proof, &circuit, &public, &mut ch_v).is_none());
    }

    #[test]
    fn auth_killshot_rejects_wrong_expected_address() {
        let circuit = SweepAuthCircuit::build();
        let inputs = fixture_inputs();
        let mut public = inputs.to_public();

        let mut ch_p = sweep_auth_gkr_channel();
        let (proof, _) = prove_sweep_auth_killshot(&circuit, &inputs, &mut ch_p);

        public.expected_address[0][0] += Block128::ONE;
        let mut ch_v = sweep_auth_gkr_channel();
        assert!(verify_sweep_auth_killshot(&proof, &circuit, &public, &mut ch_v).is_none());
    }

    #[test]
    fn auth_killshot_rejects_tampered_state_batch() {
        let circuit = SweepAuthCircuit::build();
        let inputs = fixture_inputs();
        let public = inputs.to_public();

        let mut ch_p = sweep_auth_gkr_channel();
        let (mut proof, _) = prove_sweep_auth_killshot(&circuit, &inputs, &mut ch_p);
        proof.batch.b_finals[0] += Block128::ONE;

        let mut ch_v = sweep_auth_gkr_channel();
        assert!(verify_sweep_auth_killshot(&proof, &circuit, &public, &mut ch_v).is_none());
    }
}
