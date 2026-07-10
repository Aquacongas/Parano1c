//! Gates pinning the owner-authorization killshot channel schedule extractor
//! to the REAL KSCHANNL transcript (`Poseidon2bChannel`, the same rate-2
//! duplex as the wallet-capsule FRICHANL channel, differing only in the IV).
//!
//! The extractor's op list replayed on a fresh channel must reach the same
//! post-state as running the real `verify_owner_auth_killshot` (post-state
//! differential — any divergence shifts every later squeeze), and the region
//! chain (`compile_duplex` + `build_duplex_columns` with the KSCHANNL IV)
//! squeezes the same challenges in the flat basis.

use noid_core::transcript::FiatShamir;
use noid_core::Block128;
use noid_gkr::owner_auth::{
    compute_owner_auth_boundary, owner_auth_gkr_channel, prove_owner_auth_killshot,
    verify_owner_auth_killshot_with_claims, OwnerAuthCircuit, OwnerAuthInputs,
    OwnerAuthProofKillShot, OwnerAuthPublicInputs, OWNER_AUTH_NUM_VARS,
};
use noid_ivc_core::deep_chain::schedule::{
    build_duplex_columns, compile_duplex, flat_of_tower_u128, LaneSource, TranscriptOp,
};
use noid_ivc_core::field::F128;
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_poseidon2b::native::domain::{capacity_iv, TAG_KSCHANNL};
use noid_recursive::acceptance::region::owner_auth_channel_schedule;

fn kschanl_iv_flat() -> [F128; 2] {
    let iv = capacity_iv(TAG_KSCHANNL);
    [flat_of_tower_u128(iv[0].0), flat_of_tower_u128(iv[1].0)]
}

/// Honest fixed-owner fixture. The secret is used only to run the native
/// prover; no secret-derived value is exposed by the extractor.
fn fixture(seed: u128) -> (OwnerAuthProofKillShot, OwnerAuthPublicInputs) {
    let circuit = OwnerAuthCircuit::build();
    let spend_secret = [Block128::from(seed + 1000), Block128::from(seed + 2000)];
    let tx_body_hash = [Block128::from(seed + 7), Block128::from(seed + 8)];
    let expected_address = compute_owner_auth_boundary(&circuit, spend_secret, tx_body_hash);
    let public = OwnerAuthPublicInputs::new(tx_body_hash, expected_address);
    let inputs = OwnerAuthInputs::from_parts(&public, spend_secret);
    let mut ch = owner_auth_gkr_channel();
    let (proof, _) = prove_owner_auth_killshot(&circuit, &inputs, &mut ch);
    (proof, public)
}

/// Drive a real KSCHANNL channel by an op list, returning every squeezed
/// challenge; data lanes are taken from `data` in order. The channel starts
/// from a bare `Poseidon2bChannel::new()` (raw KSCHANNL IV) because the
/// schedule models the init domain-tag absorb as its first op.
fn drive_channel(ops: &[TranscriptOp], data: &[Block128]) -> Vec<Block128> {
    let mut channel = Poseidon2bChannel::new();
    let mut cursor = 0usize;
    let mut challenges = Vec::new();
    for op in ops {
        match op {
            TranscriptOp::Absorb(lanes) => {
                for lane in lanes {
                    let v = match lane {
                        None => {
                            let v = data[cursor];
                            cursor += 1;
                            v
                        }
                        Some(c) => Block128::from(*c),
                    };
                    channel.absorb(v);
                }
            }
            TranscriptOp::Squeeze(m) => {
                for _ in 0..*m {
                    challenges.push(channel.squeeze());
                }
            }
        }
    }
    assert_eq!(cursor, data.len(), "data stream fully consumed");
    challenges
}

/// The extractor's op list replayed on a fresh KSCHANNL channel reaches the
/// same post-state as the REAL `verify_owner_auth_killshot` run, and the
/// region chain squeezes the same challenges.
#[test]
fn owner_auth_schedule_matches_verify_killshot() {
    let (proof, public) = fixture(0xA3);
    let circuit = OwnerAuthCircuit::build();

    // The real verifier path (KSCHANNL channel, init + full killshot).
    let mut real_channel = owner_auth_gkr_channel();
    let claims =
        verify_owner_auth_killshot_with_claims(&proof, &circuit, &public, &mut real_channel)
            .expect("honest owner-auth killshot verifies");
    let _ = claims;

    // The extracted schedule replayed on a fresh channel.
    let schedule = owner_auth_channel_schedule(&proof, &public);
    let replay_challenges = drive_channel(&schedule.ops, &schedule.data_tower);

    // Post-state differential: any divergence anywhere in the schedule
    // shifts every later squeeze. The real channel was last touched by
    // verify_batch_eval (the PCS opening runs on a separate channel), so
    // both are in the post-step-6 state.
    {
        let mut replay = Poseidon2bChannel::new();
        let mut cursor = 0usize;
        for op in &schedule.ops {
            match op {
                TranscriptOp::Absorb(lanes) => {
                    for lane in lanes {
                        let v = match lane {
                            None => {
                                let v = schedule.data_tower[cursor];
                                cursor += 1;
                                v
                            }
                            Some(c) => Block128::from(*c),
                        };
                        replay.absorb(v);
                    }
                }
                TranscriptOp::Squeeze(m) => {
                    for _ in 0..*m {
                        let _ = replay.squeeze();
                    }
                }
            }
        }
        assert_eq!(cursor, schedule.data_tower.len());
        assert_eq!(
            replay.squeeze(),
            real_channel.squeeze(),
            "schedule diverged from verify_owner_auth_killshot"
        );
    }

    // Region chain replay: same challenges in the flat basis.
    let layout = compile_duplex(&schedule.ops);
    let w_log = layout.slots.len().next_power_of_two().trailing_zeros() as usize;
    let cols = build_duplex_columns(&layout, kschanl_iv_flat(), &schedule.data_flat, w_log);
    assert_eq!(cols.challenges.len(), replay_challenges.len());
    for (k, (region, tower)) in cols
        .challenges
        .iter()
        .zip(replay_challenges.iter())
        .enumerate()
    {
        assert_eq!(
            *region,
            flat_of_tower_u128(tower.0),
            "challenge {k} diverged"
        );
    }
    eprintln!(
        "[owner-auth-channel] nv={}: {} slots, {} data lanes, {} challenges",
        OWNER_AUTH_NUM_VARS,
        layout.slots.len(),
        layout.n_data,
        cols.challenges.len()
    );

    // Negative: flipping one absorbed data lane shifts the post-state.
    {
        let mut bad = schedule.data_tower.clone();
        bad[5] += Block128::from(1u128);
        let bad_challenges = drive_channel(&schedule.ops, &bad);
        assert_ne!(
            bad_challenges.last(),
            replay_challenges.last(),
            "tampered lane left the challenge stream unchanged"
        );
    }

    // Negative: a wrong protocol constant (a small constant lane) shifts
    // the transcript.
    {
        let mut bad_ops = schedule.ops.clone();
        let mut patched = false;
        for op in bad_ops.iter_mut() {
            if let TranscriptOp::Absorb(lanes) = op {
                for lane in lanes.iter_mut() {
                    if let Some(c) = lane {
                        if *c != 0 && !patched && *c < 1 << 20 {
                            *c += 1;
                            patched = true;
                        }
                    }
                }
            }
        }
        assert!(patched, "no small constant lane found to patch");
        let bad_challenges = drive_channel(&bad_ops, &schedule.data_tower);
        assert_ne!(
            bad_challenges.last(),
            replay_challenges.last(),
            "tampered constant left the challenge stream unchanged"
        );
    }
}

/// Layout facts the [G] assembly depends on: every owner-auth challenge is
/// readable from a carry cell, duplex lane order holds, and the challenge
/// count is the modeled `5*num_vars + 3` (rho + 4 sumchecks of num_vars each,
/// plus delta + boundary-α + batch-α).
#[test]
fn owner_auth_layout_shape_facts() {
    let (proof, public) = fixture(0xFAC7);
    let schedule = owner_auth_channel_schedule(&proof, &public);
    let layout = compile_duplex(&schedule.ops);
    let num_vars = OWNER_AUTH_NUM_VARS;
    for &(slot, lane) in &layout.challenges {
        assert!(slot < layout.slots.len());
        assert!(lane < 2);
    }
    for s in &layout.slots {
        if s.lanes[1].is_some() && !matches!(s.lanes[1], Some(LaneSource::Const(_))) {
            assert!(s.lanes[0].is_some());
        }
    }
    assert_eq!(
        layout.challenges.len(),
        5 * num_vars + 3,
        "owner-auth squeeze budget = 5*num_vars + 3"
    );
}
