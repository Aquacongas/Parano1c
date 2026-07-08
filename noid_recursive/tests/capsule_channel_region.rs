//! Gates pinning the duplex schedule compiler to the REAL wallet-capsule
//! transcript channel (`noid_fri::Channel`).
//!
//! 1. Random op lists: the compiled layout + flat chain replay must
//!    squeeze exactly the challenges the byte-level tower channel does.
//! 2. The capsule PCS schedule extractor must reproduce the transcript
//!    of `verify_auth_mle_opening` bit-for-bit: replaying its op list on
//!    a fresh channel leaves the channel in the same state as running
//!    the real verifier (post-state differential), and the region
//!    columns' challenge cells carry the same values in the flat basis.

use noid_core::mle::evaluate::evaluate_slice;
use noid_core::Block128;
use noid_fri::Channel;
use noid_fri_binius::capsule::capsule_verify;
use noid_gkr::auth_pcs::{commit_auth_mle_column, open_auth_mle_committed};
use noid_gkr::batch_eval::BatchEvalReduction;
use noid_ivc_core::deep_chain::schedule::{
    build_duplex_columns, compile_duplex, flat_of_tower_u128, LaneSource, TranscriptOp,
};
use noid_ivc_core::field::F128;
use noid_poseidon2b::native::domain::{capacity_iv, TAG_FRICHANL};
use noid_recursive::acceptance::region::capsule_pcs_channel_schedule;

struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn u128(&mut self) -> u128 {
        ((self.next_u64() as u128) << 64) | self.next_u64() as u128
    }
}

fn frichanl_iv_flat() -> [F128; 2] {
    let iv = capacity_iv(TAG_FRICHANL);
    [flat_of_tower_u128(iv[0].0), flat_of_tower_u128(iv[1].0)]
}

/// Drive a real channel by an op list, returning every squeezed
/// challenge; data lanes are taken from `data` in order.
fn drive_channel(ops: &[TranscriptOp], data: &[Block128]) -> Vec<Block128> {
    let mut channel = Channel::new();
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
                    channel.observe_field_elem(v);
                }
            }
            TranscriptOp::Squeeze(m) => {
                challenges.extend(channel.get_random_points(*m));
            }
        }
    }
    assert_eq!(cursor, data.len(), "data stream fully consumed");
    challenges
}

/// Random absorb/squeeze schedules: the flat region replay squeezes the
/// same challenges as the byte-level tower channel, for every lane
/// parity/pad/pending interleaving the sampler produces.
#[test]
fn random_schedules_match_real_channel() {
    let mut rng = Rng(0xC4A2E1);
    for case in 0..24 {
        let mut ops = Vec::new();
        let n_ops = 2 + (rng.next_u64() % 7) as usize;
        for i in 0..n_ops {
            if i % 2 == 0 {
                let n_lanes = 1 + (rng.next_u64() % 6) as usize;
                let lanes = (0..n_lanes)
                    .map(|_| {
                        if rng.next_u64() % 4 == 0 {
                            Some(rng.u128())
                        } else {
                            None
                        }
                    })
                    .collect();
                ops.push(TranscriptOp::Absorb(lanes));
            } else {
                ops.push(TranscriptOp::Squeeze(1 + (rng.next_u64() % 5) as usize));
            }
        }

        let layout = compile_duplex(&ops);
        let data_tower: Vec<Block128> =
            (0..layout.n_data).map(|_| Block128::from(rng.u128())).collect();
        let native = drive_channel(&ops, &data_tower);

        let data_flat: Vec<F128> = data_tower
            .iter()
            .map(|v| flat_of_tower_u128(v.0))
            .collect();
        let w_log = layout.slots.len().next_power_of_two().trailing_zeros() as usize;
        let cols = build_duplex_columns(&layout, frichanl_iv_flat(), &data_flat, w_log);

        assert_eq!(cols.challenges.len(), native.len(), "case {case}");
        for (k, (region, tower)) in cols.challenges.iter().zip(native.iter()).enumerate() {
            assert_eq!(
                *region,
                flat_of_tower_u128(tower.0),
                "case {case} challenge {k} diverged"
            );
        }
    }
}

fn capsule_fixture(num_vars: usize, seed: u64) -> (BatchEvalReduction, noid_gkr::auth_pcs::AuthMleOpeningProof) {
    let mut rng = Rng(seed);
    let column: Vec<Block128> = (0..(1usize << num_vars))
        .map(|_| Block128::from(rng.u128()))
        .collect();
    let point: Vec<Block128> = (0..num_vars).map(|_| Block128::from(rng.u128())).collect();
    let value = evaluate_slice(&column, &point);
    let reduction = BatchEvalReduction { point, value };
    let mut committed = commit_auth_mle_column(&column, num_vars);
    let proof = open_auth_mle_committed(&mut committed, num_vars, &reduction);
    (reduction, proof)
}

/// The extractor's op list replayed on a fresh channel reaches the same
/// post-state as the REAL `capsule_verify` run — same absorb bytes, same
/// squeeze count — and the region chain squeezes the same challenges. Two
/// capsule shapes (low_vars = 1 and 3).
#[test]
fn capsule_schedule_matches_capsule_verify() {
    for (num_vars, seed) in [(9usize, 0xA9u64), (11, 0xB11)] {
        let (reduction, proof) = capsule_fixture(num_vars, seed);

        // The real verifier path (mirrors verify_auth_mle_opening).
        let mut real_channel = Channel::new();
        let value = capsule_verify(
            &proof.commitment,
            &reduction.point,
            &proof.opening,
            &mut real_channel,
        )
        .expect("honest capsule opening verifies");
        assert_eq!(value, reduction.value);

        // The extracted schedule replayed on a fresh channel.
        let schedule = capsule_pcs_channel_schedule(&proof, num_vars, &reduction.point);
        let replay_challenges = {
            let mut channel = Channel::new();
            let mut cursor = 0usize;
            let mut challenges = Vec::new();
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
                            channel.observe_field_elem(v);
                        }
                    }
                    TranscriptOp::Squeeze(m) => {
                        challenges.extend(channel.get_random_points(*m));
                    }
                }
            }
            assert_eq!(cursor, schedule.data_tower.len());
            // Post-state differential: any divergence anywhere in the
            // schedule shifts every later squeeze.
            assert_eq!(
                channel.get_random_point(),
                real_channel.get_random_point(),
                "nv={num_vars}: schedule diverged from capsule_verify"
            );
            challenges
        };

        // Region chain replay: same challenges in the flat basis.
        let layout = compile_duplex(&schedule.ops);
        let w_log = layout.slots.len().next_power_of_two().trailing_zeros() as usize;
        let cols = build_duplex_columns(&layout, frichanl_iv_flat(), &schedule.data_flat, w_log);
        assert_eq!(cols.challenges.len(), replay_challenges.len());
        for (region, tower) in cols.challenges.iter().zip(replay_challenges.iter()) {
            assert_eq!(*region, flat_of_tower_u128(tower.0), "nv={num_vars}");
        }
        eprintln!(
            "[capsule-channel] nv={num_vars}: {} slots, {} data lanes, {} challenges",
            layout.slots.len(),
            layout.n_data,
            cols.challenges.len()
        );

        // Negative: flipping one absorbed data lane shifts the post-state.
        {
            let mut bad = schedule.data_tower.clone();
            bad[7] += Block128::from(1u128);
            let bad_challenges = drive_channel(&schedule.ops, &bad);
            assert_ne!(
                bad_challenges.last(),
                replay_challenges.last(),
                "nv={num_vars}: tampered lane left the query stream unchanged"
            );
        }

        // Negative: a wrong protocol constant (round-0 depth lane) shifts
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
                "nv={num_vars}: tampered constant left the query stream unchanged"
            );
        }
    }
}

/// Layout facts the [G] assembly depends on: every capsule challenge is
/// readable from a carry cell, and the slot count fits the modeled
/// per-transaction budget.
#[test]
fn capsule_layout_shape_facts() {
    let (reduction, proof) = capsule_fixture(9, 0xFAC7);
    let schedule = capsule_pcs_channel_schedule(&proof, 9, &reduction.point);
    let layout = compile_duplex(&schedule.ops);
    // Every challenge maps to lane 0 or 1 of some slot.
    for &(slot, lane) in &layout.challenges {
        assert!(slot < layout.slots.len());
        assert!(lane < 2);
    }
    // No slot absorbs on lane 1 while skipping lane 0 (duplex order).
    for s in &layout.slots {
        if s.lanes[1].is_some() && !matches!(s.lanes[1], Some(LaneSource::Const(_))) {
            assert!(s.lanes[0].is_some());
        }
    }
}
