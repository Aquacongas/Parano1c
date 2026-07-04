//! End-to-end: builder-produced traces through the full FieldR1cs
//! prove → verify pipeline with the lane-oriented challenger.
//!
//! The 1000-permutation chain is the synthetic-trace acceptance test:
//! a real 2^19-constraint instance whose witness is a Poseidon2b permutation
//! chain, with the final state pinned to the natively computed value.

use noid_ivc_core::challenger::FsLaneChallenger;
use noid_ivc_core::field::F128;
use noid_ivc_core::field_circuit::{
    FieldR1csBuilder, FsChannelTrace, LinExpr, flat_const, poseidon2b_permute,
};
use noid_ivc_core::pcs::{self, PcsParams};
use noid_ivc_core::verifier::verify_field;
use noid_ivc_prover::field_prover::prove_field;
use noid_poseidon2b::native::permutation::{Poseidon2bPermutation, STATE_SIZE};

fn params_for(m_elems: usize) -> PcsParams {
    PcsParams {
        m: m_elems + pcs::LOG_PACKING,
        log_inv_rate: 2,
        log_batch_size: 2,
        profile: Default::default(),
    }
}

const DOMAIN: &[u8] = b"field-circuit-e2e-v0";

/// Chain of 1000 Poseidon2b permutations (≈ 360k constraints, k_log = 19),
/// final state pinned to the native chain output; prove + verify roundtrip,
/// then a corrupted-witness rejection.
#[test]
fn thousand_permutation_chain_roundtrip() {
    use noid_core::Block128;

    const CHAIN: usize = 1000;

    // Native reference chain.
    let seed: [Block128; STATE_SIZE] = [
        Block128(0x0123_4567_89ab_cdef_fedc_ba98_7654_3210),
        Block128(0xffff_0000_ffff_0000_aaaa_5555_aaaa_5555),
        Block128(0x1111_2222_3333_4444_5555_6666_7777_8888),
        Block128(0xdead_beef_cafe_babe_0123_4567_89ab_cdef),
    ];
    let mut expected = seed;
    for _ in 0..CHAIN {
        Poseidon2bPermutation.permute_mut(&mut expected);
    }

    // Circuit chain.
    let mut b = FieldR1csBuilder::new();
    let mut state: [LinExpr; STATE_SIZE] =
        std::array::from_fn(|i| LinExpr::from_wire(b.alloc_f128(flat_const(seed[i].0))));
    for _ in 0..CHAIN {
        state = poseidon2b_permute(&mut b, state);
    }
    for i in 0..STATE_SIZE {
        b.pin_f128(&state[i], flat_const(expected[i].0));
    }
    let n_constraints = b.num_wires();
    let (r1cs, z) = b.build();
    assert!(
        (360_000..=361_000).contains(&n_constraints),
        "unexpected chain size: {n_constraints}"
    );
    assert_eq!(r1cs.m, 19);
    assert!(r1cs.satisfies(&z));

    let params = params_for(r1cs.m);
    let mut ch_p = FsLaneChallenger::new(DOMAIN);
    let (proof, commitment, claim_p) = prove_field(&r1cs, &z, &params, &mut ch_p);

    let mut ch_v = FsLaneChallenger::new(DOMAIN);
    let claim_v = verify_field(&r1cs, &commitment, &proof, &mut ch_v)
        .expect("honest 1000-permutation chain proof rejected");
    assert_eq!(claim_p, claim_v);

    // A corrupted chain witness (one S-box wire) must not satisfy.
    let mut bad = z;
    bad[10_000] += F128::ONE;
    assert!(!r1cs.satisfies(&bad));
}

/// An FS-trace circuit proven end-to-end: the trace replays a lane-challenger
/// transcript (labels, observes, samples, PoW) and pins the sampled
/// challenges to the natively derived values — the killshot-slot pattern in
/// miniature.
#[test]
fn fs_trace_circuit_roundtrip() {
    use noid_ivc_core::challenger::Challenger;

    // Native transcript.
    let mut native = FsLaneChallenger::new(b"mini-killshot");
    native.observe_label(b"round-1");
    let msg = [
        F128 { lo: 7, hi: 1 },
        F128 {
            lo: 0xdead,
            hi: 0xbeef,
        },
    ];
    native.observe_f128_slice(&msg);
    let c1 = native.sample_f128();
    native.observe_f128(c1 * c1); // a fake "prover response"
    let nonce = native.grind_pow(6);
    let c2s = native.sample_f128_vec(2);

    // Trace circuit.
    let mut b = FieldR1csBuilder::new();
    let mut trace = FsChannelTrace::new(&mut b, b"mini-killshot");
    trace.observe_label(&mut b, b"round-1");
    let msg_exprs: Vec<LinExpr> = msg
        .iter()
        .map(|&v| LinExpr::from_wire(b.alloc_f128(v)))
        .collect();
    trace.observe_f128_slice(&mut b, &msg_exprs);
    let c1_expr = trace.sample_f128(&mut b);
    // Replay the algebra on the sampled challenge (c1²) — one mul.
    let c1_sq = LinExpr::from_wire(b.mul(&c1_expr, &c1_expr));
    trace.observe_f128(&mut b, &c1_sq);
    let nonce_expr = LinExpr::from_wire(b.alloc_f128(F128 { lo: nonce, hi: 0 }));
    trace.verify_pow_trace(&mut b, &nonce_expr, 6);
    let c2_exprs = trace.sample_f128_vec(&mut b, 2);
    // Pin the final challenges to the native values (the [B]-style public
    // binding of a real slot).
    for (e, c) in c2_exprs.iter().zip(c2s.iter()) {
        b.pin_f128(e, *c);
    }

    let (r1cs, z) = b.build();
    assert!(r1cs.satisfies(&z));

    let params = params_for(r1cs.m);
    let mut ch_p = FsLaneChallenger::new(DOMAIN);
    let (proof, commitment, _) = prove_field(&r1cs, &z, &params, &mut ch_p);
    let mut ch_v = FsLaneChallenger::new(DOMAIN);
    verify_field(&r1cs, &commitment, &proof, &mut ch_v)
        .expect("honest FS-trace circuit proof rejected");

    // Corrupting an absorbed message desynchronizes the replayed sponge —
    // the permutation rows were built for the honest value → unsatisfiable.
    let mut bad = z;
    bad[1] += F128::ONE; // wire 1 = msg[0] (first allocation after the const wire)
    assert!(!r1cs.satisfies(&bad));
}
