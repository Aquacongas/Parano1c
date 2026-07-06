//! The miniature [G] slot, end to end: the reference chain family's whole
//! claim DAG replayed IN-TRACE, its committed columns living as witness
//! slices, every terminal claim discharged through the REAL batched PCS
//! opening via public-IO — a complete FieldR1cs proof of the region-layer
//! pattern at family scale.
//!
//! Layout: each family column occupies a dyadic-aligned witness slice; the
//! IO slice carries every pending claim's (point, value) lanes, pinned
//! in-trace to the replayed sumcheck wires; the proof envelope exposes the
//! same lanes, and `prove/verify_field_with_public_io` turns them into
//! opening claims against the committed witness. A column lane the prover
//! flips after the fact makes exactly one opening claim false — the
//! BaseFold layer rejects it.

use noid_ivc_core::challenger::FsLaneChallenger;
use noid_ivc_core::deep_chain::family::{
    self, build_family, g0_terms, g1_terms, run_family, substitution_terms, FamilyProofs,
    W_LOG,
};
use noid_ivc_core::deep_chain::relations::{ColRef, RelationTerm};
use noid_ivc_core::field::F128;
use noid_ivc_core::field_circuit::{FieldR1csBuilder, FsChannelTrace, LinExpr};
use noid_ivc_core::pcs::{self, PcsParams};
use noid_ivc_core::public_io::{IoClaimSpec, PublicIoSpec, WitnessSlice};
use noid_poseidon2b::native::permutation::STATE_SIZE;
use noid_recursive::acceptance::trace::deep_chain::{
    verify_column_relation_trace, verify_deep_chain_walk_trace, verify_shift_discharge_trace,
    ColumnRelationProofTrace, DeepChainWalkProofTrace, LaneClaimGroupTrace, RelationTermTrace,
    ShiftDischargeProofTrace,
};

const FAMILY_DOMAIN: &[u8] = b"deep-chain-family";
const OUTER_DOMAIN: &[u8] = b"region-slot-e2e";

/// Align the builder to a dyadic boundary with zero filler wires and
/// allocate one column as a witness slice.
fn alloc_column_slice(
    b: &mut FieldR1csBuilder,
    col: &[F128],
    log2_len: usize,
) -> (WitnessSlice, Vec<LinExpr>) {
    let block = 1usize << log2_len;
    while b.num_wires() % block != 0 {
        b.alloc_f128(F128::ZERO);
    }
    let index = b.num_wires() / block;
    let wires: Vec<LinExpr> = col
        .iter()
        .map(|&v| LinExpr::from_wire(b.alloc_f128(v)))
        .collect();
    for _ in col.len()..block {
        b.alloc_f128(F128::ZERO);
    }
    (WitnessSlice { log2_len, index }, wires)
}

fn const_terms(terms: &[RelationTerm]) -> Vec<RelationTermTrace> {
    terms
        .iter()
        .map(|t| RelationTermTrace {
            coeff: LinExpr::constant(t.coeff),
            factors: t.factors.clone(),
        })
        .collect()
}

/// One pending claim, trace side: the target column, the derived-point
/// wires and the claimed-value wire.
struct PendingClaimTrace {
    col: usize,
    point: Vec<LinExpr>,
    value: LinExpr,
}

#[test]
fn region_slot_end_to_end() {
    // ---- Native family + proofs.
    let fam = build_family(0x9E10);
    let mut proofs = FamilyProofs::default();
    let mut ch_native = FsLaneChallenger::new(FAMILY_DOMAIN);
    let native_pending =
        run_family(&fam, true, &mut ch_native, &mut proofs).expect("native family proves");

    // ---- Trace circuit: columns as slices, then the DAG twins.
    let mut b = FieldR1csBuilder::new();
    let mut slices = Vec::new();
    for col in &fam.committed {
        slices.push(alloc_column_slice(&mut b, col, W_LOG));
    }

    let mut ch = FsChannelTrace::new(&mut b, FAMILY_DOMAIN);
    let mut pending: Vec<PendingClaimTrace> = Vec::new();

    // Booleanity of D.
    let bool_terms = vec![
        RelationTerm {
            coeff: F128::ONE,
            factors: vec![ColRef::Committed(family::D), ColRef::Committed(family::D)],
        },
        RelationTerm {
            coeff: F128::ONE,
            factors: vec![ColRef::Committed(family::D)],
        },
    ];
    let rho = ch.sample_f128_vec(&mut b, W_LOG);
    let proof_e = ColumnRelationProofTrace::alloc(
        &mut b,
        proofs.booleanity.as_ref().expect("booleanity proof"),
        W_LOG,
        1,
    );
    let zero = LinExpr::zero();
    let point = verify_column_relation_trace(
        &mut b,
        &mut ch,
        W_LOG,
        &zero,
        &rho,
        &const_terms(&bool_terms),
        &[],
        &proof_e,
    );
    pending.push(PendingClaimTrace {
        col: family::D,
        point: point.clone(),
        value: proof_e.final_values[0].clone(),
    });

    // Selector-consistency for G0/G1 (claims on every committed ref).
    for (terms, proof) in [
        (g0_terms(), proofs.g0.as_ref().expect("g0")),
        (g1_terms(), proofs.g1.as_ref().expect("g1")),
    ] {
        let refs = noid_ivc_core::deep_chain::relations::distinct_refs(&terms);
        let rho = ch.sample_f128_vec(&mut b, W_LOG);
        let proof_e = ColumnRelationProofTrace::alloc(&mut b, proof, W_LOG, refs.len());
        let point = verify_column_relation_trace(
            &mut b,
            &mut ch,
            W_LOG,
            &zero,
            &rho,
            &const_terms(&terms),
            &[],
        &proof_e,
        );
        for (r, v) in refs.iter().zip(proof_e.final_values.iter()) {
            if let ColRef::Committed(c) = r {
                pending.push(PendingClaimTrace {
                    col: *c,
                    point: point.clone(),
                    value: v.clone(),
                });
            }
        }
    }

    // Selection: C = S_out lane 0.
    let sel_terms = vec![
        RelationTerm {
            coeff: F128::ONE,
            factors: vec![ColRef::Committed(family::C)],
        },
        RelationTerm {
            coeff: F128::ONE,
            factors: vec![ColRef::Internal(0)],
        },
    ];
    let rho_sel = ch.sample_f128_vec(&mut b, W_LOG);
    let sel_proof_e = ColumnRelationProofTrace::alloc(
        &mut b,
        proofs.selection.as_ref().expect("selection"),
        W_LOG,
        2,
    );
    let sel_point = verify_column_relation_trace(
        &mut b,
        &mut ch,
        W_LOG,
        &zero,
        &rho_sel,
        &const_terms(&sel_terms),
        &[],
        &sel_proof_e,
    );
    pending.push(PendingClaimTrace {
        col: family::C,
        point: sel_point.clone(),
        value: sel_proof_e.final_values[0].clone(),
    });

    // Output exposure: O = END·S_out lane 0.
    let out_terms = vec![
        RelationTerm {
            coeff: F128::ONE,
            factors: vec![ColRef::Committed(family::O)],
        },
        RelationTerm {
            coeff: F128::ONE,
            factors: vec![ColRef::Committed(family::END), ColRef::Internal(0)],
        },
    ];
    let rho_out = ch.sample_f128_vec(&mut b, W_LOG);
    let out_proof_e = ColumnRelationProofTrace::alloc(
        &mut b,
        proofs.output.as_ref().expect("output"),
        W_LOG,
        3,
    );
    let out_point = verify_column_relation_trace(
        &mut b,
        &mut ch,
        W_LOG,
        &zero,
        &rho_out,
        &const_terms(&out_terms),
        &[],
        &out_proof_e,
    );
    let out_refs = noid_ivc_core::deep_chain::relations::distinct_refs(&out_terms);
    for (r, v) in out_refs.iter().zip(out_proof_e.final_values.iter()) {
        if let ColRef::Committed(c) = r {
            pending.push(PendingClaimTrace {
                col: *c,
                point: out_point.clone(),
                value: v.clone(),
            });
        }
    }

    // The walk: groups tie lane 0 to the relations' internal claims; lanes
    // 1..3 are prover-supplied witness (from the recorded native groups).
    let native_groups = proofs.walk_groups.as_ref().expect("groups");
    let mut groups_e = Vec::new();
    for (gi, (point_e, lane0)) in [
        (sel_point.clone(), sel_proof_e.final_values[1].clone()),
        (out_point.clone(), out_proof_e.final_values[2].clone()),
    ]
    .into_iter()
    .enumerate()
    {
        let values: [LinExpr; STATE_SIZE] = std::array::from_fn(|j| {
            if j == 0 {
                lane0.clone()
            } else {
                LinExpr::from_wire(b.alloc_f128(native_groups[gi].values[j]))
            }
        });
        groups_e.push(LaneClaimGroupTrace {
            point: point_e,
            values,
        });
    }
    let walk_e =
        DeepChainWalkProofTrace::alloc(&mut b, proofs.walk.as_ref().expect("walk"), W_LOG);
    let terminal = verify_deep_chain_walk_trace(&mut b, &mut ch, W_LOG, &groups_e, &walk_e);

    // Substitution at the walk terminal (challenge-derived coefficients).
    let alpha = ch.sample_f128(&mut b);
    let native_sub_terms = substitution_terms(F128::ONE); // structure only
    let mut alpha_pow = LinExpr::constant(F128::ONE);
    let mut target = LinExpr::zero();
    let mut alpha_powers = Vec::with_capacity(STATE_SIZE);
    for e in 0..STATE_SIZE {
        alpha_pow = noid_recursive::acceptance::trace::mul(&mut b, &alpha_pow, &alpha);
        alpha_powers.push(alpha_pow.clone());
        target = target.add(&noid_recursive::acceptance::trace::mul(
            &mut b,
            &alpha_pow,
            &terminal.values[e],
        ));
    }
    // m_j = Σ_e α^{e+1}·MDS_FULL[e][j] — affine in the α-power wires.
    let mds = noid_ivc_core::deep_chain::flat_mds(true);
    let m: Vec<LinExpr> = (0..STATE_SIZE)
        .map(|j| {
            let mut acc = LinExpr::zero();
            for (e, p) in alpha_powers.iter().enumerate() {
                acc = acc.add(&p.scale(mds[e][j]));
            }
            acc
        })
        .collect();
    // The native term order of substitution_terms: lane-0 terms (START·A0,
    // G0·C', G1·SIB) then lane-1 terms (START·A1, G1·C', G0·SIB).
    let sub_terms_e: Vec<RelationTermTrace> = native_sub_terms
        .iter()
        .enumerate()
        .map(|(i, t)| RelationTermTrace {
            coeff: m[i / 3].clone(),
            factors: t.factors.clone(),
        })
        .collect();
    let sub_refs = noid_ivc_core::deep_chain::relations::distinct_refs(&native_sub_terms);
    let sub_proof_e = ColumnRelationProofTrace::alloc(
        &mut b,
        proofs.substitution.as_ref().expect("substitution"),
        W_LOG,
        sub_refs.len(),
    );
    let sub_point = verify_column_relation_trace(
        &mut b,
        &mut ch,
        W_LOG,
        &target,
        &terminal.point,
        &sub_terms_e,
        &[],
        &sub_proof_e,
    );
    let mut shift_target = None;
    for (r, v) in sub_refs.iter().zip(sub_proof_e.final_values.iter()) {
        match r {
            ColRef::Committed(c) => pending.push(PendingClaimTrace {
                col: *c,
                point: sub_point.clone(),
                value: v.clone(),
            }),
            ColRef::CommittedShift(_) => shift_target = Some(v.clone()),
            ColRef::Internal(_)
            | ColRef::Fixed(_)
            | ColRef::CommittedShift2(_)
            | ColRef::Window { .. } => unreachable!(),
        }
    }

    // Shift discharge for the carry column.
    let shift_e = ShiftDischargeProofTrace::alloc(
        &mut b,
        proofs.shift.as_ref().expect("shift"),
        W_LOG,
    );
    let shift_point = verify_shift_discharge_trace(
        &mut b,
        &mut ch,
        W_LOG,
        &sub_point,
        &shift_target.expect("wiring references the carry shift"),
        0,
        &shift_e,
    );
    pending.push(PendingClaimTrace {
        col: family::C,
        point: shift_point,
        value: shift_e.final_value.clone(),
    });

    // ---- IO slice: (point ‖ value) lanes per pending claim, pinned to the
    // replayed wires; the spec derives one opening claim per entry.
    assert_eq!(pending.len(), native_pending.len(), "claim count lockstep");
    let lanes_per_claim = W_LOG + 1;
    let io_len = pending.len() * lanes_per_claim;
    let io_log = io_len.next_power_of_two().trailing_zeros() as usize;
    let mut io_values = Vec::with_capacity(io_len);
    for nc in &native_pending {
        io_values.extend_from_slice(&nc.point);
        io_values.push(nc.value);
    }
    let (io_slice, io_wires) = alloc_column_slice(&mut b, &io_values, io_log);
    for (ci, claim) in pending.iter().enumerate() {
        let base = ci * lanes_per_claim;
        for (k, p) in claim.point.iter().enumerate() {
            noid_recursive::acceptance::trace::pin_eq(&mut b, p, &io_wires[base + k]);
        }
        noid_recursive::acceptance::trace::pin_eq(
            &mut b,
            &claim.value,
            &io_wires[base + W_LOG],
        );
    }
    let spec = PublicIoSpec {
        io_slice,
        io_len,
        claims: pending
            .iter()
            .enumerate()
            .map(|(ci, claim)| IoClaimSpec {
                slice: slices[claim.col].0,
                point: ci * lanes_per_claim..ci * lanes_per_claim + W_LOG,
                value: ci * lanes_per_claim + W_LOG,
            })
            .collect(),
    };

    // ---- The real proof.
    let (r1cs, z) = b.build();
    assert!(r1cs.satisfies(&z), "honest region-slot trace unsatisfiable");
    let params = PcsParams {
        m: r1cs.m + pcs::LOG_PACKING,
        log_inv_rate: 2,
        log_batch_size: 2,
        profile: Default::default(),
    };
    let mut ch_p = FsLaneChallenger::new(OUTER_DOMAIN);
    let (proof, commitment, _) = noid_ivc_prover::field_prover::prove_field_with_public_io(
        &r1cs, &z, &params, &spec, &io_values, &mut ch_p,
    );
    let mut ch_v = FsLaneChallenger::new(OUTER_DOMAIN);
    noid_ivc_core::verifier::verify_field_with_public_io(
        &r1cs,
        &commitment,
        &proof,
        &spec,
        &io_values,
        &mut ch_v,
    )
    .expect("the region slot proof verifies");

    eprintln!(
        "[region-slot] rows = {} (m = {}), opening claims = {}",
        z.len(),
        r1cs.m,
        2 + 1 + spec.claims.len()
    );

    // ---- The money negative: flip ONE carry-column lane in the committed
    // witness. The trace stays satisfiable (columns are free wires) and the
    // envelope is unchanged, but the opening claim against the flipped
    // column is now FALSE — the PCS layer must reject.
    let mut bad_z = z.clone();
    let carry_slice = slices[family::C].0;
    bad_z[carry_slice.start() + 3] += F128::ONE;
    assert!(r1cs.satisfies(&bad_z), "columns are free wires");
    let mut ch_p = FsLaneChallenger::new(OUTER_DOMAIN);
    let (bad_proof, bad_commitment, _) = noid_ivc_prover::field_prover::prove_field_with_public_io(
        &r1cs, &bad_z, &params, &spec, &io_values, &mut ch_p,
    );
    let mut ch_v = FsLaneChallenger::new(OUTER_DOMAIN);
    assert!(
        noid_ivc_core::verifier::verify_field_with_public_io(
            &r1cs,
            &bad_commitment,
            &bad_proof,
            &spec,
            &io_values,
            &mut ch_v,
        )
        .is_err(),
        "a flipped committed column lane must break its opening claim"
    );
}
