//! End-to-end deep-chain family gates over the reference family
//! (`noid_ivc_core::deep_chain::family`) — see the module docs there.

use noid_ivc_core::challenger::{Challenger, FsLaneChallenger};
use noid_ivc_core::deep_chain::family::{
    build_family, discharge, run_family, FamilyProofs, C, D, G0, O, SIB,
};
use noid_ivc_core::field::F128;

#[test]
fn honest_family_end_to_end() {
    let fam = build_family(0xFA111);
    let mut proofs = FamilyProofs::default();

    let mut ch_p = FsLaneChallenger::new(b"deep-chain-family");
    let pending_p =
        run_family(&fam, true, &mut ch_p, &mut proofs).expect("prover side never fails");
    discharge(&fam, &pending_p).expect("prover-side claims true");

    let mut ch_v = FsLaneChallenger::new(b"deep-chain-family");
    let pending_v = run_family(&fam, false, &mut ch_v, &mut proofs).expect("honest family verifies");
    discharge(&fam, &pending_v).expect("verifier-side claims true");

    assert_eq!(ch_p.sample_f128(), ch_v.sample_f128(), "transcript lockstep");
}

/// Corrupt each committed column in turn (one slot), regenerate the proof
/// honestly OVER THE CORRUPTED DATA, and check the protocol catches it:
/// either a relation rejects outright or a discharged claim is false
/// against the HONEST columns' commitment. This simulates a cheating
/// prover whose region/carry columns disagree with the real chains.
#[test]
fn corrupted_columns_rejected() {
    let honest = build_family(0xFA22);

    for col in [C, O, D, SIB, G0] {
        let mut bad = build_family(0xFA22);
        bad.committed[col][5] += F128::ONE;

        let mut proofs = FamilyProofs::default();
        let mut ch_p = FsLaneChallenger::new(b"deep-chain-family");
        let Ok(_) = run_family(&bad, true, &mut ch_p, &mut proofs) else {
            continue; // prover-side assert tripped — also a catch
        };

        let mut ch_v = FsLaneChallenger::new(b"deep-chain-family");
        let caught = match run_family(&bad, false, &mut ch_v, &mut proofs) {
            Err(_) => true,
            // The verifier's claims discharge against the HONEST columns
            // (the commitment binds those), so corruption must surface.
            Ok(pending) => discharge(&honest, &pending).is_err(),
        };
        assert!(caught, "corrupted column {col} slipped through");
    }
}

/// A lying walk start group (forged lane-1..3 values) must end in a false
/// terminal claim against the committed wiring.
#[test]
fn forged_walk_lane_values_rejected() {
    let fam = build_family(0xFA33);
    let mut proofs = FamilyProofs::default();
    let mut ch_p = FsLaneChallenger::new(b"deep-chain-family");
    run_family(&fam, true, &mut ch_p, &mut proofs).expect("prove");

    // Forge lane 2 of the first start group and re-run the verifier side.
    proofs
        .walk_groups
        .as_mut()
        .expect("groups recorded")[0]
        .values[2] += F128::ONE;
    let mut ch_v = FsLaneChallenger::new(b"deep-chain-family");
    let caught = match run_family(&fam, false, &mut ch_v, &mut proofs) {
        Err(_) => true,
        Ok(pending) => discharge(&fam, &pending).is_err(),
    };
    assert!(caught, "forged start-group lane value slipped through");
}
