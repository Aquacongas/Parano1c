//! Differential gate for the disconnected ZK authorization transcript.
//!
//! Owner is closed natively with `Poseidon2bWideChannel::close_into_bridge`; the
//! same transcript is replayed by the recursive duplex columns and its final
//! `C0..C3` cells must be that exact bridge.  Main then absorbs those four
//! derived lanes followed by `sigma`, and both implementations must expose the
//! same challenge stream.

use noid_core::{Block128, Block256};
use noid_ivc_core::deep_chain::schedule::{
    build_duplex_columns, flat_of_tower_u128, DuplexColumns, TranscriptOp,
};
use noid_ivc_core::field::{F128, F256};
use noid_poseidon2b::channel::Poseidon2bWideChannel;
use noid_poseidon2b::native::domain::{capacity_iv, TAG_KSCH256};
use noid_recursive::acceptance::zk_auth_capsule_schedule::{
    ZkAuthCapsuleDuplexSchedules, ZK_AUTH_BRIDGE_LANES, ZK_AUTH_MAIN_ALGEBRAIC_SQUEEZES,
    ZK_AUTH_MAIN_COMPILED_SLOTS, ZK_AUTH_MAIN_DYNAMIC_LANES, ZK_AUTH_MAIN_FROM_OWNER_TAG,
    ZK_AUTH_MAIN_SIGMA_DATA_INDEX, ZK_AUTH_OWNER_BRIDGE_SLOT, ZK_AUTH_OWNER_COMPILED_SLOTS,
    ZK_AUTH_OWNER_DYNAMIC_LANES, ZK_AUTH_OWNER_SQUEEZES, ZK_AUTH_OWNER_TO_MAIN_CLOSE_TAG,
    ZK_AUTH_SOURCE_CAP_LANES, ZK_AUTH_TERMINAL_FIELDS,
};

const OWNER_PUBLIC_STATEMENT_LANES: usize = 4;
const OWNER_SOURCE_CAP_DATA_START: usize = OWNER_PUBLIC_STATEMENT_LANES;
const OWNER_TERMINAL_DATA_START: usize = ZK_AUTH_OWNER_DYNAMIC_LANES - ZK_AUTH_TERMINAL_FIELDS;

fn ksch256_iv_flat() -> [F128; 2] {
    let iv = capacity_iv(TAG_KSCH256);
    [flat_of_tower_u128(iv[0].0), flat_of_tower_u128(iv[1].0)]
}

fn flat_data(data: &[Block128]) -> Vec<F128> {
    data.iter()
        .map(|value| flat_of_tower_u128(value.0))
        .collect()
}

fn deterministic_data(len: usize, domain: u128) -> Vec<Block128> {
    (0..len)
        .map(|i| {
            let i = i as u128 + 1;
            Block128::from(domain ^ i.wrapping_mul(0x9E37_79B9_7F4A_7C15))
        })
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
struct NativeChallengeStream {
    algebraic: Vec<Block256>,
    base: Vec<Block128>,
}

/// Replay the production mixed-width transcript. The first
/// `algebraic_squeezes` consume complete rate blocks as C1 challenges; any
/// remaining raw lanes are the grind output and packed query seeds.
fn drive_channel(
    ops: &[TranscriptOp],
    data: &[Block128],
    algebraic_squeezes: usize,
) -> NativeChallengeStream {
    let mut channel = Poseidon2bWideChannel::new();
    let mut cursor = 0usize;
    let mut remaining_algebraic = algebraic_squeezes;
    let mut algebraic = Vec::with_capacity(algebraic_squeezes);
    let mut base = Vec::new();
    for op in ops {
        match op {
            TranscriptOp::Absorb(lanes) => {
                for lane in lanes {
                    let value = match lane {
                        Some(constant) => Block128::from(*constant),
                        None => {
                            let value = data[cursor];
                            cursor += 1;
                            value
                        }
                    };
                    channel.absorb_base(value);
                }
            }
            TranscriptOp::Squeeze(count) => {
                if remaining_algebraic != 0 {
                    assert_eq!(count % 2, 0, "wide squeeze consumes two raw lanes");
                    let wide = count / 2;
                    assert!(wide <= remaining_algebraic);
                    algebraic.extend((0..wide).map(|_| channel.squeeze_wide()));
                    remaining_algebraic -= wide;
                } else {
                    base.extend((0..*count).map(|_| channel.squeeze_base()));
                }
            }
        }
    }
    assert_eq!(cursor, data.len(), "native replay consumed every data lane");
    assert_eq!(remaining_algebraic, 0);
    NativeChallengeStream { algebraic, base }
}

/// Replay Owner up to (but not including) its fixed final close block, then
/// invoke the production consuming bridge API for that block.
fn close_owner_natively(
    ops: &[TranscriptOp],
    data: &[Block128],
) -> ([Block128; 4], NativeChallengeStream) {
    let (close, prefix) = ops.split_last().expect("Owner schedule is non-empty");
    assert_eq!(
        close,
        &TranscriptOp::Absorb(vec![Some(ZK_AUTH_OWNER_TO_MAIN_CLOSE_TAG), Some(0),]),
        "the last Owner operation is the unique full close block"
    );

    let mut channel = Poseidon2bWideChannel::new();
    let mut cursor = 0usize;
    let mut challenges = Vec::with_capacity(ZK_AUTH_OWNER_SQUEEZES);
    for op in prefix {
        match op {
            TranscriptOp::Absorb(lanes) => {
                for lane in lanes {
                    let value = match lane {
                        Some(constant) => Block128::from(*constant),
                        None => {
                            let value = data[cursor];
                            cursor += 1;
                            value
                        }
                    };
                    channel.absorb_base(value);
                }
            }
            TranscriptOp::Squeeze(count) => {
                assert_eq!(count % 2, 0, "Owner has only wide challenges");
                challenges.extend((0..count / 2).map(|_| channel.squeeze_wide()));
            }
        }
    }
    assert_eq!(cursor, data.len(), "Owner replay consumed every data lane");
    assert_eq!(challenges.len(), ZK_AUTH_OWNER_SQUEEZES);
    (
        channel.close_into_bridge(Block128::from(ZK_AUTH_OWNER_TO_MAIN_CLOSE_TAG)),
        NativeChallengeStream {
            algebraic: challenges,
            base: Vec::new(),
        },
    )
}

fn assert_native_challenges_match_columns(native: &NativeChallengeStream, columns: &DuplexColumns) {
    let wide_raw_lanes = 2 * native.algebraic.len();
    assert_eq!(wide_raw_lanes + native.base.len(), columns.challenges.len());
    for (index, (tower, raw)) in native
        .algebraic
        .iter()
        .zip(columns.challenges[..wide_raw_lanes].chunks_exact(2))
        .enumerate()
    {
        assert_eq!(
            F256::from_tower(*tower),
            F256::from_raw_challenge_lanes(raw[0], raw[1]),
            "native/recursive algebraic challenge {index} diverged"
        );
    }
    for (index, (tower, flat)) in native
        .base
        .iter()
        .zip(&columns.challenges[wide_raw_lanes..])
        .enumerate()
    {
        assert_eq!(
            flat_of_tower_u128(tower.0),
            *flat,
            "native/recursive base challenge {index} diverged"
        );
    }
}

struct SplitRun {
    bridge: [Block128; 4],
    main_data: Vec<Block128>,
    main_native_challenges: NativeChallengeStream,
    main_columns: DuplexColumns,
}

fn run_split(owner_data: &[Block128], main_proof_data: &[Block128]) -> SplitRun {
    let schedules = ZkAuthCapsuleDuplexSchedules::selected();
    let owner_layout = schedules.owner_layout();
    let main_layout = schedules.main_layout();

    let (bridge, owner_native_challenges) = close_owner_natively(&schedules.owner_ops, owner_data);
    let owner_columns = build_duplex_columns(
        &owner_layout,
        ksch256_iv_flat(),
        &flat_data(owner_data),
        owner_layout
            .slots
            .len()
            .next_power_of_two()
            .trailing_zeros() as usize,
    );
    assert_native_challenges_match_columns(&owner_native_challenges, &owner_columns);
    assert_eq!(owner_layout.slots.len(), ZK_AUTH_OWNER_COMPILED_SLOTS);
    for lane in 0..ZK_AUTH_BRIDGE_LANES {
        assert_eq!(
            flat_of_tower_u128(bridge[lane].0),
            owner_columns.c[lane][ZK_AUTH_OWNER_BRIDGE_SLOT],
            "Owner bridge lane C{lane} diverged"
        );
    }

    assert_eq!(
        main_proof_data.len(),
        ZK_AUTH_MAIN_DYNAMIC_LANES - ZK_AUTH_BRIDGE_LANES
    );
    let mut main_data = Vec::with_capacity(ZK_AUTH_MAIN_DYNAMIC_LANES);
    main_data.extend_from_slice(&bridge);
    main_data.extend_from_slice(main_proof_data);
    assert_eq!(main_data.len(), ZK_AUTH_MAIN_DYNAMIC_LANES);

    let main_native_challenges = drive_channel(
        &schedules.main_ops,
        &main_data,
        ZK_AUTH_MAIN_ALGEBRAIC_SQUEEZES,
    );
    let main_columns = build_duplex_columns(
        &main_layout,
        ksch256_iv_flat(),
        &flat_data(&main_data),
        main_layout.slots.len().next_power_of_two().trailing_zeros() as usize,
    );
    assert_native_challenges_match_columns(&main_native_challenges, &main_columns);
    assert_eq!(main_layout.slots.len(), ZK_AUTH_MAIN_COMPILED_SLOTS);

    SplitRun {
        bridge,
        main_data,
        main_native_challenges,
        main_columns,
    }
}

fn assert_downstream_changed(baseline: &SplitRun, changed: &SplitRun, cause: &str) {
    assert_ne!(
        baseline.main_native_challenges.algebraic[0], changed.main_native_challenges.algebraic[0],
        "{cause} did not change gamma"
    );
    assert_ne!(
        baseline.main_native_challenges.base.last(),
        changed.main_native_challenges.base.last(),
        "{cause} did not change the final Main query seed"
    );
    assert_ne!(
        baseline.main_native_challenges, changed.main_native_challenges,
        "{cause} left the native Main challenge stream unchanged"
    );
    assert_ne!(
        baseline.main_columns.challenges, changed.main_columns.challenges,
        "{cause} left the recursive Main challenge stream unchanged"
    );
}

#[test]
fn split_owner_bridge_matches_recursive_columns_and_binds_main() {
    assert_eq!(
        OWNER_SOURCE_CAP_DATA_START + ZK_AUTH_SOURCE_CAP_LANES,
        20,
        "source-cap data range is pinned"
    );
    assert_eq!(OWNER_TERMINAL_DATA_START, 248, "terminal claims are pinned");

    let owner_data = deterministic_data(ZK_AUTH_OWNER_DYNAMIC_LANES, 0x0A11_CE00_0000_0001);
    // Main proof data begins with sigma.  The bridge is derived and therefore
    // deliberately absent from this proof-carried vector.
    let main_proof_data = deterministic_data(
        ZK_AUTH_MAIN_DYNAMIC_LANES - ZK_AUTH_BRIDGE_LANES,
        0x0A11_CE00_0000_0002,
    );
    let baseline = run_split(&owner_data, &main_proof_data);

    // Exact Main prefix placement in both the dynamic data stream and the
    // materialized absorb columns: tag, bridge[0..4), then sigma.
    assert_eq!(
        &baseline.main_data[..ZK_AUTH_BRIDGE_LANES],
        &baseline.bridge
    );
    assert_eq!(ZK_AUTH_MAIN_SIGMA_DATA_INDEX, ZK_AUTH_BRIDGE_LANES);
    assert_eq!(
        baseline.main_data[ZK_AUTH_MAIN_SIGMA_DATA_INDEX],
        main_proof_data[0]
    );
    assert_eq!(
        baseline.main_columns.a[0][0],
        F128::ZERO,
        "Main slot 0 lane 0 is the fixed Main tag"
    );
    assert_eq!(
        baseline.main_columns.a[1][0],
        flat_of_tower_u128(baseline.bridge[0].0)
    );
    assert_eq!(
        baseline.main_columns.a[0][1],
        flat_of_tower_u128(baseline.bridge[1].0)
    );
    assert_eq!(
        baseline.main_columns.a[1][1],
        flat_of_tower_u128(baseline.bridge[2].0)
    );
    assert_eq!(
        baseline.main_columns.a[0][2],
        flat_of_tower_u128(baseline.bridge[3].0)
    );
    assert_eq!(
        baseline.main_columns.a[1][2],
        flat_of_tower_u128(main_proof_data[0].0)
    );
    assert_eq!(ZK_AUTH_MAIN_FROM_OWNER_TAG, 0x5A4B_AA10_0000_0001);

    // A source-cap mutation occurs before all Owner challenges and must cross
    // the four-lane bridge into Main.
    let mut bad_cap = owner_data.clone();
    bad_cap[OWNER_SOURCE_CAP_DATA_START] += Block128::from(1u128);
    let cap_run = run_split(&bad_cap, &main_proof_data);
    assert_ne!(baseline.bridge, cap_run.bridge);
    assert_downstream_changed(&baseline, &cap_run, "Owner source-cap mutation");

    // Terminal claims are absorbed before eta and before the close block.
    let mut bad_claim = owner_data.clone();
    bad_claim[OWNER_TERMINAL_DATA_START] += Block128::from(1u128);
    let claim_run = run_split(&bad_claim, &main_proof_data);
    assert_ne!(baseline.bridge, claim_run.bridge);
    assert_downstream_changed(&baseline, &claim_run, "Owner terminal-claim mutation");

    // A direct bridge-wire corruption is also caught by the Main transcript;
    // replay both native and recursive implementations on the same bad wire.
    let schedules = ZkAuthCapsuleDuplexSchedules::selected();
    let mut bad_bridge_data = baseline.main_data.clone();
    bad_bridge_data[2] += Block128::from(1u128);
    let bad_bridge_native = drive_channel(
        &schedules.main_ops,
        &bad_bridge_data,
        ZK_AUTH_MAIN_ALGEBRAIC_SQUEEZES,
    );
    let bad_bridge_columns = build_duplex_columns(
        &schedules.main_layout(),
        ksch256_iv_flat(),
        &flat_data(&bad_bridge_data),
        ZK_AUTH_MAIN_COMPILED_SLOTS
            .next_power_of_two()
            .trailing_zeros() as usize,
    );
    assert_native_challenges_match_columns(&bad_bridge_native, &bad_bridge_columns);
    assert_ne!(
        baseline.main_native_challenges.algebraic[0],
        bad_bridge_native.algebraic[0]
    );
    assert_ne!(
        baseline.main_native_challenges.base.last(),
        bad_bridge_native.base.last()
    );
    assert_ne!(
        baseline.main_columns.challenges,
        bad_bridge_columns.challenges
    );
}
