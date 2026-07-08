// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Bench-only OwnerAuth accumulator laboratory.
//!
//! This benchmark preserves the current wallet-produced
//! `OwnerAuthProofKillShot` model. It measures one focused path: accumulate the
//! verifier-facing non-PCS authorization surface with a streaming binary-field
//! RLC kernel, while reporting the PCS opening payload as the remaining
//! production research target.
//!
//! This file is not consensus authority and does not implement a recursive
//! proof. It is a cost filter for the next production design.

use std::env;
use std::time::Duration;

use bench_prover::{
    fmt_bytes, fmt_ms, standard_fixture, standard_scenario, sweep_fixture, sweep_scenario,
    time_once,
};
use noid_core::mem_profile::{current_mem_snapshot, MemSnapshot};
use noid_core::transcript::FiatShamir;
use noid_core::{
    hardware::{clmul_gcm, flat_to_tower_u128, tower_to_flat_u128},
    Block128, TowerField,
};
use noid_gkr::{
    owner_auth_gkr_channel, prove_owner_auth_killshot, verify_owner_auth_killshot_with_claims,
    OwnerAuthCircuit, OwnerAuthProofKillShot, OwnerAuthPublicInputs, OwnerAuthVerifierClaims,
};
use noid_poseidon2b::channel::Poseidon2bChannel;

const DEFAULT_ACCUM_NS: &[usize] = &[1];
const DEFAULT_PARALLEL_CHUNK: usize = 4096;
const CORE_CLAIM_BYTES: usize = 6 * 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaseKind {
    Standard4x8,
    Sweep25x2,
}

impl CaseKind {
    fn label(self) -> &'static str {
        match self {
            Self::Standard4x8 => "Standard4x8",
            Self::Sweep25x2 => "Sweep25x2",
        }
    }
}

struct RealAuthFixture {
    public: OwnerAuthPublicInputs,
    proof: OwnerAuthProofKillShot,
}

#[derive(Debug, Clone, Copy)]
struct CoreAccumResult {
    digest: Block128,
    beta: Block128,
    absorbed_fields: usize,
}

#[derive(Debug, Default, Clone, Copy)]
struct PcsPayloadStats {
    commitment_bytes: usize,
    opening_bytes: usize,
    upper_evals: usize,
    h_evals: usize,
    source_symbols: usize,
    source_siblings: usize,
    mid_symbols: usize,
    mid_siblings: usize,
}

impl PcsPayloadStats {
    fn from_proof(proof: &OwnerAuthProofKillShot) -> Self {
        let opening = &proof.pcs.opening;
        Self {
            commitment_bytes: proof.pcs.commitment.cap.hashes.len() * 32,
            opening_bytes: opening.byte_len(),
            upper_evals: opening.upper_partial_evals.len(),
            h_evals: opening.h_evals.len(),
            source_symbols: opening.source_symbols.len(),
            source_siblings: opening.source_batch.siblings.len(),
            mid_symbols: opening.mid_symbols.len(),
            mid_siblings: opening.mid_batch.siblings.len(),
        }
    }


    fn add(self, other: Self) -> Self {
        Self {
            commitment_bytes: self.commitment_bytes + other.commitment_bytes,
            opening_bytes: self.opening_bytes + other.opening_bytes,
            upper_evals: self.upper_evals + other.upper_evals,
            h_evals: self.h_evals + other.h_evals,
            source_symbols: self.source_symbols + other.source_symbols,
            source_siblings: self.source_siblings + other.source_siblings,
            mid_symbols: self.mid_symbols + other.mid_symbols,
            mid_siblings: self.mid_siblings + other.mid_siblings,
        }
    }


    fn opening_payload_bytes(self) -> usize {
        self.opening_bytes
    }
}

trait FieldSink {
    fn absorb(&mut self, value: Block128);

    #[inline]
    fn absorb_usize(&mut self, value: usize) {
        self.absorb(Block128::from(value as u128));
    }

    #[inline]
    fn absorb_u32(&mut self, value: u32) {
        self.absorb(Block128::from(value as u128));
    }

    fn absorb_hash(&mut self, hash: &[u8; 32]) {
        let mut lo = [0u8; 16];
        let mut hi = [0u8; 16];
        lo.copy_from_slice(&hash[..16]);
        hi.copy_from_slice(&hash[16..]);
        self.absorb(Block128::from(u128::from_le_bytes(lo)));
        self.absorb(Block128::from(u128::from_le_bytes(hi)));
    }
}

struct TowerRlc {
    acc: Block128,
    power: Block128,
    beta: Block128,
    absorbed_fields: usize,
}

impl TowerRlc {
    fn new(beta: Block128) -> Self {
        Self {
            acc: Block128::ZERO,
            power: Block128::ONE,
            beta,
            absorbed_fields: 0,
        }
    }
}

impl FieldSink for TowerRlc {
    #[inline]
    fn absorb(&mut self, value: Block128) {
        self.acc += self.power * value;
        self.power *= self.beta;
        self.absorbed_fields += 1;
    }
}

struct ClmulRlc {
    acc_flat: u128,
    power_flat: u128,
    beta_flat: u128,
    absorbed_fields: usize,
}

impl ClmulRlc {
    fn new(beta: Block128) -> Self {
        Self {
            acc_flat: 0,
            power_flat: tower_to_flat_u128(Block128::ONE.to_u128()),
            beta_flat: tower_to_flat_u128(beta.to_u128()),
            absorbed_fields: 0,
        }
    }

    fn digest(&self) -> Block128 {
        Block128::from(flat_to_tower_u128(self.acc_flat))
    }
}

impl FieldSink for ClmulRlc {
    #[inline]
    fn absorb(&mut self, value: Block128) {
        self.acc_flat ^= clmul_gcm(self.power_flat, tower_to_flat_u128(value.to_u128()));
        self.power_flat = clmul_gcm(self.power_flat, self.beta_flat);
        self.absorbed_fields += 1;
    }
}

fn env_usize_list(name: &str, default: &[usize]) -> Vec<usize> {
    let Ok(value) = env::var(name) else {
        return default.to_vec();
    };
    let parsed = value
        .split(',')
        .filter_map(|part| part.trim().parse::<usize>().ok())
        .filter(|&n| (1..=255).contains(&n))
        .collect::<Vec<_>>();
    if parsed.is_empty() {
        default.to_vec()
    } else {
        parsed
    }
}

fn env_flag(name: &str) -> bool {
    env::var(name)
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn env_chunk() -> usize {
    env::var("NOID_O1_AUTH_ACCUM_CHUNK")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|&value| value > 0)
        .unwrap_or(DEFAULT_PARALLEL_CHUNK)
}

fn fmt_mem(snapshot: Option<MemSnapshot>) -> String {
    match snapshot {
        Some(snapshot) => format!("{:>7.1}M", snapshot.hwm_mb()),
        None => "      n/a".to_string(),
    }
}

fn duration_per_tx(duration: Duration, n: usize) -> Duration {
    Duration::from_secs_f64(duration.as_secs_f64() / n.max(1) as f64)
}

fn channel_absorb_hash(channel: &mut Poseidon2bChannel, hash: &[u8; 32]) {
    let mut lo = [0u8; 16];
    let mut hi = [0u8; 16];
    lo.copy_from_slice(&hash[..16]);
    hi.copy_from_slice(&hash[16..]);
    channel.absorb(Block128::from(u128::from_le_bytes(lo)));
    channel.absorb(Block128::from(u128::from_le_bytes(hi)));
}

fn absorb_public_to_channel(channel: &mut Poseidon2bChannel, public: &OwnerAuthPublicInputs) {
    channel.absorb(Block128::from(public.layout.owner_count as u128));
    channel.absorb(Block128::from(public.layout.live_slots as u128));
    channel.absorb(Block128::from(public.layout.slot_bits as u128));
    channel.absorb(Block128::from(public.layout.num_vars as u128));
    channel.absorb(Block128::from(public.layout.padded_slots as u128));
    channel.absorb(public.tx_body_hash[0]);
    channel.absorb(public.tx_body_hash[1]);
    channel.absorb(Block128::from(public.live_input_positions.len() as u128));
    for &position in &public.live_input_positions {
        channel.absorb(Block128::from(position as u128));
    }
    channel.absorb(Block128::from(public.live_slot_indices.len() as u128));
    for &slot in &public.live_slot_indices {
        channel.absorb(Block128::from(slot as u128));
    }
    channel.absorb(Block128::from(public.input_to_group.len() as u128));
    for &group in &public.input_to_group {
        channel.absorb(Block128::from(group as u128));
    }
    channel.absorb(Block128::from(public.expected_address.len() as u128));
    for address in &public.expected_address {
        channel.absorb(address[0]);
        channel.absorb(address[1]);
    }
}

fn absorb_pcs_commitment_to_channel(
    channel: &mut Poseidon2bChannel,
    proof: &OwnerAuthProofKillShot,
) {
    let commitment = &proof.pcs.commitment;
    channel.absorb(Block128::from(commitment.log_rows as u128));
    channel.absorb(Block128::from(commitment.cap.hashes.len() as u128));
    for hash in &commitment.cap.hashes {
        channel_absorb_hash(channel, hash);
    }
}

fn derive_accumulation_beta(fixtures: &[RealAuthFixture]) -> Block128 {
    let mut channel = Poseidon2bChannel::new();
    channel.absorb(Block128::from(0xA07D_ACC0_0000_1001u128));
    channel.absorb(Block128::from(fixtures.len() as u128));
    for (index, fixture) in fixtures.iter().enumerate() {
        channel.absorb(Block128::from(index as u128));
        absorb_public_to_channel(&mut channel, &fixture.public);
        absorb_pcs_commitment_to_channel(&mut channel, &fixture.proof);
    }
    let beta = channel.squeeze();
    if beta == Block128::ZERO {
        Block128::ONE
    } else {
        beta
    }
}

fn absorb_public_fields<S: FieldSink>(sink: &mut S, index: usize, public: &OwnerAuthPublicInputs) {
    sink.absorb_usize(index);
    sink.absorb_usize(public.layout.owner_count);
    sink.absorb_usize(public.layout.live_slots);
    sink.absorb_usize(public.layout.slot_bits);
    sink.absorb_usize(public.layout.num_vars);
    sink.absorb_usize(public.layout.padded_slots);
    sink.absorb(public.tx_body_hash[0]);
    sink.absorb(public.tx_body_hash[1]);
    sink.absorb_usize(public.live_input_positions.len());
    for &position in &public.live_input_positions {
        sink.absorb_usize(position);
    }
    sink.absorb_usize(public.live_slot_indices.len());
    for &slot in &public.live_slot_indices {
        sink.absorb_u32(slot);
    }
    sink.absorb_usize(public.input_to_group.len());
    for &group in &public.input_to_group {
        sink.absorb_usize(group);
    }
    sink.absorb_usize(public.expected_address.len());
    for address in &public.expected_address {
        sink.absorb(address[0]);
        sink.absorb(address[1]);
    }
}

fn absorb_gkr_proof_fields<S: FieldSink>(sink: &mut S, proof: &OwnerAuthProofKillShot) {
    sink.absorb_usize(proof.kill_shot.main.round_polys.len());
    for poly in &proof.kill_shot.main.round_polys {
        sink.absorb_usize(poly.coeffs_no_linear.len());
        for &coeff in &poly.coeffs_no_linear {
            sink.absorb(coeff);
        }
    }
    sink.absorb(proof.kill_shot.main.state_at_r);
    for &value in &proof.kill_shot.main.state_lane_dec_at_r {
        sink.absorb(value);
    }

    sink.absorb_usize(proof.kill_shot.shift.round_polys.len());
    for round in &proof.kill_shot.shift.round_polys {
        for &eval in &round.evals_at_1_2 {
            sink.absorb(eval);
        }
    }
    sink.absorb(proof.kill_shot.shift.state_at_r2);

    sink.absorb_usize(proof.boundary.round_polys.len());
    for round in &proof.boundary.round_polys {
        for &eval in &round.evals_at_1_2 {
            sink.absorb(eval);
        }
    }
    sink.absorb(proof.boundary.state_at_r);

    sink.absorb_usize(proof.batch.rounds.len());
    for round in &proof.batch.rounds {
        for &eval in &round.evals_at_1_2 {
            sink.absorb(eval);
        }
    }
    sink.absorb(proof.batch.b_final);
}

fn absorb_pcs_commitment_fields<S: FieldSink>(sink: &mut S, proof: &OwnerAuthProofKillShot) {
    let commitment = &proof.pcs.commitment;
    sink.absorb_usize(commitment.log_rows);
    sink.absorb_usize(commitment.cap.hashes.len());
    for hash in &commitment.cap.hashes {
        sink.absorb_hash(hash);
    }
}

fn absorb_pcs_opening_witness_fields<S: FieldSink>(sink: &mut S, proof: &OwnerAuthProofKillShot) {
    let opening = &proof.pcs.opening;
    sink.absorb(opening.value);
    sink.absorb_usize(opening.upper_partial_evals.len());
    for &value in &opening.upper_partial_evals {
        sink.absorb(value);
    }
    sink.absorb_usize(opening.h_evals.len());
    for &value in &opening.h_evals {
        sink.absorb(value);
    }
    sink.absorb_hash(&opening.mid_root);
    sink.absorb(Block128::from(opening.grind_nonce as u128));
    sink.absorb_usize(opening.source_symbols.len());
    for &value in &opening.source_symbols {
        sink.absorb(value);
    }
    sink.absorb_usize(opening.source_batch.siblings.len());
    for sibling in &opening.source_batch.siblings {
        sink.absorb_hash(sibling);
    }
    sink.absorb_usize(opening.mid_symbols.len());
    for &value in &opening.mid_symbols {
        sink.absorb(value);
    }
    sink.absorb_usize(opening.mid_batch.siblings.len());
    for sibling in &opening.mid_batch.siblings {
        sink.absorb_hash(sibling);
    }
}

fn absorb_claim_fields<S: FieldSink>(sink: &mut S, claims: &OwnerAuthVerifierClaims) {
    sink.absorb_usize(claims.main.r_prime.len());
    for &value in &claims.main.r_prime {
        sink.absorb(value);
    }
    sink.absorb(claims.main.state_at_r);
    for &value in &claims.main.state_lane_dec_at_r {
        sink.absorb(value);
    }

    sink.absorb_usize(claims.shift.r_double_prime.len());
    for &value in &claims.shift.r_double_prime {
        sink.absorb(value);
    }
    sink.absorb(claims.shift.state_at_r2);

    sink.absorb_usize(claims.boundary.point.len());
    for &value in &claims.boundary.point {
        sink.absorb(value);
    }
    sink.absorb(claims.boundary.state_at_r);

    sink.absorb_usize(claims.state_claims.len());
    for claim in &claims.state_claims {
        sink.absorb_usize(claim.point.len());
        for &value in &claim.point {
            sink.absorb(value);
        }
        sink.absorb(claim.value);
    }

    sink.absorb_usize(claims.state.point.len());
    for &value in &claims.state.point {
        sink.absorb(value);
    }
    sink.absorb(claims.state.value);
}

fn absorb_core_fields<S: FieldSink>(
    sink: &mut S,
    fixtures: &[RealAuthFixture],
    claims: &[OwnerAuthVerifierClaims],
) {
    assert_eq!(fixtures.len(), claims.len());
    sink.absorb(Block128::from(0xA07D_ACC0_0000_1002u128));
    sink.absorb_usize(fixtures.len());
    for (index, (fixture, claim)) in fixtures.iter().zip(claims).enumerate() {
        absorb_public_fields(sink, index, &fixture.public);
        absorb_gkr_proof_fields(sink, &fixture.proof);
        absorb_pcs_commitment_fields(sink, &fixture.proof);
        absorb_claim_fields(sink, claim);
    }
}

fn absorb_full_witness_fields<S: FieldSink>(
    sink: &mut S,
    fixtures: &[RealAuthFixture],
    claims: &[OwnerAuthVerifierClaims],
) {
    absorb_core_fields(sink, fixtures, claims);
    sink.absorb(Block128::from(0xA07D_ACC0_0000_1003u128));
    for fixture in fixtures {
        absorb_pcs_opening_witness_fields(sink, &fixture.proof);
    }
}

fn accumulate_core_clmul(
    fixtures: &[RealAuthFixture],
    claims: &[OwnerAuthVerifierClaims],
) -> CoreAccumResult {
    let beta = derive_accumulation_beta(fixtures);
    let mut rlc = ClmulRlc::new(beta);
    absorb_core_fields(&mut rlc, fixtures, claims);
    CoreAccumResult {
        digest: rlc.digest(),
        beta,
        absorbed_fields: rlc.absorbed_fields,
    }
}

fn scan_full_witness_clmul(
    fixtures: &[RealAuthFixture],
    claims: &[OwnerAuthVerifierClaims],
) -> CoreAccumResult {
    let beta = derive_accumulation_beta(fixtures);
    let mut rlc = ClmulRlc::new(beta);
    absorb_full_witness_fields(&mut rlc, fixtures, claims);
    CoreAccumResult {
        digest: rlc.digest(),
        beta,
        absorbed_fields: rlc.absorbed_fields,
    }
}

fn accumulate_core_tower(
    fixtures: &[RealAuthFixture],
    claims: &[OwnerAuthVerifierClaims],
) -> CoreAccumResult {
    let beta = derive_accumulation_beta(fixtures);
    let mut rlc = TowerRlc::new(beta);
    absorb_core_fields(&mut rlc, fixtures, claims);
    CoreAccumResult {
        digest: rlc.acc,
        beta,
        absorbed_fields: rlc.absorbed_fields,
    }
}

fn build_real_auth_fixture(case: CaseKind, i: usize) -> RealAuthFixture {
    match case {
        CaseKind::Standard4x8 => {
            let fixture = standard_fixture(standard_scenario(
                "o1-auth-accum-standard",
                4,
                8,
                20_000 + (i as u32) * 128,
                0xA11CE_0000 + i as u128 * 0x1000,
            ));
            RealAuthFixture {
                public: fixture.auth_public,
                proof: fixture.auth_proof,
            }
        }
        CaseKind::Sweep25x2 => {
            let fixture = sweep_fixture(sweep_scenario(
                "o1-auth-accum-sweep",
                25,
                2_000_000 + (i as u32) * 128,
                0xB0B0_0000 + i as u128 * 0x1000,
            ));
            let circuit = OwnerAuthCircuit::build(fixture.auth_inputs.layout);
            let mut channel = owner_auth_gkr_channel();
            let (proof, _) =
                prove_owner_auth_killshot(&circuit, &fixture.auth_inputs, &mut channel);
            RealAuthFixture {
                public: fixture.auth_public,
                proof,
            }
        }
    }
}

fn build_real_auth_fixtures(case: CaseKind, n: usize) -> Vec<RealAuthFixture> {
    (0..n)
        .map(|i| build_real_auth_fixture(case, i))
        .collect::<Vec<_>>()
}

fn verify_real_auth_claims(fixtures: &[RealAuthFixture]) -> Vec<OwnerAuthVerifierClaims> {
    fixtures
        .iter()
        .map(|fixture| {
            let circuit = OwnerAuthCircuit::build(fixture.public.layout);
            let mut channel = owner_auth_gkr_channel();
            verify_owner_auth_killshot_with_claims(
                &fixture.proof,
                &circuit,
                &fixture.public,
                &mut channel,
            )
            .expect("real auth proof verifies with claims")
        })
        .collect()
}

fn total_pcs_payload(fixtures: &[RealAuthFixture]) -> PcsPayloadStats {
    fixtures
        .iter()
        .map(|fixture| PcsPayloadStats::from_proof(&fixture.proof))
        .fold(PcsPayloadStats::default(), PcsPayloadStats::add)
}

fn print_accum_row(case: CaseKind, n: usize, run_equivalence_check: bool) {
    let start_mem = current_mem_snapshot();
    let (build_time, fixtures) = time_once(|| build_real_auth_fixtures(case, n));
    let wallet_proof_bytes: usize = fixtures.iter().map(|f| f.proof.byte_len()).sum();
    let pcs_payload = total_pcs_payload(&fixtures);
    let (verify_time, claims) = time_once(|| verify_real_auth_claims(&fixtures));
    let (accum_time, accum) = time_once(|| accumulate_core_clmul(&fixtures, &claims));
    let (full_scan_time, full_scan) = time_once(|| scan_full_witness_clmul(&fixtures, &claims));

    if run_equivalence_check {
        let tower = accumulate_core_tower(&fixtures, &claims);
        assert_eq!(tower.beta, accum.beta);
        assert_eq!(tower.digest, accum.digest);
        assert_eq!(tower.absorbed_fields, accum.absorbed_fields);
    }

    let end_mem = current_mem_snapshot();
    let delta_rss = match (start_mem, end_mem) {
        (Some(start), Some(end)) => format!("{:>+7.1}M", end.delta_rss_mb(start)),
        _ => "      n/a".to_string(),
    };
    println!(
        "  {case:<12} {n:>4}  {build:>10} {verify:>10} {accum_t:>10} {full_scan:>10} {wallet:>12} {pcs_pending:>12} {claim:>10} {fields:>9} {full_fields:>11} {rss:>9} {hwm:>9}  beta={beta:032x} digest={digest:032x}",
        case = case.label(),
        n = n,
        build = fmt_ms(build_time),
        verify = fmt_ms(verify_time),
        accum_t = fmt_ms(accum_time),
        full_scan = fmt_ms(full_scan_time),
        wallet = fmt_bytes(wallet_proof_bytes),
        pcs_pending = fmt_bytes(pcs_payload.opening_payload_bytes()),
        claim = fmt_bytes(CORE_CLAIM_BYTES),
        fields = accum.absorbed_fields,
        full_fields = full_scan.absorbed_fields,
        rss = delta_rss,
        hwm = fmt_mem(end_mem),
        beta = accum.beta.to_u128(),
        digest = accum.digest.to_u128(),
    );
    println!(
        "      pcs split: commitment={} opening={}",
        fmt_bytes(pcs_payload.commitment_bytes),
        fmt_bytes(pcs_payload.opening_bytes),
    );
    println!(
        "      pcs shape: upper={} h={} source_symbols={} source_siblings={} mid_symbols={} mid_siblings={}",
        pcs_payload.upper_evals,
        pcs_payload.h_evals,
        pcs_payload.source_symbols,
        pcs_payload.source_siblings,
        pcs_payload.mid_symbols,
        pcs_payload.mid_siblings,
    );
    println!(
        "      per tx: core_accum={} full_scan={}",
        fmt_ms(duration_per_tx(accum_time, n)),
        fmt_ms(duration_per_tx(full_scan_time, n)),
    );
}

fn print_header() {
    println!(
        "  {case:<12} {n:>4}  {build:>10} {verify:>10} {accum:>10} {scan:>10} {wallet:>12} {pcs:>12} {claim:>10} {fields:>9} {full_fields:>11} {rss:>9} {hwm:>9}  digest",
        case = "case",
        n = "n",
        build = "build",
        verify = "verify",
        accum = "core_accum",
        scan = "full_scan",
        wallet = "wallet",
        pcs = "pcs_pending",
        claim = "core_claim",
        fields = "fields",
        full_fields = "full_fields",
        rss = "rss_delta",
        hwm = "HWM",
    );
    println!(
        "  {:-<12} {:-<4}  {:-<10} {:-<10} {:-<10} {:-<10} {:-<12} {:-<12} {:-<10} {:-<9} {:-<11} {:-<9} {:-<9}  {:-<40}",
        "", "", "", "", "", "", "", "", "", "", "", "", "", ""
    );
}

fn main() {
    let ns = env_usize_list("NOID_O1_AUTH_ACCUM_NS", DEFAULT_ACCUM_NS);
    let include_sweep = env_flag("NOID_O1_AUTH_ACCUM_SWEEP");
    let run_equivalence_check = env_flag("NOID_O1_AUTH_ACCUM_CHECK") || ns.iter().all(|&n| n <= 16);
    let _parallel_chunk = env_chunk();

    println!();
    println!("  =====================================================================");
    println!("  PARANOID OwnerAuth Accumulator Lite Bench");
    println!("  =====================================================================");
    println!("  Bench-only accumulator front-end. No consensus authority.");
    println!("  The timed core uses streaming CLMUL over Block128.");
    println!("  Defaults are intentionally small. Override with:");
    println!("    NOID_O1_AUTH_ACCUM_NS=1,4,16");
    println!("    NOID_O1_AUTH_ACCUM_SWEEP=1");
    println!("    NOID_O1_AUTH_ACCUM_CHECK=1");
    println!();

    print_header();
    for &n in &ns {
        print_accum_row(CaseKind::Standard4x8, n, run_equivalence_check);
        if include_sweep {
            print_accum_row(CaseKind::Sweep25x2, n, run_equivalence_check);
        }
    }

    println!();
    println!("  Notes:");
    println!("    core_accum is the non-PCS verifier-facing accumulator kernel.");
    println!("    full_scan is the cost of streaming the whole current wallet proof witness.");
    println!("    pcs_pending is the opening payload that still needs its own batch decider.");
    println!("    build creates wallet proofs only to feed this bench; real users create them.");
    println!();
    println!("  Reproduce: cargo bench -p bench_prover --bench o1_auth_accumulator_lite");
    println!();
}
