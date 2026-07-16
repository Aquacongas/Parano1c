// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! End-to-end wallet-local PagedSpend benchmark.
//!
//! Each sample constructs the complete page group, hashes it, creates exactly
//! one unchanged wallet capsule, encodes/decodes the atomic intent and runs
//! local authorization verification. Network RTT is deliberately excluded.

use std::time::{Duration, Instant};

use noid_gkr::{
    prove_paged_spend_authorization, verify_paged_spend_authorization, OwnerAuthWitness,
    WalletAuthorizationBundle,
};
use noid_poseidon2b::primitives::{derive_address, SpendSecret};
use noid_tx::{output_bitmap_bit, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS};
use paranoid_two_class_research::paged_spend::{
    hash_paged_spend, PagedSpendIntent, TxPage, MAX_PAGED_SPEND_INPUTS, PAGED_SPEND_END_BIT,
    PAGED_SPEND_START_BIT,
};

const DEFAULT_SAMPLES: usize = 20;
const INPUT_AMOUNT: u64 = 1_000_000;

#[derive(Clone, Copy)]
struct Case {
    label: &'static str,
    inputs: usize,
    seed: u128,
}

#[derive(Default)]
struct Sample {
    build_hash: Duration,
    prove: Duration,
    admission: Duration,
    total: Duration,
    pages: usize,
    proof_bytes: usize,
    intent_bytes: usize,
}

fn mk_secret(seed: u128) -> SpendSecret {
    let low = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xA5A5_A5A5_A5A5_A5A5;
    let high = seed.wrapping_mul(0xBF58_476D_1CE4_E5B9) ^ 0x5A5A_5A5A_5A5A_5A5A;
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&low.to_le_bytes());
    bytes[16..].copy_from_slice(&high.to_le_bytes());
    SpendSecret::from_bytes(bytes)
}

fn fmt_ms(duration: Duration) -> String {
    let milliseconds = duration.as_secs_f64() * 1_000.0;
    if milliseconds >= 1_000.0 {
        format!("{:>8.2} s ", milliseconds / 1_000.0)
    } else {
        format!("{:>8.2} ms", milliseconds)
    }
}

fn fmt_bytes(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:>8.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:>8.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:>8} B ", bytes)
    }
}

fn samples() -> usize {
    std::env::var("NOID_WALLET_BENCH_SAMPLES")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|&value| value > 0)
        .unwrap_or(DEFAULT_SAMPLES)
}

fn percentile(mut values: Vec<Duration>, percentile: usize) -> Duration {
    assert!(!values.is_empty());
    assert!((1..=100).contains(&percentile));
    values.sort_unstable();
    let rank = (percentile * values.len()).div_ceil(100);
    values[rank.saturating_sub(1)]
}

fn build_pages(input_count: usize, seed: u128) -> Vec<TxPage> {
    assert!((1..=MAX_PAGED_SPEND_INPUTS).contains(&input_count));
    let secret = mk_secret(seed);
    let owner = derive_address(&secret);
    let fee = 5_000u64;
    let page_count = input_count.div_ceil(TX_INPUTS);
    let output_amount = (input_count as u64)
        .checked_mul(INPUT_AMOUNT)
        .and_then(|sum| sum.checked_sub(fee))
        .expect("benchmark balance");

    (0..page_count)
        .map(|page_index| {
            let mut inputs = [TxInput::dummy(); TX_INPUTS];
            let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
            let mut bitmap = 0u16;
            for (slot, input) in inputs.iter_mut().enumerate() {
                let input_index = page_index * TX_INPUTS + slot;
                if input_index < input_count {
                    *input = TxInput {
                        slot_index: input_index as u32 + 1,
                        amount: INPUT_AMOUNT,
                        creation_id: input_index as u64 + 1,
                    };
                    bitmap |= 1 << slot;
                }
            }
            if page_index == 0 {
                outputs[0] = TxOutput {
                    slot_index: 1_000_000,
                    amount: output_amount,
                    owner,
                };
                bitmap |= output_bitmap_bit(0);
                bitmap |= PAGED_SPEND_START_BIT;
            }
            if page_index + 1 == page_count {
                bitmap |= PAGED_SPEND_END_BIT;
            }
            TxPage::new(TxBody {
                epoch_anchor: [0xA5; 32],
                fee: if page_index == 0 { fee } else { 0 },
                input_owner: owner,
                inputs,
                outputs,
                validity_bitmap: bitmap,
                is_coinbase: false,
            })
            .expect("canonical benchmark page")
        })
        .collect()
}

fn run_sample(case: Case) -> Sample {
    let total_started = Instant::now();

    let build_started = Instant::now();
    let pages = build_pages(case.inputs, case.seed);
    let logical_txid = hash_paged_spend(&pages).expect("canonical PagedSpend hash");
    let build_hash = build_started.elapsed();

    let prove_started = Instant::now();
    let proof =
        prove_paged_spend_authorization(&pages, OwnerAuthWitness::new(mk_secret(case.seed)))
            .expect("one PagedSpend capsule")
            .proof;
    let prove = prove_started.elapsed();

    let admission_started = Instant::now();
    let bundle = WalletAuthorizationBundle { proof };
    let proof_bytes = bundle.to_bytes().expect("canonical wallet bundle");
    let intent = PagedSpendIntent::new(pages.clone(), proof_bytes.clone())
        .expect("atomic PagedSpend intent");
    assert_eq!(intent.logical_txid(), logical_txid);
    let intent_bytes = intent.to_bytes().expect("encode PagedSpend intent");
    let decoded = PagedSpendIntent::from_bytes(&intent_bytes).expect("decode PagedSpend intent");
    verify_paged_spend_authorization(&decoded.pages, &bundle)
        .expect("local PagedSpend admission verification");
    let admission = admission_started.elapsed();

    Sample {
        build_hash,
        prove,
        admission,
        total: total_started.elapsed(),
        pages: pages.len(),
        proof_bytes: proof_bytes.len(),
        intent_bytes: intent_bytes.len(),
    }
}

fn main() {
    let sample_count = samples();
    println!("PARANOID PagedSpend wallet-local path, samples={sample_count}");
    println!(
        "Includes build + logical hash + one capsule + local admission; excludes network RTT.\n"
    );

    for case in [
        Case {
            label: "send-1",
            inputs: 1,
            seed: 0xA301,
        },
        Case {
            label: "consolidate-100",
            inputs: 100,
            seed: 0xA364,
        },
        Case {
            label: "consolidate-1020",
            inputs: 1_020,
            seed: 0xA3FC,
        },
    ] {
        // Untimed warm-up also checks the exact worst-case intent shape.
        let warm = run_sample(case);
        let mut measured = Vec::with_capacity(sample_count);
        for _ in 0..sample_count {
            measured.push(run_sample(case));
        }
        let metric = |read: fn(&Sample) -> Duration| {
            let values = measured.iter().map(read).collect::<Vec<_>>();
            (percentile(values.clone(), 50), percentile(values, 95))
        };
        let (build_p50, build_p95) = metric(|sample| sample.build_hash);
        let (prove_p50, prove_p95) = metric(|sample| sample.prove);
        let (admit_p50, admit_p95) = metric(|sample| sample.admission);
        let (total_p50, total_p95) = metric(|sample| sample.total);

        println!(
            "  {}: {} inputs / {} pages",
            case.label, case.inputs, warm.pages
        );
        println!(
            "    page build + hash: p50 {} / p95 {}",
            fmt_ms(build_p50),
            fmt_ms(build_p95)
        );
        println!(
            "    one capsule:       p50 {} / p95 {}",
            fmt_ms(prove_p50),
            fmt_ms(prove_p95)
        );
        println!(
            "    local admission:   p50 {} / p95 {}",
            fmt_ms(admit_p50),
            fmt_ms(admit_p95)
        );
        println!(
            "    end-to-end:        p50 {} / p95 {}",
            fmt_ms(total_p50),
            fmt_ms(total_p95)
        );
        println!(
            "    proof / intent:    {} / {}",
            fmt_bytes(warm.proof_bytes),
            fmt_bytes(warm.intent_bytes)
        );
    }
}
