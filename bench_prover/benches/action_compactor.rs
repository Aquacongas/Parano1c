// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Bitmap-driven action-compactor row/RSS gate.
//!
//! Defaults to B25. Use `NOID_ACTION_TIERS=25,255`; B255 intentionally
//! builds the real 4,096-row sorting network and may be expensive.

use std::time::Instant;

use bench_prover::legal_block_scenarios;
use noid_core::mem_profile::current_mem_snapshot;
use noid_core::Block128;
use noid_recursive::acceptance::shape::ShapeClass;
use noid_recursive::acceptance::trace::action_compaction::{
    bind_mint_packed_values_body_order, compact_action_rows,
};
use noid_recursive::acceptance::trace::action_surface::ActionRowTrace;
use noid_recursive::acceptance::trace::{alloc_block, FieldR1csBuilder, LinExpr};

fn requested_tiers() -> Vec<usize> {
    let raw = std::env::var("NOID_ACTION_TIERS").unwrap_or_else(|_| "25".into());
    let tiers: Vec<_> = raw
        .split(',')
        .filter_map(|part| part.trim().parse().ok())
        .collect();
    assert!(!tiers.is_empty());
    assert!(tiers
        .iter()
        .all(|tier| noid_chain::consensus::params::BLOCK_PAGE_CLASS_TIERS.contains(tier)));
    tiers
}

fn row(b: &mut FieldR1csBuilder, ordinal: usize, live: bool, is_mint: bool) -> ActionRowTrace {
    let live_value = if live { 1u128 } else { 0u128 };
    let live_w = alloc_block(b, Block128::from(live_value));
    let selected = |b: &mut FieldR1csBuilder, value: u128| {
        alloc_block(b, Block128::from(if live { value } else { 0 }))
    };
    ActionRowTrace {
        live: live_w.clone(),
        slot_index: selected(b, ordinal as u128 + 1),
        value: selected(b, ordinal as u128 + 10_000),
        owner: [
            selected(b, ordinal as u128 + 20_000),
            selected(b, ordinal as u128 + 30_000),
        ],
        is_mint: if is_mint { live_w } else { LinExpr::zero() },
    }
}

fn main() {
    println!("PARANOID bitmap action-compactor gate");
    println!("NOID_ACTION_TIERS=25,255 selects class runs.\n");

    for tier in requested_tiers() {
        let class = ShapeClass { tier };
        let scenarios = legal_block_scenarios("action-compactor", tier, 0xAC71_0000);
        let mut pattern = Vec::with_capacity(class.action_candidate_capacity());
        let mut kinds = Vec::with_capacity(class.action_candidate_capacity());
        pattern.push(true); // canonical coinbase mint
        kinds.push(true);
        for scenario in &scenarios {
            for input in 0..noid_tx::TX_INPUTS {
                pattern.push(scenario.body.input_is_live(input));
                kinds.push(false);
            }
            for output in 0..noid_tx::TX_OUTPUTS {
                pattern.push(scenario.body.output_is_live(output));
                kinds.push(true);
            }
        }
        assert_eq!(pattern.len(), class.action_candidate_capacity());
        assert_eq!(
            pattern.iter().filter(|&&live| live).count(),
            class.touched_capacity()
        );

        let before = current_mem_snapshot();
        let started = Instant::now();
        let mut b = FieldR1csBuilder::new();
        let mut candidates: Vec<_> = pattern
            .iter()
            .zip(kinds.iter())
            .enumerate()
            .map(|(ordinal, (&live, &mint))| row(&mut b, ordinal, live, mint))
            .collect();
        let mint_count = pattern
            .iter()
            .zip(&kinds)
            .filter(|(live, mint)| **live && **mint)
            .count();
        let parent_alloc = alloc_block(&mut b, Block128::from(100u128));
        let child_alloc = alloc_block(&mut b, Block128::from(100u128 + mint_count as u128));
        let block_height = alloc_block(&mut b, Block128::from(7u128));
        bind_mint_packed_values_body_order(
            &mut b,
            &mut candidates,
            &parent_alloc,
            &child_alloc,
            &block_height,
        );
        let compact = compact_action_rows(&mut b, &candidates, class.touched_capacity());
        assert_eq!(compact.source_rows, class.action_candidate_capacity());
        assert_eq!(compact.sort_rows, class.action_sort_capacity());
        let assembly = started.elapsed();
        let rows_before_build = b.num_wires();
        let (r1cs, witness) = b.build();
        let build = started.elapsed() - assembly;
        let verify = std::env::var_os("NOID_ACTION_VERIFY").is_some() || tier != 255;
        let verify_started = Instant::now();
        if verify {
            assert!(r1cs.satisfies(&witness));
        }
        let after = current_mem_snapshot();

        println!("  B{tier}");
        println!("    candidates:       {}", compact.source_rows);
        println!("    sort rows:        {}", compact.sort_rows);
        println!("    live capacity:    {}", compact.rows.len());
        println!("    builder wires:    {rows_before_build}");
        println!("    useful R1CS rows: {}", r1cs.useful_rows);
        println!("    padded m:         {}", r1cs.m);
        println!("    assemble:         {:.3} s", assembly.as_secs_f64());
        println!("    build matrices:   {:.3} s", build.as_secs_f64());
        if verify {
            println!(
                "    satisfy:          {:.3} s",
                verify_started.elapsed().as_secs_f64()
            );
        } else {
            println!("    satisfy:          skipped (set NOID_ACTION_VERIFY=1)");
        }
        if let (Some(before), Some(after)) = (before, after) {
            println!("    RSS:              {:.1} MiB", after.rss_mb());
            println!("    peak RSS:         {:.1} MiB", after.hwm_mb());
            println!(
                "    RSS delta:        {:.1} MiB",
                after.delta_rss_mb(before)
            );
        }
    }
}
