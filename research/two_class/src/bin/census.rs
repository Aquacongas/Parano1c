// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use paranoid_two_class_research::{geometry, parent_union};

fn main() {
    println!("B25/B255 isolated PagedSpend research census");
    println!(
        "B25 pages/auths   {}/{} (m{})",
        geometry::B25_PAGE_CAPACITY,
        geometry::B25_AUTHORIZATION_CAPACITY,
        geometry::B25_OUTER_M,
    );
    println!(
        "B255 pages/auths  {}/{}+pad (m{})",
        geometry::B255_PAGE_CAPACITY,
        geometry::B255_LIVE_AUTHORIZATION_CAPACITY,
        geometry::B255_OUTER_M,
    );
    println!(
        "B25 inputs/outputs {}/{}",
        geometry::B25_INPUT_CAPACITY,
        geometry::B25_OUTPUT_CAPACITY,
    );
    println!(
        "B255 inputs/outputs {}/{}",
        geometry::B255_INPUT_CAPACITY,
        geometry::B255_OUTPUT_CAPACITY,
    );
    println!(
        "logical max       {} pages / {} inputs / {} outputs",
        geometry::LOGICAL_PAGE_CAPACITY,
        geometry::LOGICAL_INPUT_CAPACITY,
        geometry::LOGICAL_OUTPUT_CAPACITY,
    );
    println!("B25 saturated TPS {:.3}", geometry::b25_saturated_tps());
    println!(
        "protocol TPS      {:.3}",
        geometry::protocol_saturated_tps()
    );
    let parent = parent_union::ParentUnionLayout::canonical();
    println!(
        "parent m22/m24 q  {}/{}",
        parent.b25.fri_queries, parent.b255.fri_queries
    );
    println!(
        "parent union tail  {} fields",
        parent.inactive_m22_suffix_fields
    );
}
