// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use paranoid_two_class_research::{geometry, parent_union};

fn main() {
    println!("B64/B255 isolated PagedSpend research census");
    println!(
        "B64 pages/auths   {}/{} (m{})",
        geometry::B64_PAGE_CAPACITY,
        geometry::B64_AUTHORIZATION_CAPACITY,
        geometry::B64_OUTER_M,
    );
    println!(
        "B255 pages/auths  {}/{}+pad (m{})",
        geometry::B255_PAGE_CAPACITY,
        geometry::B255_LIVE_AUTHORIZATION_CAPACITY,
        geometry::B255_OUTER_M,
    );
    println!(
        "B64 inputs/outputs {}/{}",
        geometry::B64_INPUT_CAPACITY,
        geometry::B64_OUTPUT_CAPACITY,
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
    println!("B64 saturated TPS {:.3}", geometry::b64_saturated_tps());
    println!(
        "protocol TPS      {:.3}",
        geometry::protocol_saturated_tps()
    );
    let parent = parent_union::ParentUnionLayout::canonical();
    println!(
        "parent m23/m24 q  {}/{}",
        parent.b64.fri_queries, parent.b255.fri_queries
    );
    println!(
        "parent union tail  {} fields",
        parent.inactive_m23_suffix_fields
    );
}
