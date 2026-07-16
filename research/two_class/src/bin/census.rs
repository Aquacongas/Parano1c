// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use paranoid_two_class_research::{
    action_relation, budget, geometry, page_binding, paged_spend_relation,
};

fn main() {
    println!("B128/B256 isolated two-class research census");
    println!(
        "pages/auths       {}/{}",
        geometry::PAGE_CAPACITY,
        geometry::AUTHORIZATION_CAPACITY
    );
    println!(
        "inputs/outputs    {}/{}",
        geometry::INPUT_CAPACITY,
        geometry::OUTPUT_CAPACITY
    );
    println!("reference TPS     {:.3}", geometry::reference_l1_tps());
    println!("protocol TPS      {:.3}", geometry::protocol_l1_tps());
    println!("m23 rows          {}", budget::M23_ROWS);
    println!("direct SIMD auth  {}", budget::DIRECT_SIMD_AUTH_ROWS_A128);
    println!(
        "PagedSpend scanner {} ({} with existing u64 ranges)",
        paged_spend_relation::PAGED_SPEND_A128_SCANNER_ROWS,
        paged_spend_relation::PAGED_SPEND_A128_REUSED_SCANNER_ROWS,
    );
    println!(
        "page binding       {}",
        page_binding::P128_PAGE_BINDING_ROWS
    );
    println!(
        "action relation    {}",
        action_relation::ACTION_RELATION_ROWS
    );
    println!(
        "non-auth ceiling  {}",
        budget::M23_ROWS - budget::DIRECT_SIMD_AUTH_ROWS_A128
    );
}
