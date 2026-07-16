// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use paranoid_two_class_research::{
    action_relation, budget, geometry, page_binding, paged_spend_relation, parent_union,
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
    let parent = parent_union::ParentUnionLayout::canonical();
    println!(
        "parent m23/m24 q  {}/{}",
        parent.b128.fri_queries, parent.b256.fri_queries
    );
    println!(
        "parent union tail  {} fields",
        parent.inactive_m23_suffix_fields
    );
    println!(
        "production B64     direct={} history={} shared={}",
        budget::PRODUCTION_B64_DIRECT_BLOCK_ROWS,
        budget::PRODUCTION_B64_HISTORY_STEP_ROWS,
        budget::PRODUCTION_B64_SHARED_HISTORY_ROWS,
    );
    println!(
        "standard A128 floor {} (+shared baseline={})",
        budget::STANDARD_A128_AUTH_META_FLOOR,
        budget::STANDARD_A128_WITH_B64_SHARED_BASELINE,
    );
    println!(
        "optimized known    {} (unresolved={}, baseline margin={})",
        budget::KNOWN_OPTIMIZED_CORE_ROWS_A128,
        budget::OPTIMIZED_UNRESOLVED_BUDGET_A128,
        budget::OPTIMIZED_MARGIN_AFTER_B64_SHARED_BASELINE,
    );
    println!(
        "non-auth ceiling  {}",
        budget::M23_ROWS - budget::DIRECT_SIMD_AUTH_ROWS_A128
    );
}
