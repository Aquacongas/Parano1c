// SPDX-License-Identifier: Apache-2.0

//! Shared full-node/mobile header planner.
//!
//! Extracted from the authoritative full-node planning path.
//!
//! Native validation and cumulative-work fork choice occur before any
//! exact block body is scheduled.

use std::sync::Arc;

use tokio::sync::RwLock;

use noid_chain::storage::{MdbxChainContext, MdbxStore};

use crate::snapshot_header_staging::validate_bounded_header_extension;

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub enum HeaderInventoryPlan {
    Confirmed {
        tip: crate::ChainPoint,
    },
    Behind,
    NeedOlder {
        start_height: u64,
        count: u16,
    },
    Candidate {
        headers: Vec<crate::header_dag::ValidatedHeader>,
        records: Vec<noid_p2p::header_protocol::HeaderInventoryRecord>,
        old_tip: crate::ChainPoint,
        target: crate::ChainPoint,
    },
    FinalizedDivergence,
}

pub fn nonfinal_header_discovery_range(local_height: u64) -> Option<(u64, u16)> {
    if local_height == 0 {
        return None;
    }
    let start_height = finalized_header_search_floor(local_height);
    let count = local_height.saturating_sub(start_height).saturating_add(1);
    Some((
        start_height,
        u16::try_from(count).expect("finality-bounded header discovery count fits u16"),
    ))
}

pub fn finalized_header_search_floor(local_height: u64) -> u64 {
    local_height.saturating_sub(noid_chain::consensus::params::CONSENSUS_FINALITY_DEPTH)
}

pub fn header_batch_exhausts_nonfinal_window(local_height: u64, oldest_height: u64) -> bool {
    oldest_height <= finalized_header_search_floor(local_height)
}

pub fn header_inventory_validation_anchor(
    canonical: Option<crate::ChainPoint>,
    validated_dag: Option<crate::ChainPoint>,
) -> Option<crate::ChainPoint> {
    // If the response includes a canonical point, replay the bounded branch
    // from that point even when every later header is already present in the
    // DAG. This turns a later exact-inventory response into a fresh data plan
    // instead of incorrectly classifying it as Behind. A DAG-only anchor is
    // still required for a continuation whose canonical base is outside the
    // bounded response.
    canonical.or(validated_dag)
}

pub fn record_validated_headers(
    dag: &mut crate::header_dag::HeaderDag,
    headers: &[crate::header_dag::ValidatedHeader],
) -> Result<(), crate::header_dag::HeaderDagError> {
    for header in headers {
        dag.insert(*header)?;
    }
    Ok(())
}

/// A provider response may repeat headers which already entered HeaderDAG
/// through an earlier header-only announcement. Preserve its exact object
/// inventory even when the control-plane planner consequently classifies the
/// batch as already known/behind. Unknown headers still require the native
/// validation path before they may receive any availability hints.
pub fn advertise_inventory_for_known_headers(
    dag: &mut crate::header_dag::HeaderDag,
    peer: libp2p::PeerId,
    records: &[noid_p2p::header_protocol::HeaderInventoryRecord],
) -> Result<usize, crate::header_dag::HeaderDagError> {
    let known_inventory = records
        .iter()
        .filter(|record| record.body.is_some() || record.terminal.is_some())
        .filter(|record| {
            let hash = noid_chain::block_id(&record.header);
            dag.get(&hash)
                .is_some_and(|known| known.header == record.header)
        })
        .copied()
        .collect::<Vec<_>>();
    if known_inventory.is_empty() {
        return Ok(0);
    }
    dag.advertise_inventory(peer, &known_inventory)
}

/// Turn one bounded v3 inventory into a source-independent suffix plan. All
/// native header checks and cumulative-work comparison happen before any body
/// request is scheduled.
pub async fn plan_header_inventory(
    chain: &Arc<RwLock<MdbxChainContext>>,
    store: &MdbxStore,
    header_dag: &crate::header_dag::HeaderDag,
    records: Vec<noid_p2p::header_protocol::HeaderInventoryRecord>,
) -> Result<HeaderInventoryPlan, String> {
    use crate::{header_dag::ValidatedHeader, ChainPoint};
    use noid_chain::consensus::params::CONSENSUS_FINALITY_DEPTH;

    let (our_tip, our_tip_hash, canonical_ancestors) = {
        let ctx = chain.read().await;
        let our_tip = ctx.tip_height();
        let ancestors = records
            .iter()
            .filter_map(|record| {
                let hash = noid_chain::block_id(&record.header);
                ctx.find_ancestor_height(&hash).map(|height| (height, hash))
            })
            .collect::<Vec<_>>();
        (our_tip, ctx.tip_hash(), ancestors)
    };
    let old_tip = ChainPoint::new(our_tip, our_tip_hash);
    if records.is_empty() {
        return Ok(nonfinal_header_discovery_range(our_tip).map_or(
            HeaderInventoryPlan::Behind,
            |(start_height, count)| HeaderInventoryPlan::NeedOlder {
                start_height,
                count,
            },
        ));
    }
    // A continuation may be anchored at an already native-validated DAG
    // parent which has not yet been committed. Canonical MDBX is therefore
    // not the only valid control-plane anchor.
    let dag_ancestors = records.iter().filter_map(|record| {
        let hash = noid_chain::block_id(&record.header);
        let point = ChainPoint::new(record.header.height, hash);
        if point == header_dag.finalized() {
            return Some(point);
        }
        header_dag
            .get(&hash)
            .filter(|known| known.header == record.header)
            .map(ValidatedHeader::point)
    });
    let canonical_ancestor = canonical_ancestors
        .into_iter()
        .map(|(height, hash)| ChainPoint::new(height, hash))
        .filter(|point| point.height >= header_dag.finalized().height)
        .max_by_key(|point| point.height);
    let dag_ancestor = dag_ancestors.max_by_key(|point| point.height);
    let ancestor = header_inventory_validation_anchor(canonical_ancestor, dag_ancestor);

    let Some(ancestor) = ancestor else {
        let oldest = records.first().map_or(0, |record| record.header.height);
        if header_batch_exhausts_nonfinal_window(our_tip, oldest) {
            return Ok(HeaderInventoryPlan::FinalizedDivergence);
        }
        return Ok(HeaderInventoryPlan::NeedOlder {
            start_height: finalized_header_search_floor(our_tip),
            count: (CONSENSUS_FINALITY_DEPTH as u16 * 2).min(512),
        });
    };
    if ancestor.height < header_dag.finalized().height {
        return Ok(HeaderInventoryPlan::FinalizedDivergence);
    }
    let ancestor_height = ancestor.height;
    let ancestor_hash = ancestor.hash;

    let competing_records = records
        .into_iter()
        .filter(|record| record.header.height > ancestor_height)
        .collect::<Vec<_>>();
    if competing_records.is_empty() {
        return Ok(
            if ancestor_height == our_tip && ancestor_hash == our_tip_hash {
                HeaderInventoryPlan::Confirmed { tip: old_tip }
            } else {
                HeaderInventoryPlan::Behind
            },
        );
    }
    let competing_headers = competing_records
        .iter()
        .map(|record| record.header)
        .collect::<Vec<_>>();
    let validation_store = store.clone();
    let mut validation_headers = if ancestor == header_dag.finalized() {
        Vec::new()
    } else {
        header_dag
            .path_from(header_dag.finalized(), ancestor)
            .map_err(|error| format!("load header DAG validation ancestry: {error}"))?
            .into_iter()
            .map(|header| header.header)
            .collect::<Vec<_>>()
    };
    validation_headers.extend_from_slice(&competing_headers);
    let validation_base_height = header_dag.finalized().height;
    let target_work = tokio::task::spawn_blocking(move || {
        validate_bounded_header_extension(
            &validation_store,
            validation_base_height,
            &validation_headers,
            unix_now(),
        )
        .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("header validation worker failed: {error}"))??;

    let mut cumulative_work = header_dag
        .cumulative_work(ancestor)
        .map_err(|error| format!("load header-plan ancestor work: {error}"))?;
    let mut validated = Vec::with_capacity(competing_headers.len());
    for header in competing_headers {
        cumulative_work = noid_chain::add_work(
            &cumulative_work,
            &noid_chain::block_work(&header.difficulty_target),
        );
        validated.push(ValidatedHeader::new_after_consensus_checks(
            header,
            cumulative_work,
        ));
    }
    if cumulative_work != target_work {
        return Err("header-plan chainwork disagrees with native validation".into());
    }
    let target = validated
        .last()
        .expect("non-empty competing header suffix")
        .point();
    Ok(HeaderInventoryPlan::Candidate {
        headers: validated,
        records: competing_records,
        old_tip,
        target,
    })
}

/// Build one immutable suffix plan from HeaderDAG authority while keeping
/// object availability attributed to the exact peers that advertised it.
/// The bootstrap offer contains only the selected tip terminal; body sources
/// are merged independently afterwards.
pub fn source_independent_suffix_offer(
    dag: &crate::header_dag::HeaderDag,
    preferred_peer: libp2p::PeerId,
    old_tip: crate::ChainPoint,
    base: crate::ChainPoint,
    headers: Vec<crate::header_dag::ValidatedHeader>,
) -> Result<
    (
        libp2p::PeerId,
        crate::suffix_sync::SuffixOffer,
        Vec<(
            libp2p::PeerId,
            Vec<noid_p2p::header_protocol::HeaderInventoryRecord>,
        )>,
    ),
    crate::suffix_sync::SuffixSyncError,
> {
    use crate::suffix_sync::{SuffixOffer, SuffixSyncError};

    let target = headers.last().ok_or(SuffixSyncError::EmptySuffix)?.point();
    let (terminal_peer, terminal) = dag
        .terminal_provider(target, Some(preferred_peer))
        .ok_or(SuffixSyncError::MissingTipTerminal)?;
    let mut bootstrap = headers
        .iter()
        .map(|header| noid_p2p::header_protocol::HeaderInventoryRecord::header_only(header.header))
        .collect::<Vec<_>>();
    bootstrap
        .last_mut()
        .expect("non-empty suffix checked above")
        .terminal = Some(terminal);
    let offer = if base == old_tip {
        SuffixOffer::live(base, headers.clone(), &bootstrap)?
    } else {
        SuffixOffer::reorg(old_tip, base, headers.clone(), &bootstrap)?
    };
    let inventories = dag
        .inventory_providers(&headers)
        .into_iter()
        .map(|peer| (peer, dag.inventory_for_provider(peer, &headers)))
        .collect::<Vec<_>>();
    let every_body_has_a_source = headers.iter().enumerate().all(|(index, header)| {
        inventories.iter().any(|(_, records)| {
            records
                .get(index)
                .and_then(|record| record.body)
                .is_some_and(|body| {
                    body.claim.height == header.header.height
                        && body.claim.block_hash == header.hash
                })
        })
    });
    if !every_body_has_a_source {
        return Err(SuffixSyncError::MissingBodySource);
    }
    Ok((terminal_peer, offer, inventories))
}
