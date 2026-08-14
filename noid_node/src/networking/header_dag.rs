// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Bounded branch graph for headers that already passed native validation.

use std::collections::{HashMap, HashSet};

use noid_chain::{
    block_header::{block_id, BlockHeader},
    consensus::fork_choice::{choose_chain_by_work, ChainChoice},
};
use thiserror::Error;

use super::types::{ChainPoint, Hash32};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedHeader {
    pub header: BlockHeader,
    pub hash: Hash32,
    pub cumulative_work: Hash32,
}

impl ValidatedHeader {
    /// Construct only after the caller has run the complete native header
    /// checks for this exact ancestry.
    pub fn new_after_consensus_checks(header: BlockHeader, cumulative_work: Hash32) -> Self {
        Self {
            hash: block_id(&header),
            header,
            cumulative_work,
        }
    }

    pub const fn point(&self) -> ChainPoint {
        ChainPoint::new(self.header.height, self.hash)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderDagUpdate {
    Duplicate,
    Added,
    NewBest {
        previous: ChainPoint,
        best: ChainPoint,
    },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HeaderDagError {
    #[error("header is at or below the finalized boundary")]
    BelowFinalized,
    #[error("validated header parent is unknown")]
    MissingParent,
    #[error("validated header height does not follow its parent")]
    BadHeight,
    #[error("header hash already identifies different data")]
    HashCollision,
    #[error("header DAG reached its configured capacity")]
    Capacity,
    #[error("requested header is unknown")]
    UnknownHeader,
    #[error("requested base is not an ancestor of the target")]
    NotAncestor,
    #[error("new finalized point is not on the current best ancestry")]
    FinalizedOffBestChain,
}

/// The DAG does not validate State or commit chain data. It only retains
/// already native-validated headers and performs deterministic work ordering.
pub struct HeaderDag {
    finalized: ChainPoint,
    finalized_work: Hash32,
    best: ChainPoint,
    best_work: Hash32,
    nodes: HashMap<Hash32, ValidatedHeader>,
    max_nodes: usize,
}

impl HeaderDag {
    pub fn new(finalized: ChainPoint, finalized_work: Hash32, max_nodes: usize) -> Self {
        assert!(max_nodes > 0, "header DAG capacity must be non-zero");
        Self {
            finalized,
            finalized_work,
            best: finalized,
            best_work: finalized_work,
            nodes: HashMap::new(),
            max_nodes,
        }
    }

    pub const fn finalized(&self) -> ChainPoint {
        self.finalized
    }

    pub const fn best_tip(&self) -> ChainPoint {
        self.best
    }

    pub const fn best_work(&self) -> Hash32 {
        self.best_work
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn get(&self, hash: &Hash32) -> Option<&ValidatedHeader> {
        self.nodes.get(hash)
    }

    pub fn insert(
        &mut self,
        candidate: ValidatedHeader,
    ) -> Result<HeaderDagUpdate, HeaderDagError> {
        if candidate.header.height <= self.finalized.height {
            return Err(HeaderDagError::BelowFinalized);
        }
        if let Some(existing) = self.nodes.get(&candidate.hash) {
            return if existing == &candidate {
                Ok(HeaderDagUpdate::Duplicate)
            } else {
                Err(HeaderDagError::HashCollision)
            };
        }
        if self.nodes.len() >= self.max_nodes {
            return Err(HeaderDagError::Capacity);
        }

        let parent = if candidate.header.prev_block_hash == self.finalized.hash {
            self.finalized
        } else {
            self.nodes
                .get(&candidate.header.prev_block_hash)
                .map(ValidatedHeader::point)
                .ok_or(HeaderDagError::MissingParent)?
        };
        if candidate.header.height != parent.height.saturating_add(1) {
            return Err(HeaderDagError::BadHeight);
        }

        let previous = self.best;
        let candidate_point = candidate.point();
        let candidate_work = candidate.cumulative_work;
        self.nodes.insert(candidate.hash, candidate);
        if matches!(
            choose_chain_by_work(
                &candidate_work,
                &candidate_point.hash,
                &self.best_work,
                &self.best.hash,
            ),
            ChainChoice::A
        ) {
            self.best = candidate_point;
            self.best_work = candidate_work;
            Ok(HeaderDagUpdate::NewBest {
                previous,
                best: self.best,
            })
        } else {
            Ok(HeaderDagUpdate::Added)
        }
    }

    pub fn path_from(
        &self,
        base: ChainPoint,
        target: ChainPoint,
    ) -> Result<Vec<ValidatedHeader>, HeaderDagError> {
        if base == target {
            return Ok(Vec::new());
        }
        let mut cursor = target;
        let mut reversed = Vec::new();
        while cursor != base {
            if cursor.height <= base.height {
                return Err(HeaderDagError::NotAncestor);
            }
            let node = self
                .nodes
                .get(&cursor.hash)
                .ok_or(HeaderDagError::UnknownHeader)?;
            reversed.push(*node);
            cursor = ChainPoint::new(
                node.header.height.saturating_sub(1),
                node.header.prev_block_hash,
            );
        }
        reversed.reverse();
        Ok(reversed)
    }

    pub fn common_ancestor(
        &self,
        left: ChainPoint,
        right: ChainPoint,
    ) -> Result<ChainPoint, HeaderDagError> {
        let mut left = left;
        let mut right = right;
        while left.height > right.height {
            left = self.parent(left)?;
        }
        while right.height > left.height {
            right = self.parent(right)?;
        }
        while left != right {
            if left.height <= self.finalized.height || right.height <= self.finalized.height {
                return Err(HeaderDagError::NotAncestor);
            }
            left = self.parent(left)?;
            right = self.parent(right)?;
        }
        Ok(left)
    }

    pub fn is_ancestor(
        &self,
        ancestor: ChainPoint,
        descendant: ChainPoint,
    ) -> Result<bool, HeaderDagError> {
        if ancestor.height > descendant.height {
            return Ok(false);
        }
        let mut cursor = descendant;
        while cursor.height > ancestor.height {
            cursor = self.parent(cursor)?;
        }
        Ok(cursor == ancestor)
    }

    pub fn advance_finalized(
        &mut self,
        finalized: ChainPoint,
        finalized_work: Hash32,
    ) -> Result<(), HeaderDagError> {
        if finalized == self.finalized {
            self.finalized_work = finalized_work;
            return Ok(());
        }
        if !self.is_ancestor(finalized, self.best)? {
            return Err(HeaderDagError::FinalizedOffBestChain);
        }

        let mut keep = HashSet::new();
        for point in self
            .nodes
            .values()
            .map(ValidatedHeader::point)
            .filter(|point| point.height > finalized.height)
        {
            if self.is_ancestor(finalized, point).unwrap_or(false) {
                keep.insert(point.hash);
            }
        }
        self.nodes.retain(|hash, _| keep.contains(hash));
        self.finalized = finalized;
        self.finalized_work = finalized_work;
        if self.best.height <= finalized.height {
            self.best = finalized;
            self.best_work = finalized_work;
        }
        Ok(())
    }

    fn parent(&self, point: ChainPoint) -> Result<ChainPoint, HeaderDagError> {
        if point == self.finalized {
            return Err(HeaderDagError::NotAncestor);
        }
        let node = self
            .nodes
            .get(&point.hash)
            .ok_or(HeaderDagError::UnknownHeader)?;
        let parent = ChainPoint::new(
            node.header.height.saturating_sub(1),
            node.header.prev_block_hash,
        );
        if parent.height < self.finalized.height {
            return Err(HeaderDagError::NotAncestor);
        }
        if parent.height == self.finalized.height && parent != self.finalized {
            return Err(HeaderDagError::NotAncestor);
        }
        Ok(parent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::consensus::genesis_header;

    fn child(parent: BlockHeader, nonce: u128, work: u8) -> ValidatedHeader {
        let mut header = parent;
        header.prev_block_hash = block_id(&parent);
        header.height = parent.height + 1;
        header.timestamp += 1;
        header.nonce = nonce;
        ValidatedHeader::new_after_consensus_checks(header, [work; 32])
    }

    #[test]
    fn best_tip_uses_work_and_exact_hash_tie_break() {
        let genesis = genesis_header();
        let finalized = ChainPoint::new(0, block_id(&genesis));
        let mut dag = HeaderDag::new(finalized, [1; 32], 16);
        let a = child(genesis, 1, 2);
        let b = child(genesis, 2, 3);

        assert!(matches!(
            dag.insert(a).unwrap(),
            HeaderDagUpdate::NewBest { .. }
        ));
        assert!(matches!(
            dag.insert(b).unwrap(),
            HeaderDagUpdate::NewBest { best, .. } if best == b.point()
        ));
        assert_eq!(dag.best_tip(), b.point());
    }

    #[test]
    fn exact_paths_and_common_ancestor_are_source_independent() {
        let genesis = genesis_header();
        let finalized = ChainPoint::new(0, block_id(&genesis));
        let mut dag = HeaderDag::new(finalized, [1; 32], 16);
        let a1 = child(genesis, 1, 2);
        let a2 = child(a1.header, 2, 3);
        let b2 = child(a1.header, 3, 4);
        dag.insert(a1).unwrap();
        dag.insert(a2).unwrap();
        dag.insert(b2).unwrap();

        assert_eq!(
            dag.common_ancestor(a2.point(), b2.point()).unwrap(),
            a1.point()
        );
        assert_eq!(dag.path_from(a1.point(), b2.point()).unwrap(), vec![b2]);
    }

    #[test]
    fn missing_parent_and_capacity_fail_without_mutation() {
        let genesis = genesis_header();
        let finalized = ChainPoint::new(0, block_id(&genesis));
        let mut dag = HeaderDag::new(finalized, [1; 32], 1);
        let a = child(genesis, 1, 2);
        let mut orphan = child(a.header, 2, 3);
        orphan.header.prev_block_hash = [9; 32];
        orphan.hash = block_id(&orphan.header);
        assert_eq!(dag.insert(orphan), Err(HeaderDagError::MissingParent));
        assert_eq!(dag.len(), 0);
        dag.insert(a).unwrap();
        let b = child(genesis, 4, 3);
        assert_eq!(dag.insert(b), Err(HeaderDagError::Capacity));
        assert_eq!(dag.len(), 1);
    }
}
