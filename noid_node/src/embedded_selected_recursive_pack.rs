// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Build-authenticated, runtime-ready selected-recursive release material.
//!
//! Official builds contain one registry and nine compressed fixed-width
//! matrix images derived from the canonical release leaves. The bytes stay
//! compressed in `.rodata`; runtime only copies ready arrays for requested
//! tiers. There is deliberately no path or filesystem fallback in this API.

use std::fmt;

use noid_ivc_core::field_r1cs::BuildAuthenticatedFieldR1csSeal;
use noid_miner::SelectedRecursiveMatrixKind;
#[cfg(test)]
use noid_miner::SelectedRecursiveTier;

pub const EMBEDDED_SELECTED_RECURSIVE_LEAF_COUNT: usize = 9;

/// Runtime-ready matrix image produced from a build-authenticated canonical
/// release leaf.
pub struct EmbeddedSelectedRecursiveLeaf {
    kind: SelectedRecursiveMatrixKind,
    compressed_runtime_image: &'static [u8],
    build_seal: BuildAuthenticatedFieldR1csSeal,
}

impl fmt::Debug for EmbeddedSelectedRecursiveLeaf {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmbeddedSelectedRecursiveLeaf")
            .field("kind", &self.kind)
            .field(
                "compressed_runtime_image",
                &self.compressed_runtime_image.len(),
            )
            .field("build_seal", &self.build_seal)
            .finish()
    }
}

impl EmbeddedSelectedRecursiveLeaf {
    pub const fn kind(&self) -> SelectedRecursiveMatrixKind {
        self.kind
    }

    pub const fn compressed_runtime_image(&self) -> &'static [u8] {
        self.compressed_runtime_image
    }

    pub const fn build_seal(&self) -> BuildAuthenticatedFieldR1csSeal {
        self.build_seal
    }

    #[cfg(test)]
    pub const fn canonical_relative_path(&self) -> &'static str {
        canonical_compressed_relative_path(self.kind)
    }
}

/// Complete self-contained selected-recursive pack.
pub struct EmbeddedSelectedRecursivePack {
    registry_bytes: &'static [u8],
    registry_digest: [u8; 32],
    leaves: [EmbeddedSelectedRecursiveLeaf; EMBEDDED_SELECTED_RECURSIVE_LEAF_COUNT],
}

impl fmt::Debug for EmbeddedSelectedRecursivePack {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmbeddedSelectedRecursivePack")
            .field("registry_bytes", &self.registry_bytes.len())
            .field("registry_digest", &self.registry_digest)
            .field("leaves", &self.leaves)
            .finish()
    }
}

impl EmbeddedSelectedRecursivePack {
    pub const fn registry_bytes(&self) -> &'static [u8] {
        self.registry_bytes
    }

    pub const fn registry_digest(&self) -> [u8; 32] {
        self.registry_digest
    }

    pub const fn leaves(
        &self,
    ) -> &[EmbeddedSelectedRecursiveLeaf; EMBEDDED_SELECTED_RECURSIVE_LEAF_COUNT] {
        &self.leaves
    }

    pub fn embedded_bytes_total(&self) -> usize {
        self.registry_bytes.len()
            + self
                .leaves
                .iter()
                .map(|leaf| leaf.compressed_runtime_image.len())
                .sum::<usize>()
    }
}

/// Returns `None` only for an explicitly pack-free development build. An
/// official build cannot reach that state because `build.rs` requires all
/// release inputs together and authenticates them before compilation.
pub fn embedded_selected_recursive_pack() -> Option<&'static EmbeddedSelectedRecursivePack> {
    GENERATED_SELECTED_RECURSIVE_PACK.as_ref()
}

#[cfg(test)]
pub const fn canonical_leaf_index(kind: SelectedRecursiveMatrixKind) -> usize {
    match kind {
        SelectedRecursiveMatrixKind::GenesisLink => 0,
        SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B8) => 1,
        SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B32) => 2,
        SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B64) => 3,
        SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B255) => 4,
        SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B8) => 5,
        SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B32) => 6,
        SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B64) => 7,
        SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B255) => 8,
    }
}

#[cfg(test)]
pub const fn canonical_compressed_relative_path(kind: SelectedRecursiveMatrixKind) -> &'static str {
    match kind {
        SelectedRecursiveMatrixKind::GenesisLink => "v1/genesis-link.field-r1cs.zst",
        SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B8) => {
            "v1/link-b8.field-r1cs.zst"
        }
        SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B32) => {
            "v1/link-b32.field-r1cs.zst"
        }
        SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B64) => {
            "v1/link-b64.field-r1cs.zst"
        }
        SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B255) => {
            "v1/link-b255.field-r1cs.zst"
        }
        SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B8) => {
            "v1/block-b8.field-r1cs.zst"
        }
        SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B32) => {
            "v1/block-b32.field-r1cs.zst"
        }
        SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B64) => {
            "v1/block-b64.field-r1cs.zst"
        }
        SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B255) => {
            "v1/block-b255.field-r1cs.zst"
        }
    }
}

include!(concat!(env!("OUT_DIR"), "/selected_recursive_pack.rs"));

#[cfg(test)]
mod tests {
    use super::*;

    const KINDS: [SelectedRecursiveMatrixKind; EMBEDDED_SELECTED_RECURSIVE_LEAF_COUNT] = [
        SelectedRecursiveMatrixKind::GenesisLink,
        SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B8),
        SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B32),
        SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B64),
        SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B255),
        SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B8),
        SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B32),
        SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B64),
        SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B255),
    ];

    #[test]
    fn canonical_leaf_index_is_dense_and_stable() {
        for (expected, kind) in KINDS.into_iter().enumerate() {
            assert_eq!(canonical_leaf_index(kind), expected);
        }
    }

    #[test]
    fn generated_pack_preserves_canonical_identity_order() {
        let Some(pack) = embedded_selected_recursive_pack() else {
            return;
        };
        for (expected, leaf) in KINDS.into_iter().zip(pack.leaves()) {
            assert_eq!(leaf.kind(), expected);
            assert!(leaf.canonical_relative_path().ends_with(".zst"));
            assert!(!leaf.compressed_runtime_image().is_empty());
            assert!(leaf.build_seal().canonical_bytes() > 0);
        }
        assert!(!pack.registry_bytes().is_empty());
    }
}
