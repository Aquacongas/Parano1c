// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! GKR-spine tx-body Merkle module.
//!
//! The 59-perm AIR has been retired; GKR owns Merkle proving. This
//! module now exposes only the layout constants and boundary-pin struct
//! that the outer STARK composite (`TxBodySpineComposite`) and GKR
//! (`noid_gkr`) still require.

pub mod layout;

pub use layout::{
    build_instance_layout, instance_row_offset, InstanceMeta, InstanceRole,
    TxBodyMerkleBoundaryPins, TXBODY_MERKLE_LAYOUT, TXBODY_MERKLE_N_PERMS, TXBODY_MERKLE_SLOT_ROWS,
};
