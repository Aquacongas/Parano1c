// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Compact, matrix-free production registry for selected history recursion.
//!
//! A node retains four Block class identities, four Link class identities and
//! one shared genesis proof.  The nine multi-gigabyte-capable matrices live in
//! the streaming matrix store and are never serialized here.  Region VK fixed
//! tables that are canonical consequences of a tier are regenerated from
//! their compact descriptors instead of being copied into the artifact.

use std::fmt;
use std::sync::Arc;

use noid_chain::consensus::params::USER_TX_CLASS_TIERS;
use noid_ivc_core::deep_chain::schedule::TranscriptOp;
use noid_ivc_core::field::F128;
use noid_ivc_core::pcs::ligerito::LigeritoProfile;
use noid_ivc_core::pcs::PcsParams;
use noid_ivc_core::proof::FieldShape;
use noid_ivc_core::public_io::{IoClaimSpec, PublicIoSpec, WitnessSlice};
use noid_poseidon2b::native::poseidon2b_hash_byte_slices;

use crate::acceptance::block_class::{BlockClass, BlockProofError};
use crate::acceptance::split_link::{
    CanonicalLadderError, CanonicalSplitLinkLadder, LadderSlotInfo, LinkProofError, SplitLinkClass,
};
use crate::region_sidecar::{
    BlockRegionSidecarVk, CombinedDuplexRegionDescriptor, CombinedDuplexRegionVk,
    CombinedDuplexSubChannelDescriptor, LinkRegionSidecarVk, MerkleRegionFamily, MerkleRegionVk,
    RegionSidecarError, SelectedZkBlockRegionVkSlices, COMBINED_DUPLEX_REGION_COMMITTED_COLUMNS,
    MAX_COMBINED_DUPLEX_SCHEDULE_OPS, MAX_COMBINED_DUPLEX_SUBCHANNELS,
    MAX_COMBINED_DUPLEX_TX_TILE_LOG, MERKLE_REGION_COMMITTED_COLUMNS,
};
use crate::selected_history::{
    decode_selected_history_terminal_package, SelectedHistoryCodecError,
    SelectedHistoryTerminalPackage, MAX_SELECTED_HISTORY_TERMINAL_PACKAGE_BYTES,
};

pub const SELECTED_RECURSIVE_CLASS_REGISTRY_VERSION: u16 = 1;
pub const MAX_SELECTED_RECURSIVE_CLASS_REGISTRY_BYTES: usize = 4 * 1024 * 1024;

const REGISTRY_MAGIC: [u8; 16] = *b"NOID/SRCLASS/V1\0";
const REGISTRY_HEADER_BYTES: usize = REGISTRY_MAGIC.len() + 2 + 8;
const REGISTRY_TRAILER_BYTES: usize = 32;
const REGISTRY_DIGEST_DOMAIN: &[u8] = b"NOID/SELECTED-RECURSIVE-CLASS-REGISTRY/V1";
const CLASS_COUNT: usize = USER_TX_CLASS_TIERS.len();
const MAX_PUBLIC_IO_CLAIMS: usize = 16;
const MAX_GENESIS_PACKAGE_BYTES: usize = MAX_SELECTED_HISTORY_TERMINAL_PACKAGE_BYTES;
const MAX_MERKLE_FAMILIES: usize = 64;
const MAX_TRANSCRIPT_ABSORB_LANES: usize = 4096;

/// An owned registry decoded from local release material.  It contains no
/// `FieldR1cs`, sample Block envelope, witness, or per-tier proof.
pub struct OwnedSelectedRecursiveClassRegistry {
    block_classes: [BlockClass; CLASS_COUNT],
    descriptor: CanonicalSplitLinkLadder,
    link_classes: [SplitLinkClass; CLASS_COUNT],
}

impl OwnedSelectedRecursiveClassRegistry {
    pub fn block_classes(&self) -> &[BlockClass; CLASS_COUNT] {
        &self.block_classes
    }

    pub fn descriptor(&self) -> &CanonicalSplitLinkLadder {
        &self.descriptor
    }

    pub fn link_classes(&self) -> &[SplitLinkClass; CLASS_COUNT] {
        &self.link_classes
    }

    pub fn encode(&self) -> Result<Vec<u8>, SelectedRecursiveClassRegistryError> {
        encode_selected_recursive_class_registry(
            &self.block_classes,
            &self.descriptor,
            &self.link_classes,
        )
    }
}

#[derive(Debug)]
pub enum SelectedRecursiveClassRegistryError {
    TooLarge {
        actual: usize,
        max: usize,
    },
    Truncated,
    BadMagic,
    UnsupportedVersion {
        actual: u16,
    },
    LengthOverflow,
    LengthMismatch {
        expected: usize,
        actual: usize,
    },
    DigestMismatch,
    InvalidLength {
        field: &'static str,
        actual: u64,
        max: usize,
    },
    InvalidValue(&'static str),
    Block {
        slot: usize,
        source: BlockProofError,
    },
    Link {
        slot: usize,
        source: LinkProofError,
    },
    Ladder(CanonicalLadderError),
    Region(RegionSidecarError),
    Genesis(SelectedHistoryCodecError),
}

impl fmt::Display for SelectedRecursiveClassRegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { actual, max } => {
                write!(f, "class registry is {actual} bytes; cap is {max}")
            }
            Self::Truncated => f.write_str("class registry is truncated"),
            Self::BadMagic => f.write_str("class registry magic mismatch"),
            Self::UnsupportedVersion { actual } => {
                write!(f, "unsupported class registry version {actual}")
            }
            Self::LengthOverflow => f.write_str("class registry length does not fit platform"),
            Self::LengthMismatch { expected, actual } => write!(
                f,
                "class registry length mismatch: expected {expected}, got {actual}"
            ),
            Self::DigestMismatch => f.write_str("class registry payload digest mismatch"),
            Self::InvalidLength { field, actual, max } => {
                write!(f, "class registry {field} length {actual} exceeds {max}")
            }
            Self::InvalidValue(field) => write!(f, "class registry invalid {field}"),
            Self::Block { slot, source } => {
                write!(f, "class registry Block slot {slot}: {source}")
            }
            Self::Link { slot, source } => {
                write!(f, "class registry Link slot {slot}: {source}")
            }
            Self::Ladder(source) => write!(f, "class registry ladder: {source}"),
            Self::Region(source) => write!(f, "class registry region VK: {source}"),
            Self::Genesis(source) => write!(f, "class registry genesis envelope: {source}"),
        }
    }
}

impl std::error::Error for SelectedRecursiveClassRegistryError {}

impl From<CanonicalLadderError> for SelectedRecursiveClassRegistryError {
    fn from(value: CanonicalLadderError) -> Self {
        Self::Ladder(value)
    }
}

impl From<RegionSidecarError> for SelectedRecursiveClassRegistryError {
    fn from(value: RegionSidecarError) -> Self {
        Self::Region(value)
    }
}

impl From<SelectedHistoryCodecError> for SelectedRecursiveClassRegistryError {
    fn from(value: SelectedHistoryCodecError) -> Self {
        Self::Genesis(value)
    }
}

#[derive(Clone)]
struct BlockWire {
    tier: usize,
    config_bits: u8,
    config_queries: usize,
    config_tier: usize,
    shape: FieldShape,
    pcs: PcsParams,
    spec: PublicIoSpec,
    matrix_digest: [u8; 32],
    vk_slices: SelectedZkBlockRegionVkSlices,
    child_vk_digests: [[u8; 32]; 6],
    vk_digest: [u8; 32],
    post_commit_digest: [u8; 32],
}

#[derive(Clone)]
struct LinkWire {
    slot: usize,
    shape: FieldShape,
    pcs: PcsParams,
    spec: PublicIoSpec,
    matrix_digest: [u8; 32],
    post_commit_digest: [u8; 32],
    genesis_digest: [u8; 32],
    genesis_post_commit_digest: [u8; 32],
    sidecar_vk_digest: [u8; 32],
    b_spec: PublicIoSpec,
    b_pcs: PcsParams,
    b_sidecar_vk_digest: [u8; 32],
    b_post_commit_digest: [u8; 32],
}

#[derive(Clone)]
struct LinkVkWire {
    leaf_purpose: [u8; 32],
    leaf_tx_tile_log: usize,
    leaf_subchannels: Vec<SubchannelWire>,
    leaf_slices: [WitnessSlice; COMBINED_DUPLEX_REGION_COMMITTED_COLUMNS],
    leaf_digest: [u8; 32],
    path_purpose: [u8; 32],
    path_w_log: usize,
    path_block_log: usize,
    path_slices: [WitnessSlice; MERKLE_REGION_COMMITTED_COLUMNS],
    path_families: Vec<MerkleRegionFamily>,
    path_digest: [u8; 32],
    vk_digest: [u8; 32],
}

#[derive(Clone)]
struct SubchannelWire {
    schedule: Vec<TranscriptOp>,
    iv: [F128; 2],
}

struct RegistryWire {
    blocks: [BlockWire; CLASS_COUNT],
    descriptor_shape: FieldShape,
    descriptor_pcs: PcsParams,
    descriptor_slots: [LadderSlotInfo; CLASS_COUNT],
    link_vk: LinkVkWire,
    links: [LinkWire; CLASS_COUNT],
    genesis_package: Vec<u8>,
}

/// Encode a fully materialized production registry without touching any
/// matrix source.  Validation happens before bytes are authored.
pub fn encode_selected_recursive_class_registry(
    blocks: &[BlockClass; CLASS_COUNT],
    descriptor: &CanonicalSplitLinkLadder,
    links: &[SplitLinkClass; CLASS_COUNT],
) -> Result<Vec<u8>, SelectedRecursiveClassRegistryError> {
    descriptor.validate_materialized(links)?;
    let block_wires = try_array_from_fn(|slot| block_wire(slot, &blocks[slot]))?;
    let link_wires = try_array_from_fn(|slot| link_wire(slot, &links[slot]))?;
    let link_vk = link_vk_wire(links[0].sidecar_vk())?;
    for (slot, class) in links.iter().enumerate() {
        if class.sidecar_vk().transcript_digest() != link_vk.vk_digest {
            return Err(SelectedRecursiveClassRegistryError::InvalidValue(
                "shared Link sidecar VK",
            ));
        }
        if class.slot() != slot {
            return Err(SelectedRecursiveClassRegistryError::InvalidValue(
                "Link slot",
            ));
        }
    }

    let genesis =
        SelectedHistoryTerminalPackage::new(0, [0u8; 32], 0, links[0].genesis_envelope().clone())?
            .encode()?;
    if genesis.len() > MAX_GENESIS_PACKAGE_BYTES {
        return Err(SelectedRecursiveClassRegistryError::InvalidLength {
            field: "genesis package",
            actual: genesis.len() as u64,
            max: MAX_GENESIS_PACKAGE_BYTES,
        });
    }

    let wire = RegistryWire {
        blocks: block_wires,
        descriptor_shape: descriptor.link_shape(),
        descriptor_pcs: descriptor.link_pcs_params().clone(),
        descriptor_slots: descriptor.slots().clone(),
        link_vk,
        links: link_wires,
        genesis_package: genesis,
    };
    let mut body = Writer::new();
    encode_registry_body(&mut body, &wire);
    finish_artifact(body.finish())
}

/// Allocation-free outer length preflight followed by bounded manual decode
/// and canonical rehydration.  Every nested count is checked against a fixed
/// protocol maximum and remaining bytes before a `Vec` reserves storage.
pub fn decode_selected_recursive_class_registry(
    bytes: &[u8],
) -> Result<OwnedSelectedRecursiveClassRegistry, SelectedRecursiveClassRegistryError> {
    let body = preflight_artifact(bytes)?;
    preflight_registry_body(body)?;
    let wire = decode_registry_body(body)?;
    materialize_registry(wire)
}

fn finish_artifact(body: Vec<u8>) -> Result<Vec<u8>, SelectedRecursiveClassRegistryError> {
    let total = REGISTRY_HEADER_BYTES
        .checked_add(body.len())
        .and_then(|value| value.checked_add(REGISTRY_TRAILER_BYTES))
        .ok_or(SelectedRecursiveClassRegistryError::LengthOverflow)?;
    if total > MAX_SELECTED_RECURSIVE_CLASS_REGISTRY_BYTES {
        return Err(SelectedRecursiveClassRegistryError::TooLarge {
            actual: total,
            max: MAX_SELECTED_RECURSIVE_CLASS_REGISTRY_BYTES,
        });
    }
    let digest = registry_digest(&body);
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(&REGISTRY_MAGIC);
    bytes.extend_from_slice(&SELECTED_RECURSIVE_CLASS_REGISTRY_VERSION.to_le_bytes());
    bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&body);
    bytes.extend_from_slice(&digest);
    Ok(bytes)
}

fn preflight_artifact(bytes: &[u8]) -> Result<&[u8], SelectedRecursiveClassRegistryError> {
    if bytes.len() > MAX_SELECTED_RECURSIVE_CLASS_REGISTRY_BYTES {
        return Err(SelectedRecursiveClassRegistryError::TooLarge {
            actual: bytes.len(),
            max: MAX_SELECTED_RECURSIVE_CLASS_REGISTRY_BYTES,
        });
    }
    if bytes.len() < REGISTRY_HEADER_BYTES + REGISTRY_TRAILER_BYTES {
        return Err(SelectedRecursiveClassRegistryError::Truncated);
    }
    if bytes[..REGISTRY_MAGIC.len()] != REGISTRY_MAGIC {
        return Err(SelectedRecursiveClassRegistryError::BadMagic);
    }
    let version = u16::from_le_bytes(
        bytes[REGISTRY_MAGIC.len()..REGISTRY_MAGIC.len() + 2]
            .try_into()
            .unwrap(),
    );
    if version != SELECTED_RECURSIVE_CLASS_REGISTRY_VERSION {
        return Err(SelectedRecursiveClassRegistryError::UnsupportedVersion { actual: version });
    }
    let body_len_offset = REGISTRY_MAGIC.len() + 2;
    let body_len = u64::from_le_bytes(
        bytes[body_len_offset..body_len_offset + 8]
            .try_into()
            .unwrap(),
    );
    let body_len = usize::try_from(body_len)
        .map_err(|_| SelectedRecursiveClassRegistryError::LengthOverflow)?;
    let expected = REGISTRY_HEADER_BYTES
        .checked_add(body_len)
        .and_then(|value| value.checked_add(REGISTRY_TRAILER_BYTES))
        .ok_or(SelectedRecursiveClassRegistryError::LengthOverflow)?;
    if expected != bytes.len() {
        return Err(SelectedRecursiveClassRegistryError::LengthMismatch {
            expected,
            actual: bytes.len(),
        });
    }
    let body = &bytes[REGISTRY_HEADER_BYTES..REGISTRY_HEADER_BYTES + body_len];
    let advertised: [u8; 32] = bytes[REGISTRY_HEADER_BYTES + body_len..]
        .try_into()
        .unwrap();
    if registry_digest(body) != advertised {
        return Err(SelectedRecursiveClassRegistryError::DigestMismatch);
    }
    Ok(body)
}

fn registry_digest(body: &[u8]) -> [u8; 32] {
    poseidon2b_hash_byte_slices(REGISTRY_DIGEST_DOMAIN, &[body])
}

fn block_wire(
    slot: usize,
    class: &BlockClass,
) -> Result<BlockWire, SelectedRecursiveClassRegistryError> {
    let expected_tier = USER_TX_CLASS_TIERS[slot];
    class
        .validate_selected_zk_identity_for_tier(expected_tier)
        .map_err(|source| SelectedRecursiveClassRegistryError::Block { slot, source })?;
    let vk_slices = class.sidecar_vk().selected_registry_slices()?;
    let child_vk_digests = [
        class.sidecar_vk().wallet_a().transcript_digest(),
        class.sidecar_vk().meta_a().transcript_digest(),
        class.sidecar_vk().wallet_b().transcript_digest(),
        class.sidecar_vk().meta_b().transcript_digest(),
        class.sidecar_vk().owner_c().transcript_digest(),
        class.sidecar_vk().main_c().transcript_digest(),
    ];
    Ok(BlockWire {
        tier: class.tier(),
        config_bits: 0x1f,
        config_queries: noid_fri_binius::capsule::CAPSULE_NUM_QUERIES,
        config_tier: class.tier(),
        shape: class.shape,
        pcs: class.pcs_params.clone(),
        spec: class.spec.clone(),
        matrix_digest: class
            .registry_matrix_digest()
            .map_err(|source| SelectedRecursiveClassRegistryError::Block { slot, source })?,
        vk_slices,
        child_vk_digests,
        vk_digest: class.sidecar_vk().transcript_digest(),
        post_commit_digest: *class.post_commit_class_digest(),
    })
}

fn link_wire(
    slot: usize,
    class: &SplitLinkClass,
) -> Result<LinkWire, SelectedRecursiveClassRegistryError> {
    let matrix_digest = class.class_statement_digest.get().copied().ok_or(
        SelectedRecursiveClassRegistryError::InvalidValue("Link matrix digest"),
    )?;
    let hosted =
        class
            .ladder()
            .get(slot)
            .ok_or(SelectedRecursiveClassRegistryError::InvalidValue(
                "Link hosted slot",
            ))?;
    Ok(LinkWire {
        slot,
        shape: class.shape,
        pcs: class.pcs_params.clone(),
        spec: class.spec.clone(),
        matrix_digest,
        post_commit_digest: *class.post_commit_class_digest(),
        genesis_digest: class.genesis_digest,
        genesis_post_commit_digest: class
            .registry_genesis_post_commit_digest()
            .map_err(|source| SelectedRecursiveClassRegistryError::Link { slot, source })?,
        sidecar_vk_digest: class.sidecar_vk().transcript_digest(),
        b_spec: crate::acceptance::block_class::block_io_spec(),
        b_pcs: hosted.b_pcs_params.clone(),
        b_sidecar_vk_digest: hosted.b_sidecar_vk_digest,
        b_post_commit_digest: hosted.b_post_commit_class_digest,
    })
}

fn link_vk_wire(
    vk: &LinkRegionSidecarVk,
) -> Result<LinkVkWire, SelectedRecursiveClassRegistryError> {
    let leaf = vk.leaf_a();
    let mut leaf_subchannels = Vec::with_capacity(leaf.descriptor().subchannels().len());
    for channel in leaf.descriptor().subchannels() {
        leaf_subchannels.push(SubchannelWire {
            schedule: channel.schedule().to_vec(),
            iv: channel.iv_flat(),
        });
    }
    let path = vk.path_b();
    Ok(LinkVkWire {
        leaf_purpose: *leaf.purpose(),
        leaf_tx_tile_log: leaf.descriptor().tx_tile_log(),
        leaf_subchannels,
        leaf_slices: *leaf.slices(),
        leaf_digest: leaf.transcript_digest(),
        path_purpose: *path.purpose(),
        path_w_log: path.w_log(),
        path_block_log: path.block_log(),
        path_slices: *path.slices(),
        path_families: path.families().to_vec(),
        path_digest: path.transcript_digest(),
        vk_digest: vk.transcript_digest(),
    })
}

fn materialize_registry(
    wire: RegistryWire,
) -> Result<OwnedSelectedRecursiveClassRegistry, SelectedRecursiveClassRegistryError> {
    let blocks_vec = wire
        .blocks
        .into_iter()
        .enumerate()
        .map(|(slot, block)| materialize_block(slot, block))
        .collect::<Result<Vec<_>, _>>()?;
    let blocks: [BlockClass; CLASS_COUNT] = blocks_vec
        .try_into()
        .map_err(|_| SelectedRecursiveClassRegistryError::InvalidValue("Block count"))?;

    let descriptor = CanonicalSplitLinkLadder::try_new(
        wire.descriptor_shape,
        wire.descriptor_pcs,
        wire.descriptor_slots.to_vec(),
    )?;
    for (slot, (info, block)) in descriptor.slots().iter().zip(&blocks).enumerate() {
        if info.tier != block.tier()
            || info.b_shape != block.shape
            || info.b_digest
                != block
                    .registry_matrix_digest()
                    .map_err(|source| SelectedRecursiveClassRegistryError::Block { slot, source })?
            || !same_pcs(&info.b_pcs_params, &block.pcs_params)
            || info.b_post_commit_class_digest != *block.post_commit_class_digest()
            || info.b_sidecar_vk_digest != block.sidecar_vk().transcript_digest()
        {
            return Err(SelectedRecursiveClassRegistryError::InvalidValue(
                "Block/ladder binding",
            ));
        }
    }

    let sidecar_vk = Arc::new(materialize_link_vk(wire.link_vk)?);
    let package = decode_selected_history_terminal_package(&wire.genesis_package)?;
    if package.terminal_height() != 0
        || package.terminal_hash() != [0u8; 32]
        || package.canonical_tip_slot() != 0
        || package.canonical_tip_tier() != USER_TX_CLASS_TIERS[0]
    {
        return Err(SelectedRecursiveClassRegistryError::InvalidValue(
            "genesis package metadata",
        ));
    }
    let genesis_envelope = Arc::new(package.into_terminal_envelope());

    let links_vec = wire
        .links
        .into_iter()
        .enumerate()
        .map(|(slot, link)| {
            if link.slot != slot {
                return Err(SelectedRecursiveClassRegistryError::InvalidValue(
                    "Link order",
                ));
            }
            if link.sidecar_vk_digest != sidecar_vk.transcript_digest() {
                return Err(SelectedRecursiveClassRegistryError::InvalidValue(
                    "Link class sidecar VK digest",
                ));
            }
            SplitLinkClass::from_selected_registry_parts(
                &descriptor,
                slot,
                &blocks[slot],
                link.shape,
                link.pcs,
                link.spec,
                link.matrix_digest,
                link.post_commit_digest,
                link.genesis_digest,
                link.genesis_post_commit_digest,
                Arc::clone(&sidecar_vk),
                Arc::clone(&genesis_envelope),
                link.b_spec,
                link.b_pcs,
                link.b_sidecar_vk_digest,
                link.b_post_commit_digest,
            )
            .map_err(|source| SelectedRecursiveClassRegistryError::Link { slot, source })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let links: [SplitLinkClass; CLASS_COUNT] = links_vec
        .try_into()
        .map_err(|_| SelectedRecursiveClassRegistryError::InvalidValue("Link count"))?;
    descriptor.validate_materialized(&links)?;
    Ok(OwnedSelectedRecursiveClassRegistry {
        block_classes: blocks,
        descriptor,
        link_classes: links,
    })
}

fn materialize_block(
    slot: usize,
    wire: BlockWire,
) -> Result<BlockClass, SelectedRecursiveClassRegistryError> {
    let expected_tier = USER_TX_CLASS_TIERS[slot];
    if wire.tier != expected_tier
        || wire.config_bits != 0x1f
        || wire.config_queries != noid_fri_binius::capsule::CAPSULE_NUM_QUERIES
        || wire.config_tier != expected_tier
    {
        return Err(SelectedRecursiveClassRegistryError::InvalidValue(
            "Block production config",
        ));
    }
    let vk = BlockRegionSidecarVk::from_selected_registry_slices(wire.tier, wire.vk_slices)?;
    let child = [
        vk.wallet_a().transcript_digest(),
        vk.meta_a().transcript_digest(),
        vk.wallet_b().transcript_digest(),
        vk.meta_b().transcript_digest(),
        vk.owner_c().transcript_digest(),
        vk.main_c().transcript_digest(),
    ];
    if child != wire.child_vk_digests || vk.transcript_digest() != wire.vk_digest {
        return Err(SelectedRecursiveClassRegistryError::InvalidValue(
            "Block sidecar VK digest",
        ));
    }
    BlockClass::from_selected_registry_parts(
        wire.tier,
        wire.shape,
        wire.pcs,
        wire.spec,
        wire.matrix_digest,
        vk,
        wire.post_commit_digest,
    )
    .map_err(|source| SelectedRecursiveClassRegistryError::Block { slot, source })
}

fn materialize_link_vk(
    wire: LinkVkWire,
) -> Result<LinkRegionSidecarVk, SelectedRecursiveClassRegistryError> {
    let mut channels = Vec::with_capacity(wire.leaf_subchannels.len());
    for channel in wire.leaf_subchannels {
        channels.push(CombinedDuplexSubChannelDescriptor::new(
            channel.schedule,
            channel.iv,
        )?);
    }
    let descriptor = CombinedDuplexRegionDescriptor::new(wire.leaf_tx_tile_log, channels)?;
    let leaf = CombinedDuplexRegionVk::new(wire.leaf_purpose, descriptor, wire.leaf_slices)?;
    if leaf.transcript_digest() != wire.leaf_digest {
        return Err(SelectedRecursiveClassRegistryError::InvalidValue(
            "Link leaf VK digest",
        ));
    }
    let path = MerkleRegionVk::new(
        wire.path_purpose,
        wire.path_w_log,
        wire.path_slices,
        wire.path_block_log,
        wire.path_families,
    )?;
    if path.transcript_digest() != wire.path_digest {
        return Err(SelectedRecursiveClassRegistryError::InvalidValue(
            "Link path VK digest",
        ));
    }
    let vk = LinkRegionSidecarVk::new(leaf, path)?;
    if vk.transcript_digest() != wire.vk_digest {
        return Err(SelectedRecursiveClassRegistryError::InvalidValue(
            "Link sidecar VK digest",
        ));
    }
    Ok(vk)
}

fn same_pcs(left: &PcsParams, right: &PcsParams) -> bool {
    left.m == right.m
        && left.log_inv_rate == right.log_inv_rate
        && left.log_batch_size == right.log_batch_size
        && left.profile == right.profile
}

fn encode_registry_body(out: &mut Writer, wire: &RegistryWire) {
    out.u8(CLASS_COUNT as u8);
    for block in &wire.blocks {
        encode_block(out, block);
    }
    encode_shape(out, wire.descriptor_shape);
    encode_pcs(out, &wire.descriptor_pcs);
    out.u8(CLASS_COUNT as u8);
    for slot in &wire.descriptor_slots {
        encode_ladder_slot(out, slot);
    }
    encode_link_vk(out, &wire.link_vk);
    out.u8(CLASS_COUNT as u8);
    for link in &wire.links {
        encode_link(out, link);
    }
    out.bytes(&wire.genesis_package);
}

fn decode_registry_body(bytes: &[u8]) -> Result<RegistryWire, SelectedRecursiveClassRegistryError> {
    let mut input = Reader::new(bytes);
    input.exact_count("Block count", CLASS_COUNT)?;
    let blocks = try_array_from_fn(|_| decode_block(&mut input))?;
    let descriptor_shape = decode_shape(&mut input)?;
    let descriptor_pcs = decode_pcs(&mut input)?;
    input.exact_count("ladder slot count", CLASS_COUNT)?;
    let descriptor_slots = try_array_from_fn(|_| decode_ladder_slot(&mut input))?;
    let link_vk = decode_link_vk(&mut input)?;
    input.exact_count("Link count", CLASS_COUNT)?;
    let links = try_array_from_fn(|_| decode_link(&mut input))?;
    let genesis_package = input.byte_vec("genesis package", MAX_GENESIS_PACKAGE_BYTES)?;
    input.finish()?;
    Ok(RegistryWire {
        blocks,
        descriptor_shape,
        descriptor_pcs,
        descriptor_slots,
        link_vk,
        links,
        genesis_package,
    })
}

/// Complete allocation-free structural pass over the manual body codec.
/// Every collection length, tag, range and terminal byte count is consumed
/// before `decode_registry_body` is allowed to allocate even a small vector.
fn preflight_registry_body(bytes: &[u8]) -> Result<(), SelectedRecursiveClassRegistryError> {
    let mut input = Reader::new(bytes);
    input.exact_count("Block count", CLASS_COUNT)?;
    for _ in 0..CLASS_COUNT {
        preflight_block(&mut input)?;
    }
    preflight_shape(&mut input)?;
    preflight_pcs(&mut input)?;
    input.exact_count("ladder slot count", CLASS_COUNT)?;
    for _ in 0..CLASS_COUNT {
        preflight_ladder_slot(&mut input)?;
    }
    preflight_link_vk(&mut input)?;
    input.exact_count("Link count", CLASS_COUNT)?;
    for _ in 0..CLASS_COUNT {
        preflight_link(&mut input)?;
    }
    input.byte_slice("genesis package", MAX_GENESIS_PACKAGE_BYTES)?;
    input.finish()
}

fn preflight_block(input: &mut Reader<'_>) -> Result<(), SelectedRecursiveClassRegistryError> {
    input.take(2 + 1 + 2 + 2)?;
    preflight_shape(input)?;
    preflight_pcs(input)?;
    preflight_spec(input)?;
    input.take(32)?;
    // Six fixed-count child slice sets: 6, 8, 9, 9, 6, 6.
    input.take((6 + 8 + 9 + 9 + 6 + 6) * (1 + 8))?;
    input.take(6 * 32 + 32 + 32)?;
    Ok(())
}

fn preflight_ladder_slot(
    input: &mut Reader<'_>,
) -> Result<(), SelectedRecursiveClassRegistryError> {
    input.take(2)?;
    preflight_shape(input)?;
    input.take(32)?;
    preflight_pcs(input)?;
    input.take(32 + 32)?;
    Ok(())
}

fn preflight_link(input: &mut Reader<'_>) -> Result<(), SelectedRecursiveClassRegistryError> {
    input.take(1)?;
    preflight_shape(input)?;
    preflight_pcs(input)?;
    preflight_spec(input)?;
    input.take(5 * 32)?;
    preflight_spec(input)?;
    preflight_pcs(input)?;
    input.take(2 * 32)?;
    Ok(())
}

fn preflight_link_vk(input: &mut Reader<'_>) -> Result<(), SelectedRecursiveClassRegistryError> {
    input.take(32)?;
    let tile_log = input.usize_u8()?;
    if tile_log > MAX_COMBINED_DUPLEX_TX_TILE_LOG {
        return Err(SelectedRecursiveClassRegistryError::InvalidValue(
            "combined duplex tile log",
        ));
    }
    let channel_count = input.len_u16(
        "combined duplex subchannels",
        MAX_COMBINED_DUPLEX_SUBCHANNELS,
    )?;
    for _ in 0..channel_count {
        let op_count =
            input.len_u16("combined duplex schedule", MAX_COMBINED_DUPLEX_SCHEDULE_OPS)?;
        for _ in 0..op_count {
            match input.u8()? {
                0 => {
                    let lane_count = input
                        .len_u16("combined duplex absorb lanes", MAX_TRANSCRIPT_ABSORB_LANES)?;
                    for _ in 0..lane_count {
                        match input.u8()? {
                            0 => {}
                            1 => {
                                input.take(16)?;
                            }
                            _ => {
                                return Err(SelectedRecursiveClassRegistryError::InvalidValue(
                                    "transcript lane tag",
                                ))
                            }
                        }
                    }
                }
                1 => {
                    input.take(2)?;
                }
                _ => {
                    return Err(SelectedRecursiveClassRegistryError::InvalidValue(
                        "transcript operation tag",
                    ))
                }
            }
        }
        input.take(2 * 16)?;
    }
    input.take(COMBINED_DUPLEX_REGION_COMMITTED_COLUMNS * 9)?;
    input.take(32 + 32 + 1 + 1)?;
    input.take(MERKLE_REGION_COMMITTED_COLUMNS * 9)?;
    let family_count = input.len_u8("Merkle families", MAX_MERKLE_FAMILIES)?;
    for _ in 0..family_count {
        match input.u8()? {
            0 | 1 => {
                input.take(4 + 2 + 4 + 2 * 16)?;
            }
            2 => {
                input.take(4 + 4 + 2 * 16)?;
            }
            _ => {
                return Err(SelectedRecursiveClassRegistryError::InvalidValue(
                    "Merkle family tag",
                ))
            }
        }
    }
    input.take(32 + 32)?;
    Ok(())
}

fn preflight_shape(input: &mut Reader<'_>) -> Result<(), SelectedRecursiveClassRegistryError> {
    input.take(4)?;
    Ok(())
}

fn preflight_pcs(input: &mut Reader<'_>) -> Result<(), SelectedRecursiveClassRegistryError> {
    let bytes = input.take(4)?;
    if bytes[3] > 2 {
        return Err(SelectedRecursiveClassRegistryError::InvalidValue(
            "PCS profile",
        ));
    }
    Ok(())
}

fn preflight_spec(input: &mut Reader<'_>) -> Result<(), SelectedRecursiveClassRegistryError> {
    input.take(9 + 4)?;
    let count = input.len_u8("public IO claims", MAX_PUBLIC_IO_CLAIMS)?;
    for _ in 0..count {
        input.take(9)?;
        let start = input.u32()?;
        let end = input.u32()?;
        input.take(4)?;
        if start > end {
            return Err(SelectedRecursiveClassRegistryError::InvalidValue(
                "public IO claim range",
            ));
        }
    }
    Ok(())
}

fn encode_block(out: &mut Writer, wire: &BlockWire) {
    out.u16(wire.tier as u16);
    out.u8(wire.config_bits);
    out.u16(wire.config_queries as u16);
    out.u16(wire.config_tier as u16);
    encode_shape(out, wire.shape);
    encode_pcs(out, &wire.pcs);
    encode_spec(out, &wire.spec);
    out.digest(&wire.matrix_digest);
    encode_block_vk_slices(out, &wire.vk_slices);
    for digest in &wire.child_vk_digests {
        out.digest(digest);
    }
    out.digest(&wire.vk_digest);
    out.digest(&wire.post_commit_digest);
}

fn decode_block(input: &mut Reader<'_>) -> Result<BlockWire, SelectedRecursiveClassRegistryError> {
    let tier = input.usize_u16()?;
    let config_bits = input.u8()?;
    let config_queries = input.usize_u16()?;
    let config_tier = input.usize_u16()?;
    let shape = decode_shape(input)?;
    let pcs = decode_pcs(input)?;
    let spec = decode_spec(input)?;
    let matrix_digest = input.digest()?;
    let vk_slices = decode_block_vk_slices(input)?;
    let child_vk_digests = try_array_from_fn(|_| input.digest())?;
    let vk_digest = input.digest()?;
    let post_commit_digest = input.digest()?;
    Ok(BlockWire {
        tier,
        config_bits,
        config_queries,
        config_tier,
        shape,
        pcs,
        spec,
        matrix_digest,
        vk_slices,
        child_vk_digests,
        vk_digest,
        post_commit_digest,
    })
}

fn encode_link(out: &mut Writer, wire: &LinkWire) {
    out.u8(wire.slot as u8);
    encode_shape(out, wire.shape);
    encode_pcs(out, &wire.pcs);
    encode_spec(out, &wire.spec);
    out.digest(&wire.matrix_digest);
    out.digest(&wire.post_commit_digest);
    out.digest(&wire.genesis_digest);
    out.digest(&wire.genesis_post_commit_digest);
    out.digest(&wire.sidecar_vk_digest);
    encode_spec(out, &wire.b_spec);
    encode_pcs(out, &wire.b_pcs);
    out.digest(&wire.b_sidecar_vk_digest);
    out.digest(&wire.b_post_commit_digest);
}

fn decode_link(input: &mut Reader<'_>) -> Result<LinkWire, SelectedRecursiveClassRegistryError> {
    Ok(LinkWire {
        slot: input.usize_u8()?,
        shape: decode_shape(input)?,
        pcs: decode_pcs(input)?,
        spec: decode_spec(input)?,
        matrix_digest: input.digest()?,
        post_commit_digest: input.digest()?,
        genesis_digest: input.digest()?,
        genesis_post_commit_digest: input.digest()?,
        sidecar_vk_digest: input.digest()?,
        b_spec: decode_spec(input)?,
        b_pcs: decode_pcs(input)?,
        b_sidecar_vk_digest: input.digest()?,
        b_post_commit_digest: input.digest()?,
    })
}

fn encode_link_vk(out: &mut Writer, wire: &LinkVkWire) {
    out.digest(&wire.leaf_purpose);
    out.u8(wire.leaf_tx_tile_log as u8);
    out.u16(wire.leaf_subchannels.len() as u16);
    for channel in &wire.leaf_subchannels {
        out.u16(channel.schedule.len() as u16);
        for op in &channel.schedule {
            match op {
                TranscriptOp::Absorb(lanes) => {
                    out.u8(0);
                    out.u16(lanes.len() as u16);
                    for lane in lanes {
                        match lane {
                            None => out.u8(0),
                            Some(value) => {
                                out.u8(1);
                                out.u128(*value);
                            }
                        }
                    }
                }
                TranscriptOp::Squeeze(count) => {
                    out.u8(1);
                    out.u16(*count as u16);
                }
            }
        }
        out.f128(channel.iv[0]);
        out.f128(channel.iv[1]);
    }
    encode_slices(out, &wire.leaf_slices);
    out.digest(&wire.leaf_digest);
    out.digest(&wire.path_purpose);
    out.u8(wire.path_w_log as u8);
    out.u8(wire.path_block_log as u8);
    encode_slices(out, &wire.path_slices);
    out.u8(wire.path_families.len() as u8);
    for family in &wire.path_families {
        encode_merkle_family(out, *family);
    }
    out.digest(&wire.path_digest);
    out.digest(&wire.vk_digest);
}

fn decode_link_vk(
    input: &mut Reader<'_>,
) -> Result<LinkVkWire, SelectedRecursiveClassRegistryError> {
    let leaf_purpose = input.digest()?;
    let leaf_tx_tile_log = input.usize_u8()?;
    if leaf_tx_tile_log > MAX_COMBINED_DUPLEX_TX_TILE_LOG {
        return Err(SelectedRecursiveClassRegistryError::InvalidValue(
            "combined duplex tile log",
        ));
    }
    let channel_count = input.len_u16(
        "combined duplex subchannels",
        MAX_COMBINED_DUPLEX_SUBCHANNELS,
    )?;
    let mut leaf_subchannels = Vec::with_capacity(channel_count);
    for _ in 0..channel_count {
        let op_count =
            input.len_u16("combined duplex schedule", MAX_COMBINED_DUPLEX_SCHEDULE_OPS)?;
        let mut schedule = Vec::with_capacity(op_count);
        for _ in 0..op_count {
            let tag = input.u8()?;
            match tag {
                0 => {
                    let lane_count = input
                        .len_u16("combined duplex absorb lanes", MAX_TRANSCRIPT_ABSORB_LANES)?;
                    let mut lanes = Vec::with_capacity(lane_count);
                    for _ in 0..lane_count {
                        lanes.push(match input.u8()? {
                            0 => None,
                            1 => Some(input.u128()?),
                            _ => {
                                return Err(SelectedRecursiveClassRegistryError::InvalidValue(
                                    "transcript lane tag",
                                ));
                            }
                        });
                    }
                    schedule.push(TranscriptOp::Absorb(lanes));
                }
                1 => schedule.push(TranscriptOp::Squeeze(input.usize_u16()?)),
                _ => {
                    return Err(SelectedRecursiveClassRegistryError::InvalidValue(
                        "transcript operation tag",
                    ));
                }
            }
        }
        leaf_subchannels.push(SubchannelWire {
            schedule,
            iv: [input.f128()?, input.f128()?],
        });
    }
    let leaf_slices = decode_slices(input)?;
    let leaf_digest = input.digest()?;
    let path_purpose = input.digest()?;
    let path_w_log = input.usize_u8()?;
    let path_block_log = input.usize_u8()?;
    let path_slices = decode_slices(input)?;
    let family_count = input.len_u8("Merkle families", MAX_MERKLE_FAMILIES)?;
    let mut path_families = Vec::with_capacity(family_count);
    for _ in 0..family_count {
        path_families.push(decode_merkle_family(input)?);
    }
    let path_digest = input.digest()?;
    let vk_digest = input.digest()?;
    Ok(LinkVkWire {
        leaf_purpose,
        leaf_tx_tile_log,
        leaf_subchannels,
        leaf_slices,
        leaf_digest,
        path_purpose,
        path_w_log,
        path_block_log,
        path_slices,
        path_families,
        path_digest,
        vk_digest,
    })
}

fn encode_merkle_family(out: &mut Writer, family: MerkleRegionFamily) {
    match family {
        MerkleRegionFamily::FeedForward {
            offset,
            depth,
            n_paths,
            iv,
        } => {
            out.u8(0);
            out.u32(offset as u32);
            out.u16(depth as u16);
            out.u32(n_paths as u32);
            out.f128(iv[0]);
            out.f128(iv[1]);
        }
        MerkleRegionFamily::TwoPermutation {
            offset,
            depth,
            n_paths,
            iv,
        } => {
            out.u8(1);
            out.u32(offset as u32);
            out.u16(depth as u16);
            out.u32(n_paths as u32);
            out.f128(iv[0]);
            out.f128(iv[1]);
        }
        MerkleRegionFamily::PairedUpdate {
            offset,
            n_updates,
            iv,
        } => {
            out.u8(2);
            out.u32(offset as u32);
            out.u32(n_updates as u32);
            out.f128(iv[0]);
            out.f128(iv[1]);
        }
    }
}

fn decode_merkle_family(
    input: &mut Reader<'_>,
) -> Result<MerkleRegionFamily, SelectedRecursiveClassRegistryError> {
    let tag = input.u8()?;
    let offset = input.usize_u32()?;
    Ok(match tag {
        0 => MerkleRegionFamily::FeedForward {
            offset,
            depth: input.usize_u16()?,
            n_paths: input.usize_u32()?,
            iv: [input.f128()?, input.f128()?],
        },
        1 => MerkleRegionFamily::TwoPermutation {
            offset,
            depth: input.usize_u16()?,
            n_paths: input.usize_u32()?,
            iv: [input.f128()?, input.f128()?],
        },
        2 => MerkleRegionFamily::PairedUpdate {
            offset,
            n_updates: input.usize_u32()?,
            iv: [input.f128()?, input.f128()?],
        },
        _ => {
            return Err(SelectedRecursiveClassRegistryError::InvalidValue(
                "Merkle family tag",
            ));
        }
    })
}

fn encode_ladder_slot(out: &mut Writer, slot: &LadderSlotInfo) {
    out.u16(slot.tier as u16);
    encode_shape(out, slot.b_shape);
    out.digest(&slot.b_digest);
    encode_pcs(out, &slot.b_pcs_params);
    out.digest(&slot.b_post_commit_class_digest);
    out.digest(&slot.b_sidecar_vk_digest);
}

fn decode_ladder_slot(
    input: &mut Reader<'_>,
) -> Result<LadderSlotInfo, SelectedRecursiveClassRegistryError> {
    Ok(LadderSlotInfo {
        tier: input.usize_u16()?,
        b_shape: decode_shape(input)?,
        b_digest: input.digest()?,
        b_pcs_params: decode_pcs(input)?,
        b_post_commit_class_digest: input.digest()?,
        b_sidecar_vk_digest: input.digest()?,
    })
}

fn encode_shape(out: &mut Writer, shape: FieldShape) {
    out.u8(shape.m as u8);
    out.u8(shape.k_log as u8);
    out.u8(shape.k_skip as u8);
    match shape.const_pin {
        None => out.u8(u8::MAX),
        Some(pin) => out.u8(pin as u8),
    }
}

fn decode_shape(input: &mut Reader<'_>) -> Result<FieldShape, SelectedRecursiveClassRegistryError> {
    let m = input.usize_u8()?;
    let k_log = input.usize_u8()?;
    let k_skip = input.usize_u8()?;
    let pin = input.u8()?;
    Ok(FieldShape {
        m,
        k_log,
        k_skip,
        const_pin: (pin != u8::MAX).then_some(usize::from(pin)),
    })
}

fn encode_pcs(out: &mut Writer, pcs: &PcsParams) {
    out.u8(pcs.m as u8);
    out.u8(pcs.log_inv_rate as u8);
    out.u8(pcs.log_batch_size as u8);
    out.u8(match pcs.profile {
        LigeritoProfile::Fast => 0,
        LigeritoProfile::Slim => 1,
        LigeritoProfile::Secure => 2,
    });
}

fn decode_pcs(input: &mut Reader<'_>) -> Result<PcsParams, SelectedRecursiveClassRegistryError> {
    let m = input.usize_u8()?;
    let log_inv_rate = input.usize_u8()?;
    let log_batch_size = input.usize_u8()?;
    let profile = match input.u8()? {
        0 => LigeritoProfile::Fast,
        1 => LigeritoProfile::Slim,
        2 => LigeritoProfile::Secure,
        _ => {
            return Err(SelectedRecursiveClassRegistryError::InvalidValue(
                "PCS profile",
            ));
        }
    };
    Ok(PcsParams {
        m,
        log_inv_rate,
        log_batch_size,
        profile,
    })
}

fn encode_spec(out: &mut Writer, spec: &PublicIoSpec) {
    encode_slice(out, spec.io_slice);
    out.u32(spec.io_len as u32);
    out.u8(spec.claims.len() as u8);
    for claim in &spec.claims {
        encode_slice(out, claim.slice);
        out.u32(claim.point.start as u32);
        out.u32(claim.point.end as u32);
        out.u32(claim.value as u32);
    }
}

fn decode_spec(
    input: &mut Reader<'_>,
) -> Result<PublicIoSpec, SelectedRecursiveClassRegistryError> {
    let io_slice = decode_slice(input)?;
    let io_len = input.usize_u32()?;
    let count = input.len_u8("public IO claims", MAX_PUBLIC_IO_CLAIMS)?;
    let mut claims = Vec::with_capacity(count);
    for _ in 0..count {
        let slice = decode_slice(input)?;
        let start = input.usize_u32()?;
        let end = input.usize_u32()?;
        let value = input.usize_u32()?;
        if start > end {
            return Err(SelectedRecursiveClassRegistryError::InvalidValue(
                "public IO claim range",
            ));
        }
        claims.push(IoClaimSpec {
            slice,
            point: start..end,
            value,
        });
    }
    Ok(PublicIoSpec {
        io_slice,
        io_len,
        claims,
    })
}

fn encode_block_vk_slices(out: &mut Writer, slices: &SelectedZkBlockRegionVkSlices) {
    encode_slices(out, &slices.wallet_a);
    encode_slices(out, &slices.meta_a);
    encode_slices(out, &slices.wallet_b);
    encode_slices(out, &slices.meta_b);
    encode_slices(out, &slices.owner_c);
    encode_slices(out, &slices.main_c);
}

fn decode_block_vk_slices(
    input: &mut Reader<'_>,
) -> Result<SelectedZkBlockRegionVkSlices, SelectedRecursiveClassRegistryError> {
    Ok(SelectedZkBlockRegionVkSlices {
        wallet_a: decode_slices(input)?,
        meta_a: decode_slices(input)?,
        wallet_b: decode_slices(input)?,
        meta_b: decode_slices(input)?,
        owner_c: decode_slices(input)?,
        main_c: decode_slices(input)?,
    })
}

fn encode_slices<const N: usize>(out: &mut Writer, slices: &[WitnessSlice; N]) {
    for slice in slices {
        encode_slice(out, *slice);
    }
}

fn decode_slices<const N: usize>(
    input: &mut Reader<'_>,
) -> Result<[WitnessSlice; N], SelectedRecursiveClassRegistryError> {
    try_array_from_fn(|_| decode_slice(input))
}

fn try_array_from_fn<T, E, F, const N: usize>(mut make: F) -> Result<[T; N], E>
where
    F: FnMut(usize) -> Result<T, E>,
{
    let mut values = Vec::with_capacity(N);
    for index in 0..N {
        values.push(make(index)?);
    }
    Ok(values
        .try_into()
        .unwrap_or_else(|_| unreachable!("fixed array length was preallocated")))
}

fn encode_slice(out: &mut Writer, slice: WitnessSlice) {
    out.u8(slice.log2_len as u8);
    out.u64(slice.index as u64);
}

fn decode_slice(
    input: &mut Reader<'_>,
) -> Result<WitnessSlice, SelectedRecursiveClassRegistryError> {
    Ok(WitnessSlice {
        log2_len: input.usize_u8()?,
        index: input.usize_u64()?,
    })
}

struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(64 * 1024),
        }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }
    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }
    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }
    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }
    fn u128(&mut self, value: u128) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }
    fn f128(&mut self, value: F128) {
        self.u64(value.lo);
        self.u64(value.hi);
    }
    fn digest(&mut self, value: &[u8; 32]) {
        self.bytes.extend_from_slice(value);
    }
    fn bytes(&mut self, value: &[u8]) {
        self.u64(value.len() as u64);
        self.bytes.extend_from_slice(value);
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], SelectedRecursiveClassRegistryError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(SelectedRecursiveClassRegistryError::LengthOverflow)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(SelectedRecursiveClassRegistryError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn finish(self) -> Result<(), SelectedRecursiveClassRegistryError> {
        if self.offset != self.bytes.len() {
            return Err(SelectedRecursiveClassRegistryError::LengthMismatch {
                expected: self.offset,
                actual: self.bytes.len(),
            });
        }
        Ok(())
    }

    fn u8(&mut self) -> Result<u8, SelectedRecursiveClassRegistryError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, SelectedRecursiveClassRegistryError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, SelectedRecursiveClassRegistryError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, SelectedRecursiveClassRegistryError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn u128(&mut self) -> Result<u128, SelectedRecursiveClassRegistryError> {
        Ok(u128::from_le_bytes(self.take(16)?.try_into().unwrap()))
    }
    fn f128(&mut self) -> Result<F128, SelectedRecursiveClassRegistryError> {
        Ok(F128::new(self.u64()?, self.u64()?))
    }
    fn digest(&mut self) -> Result<[u8; 32], SelectedRecursiveClassRegistryError> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    fn usize_u8(&mut self) -> Result<usize, SelectedRecursiveClassRegistryError> {
        Ok(usize::from(self.u8()?))
    }
    fn usize_u16(&mut self) -> Result<usize, SelectedRecursiveClassRegistryError> {
        Ok(usize::from(self.u16()?))
    }
    fn usize_u32(&mut self) -> Result<usize, SelectedRecursiveClassRegistryError> {
        usize::try_from(self.u32()?)
            .map_err(|_| SelectedRecursiveClassRegistryError::LengthOverflow)
    }
    fn usize_u64(&mut self) -> Result<usize, SelectedRecursiveClassRegistryError> {
        usize::try_from(self.u64()?)
            .map_err(|_| SelectedRecursiveClassRegistryError::LengthOverflow)
    }
    fn exact_count(
        &mut self,
        field: &'static str,
        expected: usize,
    ) -> Result<(), SelectedRecursiveClassRegistryError> {
        let actual = self.usize_u8()?;
        if actual != expected {
            return Err(SelectedRecursiveClassRegistryError::InvalidLength {
                field,
                actual: actual as u64,
                max: expected,
            });
        }
        Ok(())
    }
    fn len_u8(
        &mut self,
        field: &'static str,
        max: usize,
    ) -> Result<usize, SelectedRecursiveClassRegistryError> {
        let actual = self.usize_u8()?;
        self.check_len(field, actual, max)
    }
    fn len_u16(
        &mut self,
        field: &'static str,
        max: usize,
    ) -> Result<usize, SelectedRecursiveClassRegistryError> {
        let actual = self.usize_u16()?;
        self.check_len(field, actual, max)
    }
    fn check_len(
        &self,
        field: &'static str,
        actual: usize,
        max: usize,
    ) -> Result<usize, SelectedRecursiveClassRegistryError> {
        if actual > max {
            return Err(SelectedRecursiveClassRegistryError::InvalidLength {
                field,
                actual: actual as u64,
                max,
            });
        }
        Ok(actual)
    }
    fn byte_vec(
        &mut self,
        field: &'static str,
        max: usize,
    ) -> Result<Vec<u8>, SelectedRecursiveClassRegistryError> {
        Ok(self.byte_slice(field, max)?.to_vec())
    }
    fn byte_slice(
        &mut self,
        field: &'static str,
        max: usize,
    ) -> Result<&'a [u8], SelectedRecursiveClassRegistryError> {
        let raw = self.u64()?;
        let len = usize::try_from(raw)
            .map_err(|_| SelectedRecursiveClassRegistryError::LengthOverflow)?;
        self.check_len(field, len, max)?;
        self.take(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_shape(m: usize) -> FieldShape {
        FieldShape {
            m,
            k_log: m,
            k_skip: 6,
            const_pin: Some(0),
        }
    }

    fn fixture_pcs(m: usize) -> PcsParams {
        PcsParams {
            m: m + noid_ivc_core::pcs::LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 5,
            profile: LigeritoProfile::Fast,
        }
    }

    fn fixture_spec() -> PublicIoSpec {
        PublicIoSpec {
            io_slice: WitnessSlice {
                log2_len: 5,
                index: 1,
            },
            io_len: 20,
            claims: Vec::new(),
        }
    }

    fn fixture_slices<const N: usize>(log: usize, base: usize) -> [WitnessSlice; N] {
        std::array::from_fn(|index| WitnessSlice {
            log2_len: log,
            index: base + index,
        })
    }

    fn fixture_block(slot: usize) -> BlockWire {
        let tier = USER_TX_CLASS_TIERS[slot];
        let m = crate::acceptance::split_link::CANONICAL_BLOCK_CLASS_MS[slot];
        BlockWire {
            tier,
            config_bits: 0x1f,
            config_queries: noid_fri_binius::capsule::CAPSULE_NUM_QUERIES,
            config_tier: tier,
            shape: fixture_shape(m),
            pcs: fixture_pcs(m),
            spec: fixture_spec(),
            matrix_digest: [slot as u8; 32],
            vk_slices: SelectedZkBlockRegionVkSlices {
                wallet_a: fixture_slices(8, 10),
                meta_a: fixture_slices(8, 20),
                wallet_b: fixture_slices(8, 30),
                meta_b: fixture_slices(8, 40),
                owner_c: fixture_slices(8, 50),
                main_c: fixture_slices(8, 60),
            },
            child_vk_digests: [[slot as u8; 32]; 6],
            vk_digest: [slot as u8 + 10; 32],
            post_commit_digest: [slot as u8 + 20; 32],
        }
    }

    fn fixture_link(slot: usize) -> LinkWire {
        LinkWire {
            slot,
            shape: fixture_shape(24),
            pcs: fixture_pcs(24),
            spec: fixture_spec(),
            matrix_digest: [slot as u8 + 30; 32],
            post_commit_digest: [slot as u8 + 40; 32],
            genesis_digest: [50; 32],
            genesis_post_commit_digest: [51; 32],
            sidecar_vk_digest: [52; 32],
            b_spec: fixture_spec(),
            b_pcs: fixture_pcs(crate::acceptance::split_link::CANONICAL_BLOCK_CLASS_MS[slot]),
            b_sidecar_vk_digest: [slot as u8 + 60; 32],
            b_post_commit_digest: [slot as u8 + 70; 32],
        }
    }

    fn fixture_wire() -> RegistryWire {
        let blocks = std::array::from_fn(fixture_block);
        let descriptor_slots = std::array::from_fn(|slot| LadderSlotInfo {
            tier: USER_TX_CLASS_TIERS[slot],
            b_shape: blocks[slot].shape,
            b_digest: blocks[slot].matrix_digest,
            b_pcs_params: blocks[slot].pcs.clone(),
            b_post_commit_class_digest: blocks[slot].post_commit_digest,
            b_sidecar_vk_digest: blocks[slot].vk_digest,
        });
        RegistryWire {
            blocks,
            descriptor_shape: fixture_shape(24),
            descriptor_pcs: fixture_pcs(24),
            descriptor_slots,
            link_vk: LinkVkWire {
                leaf_purpose: [80; 32],
                leaf_tx_tile_log: 1,
                leaf_subchannels: vec![SubchannelWire {
                    schedule: vec![
                        TranscriptOp::Absorb(vec![None, Some(7)]),
                        TranscriptOp::Squeeze(2),
                    ],
                    iv: [F128::new(1, 2), F128::new(3, 4)],
                }],
                leaf_slices: fixture_slices(8, 70),
                leaf_digest: [81; 32],
                path_purpose: [82; 32],
                path_w_log: 8,
                path_block_log: 4,
                path_slices: fixture_slices(8, 80),
                path_families: vec![MerkleRegionFamily::PairedUpdate {
                    offset: 3,
                    n_updates: 2,
                    iv: [F128::new(5, 6), F128::new(7, 8)],
                }],
                path_digest: [83; 32],
                vk_digest: [84; 32],
            },
            links: std::array::from_fn(fixture_link),
            genesis_package: vec![1, 2, 3, 4],
        }
    }

    #[test]
    fn outer_artifact_roundtrip_and_tamper_fail_closed() {
        let body = b"compact-registry-fixture".to_vec();
        let encoded = finish_artifact(body.clone()).unwrap();
        assert_eq!(preflight_artifact(&encoded).unwrap(), body);

        let mut tampered = encoded.clone();
        tampered[REGISTRY_HEADER_BYTES] ^= 1;
        assert!(matches!(
            preflight_artifact(&tampered),
            Err(SelectedRecursiveClassRegistryError::DigestMismatch)
        ));
        assert!(preflight_artifact(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(matches!(
            preflight_artifact(&trailing),
            Err(SelectedRecursiveClassRegistryError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn compact_body_codec_roundtrips_without_serde() {
        let expected = fixture_wire();
        let mut writer = Writer::new();
        encode_registry_body(&mut writer, &expected);
        let encoded = writer.finish();
        preflight_registry_body(&encoded).unwrap();
        let actual = decode_registry_body(&encoded).unwrap();
        assert_eq!(actual.blocks[3].tier, 255);
        assert_eq!(
            actual.blocks[2].matrix_digest,
            expected.blocks[2].matrix_digest
        );
        assert_eq!(actual.descriptor_shape, expected.descriptor_shape);
        assert_eq!(actual.descriptor_slots[1].tier, 32);
        assert_eq!(actual.link_vk.leaf_subchannels[0].schedule.len(), 2);
        assert_eq!(actual.link_vk.path_families, expected.link_vk.path_families);
        assert_eq!(
            actual.links[3].post_commit_digest,
            expected.links[3].post_commit_digest
        );
        assert_eq!(actual.genesis_package, expected.genesis_package);
    }

    #[test]
    fn nested_length_bomb_is_rejected_before_payload_copy() {
        let mut writer = Writer::new();
        writer.u64((MAX_GENESIS_PACKAGE_BYTES as u64) + 1);
        let bytes = writer.finish();
        let mut reader = Reader::new(&bytes);
        assert!(matches!(
            reader.byte_vec("genesis package", MAX_GENESIS_PACKAGE_BYTES),
            Err(SelectedRecursiveClassRegistryError::InvalidLength {
                field: "genesis package",
                ..
            })
        ));

        let fixture = fixture_wire();
        let mut writer = Writer::new();
        encode_registry_body(&mut writer, &fixture);
        let mut body = writer.finish();
        let genesis_len_offset = body.len() - fixture.genesis_package.len() - 8;
        body[genesis_len_offset..genesis_len_offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(
            preflight_registry_body(&body),
            Err(SelectedRecursiveClassRegistryError::LengthOverflow)
                | Err(SelectedRecursiveClassRegistryError::InvalidLength { .. })
        ));
    }

    #[test]
    fn compact_wire_source_has_no_matrix_or_sample_fields() {
        let source = include_str!("class_registry.rs");
        let retained = source
            .split("struct RegistryWire")
            .nth(1)
            .unwrap()
            .split("/// Encode a fully materialized")
            .next()
            .unwrap();
        assert!(!retained.contains("FieldR1cs"));
        assert!(!retained.contains("BlockProofEnvelope"));
        assert!(!retained.contains("sample"));
        assert_eq!(retained.matches("genesis_package").count(), 1);
    }
}
