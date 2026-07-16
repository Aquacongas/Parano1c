// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Native PagedSpend primitive.
//!
//! A page is the existing 323-byte Tx8x2 record. Bits 10 and 11 of its
//! validity bitmap delimit an atomic logical transaction; the input/output
//! records and page hash otherwise keep their existing representation.

use std::collections::HashSet;

use noid_core::Block128;
use noid_poseidon2b::native::{capacity_iv, DomainTag, Poseidon2bSponge};
use noid_poseidon2b::primitives::{Address, TxBodyHash};
use noid_tx::{
    TxBody, TxInput, TxOutput, WireError, TX_BODY_WIRE_SIZE, TX_INPUTS, TX_OUTPUTS,
    TX_VALIDITY_MASK,
};

use crate::geometry::{
    ProofClass, B255_INPUT_CAPACITY, B255_LIVE_AUTHORIZATION_CAPACITY, B255_OUTPUT_CAPACITY,
    B255_PAGE_CAPACITY,
};

const TAG_PAGEDTX: DomainTag = DomainTag::new(b"PAGEDTX_");

pub const PAGEDTX_VERSION: u16 = 1;
pub const PAGEDSPEND_START_BIT: u16 = 1 << 10;
pub const PAGEDSPEND_END_BIT: u16 = 1 << 11;
const PAGEDSPEND_MARKER_MASK: u16 = PAGEDSPEND_START_BIT | PAGEDSPEND_END_BIT;
const PAGEDSPEND_VALIDITY_MASK: u16 = TX_VALIDITY_MASK | PAGEDSPEND_MARKER_MASK;

pub const MAX_PAGEDSPEND_PAGES: usize = 128;
pub const MAX_PAGEDSPEND_INPUTS: usize = 1_020;
pub const MAX_PAGEDSPEND_OUTPUTS: usize = MAX_PAGEDSPEND_PAGES * TX_OUTPUTS;

pub const MAX_BLOCK_USER_PAGES: usize = B255_PAGE_CAPACITY;
pub const MAX_BLOCK_LOGICAL_TRANSACTIONS: usize = B255_LIVE_AUTHORIZATION_CAPACITY;
pub const MAX_BLOCK_LIVE_INPUTS: usize = B255_INPUT_CAPACITY;
pub const MAX_BLOCK_LIVE_OUTPUTS: usize = B255_OUTPUT_CAPACITY;

pub const PAGEDSPEND_INTENT_MARKER: u8 = 0xA3;
pub const MAX_PAGEDSPEND_AUTHORIZATION_BYTES: usize = 61_012;
pub const PAGEDSPEND_INTENT_FIXED_OVERHEAD: usize = 1 + 2 + 4;
pub const MAX_PAGEDSPEND_INTENT_BYTES: usize = PAGEDSPEND_INTENT_FIXED_OVERHEAD
    + MAX_PAGEDSPEND_PAGES * TX_BODY_WIRE_SIZE
    + MAX_PAGEDSPEND_AUTHORIZATION_BYTES;

const _: () = assert!(MAX_PAGEDSPEND_INPUTS <= MAX_PAGEDSPEND_PAGES * TX_INPUTS);
const _: () = assert!(MAX_PAGEDSPEND_OUTPUTS == MAX_PAGEDSPEND_PAGES * TX_OUTPUTS);
const _: () = assert!(MAX_PAGEDSPEND_PAGES <= u16::MAX as usize);
const _: () = assert!(MAX_PAGEDSPEND_INPUTS <= u16::MAX as usize);
const _: () = assert!(MAX_PAGEDSPEND_OUTPUTS <= u16::MAX as usize);
const _: () = assert!(MAX_PAGEDSPEND_INTENT_BYTES == 102_363);
const _: () = assert!(MAX_BLOCK_USER_PAGES == 255);
const _: () = assert!(MAX_BLOCK_LOGICAL_TRANSACTIONS == 255);
const _: () = assert!(MAX_BLOCK_LIVE_INPUTS == 1_020);
const _: () = assert!(MAX_BLOCK_LIVE_OUTPUTS == 510);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxPage {
    pub body: TxBody,
}

impl TxPage {
    pub fn new(body: TxBody) -> Result<Self, PagedSpendError> {
        validate_page_shape(&body, 0)?;
        Ok(Self { body })
    }

    #[inline]
    pub fn is_start(&self) -> bool {
        self.body.validity_bitmap & PAGEDSPEND_START_BIT != 0
    }

    #[inline]
    pub fn is_end(&self) -> bool {
        self.body.validity_bitmap & PAGEDSPEND_END_BIT != 0
    }

    #[inline]
    pub fn page_hash(&self) -> TxBodyHash {
        self.body.txid()
    }

    pub fn to_bytes(&self) -> Result<[u8; TX_BODY_WIRE_SIZE], PagedSpendError> {
        validate_page_shape(&self.body, 0)?;
        Ok(encode_page_body(&self.body))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PagedSpendError> {
        if bytes.len() != TX_BODY_WIRE_SIZE {
            return Err(if bytes.len() < TX_BODY_WIRE_SIZE {
                PagedSpendError::Wire(WireError::Truncated)
            } else {
                PagedSpendError::Wire(WireError::TrailingBytes)
            });
        }
        let mut src = bytes;
        let body = decode_page_body(&mut src)?;
        debug_assert!(src.is_empty());
        Self::new(body)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PagedSpendFacts {
    pub logical_txid: TxBodyHash,
    pub input_owner: Address,
    pub epoch_anchor: [u8; 32],
    pub fee: u64,
    pub live_inputs: u16,
    pub live_outputs: u16,
    pub input_sum: u128,
    pub output_sum: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PagedSpendStreamFacts {
    pub proof_class: ProofClass,
    pub groups: Vec<PagedSpendFacts>,
    pub page_count: u16,
    pub logical_count: u16,
    pub live_inputs: u16,
    pub live_outputs: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalPagedSpendAuth {
    pub logical_txid: TxBodyHash,
    pub input_owner: Address,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PagedSpendIntent {
    pub pages: Vec<TxPage>,
    pub authorization_bytes: Vec<u8>,
}

impl PagedSpendIntent {
    pub fn new(pages: Vec<TxPage>, authorization_bytes: Vec<u8>) -> Result<Self, PagedSpendError> {
        validate_paged_spend(&pages)?;
        if authorization_bytes.len() > MAX_PAGEDSPEND_AUTHORIZATION_BYTES {
            return Err(PagedSpendError::AuthorizationTooLarge {
                actual: authorization_bytes.len(),
            });
        }
        Ok(Self {
            pages,
            authorization_bytes,
        })
    }

    #[inline]
    pub fn logical_txid(&self) -> TxBodyHash {
        hash_paged_spend_unchecked(&self.pages)
    }

    pub fn encode(&self) -> Result<Vec<u8>, PagedSpendError> {
        validate_paged_spend(&self.pages)?;
        if self.authorization_bytes.len() > MAX_PAGEDSPEND_AUTHORIZATION_BYTES {
            return Err(PagedSpendError::AuthorizationTooLarge {
                actual: self.authorization_bytes.len(),
            });
        }
        let auth_len = u32::try_from(self.authorization_bytes.len())
            .map_err(|_| PagedSpendError::Wire(WireError::LengthOverflow))?;
        let mut out = Vec::with_capacity(
            PAGEDSPEND_INTENT_FIXED_OVERHEAD
                + self.pages.len() * TX_BODY_WIRE_SIZE
                + self.authorization_bytes.len(),
        );
        out.push(PAGEDSPEND_INTENT_MARKER);
        out.extend_from_slice(&(self.pages.len() as u16).to_le_bytes());
        for page in &self.pages {
            out.extend_from_slice(&page.to_bytes()?);
        }
        out.extend_from_slice(&auth_len.to_le_bytes());
        out.extend_from_slice(&self.authorization_bytes);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PagedSpendError> {
        let mut src = bytes;
        if take(&mut src, 1)?[0] != PAGEDSPEND_INTENT_MARKER {
            return Err(PagedSpendError::Wire(WireError::BadMarker));
        }
        let page_count = take_u16(&mut src)? as usize;
        validate_page_count(page_count)?;
        let page_bytes = page_count
            .checked_mul(TX_BODY_WIRE_SIZE)
            .ok_or(PagedSpendError::Wire(WireError::LengthOverflow))?;
        let encoded_pages = take(&mut src, page_bytes)?;
        let mut pages = Vec::with_capacity(page_count);
        for bytes in encoded_pages.chunks_exact(TX_BODY_WIRE_SIZE) {
            pages.push(TxPage::from_bytes(bytes)?);
        }
        let auth_len = take_u32(&mut src)? as usize;
        if auth_len > MAX_PAGEDSPEND_AUTHORIZATION_BYTES {
            return Err(PagedSpendError::AuthorizationTooLarge { actual: auth_len });
        }
        let authorization_bytes = take(&mut src, auth_len)?.to_vec();
        if !src.is_empty() {
            return Err(PagedSpendError::Wire(WireError::TrailingBytes));
        }
        Self::new(pages, authorization_bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PagedSpendError {
    Wire(WireError),
    PageCount {
        actual: usize,
    },
    ReservedBitmapBits {
        page: usize,
        bitmap: u16,
    },
    CoinbasePage {
        page: usize,
    },
    DeadInputNotZero {
        page: usize,
        slot: usize,
    },
    DeadOutputNotZero {
        page: usize,
        slot: usize,
    },
    MissingStart,
    UnexpectedStart {
        page: usize,
    },
    MissingEnd,
    UnexpectedEnd {
        page: usize,
    },
    OwnerMismatch {
        page: usize,
    },
    EpochMismatch {
        page: usize,
    },
    ContinuationFee {
        page: usize,
    },
    SparseInputs {
        page: usize,
        slot: usize,
    },
    SparseOutputs {
        page: usize,
        slot: usize,
    },
    NoLiveInputs,
    TooManyInputs {
        actual: usize,
    },
    TooManyOutputs {
        actual: usize,
    },
    NonMinimalPageCount {
        actual: usize,
        required: usize,
    },
    DuplicateInputSlot {
        slot: u32,
    },
    DuplicateOutputSlot {
        slot: u32,
    },
    InputOutputSlotOverlap {
        slot: u32,
    },
    InputSumOverflow,
    OutputSumOverflow,
    OutputPlusFeeOverflow,
    BalanceMismatch {
        input_sum: u128,
        output_sum: u128,
        fee: u64,
    },
    AuthorizationTooLarge {
        actual: usize,
    },
    UnterminatedGroup {
        start_page: usize,
    },
    TooManyGroups {
        actual: usize,
        capacity: usize,
    },
    BlockPageLimit {
        actual: usize,
        capacity: usize,
    },
    ProofClassMismatch {
        expected: ProofClass,
        actual: ProofClass,
    },
    BlockInputLimit {
        actual: usize,
        capacity: usize,
    },
    BlockOutputLimit {
        actual: usize,
        capacity: usize,
    },
}

impl std::fmt::Display for PagedSpendError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for PagedSpendError {}

impl From<WireError> for PagedSpendError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

pub fn hash_paged_spend(pages: &[TxPage]) -> Result<TxBodyHash, PagedSpendError> {
    validate_paged_spend(pages)?;
    Ok(hash_paged_spend_unchecked(pages))
}

fn hash_paged_spend_unchecked(pages: &[TxPage]) -> TxBodyHash {
    debug_assert!(!pages.is_empty() && pages.len() <= MAX_PAGEDSPEND_PAGES);
    let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(TAG_PAGEDTX));
    sponge.absorb_pair(
        Block128::from(PAGEDTX_VERSION as u128),
        Block128::from(pages.len() as u128),
    );
    for page in pages {
        let [lo, hi] = page.page_hash().as_fields();
        sponge.absorb_pair(lo, hi);
    }
    TxBodyHash(sponge.finalize())
}

pub fn canonical_paged_spend_auth(
    pages: &[TxPage],
) -> Result<CanonicalPagedSpendAuth, PagedSpendError> {
    let facts = validate_paged_spend(pages)?;
    Ok(CanonicalPagedSpendAuth {
        logical_txid: facts.logical_txid,
        input_owner: facts.input_owner,
    })
}

/// Parse and validate the canonical flat user-page stream of one block.
///
/// The returned groups are in physical order and are the exact logical leaves
/// used by authorization compaction and the transaction root. This function
/// does not activate a block wire format; it is the native twin for the
/// production B64/B255 relation.
pub fn validate_paged_spend_stream(
    pages: &[TxPage],
) -> Result<PagedSpendStreamFacts, PagedSpendError> {
    let Some(proof_class) = ProofClass::for_page_count(pages.len()) else {
        return Err(PagedSpendError::BlockPageLimit {
            actual: pages.len(),
            capacity: MAX_BLOCK_USER_PAGES,
        });
    };
    validate_paged_spend_stream_for_class(pages, proof_class)
}

/// Validate a page stream against its authenticated proof class.
///
/// The class is canonical: 0..=64 pages are B64 and 65..=255 pages are B255.
/// A caller cannot voluntarily place a small block in m24 or a large block in
/// m23, which keeps class selection deterministic across consensus, proving
/// and mining.
pub fn validate_paged_spend_stream_for_class(
    pages: &[TxPage],
    proof_class: ProofClass,
) -> Result<PagedSpendStreamFacts, PagedSpendError> {
    if pages.len() > proof_class.page_capacity() {
        return Err(PagedSpendError::BlockPageLimit {
            actual: pages.len(),
            capacity: proof_class.page_capacity(),
        });
    }
    let expected =
        ProofClass::for_page_count(pages.len()).ok_or(PagedSpendError::BlockPageLimit {
            actual: pages.len(),
            capacity: MAX_BLOCK_USER_PAGES,
        })?;
    if expected != proof_class {
        return Err(PagedSpendError::ProofClassMismatch {
            expected,
            actual: proof_class,
        });
    }
    let mut groups = Vec::with_capacity(pages.len());
    let mut cursor = 0usize;
    while cursor < pages.len() {
        let start = cursor;
        let Some(relative_end) = pages[start..].iter().position(TxPage::is_end) else {
            return Err(PagedSpendError::UnterminatedGroup { start_page: start });
        };
        let end = start + relative_end + 1;
        groups.push(validate_paged_spend(&pages[start..end])?);
        if groups.len() > proof_class.live_authorization_capacity() {
            return Err(PagedSpendError::TooManyGroups {
                actual: groups.len(),
                capacity: proof_class.live_authorization_capacity(),
            });
        }
        cursor = end;
    }

    let live_inputs = groups
        .iter()
        .try_fold(0usize, |sum, group| {
            sum.checked_add(group.live_inputs as usize)
        })
        .ok_or(PagedSpendError::BlockInputLimit {
            actual: usize::MAX,
            capacity: proof_class.input_capacity(),
        })?;
    if live_inputs > proof_class.input_capacity() {
        return Err(PagedSpendError::BlockInputLimit {
            actual: live_inputs,
            capacity: proof_class.input_capacity(),
        });
    }
    let live_outputs = groups
        .iter()
        .try_fold(0usize, |sum, group| {
            sum.checked_add(group.live_outputs as usize)
        })
        .ok_or(PagedSpendError::BlockOutputLimit {
            actual: usize::MAX,
            capacity: proof_class.output_capacity(),
        })?;
    if live_outputs > proof_class.output_capacity() {
        return Err(PagedSpendError::BlockOutputLimit {
            actual: live_outputs,
            capacity: proof_class.output_capacity(),
        });
    }

    // Block-wide slot uniqueness is checked here as part of the flat-stream
    // native twin, before any state read or capsule verification.
    let mut input_slots = HashSet::with_capacity(live_inputs);
    let mut output_slots = HashSet::with_capacity(live_outputs);
    for page in pages {
        for (_, input) in page.body.live_inputs() {
            if !input_slots.insert(input.slot_index) {
                return Err(PagedSpendError::DuplicateInputSlot {
                    slot: input.slot_index,
                });
            }
        }
        for (_, output) in page.body.live_outputs() {
            if !output_slots.insert(output.slot_index) {
                return Err(PagedSpendError::DuplicateOutputSlot {
                    slot: output.slot_index,
                });
            }
        }
    }
    if let Some(slot) = input_slots.intersection(&output_slots).next() {
        return Err(PagedSpendError::InputOutputSlotOverlap { slot: *slot });
    }

    Ok(PagedSpendStreamFacts {
        proof_class,
        page_count: pages.len() as u16,
        logical_count: groups.len() as u16,
        live_inputs: live_inputs as u16,
        live_outputs: live_outputs as u16,
        groups,
    })
}

pub fn validate_paged_spend(pages: &[TxPage]) -> Result<PagedSpendFacts, PagedSpendError> {
    validate_page_count(pages.len())?;
    for (page_index, page) in pages.iter().enumerate() {
        validate_page_shape(&page.body, page_index)?;
    }
    if !pages[0].is_start() {
        return Err(PagedSpendError::MissingStart);
    }
    if !pages[pages.len() - 1].is_end() {
        return Err(PagedSpendError::MissingEnd);
    }
    for (index, page) in pages.iter().enumerate() {
        if index != 0 && page.is_start() {
            return Err(PagedSpendError::UnexpectedStart { page: index });
        }
        if index + 1 != pages.len() && page.is_end() {
            return Err(PagedSpendError::UnexpectedEnd { page: index });
        }
        if page.body.input_owner != pages[0].body.input_owner {
            return Err(PagedSpendError::OwnerMismatch { page: index });
        }
        if page.body.epoch_anchor != pages[0].body.epoch_anchor {
            return Err(PagedSpendError::EpochMismatch { page: index });
        }
        if index != 0 && page.body.fee != 0 {
            return Err(PagedSpendError::ContinuationFee { page: index });
        }
    }

    let mut input_slots = HashSet::with_capacity(MAX_PAGEDSPEND_INPUTS);
    let mut output_slots = HashSet::with_capacity(MAX_PAGEDSPEND_OUTPUTS);
    let mut live_inputs = 0usize;
    let mut live_outputs = 0usize;
    let mut input_sum = 0u128;
    let mut output_sum = 0u128;
    let mut input_gap = false;
    let mut output_gap = false;

    for (page_index, page) in pages.iter().enumerate() {
        for (slot, input) in page.body.inputs.iter().enumerate() {
            if page.body.input_is_live(slot) {
                if input_gap {
                    return Err(PagedSpendError::SparseInputs {
                        page: page_index,
                        slot,
                    });
                }
                live_inputs += 1;
                if live_inputs > MAX_PAGEDSPEND_INPUTS {
                    return Err(PagedSpendError::TooManyInputs {
                        actual: live_inputs,
                    });
                }
                if !input_slots.insert(input.slot_index) {
                    return Err(PagedSpendError::DuplicateInputSlot {
                        slot: input.slot_index,
                    });
                }
                input_sum = input_sum
                    .checked_add(input.amount as u128)
                    .ok_or(PagedSpendError::InputSumOverflow)?;
            } else {
                input_gap = true;
            }
        }
        for (slot, output) in page.body.outputs.iter().enumerate() {
            if page.body.output_is_live(slot) {
                if output_gap {
                    return Err(PagedSpendError::SparseOutputs {
                        page: page_index,
                        slot,
                    });
                }
                live_outputs += 1;
                if live_outputs > MAX_PAGEDSPEND_OUTPUTS {
                    return Err(PagedSpendError::TooManyOutputs {
                        actual: live_outputs,
                    });
                }
                if !output_slots.insert(output.slot_index) {
                    return Err(PagedSpendError::DuplicateOutputSlot {
                        slot: output.slot_index,
                    });
                }
                output_sum = output_sum
                    .checked_add(output.amount as u128)
                    .ok_or(PagedSpendError::OutputSumOverflow)?;
            } else {
                output_gap = true;
            }
        }
    }
    if live_inputs == 0 {
        return Err(PagedSpendError::NoLiveInputs);
    }
    if let Some(slot) = input_slots.intersection(&output_slots).next() {
        return Err(PagedSpendError::InputOutputSlotOverlap { slot: *slot });
    }
    let required_pages = 1usize
        .max(live_inputs.div_ceil(TX_INPUTS))
        .max(live_outputs.div_ceil(TX_OUTPUTS));
    if pages.len() != required_pages {
        return Err(PagedSpendError::NonMinimalPageCount {
            actual: pages.len(),
            required: required_pages,
        });
    }
    let fee = pages[0].body.fee;
    let expected = output_sum
        .checked_add(fee as u128)
        .ok_or(PagedSpendError::OutputPlusFeeOverflow)?;
    if input_sum != expected {
        return Err(PagedSpendError::BalanceMismatch {
            input_sum,
            output_sum,
            fee,
        });
    }
    Ok(PagedSpendFacts {
        logical_txid: hash_paged_spend_unchecked(pages),
        input_owner: pages[0].body.input_owner,
        epoch_anchor: pages[0].body.epoch_anchor,
        fee,
        live_inputs: live_inputs as u16,
        live_outputs: live_outputs as u16,
        input_sum,
        output_sum,
    })
}

fn validate_page_count(count: usize) -> Result<(), PagedSpendError> {
    if !(1..=MAX_PAGEDSPEND_PAGES).contains(&count) {
        return Err(PagedSpendError::PageCount { actual: count });
    }
    Ok(())
}

fn validate_page_shape(body: &TxBody, page: usize) -> Result<(), PagedSpendError> {
    if body.validity_bitmap & !PAGEDSPEND_VALIDITY_MASK != 0 {
        return Err(PagedSpendError::ReservedBitmapBits {
            page,
            bitmap: body.validity_bitmap,
        });
    }
    if body.is_coinbase {
        return Err(PagedSpendError::CoinbasePage { page });
    }
    for (slot, input) in body.inputs.iter().enumerate() {
        if !body.input_is_live(slot) && *input != TxInput::dummy() {
            return Err(PagedSpendError::DeadInputNotZero { page, slot });
        }
    }
    for (slot, output) in body.outputs.iter().enumerate() {
        if !body.output_is_live(slot) && *output != TxOutput::dummy() {
            return Err(PagedSpendError::DeadOutputNotZero { page, slot });
        }
    }
    Ok(())
}

fn encode_page_body(body: &TxBody) -> [u8; TX_BODY_WIRE_SIZE] {
    let mut out = Vec::with_capacity(TX_BODY_WIRE_SIZE);
    out.extend_from_slice(&body.epoch_anchor);
    out.extend_from_slice(&body.fee.to_le_bytes());
    out.extend_from_slice(&body.input_owner.0);
    for input in &body.inputs {
        input.encode(&mut out);
    }
    for output in &body.outputs {
        output.encode(&mut out);
    }
    out.extend_from_slice(&body.validity_bitmap.to_le_bytes());
    out.push(body.is_coinbase as u8);
    out.try_into()
        .expect("TxPage retains the 323-byte body wire")
}

fn decode_page_body(src: &mut &[u8]) -> Result<TxBody, PagedSpendError> {
    let epoch_anchor = take(src, 32)?.try_into().unwrap();
    let fee = u64::from_le_bytes(take(src, 8)?.try_into().unwrap());
    let input_owner = Address(take(src, 32)?.try_into().unwrap());
    let mut inputs = [TxInput::dummy(); TX_INPUTS];
    for input in &mut inputs {
        *input = TxInput::decode(src)?;
    }
    let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
    for output in &mut outputs {
        *output = TxOutput::decode(src)?;
    }
    let validity_bitmap = take_u16(src)?;
    let is_coinbase = match take(src, 1)?[0] {
        0 => false,
        1 => true,
        _ => return Err(PagedSpendError::Wire(WireError::InvalidBool)),
    };
    Ok(TxBody {
        epoch_anchor,
        fee,
        input_owner,
        inputs,
        outputs,
        validity_bitmap,
        is_coinbase,
    })
}

fn take<'a>(src: &mut &'a [u8], len: usize) -> Result<&'a [u8], PagedSpendError> {
    if src.len() < len {
        return Err(PagedSpendError::Wire(WireError::Truncated));
    }
    let (head, tail) = src.split_at(len);
    *src = tail;
    Ok(head)
}

fn take_u16(src: &mut &[u8]) -> Result<u16, PagedSpendError> {
    Ok(u16::from_le_bytes(take(src, 2)?.try_into().unwrap()))
}

fn take_u32(src: &mut &[u8]) -> Result<u32, PagedSpendError> {
    Ok(u32::from_le_bytes(take(src, 4)?.try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_tx::output_bitmap_bit;

    fn owner() -> Address {
        Address([0x42; 32])
    }

    fn pages(input_count: usize, output_count: usize, fee: u64) -> Vec<TxPage> {
        let page_count = 1usize
            .max(input_count.div_ceil(TX_INPUTS))
            .max(output_count.div_ceil(TX_OUTPUTS));
        const INPUT_AMOUNT: u64 = 100_000;
        let output_total = input_count as u64 * INPUT_AMOUNT - fee;
        let mut pages = Vec::with_capacity(page_count);
        for page_index in 0..page_count {
            let mut inputs = [TxInput::dummy(); TX_INPUTS];
            let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
            let mut bitmap = 0u16;
            for slot in 0..TX_INPUTS {
                let index = page_index * TX_INPUTS + slot;
                if index < input_count {
                    inputs[slot] = TxInput {
                        slot_index: index as u32 + 1,
                        amount: INPUT_AMOUNT,
                        creation_id: index as u64 + 50,
                    };
                    bitmap |= 1 << slot;
                }
            }
            for slot in 0..TX_OUTPUTS {
                let index = page_index * TX_OUTPUTS + slot;
                if index < output_count {
                    outputs[slot] = TxOutput {
                        slot_index: 10_000 + index as u32,
                        amount: if index + 1 == output_count {
                            output_total - (output_count as u64 - 1)
                        } else {
                            1
                        },
                        owner: owner(),
                    };
                    bitmap |= output_bitmap_bit(slot);
                }
            }
            if page_index == 0 {
                bitmap |= PAGEDSPEND_START_BIT;
            }
            if page_index + 1 == page_count {
                bitmap |= PAGEDSPEND_END_BIT;
            }
            pages.push(
                TxPage::new(TxBody {
                    epoch_anchor: [9u8; 32],
                    fee: if page_index == 0 { fee } else { 0 },
                    input_owner: owner(),
                    inputs,
                    outputs,
                    validity_bitmap: bitmap,
                    is_coinbase: false,
                })
                .unwrap(),
            );
        }
        pages
    }

    #[test]
    fn one_page_round_trip_and_hash_are_binding() {
        let pages = pages(1, 1, 3);
        let facts = validate_paged_spend(&pages).unwrap();
        assert_eq!(facts.live_inputs, 1);
        assert_eq!(facts.live_outputs, 1);
        assert_eq!(facts.input_sum, 100_000);
        assert_eq!(facts.output_sum, 99_997);
        assert_eq!(facts.logical_txid, hash_paged_spend(&pages).unwrap());
        assert_eq!(
            facts.logical_txid.0,
            [
                144, 52, 42, 186, 154, 94, 96, 45, 163, 83, 87, 77, 200, 176, 104, 60, 207, 115,
                158, 254, 28, 206, 83, 209, 198, 238, 59, 242, 133, 203, 62, 33,
            ],
            "PAGEDTX_ v1 one-page vector drifted",
        );

        let intent = PagedSpendIntent::new(pages.clone(), vec![1, 2, 3]).unwrap();
        let encoded = intent.encode().unwrap();
        assert_eq!(PagedSpendIntent::decode(&encoded).unwrap(), intent);

        let mut changed = pages;
        changed[0].body.epoch_anchor[0] ^= 1;
        assert_ne!(
            hash_paged_spend(&changed).unwrap(),
            facts.logical_txid,
            "logical hash must bind the exact page hash"
        );
    }

    #[test]
    fn hundred_inputs_are_one_thirteen_page_transaction() {
        let pages = pages(100, 1, 15_700);
        let facts = validate_paged_spend(&pages).unwrap();
        assert_eq!(pages.len(), 13);
        assert_eq!(facts.live_inputs, 100);
        assert_eq!(facts.live_outputs, 1);
        assert_eq!(
            facts.logical_txid.0,
            [
                146, 51, 163, 26, 201, 252, 165, 184, 7, 167, 210, 110, 137, 207, 62, 174, 217,
                182, 224, 6, 154, 133, 49, 117, 219, 162, 161, 240, 76, 37, 249, 65,
            ],
            "PAGEDTX_ v1 100-input/13-page vector drifted",
        );
        let statement = canonical_paged_spend_auth(&pages).unwrap();
        assert_eq!(statement.logical_txid, facts.logical_txid);
        assert_eq!(statement.input_owner, owner());
    }

    #[test]
    fn maximum_input_group_uses_exactly_128_pages() {
        let pages = pages(1_020, 1, 5_000);
        let facts = validate_paged_spend(&pages).unwrap();
        assert_eq!(pages.len(), MAX_PAGEDSPEND_PAGES);
        assert_eq!(facts.live_inputs, 1_020);
        assert_eq!(
            facts.logical_txid.0,
            [
                45, 143, 66, 164, 239, 252, 242, 233, 221, 159, 123, 187, 161, 13, 1, 61, 153, 164,
                221, 118, 174, 187, 6, 222, 23, 120, 245, 210, 243, 96, 115, 252,
            ],
            "PAGEDTX_ v1 1020-input/128-page vector drifted",
        );
        assert_eq!(
            validate_paged_spend_stream_for_class(&pages, ProofClass::B64),
            Err(PagedSpendError::BlockPageLimit {
                actual: 128,
                capacity: 64,
            })
        );
        let block = validate_paged_spend_stream_for_class(&pages, ProofClass::B255).unwrap();
        assert_eq!(block.proof_class, ProofClass::B255);
        assert_eq!(block.logical_count, 1);
        assert_eq!(block.live_inputs, 1_020);
    }

    #[test]
    fn page_order_changes_logical_hash() {
        let original = pages(9, 1, 3);
        let original_hash = hash_paged_spend(&original).unwrap();
        let mut reordered = original.clone();
        reordered.swap(0, 1);
        // Hash order is binding even before canonical boundary validation.
        assert_ne!(hash_paged_spend_unchecked(&reordered), original_hash);
        assert!(validate_paged_spend(&reordered).is_err());
    }

    #[test]
    fn malformed_group_boundaries_and_continuation_fee_reject() {
        let mut missing_start = pages(9, 1, 3);
        missing_start[0].body.validity_bitmap &= !PAGEDSPEND_START_BIT;
        assert_eq!(
            validate_paged_spend(&missing_start),
            Err(PagedSpendError::MissingStart)
        );

        let mut early_end = pages(9, 1, 3);
        early_end[0].body.validity_bitmap |= PAGEDSPEND_END_BIT;
        assert_eq!(
            validate_paged_spend(&early_end),
            Err(PagedSpendError::UnexpectedEnd { page: 0 })
        );

        let mut continuation_fee = pages(9, 1, 3);
        continuation_fee[1].body.fee = 1;
        assert_eq!(
            validate_paged_spend(&continuation_fee),
            Err(PagedSpendError::ContinuationFee { page: 1 })
        );
    }

    #[test]
    fn sparse_mixed_and_unbalanced_groups_reject() {
        let mut sparse = pages(9, 1, 3);
        sparse[0].body.validity_bitmap &= !(1 << 7);
        sparse[0].body.inputs[7] = TxInput::dummy();
        assert!(matches!(
            validate_paged_spend(&sparse),
            Err(PagedSpendError::SparseInputs { .. })
        ));

        let mut mixed = pages(9, 1, 3);
        mixed[1].body.input_owner = Address([7u8; 32]);
        assert_eq!(
            validate_paged_spend(&mixed),
            Err(PagedSpendError::OwnerMismatch { page: 1 })
        );

        let mut unbalanced = pages(9, 1, 3);
        unbalanced[0].body.outputs[0].amount += 1;
        assert!(matches!(
            validate_paged_spend(&unbalanced),
            Err(PagedSpendError::BalanceMismatch { .. })
        ));
    }

    #[test]
    fn wire_rejects_trailing_truncated_and_oversized_authorization() {
        let intent = PagedSpendIntent::new(pages(1, 1, 3), vec![5; 20]).unwrap();
        let encoded = intent.encode().unwrap();
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            PagedSpendIntent::decode(&trailing),
            Err(PagedSpendError::Wire(WireError::TrailingBytes))
        );
        assert_eq!(
            PagedSpendIntent::decode(&encoded[..encoded.len() - 1]),
            Err(PagedSpendError::Wire(WireError::Truncated))
        );
        assert!(matches!(
            PagedSpendIntent::new(
                pages(1, 1, 3),
                vec![0; MAX_PAGEDSPEND_AUTHORIZATION_BYTES + 1]
            ),
            Err(PagedSpendError::AuthorizationTooLarge { .. })
        ));
    }

    #[test]
    fn exact_wire_maximum_is_frozen() {
        assert_eq!(MAX_PAGEDSPEND_OUTPUTS, 256);
        assert_eq!(MAX_PAGEDSPEND_INTENT_BYTES, 102_363);
    }

    fn independent_stream(count: usize) -> Vec<TxPage> {
        let mut stream = Vec::with_capacity(count);
        for index in 0..count {
            let mut group = pages(1, 1, 3);
            group[0].body.inputs[0].slot_index = index as u32 + 1;
            group[0].body.inputs[0].creation_id = index as u64 + 1;
            group[0].body.outputs[0].slot_index = 10_000 + index as u32;
            group[0].body.epoch_anchor[0] = index as u8;
            stream.push(group.remove(0));
        }
        stream
    }

    #[test]
    fn flat_stream_has_exact_64_65_255_class_boundary() {
        for (count, class) in [
            (64, ProofClass::B64),
            (65, ProofClass::B255),
            (255, ProofClass::B255),
        ] {
            let stream = independent_stream(count);
            let facts = validate_paged_spend_stream(&stream).unwrap();
            assert_eq!(facts.proof_class, class);
            assert_eq!(facts.page_count as usize, count);
            assert_eq!(facts.logical_count as usize, count);
            assert_eq!(facts.groups.len(), count);
            let unique = facts
                .groups
                .iter()
                .map(|group| group.logical_txid)
                .collect::<HashSet<_>>();
            assert_eq!(unique.len(), count);
        }

        let b64 = independent_stream(64);
        assert!(validate_paged_spend_stream_for_class(&b64, ProofClass::B64).is_ok());
        assert_eq!(
            validate_paged_spend_stream_for_class(&b64, ProofClass::B255),
            Err(PagedSpendError::ProofClassMismatch {
                expected: ProofClass::B64,
                actual: ProofClass::B255,
            })
        );

        let b255 = independent_stream(65);
        assert_eq!(
            validate_paged_spend_stream_for_class(&b255, ProofClass::B64),
            Err(PagedSpendError::BlockPageLimit {
                actual: 65,
                capacity: 64,
            })
        );
    }

    #[test]
    fn block_decoder_rejects_the_256th_user_page() {
        let stream = independent_stream(255);
        let mut oversized = stream.clone();
        oversized.push(stream[0].clone());
        assert_eq!(
            validate_paged_spend_stream(&oversized),
            Err(PagedSpendError::BlockPageLimit {
                actual: 256,
                capacity: 255,
            })
        );
    }

    #[test]
    fn empty_user_page_stream_is_the_coinbase_only_boundary() {
        let facts = validate_paged_spend_stream(&[]).unwrap();
        assert_eq!(facts.proof_class, ProofClass::B64);
        assert!(facts.groups.is_empty());
        assert_eq!(facts.page_count, 0);
        assert_eq!(facts.logical_count, 0);
        assert_eq!(facts.live_inputs, 0);
        assert_eq!(facts.live_outputs, 0);
    }

    #[test]
    fn flat_stream_rejects_partial_and_cross_group_conflicts() {
        let mut partial = pages(9, 1, 3);
        partial.last_mut().unwrap().body.validity_bitmap &= !PAGEDSPEND_END_BIT;
        assert_eq!(
            validate_paged_spend_stream(&partial),
            Err(PagedSpendError::UnterminatedGroup { start_page: 0 })
        );

        let first = pages(1, 1, 3).remove(0);
        let mut second = pages(1, 1, 3).remove(0);
        second.body.epoch_anchor[0] ^= 1;
        assert!(matches!(
            validate_paged_spend_stream(&[first, second]),
            Err(PagedSpendError::DuplicateInputSlot { slot: 1 })
        ));
    }
}
