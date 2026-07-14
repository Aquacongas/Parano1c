// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical selected-history terminal package and local-authority verifier.
//!
//! The wire object contains only terminal metadata and the active split-link
//! proof envelope.  In particular, it never carries a matrix digest, a class
//! digest, a post-commit digest, a verification key, or a matrix.  Those are
//! verifier authority and are derived exclusively from a locally materialized
//! [`CanonicalSplitLinkLadder`] registry.
//!
//! Verification is bounded-memory: the terminal proof is replayed with the
//! matrix-free deferred Field verifier, then the terminal Link matrix is
//! leased once to discharge its fresh claim and (when live) its accumulator
//! lane. Every other live Link/Block matrix is then leased, checked, and
//! released one at a time before the one-shot tip decision can finish.

use std::fmt;
use std::io::Cursor;

use bincode::Options;
use noid_chain::consensus::params::USER_TX_CLASS_TIERS;
use noid_chain::consensus::wire_limits::MAX_HISTORY_PROOF_BYTES;
use noid_chain::{block_id, BlockHeader};
use noid_ivc_core::field::F128;
use noid_ivc_core::field_r1cs::FieldR1cs;
use noid_ivc_core::matrix_claim::MatrixClaimEvaluator;
use noid_ivc_core::proof::FieldShape;
use serde::de::{
    self, DeserializeOwned, DeserializeSeed, EnumAccess, MapAccess, SeqAccess, VariantAccess,
    Visitor,
};

use crate::acceptance::split_link::{
    begin_tip_split_decision_deferred_matrix, tip_block_accumulator_split, CanonicalLadderError,
    CanonicalSplitLinkLadder, LinkProofEnvelope, SplitLinkClass, CANONICAL_BLOCK_CLASS_MS,
    CANONICAL_LINK_CLASS_M,
};
use crate::accumulator::{ChainAccumulator, CHAIN_ACCUMULATOR_LANES};

/// First and only pre-launch selected-history terminal wire version.
pub const SELECTED_HISTORY_TERMINAL_VERSION: u16 = 1;

/// The terminal package uses the existing consensus history-proof admission
/// budget.  The limit is checked before any bincode call.
pub const MAX_SELECTED_HISTORY_TERMINAL_PACKAGE_BYTES: usize = MAX_HISTORY_PROOF_BYTES;

/// Fixed prefix: version, height, hash, slot, tier, envelope Vec length.
const SELECTED_HISTORY_WIRE_PREFIX_BYTES: usize = 2 + 8 + 32 + 1 + 2 + 8;

/// Maximum bincode payload admitted for the terminal [`LinkProofEnvelope`].
pub const MAX_SELECTED_HISTORY_TERMINAL_ENVELOPE_BYTES: usize =
    MAX_SELECTED_HISTORY_TERMINAL_PACKAGE_BYTES - SELECTED_HISTORY_WIRE_PREFIX_BYTES;

/// Exact public-IO lane count of the production B8/B32/B64/B255 split ladder.
///
/// Layout: genesis flag, two 2-lane-per-slot identity blocks, four Link
/// accumulator lanes, four Block accumulator lanes, and the direct chain
/// accumulator.  This is checked after decoding and again by the local class.
pub const SELECTED_HISTORY_LINK_IO_LANES: usize = 1
    + 4 * USER_TX_CLASS_TIERS.len()
    + USER_TX_CLASS_TIERS.len() * (2 * CANONICAL_LINK_CLASS_M + 3)
    + (2 * CANONICAL_BLOCK_CLASS_MS[0] + 3)
    + (2 * CANONICAL_BLOCK_CLASS_MS[1] + 3)
    + (2 * CANONICAL_BLOCK_CLASS_MS[2] + 3)
    + (2 * CANONICAL_BLOCK_CLASS_MS[3] + 3)
    + CHAIN_ACCUMULATOR_LANES;

/// Canonical decoded terminal package.
///
/// All fields are private so construction cannot skip the version and
/// slot/tier invariants.  The proof envelope is the only remote proof object;
/// verifier class authority is deliberately absent.
#[derive(Clone, Debug)]
pub struct SelectedHistoryTerminalPackage {
    version: u16,
    terminal_height: u64,
    terminal_hash: [u8; 32],
    canonical_tip_slot: u8,
    canonical_tip_tier: u16,
    terminal_envelope: LinkProofEnvelope,
}

impl SelectedHistoryTerminalPackage {
    /// Construct a canonical package.  The tier is derived from the consensus
    /// slot table rather than accepted from a caller.
    pub fn new(
        terminal_height: u64,
        terminal_hash: [u8; 32],
        canonical_tip_slot: usize,
        terminal_envelope: LinkProofEnvelope,
    ) -> Result<Self, SelectedHistoryCodecError> {
        let (slot, tier) = canonical_selector(canonical_tip_slot)?;
        if terminal_envelope.io().len() != SELECTED_HISTORY_LINK_IO_LANES {
            return Err(SelectedHistoryCodecError::EnvelopeIoLength {
                expected: SELECTED_HISTORY_LINK_IO_LANES,
                actual: terminal_envelope.io().len(),
            });
        }
        Ok(Self {
            version: SELECTED_HISTORY_TERMINAL_VERSION,
            terminal_height,
            terminal_hash,
            canonical_tip_slot: slot,
            canonical_tip_tier: tier,
            terminal_envelope,
        })
    }

    pub fn version(&self) -> u16 {
        self.version
    }

    pub fn terminal_height(&self) -> u64 {
        self.terminal_height
    }

    pub fn terminal_hash(&self) -> [u8; 32] {
        self.terminal_hash
    }

    pub fn canonical_tip_slot(&self) -> usize {
        usize::from(self.canonical_tip_slot)
    }

    pub fn canonical_tip_tier(&self) -> usize {
        usize::from(self.canonical_tip_tier)
    }

    pub fn terminal_envelope(&self) -> &LinkProofEnvelope {
        &self.terminal_envelope
    }

    /// Consume a locally decoded package and transfer its terminal proof into
    /// the next durable Link job without cloning the proof envelope.
    pub fn into_terminal_envelope(self) -> LinkProofEnvelope {
        self.terminal_envelope
    }

    /// Exact canonical wire encoding.
    pub fn encode(&self) -> Result<Vec<u8>, SelectedHistoryCodecError> {
        encode_selected_history_terminal_package(self)
    }
}

/// Fail-closed terminal wire errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectedHistoryCodecError {
    PackageTooLarge {
        actual: usize,
        max: usize,
    },
    TruncatedPrefix,
    UnsupportedVersion {
        actual: u16,
    },
    InvalidTipSlot {
        actual: usize,
    },
    TipTierMismatch {
        slot: usize,
        expected: usize,
        actual: usize,
    },
    EmptyEnvelope,
    EnvelopeTooLarge {
        actual: u64,
        max: usize,
    },
    EnvelopeLengthOverflow,
    TruncatedEnvelope {
        expected: usize,
        actual: usize,
    },
    TrailingBytes {
        expected: usize,
        actual: usize,
    },
    EnvelopeCodec(String),
    EnvelopeIoLength {
        expected: usize,
        actual: usize,
    },
}

impl fmt::Display for SelectedHistoryCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PackageTooLarge { actual, max } => {
                write!(
                    f,
                    "selected-history package is {actual} bytes; cap is {max}"
                )
            }
            Self::TruncatedPrefix => f.write_str("selected-history wire prefix is truncated"),
            Self::UnsupportedVersion { actual } => {
                write!(f, "unsupported selected-history version {actual}")
            }
            Self::InvalidTipSlot { actual } => {
                write!(f, "selected-history tip slot {actual} is not canonical")
            }
            Self::TipTierMismatch {
                slot,
                expected,
                actual,
            } => write!(
                f,
                "selected-history tip slot {slot} requires tier {expected}, got {actual}"
            ),
            Self::EmptyEnvelope => f.write_str("selected-history terminal envelope is empty"),
            Self::EnvelopeTooLarge { actual, max } => write!(
                f,
                "selected-history terminal envelope is {actual} bytes; cap is {max}"
            ),
            Self::EnvelopeLengthOverflow => {
                f.write_str("selected-history envelope length does not fit this platform")
            }
            Self::TruncatedEnvelope { expected, actual } => write!(
                f,
                "selected-history wire is truncated: expected {expected} bytes, got {actual}"
            ),
            Self::TrailingBytes { expected, actual } => write!(
                f,
                "selected-history wire has trailing bytes: expected {expected}, got {actual}"
            ),
            Self::EnvelopeCodec(error) => {
                write!(f, "selected-history terminal envelope codec: {error}")
            }
            Self::EnvelopeIoLength { expected, actual } => write!(
                f,
                "selected-history Link IO has {actual} lanes; canonical length is {expected}"
            ),
        }
    }
}

impl std::error::Error for SelectedHistoryCodecError {}

#[derive(Clone, Copy)]
struct WirePreflight<'a> {
    terminal_height: u64,
    terminal_hash: [u8; 32],
    canonical_tip_slot: u8,
    canonical_tip_tier: u16,
    envelope_bytes: &'a [u8],
}

fn canonical_selector(slot: usize) -> Result<(u8, u16), SelectedHistoryCodecError> {
    let tier = USER_TX_CLASS_TIERS
        .get(slot)
        .copied()
        .ok_or(SelectedHistoryCodecError::InvalidTipSlot { actual: slot })?;
    let slot = u8::try_from(slot)
        .map_err(|_| SelectedHistoryCodecError::InvalidTipSlot { actual: slot })?;
    let tier = u16::try_from(tier).expect("canonical transaction tier fits u16");
    Ok((slot, tier))
}

/// Allocation-free preflight of the complete outer fixed-int wire.
///
/// In particular, the forged bincode-v1 Vec length is checked against the
/// byte cap and the exact remaining slice before the envelope deserializer is
/// entered.  This is the allocation boundary for network-controlled bytes.
fn preflight_wire(bytes: &[u8]) -> Result<WirePreflight<'_>, SelectedHistoryCodecError> {
    if bytes.len() > MAX_SELECTED_HISTORY_TERMINAL_PACKAGE_BYTES {
        return Err(SelectedHistoryCodecError::PackageTooLarge {
            actual: bytes.len(),
            max: MAX_SELECTED_HISTORY_TERMINAL_PACKAGE_BYTES,
        });
    }
    if bytes.len() < SELECTED_HISTORY_WIRE_PREFIX_BYTES {
        return Err(SelectedHistoryCodecError::TruncatedPrefix);
    }

    let version = u16::from_le_bytes(bytes[0..2].try_into().unwrap());
    if version != SELECTED_HISTORY_TERMINAL_VERSION {
        return Err(SelectedHistoryCodecError::UnsupportedVersion { actual: version });
    }
    let terminal_height = u64::from_le_bytes(bytes[2..10].try_into().unwrap());
    let terminal_hash = bytes[10..42].try_into().unwrap();
    let canonical_tip_slot = bytes[42];
    let canonical_tip_tier = u16::from_le_bytes(bytes[43..45].try_into().unwrap());
    let (_, expected_tier) = canonical_selector(usize::from(canonical_tip_slot))?;
    if canonical_tip_tier != expected_tier {
        return Err(SelectedHistoryCodecError::TipTierMismatch {
            slot: usize::from(canonical_tip_slot),
            expected: usize::from(expected_tier),
            actual: usize::from(canonical_tip_tier),
        });
    }

    let encoded_len = u64::from_le_bytes(bytes[45..53].try_into().unwrap());
    if encoded_len == 0 {
        return Err(SelectedHistoryCodecError::EmptyEnvelope);
    }
    if encoded_len > MAX_SELECTED_HISTORY_TERMINAL_ENVELOPE_BYTES as u64 {
        return Err(SelectedHistoryCodecError::EnvelopeTooLarge {
            actual: encoded_len,
            max: MAX_SELECTED_HISTORY_TERMINAL_ENVELOPE_BYTES,
        });
    }
    let encoded_len = usize::try_from(encoded_len)
        .map_err(|_| SelectedHistoryCodecError::EnvelopeLengthOverflow)?;
    let expected_total = SELECTED_HISTORY_WIRE_PREFIX_BYTES
        .checked_add(encoded_len)
        .ok_or(SelectedHistoryCodecError::EnvelopeLengthOverflow)?;
    match bytes.len().cmp(&expected_total) {
        std::cmp::Ordering::Less => {
            return Err(SelectedHistoryCodecError::TruncatedEnvelope {
                expected: expected_total,
                actual: bytes.len(),
            });
        }
        std::cmp::Ordering::Greater => {
            return Err(SelectedHistoryCodecError::TrailingBytes {
                expected: expected_total,
                actual: bytes.len(),
            });
        }
        std::cmp::Ordering::Equal => {}
    }

    Ok(WirePreflight {
        terminal_height,
        terminal_hash,
        canonical_tip_slot,
        canonical_tip_tier,
        envelope_bytes: &bytes[SELECTED_HISTORY_WIRE_PREFIX_BYTES..],
    })
}

/// Serialize one canonical selected-history terminal package.
pub fn encode_selected_history_terminal_package(
    package: &SelectedHistoryTerminalPackage,
) -> Result<Vec<u8>, SelectedHistoryCodecError> {
    if package.version != SELECTED_HISTORY_TERMINAL_VERSION {
        return Err(SelectedHistoryCodecError::UnsupportedVersion {
            actual: package.version,
        });
    }
    let (_, expected_tier) = canonical_selector(usize::from(package.canonical_tip_slot))?;
    if package.canonical_tip_tier != expected_tier {
        return Err(SelectedHistoryCodecError::TipTierMismatch {
            slot: usize::from(package.canonical_tip_slot),
            expected: usize::from(expected_tier),
            actual: usize::from(package.canonical_tip_tier),
        });
    }
    if package.terminal_envelope.io().len() != SELECTED_HISTORY_LINK_IO_LANES {
        return Err(SelectedHistoryCodecError::EnvelopeIoLength {
            expected: SELECTED_HISTORY_LINK_IO_LANES,
            actual: package.terminal_envelope.io().len(),
        });
    }

    let envelope_bytes = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&package.terminal_envelope)
        .map_err(|error| SelectedHistoryCodecError::EnvelopeCodec(error.to_string()))?;
    if envelope_bytes.is_empty() {
        return Err(SelectedHistoryCodecError::EmptyEnvelope);
    }
    if envelope_bytes.len() > MAX_SELECTED_HISTORY_TERMINAL_ENVELOPE_BYTES {
        return Err(SelectedHistoryCodecError::EnvelopeTooLarge {
            actual: envelope_bytes.len() as u64,
            max: MAX_SELECTED_HISTORY_TERMINAL_ENVELOPE_BYTES,
        });
    }

    let mut encoded = Vec::with_capacity(SELECTED_HISTORY_WIRE_PREFIX_BYTES + envelope_bytes.len());
    encoded.extend_from_slice(&package.version.to_le_bytes());
    encoded.extend_from_slice(&package.terminal_height.to_le_bytes());
    encoded.extend_from_slice(&package.terminal_hash);
    encoded.push(package.canonical_tip_slot);
    encoded.extend_from_slice(&package.canonical_tip_tier.to_le_bytes());
    encoded.extend_from_slice(&(envelope_bytes.len() as u64).to_le_bytes());
    encoded.extend_from_slice(&envelope_bytes);
    debug_assert!(preflight_wire(&encoded).is_ok());
    Ok(encoded)
}

#[cfg(test)]
static ENVELOPE_DESERIALIZE_ATTEMPTS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Deserializer adapter that rejects forged collection lengths before serde's
/// collection visitor sees them and suppresses its eager-capacity hint.
///
/// Bincode's byte limit is necessary but not sufficient on its own: ordinary
/// `Vec<T>` deserialization may reserve from the claimed sequence length before
/// the truncated payload is discovered.  This adapter recursively wraps every
/// seed/visitor boundary, caps the declared length, and reports a zero capacity
/// hint.  Allocation therefore grows only as capped bytes are actually parsed.
struct SequencePreflightDeserializer<D> {
    inner: D,
    max_sequence_len: usize,
}

impl<D> SequencePreflightDeserializer<D> {
    fn new(inner: D, max_sequence_len: usize) -> Self {
        Self {
            inner,
            max_sequence_len,
        }
    }
}

struct SequencePreflightSeed<S> {
    inner: S,
    max_sequence_len: usize,
}

impl<'de, S> DeserializeSeed<'de> for SequencePreflightSeed<S>
where
    S: DeserializeSeed<'de>,
{
    type Value = S::Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        self.inner.deserialize(SequencePreflightDeserializer::new(
            deserializer,
            self.max_sequence_len,
        ))
    }
}

struct SequencePreflightVisitor<V> {
    inner: V,
    max_sequence_len: usize,
}

fn preflight_collection_len<E: de::Error>(length: Option<usize>, max: usize) -> Result<(), E> {
    if let Some(actual) = length {
        if actual > max {
            return Err(E::custom(format_args!(
                "declared collection length {actual} exceeds selected-history cap {max}"
            )));
        }
    }
    Ok(())
}

impl<'de, V> Visitor<'de> for SequencePreflightVisitor<V>
where
    V: Visitor<'de>,
{
    type Value = V::Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.expecting(formatter)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.inner.visit_none()
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        self.inner.visit_some(SequencePreflightDeserializer::new(
            deserializer,
            self.max_sequence_len,
        ))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.inner.visit_unit()
    }

    fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        self.inner
            .visit_newtype_struct(SequencePreflightDeserializer::new(
                deserializer,
                self.max_sequence_len,
            ))
    }

    fn visit_seq<A>(self, sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        preflight_collection_len::<A::Error>(sequence.size_hint(), self.max_sequence_len)?;
        self.inner.visit_seq(SequencePreflightSeqAccess {
            inner: sequence,
            max_sequence_len: self.max_sequence_len,
        })
    }

    fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        preflight_collection_len::<A::Error>(map.size_hint(), self.max_sequence_len)?;
        self.inner.visit_map(SequencePreflightMapAccess {
            inner: map,
            max_sequence_len: self.max_sequence_len,
        })
    }

    fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
    where
        A: EnumAccess<'de>,
    {
        self.inner.visit_enum(SequencePreflightEnumAccess {
            inner: data,
            max_sequence_len: self.max_sequence_len,
        })
    }
}

struct SequencePreflightSeqAccess<A> {
    inner: A,
    max_sequence_len: usize,
}

impl<'de, A> SeqAccess<'de> for SequencePreflightSeqAccess<A>
where
    A: SeqAccess<'de>,
{
    type Error = A::Error;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
    where
        T: DeserializeSeed<'de>,
    {
        self.inner.next_element_seed(SequencePreflightSeed {
            inner: seed,
            max_sequence_len: self.max_sequence_len,
        })
    }

    fn size_hint(&self) -> Option<usize> {
        // Never let a network-controlled length drive eager Vec allocation.
        Some(0)
    }
}

struct SequencePreflightMapAccess<A> {
    inner: A,
    max_sequence_len: usize,
}

impl<'de, A> MapAccess<'de> for SequencePreflightMapAccess<A>
where
    A: MapAccess<'de>,
{
    type Error = A::Error;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, Self::Error>
    where
        K: DeserializeSeed<'de>,
    {
        self.inner.next_key_seed(SequencePreflightSeed {
            inner: seed,
            max_sequence_len: self.max_sequence_len,
        })
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, Self::Error>
    where
        V: DeserializeSeed<'de>,
    {
        self.inner.next_value_seed(SequencePreflightSeed {
            inner: seed,
            max_sequence_len: self.max_sequence_len,
        })
    }

    fn size_hint(&self) -> Option<usize> {
        Some(0)
    }
}

struct SequencePreflightEnumAccess<A> {
    inner: A,
    max_sequence_len: usize,
}

impl<'de, A> EnumAccess<'de> for SequencePreflightEnumAccess<A>
where
    A: EnumAccess<'de>,
{
    type Error = A::Error;
    type Variant = SequencePreflightVariantAccess<A::Variant>;

    fn variant_seed<V>(self, seed: V) -> Result<(V::Value, Self::Variant), Self::Error>
    where
        V: DeserializeSeed<'de>,
    {
        let (value, variant) = self.inner.variant_seed(SequencePreflightSeed {
            inner: seed,
            max_sequence_len: self.max_sequence_len,
        })?;
        Ok((
            value,
            SequencePreflightVariantAccess {
                inner: variant,
                max_sequence_len: self.max_sequence_len,
            },
        ))
    }
}

struct SequencePreflightVariantAccess<A> {
    inner: A,
    max_sequence_len: usize,
}

impl<'de, A> VariantAccess<'de> for SequencePreflightVariantAccess<A>
where
    A: VariantAccess<'de>,
{
    type Error = A::Error;

    fn unit_variant(self) -> Result<(), Self::Error> {
        self.inner.unit_variant()
    }

    fn newtype_variant_seed<T>(self, seed: T) -> Result<T::Value, Self::Error>
    where
        T: DeserializeSeed<'de>,
    {
        self.inner.newtype_variant_seed(SequencePreflightSeed {
            inner: seed,
            max_sequence_len: self.max_sequence_len,
        })
    }

    fn tuple_variant<V>(self, len: usize, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        preflight_collection_len::<Self::Error>(Some(len), self.max_sequence_len)?;
        self.inner.tuple_variant(
            len,
            SequencePreflightVisitor {
                inner: visitor,
                max_sequence_len: self.max_sequence_len,
            },
        )
    }

    fn struct_variant<V>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        preflight_collection_len::<Self::Error>(Some(fields.len()), self.max_sequence_len)?;
        self.inner.struct_variant(
            fields,
            SequencePreflightVisitor {
                inner: visitor,
                max_sequence_len: self.max_sequence_len,
            },
        )
    }
}

macro_rules! forward_plain_deserialize {
    ($method:ident) => {
        fn $method<V>(self, visitor: V) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.inner.$method(visitor)
        }
    };
    ($method:ident, $($argument:ident: $argument_type:ty),+ $(,)?) => {
        fn $method<V>(
            self,
            $($argument: $argument_type,)+
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            self.inner.$method($($argument,)+ visitor)
        }
    };
}

impl<'de, D> de::Deserializer<'de> for SequencePreflightDeserializer<D>
where
    D: de::Deserializer<'de>,
{
    type Error = D::Error;

    forward_plain_deserialize!(deserialize_any);
    forward_plain_deserialize!(deserialize_bool);
    forward_plain_deserialize!(deserialize_i8);
    forward_plain_deserialize!(deserialize_i16);
    forward_plain_deserialize!(deserialize_i32);
    forward_plain_deserialize!(deserialize_i64);
    forward_plain_deserialize!(deserialize_i128);
    forward_plain_deserialize!(deserialize_u8);
    forward_plain_deserialize!(deserialize_u16);
    forward_plain_deserialize!(deserialize_u32);
    forward_plain_deserialize!(deserialize_u64);
    forward_plain_deserialize!(deserialize_u128);
    forward_plain_deserialize!(deserialize_f32);
    forward_plain_deserialize!(deserialize_f64);
    forward_plain_deserialize!(deserialize_char);
    forward_plain_deserialize!(deserialize_str);
    forward_plain_deserialize!(deserialize_string);
    forward_plain_deserialize!(deserialize_bytes);
    forward_plain_deserialize!(deserialize_byte_buf);
    forward_plain_deserialize!(deserialize_unit);
    forward_plain_deserialize!(deserialize_unit_struct, name: &'static str);
    forward_plain_deserialize!(deserialize_identifier);
    forward_plain_deserialize!(deserialize_ignored_any);

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.inner.deserialize_option(SequencePreflightVisitor {
            inner: visitor,
            max_sequence_len: self.max_sequence_len,
        })
    }

    fn deserialize_newtype_struct<V>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.inner.deserialize_newtype_struct(
            name,
            SequencePreflightVisitor {
                inner: visitor,
                max_sequence_len: self.max_sequence_len,
            },
        )
    }

    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.inner.deserialize_seq(SequencePreflightVisitor {
            inner: visitor,
            max_sequence_len: self.max_sequence_len,
        })
    }

    fn deserialize_tuple<V>(self, len: usize, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        preflight_collection_len::<Self::Error>(Some(len), self.max_sequence_len)?;
        self.inner.deserialize_tuple(
            len,
            SequencePreflightVisitor {
                inner: visitor,
                max_sequence_len: self.max_sequence_len,
            },
        )
    }

    fn deserialize_tuple_struct<V>(
        self,
        name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        preflight_collection_len::<Self::Error>(Some(len), self.max_sequence_len)?;
        self.inner.deserialize_tuple_struct(
            name,
            len,
            SequencePreflightVisitor {
                inner: visitor,
                max_sequence_len: self.max_sequence_len,
            },
        )
    }

    fn deserialize_map<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.inner.deserialize_map(SequencePreflightVisitor {
            inner: visitor,
            max_sequence_len: self.max_sequence_len,
        })
    }

    fn deserialize_struct<V>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        preflight_collection_len::<Self::Error>(Some(fields.len()), self.max_sequence_len)?;
        self.inner.deserialize_struct(
            name,
            fields,
            SequencePreflightVisitor {
                inner: visitor,
                max_sequence_len: self.max_sequence_len,
            },
        )
    }

    fn deserialize_enum<V>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        preflight_collection_len::<Self::Error>(Some(variants.len()), self.max_sequence_len)?;
        self.inner.deserialize_enum(
            name,
            variants,
            SequencePreflightVisitor {
                inner: visitor,
                max_sequence_len: self.max_sequence_len,
            },
        )
    }

    fn is_human_readable(&self) -> bool {
        self.inner.is_human_readable()
    }
}

fn deserialize_envelope_allocation_safe<T: DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, SelectedHistoryCodecError> {
    let mut reader = Cursor::new(bytes);
    let options = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(bytes.len() as u64);
    let value = {
        let mut deserializer = bincode::Deserializer::with_reader(&mut reader, options);
        T::deserialize(SequencePreflightDeserializer::new(
            &mut deserializer,
            MAX_SELECTED_HISTORY_TERMINAL_ENVELOPE_BYTES,
        ))
        .map_err(|error| SelectedHistoryCodecError::EnvelopeCodec(error.to_string()))?
    };
    let consumed = usize::try_from(reader.position())
        .map_err(|_| SelectedHistoryCodecError::EnvelopeLengthOverflow)?;
    if consumed != bytes.len() {
        return Err(SelectedHistoryCodecError::TrailingBytes {
            expected: consumed,
            actual: bytes.len(),
        });
    }
    Ok(value)
}

/// Decode only after the fixed outer preflight has bounded the sole remote
/// byte vector.  The recursive sequence adapter rejects every nested forged
/// length before allocation, while the bincode decoder retains an exact byte
/// limit and an explicit consumed-length/trailing check.
pub fn decode_selected_history_terminal_package(
    bytes: &[u8],
) -> Result<SelectedHistoryTerminalPackage, SelectedHistoryCodecError> {
    let wire = preflight_wire(bytes)?;
    #[cfg(test)]
    ENVELOPE_DESERIALIZE_ATTEMPTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let envelope: LinkProofEnvelope = deserialize_envelope_allocation_safe(wire.envelope_bytes)?;
    if envelope.io().len() != SELECTED_HISTORY_LINK_IO_LANES {
        return Err(SelectedHistoryCodecError::EnvelopeIoLength {
            expected: SELECTED_HISTORY_LINK_IO_LANES,
            actual: envelope.io().len(),
        });
    }
    Ok(SelectedHistoryTerminalPackage {
        version: SELECTED_HISTORY_TERMINAL_VERSION,
        terminal_height: wire.terminal_height,
        terminal_hash: wire.terminal_hash,
        canonical_tip_slot: wire.canonical_tip_slot,
        canonical_tip_tier: wire.canonical_tip_tier,
        terminal_envelope: envelope,
    })
}

/// A locally materialized production registry.  Remote data has no entry
/// point for supplying or overriding these identities.
pub struct CanonicalSelectedHistoryRegistry<'a> {
    classes: &'a [SplitLinkClass],
    link_class_digests: [[u8; 32]; USER_TX_CLASS_TIERS.len()],
    link_post_commit_class_digests: [[u8; 32]; USER_TX_CLASS_TIERS.len()],
}

/// Copy-only authority derived while a complete materialization is being
/// validated.  The type and its constructor stay crate-private so external
/// callers cannot turn arbitrary digest tables into a canonical registry.
#[derive(Clone, Copy)]
pub(crate) struct ValidatedSelectedHistoryRegistryIdentities {
    link_class_digests: [[u8; 32]; USER_TX_CLASS_TIERS.len()],
    link_post_commit_class_digests: [[u8; 32]; USER_TX_CLASS_TIERS.len()],
}

impl ValidatedSelectedHistoryRegistryIdentities {
    /// Copy identity tables whose exact source registry was fully validated by
    /// the release build. Runtime does not re-walk classes or re-verify the
    /// shared Genesis proof merely to recover these already-stored digests.
    ///
    /// # Safety
    ///
    /// Both tables must come from the exact build-authenticated registry body
    /// used to construct the corresponding Link classes.
    pub(crate) const unsafe fn from_build_authenticated_tables(
        link_class_digests: [[u8; 32]; USER_TX_CLASS_TIERS.len()],
        link_post_commit_class_digests: [[u8; 32]; USER_TX_CLASS_TIERS.len()],
    ) -> Self {
        Self {
            link_class_digests,
            link_post_commit_class_digests,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectedHistoryRegistryError {
    NonCanonical(CanonicalLadderError),
    MissingLinkClassDigest { slot: usize },
}

impl fmt::Display for SelectedHistoryRegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonCanonical(error) => {
                write!(f, "non-canonical selected-history registry: {error}")
            }
            Self::MissingLinkClassDigest { slot } => {
                write!(f, "local selected-history Link class {slot} is not frozen")
            }
        }
    }
}

impl std::error::Error for SelectedHistoryRegistryError {}

impl<'a> CanonicalSelectedHistoryRegistry<'a> {
    /// Validate the complete local materialization once and derive both Link
    /// identity tables from it.  No digest-taking constructor exists.
    pub fn try_new(
        descriptor: &CanonicalSplitLinkLadder,
        classes: &'a [SplitLinkClass],
    ) -> Result<Self, SelectedHistoryRegistryError> {
        descriptor
            .validate_materialized(classes)
            .map_err(SelectedHistoryRegistryError::NonCanonical)?;
        let identities = Self::capture_validated_identities(classes)?;
        Ok(Self::from_validated_materialization(classes, identities))
    }

    fn capture_validated_identities(
        classes: &[SplitLinkClass],
    ) -> Result<ValidatedSelectedHistoryRegistryIdentities, SelectedHistoryRegistryError> {
        let mut link_class_digests = [[0u8; 32]; USER_TX_CLASS_TIERS.len()];
        let mut link_post_commit_class_digests = [[0u8; 32]; USER_TX_CLASS_TIERS.len()];
        for (slot, class) in classes.iter().enumerate() {
            link_class_digests[slot] = class
                .class_statement_digest
                .get()
                .copied()
                .ok_or(SelectedHistoryRegistryError::MissingLinkClassDigest { slot })?;
            link_post_commit_class_digests[slot] = *class.post_commit_class_digest();
        }
        Ok(ValidatedSelectedHistoryRegistryIdentities {
            link_class_digests,
            link_post_commit_class_digests,
        })
    }

    /// Reborrow a materialization whose owning decoder already performed the
    /// complete descriptor, class, sidecar, and shared-genesis validation.
    /// This is deliberately unavailable outside `noid_recursive`.
    pub(crate) fn from_validated_materialization(
        classes: &'a [SplitLinkClass],
        identities: ValidatedSelectedHistoryRegistryIdentities,
    ) -> Self {
        Self {
            classes,
            link_class_digests: identities.link_class_digests,
            link_post_commit_class_digests: identities.link_post_commit_class_digests,
        }
    }

    pub(crate) const fn validated_identities(&self) -> ValidatedSelectedHistoryRegistryIdentities {
        ValidatedSelectedHistoryRegistryIdentities {
            link_class_digests: self.link_class_digests,
            link_post_commit_class_digests: self.link_post_commit_class_digests,
        }
    }

    fn class(&self, slot: usize) -> &SplitLinkClass {
        &self.classes[slot]
    }

    /// Frozen Link matrix identity for one canonical tier slot.
    pub fn link_class_digest(&self, slot: usize) -> Option<[u8; 32]> {
        self.link_class_digests.get(slot).copied()
    }

    /// Frozen Link matrix/VK post-commit identity for one canonical tier slot.
    pub fn link_post_commit_class_digest(&self, slot: usize) -> Option<[u8; 32]> {
        self.link_post_commit_class_digests.get(slot).copied()
    }
}

/// Which locally rebuilt matrix the streaming verifier needs next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectedHistoryMatrixFamily {
    Link,
    Block,
}

/// Bounded request passed to the local matrix source.  `tier` is derived from
/// the canonical registry; it is never copied from an unverified authority
/// table in the package.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectedHistoryMatrixRequest {
    pub family: SelectedHistoryMatrixFamily,
    pub slot: usize,
    pub tier: usize,
    shape: FieldShape,
    statement_digest: [u8; 32],
}

impl SelectedHistoryMatrixRequest {
    /// Frozen shape the local artifact must decode to.
    pub const fn shape(&self) -> FieldShape {
        self.shape
    }

    /// Frozen structural statement identity the local artifact must match.
    pub const fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }
}

/// One transient matrix evaluator whose admission remains held for the full
/// authenticated scan. Implementations may attach process-global residency,
/// opened-file, or mapping guards; the verifier never unwraps storage from
/// the lease and never requires a resident CSR.
pub trait SelectedHistoryMatrixLease {
    fn evaluator(&mut self) -> &mut dyn MatrixClaimEvaluator;
}

impl SelectedHistoryMatrixLease for FieldR1cs {
    fn evaluator(&mut self) -> &mut dyn MatrixClaimEvaluator {
        self
    }
}

/// Dependency-clean local source contract for streaming terminal
/// verification.  At most one returned lease is live when the next load is
/// requested.
pub trait SelectedHistoryMatrixSource {
    type Lease: SelectedHistoryMatrixLease;
    type Error: fmt::Display;

    fn load_matrix(
        &mut self,
        request: SelectedHistoryMatrixRequest,
    ) -> Result<Self::Lease, Self::Error>;
}

impl<F, E> SelectedHistoryMatrixSource for F
where
    F: FnMut(SelectedHistoryMatrixRequest) -> Result<FieldR1cs, E>,
    E: fmt::Display,
{
    type Lease = FieldR1cs;
    type Error = E;

    fn load_matrix(
        &mut self,
        request: SelectedHistoryMatrixRequest,
    ) -> Result<Self::Lease, Self::Error> {
        self(request)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectedHistoryVerificationError {
    Package(SelectedHistoryCodecError),
    TerminalHeightMismatch {
        package: u64,
        local: u64,
    },
    TerminalHashMismatch,
    MatrixSource {
        request: SelectedHistoryMatrixRequest,
        error: String,
    },
    TipDecision(String),
    AccumulatorDecode(String),
    AccumulatorBoundary(String),
}

impl fmt::Display for SelectedHistoryVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Package(error) => write!(f, "selected-history package: {error}"),
            Self::TerminalHeightMismatch { package, local } => write!(
                f,
                "selected-history terminal height {package} does not match local tip {local}"
            ),
            Self::TerminalHashMismatch => {
                f.write_str("selected-history terminal hash does not match the local tip")
            }
            Self::MatrixSource { request, error } => write!(
                f,
                "local {:?} matrix source failed for slot {} (tier {}): {error}",
                request.family, request.slot, request.tier
            ),
            Self::TipDecision(error) => write!(f, "selected-history tip rejected: {error}"),
            Self::AccumulatorDecode(error) => {
                write!(f, "selected-history accumulator decode failed: {error}")
            }
            Self::AccumulatorBoundary(error) => {
                write!(f, "selected-history accumulator boundary failed: {error}")
            }
        }
    }
}

impl std::error::Error for SelectedHistoryVerificationError {}

impl From<SelectedHistoryCodecError> for SelectedHistoryVerificationError {
    fn from(error: SelectedHistoryCodecError) -> Self {
        Self::Package(error)
    }
}

fn matrix_request(
    family: SelectedHistoryMatrixFamily,
    slot: usize,
    registry: &CanonicalSelectedHistoryRegistry<'_>,
) -> SelectedHistoryMatrixRequest {
    let (shape, statement_digest) = match family {
        SelectedHistoryMatrixFamily::Link => (
            registry.class(slot).shape,
            registry.link_class_digests[slot],
        ),
        SelectedHistoryMatrixFamily::Block => {
            let info = &registry.class(slot).ladder()[slot];
            (info.b_shape, info.b_digest)
        }
    };
    SelectedHistoryMatrixRequest {
        family,
        slot,
        tier: USER_TX_CLASS_TIERS[slot],
        shape,
        statement_digest,
    }
}

fn load_matrix<S: SelectedHistoryMatrixSource>(
    source: &mut S,
    request: SelectedHistoryMatrixRequest,
) -> Result<S::Lease, SelectedHistoryVerificationError> {
    source
        .load_matrix(request)
        .map_err(|error| SelectedHistoryVerificationError::MatrixSource {
            request,
            error: error.to_string(),
        })
}

/// Verify one selected-history terminal package against local canonical
/// headers and a local, one-matrix-at-a-time reconstruction source.
///
/// `matrix_source` must rebuild/load matrices from the node's own published
/// class registry.  Returned matrices are owned by this function and dropped
/// after their single check; at no point is a full matrix bank retained.
pub fn verify_selected_history_terminal<S: SelectedHistoryMatrixSource>(
    package: &SelectedHistoryTerminalPackage,
    registry: &CanonicalSelectedHistoryRegistry<'_>,
    local_tip_header: &BlockHeader,
    local_epoch_anchor_header: &BlockHeader,
    matrix_source: &mut S,
) -> Result<ChainAccumulator, SelectedHistoryVerificationError> {
    if package.version != SELECTED_HISTORY_TERMINAL_VERSION {
        return Err(SelectedHistoryCodecError::UnsupportedVersion {
            actual: package.version,
        }
        .into());
    }
    let (_, expected_tier) = canonical_selector(package.canonical_tip_slot())?;
    if package.canonical_tip_tier != expected_tier {
        return Err(SelectedHistoryCodecError::TipTierMismatch {
            slot: package.canonical_tip_slot(),
            expected: usize::from(expected_tier),
            actual: package.canonical_tip_tier(),
        }
        .into());
    }
    if package.terminal_envelope.io().len() != SELECTED_HISTORY_LINK_IO_LANES {
        return Err(SelectedHistoryCodecError::EnvelopeIoLength {
            expected: SELECTED_HISTORY_LINK_IO_LANES,
            actual: package.terminal_envelope.io().len(),
        }
        .into());
    }
    if package.terminal_height != local_tip_header.height {
        return Err(SelectedHistoryVerificationError::TerminalHeightMismatch {
            package: package.terminal_height,
            local: local_tip_header.height,
        });
    }
    if package.terminal_hash != block_id(local_tip_header) {
        return Err(SelectedHistoryVerificationError::TerminalHashMismatch);
    }

    let tip_slot = package.canonical_tip_slot();
    let tip_class = registry.class(tip_slot);
    let layout = tip_class.layout();
    // Replay the Field proof without a matrix first.  Only a valid proof can
    // trigger the large local artifact load, and the returned typestate still
    // cannot be accepted until its fresh claim is discharged below.
    let deferred = begin_tip_split_decision_deferred_matrix(
        tip_class,
        &package.terminal_envelope,
        &registry.link_class_digests,
        &registry.link_post_commit_class_digests,
    )
    .map_err(SelectedHistoryVerificationError::TipDecision)?;
    let tip_matrix_request = matrix_request(SelectedHistoryMatrixFamily::Link, tip_slot, registry);
    let mut tip_matrix = load_matrix(matrix_source, tip_matrix_request)?;
    let mut pending = deferred
        .discharge_tip_matrix(tip_matrix.evaluator())
        .map_err(|error| SelectedHistoryVerificationError::TipDecision(error.to_string()))?;

    // Discharge also consumed the tip's live accumulator lane against this
    // same structurally authenticated CSR. Release it before any next load.
    drop(tip_matrix);

    for (slot, lane) in layout.link_lanes.iter().enumerate() {
        if slot == tip_slot || package.terminal_envelope.io()[lane.live] != F128::ONE {
            continue;
        }
        let request = matrix_request(SelectedHistoryMatrixFamily::Link, slot, registry);
        let mut matrix = load_matrix(matrix_source, request)?;
        pending
            .check_link_matrix(slot, matrix.evaluator())
            .map_err(SelectedHistoryVerificationError::TipDecision)?;
        drop(matrix);
    }
    for (slot, lane) in layout.b_lanes.iter().enumerate() {
        if package.terminal_envelope.io()[lane.live] != F128::ONE {
            continue;
        }
        let request = matrix_request(SelectedHistoryMatrixFamily::Block, slot, registry);
        let mut matrix = load_matrix(matrix_source, request)?;
        pending
            .check_block_matrix(slot, matrix.evaluator())
            .map_err(SelectedHistoryVerificationError::TipDecision)?;
        drop(matrix);
    }
    pending
        .finish()
        .map_err(SelectedHistoryVerificationError::TipDecision)?;

    let accumulator =
        tip_block_accumulator_split(tip_class, &package.terminal_envelope).map_err(|error| {
            SelectedHistoryVerificationError::AccumulatorDecode(format!("{error:?}"))
        })?;
    accumulator
        .validate_local_header_boundary(local_tip_header, local_epoch_anchor_header)
        .map_err(|error| {
            SelectedHistoryVerificationError::AccumulatorBoundary(error.to_string())
        })?;
    Ok(accumulator)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    fn wire(
        version: u16,
        slot: u8,
        tier: u16,
        declared_envelope_len: u64,
        envelope: &[u8],
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&version.to_le_bytes());
        bytes.extend_from_slice(&9u64.to_le_bytes());
        bytes.extend_from_slice(&[0xA5; 32]);
        bytes.push(slot);
        bytes.extend_from_slice(&tier.to_le_bytes());
        bytes.extend_from_slice(&declared_envelope_len.to_le_bytes());
        bytes.extend_from_slice(envelope);
        bytes
    }

    #[test]
    fn production_io_lane_constant_matches_frozen_layout() {
        // 1 genesis flag + 16 whitelist lanes + 4 x (2*22 + 3) m22 Link
        // claim lanes + (47 + 49 + 49 + 51) Block claim lanes + the
        // eleven-lane direct chain accumulator.
        assert_eq!(SELECTED_HISTORY_LINK_IO_LANES, 412);
    }

    #[test]
    fn allocation_free_wire_preflight_accepts_only_exact_canonical_metadata() {
        let bytes = wire(SELECTED_HISTORY_TERMINAL_VERSION, 3, 255, 4, &[1, 2, 3, 4]);
        let preflight = preflight_wire(&bytes).unwrap();
        assert_eq!(preflight.terminal_height, 9);
        assert_eq!(preflight.terminal_hash, [0xA5; 32]);
        assert_eq!(preflight.canonical_tip_slot, 3);
        assert_eq!(preflight.canonical_tip_tier, 255);
        assert_eq!(preflight.envelope_bytes, [1, 2, 3, 4]);

        assert!(matches!(
            preflight_wire(&wire(2, 3, 255, 1, &[1])),
            Err(SelectedHistoryCodecError::UnsupportedVersion { actual: 2 })
        ));
        assert!(matches!(
            preflight_wire(&wire(1, 4, 255, 1, &[1])),
            Err(SelectedHistoryCodecError::InvalidTipSlot { actual: 4 })
        ));
        assert!(matches!(
            preflight_wire(&wire(1, 2, 255, 1, &[1])),
            Err(SelectedHistoryCodecError::TipTierMismatch {
                slot: 2,
                expected: 64,
                actual: 255
            })
        ));
    }

    #[test]
    fn forged_vec_lengths_trailing_and_oversize_fail_before_bincode() {
        let before = ENVELOPE_DESERIALIZE_ATTEMPTS.load(Ordering::Relaxed);
        let cases = [
            wire(1, 0, 8, 0, &[]),
            wire(1, 0, 8, 5, &[1, 2, 3, 4]),
            wire(1, 0, 8, 3, &[1, 2, 3, 4]),
            wire(
                1,
                0,
                8,
                MAX_SELECTED_HISTORY_TERMINAL_ENVELOPE_BYTES as u64 + 1,
                &[],
            ),
            wire(2, 0, 8, 1, &[1]),
            wire(1, 1, 8, 1, &[1]),
        ];
        for malformed in &cases {
            assert!(decode_selected_history_terminal_package(malformed).is_err());
        }
        assert_eq!(
            ENVELOPE_DESERIALIZE_ATTEMPTS.load(Ordering::Relaxed),
            before,
            "outer preflight must reject before serde/bincode"
        );

        let oversize = vec![0u8; MAX_SELECTED_HISTORY_TERMINAL_PACKAGE_BYTES + 1];
        assert!(matches!(
            decode_selected_history_terminal_package(&oversize),
            Err(SelectedHistoryCodecError::PackageTooLarge { .. })
        ));
        assert_eq!(
            ENVELOPE_DESERIALIZE_ATTEMPTS.load(Ordering::Relaxed),
            before
        );
    }

    #[test]
    fn nested_sequence_guard_rejects_length_bomb_before_vec_reserve() {
        #[derive(Debug, serde::Deserialize)]
        struct SequenceFixture {
            values: Vec<u64>,
        }

        let forged = u64::MAX.to_le_bytes();
        let error = deserialize_envelope_allocation_safe::<SequenceFixture>(&forged).unwrap_err();
        assert!(matches!(error, SelectedHistoryCodecError::EnvelopeCodec(_)));
        assert!(error.to_string().contains("declared collection length"));

        let mut canonical = Vec::new();
        canonical.extend_from_slice(&2u64.to_le_bytes());
        canonical.extend_from_slice(&11u64.to_le_bytes());
        canonical.extend_from_slice(&13u64.to_le_bytes());
        let decoded = deserialize_envelope_allocation_safe::<SequenceFixture>(&canonical).unwrap();
        assert_eq!(decoded.values, vec![11, 13]);

        let mut trailing = canonical;
        trailing.push(0);
        assert!(matches!(
            deserialize_envelope_allocation_safe::<SequenceFixture>(&trailing),
            Err(SelectedHistoryCodecError::TrailingBytes { .. })
        ));
    }

    #[test]
    fn terminal_verifier_uses_deferred_csr_discharge_before_any_tip_acceptance() {
        let source = include_str!("selected_history.rs");
        let verifier = source
            .split("pub fn verify_selected_history_terminal<")
            .nth(1)
            .expect("selected terminal verifier")
            .split("#[cfg(test)]")
            .next()
            .expect("selected terminal verifier boundary");
        let replay = verifier
            .find("begin_tip_split_decision_deferred_matrix(")
            .expect("matrix-free deferred replay");
        let load = verifier
            .find("let mut tip_matrix = load_matrix(")
            .expect("leased tip matrix load");
        let discharge = verifier
            .find(".discharge_tip_matrix(tip_matrix.evaluator())")
            .expect("mandatory fresh-claim discharge");
        let release = verifier
            .find("drop(tip_matrix);")
            .expect("tip matrix release");
        assert!(replay < load && load < discharge && discharge < release);
        assert!(!verifier.contains("begin_tip_split_decision("));
        assert!(!verifier.contains("verify_split_link_proof("));
        assert!(!verifier.contains("csc_lincheck_circuit"));
        assert!(!verifier.contains("FieldR1cs::read_artifact"));
    }
}
