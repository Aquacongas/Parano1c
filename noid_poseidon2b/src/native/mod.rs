// SPDX-License-Identifier: Apache-2.0

pub mod compression;
pub mod digest;
pub mod domain;
pub mod permutation;
pub mod zero_subtree;

pub use compression::{compress, Poseidon2bSponge};
pub use digest::{poseidon2b_digest, poseidon2b_digest_field, poseidon2b_digest_pair};
pub use domain::{
    capacity_iv, DomainTag, TAG_ADDRESS, TAG_AUTHTAG, TAG_BLOCKHDR, TAG_CLAIMS, TAG_COMMIT,
    TAG_COMPRESS, TAG_DAWTNSS, TAG_FRISTATE, TAG_FSCHALNG, TAG_LEAF, TAG_OUTLEAF, TAG_SEGMENTTREE,
    TAG_TXBODY,
};
pub use permutation::{sbox_x7, Poseidon2bPermutation};
