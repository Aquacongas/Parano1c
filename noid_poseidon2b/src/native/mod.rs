// SPDX-License-Identifier: Apache-2.0

pub mod compression;
pub mod digest;
pub mod domain;
pub mod permutation;

pub use compression::{
    compress, compress_with_tag, poseidon2b_hash_byte_slices, poseidon2b_hash_bytes,
    Poseidon2bSponge,
};
pub use digest::{poseidon2b_digest, poseidon2b_digest_field, poseidon2b_digest_pair};
pub use domain::{
    capacity_iv, DomainTag, TAG_ACCBLK, TAG_ADDRFIX, TAG_BLOCKHDR, TAG_BYTEHASH, TAG_CLAIMS,
    TAG_COMMIT, TAG_COMPRESS, TAG_DAWTNSS, TAG_EXSTNOD, TAG_EXSTROT, TAG_EXSTSLT, TAG_FRISTATE,
    TAG_FSCHALNG, TAG_HISTCLM, TAG_HISTPRF, TAG_HISTTRN, TAG_LEAF, TAG_OUTLEAF, TAG_POWHDR,
    TAG_RGDBUCK, TAG_RGDNODE, TAG_SEGMENTTREE, TAG_TXBODY,
};
pub use permutation::{sbox_x7, Poseidon2bPermutation};
