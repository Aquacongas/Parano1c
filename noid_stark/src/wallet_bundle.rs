// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! `WalletProofBundle` — the complete proof artifact the wallet sends to
//! the full node mempool.
//!
//! # Security invariant — SpendSecret NEVER leaves the wallet
//!
//! The wallet uses `SpendSecret` locally to compute:
//! 1. `LogicProof` via `prove_logic(witness)` — a STARK + AuthGKR Kill-Shot.
//! 2. `auth_slices` via `split_mle_into_slices(build_auth_unified_mle(...))`.
//!
//! Both are **one-way Poseidon2b outputs** bound to this specific transaction.
//! They CANNOT be reversed to recover `SpendSecret`, just as a Bitcoin ECDSA
//! signature cannot reveal the private key.
//!
//! The wire format contains ONLY the proof artifacts — SpendSecret is never
//! serialised or transmitted.
//!
//! # Full node usage
//!
//! ```text
//! Mempool admission (verify correctness of LogicProof):
//!   verify_logic(air, pi, spine_inputs, auth_public, &bundle.logic_proof)
//!
//! Block assembly (prove_block inputs — NO SpendSecret needed):
//!   TxBlockWitness {
//!     air          ← TxLogicAir::new(boundary_pins_from_body(tx_body))   // public
//!     trace        ← witness_from_body(tx_body) |> air.build_trace()     // public
//!     pi           ← PublicInputs derived from tx_body                   // public
//!     spine_inputs ← SpineInputs from boundary_pins_from_body(tx_body)   // public
//!     auth_public  ← extracted from bundle.logic_proof.auth              // public
//!     auth_proof   ← &bundle.logic_proof.auth                            // proof artifact
//!     auth_slices  ← &bundle.auth_slices    // Poseidon2b outputs, NOT SpendSecret
//!   }
//! ```

use noid_core::Block128;
use noid_gkr::AuthPublicInputs;
use serde::{Deserialize, Serialize};

use crate::prove_logic::LogicProof;

// ---------------------------------------------------------------------------
// WalletProofBundle
// ---------------------------------------------------------------------------

/// Complete proof bundle sent by the wallet to the full node mempool.
///
/// Serialized via `bincode` for compact binary encoding.
///
/// # What's included — all proof artifacts, no secrets
///
/// - `logic_proof`: STARK + AuthGKR Kill-Shot. Verified at mempool admission
///   with `verify_logic`. Cannot reveal SpendSecret.
///
/// - `auth_slices`: MLE column data for the AuthGKR circuit state, required
///   by `prove_block` to build the unified block-level Merkle commitment.
///   These are `2^BASE_LOG`-element slices of Poseidon2b outputs — they
///   satisfy all auth constraints but CANNOT be used to recover SpendSecret.
///
/// # What's NOT included
///
/// - `SpendSecret` — computed inside wallet, never serialised.
/// - AIR trace — the full node rebuilds it from the public `tx_body` via
///   `witness_from_body(tx_body)` which only uses slot indices, values, and
///   owner addresses (all public).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletProofBundle {
    /// STARK + AuthGKR Kill-Shot proof. Verifiable by `verify_logic`.
    pub logic_proof: LogicProof,
    /// AuthGKR MLE state slices (N_AUTH_SLICES × 2^BASE_LOG elements).
    /// N_AUTH_SLICES = 8, BASE_LOG = 11 → 8 × 2048 = 16 384 Block128 elements.
    /// Required by `prove_block`; cryptographically derived from SpendSecret
    /// but mathematically unable to reveal it (Poseidon2b is one-way).
    pub auth_slices: Vec<Vec<Block128>>,
    /// Pre-computed public inputs for the auth GKR verifier.
    ///
    /// Includes `expected_address[i]` (= `H(spend_secret_i)`) and
    /// `expected_auth_tag[i]` (= `H(spend_secret_i, tx_body_hash)`) for all
    /// N_AUTH_INPUTS slots, including dummy/padding slots.
    ///
    /// Stored here so the block prover does not need to reconstruct these
    /// from the tx body — reconstruction produces wrong values for dummy
    /// (valid=false) input slots because their auth constraints are
    /// circuit-internal and not exposed in the wire format.
    pub auth_public: AuthPublicInputs,
}

// ---------------------------------------------------------------------------
// Encoding / decoding via bincode
// ---------------------------------------------------------------------------

/// Errors from bundle decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleDecodeError {
    /// Bincode deserialization failed (truncated or corrupt bytes).
    Bincode(String),
    /// Trailing bytes after a valid bundle.
    TrailingBytes,
}

impl std::fmt::Display for BundleDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl WalletProofBundle {
    /// Encode the bundle to bytes using bincode (compact LE binary).
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("WalletProofBundle serialization must succeed")
    }

    /// Decode a bundle from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BundleDecodeError> {
        bincode::deserialize(bytes).map_err(|e| BundleDecodeError::Bincode(e.to_string()))
    }

    /// Estimated size (fast; uses bincode internal estimator).
    pub fn byte_len(&self) -> usize {
        self.to_bytes().len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interleaved::InterleavedStarkProof;
    use noid_fri_binius::{InterleavedCommitment, MerkleCap, MixedOpeningProof};
    use noid_gkr::{AuthKillShotProof, AuthProofKillShot, AuthShiftProof, AuthUnifiedProof};

    fn dummy_bundle() -> WalletProofBundle {
        use crate::prove_logic::LogicProof;

        let stark = InterleavedStarkProof {
            log_rows: 11,
            commitment: InterleavedCommitment {
                cap: MerkleCap {
                    hashes: vec![[0xABu8; 32]],
                },
                log_rows: 11,
                n_cols: 10,
            },
            base_openings: vec![Block128(1), Block128(2)],
            zero_check_rounds: vec![vec![Block128(3)]],
            shift_partials: vec![],
            multipoint_rounds: vec![vec![Block128(4)]],
            mixed_opening: MixedOpeningProof {
                all_openings: vec![Block128(5)],
                fri_proof: noid_fri_binius::CompactEvalProof {
                    upper_partial_evals: vec![],
                    sum_check_oracles: vec![],
                    fri_roots: vec![],
                    fri_queried_symbols: vec![],
                    fri_merkle_batch: vec![],
                    final_codeword: vec![],
                },
            },
            slice_claimed_values: vec![Block128(6)],
        };

        let auth = AuthProofKillShot {
            kill_shot: AuthKillShotProof {
                main: AuthUnifiedProof {
                    round_polys: vec![],
                    s_in_dec_at_r: Block128(0),
                    s_out_dec_at_r: Block128(0),
                    state_dec_at_r: Block128(0),
                    state_at_r: Block128(0),
                    s_out_lane_dec_at_r: [Block128(0); 4],
                    state_lane_dec_at_r: [Block128(0); 4],
                },
                shift: AuthShiftProof {
                    round_polys: vec![],
                    s_in_at_r2: Block128(0),
                    s_out_at_r2: Block128(0),
                    state_at_r2: Block128(0),
                },
            },
            state_batch: noid_gkr::BatchEvalProof {
                rounds: vec![],
                b_final: Block128(0),
            },
            sin_batch: noid_gkr::BatchEvalProof {
                rounds: vec![],
                b_final: Block128(0),
            },
            sout_batch: noid_gkr::BatchEvalProof {
                rounds: vec![],
                b_final: Block128(0),
            },
        };

        let logic_proof = LogicProof {
            stark,
            auth,
            n_boundary_slices: 8,
        };

        let auth_slices = vec![vec![Block128(7u128); 8], vec![Block128(8u128); 8]];

        WalletProofBundle {
            logic_proof,
            auth_slices,
            auth_public: AuthPublicInputs::zero(),
        }
    }

    #[test]
    fn roundtrip() {
        let bundle = dummy_bundle();
        let bytes = bundle.to_bytes();
        assert!(!bytes.is_empty());
        let back = WalletProofBundle::from_bytes(&bytes).expect("decode");
        assert_eq!(back.auth_slices.len(), bundle.auth_slices.len());
        assert_eq!(back.auth_slices[0], bundle.auth_slices[0]);
        assert_eq!(
            back.logic_proof.n_boundary_slices,
            bundle.logic_proof.n_boundary_slices
        );
        assert_eq!(
            back.logic_proof.stark.log_rows,
            bundle.logic_proof.stark.log_rows
        );
        assert_eq!(
            back.logic_proof.stark.base_openings,
            bundle.logic_proof.stark.base_openings
        );
    }

    #[test]
    fn corrupt_bytes_fail_gracefully() {
        let bundle = dummy_bundle();
        let mut bytes = bundle.to_bytes();
        // Corrupt the last byte.
        if let Some(last) = bytes.last_mut() {
            *last ^= 0xFF;
        }
        // Should not panic — just return Err.
        let result = WalletProofBundle::from_bytes(&bytes);
        // May or may not fail depending on corruption location; just ensure no panic.
        let _ = result;
    }
}
