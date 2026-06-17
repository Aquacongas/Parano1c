// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Wallet proof bundle variants sent by wallets to full nodes.
//!
//! The bundle is shape-dispatched: `Standard4x8` and `Sweep25x2` carry
//! different proof artifacts, so they cannot be accidentally accepted under the
//! wrong fixed circuit family. Spend secrets are never serialized.

use noid_core::Block128;
use noid_gkr::{AuthPublicInputs, SweepAuthPublicInputs};
use noid_tx::TxShape;
use serde::{Deserialize, Serialize};

use crate::prove_logic::LogicProof;
use crate::prove_logic_sweep::SweepLogicProof;

/// Standard fast-path wallet proof bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandardWalletProofBundle {
    /// STARK + standard 4-input AuthGKR Kill-Shot proof.
    pub logic_proof: LogicProof,
    /// Standard AuthGKR MLE state slices required by current block proving.
    pub auth_slices: Vec<Vec<Block128>>,
    /// Public-only standard auth boundary.
    pub auth_public: AuthPublicInputs,
}

/// Sweep25x2 wallet proof bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweepWalletProofBundle {
    /// STARK over sweep balance plus sweep AuthGKR + sweep SpineGKR.
    pub logic_proof: SweepLogicProof,
    /// Sweep AuthGKR MLE `state` slices required by the sweep block bucket.
    /// This mirrors `StandardWalletProofBundle::auth_slices` for Sweep25x2.
    pub auth_slices: Vec<Vec<Block128>>,
    /// Public-only sweep auth boundary.
    pub auth_public: SweepAuthPublicInputs,
}

/// Complete proof bundle sent by the wallet to the full node mempool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalletProofBundle {
    Standard4x8(StandardWalletProofBundle),
    Sweep25x2(SweepWalletProofBundle),
}

impl WalletProofBundle {
    pub fn shape(&self) -> TxShape {
        match self {
            Self::Standard4x8(_) => TxShape::Standard4x8,
            Self::Sweep25x2(_) => TxShape::Sweep25x2,
        }
    }

    /// Encode the bundle to bytes using bincode (compact LE binary).
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("WalletProofBundle serialization must succeed")
    }

    /// Decode a bundle from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BundleDecodeError> {
        bincode::deserialize(bytes).map_err(|e| BundleDecodeError::Bincode(e.to_string()))
    }

    /// Estimated size (fast; uses bincode serialization).
    pub fn byte_len(&self) -> usize {
        self.to_bytes().len()
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interleaved::InterleavedStarkProof;
    use noid_fri_binius::{InterleavedCommitment, MerkleCap, MixedOpeningProof};
    use noid_gkr::{
        AuthKillShotProof, AuthProofKillShot, AuthShiftProof, AuthUnifiedProof,
        SweepAuthKillShotProof, SweepAuthProofKillShot, SweepAuthShiftProof, SweepAuthUnifiedProof,
        SweepSpineKillShotProof, SweepSpineProofKillShot, SweepSpineShiftProof,
        SweepSpineUnifiedProof,
    };

    fn dummy_stark() -> InterleavedStarkProof {
        InterleavedStarkProof {
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
        }
    }

    fn dummy_standard_auth() -> AuthProofKillShot {
        AuthProofKillShot {
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
        }
    }

    fn dummy_sweep_auth() -> SweepAuthProofKillShot {
        SweepAuthProofKillShot {
            kill_shot: SweepAuthKillShotProof {
                main: SweepAuthUnifiedProof {
                    round_polys: vec![],
                    s_in_dec_at_r: Block128(0),
                    s_out_dec_at_r: Block128(0),
                    state_dec_at_r: Block128(0),
                    state_at_r: Block128(0),
                    s_out_lane_dec_at_r: [Block128(0); 4],
                    state_lane_dec_at_r: [Block128(0); 4],
                },
                shift: SweepAuthShiftProof {
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
        }
    }

    fn dummy_sweep_spine() -> SweepSpineProofKillShot {
        SweepSpineProofKillShot {
            kill_shot: SweepSpineKillShotProof {
                main: SweepSpineUnifiedProof {
                    round_polys: vec![],
                    s_in_dec_at_r: Block128(0),
                    s_out_dec_at_r: Block128(0),
                    state_dec_at_r: Block128(0),
                    state_at_r: Block128(0),
                    s_out_lane_dec_at_r: [Block128(0); 4],
                    state_lane_dec_at_r: [Block128(0); 4],
                },
                shift: SweepSpineShiftProof {
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
        }
    }

    fn dummy_standard_bundle() -> WalletProofBundle {
        let logic_proof = LogicProof {
            stark: dummy_stark(),
            auth: dummy_standard_auth(),
            n_boundary_slices: 8,
        };
        WalletProofBundle::Standard4x8(StandardWalletProofBundle {
            logic_proof,
            auth_slices: vec![vec![Block128(7u128); 8], vec![Block128(8u128); 8]],
            auth_public: AuthPublicInputs::zero(),
        })
    }

    fn dummy_sweep_bundle() -> WalletProofBundle {
        let logic_proof = SweepLogicProof {
            stark: dummy_stark(),
            auth: dummy_sweep_auth(),
            spine: dummy_sweep_spine(),
            n_boundary_slices: 216,
        };
        WalletProofBundle::Sweep25x2(SweepWalletProofBundle {
            logic_proof,
            auth_slices: vec![
                vec![Block128(9u128); 8];
                crate::prove_logic_sweep::N_SWEEP_AUTH_SLICES
            ],
            auth_public: SweepAuthPublicInputs::zero(),
        })
    }

    #[test]
    fn standard_roundtrip() {
        let bundle = dummy_standard_bundle();
        let bytes = bundle.to_bytes();
        assert!(!bytes.is_empty());
        let back = WalletProofBundle::from_bytes(&bytes).expect("decode");
        assert_eq!(back.shape(), TxShape::Standard4x8);
        match back {
            WalletProofBundle::Standard4x8(b) => {
                assert_eq!(b.auth_slices.len(), 2);
                assert_eq!(b.logic_proof.n_boundary_slices, 8);
            }
            WalletProofBundle::Sweep25x2(_) => panic!("wrong variant"),
        }
    }

    #[test]
    fn sweep_roundtrip() {
        let bundle = dummy_sweep_bundle();
        let bytes = bundle.to_bytes();
        assert!(!bytes.is_empty());
        let back = WalletProofBundle::from_bytes(&bytes).expect("decode");
        assert_eq!(back.shape(), TxShape::Sweep25x2);
        match back {
            WalletProofBundle::Sweep25x2(b) => {
                assert_eq!(b.logic_proof.n_boundary_slices, 216);
                assert_eq!(
                    b.auth_slices.len(),
                    crate::prove_logic_sweep::N_SWEEP_AUTH_SLICES
                );
            }
            WalletProofBundle::Standard4x8(_) => panic!("wrong variant"),
        }
    }

    #[test]
    fn corrupt_bytes_fail_gracefully() {
        let bundle = dummy_standard_bundle();
        let mut bytes = bundle.to_bytes();
        if let Some(last) = bytes.last_mut() {
            *last ^= 0xFF;
        }
        let _ = WalletProofBundle::from_bytes(&bytes);
    }
}
