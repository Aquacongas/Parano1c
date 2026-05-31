// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Step 1a — typed topology description of the `AuthCircuit`:
//! per-input HAddr (2 perms) + HAuth (3 perms) sponges packed into a
//! single GKR sub-protocol. The purpose is to evacuate all Poseidon2b
//! authorisation permutations out of the STARK AIR, mirroring what the
//! 59-slot `SpineCircuit` does for `tx_body_hash` already.
//!
//! ## What the circuit proves
//!
//! Given `SpendSecret[i]` (private) and `tx_body_hash` (public) for each
//! live input `i ∈ 0..N_AUTH_INPUTS`, the circuit recomputes
//!
//!   - `Address[i]   = H_ADDR (SpendSecret[i])` (2-perm sponge, IV = `TAG_ADDRESS`)
//!   - `AuthTag[i]   = H_AUTH (SpendSecret[i], tx_body_hash)` (3-perm sponge, IV = `TAG_AUTHTAG`)
//!
//! and exposes the derived `(Address[i], AuthTag[i])` pairs at the GKR
//! boundary. The STARK side (landed in Step 1b) pins these boundaries
//! via `PublicColumn` so `T1a` / `T2a/b` close through equality, not
//! through trace materialisation of the sponge state.
//!
//! ## Topology
//!
//! Five slots per input, post-order:
//!
//! | slot (per input) | role        | chain                                   |
//! |------------------|-------------|-----------------------------------------|
//! | 0                | HAddrPermA  | head, IV = `capacity_iv(TAG_ADDRESS)`   |
//! | 1                | HAddrPermB  | chains from A, absorbs pad `[PAD_0, PAD_1]` — emits `Address` |
//! | 2                | HAuthPermA  | head, IV = `capacity_iv(TAG_AUTHTAG)`   |
//! | 3                | HAuthPermB  | chains from A, absorbs `tx_body_hash`   |
//! | 4                | HAuthPermC  | chains from B, absorbs pad — emits `AuthTag` |
//!
//! `N_AUTH_SLOTS = 5 * N_AUTH_INPUTS = 20` for the canonical `noid_tx`
//! `MAX_INPUTS = 4`.
//!
//! ## Boundary surface
//!
//! - **Private** (prover only): `spend_secret[i] = [a, b]`.
//! - **Public** (verifier): `tx_body_hash = [c, d]`, `expected_address[i]`,
//!   `expected_auth_tag[i]`.
//!
//! The verifier reconstructs every slot's `state_in` natively from these
//! inputs + previous slots' outputs (see `auth_oracle`). The sumcheck
//! (see `auth_sumcheck`) then discharges per-slot `state`-MLE claims
//! against the concatenated boundary MLE. Equality-bound output pins:
//!
//!   - HAddrPermB slot's `state_out[0..1]` == `expected_address[i]`,
//!   - HAuthPermC slot's `state_out[0..1]` == `expected_auth_tag[i]`.
//!
//! Any mismatch rejects deterministically — no probabilistic handoff.
//!
//! ## Privacy invariant (load-bearing — `SPECIFICATION.md §5`)
//!
//! `spend_secret[i]` is a witness-only input. The sumcheck transcript
//! never absorbs raw secret values; it only absorbs the publicly-known
//! `(claimed_address, claimed_auth_tag, tx_body_hash)` boundary and the
//! derived sumcheck proof bytes, which expose only random-point MLE
//! evaluations — the same hiding profile as the current in-AIR proof.
//! The secret is therefore not recoverable from the payload.

use noid_core::{Block128, TowerField};
use noid_poseidon2b::native::domain::{capacity_iv, TAG_ADDRESS, TAG_AUTHTAG};
use noid_tx::MAX_INPUTS;

/// Number of independent `(HAddr + HAuth)` chains packed into the
/// `AuthCircuit`. Locked to `noid_tx::MAX_INPUTS` so the circuit shape
/// is a compile-time constant, exactly like the 59-slot spine.
pub const N_AUTH_INPUTS: usize = MAX_INPUTS;

/// Number of permutation slots per input: 2 (HAddr) + 3 (HAuth) = 5.
pub const N_SLOTS_PER_INPUT: usize = 5;

/// Total number of permutation slots in the auth circuit.
pub const N_AUTH_SLOTS: usize = N_SLOTS_PER_INPUT * N_AUTH_INPUTS;

/// First padding byte pushed by the sponge's `finalize()` flush on an
/// empty buffer: matches `fill_padding` in
/// `noid_poseidon2b::native::compression`. Used by HAddrPermB (after
/// 1 absorb_pair → 1 permute → 32-byte pad flush) and HAuthPermC (after
/// 2 absorb_pairs → 2 permutes → 32-byte pad flush).
pub const AUTH_PAD_0: u128 = 0x80;
/// Second padding byte (MSB of the 16-byte lane): `0x01 << 120`.
pub const AUTH_PAD_1: u128 = 0x01u128 << 120;

/// Per-slot role tag, indexed by `input_idx` so every descriptor is
/// self-describing without having to walk the slot table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthSlotRole {
    /// `derive_address` sponge, permutation A (head, IV = `TAG_ADDRESS`,
    /// absorbs `spend_secret`).
    HAddrPermA { input_idx: u8 },
    /// `derive_address` sponge, permutation B (chains from A, absorbs
    /// the `[PAD_0, PAD_1]` sponge-finalize flush). `state_out[0..1]`
    /// is the derived `Address`.
    HAddrPermB { input_idx: u8 },
    /// `hash_auth_tag` sponge, permutation A (head, IV = `TAG_AUTHTAG`,
    /// absorbs `spend_secret`).
    HAuthPermA { input_idx: u8 },
    /// `hash_auth_tag` sponge, permutation B (chains from A, absorbs
    /// `tx_body_hash`).
    HAuthPermB { input_idx: u8 },
    /// `hash_auth_tag` sponge, permutation C (chains from B, absorbs
    /// the `[PAD_0, PAD_1]` finalize flush). `state_out[0..1]` is the
    /// derived `AuthTag`.
    HAuthPermC { input_idx: u8 },
}

impl AuthSlotRole {
    /// The input index this slot belongs to.
    #[inline]
    pub fn input_idx(&self) -> usize {
        match self {
            AuthSlotRole::HAddrPermA { input_idx }
            | AuthSlotRole::HAddrPermB { input_idx }
            | AuthSlotRole::HAuthPermA { input_idx }
            | AuthSlotRole::HAuthPermB { input_idx }
            | AuthSlotRole::HAuthPermC { input_idx } => *input_idx as usize,
        }
    }
}

/// One slot of the auth circuit, mirroring `SlotDescriptor` on the
/// spine side but with auth-specific role / chaining metadata.
#[derive(Debug, Clone, Copy)]
pub struct AuthSlotDescriptor {
    /// Instance id in `0..N_AUTH_SLOTS`.
    pub id: usize,
    /// Role of this slot.
    pub role: AuthSlotRole,
    /// Capacity IV used at the head of this slot's sub-sponge. Carried
    /// on every descriptor for local availability (matches the spine
    /// convention).
    pub capacity_iv: [Block128; 2],
    /// `true` if this slot is the head of its sub-sponge.
    pub is_head: bool,
    /// For non-head slots: the id of the previous slot whose
    /// `state_out` feeds into this slot before the absorb XOR.
    pub prev_output_src: Option<usize>,
}

/// Public-only subset of the auth boundary. Used by verifiers and block
/// provers who must never see `spend_secret`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthPublicInputs {
    /// `tx_body_hash = [hi, lo]`. Pinned on the STARK side via the spine bridge.
    pub tx_body_hash: [Block128; 2],
    /// Claimed `Address[i] = [hi, lo]`.
    pub expected_address: [[Block128; 2]; N_AUTH_INPUTS],
    /// Claimed `AuthTag[i] = [hi, lo]`.
    pub expected_auth_tag: [[Block128; 2]; N_AUTH_INPUTS],
}

impl AuthPublicInputs {
    pub fn zero() -> Self {
        Self {
            tx_body_hash: [Block128::ZERO; 2],
            expected_address: [[Block128::ZERO; 2]; N_AUTH_INPUTS],
            expected_auth_tag: [[Block128::ZERO; 2]; N_AUTH_INPUTS],
        }
    }
}

/// Per-transaction private + public witness inputs the GKR boundary
/// carries. Public fields are the same cells the STARK's `PublicColumn`
/// pins consume (landed in Step 1b); private fields are witness-only.
///
/// PRIVACY: This struct must NEVER leave the wallet. The block prover
/// receives only `AuthPublicInputs` + a pre-built `AuthProofKillShot`.
///
/// SECURITY: `Debug` is intentionally NOT derived — the struct contains
/// `spend_secret` which must never appear in logs, panic output, or
/// test output. Use `auth_inputs.to_public()` for any diagnostic
/// printing that is safe to expose.
#[derive(Clone, Copy)]
pub struct AuthInputs {
    /// Per-input `SpendSecret = [secret_hi, secret_lo]`. **Private.**
    /// Inactive rows MUST be filled with the zero secret — the circuit
    /// shape is constant.
    pub spend_secret: [[Block128; 2]; N_AUTH_INPUTS],
    /// `tx_body_hash = [hi, lo]`. **Public** — pinned on the STARK side
    /// via the existing spine bridge.
    pub tx_body_hash: [Block128; 2],
    /// Claimed `Address[i] = [hi, lo]`. **Public.**
    pub expected_address: [[Block128; 2]; N_AUTH_INPUTS],
    /// Claimed `AuthTag[i] = [hi, lo]`. **Public.**
    pub expected_auth_tag: [[Block128; 2]; N_AUTH_INPUTS],
}

impl AuthInputs {
    /// Extract the public-only subset, discarding `spend_secret`.
    pub fn to_public(&self) -> AuthPublicInputs {
        AuthPublicInputs {
            tx_body_hash: self.tx_body_hash,
            expected_address: self.expected_address,
            expected_auth_tag: self.expected_auth_tag,
        }
    }
}

impl AuthInputs {
    /// Zeroed fixture (every secret / claim lane is `Block128::ZERO`).
    /// Useful as a building block in tests; the oracle will override
    /// the `expected_*` fields by re-executing the sponge natively.
    pub fn zero() -> Self {
        Self {
            spend_secret: [[Block128::ZERO; 2]; N_AUTH_INPUTS],
            tx_body_hash: [Block128::ZERO; 2],
            expected_address: [[Block128::ZERO; 2]; N_AUTH_INPUTS],
            expected_auth_tag: [[Block128::ZERO; 2]; N_AUTH_INPUTS],
        }
    }

    /// Construct from public inputs + private secret.
    pub fn from_parts(
        public: &AuthPublicInputs,
        spend_secret: [[Block128; 2]; N_AUTH_INPUTS],
    ) -> Self {
        Self {
            spend_secret,
            tx_body_hash: public.tx_body_hash,
            expected_address: public.expected_address,
            expected_auth_tag: public.expected_auth_tag,
        }
    }
}

/// Custom Debug for AuthInputs: spend_secret is redacted to prevent
/// accidental exposure in logs, panic output, or test diagnostics.
/// Only the public fields are shown.
impl std::fmt::Debug for AuthInputs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthInputs")
            .field("spend_secret", &"[REDACTED]")
            .field("tx_body_hash", &self.tx_body_hash)
            .field("expected_address", &self.expected_address)
            .field("expected_auth_tag", &self.expected_auth_tag)
            .finish()
    }
}

/// Static topology of the 20-slot auth circuit. Cheap to construct
/// (one allocation, `O(N_AUTH_SLOTS)` work), typically built once per
/// process and reused.
#[derive(Debug, Clone)]
pub struct AuthCircuit {
    pub slots: Vec<AuthSlotDescriptor>,
}

impl AuthCircuit {
    /// Build the full topology for the canonical `MAX_INPUTS`.
    pub fn build() -> Self {
        let iv_addr = capacity_iv(TAG_ADDRESS);
        let iv_auth = capacity_iv(TAG_AUTHTAG);

        let mut slots = Vec::with_capacity(N_AUTH_SLOTS);
        for input_idx_usize in 0..N_AUTH_INPUTS {
            let input_idx = input_idx_usize as u8;
            let base = slots.len();

            // HAddrPermA — head.
            slots.push(AuthSlotDescriptor {
                id: base,
                role: AuthSlotRole::HAddrPermA { input_idx },
                capacity_iv: iv_addr,
                is_head: true,
                prev_output_src: None,
            });
            // HAddrPermB — chains from A.
            slots.push(AuthSlotDescriptor {
                id: base + 1,
                role: AuthSlotRole::HAddrPermB { input_idx },
                capacity_iv: iv_addr,
                is_head: false,
                prev_output_src: Some(base),
            });
            // HAuthPermA — head (fresh sub-sponge under TAG_AUTHTAG).
            slots.push(AuthSlotDescriptor {
                id: base + 2,
                role: AuthSlotRole::HAuthPermA { input_idx },
                capacity_iv: iv_auth,
                is_head: true,
                prev_output_src: None,
            });
            // HAuthPermB — chains from HAuthPermA.
            slots.push(AuthSlotDescriptor {
                id: base + 3,
                role: AuthSlotRole::HAuthPermB { input_idx },
                capacity_iv: iv_auth,
                is_head: false,
                prev_output_src: Some(base + 2),
            });
            // HAuthPermC — chains from HAuthPermB.
            slots.push(AuthSlotDescriptor {
                id: base + 4,
                role: AuthSlotRole::HAuthPermC { input_idx },
                capacity_iv: iv_auth,
                is_head: false,
                prev_output_src: Some(base + 3),
            });
        }

        debug_assert_eq!(slots.len(), N_AUTH_SLOTS);
        Self { slots }
    }

    /// Slot id of the HAddrPermB permutation whose `state_out[0..1]` is
    /// the derived `Address` for `input_idx`.
    #[inline]
    pub fn haddr_output_slot(input_idx: usize) -> usize {
        debug_assert!(input_idx < N_AUTH_INPUTS);
        input_idx * N_SLOTS_PER_INPUT + 1
    }

    /// Slot id of the HAuthPermC permutation whose `state_out[0..1]` is
    /// the derived `AuthTag` for `input_idx`.
    #[inline]
    pub fn hauth_output_slot(input_idx: usize) -> usize {
        debug_assert!(input_idx < N_AUTH_INPUTS);
        input_idx * N_SLOTS_PER_INPUT + 4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_has_expected_slot_count_and_shape() {
        let c = AuthCircuit::build();
        assert_eq!(c.slots.len(), N_AUTH_SLOTS);
        assert_eq!(N_AUTH_SLOTS, 5 * N_AUTH_INPUTS);
    }

    #[test]
    fn heads_are_ivs_non_heads_chain_prev() {
        let c = AuthCircuit::build();
        for s in &c.slots {
            match s.role {
                AuthSlotRole::HAddrPermA { .. } | AuthSlotRole::HAuthPermA { .. } => {
                    assert!(s.is_head);
                    assert!(s.prev_output_src.is_none());
                }
                AuthSlotRole::HAddrPermB { .. }
                | AuthSlotRole::HAuthPermB { .. }
                | AuthSlotRole::HAuthPermC { .. } => {
                    assert!(!s.is_head);
                    assert_eq!(s.prev_output_src, Some(s.id - 1));
                }
            }
        }
    }

    #[test]
    fn ivs_match_domain_tags() {
        let c = AuthCircuit::build();
        let iv_addr = capacity_iv(TAG_ADDRESS);
        let iv_auth = capacity_iv(TAG_AUTHTAG);
        for s in &c.slots {
            match s.role {
                AuthSlotRole::HAddrPermA { .. } | AuthSlotRole::HAddrPermB { .. } => {
                    assert_eq!(s.capacity_iv, iv_addr);
                }
                AuthSlotRole::HAuthPermA { .. }
                | AuthSlotRole::HAuthPermB { .. }
                | AuthSlotRole::HAuthPermC { .. } => {
                    assert_eq!(s.capacity_iv, iv_auth);
                }
            }
        }
    }

    #[test]
    fn output_slot_accessors_land_on_correct_role() {
        let c = AuthCircuit::build();
        for i in 0..N_AUTH_INPUTS {
            let addr_slot = &c.slots[AuthCircuit::haddr_output_slot(i)];
            assert!(
                matches!(addr_slot.role, AuthSlotRole::HAddrPermB { input_idx } if input_idx as usize == i)
            );

            let auth_slot = &c.slots[AuthCircuit::hauth_output_slot(i)];
            assert!(
                matches!(auth_slot.role, AuthSlotRole::HAuthPermC { input_idx } if input_idx as usize == i)
            );
        }
    }
}
