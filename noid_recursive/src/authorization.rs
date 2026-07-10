// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Native authorization-batch relation for recursive history proving.
//!
//! This module intentionally sits below `noid_block`: it depends only on the
//! semantic block and the OwnerAuth verifier boundary. The public HistoryProof
//! relation must prove this verifier language in-proof; this native function is
//! the exact specification and test oracle for that component.

use noid_chain::Block;
use noid_core::transcript::FiatShamir;
use noid_core::Block128;
use noid_gkr::{
    canonical_authorization_statement_from_body, init_owner_auth_gkr_channel,
    validate_authorization_statement, verify_owner_auth_killshot_with_claims,
    CanonicalAuthorizationStatement, OwnerAuthCircuit, OwnerAuthProofKillShot,
    OwnerAuthVerifierClaims, VerifiedAuthorization, VerifiedAuthorizationBatch,
    VerifyAuthorizationError,
};
use noid_poseidon2b::Poseidon2bChannel;
use rayon::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FiatShamirTraceOp {
    Absorb(Block128),
    Squeeze(Block128),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuthorizationVerifierTrace {
    pub tx_index: usize,
    pub live_input_count: usize,
    pub proof_byte_len: usize,
    pub transcript: Vec<FiatShamirTraceOp>,
    pub verifier_claims: OwnerAuthVerifierClaims,
}

struct TracingPoseidon2bChannel {
    inner: Poseidon2bChannel,
    transcript: Vec<FiatShamirTraceOp>,
}

impl TracingPoseidon2bChannel {
    fn new() -> Self {
        Self {
            inner: Poseidon2bChannel::new(),
            transcript: Vec::new(),
        }
    }

    fn into_transcript(self) -> Vec<FiatShamirTraceOp> {
        self.transcript
    }
}

impl FiatShamir<Block128> for TracingPoseidon2bChannel {
    fn absorb(&mut self, elem: Block128) {
        self.transcript.push(FiatShamirTraceOp::Absorb(elem));
        self.inner.absorb(elem);
    }

    fn squeeze(&mut self) -> Block128 {
        let challenge = self.inner.squeeze();
        self.transcript.push(FiatShamirTraceOp::Squeeze(challenge));
        challenge
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationBatchError {
    SidecarShapeMismatch {
        expected_user_txs: usize,
        actual_proofs: usize,
    },
    Statement {
        tx_index: usize,
    },
    Proof {
        tx_index: usize,
    },
    EmptyVerifiedCounts {
        tx_index: usize,
    },
}

/// Canonical traced form of `noid_gkr::verify_authorization_statement_proof`:
/// the same checks with the same error semantics, additionally capturing the
/// verifier's FS transcript and final claims for recursive component inputs.
///
/// The `AcceptBlock` batch replay injects this through a tracing
/// `AuthorizationVerifier` so every owner-auth killshot is verified exactly
/// once per block.
pub fn verify_authorization_statement_proof_with_trace(
    statement: &CanonicalAuthorizationStatement,
    proof: &OwnerAuthProofKillShot,
) -> Result<(VerifiedAuthorization, AuthorizationVerifierTrace), VerifyAuthorizationError> {
    validate_authorization_statement(statement)?;
    let circuit = OwnerAuthCircuit::build();
    let mut channel = TracingPoseidon2bChannel::new();
    init_owner_auth_gkr_channel(&mut channel);
    let verifier_claims =
        verify_owner_auth_killshot_with_claims(proof, &circuit, &statement.public, &mut channel)
            .ok_or(VerifyAuthorizationError::AuthProof)?;

    let verified = VerifiedAuthorization {
        tx_index: statement.tx_index,
        live_input_count: usize::from(statement.live_input_count),
    };
    let trace = AuthorizationVerifierTrace {
        tx_index: statement.tx_index,
        live_input_count: verified.live_input_count,
        proof_byte_len: proof.byte_len(),
        transcript: channel.into_transcript(),
        verifier_claims,
    };
    Ok((verified, trace))
}

fn verify_authorization_statement_with_trace(
    statement: &CanonicalAuthorizationStatement,
    proof: &OwnerAuthProofKillShot,
) -> Result<(VerifiedAuthorization, AuthorizationVerifierTrace), AuthorizationBatchError> {
    verify_authorization_statement_proof_with_trace(statement, proof).map_err(|_| {
        AuthorizationBatchError::Proof {
            tx_index: statement.tx_index,
        }
    })
}

pub fn verify_authorization_batch_native(
    block: &Block,
    proofs: &[OwnerAuthProofKillShot],
) -> Result<VerifiedAuthorizationBatch, AuthorizationBatchError> {
    verify_authorization_batch_native_with_traces(block, proofs).map(|(batch, _)| batch)
}

pub fn verify_authorization_batch_native_with_traces(
    block: &Block,
    proofs: &[OwnerAuthProofKillShot],
) -> Result<(VerifiedAuthorizationBatch, Vec<AuthorizationVerifierTrace>), AuthorizationBatchError>
{
    let user_txs: Vec<_> = block
        .transactions
        .iter()
        .enumerate()
        .filter(|(_, tx)| !tx.body.is_coinbase)
        .collect();
    if user_txs.len() != proofs.len() {
        return Err(AuthorizationBatchError::SidecarShapeMismatch {
            expected_user_txs: user_txs.len(),
            actual_proofs: proofs.len(),
        });
    }

    let verified = user_txs
        .par_iter()
        .zip(proofs.par_iter())
        .map(|((tx_index, tx), proof)| {
            let statement = canonical_authorization_statement_from_body(
                *tx_index,
                tx.txid().as_fields(),
                &tx.body,
            )
            .map_err(|_| AuthorizationBatchError::Statement {
                tx_index: *tx_index,
            })?;
            let (verified, trace) = verify_authorization_statement_with_trace(&statement, proof)?;
            if verified.live_input_count == 0 {
                return Err(AuthorizationBatchError::EmptyVerifiedCounts {
                    tx_index: *tx_index,
                });
            }
            Ok((verified.live_input_count, trace))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let live_input_count_total = verified
        .iter()
        .map(|(live_inputs, _)| *live_inputs)
        .sum::<usize>();
    let traces = verified
        .into_iter()
        .map(|(_, trace)| trace)
        .collect::<Vec<_>>();

    Ok((
        VerifiedAuthorizationBatch {
            user_tx_count: user_txs.len(),
            live_input_count_total,
        },
        traces,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::BlockHeader;
    use noid_core::TowerField;
    use noid_gkr::OwnerAuthWitness;
    use noid_poseidon2b::primitives::{derive_address, Address, SpendSecret};
    use noid_tx::{
        output_bitmap_bit, Transaction, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS,
    };

    fn body_and_secret() -> (TxBody, SpendSecret) {
        let secret = SpendSecret([0x42; 32]);
        let owner = derive_address(&secret);
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: 7,
            amount: 100,
            creation_id: 0,
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: 1007,
            amount: 97,
            owner: Address([0x11; 32]),
        };
        let body = TxBody {
            epoch_anchor: [0xA5; 32],
            fee: 3,
            input_owner: owner,
            inputs,
            outputs,
            validity_bitmap: 1 | output_bitmap_bit(0),
            is_coinbase: false,
        };
        (body, secret)
    }

    fn tx(body: TxBody) -> Transaction {
        Transaction::new(body)
    }

    fn block(transaction: Transaction) -> Block {
        Block {
            header: BlockHeader {
                prev_block_hash: [0u8; 32],
                state_root: [1u8; 32],
                tx_root: [2u8; 32],
                timestamp: 1,
                height: 1,
                miner_address: Address([0x33; 32]),
                nonce: 0,
                difficulty_target: [0xFF; 32],
                log_slots: 24,
                active_slot_count: 1,
                alloc_counter: 1,
            },
            transactions: vec![transaction],
        }
    }

    #[test]
    fn authorization_batch_accepts_and_rejects_tamper() {
        let (body, secret) = body_and_secret();
        let raw_secret = secret.0;
        let proof = noid_gkr::prove_wallet_authorization(&body, OwnerAuthWitness::new(secret))
            .expect("wallet auth")
            .proof;
        let block = block(tx(body));

        let verified = verify_authorization_batch_native(&block, std::slice::from_ref(&proof))
            .expect("authorization batch verifies");
        assert_eq!(verified.user_tx_count, 1);
        assert_eq!(verified.live_input_count_total, 1);

        let (verified, traces) =
            verify_authorization_batch_native_with_traces(&block, std::slice::from_ref(&proof))
                .expect("traced authorization batch verifies");
        assert_eq!(verified.user_tx_count, 1);
        assert_eq!(traces.len(), 1);
        assert_eq!(traces[0].tx_index, 0);
        assert_eq!(traces[0].live_input_count, 1);
        assert_eq!(traces[0].proof_byte_len, proof.byte_len());
        assert_eq!(traces[0].verifier_claims.state_claims.len(), 3);
        assert_eq!(
            traces[0].verifier_claims.state_claims[0].value,
            traces[0].verifier_claims.main.state_at_r
        );
        assert_eq!(
            traces[0].verifier_claims.state_claims[1].value,
            traces[0].verifier_claims.shift.state_at_r2
        );
        assert_eq!(
            traces[0].verifier_claims.state_claims[2].value,
            traces[0].verifier_claims.boundary.state_at_r
        );
        assert_eq!(
            traces[0].verifier_claims.state.point.len(),
            traces[0].verifier_claims.state_claims[0].point.len()
        );
        let first_squeeze = traces[0]
            .transcript
            .iter()
            .position(|op| matches!(op, FiatShamirTraceOp::Squeeze(_)))
            .expect("accepted proof verifier must squeeze challenges");
        assert!(
            first_squeeze > 8,
            "public statement and PCS commitment must be absorbed first"
        );
        assert!(traces[0].transcript[..first_squeeze]
            .iter()
            .all(|op| matches!(op, FiatShamirTraceOp::Absorb(_))));

        // The recursive verifier artifact is public replay data. It may carry
        // the authorization proof and Fiat-Shamir transcript, but never the
        // wallet's raw owner witness.
        let encoded_trace = bincode::serialize(&traces[0]).expect("serialize verifier trace");
        assert!(
            !encoded_trace
                .windows(raw_secret.len())
                .any(|window| window == raw_secret),
            "authorization verifier trace serialized the raw spend secret"
        );

        let mut bad_hash_block = block.clone();
        bad_hash_block.transactions[0].body.epoch_anchor[0] ^= 0x80;
        assert!(matches!(
            verify_authorization_batch_native_with_traces(
                &bad_hash_block,
                std::slice::from_ref(&proof)
            ),
            Err(AuthorizationBatchError::Proof { tx_index: 0 })
        ));

        let mut bad = proof.clone();
        bad.kill_shot.main.state_at_r += noid_core::Block128::ONE;
        assert!(matches!(
            verify_authorization_batch_native(&block, &[bad]),
            Err(AuthorizationBatchError::Proof { tx_index: 0 })
        ));
        assert!(matches!(
            verify_authorization_batch_native(&block, &[]),
            Err(AuthorizationBatchError::SidecarShapeMismatch {
                expected_user_txs: 1,
                actual_proofs: 0
            })
        ));
    }
}
