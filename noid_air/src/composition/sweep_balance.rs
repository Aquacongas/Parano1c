// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Shape-specific balance witness plumbing for `Sweep25x2`.
//!
//! This deliberately integrates only the conservation-law AIR for the large
//! sweep shape. AuthGKR, tx-body spine and full wallet proof dispatch remain
//! separate milestones, so the standard `TxLogicAir` stays unchanged.

use crate::airs::{
    Sweep25x2BalanceGateAir, BALANCE_MIN_LOG_ROWS, SWEEP_BALANCE_INPUTS, SWEEP_BALANCE_OUTPUTS,
};
use crate::Trace;
use noid_tx::{TxBody, TxShape};

/// Log-rows used by the standalone `Sweep25x2` balance proof.
pub const SWEEP25X2_BALANCE_LOG_ROWS: usize = BALANCE_MIN_LOG_ROWS;

/// Witness operands for the standalone `Sweep25x2` balance AIR.
#[derive(Clone)]
pub struct Sweep25x2BalanceWitness {
    /// Body cloned for auditability and future shape-specific integration.
    pub body: TxBody,
    pub balance_inputs: [u64; SWEEP_BALANCE_INPUTS],
    pub balance_outputs: [u64; SWEEP_BALANCE_OUTPUTS],
    pub balance_fee: u64,
}

impl Sweep25x2BalanceWitness {
    /// Build the standalone sweep balance AIR and honest trace.
    pub fn build_air_and_trace(&self) -> (Sweep25x2BalanceGateAir, Trace) {
        self.build_air_and_trace_with_log_rows(SWEEP25X2_BALANCE_LOG_ROWS)
    }

    /// Build the standalone sweep balance AIR and honest trace at an explicit
    /// row count. This is useful for proving tests that want to match a broader
    /// composition's base length later.
    pub fn build_air_and_trace_with_log_rows(
        &self,
        log_rows: usize,
    ) -> (Sweep25x2BalanceGateAir, Trace) {
        let air = Sweep25x2BalanceGateAir::new(log_rows);
        let trace = air.build_trace(self.balance_inputs, self.balance_outputs, self.balance_fee);
        (air, trace)
    }
}

/// Derive standalone sweep balance operands from a `TxBody`.
///
/// This helper is intentionally shape-strict. It is not a full wallet proof
/// witness: it only lowers public values into the 25-input / 2-output
/// conservation AIR.
pub fn sweep25x2_balance_witness_from_body(body: &TxBody) -> Sweep25x2BalanceWitness {
    assert_eq!(
        body.shape,
        TxShape::Sweep25x2,
        "unsupported tx body shape for Sweep25x2 balance AIR"
    );
    assert!(
        !body.is_coinbase,
        "Sweep25x2 balance AIR does not support coinbase transactions"
    );
    assert!(
        body.inputs.len() <= SWEEP_BALANCE_INPUTS,
        "inputs exceed Sweep25x2 balance input capacity"
    );
    assert!(
        body.outputs.len() <= SWEEP_BALANCE_OUTPUTS,
        "outputs exceed Sweep25x2 balance output capacity"
    );
    assert!(
        body.fee <= u64::MAX as u128,
        "TxBody.fee ({}) exceeds u64::MAX — sweep balance circuit cannot represent it",
        body.fee,
    );

    let mut balance_inputs = [0u64; SWEEP_BALANCE_INPUTS];
    for (i, inp) in body.inputs.iter().enumerate() {
        if inp.valid {
            balance_inputs[i] = inp.value;
        }
    }

    let mut balance_outputs = [0u64; SWEEP_BALANCE_OUTPUTS];
    for (i, out) in body.outputs.iter().enumerate() {
        if out.valid {
            balance_outputs[i] = out.value;
        }
    }

    Sweep25x2BalanceWitness {
        body: body.clone(),
        balance_inputs,
        balance_outputs,
        balance_fee: body.fee as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Air;
    use noid_poseidon2b::primitives::{Address, SpendSecret};
    use noid_tx::{TxInput, TxOutput};

    fn mk_input(i: usize) -> TxInput {
        TxInput {
            slot_index: i as u32,
            value: 100 + i as u64,
            owner: Address([i as u8; 32]),
            spend_secret: SpendSecret([0xA0 ^ i as u8; 32]),
            valid: true,
        }
    }

    fn mk_sweep_body() -> TxBody {
        let inputs: Vec<TxInput> = (0..SWEEP_BALANCE_INPUTS).map(mk_input).collect();
        let total: u64 = inputs.iter().map(|i| i.value).sum();
        let fee = 77u64;
        let spendable = total - fee;
        TxBody {
            shape: TxShape::Sweep25x2,
            epoch_anchor: [0xCC; 32],
            fee: fee as u128,
            inputs,
            outputs: vec![
                TxOutput {
                    slot_index: 100,
                    value: spendable / 2,
                    owner: Address([0x11; 32]),
                    valid: true,
                },
                TxOutput {
                    slot_index: 101,
                    value: spendable - spendable / 2,
                    owner: Address([0x22; 32]),
                    valid: true,
                },
            ],
            is_coinbase: false,
        }
    }

    #[test]
    fn sweep_balance_witness_from_body_accepts_25x2() {
        let body = mk_sweep_body();
        let witness = sweep25x2_balance_witness_from_body(&body);
        assert_eq!(witness.balance_inputs[0], 100);
        assert_eq!(witness.balance_inputs[24], 124);
        assert_eq!(witness.balance_fee, 77);

        let (air, trace) = witness.build_air_and_trace();
        assert!(air.check(&trace));
    }

    #[test]
    #[should_panic(expected = "unsupported tx body shape for Sweep25x2 balance AIR")]
    fn sweep_balance_witness_rejects_standard_shape() {
        let mut body = mk_sweep_body();
        body.shape = TxShape::Standard4x8;
        let _ = sweep25x2_balance_witness_from_body(&body);
    }

    #[test]
    #[should_panic(expected = "Sweep25x2 balance AIR does not support coinbase transactions")]
    fn sweep_balance_witness_rejects_coinbase() {
        let mut body = mk_sweep_body();
        body.is_coinbase = true;
        let _ = sweep25x2_balance_witness_from_body(&body);
    }
}
