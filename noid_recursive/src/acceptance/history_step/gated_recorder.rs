// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Parent-arm recorder for the base-selectable HistoryStep relation.
//!
//! It is transcript-identical to `FsChannelUnionRecorder`.  The sole local
//! difference is that the BaseFold grind range equality goes through the
//! recursive trace's scoped `pin_eq`, so `live = 0` gates that verifier
//! rejection together with every other parent-arm rejection.  No transcript
//! byte, proof parameter, or primitive is changed.

use noid_ivc_core::challenger::{
    fs_lane_iv_flat, fs_op_lane, fs_pack_bytes_lanes, fs_pad_lane_flat, FS_KIND_SCALAR,
    FS_KIND_SLICE, FS_OP_BYTES, FS_OP_DOMAIN, FS_OP_LABEL, FS_OP_OBSERVE, FS_OP_POW, FS_OP_SQUEEZE,
};
use noid_ivc_core::field::F128;
use noid_ivc_core::field_circuit::{
    f128_from_u128, f128_to_u128, FieldR1csBuilder, FsChannelOps, LinExpr, RecordedChannel,
};
use noid_poseidon2b::native::permutation::STATE_SIZE;

use super::super::trace::pin_eq;

pub(super) struct BaseSelectableParentRecorder {
    state: [F128; STATE_SIZE],
    buffered: Option<F128>,
    pending: Option<F128>,
    cur_absorb: Vec<Option<u128>>,
    ops: Vec<noid_ivc_core::deep_chain::schedule::TranscriptOp>,
    data_wires: Vec<LinExpr>,
    data_flat: Vec<F128>,
    challenge_wires: Vec<LinExpr>,
    perms: usize,
}

impl BaseSelectableParentRecorder {
    pub(super) fn new(domain: &[u8]) -> Self {
        let [iv0, iv1] = fs_lane_iv_flat();
        let mut recorder = Self {
            state: [F128::ZERO, F128::ZERO, iv0, iv1],
            buffered: None,
            pending: None,
            cur_absorb: Vec::new(),
            ops: Vec::new(),
            data_wires: Vec::new(),
            data_flat: Vec::new(),
            challenge_wires: Vec::new(),
            perms: 0,
        };
        recorder.absorb_const(fs_op_lane(FS_OP_DOMAIN, 0, domain.len() as u64));
        for lane in fs_pack_bytes_lanes(domain) {
            recorder.absorb_const(lane);
        }
        recorder
    }

    fn flat_bits(value: F128) -> u128 {
        (value.lo as u128) | ((value.hi as u128) << 64)
    }

    fn permute(&mut self) {
        let mut lanes: [u128; STATE_SIZE] =
            std::array::from_fn(|index| Self::flat_bits(self.state[index]));
        noid_poseidon2b::native::permutation::permute_flat_u128(&mut lanes);
        self.state = std::array::from_fn(|index| F128 {
            lo: lanes[index] as u64,
            hi: (lanes[index] >> 64) as u64,
        });
        self.perms += 1;
    }

    fn absorb_native(&mut self, value: F128) {
        self.pending = None;
        if let Some(first) = self.buffered.take() {
            self.state[0] += first;
            self.state[1] += value;
            self.permute();
        } else {
            self.buffered = Some(value);
        }
    }

    fn absorb_const(&mut self, value: F128) {
        self.cur_absorb
            .push(Some(noid_core::hardware::flat_to_tower_u128(
                Self::flat_bits(value),
            )));
        self.absorb_native(value);
    }

    fn absorb_expr(&mut self, builder: &FieldR1csBuilder, expression: &LinExpr) {
        if expression.is_const() {
            self.absorb_const(expression.constant);
        } else {
            let value = expression.eval(builder.values());
            self.cur_absorb.push(None);
            self.data_wires.push(expression.clone());
            self.data_flat.push(value);
            self.absorb_native(value);
        }
    }

    fn close_absorb(&mut self) {
        if !self.cur_absorb.is_empty() {
            self.ops
                .push(noid_ivc_core::deep_chain::schedule::TranscriptOp::Absorb(
                    std::mem::take(&mut self.cur_absorb),
                ));
        }
    }

    fn squeeze_native(&mut self) -> F128 {
        if let Some(pending) = self.pending.take() {
            return pending;
        }
        if let Some(first) = self.buffered.take() {
            self.state[0] += first;
            self.state[1] += fs_pad_lane_flat();
            self.permute();
        }
        let out = self.state[0];
        self.pending = Some(self.state[1]);
        self.permute();
        out
    }

    fn squeeze(&mut self, builder: &mut FieldR1csBuilder) -> LinExpr {
        let value = self.squeeze_native();
        let wire = LinExpr::from_wire(builder.alloc_f128(value));
        self.challenge_wires.push(wire.clone());
        wire
    }

    fn gated_decompose_bits_le(
        builder: &mut FieldR1csBuilder,
        expression: &LinExpr,
        n_bits: usize,
    ) {
        assert!(n_bits <= 128);
        let value = f128_to_u128(expression.eval(builder.values()));
        let bits = (0..n_bits)
            .map(|bit| builder.alloc_bool((value >> bit) & 1 == 1))
            .collect::<Vec<_>>();
        let reconstructed =
            bits.into_iter()
                .enumerate()
                .fold(LinExpr::zero(), |sum, (bit, wire)| {
                    sum.add(&LinExpr::from_wire(wire).scale(f128_from_u128(1u128 << bit)))
                });
        pin_eq(builder, &reconstructed, expression);
    }

    pub(super) fn finish(mut self) -> RecordedChannel {
        self.close_absorb();
        RecordedChannel {
            ops: self.ops,
            data_wires: self.data_wires,
            data_flat: self.data_flat,
            challenge_wires: self.challenge_wires,
            post_state: self.state,
            perms: self.perms,
        }
    }
}

impl FsChannelOps for BaseSelectableParentRecorder {
    fn observe_label(&mut self, _builder: &mut FieldR1csBuilder, label: &[u8]) {
        self.absorb_const(fs_op_lane(FS_OP_LABEL, 0, label.len() as u64));
        for lane in fs_pack_bytes_lanes(label) {
            self.absorb_const(lane);
        }
    }

    fn observe_f128(&mut self, builder: &mut FieldR1csBuilder, value: &LinExpr) {
        self.absorb_const(fs_op_lane(FS_OP_OBSERVE, FS_KIND_SCALAR, 0));
        self.absorb_expr(builder, value);
    }

    fn observe_f128_slice(&mut self, builder: &mut FieldR1csBuilder, values: &[LinExpr]) {
        self.absorb_const(fs_op_lane(
            FS_OP_OBSERVE,
            FS_KIND_SLICE,
            values.len() as u64,
        ));
        for value in values {
            self.absorb_expr(builder, value);
        }
    }

    fn sample_f128(&mut self, builder: &mut FieldR1csBuilder) -> LinExpr {
        self.absorb_const(fs_op_lane(FS_OP_SQUEEZE, FS_KIND_SCALAR, 0));
        self.close_absorb();
        self.ops
            .push(noid_ivc_core::deep_chain::schedule::TranscriptOp::Squeeze(
                1,
            ));
        self.squeeze(builder)
    }

    fn sample_f128_vec(&mut self, builder: &mut FieldR1csBuilder, n: usize) -> Vec<LinExpr> {
        self.absorb_const(fs_op_lane(FS_OP_SQUEEZE, FS_KIND_SLICE, n as u64));
        self.close_absorb();
        self.ops
            .push(noid_ivc_core::deep_chain::schedule::TranscriptOp::Squeeze(
                n,
            ));
        (0..n).map(|_| self.squeeze(builder)).collect()
    }

    fn verify_pow(&mut self, builder: &mut FieldR1csBuilder, nonce: &LinExpr, bits: u32) {
        assert!(bits <= 64, "leading-zero window limited to the top limb");
        self.absorb_const(fs_op_lane(FS_OP_POW, 0, bits as u64));
        self.absorb_expr(builder, nonce);
        self.absorb_const(fs_op_lane(FS_OP_SQUEEZE, FS_KIND_SCALAR, 0));
        self.close_absorb();
        self.ops
            .push(noid_ivc_core::deep_chain::schedule::TranscriptOp::Squeeze(
                1,
            ));
        let challenge = self.squeeze(builder);
        if bits > 0 {
            Self::gated_decompose_bits_le(builder, &challenge, 128 - bits as usize);
        } else {
            Self::gated_decompose_bits_le(builder, nonce, 0);
        }
    }

    fn observe_bytes_const(&mut self, _builder: &mut FieldR1csBuilder, bytes: &[u8]) {
        self.absorb_const(fs_op_lane(FS_OP_BYTES, 0, bytes.len() as u64));
        for lane in fs_pack_bytes_lanes(bytes) {
            self.absorb_const(lane);
        }
    }

    fn observe_lanes(&mut self, builder: &mut FieldR1csBuilder, byte_len: u64, lanes: &[LinExpr]) {
        assert_eq!(lanes.len() as u64, byte_len.div_ceil(16));
        self.absorb_const(fs_op_lane(FS_OP_BYTES, 0, byte_len));
        for lane in lanes {
            self.absorb_expr(builder, lane);
        }
    }
}
