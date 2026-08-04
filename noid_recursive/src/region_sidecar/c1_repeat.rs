// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! C1 response adapter for sequential base-field sidecar repetition.
//!
//! Sidecar algebra stays in `GF(2^128)`, but every public-coin draw is a
//! canonically framed C1 wide response.  One repetition consumes the uniform
//! low coordinate; the trace-one high coordinate remains part of the typed
//! response and advances the transcript.  Running two complete repetitions
//! sequentially then gives two conditionally fresh base-field challenge
//! streams without paying extension-field multiplication rows.

use noid_ivc_core::challenger::Challenger;
use noid_ivc_core::field::{F128, F256};
#[cfg(test)]
use noid_ivc_core::field_circuit::{ExtExpr, FieldR1csBuilder, FsChannelOps, LinExpr};

pub(super) const SIDECAR_C1_REPETITIONS: usize = 2;

/// Native channel view whose scalar samples are C1 wide samples projected to
/// their uniform low coordinate.  Observations keep their original base-field
/// framing; only verifier responses are widened.
pub(super) struct WideResponseLowChallenger<'a, C> {
    inner: &'a mut C,
}

impl<'a, C> WideResponseLowChallenger<'a, C> {
    pub(super) fn new(inner: &'a mut C) -> Self {
        Self { inner }
    }
}

impl<C: Challenger> Challenger for WideResponseLowChallenger<'_, C> {
    fn observe_label(&mut self, label: &[u8]) {
        self.inner.observe_label(label);
    }

    fn observe_f128(&mut self, value: F128) {
        self.inner.observe_f128(value);
    }

    fn observe_f128_slice(&mut self, values: &[F128]) {
        self.inner.observe_f128_slice(values);
    }

    fn observe_f256(&mut self, value: F256) {
        self.inner.observe_f256(value);
    }

    fn observe_f256_slice(&mut self, values: &[F256]) {
        self.inner.observe_f256_slice(values);
    }

    fn observe_bytes(&mut self, bytes: &[u8]) {
        self.inner.observe_bytes(bytes);
    }

    fn sample_f128(&mut self) -> F128 {
        self.inner.sample_f256().lo
    }

    fn sample_f128_vec(&mut self, n: usize) -> Vec<F128> {
        self.inner
            .sample_f256_vec(n)
            .into_iter()
            .map(|challenge| challenge.lo)
            .collect()
    }

    fn sample_f256(&mut self) -> F256 {
        self.inner.sample_f256()
    }

    fn sample_f256_vec(&mut self, n: usize) -> Vec<F256> {
        self.inner.sample_f256_vec(n)
    }

    fn grind_pow(&mut self, bits: u32) -> u64 {
        self.inner.grind_pow(bits)
    }

    fn verify_pow(&mut self, nonce: u64, bits: u32) -> bool {
        self.inner.verify_pow(nonce, bits)
    }
}

/// Recursive channel twin of [`WideResponseLowChallenger`].  The discarded
/// expression coordinate is still allocated and constrained by the canonical
/// C1 sampler inside the underlying channel.
#[cfg(test)]
pub(super) struct WideResponseLowTrace<'a, C> {
    inner: &'a mut C,
}

#[cfg(test)]
impl<'a, C> WideResponseLowTrace<'a, C> {
    pub(super) fn new(inner: &'a mut C) -> Self {
        Self { inner }
    }
}

#[cfg(test)]
impl<C: FsChannelOps> FsChannelOps for WideResponseLowTrace<'_, C> {
    fn observe_label(&mut self, builder: &mut FieldR1csBuilder, label: &[u8]) {
        self.inner.observe_label(builder, label);
    }

    fn observe_f128(&mut self, builder: &mut FieldR1csBuilder, value: &LinExpr) {
        self.inner.observe_f128(builder, value);
    }

    fn observe_f128_slice(&mut self, builder: &mut FieldR1csBuilder, values: &[LinExpr]) {
        self.inner.observe_f128_slice(builder, values);
    }

    fn observe_f256(&mut self, builder: &mut FieldR1csBuilder, value: &ExtExpr) {
        self.inner.observe_f256(builder, value);
    }

    fn observe_f256_slice(&mut self, builder: &mut FieldR1csBuilder, values: &[ExtExpr]) {
        self.inner.observe_f256_slice(builder, values);
    }

    fn sample_f128(&mut self, builder: &mut FieldR1csBuilder) -> LinExpr {
        self.inner.sample_f256(builder).lo
    }

    fn sample_f128_vec(&mut self, builder: &mut FieldR1csBuilder, n: usize) -> Vec<LinExpr> {
        self.inner
            .sample_f256_vec(builder, n)
            .into_iter()
            .map(|challenge| challenge.lo)
            .collect()
    }

    fn sample_f256(&mut self, builder: &mut FieldR1csBuilder) -> ExtExpr {
        self.inner.sample_f256(builder)
    }

    fn sample_f256_vec(&mut self, builder: &mut FieldR1csBuilder, n: usize) -> Vec<ExtExpr> {
        self.inner.sample_f256_vec(builder, n)
    }

    fn verify_pow(&mut self, builder: &mut FieldR1csBuilder, nonce: &LinExpr, bits: u32) {
        self.inner.verify_pow(builder, nonce, bits);
    }

    fn observe_bytes_const(&mut self, builder: &mut FieldR1csBuilder, bytes: &[u8]) {
        self.inner.observe_bytes_const(builder, bytes);
    }

    fn observe_lanes(&mut self, builder: &mut FieldR1csBuilder, byte_len: u64, lanes: &[LinExpr]) {
        self.inner.observe_lanes(builder, byte_len, lanes);
    }
}

#[cfg(test)]
mod tests {
    use noid_ivc_core::challenger::FsLaneChallenger;
    use noid_ivc_core::field_circuit::{FsChannelTrace, FsChannelUnionRecorder};

    use super::*;

    const DOMAIN: &[u8] = b"sidecar-c1-wide-response-low-test";

    #[test]
    fn native_and_recursive_wide_response_projection_are_lockstep() {
        let values = [F128::new(1, 2), F128::new(3, 4), F128::new(5, 6)];

        let mut native = FsLaneChallenger::new_c1(DOMAIN);
        let mut builder = FieldR1csBuilder::new();
        let mut trace = FsChannelTrace::new_c1(&mut builder, DOMAIN);
        let expressions = values.map(|value| LinExpr::from_wire(builder.alloc_f128(value)));

        let (native_scalar, native_vector) = {
            let mut channel = WideResponseLowChallenger::new(&mut native);
            channel.observe_label(b"repetition-0");
            channel.observe_f128_slice(&values);
            (channel.sample_f128(), channel.sample_f128_vec(7))
        };
        let (trace_scalar, trace_vector) = {
            let mut channel = WideResponseLowTrace::new(&mut trace);
            channel.observe_label(&mut builder, b"repetition-0");
            channel.observe_f128_slice(&mut builder, &expressions);
            (
                channel.sample_f128(&mut builder),
                channel.sample_f128_vec(&mut builder, 7),
            )
        };

        assert_eq!(trace_scalar.eval(builder.values()), native_scalar);
        assert_eq!(
            trace_vector
                .iter()
                .map(|value| value.eval(builder.values()))
                .collect::<Vec<_>>(),
            native_vector,
        );
        assert_eq!(
            trace.sample_f256(&mut builder).eval(builder.values()),
            native.sample_f256(),
            "the unused high response coordinates did not advance in lockstep",
        );
        let (r1cs, witness) = builder.build();
        assert!(r1cs.satisfies(&witness));
    }

    #[test]
    fn recorder_exposes_two_squeeze_lanes_per_scalar_response() {
        let mut builder = FieldR1csBuilder::new();
        let mut recorder = FsChannelUnionRecorder::new_c1(DOMAIN);
        let value = LinExpr::from_wire(builder.alloc_f128(F128::new(7, 8)));
        {
            let mut channel = WideResponseLowTrace::new(&mut recorder);
            channel.observe_f128(&mut builder, &value);
            let _ = channel.sample_f128(&mut builder);
            let _ = channel.sample_f128_vec(&mut builder, 3);
        }
        let recording = recorder.finish();
        let squeeze_counts = recording
            .ops
            .iter()
            .filter_map(|op| match op {
                noid_ivc_core::deep_chain::schedule::TranscriptOp::Squeeze(count) => Some(*count),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(squeeze_counts, vec![2, 6]);
        assert_eq!(recording.challenge_wires.len(), 8);
    }
}
