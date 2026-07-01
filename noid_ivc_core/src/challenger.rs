//! Verifier-randomness abstraction.
//!
//! A [`Challenger`] is the source of verifier challenges in the protocol.
//! The prover writes its messages into the challenger (`observe_*`) and reads
//! challenges back out (`sample_*`). The verifier mirrors this exactly — as
//! it walks through the proof, it observes each prover message and samples
//! the same challenges, so both sides derive the same randomness in lockstep.
//!
//! Two implementations:
//! - `RandomChallenger` — seeded pseudo-random, ignores observed messages.
//!   Kept around for bench isolation (measure prover cost without FS overhead)
//!   and soundness mutation tests. **Not sound for real proofs**, and to make
//!   that structural it is compiled *only* under `cfg(test)` or the
//!   `unsound-challenger` feature — a normal (real-proof) build has no insecure
//!   challenger to reach for.
//! - [`FsChallenger`] — Fiat-Shamir transcript backed by the production
//!   Poseidon2b sponge domain.

use crate::field::F128;
use noid_poseidon2b::native::{
    Poseidon2bSponge, TAG_FSCHALNG, capacity_iv, poseidon2b_hash_byte_slices,
};

// `Send` supertrait: the verifier runs its PIOP/PCS replay inside a dedicated
// single-thread rayon pool (see `verifier::verifier_pool`), so the challenger
// it threads through must be able to cross into that pool. Both concrete
// challengers (`RandomChallenger`, `FsChallenger`) are trivially `Send`.
pub trait Challenger: Send {
    /// Absorb a domain-separation label (e.g. `b"history-zerocheck-v0"`). Each
    /// protocol entry should call this once on entry so a transcript from
    /// one protocol cannot be replayed as another.
    fn observe_label(&mut self, _label: &[u8]) {
        // default no-op — RandomChallenger inherits this.
    }

    /// Absorb a single F128 prover message.
    fn observe_f128(&mut self, value: F128);

    /// Absorb a slice of F128 prover messages (e.g. the round-1 vector).
    fn observe_f128_slice(&mut self, values: &[F128]) {
        for v in values {
            self.observe_f128(*v);
        }
    }

    /// Absorb arbitrary bytes (e.g. a Merkle root or a statement digest).
    fn observe_bytes(&mut self, _bytes: &[u8]) {
        // default no-op — RandomChallenger inherits this.
    }

    /// Produce one F128 challenge.
    fn sample_f128(&mut self) -> F128;

    /// Produce `n` F128 challenges, in order.
    fn sample_f128_vec(&mut self, n: usize) -> Vec<F128> {
        (0..n).map(|_| self.sample_f128()).collect()
    }

    /// Prover-side transcript grinding: snapshot the current transcript state,
    /// search for a `u64` nonce such that the Poseidon2b proof hash over
    /// `(state, nonce)` has at least `bits` leading zero bits, then absorb the
    /// nonce into the transcript so subsequent challenges bind to it.
    ///
    /// Default implementation is a no-op (returns 0). Real implementations
    /// — e.g. [`FsChallenger`] — do the actual grind work and absorb the
    /// nonce. `bits = 0` means "no PoW required"; still absorbs the 0 nonce
    /// so the verifier mirror is byte-identical.
    fn grind_pow(&mut self, _bits: u32) -> u64 {
        0
    }

    /// Verifier-side mirror of [`Self::grind_pow`]: check that `nonce`
    /// satisfies the `bits`-leading-zeros PoW against the current transcript
    /// state, then absorb the nonce so the running state stays in lockstep
    /// with the prover.
    ///
    /// Default implementation accepts unconditionally (no-op). Real
    /// implementations must check the PoW; an honest verifier rejects the
    /// proof if this returns `false`.
    fn verify_pow(&mut self, _nonce: u64, _bits: u32) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// RandomChallenger — seeded SplitMix64 pseudo-random source.
//
// Ignores observed messages (no Fiat-Shamir binding). Keep for bench isolation
// and soundness mutation tests; real proofs MUST use FsChallenger.
//
// Gated behind `cfg(test)` / `feature = "unsound-challenger"`: a real-proof
// build does not compile this type at all, so no production code path can
// accidentally instantiate an unsound challenger. See the module docs.
// ---------------------------------------------------------------------------

#[cfg(any(test, feature = "unsound-challenger"))]
#[derive(Clone, Debug)]
pub struct RandomChallenger {
    state: u64,
}

#[cfg(any(test, feature = "unsound-challenger"))]
impl RandomChallenger {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }
}

#[cfg(any(test, feature = "unsound-challenger"))]
impl Challenger for RandomChallenger {
    #[inline]
    fn observe_f128(&mut self, _value: F128) {
        // intentional no-op: random challenger is independent of prover state
    }

    fn sample_f128(&mut self) -> F128 {
        let lo = splitmix64(&mut self.state);
        let hi = splitmix64(&mut self.state);
        F128 { lo, hi }
    }
}

#[cfg(any(test, feature = "unsound-challenger"))]
#[inline]
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E3779B97F4A7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

// ---------------------------------------------------------------------------
// FsChallenger — Fiat-Shamir transcript.
//
// Tag bytes (one-byte op + one-byte kind) encode the operation type so that
// e.g. an `observe_f128_slice` of length 1 cannot collide with `observe_f128`,
// and a slice observation cannot collide with two scalar observations of the
// same total length.
//
// Sampling clones the live transcript state, squeezes challenge bytes, and
// absorbs the squeezed output back into the live state. This "duplex" pattern
// binds each subsequent challenge/observation to all prior squeezed output.
// ---------------------------------------------------------------------------

const OP_DOMAIN: u8 = 0x01;
const OP_LABEL: u8 = 0x02;
const OP_OBSERVE: u8 = 0x03;
const OP_SQUEEZE: u8 = 0x04;
const OP_BYTES: u8 = 0x05;

const KIND_SCALAR: u8 = 0x01;
const KIND_SLICE: u8 = 0x02;

/// Global Fiat-Shamir hash counters, enabled with `--features hash-count`.
/// Tracks proof-core squeeze count and PoW hash checks; absorbed
/// transcript bytes are tracked via [`FsChallenger::absorbed_bytes`].
#[cfg(feature = "hash-count")]
pub mod fs_count {
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

    /// Number of XOF finalizations (one per `sample_f128` /
    /// `sample_f128_vec` / PoW state-digest extraction).
    pub static SQUEEZES: AtomicU64 = AtomicU64::new(0);
    /// Number of PoW hash evaluations.
    pub static POW_HASH: AtomicU64 = AtomicU64::new(0);

    pub fn reset() {
        SQUEEZES.store(0, Relaxed);
        POW_HASH.store(0, Relaxed);
    }

    /// (squeezes, pow_hash_calls)
    pub fn snapshot() -> (u64, u64) {
        (SQUEEZES.load(Relaxed), POW_HASH.load(Relaxed))
    }
}

#[derive(Clone)]
pub struct FsChallenger {
    sponge: Poseidon2bSponge,
    /// Running total of absorbed transcript bytes, for the `hash-count`
    /// instrumentation (read only under that feature).
    #[allow(dead_code)]
    n_absorbed: u64,
}

impl FsChallenger {
    /// New challenger seeded with a domain-separation tag (e.g.
    /// `b"history-r1cs-v0"`). The domain is length-prefixed before being
    /// absorbed so two domains where one is a prefix of the other cannot
    /// produce the same initial state.
    pub fn new(domain: &[u8]) -> Self {
        let mut c = Self {
            sponge: Poseidon2bSponge::with_iv(capacity_iv(TAG_FSCHALNG)),
            n_absorbed: 0,
        };
        c.absorb(&[OP_DOMAIN]);
        c.absorb(&(domain.len() as u64).to_le_bytes());
        c.absorb(domain);
        c
    }

    /// Absorb bytes into the running transcript state.
    #[inline]
    fn absorb(&mut self, bytes: &[u8]) {
        self.sponge.update(bytes);
        self.n_absorbed = self.n_absorbed.wrapping_add(bytes.len() as u64);
    }

    #[inline]
    fn absorb_f128(&mut self, v: F128) {
        self.absorb(&v.lo.to_le_bytes());
        self.absorb(&v.hi.to_le_bytes());
    }

    /// Squeeze `out.len()` pseudorandom bytes from a cloned Poseidon2b
    /// transcript state without mutating the live transcript.
    fn squeeze_into(&self, out: &mut [u8]) {
        let mut sponge = self.sponge.clone();
        sponge.flush_to_squeeze();

        let mut off = 0usize;
        while off < out.len() {
            let pair = sponge.squeeze();
            let mut block = [0u8; 32];
            block[..16].copy_from_slice(&pair[0].to_u128().to_le_bytes());
            block[16..].copy_from_slice(&pair[1].to_u128().to_le_bytes());
            let take = (out.len() - off).min(32);
            out[off..off + take].copy_from_slice(&block[..take]);
            off += take;
        }
    }

    /// Total bytes absorbed into the transcript so far. Used by the
    /// `hash-count` instrumentation.
    #[cfg(feature = "hash-count")]
    pub fn absorbed_bytes(&self) -> u64 {
        self.n_absorbed
    }
}

impl Challenger for FsChallenger {
    fn observe_label(&mut self, label: &[u8]) {
        self.absorb(&[OP_LABEL]);
        self.absorb(&(label.len() as u64).to_le_bytes());
        self.absorb(label);
    }

    fn observe_f128(&mut self, value: F128) {
        self.absorb(&[OP_OBSERVE, KIND_SCALAR]);
        self.absorb_f128(value);
    }

    fn observe_f128_slice(&mut self, values: &[F128]) {
        self.absorb(&[OP_OBSERVE, KIND_SLICE]);
        self.absorb(&(values.len() as u64).to_le_bytes());
        for v in values {
            self.absorb_f128(*v);
        }
    }

    fn observe_bytes(&mut self, bytes: &[u8]) {
        self.absorb(&[OP_BYTES]);
        self.absorb(&(bytes.len() as u64).to_le_bytes());
        self.absorb(bytes);
    }

    fn sample_f128(&mut self) -> F128 {
        #[cfg(feature = "hash-count")]
        fs_count::SQUEEZES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.absorb(&[OP_SQUEEZE, KIND_SCALAR]);
        let mut buf = [0u8; 16];
        self.squeeze_into(&mut buf);
        // Re-absorb the squeezed bytes so subsequent ops bind to this challenge.
        self.absorb(&buf);
        let lo = u64::from_le_bytes(buf[..8].try_into().unwrap());
        let hi = u64::from_le_bytes(buf[8..].try_into().unwrap());
        F128 { lo, hi }
    }

    fn sample_f128_vec(&mut self, n: usize) -> Vec<F128> {
        #[cfg(feature = "hash-count")]
        fs_count::SQUEEZES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.absorb(&[OP_SQUEEZE, KIND_SLICE]);
        self.absorb(&(n as u64).to_le_bytes());
        let mut buf = vec![0u8; n * 16];
        self.squeeze_into(&mut buf);
        self.absorb(&buf);
        buf.chunks_exact(16)
            .map(|c| F128 {
                lo: u64::from_le_bytes(c[..8].try_into().unwrap()),
                hi: u64::from_le_bytes(c[8..].try_into().unwrap()),
            })
            .collect()
    }

    fn grind_pow(&mut self, bits: u32) -> u64 {
        let state_digest = self.pow_state_digest();
        // Aggregate-aware parallelism: decide on the grind's *expected hash
        // work* (`2^bits`), not a raw bit threshold. Fold-challenge grinds are
        // individually modest — e.g. 2^15 at L0 under the per-round profiles —
        // but the prover issues one per lane fold (6× at L0, 3× per recursive
        // level), so the per-level aggregate (~2^17–2^18 hashes) lands on the
        // multi-threaded critical path. We go parallel once a single grind
        // clears the rayon dispatch break-even (~2^13 hashes); the genuinely
        // tiny deep-level grinds (2^3–2^11) stay sequential, where the serial
        // loop beats parallel-dispatch overhead. `find_first` returns the
        // globally smallest satisfying nonce, so the result is identical to the
        // sequential search (deterministic proofs) regardless of this choice.
        const PARALLEL_GRIND_MIN_HASHES: u64 = 1 << 13;
        let nonce = if bits == 0 {
            0
        } else if (1u64 << bits.min(63)) < PARALLEL_GRIND_MIN_HASHES {
            // Sequential search: try u64 nonces until the Poseidon2b proof
            // hash has `bits` leading zeros.
            let mut nonce: u64 = 0;
            loop {
                if proof_hash_has_leading_zero_bits(&state_digest, nonce, bits) {
                    break nonce;
                }
                nonce = nonce.wrapping_add(1);
            }
        } else {
            // Block-parallel search. Blocks are scanned in order and
            // `find_first` returns the smallest match within a block, so the
            // result is deterministic (the globally smallest satisfying nonce).
            // Block ≈ 2× the expected attempts: large enough that the match
            // usually falls inside one block (so all threads do useful
            // pre-match work), small enough to avoid the 4× over-scan the old
            // `+2` block caused (which left ~¾ of threads doing cancelled work).
            use rayon::prelude::*;
            let block: u64 = 1 << (bits.min(24) + 1);
            let mut start: u64 = 0;
            loop {
                if let Some(n) = (start..start.saturating_add(block))
                    .into_par_iter()
                    .find_first(|&n| proof_hash_has_leading_zero_bits(&state_digest, n, bits))
                {
                    break n;
                }
                start = start.saturating_add(block);
            }
        };
        // Absorb the nonce so subsequent transcript state binds to it.
        // Verifier mirrors via verify_pow.
        self.observe_bytes(&nonce.to_le_bytes());
        nonce
    }

    fn verify_pow(&mut self, nonce: u64, bits: u32) -> bool {
        let state_digest = self.pow_state_digest();
        let ok = if bits == 0 {
            // No PoW required here. An honest prover emits the canonical nonce
            // 0 (see `grind_pow`), so reject any non-zero value: it can only be
            // a re-grinding knob, and accepting it would leave proofs malleable
            // (a proof and its nonce-mutated twin would both verify). This
            // closes no soundness gap — when grinding_bits = 0 the query phase
            // already carries the full security target, and the FS soundness
            // accounting assumes free re-grinding regardless — it just keeps
            // proofs canonical / non-malleable at zero-bit grinding sites.
            nonce == 0
        } else {
            proof_hash_has_leading_zero_bits(&state_digest, nonce, bits)
        };
        // Absorb regardless of `ok` so the transcript stays byte-identical to
        // the prover's (an honest prover always reaches this with the same
        // nonce); a failed check rejects the proof at the call site anyway.
        self.observe_bytes(&nonce.to_le_bytes());
        ok
    }
}

impl FsChallenger {
    /// Extract a 32-byte digest from the current challenger state to use as the
    /// PoW base, without mutating the live transcript.
    #[inline]
    fn pow_state_digest(&self) -> [u8; 32] {
        #[cfg(feature = "hash-count")]
        fs_count::SQUEEZES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut out = [0u8; 32];
        self.squeeze_into(&mut out);
        out
    }
}

/// Check whether the proof-core PoW hash over `(state_digest, nonce)` has at
/// least `bits` leading zero bits.
#[inline]
fn proof_hash_has_leading_zero_bits(state_digest: &[u8; 32], nonce: u64, bits: u32) -> bool {
    #[cfg(feature = "hash-count")]
    fs_count::POW_HASH.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let h: [u8; 32] = {
        let nonce_bytes = nonce.to_le_bytes();
        poseidon2b_hash_byte_slices(b"NOID/IVC/FS-POW/v1", &[state_digest, &nonce_bytes])
    };

    digest_has_leading_zero_bits(&h, bits)
}

#[inline]
fn digest_has_leading_zero_bits(h: &[u8; 32], bits: u32) -> bool {
    let full_bytes = (bits / 8) as usize;
    let extra = bits % 8;
    for &b in h.iter().take(full_bytes) {
        if b != 0 {
            return false;
        }
    }
    if extra > 0 && (h[full_bytes] >> (8 - extra)) != 0 {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Prover-side PoW grinding produces a nonce that the verifier-side
    /// `verify_pow` accepts at the same transcript position. State binding
    /// is preserved — sampling after PoW gives identical challenges on both
    /// sides.
    #[test]
    fn fs_challenger_pow_roundtrip() {
        for bits in [0u32, 5, 10, 14] {
            let mut prover = FsChallenger::new(b"pow-test");
            prover.observe_label(b"history-pow-test");
            prover.observe_bytes(b"some root data");
            let nonce = prover.grind_pow(bits);

            let mut verifier = FsChallenger::new(b"pow-test");
            verifier.observe_label(b"history-pow-test");
            verifier.observe_bytes(b"some root data");
            assert!(
                verifier.verify_pow(nonce, bits),
                "verify failed at bits={bits}"
            );

            // Subsequent challenges must agree.
            for _ in 0..4 {
                assert_eq!(prover.sample_f128(), verifier.sample_f128());
            }
        }
    }

    /// `verify_pow` rejects a wrong nonce when grinding bits > 0.
    #[test]
    fn fs_challenger_pow_rejects_wrong_nonce() {
        let mut prover = FsChallenger::new(b"pow-test");
        prover.observe_bytes(b"root");
        let nonce = prover.grind_pow(10);
        let bad_nonce = nonce.wrapping_add(1);

        let mut verifier = FsChallenger::new(b"pow-test");
        verifier.observe_bytes(b"root");
        assert!(
            !verifier.verify_pow(bad_nonce, 10),
            "should reject wrong nonce"
        );
    }

    /// At a zero-bit grinding site `verify_pow` accepts the canonical nonce 0
    /// (what `grind_pow(0)` emits) but rejects any non-zero nonce, so a proof
    /// can't be made malleable by swapping in an arbitrary nonce.
    #[test]
    fn fs_challenger_pow_zero_bits_requires_canonical_nonce() {
        let mk = || {
            let mut ch = FsChallenger::new(b"pow-test");
            ch.observe_bytes(b"root");
            ch
        };
        assert_eq!(mk().grind_pow(0), 0, "honest zero-bit grind is the 0 nonce");
        assert!(mk().verify_pow(0, 0), "canonical 0 nonce must verify");
        for bad in [1u64, 42, u64::MAX] {
            assert!(
                !mk().verify_pow(bad, 0),
                "non-zero nonce {bad} must be rejected at zero-bit grinding"
            );
        }
    }

    /// Default Challenger impl (RandomChallenger) is a no-op for PoW.
    #[test]
    fn random_challenger_pow_is_noop() {
        let mut ch = RandomChallenger::new(0);
        assert_eq!(ch.grind_pow(16), 0);
        assert!(ch.verify_pow(0, 16));
    }

    #[test]
    fn random_challenger_is_deterministic_per_seed() {
        let mut c1 = RandomChallenger::new(42);
        let mut c2 = RandomChallenger::new(42);
        for _ in 0..16 {
            assert_eq!(c1.sample_f128(), c2.sample_f128());
        }
    }

    #[test]
    fn random_challenger_observe_is_noop() {
        // Observing arbitrary messages does not change the sampled values.
        let mut c1 = RandomChallenger::new(7);
        let mut c2 = RandomChallenger::new(7);
        c2.observe_f128(F128 {
            lo: 0xDEADBEEF,
            hi: 0xCAFEBABE,
        });
        c2.observe_f128_slice(&[F128::ONE, F128::ZERO]);
        c2.observe_label(b"ignored");
        c2.observe_bytes(b"also ignored");
        for _ in 0..8 {
            assert_eq!(c1.sample_f128(), c2.sample_f128());
        }
    }

    #[test]
    fn sample_f128_vec_matches_individual_samples() {
        let mut c1 = RandomChallenger::new(99);
        let mut c2 = RandomChallenger::new(99);
        let batch = c1.sample_f128_vec(5);
        let individual: Vec<F128> = (0..5).map(|_| c2.sample_f128()).collect();
        assert_eq!(batch, individual);
    }

    // ---- FsChallenger ------------------------------------------------------

    #[test]
    fn fs_challenger_identical_scripts_produce_identical_output() {
        let mut c1 = FsChallenger::new(b"history-test");
        let mut c2 = FsChallenger::new(b"history-test");
        let msg = F128 {
            lo: 0x1234,
            hi: 0x5678,
        };
        c1.observe_f128(msg);
        c2.observe_f128(msg);
        let r1 = c1.sample_f128_vec(8);
        let r2 = c2.sample_f128_vec(8);
        assert_eq!(r1, r2);
    }

    #[test]
    fn fs_challenger_different_domains_diverge() {
        let mut c1 = FsChallenger::new(b"history-a");
        let mut c2 = FsChallenger::new(b"history-b");
        assert_ne!(c1.sample_f128(), c2.sample_f128());
    }

    #[test]
    fn fs_challenger_different_observations_diverge() {
        let mut c1 = FsChallenger::new(b"history");
        let mut c2 = FsChallenger::new(b"history");
        c1.observe_f128(F128::ONE);
        c2.observe_f128(F128::ZERO);
        assert_ne!(c1.sample_f128(), c2.sample_f128());
    }

    #[test]
    fn fs_challenger_label_changes_output() {
        let mut c1 = FsChallenger::new(b"history");
        let mut c2 = FsChallenger::new(b"history");
        c1.observe_label(b"phase-A");
        // c2 omits the label entirely.
        assert_ne!(c1.sample_f128(), c2.sample_f128());
    }

    #[test]
    fn fs_challenger_scalar_vs_slice_dont_collide() {
        // observe_f128_slice(&[v]) must NOT produce the same state as
        // observe_f128(v) — the length prefix and kind tag must defeat this.
        let v = F128 { lo: 0xAB, hi: 0xCD };
        let mut c1 = FsChallenger::new(b"history");
        let mut c2 = FsChallenger::new(b"history");
        c1.observe_f128(v);
        c2.observe_f128_slice(&[v]);
        assert_ne!(c1.sample_f128(), c2.sample_f128());
    }

    #[test]
    fn fs_challenger_two_scalars_dont_collide_with_one_slice_of_two() {
        let a = F128 { lo: 1, hi: 2 };
        let b = F128 { lo: 3, hi: 4 };
        let mut c1 = FsChallenger::new(b"history");
        let mut c2 = FsChallenger::new(b"history");
        c1.observe_f128(a);
        c1.observe_f128(b);
        c2.observe_f128_slice(&[a, b]);
        assert_ne!(c1.sample_f128(), c2.sample_f128());
    }

    #[test]
    fn fs_challenger_sample_one_vs_sample_vec_one_differ() {
        // Squeeze tag differs (KIND_SCALAR vs KIND_SLICE+len), so a single
        // sample_f128 must not equal sample_f128_vec(1)[0].
        let mut c1 = FsChallenger::new(b"history");
        let mut c2 = FsChallenger::new(b"history");
        assert_ne!(c1.sample_f128(), c2.sample_f128_vec(1)[0]);
    }

    #[test]
    fn fs_challenger_sample_advances_state() {
        // After a sample, the next observation should not collapse to the
        // pre-sample state (the squeezed bytes are re-absorbed).
        let mut c1 = FsChallenger::new(b"history");
        let mut c2 = FsChallenger::new(b"history");
        let _ = c1.sample_f128();
        // c2 skips the sample.
        c1.observe_f128(F128::ONE);
        c2.observe_f128(F128::ONE);
        assert_ne!(c1.sample_f128(), c2.sample_f128());
    }
}
