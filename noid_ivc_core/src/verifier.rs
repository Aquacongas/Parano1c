//! Top-level R1CS verifier: walks the challenger in lockstep with the
//! prover, runs `zerocheck::verify` and `lincheck::verify`, derives the two
//! ZClaims, and verifies the PCS openings at those points against the
//! witness commitment.

use crate::challenger::Challenger;
use crate::field::F128;
use crate::lincheck::{self, QuirkyPoint};
use crate::pcs::{self, Commitment};
use crate::proof::{R1csClaim, R1csProof, R1csProofLigerito, ZClaim};
use crate::public_io::bind_post_commit_class;
use crate::r1cs::BlockR1cs;
use crate::zerocheck;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The commitment's PCS parameters do not match the instance shape.
    /// A hard error (not a debug assert): the snapshot decider feeds this
    /// path adversarial envelopes, and a mismatched `m` would otherwise
    /// size downstream structures from attacker-supplied bytes.
    ParamsMismatch,
    Zerocheck(zerocheck::VerifyError),
    Lincheck(lincheck::VerifyError),
    PcsAb(pcs::VerifyError),
    PcsC(pcs::VerifyError),
    /// A post-commit auxiliary protocol rejected before its terminal witness
    /// claims were appended to the shared PCS batch.
    Auxiliary,
}

/// Opaque capability handed only to a causally post-commit verifier callback.
/// It delegates the exact enclosing challenger and owns the claim sink that
/// the verifier automatically appends to the shared PCS batch.
pub struct FieldPostCommitVerifierContext<'a, Ch> {
    commitment: &'a Commitment,
    total_vars: usize,
    challenger: &'a mut Ch,
    claims: Vec<pcs::QuirkyDirectClaim>,
}

impl<'a, Ch> FieldPostCommitVerifierContext<'a, Ch> {
    fn new(commitment: &'a Commitment, total_vars: usize, challenger: &'a mut Ch) -> Self {
        Self {
            commitment,
            total_vars,
            challenger,
            claims: Vec::new(),
        }
    }

    fn finish(self) -> Vec<pcs::QuirkyDirectClaim> {
        self.claims
    }

    pub fn commitment(&self) -> &'a Commitment {
        self.commitment
    }

    pub fn total_vars(&self) -> usize {
        self.total_vars
    }

    pub fn append_claim(&mut self, claim: pcs::QuirkyDirectClaim) {
        self.claims.push(claim);
    }

    pub fn append_claims(&mut self, claims: impl IntoIterator<Item = pcs::QuirkyDirectClaim>) {
        self.claims.extend(claims);
    }

    pub fn claim_count(&self) -> usize {
        self.claims.len()
    }
}

impl<Ch: Challenger> Challenger for FieldPostCommitVerifierContext<'_, Ch> {
    fn observe_label(&mut self, label: &[u8]) {
        self.challenger.observe_label(label);
    }

    fn observe_f128(&mut self, value: F128) {
        self.challenger.observe_f128(value);
    }

    fn observe_f128_slice(&mut self, values: &[F128]) {
        self.challenger.observe_f128_slice(values);
    }

    fn observe_bytes(&mut self, bytes: &[u8]) {
        self.challenger.observe_bytes(bytes);
    }

    fn sample_f128(&mut self) -> F128 {
        self.challenger.sample_f128()
    }

    fn sample_f128_vec(&mut self, n: usize) -> Vec<F128> {
        self.challenger.sample_f128_vec(n)
    }

    fn grind_pow(&mut self, bits: u32) -> u64 {
        self.challenger.grind_pow(bits)
    }

    fn verify_pow(&mut self, nonce: u64, bits: u32) -> bool {
        self.challenger.verify_pow(nonce, bits)
    }
}

/// Dedicated single-thread rayon pool that the verifier runs inside.
///
/// The verifier is intentionally single-threaded — matching the convention of
/// comparable provers (binius64, plonky3, hashcaster all ship serial
/// verifiers) and keeping reported verify times honest single-core numbers.
/// The verify path shares several `par_*` helpers with the (multi-threaded)
/// prover — e.g. `lincheck::fold_alpha_batched`, `sumcheck_bind_top_in_place_par`,
/// and the Ligerito residual eval — so rather than fork every shared helper, the
/// reusable verify cores (`verify_core`, `verify_claims`, `verify_claims_ligerito`)
/// run their body via `verifier_pool().install(..)`. Any `par_iter` reached from
/// there uses this 1-thread pool and collapses onto a single worker, without
/// touching the prover's use of the global pool.
fn verifier_pool() -> &'static rayon::ThreadPool {
    use std::sync::OnceLock;
    static POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();
    POOL.get_or_init(|| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            // The whole verify body runs on this worker — including the deep
            // recursive Ligerito verifier — so give it an ample stack. A rayon
            // worker otherwise defaults to ~2 MiB (vs the 8 MiB main thread),
            // which the recursion overflows.
            .stack_size(64 * 1024 * 1024)
            .thread_name(|_| "history-verify".to_string())
            .build()
            .expect("build single-thread verifier pool")
    })
}

pub fn verify<Ch: Challenger>(
    r1cs: &BlockR1cs,
    commitment: &Commitment,
    proof: &R1csProof,
    lincheck_circuit: &dyn lincheck::LincheckCircuit,
    challenger: &mut Ch,
) -> Result<R1csClaim, VerifyError> {
    // ---- Replay zerocheck + lincheck → the two base claims.
    let (ab, c) = verify_core(
        r1cs,
        &proof.zerocheck,
        &proof.lincheck,
        commitment,
        lincheck_circuit,
        challenger,
    )?;

    // ---- Verify the batched PCS opening covering both z-claims.
    verify_claims(
        commitment,
        &[ab.clone(), c.clone()],
        &proof.pcs_open,
        challenger,
    )
    .map_err(VerifyError::PcsAb)?;

    Ok(R1csClaim { ab, c })
}

/// Ligerito-backend mirror of [`verify`]. Same FS protocol replay; only the
/// final PCS verification step differs.
pub fn verify_ligerito<Ch: Challenger>(
    r1cs: &BlockR1cs,
    commitment: &Commitment,
    proof: &R1csProofLigerito,
    lincheck_circuit: &dyn lincheck::LincheckCircuit,
    pcs_params: &crate::pcs::PcsParams,
    challenger: &mut Ch,
) -> Result<R1csClaim, VerifyError> {
    let (ab, c) = verify_core(
        r1cs,
        &proof.zerocheck,
        &proof.lincheck,
        commitment,
        lincheck_circuit,
        challenger,
    )?;
    verify_claims_ligerito(
        commitment,
        &[ab.clone(), c.clone()],
        &proof.pcs_open,
        pcs_params,
        challenger,
    )
    .map_err(VerifyError::PcsAb)?;
    Ok(R1csClaim { ab, c })
}

/// Ligerito-backend mirror of [`verify_claims`].
pub fn verify_claims_ligerito<Ch: Challenger>(
    commitment: &Commitment,
    claims: &[ZClaim],
    pcs_open: &pcs::BatchOpeningProofLigerito,
    pcs_params: &crate::pcs::PcsParams,
    challenger: &mut Ch,
) -> Result<(), pcs::VerifyError> {
    // Verification is single-threaded; run the body on the dedicated 1-thread pool.
    verifier_pool().install(move || {
        verify_claims_ligerito_inner(commitment, claims, pcs_open, pcs_params, challenger)
    })
}

fn verify_claims_ligerito_inner<Ch: Challenger>(
    commitment: &Commitment,
    claims: &[ZClaim],
    pcs_open: &pcs::BatchOpeningProofLigerito,
    pcs_params: &crate::pcs::PcsParams,
    challenger: &mut Ch,
) -> Result<(), pcs::VerifyError> {
    let z_skips: Vec<F128> = claims.iter().map(|c| c.point.z_skip).collect();
    let values: Vec<F128> = claims.iter().map(|c| c.value).collect();
    let x_fulls: Vec<Vec<F128>> = claims
        .iter()
        .map(|c| {
            let mut v = c.point.x_inner_rest.clone();
            v.extend_from_slice(&c.point.x_outer);
            v
        })
        .collect();
    let x_refs: Vec<&[F128]> = x_fulls.iter().map(|v| v.as_slice()).collect();
    let log_n = pcs_params.m - pcs::LOG_PACKING;
    let lig_v_config = crate::pcs::ligerito::verifier_config_for(
        log_n,
        pcs_params.log_batch_size,
        pcs_params.profile,
    )
    .expect("Ligerito default verifier config");
    pcs::verify_opening_batch_ligerito_mixed(
        commitment,
        &values,
        &z_skips,
        &x_refs,
        &[],
        pcs_open,
        &lig_v_config,
        challenger,
    )
}

/// Replay bind → zerocheck → lincheck and reconstruct the two base z-claims
/// (`ab`, `c`), stopping before the PCS open. Mirror of
/// `noid_ivc_prover::prover::prove_fast_core`; relation wrappers reuse this then call
/// [`verify_claims`] over `[ab, c, …]`.
pub fn verify_core<Ch: Challenger>(
    r1cs: &BlockR1cs,
    zerocheck_proof: &zerocheck::ZerocheckProof,
    lincheck_proof: &lincheck::LincheckProof,
    commitment: &Commitment,
    lincheck_circuit: &dyn lincheck::LincheckCircuit,
    challenger: &mut Ch,
) -> Result<(ZClaim, ZClaim), VerifyError> {
    // Verification is single-threaded; run the body on the dedicated 1-thread pool.
    verifier_pool().install(move || {
        verify_core_inner(
            r1cs,
            zerocheck_proof,
            lincheck_proof,
            commitment,
            lincheck_circuit,
            challenger,
        )
    })
}

fn verify_core_inner<Ch: Challenger>(
    r1cs: &BlockR1cs,
    zerocheck_proof: &zerocheck::ZerocheckProof,
    lincheck_proof: &lincheck::LincheckProof,
    commitment: &Commitment,
    lincheck_circuit: &dyn lincheck::LincheckCircuit,
    challenger: &mut Ch,
) -> Result<(ZClaim, ZClaim), VerifyError> {
    // Boolean-witness path: the packed commitment covers exactly the 2^m
    // witness bits. Same hard shape gate as the field path.
    if commitment.params.m != r1cs.m
        || commitment.params.log_batch_size + pcs::LOG_PACKING > commitment.params.m
    {
        return Err(VerifyError::ParamsMismatch);
    }

    let trace = std::env::var("VERIFY_TRACE").is_ok();
    let fmt = |s: f64| -> String {
        let ms = s * 1000.0;
        if ms < 1.0 {
            format!("{:>8.2} µs", s * 1e6)
        } else {
            format!("{:>8.2} ms", ms)
        }
    };

    // ---- Bind FS transcript to the statement (mirrors prover::prove).
    let t = std::time::Instant::now();
    crate::proof::bind_statement(challenger, r1cs, commitment);
    if trace {
        eprintln!(
            "      [vco] bind_statement: {}",
            fmt(t.elapsed().as_secs_f64())
        );
    }

    // ---- Zerocheck.
    let t = std::time::Instant::now();
    let zc_claim =
        zerocheck::verify(r1cs.m, zerocheck_proof, challenger).map_err(VerifyError::Zerocheck)?;
    if trace {
        eprintln!(
            "      [vco] zerocheck::verify: {}",
            fmt(t.elapsed().as_secs_f64())
        );
    }

    // ---- Build lincheck's shared quirky point from the zerocheck output.
    let inner_rest_len = r1cs.k_log - r1cs.k_skip;
    let x_ab = QuirkyPoint {
        z_skip: zc_claim.z,
        x_inner_rest: zc_claim.mlv_challenges[..inner_rest_len].to_vec(),
        x_outer: zc_claim.mlv_challenges[inner_rest_len..].to_vec(),
    };

    // ---- Lincheck. v_a, v_b come from the zerocheck's final â, b̂ evals.
    let t = std::time::Instant::now();
    let lc_claim = lincheck::verify(
        r1cs.m,
        r1cs.k_log,
        r1cs.k_skip,
        lincheck_circuit,
        &x_ab,
        zc_claim.a_eval,
        zc_claim.b_eval,
        lincheck_proof,
        challenger,
    )
    .map_err(VerifyError::Lincheck)?;
    if trace {
        eprintln!(
            "      [vco] lincheck::verify: {}",
            fmt(t.elapsed().as_secs_f64())
        );
    }

    // ---- Build the two z-claims (must match what `prove` returned).
    let ab = ZClaim {
        point: QuirkyPoint {
            z_skip: lc_claim.r_inner_skip,
            x_inner_rest: lc_claim.r_inner_rest.clone(),
            x_outer: x_ab.x_outer.clone(),
        },
        value: lc_claim.w,
    };
    // c-claim is already a z-claim since `C = I` ⇒ ĉ = ẑ.
    let c = ZClaim {
        point: QuirkyPoint {
            z_skip: zc_claim.z,
            x_inner_rest: zc_claim.r_rest[..inner_rest_len].to_vec(),
            x_outer: zc_claim.r_rest[inner_rest_len..].to_vec(),
        },
        value: zc_claim.c_eval,
    };

    Ok((ab, c))
}

/// Verify a batched PCS opening over an arbitrary list of `ẑ`-claims — the
/// mirror of `noid_ivc_prover::prover::open_claims`. Relation wrappers (e.g. the hash
/// chain) reuse this with their own appended claims. Must run at the same
/// transcript position as the prover's open.
pub fn verify_claims<Ch: Challenger>(
    commitment: &Commitment,
    claims: &[ZClaim],
    pcs_open: &pcs::BatchOpeningProof,
    challenger: &mut Ch,
) -> Result<(), pcs::VerifyError> {
    // Verification is single-threaded; run the body on the dedicated 1-thread pool.
    verifier_pool().install(move || verify_claims_inner(commitment, claims, pcs_open, challenger))
}

fn verify_claims_inner<Ch: Challenger>(
    commitment: &Commitment,
    claims: &[ZClaim],
    pcs_open: &pcs::BatchOpeningProof,
    challenger: &mut Ch,
) -> Result<(), pcs::VerifyError> {
    let z_skips: Vec<F128> = claims.iter().map(|c| c.point.z_skip).collect();
    let values: Vec<F128> = claims.iter().map(|c| c.value).collect();
    let x_fulls: Vec<Vec<F128>> = claims
        .iter()
        .map(|c| {
            let mut v = c.point.x_inner_rest.clone();
            v.extend_from_slice(&c.point.x_outer);
            v
        })
        .collect();
    let x_refs: Vec<&[F128]> = x_fulls.iter().map(|v| v.as_slice()).collect();
    pcs::verify_opening_batch(commitment, &values, &z_skips, &x_refs, pcs_open, challenger)
}

/// Verify a **FieldR1cs** proof: field zerocheck → shared lincheck
/// (coefficient-carrying circuit) → batched quirky-direct PCS opening.
/// Structural mirror of [`verify`]; same single-threaded pool policy.
pub fn verify_field<Ch: Challenger>(
    r1cs: &crate::field_r1cs::FieldR1cs,
    commitment: &Commitment,
    proof: &crate::proof::FieldR1csProof,
    challenger: &mut Ch,
) -> Result<R1csClaim, VerifyError> {
    verifier_pool().install(move || {
        verify_field_inner(r1cs, commitment, proof, None, challenger, |_, _| {
            Ok(Vec::new())
        })
    })
}

/// [`verify_field`] with a public-IO envelope: mirrors
/// `prove_field_with_public_io` — absorbs the spec + envelope lanes right
/// after the statement binding, samples the binding point, and checks the
/// appended IO claims in the batched PCS opening (see
/// [`crate::public_io`]). The spec is a verification-key constant; the
/// envelope lanes are the proof's public values.
pub fn verify_field_with_public_io<Ch: Challenger>(
    r1cs: &crate::field_r1cs::FieldR1cs,
    commitment: &Commitment,
    proof: &crate::proof::FieldR1csProof,
    spec: &crate::public_io::PublicIoSpec,
    io: &[crate::field::F128],
    challenger: &mut Ch,
) -> Result<R1csClaim, VerifyError> {
    verifier_pool().install(move || {
        verify_field_inner(
            r1cs,
            commitment,
            proof,
            Some((spec, io)),
            challenger,
            |_, _| Ok(Vec::new()),
        )
    })
}

/// [`verify_field_with_public_io`] plus a post-commit auxiliary verifier.
///
/// This mirrors
/// `noid_ivc_prover::field_prover::prove_field_with_public_io_and_post_commit`:
/// the callback runs after the statement/commitment/public-IO binding and
/// before the outer zerocheck. It must replay the auxiliary proof in the same
/// challenger and return its terminal claims on this exact commitment.
pub fn verify_field_with_public_io_and_post_commit<Ch, Aux, PostCommit>(
    r1cs: &crate::field_r1cs::FieldR1cs,
    commitment: &Commitment,
    proof: &crate::proof::FieldR1csProof,
    spec: &crate::public_io::PublicIoSpec,
    io: &[crate::field::F128],
    auxiliary: &Aux,
    challenger: &mut Ch,
    post_commit: PostCommit,
) -> Result<R1csClaim, VerifyError>
where
    Ch: Challenger,
    Aux: Sync,
    PostCommit: FnOnce(&Aux, &mut Ch) -> Result<Vec<pcs::QuirkyDirectClaim>, VerifyError> + Send,
{
    verifier_pool().install(move || {
        verify_field_inner(
            r1cs,
            commitment,
            proof,
            Some((spec, io)),
            challenger,
            |_, challenger| post_commit(auxiliary, challenger),
        )
    })
}

/// Typestate verifier twin of
/// `noid_ivc_prover::field_prover::prove_field_with_public_io_and_post_commit_context`.
/// The class digest is absorbed after public IO and before the callback.  The
/// callback writes terminal claims into the opaque context; this wrapper
/// appends them to the shared PCS batch automatically.
#[allow(clippy::too_many_arguments)]
pub fn verify_field_with_public_io_and_post_commit_context<Ch, Aux, PostCommit>(
    r1cs: &crate::field_r1cs::FieldR1cs,
    commitment: &Commitment,
    proof: &crate::proof::FieldR1csProof,
    spec: &crate::public_io::PublicIoSpec,
    io: &[crate::field::F128],
    post_commit_class_digest: &[u8; 32],
    auxiliary: &Aux,
    challenger: &mut Ch,
    post_commit: PostCommit,
) -> Result<R1csClaim, VerifyError>
where
    Ch: Challenger,
    Aux: Sync,
    PostCommit:
        FnOnce(&Aux, &mut FieldPostCommitVerifierContext<'_, Ch>) -> Result<(), VerifyError> + Send,
{
    verifier_pool().install(move || {
        verify_field_inner(
            r1cs,
            commitment,
            proof,
            Some((spec, io)),
            challenger,
            |commitment, challenger| {
                bind_post_commit_class(challenger, post_commit_class_digest);
                let mut context =
                    FieldPostCommitVerifierContext::new(commitment, r1cs.m, challenger);
                post_commit(auxiliary, &mut context)?;
                Ok(context.finish())
            },
        )
    })
}

/// Matrix-free verification for the self-verification chain: transcript-
/// identical to [`verify_field_with_public_io`], but the lincheck final
/// consistency is DEFERRED — the function returns the bilinear claim the
/// instance matrices must satisfy (see [`crate::matrix_claim`]) instead of
/// checking it against them. The statement enters through its digest and
/// shape parameters only, so a trace twin of this function can verify
/// proofs of its own class. The caller MUST fold + eventually discharge
/// the returned claim; acceptance here alone binds the proof to SOME
/// matrices, not to the instance's.
#[allow(clippy::too_many_arguments)]
pub fn verify_field_deferred_matrix<Ch: Challenger>(
    shape: &crate::proof::FieldShape,
    statement_digest: &[u8; 32],
    commitment: &Commitment,
    proof: &crate::proof::FieldR1csProof,
    spec: &crate::public_io::PublicIoSpec,
    io: &[crate::field::F128],
    challenger: &mut Ch,
) -> Result<(R1csClaim, crate::matrix_claim::FreshLincheckClaim), VerifyError> {
    verifier_pool().install(move || {
        verify_field_deferred_matrix_inner(
            shape,
            statement_digest,
            commitment,
            proof,
            spec,
            io,
            challenger,
            |_, _| Ok(Vec::new()),
        )
    })
}

/// Matrix-free [`verify_field_deferred_matrix`] with a post-commit auxiliary
/// verifier. The callback ordering and terminal-claim semantics are identical
/// to [`verify_field_with_public_io_and_post_commit`].
#[allow(clippy::too_many_arguments)]
pub fn verify_field_deferred_matrix_with_post_commit<Ch, Aux, PostCommit>(
    shape: &crate::proof::FieldShape,
    statement_digest: &[u8; 32],
    commitment: &Commitment,
    proof: &crate::proof::FieldR1csProof,
    spec: &crate::public_io::PublicIoSpec,
    io: &[crate::field::F128],
    auxiliary: &Aux,
    challenger: &mut Ch,
    post_commit: PostCommit,
) -> Result<(R1csClaim, crate::matrix_claim::FreshLincheckClaim), VerifyError>
where
    Ch: Challenger,
    Aux: Sync,
    PostCommit: FnOnce(&Aux, &mut Ch) -> Result<Vec<pcs::QuirkyDirectClaim>, VerifyError> + Send,
{
    verifier_pool().install(move || {
        verify_field_deferred_matrix_inner(
            shape,
            statement_digest,
            commitment,
            proof,
            spec,
            io,
            challenger,
            |_, challenger| post_commit(auxiliary, challenger),
        )
    })
}

/// Matrix-free typestate twin of
/// [`verify_field_with_public_io_and_post_commit_context`].  It binds the same
/// explicit auxiliary class and uses the same append-only claim context before
/// returning the deferred matrix claim.
#[allow(clippy::too_many_arguments)]
pub fn verify_field_deferred_matrix_with_post_commit_context<Ch, Aux, PostCommit>(
    shape: &crate::proof::FieldShape,
    statement_digest: &[u8; 32],
    commitment: &Commitment,
    proof: &crate::proof::FieldR1csProof,
    spec: &crate::public_io::PublicIoSpec,
    io: &[crate::field::F128],
    post_commit_class_digest: &[u8; 32],
    auxiliary: &Aux,
    challenger: &mut Ch,
    post_commit: PostCommit,
) -> Result<(R1csClaim, crate::matrix_claim::FreshLincheckClaim), VerifyError>
where
    Ch: Challenger,
    Aux: Sync,
    PostCommit:
        FnOnce(&Aux, &mut FieldPostCommitVerifierContext<'_, Ch>) -> Result<(), VerifyError> + Send,
{
    verifier_pool().install(move || {
        verify_field_deferred_matrix_inner(
            shape,
            statement_digest,
            commitment,
            proof,
            spec,
            io,
            challenger,
            |commitment, challenger| {
                bind_post_commit_class(challenger, post_commit_class_digest);
                let mut context =
                    FieldPostCommitVerifierContext::new(commitment, shape.m, challenger);
                post_commit(auxiliary, &mut context)?;
                Ok(context.finish())
            },
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_field_deferred_matrix_inner<Ch: Challenger>(
    shape: &crate::proof::FieldShape,
    statement_digest: &[u8; 32],
    commitment: &Commitment,
    proof: &crate::proof::FieldR1csProof,
    spec: &crate::public_io::PublicIoSpec,
    io: &[crate::field::F128],
    challenger: &mut Ch,
    post_commit: impl FnOnce(&Commitment, &mut Ch) -> Result<Vec<pcs::QuirkyDirectClaim>, VerifyError>,
) -> Result<(R1csClaim, crate::matrix_claim::FreshLincheckClaim), VerifyError> {
    if commitment.params.m != shape.m + pcs::LOG_PACKING
        || commitment.params.log_batch_size + pcs::LOG_PACKING > commitment.params.m
    {
        return Err(VerifyError::ParamsMismatch);
    }

    crate::proof::bind_statement_field_parts(challenger, statement_digest, commitment);
    let io_claims = crate::public_io::bind_public_io(challenger, spec, io, shape.m);
    let auxiliary_claims = post_commit(commitment, challenger)?;

    let zc_claim = zerocheck::field::verify(shape.m, &proof.zerocheck, challenger)
        .map_err(VerifyError::Zerocheck)?;

    let inner_rest_len = shape.k_log - shape.k_skip;
    let x_ab = QuirkyPoint {
        z_skip: zc_claim.z,
        x_inner_rest: zc_claim.mlv_challenges[..inner_rest_len].to_vec(),
        x_outer: zc_claim.mlv_challenges[inner_rest_len..].to_vec(),
    };
    let (lc_claim, fresh) = lincheck::verify_deferred(
        shape.m,
        shape.k_log,
        shape.k_skip,
        shape.const_pin,
        &x_ab,
        zc_claim.a_eval,
        zc_claim.b_eval,
        &proof.lincheck,
        challenger,
    )
    .map_err(VerifyError::Lincheck)?;

    let ab = ZClaim {
        point: QuirkyPoint {
            z_skip: lc_claim.r_inner_skip,
            x_inner_rest: lc_claim.r_inner_rest.clone(),
            x_outer: x_ab.x_outer.clone(),
        },
        value: lc_claim.w,
    };
    let c = ZClaim {
        point: QuirkyPoint {
            z_skip: zc_claim.z,
            x_inner_rest: zc_claim.r_rest[..inner_rest_len].to_vec(),
            x_outer: zc_claim.r_rest[inner_rest_len..].to_vec(),
        },
        value: zc_claim.c_eval,
    };

    let x_rest_of = |zc: &ZClaim| -> Vec<F128> {
        let mut v = zc.point.x_inner_rest.clone();
        v.extend_from_slice(&zc.point.x_outer);
        v
    };
    let ab_rest = x_rest_of(&ab);
    let c_rest = x_rest_of(&c);
    let mut refs = vec![
        pcs::QuirkyDirectClaimRef {
            z_skip: ab.point.z_skip,
            k_skip: shape.k_skip,
            x_rest: &ab_rest,
            value: ab.value,
        },
        pcs::QuirkyDirectClaimRef {
            z_skip: c.point.z_skip,
            k_skip: shape.k_skip,
            x_rest: &c_rest,
            value: c.value,
        },
    ];
    refs.extend(io_claims.iter().map(|cl| pcs::QuirkyDirectClaimRef {
        z_skip: cl.z_skip,
        k_skip: cl.k_skip,
        x_rest: &cl.x_rest,
        value: cl.value,
    }));
    refs.extend(auxiliary_claims.iter().map(|cl| pcs::QuirkyDirectClaimRef {
        z_skip: cl.z_skip,
        k_skip: cl.k_skip,
        x_rest: &cl.x_rest,
        value: cl.value,
    }));
    pcs::verify_opening_batch_quirky_direct(commitment, &refs, &proof.pcs_open, challenger)
        .map_err(VerifyError::PcsAb)?;

    Ok((R1csClaim { ab, c }, fresh))
}

fn verify_field_inner<Ch: Challenger>(
    r1cs: &crate::field_r1cs::FieldR1cs,
    commitment: &Commitment,
    proof: &crate::proof::FieldR1csProof,
    public_io: Option<(&crate::public_io::PublicIoSpec, &[crate::field::F128])>,
    challenger: &mut Ch,
    post_commit: impl FnOnce(&Commitment, &mut Ch) -> Result<Vec<pcs::QuirkyDirectClaim>, VerifyError>,
) -> Result<R1csClaim, VerifyError> {
    // The commitment must be sized for THIS instance (one committed F128
    // element per witness element) before any parameter-derived structure
    // is built. See [`VerifyError::ParamsMismatch`].
    if commitment.params.m != r1cs.m + pcs::LOG_PACKING
        || commitment.params.log_batch_size + pcs::LOG_PACKING > commitment.params.m
    {
        return Err(VerifyError::ParamsMismatch);
    }

    // ---- Bind the FS transcript to the statement (mirrors prove_field).
    crate::proof::bind_statement_field(challenger, r1cs, commitment);

    // ---- Public-IO envelope binding (mirrors prove_field_with_public_io).
    let io_claims: Vec<pcs::QuirkyDirectClaim> = match public_io {
        Some((spec, io)) => crate::public_io::bind_public_io(challenger, spec, io, r1cs.m),
        None => Vec::new(),
    };
    let auxiliary_claims = post_commit(commitment, challenger)?;

    // ---- Field zerocheck.
    let zc_claim = zerocheck::field::verify(r1cs.m, &proof.zerocheck, challenger)
        .map_err(VerifyError::Zerocheck)?;

    // ---- Lincheck (shared verify; witness semantics enter via the circuit).
    let inner_rest_len = r1cs.k_log - r1cs.k_skip;
    let x_ab = QuirkyPoint {
        z_skip: zc_claim.z,
        x_inner_rest: zc_claim.mlv_challenges[..inner_rest_len].to_vec(),
        x_outer: zc_claim.mlv_challenges[inner_rest_len..].to_vec(),
    };
    let lc_claim = lincheck::verify(
        r1cs.m,
        r1cs.k_log,
        r1cs.k_skip,
        r1cs.csc_lincheck_circuit(),
        &x_ab,
        zc_claim.a_eval,
        zc_claim.b_eval,
        &proof.lincheck,
        challenger,
    )
    .map_err(VerifyError::Lincheck)?;

    // ---- The two z-claims (must match what prove_field returned).
    let ab = ZClaim {
        point: QuirkyPoint {
            z_skip: lc_claim.r_inner_skip,
            x_inner_rest: lc_claim.r_inner_rest.clone(),
            x_outer: x_ab.x_outer.clone(),
        },
        value: lc_claim.w,
    };
    let c = ZClaim {
        point: QuirkyPoint {
            z_skip: zc_claim.z,
            x_inner_rest: zc_claim.r_rest[..inner_rest_len].to_vec(),
            x_outer: zc_claim.r_rest[inner_rest_len..].to_vec(),
        },
        value: zc_claim.c_eval,
    };

    // ---- Batched quirky-direct PCS opening over both claims.
    let x_rest_of = |zc: &ZClaim| -> Vec<F128> {
        let mut v = zc.point.x_inner_rest.clone();
        v.extend_from_slice(&zc.point.x_outer);
        v
    };
    let ab_rest = x_rest_of(&ab);
    let c_rest = x_rest_of(&c);
    let mut refs = vec![
        pcs::QuirkyDirectClaimRef {
            z_skip: ab.point.z_skip,
            k_skip: r1cs.k_skip,
            x_rest: &ab_rest,
            value: ab.value,
        },
        pcs::QuirkyDirectClaimRef {
            z_skip: c.point.z_skip,
            k_skip: r1cs.k_skip,
            x_rest: &c_rest,
            value: c.value,
        },
    ];
    refs.extend(io_claims.iter().map(|cl| pcs::QuirkyDirectClaimRef {
        z_skip: cl.z_skip,
        k_skip: cl.k_skip,
        x_rest: &cl.x_rest,
        value: cl.value,
    }));
    refs.extend(auxiliary_claims.iter().map(|cl| pcs::QuirkyDirectClaimRef {
        z_skip: cl.z_skip,
        k_skip: cl.k_skip,
        x_rest: &cl.x_rest,
        value: cl.value,
    }));
    pcs::verify_opening_batch_quirky_direct(commitment, &refs, &proof.pcs_open, challenger)
        .map_err(VerifyError::PcsAb)?;

    Ok(R1csClaim { ab, c })
}

#[cfg(test)]
mod tests {
    /// The verifier is intentionally single-threaded: every `par_*` reached
    /// from a verify core must collapse onto the one-thread `verifier_pool`.
    /// Guard the invariant so a future `ThreadPoolBuilder` tweak can't silently
    /// re-parallelize verification.
    ///
    /// (The end-to-end prove → verify roundtrip and tamper-rejection tests live
    /// in `noid-ivc-prover`'s `tests/verifier_roundtrip.rs`, since they need the
    /// prove path.)
    #[test]
    fn verifier_pool_is_single_threaded() {
        let n = super::verifier_pool().install(rayon::current_num_threads);
        assert_eq!(n, 1, "verifier_pool must have exactly one worker thread");
    }
}
