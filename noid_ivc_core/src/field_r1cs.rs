//! Block-diagonal R1CS over F_{2^128} — the substrate of the recursive
//! acceptance proof.
//!
//! Generalizes [`crate::r1cs::BlockR1cs`] from a boolean witness to
//! `z ∈ F_{2^128}^{2^m}`: the relation is `(A·z) ⊙ (B·z) = C·z` with the
//! Hadamard product now a genuine field multiplication per constraint row.
//! The sparse base matrices carry F128 coefficients, so linear layers
//! (Poseidon2b MDS, round constants via the constant wire) cost zero extra
//! constraints.
//!
//! Conventions shared with the boolean path:
//! - `C = I` (circuit R1CS): every witness element is constrained as
//!   `z_i = (A·z)_i · (B·z)_i`, and the zerocheck's c-claim is directly a
//!   z-claim. `C` is not materialized.
//! - Block-diagonal structure: `A = I_{2^(m−k_log)} ⊗ A_0` with `A_0` a
//!   `k × k` sparse matrix, `k = 2^k_log`.
//! - `k_skip` is the univariate-skip dimension of the field zerocheck
//!   ([`crate::zerocheck::field`]) and the lincheck quirky-point layout.
//! - `const_pin` drives the lincheck constant-wire pin (the committed
//!   constant-one column), closing the all-zero-witness gap — see
//!   `docs/const-wire-pin.md`.

use crate::field::F128;
use crate::lincheck::LincheckCircuit;

/// Interns F128 coefficients into a dedup'd table + `u32` indices, preserving
/// first-seen order (deterministic for a fixed construction sequence).
#[derive(Default)]
pub(crate) struct ValueInterner {
    table: Vec<F128>,
    map: std::collections::HashMap<u128, u32>,
}

impl ValueInterner {
    #[inline]
    pub(crate) fn intern(&mut self, v: F128) -> u32 {
        let key = ((v.hi as u128) << 64) | v.lo as u128;
        *self.map.entry(key).or_insert_with(|| {
            let idx = self.table.len() as u32;
            self.table.push(v);
            idx
        })
    }
    pub(crate) fn into_table(self) -> Vec<F128> {
        self.table
    }
}

/// Sparse matrix over F_{2^128} in **dictionary-encoded CSR** form. Row `r`'s
/// nonzero columns are `col_indices[row_offsets[r]..row_offsets[r + 1]]`; each
/// nonzero's coefficient is `value_table[value_indices[i]]` at the matching
/// position. Absent columns are zero. Per-row entry order is preserved from
/// construction — both [`FieldR1cs::statement_digest`] and the lincheck column
/// fold depend on it. Coefficients must be nonzero (a zero coefficient is
/// representable but wasteful and forbidden by convention).
///
/// The matrix is a **protocol constant**, so its coefficients are a small fixed
/// set — a few hundred distinct values (MDS entries, round constants,
/// additive-NTT twiddles) heavily repeated across millions of nonzeros. Storing
/// a `u32` index (4 B) into a tiny table instead of a 16 B `F128` per nonzero
/// roughly halves the matrix vs the plain-CSR `Vec<F128>` (12 B saved per
/// nonzero) — which itself already halved the former `Vec<Vec<(u32, F128)>>`
/// (32 B/nonzero + a 24 B `Vec` header per row). The matrix is the single
/// largest resident prover buffer at block-bearing (2^23–2^24) sizes.
#[derive(Clone, Debug)]
pub struct SparseFieldMatrix {
    pub num_rows: usize,
    pub num_cols: usize,
    /// Column index of each nonzero, grouped by row per `row_offsets`.
    pub col_indices: Vec<u32>,
    /// Coefficient-table index of each nonzero, parallel to `col_indices`.
    pub value_indices: Vec<u32>,
    /// Distinct coefficient values; `value_table[value_indices[i]]` is the
    /// coefficient of nonzero `i`.
    pub value_table: Vec<F128>,
    /// Row boundaries: length `num_rows + 1`, monotone non-decreasing,
    /// `row_offsets[0] == 0` and `row_offsets[num_rows] == col_indices.len()`.
    pub row_offsets: Vec<usize>,
}

/// Compared by DECODED content: two matrices are equal iff their columns,
/// offsets and per-nonzero coefficient VALUES match — independent of the
/// interning order of `value_table` (the drift-check gates rely on this).
impl PartialEq for SparseFieldMatrix {
    fn eq(&self, other: &Self) -> bool {
        self.num_rows == other.num_rows
            && self.num_cols == other.num_cols
            && self.row_offsets == other.row_offsets
            && self.col_indices == other.col_indices
            && self.value_indices.len() == other.value_indices.len()
            && self
                .value_indices
                .iter()
                .zip(&other.value_indices)
                .all(|(&a, &b)| self.value_table[a as usize] == other.value_table[b as usize])
    }
}

impl SparseFieldMatrix {
    /// Build from a row-major `(column, coefficient)` list — the natural
    /// builder output. Interns coefficients into the value table as it flattens
    /// (each inner `Vec` frees as consumed), preserving per-row entry order.
    pub fn from_rows(num_cols: usize, rows: Vec<Vec<(u32, F128)>>) -> Self {
        let num_rows = rows.len();
        let nnz: usize = rows.iter().map(|r| r.len()).sum();
        let mut col_indices = Vec::with_capacity(nnz);
        let mut value_indices = Vec::with_capacity(nnz);
        let mut row_offsets = Vec::with_capacity(num_rows + 1);
        let mut interner = ValueInterner::default();
        row_offsets.push(0);
        for row in rows {
            for (c, v) in row {
                col_indices.push(c);
                value_indices.push(interner.intern(v));
            }
            row_offsets.push(col_indices.len());
        }
        Self {
            num_rows,
            num_cols,
            col_indices,
            value_indices,
            value_table: interner.into_table(),
            row_offsets,
        }
    }

    /// Assemble directly from dictionary-encoded arrays (the builder's output).
    pub fn from_dict(
        num_cols: usize,
        col_indices: Vec<u32>,
        value_indices: Vec<u32>,
        value_table: Vec<F128>,
        row_offsets: Vec<usize>,
    ) -> Self {
        Self {
            num_rows: row_offsets.len() - 1,
            num_cols,
            col_indices,
            value_indices,
            value_table,
            row_offsets,
        }
    }

    /// Identity matrix of side `k`.
    pub fn identity(k: usize) -> Self {
        Self {
            num_rows: k,
            num_cols: k,
            col_indices: (0..k as u32).collect(),
            value_indices: vec![0u32; k],
            value_table: vec![F128::ONE],
            row_offsets: (0..=k).collect(),
        }
    }

    /// All-zero matrix of side `k`.
    pub fn zero(k: usize) -> Self {
        Self {
            num_rows: k,
            num_cols: k,
            col_indices: Vec::new(),
            value_indices: Vec::new(),
            value_table: Vec::new(),
            row_offsets: vec![0usize; k + 1],
        }
    }

    pub fn nnz(&self) -> usize {
        self.value_indices.len()
    }

    /// Number of distinct coefficient values (the dictionary size).
    pub fn distinct_values(&self) -> usize {
        self.value_table.len()
    }

    /// Entry-index range `[start, end)` of row `r`.
    #[inline]
    pub fn row_range(&self, r: usize) -> std::ops::Range<usize> {
        self.row_offsets[r]..self.row_offsets[r + 1]
    }

    /// Column indices of row `r`.
    #[inline]
    pub fn row_cols(&self, r: usize) -> &[u32] {
        &self.col_indices[self.row_range(r)]
    }

    /// Number of nonzero entries in row `r`.
    #[inline]
    pub fn row_len(&self, r: usize) -> usize {
        self.row_offsets[r + 1] - self.row_offsets[r]
    }

    /// `(column, coefficient)` pairs of row `r`, in stored order (coefficients
    /// decoded through the value table). This is the primary accessor — the
    /// dictionary encoding is transparent to callers.
    #[inline]
    pub fn row(&self, r: usize) -> impl Iterator<Item = (u32, F128)> + '_ {
        let range = self.row_range(r);
        let table = &self.value_table;
        self.col_indices[range.clone()].iter().copied().zip(
            self.value_indices[range]
                .iter()
                .map(move |&vi| table[vi as usize]),
        )
    }
}

/// Block-diagonal R1CS instance with an F128 witness.
///
/// Total witness length `N = 2^m` **field elements** (not bits). The
/// constraint hypercube also has `2^m` points — one deg-2 constraint per
/// witness element under the `C = I` convention.
#[derive(Debug)]
pub struct FieldR1cs {
    /// log2 of the witness length in F128 elements (= log2 constraint count).
    pub m: usize,
    /// log2 of the base-matrix side `k`.
    pub k_log: usize,
    /// Univariate-skip dimension (`k_skip ≤ k_log`); the protocol standard is
    /// [`crate::zerocheck::K_SKIP`] = 6.
    pub k_skip: usize,
    /// Rows `[0, useful_rows)` of each block carry real witness data; rows
    /// `[useful_rows, 2^k_log)` are zero padding with empty matrix rows.
    /// Default `1 << k_log` (no padding).
    pub useful_rows: usize,
    pub a_0: SparseFieldMatrix,
    pub b_0: SparseFieldMatrix,
    /// Column of a constant-one wire pinned across all blocks, or `None`.
    /// See [`LincheckCircuit::const_pin_col`].
    pub const_pin: Option<usize>,
    /// Lazily-cached statement digest (see [`Self::statement_digest`]).
    #[doc(hidden)]
    pub digest_cache: std::sync::OnceLock<[u8; 32]>,
    /// Lazily-cached CSC lincheck circuit (see [`Self::csc_lincheck_circuit`]).
    #[doc(hidden)]
    pub csc_cache: std::sync::OnceLock<FieldCscCircuit>,
}

impl Clone for FieldR1cs {
    fn clone(&self) -> Self {
        Self {
            m: self.m,
            k_log: self.k_log,
            k_skip: self.k_skip,
            useful_rows: self.useful_rows,
            a_0: self.a_0.clone(),
            b_0: self.b_0.clone(),
            const_pin: self.const_pin,
            digest_cache: std::sync::OnceLock::new(),
            csc_cache: std::sync::OnceLock::new(),
        }
    }
}

impl FieldR1cs {
    pub fn n_outer(&self) -> usize {
        1usize << self.n_log()
    }
    pub fn n_log(&self) -> usize {
        self.m - self.k_log
    }
    pub fn k(&self) -> usize {
        1usize << self.k_log
    }
    /// Total witness length in F128 elements.
    pub fn n(&self) -> usize {
        1usize << self.m
    }

    /// Structural validation: matrix shapes, `k_skip ≤ k_log ≤ m`,
    /// `useful_rows ≤ k`, `const_pin < k`.
    pub fn validate_shape(&self) {
        let k = self.k();
        assert!(self.k_skip <= self.k_log, "k_skip > k_log");
        assert!(self.k_log <= self.m, "k_log > m");
        assert!(self.useful_rows <= k, "useful_rows > k");
        assert_eq!(self.a_0.num_rows, k);
        assert_eq!(self.a_0.num_cols, k);
        assert_eq!(self.b_0.num_rows, k);
        assert_eq!(self.b_0.num_cols, k);
        if let Some(col) = self.const_pin {
            assert!(col < k, "const_pin out of range");
        }
    }

    /// `a = (I ⊗ A_0) · z` over F128.
    pub fn apply_a(&self, z: &[F128]) -> Vec<F128> {
        apply_block_diag_field(&self.a_0, z, self.k_log)
    }

    /// `b = (I ⊗ B_0) · z` over F128.
    pub fn apply_b(&self, z: &[F128]) -> Vec<F128> {
        apply_block_diag_field(&self.b_0, z, self.k_log)
    }

    /// Check `(A·z) ⊙ (B·z) = z` per element (`C = I`).
    pub fn satisfies(&self, z: &[F128]) -> bool {
        assert_eq!(z.len(), self.n());
        let a = self.apply_a(z);
        let b = self.apply_b(z);
        a.iter()
            .zip(b.iter())
            .zip(z.iter())
            .all(|((ai, bi), zi)| *ai * *bi == *zi)
    }

    /// Build a [`FlipBattery`] over this instance and an honest witness —
    /// the fast path for wire-flip mutation gates (`O(column degree)` per
    /// flip instead of a full [`Self::satisfies`] pass).
    pub fn flip_battery(&self, z: &[F128]) -> FlipBattery<'_> {
        FlipBattery::new(self, z)
    }

    /// Poseidon2b hash of the instance (parameters + coefficient matrices).
    /// Binds the Fiat-Shamir transcript to the statement being proved.
    ///
    /// Two-level chunked construction: matrix rows are serialized in fixed
    /// [`DIGEST_SPAN_ROWS`]-row spans, each span hashed independently (in
    /// parallel — a big instance serializes to hundreds of MB, which a single
    /// sequential sponge would take tens of seconds to absorb, and this way
    /// the full serialization is never materialized at once), and the top
    /// hash absorbs the header fields plus the span digests in order. The
    /// encoding stays injective: the header fixes both matrices' row counts
    /// (hence the span count), every row is length-prefixed inside its span,
    /// and span digests are fixed-width.
    ///
    /// For production verifier-trace shapes the matrix is a protocol
    /// constant, so this value is a per-shape-class constant: compute it
    /// once and install it on fresh instances with
    /// [`Self::seed_statement_digest`] instead of re-hashing per instance.
    pub fn statement_digest(&self) -> [u8; 32] {
        *self
            .digest_cache
            .get_or_init(|| self.structural_statement_digest())
    }

    /// Recompute the statement digest directly from the matrix structure,
    /// deliberately ignoring [`Self::digest_cache`].
    ///
    /// Ordinary proof construction uses [`Self::statement_digest`] so a
    /// locally established class constant can be seeded cheaply. Trust
    /// boundaries that accept a matrix supplied by another component must use
    /// this method instead: otherwise that component could seed the expected
    /// digest onto different matrix contents and bypass the local structural
    /// identity check.
    pub fn structural_statement_digest(&self) -> [u8; 32] {
        let mut top = Vec::new();
        push_u64(&mut top, self.m as u64);
        push_u64(&mut top, self.k_log as u64);
        push_u64(&mut top, self.k_skip as u64);
        push_u64(&mut top, self.useful_rows as u64);
        // Encode the pin unambiguously: 0 = None, 1 + col = Some(col).
        push_u64(&mut top, self.const_pin.map(|c| 1 + c as u64).unwrap_or(0));
        for m_0 in [&self.a_0, &self.b_0] {
            push_u64(&mut top, m_0.num_rows as u64);
            push_u64(&mut top, m_0.num_cols as u64);
            for digest in matrix_span_digests(m_0) {
                top.extend_from_slice(&digest);
            }
        }
        noid_poseidon2b::native::poseidon2b_hash_byte_slices(b"NOID/IVC/FIELD-R1CS-STMT", &[&top])
    }

    /// Install a precomputed statement digest — the per-shape-class protocol
    /// constant — skipping the content hash entirely.
    ///
    /// This is safe only after the caller has already established that the
    /// matrix contents have this identity (for example by reproducing a frozen
    /// class relation). A verifier receiving a matrix from another component
    /// must compare [`Self::structural_statement_digest`] instead of trusting
    /// this seedable cache. Panics if a different digest is already cached.
    pub fn seed_statement_digest(&self, digest: [u8; 32]) {
        if self.digest_cache.set(digest).is_err() {
            assert_eq!(
                *self.digest_cache.get().expect("cache is set"),
                digest,
                "seed_statement_digest: a different digest is already cached"
            );
        }
    }

    /// CSC-transposed `LincheckCircuit` over `(a_0, b_0)` with F128
    /// coefficients. Built lazily on first access and cached.
    pub fn csc_lincheck_circuit(&self) -> &FieldCscCircuit {
        self.csc_cache.get_or_init(|| {
            FieldCscCircuit::from_matrices(&self.a_0, &self.b_0).with_const_pin(self.const_pin)
        })
    }

    /// Release the lazily materialized CSC transpose while retaining the
    /// canonical CSR statement.  Long-lived class registries and streaming
    /// deciders call this after a proof phase so one verification cache per
    /// frozen class does not remain resident between prover jobs.
    ///
    /// The cache is purely derived data and is rebuilt on the next
    /// [`Self::csc_lincheck_circuit`] access. Returns whether a cache was
    /// present.
    pub fn release_csc_cache(&mut self) -> bool {
        self.csc_cache.take().is_some()
    }
}

/// Rows per statement-digest span. Small enough that per-span buffers stay
/// cache-friendly (a ~20-nnz/row span is ~1 MB), large enough that span
/// digests are negligible against the span payloads.
const DIGEST_SPAN_ROWS: usize = 2048;

/// Independent Poseidon2b digests of a coefficient matrix's rows in
/// [`DIGEST_SPAN_ROWS`]-row spans (parallel), each span serialized as
/// length-prefixed rows of `(column, coeff.lo, coeff.hi)` u64 triples.
fn matrix_span_digests(m: &SparseFieldMatrix) -> Vec<[u8; 32]> {
    use rayon::prelude::*;
    let n_spans = m.num_rows.div_ceil(DIGEST_SPAN_ROWS);
    (0..n_spans)
        .into_par_iter()
        .map(|s| {
            let r0 = s * DIGEST_SPAN_ROWS;
            let r1 = ((s + 1) * DIGEST_SPAN_ROWS).min(m.num_rows);
            let payload: usize = (r0..r1).map(|r| 8 + 24 * m.row_len(r)).sum();
            let mut bytes = Vec::with_capacity(payload);
            for r in r0..r1 {
                push_u64(&mut bytes, m.row_len(r) as u64);
                for (col, coeff) in m.row(r) {
                    push_u64(&mut bytes, col as u64);
                    push_u64(&mut bytes, coeff.lo);
                    push_u64(&mut bytes, coeff.hi);
                }
            }
            noid_poseidon2b::native::poseidon2b_hash_byte_slices(
                b"NOID/IVC/FIELD-R1CS-SPAN",
                &[&bytes],
            )
        })
        .collect()
}

#[inline]
fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Block-diagonal `(I ⊗ M_0) · z` over F128.
///
/// Parallel over the Kronecker blocks AND, within each block, over row chunks.
/// Block-only parallelism (one task per `k`-sized block) starves when there
/// are few large blocks: the recursion link commits ONE block of `2^k_log`
/// rows, so a block-parallel loop is a single serial task walking millions of
/// rows (measured ~6.5 s at `k_log = 24`). Nesting a row-chunk `par_chunks_mut`
/// restores full core utilization there and is a no-op for the many-small-block
/// regime (a block shorter than `ROW_CHUNK` yields one inner chunk). The
/// per-row work and its accumulation order are unchanged, so the output is
/// bit-identical to the serial form.
pub fn apply_block_diag_field(m_0: &SparseFieldMatrix, z: &[F128], k_log: usize) -> Vec<F128> {
    use rayon::prelude::*;

    let k = 1usize << k_log;
    assert_eq!(m_0.num_rows, k);
    assert_eq!(m_0.num_cols, k);
    assert_eq!(z.len() % k, 0);

    const ROW_CHUNK: usize = 4096;
    let mut out = vec![F128::ZERO; z.len()];
    out.par_chunks_mut(k)
        .zip(z.par_chunks(k))
        .for_each(|(out_block, z_block)| {
            out_block
                .par_chunks_mut(ROW_CHUNK)
                .enumerate()
                .for_each(|(ci, out_rows)| {
                    let r0 = ci * ROW_CHUNK;
                    for (j, o) in out_rows.iter_mut().enumerate() {
                        let mut acc = F128::ZERO;
                        for (c, coeff) in m_0.row(r0 + j) {
                            acc += coeff * z_block[c as usize];
                        }
                        *o = acc;
                    }
                });
        });
    out
}

// ---------------------------------------------------------------------------
// FlipBattery: incremental single-wire mutation checks
// ---------------------------------------------------------------------------

/// Incremental wire-flip mutation checker: precomputes `Az`, `Bz` and
/// per-column row lists once, then answers "does the trace still satisfy
/// after `z[w] += 1`?" in `O(deg_A(w) + deg_B(w))` — a single-wire flip
/// only perturbs the rows whose A/B row reads that wire (block-diagonal
/// relation, `C = I`, so the flipped wire's own row is the only RHS
/// change). Semantically identical to cloning the witness, flipping, and
/// running the full [`FieldR1cs::satisfies`]; mutation batteries at
/// verifier-trace scale (`2^20+` rows × 10⁴+ targets) are infeasible
/// with full passes and instant with this.
pub struct FlipBattery<'a> {
    r1cs: &'a FieldR1cs,
    z: Vec<F128>,
    az: Vec<F128>,
    bz: Vec<F128>,
    /// Per inner column: the block-local rows reading it, with coefficients.
    cols_a: Vec<Vec<(u32, F128)>>,
    cols_b: Vec<Vec<(u32, F128)>>,
}

impl<'a> FlipBattery<'a> {
    pub fn new(r1cs: &'a FieldR1cs, z: &[F128]) -> Self {
        assert_eq!(z.len(), r1cs.n());
        let az = r1cs.apply_a(z);
        let bz = r1cs.apply_b(z);
        assert!(
            az.iter()
                .zip(bz.iter())
                .zip(z.iter())
                .all(|((a, b), zi)| *a * *b == *zi),
            "FlipBattery requires an honest witness"
        );
        let transpose = |m: &SparseFieldMatrix| {
            let mut cols: Vec<Vec<(u32, F128)>> = vec![Vec::new(); m.num_cols];
            for r in 0..m.num_rows {
                for (c, coeff) in m.row(r) {
                    cols[c as usize].push((r as u32, coeff));
                }
            }
            cols
        };
        Self {
            r1cs,
            z: z.to_vec(),
            az,
            bz,
            cols_a: transpose(&r1cs.a_0),
            cols_b: transpose(&r1cs.b_0),
        }
    }

    /// Whether the trace still satisfies after flipping `z[w] += 1`
    /// (leaves the battery state unchanged).
    pub fn survives_flip(&mut self, w: usize) -> bool {
        let k_log = self.r1cs.k_log;
        let base = (w >> k_log) << k_log;
        let i = w & ((1usize << k_log) - 1);

        // Apply the delta (char 2: Δz = 1 ⇒ Δ(Az)[r] = A[r][i]).
        self.z[w] += F128::ONE;
        for &(r, coeff) in &self.cols_a[i] {
            self.az[base + r as usize] += coeff;
        }
        for &(r, coeff) in &self.cols_b[i] {
            self.bz[base + r as usize] += coeff;
        }

        // Check the affected rows (both column lists plus the wire's own
        // row); duplicates re-check harmlessly.
        let mut ok = {
            let r = w;
            self.az[r] * self.bz[r] == self.z[r]
        };
        if ok {
            for &(r, _) in &self.cols_a[i] {
                let r = base + r as usize;
                if self.az[r] * self.bz[r] != self.z[r] {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            for &(r, _) in &self.cols_b[i] {
                let r = base + r as usize;
                if self.az[r] * self.bz[r] != self.z[r] {
                    ok = false;
                    break;
                }
            }
        }

        // Revert (char 2: adding the same deltas again).
        self.z[w] += F128::ONE;
        for &(r, coeff) in &self.cols_a[i] {
            self.az[base + r as usize] += coeff;
        }
        for &(r, coeff) in &self.cols_b[i] {
            self.bz[base + r as usize] += coeff;
        }
        ok
    }

    /// Run the battery over a wire range, returning the survivors.
    pub fn survivors(&mut self, range: std::ops::Range<usize>) -> Vec<usize> {
        range.filter(|&w| self.survives_flip(w)).collect()
    }

    /// Whether `w` is a pin-row helper: the free wire `pin_f128`
    /// materializes so its row can constrain an expression SUM. Such a
    /// wire appears with coefficient one in its own A row (where it
    /// cancels against the `C = I` right-hand side in char 2), that row's
    /// B side is the constant-one wire, and nothing else reads it —
    /// flipping it is satisfiability-neutral BY CONSTRUCTION, so mutation
    /// batteries exclude exactly this shape.
    pub fn is_pin_helper(&self, w: usize) -> bool {
        let i = w & ((1usize << self.r1cs.k_log) - 1);
        self.cols_b[i].is_empty()
            && self.cols_a[i].len() == 1
            && self.cols_a[i][0] == (i as u32, F128::ONE)
            && self.r1cs.b_0.row_cols(i) == [0u32]
            && self.r1cs.b_0.row(i).next().map(|(_, v)| v) == Some(F128::ONE)
    }

    /// [`Self::survivors`] minus the pin-helper class — the standard gate
    /// for assembled traces where pin rows interleave with allocations.
    pub fn survivors_excluding_pin_helpers(&mut self, range: std::ops::Range<usize>) -> Vec<usize> {
        range
            .filter(|&w| !self.is_pin_helper(w) && self.survives_flip(w))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// FieldCscCircuit: coefficient-carrying LincheckCircuit
// ---------------------------------------------------------------------------

/// Column-major (CSC) [`LincheckCircuit`] over a pair of F128-coefficient
/// matrices: vs the binary-matrix fold, the eq-weighted column
/// marginal gains one field multiplication per nonzero,
///
///   `comb[c] = α · Σ_{(r,κ) ∈ colA(c)} κ · eq_inner[r]
///            +     Σ_{(r,κ) ∈ colB(c)} κ · eq_inner[r]`
///
/// replacing the boolean path's XOR accumulation. Everything else in the
/// lincheck (sumcheck rounds, univariate skip, transcript) is untouched.
#[derive(Clone)]
pub struct FieldCscCircuit {
    n_cols: usize,
    a_col_ptr: Vec<u32>,
    a_rows: Vec<u32>,
    a_coeffs: Vec<F128>,
    b_col_ptr: Vec<u32>,
    b_rows: Vec<u32>,
    b_coeffs: Vec<F128>,
    const_pin: Option<usize>,
}

impl std::fmt::Debug for FieldCscCircuit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FieldCscCircuit")
            .field("n_cols", &self.n_cols)
            .field("nnz_a", &self.a_rows.len())
            .field("nnz_b", &self.b_rows.len())
            .finish()
    }
}

/// Flatten one coefficient matrix into CSC arrays.
fn field_csc_from_rows(m: &SparseFieldMatrix) -> (Vec<u32>, Vec<u32>, Vec<F128>) {
    assert!(m.num_rows <= u32::MAX as usize);
    assert!(m.num_cols <= u32::MAX as usize);
    let mut col_ptr = vec![0u32; m.num_cols + 1];
    for &c in &m.col_indices {
        col_ptr[c as usize + 1] += 1;
    }
    for c in 0..m.num_cols {
        col_ptr[c + 1] += col_ptr[c];
    }
    let mut next = col_ptr.clone();
    let nnz = *col_ptr.last().unwrap() as usize;
    let mut rows_flat = vec![0u32; nnz];
    let mut coeffs_flat = vec![F128::ZERO; nnz];
    for r in 0..m.num_rows {
        for (c, coeff) in m.row(r) {
            let c = c as usize;
            let slot = next[c] as usize;
            rows_flat[slot] = r as u32;
            coeffs_flat[slot] = coeff;
            next[c] += 1;
        }
    }
    (col_ptr, rows_flat, coeffs_flat)
}

impl FieldCscCircuit {
    pub fn from_matrices(a_0: &SparseFieldMatrix, b_0: &SparseFieldMatrix) -> Self {
        assert_eq!(a_0.num_rows, b_0.num_rows);
        assert_eq!(a_0.num_cols, b_0.num_cols);
        let (a_col_ptr, a_rows, a_coeffs) = field_csc_from_rows(a_0);
        let (b_col_ptr, b_rows, b_coeffs) = field_csc_from_rows(b_0);
        Self {
            n_cols: a_0.num_cols,
            a_col_ptr,
            a_rows,
            a_coeffs,
            b_col_ptr,
            b_rows,
            b_coeffs,
            const_pin: None,
        }
    }

    /// Set the constant-wire pin column (see `docs/const-wire-pin.md`).
    pub fn with_const_pin(mut self, const_pin: Option<usize>) -> Self {
        self.const_pin = const_pin;
        self
    }
}

/// Same rayon-dispatch threshold as the boolean `CscCircuit`.
const FIELD_FOLD_PAR_THRESHOLD: usize = 1usize << 12;

/// Peak-memory budget for the lincheck fold's per-chunk partial combs. Each
/// parallel chunk holds one width-`n_cols` F128 comb; at the m=24 block-bearing
/// class `n_cols = 2^24` (256 MB/comb), so one comb per worker was a multi-GB
/// transient (the largest at that scale). The chunk count is capped so the live
/// combs stay under this budget, trading a little fold parallelism (the fold is
/// a small fraction of prove time) for a bounded footprint. Small instances
/// have small combs, so the cap only binds at large `m`.
const FOLD_COMB_BUDGET_BYTES: usize = 1usize << 30;

impl LincheckCircuit for FieldCscCircuit {
    fn n_cols(&self) -> usize {
        self.n_cols
    }
    fn const_pin_col(&self) -> Option<usize> {
        self.const_pin
    }
    fn fold_alpha_batched(&self, alpha: F128, eq_inner: &[F128]) -> Vec<F128> {
        use rayon::prelude::*;
        assert_eq!(eq_inner.len(), self.n_cols);
        let one_col = |c: usize| {
            let mut sa = F128::ZERO;
            let (lo, hi) = (self.a_col_ptr[c] as usize, self.a_col_ptr[c + 1] as usize);
            for (r, coeff) in self.a_rows[lo..hi].iter().zip(&self.a_coeffs[lo..hi]) {
                sa += *coeff * eq_inner[*r as usize];
            }
            let mut sb = F128::ZERO;
            let (lo, hi) = (self.b_col_ptr[c] as usize, self.b_col_ptr[c + 1] as usize);
            for (r, coeff) in self.b_rows[lo..hi].iter().zip(&self.b_coeffs[lo..hi]) {
                sb += *coeff * eq_inner[*r as usize];
            }
            alpha * sa + sb
        };
        if self.n_cols < FIELD_FOLD_PAR_THRESHOLD {
            return (0..self.n_cols).map(one_col).collect();
        }
        let mut out = vec![F128::ZERO; self.n_cols];
        out.par_iter_mut()
            .enumerate()
            .for_each(|(c, slot)| *slot = one_col(c));
        out
    }
}

/// Borrowing, **row-major** [`LincheckCircuit`] over a pair of
/// F128-coefficient matrices `(a_0, b_0)`.
///
/// It folds directly off the row-major [`SparseFieldMatrix`] storage the
/// prover already owns, so — unlike [`FieldCscCircuit`] — it allocates **no**
/// transposed CSC copy. During the prover's lincheck+open window only ONE
/// matrix representation (the un-droppable row-major `a_0`/`b_0`) stays
/// resident, roughly halving constraint-matrix RAM.
///
/// `fold_alpha_batched` is **value-identical** to
/// [`FieldCscCircuit::fold_alpha_batched`]: it computes the same
///
///   `comb[c] = α · Σ_{r} A_0[r,c]·eq[r] + Σ_{r} B_0[r,c]·eq[r]`
///
/// by scattering `α·coeff·eq[r]` (matrix A) and `coeff·eq[r]` (matrix B) into
/// `comb[c]`. GF(2^128) addition is exact, associative and commutative, so the
/// scatter/accumulation order is irrelevant to the result (the
/// `csc_fold_matches_direct` test asserts this scatter form equals the CSC
/// fold bit-for-bit). Identical `comb_vec` ⇒ identical Fiat-Shamir transcript
/// ⇒ byte-identical proof.
pub struct FieldRowCircuit<'a> {
    a_0: &'a SparseFieldMatrix,
    b_0: &'a SparseFieldMatrix,
    const_pin: Option<usize>,
}

impl<'a> FieldRowCircuit<'a> {
    pub fn new(
        a_0: &'a SparseFieldMatrix,
        b_0: &'a SparseFieldMatrix,
        const_pin: Option<usize>,
    ) -> Self {
        debug_assert_eq!(a_0.num_rows, b_0.num_rows);
        debug_assert_eq!(a_0.num_cols, b_0.num_cols);
        Self {
            a_0,
            b_0,
            const_pin,
        }
    }
}

impl LincheckCircuit for FieldRowCircuit<'_> {
    fn n_cols(&self) -> usize {
        self.a_0.num_cols
    }
    fn const_pin_col(&self) -> Option<usize> {
        self.const_pin
    }
    fn fold_alpha_batched(&self, alpha: F128, eq_inner: &[F128]) -> Vec<F128> {
        use rayon::prelude::*;
        let n = self.a_0.num_cols;
        assert_eq!(eq_inner.len(), n);

        let nnz = self.a_0.nnz() + self.b_0.nnz();

        // Serial scatter for small instances: one output comb, `comb[c] +=
        // weight·coeff·eq[r]` over each matrix's rows (weight α for A, 1 for B).
        if nnz < FIELD_FOLD_PAR_THRESHOLD {
            let mut comb = vec![F128::ZERO; n];
            for r in 0..self.a_0.num_rows {
                let er = eq_inner[r];
                for (c, coeff) in self.a_0.row(r) {
                    comb[c as usize] += alpha * coeff * er;
                }
            }
            for r in 0..self.b_0.num_rows {
                let er = eq_inner[r];
                for (c, coeff) in self.b_0.row(r) {
                    comb[c as usize] += coeff * er;
                }
            }
            return comb;
        }

        // Parallel scatter: split the rows into row-chunks, each producing a
        // private width-`n` partial comb, reduced with field addition (char-2,
        // associative ⇒ value-identical to any other order).
        //
        // Chunk count = `threads` (ONE contiguous chunk per worker), NOT a
        // multiple of it: each partial comb is `n = n_cols` F128 (256 MB at
        // the m=24 block-bearing class), so `4 * threads` chunks made the fold
        // a multi-GB transient — VmHWM showed a +266 MB spike at m=19
        // (n_cols = 8 MB), i.e. ~8.5 GB at m=24 (n_cols = 256 MB), the single
        // largest prover transient and invisible to lap-boundary RSS. One
        // chunk per worker caps the live combs at ~`threads` (uniform row
        // density load-balances the equal ranges), trading a little
        // work-steal slack for the memory. Preserves the CSC fold's
        // column-parallelism without materializing a transpose.
        let threads = rayon::current_num_threads().max(1);
        // Cap the chunk count so the live per-chunk combs fit the memory budget
        // (see FOLD_COMB_BUDGET_BYTES): one comb per worker was ~threads * n_cols
        // F128, and `reduce`'s per-segment identity seed doubled that. Bound the
        // chunks by the budget and use `reduce_with` (no identity comb — it
        // folds the map outputs directly, the first as seed).
        let comb_bytes = n * std::mem::size_of::<F128>();
        let max_chunks = (FOLD_COMB_BUDGET_BYTES / comb_bytes.max(1)).max(1);
        let fold_matrix = |m: &SparseFieldMatrix, weight: F128| -> Vec<F128> {
            let target_chunks = threads.min(max_chunks).max(1);
            let chunk = m.num_rows.div_ceil(target_chunks).max(256);
            let n_chunks = m.num_rows.div_ceil(chunk);
            (0..n_chunks)
                .into_par_iter()
                .map(|ci| {
                    let r0 = ci * chunk;
                    let r1 = ((ci + 1) * chunk).min(m.num_rows);
                    let mut comb = vec![F128::ZERO; n];
                    for r in r0..r1 {
                        let er = eq_inner[r];
                        for (c, coeff) in m.row(r) {
                            comb[c as usize] += weight * coeff * er;
                        }
                    }
                    comb
                })
                .reduce_with(|mut acc, part| {
                    for (x, y) in acc.iter_mut().zip(part) {
                        *x += y;
                    }
                    acc
                })
                .unwrap_or_else(|| vec![F128::ZERO; n])
        };

        let mut comb = fold_matrix(self.a_0, alpha);
        let b_comb = fold_matrix(self.b_0, F128::ONE);
        for (x, y) in comb.iter_mut().zip(b_comb) {
            *x += y;
        }
        comb
    }
}

// ---------------------------------------------------------------------------
// Synthetic instances (tests + the substrate throughput bench)
// ---------------------------------------------------------------------------

/// Deterministic synthetic satisfiable instance + witness — test/bench
/// fixture (a stand-in for builder-produced gadget traces).
///
/// Shape mimics a verifier-replay trace: column 0 of every block is the
/// constant-one wire (`const_pin = Some(0)`, row-0 constraint `z_0² = z_0`
/// with the honest witness at 1), every later row is a multiplication of two
/// coefficient-weighted combinations of earlier wires (strictly
/// lower-triangular support, 1–4 nonzeros per matrix row — the density of
/// Poseidon2b round chains under option A). The witness is derived alongside,
/// so `satisfies` holds by construction.
pub fn synthetic_satisfiable(m: usize, k_log: usize, seed: u64) -> (FieldR1cs, Vec<F128>) {
    let k = 1usize << k_log;
    assert!(k_log >= 1 && k_log <= m);
    let mut state = seed;
    let mut next_u64 = move || {
        state = state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    };
    let mut next_f128_nonzero = move || loop {
        let v = F128 {
            lo: next_u64(),
            hi: next_u64(),
        };
        if v != F128::ZERO {
            return v;
        }
    };

    let gen_matrix =
        |rng: &mut dyn FnMut() -> u64, coeff: &mut dyn FnMut() -> F128| -> SparseFieldMatrix {
            SparseFieldMatrix::from_rows(
                k,
                (0..k)
                    .map(|r| {
                        if r == 0 {
                            // Constant-wire row: z_0 · z_0 = z_0.
                            return vec![(0u32, F128::ONE)];
                        }
                        let n_nonzero = 1 + (rng() % 4) as usize;
                        (0..n_nonzero)
                            .map(|_| ((rng() as usize % r) as u32, coeff()))
                            .collect()
                    })
                    .collect(),
            )
        };
    let mut rng_a = {
        let mut s = seed ^ 0xA;
        move || {
            s = s.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = s;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^ (z >> 31)
        }
    };
    let a_0 = gen_matrix(&mut rng_a, &mut next_f128_nonzero);
    let mut rng_b = {
        let mut s = seed ^ 0xB;
        move || {
            s = s.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = s;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^ (z >> 31)
        }
    };
    let b_0 = gen_matrix(&mut rng_b, &mut next_f128_nonzero);

    let n = 1usize << m;
    let mut z = vec![F128::ZERO; n];
    let n_outer = n / k;
    for blk in 0..n_outer {
        let base = blk * k;
        z[base] = F128::ONE; // the constant wire
        for r in 1..k {
            let dot = |m: &SparseFieldMatrix| {
                let mut acc = F128::ZERO;
                for (c, coeff) in m.row(r) {
                    acc += coeff * z[base + c as usize];
                }
                acc
            };
            z[base + r] = dot(&a_0) * dot(&b_0);
        }
    }

    let r1cs = FieldR1cs {
        m,
        k_log,
        k_skip: crate::zerocheck::K_SKIP.min(k_log),
        useful_rows: k,
        a_0,
        b_0,
        const_pin: Some(0),
        digest_cache: std::sync::OnceLock::new(),
        csc_cache: std::sync::OnceLock::new(),
    };
    debug_assert!(r1cs.satisfies(&z));
    (r1cs, z)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lincheck::build_eq_table;

    struct Rng(u64);
    impl Rng {
        fn new(seed: u64) -> Self {
            Self(seed)
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^ (z >> 31)
        }
        fn f128(&mut self) -> F128 {
            F128 {
                lo: self.next_u64(),
                hi: self.next_u64(),
            }
        }
    }

    fn random_satisfiable(m: usize, k_log: usize, seed: u64) -> (FieldR1cs, Vec<F128>) {
        synthetic_satisfiable(m, k_log, seed)
    }

    #[test]
    fn random_instances_satisfy() {
        for &(m, k_log, seed) in &[(8usize, 4usize, 1u64), (10, 6, 2), (12, 8, 3)] {
            let (r1cs, z) = random_satisfiable(m, k_log, seed);
            r1cs.validate_shape();
            assert!(r1cs.satisfies(&z), "m={m} k_log={k_log}");

            // Corrupt one element → unsatisfied. Index 1 is a constrained row
            // (row 0 is the free-input row where any corruption also breaks
            // the z_0 = 0 constraint, but 1 exercises the multiplicative row).
            let mut bad = z.clone();
            bad[1] += F128::ONE;
            assert!(!r1cs.satisfies(&bad), "corruption accepted m={m}");
        }
    }

    #[test]
    fn identity_a_b_forces_idempotents() {
        // A_0 = B_0 = I ⇒ constraint z_i² = z_i ⇒ z_i ∈ {0, 1} (the only
        // idempotents of a field). Field semantics differ from GF(2) bitwise:
        // an arbitrary F128 element does NOT satisfy it.
        let k_log = 3;
        let m = 5;
        let r1cs = FieldR1cs {
            m,
            k_log,
            k_skip: 3,
            useful_rows: 1 << k_log,
            a_0: SparseFieldMatrix::identity(1 << k_log),
            b_0: SparseFieldMatrix::identity(1 << k_log),
            const_pin: None,
            digest_cache: std::sync::OnceLock::new(),
            csc_cache: std::sync::OnceLock::new(),
        };
        let mut z = vec![F128::ZERO; 1 << m];
        z[3] = F128::ONE;
        assert!(r1cs.satisfies(&z));
        z[5] = F128 { lo: 2, hi: 0 };
        assert!(!r1cs.satisfies(&z), "non-idempotent element accepted");
    }

    #[test]
    fn csc_cache_can_be_released_and_rebuilt() {
        let (mut r1cs, _) = random_satisfiable(10, 6, 0xC5C);
        assert!(!r1cs.release_csc_cache(), "fresh instance has no CSC");
        let first_shape = {
            let csc = r1cs.csc_lincheck_circuit();
            (csc.n_cols, csc.a_rows.len(), csc.b_rows.len())
        };
        assert!(r1cs.release_csc_cache(), "materialized CSC was released");
        assert!(!r1cs.release_csc_cache(), "release is idempotent");
        let rebuilt = r1cs.csc_lincheck_circuit();
        assert_eq!(
            (rebuilt.n_cols, rebuilt.a_rows.len(), rebuilt.b_rows.len()),
            first_shape,
            "rebuilt CSC shape drifted",
        );
    }

    /// FieldCscCircuit::fold_alpha_batched matches the direct definition
    /// `comb[c] = α·Σ_r A_0[r,c]·eq[r] + Σ_r B_0[r,c]·eq[r]`.
    #[test]
    fn csc_fold_matches_direct() {
        let (r1cs, _) = random_satisfiable(10, 6, 77);
        let k = r1cs.k();
        let mut rng = Rng::new(999);
        let point: Vec<F128> = (0..r1cs.k_log).map(|_| rng.f128()).collect();
        let eq_inner = build_eq_table(&point);
        assert_eq!(eq_inner.len(), k);
        let alpha = rng.f128();

        let circuit = r1cs.csc_lincheck_circuit();
        let got = circuit.fold_alpha_batched(alpha, &eq_inner);

        let mut expected = vec![F128::ZERO; k];
        for r in 0..r1cs.a_0.num_rows {
            for (c, coeff) in r1cs.a_0.row(r) {
                expected[c as usize] += alpha * coeff * eq_inner[r];
            }
        }
        for r in 0..r1cs.b_0.num_rows {
            for (c, coeff) in r1cs.b_0.row(r) {
                expected[c as usize] += coeff * eq_inner[r];
            }
        }
        assert_eq!(got, expected);
    }

    #[test]
    fn statement_digest_distinguishes_instances() {
        let (r1cs_a, _) = random_satisfiable(8, 4, 10);
        let (r1cs_b, _) = random_satisfiable(8, 4, 11);
        assert_ne!(r1cs_a.statement_digest(), r1cs_b.statement_digest());

        // Coefficient change flips the digest (perturb a table entry — every
        // nonzero mapping to it decodes to the new value; `clone` resets the
        // digest cache, so it is re-hashed).
        let mut r1cs_c = r1cs_a.clone();
        *r1cs_c
            .a_0
            .value_table
            .first_mut()
            .expect("matrix has at least one distinct value") += F128::ONE;
        assert_ne!(r1cs_a.statement_digest(), r1cs_c.statement_digest());

        // Same content → same digest (cache-independent).
        let r1cs_d = r1cs_a.clone();
        assert_eq!(r1cs_a.statement_digest(), r1cs_d.statement_digest());
    }

    /// The chunked digest is sensitive to content in EVERY span, not just the
    /// first: k = 2^12 rows = two spans of `DIGEST_SPAN_ROWS`.
    #[test]
    fn statement_digest_covers_all_spans() {
        let (r1cs, _) = random_satisfiable(12, 12, 5);
        assert!(r1cs.k() > DIGEST_SPAN_ROWS, "instance must span ≥2 chunks");
        let base = r1cs.statement_digest();

        for &row in &[1usize, DIGEST_SPAN_ROWS - 1, DIGEST_SPAN_ROWS, r1cs.k() - 1] {
            let mut mutated = r1cs.clone();
            assert!(mutated.b_0.row_len(row) > 0, "synthetic rows are nonempty");
            // Perturb exactly this one nonzero: point it at a fresh table entry
            // holding (old value + 1), leaving all other nonzeros untouched.
            let entry = mutated.b_0.row_offsets[row];
            let old = mutated.b_0.value_table[mutated.b_0.value_indices[entry] as usize];
            let new_idx = mutated.b_0.value_table.len() as u32;
            mutated.b_0.value_table.push(old + F128::ONE);
            mutated.b_0.value_indices[entry] = new_idx;
            assert_ne!(
                base,
                mutated.statement_digest(),
                "coefficient change in row {row} must flip the digest"
            );
        }
    }

    #[test]
    fn seed_statement_digest_installs_constant() {
        let (r1cs, _) = random_satisfiable(8, 4, 21);
        let true_digest = r1cs.statement_digest();

        // Seeding a fresh instance short-circuits the content hash.
        let fresh = r1cs.clone();
        fresh.seed_statement_digest(true_digest);
        assert_eq!(fresh.statement_digest(), true_digest);

        // Seeding the already-computed digest again is a no-op.
        fresh.seed_statement_digest(true_digest);

        // A seeded digest wins even if it is not the content hash. Callers at
        // a matrix trust boundary must use structural_statement_digest().
        let mislabeled = r1cs.clone();
        mislabeled.seed_statement_digest([0xAB; 32]);
        assert_eq!(mislabeled.statement_digest(), [0xAB; 32]);
        assert_eq!(
            mislabeled.structural_statement_digest(),
            true_digest,
            "cache-independent digest must recover the matrix's real identity",
        );
    }

    #[test]
    fn structural_statement_digest_rejects_seeded_content_substitution() {
        let (honest, _) = random_satisfiable(8, 4, 0x51A7_E001);
        let expected = honest.structural_statement_digest();
        let mut substituted = honest.clone();
        let entry = substituted.a_0.row_offsets[0];
        let old = substituted.a_0.value_table[substituted.a_0.value_indices[entry] as usize];
        let replacement = substituted.a_0.value_table.len() as u32;
        substituted.a_0.value_table.push(old + F128::ONE);
        substituted.a_0.value_indices[entry] = replacement;
        substituted.seed_statement_digest(expected);

        assert_eq!(
            substituted.statement_digest(),
            expected,
            "the ordinary class cache is intentionally seedable",
        );
        assert_ne!(
            substituted.structural_statement_digest(),
            expected,
            "a trust-boundary digest must ignore the seeded cache",
        );
    }

    #[test]
    #[should_panic(expected = "different digest is already cached")]
    fn seed_statement_digest_rejects_conflict() {
        let (r1cs, _) = random_satisfiable(8, 4, 22);
        let _ = r1cs.statement_digest();
        r1cs.seed_statement_digest([0xCD; 32]);
    }

    /// FlipBattery answers exactly what a full clone-flip-satisfies pass
    /// answers, for EVERY wire of several instances (multi-block shapes
    /// included), and leaves its state intact between queries.
    #[test]
    fn flip_battery_matches_full_satisfies() {
        for (m, k_log, seed) in [(6usize, 6usize, 1u64), (8, 5, 2), (7, 7, 3)] {
            let (r1cs, z) = random_satisfiable(m, k_log, seed);
            assert!(r1cs.satisfies(&z));
            let mut battery = r1cs.flip_battery(&z);
            for w in 0..z.len() {
                let mut bad = z.clone();
                bad[w] += F128::ONE;
                let full = r1cs.satisfies(&bad);
                assert_eq!(
                    battery.survives_flip(w),
                    full,
                    "m={m} k_log={k_log} wire {w}"
                );
            }
            // State intact: a second pass agrees with itself.
            for w in (0..z.len()).step_by(7) {
                let mut bad = z.clone();
                bad[w] += F128::ONE;
                assert_eq!(battery.survives_flip(w), r1cs.satisfies(&bad));
            }
        }
    }

    #[test]
    fn apply_block_diag_field_blocks_independent() {
        let (r1cs, z) = random_satisfiable(9, 5, 42);
        let k = r1cs.k();
        let a_full = r1cs.apply_a(&z);
        // Per-block manual apply must match.
        for blk in 0..r1cs.n_outer() {
            let base = blk * k;
            for r in 0..r1cs.a_0.num_rows {
                let mut acc = F128::ZERO;
                for (c, coeff) in r1cs.a_0.row(r) {
                    acc += coeff * z[base + c as usize];
                }
                assert_eq!(a_full[base + r], acc, "blk={blk} r={r}");
            }
        }
    }
}
