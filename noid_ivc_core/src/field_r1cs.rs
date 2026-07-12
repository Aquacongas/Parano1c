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
use std::fmt;
use std::io::{self, Read, Seek, SeekFrom, Write};

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

// ---------------------------------------------------------------------------
// Canonical matrix artifact codec
// ---------------------------------------------------------------------------

/// Magic prefix of the canonical on-disk [`FieldR1cs`] artifact.
pub const FIELD_R1CS_ARTIFACT_MAGIC: [u8; 8] = *b"NOIDR1CS";
/// First canonical artifact version. All integers, including field limbs, are
/// encoded little-endian.
pub const FIELD_R1CS_ARTIFACT_VERSION: u16 = 1;

// The complete fixed header is deliberately 128 bytes:
// magic/version/header-size/total-size, the FieldR1cs parameters, then two
// five-u64 matrix descriptors (rows, columns, nnz, values, offsets).
const FIELD_R1CS_ARTIFACT_HEADER_BYTES: usize = 128;
const FIELD_R1CS_ARTIFACT_IO_CHUNK_BYTES: usize = 64 * 1024;

/// Identifies one base matrix in a malformed artifact error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldR1csArtifactMatrix {
    A,
    B,
}

/// Fail-closed error returned by the canonical matrix artifact codec.
#[derive(Debug)]
pub enum FieldR1csArtifactError {
    Io(io::Error),
    Truncated {
        offset: u64,
        needed: usize,
    },
    TrailingBytes,
    InvalidMagic,
    UnsupportedVersion {
        actual: u16,
    },
    InvalidHeaderLength {
        actual: u16,
    },
    InvalidShape(&'static str),
    ShapeMismatch {
        field: &'static str,
        expected: u64,
        actual: u64,
    },
    MatrixDimensions {
        matrix: FieldR1csArtifactMatrix,
        expected: u64,
        rows: u64,
        cols: u64,
    },
    MatrixLengthMismatch {
        matrix: FieldR1csArtifactMatrix,
        field: &'static str,
        expected: u64,
        actual: u64,
    },
    CountOutOfRange {
        matrix: FieldR1csArtifactMatrix,
        field: &'static str,
        actual: u64,
        maximum: u64,
    },
    LengthArithmetic,
    TotalLengthMismatch {
        declared: u64,
        computed: u64,
    },
    TooLarge {
        actual: u64,
        max: usize,
    },
    Allocation {
        matrix: FieldR1csArtifactMatrix,
        field: &'static str,
    },
    InvalidRowOffset {
        matrix: FieldR1csArtifactMatrix,
        index: usize,
        previous: usize,
        actual: u64,
        nnz: usize,
    },
    InvalidColumn {
        matrix: FieldR1csArtifactMatrix,
        index: usize,
        actual: u32,
        num_cols: usize,
    },
    InvalidValueIndex {
        matrix: FieldR1csArtifactMatrix,
        index: usize,
        actual: u32,
        value_count: usize,
    },
    NonCanonicalValueCount {
        matrix: FieldR1csArtifactMatrix,
        values: u64,
        nnz: u64,
    },
    NonCanonicalValueIndexOrder {
        matrix: FieldR1csArtifactMatrix,
        index: usize,
        expected_next: usize,
        actual: u32,
    },
    UnusedCoefficient {
        matrix: FieldR1csArtifactMatrix,
        index: usize,
    },
    ZeroCoefficient {
        matrix: FieldR1csArtifactMatrix,
        index: usize,
    },
    DuplicateCoefficient {
        matrix: FieldR1csArtifactMatrix,
        first: usize,
        duplicate: usize,
    },
    StructuralDigestMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    BackingLengthMismatch {
        expected: u64,
        actual: u64,
    },
    BackingFileChanged,
    StreamingDictionaryTooLarge {
        matrix: FieldR1csArtifactMatrix,
        actual: u64,
        maximum: u64,
    },
    MatrixClaimShape(&'static str),
    MatrixEvaluatorAlreadyConsumed,
}

impl fmt::Display for FieldR1csArtifactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "FieldR1cs artifact I/O: {error}"),
            other => write!(f, "{other:?}"),
        }
    }
}

impl std::error::Error for FieldR1csArtifactError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for FieldR1csArtifactError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Copy, Debug)]
struct ArtifactMatrixCounts {
    rows: u64,
    cols: u64,
    nnz: u64,
    values: u64,
    offsets: u64,
}

impl ArtifactMatrixCounts {
    fn encoded_bytes(self) -> Result<u64, FieldR1csArtifactError> {
        self.offsets
            .checked_mul(8)
            .and_then(|bytes| self.nnz.checked_mul(8).and_then(|n| bytes.checked_add(n)))
            .and_then(|bytes| {
                self.values
                    .checked_mul(16)
                    .and_then(|n| bytes.checked_add(n))
            })
            .ok_or(FieldR1csArtifactError::LengthArithmetic)
    }
}

#[derive(Clone, Copy, Debug)]
struct ArtifactHeader {
    total_bytes: u64,
    m: u32,
    k_log: u32,
    k_skip: u32,
    useful_rows: u64,
    const_pin_plus_one: u64,
    matrices: [ArtifactMatrixCounts; 2],
}

/// Small canonical coefficient dictionary prepared for one matrix while its
/// existing CSR arrays stay in place. Builder-produced matrices may share a
/// superset dictionary between A and B; the artifact never persists that
/// non-canonical representation.
struct CanonicalArtifactDictionary {
    by_value: std::collections::HashMap<u128, u32>,
    values: Vec<F128>,
}

impl ArtifactHeader {
    fn computed_bytes(self) -> Result<u64, FieldR1csArtifactError> {
        self.matrices
            .iter()
            .try_fold(FIELD_R1CS_ARTIFACT_HEADER_BYTES as u64, |total, matrix| {
                total
                    .checked_add(matrix.encoded_bytes()?)
                    .ok_or(FieldR1csArtifactError::LengthArithmetic)
            })
    }
}

fn artifact_matrix_name(index: usize) -> FieldR1csArtifactMatrix {
    if index == 0 {
        FieldR1csArtifactMatrix::A
    } else {
        FieldR1csArtifactMatrix::B
    }
}

fn checked_u64(value: usize) -> Result<u64, FieldR1csArtifactError> {
    u64::try_from(value).map_err(|_| FieldR1csArtifactError::LengthArithmetic)
}

fn validate_artifact_shape(
    m: usize,
    k_log: usize,
    k_skip: usize,
    useful_rows: usize,
    const_pin: Option<usize>,
) -> Result<usize, FieldR1csArtifactError> {
    if k_skip > k_log {
        return Err(FieldR1csArtifactError::InvalidShape("k_skip > k_log"));
    }
    if k_log > m {
        return Err(FieldR1csArtifactError::InvalidShape("k_log > m"));
    }
    if m >= usize::BITS as usize {
        return Err(FieldR1csArtifactError::InvalidShape(
            "m is outside the usize power-of-two domain",
        ));
    }
    let k = 1usize
        .checked_shl(
            u32::try_from(k_log)
                .map_err(|_| FieldR1csArtifactError::InvalidShape("k_log is too large"))?,
        )
        .ok_or(FieldR1csArtifactError::InvalidShape(
            "k_log is outside the usize power-of-two domain",
        ))?;
    if useful_rows > k {
        return Err(FieldR1csArtifactError::InvalidShape("useful_rows > k"));
    }
    if const_pin.is_some_and(|column| column >= k) {
        return Err(FieldR1csArtifactError::InvalidShape(
            "const_pin is outside the base matrix",
        ));
    }
    Ok(k)
}

fn validate_sparse_artifact_matrix(
    matrix: &SparseFieldMatrix,
    side: FieldR1csArtifactMatrix,
    k: usize,
) -> Result<(ArtifactMatrixCounts, CanonicalArtifactDictionary), FieldR1csArtifactError> {
    let expected = checked_u64(k)?;
    if matrix.num_rows != k || matrix.num_cols != k {
        return Err(FieldR1csArtifactError::MatrixDimensions {
            matrix: side,
            expected,
            rows: checked_u64(matrix.num_rows)?,
            cols: checked_u64(matrix.num_cols)?,
        });
    }
    let nnz = matrix.col_indices.len();
    if matrix.value_indices.len() != nnz {
        return Err(FieldR1csArtifactError::MatrixLengthMismatch {
            matrix: side,
            field: "value_indices",
            expected: checked_u64(nnz)?,
            actual: checked_u64(matrix.value_indices.len())?,
        });
    }
    let expected_offsets = k
        .checked_add(1)
        .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
    if matrix.row_offsets.len() != expected_offsets {
        return Err(FieldR1csArtifactError::MatrixLengthMismatch {
            matrix: side,
            field: "row_offsets",
            expected: checked_u64(expected_offsets)?,
            actual: checked_u64(matrix.row_offsets.len())?,
        });
    }
    if checked_u64(nnz)? > u32::MAX as u64 {
        return Err(FieldR1csArtifactError::CountOutOfRange {
            matrix: side,
            field: "nnz",
            actual: checked_u64(nnz)?,
            maximum: u32::MAX as u64,
        });
    }
    if checked_u64(matrix.value_table.len())? > u32::MAX as u64 {
        return Err(FieldR1csArtifactError::CountOutOfRange {
            matrix: side,
            field: "values",
            actual: checked_u64(matrix.value_table.len())?,
            maximum: u32::MAX as u64,
        });
    }

    let mut previous = 0usize;
    for (index, &actual) in matrix.row_offsets.iter().enumerate() {
        if (index == 0 && actual != 0) || actual < previous || actual > nnz {
            return Err(FieldR1csArtifactError::InvalidRowOffset {
                matrix: side,
                index,
                previous,
                actual: checked_u64(actual)?,
                nnz,
            });
        }
        previous = actual;
    }
    if previous != nnz {
        return Err(FieldR1csArtifactError::InvalidRowOffset {
            matrix: side,
            index: matrix.row_offsets.len() - 1,
            previous,
            actual: checked_u64(previous)?,
            nnz,
        });
    }
    for (index, &column) in matrix.col_indices.iter().enumerate() {
        if column as usize >= matrix.num_cols {
            return Err(FieldR1csArtifactError::InvalidColumn {
                matrix: side,
                index,
                actual: column,
                num_cols: matrix.num_cols,
            });
        }
    }
    for (index, &value_index) in matrix.value_indices.iter().enumerate() {
        if value_index as usize >= matrix.value_table.len() {
            return Err(FieldR1csArtifactError::InvalidValueIndex {
                matrix: side,
                index,
                actual: value_index,
                value_count: matrix.value_table.len(),
            });
        }
    }
    for (index, &value) in matrix.value_table.iter().enumerate() {
        if value == F128::ZERO {
            return Err(FieldR1csArtifactError::ZeroCoefficient {
                matrix: side,
                index,
            });
        }
    }

    // Re-intern by decoded coefficient in first-use order. This is bounded by
    // the small protocol coefficient alphabet and does not copy either CSR
    // index array.
    let mut dictionary = CanonicalArtifactDictionary {
        by_value: std::collections::HashMap::new(),
        values: Vec::new(),
    };
    for &source_index in &matrix.value_indices {
        let value = matrix.value_table[source_index as usize];
        let key = ((value.hi as u128) << 64) | value.lo as u128;
        if !dictionary.by_value.contains_key(&key) {
            dictionary
                .by_value
                .try_reserve(1)
                .map_err(|_| FieldR1csArtifactError::Allocation {
                    matrix: side,
                    field: "canonical coefficient map",
                })?;
            dictionary
                .values
                .try_reserve(1)
                .map_err(|_| FieldR1csArtifactError::Allocation {
                    matrix: side,
                    field: "canonical coefficient table",
                })?;
            let actual = checked_u64(dictionary.values.len())?;
            let canonical_index = u32::try_from(dictionary.values.len()).map_err(|_| {
                FieldR1csArtifactError::CountOutOfRange {
                    matrix: side,
                    field: "canonical values",
                    actual,
                    maximum: u32::MAX as u64,
                }
            })?;
            dictionary.by_value.insert(key, canonical_index);
            dictionary.values.push(value);
        }
    }

    Ok((
        ArtifactMatrixCounts {
            rows: expected,
            cols: expected,
            nnz: checked_u64(nnz)?,
            values: checked_u64(dictionary.values.len())?,
            offsets: checked_u64(expected_offsets)?,
        },
        dictionary,
    ))
}

fn validate_unique_nonzero_coefficients(
    value_table: &[F128],
    matrix: FieldR1csArtifactMatrix,
) -> Result<(), FieldR1csArtifactError> {
    // A u32 permutation costs 4 bytes per 16-byte coefficient, substantially
    // less peak memory than a HashSet while preserving O(v log v) rejection
    // for a maliciously large declared dictionary.
    let mut order = Vec::new();
    order
        .try_reserve_exact(value_table.len())
        .map_err(|_| FieldR1csArtifactError::Allocation {
            matrix,
            field: "coefficient uniqueness order",
        })?;
    for (index, &value) in value_table.iter().enumerate() {
        if value == F128::ZERO {
            return Err(FieldR1csArtifactError::ZeroCoefficient { matrix, index });
        }
        order.push(
            u32::try_from(index).map_err(|_| FieldR1csArtifactError::CountOutOfRange {
                matrix,
                field: "values",
                actual: index as u64,
                maximum: u32::MAX as u64,
            })?,
        );
    }
    order.sort_unstable_by_key(|&index| {
        let value = value_table[index as usize];
        ((value.hi as u128) << 64) | value.lo as u128
    });
    for pair in order.windows(2) {
        let first = pair[0] as usize;
        let duplicate = pair[1] as usize;
        if value_table[first] == value_table[duplicate] {
            return Err(FieldR1csArtifactError::DuplicateCoefficient {
                matrix,
                first,
                duplicate,
            });
        }
    }
    Ok(())
}

fn write_u32_slice<W: Write + ?Sized>(
    writer: &mut W,
    values: &[u32],
) -> Result<(), FieldR1csArtifactError> {
    let mut scratch = [0u8; FIELD_R1CS_ARTIFACT_IO_CHUNK_BYTES];
    for chunk in values.chunks(FIELD_R1CS_ARTIFACT_IO_CHUNK_BYTES / 4) {
        for (bytes, value) in scratch.chunks_exact_mut(4).zip(chunk) {
            bytes.copy_from_slice(&value.to_le_bytes());
        }
        writer.write_all(&scratch[..chunk.len() * 4])?;
    }
    Ok(())
}

fn write_canonical_value_indices<W: Write + ?Sized>(
    writer: &mut W,
    matrix: &SparseFieldMatrix,
    dictionary: &CanonicalArtifactDictionary,
) -> Result<(), FieldR1csArtifactError> {
    let mut scratch = [0u8; FIELD_R1CS_ARTIFACT_IO_CHUNK_BYTES];
    for chunk in matrix
        .value_indices
        .chunks(FIELD_R1CS_ARTIFACT_IO_CHUNK_BYTES / 4)
    {
        for (bytes, &source_index) in scratch.chunks_exact_mut(4).zip(chunk) {
            let value = matrix.value_table[source_index as usize];
            let key = ((value.hi as u128) << 64) | value.lo as u128;
            let canonical_index = dictionary
                .by_value
                .get(&key)
                .copied()
                .expect("validated coefficient was installed in canonical dictionary");
            bytes.copy_from_slice(&canonical_index.to_le_bytes());
        }
        writer.write_all(&scratch[..chunk.len() * 4])?;
    }
    Ok(())
}

fn write_usize_as_u64_slice<W: Write + ?Sized>(
    writer: &mut W,
    values: &[usize],
) -> Result<(), FieldR1csArtifactError> {
    let mut scratch = [0u8; FIELD_R1CS_ARTIFACT_IO_CHUNK_BYTES];
    for chunk in values.chunks(FIELD_R1CS_ARTIFACT_IO_CHUNK_BYTES / 8) {
        for (bytes, &value) in scratch.chunks_exact_mut(8).zip(chunk) {
            bytes.copy_from_slice(&checked_u64(value)?.to_le_bytes());
        }
        writer.write_all(&scratch[..chunk.len() * 8])?;
    }
    Ok(())
}

fn write_f128_slice<W: Write + ?Sized>(
    writer: &mut W,
    values: &[F128],
) -> Result<(), FieldR1csArtifactError> {
    let mut scratch = [0u8; FIELD_R1CS_ARTIFACT_IO_CHUNK_BYTES];
    for chunk in values.chunks(FIELD_R1CS_ARTIFACT_IO_CHUNK_BYTES / 16) {
        for (bytes, value) in scratch.chunks_exact_mut(16).zip(chunk) {
            bytes[..8].copy_from_slice(&value.lo.to_le_bytes());
            bytes[8..].copy_from_slice(&value.hi.to_le_bytes());
        }
        writer.write_all(&scratch[..chunk.len() * 16])?;
    }
    Ok(())
}

fn read_exact_artifact<R: Read + ?Sized>(
    reader: &mut R,
    bytes: &mut [u8],
    offset: &mut u64,
) -> Result<(), FieldR1csArtifactError> {
    match reader.read_exact(bytes) {
        Ok(()) => {
            *offset = offset
                .checked_add(bytes.len() as u64)
                .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            Err(FieldR1csArtifactError::Truncated {
                offset: *offset,
                needed: bytes.len(),
            })
        }
        Err(error) => Err(FieldR1csArtifactError::Io(error)),
    }
}

fn reserve_artifact_vec<T>(
    length: usize,
    matrix: FieldR1csArtifactMatrix,
    field: &'static str,
) -> Result<Vec<T>, FieldR1csArtifactError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(length)
        .map_err(|_| FieldR1csArtifactError::Allocation { matrix, field })?;
    Ok(values)
}

fn read_u32_vec<R: Read + ?Sized, F>(
    reader: &mut R,
    offset: &mut u64,
    length: usize,
    matrix: FieldR1csArtifactMatrix,
    field: &'static str,
    mut validate: F,
) -> Result<Vec<u32>, FieldR1csArtifactError>
where
    F: FnMut(usize, u32) -> Result<(), FieldR1csArtifactError>,
{
    let mut values = reserve_artifact_vec(length, matrix, field)?;
    let mut scratch = [0u8; FIELD_R1CS_ARTIFACT_IO_CHUNK_BYTES];
    while values.len() < length {
        let count = (length - values.len()).min(FIELD_R1CS_ARTIFACT_IO_CHUNK_BYTES / 4);
        read_exact_artifact(reader, &mut scratch[..count * 4], offset)?;
        for bytes in scratch[..count * 4].chunks_exact(4) {
            let value = u32::from_le_bytes(bytes.try_into().expect("four-byte chunk"));
            validate(values.len(), value)?;
            values.push(value);
        }
    }
    Ok(values)
}

fn read_row_offsets<R: Read + ?Sized>(
    reader: &mut R,
    offset: &mut u64,
    length: usize,
    nnz: usize,
    matrix: FieldR1csArtifactMatrix,
) -> Result<Vec<usize>, FieldR1csArtifactError> {
    let mut values = reserve_artifact_vec(length, matrix, "row_offsets")?;
    let mut scratch = [0u8; FIELD_R1CS_ARTIFACT_IO_CHUNK_BYTES];
    while values.len() < length {
        let count = (length - values.len()).min(FIELD_R1CS_ARTIFACT_IO_CHUNK_BYTES / 8);
        read_exact_artifact(reader, &mut scratch[..count * 8], offset)?;
        for bytes in scratch[..count * 8].chunks_exact(8) {
            let raw = u64::from_le_bytes(bytes.try_into().expect("eight-byte chunk"));
            let index = values.len();
            let previous = values.last().copied().unwrap_or(0);
            let value =
                usize::try_from(raw).map_err(|_| FieldR1csArtifactError::InvalidRowOffset {
                    matrix,
                    index,
                    previous,
                    actual: raw,
                    nnz,
                })?;
            if (index == 0 && value != 0) || value < previous || value > nnz {
                return Err(FieldR1csArtifactError::InvalidRowOffset {
                    matrix,
                    index,
                    previous,
                    actual: raw,
                    nnz,
                });
            }
            values.push(value);
        }
    }
    let final_offset = values.last().copied().unwrap_or(usize::MAX);
    if final_offset != nnz {
        return Err(FieldR1csArtifactError::InvalidRowOffset {
            matrix,
            index: length.saturating_sub(1),
            previous: final_offset,
            actual: final_offset as u64,
            nnz,
        });
    }
    Ok(values)
}

fn read_f128_vec<R: Read + ?Sized>(
    reader: &mut R,
    offset: &mut u64,
    length: usize,
    matrix: FieldR1csArtifactMatrix,
) -> Result<Vec<F128>, FieldR1csArtifactError> {
    let mut values = reserve_artifact_vec(length, matrix, "value_table")?;
    let mut scratch = [0u8; FIELD_R1CS_ARTIFACT_IO_CHUNK_BYTES];
    while values.len() < length {
        let count = (length - values.len()).min(FIELD_R1CS_ARTIFACT_IO_CHUNK_BYTES / 16);
        read_exact_artifact(reader, &mut scratch[..count * 16], offset)?;
        for bytes in scratch[..count * 16].chunks_exact(16) {
            let value = F128 {
                lo: u64::from_le_bytes(bytes[..8].try_into().expect("low limb")),
                hi: u64::from_le_bytes(bytes[8..].try_into().expect("high limb")),
            };
            if value == F128::ZERO {
                return Err(FieldR1csArtifactError::ZeroCoefficient {
                    matrix,
                    index: values.len(),
                });
            }
            values.push(value);
        }
    }
    Ok(values)
}

fn push_header_u16(
    header: &mut [u8; FIELD_R1CS_ARTIFACT_HEADER_BYTES],
    at: &mut usize,
    value: u16,
) {
    header[*at..*at + 2].copy_from_slice(&value.to_le_bytes());
    *at += 2;
}

fn push_header_u32(
    header: &mut [u8; FIELD_R1CS_ARTIFACT_HEADER_BYTES],
    at: &mut usize,
    value: u32,
) {
    header[*at..*at + 4].copy_from_slice(&value.to_le_bytes());
    *at += 4;
}

fn push_header_u64(
    header: &mut [u8; FIELD_R1CS_ARTIFACT_HEADER_BYTES],
    at: &mut usize,
    value: u64,
) {
    header[*at..*at + 8].copy_from_slice(&value.to_le_bytes());
    *at += 8;
}

fn take_header_u16(header: &[u8; FIELD_R1CS_ARTIFACT_HEADER_BYTES], at: &mut usize) -> u16 {
    let value = u16::from_le_bytes(header[*at..*at + 2].try_into().expect("header u16"));
    *at += 2;
    value
}

fn take_header_u32(header: &[u8; FIELD_R1CS_ARTIFACT_HEADER_BYTES], at: &mut usize) -> u32 {
    let value = u32::from_le_bytes(header[*at..*at + 4].try_into().expect("header u32"));
    *at += 4;
    value
}

fn take_header_u64(header: &[u8; FIELD_R1CS_ARTIFACT_HEADER_BYTES], at: &mut usize) -> u64 {
    let value = u64::from_le_bytes(header[*at..*at + 8].try_into().expect("header u64"));
    *at += 8;
    value
}

impl FieldR1cs {
    /// Stream this canonical matrix artifact to `writer` without constructing
    /// a second serialized matrix in memory.
    ///
    /// The writer is expected to be buffered by the caller when it is a raw
    /// file. This method itself uses only one fixed 64-KiB conversion buffer.
    pub fn write_artifact<W: Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<(), FieldR1csArtifactError> {
        let k = validate_artifact_shape(
            self.m,
            self.k_log,
            self.k_skip,
            self.useful_rows,
            self.const_pin,
        )?;
        let (a_counts, a_dictionary) =
            validate_sparse_artifact_matrix(&self.a_0, FieldR1csArtifactMatrix::A, k)?;
        let (b_counts, b_dictionary) =
            validate_sparse_artifact_matrix(&self.b_0, FieldR1csArtifactMatrix::B, k)?;
        let matrices = [a_counts, b_counts];
        let m = u32::try_from(self.m)
            .map_err(|_| FieldR1csArtifactError::InvalidShape("m does not fit u32"))?;
        let k_log = u32::try_from(self.k_log)
            .map_err(|_| FieldR1csArtifactError::InvalidShape("k_log does not fit u32"))?;
        let k_skip = u32::try_from(self.k_skip)
            .map_err(|_| FieldR1csArtifactError::InvalidShape("k_skip does not fit u32"))?;
        let const_pin_plus_one = match self.const_pin {
            None => 0,
            Some(column) => checked_u64(
                column
                    .checked_add(1)
                    .ok_or(FieldR1csArtifactError::LengthArithmetic)?,
            )?,
        };
        let mut artifact = ArtifactHeader {
            total_bytes: 0,
            m,
            k_log,
            k_skip,
            useful_rows: checked_u64(self.useful_rows)?,
            const_pin_plus_one,
            matrices,
        };
        artifact.total_bytes = artifact.computed_bytes()?;

        let mut header = [0u8; FIELD_R1CS_ARTIFACT_HEADER_BYTES];
        header[..FIELD_R1CS_ARTIFACT_MAGIC.len()].copy_from_slice(&FIELD_R1CS_ARTIFACT_MAGIC);
        let mut at = FIELD_R1CS_ARTIFACT_MAGIC.len();
        push_header_u16(&mut header, &mut at, FIELD_R1CS_ARTIFACT_VERSION);
        push_header_u16(
            &mut header,
            &mut at,
            FIELD_R1CS_ARTIFACT_HEADER_BYTES as u16,
        );
        push_header_u64(&mut header, &mut at, artifact.total_bytes);
        push_header_u32(&mut header, &mut at, artifact.m);
        push_header_u32(&mut header, &mut at, artifact.k_log);
        push_header_u32(&mut header, &mut at, artifact.k_skip);
        push_header_u64(&mut header, &mut at, artifact.useful_rows);
        push_header_u64(&mut header, &mut at, artifact.const_pin_plus_one);
        for matrix in artifact.matrices {
            push_header_u64(&mut header, &mut at, matrix.rows);
            push_header_u64(&mut header, &mut at, matrix.cols);
            push_header_u64(&mut header, &mut at, matrix.nnz);
            push_header_u64(&mut header, &mut at, matrix.values);
            push_header_u64(&mut header, &mut at, matrix.offsets);
        }
        debug_assert_eq!(at, FIELD_R1CS_ARTIFACT_HEADER_BYTES);
        writer.write_all(&header)?;

        for (matrix, dictionary) in [(&self.a_0, &a_dictionary), (&self.b_0, &b_dictionary)] {
            write_usize_as_u64_slice(writer, &matrix.row_offsets)?;
            write_u32_slice(writer, &matrix.col_indices)?;
            write_canonical_value_indices(writer, matrix, dictionary)?;
            write_f128_slice(writer, &dictionary.values)?;
        }
        Ok(())
    }

    /// Load one canonical matrix artifact under local shape and structural
    /// digest authority.
    ///
    /// Both descriptors and the complete byte arithmetic are checked against
    /// `max_bytes` before the first matrix vector is allocated. The returned
    /// object has empty digest and CSC caches; in particular the externally
    /// supplied digest is never installed into the seedable digest cache.
    pub fn read_artifact<R: Read + ?Sized>(
        reader: &mut R,
        expected_shape: crate::proof::FieldShape,
        expected_structural_digest: [u8; 32],
        max_bytes: usize,
    ) -> Result<Self, FieldR1csArtifactError> {
        if max_bytes < FIELD_R1CS_ARTIFACT_HEADER_BYTES {
            return Err(FieldR1csArtifactError::TooLarge {
                actual: FIELD_R1CS_ARTIFACT_HEADER_BYTES as u64,
                max: max_bytes,
            });
        }
        let expected_k = validate_artifact_shape(
            expected_shape.m,
            expected_shape.k_log,
            expected_shape.k_skip,
            0,
            expected_shape.const_pin,
        )?;
        let expected_k_u64 = checked_u64(expected_k)?;

        let mut offset = 0u64;
        let mut header_bytes = [0u8; FIELD_R1CS_ARTIFACT_HEADER_BYTES];
        read_exact_artifact(reader, &mut header_bytes, &mut offset)?;
        if header_bytes[..FIELD_R1CS_ARTIFACT_MAGIC.len()] != FIELD_R1CS_ARTIFACT_MAGIC {
            return Err(FieldR1csArtifactError::InvalidMagic);
        }
        let mut at = FIELD_R1CS_ARTIFACT_MAGIC.len();
        let version = take_header_u16(&header_bytes, &mut at);
        if version != FIELD_R1CS_ARTIFACT_VERSION {
            return Err(FieldR1csArtifactError::UnsupportedVersion { actual: version });
        }
        let header_length = take_header_u16(&header_bytes, &mut at);
        if header_length as usize != FIELD_R1CS_ARTIFACT_HEADER_BYTES {
            return Err(FieldR1csArtifactError::InvalidHeaderLength {
                actual: header_length,
            });
        }
        let total_bytes = take_header_u64(&header_bytes, &mut at);
        let m = take_header_u32(&header_bytes, &mut at);
        let k_log = take_header_u32(&header_bytes, &mut at);
        let k_skip = take_header_u32(&header_bytes, &mut at);
        let useful_rows = take_header_u64(&header_bytes, &mut at);
        let const_pin_plus_one = take_header_u64(&header_bytes, &mut at);
        let mut matrices = [ArtifactMatrixCounts {
            rows: 0,
            cols: 0,
            nnz: 0,
            values: 0,
            offsets: 0,
        }; 2];
        for matrix in &mut matrices {
            matrix.rows = take_header_u64(&header_bytes, &mut at);
            matrix.cols = take_header_u64(&header_bytes, &mut at);
            matrix.nnz = take_header_u64(&header_bytes, &mut at);
            matrix.values = take_header_u64(&header_bytes, &mut at);
            matrix.offsets = take_header_u64(&header_bytes, &mut at);
        }
        debug_assert_eq!(at, FIELD_R1CS_ARTIFACT_HEADER_BYTES);
        let artifact = ArtifactHeader {
            total_bytes,
            m,
            k_log,
            k_skip,
            useful_rows,
            const_pin_plus_one,
            matrices,
        };

        let compare_shape = |field: &'static str,
                             expected: usize,
                             actual: u64|
         -> Result<(), FieldR1csArtifactError> {
            let expected = checked_u64(expected)?;
            if actual != expected {
                return Err(FieldR1csArtifactError::ShapeMismatch {
                    field,
                    expected,
                    actual,
                });
            }
            Ok(())
        };
        compare_shape("m", expected_shape.m, u64::from(artifact.m))?;
        compare_shape("k_log", expected_shape.k_log, u64::from(artifact.k_log))?;
        compare_shape("k_skip", expected_shape.k_skip, u64::from(artifact.k_skip))?;
        let expected_pin_plus_one = match expected_shape.const_pin {
            None => 0,
            Some(column) => checked_u64(
                column
                    .checked_add(1)
                    .ok_or(FieldR1csArtifactError::LengthArithmetic)?,
            )?,
        };
        if artifact.const_pin_plus_one != expected_pin_plus_one {
            return Err(FieldR1csArtifactError::ShapeMismatch {
                field: "const_pin",
                expected: expected_pin_plus_one,
                actual: artifact.const_pin_plus_one,
            });
        }
        let useful_rows = usize::try_from(artifact.useful_rows)
            .map_err(|_| FieldR1csArtifactError::InvalidShape("useful_rows does not fit usize"))?;
        validate_artifact_shape(
            expected_shape.m,
            expected_shape.k_log,
            expected_shape.k_skip,
            useful_rows,
            expected_shape.const_pin,
        )?;

        let expected_offsets = expected_k_u64
            .checked_add(1)
            .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
        for (index, matrix) in artifact.matrices.iter().copied().enumerate() {
            let side = artifact_matrix_name(index);
            if matrix.rows != expected_k_u64 || matrix.cols != expected_k_u64 {
                return Err(FieldR1csArtifactError::MatrixDimensions {
                    matrix: side,
                    expected: expected_k_u64,
                    rows: matrix.rows,
                    cols: matrix.cols,
                });
            }
            if matrix.offsets != expected_offsets {
                return Err(FieldR1csArtifactError::MatrixLengthMismatch {
                    matrix: side,
                    field: "row_offsets",
                    expected: expected_offsets,
                    actual: matrix.offsets,
                });
            }
            for (field, count) in [("nnz", matrix.nnz), ("values", matrix.values)] {
                if count > u32::MAX as u64 {
                    return Err(FieldR1csArtifactError::CountOutOfRange {
                        matrix: side,
                        field,
                        actual: count,
                        maximum: u32::MAX as u64,
                    });
                }
            }
            if matrix.values > matrix.nnz || (matrix.nnz != 0 && matrix.values == 0) {
                return Err(FieldR1csArtifactError::NonCanonicalValueCount {
                    matrix: side,
                    values: matrix.values,
                    nnz: matrix.nnz,
                });
            }
        }

        let computed_bytes = artifact.computed_bytes()?;
        if artifact.total_bytes != computed_bytes {
            return Err(FieldR1csArtifactError::TotalLengthMismatch {
                declared: artifact.total_bytes,
                computed: computed_bytes,
            });
        }
        let max_u64 = u64::try_from(max_bytes).unwrap_or(u64::MAX);
        if computed_bytes > max_u64 {
            return Err(FieldR1csArtifactError::TooLarge {
                actual: computed_bytes,
                max: max_bytes,
            });
        }

        let mut decoded = Vec::with_capacity(2);
        for (index, counts) in artifact.matrices.iter().copied().enumerate() {
            let side = artifact_matrix_name(index);
            let nnz = usize::try_from(counts.nnz)
                .map_err(|_| FieldR1csArtifactError::LengthArithmetic)?;
            let value_count = usize::try_from(counts.values)
                .map_err(|_| FieldR1csArtifactError::LengthArithmetic)?;
            let offset_count = usize::try_from(counts.offsets)
                .map_err(|_| FieldR1csArtifactError::LengthArithmetic)?;
            let row_offsets = read_row_offsets(reader, &mut offset, offset_count, nnz, side)?;
            let col_indices = read_u32_vec(
                reader,
                &mut offset,
                nnz,
                side,
                "col_indices",
                |entry, column| {
                    if column as usize >= expected_k {
                        return Err(FieldR1csArtifactError::InvalidColumn {
                            matrix: side,
                            index: entry,
                            actual: column,
                            num_cols: expected_k,
                        });
                    }
                    Ok(())
                },
            )?;
            let mut next_value_index = 0usize;
            let value_indices = read_u32_vec(
                reader,
                &mut offset,
                nnz,
                side,
                "value_indices",
                |entry, value_index| {
                    if value_index as usize >= value_count {
                        return Err(FieldR1csArtifactError::InvalidValueIndex {
                            matrix: side,
                            index: entry,
                            actual: value_index,
                            value_count,
                        });
                    }
                    let actual = value_index as usize;
                    if actual > next_value_index {
                        return Err(FieldR1csArtifactError::NonCanonicalValueIndexOrder {
                            matrix: side,
                            index: entry,
                            expected_next: next_value_index,
                            actual: value_index,
                        });
                    }
                    if actual == next_value_index {
                        next_value_index += 1;
                    }
                    Ok(())
                },
            )?;
            if next_value_index != value_count {
                return Err(FieldR1csArtifactError::UnusedCoefficient {
                    matrix: side,
                    index: next_value_index,
                });
            }
            let value_table = read_f128_vec(reader, &mut offset, value_count, side)?;
            validate_unique_nonzero_coefficients(&value_table, side)?;
            decoded.push(SparseFieldMatrix {
                num_rows: expected_k,
                num_cols: expected_k,
                col_indices,
                value_indices,
                value_table,
                row_offsets,
            });
        }
        debug_assert_eq!(offset, computed_bytes);

        let mut trailing = [0u8; 1];
        loop {
            match reader.read(&mut trailing) {
                Ok(0) => break,
                Ok(_) => return Err(FieldR1csArtifactError::TrailingBytes),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(FieldR1csArtifactError::Io(error)),
            }
        }

        let b_0 = decoded.pop().expect("two matrices decoded");
        let a_0 = decoded.pop().expect("two matrices decoded");
        let r1cs = Self {
            m: expected_shape.m,
            k_log: expected_shape.k_log,
            k_skip: expected_shape.k_skip,
            useful_rows,
            a_0,
            b_0,
            const_pin: expected_shape.const_pin,
            digest_cache: std::sync::OnceLock::new(),
            csc_cache: std::sync::OnceLock::new(),
        };
        let actual_digest = r1cs.structural_statement_digest();
        if actual_digest != expected_structural_digest {
            return Err(FieldR1csArtifactError::StructuralDigestMismatch {
                expected: expected_structural_digest,
                actual: actual_digest,
            });
        }
        Ok(r1cs)
    }

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

// ---------------------------------------------------------------------------
// Bounded-memory seekable artifact evaluator
// ---------------------------------------------------------------------------

/// Maximum coefficient dictionary retained by the streaming verifier for one
/// base matrix. Production verifier circuits use only a few hundred distinct
/// constants; this protocol-policy cap keeps a hostile but otherwise valid
/// artifact from turning its dictionary into a second multi-gigabyte matrix.
pub const STREAMING_FIELD_R1CS_MAX_DICTIONARY_VALUES: usize = 1 << 16;

const STREAMING_FIELD_R1CS_ENTRY_CHUNK: usize = 64 * 1024;

#[derive(Clone, Copy, Debug)]
struct SeekableArtifactMatrixLayout {
    side: FieldR1csArtifactMatrix,
    counts: ArtifactMatrixCounts,
    row_offsets_at: u64,
    columns_at: u64,
    value_indices_at: u64,
    values_at: u64,
}

/// A canonical `FieldR1cs` artifact that remains on a seekable backing store.
///
/// Construction performs a complete canonical scan and authenticates the
/// structural statement digest without allocating CSR arrays. Every later
/// claim evaluation scans and authenticates the exact rows again, protecting
/// callers against same-length mutation after preflight. Retained memory is
/// bounded by two 256-KiB entry buffers, one 2049-entry offset window, the
/// factorized equality tables, and one capped coefficient dictionary.
pub struct SeekableFieldR1csArtifact<R> {
    reader: R,
    shape: crate::proof::FieldShape,
    useful_rows: usize,
    total_bytes: u64,
    header_bytes: [u8; FIELD_R1CS_ARTIFACT_HEADER_BYTES],
    layouts: [SeekableArtifactMatrixLayout; 2],
    expected_structural_digest: [u8; 32],
}

impl<R: Read + Seek> SeekableFieldR1csArtifact<R> {
    /// Open, preflight, fully validate, and structurally authenticate a
    /// canonical artifact without materializing either sparse matrix.
    pub fn open(
        reader: R,
        expected_shape: crate::proof::FieldShape,
        expected_structural_digest: [u8; 32],
        max_bytes: u64,
    ) -> Result<Self, FieldR1csArtifactError> {
        let mut artifact = Self::preflight_header(
            reader,
            expected_shape,
            expected_structural_digest,
            max_bytes,
        )?;
        artifact.scan_authenticated(None, None)?;
        Ok(artifact)
    }

    fn preflight_header(
        mut reader: R,
        expected_shape: crate::proof::FieldShape,
        expected_structural_digest: [u8; 32],
        max_bytes: u64,
    ) -> Result<Self, FieldR1csArtifactError> {
        let actual_bytes = reader.seek(SeekFrom::End(0))?;
        if actual_bytes > max_bytes {
            return Err(FieldR1csArtifactError::TooLarge {
                actual: actual_bytes,
                max: usize::try_from(max_bytes).unwrap_or(usize::MAX),
            });
        }
        if actual_bytes < FIELD_R1CS_ARTIFACT_HEADER_BYTES as u64 {
            return Err(FieldR1csArtifactError::Truncated {
                offset: actual_bytes,
                needed: FIELD_R1CS_ARTIFACT_HEADER_BYTES,
            });
        }

        reader.seek(SeekFrom::Start(0))?;
        let mut offset = 0u64;
        let mut header_bytes = [0u8; FIELD_R1CS_ARTIFACT_HEADER_BYTES];
        read_exact_artifact(&mut reader, &mut header_bytes, &mut offset)?;
        if header_bytes[..FIELD_R1CS_ARTIFACT_MAGIC.len()] != FIELD_R1CS_ARTIFACT_MAGIC {
            return Err(FieldR1csArtifactError::InvalidMagic);
        }
        let mut at = FIELD_R1CS_ARTIFACT_MAGIC.len();
        let version = take_header_u16(&header_bytes, &mut at);
        if version != FIELD_R1CS_ARTIFACT_VERSION {
            return Err(FieldR1csArtifactError::UnsupportedVersion { actual: version });
        }
        let header_length = take_header_u16(&header_bytes, &mut at);
        if header_length as usize != FIELD_R1CS_ARTIFACT_HEADER_BYTES {
            return Err(FieldR1csArtifactError::InvalidHeaderLength {
                actual: header_length,
            });
        }
        let total_bytes = take_header_u64(&header_bytes, &mut at);
        let m = take_header_u32(&header_bytes, &mut at);
        let k_log = take_header_u32(&header_bytes, &mut at);
        let k_skip = take_header_u32(&header_bytes, &mut at);
        let useful_rows_raw = take_header_u64(&header_bytes, &mut at);
        let const_pin_plus_one = take_header_u64(&header_bytes, &mut at);
        let mut matrices = [ArtifactMatrixCounts {
            rows: 0,
            cols: 0,
            nnz: 0,
            values: 0,
            offsets: 0,
        }; 2];
        for matrix in &mut matrices {
            matrix.rows = take_header_u64(&header_bytes, &mut at);
            matrix.cols = take_header_u64(&header_bytes, &mut at);
            matrix.nnz = take_header_u64(&header_bytes, &mut at);
            matrix.values = take_header_u64(&header_bytes, &mut at);
            matrix.offsets = take_header_u64(&header_bytes, &mut at);
        }
        debug_assert_eq!(at, FIELD_R1CS_ARTIFACT_HEADER_BYTES);

        let expected_k = validate_artifact_shape(
            expected_shape.m,
            expected_shape.k_log,
            expected_shape.k_skip,
            0,
            expected_shape.const_pin,
        )?;
        let expected_k_u64 = checked_u64(expected_k)?;
        for (field, expected, actual) in [
            ("m", expected_shape.m as u64, u64::from(m)),
            ("k_log", expected_shape.k_log as u64, u64::from(k_log)),
            ("k_skip", expected_shape.k_skip as u64, u64::from(k_skip)),
        ] {
            if expected != actual {
                return Err(FieldR1csArtifactError::ShapeMismatch {
                    field,
                    expected,
                    actual,
                });
            }
        }
        let expected_pin_plus_one = expected_shape
            .const_pin
            .map(|column| (column as u64) + 1)
            .unwrap_or(0);
        if const_pin_plus_one != expected_pin_plus_one {
            return Err(FieldR1csArtifactError::ShapeMismatch {
                field: "const_pin",
                expected: expected_pin_plus_one,
                actual: const_pin_plus_one,
            });
        }
        let useful_rows = usize::try_from(useful_rows_raw)
            .map_err(|_| FieldR1csArtifactError::InvalidShape("useful_rows does not fit usize"))?;
        validate_artifact_shape(
            expected_shape.m,
            expected_shape.k_log,
            expected_shape.k_skip,
            useful_rows,
            expected_shape.const_pin,
        )?;

        let expected_offsets = expected_k_u64
            .checked_add(1)
            .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
        for (index, counts) in matrices.iter().copied().enumerate() {
            let side = artifact_matrix_name(index);
            if counts.rows != expected_k_u64 || counts.cols != expected_k_u64 {
                return Err(FieldR1csArtifactError::MatrixDimensions {
                    matrix: side,
                    expected: expected_k_u64,
                    rows: counts.rows,
                    cols: counts.cols,
                });
            }
            if counts.offsets != expected_offsets {
                return Err(FieldR1csArtifactError::MatrixLengthMismatch {
                    matrix: side,
                    field: "row_offsets",
                    expected: expected_offsets,
                    actual: counts.offsets,
                });
            }
            if counts.nnz > u32::MAX as u64 {
                return Err(FieldR1csArtifactError::CountOutOfRange {
                    matrix: side,
                    field: "nnz",
                    actual: counts.nnz,
                    maximum: u32::MAX as u64,
                });
            }
            if counts.values > u32::MAX as u64 {
                return Err(FieldR1csArtifactError::CountOutOfRange {
                    matrix: side,
                    field: "values",
                    actual: counts.values,
                    maximum: u32::MAX as u64,
                });
            }
            if counts.values > counts.nnz || (counts.nnz != 0 && counts.values == 0) {
                return Err(FieldR1csArtifactError::NonCanonicalValueCount {
                    matrix: side,
                    values: counts.values,
                    nnz: counts.nnz,
                });
            }
            if counts.values > STREAMING_FIELD_R1CS_MAX_DICTIONARY_VALUES as u64 {
                return Err(FieldR1csArtifactError::StreamingDictionaryTooLarge {
                    matrix: side,
                    actual: counts.values,
                    maximum: STREAMING_FIELD_R1CS_MAX_DICTIONARY_VALUES as u64,
                });
            }
        }

        let artifact = ArtifactHeader {
            total_bytes,
            m,
            k_log,
            k_skip,
            useful_rows: useful_rows_raw,
            const_pin_plus_one,
            matrices,
        };
        let computed_bytes = artifact.computed_bytes()?;
        if total_bytes != computed_bytes {
            return Err(FieldR1csArtifactError::TotalLengthMismatch {
                declared: total_bytes,
                computed: computed_bytes,
            });
        }
        if actual_bytes != total_bytes {
            return Err(FieldR1csArtifactError::BackingLengthMismatch {
                expected: total_bytes,
                actual: actual_bytes,
            });
        }

        let mut cursor = FIELD_R1CS_ARTIFACT_HEADER_BYTES as u64;
        let mut layouts = [SeekableArtifactMatrixLayout {
            side: FieldR1csArtifactMatrix::A,
            counts: matrices[0],
            row_offsets_at: 0,
            columns_at: 0,
            value_indices_at: 0,
            values_at: 0,
        }; 2];
        for (index, counts) in matrices.iter().copied().enumerate() {
            let row_offsets_at = cursor;
            let columns_at = row_offsets_at
                .checked_add(
                    counts
                        .offsets
                        .checked_mul(8)
                        .ok_or(FieldR1csArtifactError::LengthArithmetic)?,
                )
                .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
            let value_indices_at = columns_at
                .checked_add(
                    counts
                        .nnz
                        .checked_mul(4)
                        .ok_or(FieldR1csArtifactError::LengthArithmetic)?,
                )
                .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
            let values_at = value_indices_at
                .checked_add(
                    counts
                        .nnz
                        .checked_mul(4)
                        .ok_or(FieldR1csArtifactError::LengthArithmetic)?,
                )
                .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
            cursor = values_at
                .checked_add(
                    counts
                        .values
                        .checked_mul(16)
                        .ok_or(FieldR1csArtifactError::LengthArithmetic)?,
                )
                .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
            layouts[index] = SeekableArtifactMatrixLayout {
                side: artifact_matrix_name(index),
                counts,
                row_offsets_at,
                columns_at,
                value_indices_at,
                values_at,
            };
        }
        debug_assert_eq!(cursor, total_bytes);

        Ok(Self {
            reader,
            shape: expected_shape,
            useful_rows,
            total_bytes,
            header_bytes,
            layouts,
            expected_structural_digest,
        })
    }

    pub fn reader(&self) -> &R {
        &self.reader
    }

    /// Mutable backing access is provided for file-metadata adapters and
    /// tests. Any byte mutation is still rejected by the next authenticated
    /// evaluation because header, length, canonical rows, and digest are
    /// rechecked together.
    pub fn reader_mut(&mut self) -> &mut R {
        &mut self.reader
    }

    pub const fn useful_rows(&self) -> usize {
        self.useful_rows
    }

    fn read_at(&mut self, at: u64, bytes: &mut [u8]) -> Result<(), FieldR1csArtifactError> {
        self.reader.seek(SeekFrom::Start(at))?;
        let mut offset = at;
        read_exact_artifact(&mut self.reader, bytes, &mut offset)
    }

    fn ensure_backing_identity(&mut self) -> Result<(), FieldR1csArtifactError> {
        let actual = self.reader.seek(SeekFrom::End(0))?;
        if actual != self.total_bytes {
            return Err(FieldR1csArtifactError::BackingLengthMismatch {
                expected: self.total_bytes,
                actual,
            });
        }
        let mut current = [0u8; FIELD_R1CS_ARTIFACT_HEADER_BYTES];
        self.read_at(0, &mut current)?;
        if current != self.header_bytes {
            return Err(FieldR1csArtifactError::BackingFileChanged);
        }
        Ok(())
    }

    fn load_dictionary(
        &mut self,
        layout: SeekableArtifactMatrixLayout,
    ) -> Result<Vec<F128>, FieldR1csArtifactError> {
        let count = usize::try_from(layout.counts.values)
            .map_err(|_| FieldR1csArtifactError::LengthArithmetic)?;
        let byte_len = count
            .checked_mul(16)
            .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(byte_len)
            .map_err(|_| FieldR1csArtifactError::Allocation {
                matrix: layout.side,
                field: "streaming coefficient bytes",
            })?;
        bytes.resize(byte_len, 0);
        self.read_at(layout.values_at, &mut bytes)?;

        let mut values = Vec::new();
        values
            .try_reserve_exact(count)
            .map_err(|_| FieldR1csArtifactError::Allocation {
                matrix: layout.side,
                field: "streaming coefficient table",
            })?;
        for (index, chunk) in bytes.chunks_exact(16).enumerate() {
            let value = F128 {
                lo: u64::from_le_bytes(chunk[..8].try_into().expect("low limb")),
                hi: u64::from_le_bytes(chunk[8..].try_into().expect("high limb")),
            };
            if value == F128::ZERO {
                return Err(FieldR1csArtifactError::ZeroCoefficient {
                    matrix: layout.side,
                    index,
                });
            }
            values.push(value);
        }
        drop(bytes);
        validate_unique_nonzero_coefficients(&values, layout.side)?;
        Ok(values)
    }

    fn scan_authenticated(
        &mut self,
        fresh: Option<&crate::matrix_claim::FreshLincheckClaim>,
        accumulated: Option<&crate::matrix_claim::MatrixAccClaim>,
    ) -> Result<crate::matrix_claim::AuthenticatedMatrixClaimEvaluations, FieldR1csArtifactError>
    {
        self.ensure_backing_identity()?;
        validate_streaming_claim_shapes(self.shape, fresh, accumulated)?;

        let fresh_weights = fresh.map(|claim| StreamingFreshWeights::new(self.shape, claim));
        let accumulated_weights =
            accumulated.map(|claim| StreamingAccumulatedWeights::new(self.shape, claim));
        let spans = (1usize << self.shape.k_log).div_ceil(DIGEST_SPAN_ROWS);
        let top_payload_len = 5u64
            .checked_mul(8)
            .and_then(|n| n.checked_add(2 * 16))
            .and_then(|n| n.checked_add((2 * spans * 32) as u64))
            .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
        let mut top = StreamingOnePieceByteHash::new(b"NOID/IVC/FIELD-R1CS-STMT", top_payload_len);
        for value in [
            self.shape.m as u64,
            self.shape.k_log as u64,
            self.shape.k_skip as u64,
            self.useful_rows as u64,
            self.shape
                .const_pin
                .map(|column| 1 + column as u64)
                .unwrap_or(0),
        ] {
            top.update(&value.to_le_bytes());
        }

        let mut fresh_total = F128::ZERO;
        let mut accumulated_total = F128::ZERO;
        for matrix_index in 0..2 {
            let layout = self.layouts[matrix_index];
            let dictionary = self.load_dictionary(layout)?;
            top.update(&layout.counts.rows.to_le_bytes());
            top.update(&layout.counts.cols.to_le_bytes());
            let (fresh_matrix, accumulated_matrix) = self.scan_matrix_rows(
                layout,
                &dictionary,
                fresh_weights.as_ref(),
                accumulated_weights.as_ref(),
                &mut top,
            )?;
            if let Some(weights) = fresh_weights.as_ref() {
                fresh_total += fresh_matrix * weights.side_weight(matrix_index);
            }
            if let Some(weights) = accumulated_weights.as_ref() {
                accumulated_total += accumulated_matrix * weights.side_weight(matrix_index);
            }
        }
        let structural_digest = top.finalize();
        self.ensure_backing_identity()?;
        if structural_digest != self.expected_structural_digest {
            return Err(FieldR1csArtifactError::StructuralDigestMismatch {
                expected: self.expected_structural_digest,
                actual: structural_digest,
            });
        }
        Ok(
            crate::matrix_claim::AuthenticatedMatrixClaimEvaluations::new(
                structural_digest,
                fresh.map(|_| fresh_total),
                accumulated.map(|_| accumulated_total),
            ),
        )
    }

    fn scan_matrix_rows(
        &mut self,
        layout: SeekableArtifactMatrixLayout,
        dictionary: &[F128],
        fresh: Option<&StreamingFreshWeights<'_>>,
        accumulated: Option<&StreamingAccumulatedWeights>,
        top: &mut StreamingOnePieceByteHash,
    ) -> Result<(F128, F128), FieldR1csArtifactError> {
        let num_rows = usize::try_from(layout.counts.rows)
            .map_err(|_| FieldR1csArtifactError::LengthArithmetic)?;
        let nnz = usize::try_from(layout.counts.nnz)
            .map_err(|_| FieldR1csArtifactError::LengthArithmetic)?;
        let mut columns = vec![0u8; STREAMING_FIELD_R1CS_ENTRY_CHUNK * 4];
        let mut value_indices = vec![0u8; STREAMING_FIELD_R1CS_ENTRY_CHUNK * 4];
        let mut next_dictionary_index = 0usize;
        let mut previous_offset = 0usize;
        let mut fresh_matrix = F128::ZERO;
        let mut accumulated_matrix = F128::ZERO;
        let mut offset_bytes = vec![0u8; (DIGEST_SPAN_ROWS + 1) * 8];
        let mut offsets = Vec::with_capacity(DIGEST_SPAN_ROWS + 1);

        for span_index in 0..num_rows.div_ceil(DIGEST_SPAN_ROWS) {
            let first_row = span_index * DIGEST_SPAN_ROWS;
            let rows = (num_rows - first_row).min(DIGEST_SPAN_ROWS);
            let offsets_len = rows + 1;
            offsets.clear();
            self.read_at(
                layout.row_offsets_at + (first_row as u64) * 8,
                &mut offset_bytes[..offsets_len * 8],
            )?;
            for (local, bytes) in offset_bytes[..offsets_len * 8].chunks_exact(8).enumerate() {
                let raw = u64::from_le_bytes(bytes.try_into().expect("row offset"));
                let actual =
                    usize::try_from(raw).map_err(|_| FieldR1csArtifactError::InvalidRowOffset {
                        matrix: layout.side,
                        index: first_row + local,
                        previous: previous_offset,
                        actual: raw,
                        nnz,
                    })?;
                if (first_row == 0 && local == 0 && actual != 0)
                    || actual < previous_offset
                    || actual > nnz
                {
                    return Err(FieldR1csArtifactError::InvalidRowOffset {
                        matrix: layout.side,
                        index: first_row + local,
                        previous: previous_offset,
                        actual: raw,
                        nnz,
                    });
                }
                previous_offset = actual;
                offsets.push(actual);
            }
            let first_entry = offsets[0];
            let final_entry = *offsets.last().expect("one row offset");
            let span_payload_len = (rows as u64)
                .checked_mul(8)
                .and_then(|n| {
                    (final_entry - first_entry)
                        .checked_mul(24)
                        .and_then(|entries| n.checked_add(entries as u64))
                })
                .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
            let mut span =
                StreamingOnePieceByteHash::new(b"NOID/IVC/FIELD-R1CS-SPAN", span_payload_len);

            let mut row = 0usize;
            let mut cursor = first_entry;
            let mut fresh_row = F128::ZERO;
            let mut accumulated_row = F128::ZERO;
            streaming_begin_empty_rows(&offsets, &mut row, &mut span);
            while cursor < final_entry {
                if row >= rows {
                    return Err(FieldR1csArtifactError::InvalidRowOffset {
                        matrix: layout.side,
                        index: first_row + row,
                        previous: cursor,
                        actual: cursor as u64,
                        nnz,
                    });
                }
                if cursor == offsets[row] {
                    span.update(&((offsets[row + 1] - offsets[row]) as u64).to_le_bytes());
                }
                let count = (final_entry - cursor).min(STREAMING_FIELD_R1CS_ENTRY_CHUNK);
                self.read_at(
                    layout.columns_at + (cursor as u64) * 4,
                    &mut columns[..count * 4],
                )?;
                self.read_at(
                    layout.value_indices_at + (cursor as u64) * 4,
                    &mut value_indices[..count * 4],
                )?;
                for entry in 0..count {
                    let absolute = cursor + entry;
                    while row < rows && absolute == offsets[row + 1] {
                        streaming_finish_row(
                            first_row + row,
                            &mut fresh_row,
                            &mut accumulated_row,
                            &mut fresh_matrix,
                            &mut accumulated_matrix,
                            fresh,
                            accumulated,
                        );
                        row += 1;
                        streaming_begin_empty_rows(&offsets, &mut row, &mut span);
                        if row < rows && absolute == offsets[row] {
                            span.update(&((offsets[row + 1] - offsets[row]) as u64).to_le_bytes());
                        }
                    }
                    let col_at = entry * 4;
                    let column = u32::from_le_bytes(
                        columns[col_at..col_at + 4]
                            .try_into()
                            .expect("column bytes"),
                    );
                    if column as usize >= num_rows {
                        return Err(FieldR1csArtifactError::InvalidColumn {
                            matrix: layout.side,
                            index: absolute,
                            actual: column,
                            num_cols: num_rows,
                        });
                    }
                    let value_index = u32::from_le_bytes(
                        value_indices[col_at..col_at + 4]
                            .try_into()
                            .expect("value-index bytes"),
                    );
                    let value_at = value_index as usize;
                    if value_at >= dictionary.len() {
                        return Err(FieldR1csArtifactError::InvalidValueIndex {
                            matrix: layout.side,
                            index: absolute,
                            actual: value_index,
                            value_count: dictionary.len(),
                        });
                    }
                    if value_at > next_dictionary_index {
                        return Err(FieldR1csArtifactError::NonCanonicalValueIndexOrder {
                            matrix: layout.side,
                            index: absolute,
                            expected_next: next_dictionary_index,
                            actual: value_index,
                        });
                    }
                    if value_at == next_dictionary_index {
                        next_dictionary_index += 1;
                    }
                    let coefficient = dictionary[value_at];
                    span.update(&(column as u64).to_le_bytes());
                    span.update(&coefficient.lo.to_le_bytes());
                    span.update(&coefficient.hi.to_le_bytes());
                    if let Some(weights) = fresh {
                        fresh_row += coefficient * weights.column_weight(column as usize);
                    }
                    if let Some(weights) = accumulated {
                        accumulated_row += coefficient * weights.column_weight(column as usize);
                    }
                }
                cursor += count;
            }
            while row < rows {
                if cursor != offsets[row + 1] {
                    return Err(FieldR1csArtifactError::InvalidRowOffset {
                        matrix: layout.side,
                        index: first_row + row + 1,
                        previous: cursor,
                        actual: offsets[row + 1] as u64,
                        nnz,
                    });
                }
                if offsets[row] == offsets[row + 1] {
                    span.update(&0u64.to_le_bytes());
                    row += 1;
                    continue;
                }
                streaming_finish_row(
                    first_row + row,
                    &mut fresh_row,
                    &mut accumulated_row,
                    &mut fresh_matrix,
                    &mut accumulated_matrix,
                    fresh,
                    accumulated,
                );
                row += 1;
            }
            top.update(&span.finalize());
        }
        if previous_offset != nnz {
            return Err(FieldR1csArtifactError::InvalidRowOffset {
                matrix: layout.side,
                index: num_rows,
                previous: previous_offset,
                actual: previous_offset as u64,
                nnz,
            });
        }
        if next_dictionary_index != dictionary.len() {
            return Err(FieldR1csArtifactError::UnusedCoefficient {
                matrix: layout.side,
                index: next_dictionary_index,
            });
        }
        Ok((fresh_matrix, accumulated_matrix))
    }
}

/// Header/layout-only typestate for one terminal claim evaluation.
///
/// Construction validates the exact backing length, frozen shape, count
/// arithmetic, dictionary cap, and section boundaries, but deliberately does
/// not authenticate payload rows. The only operation that can produce an
/// authenticated result consumes its one-shot evaluation right and performs
/// canonical validation, structural hashing, and all requested claim
/// evaluations in the same full payload pass.
pub struct PreflightSeekableFieldR1csArtifact<R> {
    artifact: SeekableFieldR1csArtifact<R>,
    consumed: bool,
}

impl<R: Read + Seek> PreflightSeekableFieldR1csArtifact<R> {
    pub fn open(
        reader: R,
        expected_shape: crate::proof::FieldShape,
        expected_structural_digest: [u8; 32],
        max_bytes: u64,
    ) -> Result<Self, FieldR1csArtifactError> {
        Ok(Self {
            artifact: SeekableFieldR1csArtifact::preflight_header(
                reader,
                expected_shape,
                expected_structural_digest,
                max_bytes,
            )?,
            consumed: false,
        })
    }

    pub fn reader(&self) -> &R {
        self.artifact.reader()
    }
}

impl<R: Read + Seek> crate::matrix_claim::MatrixClaimEvaluator
    for PreflightSeekableFieldR1csArtifact<R>
{
    fn field_shape(&self) -> crate::proof::FieldShape {
        self.artifact.shape
    }

    fn evaluate_matrix_claims(
        &mut self,
        fresh: Option<&crate::matrix_claim::FreshLincheckClaim>,
        accumulated: Option<&crate::matrix_claim::MatrixAccClaim>,
    ) -> Result<crate::matrix_claim::AuthenticatedMatrixClaimEvaluations, FieldR1csArtifactError>
    {
        if self.consumed {
            return Err(FieldR1csArtifactError::MatrixEvaluatorAlreadyConsumed);
        }
        self.consumed = true;
        self.artifact.scan_authenticated(fresh, accumulated)
    }
}

impl<R: Read + Seek> crate::matrix_claim::MatrixClaimEvaluator for SeekableFieldR1csArtifact<R> {
    fn field_shape(&self) -> crate::proof::FieldShape {
        self.shape
    }

    fn evaluate_matrix_claims(
        &mut self,
        fresh: Option<&crate::matrix_claim::FreshLincheckClaim>,
        accumulated: Option<&crate::matrix_claim::MatrixAccClaim>,
    ) -> Result<crate::matrix_claim::AuthenticatedMatrixClaimEvaluations, FieldR1csArtifactError>
    {
        self.scan_authenticated(fresh, accumulated)
    }
}

fn validate_streaming_claim_shapes(
    shape: crate::proof::FieldShape,
    fresh: Option<&crate::matrix_claim::FreshLincheckClaim>,
    accumulated: Option<&crate::matrix_claim::MatrixAccClaim>,
) -> Result<(), FieldR1csArtifactError> {
    if let Some(claim) = fresh {
        let rest = shape.k_log - shape.k_skip;
        if claim.x_inner_rest.len() != rest || claim.r_inner_rest.len() != rest {
            return Err(FieldR1csArtifactError::MatrixClaimShape(
                "fresh inner-rest width",
            ));
        }
        if claim.z_partial.len() != 1usize << shape.k_skip {
            return Err(FieldR1csArtifactError::MatrixClaimShape(
                "fresh partial window",
            ));
        }
    }
    if accumulated.is_some_and(|claim| claim.point.len() != 2 * shape.k_log + 1) {
        return Err(FieldR1csArtifactError::MatrixClaimShape(
            "accumulated point width",
        ));
    }
    Ok(())
}

struct StreamingFactoredEqTable {
    low: Vec<F128>,
    high: Vec<F128>,
    low_bits: usize,
    low_mask: usize,
}

impl StreamingFactoredEqTable {
    fn new(point: &[F128]) -> Self {
        let low_bits = point.len() / 2;
        Self {
            low: crate::lincheck::build_eq_table(&point[..low_bits]),
            high: crate::lincheck::build_eq_table(&point[low_bits..]),
            low_bits,
            low_mask: (1usize << low_bits) - 1,
        }
    }

    #[inline(always)]
    fn value(&self, index: usize) -> F128 {
        self.low[index & self.low_mask] * self.high[index >> self.low_bits]
    }
}

struct StreamingFreshWeights<'a> {
    claim: &'a crate::matrix_claim::FreshLincheckClaim,
    k_skip: usize,
    mask: usize,
    lambda: Vec<F128>,
    row_rest: StreamingFactoredEqTable,
    col_rest: StreamingFactoredEqTable,
}

impl<'a> StreamingFreshWeights<'a> {
    fn new(
        shape: crate::proof::FieldShape,
        claim: &'a crate::matrix_claim::FreshLincheckClaim,
    ) -> Self {
        Self {
            claim,
            k_skip: shape.k_skip,
            mask: (1usize << shape.k_skip) - 1,
            lambda: crate::zerocheck::multilinear::lagrange_weights_naive(
                shape.k_skip,
                claim.z_skip,
            ),
            row_rest: StreamingFactoredEqTable::new(&claim.x_inner_rest),
            col_rest: StreamingFactoredEqTable::new(&claim.r_inner_rest),
        }
    }

    fn side_weight(&self, index: usize) -> F128 {
        if index == 0 {
            self.claim.alpha
        } else {
            F128::ONE
        }
    }

    fn row_weight(&self, row: usize) -> F128 {
        self.lambda[row & self.mask] * self.row_rest.value(row >> self.k_skip)
    }

    fn column_weight(&self, column: usize) -> F128 {
        self.claim.z_partial[column & self.mask] * self.col_rest.value(column >> self.k_skip)
    }
}

struct StreamingAccumulatedWeights {
    stack: F128,
    row: StreamingFactoredEqTable,
    column: StreamingFactoredEqTable,
}

impl StreamingAccumulatedWeights {
    fn new(shape: crate::proof::FieldShape, claim: &crate::matrix_claim::MatrixAccClaim) -> Self {
        let (row, column) = claim.point.split_at(shape.k_log + 1);
        Self {
            stack: row[shape.k_log],
            row: StreamingFactoredEqTable::new(&row[..shape.k_log]),
            column: StreamingFactoredEqTable::new(column),
        }
    }

    fn side_weight(&self, index: usize) -> F128 {
        if index == 0 {
            F128::ONE + self.stack
        } else {
            self.stack
        }
    }

    fn row_weight(&self, row: usize) -> F128 {
        self.row.value(row)
    }

    fn column_weight(&self, column: usize) -> F128 {
        self.column.value(column)
    }
}

fn streaming_begin_empty_rows(
    offsets: &[usize],
    row: &mut usize,
    span: &mut StreamingOnePieceByteHash,
) {
    while *row + 1 < offsets.len() && offsets[*row] == offsets[*row + 1] {
        span.update(&0u64.to_le_bytes());
        *row += 1;
    }
}

#[allow(clippy::too_many_arguments)]
fn streaming_finish_row(
    row: usize,
    fresh_row: &mut F128,
    accumulated_row: &mut F128,
    fresh_matrix: &mut F128,
    accumulated_matrix: &mut F128,
    fresh: Option<&StreamingFreshWeights<'_>>,
    accumulated: Option<&StreamingAccumulatedWeights>,
) {
    if let Some(weights) = fresh {
        *fresh_matrix += *fresh_row * weights.row_weight(row);
        *fresh_row = F128::ZERO;
    }
    if let Some(weights) = accumulated {
        *accumulated_matrix += *accumulated_row * weights.row_weight(row);
        *accumulated_row = F128::ZERO;
    }
}

struct StreamingOnePieceByteHash(noid_poseidon2b::native::Poseidon2bSponge);

impl StreamingOnePieceByteHash {
    fn new(domain: &[u8], payload_len: u64) -> Self {
        let mut sponge = noid_poseidon2b::native::Poseidon2bSponge::with_iv(
            noid_poseidon2b::native::capacity_iv(noid_poseidon2b::native::TAG_BYTEHASH),
        );
        sponge.update(&(domain.len() as u64).to_le_bytes());
        sponge.update(domain);
        sponge.update(&1u64.to_le_bytes());
        sponge.update(&payload_len.to_le_bytes());
        Self(sponge)
    }

    fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    fn finalize(self) -> [u8; 32] {
        self.0.finalize()
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
/// caller already owns, so — unlike [`FieldCscCircuit`] — it allocates **no**
/// transposed CSC copy. During a prover or verifier lincheck window only ONE
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
        let threads = rayon::current_num_threads().max(1);

        // Serial scatter for small instances and for the deliberately
        // single-threaded production verifier: one output comb,
        // `comb[c] += weight·coeff·eq[r]` over both matrices' rows (weight α
        // for A, 1 for B). Besides avoiding parallel overhead, the verifier
        // therefore never holds separate width-n A and B partial combs.
        if nnz < FIELD_FOLD_PAR_THRESHOLD || threads == 1 {
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
    use crate::proof::FieldShape;
    use std::io::{Cursor, Read, Seek, SeekFrom};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct CountingCursor {
        inner: Cursor<Vec<u8>>,
        bytes_read: Arc<AtomicUsize>,
    }

    impl Read for CountingCursor {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            let read = self.inner.read(bytes)?;
            self.bytes_read.fetch_add(read, Ordering::Relaxed);
            Ok(read)
        }
    }

    impl Seek for CountingCursor {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.inner.seek(position)
        }
    }

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

    fn artifact_fixture(seed: u64) -> (FieldR1cs, FieldShape, [u8; 32], Vec<u8>) {
        let (r1cs, _) = random_satisfiable(8, 4, seed);
        let shape = FieldShape::of(&r1cs);
        let digest = r1cs.structural_statement_digest();
        let mut bytes = Vec::new();
        r1cs.write_artifact(&mut bytes).unwrap();
        (r1cs, shape, digest, bytes)
    }

    fn decode_fixture(
        bytes: &[u8],
        shape: FieldShape,
        digest: [u8; 32],
    ) -> Result<FieldR1cs, FieldR1csArtifactError> {
        FieldR1cs::read_artifact(&mut Cursor::new(bytes), shape, digest, bytes.len())
    }

    fn header_u64(bytes: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
    }

    fn set_header_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn field_r1cs_artifact_roundtrip_has_empty_derived_caches() {
        let (expected, shape, digest, bytes) = artifact_fixture(0xA271_FAC7);
        assert_eq!(
            header_u64(&bytes, 12) as usize,
            bytes.len(),
            "fixed header must bind the exact artifact length",
        );

        let decoded = decode_fixture(&bytes, shape, digest).unwrap();
        assert_eq!(decoded.m, expected.m);
        assert_eq!(decoded.k_log, expected.k_log);
        assert_eq!(decoded.k_skip, expected.k_skip);
        assert_eq!(decoded.useful_rows, expected.useful_rows);
        assert_eq!(decoded.const_pin, expected.const_pin);
        assert_eq!(decoded.a_0, expected.a_0);
        assert_eq!(decoded.b_0, expected.b_0);
        assert!(decoded.digest_cache.get().is_none());
        assert!(decoded.csc_cache.get().is_none());
        assert_eq!(decoded.structural_statement_digest(), digest);
    }

    #[test]
    fn seekable_artifact_evaluations_match_in_memory_without_csr_decode() {
        use crate::matrix_claim::{
            FreshLincheckClaim, MatrixAccClaim, MatrixClaimEvaluator, fresh_claim_value,
            stacked_matrix_mle_eval,
        };

        let (r1cs, shape, digest, bytes) = artifact_fixture(0x51EA_4AB1);
        let rest = shape.k_log - shape.k_skip;
        let mut rng = Rng::new(0xE0A1_5A7E);
        let fresh = FreshLincheckClaim {
            alpha: rng.f128(),
            z_skip: rng.f128(),
            x_inner_rest: (0..rest).map(|_| rng.f128()).collect(),
            r_inner_rest: (0..rest).map(|_| rng.f128()).collect(),
            z_partial: (0..1usize << shape.k_skip).map(|_| rng.f128()).collect(),
            value: F128::ZERO,
        };
        let accumulated = MatrixAccClaim {
            point: (0..2 * shape.k_log + 1).map(|_| rng.f128()).collect(),
            value: F128::ZERO,
        };
        let expected_fresh = fresh_claim_value(&r1cs, &fresh);
        let expected_accumulated = stacked_matrix_mle_eval(&r1cs, &accumulated);

        let mut view = SeekableFieldR1csArtifact::open(
            Cursor::new(bytes.clone()),
            shape,
            digest,
            bytes.len() as u64,
        )
        .unwrap();
        let evaluated = view
            .evaluate_matrix_claims(Some(&fresh), Some(&accumulated))
            .unwrap();
        assert_eq!(evaluated.structural_digest(), digest);
        assert_eq!(evaluated.fresh_value(), Some(expected_fresh));
        assert_eq!(evaluated.accumulated_value(), Some(expected_accumulated));
        assert_eq!(view.useful_rows(), r1cs.useful_rows);
    }

    #[test]
    fn terminal_preflight_reads_payload_exactly_once() {
        use crate::matrix_claim::{MatrixAccClaim, MatrixClaimEvaluator};

        let (_r1cs, shape, digest, bytes) = artifact_fixture(0x0A11_CE55);
        // The fixture has fewer than DIGEST_SPAN_ROWS rows, so neither
        // matrix rereads an overlapping span-boundary offset.
        assert!((1usize << shape.k_log) < DIGEST_SPAN_ROWS);
        let bytes_read = Arc::new(AtomicUsize::new(0));
        let reader = CountingCursor {
            inner: Cursor::new(bytes.clone()),
            bytes_read: Arc::clone(&bytes_read),
        };
        let mut preflight =
            PreflightSeekableFieldR1csArtifact::open(reader, shape, digest, bytes.len() as u64)
                .unwrap();
        assert_eq!(
            bytes_read.load(Ordering::Relaxed),
            FIELD_R1CS_ARTIFACT_HEADER_BYTES,
            "header preflight must not scan the payload",
        );

        let claim = MatrixAccClaim {
            point: vec![F128::ZERO; 2 * shape.k_log + 1],
            value: F128::ZERO,
        };
        preflight
            .evaluate_matrix_claims(None, Some(&claim))
            .unwrap();
        let payload = bytes.len() - FIELD_R1CS_ARTIFACT_HEADER_BYTES;
        assert_eq!(
            bytes_read.load(Ordering::Relaxed),
            3 * FIELD_R1CS_ARTIFACT_HEADER_BYTES + payload,
            "one header preflight, two identity-header reads, and exactly one payload pass",
        );
        assert!(matches!(
            preflight.evaluate_matrix_claims(None, Some(&claim)),
            Err(FieldR1csArtifactError::MatrixEvaluatorAlreadyConsumed)
        ));
    }

    #[test]
    fn seekable_artifact_matches_across_digest_spans_and_entry_chunks() {
        use crate::matrix_claim::{
            FreshLincheckClaim, MatrixAccClaim, MatrixClaimEvaluator, fresh_claim_value,
            stacked_matrix_mle_eval,
        };

        let k_log = 12usize;
        let k = 1usize << k_log;
        let mut a_rows = vec![Vec::new(); k];
        // Row 7 ends exactly at an entry-chunk boundary; row 8 begins the
        // next chunk. The last/first rows around DIGEST_SPAN_ROWS exercise
        // the independent span boundary, including adjacent empty padding.
        a_rows[7] = (0..STREAMING_FIELD_R1CS_ENTRY_CHUNK)
            .map(|index| ((index % k) as u32, F128::ONE))
            .collect();
        a_rows[8].push((17, F128::new(3, 7)));
        a_rows[DIGEST_SPAN_ROWS - 1].push((18, F128::new(4, 8)));
        a_rows[DIGEST_SPAN_ROWS].push((19, F128::new(5, 9)));
        let r1cs = FieldR1cs {
            m: k_log,
            k_log,
            k_skip: 6,
            useful_rows: DIGEST_SPAN_ROWS + 1,
            a_0: SparseFieldMatrix::from_rows(k, a_rows),
            b_0: SparseFieldMatrix::zero(k),
            const_pin: Some(0),
            digest_cache: std::sync::OnceLock::new(),
            csc_cache: std::sync::OnceLock::new(),
        };
        let shape = FieldShape::of(&r1cs);
        let digest = r1cs.structural_statement_digest();
        let mut bytes = Vec::new();
        r1cs.write_artifact(&mut bytes).unwrap();
        let mut rng = Rng::new(0x5A4E_C2055);
        let fresh = FreshLincheckClaim {
            alpha: rng.f128(),
            z_skip: rng.f128(),
            x_inner_rest: (0..k_log - 6).map(|_| rng.f128()).collect(),
            r_inner_rest: (0..k_log - 6).map(|_| rng.f128()).collect(),
            z_partial: (0..64).map(|_| rng.f128()).collect(),
            value: F128::ZERO,
        };
        let accumulated = MatrixAccClaim {
            point: (0..2 * k_log + 1).map(|_| rng.f128()).collect(),
            value: F128::ZERO,
        };
        let mut view = SeekableFieldR1csArtifact::open(
            Cursor::new(bytes.clone()),
            shape,
            digest,
            bytes.len() as u64,
        )
        .unwrap();
        let evaluated = view
            .evaluate_matrix_claims(Some(&fresh), Some(&accumulated))
            .unwrap();
        assert_eq!(
            evaluated.fresh_value(),
            Some(fresh_claim_value(&r1cs, &fresh))
        );
        assert_eq!(
            evaluated.accumulated_value(),
            Some(stacked_matrix_mle_eval(&r1cs, &accumulated))
        );
    }

    #[test]
    fn seekable_artifact_reauthenticates_same_length_mutation() {
        use crate::matrix_claim::MatrixClaimEvaluator;

        let (_r1cs, shape, digest, bytes) = artifact_fixture(0x5A4E_1E67);
        let mut view = SeekableFieldR1csArtifact::open(
            Cursor::new(bytes.clone()),
            shape,
            digest,
            bytes.len() as u64,
        )
        .unwrap();
        let a_offsets = header_u64(&bytes, 80) as usize;
        let a_columns_at = FIELD_R1CS_ARTIFACT_HEADER_BYTES + a_offsets * 8;
        view.reader_mut().get_mut()[a_columns_at] ^= 1;
        assert!(matches!(
            view.evaluate_matrix_claims(None, None),
            Err(FieldR1csArtifactError::StructuralDigestMismatch { .. })
                | Err(FieldR1csArtifactError::InvalidColumn { .. })
        ));
    }

    #[test]
    fn terminal_preflight_defers_but_never_skips_payload_rejection() {
        use crate::matrix_claim::MatrixClaimEvaluator;

        let (_r1cs, shape, digest, mut bytes) = artifact_fixture(0xDEFE_22ED);
        let a_offsets = header_u64(&bytes, 80) as usize;
        let a_columns_at = FIELD_R1CS_ARTIFACT_HEADER_BYTES + a_offsets * 8;
        bytes[a_columns_at..a_columns_at + 4].copy_from_slice(&(1u32 << shape.k_log).to_le_bytes());

        let mut preflight = PreflightSeekableFieldR1csArtifact::open(
            Cursor::new(bytes.clone()),
            shape,
            digest,
            bytes.len() as u64,
        )
        .expect("header/layout preflight deliberately does not authenticate payload rows");
        assert!(matches!(
            preflight.evaluate_matrix_claims(None, None),
            Err(FieldR1csArtifactError::InvalidColumn { .. })
                | Err(FieldR1csArtifactError::StructuralDigestMismatch { .. })
        ));
    }

    #[test]
    fn seekable_artifact_fails_closed_on_length_and_header_changes() {
        use crate::matrix_claim::MatrixClaimEvaluator;

        let (_r1cs, shape, digest, bytes) = artifact_fixture(0x7A11_1E5E);
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            SeekableFieldR1csArtifact::open(
                Cursor::new(trailing.clone()),
                shape,
                digest,
                trailing.len() as u64,
            ),
            Err(FieldR1csArtifactError::BackingLengthMismatch { .. })
        ));
        let truncated = &bytes[..bytes.len() - 1];
        assert!(
            SeekableFieldR1csArtifact::open(
                Cursor::new(truncated),
                shape,
                digest,
                bytes.len() as u64,
            )
            .is_err()
        );

        let mut view = SeekableFieldR1csArtifact::open(
            Cursor::new(bytes.clone()),
            shape,
            digest,
            bytes.len() as u64,
        )
        .unwrap();
        view.reader_mut().get_mut()[20] ^= 1;
        assert!(matches!(
            view.evaluate_matrix_claims(None, None),
            Err(FieldR1csArtifactError::BackingFileChanged)
        ));
    }

    #[test]
    fn seekable_artifact_rejects_noncanonical_sparse_sections() {
        let (_r1cs, shape, digest, bytes) = artifact_fixture(0xBAD5_EC71);
        let a_nnz = header_u64(&bytes, 64) as usize;
        let a_values = header_u64(&bytes, 72) as usize;
        let a_offsets = header_u64(&bytes, 80) as usize;
        assert!(a_nnz > 0 && a_values >= 2);
        let offsets_at = FIELD_R1CS_ARTIFACT_HEADER_BYTES;
        let columns_at = offsets_at + a_offsets * 8;
        let indices_at = columns_at + a_nnz * 4;
        let values_at = indices_at + a_nnz * 4;

        let reject = |candidate: Vec<u8>| match SeekableFieldR1csArtifact::open(
            Cursor::new(candidate.clone()),
            shape,
            digest,
            candidate.len() as u64,
        ) {
            Ok(_) => panic!("malformed seekable artifact must fail closed"),
            Err(error) => error,
        };

        let mut bad_offset = bytes.clone();
        bad_offset[offsets_at..offsets_at + 8].copy_from_slice(&1u64.to_le_bytes());
        assert!(matches!(
            reject(bad_offset),
            FieldR1csArtifactError::InvalidRowOffset { .. }
        ));

        let mut bad_column = bytes.clone();
        bad_column[columns_at..columns_at + 4]
            .copy_from_slice(&(1u32 << shape.k_log).to_le_bytes());
        assert!(matches!(
            reject(bad_column),
            FieldR1csArtifactError::InvalidColumn { .. }
        ));

        let mut bad_index = bytes.clone();
        bad_index[indices_at..indices_at + 4].copy_from_slice(&(a_values as u32).to_le_bytes());
        assert!(matches!(
            reject(bad_index),
            FieldR1csArtifactError::InvalidValueIndex { .. }
        ));

        let mut skipped_first = bytes.clone();
        skipped_first[indices_at..indices_at + 4].copy_from_slice(&1u32.to_le_bytes());
        assert!(matches!(
            reject(skipped_first),
            FieldR1csArtifactError::NonCanonicalValueIndexOrder { .. }
        ));

        let mut zero = bytes.clone();
        zero[values_at..values_at + 16].fill(0);
        assert!(matches!(
            reject(zero),
            FieldR1csArtifactError::ZeroCoefficient { .. }
        ));

        let mut duplicate = bytes;
        let first = duplicate[values_at..values_at + 16].to_vec();
        duplicate[values_at + 16..values_at + 32].copy_from_slice(&first);
        assert!(matches!(
            reject(duplicate),
            FieldR1csArtifactError::DuplicateCoefficient { .. }
        ));
    }

    #[test]
    fn seekable_artifact_scratch_is_protocol_bounded() {
        assert!(STREAMING_FIELD_R1CS_ENTRY_CHUNK * 8 <= 512 * 1024);
        assert!(STREAMING_FIELD_R1CS_MAX_DICTIONARY_VALUES * 16 <= 1024 * 1024);
        let source = include_str!("field_r1cs.rs");
        let implementation = source
            .split("pub struct SeekableFieldR1csArtifact")
            .nth(1)
            .expect("streaming artifact view")
            .split("/// Rows per statement-digest span")
            .next()
            .expect("streaming implementation boundary");
        assert!(!implementation.contains("read_artifact(&mut"));
        assert!(!implementation.contains("SparseFieldMatrix {"));
    }

    #[test]
    fn field_r1cs_artifact_writer_canonicalizes_shared_dictionary() {
        let (honest, shape, digest, canonical_bytes) = artifact_fixture(0xCA10_D1C7);
        let mut shared = honest.clone();

        // Model the builder's shared A/B dictionary: reorder all A entries,
        // remap the references so decoded rows stay identical, then retain an
        // unused duplicate entry from the shared superset.
        let value_count = shared.a_0.value_table.len();
        assert!(value_count > 2);
        shared.a_0.value_table.rotate_left(1);
        for value_index in &mut shared.a_0.value_indices {
            *value_index = (*value_index + value_count as u32 - 1) % value_count as u32;
        }
        shared.a_0.value_table.push(shared.a_0.value_table[0]);
        assert_eq!(shared.a_0, honest.a_0);
        assert_eq!(shared.structural_statement_digest(), digest);

        let mut canonicalized = Vec::new();
        shared.write_artifact(&mut canonicalized).unwrap();
        assert_eq!(
            canonicalized, canonical_bytes,
            "writer must emit first-use per-matrix dictionaries, independent of builder interning",
        );
        let decoded = decode_fixture(&canonicalized, shape, digest).unwrap();
        assert_eq!(decoded.a_0, honest.a_0);
        assert_eq!(decoded.b_0, honest.b_0);
    }

    #[test]
    fn field_r1cs_artifact_reader_rejects_semantic_dictionary_reordering() {
        let (honest, shape, digest, mut bytes) = artifact_fixture(0x57A1_C7D1);
        let a_nnz = header_u64(&bytes, 64) as usize;
        let a_values = header_u64(&bytes, 72) as usize;
        let a_offsets = header_u64(&bytes, 80) as usize;
        assert!(a_values >= 2);
        let value_indices_start = FIELD_R1CS_ARTIFACT_HEADER_BYTES + a_offsets * 8 + a_nnz * 4;
        let values_start = value_indices_start + a_nnz * 4;

        // Swap dictionary entries 0/1 and all of their references. The
        // decoded coefficient in every row is unchanged, but the first used
        // artifact index is now 1 rather than canonical index 0.
        for encoded in bytes[value_indices_start..values_start].chunks_exact_mut(4) {
            let index = u32::from_le_bytes(encoded.try_into().unwrap());
            let remapped = match index {
                0 => 1u32,
                1 => 0u32,
                other => other,
            };
            encoded.copy_from_slice(&remapped.to_le_bytes());
        }
        let first: [u8; 16] = bytes[values_start..values_start + 16].try_into().unwrap();
        let second: [u8; 16] = bytes[values_start + 16..values_start + 32]
            .try_into()
            .unwrap();
        bytes[values_start..values_start + 16].copy_from_slice(&second);
        bytes[values_start + 16..values_start + 32].copy_from_slice(&first);

        assert!(matches!(
            decode_fixture(&bytes, shape, digest),
            Err(FieldR1csArtifactError::NonCanonicalValueIndexOrder {
                matrix: FieldR1csArtifactMatrix::A,
                expected_next: 0,
                actual: 1,
                ..
            })
        ));
        // Keep the semantic equivalence premise explicit and independent of
        // the decoder under test.
        let mut equivalent = honest.clone();
        equivalent.a_0.value_table.swap(0, 1);
        for index in &mut equivalent.a_0.value_indices {
            *index = match *index {
                0 => 1,
                1 => 0,
                other => other,
            };
        }
        assert_eq!(equivalent.structural_statement_digest(), digest);
    }

    #[test]
    fn field_r1cs_artifact_rejects_seeded_content_substitution() {
        let (honest, shape, expected_digest, _) = artifact_fixture(0x0D16_5E57);
        let mut substituted = honest.clone();
        let entry = substituted.a_0.row_offsets[1];
        substituted.a_0.col_indices[entry] =
            (substituted.a_0.col_indices[entry] + 1) % substituted.a_0.num_cols as u32;
        assert_ne!(substituted.structural_statement_digest(), expected_digest,);
        substituted.seed_statement_digest(expected_digest);

        let mut bytes = Vec::new();
        substituted.write_artifact(&mut bytes).unwrap();
        assert!(matches!(
            decode_fixture(&bytes, shape, expected_digest),
            Err(FieldR1csArtifactError::StructuralDigestMismatch { .. })
        ));
    }

    struct CountingReader<'a> {
        inner: Cursor<&'a [u8]>,
        bytes_read: usize,
    }

    impl Read for CountingReader<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let read = self.inner.read(buffer)?;
            self.bytes_read += read;
            Ok(read)
        }
    }

    #[test]
    fn field_r1cs_artifact_rejects_forged_huge_counts_before_payload() {
        let (_, shape, digest, mut bytes) = artifact_fixture(0xC0A1_7001);
        // A.nnz is the third u64 of the first descriptor.
        set_header_u64(&mut bytes, 64, u64::MAX);
        let max_bytes = bytes.len();
        let mut reader = CountingReader {
            inner: Cursor::new(bytes.as_slice()),
            bytes_read: 0,
        };
        assert!(matches!(
            FieldR1cs::read_artifact(&mut reader, shape, digest, max_bytes),
            Err(FieldR1csArtifactError::CountOutOfRange {
                matrix: FieldR1csArtifactMatrix::A,
                field: "nnz",
                ..
            })
        ));
        assert_eq!(
            reader.bytes_read, FIELD_R1CS_ARTIFACT_HEADER_BYTES,
            "untrusted vector counts must fail before payload reads or allocations",
        );
    }

    #[test]
    fn field_r1cs_artifact_rejects_bad_dimensions_and_offsets() {
        let (_, shape, digest, bytes) = artifact_fixture(0xBAD0_FF5E7);

        let mut bad_dimensions = bytes.clone();
        set_header_u64(&mut bad_dimensions, 48, (1u64 << shape.k_log) - 1);
        assert!(matches!(
            decode_fixture(&bad_dimensions, shape, digest),
            Err(FieldR1csArtifactError::MatrixDimensions {
                matrix: FieldR1csArtifactMatrix::A,
                ..
            })
        ));

        let mut bad_first_offset = bytes;
        set_header_u64(&mut bad_first_offset, FIELD_R1CS_ARTIFACT_HEADER_BYTES, 1);
        assert!(matches!(
            decode_fixture(&bad_first_offset, shape, digest),
            Err(FieldR1csArtifactError::InvalidRowOffset {
                matrix: FieldR1csArtifactMatrix::A,
                index: 0,
                ..
            })
        ));
    }

    #[test]
    fn field_r1cs_artifact_rejects_bad_indices_and_zero_coefficients() {
        let (_, shape, digest, bytes) = artifact_fixture(0xBAD1_D1CE5);
        let a_nnz = header_u64(&bytes, 64) as usize;
        let a_values = header_u64(&bytes, 72) as usize;
        let a_offsets = header_u64(&bytes, 80) as usize;
        assert!(a_values >= 2);
        let columns_start = FIELD_R1CS_ARTIFACT_HEADER_BYTES + a_offsets * 8;
        let value_indices_start = columns_start + a_nnz * 4;
        let values_start = value_indices_start + a_nnz * 4;

        let mut bad_column = bytes.clone();
        bad_column[columns_start..columns_start + 4]
            .copy_from_slice(&(1u32 << shape.k_log).to_le_bytes());
        assert!(matches!(
            decode_fixture(&bad_column, shape, digest),
            Err(FieldR1csArtifactError::InvalidColumn {
                matrix: FieldR1csArtifactMatrix::A,
                ..
            })
        ));

        let mut bad_value_index = bytes.clone();
        bad_value_index[value_indices_start..value_indices_start + 4]
            .copy_from_slice(&(a_values as u32).to_le_bytes());
        assert!(matches!(
            decode_fixture(&bad_value_index, shape, digest),
            Err(FieldR1csArtifactError::InvalidValueIndex {
                matrix: FieldR1csArtifactMatrix::A,
                ..
            })
        ));

        let mut zero_coefficient = bytes;
        let mut duplicate_coefficient = zero_coefficient.clone();
        duplicate_coefficient[values_start + 16..values_start + 32]
            .copy_from_slice(&zero_coefficient[values_start..values_start + 16]);
        assert!(matches!(
            decode_fixture(&duplicate_coefficient, shape, digest),
            Err(FieldR1csArtifactError::DuplicateCoefficient {
                matrix: FieldR1csArtifactMatrix::A,
                ..
            })
        ));

        zero_coefficient[values_start..values_start + 16].fill(0);
        assert!(matches!(
            decode_fixture(&zero_coefficient, shape, digest),
            Err(FieldR1csArtifactError::ZeroCoefficient {
                matrix: FieldR1csArtifactMatrix::A,
                index: 0,
            })
        ));
    }

    #[test]
    fn field_r1cs_artifact_rejects_trailing_and_truncated_bytes() {
        let (_, shape, digest, bytes) = artifact_fixture(0x7A11_1A7E);

        let mut trailing = bytes.clone();
        trailing.push(0xA5);
        assert!(matches!(
            decode_fixture(&trailing, shape, digest),
            Err(FieldR1csArtifactError::TrailingBytes)
        ));

        let truncated = &bytes[..bytes.len() - 1];
        assert!(matches!(
            FieldR1cs::read_artifact(&mut Cursor::new(truncated), shape, digest, bytes.len(),),
            Err(FieldR1csArtifactError::Truncated { .. })
        ));
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

        let row = FieldRowCircuit::new(&r1cs.a_0, &r1cs.b_0, r1cs.const_pin);
        let row_got = row.fold_alpha_batched(alpha, &eq_inner);
        assert_eq!(row_got, got, "row-major fold drifted from CSC fold");
    }

    /// The borrowing row fold is value-identical to the legacy CSC gather in
    /// both its one-comb verifier path and its parallel prover path.
    #[test]
    fn row_fold_matches_csc_in_serial_and_parallel_pools() {
        let (r1cs, _) = random_satisfiable(13, 12, 0xA11C_E551);
        let mut rng = Rng::new(0xF01D_E001);
        let point: Vec<F128> = (0..r1cs.k_log).map(|_| rng.f128()).collect();
        let eq_inner = build_eq_table(&point);
        let alpha = rng.f128();
        let csc =
            FieldCscCircuit::from_matrices(&r1cs.a_0, &r1cs.b_0).with_const_pin(r1cs.const_pin);
        let expected = csc.fold_alpha_batched(alpha, &eq_inner);
        let row = FieldRowCircuit::new(&r1cs.a_0, &r1cs.b_0, r1cs.const_pin);

        let serial = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .expect("one-thread test pool")
            .install(|| row.fold_alpha_batched(alpha, &eq_inner));
        let parallel = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .expect("two-thread test pool")
            .install(|| row.fold_alpha_batched(alpha, &eq_inner));

        assert_eq!(serial, expected, "single-comb verifier fold drifted");
        assert_eq!(parallel, expected, "parallel row fold drifted");
    }

    /// A proof produced against either circuit representation is byte-for-byte
    /// identical and the shared verifier accepts it with the same terminal
    /// claim. This pins the transcript/acceptance semantics while production
    /// verification switches from retained CSC to borrowing CSR.
    #[test]
    fn row_and_csc_lincheck_transcripts_and_acceptance_match() {
        use crate::challenger::FsChallenger;
        use crate::lincheck::{QuirkyPoint, prove_field, verify};

        let (r1cs, z) = random_satisfiable(10, 7, 0x7E57_C5C0);
        let mut rng = Rng::new(0x7A4A_5C71);
        let x_ab = QuirkyPoint {
            z_skip: rng.f128(),
            x_inner_rest: (0..r1cs.k_log - r1cs.k_skip).map(|_| rng.f128()).collect(),
            x_outer: (0..r1cs.m - r1cs.k_log).map(|_| rng.f128()).collect(),
        };
        let row = FieldRowCircuit::new(&r1cs.a_0, &r1cs.b_0, r1cs.const_pin);
        let csc =
            FieldCscCircuit::from_matrices(&r1cs.a_0, &r1cs.b_0).with_const_pin(r1cs.const_pin);

        let mut ch_row = FsChallenger::new(b"field-row-csc-parity-v0");
        let (proof_row, claim_row) = prove_field(
            &z,
            r1cs.m,
            r1cs.k_log,
            r1cs.k_skip,
            r1cs.useful_rows,
            &row,
            &x_ab,
            &mut ch_row,
        );
        let mut ch_csc = FsChallenger::new(b"field-row-csc-parity-v0");
        let (proof_csc, claim_csc) = prove_field(
            &z,
            r1cs.m,
            r1cs.k_log,
            r1cs.k_skip,
            r1cs.useful_rows,
            &csc,
            &x_ab,
            &mut ch_csc,
        );
        assert_eq!(proof_row, proof_csc, "lincheck proof/transcript drifted");
        assert_eq!(claim_row, claim_csc, "prover terminal claim drifted");

        let a = apply_block_diag_field(&r1cs.a_0, &z, r1cs.k_log);
        let b = apply_block_diag_field(&r1cs.b_0, &z, r1cs.k_log);
        let eval = |values: &[F128]| {
            let skip =
                crate::zerocheck::multilinear::lagrange_weights_naive(r1cs.k_skip, x_ab.z_skip);
            let rest = build_eq_table(&x_ab.x_inner_rest);
            let outer = build_eq_table(&x_ab.x_outer);
            let inner_mask = (1usize << r1cs.k_log) - 1;
            let skip_mask = (1usize << r1cs.k_skip) - 1;
            values
                .iter()
                .enumerate()
                .fold(F128::ZERO, |acc, (i, value)| {
                    let inner = i & inner_mask;
                    acc + *value
                        * skip[inner & skip_mask]
                        * rest[inner >> r1cs.k_skip]
                        * outer[i >> r1cs.k_log]
                })
        };
        let (v_a, v_b) = (eval(&a), eval(&b));

        let mut ch_verify_row = FsChallenger::new(b"field-row-csc-parity-v0");
        let accepted_row = verify(
            r1cs.m,
            r1cs.k_log,
            r1cs.k_skip,
            &row,
            &x_ab,
            v_a,
            v_b,
            &proof_row,
            &mut ch_verify_row,
        )
        .expect("borrowing row verifier rejected the parity proof");
        let mut ch_verify_csc = FsChallenger::new(b"field-row-csc-parity-v0");
        let accepted_csc = verify(
            r1cs.m,
            r1cs.k_log,
            r1cs.k_skip,
            &csc,
            &x_ab,
            v_a,
            v_b,
            &proof_row,
            &mut ch_verify_csc,
        )
        .expect("legacy CSC verifier rejected the parity proof");

        assert_eq!(accepted_row, claim_row);
        assert_eq!(accepted_row, accepted_csc, "verifier acceptance drifted");
        assert!(
            r1cs.csc_cache.get().is_none(),
            "row verification populated the retained CSC cache",
        );
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
