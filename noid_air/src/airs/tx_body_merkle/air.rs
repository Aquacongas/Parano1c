// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage 3d-0.9 — `TxBodyMerkleAir` (59-instance Poseidon2b stack with
//! pre-MDS binding).
//!
//! # Topology (Option α, 3d-0.9.B)
//!
//! The stack proves **59** Poseidon2b permutations, grouped by sub-sponge:
//!
//! ```text
//!    4 input leaves  × 3 perms = 12
//!    8 output leaves × 2 perms = 16
//!   15 compress nodes × 2 perms = 30
//!    1 wrap          × 1 perm  =  1
//!   -------------------------------
//!   total                       = 59
//! ```
//!
//! Of these, **28 are "heads"** — the first permutation of a sub-sponge,
//! whose pre-MDS row-0 state is a fresh seed (capacity IV + first
//! absorb block, or a compress left-child digest + IV) rather than the
//! previous permutation's output plus an inter-perm XOR absorb.
//!
//! # Column layout
//!
//! | range                 | name              | stride              |
//! |-----------------------|-------------------|---------------------|
//! | 0..30                 | Poseidon perm     | row-major, per-instance |
//! | 30..34                | `pre_s[0..4]`     | head row 0 only     |
//! | 34                    | `head_row_0`      | multi-hot indicator |
//!
//! `pre_s` is four committed witness columns carrying the pre-MDS seed
//! for each head instance on that head's row-0. Row-0 of every head is
//! then tied to `pre_s` via a new MDS binding gate:
//!
//! ```text
//!   s[lane]@head_row_0 + Σ MDS_FULL[lane][j] · pre_s[j]@head_row_0 == 0
//! ```
//!
//! gated by the multi-hot `head_row_0` public-column indicator.
//!
//! Non-head instances leave `pre_s` at zero on their row-0 and will be
//! wired to their predecessor via echo columns in 3d-0.9.E.4 (inter-
//! perm absorb). `head_row_0` is zero on non-head row-0s (so the MDS
//! binding gate is suppressed) and zero everywhere else.
//!
//! # Soundness boundary (end of 3d-0.9.E.3)
//!
//! After E.3 the AIR fully closes the row-0 side of every sub-sponge:
//!
//! - `head_row_0` is hot on **all 28 head row-0s** (12 leaf + 15
//!   compress + 1 wrap) — the MDS-binding gate binds `s@row_0` to
//!   `pre_s@row_0` on every head.
//! - `pre_s[2..3]@every_head_row_0` is pinned by a pair of head-gated
//!   `WeightedLinearGate`s against the capacity-IV public columns
//!   `iv_prog[0..1]` carrying the role's native-sponge IV
//!   (`TAG_LEAF` / `TAG_COMMIT` / `TAG_COMPRESS` / `TAG_TXBODY`). The
//!   gate is `SelectorGate(head_row_0, pre_s[lane] + iv_prog[lane-2] == 0)`,
//!   so on non-head row-0s `pre_s[2..3]` stays **free**; §3d-0.9.E.4
//!   echoes the prior perm's capacity output into those cells.
//! - `pre_s[0..1]@compress_head_row_0` is pinned to the echoed left-
//!   child digest by the `dst_pin` family.
//! - `pre_s[0..1]@leaf_head_row_0` stays a free witness in E.3 and is
//!   pinned to the published tx-body payload in §3d-0.9.H. This is a
//!   **statement boundary**, not a gap: the AIR already proves
//!   "given `pre_s@row_0`, the instance output is
//!   `Poseidon2b(pre_s@row_0)`"; H ties `pre_s@row_0` to public input.
//!
//! The only piece of row-0 binding **not** done in E.3 is the inter-
//! perm continuation (Perm A → Perm B → Perm C). Those row-0 seeds on
//! non-heads are covered in §3d-0.9.E.4; until E.4 lands, the non-head
//! Perm trace is **not** constrained to continue the prior perm's
//! sub-sponge — this is an acknowledged open obligation and blocks
//! end-to-end tx-body soundness.
//!
//! # Row layout
//!
//! One Poseidon2b permutation instance occupies a `SLOT = 128`-row slice
//! (nearest power-of-2 ≥ `N_ROUNDS + 1 = 67`). At 59 instances × 128
//! rows = 7552 live rows, the trace fits in `2^13 = 8192` rows — a
//! 2× halving compared to the 3c-5 `log_rows = 14` stack.

use std::collections::HashMap;
use std::sync::LazyLock;

use crate::airs::poseidon_perm::{
    emit_perm_all_at, emit_perm_public_columns_row_major_at, write_perm_trace_at_offset,
    PermLayout, DEFAULT_PERM_LAYOUT, POSEIDON_PERM_N_COLS,
};
use crate::gates::{
    emit_public_cell, row_indicator_programme, PublicColumn, SelectorGate, WeightedLinearGate,
    WeightedLinearGateShifted,
};
use crate::{Air, ColumnDomain, Constraint, Trace};
use noid_core::{Block128, TowerField};
use noid_poseidon2b::native::domain::{
    capacity_iv, TAG_COMMIT, TAG_COMPRESS, TAG_LEAF, TAG_TXBODY,
};
use noid_poseidon2b::native::permutation::{MDS_FULL, STATE_SIZE};

use super::echo::{allocate_echo_columns, DstPin, EchoAssignments, EchoColumnPlan, EchoTie};
use super::layout::{build_instance_layout, InstanceMeta, InstanceRole};

pub use super::layout::N_INSTANCES as TXBODY_MERKLE_N_PERMS;
pub use noid_poseidon2b::native::permutation::N_ROUNDS;

/// Rows allotted to each permutation instance.
pub const TXBODY_MERKLE_SLOT_ROWS: usize = 128;
pub const TXBODY_MERKLE_SLOT_LOG_ROWS: usize = 7;

/// Total row count: 59 × 128 = 7552 ≤ 2^13 = 8192.
pub const TXBODY_MERKLE_LOG_ROWS: usize = 13;
pub const TXBODY_MERKLE_N_ROWS: usize = 1 << TXBODY_MERKLE_LOG_ROWS;

/// Column base offsets.
pub const TXBODY_MERKLE_PERM_BASE: usize = 0;
pub const TXBODY_MERKLE_PRE_S_BASE: usize = POSEIDON_PERM_N_COLS;
pub const TXBODY_MERKLE_HEAD_ROW_0: usize = TXBODY_MERKLE_PRE_S_BASE + STATE_SIZE;

/// Base of the 2 capacity-IV programme columns `iv_prog[0]` and
/// `iv_prog[1]`, carrying `capacity_iv(role.tag)[0]` / `[1]` on each of
/// the 28 head row-0s and zero elsewhere. Wired to `pre_s[2]` / `pre_s[3]`
/// via a `SelectorGate(head_row_0, pre_s[lane] + iv_prog[lane - 2] == 0)`.
/// Splitting the IV out of `pre_s[2..3]` (vs. pinning `pre_s[2..3]`
/// directly as a PublicColumn) is what leaves the **non-head** row-0
/// cells of `pre_s[2..3]` free so §3d-0.9.E.4 can echo the prior
/// perm's capacity-lane output into them.
pub const TXBODY_MERKLE_IV_PROG_BASE: usize = TXBODY_MERKLE_HEAD_ROW_0 + 1;

/// `any_row_0` multi-hot indicator (ONE on every `slot_base_row` of
/// the 59 instances, zero everywhere else). Introduced in §3d-0.9.E.4.a
/// as the selector for the MDS row-0 binding gate, which previously
/// ran under `head_row_0` only and left non-head row-0 cells
/// unconstrained. With `any_row_0` as selector, every slot's row-0
/// `s[lane]` is bound to its `pre_s[lane]` by `MDS_FULL`, making
/// E.4.a's capacity-lane dst_pin on `pre_s[2..3]` propagate
/// downstream into the permutation.
pub const TXBODY_MERKLE_ANY_ROW_0: usize = TXBODY_MERKLE_IV_PROG_BASE + 2;

/// First column index carrying an echo witness value.
pub const TXBODY_MERKLE_ECHO_BASE: usize = TXBODY_MERKLE_ANY_ROW_0 + 1;

/// Number of echo columns allocated for the left-child digest ties.
/// Currently derived from the 3d-0.9.E.1 enumeration (left-child
/// digest ties only). 3d-0.9.E.4 will extend enumeration with
/// right-child / pad / IV ties.
pub static N_ECHO_COLS: LazyLock<usize> =
    LazyLock::new(|| ECHO_ASSIGNMENTS.columns.len());

/// §3d-0.9.E.4.c — number of leaf non-head rate-lane payload witness
/// columns. Opt E.4.c-1: the 16 leaf non-head instances share two
/// physical columns (one per rate lane 0 / 1); each column carries
/// one payload word at `row_0` of each of the 16 instances and zero
/// elsewhere. The row-gated absorb gate
/// `SelectorGate(single_hot_row_0, pre_s[lane] + echo_prev_out[lane] +
/// payload_lane[lane] == 0)` fires independently on each of the 16
/// row-0s, so physical sharing is constraint-equivalent to 32 separate
/// columns but cuts commit / sumcheck / FRI cost by 30 columns.
///
/// Before §3d-0.9.H lands, these columns are *free* witnesses: the
/// E.4.c gate only checks the 3-term XOR, without pinning `payload`
/// to the §3b-4 tx-body value / owner / tag columns. H will close
/// that tie (see the optimization plan in ROADMAP §3d-0.9.H).
pub const N_LEAF_RATE_PAYLOAD_COLS: usize = 2;

/// Stage 1 — number of single-hot indicator columns added for the
/// O2 / O3 boundary pins. See `CRYPTO.md §Stage 1`:
///
/// - one indicator at `slot_base_row(28)` (O3.a, dead-pair pos=0 PermA)
/// - one indicator at `slot_base_row(42)` (O3.b, dead-pair pos=7 PermA)
/// - one indicator at `slot_base_row(58) + N_ROUNDS` (O2, wrap output)
pub const TXBODY_MERKLE_BOUNDARY_PIN_N_COLS: usize = 3;

/// Stage 1b — number of public columns added for the O1 leaf-payload
/// binding. See ROADMAP §Stage 1b.
///
/// - 1 multi-hot `leaf_perm_a_row_0` selector (hot on the 12 leaf
///   PermA head row-0s).
/// - 2 `o1_prog[0..1]` programme columns carrying the declared
///   absorbed payload values per rate lane. Each column carries the
///   appropriate word on each of the 28 leaf row-0s (12 head + 16
///   non-head) and zero elsewhere.
///
/// Stage 1b scope: binds leaf payload words to the Merkle hash
/// inputs **only**. It does NOT yet prove consistency with
/// TxValidity amounts / owners — that remains Stage 2.
///
/// Stage 1b compression: one extra multi-hot programme column
/// (`leaf_non_head_row_0`) replaces 16 per-row single-hot gates; the
/// 32 non-head pin constraints collapse into 2 SelectorGates.
pub const TXBODY_MERKLE_O1_N_COLS: usize = 4;

/// Stage 1b — expected padding word for the second rate lane of the
/// input-leaf `finalize` permutation (PermC). The native sponge
/// triggers `fill_padding` on an empty 32-byte buffer, producing
/// `[0x80, 0, …, 0, 0x01]` which split into two 16-byte rate lanes
/// yields `PAD0 = 0x80` in lane 0 and `PAD1 = 1 << 120` in lane 1.
pub const O1_INPUT_LEAF_PAD_WORD_0: u128 = 0x80u128;
pub const O1_INPUT_LEAF_PAD_WORD_1: u128 = 1u128 << 120;

/// Stage 1b — expected padding word for the second rate lane of the
/// output-leaf `finalize` permutation (PermB). After absorbing
/// `owner_lo` into rate lane 0 the buffer has 16 bytes free in the
/// upper half; `fill_padding` sets byte 0 = `0x80` and byte 15 =
/// `0x01` of that slice, yielding the little-endian word
/// `0x80 | (1 << 120)`.
pub const O1_OUTPUT_LEAF_PAD_WORD: u128 = 0x80u128 | (1u128 << 120);

/// Post-order instance ids of the four cells pinned by Stage 1. Asserted
/// against the layout at AIR-construction time (see
/// `emit_tx_body_merkle_constraints_with_boundary_pins`).
const BOUNDARY_INSTANCE_POS_0_PERM_A: usize = 28;
const BOUNDARY_INSTANCE_POS_0_PERM_B: usize = 29;
const BOUNDARY_INSTANCE_POS_7_PERM_A: usize = 42;
const BOUNDARY_INSTANCE_WRAP: usize = 58;

/// Total committed column count.
///
/// | range    | width           | purpose                     |
/// |----------|-----------------|-----------------------------|
/// | perm     | 30              | Poseidon2b permutation lane |
/// | pre_s    | 4               | row-0 pre-MDS seed          |
/// | head     | 1               | head_row_0 multi-hot        |
/// | iv_prog  | 2               | capacity-IV programme per lane (2..3) |
/// | any_r0   | 1               | multi-hot on every slot_base_row |
/// | echo     | `*N_ECHO_COLS`  | echo witnesses              |
///
/// Note: the `transition` / `src_pin` / `dst_pin` selector programmes
/// are appended at emission time as public columns *after* this base
/// range; `TXBODY_MERKLE_N_COLS` tracks the total width (witness + public)
/// including those programmes via [`ECHO_MASK_COLUMNS`].
pub static TXBODY_MERKLE_N_COLS: LazyLock<usize> = LazyLock::new(|| {
    TXBODY_MERKLE_ECHO_BASE
        + *N_ECHO_COLS
        + ECHO_MASK_COLUMNS.total
        + N_LEAF_RATE_PAYLOAD_COLS
});

/// Base column index for the §3d-0.9.E.4.c leaf-rate payload witness
/// block. Sits at the very tail of the committed column layout so that
/// §3d-0.9.H may either pin each payload column to a §3b-4 tx-body
/// column (keeping these as independent witnesses) or fold them away
/// entirely (per Opt H-1). Index is computed lazily because
/// `*N_ECHO_COLS` and `ECHO_MASK_COLUMNS.total` are LazyLock.
pub static TXBODY_MERKLE_PAYLOAD_BASE: LazyLock<usize> =
    LazyLock::new(|| TXBODY_MERKLE_ECHO_BASE + *N_ECHO_COLS + ECHO_MASK_COLUMNS.total);

/// Stage 1 — column index at which the three boundary-pin indicator
/// columns start. Sits at the tail of the legacy trace width, only
/// allocated when the caller constructs `TxBodyMerkleAir` via
/// [`TxBodyMerkleAir::new_with_boundary_pins`].
pub static TXBODY_MERKLE_BOUNDARY_PIN_BASE: LazyLock<usize> =
    LazyLock::new(|| *TXBODY_MERKLE_PAYLOAD_BASE + N_LEAF_RATE_PAYLOAD_COLS);

/// Stage 1 — total committed column count when boundary pins are
/// attached. Legacy `TxBodyMerkleAir::new()` ignores this and keeps
/// the pre-Stage-1 width `*TXBODY_MERKLE_N_COLS`.
///
/// Stage 1b piggy-backs on the boundary-pin constructor: its three
/// public columns (`leaf_perm_a_row_0` + two `o1_prog[0..1]`
/// programmes) are appended immediately after the boundary-pin
/// indicators. `TxBodyMerkleAir::new()` without pins stays at the
/// pre-Stage-1 width.
pub static TXBODY_MERKLE_N_COLS_WITH_BOUNDARY_PINS: LazyLock<usize> = LazyLock::new(|| {
    *TXBODY_MERKLE_N_COLS + TXBODY_MERKLE_BOUNDARY_PIN_N_COLS + TXBODY_MERKLE_O1_N_COLS
});

/// Stage 1b — base column index of the `leaf_perm_a_row_0` multi-hot
/// selector. The two `o1_prog[0..1]` programme columns sit at
/// `+1` and `+2`.
pub static TXBODY_MERKLE_O1_BASE: LazyLock<usize> =
    LazyLock::new(|| *TXBODY_MERKLE_PAYLOAD_BASE + N_LEAF_RATE_PAYLOAD_COLS
        + TXBODY_MERKLE_BOUNDARY_PIN_N_COLS);
pub const TXBODY_MERKLE_O1_LEAF_PERM_A_ROW_0_OFFSET: usize = 0;
pub const TXBODY_MERKLE_O1_PROG_BASE_OFFSET: usize = 1;
/// Stage 1b compression — offset of the `leaf_non_head_row_0`
/// multi-hot selector (ONE on the 16 leaf non-head row-0 positions,
/// ZERO elsewhere). Lets the 16 per-row non-head pins share a single
/// SelectorGate per lane.
pub const TXBODY_MERKLE_O1_LEAF_NON_HEAD_ROW_0_OFFSET: usize = 3;

/// Stage 1 — three verifier-known constants that bind the AIR to the
/// tx-body layer. See `CRYPTO.md §Stage 1` for the pin catalogue and
/// soundness argument. Each field stores the little-endian
/// [`Block128; 2`] representation of a 32-byte digest (as produced by
/// `noid_poseidon2b::primitives::{Address, TxBodyHash}::as_fields`).
#[derive(Debug, Clone, Copy, Default)]
pub struct TxBodyMerkleBoundaryPins {
    /// L0 of the tx-body Merkle tree, pinned into
    /// `pre_s[0..1] @ slot_base_row(28)`.
    pub prev_state_root: [Block128; 2],
    /// L1 of the tx-body Merkle tree. Injected as the constant term of
    /// the existing pos=0 PermB rate-absorb gate (instance 29).
    pub fee_leaf: [Block128; 2],
    /// Canonical tx-body hash; pinned into `s[0..1]` at the wrap
    /// instance's post-MDS output row (instance 58).
    pub tx_body_hash: [Block128; 2],
    /// Stage 1b — declared absorbed payload for each of the 4 input
    /// leaves. `input_leaf_absorb[leaf][word]` holds the four
    /// `hash_leaf([slot, value, owner_hi, owner_lo])` field inputs in
    /// canonical order. Word 0/1 are absorbed into PermA's
    /// `pre_s[0..1]`; word 2/3 appear at PermB's `payload[0..1]`.
    pub input_leaf_absorb: [[Block128; 4]; 4],
    /// Stage 1b — declared absorbed payload for each of the 8 output
    /// leaves (`hash_utxo_leaf(value, owner)`). Word 0 = value, word 1
    /// = owner_hi (absorbed into PermA's `pre_s[0..1]`); word 2 =
    /// owner_lo (appears at PermB's `payload[0]`).
    pub output_leaf_absorb: [[Block128; 3]; 8],
}

/// Enumerate leaf non-head instances whose rate lanes 0..1 absorb a
/// payload chunk on row-0. Returns the 16 instance ids in `layout`
/// order (InputLeafPermB / PermC + OutputLeafPermB).
pub fn leaf_rate_absorb_instance_ids(layout: &[InstanceMeta]) -> Vec<usize> {
    layout
        .iter()
        .enumerate()
        .filter_map(|(id, m)| {
            matches!(
                m.role,
                InstanceRole::InputLeafPermB { .. }
                    | InstanceRole::InputLeafPermC { .. }
                    | InstanceRole::OutputLeafPermB { .. }
            )
            .then_some(id)
        })
        .collect()
}

/// Column carrying leaf-rate payload chunks for `lane ∈ {0, 1}`.
/// Under Opt E.4.c-1, all 16 leaf non-head instances share this single
/// column per lane: each instance's payload lives at its own `row_0`
/// and every row-gated absorb gate reads only that slot. `slot`
/// (0..16) is retained in the API signature so callers keep the
/// per-instance indexing convention; it is asserted in-range but no
/// longer influences the column index.
#[inline]
pub fn leaf_rate_payload_col(leaf_rate_slot: usize, lane: usize) -> usize {
    debug_assert!(leaf_rate_slot < 16);
    debug_assert!(lane < 2);
    *TXBODY_MERKLE_PAYLOAD_BASE + lane
}

/// Union of every echo tie class shipped so far:
///
/// - §3d-0.9.E.1: left-child-digest ties on compress / wrap Perm A.
/// - §3d-0.9.E.4.a: capacity-lane continuation ties on every
///   non-head perm (lanes 2..3).
///
/// E.4.b (compress rate-lane absorb with right-child) and E.4.c
/// (leaf-sponge rate-lane absorb with payload witness) are pending.
pub fn enumerate_all_ties(layout: &[InstanceMeta]) -> Vec<EchoTie> {
    let mut ties = enumerate_child_digest_ties(layout);
    ties.extend(enumerate_capacity_continuation_ties(layout));
    ties.extend(enumerate_compress_rate_continuation_ties(layout));
    ties.extend(enumerate_leaf_rate_continuation_ties(layout));
    ties
}

/// One-shot echo allocation, deterministic at process start.
pub static ECHO_ASSIGNMENTS: LazyLock<EchoAssignments> = LazyLock::new(|| {
    let layout = build_instance_layout();
    let ties = enumerate_all_ties(&layout);
    allocate_echo_columns(&ties).expect("echo allocator on honest layout must succeed")
});

/// All ties enumerated for the current shipped subset, deterministic.
pub static ECHO_TIES: LazyLock<Vec<EchoTie>> = LazyLock::new(|| {
    let layout = build_instance_layout();
    enumerate_all_ties(&layout)
});

/// Per-gate selector programme assignments and column layout after the
/// echo mask block. Produced by [`plan_echo_mask_columns`] from the
/// allocator output + tie list; memoised so the AIR, trace builder, and
/// public-column emitter agree on the same programmes.
pub static ECHO_MASK_COLUMNS: LazyLock<EchoMaskPlan> =
    LazyLock::new(|| plan_echo_mask_columns(&ECHO_ASSIGNMENTS, &ECHO_TIES));

/// A single multi-hot programme referenced by one or more gates. The
/// `hot_rows` vector uses deterministic sort order so two identical
/// programmes compare equal under `Eq`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct EchoMaskProgramme {
    hot_rows: Vec<usize>,
}

impl EchoMaskProgramme {
    fn from_rows(mut hot_rows: Vec<usize>) -> Self {
        hot_rows.sort_unstable();
        hot_rows.dedup();
        Self { hot_rows }
    }

    fn to_vec(&self, total_rows: usize) -> Vec<Block128> {
        let mut out = vec![Block128::ZERO; total_rows];
        for &r in &self.hot_rows {
            if r < total_rows {
                out[r] = Block128::ONE;
            }
        }
        out
    }
}

/// Resolved mask-column layout.
///
/// `total` is the count of **distinct** mask programmes after Opt 6
/// de-duplication. The per-echo-column `transition_col` gives the
/// committed column index carrying the `hold_mask` programme for that
/// echo; `src_pin_col[t]` gives the column for tie `t`'s `src_mask`.
/// All indices are relative to [`Air::n_columns`] and point into the
/// tail of the public-column emission.
#[derive(Debug, Clone)]
pub struct EchoMaskPlan {
    /// Distinct programmes in emission order.
    programmes: Vec<EchoMaskProgramme>,
    /// `transition_col[c]` — column index of `hold_mask` for echo c.
    transition_col: Vec<usize>,
    /// `src_pin_col[t]` — column index of `src_mask` for tie t.
    src_pin_col: Vec<usize>,
    /// `dst_pin_col[t][i]` — column index of `dst_mask` for the
    /// i-th dst pin of tie t. Under Opt 6, two dst pins at the same
    /// `dst_row` share the same column even if they belong to
    /// different ties.
    dst_pin_col: Vec<Vec<usize>>,
    /// Single-hot-row → column index. Populated by `plan_echo_mask_columns`
    /// for every `[row]` programme interned as a `src_pin` or `dst_pin`
    /// mask. Used by §3d-0.9.E.4.b to gate the 3-term rate-absorb gate
    /// on `b.slot_base_row` without emitting a new mask column (the
    /// programme is already interned by E.4.a's dst_pin on lanes 2..3
    /// of the same instance).
    single_hot_col: HashMap<usize, usize>,
    /// Total width of this block; equals `programmes.len()`.
    pub total: usize,
}

/// Programme-hash de-dup (Opt 6) plus Opt 7 (no unused `active_ind`):
/// emits one [`PublicColumn`] per distinct `hot_rows` set, pointing
/// multiple gates at the same physical column when their selector
/// programmes coincide. `transition` for echo `c` is hot on
/// `[src_row, max_dst_row - 1]` across every epoch; `src_pin` for tie
/// `t` is hot on the single row `src_row`.
fn plan_echo_mask_columns(
    assignments: &EchoAssignments,
    ties: &[EchoTie],
) -> EchoMaskPlan {
    let mask_base = TXBODY_MERKLE_ECHO_BASE + assignments.columns.len();
    let mut seen: HashMap<EchoMaskProgramme, usize> = HashMap::new();
    let mut programmes: Vec<EchoMaskProgramme> = Vec::new();
    let mut single_hot_col: HashMap<usize, usize> = HashMap::new();
    let intern = |p: EchoMaskProgramme,
                      programmes: &mut Vec<EchoMaskProgramme>,
                      seen: &mut HashMap<EchoMaskProgramme, usize>,
                      single_hot_col: &mut HashMap<usize, usize>|
     -> usize {
        if let Some(&idx) = seen.get(&p) {
            return idx;
        }
        let idx = programmes.len();
        if p.hot_rows.len() == 1 {
            single_hot_col.insert(p.hot_rows[0], mask_base + idx);
        }
        seen.insert(p.clone(), idx);
        programmes.push(p);
        idx
    };

    let mut transition_col = Vec::with_capacity(assignments.columns.len());
    for plan in &assignments.columns {
        let hot = hold_mask_hot_rows(plan);
        let idx = intern(
            EchoMaskProgramme::from_rows(hot),
            &mut programmes,
            &mut seen,
            &mut single_hot_col,
        );
        transition_col.push(mask_base + idx);
    }

    let mut src_pin_col = Vec::with_capacity(ties.len());
    for tie in ties {
        let idx = intern(
            EchoMaskProgramme::from_rows(vec![tie.src_row]),
            &mut programmes,
            &mut seen,
            &mut single_hot_col,
        );
        src_pin_col.push(mask_base + idx);
    }

    let mut dst_pin_col: Vec<Vec<usize>> = Vec::with_capacity(ties.len());
    for tie in ties {
        let mut per_tie = Vec::with_capacity(tie.dst_pins.len());
        for pin in &tie.dst_pins {
            let idx = intern(
                EchoMaskProgramme::from_rows(vec![pin.dst_row]),
                &mut programmes,
                &mut seen,
                &mut single_hot_col,
            );
            per_tie.push(mask_base + idx);
        }
        dst_pin_col.push(per_tie);
    }

    // §3d-0.9.E.4.b live_consumer rows that did not get an automatic
    // interning via src/dst pins — intern them here so the rate-absorb
    // gate can look up a single-hot selector column by row.
    for tie in ties {
        for &row in &tie.live_consumers {
            intern(
                EchoMaskProgramme::from_rows(vec![row]),
                &mut programmes,
                &mut seen,
                &mut single_hot_col,
            );
        }
    }

    EchoMaskPlan {
        total: programmes.len(),
        programmes,
        transition_col,
        src_pin_col,
        dst_pin_col,
        single_hot_col,
    }
}

impl EchoMaskPlan {
    /// Column index of the single-hot mask programme for `row`, if one
    /// has been interned (either as a src_pin / dst_pin or as a live
    /// consumer). Used by §3d-0.9.E.4.b to gate the rate-absorb gate.
    pub fn single_hot_col(&self, row: usize) -> Option<usize> {
        self.single_hot_col.get(&row).copied()
    }
}

fn hold_mask_hot_rows(plan: &EchoColumnPlan) -> Vec<usize> {
    let mut rows = Vec::new();
    for epoch in &plan.epochs {
        for row in epoch.src_row..epoch.max_dst_row {
            rows.push(row);
        }
    }
    rows
}

pub const TXBODY_MERKLE_LAYOUT: PermLayout = DEFAULT_PERM_LAYOUT;

/// Row offset of instance `k`'s first row.
#[inline]
pub const fn instance_row_offset(k: usize) -> usize {
    k * TXBODY_MERKLE_SLOT_ROWS
}

/// Build an honest witness trace.
///
/// Per §3d-0.9.E.3, every head row-0 is fully populated:
/// - `pre_s[0..1]` is the caller's input on leaf heads, the echoed
///   left-child Perm output digest on compress / wrap heads (for dead-
///   pair compress heads with no AIR child, the caller's input passes
///   through and is payload-pinned in §3d-0.9.H).
/// - `pre_s[2..3]` is the role's capacity-IV (pinned by the
///   capacity-IV PublicColumns).
/// - `head_row_0` is ONE on all 28 heads, activating the MDS binding
///   gate on every head row-0.
pub fn build_tx_body_merkle_trace(
    inputs: &[[Block128; STATE_SIZE]; TXBODY_MERKLE_N_PERMS],
) -> Vec<Vec<Block128>> {
    build_tx_body_merkle_trace_inner(inputs, None)
}

fn build_tx_body_merkle_trace_inner(
    inputs: &[[Block128; STATE_SIZE]; TXBODY_MERKLE_N_PERMS],
    pins: Option<&TxBodyMerkleBoundaryPins>,
) -> Vec<Vec<Block128>> {
    let n_cols = *TXBODY_MERKLE_N_COLS;
    let mut cols: Vec<Vec<Block128>> = (0..n_cols)
        .map(|_| vec![Block128::ZERO; TXBODY_MERKLE_N_ROWS])
        .collect();

    let layout = build_instance_layout();
    for (k, input) in inputs.iter().enumerate() {
        let row_offset = instance_row_offset(k);
        let meta = &layout[k];

        // For compress / wrap heads, override the top two lanes of the
        // input with the left child's Perm output digest — that is the
        // echo-fed seed the `dst_pin` family will constrain. Capacity-IV
        // lanes (2..4) still come from `inputs[k]` until §3d-0.9.E.4
        // installs the capacity-IV pins.
        let mut effective_input = effective_perm_input(meta, *input, &cols, k);
        // O3.c: instance 29 (pos=0 PermB) dead-pair right-child absorb
        // injects `fee_leaf[lane]` into rate lanes 0..1 so the modified
        // absorb gate `pre_s_B + echo_prev_A + fee_leaf == 0` holds.
        if let Some(p) = pins {
            if k == BOUNDARY_INSTANCE_POS_0_PERM_B {
                for lane in 0..2 {
                    effective_input[lane] = effective_input[lane] + p.fee_leaf[lane];
                }
            }
            // Stage 1b — O1 leaf head rate-lane override. Force the
            // pre_s[0..1] cell to carry the declared absorbed payload
            // word so the head-pin gate `pre_s == o1_prog` holds.
            match meta.role {
                InstanceRole::InputLeafPermA { leaf_idx } => {
                    for lane in 0..2 {
                        effective_input[lane] =
                            p.input_leaf_absorb[leaf_idx as usize][lane];
                    }
                }
                InstanceRole::OutputLeafPermA { leaf_idx } => {
                    for lane in 0..2 {
                        effective_input[lane] =
                            p.output_leaf_absorb[leaf_idx as usize][lane];
                    }
                }
                // Stage 1b — O1 leaf non-head rate-lane override. The
                // payload column is derived as `pre_s + prev_out`; to
                // make it equal the declared payload word the caller's
                // input to `pre_s[lane]` must be `prev_out + declared`.
                InstanceRole::InputLeafPermB { leaf_idx } => {
                    let prev_row = (k - 1) * TXBODY_MERKLE_SLOT_ROWS + N_ROUNDS;
                    for lane in 0..2 {
                        let prev_out =
                            cols[TXBODY_MERKLE_LAYOUT.s + lane][prev_row];
                        effective_input[lane] =
                            prev_out + p.input_leaf_absorb[leaf_idx as usize][2 + lane];
                    }
                }
                InstanceRole::InputLeafPermC { .. } => {
                    let prev_row = (k - 1) * TXBODY_MERKLE_SLOT_ROWS + N_ROUNDS;
                    let pad = [
                        Block128::from(O1_INPUT_LEAF_PAD_WORD_0),
                        Block128::from(O1_INPUT_LEAF_PAD_WORD_1),
                    ];
                    for lane in 0..2 {
                        let prev_out =
                            cols[TXBODY_MERKLE_LAYOUT.s + lane][prev_row];
                        effective_input[lane] = prev_out + pad[lane];
                    }
                }
                InstanceRole::OutputLeafPermB { leaf_idx } => {
                    let prev_row = (k - 1) * TXBODY_MERKLE_SLOT_ROWS + N_ROUNDS;
                    let declared = [
                        p.output_leaf_absorb[leaf_idx as usize][2],
                        Block128::from(O1_OUTPUT_LEAF_PAD_WORD),
                    ];
                    for lane in 0..2 {
                        let prev_out =
                            cols[TXBODY_MERKLE_LAYOUT.s + lane][prev_row];
                        effective_input[lane] = prev_out + declared[lane];
                    }
                }
                _ => {}
            }
        }
        write_perm_trace_at_offset(
            &mut cols,
            TXBODY_MERKLE_LAYOUT,
            effective_input,
            row_offset,
        );

        // pre_s@row_offset mirrors the effective input on every head
        // row-0: lanes 0..1 come from the caller (leaf) or the echoed
        // left-child digest (compress/wrap); lanes 2..3 are the role's
        // capacity IV. The MDS-binding gate then ties `s@row_0` to
        // these four cells, and the capacity-IV PublicColumns ensure
        // `pre_s[2..3]` matches the declared IV on every head.
        cols[TXBODY_MERKLE_ANY_ROW_0][row_offset] = Block128::ONE;

        // pre_s@row_0 mirrors the effective input on every slot (head
        // and non-head). On head row-0, lanes 2..3 are the role's IV.
        // On non-head row-0, lanes 2..3 echo the prior perm's capacity
        // output (§3d-0.9.E.4.a); rate lanes 0..1 will be pinned by
        // the absorb-based ties of §3d-0.9.E.4.b / E.4.c.
        for lane in 0..STATE_SIZE {
            cols[TXBODY_MERKLE_PRE_S_BASE + lane][row_offset] =
                effective_input[lane];
        }
        if meta.is_head {
            cols[TXBODY_MERKLE_HEAD_ROW_0][row_offset] = Block128::ONE;
            if let Some(iv) = head_capacity_iv(&meta.role) {
                cols[TXBODY_MERKLE_IV_PROG_BASE][row_offset] = iv[0];
                cols[TXBODY_MERKLE_IV_PROG_BASE + 1][row_offset] = iv[1];
            }
        }
    }

    // Echo columns.
    //
    // Each echo column carries the value `cols[src_col][src_row]` across
    // every row of its live interval `[src_row, max_dst_row]` for every
    // epoch on that column, zero on suppressed (inter-epoch) rows.
    // The `transition` gate is selector-gated by a `hold_mask` public
    // programme built from the same epoch list, so no witness indicator
    // is needed (§3d-0.9.E.2, Opt 7).
    let assignments = &*ECHO_ASSIGNMENTS;
    let ties = &*ECHO_TIES;
    for (col_idx, plan) in assignments.columns.iter().enumerate() {
        let echo_col = TXBODY_MERKLE_ECHO_BASE + col_idx;
        for (epoch_idx, &tie_id) in plan.tie_ids.iter().enumerate() {
            let tie = &ties[tie_id];
            let epoch = plan.epochs[epoch_idx];
            let value = cols[tie.src_col][tie.src_row];
            for row in epoch.src_row..=epoch.max_dst_row {
                cols[echo_col][row] = value;
            }
        }
    }

    // §3d-0.9.E.4.c — leaf rate-lane payload witness. For every leaf
    // non-head (InputLeafPermB / C, OutputLeafPermB), write the payload
    // value that satisfies the absorb gate
    //     pre_s[lane] + prev_out_A_or_B[lane] + payload[lane] == 0
    // on that instance's row-0. Before §3d-0.9.H, `payload` is a free
    // witness — the honest builder derives it from `pre_s` (= caller's
    // input on leaf non-heads) and the prior perm's rate-lane output.
    let leaf_rate_ids = leaf_rate_absorb_instance_ids(&layout);
    for (slot, &id) in leaf_rate_ids.iter().enumerate() {
        let meta = &layout[id];
        let prev = &layout[id - 1];
        let prev_out_row = prev.slot_base_row + N_ROUNDS;
        let b_row_0 = meta.slot_base_row;
        for lane in 0..2usize {
            let pre_s = cols[TXBODY_MERKLE_PRE_S_BASE + lane][b_row_0];
            let prev_out = cols[TXBODY_MERKLE_LAYOUT.s + lane][prev_out_row];
            let payload = pre_s + prev_out;
            cols[leaf_rate_payload_col(slot, lane)][b_row_0] = payload;
        }
    }

    // Mask programme cells. These are public columns and `Air::check`
    // native-verifies each trace cell matches the declared programme,
    // so the honest trace builder has to write the multi-hot ONEs into
    // place (same contract as `head_row_0`).
    let mask = &*ECHO_MASK_COLUMNS;
    let mask_base = TXBODY_MERKLE_ECHO_BASE + *N_ECHO_COLS;
    for (i, programme) in mask.programmes.iter().enumerate() {
        let col = mask_base + i;
        for &row in &programme.hot_rows {
            if row < TXBODY_MERKLE_N_ROWS {
                cols[col][row] = Block128::ONE;
            }
        }
    }

    cols
}

/// Per-column `ColumnDomain` tag for the Stage 3d-0.9 trace.
///
/// Most witness / public columns carry bit-valued programmes that the
/// DA / commitment layer can pack 128x. Returning these to the caller
/// as a `Bit`-domain tag is soundness-neutral (AIR evaluation always
/// lifts to `Block128`) but collapses the physical commitment width of
/// the 20+ mask / indicator / perm-selector columns by a factor of 128.
///
/// The tagging rules:
///
/// - Poseidon perm block: `is_full`, `is_round` → `Bit`; all other
///   lanes (`s`, `sin`, `x2`, `x4`, `x3`, `sout`, `rc[0..4]`) → `Block128`.
/// - `pre_s[0..4]` → `Block128` (full digest words).
/// - `head_row_0` → `Bit`.
/// - Echo witness columns → `Block128` (carry full digest words).
/// - Echo mask programme columns → `Bit` (single-hot / multi-hot
///   indicators).
pub fn tx_body_merkle_column_domains() -> Vec<ColumnDomain> {
    let n = *TXBODY_MERKLE_N_COLS;
    let mut domains = vec![ColumnDomain::Block128; n];
    domains[TXBODY_MERKLE_LAYOUT.is_full] = ColumnDomain::Bit;
    domains[TXBODY_MERKLE_LAYOUT.is_round] = ColumnDomain::Bit;
    domains[TXBODY_MERKLE_HEAD_ROW_0] = ColumnDomain::Bit;
    domains[TXBODY_MERKLE_ANY_ROW_0] = ColumnDomain::Bit;
    let mask_base = TXBODY_MERKLE_ECHO_BASE + *N_ECHO_COLS;
    for i in 0..ECHO_MASK_COLUMNS.total {
        domains[mask_base + i] = ColumnDomain::Bit;
    }
    domains
}

/// Build an honest trace, tagged with [`tx_body_merkle_column_domains`].
pub fn build_tx_body_merkle_typed_trace(
    inputs: &[[Block128; STATE_SIZE]; TXBODY_MERKLE_N_PERMS],
) -> Trace {
    Trace::new_with_domains(
        build_tx_body_merkle_trace(inputs),
        tx_body_merkle_column_domains(),
    )
}

/// Stage 1 — column-domain tagger with `Bit` tags for the three
/// boundary-pin indicator columns appended at the tail. Stage 1b
/// appends the `leaf_perm_a_row_0` multi-hot selector as `Bit` and
/// leaves the two `o1_prog[0..1]` programme columns as `Block128`
/// (they carry full digest-word values).
pub fn tx_body_merkle_column_domains_with_boundary_pins() -> Vec<ColumnDomain> {
    let mut domains = tx_body_merkle_column_domains();
    domains.resize(
        *TXBODY_MERKLE_N_COLS_WITH_BOUNDARY_PINS,
        ColumnDomain::Block128,
    );
    let pin_base = *TXBODY_MERKLE_BOUNDARY_PIN_BASE;
    for i in 0..TXBODY_MERKLE_BOUNDARY_PIN_N_COLS {
        domains[pin_base + i] = ColumnDomain::Bit;
    }
    domains[*TXBODY_MERKLE_O1_BASE + TXBODY_MERKLE_O1_LEAF_PERM_A_ROW_0_OFFSET] =
        ColumnDomain::Bit;
    domains[*TXBODY_MERKLE_O1_BASE + TXBODY_MERKLE_O1_LEAF_NON_HEAD_ROW_0_OFFSET] =
        ColumnDomain::Bit;
    domains
}

/// Stage 1 — honest trace builder with boundary pins attached.
///
/// 1. Overrides the dead-pair compress heads' rate lanes in
///    `inputs[28]` and `inputs[42]` so the permutation runs on the
///    pinned seeds (keeps `s@row_0`, `pre_s@row_0` and every downstream
///    cell internally consistent with the O3.a / O3.b pins).
/// 2. Calls the inner builder with `Some(pins)` so instance 29's
///    rate input absorbs `fee_leaf[lane]` (O3.c).
/// 3. Widens the column set to include the three single-hot boundary-
///    pin indicators, each hot on exactly one row.
///
/// The wrap output at `s[0..1] @ instance 58 row N_ROUNDS` is produced
/// honestly by `write_perm_trace_at_offset`; the caller must supply an
/// input chain that actually hashes down to `pins.tx_body_hash`, else
/// the O2 pin fails at `Air::check` time. See the round-trip test for
/// the canonical pin-derivation path.
pub fn build_tx_body_merkle_trace_with_boundary_pins(
    inputs: &[[Block128; STATE_SIZE]; TXBODY_MERKLE_N_PERMS],
    pins: &TxBodyMerkleBoundaryPins,
) -> Vec<Vec<Block128>> {
    let mut inputs_pinned = *inputs;
    for lane in 0..2usize {
        inputs_pinned[BOUNDARY_INSTANCE_POS_0_PERM_A][lane] = pins.prev_state_root[lane];
        inputs_pinned[BOUNDARY_INSTANCE_POS_7_PERM_A][lane] = Block128::ZERO;
    }
    let mut cols = build_tx_body_merkle_trace_inner(&inputs_pinned, Some(pins));
    cols.resize(
        *TXBODY_MERKLE_N_COLS_WITH_BOUNDARY_PINS,
        vec![Block128::ZERO; TXBODY_MERKLE_N_ROWS],
    );
    let layout = build_instance_layout();
    let pin_base = *TXBODY_MERKLE_BOUNDARY_PIN_BASE;
    cols[pin_base][layout[BOUNDARY_INSTANCE_POS_0_PERM_A].slot_base_row] = Block128::ONE;
    cols[pin_base + 1][layout[BOUNDARY_INSTANCE_POS_7_PERM_A].slot_base_row] = Block128::ONE;
    cols[pin_base + 2]
        [layout[BOUNDARY_INSTANCE_WRAP].slot_base_row + N_ROUNDS] = Block128::ONE;

    // Stage 1b — O1 public-column cell values. `leaf_perm_a_row_0` is
    // multi-hot on the 12 leaf PermA head rows; `o1_prog[lane]`
    // carries the declared payload word on each of the 28 leaf
    // row-0s.
    let o1_base = *TXBODY_MERKLE_O1_BASE;
    let selector_programme = leaf_perm_a_row_0_programme();
    for (row, v) in selector_programme.iter().enumerate() {
        cols[o1_base + TXBODY_MERKLE_O1_LEAF_PERM_A_ROW_0_OFFSET][row] = *v;
    }
    let non_head_programme = leaf_non_head_row_0_programme();
    for (row, v) in non_head_programme.iter().enumerate() {
        cols[o1_base + TXBODY_MERKLE_O1_LEAF_NON_HEAD_ROW_0_OFFSET][row] = *v;
    }
    for lane in 0..2usize {
        let prog = o1_payload_programme(pins, lane);
        for (row, v) in prog.iter().enumerate() {
            cols[o1_base + TXBODY_MERKLE_O1_PROG_BASE_OFFSET + lane][row] = *v;
        }
    }
    cols
}

/// Extract instance `k`'s permutation output.
pub fn extract_instance_output(
    cols: &[Vec<Block128>],
    k: usize,
) -> [Block128; STATE_SIZE] {
    let row = instance_row_offset(k) + N_ROUNDS;
    let mut out = [Block128::ZERO; STATE_SIZE];
    for lane in 0..STATE_SIZE {
        out[lane] = cols[TXBODY_MERKLE_LAYOUT.s + lane][row];
    }
    out
}

/// Build the `head_row_0` multi-hot indicator programme.
///
/// Hot on all 28 head row-0s (12 leaf Perm A + 15 compress Perm A + 1
/// wrap). The MDS-binding gate `s[lane] = Σ MDS[lane][j] · pre_s[j]`
/// therefore fires on every head row-0, binding `s@row_0` to `pre_s@row_0`
/// unconditionally. Per-lane pinning of `pre_s@row_0` is split across
/// three mechanisms:
///
/// - `pre_s[0..1]@compress/wrap_head_row_0` — pinned to the echoed
///   left-child digest via the `dst_pin` family (§3d-0.9.E.3).
/// - `pre_s[2..3]@every_head_row_0` — pinned to the role's capacity IV
///   via the `capacity_iv_pin` PublicColumn family (§3d-0.9.E.3, this
///   sub-stage).
/// - `pre_s[0..1]@leaf_head_row_0` — stays a free witness inside E.3;
///   §3d-0.9.H pins it to the published tx-body payload.
///
/// Soundness boundary at the end of E.3: the AIR proves "for every head
/// row-0, `s@row_0 = MDS · pre_s@row_0` where `pre_s[2..3]` is the
/// declared IV and `pre_s[0..1]` of compress/wrap heads is the echoed
/// child digest". The inter-perm absorb between Perm A / B / C is
/// closed in §3d-0.9.E.4; leaf-payload binding is closed in §3d-0.9.H.
pub fn head_row_0_programme() -> Vec<Block128> {
    let mut out = vec![Block128::ZERO; TXBODY_MERKLE_N_ROWS];
    let layout = build_instance_layout();
    for (k, meta) in layout.iter().enumerate() {
        if meta.is_head {
            out[instance_row_offset(k)] = Block128::ONE;
        }
    }
    out
}

/// `any_row_0` multi-hot programme — ONE at `slot_base_row` of every
/// one of the 59 instances, zero elsewhere. Selector for the MDS
/// row-0 binding gate under §3d-0.9.E.4.a.
pub fn any_row_0_programme() -> Vec<Block128> {
    let mut out = vec![Block128::ZERO; TXBODY_MERKLE_N_ROWS];
    for k in 0..TXBODY_MERKLE_N_PERMS {
        out[instance_row_offset(k)] = Block128::ONE;
    }
    out
}

/// Returns `true` for the 12 leaf-head roles whose `pre_s[0..2]@row_0`
/// is public-input-seeded at AIR-build time (input-leaf / output-leaf
/// Perm A). On these rows `pre_s[0..2]` remains a free witness in
/// §3d-0.9.E — 3d-0.9.H pins those cells to the published tx-body
/// payload (slot/value/owner/…). `pre_s[2..3]` is pinned here as a
/// PublicColumn carrying the role's capacity IV.
///
/// Compress / wrap heads have their `pre_s[0..1]` wired to the echoed
/// child digest via the `dst_pin` family, and `pre_s[2..3]` to the
/// same capacity-IV public columns.
fn is_leaf_head(role: &InstanceRole) -> bool {
    matches!(
        role,
        InstanceRole::InputLeafPermA { .. } | InstanceRole::OutputLeafPermA { .. }
    )
}

/// Capacity-IV seed `(pre_s[2], pre_s[3])` for the head row-0 of
/// instance with role `role`. Every head-role maps to exactly one
/// capacity IV:
///
/// | role                 | sub-sponge tag | pre_s[2..3] seed          |
/// |----------------------|----------------|---------------------------|
/// | `InputLeafPermA`     | `LEAF____`     | `capacity_iv(TAG_LEAF)`   |
/// | `OutputLeafPermA`    | `COMMIT__`     | `capacity_iv(TAG_COMMIT)` |
/// | `CompressPermA`      | `COMPRESS`     | `capacity_iv(TAG_COMPRESS)`|
/// | `WrapPerm`           | `TXBODY__`     | `capacity_iv(TAG_TXBODY)` |
///
/// Must match the native Poseidon2b constructions in
/// `noid_poseidon2b::primitives`. Non-head roles return `None`.
fn head_capacity_iv(role: &InstanceRole) -> Option<[Block128; 2]> {
    let tag = match role {
        InstanceRole::InputLeafPermA { .. } => TAG_LEAF,
        InstanceRole::OutputLeafPermA { .. } => TAG_COMMIT,
        InstanceRole::CompressPermA { .. } => TAG_COMPRESS,
        InstanceRole::WrapPerm => TAG_TXBODY,
        _ => return None,
    };
    Some(capacity_iv(tag))
}

/// Compute the permutation input actually fed to `write_perm_trace_at_offset`
/// for instance `meta`, accounting for the head-row-0 overrides:
///
/// - Every head's lanes 2..3 are forced to `capacity_iv(role.tag)` —
///   the Poseidon2b sub-sponge IV. This makes the AIR statement agree
///   with the native sponge regardless of what the caller supplied.
/// - Compress / wrap heads additionally override lanes 0..1 with the
///   left-child's Perm-A output digest (picked up from the already-
///   written slot of the child instance, thanks to post-order layout).
/// - Leaf heads keep lanes 0..1 verbatim from `input`; those cells stay
///   witness-free in E.3 and will be payload-pinned in §3d-0.9.H.
/// - Non-heads (Perm B / C) keep their caller-supplied input; the
///   inter-perm absorb tie lands in §3d-0.9.E.4.
fn effective_perm_input(
    meta: &InstanceMeta,
    input: [Block128; STATE_SIZE],
    cols: &[Vec<Block128>],
    instance_id: usize,
) -> [Block128; STATE_SIZE] {
    if !meta.is_head {
        // §3d-0.9.E.4.a: non-head row-0 capacity lanes (2..3) come from
        // the prior perm's s[lane]@N_ROUNDS (pure capacity pass-through).
        // §3d-0.9.E.4.b (compress only): rate lanes (0..1) come from
        // `prev_out_A[lane] + right_child.s[lane]@N_ROUNDS` (dead-pair
        // right-child is the zero digest → term drops out).
        // Non-compress non-heads (InputLeafPermB/C, OutputLeafPermB)
        // keep rate lanes caller-supplied until §3d-0.9.E.4.c.
        let mut out = input;
        let prev_row = (instance_id - 1) * TXBODY_MERKLE_SLOT_ROWS + N_ROUNDS;
        for lane in 2..STATE_SIZE {
            out[lane] = cols[TXBODY_MERKLE_LAYOUT.s + lane][prev_row];
        }
        if matches!(meta.role, InstanceRole::CompressPermB { .. }) {
            let right_id = meta.children.and_then(|[_, r]| r);
            for lane in 0..2 {
                let mut val = cols[TXBODY_MERKLE_LAYOUT.s + lane][prev_row];
                if let Some(rid) = right_id {
                    let r_row = rid * TXBODY_MERKLE_SLOT_ROWS + N_ROUNDS;
                    val = val + cols[TXBODY_MERKLE_LAYOUT.s + lane][r_row];
                }
                out[lane] = val;
            }
        }
        return out;
    }
    let mut out = input;
    if let Some(iv) = head_capacity_iv(&meta.role) {
        out[2] = iv[0];
        out[3] = iv[1];
    }
    if !is_leaf_head(&meta.role) {
        if let Some([Some(left_id), _]) = meta.children {
            let src_row = left_id * TXBODY_MERKLE_SLOT_ROWS + N_ROUNDS;
            for lane in 0..2 {
                out[lane] = cols[TXBODY_MERKLE_LAYOUT.s + lane][src_row];
            }
        }
    }
    out
}

/// Enumerate every cross-instance **child-digest echo tie** implied by
/// the Option α layout. Each compress (and the wrap) instance reads two
/// digests as inputs to its Perm A row-0 pre-MDS seed:
///
/// - **Left child digest** (`state[0..2]` going into the compress's own
///   `pre_s[0..2]@row_0`). Produced at `child.slot_base_row + N_ROUNDS`
///   lanes 0..2 of the Poseidon `s` columns.
/// - **Right child digest** is absorbed between Perm A and Perm B via
///   the inter-perm XOR; that's a separate tie class (enumerated in a
///   future sub-step) — here we only collect the Perm-A left-child
///   echoes.
///
/// Ties whose child is a non-AIR tree leaf (`prev_state_root`, `fee`,
/// zero-pad) are skipped here — those will be pinned as public-column
/// constants in 3d-0.9.H rather than echoed from another instance.
///
/// The wrap instance's child is the root compress Perm B, absorbed the
/// same way (one left-child echo for `pre_s[0..2]`).
///
/// Returns `(ties, owners)` where `owners[i]` is a pretty debug label.
/// 3d-0.9.E.2 feeds `ties` into the allocator; this step proves the
/// enumeration is self-consistent independently of the AIR wiring.
/// §3d-0.9.E.4.a — capacity-lane continuation ties.
///
/// Poseidon2b sponge: `absorb` XORs input into **rate** lanes (0..1)
/// only; capacity lanes (2..3) pass through unchanged between
/// permutations. Therefore on every **non-head** row-0, lanes 2..3
/// of pre-MDS state equal the corresponding post-MDS lanes of the
/// previous permutation in the same sub-sponge.
///
/// For every non-head instance we emit one tie per capacity lane:
///   - `src  = { row = prev.slot_base_row + N_ROUNDS, col = s[lane] }`
///   - `dst  = { row = meta.slot_base_row,            col = pre_s[lane] }`
///
/// Predecessor: in the current layout every non-head Perm X has its
/// predecessor at instance id `k - 1` (InputLeafPerm{A,B,C} chain
/// and Perm{A,B} chain for compress/output-leaf). This is an
/// invariant of `build_instance_layout`; we assert it here to keep
/// the E.4 enumeration safely decoupled from future reordering.
///
/// Rate-lane (0..1) continuation is §3d-0.9.E.4.b / E.4.c and adds
/// an absorb term; capacity lanes are the pure-`dst_pin` subset.
pub fn enumerate_capacity_continuation_ties(
    layout: &[InstanceMeta],
) -> Vec<EchoTie> {
    let mut ties: Vec<EchoTie> = Vec::new();
    for (k, meta) in layout.iter().enumerate() {
        if meta.is_head {
            continue;
        }
        assert!(k > 0, "non-head instance at id 0 has no predecessor");
        let prev = &layout[k - 1];
        // All non-head roles in this layout chain directly off the
        // immediately preceding perm; assert it.
        match (prev.role, meta.role) {
            (InstanceRole::InputLeafPermA { leaf_idx: a },
             InstanceRole::InputLeafPermB { leaf_idx: b }) if a == b => {}
            (InstanceRole::InputLeafPermB { leaf_idx: a },
             InstanceRole::InputLeafPermC { leaf_idx: b }) if a == b => {}
            (InstanceRole::OutputLeafPermA { leaf_idx: a },
             InstanceRole::OutputLeafPermB { leaf_idx: b }) if a == b => {}
            (InstanceRole::CompressPermA { level: la, pos: pa },
             InstanceRole::CompressPermB { level: lb, pos: pb })
                if la == lb && pa == pb => {}
            _ => panic!(
                "non-head instance {k} ({:?}) predecessor {:?} is not \
                 the previous perm of the same sub-sponge",
                meta.role, prev.role
            ),
        }
        let src_row = prev.slot_base_row + N_ROUNDS;
        let dst_row = meta.slot_base_row;
        for lane in 2..STATE_SIZE {
            ties.push(EchoTie {
                src_row,
                src_col: TXBODY_MERKLE_LAYOUT.s + lane,
                dst_pins: vec![DstPin {
                    dst_row,
                    dst_col: TXBODY_MERKLE_PRE_S_BASE + lane,
                }],
                live_consumers: Vec::new(),
                lane: lane as u8,
            });
        }
    }
    ties
}

/// §3d-0.9.E.4.b — compress rate-lane absorb ties (committed-echo form).
///
/// For every CompressPermB, emit up to 4 read-only `EchoTie`s that
/// carry `live_consumers = [b.slot_base_row]` and NO `dst_pins`:
///
/// - `prev_out_A[0]`, `prev_out_A[1]` (always — 15 nodes × 2 = 30 ties);
/// - `right_child.s[0]@N_ROUNDS`, `right_child.s[1]@N_ROUNDS` only when
///   the right tree child is an AIR instance (13 live nodes × 2 = 26).
///
/// The 3-term rate-absorb gate `pre_s_B[lane] + echo_prev_A[lane] +
/// echo_rc[lane] == 0` reads these echoes directly at
/// `b.slot_base_row` under a single-hot selector. Dead-pair compress
/// nodes (L0/L1, L14/L15 parents — primitives.rs treats L14, L15 as
/// zero-digest, not a TAG_LEAF padding digest) only emit the prev_out
/// ties; their absorb gate collapses to the 2-term form
/// `pre_s_B[lane] + echo_prev_A[lane] == 0` at emit time.
pub fn enumerate_compress_rate_continuation_ties(
    layout: &[InstanceMeta],
) -> Vec<EchoTie> {
    let mut ties: Vec<EchoTie> = Vec::new();
    for (b_id, b_meta) in layout.iter().enumerate() {
        let (level, pos) = match b_meta.role {
            InstanceRole::CompressPermB { level, pos } => (level, pos),
            _ => continue,
        };
        debug_assert!(b_id > 0);
        let a_meta = &layout[b_id - 1];
        debug_assert!(matches!(
            a_meta.role,
            InstanceRole::CompressPermA { level: l, pos: p } if l == level && p == pos
        ));
        let a_out_row = a_meta.slot_base_row + N_ROUNDS;
        let b_row_0 = b_meta.slot_base_row;
        for lane in 0..2usize {
            ties.push(EchoTie {
                src_row: a_out_row,
                src_col: TXBODY_MERKLE_LAYOUT.s + lane,
                dst_pins: Vec::new(),
                live_consumers: vec![b_row_0],
                lane: lane as u8,
            });
        }
        if let Some([_, Some(right_id)]) = a_meta.children {
            let r_out_row = layout[right_id].slot_base_row + N_ROUNDS;
            for lane in 0..2usize {
                ties.push(EchoTie {
                    src_row: r_out_row,
                    src_col: TXBODY_MERKLE_LAYOUT.s + lane,
                    dst_pins: Vec::new(),
                    live_consumers: vec![b_row_0],
                    lane: lane as u8,
                });
            }
        }
    }
    ties
}

/// §3d-0.9.E.4.c — leaf rate-lane absorb ties (committed-echo form).
///
/// For every leaf non-head instance (InputLeafPermB, InputLeafPermC,
/// OutputLeafPermB — 16 total), emit 2 read-only `EchoTie`s carrying
/// the rate-lane output of the previous perm in the same sub-sponge
/// into the non-head's row-0 as `live_consumers = [b_row_0]`, no
/// `dst_pins`. The 3-term rate-absorb gate
/// `pre_s[lane] + echo_prev_out[lane] + payload[lane] == 0` reads
/// these echoes at each non-head's row-0 under the single-hot
/// row-0 selector (already interned by E.4.a's dst_pin on lanes 2..3
/// of the same instance).
///
/// Mechanism is identical to `enumerate_compress_rate_continuation_ties`
/// but without the right-child echo: payload chunk comes from a
/// dedicated witness column (see [`N_LEAF_RATE_PAYLOAD_COLS`] /
/// [`leaf_rate_payload_col`]), not from another instance's trace.
/// §3d-0.9.H pins the payload columns to the §3b-4 tx-body columns.
pub fn enumerate_leaf_rate_continuation_ties(
    layout: &[InstanceMeta],
) -> Vec<EchoTie> {
    let mut ties: Vec<EchoTie> = Vec::new();
    for (id, meta) in layout.iter().enumerate() {
        let is_leaf_non_head = matches!(
            meta.role,
            InstanceRole::InputLeafPermB { .. }
                | InstanceRole::InputLeafPermC { .. }
                | InstanceRole::OutputLeafPermB { .. }
        );
        if !is_leaf_non_head {
            continue;
        }
        debug_assert!(id > 0);
        let prev = &layout[id - 1];
        let prev_out_row = prev.slot_base_row + N_ROUNDS;
        let consumer_row = meta.slot_base_row;
        for lane in 0..2usize {
            ties.push(EchoTie {
                src_row: prev_out_row,
                src_col: TXBODY_MERKLE_LAYOUT.s + lane,
                dst_pins: Vec::new(),
                live_consumers: vec![consumer_row],
                lane: lane as u8,
            });
        }
    }
    ties
}

pub fn enumerate_child_digest_ties(
    layout: &[InstanceMeta],
) -> Vec<EchoTie> {
    let mut ties: Vec<EchoTie> = Vec::new();
    for (parent_id, meta) in layout.iter().enumerate() {
        // Only Perm A of a compress / wrap carries a left-child digest
        // at row 0.
        let is_perm_a_of_compress_or_wrap = matches!(
            meta.role,
            InstanceRole::CompressPermA { .. } | InstanceRole::WrapPerm
        );
        if !is_perm_a_of_compress_or_wrap {
            continue;
        }
        let children = match meta.children {
            Some(c) => c,
            None => continue,
        };
        // Left-child digest echo: lanes 0..2 of parent's pre_s at row 0
        // from lanes 0..2 of the child's `s` at row `N_ROUNDS`.
        if let Some(left_id) = children[0] {
            let src_row = layout[left_id].slot_base_row + N_ROUNDS;
            let dst_row = meta.slot_base_row;
            for lane in 0..2 {
                ties.push(EchoTie {
                    src_row,
                    src_col: TXBODY_MERKLE_LAYOUT.s + lane,
                    dst_pins: vec![DstPin {
                        dst_row,
                        dst_col: TXBODY_MERKLE_PRE_S_BASE + lane,
                    }],
                    live_consumers: Vec::new(),
                    lane: lane as u8,
                });
            }
        }
        let _ = parent_id; // reserved for debug labelling in later steps
    }
    ties
}

/// Row-0 MDS binding gate terms for every lane, precomputed once.
/// `s[lane] + Σ MDS_FULL[lane][j] · pre_s[j] == 0`.
static MDS_ROW_0_TERMS: LazyLock<[Vec<(usize, Block128)>; STATE_SIZE]> = LazyLock::new(|| {
    std::array::from_fn(|lane| {
        let mut terms = Vec::with_capacity(1 + STATE_SIZE);
        terms.push((TXBODY_MERKLE_LAYOUT.s + lane, Block128::ONE));
        for j in 0..STATE_SIZE {
            terms.push((
                TXBODY_MERKLE_PRE_S_BASE + j,
                Block128::from(MDS_FULL[lane][j]),
            ));
        }
        terms
    })
});

/// Emit the stacked-permutation constraint set plus:
///
/// - 4 row-0 MDS gates (one per lane), selector-gated by `head_row_0`.
/// - `n_echo` `transition` gates (`echo@r == echo@r+1` under
///   `hold_mask`).
/// - `n_ties` `src_pin` gates (`echo == src_col` at each tie's
///   `src_row` under `src_mask`).
///
/// The matching `dst_pin` family lands together with the non-head
/// `pre_s` demotion in a follow-up step (E.3.2): today every instance
/// still carries its own public-input seed at row-0, so the dst cell
/// does not yet equal the echoed child digest.
pub fn emit_tx_body_merkle_constraints() -> Vec<Box<dyn Constraint>> {
    emit_tx_body_merkle_constraints_inner(None)
}

fn emit_tx_body_merkle_constraints_inner(
    pins: Option<&TxBodyMerkleBoundaryPins>,
) -> Vec<Box<dyn Constraint>> {
    let mut out = emit_perm_all_at(TXBODY_MERKLE_LAYOUT);
    // MDS row-0 binding on every slot_base_row (head AND non-head).
    // See `TXBODY_MERKLE_ANY_ROW_0` docstring for why this selector
    // had to be widened in §3d-0.9.E.4.a.
    for lane in 0..STATE_SIZE {
        let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new(
            MDS_ROW_0_TERMS[lane].clone(),
            Block128::ZERO,
        ));
        out.push(Box::new(SelectorGate::new(TXBODY_MERKLE_ANY_ROW_0, inner)));
    }

    // Capacity-IV binding on pre_s[2..3] at head row_0 only. The
    // iv_prog[lane - 2] public columns carry the role-appropriate IV
    // on head row-0 and zero elsewhere; the SelectorGate on
    // head_row_0 ensures non-head row-0s are unconstrained so that
    // §3d-0.9.E.4 can echo the prior perm's capacity output into
    // pre_s[2..3] on Perm B / Perm C row-0s.
    for lane in 2..STATE_SIZE {
        let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new(
            vec![
                (TXBODY_MERKLE_PRE_S_BASE + lane, Block128::ONE),
                (TXBODY_MERKLE_IV_PROG_BASE + (lane - 2), Block128::ONE),
            ],
            Block128::ZERO,
        ));
        out.push(Box::new(SelectorGate::new(TXBODY_MERKLE_HEAD_ROW_0, inner)));
    }

    let mask = &*ECHO_MASK_COLUMNS;
    for (c, &transition_col) in mask.transition_col.iter().enumerate() {
        let echo_col = TXBODY_MERKLE_ECHO_BASE + c;
        let inner: Box<dyn Constraint> = Box::new(WeightedLinearGateShifted::new(
            vec![(echo_col, Block128::ONE)],
            vec![(echo_col, Block128::ONE)],
            Block128::ZERO,
        ));
        out.push(Box::new(SelectorGate::new(transition_col, inner)));
    }

    let assignments = &*ECHO_ASSIGNMENTS;
    let ties = &*ECHO_TIES;
    for (tie_idx, tie) in ties.iter().enumerate() {
        let echo_col = TXBODY_MERKLE_ECHO_BASE + assignments.tie_to_column[tie_idx];
        let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new(
            vec![(echo_col, Block128::ONE), (tie.src_col, Block128::ONE)],
            Block128::ZERO,
        ));
        out.push(Box::new(SelectorGate::new(mask.src_pin_col[tie_idx], inner)));
    }

    // dst_pin gates — one per (tie, dst_pin). Each binds the echo column
    // to the dst trace cell on the dst_row via a single-hot `dst_mask`
    // programme. Under Opt 6, two ties with the same dst_row share the
    // same `dst_mask` public column.
    for (tie_idx, tie) in ties.iter().enumerate() {
        let echo_col = TXBODY_MERKLE_ECHO_BASE + assignments.tie_to_column[tie_idx];
        for (pin_idx, pin) in tie.dst_pins.iter().enumerate() {
            let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new(
                vec![(echo_col, Block128::ONE), (pin.dst_col, Block128::ONE)],
                Block128::ZERO,
            ));
            out.push(Box::new(SelectorGate::new(
                mask.dst_pin_col[tie_idx][pin_idx],
                inner,
            )));
        }
    }

    // §3d-0.9.E.4.b — compress rate-lane absorb gates. For every
    // CompressPermB at `b_row_0`, lane ∈ {0, 1}:
    //
    //   pre_s_B[lane] + echo_prev_A[lane]                 == 0   (dead-pair)
    //   pre_s_B[lane] + echo_prev_A[lane] + echo_rc[lane] == 0   (live)
    //
    // Selector: single-hot `b_row_0` mask (already interned as the
    // dst_pin / live-consumer programme via EchoMaskPlan::single_hot_col).
    let layout = build_instance_layout();
    for (b_id, b_meta) in layout.iter().enumerate() {
        if !matches!(b_meta.role, InstanceRole::CompressPermB { .. }) {
            continue;
        }
        let a_meta = &layout[b_id - 1];
        let a_out_row = a_meta.slot_base_row + N_ROUNDS;
        let right_id = a_meta.children.and_then(|[_, r]| r);
        let b_row_0 = b_meta.slot_base_row;
        let selector = mask
            .single_hot_col(b_row_0)
            .expect("b_row_0 selector must be interned by E.4.a dst_pin or E.4.b live_consumer");
        for lane in 0..2usize {
            let echo_prev = find_read_only_echo(
                ties,
                assignments,
                a_out_row,
                TXBODY_MERKLE_LAYOUT.s + lane,
                b_row_0,
            )
            .expect("prev_out_A rate echo must be enumerated");
            let mut terms = vec![
                (TXBODY_MERKLE_PRE_S_BASE + lane, Block128::ONE),
                (echo_prev, Block128::ONE),
            ];
            if let Some(rid) = right_id {
                let r_out_row = layout[rid].slot_base_row + N_ROUNDS;
                let echo_rc = find_read_only_echo(
                    ties,
                    assignments,
                    r_out_row,
                    TXBODY_MERKLE_LAYOUT.s + lane,
                    b_row_0,
                )
                .expect("right-child rate echo must be enumerated for live pair");
                terms.push((echo_rc, Block128::ONE));
            }
            // O3.c: under boundary-pin construction, instance 29
            // (pos=0 PermB, dead-pair parent of L0=prev_state_root and
            // L1=fee_leaf) absorbs `fee_leaf[lane]` as the verifier-
            // known constant term. Every other CompressPermB keeps
            // constant = ZERO (live pairs already add echo_rc; the
            // pos=7 dead-pair absorbs L15 = zero).
            let constant = match pins {
                Some(p) if b_id == BOUNDARY_INSTANCE_POS_0_PERM_B => p.fee_leaf[lane],
                _ => Block128::ZERO,
            };
            let inner: Box<dyn Constraint> =
                Box::new(WeightedLinearGate::new(terms, constant));
            out.push(Box::new(SelectorGate::new(selector, inner)));
        }
    }

    // §3d-0.9.E.4.c — leaf rate-lane absorb gates. For every leaf
    // non-head (InputLeafPermB / C, OutputLeafPermB) at `row_0`,
    // lane ∈ {0, 1}:
    //
    //   pre_s[lane] + echo_prev_out[lane] + payload[lane] == 0
    //
    // Selector: single-hot `row_0` mask (already interned as the
    // dst_pin / live-consumer programme via EchoMaskPlan::single_hot_col).
    // Payload columns are free witnesses until §3d-0.9.H pins them to
    // the §3b-4 tx-body value / owner / tag columns.
    let leaf_rate_ids = leaf_rate_absorb_instance_ids(&layout);
    for (slot, &id) in leaf_rate_ids.iter().enumerate() {
        let meta = &layout[id];
        let prev = &layout[id - 1];
        let prev_out_row = prev.slot_base_row + N_ROUNDS;
        let row_0 = meta.slot_base_row;
        let selector = mask
            .single_hot_col(row_0)
            .expect("leaf non-head row_0 selector must be interned by E.4.a dst_pin");
        for lane in 0..2usize {
            let echo_prev = find_read_only_echo(
                ties,
                assignments,
                prev_out_row,
                TXBODY_MERKLE_LAYOUT.s + lane,
                row_0,
            )
            .expect("prev_out leaf rate echo must be enumerated by E.4.c");
            let payload_col = leaf_rate_payload_col(slot, lane);
            let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new(
                vec![
                    (TXBODY_MERKLE_PRE_S_BASE + lane, Block128::ONE),
                    (echo_prev, Block128::ONE),
                    (payload_col, Block128::ONE),
                ],
                Block128::ZERO,
            ));
            out.push(Box::new(SelectorGate::new(selector, inner)));
        }
    }

    out
}

/// Locate the echo-column carrying a read-only tie (no dst_pins) whose
/// `(src_row, src_col, live_consumers == [consumer_row])` matches. Used
/// by §3d-0.9.E.4.b to wire the rate-absorb gate to the echo values
/// enumerated by `enumerate_compress_rate_continuation_ties`.
fn find_read_only_echo(
    ties: &[EchoTie],
    assignments: &EchoAssignments,
    src_row: usize,
    src_col: usize,
    consumer_row: usize,
) -> Option<usize> {
    for (tie_idx, tie) in ties.iter().enumerate() {
        if !tie.dst_pins.is_empty() {
            continue;
        }
        if tie.src_row == src_row
            && tie.src_col == src_col
            && tie.live_consumers.len() == 1
            && tie.live_consumers[0] == consumer_row
        {
            return Some(TXBODY_MERKLE_ECHO_BASE + assignments.tie_to_column[tie_idx]);
        }
    }
    None
}

/// Build the `pre_s[2]` / `pre_s[3]` capacity-IV programme (one entry
/// per `lane ∈ {2, 3}`). On every head row-0 the cell carries
/// `capacity_iv(role.tag)[lane - 2]`; all other rows carry zero
/// (which matches the honest trace, where `pre_s` columns are zero
/// outside head row-0).
pub fn capacity_iv_programme(lane: usize) -> Vec<Block128> {
    assert!(lane == 2 || lane == 3, "capacity_iv lives on lanes 2..3");
    let mut out = vec![Block128::ZERO; TXBODY_MERKLE_N_ROWS];
    let layout = build_instance_layout();
    for (k, meta) in layout.iter().enumerate() {
        if let Some(iv) = head_capacity_iv(&meta.role) {
            out[instance_row_offset(k)] = iv[lane - 2];
        }
    }
    out
}

/// Stage 1b — row schedule for the O1 leaf-payload binding.
///
/// Returns `(head_rows, nonhead_row_lane_word)`:
///
/// - `head_rows`: the 12 leaf PermA `slot_base_row` positions where
///   `leaf_perm_a_row_0` is hot and the head-pin gates fire.
/// - `nonhead_row_lane_word`: for each leaf non-head instance, the
///   tuple `(b_row_0, [(lane0_value, lane1_value)])` giving the two
///   absorbed rate-lane values (PermB word 2/3 for input leaves,
///   PermB word 2 + pad for output leaves, pad/pad for the
///   input-leaf finalize PermC).
///
/// Enforces three safeguards at construction time:
///
/// 1. All 12 head rows are distinct.
/// 2. Every row is strictly less than `TXBODY_MERKLE_N_ROWS`.
/// 3. No row collides between the head set and the non-head set (head
///    selector is multi-hot; the non-head selector re-uses
///    `ECHO_MASK_COLUMNS.single_hot_col`, which is guaranteed single-
///    hot on that row by the existing E.4.c / E.4.a interning).
fn o1_row_schedule(
    pins: &TxBodyMerkleBoundaryPins,
) -> (Vec<usize>, Vec<(usize, [Block128; 2])>) {
    let layout = build_instance_layout();
    let mut head_rows: Vec<usize> = Vec::with_capacity(12);
    let mut nonhead: Vec<(usize, [Block128; 2])> = Vec::with_capacity(16);

    for (id, meta) in layout.iter().enumerate() {
        match meta.role {
            InstanceRole::InputLeafPermA { leaf_idx } => {
                head_rows.push(meta.slot_base_row);
                let _ = pins.input_leaf_absorb[leaf_idx as usize];
            }
            InstanceRole::OutputLeafPermA { leaf_idx } => {
                head_rows.push(meta.slot_base_row);
                let _ = pins.output_leaf_absorb[leaf_idx as usize];
            }
            InstanceRole::InputLeafPermB { leaf_idx } => {
                let words = &pins.input_leaf_absorb[leaf_idx as usize];
                nonhead.push((meta.slot_base_row, [words[2], words[3]]));
            }
            InstanceRole::InputLeafPermC { .. } => {
                nonhead.push((
                    meta.slot_base_row,
                    [
                        Block128::from(O1_INPUT_LEAF_PAD_WORD_0),
                        Block128::from(O1_INPUT_LEAF_PAD_WORD_1),
                    ],
                ));
            }
            InstanceRole::OutputLeafPermB { leaf_idx } => {
                let words = &pins.output_leaf_absorb[leaf_idx as usize];
                nonhead.push((
                    meta.slot_base_row,
                    [words[2], Block128::from(O1_OUTPUT_LEAF_PAD_WORD)],
                ));
            }
            _ => {}
        }
        let _ = id;
    }

    // Safeguard 1: all 12 head rows are unique.
    assert_eq!(head_rows.len(), 12, "Stage 1b: must have 12 leaf head rows");
    let mut sorted = head_rows.clone();
    sorted.sort_unstable();
    for w in sorted.windows(2) {
        assert_ne!(w[0], w[1], "Stage 1b: head rows must be unique");
    }
    // Safeguard 2: every row is strictly less than the trace height.
    for &r in &head_rows {
        assert!(r < TXBODY_MERKLE_N_ROWS, "Stage 1b: head row {r} out of bounds");
    }
    assert_eq!(nonhead.len(), 16, "Stage 1b: must have 16 leaf non-head rows");
    for &(r, _) in &nonhead {
        assert!(r < TXBODY_MERKLE_N_ROWS, "Stage 1b: non-head row {r} out of bounds");
    }
    // Safeguard 3: head rows and non-head rows are disjoint sets.
    let head_set: std::collections::HashSet<usize> = head_rows.iter().copied().collect();
    for &(r, _) in &nonhead {
        assert!(
            !head_set.contains(&r),
            "Stage 1b: non-head row {r} collides with a head row"
        );
    }

    (head_rows, nonhead)
}

/// Stage 1b — `leaf_perm_a_row_0` multi-hot programme. Hot on the 12
/// leaf PermA `slot_base_row`s; zero elsewhere.
pub fn leaf_perm_a_row_0_programme() -> Vec<Block128> {
    let mut out = vec![Block128::ZERO; TXBODY_MERKLE_N_ROWS];
    let layout = build_instance_layout();
    for meta in layout.iter() {
        match meta.role {
            InstanceRole::InputLeafPermA { .. } | InstanceRole::OutputLeafPermA { .. } => {
                out[meta.slot_base_row] = Block128::ONE;
            }
            _ => {}
        }
    }
    out
}

/// Stage 1b compression — `leaf_non_head_row_0` multi-hot programme.
/// Hot on the 16 leaf non-head `slot_base_row`s (PermB rate-absorb
/// heads, PermC finalize heads, output PermB payload heads); zero
/// elsewhere. Lets the 16 per-row non-head pin constraints collapse
/// into a single SelectorGate per lane.
pub fn leaf_non_head_row_0_programme() -> Vec<Block128> {
    let mut out = vec![Block128::ZERO; TXBODY_MERKLE_N_ROWS];
    let layout = build_instance_layout();
    for meta in layout.iter() {
        match meta.role {
            InstanceRole::InputLeafPermB { .. }
            | InstanceRole::InputLeafPermC { .. }
            | InstanceRole::OutputLeafPermB { .. } => {
                out[meta.slot_base_row] = Block128::ONE;
            }
            _ => {}
        }
    }
    out
}

/// Stage 1b — `o1_prog[lane]` programme column carrying the declared
/// absorbed payload value at every leaf row-0 (head + non-head), zero
/// elsewhere.
///
/// - Leaf head row-0s: carries `input_leaf_absorb[leaf][lane]` for
///   input PermA and `output_leaf_absorb[leaf][lane]` for output
///   PermA (lane 0/1).
/// - Leaf non-head row-0s: carries the non-head lane value from
///   `o1_row_schedule` (PermB payload word, finalize padding, etc.).
pub fn o1_payload_programme(pins: &TxBodyMerkleBoundaryPins, lane: usize) -> Vec<Block128> {
    assert!(lane < 2, "o1_payload_programme: lane must be 0 or 1");
    let mut out = vec![Block128::ZERO; TXBODY_MERKLE_N_ROWS];
    let layout = build_instance_layout();
    for meta in layout.iter() {
        let row = meta.slot_base_row;
        match meta.role {
            InstanceRole::InputLeafPermA { leaf_idx } => {
                out[row] = pins.input_leaf_absorb[leaf_idx as usize][lane];
            }
            InstanceRole::OutputLeafPermA { leaf_idx } => {
                out[row] = pins.output_leaf_absorb[leaf_idx as usize][lane];
            }
            InstanceRole::InputLeafPermB { leaf_idx } => {
                out[row] = pins.input_leaf_absorb[leaf_idx as usize][2 + lane];
            }
            InstanceRole::InputLeafPermC { .. } => {
                out[row] = Block128::from(if lane == 0 {
                    O1_INPUT_LEAF_PAD_WORD_0
                } else {
                    O1_INPUT_LEAF_PAD_WORD_1
                });
            }
            InstanceRole::OutputLeafPermB { leaf_idx } => {
                out[row] = if lane == 0 {
                    pins.output_leaf_absorb[leaf_idx as usize][2]
                } else {
                    Block128::from(O1_OUTPUT_LEAF_PAD_WORD)
                };
            }
            _ => {}
        }
    }
    out
}

/// Public-column declarations:
///
/// - 6 perm programme columns (`is_full`, `is_round`, `rc[0..4]`).
/// - 1 `head_row_0` multi-hot indicator.
/// - 2 capacity-IV programme columns `iv_prog[0]` / `iv_prog[1]`
///   (corresponding to `pre_s[2]` / `pre_s[3]`), wired to `pre_s[2..3]`
///   via head-gated SelectorGates in `emit_tx_body_merkle_constraints`.
/// - `ECHO_MASK_COLUMNS.total` echo mask programmes (after Opt 6
///   programme-hash dedup).
pub fn emit_tx_body_merkle_public_columns() -> Vec<PublicColumn> {
    let mut out = emit_perm_public_columns_row_major_at(
        TXBODY_MERKLE_LAYOUT,
        TXBODY_MERKLE_N_PERMS,
        TXBODY_MERKLE_SLOT_ROWS,
        TXBODY_MERKLE_N_ROWS,
    );
    out.push(PublicColumn::new(
        TXBODY_MERKLE_HEAD_ROW_0,
        head_row_0_programme(),
    ));
    out.push(PublicColumn::new(
        TXBODY_MERKLE_ANY_ROW_0,
        any_row_0_programme(),
    ));
    for lane in 2..STATE_SIZE {
        out.push(PublicColumn::new(
            TXBODY_MERKLE_IV_PROG_BASE + (lane - 2),
            capacity_iv_programme(lane),
        ));
    }
    let mask = &*ECHO_MASK_COLUMNS;
    let mask_base = TXBODY_MERKLE_ECHO_BASE + *N_ECHO_COLS;
    for (i, programme) in mask.programmes.iter().enumerate() {
        out.push(PublicColumn::new(
            mask_base + i,
            programme.to_vec(TXBODY_MERKLE_N_ROWS),
        ));
    }
    out
}

/// Stage 1 — constraint emitter with boundary pins attached. Produces
/// [`emit_tx_body_merkle_constraints`] plus six `emit_public_cell`
/// gates for O2 / O3.a / O3.b, and modifies (in `_inner`) the pos=0
/// PermB rate-absorb gate's constant term for O3.c. See CRYPTO.md.
pub fn emit_tx_body_merkle_constraints_with_boundary_pins(
    pins: &TxBodyMerkleBoundaryPins,
) -> Vec<Box<dyn Constraint>> {
    let mut out = emit_tx_body_merkle_constraints_inner(Some(pins));

    let layout = build_instance_layout();
    let pin_base = *TXBODY_MERKLE_BOUNDARY_PIN_BASE;
    let total_rows = TXBODY_MERKLE_N_ROWS;

    // O3.a — instance 28 pre_s[0..1] = prev_state_root.
    let m_28 = &layout[BOUNDARY_INSTANCE_POS_0_PERM_A];
    debug_assert!(matches!(
        m_28.role,
        InstanceRole::CompressPermA { level: 1, pos: 0 }
    ));
    debug_assert_eq!(m_28.children, Some([None, None]));
    for lane in 0..2usize {
        let (_pc, gate) = emit_public_cell(
            pin_base,
            m_28.slot_base_row,
            total_rows,
            TXBODY_MERKLE_PRE_S_BASE + lane,
            pins.prev_state_root[lane],
        );
        out.push(gate);
    }

    // O3.b — instance 42 pre_s[0..1] = ZERO.
    let m_42 = &layout[BOUNDARY_INSTANCE_POS_7_PERM_A];
    debug_assert!(matches!(
        m_42.role,
        InstanceRole::CompressPermA { level: 1, pos: 7 }
    ));
    debug_assert_eq!(m_42.children, Some([None, None]));
    for lane in 0..2usize {
        let (_pc, gate) = emit_public_cell(
            pin_base + 1,
            m_42.slot_base_row,
            total_rows,
            TXBODY_MERKLE_PRE_S_BASE + lane,
            Block128::ZERO,
        );
        out.push(gate);
    }

    // O2 — instance 58 (wrap) s[0..1] @ N_ROUNDS = tx_body_hash.
    let m_58 = &layout[BOUNDARY_INSTANCE_WRAP];
    debug_assert!(matches!(m_58.role, InstanceRole::WrapPerm));
    let wrap_out_row = m_58.slot_base_row + N_ROUNDS;
    for lane in 0..2usize {
        let (_pc, gate) = emit_public_cell(
            pin_base + 2,
            wrap_out_row,
            total_rows,
            TXBODY_MERKLE_LAYOUT.s + lane,
            pins.tx_body_hash[lane],
        );
        out.push(gate);
    }

    // Stage 1b — O1 leaf-payload binding.
    //
    // Binds each leaf sub-sponge's absorbed payload words to the
    // Merkle hash inputs by pinning `pre_s[lane]` (heads) and
    // `payload[lane]` (non-heads) to the programme columns
    // `o1_prog[0..1]`. The programmes carry the declared payload
    // word at each leaf row-0 (28 hot rows total) and zero
    // elsewhere; the verifier's public-column MLE check binds the
    // programme column values to `pins.{input,output}_leaf_absorb`.
    //
    // Soundness scope: this closes the Merkle-side leaf-payload
    // binding only. Cross-AIR consistency with TxValidity amounts /
    // owners is deferred to Stage 2.
    let (head_rows, nonhead) = o1_row_schedule(pins);
    let _ = (&head_rows, &nonhead); // row-schedule asserts still run
    let o1_base = *TXBODY_MERKLE_O1_BASE;
    let leaf_perm_a_sel = o1_base + TXBODY_MERKLE_O1_LEAF_PERM_A_ROW_0_OFFSET;
    let leaf_non_head_sel = o1_base + TXBODY_MERKLE_O1_LEAF_NON_HEAD_ROW_0_OFFSET;
    let o1_prog = [
        o1_base + TXBODY_MERKLE_O1_PROG_BASE_OFFSET,
        o1_base + TXBODY_MERKLE_O1_PROG_BASE_OFFSET + 1,
    ];

    // Head-pin gates: for every leaf PermA row-0 (multi-hot under
    // leaf_perm_a_row_0), pin `pre_s[lane] == o1_prog[lane]`.
    for lane in 0..2usize {
        let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new(
            vec![
                (TXBODY_MERKLE_PRE_S_BASE + lane, Block128::ONE),
                (o1_prog[lane], Block128::ONE),
            ],
            Block128::ZERO,
        ));
        out.push(Box::new(SelectorGate::new(leaf_perm_a_sel, inner)));
    }

    // Non-head-pin gates: for every leaf non-head row-0 (multi-hot
    // under leaf_non_head_row_0), pin `payload[lane] == o1_prog[lane]`.
    // The multi-hot selector collapses what would otherwise be 16
    // per-row single-hot SelectorGates into one SelectorGate per lane
    // (32 -> 2 row-local constraints).
    for lane in 0..2usize {
        let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new(
            vec![
                (*TXBODY_MERKLE_PAYLOAD_BASE + lane, Block128::ONE),
                (o1_prog[lane], Block128::ONE),
            ],
            Block128::ZERO,
        ));
        out.push(Box::new(SelectorGate::new(leaf_non_head_sel, inner)));
    }

    out
}

/// Stage 1 — public-column emitter with three single-hot boundary-pin
/// indicators appended at the tail.
pub fn emit_tx_body_merkle_public_columns_with_boundary_pins(
    pins: &TxBodyMerkleBoundaryPins,
) -> Vec<PublicColumn> {
    let mut out = emit_tx_body_merkle_public_columns();
    let layout = build_instance_layout();
    let pin_base = *TXBODY_MERKLE_BOUNDARY_PIN_BASE;
    let total_rows = TXBODY_MERKLE_N_ROWS;

    out.push(PublicColumn::new(
        pin_base,
        row_indicator_programme(
            layout[BOUNDARY_INSTANCE_POS_0_PERM_A].slot_base_row,
            total_rows,
        ),
    ));
    out.push(PublicColumn::new(
        pin_base + 1,
        row_indicator_programme(
            layout[BOUNDARY_INSTANCE_POS_7_PERM_A].slot_base_row,
            total_rows,
        ),
    ));
    out.push(PublicColumn::new(
        pin_base + 2,
        row_indicator_programme(
            layout[BOUNDARY_INSTANCE_WRAP].slot_base_row + N_ROUNDS,
            total_rows,
        ),
    ));

    // Stage 1b — O1 public columns.
    let o1_base = *TXBODY_MERKLE_O1_BASE;
    out.push(PublicColumn::new(
        o1_base + TXBODY_MERKLE_O1_LEAF_PERM_A_ROW_0_OFFSET,
        leaf_perm_a_row_0_programme(),
    ));
    for lane in 0..2usize {
        out.push(PublicColumn::new(
            o1_base + TXBODY_MERKLE_O1_PROG_BASE_OFFSET + lane,
            o1_payload_programme(pins, lane),
        ));
    }
    out.push(PublicColumn::new(
        o1_base + TXBODY_MERKLE_O1_LEAF_NON_HEAD_ROW_0_OFFSET,
        leaf_non_head_row_0_programme(),
    ));
    out
}

pub struct TxBodyMerkleAir {
    constraints: Vec<Box<dyn Constraint>>,
    public_columns: Vec<PublicColumn>,
    n_columns: usize,
    boundary_pins: Option<TxBodyMerkleBoundaryPins>,
}

impl TxBodyMerkleAir {
    pub fn new() -> Self {
        Self {
            constraints: emit_tx_body_merkle_constraints(),
            public_columns: emit_tx_body_merkle_public_columns(),
            n_columns: *TXBODY_MERKLE_N_COLS,
            boundary_pins: None,
        }
    }

    /// Stage 1 constructor — attach caller-supplied boundary pins for
    /// O2 (wrap output → `tx_body_hash`) and O3 (dead-pair level-1
    /// compress heads → `prev_state_root` / `fee_leaf` / `ZERO`). See
    /// `CRYPTO.md §Stage 1` for the soundness argument and the pinned
    /// cell inventory.
    pub fn new_with_boundary_pins(pins: TxBodyMerkleBoundaryPins) -> Self {
        Self {
            constraints: emit_tx_body_merkle_constraints_with_boundary_pins(&pins),
            public_columns: emit_tx_body_merkle_public_columns_with_boundary_pins(&pins),
            n_columns: *TXBODY_MERKLE_N_COLS_WITH_BOUNDARY_PINS,
            boundary_pins: Some(pins),
        }
    }

    pub fn build_trace(
        &self,
        inputs: &[[Block128; STATE_SIZE]; TXBODY_MERKLE_N_PERMS],
    ) -> Trace {
        match self.boundary_pins {
            None => build_tx_body_merkle_typed_trace(inputs),
            Some(pins) => Trace::new_with_domains(
                build_tx_body_merkle_trace_with_boundary_pins(inputs, &pins),
                tx_body_merkle_column_domains_with_boundary_pins(),
            ),
        }
    }
}

impl Default for TxBodyMerkleAir {
    fn default() -> Self {
        Self::new()
    }
}

impl Air for TxBodyMerkleAir {
    fn n_columns(&self) -> usize {
        self.n_columns
    }
    fn log_rows(&self) -> usize {
        TXBODY_MERKLE_LOG_ROWS
    }
    fn constraints(&self) -> &[Box<dyn Constraint>] {
        &self.constraints
    }
    fn public_columns(&self) -> &[PublicColumn] {
        &self.public_columns
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::native::permutation::Poseidon2bPermutation;

    fn mk_input(seed: u128) -> [Block128; STATE_SIZE] {
        let s = seed.wrapping_mul(0x9E3779B97F4A7C15);
        [
            Block128::from(s ^ 0xA5A5_A5A5_A5A5_A5A5),
            Block128::from(s.wrapping_add(1) ^ 0x5A5A_5A5A_5A5A_5A5A),
            Block128::from(s.wrapping_add(2) ^ 0xFFFF_0000_FFFF_0000),
            Block128::from(s.wrapping_add(3) ^ 0x0F0F_F0F0_0F0F_F0F0),
        ]
    }

    fn mk_batch() -> [[Block128; STATE_SIZE]; TXBODY_MERKLE_N_PERMS] {
        let mut out = [[Block128::ZERO; STATE_SIZE]; TXBODY_MERKLE_N_PERMS];
        for k in 0..TXBODY_MERKLE_N_PERMS {
            out[k] = mk_input(k as u128 + 1);
        }
        out
    }

    #[test]
    fn layout_arithmetic_is_consistent() {
        assert_eq!(TXBODY_MERKLE_N_PERMS, 59);
        assert_eq!(TXBODY_MERKLE_SLOT_ROWS, 1 << TXBODY_MERKLE_SLOT_LOG_ROWS);
        assert!(TXBODY_MERKLE_SLOT_ROWS >= N_ROUNDS + 1);
        assert!(
            TXBODY_MERKLE_N_PERMS * TXBODY_MERKLE_SLOT_ROWS <= TXBODY_MERKLE_N_ROWS,
            "59 instances must fit inside 2^13 rows",
        );
        assert_eq!(
            *TXBODY_MERKLE_N_COLS,
            POSEIDON_PERM_N_COLS
                + STATE_SIZE
                + 1
                + 2
                + 1
                + *N_ECHO_COLS
                + ECHO_MASK_COLUMNS.total
                + N_LEAF_RATE_PAYLOAD_COLS,
        );
    }

    #[test]
    fn each_instance_output_matches_native_permutation_on_effective_input() {
        // Leaf heads and non-heads permute `batch[k]` verbatim; compress
        // and wrap heads have lanes 0..1 of their input overridden by the
        // left child's Perm output digest.
        use super::super::layout::build_instance_layout;
        let batch = mk_batch();
        let cols = build_tx_body_merkle_trace(&batch);
        let layout = build_instance_layout();
        for (k, meta) in layout.iter().enumerate() {
            let effective = effective_perm_input(meta, batch[k], &cols, k);
            let mut native = effective;
            Poseidon2bPermutation.permute_mut(&mut native);
            let traced = extract_instance_output(&cols, k);
            assert_eq!(traced, native, "instance {k} output must match native");
        }
    }

    #[test]
    fn trace_dimensions_match_constants() {
        let cols = build_tx_body_merkle_trace(&mk_batch());
        assert_eq!(cols.len(), *TXBODY_MERKLE_N_COLS);
        for c in &cols {
            assert_eq!(c.len(), TXBODY_MERKLE_N_ROWS);
        }
    }

    #[test]
    fn pre_s_cells_reflect_post_relaxation_semantics() {
        // Post-E.3 invariant: every head row-0 has head_row_0 = ONE and
        // pre_s fully populated (MDS binding gate is active). Lane-by-lane:
        //   - Leaf heads: pre_s[0..1] = batch[k][0..1] (witness, payload-
        //     pinned in §3d-0.9.H). pre_s[2..3] = capacity_iv(role.tag).
        //   - Compress/wrap heads with a live left child: pre_s[0..1] =
        //     echoed digest. Dead-pair compress heads carry pre_s[0..1]
        //     from `batch[k]` — still a free witness; pinned in §3d-0.9.H
        //     via payload cells for prev_state_root / fee / pad.
        //     pre_s[2..3] = capacity_iv(COMPRESS or TXBODY).
        //   - Non-heads: pre_s = 0, head_row_0 = ZERO.
        use super::super::layout::build_instance_layout;
        let batch = mk_batch();
        let cols = build_tx_body_merkle_trace(&batch);
        let layout = build_instance_layout();
        for (k, meta) in layout.iter().enumerate() {
            let row = instance_row_offset(k);
            if meta.is_head {
                assert_eq!(cols[TXBODY_MERKLE_HEAD_ROW_0][row], Block128::ONE);
                let iv = head_capacity_iv(&meta.role).expect("head must have IV");
                assert_eq!(cols[TXBODY_MERKLE_PRE_S_BASE + 2][row], iv[0]);
                assert_eq!(cols[TXBODY_MERKLE_PRE_S_BASE + 3][row], iv[1]);
                if is_leaf_head(&meta.role) {
                    for lane in 0..2 {
                        assert_eq!(
                            cols[TXBODY_MERKLE_PRE_S_BASE + lane][row],
                            batch[k][lane],
                            "leaf head {k} lane {lane} pre_s mismatch",
                        );
                    }
                } else if let Some([Some(left), _]) = meta.children {
                    let child_src = left * TXBODY_MERKLE_SLOT_ROWS + N_ROUNDS;
                    for lane in 0..2 {
                        assert_eq!(
                            cols[TXBODY_MERKLE_PRE_S_BASE + lane][row],
                            cols[TXBODY_MERKLE_LAYOUT.s + lane][child_src],
                            "compress/wrap head {k} lane {lane} must echo child digest",
                        );
                    }
                } else {
                    // Dead-pair compress head: lanes 0..1 from batch[k].
                    for lane in 0..2 {
                        assert_eq!(
                            cols[TXBODY_MERKLE_PRE_S_BASE + lane][row],
                            batch[k][lane],
                            "dead-pair compress {k} lane {lane} pre_s mismatch",
                        );
                    }
                }
            } else {
                // §3d-0.9.E.4.a: non-head row-0 capacity lanes (2..3)
                // echo prev.s[lane]@N_ROUNDS.
                // §3d-0.9.E.4.b: for CompressPermB, rate lanes (0..1)
                // are now pinned to `prev_out_A + right_child` (or
                // just `prev_out_A` on dead-pair nodes). Other non-
                // head perms keep caller-supplied rate lanes until
                // §3d-0.9.E.4.c.
                let prev_row = (k - 1) * TXBODY_MERKLE_SLOT_ROWS + N_ROUNDS;
                if matches!(meta.role, InstanceRole::CompressPermB { .. }) {
                    let right_id = meta.children.and_then(|[_, r]| r);
                    for lane in 0..2 {
                        let mut expected =
                            cols[TXBODY_MERKLE_LAYOUT.s + lane][prev_row];
                        if let Some(rid) = right_id {
                            let r_row = rid * TXBODY_MERKLE_SLOT_ROWS + N_ROUNDS;
                            expected = expected
                                + cols[TXBODY_MERKLE_LAYOUT.s + lane][r_row];
                        }
                        assert_eq!(
                            cols[TXBODY_MERKLE_PRE_S_BASE + lane][row],
                            expected,
                            "compress PermB {k} lane {lane} rate pre_s must equal prev_out + right_child",
                        );
                    }
                } else {
                    for lane in 0..2 {
                        assert_eq!(
                            cols[TXBODY_MERKLE_PRE_S_BASE + lane][row],
                            batch[k][lane],
                            "non-head {k} lane {lane} rate pre_s must be caller input",
                        );
                    }
                }
                for lane in 2..STATE_SIZE {
                    assert_eq!(
                        cols[TXBODY_MERKLE_PRE_S_BASE + lane][row],
                        cols[TXBODY_MERKLE_LAYOUT.s + lane][prev_row],
                        "non-head {k} lane {lane} capacity pre_s must echo prev",
                    );
                }
                assert_eq!(cols[TXBODY_MERKLE_HEAD_ROW_0][row], Block128::ZERO);
            }
        }
    }

    #[test]
    fn pre_s_is_zero_on_non_row_0_rows() {
        let cols = build_tx_body_merkle_trace(&mk_batch());
        for k in 0..TXBODY_MERKLE_N_PERMS {
            let base = instance_row_offset(k);
            for delta in 1..TXBODY_MERKLE_SLOT_ROWS {
                for lane in 0..STATE_SIZE {
                    assert_eq!(
                        cols[TXBODY_MERKLE_PRE_S_BASE + lane][base + delta],
                        Block128::ZERO,
                    );
                }
            }
        }
    }

    #[test]
    fn constraint_count_matches_emitted_families() {
        // 29 interior Poseidon2b gates + 4 row-0 MDS binding gates +
        // 2 capacity-IV binding gates (pre_s[2..3] vs iv_prog[0..1]) +
        // one transition gate per echo column + one src_pin gate per tie
        // + one dst_pin gate per (tie, dst_pin) pair +
        // one rate-absorb gate per CompressPermB × lane (§3d-0.9.E.4.b) +
        // one rate-absorb gate per leaf non-head × lane (§3d-0.9.E.4.c).
        use super::super::layout::{build_instance_layout, InstanceRole};
        let cs = emit_tx_body_merkle_constraints();
        let n_echo = *N_ECHO_COLS;
        let n_ties = ECHO_TIES.len();
        let n_dst_pins: usize = ECHO_TIES.iter().map(|t| t.dst_pins.len()).sum();
        let n_compress_perm_b = build_instance_layout()
            .iter()
            .filter(|m| matches!(m.role, InstanceRole::CompressPermB { .. }))
            .count();
        let n_rate_absorb = n_compress_perm_b * 2;
        let n_leaf_rate_absorb = 16 * 2;
        assert_eq!(
            cs.len(),
            29 + STATE_SIZE + 2
                + n_echo
                + n_ties
                + n_dst_pins
                + n_rate_absorb
                + n_leaf_rate_absorb,
        );
    }

    #[test]
    fn air_accepts_honest_stacked_trace() {
        let air = TxBodyMerkleAir::new();
        let trace = air.build_trace(&mk_batch());
        assert!(air.check(&trace));
    }

    #[test]
    fn column_domain_tags_are_well_formed() {
        // Every Bit-tagged column must contain only 0/1 cells in the
        // honest trace; Trace::new_with_domains enforces this in debug,
        // but we duplicate the check here so a regression in the tagger
        // surfaces even under release.
        let domains = tx_body_merkle_column_domains();
        assert_eq!(domains.len(), *TXBODY_MERKLE_N_COLS);
        // At minimum: is_full, is_round, head_row_0, and every echo-mask
        // programme is Bit.
        // is_full + is_round + head_row_0 + any_row_0 + mask cols.
        let expected_bit_count = 4 + ECHO_MASK_COLUMNS.total;
        let bit_count = domains.iter().filter(|d| matches!(d, ColumnDomain::Bit)).count();
        assert_eq!(bit_count, expected_bit_count);

        let cols = build_tx_body_merkle_trace(&mk_batch());
        for (c, dom) in domains.iter().enumerate() {
            if matches!(dom, ColumnDomain::Bit) {
                for (r, v) in cols[c].iter().enumerate() {
                    assert!(
                        *v == Block128::ZERO || *v == Block128::ONE,
                        "Bit column {c} row {r} carries non-bit value",
                    );
                }
            }
        }
    }

    #[test]
    fn typed_trace_matches_untyped() {
        // build_tx_body_merkle_typed_trace must produce the same column
        // values as the untyped builder — only domain tags differ.
        let batch = mk_batch();
        let untyped = build_tx_body_merkle_trace(&batch);
        let typed = build_tx_body_merkle_typed_trace(&batch);
        assert_eq!(typed.columns, untyped);
        assert_eq!(typed.domains, tx_body_merkle_column_domains());
    }

    #[test]
    fn air_rejects_pre_s_tamper_at_leaf_head_row_0() {
        // Flipping any `pre_s` cell on a leaf head breaks the MDS row-0
        // binding gate AND the capacity-IV PublicColumn on lanes 2..3.
        // Instance 3 is an InputLeafPermA (leaf head).
        let air = TxBodyMerkleAir::new();
        let mut cols = build_tx_body_merkle_trace(&mk_batch());
        let row = instance_row_offset(3);
        cols[TXBODY_MERKLE_PRE_S_BASE + 2][row] =
            cols[TXBODY_MERKLE_PRE_S_BASE + 2][row] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn air_rejects_iv_prog_tamper() {
        // Flipping the iv_prog public column on any head row-0 must be
        // rejected by the public-column check (the verifier side of the
        // iv-binding gate).
        let air = TxBodyMerkleAir::new();
        use super::super::layout::build_instance_layout;
        let layout = build_instance_layout();
        let head_k = layout.iter().position(|m| m.is_head).expect("some head");
        let mut cols = build_tx_body_merkle_trace(&mk_batch());
        let row = instance_row_offset(head_k);
        cols[TXBODY_MERKLE_IV_PROG_BASE][row] =
            cols[TXBODY_MERKLE_IV_PROG_BASE][row] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn air_rejects_capacity_iv_tamper_on_every_head() {
        // The capacity-IV PublicColumn on pre_s[2..3] must reject any
        // cell flip on any of the 28 head row-0s — this is what ensures
        // compress/wrap heads cannot silently swap their sub-sponge tag.
        let air = TxBodyMerkleAir::new();
        use super::super::layout::build_instance_layout;
        let layout = build_instance_layout();
        for (k, meta) in layout.iter().enumerate() {
            if !meta.is_head {
                continue;
            }
            let mut cols = build_tx_body_merkle_trace(&mk_batch());
            let row = instance_row_offset(k);
            cols[TXBODY_MERKLE_PRE_S_BASE + 2][row] =
                cols[TXBODY_MERKLE_PRE_S_BASE + 2][row] + Block128::ONE;
            assert!(
                !air.check(&Trace::new(cols)),
                "IV tamper on head instance {k} must be rejected",
            );
        }
    }

    #[test]
    fn air_rejects_capacity_echo_tamper_on_non_head() {
        // §3d-0.9.E.4.a: non-head row-0 pre_s[2..3] is pinned to the
        // prior perm's s[2..3]@N_ROUNDS via dst_pin + src_pin ties,
        // and MDS binding (under any_row_0) further ties it into s@row_0.
        // Any flip of pre_s[2]@non_head_row_0 must be rejected.
        let air = TxBodyMerkleAir::new();
        use super::super::layout::build_instance_layout;
        let layout = build_instance_layout();
        let non_head_k = layout
            .iter()
            .position(|m| !m.is_head)
            .expect("some non-head instance");
        let mut cols = build_tx_body_merkle_trace(&mk_batch());
        let row = instance_row_offset(non_head_k);
        cols[TXBODY_MERKLE_PRE_S_BASE + 2][row] =
            cols[TXBODY_MERKLE_PRE_S_BASE + 2][row] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn enumerate_compress_rate_continuation_counts() {
        use super::super::layout::build_instance_layout;
        let layout = build_instance_layout();
        let ties = enumerate_compress_rate_continuation_ties(&layout);
        // 15 compress nodes × 2 prev_out lanes = 30 prev_out ties.
        // 13 live-pair compress nodes × 2 right-child lanes = 26 rc ties.
        //   (L0/L1 and L14/L15 parents have no right-child AIR instance.)
        assert_eq!(ties.len(), 30 + 26);
        for t in &ties {
            assert!(t.dst_pins.is_empty());
            assert_eq!(t.live_consumers.len(), 1);
            assert!(t.src_row < t.live_consumers[0]);
            assert_eq!(t.src_row % TXBODY_MERKLE_SLOT_ROWS, N_ROUNDS);
            assert_eq!(t.live_consumers[0] % TXBODY_MERKLE_SLOT_ROWS, 0);
        }
    }

    #[test]
    fn enumerate_leaf_rate_continuation_counts() {
        use super::super::layout::build_instance_layout;
        let layout = build_instance_layout();
        let ties = enumerate_leaf_rate_continuation_ties(&layout);
        // 16 leaf non-head instances × 2 rate lanes = 32 ties.
        assert_eq!(ties.len(), 32);
        for t in &ties {
            assert!(t.dst_pins.is_empty());
            assert_eq!(t.live_consumers.len(), 1);
            assert!(t.src_row < t.live_consumers[0]);
            assert_eq!(t.src_row % TXBODY_MERKLE_SLOT_ROWS, N_ROUNDS);
            assert_eq!(t.live_consumers[0] % TXBODY_MERKLE_SLOT_ROWS, 0);
            assert!(t.lane < 2);
        }
    }

    #[test]
    fn leaf_rate_payload_col_shares_one_column_per_lane() {
        // Opt E.4.c-1: every (slot, lane) → same column for fixed lane.
        // Physical sharing is constraint-equivalent because the absorb
        // gate is row-gated on a single_hot(row_0) mask, and the 16
        // row-0s are all distinct.
        let base = *TXBODY_MERKLE_PAYLOAD_BASE;
        for lane in 0..2 {
            let c_ref = leaf_rate_payload_col(0, lane);
            assert_eq!(c_ref, base + lane);
            for slot in 0..16 {
                assert_eq!(leaf_rate_payload_col(slot, lane), c_ref);
                assert!(c_ref < *TXBODY_MERKLE_N_COLS);
            }
        }
        assert_eq!(N_LEAF_RATE_PAYLOAD_COLS, 2);
    }

    #[test]
    fn air_rejects_leaf_rate_absorb_tamper() {
        // §3d-0.9.E.4.c: flipping pre_s[0] or pre_s[1] on any leaf
        // non-head row-0 must be rejected by the 3-term absorb gate.
        use super::super::layout::{build_instance_layout, InstanceRole};
        let air = TxBodyMerkleAir::new();
        let layout = build_instance_layout();
        for (k, m) in layout.iter().enumerate() {
            let is_leaf_non_head = matches!(
                m.role,
                InstanceRole::InputLeafPermB { .. }
                    | InstanceRole::InputLeafPermC { .. }
                    | InstanceRole::OutputLeafPermB { .. }
            );
            if !is_leaf_non_head {
                continue;
            }
            for lane in 0..2 {
                let mut cols = build_tx_body_merkle_trace(&mk_batch());
                let row = instance_row_offset(k);
                cols[TXBODY_MERKLE_PRE_S_BASE + lane][row] =
                    cols[TXBODY_MERKLE_PRE_S_BASE + lane][row] + Block128::ONE;
                assert!(
                    !air.check(&Trace::new(cols)),
                    "leaf rate pre_s tamper on instance {k} lane {lane} must be rejected",
                );
            }
        }
    }

    #[test]
    fn air_rejects_leaf_rate_payload_tamper() {
        // Flipping the payload witness on any leaf non-head row-0 must
        // also be rejected (same absorb gate, symmetric in terms).
        let air = TxBodyMerkleAir::new();
        use super::super::layout::build_instance_layout;
        let layout = build_instance_layout();
        let ids = leaf_rate_absorb_instance_ids(&layout);
        for (slot, &id) in ids.iter().enumerate() {
            for lane in 0..2 {
                let mut cols = build_tx_body_merkle_trace(&mk_batch());
                let row = instance_row_offset(id);
                let col = leaf_rate_payload_col(slot, lane);
                cols[col][row] = cols[col][row] + Block128::ONE;
                assert!(
                    !air.check(&Trace::new(cols)),
                    "leaf rate payload tamper slot {slot} lane {lane} must be rejected",
                );
            }
        }
    }

    #[test]
    fn air_rejects_rate_absorb_tamper_on_compress_perm_b() {
        // Flipping pre_s[0] on any CompressPermB row-0 must be rejected
        // by the 3-term rate-absorb gate (or the 2-term dead-pair variant).
        use super::super::layout::{build_instance_layout, InstanceRole};
        let air = TxBodyMerkleAir::new();
        let layout = build_instance_layout();
        for (k, m) in layout.iter().enumerate() {
            if !matches!(m.role, InstanceRole::CompressPermB { .. }) {
                continue;
            }
            let mut cols = build_tx_body_merkle_trace(&mk_batch());
            let row = instance_row_offset(k);
            cols[TXBODY_MERKLE_PRE_S_BASE][row] =
                cols[TXBODY_MERKLE_PRE_S_BASE][row] + Block128::ONE;
            assert!(
                !air.check(&Trace::new(cols)),
                "rate-absorb tamper on compress PermB {k} must be rejected",
            );
        }
    }

    #[test]
    fn air_rejects_any_row_0_programme_tamper() {
        // Flipping the any_row_0 public column off on a non-head
        // row-0 would disable MDS binding there, so the PublicColumn
        // check itself must reject the flip.
        let air = TxBodyMerkleAir::new();
        use super::super::layout::build_instance_layout;
        let layout = build_instance_layout();
        let non_head_k = layout
            .iter()
            .position(|m| !m.is_head)
            .expect("some non-head instance");
        let mut cols = build_tx_body_merkle_trace(&mk_batch());
        let row = instance_row_offset(non_head_k);
        cols[TXBODY_MERKLE_ANY_ROW_0][row] = Block128::ZERO;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn air_rejects_s_row_0_tamper_on_compress_head() {
        // Compress heads now have head_row_0 = ONE; flipping s@row_0
        // breaks the MDS binding gate the same way it does on leaves.
        let air = TxBodyMerkleAir::new();
        use super::super::layout::{build_instance_layout, InstanceRole};
        let layout = build_instance_layout();
        let compress_head = layout
            .iter()
            .position(|m| matches!(m.role, InstanceRole::CompressPermA { .. }))
            .expect("some compress head must exist");
        let mut cols = build_tx_body_merkle_trace(&mk_batch());
        let row = instance_row_offset(compress_head);
        cols[TXBODY_MERKLE_LAYOUT.s + 0][row] =
            cols[TXBODY_MERKLE_LAYOUT.s + 0][row] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn air_rejects_s_tamper_at_head_row_0() {
        let air = TxBodyMerkleAir::new();
        let mut cols = build_tx_body_merkle_trace(&mk_batch());
        let row = instance_row_offset(42);
        cols[TXBODY_MERKLE_LAYOUT.s + 1][row] =
            cols[TXBODY_MERKLE_LAYOUT.s + 1][row] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn air_rejects_tamper_in_instance_0() {
        let air = TxBodyMerkleAir::new();
        let mut cols = build_tx_body_merkle_trace(&mk_batch());
        let row = instance_row_offset(0) + 1;
        cols[TXBODY_MERKLE_LAYOUT.sout + 2][row] =
            cols[TXBODY_MERKLE_LAYOUT.sout + 2][row] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn air_rejects_tamper_in_mid_instance() {
        let air = TxBodyMerkleAir::new();
        let mut cols = build_tx_body_merkle_trace(&mk_batch());
        let row = instance_row_offset(33) + 3;
        cols[TXBODY_MERKLE_LAYOUT.s + 1][row] =
            cols[TXBODY_MERKLE_LAYOUT.s + 1][row] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn air_rejects_tamper_in_last_instance() {
        let air = TxBodyMerkleAir::new();
        let mut cols = build_tx_body_merkle_trace(&mk_batch());
        let row = instance_row_offset(TXBODY_MERKLE_N_PERMS - 1) + 10;
        cols[TXBODY_MERKLE_LAYOUT.rc + 0][row] =
            cols[TXBODY_MERKLE_LAYOUT.rc + 0][row] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn air_rejects_inter_instance_rc_tamper() {
        let air = TxBodyMerkleAir::new();
        let mut cols = build_tx_body_merkle_trace(&mk_batch());
        let pad_row = instance_row_offset(5) + N_ROUNDS + 10;
        assert!(pad_row < instance_row_offset(6));
        cols[TXBODY_MERKLE_LAYOUT.rc + 1][pad_row] = Block128::from(0xCAFE_BABE_u128);
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn enumerate_child_digest_ties_counts_and_shape() {
        use super::super::echo::allocate_echo_columns;
        use super::super::layout::{build_instance_layout, InstanceRole};

        let layout = build_instance_layout();
        let ties = enumerate_child_digest_ties(&layout);

        // Every compress / wrap Perm A with a Some(left) child emits 2
        // ties (lanes 0,1). Level-1 has 8 compress Perm A's; 4 of them
        // have both children Some, 2 have only right-child Some (pairs
        // over L0,L1 and L14,L15 = fully None left), and 2 have left
        // Some / right None... wait, by pairs:
        //   pair 0 → (L0, L1): both None → 0 left-ties
        //   pair 1 → (L2, L3): both Some → 2 left-ties
        //   pair 2 → (L4, L5): both Some → 2 left-ties
        //   pair 3 → (L6, L7): both Some → 2 left-ties
        //   pair 4 → (L8, L9): both Some → 2 left-ties
        //   pair 5 → (L10,L11): both Some → 2 left-ties
        //   pair 6 → (L12,L13): both Some → 2 left-ties
        //   pair 7 → (L14,L15): both None → 0 left-ties
        // Level-1 left-tie count = 6 × 2 = 12 lane-ties.
        // Level-2..4: every child is a compress perm B, always Some.
        //   L2: 4 nodes × 2 = 8 lane-ties
        //   L3: 2 nodes × 2 = 4
        //   L4: 1 node × 2 = 2
        // Wrap: 1 × 2 = 2.
        // Total: 12 + 8 + 4 + 2 + 2 = 28.
        assert_eq!(ties.len(), 28);

        // Every tie's src_row points at a `N_ROUNDS`-offset output row
        // of some earlier instance.
        for t in &ties {
            let mod_slot = t.src_row % TXBODY_MERKLE_SLOT_ROWS;
            assert_eq!(mod_slot, N_ROUNDS);
            assert!(t.src_col == TXBODY_MERKLE_LAYOUT.s || t.src_col == TXBODY_MERKLE_LAYOUT.s + 1);
            assert_eq!(t.dst_pins.len(), 1);
            let d = t.dst_pins[0];
            assert!(
                d.dst_col == TXBODY_MERKLE_PRE_S_BASE || d.dst_col == TXBODY_MERKLE_PRE_S_BASE + 1
            );
            // dst_row is always on a head row (multiple of slot rows).
            assert_eq!(d.dst_row % TXBODY_MERKLE_SLOT_ROWS, 0);
            // src strictly precedes dst.
            assert!(t.src_row < d.dst_row);
        }

        // Allocator runs cleanly on the enumeration.
        let alloc = allocate_echo_columns(&ties).expect("echo allocator must accept the ties");
        // Sanity: we won't need more columns than tie count.
        assert!(alloc.columns.len() <= ties.len());
        // And we use at least 2 columns (one per lane pair covered).
        assert!(alloc.columns.len() >= 2);

        // Every compress Perm A / wrap with Some left child appears.
        let mut produced: usize = 0;
        for (pid, m) in layout.iter().enumerate() {
            let is_ca = matches!(
                m.role,
                InstanceRole::CompressPermA { .. } | InstanceRole::WrapPerm
            );
            if !is_ca {
                continue;
            }
            if let Some([Some(left), _]) = m.children {
                let expected_src_row = layout[left].slot_base_row + N_ROUNDS;
                let matches = ties
                    .iter()
                    .filter(|t| t.src_row == expected_src_row && t.dst_pins[0].dst_row == m.slot_base_row)
                    .count();
                assert_eq!(matches, 2, "parent {pid} should have 2 lane-ties");
                produced += 2;
            }
        }
        assert_eq!(produced, ties.len());
    }

    #[test]
    fn echo_columns_carry_src_value_on_active_interval() {
        let batch = mk_batch();
        let cols = build_tx_body_merkle_trace(&batch);
        let assignments = &*ECHO_ASSIGNMENTS;
        let ties = &*ECHO_TIES;
        for (col_idx, plan) in assignments.columns.iter().enumerate() {
            let echo_col = TXBODY_MERKLE_ECHO_BASE + col_idx;
            for (epoch_idx, &tie_id) in plan.tie_ids.iter().enumerate() {
                let t = &ties[tie_id];
                let epoch = plan.epochs[epoch_idx];
                let expected = cols[t.src_col][t.src_row];
                assert_ne!(expected, Block128::ZERO, "honest src must be nonzero");
                for row in epoch.src_row..=epoch.max_dst_row {
                    assert_eq!(cols[echo_col][row], expected, "echo col {col_idx} row {row}");
                }
            }
        }
    }

    #[test]
    fn hold_mask_is_cold_at_and_beyond_epoch_end() {
        // CRITICAL off-by-one invariant for the `transition` gate:
        //
        //   hot rows for epoch [src, max_dst]  ==  [src, max_dst - 1]
        //
        // If `max_dst` itself were hot, the gate would read
        // `echo[max_dst] + echo[max_dst + 1]` and pin the *next* epoch's
        // pre-src row to the previous epoch's last value — the prover
        // could never switch the echo to the new tie. If any row beyond
        // `max_dst` were hot, the gate would lock the echo column
        // forever across dead rows.
        //
        // Also: hot rows must never touch `N_ROWS - 1` — the cyclic
        // `next` rotation would otherwise alias to row 0 and pin the
        // very first row of the trace. This is a trace-wide cold-zone
        // check.
        let mask = &*ECHO_MASK_COLUMNS;
        let assignments = &*ECHO_ASSIGNMENTS;
        for (c, plan) in assignments.columns.iter().enumerate() {
            let prog_idx = mask.transition_col[c] - (TXBODY_MERKLE_ECHO_BASE + *N_ECHO_COLS);
            let programme = &mask.programmes[prog_idx];
            let hot: std::collections::HashSet<usize> =
                programme.hot_rows.iter().copied().collect();

            // `max_dst` itself and `max_dst + 1` must be cold.
            for epoch in &plan.epochs {
                assert!(
                    !hot.contains(&epoch.max_dst_row),
                    "hold_mask hot at max_dst_row={} on echo col {c}: \
                     prover cannot start the next epoch's value",
                    epoch.max_dst_row,
                );
                assert!(
                    !hot.contains(&(epoch.max_dst_row + 1)),
                    "hold_mask hot beyond max_dst_row on echo col {c}",
                );
                // And `src..max_dst` must all be hot (gap = stale echo).
                for r in epoch.src_row..epoch.max_dst_row {
                    assert!(
                        hot.contains(&r),
                        "hold_mask cold inside epoch at row {r} on echo col {c}: \
                         transition gate won't enforce stability",
                    );
                }
            }

            // Global cold-zone: no hot row at N_ROWS - 1 (cyclic next
            // would alias to row 0).
            assert!(
                !hot.contains(&(TXBODY_MERKLE_N_ROWS - 1)),
                "hold_mask hot at the trace tail on echo col {c}: \
                 cyclic rotation would alias to row 0",
            );
        }
    }

    #[test]
    fn prover_can_switch_echo_value_across_epochs_on_shared_column() {
        // Direct test of the hole Opt 7 + Opt 6 must leave for the
        // allocator's disjoint-interval invariant: when two epochs
        // share one echo column, the row `max_dst_row_of_epoch_1 + 1`
        // must be free for the prover to write the next tie's value.
        // The `hold_mask` programme must NOT force equality across that
        // gap.
        let assignments = &*ECHO_ASSIGNMENTS;
        let multi_epoch_col = assignments
            .columns
            .iter()
            .enumerate()
            .find(|(_, plan)| plan.epochs.len() >= 2);
        let Some((c, plan)) = multi_epoch_col else {
            // If the current enumeration happens to produce no shared
            // column, skip — the invariant is still checked by
            // `hold_mask_is_cold_at_and_beyond_epoch_end`.
            return;
        };
        let air = TxBodyMerkleAir::new();
        let mut cols = build_tx_body_merkle_trace(&mk_batch());
        // Write a distinct value to every row between epoch-0's end and
        // epoch-1's start. These rows must be cold under hold_mask;
        // the AIR must still accept.
        let echo_col = TXBODY_MERKLE_ECHO_BASE + c;
        let gap_start = plan.epochs[0].max_dst_row + 1;
        let gap_end = plan.epochs[1].src_row; // exclusive upper bound
        assert!(gap_start < gap_end, "allocator invariant: strict `<`");
        for r in gap_start..gap_end {
            cols[echo_col][r] = Block128::from(0xDEAD_BEEF_u128 ^ r as u128);
        }
        assert!(
            air.check(&Trace::new(cols)),
            "prover must be free to switch echo values in the cold gap \
             between two epochs sharing echo col {c}",
        );
    }

    #[test]
    fn mask_programme_dedup_holds() {
        // Opt 6: every tie sharing the same `src_row` maps to the same
        // `src_mask` column, and every echo column with an identical
        // `hold_mask` hot-row set shares a `transition_col`. `total`
        // must equal the number of distinct programmes.
        let mask = &*ECHO_MASK_COLUMNS;
        let ties = &*ECHO_TIES;
        assert_eq!(mask.src_pin_col.len(), ties.len());
        assert_eq!(mask.transition_col.len(), *N_ECHO_COLS);
        // Two ties with the same src_row must point at the same column.
        for i in 0..ties.len() {
            for j in (i + 1)..ties.len() {
                if ties[i].src_row == ties[j].src_row {
                    assert_eq!(
                        mask.src_pin_col[i], mask.src_pin_col[j],
                        "ties {i} and {j} share src_row but not src_mask",
                    );
                }
            }
        }
    }

    #[test]
    fn echo_dst_cells_match_echo_value_on_dst_row() {
        // After E.3: each tie's dst cell carries the echoed child digest
        // verbatim, so `echo[dst_row] == src_val == dst_col[dst_row]`.
        // The `dst_pin` gate enforces the latter half as a constraint.
        let batch = mk_batch();
        let cols = build_tx_body_merkle_trace(&batch);
        let assignments = &*ECHO_ASSIGNMENTS;
        let ties = &*ECHO_TIES;
        for (tie_idx, t) in ties.iter().enumerate() {
            let col_idx = assignments.tie_to_column[tie_idx];
            let echo_col = TXBODY_MERKLE_ECHO_BASE + col_idx;
            let src_val = cols[t.src_col][t.src_row];
            for d in &t.dst_pins {
                assert_eq!(cols[echo_col][d.dst_row], src_val);
                assert_eq!(cols[d.dst_col][d.dst_row], src_val);
            }
        }
    }

    #[test]
    fn air_rejects_dst_pin_tamper() {
        // Flipping the dst cell (a compress/wrap head's pre_s lane 0/1)
        // away from the echoed child digest must break the `dst_pin`
        // gate. The smallest tie's dst is at the first compress head
        // with both children Some.
        let air = TxBodyMerkleAir::new();
        let mut cols = build_tx_body_merkle_trace(&mk_batch());
        let ties = &*ECHO_TIES;
        let tie = &ties[0];
        let pin = tie.dst_pins[0];
        cols[pin.dst_col][pin.dst_row] =
            cols[pin.dst_col][pin.dst_row] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn air_rejects_dst_mask_tamper() {
        // Turning off the dst_mask bit on a live pin lets the prover
        // flip the dst cell silently — the programme re-eval must catch
        // the mask flip.
        let air = TxBodyMerkleAir::new();
        let mut cols = build_tx_body_merkle_trace(&mk_batch());
        let mask = &*ECHO_MASK_COLUMNS;
        let dst_col_idx = mask.dst_pin_col[0][0];
        let ties = &*ECHO_TIES;
        let dst_row = ties[0].dst_pins[0].dst_row;
        assert_eq!(cols[dst_col_idx][dst_row], Block128::ONE);
        cols[dst_col_idx][dst_row] = Block128::ZERO;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn air_rejects_echo_interior_tamper() {
        // Flipping an echo cell inside its live interval breaks the
        // `transition` gate (neighbouring rows disagree).
        let air = TxBodyMerkleAir::new();
        let mut cols = build_tx_body_merkle_trace(&mk_batch());
        let assignments = &*ECHO_ASSIGNMENTS;
        let plan = &assignments.columns[0];
        let epoch = plan.epochs[0];
        // Pick an interior row strictly inside [src_row, max_dst_row].
        let row = epoch.src_row + 1;
        assert!(row < epoch.max_dst_row);
        let echo_col = TXBODY_MERKLE_ECHO_BASE;
        cols[echo_col][row] = cols[echo_col][row] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn air_rejects_echo_src_tamper() {
        // Flipping an echo cell at `src_row` breaks `src_pin` (echo
        // must equal the referenced perm cell).
        let air = TxBodyMerkleAir::new();
        let mut cols = build_tx_body_merkle_trace(&mk_batch());
        let assignments = &*ECHO_ASSIGNMENTS;
        let ties = &*ECHO_TIES;
        let tie = &ties[0];
        let echo_col = TXBODY_MERKLE_ECHO_BASE + assignments.tie_to_column[0];
        cols[echo_col][tie.src_row] = cols[echo_col][tie.src_row] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn air_rejects_head_row_0_tamper() {
        // Flipping head_row_0 off on a leaf-head row allows us to tamper
        // pre_s silently — so the programme-column check must reject
        // that flip. Instance 0 is an InputLeafPermA (leaf head).
        let air = TxBodyMerkleAir::new();
        let mut cols = build_tx_body_merkle_trace(&mk_batch());
        let row = instance_row_offset(0);
        assert_eq!(cols[TXBODY_MERKLE_HEAD_ROW_0][row], Block128::ONE);
        cols[TXBODY_MERKLE_HEAD_ROW_0][row] = Block128::ZERO;
        assert!(!air.check(&Trace::new(cols)));
    }

    // ---------------- Stage 1 — O2/O3 boundary pin tests ----------------

    /// Run the pinned trace builder once against `inputs` + placeholder
    /// `tx_body_hash` and read the honest wrap output back out. Returns
    /// a self-consistent `TxBodyMerkleBoundaryPins`.
    fn mk_stage1b_leaf_fixtures() -> ([[Block128; 4]; 4], [[Block128; 3]; 8]) {
        let mut inputs = [[Block128::ZERO; 4]; 4];
        for leaf in 0..4 {
            for word in 0..4 {
                let v = ((leaf as u128) << 64) | (word as u128) << 16 | 0xA1B2_C3D4u128;
                inputs[leaf][word] = Block128::from(v);
            }
        }
        let mut outputs = [[Block128::ZERO; 3]; 8];
        for leaf in 0..8 {
            for word in 0..3 {
                let v = ((leaf as u128) << 72) | (word as u128) << 24 | 0xDEAD_BEEFu128;
                outputs[leaf][word] = Block128::from(v);
            }
        }
        (inputs, outputs)
    }

    fn derive_pins(
        inputs: &[[Block128; STATE_SIZE]; TXBODY_MERKLE_N_PERMS],
        prev_state_root: [Block128; 2],
        fee_leaf: [Block128; 2],
    ) -> TxBodyMerkleBoundaryPins {
        let (input_leaf_absorb, output_leaf_absorb) = mk_stage1b_leaf_fixtures();
        let placeholder = TxBodyMerkleBoundaryPins {
            prev_state_root,
            fee_leaf,
            tx_body_hash: [Block128::ZERO; 2],
            input_leaf_absorb,
            output_leaf_absorb,
        };
        let cols = build_tx_body_merkle_trace_with_boundary_pins(inputs, &placeholder);
        let wrap_out = extract_instance_output(&cols, BOUNDARY_INSTANCE_WRAP);
        TxBodyMerkleBoundaryPins {
            prev_state_root,
            fee_leaf,
            tx_body_hash: [wrap_out[0], wrap_out[1]],
            input_leaf_absorb,
            output_leaf_absorb,
        }
    }

    fn stage1_pins_fixture() -> (
        [[Block128; STATE_SIZE]; TXBODY_MERKLE_N_PERMS],
        TxBodyMerkleBoundaryPins,
    ) {
        let inputs = mk_batch();
        let prev_state_root = [
            Block128::from(0x1122_3344_5566_7788u128),
            Block128::from(0x99AA_BBCC_DDEE_FF00u128),
        ];
        let fee_leaf = [Block128::from(0xFEEDu128), Block128::ZERO];
        let pins = derive_pins(&inputs, prev_state_root, fee_leaf);
        (inputs, pins)
    }

    #[test]
    fn boundary_pin_column_accounting() {
        assert_eq!(TXBODY_MERKLE_BOUNDARY_PIN_N_COLS, 3);
        assert_eq!(TXBODY_MERKLE_O1_N_COLS, 4);
        assert_eq!(
            *TXBODY_MERKLE_N_COLS_WITH_BOUNDARY_PINS,
            *TXBODY_MERKLE_N_COLS
                + TXBODY_MERKLE_BOUNDARY_PIN_N_COLS
                + TXBODY_MERKLE_O1_N_COLS,
        );
        assert_eq!(
            *TXBODY_MERKLE_BOUNDARY_PIN_BASE,
            *TXBODY_MERKLE_PAYLOAD_BASE + N_LEAF_RATE_PAYLOAD_COLS,
        );
        assert_eq!(
            *TXBODY_MERKLE_O1_BASE,
            *TXBODY_MERKLE_BOUNDARY_PIN_BASE + TXBODY_MERKLE_BOUNDARY_PIN_N_COLS,
        );
    }

    #[test]
    fn boundary_instance_ids_match_layout_roles() {
        let layout = build_instance_layout();
        assert!(matches!(
            layout[BOUNDARY_INSTANCE_POS_0_PERM_A].role,
            InstanceRole::CompressPermA { level: 1, pos: 0 }
        ));
        assert_eq!(
            layout[BOUNDARY_INSTANCE_POS_0_PERM_A].children,
            Some([None, None])
        );
        assert!(matches!(
            layout[BOUNDARY_INSTANCE_POS_0_PERM_B].role,
            InstanceRole::CompressPermB { level: 1, pos: 0 }
        ));
        assert!(matches!(
            layout[BOUNDARY_INSTANCE_POS_7_PERM_A].role,
            InstanceRole::CompressPermA { level: 1, pos: 7 }
        ));
        assert_eq!(
            layout[BOUNDARY_INSTANCE_POS_7_PERM_A].children,
            Some([None, None])
        );
        assert!(matches!(
            layout[BOUNDARY_INSTANCE_WRAP].role,
            InstanceRole::WrapPerm
        ));
    }

    #[test]
    fn air_accepts_honest_trace_with_boundary_pins() {
        let (inputs, pins) = stage1_pins_fixture();
        let air = TxBodyMerkleAir::new_with_boundary_pins(pins);
        let trace = air.build_trace(&inputs);
        assert!(air.check(&trace));
    }

    #[test]
    fn pinned_trace_has_expected_indicator_singletons() {
        let (inputs, pins) = stage1_pins_fixture();
        let cols = build_tx_body_merkle_trace_with_boundary_pins(&inputs, &pins);
        let pin_base = *TXBODY_MERKLE_BOUNDARY_PIN_BASE;
        let layout = build_instance_layout();
        for (offset, row) in [
            (0, layout[BOUNDARY_INSTANCE_POS_0_PERM_A].slot_base_row),
            (1, layout[BOUNDARY_INSTANCE_POS_7_PERM_A].slot_base_row),
            (
                2,
                layout[BOUNDARY_INSTANCE_WRAP].slot_base_row + N_ROUNDS,
            ),
        ] {
            let col = &cols[pin_base + offset];
            assert_eq!(col[row], Block128::ONE);
            let hot = col.iter().filter(|v| **v == Block128::ONE).count();
            assert_eq!(
                hot, 1,
                "indicator col {} must be single-hot",
                pin_base + offset
            );
        }
    }

    #[test]
    fn air_rejects_prev_state_root_pin_tamper() {
        let (inputs, pins) = stage1_pins_fixture();
        let air = TxBodyMerkleAir::new_with_boundary_pins(pins);
        let mut cols = build_tx_body_merkle_trace_with_boundary_pins(&inputs, &pins);
        let row = instance_row_offset(BOUNDARY_INSTANCE_POS_0_PERM_A);
        cols[TXBODY_MERKLE_PRE_S_BASE][row] =
            cols[TXBODY_MERKLE_PRE_S_BASE][row] + Block128::ONE;
        let trace = Trace::new_with_domains(
            cols,
            tx_body_merkle_column_domains_with_boundary_pins(),
        );
        assert!(!air.check(&trace));
    }

    #[test]
    fn air_rejects_zero_pad_pin_tamper() {
        let (inputs, pins) = stage1_pins_fixture();
        let air = TxBodyMerkleAir::new_with_boundary_pins(pins);
        let mut cols = build_tx_body_merkle_trace_with_boundary_pins(&inputs, &pins);
        let row = instance_row_offset(BOUNDARY_INSTANCE_POS_7_PERM_A);
        cols[TXBODY_MERKLE_PRE_S_BASE + 1][row] =
            cols[TXBODY_MERKLE_PRE_S_BASE + 1][row] + Block128::ONE;
        let trace = Trace::new_with_domains(
            cols,
            tx_body_merkle_column_domains_with_boundary_pins(),
        );
        assert!(!air.check(&trace));
    }

    #[test]
    fn air_rejects_tx_body_hash_pin_tamper() {
        let (inputs, pins) = stage1_pins_fixture();
        let air = TxBodyMerkleAir::new_with_boundary_pins(pins);
        let mut cols = build_tx_body_merkle_trace_with_boundary_pins(&inputs, &pins);
        let row = instance_row_offset(BOUNDARY_INSTANCE_WRAP) + N_ROUNDS;
        cols[TXBODY_MERKLE_LAYOUT.s][row] =
            cols[TXBODY_MERKLE_LAYOUT.s][row] + Block128::ONE;
        let trace = Trace::new_with_domains(
            cols,
            tx_body_merkle_column_domains_with_boundary_pins(),
        );
        assert!(!air.check(&trace));
    }

    #[test]
    fn air_rejects_mismatched_tx_body_hash_declaration() {
        // Declaring a `tx_body_hash` that disagrees with the honest
        // wrap output must fail via the O2 pin.
        let (inputs, honest_pins) = stage1_pins_fixture();
        let bad_pins = TxBodyMerkleBoundaryPins {
            tx_body_hash: [
                honest_pins.tx_body_hash[0] + Block128::ONE,
                honest_pins.tx_body_hash[1],
            ],
            ..honest_pins
        };
        let air = TxBodyMerkleAir::new_with_boundary_pins(bad_pins);
        let trace = air.build_trace(&inputs);
        assert!(!air.check(&trace));
    }

    #[test]
    fn air_rejects_mismatched_fee_leaf_declaration() {
        // AIR declares one `fee_leaf`; trace built with a different
        // honest `fee_leaf`. The O3.c constant mismatch in the
        // instance-29 rate-absorb gate must reject.
        let (inputs, honest_pins) = stage1_pins_fixture();
        let bad_pins = TxBodyMerkleBoundaryPins {
            fee_leaf: [
                honest_pins.fee_leaf[0] + Block128::ONE,
                honest_pins.fee_leaf[1],
            ],
            ..honest_pins
        };
        let air = TxBodyMerkleAir::new_with_boundary_pins(bad_pins);
        let cols = build_tx_body_merkle_trace_with_boundary_pins(&inputs, &honest_pins);
        let trace = Trace::new_with_domains(
            cols,
            tx_body_merkle_column_domains_with_boundary_pins(),
        );
        assert!(!air.check(&trace));
    }

    // ---------------- Stage 1b — O1 exhaustive tamper tests ----------------
    //
    // Scope: Stage 1b binds the 44 declared leaf payload words
    // (4 inputs × 4 words + 8 outputs × 3 words) to the Merkle hash
    // inputs. It does NOT yet prove these values match TxValidity's
    // amounts / owners; that cross-AIR consistency is Stage 2.

    fn honest_trace_with_pins(
        inputs: &[[Block128; STATE_SIZE]; TXBODY_MERKLE_N_PERMS],
        pins: &TxBodyMerkleBoundaryPins,
    ) -> Trace {
        let cols = build_tx_body_merkle_trace_with_boundary_pins(inputs, pins);
        Trace::new_with_domains(cols, tx_body_merkle_column_domains_with_boundary_pins())
    }

    #[test]
    fn stage1b_input_leaf_word_tamper_rejects() {
        let (inputs, honest_pins) = stage1_pins_fixture();
        let trace = honest_trace_with_pins(&inputs, &honest_pins);
        for leaf in 0..4 {
            for word in 0..4 {
                let mut bad_pins = honest_pins.clone();
                bad_pins.input_leaf_absorb[leaf][word] += Block128::ONE;
                let air = TxBodyMerkleAir::new_with_boundary_pins(bad_pins);
                assert!(
                    !air.check(&trace),
                    "AIR accepted tampered input_leaf_absorb[{leaf}][{word}]",
                );
            }
        }
    }

    #[test]
    fn stage1b_output_leaf_word_tamper_rejects() {
        let (inputs, honest_pins) = stage1_pins_fixture();
        let trace = honest_trace_with_pins(&inputs, &honest_pins);
        for leaf in 0..8 {
            for word in 0..3 {
                let mut bad_pins = honest_pins.clone();
                bad_pins.output_leaf_absorb[leaf][word] += Block128::ONE;
                let air = TxBodyMerkleAir::new_with_boundary_pins(bad_pins);
                assert!(
                    !air.check(&trace),
                    "AIR accepted tampered output_leaf_absorb[{leaf}][{word}]",
                );
            }
        }
    }

    #[test]
    fn stage1b_honest_pins_accepted() {
        let (inputs, honest_pins) = stage1_pins_fixture();
        let air = TxBodyMerkleAir::new_with_boundary_pins(honest_pins.clone());
        let trace = honest_trace_with_pins(&inputs, &honest_pins);
        assert!(air.check(&trace));
    }
}
