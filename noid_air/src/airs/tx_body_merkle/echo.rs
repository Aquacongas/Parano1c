// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage 3d-0.9.C — echo-column allocator.
//!
//! An **echo column** is a committed witness column held constant across
//! the trace by a selector-gated degree-1 transition gate. It pins one
//! source cell `(src_row, src_col)` on the same lane as an arbitrary
//! number of downstream destination cells `(dst_row_i, dst_col_i)`,
//! with `dst_row_i > src_row` for every consumer.
//!
//! This module is responsible for:
//!
//! 1. Representing ties (`EchoTie`) — a src pin plus one or more dst
//!    pins on the same lane.
//! 2. Allocating echo columns via interval-graph greedy coloring so
//!    multiple disjoint ties share one column when their live intervals
//!    `[src_row, max(dst_row)]` do not overlap.
//!
//! The allocator is offline and deterministic — running it on the same
//! input list always yields the same assignment, which lets the AIR
//! derive its public-column programmes at construction time.
//!
//! 3d-0.9.D plugs real tx-body-Merkle ties (child-digest → parent-
//! pre-MDS seed, inter-perm absorb XOR) into `enumerate_ties`.

/// One destination pin sharing an echo column's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DstPin {
    pub dst_row: usize,
    pub dst_col: usize,
}

/// A single echo-tie: "the value in trace cell `(src_row, src_col)`
/// equals the value in each `(dst_row_i, dst_col_i)`". `lane` is an
/// opaque tag (e.g. Poseidon2b lane 0..4) carried for debugging and
/// for scheduler heuristics; the allocator does not inspect it beyond
/// using it as part of the deterministic sort key.
///
/// `live_consumers` (added for §3d-0.9.E.4.b) are rows that must
/// observe the echo value but are NOT wired to a `dst_pin` gate —
/// the consumer is a higher-arity gate (e.g. the 3-term rate-absorb
/// gate `pre_s_B + echo_prev_A + echo_right_child == 0`) that reads
/// the echo column directly under its own selector. The allocator
/// widens the live interval to `max(dst_rows ∪ live_consumers)` so
/// the transition gate keeps the echo stable across every reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchoTie {
    pub src_row: usize,
    pub src_col: usize,
    pub dst_pins: Vec<DstPin>,
    pub live_consumers: Vec<usize>,
    pub lane: u8,
}

impl EchoTie {
    /// Iterator over every row the echo value must reach — `dst_pins`
    /// plus the `live_consumers` list.
    fn consumer_rows(&self) -> impl Iterator<Item = usize> + '_ {
        self.dst_pins
            .iter()
            .map(|p| p.dst_row)
            .chain(self.live_consumers.iter().copied())
    }

    /// End of the tie's live interval — the largest consumer row. The
    /// echo column value must stay stable across `[src_row, max_dst_row()]`.
    pub fn max_dst_row(&self) -> usize {
        self.consumer_rows()
            .max()
            .expect("EchoTie must have at least one dst pin or live consumer")
    }

    /// Smallest consumer row — sanity-checked against `src_row` by the
    /// allocator.
    pub fn min_dst_row(&self) -> usize {
        self.consumer_rows()
            .min()
            .expect("EchoTie must have at least one dst pin or live consumer")
    }
}

/// Output of `allocate_echo_columns`. Each `tie_to_column[i]` is the
/// echo-column index assigned to input tie `i`; `columns` carries the
/// list of ties grouped per column (in the order they were assigned)
/// for downstream indicator-programme synthesis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchoAssignments {
    pub tie_to_column: Vec<usize>,
    pub columns: Vec<EchoColumnPlan>,
}

/// All ties that share a single echo column, in ascending `src_row`
/// order. `epochs` lists each tie's live interval so the caller can
/// synthesize the multi-hot `active_interval` indicator programme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchoColumnPlan {
    pub tie_ids: Vec<usize>,
    pub epochs: Vec<EchoEpoch>,
}

/// Live interval of a single tie on its assigned echo column. The
/// `active_interval` indicator is hot on rows `[src_row, max_dst_row]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchoEpoch {
    pub src_row: usize,
    pub max_dst_row: usize,
}

/// Error returned when an input tie is malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchoError {
    /// Tie has neither `dst_pins` nor `live_consumers` — nothing to
    /// widen the live interval to.
    NoConsumers,
    DstBeforeOrAtSrc { tie_idx: usize },
    EmptySrcCol,
}

/// Interval-graph greedy coloring.
///
/// Algorithm:
///
/// 1. Pair each input tie with its index and validate (`dst > src`,
///    non-empty `dst_pins`).
/// 2. Sort by `(src_row, tie.lane, src_col)` ascending — deterministic
///    tie-break so two callers with the same input always get the same
///    assignment.
/// 3. For each tie in sorted order, assign to the **first** column whose
///    recorded `last_end < tie.src_row`; otherwise open a fresh column.
/// 4. Record `(src_row, max_dst_row)` in that column's epoch list and
///    bump its `last_end`.
///
/// Runs in `O(n log n + n · k)` where `k` is the output column count.
/// Good enough for the tx-body AIR scale (tens of ties).
pub fn allocate_echo_columns(ties: &[EchoTie]) -> Result<EchoAssignments, EchoError> {
    for (i, t) in ties.iter().enumerate() {
        if t.dst_pins.is_empty() && t.live_consumers.is_empty() {
            return Err(EchoError::NoConsumers);
        }
        if t.min_dst_row() <= t.src_row {
            return Err(EchoError::DstBeforeOrAtSrc { tie_idx: i });
        }
    }

    let mut order: Vec<usize> = (0..ties.len()).collect();
    order.sort_by_key(|&i| (ties[i].src_row, ties[i].lane, ties[i].src_col));

    let mut columns: Vec<EchoColumnPlan> = Vec::new();
    let mut last_end: Vec<usize> = Vec::new();
    let mut tie_to_column = vec![usize::MAX; ties.len()];

    for i in order {
        let t = &ties[i];
        let end = t.max_dst_row();
        let mut chosen: Option<usize> = None;
        for (col_idx, le) in last_end.iter().enumerate() {
            if *le < t.src_row {
                chosen = Some(col_idx);
                break;
            }
        }
        let col_idx = chosen.unwrap_or_else(|| {
            columns.push(EchoColumnPlan {
                tie_ids: Vec::new(),
                epochs: Vec::new(),
            });
            last_end.push(0);
            columns.len() - 1
        });
        columns[col_idx].tie_ids.push(i);
        columns[col_idx].epochs.push(EchoEpoch {
            src_row: t.src_row,
            max_dst_row: end,
        });
        last_end[col_idx] = end;
        tie_to_column[i] = col_idx;
    }

    Ok(EchoAssignments {
        tie_to_column,
        columns,
    })
}

/// Width of the allocation — number of distinct echo columns used.
pub fn n_echo_columns(assignments: &EchoAssignments) -> usize {
    assignments.columns.len()
}

/// Build the multi-hot active-interval indicator programme for one
/// echo column at a given total row count. Entry `[r]` is `ONE` on
/// every row `r ∈ [epoch.src_row, epoch.max_dst_row]` for some epoch,
/// `ZERO` elsewhere.
///
/// The value type is returned as `Vec<bool>` here so this module stays
/// dependency-free on `Block128`; 3d-0.9.E converts to
/// `Vec<Block128>` via a simple `.iter().map(|b| if *b { ONE } else { ZERO })`
/// shim at the AIR-wiring site.
pub fn column_active_programme(plan: &EchoColumnPlan, total_rows: usize) -> Vec<bool> {
    let mut out = vec![false; total_rows];
    for epoch in &plan.epochs {
        for row in epoch.src_row..=epoch.max_dst_row {
            if row < total_rows {
                out[row] = true;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tie(src_row: usize, dst_rows: &[usize]) -> EchoTie {
        EchoTie {
            src_row,
            src_col: 0,
            dst_pins: dst_rows
                .iter()
                .map(|&r| DstPin {
                    dst_row: r,
                    dst_col: 0,
                })
                .collect(),
            live_consumers: Vec::new(),
            lane: 0,
        }
    }

    #[test]
    fn single_tie_gets_single_column() {
        let ties = vec![tie(0, &[10])];
        let a = allocate_echo_columns(&ties).unwrap();
        assert_eq!(n_echo_columns(&a), 1);
        assert_eq!(a.tie_to_column, vec![0]);
        assert_eq!(a.columns[0].tie_ids, vec![0]);
        assert_eq!(
            a.columns[0].epochs,
            vec![EchoEpoch {
                src_row: 0,
                max_dst_row: 10
            }]
        );
    }

    #[test]
    fn non_overlapping_ties_share_column() {
        // t0: [0..10], t1: [11..20] — disjoint, can share.
        let ties = vec![tie(0, &[10]), tie(11, &[20])];
        let a = allocate_echo_columns(&ties).unwrap();
        assert_eq!(n_echo_columns(&a), 1);
        assert_eq!(a.tie_to_column, vec![0, 0]);
    }

    #[test]
    fn overlapping_ties_get_separate_columns() {
        // t0: [0..10], t1: [5..15] — overlap, need 2 columns.
        let ties = vec![tie(0, &[10]), tie(5, &[15])];
        let a = allocate_echo_columns(&ties).unwrap();
        assert_eq!(n_echo_columns(&a), 2);
        assert_eq!(a.tie_to_column, vec![0, 1]);
    }

    #[test]
    fn tight_seam_is_disallowed() {
        // t0: [0..10], t1: [10..20] — seam, src=end, must NOT share
        // (the transition gate only stays valid under strict
        // `last_end < src_row`; equality would collapse the echo value
        // at row 10).
        let ties = vec![tie(0, &[10]), tie(10, &[20])];
        let a = allocate_echo_columns(&ties).unwrap();
        assert_eq!(n_echo_columns(&a), 2);
    }

    #[test]
    fn three_overlapping_need_three_columns() {
        let ties = vec![tie(0, &[20]), tie(5, &[25]), tie(10, &[30])];
        let a = allocate_echo_columns(&ties).unwrap();
        assert_eq!(n_echo_columns(&a), 3);
    }

    #[test]
    fn chain_of_disjoint_ties_collapses_to_one_column() {
        let ties = vec![
            tie(0, &[5]),
            tie(6, &[10]),
            tie(11, &[15]),
            tie(16, &[20]),
            tie(21, &[25]),
        ];
        let a = allocate_echo_columns(&ties).unwrap();
        assert_eq!(n_echo_columns(&a), 1);
        assert_eq!(a.columns[0].tie_ids.len(), 5);
    }

    #[test]
    fn multi_dst_uses_max_as_end() {
        // One tie with three dst rows; the allocator treats the
        // interval as [src, max(dst)] = [0, 30].
        let t = EchoTie {
            src_row: 0,
            src_col: 0,
            dst_pins: vec![
                DstPin {
                    dst_row: 10,
                    dst_col: 0,
                },
                DstPin {
                    dst_row: 30,
                    dst_col: 0,
                },
                DstPin {
                    dst_row: 20,
                    dst_col: 0,
                },
            ],
            live_consumers: Vec::new(),
            lane: 0,
        };
        // Second tie [31..40] must fit after.
        let ties = vec![t, tie(31, &[40])];
        let a = allocate_echo_columns(&ties).unwrap();
        assert_eq!(n_echo_columns(&a), 1);
    }

    #[test]
    fn rejects_no_consumers() {
        let t = EchoTie {
            src_row: 0,
            src_col: 0,
            dst_pins: vec![],
            live_consumers: vec![],
            lane: 0,
        };
        assert_eq!(allocate_echo_columns(&[t]), Err(EchoError::NoConsumers));
    }

    #[test]
    fn live_consumer_extends_live_interval_without_dst_pin() {
        // Tie with only a live_consumer at row 10 — allocator must
        // accept it and produce an epoch [src, 10].
        let t = EchoTie {
            src_row: 0,
            src_col: 0,
            dst_pins: vec![],
            live_consumers: vec![10],
            lane: 0,
        };
        let a = allocate_echo_columns(&[t]).unwrap();
        assert_eq!(a.columns.len(), 1);
        assert_eq!(a.columns[0].epochs[0].max_dst_row, 10);
    }

    #[test]
    fn live_consumer_and_dst_pin_use_max() {
        // dst at 5, live_consumer at 20 — the live interval must extend
        // to 20 so the transition gate keeps the echo stable for both.
        let t = EchoTie {
            src_row: 0,
            src_col: 0,
            dst_pins: vec![DstPin {
                dst_row: 5,
                dst_col: 0,
            }],
            live_consumers: vec![20],
            lane: 0,
        };
        let a = allocate_echo_columns(&[t]).unwrap();
        assert_eq!(a.columns[0].epochs[0].max_dst_row, 20);
    }

    #[test]
    fn rejects_dst_before_src() {
        let ties = vec![tie(10, &[5])];
        assert_eq!(
            allocate_echo_columns(&ties),
            Err(EchoError::DstBeforeOrAtSrc { tie_idx: 0 }),
        );
    }

    #[test]
    fn rejects_dst_equal_to_src() {
        let ties = vec![tie(10, &[10])];
        assert_eq!(
            allocate_echo_columns(&ties),
            Err(EchoError::DstBeforeOrAtSrc { tie_idx: 0 }),
        );
    }

    #[test]
    fn deterministic_output_across_input_permutations() {
        // Two ties that can share a single column — ensure the
        // assignment is identical whether they arrive in order
        // (t0_src=0, t1_src=11) or reversed (the sort by src_row
        // normalises both).
        let ties_a = vec![tie(0, &[10]), tie(11, &[20])];
        let ties_b = vec![tie(11, &[20]), tie(0, &[10])];
        let a = allocate_echo_columns(&ties_a).unwrap();
        let b = allocate_echo_columns(&ties_b).unwrap();
        // In `ties_b` the first input is the later one, so
        // `tie_to_column[0]` is for the 11..20 tie.
        assert_eq!(a.tie_to_column, vec![0, 0]);
        assert_eq!(b.tie_to_column, vec![0, 0]);
        // Both allocators produce exactly one column.
        assert_eq!(a.columns.len(), 1);
        assert_eq!(b.columns.len(), 1);
        // Epochs are recorded in ascending src_row order regardless
        // of input ordering.
        assert_eq!(a.columns[0].epochs, b.columns[0].epochs);
    }

    #[test]
    fn active_programme_multi_hot_shape() {
        let ties = vec![tie(0, &[5]), tie(10, &[15])];
        let a = allocate_echo_columns(&ties).unwrap();
        assert_eq!(n_echo_columns(&a), 1);
        let prog = column_active_programme(&a.columns[0], 20);
        for (r, hot) in prog.iter().enumerate() {
            let expected = (0..=5).contains(&r) || (10..=15).contains(&r);
            assert_eq!(*hot, expected, "row {r}");
        }
    }

    #[test]
    fn active_programme_truncates_at_total_rows() {
        let ties = vec![tie(0, &[100])];
        let a = allocate_echo_columns(&ties).unwrap();
        let prog = column_active_programme(&a.columns[0], 10);
        assert_eq!(prog.len(), 10);
        assert!(prog.iter().all(|b| *b));
    }

    #[test]
    fn tie_max_and_min_dst_row() {
        let t = tie(5, &[12, 8, 20, 9]);
        assert_eq!(t.max_dst_row(), 20);
        assert_eq!(t.min_dst_row(), 8);
    }
}
