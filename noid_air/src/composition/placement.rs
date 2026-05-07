// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Coordinate-system spec for embedded AIRs inside the Stage 5
//! composite.
//!
//! Every embedded sub-AIR (via [`crate::composition::RowWindowWrapper`]
//! once it lands) occupies a rectangular `(col, row)` window of the
//! outer composite trace. [`CompositePlacement`] makes that window
//! first-class data instead of scattered `+ 71` / `+ 106` offset
//! arithmetic at call sites.
//!
//! Invariants enforced by [`validate_placements`]:
//!
//! 1. `col_start < col_end`, `row_start < row_end`.
//! 2. `col_end <= outer_n_cols`, `row_end <= 2^outer_log_rows`.
//! 3. **Column ranges never overlap.** Two sub-AIRs sharing columns
//!    would silently couple their constraints; the allocator
//!    panics at composite construction time.
//! 4. Row ranges **are allowed to overlap** — multiple sub-AIRs
//!    stacked at the same row band on disjoint column blocks is the
//!    expected pattern (e.g. four `HAddrAir × 4` windows share row
//!    band `[0, 256)` on four different column blocks).

/// Rectangular placement of an embedded sub-AIR inside the composite.
/// Half-open intervals: `[col_start, col_end)` × `[row_start, row_end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompositePlacement {
    /// Short debug label — shows up in overlap-check panic messages.
    pub label: &'static str,
    pub col_start: usize,
    pub col_end: usize,
    pub row_start: usize,
    pub row_end: usize,
}

impl CompositePlacement {
    pub const fn new(
        label: &'static str,
        col_start: usize,
        col_end: usize,
        row_start: usize,
        row_end: usize,
    ) -> Self {
        Self {
            label,
            col_start,
            col_end,
            row_start,
            row_end,
        }
    }

    #[inline]
    pub const fn col_range(&self) -> (usize, usize) {
        (self.col_start, self.col_end)
    }

    #[inline]
    pub const fn row_range(&self) -> (usize, usize) {
        (self.row_start, self.row_end)
    }

    #[inline]
    pub const fn n_cols(&self) -> usize {
        self.col_end - self.col_start
    }

    #[inline]
    pub const fn n_rows(&self) -> usize {
        self.row_end - self.row_start
    }
}

/// Outcome of [`validate_placements`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlacementError {
    DegenerateRange {
        label: &'static str,
    },
    OutOfBounds {
        label: &'static str,
        col_end: usize,
        outer_n_cols: usize,
        row_end: usize,
        outer_n_rows: usize,
    },
    ColumnOverlap {
        left_label: &'static str,
        right_label: &'static str,
        overlap_start: usize,
        overlap_end: usize,
    },
}

/// Validate a list of embedded placements against the outer trace
/// shape. Enforces the four invariants documented at module level.
///
/// Called once at composite construction; its cost is `O(n log n)` on
/// the number of embedded AIRs (~20 in the Stage 5 design), dwarfed
/// by every other composite-build step.
pub fn validate_placements(
    placements: &[CompositePlacement],
    outer_n_cols: usize,
    outer_log_rows: usize,
) -> Result<(), PlacementError> {
    let outer_n_rows = 1usize << outer_log_rows;

    for p in placements {
        if p.col_start >= p.col_end || p.row_start >= p.row_end {
            return Err(PlacementError::DegenerateRange { label: p.label });
        }
        if p.col_end > outer_n_cols || p.row_end > outer_n_rows {
            return Err(PlacementError::OutOfBounds {
                label: p.label,
                col_end: p.col_end,
                outer_n_cols,
                row_end: p.row_end,
                outer_n_rows,
            });
        }
    }

    // Column-overlap check: sort by col_start, then sweep.
    let mut sorted: Vec<&CompositePlacement> = placements.iter().collect();
    sorted.sort_by_key(|p| p.col_start);
    for window in sorted.windows(2) {
        let left = window[0];
        let right = window[1];
        if right.col_start < left.col_end {
            return Err(PlacementError::ColumnOverlap {
                left_label: left.label,
                right_label: right.label,
                overlap_start: right.col_start,
                overlap_end: left.col_end.min(right.col_end),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disjoint_columns_row_overlap_ok() {
        let a = CompositePlacement::new("A", 0, 71, 0, 256);
        let b = CompositePlacement::new("B", 71, 177, 0, 256);
        let c = CompositePlacement::new("C", 177, 283, 0, 256);
        assert!(validate_placements(&[a, b, c], 512, 13).is_ok());
    }

    #[test]
    fn column_overlap_rejected() {
        let a = CompositePlacement::new("A", 0, 100, 0, 256);
        let b = CompositePlacement::new("B", 50, 200, 0, 256);
        let err = validate_placements(&[a, b], 512, 13).unwrap_err();
        match err {
            PlacementError::ColumnOverlap {
                left_label,
                right_label,
                ..
            } => {
                assert_eq!(left_label, "A");
                assert_eq!(right_label, "B");
            }
            _ => panic!("expected column overlap"),
        }
    }

    #[test]
    fn column_out_of_bounds_rejected() {
        let a = CompositePlacement::new("A", 0, 100, 0, 256);
        assert!(matches!(
            validate_placements(&[a], 64, 13),
            Err(PlacementError::OutOfBounds { .. })
        ));
    }

    #[test]
    fn row_out_of_bounds_rejected() {
        let a = CompositePlacement::new("A", 0, 100, 0, 16384);
        assert!(matches!(
            validate_placements(&[a], 256, 13),
            Err(PlacementError::OutOfBounds { .. })
        ));
    }

    #[test]
    fn degenerate_range_rejected() {
        let a = CompositePlacement::new("A", 10, 10, 0, 256);
        assert!(matches!(
            validate_placements(&[a], 256, 13),
            Err(PlacementError::DegenerateRange { .. })
        ));
    }

    #[test]
    fn stage5_plan_full_layout_ok() {
        // Rough simulation of the Stage 5 Option-A layout to sanity-check
        // that the plan is in fact non-overlapping and fits at log_rows=13.
        let spine = CompositePlacement::new("Spine", 0, 354, 0, 8192);
        let haddr = (0..4).map(|i| {
            CompositePlacement::new(
                "HAddr",
                354 + i * 71,
                354 + (i + 1) * 71,
                i * 256,
                (i + 1) * 256,
            )
        });
        let haddr_end = 354 + 4 * 71;
        let hauth = (0..4).map(|i| {
            CompositePlacement::new(
                "HAuth",
                haddr_end + i * 106,
                haddr_end + (i + 1) * 106,
                i * 256,
                (i + 1) * 256,
            )
        });
        let hauth_end = haddr_end + 4 * 106;
        let hleaf = (0..8).map(|j| {
            CompositePlacement::new(
                "HLeaf",
                hauth_end + j * 106,
                hauth_end + (j + 1) * 106,
                j * 256,
                (j + 1) * 256,
            )
        });
        let hleaf_end = hauth_end + 8 * 106;
        let fri_open = CompositePlacement::new("FriOpen", hleaf_end, hleaf_end + 70, 0, 8);
        let fri_comb = CompositePlacement::new(
            "FriCombiner",
            hleaf_end + 70,
            hleaf_end + 70 + 112,
            0,
            512,
        );
        let mut all: Vec<CompositePlacement> =
            vec![spine, fri_open, fri_comb];
        all.extend(haddr);
        all.extend(hauth);
        all.extend(hleaf);

        // Placement fits inside a 2500-column × 2^13-row outer trace.
        assert!(validate_placements(&all, 2500, 13).is_ok());
    }
}
