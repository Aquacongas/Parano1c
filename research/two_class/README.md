# Two-class research laboratory

This standalone crate tests only the two hypotheses that must be resolved
before the production hard cut:

1. the complete B128/A128 relation, including PagedSpend and the unchanged ZK
   capsule, fits m23 and the reference-machine cadence;
2. one structurally fixed parent verifier accepts authenticated m23 and m24
   parents, allowing exactly two frozen HistoryStep matrices.

The crate is not part of the root workspace, consensus, release tooling or
matrix freezing. Run it explicitly:

```text
cargo test --manifest-path research/two_class/Cargo.toml
cargo run --release --manifest-path research/two_class/Cargo.toml --bin two-class-census
cargo run --release --manifest-path research/two_class/Cargo.toml --bin two-class-wallet-bench
```

Fixed geometry:

```text
B128/A128 m23       0..=128 physical user pages
B256/A256 m24       129..=255 physical user pages
logical group       <=128 pages, <=1,020 inputs, <=256 outputs
block               <=255 user pages, <=1,020 inputs initially
matrix leaves       exactly two
```

The laboratory retains no archived mixed-tree implementation and no optional
child proof. Partial row counts are diagnostics only. A production port begins
only from a satisfying complete relation and differential parent verifier.
