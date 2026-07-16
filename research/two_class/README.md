# B64/B255 PagedSpend research laboratory

This standalone crate retains only the hypotheses needed by the production
hard cut:

1. one canonical multi-page intent uses the unchanged witness-hiding capsule;
2. native block validation has the exact B64/B255 page and resource boundary;
3. one structurally fixed parent representation covers m23 and m24.

It is outside the root workspace, consensus, release tools and matrix freezer.
Run it explicitly:

```text
cargo test --manifest-path research/two_class/Cargo.toml
cargo run --release --manifest-path research/two_class/Cargo.toml --bin two-class-census
cargo run --release --manifest-path research/two_class/Cargo.toml --bin two-class-wallet-bench
```

```text
B64 / m23          0..=64 physical user pages
B255 / m24         65..=255 physical user pages
logical group      <=128 pages, <=1,020 inputs, <=256 outputs
block              <=255 pages, <=1,020 inputs, <=510 outputs
matrix leaves      exactly two
```

A128 relation budgets, capsule transpose and Merkle-forest experiments were
deleted when the launch ladder returned to the existing B64/B255 geometries.
