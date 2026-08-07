# B25/B255 PagedSpend geometry

This standalone crate checks the production two-class boundary:

1. one canonical multi-page intent uses one witness-hiding authorization capsule;
2. native block validation enforces the exact B25/B255 page and resource limits;
3. one structurally fixed parent representation covers `m=22` and `m=24`.

It is outside the root workspace and release tooling. Run it explicitly:

```text
cargo test --release --locked --manifest-path research/two_class/Cargo.toml
cargo run --release --locked --manifest-path research/two_class/Cargo.toml --bin two-class-census
cargo run --release --locked --manifest-path research/two_class/Cargo.toml --bin two-class-wallet-bench
```

```text
B25 / m22          0..=25 effective page positions
B255 / m24         26..=255 effective page positions
logical group      <=128 user pages, <=1,020 inputs, <=256 outputs
block              <=255 user pages, <=256 total physical pages
block records      <=1,020 inputs, <=510 user outputs
matrix leaves      exactly two
```

The primary reward does not consume an effective page position. An active
development payout consumes one.
