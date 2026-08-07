# PagedSpend wallet path, 20 samples

```text
timestamp       2026-08-06T13:04:28+01:00
git commit      39626b22d53cf2f2c480a7e28446c197dca68043
rustc           1.96.0 (ac68faa20 2026-05-25)
cargo           1.96.0 (30a34c682 2026-05-25)
kernel          Linux 7.0.0-28-generic x86_64
CPU             13th Gen Intel Core i7-1365U, 10 cores / 12 threads
ISA             AVX2, VPCLMULQDQ; no AVX-512
profile         release + debuginfo
samples         20 after one untimed warm-up per case
```

Command:

```text
NOID_WALLET_BENCH_SAMPLES=20 cargo run --release --locked \
  --manifest-path research/two_class/Cargo.toml \
  --bin two-class-wallet-bench
```

The measured path includes page construction, logical hashing, exactly one C1
authorization capsule, atomic-intent encode/decode and local capsule admission.
It excludes network latency and `HistoryStep` proving.

| Case | Pages | Build and hash p50/p95 | Capsule p50/p95 | Admission p50/p95 | Total p50/p95 | Proof / intent |
|---|---:|---:|---:|---:|---:|---:|
| 1 input | 1 | 0.07 / 0.09 ms | 859.58 / 934.25 ms | 28.77 / 30.40 ms | 889.07 / 963.39 ms | 87.16 / 87.48 KiB |
| 100 inputs | 13 | 0.69 / 0.76 ms | 819.96 / 888.62 ms | 29.48 / 31.04 ms | 851.07 / 920.38 ms | 86.72 / 90.83 KiB |
| 1,020 inputs | 128 | 6.62 / 6.99 ms | 806.23 / 884.88 ms | 44.87 / 46.11 ms | 857.86 / 937.07 ms | 87.32 / 127.70 KiB |

PagedSpend fan-in changes page hashing and intent bytes but still creates one
authorization capsule. Capsule time remains independent of page count within
ordinary sample variance.
