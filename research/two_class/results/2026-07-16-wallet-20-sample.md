# Two-class PagedSpend wallet path — 20 samples

```text
timestamp       2026-07-16T18:56:56+01:00
git commit      ebdbd87fa513dfa910dd97439854e6771cd9f65f
rustc           1.96.0 (ac68faa20 2026-05-25)
cargo           1.96.0 (30a34c682 2026-05-25)
kernel          Linux 6.17.0-35-generic x86_64
CPU             13th Gen Intel Core i7-1365U, 10 cores / 12 threads
ISA             AVX2, VPCLMULQDQ; no AVX-512
profile         release + debuginfo
samples         20 after one untimed warm-up per case
```

Command:

```text
NOID_WALLET_BENCH_SAMPLES=20 cargo run --release \
  --manifest-path research/two_class/Cargo.toml \
  --bin two-class-wallet-bench
```

The measured path includes page construction, logical hashing, exactly one
unchanged ZK capsule, atomic-intent encode/decode and local capsule admission.
It excludes network RTT and HistoryStep proving.

| Case | Pages | Build+hash p50/p95 | Capsule p50/p95 | Admission p50/p95 | Total p50/p95 | Proof / intent |
|---|---:|---:|---:|---:|---:|---:|
| 1 input | 1 | 0.07 / 0.07 ms | 218.99 / 341.71 ms | 10.29 / 11.25 ms | 228.30 / 352.47 ms | 56.49 / 56.81 KiB |
| 100 inputs | 13 | 0.73 / 0.76 ms | 204.43 / 243.58 ms | 12.09 / 12.69 ms | 217.32 / 255.46 ms | 56.58 / 60.69 KiB |
| 1,020 inputs | 128 | 6.61 / 7.05 ms | 199.98 / 250.82 ms | 27.30 / 29.07 ms | 233.06 / 285.81 ms | 56.11 / 96.50 KiB |

The 1,020-input case confirms that PagedSpend fan-in changes page hashing and
intent bytes but still creates one capsule. Capsule time is independent of the
number of pages within normal sample variance.
