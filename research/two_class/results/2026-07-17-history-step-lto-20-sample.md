# Production HistoryStep B64/B255 with Thin LTO — 20 samples

```text
completed       2026-07-17T02:39:22+01:00
git commit      e0f07f2ada72b740fc1ea9c78a9db5cbeb3270ad
benchmark sha   3d8d2233cb4130144f1710fe6e9df8edf286f73085680083bf9dc3ccf1cec3b9
rustc           1.96.0 (ac68faa20 2026-05-25)
kernel          Linux 6.17.0-35-generic x86_64
CPU             13th Gen Intel Core i7-1365U, 10 cores / 12 threads
ISA             AVX2, VPCLMULQDQ; no AVX-512
profile         bench: thin LTO, codegen-units=1, target-cpu=native
samples         20 per class, one proved B64 parent reused per run
desktop load    active non-isolated desktop session, already thermally hot
```

The relation, witness, authenticated matrix pack and benchmark methodology are
identical to `2026-07-17-history-step-20-sample.md`. Only executable codegen
changed. Cargo's checked profile and the experimental environment overrides
resolved to the same 6,740,768-byte benchmark artifact shown above.

Command after the profile was committed:

```text
PACK_ROOT="$PWD/target/history-step-two-class-m23-m24-r4"
env RUSTFLAGS='-C target-cpu=native' \
  NOID_HISTORY_STEP_PACK_DIR="$PACK_ROOT" \
  NOID_HISTORY_STEP_RUNTIME_METADATA_RELEASE_DIGEST=f2a9a18b677a68f69eb2897b66e5b9187a116e86519549c5cad5642dbf07f504 \
  NOID_HISTORY_STEP_PACK_LEAF_DIGESTS=afb42de39bc5f03116d99a6deeca047f2e9e05d4bebef12621cebf7c0e997e45609485592543299756f7a48d0d21f090484c78652630c391c93c09d9ab6bbca1 \
  NOID_HISTORY_STEP_BENCH_FILTER=<B64-or-B255> \
  NOID_HISTORY_STEP_BENCH_SAMPLES=20 \
  cargo bench --locked -p bench_prover --bench history_step_proof
```

Nearest-rank result:

| Class | Useful rows | Assemble p50/p95 | Prove p50/p95 | Prepare p50/p95 | Verify p50/p95 | Terminal |
|---|---:|---:|---:|---:|---:|---:|
| B64/m23 | 5,705,307 | 5.061 / 5.360 s | 6.407 / 9.027 s | 11.472 / 14.387 s | 0.666 / 0.720 s | 766,549 B |
| B255/m24 | 15,368,233 | 10.288 / 10.457 s | 13.993 / 19.249 s | 24.189 / 29.755 s | 0.770 / 1.012 s | 807,189 B |

Raw prepare milliseconds in execution order:

```text
B64   11130 11430 11653 11472 11630 14182 14190 15333 13880 11163
      11179 11230 12058 11457 14387 14290 14034 11044 11136 11266
B255  23568 24122 24207 29755 29640 23602 23996 24148 30444 29431
      23466 23963 24360 28930 29594 23900 24189 29040 26329 23846
```

Compared with the default-codegen 20-sample run:

- prepare p50 improves from 12.174 to 11.472 seconds: 5.766%;
- prepare p95 improves from 15.182 to 14.387 seconds: 5.236%;
- the strict 15-second p95 gate now has 613 ms, or 4.087%, of margin;
- one retained system-level outlier reached 15.333 seconds, but nearest-rank
  p95 correctly selects the nineteenth ordered sample at 14.387 seconds;
- B255 prepare p50 improves from 26.203 to 24.189 seconds: 7.686%;
- B255 prepare p95 improves from 32.009 to 29.755 seconds: 7.042%;
- this laptop still needs 1.613x p50 or 1.984x p95 complete-prepare throughput
  to qualify for B255, so its local production cap correctly remains B64.

The preceding phase trace placed almost all proof time in PCS commit and the
post-commit recursive phase. Thin LTO improves those cross-crate hot paths
without changing consensus, the capsule, HistoryStep matrices or wire format.

The complete pack was subsequently regenerated from a fresh root at commit
`05be8eeec61525bd51cc0744450fab39301dc57d`; runtime metadata and both matrix
leaves were byte-identical. The freezer command, SHA-256 identities and
release pins are recorded in
`2026-07-17-history-step-pack-reproduction.md`.
