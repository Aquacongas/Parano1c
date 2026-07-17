# Production HistoryStep B64/B255 — 20 samples

```text
completed       2026-07-17T02:01:54+01:00
git commit      f87fc782318dcdd98bfc794efc4321c2309f39c1
rustc           1.96.0 (ac68faa20 2026-05-25)
cargo           1.96.0 (30a34c682 2026-05-25)
kernel          Linux 6.17.0-35-generic x86_64
CPU             13th Gen Intel Core i7-1365U, 10 cores / 12 threads
ISA             AVX2, VPCLMULQDQ; no AVX-512
profile         bench/release, RUSTFLAGS=-C target-cpu=native
samples         20 per class, one proved B64 parent reused
desktop load    active non-isolated desktop session
thermal         96–99 C observed during sustained proving
```

The benchmark authenticates the frozen two-entry pack, proves and verifies an
honest recursive B64 parent, then runs the production HistoryStep assembler,
prover, terminal encoder/decoder and verifier. Parent construction, wallet
capsule generation and honest block-fixture construction are setup and excluded
from every timed sample. `prepare = assemble + prove`; PoW nonce search and
durable block commit are not included.

Pack identity:

```text
runtime digest  f2a9a18b677a68f69eb2897b66e5b9187a116e86519549c5cad5642dbf07f504
B64 leaf        afb42de39bc5f03116d99a6deeca047f2e9e05d4bebef12621cebf7c0e997e45
B255 leaf       609485592543299756f7a48d0d21f090484c78652630c391c93c09d9ab6bbca1
```

Command:

```text
PACK_ROOT="$PWD/target/history-step-two-class-m23-m24-r4"
env RUSTFLAGS='-C target-cpu=native' \
  NOID_HISTORY_STEP_PACK_DIR="$PACK_ROOT" \
  NOID_HISTORY_STEP_RUNTIME_METADATA_RELEASE_DIGEST=f2a9a18b677a68f69eb2897b66e5b9187a116e86519549c5cad5642dbf07f504 \
  NOID_HISTORY_STEP_PACK_LEAF_DIGESTS=afb42de39bc5f03116d99a6deeca047f2e9e05d4bebef12621cebf7c0e997e45609485592543299756f7a48d0d21f090484c78652630c391c93c09d9ab6bbca1 \
  NOID_HISTORY_STEP_BENCH_SAMPLES=20 \
  cargo bench --locked -p bench_prover --bench history_step_proof
```

Nearest-rank results:

| Class | Useful rows | Assemble p50/p95 | Prove p50/p95 | Prepare p50/p95 | Verify p50/p95 | Terminal |
|---|---:|---:|---:|---:|---:|---:|
| B64/m23 | 5,705,307 | 5.133 / 5.498 s | 7.195 / 9.829 s | 12.174 / 15.182 s | 0.655 / 0.906 s | 766,549 B |
| B255/m24 | 15,368,233 | 10.311 / 10.647 s | 15.858 / 21.492 s | 26.203 / 32.009 s | 0.771 / 0.859 s | 807,189 B |

Raw prepare milliseconds in execution order:

```text
B64   11615 11939 12012 12048 12460 15072 15320 15182 12669 12174
      12055 12005 12425 15126 15093 15066 14731 11418 11656 12071
B255  25504 25790 30033 31374 25027 25225 32500 28482 25085 25714
      32009 30561 24640 26203 31700 29104 25012 25745 31613 28549
```

Interpretation:

- B64 p50 has 2.826 seconds of preparation margin, but its sustained p95
  exceeds the 15-second target by 182 ms, or 1.213%. This laptop is a valid
  B64 functional floor but does not yet pass the strict release p95 cadence
  gate under the observed desktop/thermal load.
- B255 needs 1.747x more complete-prepare throughput to put its p50 at 15
  seconds and 2.134x for its p95. This machine must remain B64-only.
- B255/B64 is 2.152x at p50 and 2.108x at p95. The assembler is comparatively
  stable; most tail variance is in proving, so optimization should target the
  PCS/field-prover hot path rather than PagedSpend, networking or a third proof
  class.
