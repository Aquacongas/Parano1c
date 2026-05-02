# CarryRippleAir benchmark (Stage 3b-0.4)

AIR: 64-bit ripple-carry adder, 5 columns (a, b, sum, carry, is_reset), single rotation read on `carry` (`shifted_columns = [3]`).

Post-3b-0.4: `multipoint_fri` is the single batched FRI opening at `r''` that closes both the base claims at `r_point` and every ladder claim at `r'_s` (CRYPTO.md §12c). `ladder_block` is the per-slot §12a partials + product sumcheck transcript — no per-slot FRI anymore.

## Summary

| label | log_rows | adders | prove | verify (total) | proof size |
|-------|----------|--------|-------|-----------------|------------|
| small | 8 | 4 | 30.87 ms | 11.04 ms | 34.55 KB |
| mid | 12 | 64 | 202.48 ms | 33.54 ms | 185.86 KB |
| prod | 16 | 1024 | 2.64 s | 58.94 ms | 385.17 KB |

## Prover time buckets

| label | commit | transcript+sumcheck | ladder sumcheck | multipoint+FRI | total |
|-------|--------|---------------------|-----------------|----------------|-------|
| small | 11.65 ms (37.1%) | 6.15 ms (19.6%) | 5.63 ms (17.9%) | 8.01 ms (25.5%) | 31.44 ms |
| mid | 93.12 ms (48.1%) | 27.12 ms (14.0%) | 34.31 ms (17.7%) | 39.00 ms (20.1%) | 193.53 ms |
| prod | 1.30 s (50.5%) | 309.73 ms (12.0%) | 568.39 ms (22.1%) | 398.12 ms (15.5%) | 2.58 s |

## Verifier time buckets

| label | transcript+sumcheck | composition | ladder sumcheck | multipoint+FRI | total |
|-------|---------------------|-------------|-----------------|----------------|-------|
| small | 3.41 ms (30.9%) | 11.54 us (0.1%) | 4.40 ms (39.8%) | 3.22 ms (29.2%) | 11.04 ms |
| mid | 4.38 ms (13.1%) | 14.08 us (0.0%) | 6.36 ms (19.0%) | 22.78 ms (67.9%) | 33.54 ms |
| prod | 5.33 ms (9.0%) | 15.87 us (0.0%) | 8.02 ms (13.6%) | 45.57 ms (77.3%) | 58.94 ms |

## Proof-size buckets

| label | multipoint FRI | ladder block | multipoint share | total |
|-------|----------------|--------------|------------------|-------|
| small | 32.62 KB | 800 B | 94.4% | 34.55 KB |
| mid | 183.12 KB | 1.16 KB | 98.5% | 185.86 KB |
| prod | 381.62 KB | 1.53 KB | 99.1% | 385.17 KB |
