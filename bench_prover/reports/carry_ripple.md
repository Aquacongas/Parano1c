# CarryRippleAir benchmark (Stage 3b-0.4)

AIR: 64-bit ripple-carry adder, 5 columns (a, b, sum, carry, is_reset), single rotation read on `carry` (`shifted_columns = [3]`).

Post-3b-0.4: `multipoint_fri` is the single batched FRI opening at `r''` that closes both the base claims at `r_point` and every ladder claim at `r'_s` (CRYPTO.md §12c). `ladder_block` is the per-slot §12a partials + product sumcheck transcript — no per-slot FRI anymore.

## Summary

| label | log_rows | adders | prove | verify (total) | proof size |
|-------|----------|--------|-------|-----------------|------------|
| small | 8 | 4 | 30.57 ms | 11.76 ms | 34.55 KB |
| mid | 12 | 64 | 175.77 ms | 33.97 ms | 185.86 KB |
| prod | 16 | 1024 | 2.05 s | 65.06 ms | 385.17 KB |

## Prover time buckets

| label | commit | transcript+sumcheck | ladder sumcheck | multipoint+FRI | total |
|-------|--------|---------------------|-----------------|----------------|-------|
| small | 14.41 ms (45.7%) | 6.48 ms (20.6%) | 5.96 ms (18.9%) | 4.66 ms (14.8%) | 31.50 ms |
| mid | 95.24 ms (56.8%) | 27.70 ms (16.5%) | 13.43 ms (8.0%) | 31.41 ms (18.7%) | 167.77 ms |
| prod | 1.37 s (70.0%) | 313.86 ms (16.1%) | 108.95 ms (5.6%) | 162.02 ms (8.3%) | 1.95 s |

## Verifier time buckets

| label | transcript+sumcheck | composition | ladder sumcheck | multipoint+FRI | total |
|-------|---------------------|-------------|-----------------|----------------|-------|
| small | 3.63 ms (30.9%) | 10.62 us (0.1%) | 4.66 ms (39.6%) | 3.45 ms (29.4%) | 11.76 ms |
| mid | 4.45 ms (13.1%) | 15.97 us (0.0%) | 6.37 ms (18.7%) | 23.14 ms (68.1%) | 33.97 ms |
| prod | 6.04 ms (9.3%) | 17.57 us (0.0%) | 8.66 ms (13.3%) | 50.34 ms (77.4%) | 65.06 ms |

## Proof-size buckets

| label | multipoint FRI | ladder block | multipoint share | total |
|-------|----------------|--------------|------------------|-------|
| small | 32.62 KB | 800 B | 94.4% | 34.55 KB |
| mid | 183.12 KB | 1.16 KB | 98.5% | 185.86 KB |
| prod | 381.62 KB | 1.53 KB | 99.1% | 385.17 KB |
