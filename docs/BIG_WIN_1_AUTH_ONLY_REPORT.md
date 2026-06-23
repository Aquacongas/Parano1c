# BIG WIN 1 Auth-only Wallet Authorization Report

## 1. Executive Result

The wallet-transmitted public TxLogic STARK path was removed. Wallets now emit
`WalletAuthorizationBundle`, an AuthGKR Kill-Shot proof only. Public transaction
arithmetic is checked natively at mempool admission and is still proved inside
the canonical block buckets rebuilt from `TxBody`.

Confirmed invariants:

- The canonical accepted block relation is unchanged.
- The wallet-transmitted public STARK has been removed.
- The recipient remains non-interactive.
- No old wire format or fallback decoder remains.

## 2. Before/After Dataflow

Before:

```text
Wallet -> TxBody + WalletProofBundle(LogicProof/SweepLogicProof STARK + AuthGKR)
Mempool -> decode wallet STARK bundle + verify_logic*
Block -> rebuild public AIR from TxBody and reuse wallet auth proof
```

After:

```text
Wallet -> TxBody + WalletAuthorizationBundle(AuthGKR only)
Mempool -> validate_public_tx_logic + strict auth decode + AuthGKR verify
Block -> rebuild public TxLogic AIR from TxBody + include auth-only capsule
```

## 3. File List And Key APIs

- `noid_tx/src/public_logic.rs`: new exact public predicate.
- `noid_gkr/src/auth_statement.rs`: verifier-derived Standard/Sweep auth statements.
- `noid_gkr/src/wallet_authorization.rs`: new auth-only bundle, strict codec, prover, verifier.
- `noid_mempool/src/pool.rs`: native public predicate before AuthGKR verification.
- `noid_node/src/wallet/prover.rs`: wallet proves authorization only.
- `noid_block/src/witness_builder.rs`: block witness still rebuilds public AIR from `TxBody`.
- `noid_miner/src/miner.rs`: decodes authorization bundles in transaction order.
- `noid_stark/src/wallet_bundle.rs`, `noid_stark/src/prove_logic.rs`,
  `noid_stark/src/prove_logic_sweep.rs`: deleted old wallet STARK path.

## 4. Security Proof Correspondence

| Theorem | Code | Test evidence |
| --- | --- | --- |
| Public arithmetic is not trusted from wallet bytes | `validate_public_tx_logic` | `noid_tx` unit tests |
| Auth statement is verifier-derived | `standard_auth_public_from_body`, `sweep_auth_public_from_body` | `noid_gkr` auth tests |
| Strict auth wire format | `WalletAuthorizationBundle::from_bytes*` | `wallet_authorization::tests::*decoder*` |
| Proof/body tamper rejects | `verify_wallet_authorization` | `proof_and_body_tamper_reject` |
| Secrets are not serialized | `WalletAuthorizationBundle` carries proof only | `spend_secret_bytes_are_absent_from_serialization` |
| Canonical block proof remains required | `build_tx_witness`, `validate_block_full` | block release tests |

## 5. Differential Corpus Results

Implemented focused public predicate unit coverage for Standard and Sweep
balance/count/coinbase/fee cases. A large 100k AIR-equivalence corpus was not
run in this session.

## 6. Mutation Tests

Covered:

- trailing bytes rejected;
- unknown discriminant rejected;
- wrong bundle variant rejected;
- proof field tamper rejected;
- body owner tamper rejected;
- missing, extra, and wrong secrets rejected before proving;
- raw secret bytes absent from serialized authorization.

## 7. Benchmark Table

Benchmarks run in this session:

```text
cargo bench -p bench_prover --bench alice_sends_bob
cargo bench -p bench_prover --bench block_scaling
cargo bench -p bench_prover --bench block_hotspots
```

Wallet authorization results:

| Scenario | Prove median | Verify median | Wallet bundle | STARK bytes |
| --- | ---: | ---: | ---: | ---: |
| Standard4x8 1-in/2-out | 76.02 ms | 15.93 ms | 117.75 KiB | 0 B |
| Standard4x8 4-in/8-out | 78.90 ms | 13.84 ms | 120.85 KiB | 0 B |
| Sweep25x2 5-in/2-out | 260.87 ms | 40.51 ms | 166.91 KiB | 0 B |
| Sweep25x2 10-in/2-out | 250.11 ms | 42.45 ms | 165.79 KiB | 0 B |
| Sweep25x2 25-in/2-out | 269.69 ms | 40.27 ms | 165.47 KiB | 0 B |
| Sweep25x2 25-in/1-out | 251.61 ms | 35.96 ms | 165.00 KiB | 0 B |

Production block proof samples:

| Scenario | Full prove | Full verify | Block proof | Auth sidecar | Total |
| --- | ---: | ---: | ---: | ---: | ---: |
| 10 Standard4x8 | 2.84 s | 636.93 ms | 3.58 MiB | 1.18 MiB | 4.77 MiB |
| 20 Standard4x8 | 4.28 s | 1.13 s | 4.40 MiB | 2.36 MiB | 6.76 MiB |
| 100 Standard4x8 | 15.93 s | 5.71 s | 10.75 MiB | 11.80 MiB | 22.55 MiB |
| 1 Sweep25x2 | 1.28 s | 295.44 ms | 935.59 KiB | 166.36 KiB | 1.08 MiB |
| 4 Sweep25x2 | 3.21 s | 661.87 ms | 3.07 MiB | 664.05 KiB | 3.72 MiB |
| 10 Sweep25x2 | 5.58 s | 1.29 s | 4.01 MiB | 1.63 MiB | 5.64 MiB |
| 8 Standard + 2 Sweep | 4.83 s | 926.81 ms | 4.50 MiB | 1.27 MiB | 5.76 MiB |
| 5 Standard + 5 Sweep | 5.42 s | 1.33 s | 5.94 MiB | 1.40 MiB | 7.34 MiB |

Hotspot defaults:

| Scenario | Full prove | Full verify | Full block proof |
| --- | ---: | ---: | ---: |
| 2 Standard4x8 | 1.34 s | 257.94 ms | 952.02 KiB |
| 1 Sweep25x2 | 1.53 s | 332.63 ms | 1.23 MiB |

## 8. Wire/Cap Changes

- `TxIntent.logic_proof_bytes` was renamed to `authorization_bytes`.
- Shape-specific authorization caps were added:
  - Standard4x8: 192 KiB
  - Sweep25x2: 256 KiB
- Shape-specific TxIntent caps were reduced to reflect auth-only payloads.
- `has_proof` RPC/CLI wording was renamed to `has_authorization`.

## 9. Live-node Results

Live multi-node tests were not run in this session.

## 10. Deleted Code/Dependencies

Deleted:

- `noid_stark/src/wallet_bundle.rs`
- `noid_stark/src/prove_logic.rs`
- `noid_stark/src/prove_logic_sweep.rs`
- `noid_stark/tests/sweep_logic_proof.rs`
- unused `SegmentedFriState::set_segment_columns_with_root`

Removed the old `noid_stark` bincode dependency used only by the deleted wallet
bundle. Added `bincode` to `noid_gkr` for the new strict authorization codec.

## 11. Known Limitations

- Large randomized AIR-equivalence corpus was not executed.
- Live multi-node tests were not executed.
- `InvalidLogicProof` remains as a consensus error name for block-side TxLogic
  proof failures, which `BIG_WIN_1.md` explicitly allows when it is not the
  wallet wire artifact.

## 12. Final Grep Output Summary

The required audit grep has no production hits after excluding `BIG_WIN_1.md`
and this historical report. Remaining `LogicProof` hits in Rust source are the
existing consensus enum for block-side proof failure, not the wallet artifact.
