# HistoryStep B64/B255 release-pack clean reproduction

```text
completed       2026-07-17T04:24+01:00 (minute precision)
repository HEAD 05be8eeec61525bd51cc0744450fab39301dc57d
generator built 2026-07-17T02:10:43+01:00
generator sha   3fc405918a671accd14b792f7d5a8e8c2ec415f1dad79cdb12a89c2bddb9d40d
rustc           1.96.0 (ac68faa20 2026-05-25)
profile         release, target-cpu=native
rayon threads   12
wall time       5596.2 seconds
```

The generator binary predates the codegen-only Thin-LTO profile commit
`e0f07f2a`. From its build through the recorded repository HEAD, production
relation/freezer source did not change; outside research results, only the
root Cargo release/bench codegen profile changed. The generator SHA above
therefore identifies the exact executable used instead of attributing the
freeze to a later relink.

The current release generator was run into a fresh pack root:

```text
env NOID_ARTIFACT_ZSTD_LEVEL=19 \
  target/release/noid_matrix_gen \
  target/history-step-two-class-clean-e0f07f2
```

It completed the honest-genesis backbone, both exact parent checkpoints,
candidate/final matrix equality audit, export and final read-back
authentication with `matrices: 2/2` and exit status zero. The final class
exports were:

```text
B64/m23   5,705,307 useful rows    4,584,391 bytes    207,497 ms
B255/m24 15,368,233 useful rows   11,912,603 bytes    300,223 ms
```

The fresh output is byte-identical to the independently generated release
candidate in `target/history-step-two-class-m23-m24-r4`. `cmp` returned zero
for all three files:

| File | Bytes | SHA-256 |
|---|---:|---|
| `history-step.runtime` | 1,732,922 | `413455e41743305cf49d095aaaa0b30ea57bb3fcd4a667df17d8cd2f538afbc5` |
| `history-step-c00.field-r1cs.zst` | 4,584,391 | `29631f7fa112364b2eeebaf8eb16422d31b74c618724d8e6dbf61bdb39abdf55` |
| `history-step-c01.field-r1cs.zst` | 11,912,603 | `7e940e396d453a170df79974fce06e9de770f15267edac664cd98d7a52ec1d84` |

Total pack size is 18,229,916 bytes. The release authentication identities
also reproduce exactly:

```text
runtime metadata  f2a9a18b677a68f69eb2897b66e5b9187a116e86519549c5cad5642dbf07f504
B64 leaf          afb42de39bc5f03116d99a6deeca047f2e9e05d4bebef12621cebf7c0e997e45
B255 leaf         609485592543299756f7a48d0d21f090484c78652630c391c93c09d9ab6bbca1
bank              b24ea342d87aaba68b23c552c379cb40272d8e4f6457add89a5343c21d7339e0
```

Because the clean pack is byte-identical, the Thin-LTO 20-sample measurements
in `2026-07-17-history-step-lto-20-sample.md` apply to this reproduced release
pack without an artifact-identity qualification.
