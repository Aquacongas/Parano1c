# FROST-GKR benchmark artifact

This standalone crate reproduces the like-for-like comparison used by the
FROST-GKR paper. It is not part of the production workspace or its default
tests.

The benchmark pins
`8e514ff4eb59e7925992e8274c4f10214d7c6b9f`, the revision where the legacy
degree-two spine and Kill-Shot coexist and prove the same batch of 59
width-four Poseidon2b permutations. Comparing against current `main` would not
be honest: the production relation has evolved since that revision.

Run the publication profile from the repository root:

```sh
./research/frost_gkr/run.sh --warmups 3 --samples 20
```

The runner creates an isolated detached worktree, copies only this benchmark
crate into it, and invokes Cargo with `--release --locked`. The pinned
revision's `.cargo/config.toml` supplies `-C target-cpu=native`. Build products
are cached under the repository's ignored `target/` directory; the temporary
worktree is removed on exit.

Before timing anything, the executable constructs both honest proofs, verifies
them, discharges their terminal MLE claims natively, and checks the exact proof
accounting (`287,712` bytes versus `5,568` bytes). It then alternates legacy
and Kill-Shot samples to reduce ordering, temperature, and frequency bias.

Reported measurements distinguish:

- public prover API;
- protocol verifier API, ending in an MLE reduction;
- native terminal discharge of that reduction;
- verifier and native discharge together;
- exact algebraic proof bytes and sumcheck-round counts.

The byte count covers raw field elements in the algebraic proof objects. It
does not include serialization framing, polynomial-commitment openings, or
Merkle authentication paths. Likewise, native terminal discharge is a
benchmark harness for the preserved comparison, not a replacement for the
deployed commitment layer.

Published artifact URL:
<https://github.com/ignotusnemo/parano1d/tree/main/research/frost_gkr>

Reference run: [Intel Core i7-1365U, 20 samples](results/2026-07-17-i7-1365u-20-sample.md).
