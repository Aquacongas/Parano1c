# Paranoid

Paranoid is a proof-native UTXO blockchain written in Rust. The node validates
proof-of-work and block certificates, stores chain state in MDBX, and maintains
a recursive selected-history ladder. A constant-size terminal proof commits to
the selected chain history through a specific height.

The current release configuration uses the m22 Link class and four Block
classes: B8, B32, B64, and B255. The class registry and nine canonical R1CS
matrices are authenticated at build time and embedded in the `paranoid`
executable. A deployed node does not need matrix files beside the binary.

## Requirements

- Linux with Bash and the standard GNU userland (`tar`, `gzip`, `sha256sum`,
  and util-linux `flock`)
- Rust and Cargo with the `rustfmt` component; the current tree is verified
  with Rust 1.96.0
- A C/C++ toolchain, `pkg-config`, libclang, and OpenSSL development headers
  for native dependencies
- Python 3 for the optional live wallet scenarios in `scripts/`
- Enough RAM and disk space for proof generation and a full matrix rebuild

`Cargo.lock` is part of the release source. Use `--locked` for builds and tests
so Cargo fails instead of silently resolving a different dependency graph.

The workspace sets `-C target-cpu=native` in `.cargo/config.toml`. Release
binaries may therefore use instructions available on the build machine. Build
official artifacts on the minimum CPU baseline that the release promises to
support.

All commands below are run from the repository root.

## Automated release build

```bash
./scripts/build_release.sh
```

The script:

1. Runs the formatting gate and checks every workspace target with warnings
   denied.
2. Builds the matrix generator and pin tool from the locked dependency graph.
3. Invokes `noid_matrix_gen` exactly once, directly at zstd level 19.
4. Requires the registry plus exactly nine canonical matrix leaves.
5. Checks the independently approved m22 registry digest and computes leaf
   pins over the final compressed bytes.
6. Builds `paranoid` and `noid-cli` with the authenticated pack embedded.
7. Runs the release test suite.
8. Creates a normalized binary archive and SHA-256 checksums.

Each invocation uses a new output directory under
`target/release-builds/`. On success it prints every output path and writes the
absolute release path to `target/release-builds/LAST_RELEASE`. The output is:

```text
<release-directory>/
├── pack/
│   ├── pins.env
│   └── v1/
│       ├── selected-recursive.classes
│       └── nine *.field-r1cs.zst leaves
├── bin/
│   ├── paranoid
│   └── noid-cli
├── paranoid-release.tar.gz
├── SHA256SUMS
└── build.log
```

An optional destination can be passed as the only argument. The destination
must not already exist. `NOID_RELEASE_SKIP_TESTS=1` is available for a
local development build.

## Manual reference: build from an existing matrix pack

The pack root may contain the artifacts directly or in a `v1/` directory. The
standard layout is:

```text
target/release-pack/
├── pins.env
└── v1/
    ├── selected-recursive.classes
    ├── genesis-link.field-r1cs.zst
    ├── link-b8.field-r1cs.zst
    ├── link-b32.field-r1cs.zst
    ├── link-b64.field-r1cs.zst
    ├── link-b255.field-r1cs.zst
    ├── block-b8.field-r1cs.zst
    ├── block-b32.field-r1cs.zst
    ├── block-b64.field-r1cs.zst
    └── block-b255.field-r1cs.zst
```

Build the daemon and RPC client:

```bash
(
  set -euo pipefail
  PACK_ROOT="$PWD/target/release-pack"
  source "$PACK_ROOT/pins.env"
  export NOID_SELECTED_RECURSIVE_PACK_DIR="$PACK_ROOT"
  cargo build --locked --release -p noid_node --bins
)
```

The output is:

```text
target/release/paranoid   # node daemon
target/release/noid-cli   # JSON-RPC client
```

To build the complete workspace in the same environment:

```bash
(
  set -euo pipefail
  PACK_ROOT="$PWD/target/release-pack"
  source "$PACK_ROOT/pins.env"
  export NOID_SELECTED_RECURSIVE_PACK_DIR="$PACK_ROOT"
  cargo build --locked --release --workspace
)
```

A release build of `noid_node` requires the complete authenticated matrix
pack. The build stops with an error unless all three variables below are
present and valid:

- `NOID_SELECTED_RECURSIVE_PACK_DIR`
- `NOID_SELECTED_RECURSIVE_REGISTRY_RELEASE_DIGEST`
- `NOID_SELECTED_RECURSIVE_PACK_LEAF_DIGESTS`

`pins.env` exports the two digest variables. The pack directory is supplied
separately. `noid_node/build.rs` rejects a missing variable, a malformed pack,
or a digest mismatch.

A debug build may intentionally omit the release pack:

```bash
env \
  -u NOID_SELECTED_RECURSIVE_PACK_DIR \
  -u NOID_SELECTED_RECURSIVE_REGISTRY_RELEASE_DIGEST \
  -u NOID_SELECTED_RECURSIVE_PACK_LEAF_DIGESTS \
  cargo build --locked -p noid_node --bins
```

That build is intended for pack-free development. A pack-free relay disables
selected-history snapshot admission. `miner`, `prover`, and `extminer` modes
require a build-authenticated embedded pack and refuse to start without one.

## Manual reference: generate the registry and matrices

### 1. Build the generation tools

```bash
cargo build --locked --release -p bench_prover \
  --bin noid_matrix_gen \
  --bin noid_matrix_stats \
  --bin noid_pack_pins
```

### 2. Generate the final canonical pack

Use a new output directory so an independent rebuild cannot overwrite an
already approved pack:

```bash
(
  set -euo pipefail
  PACK_ROOT="$PWD/target/release-pack"
  test ! -e "$PACK_ROOT"
  NOID_ARTIFACT_ZSTD_LEVEL=19 \
    ./target/release/noid_matrix_gen "$PACK_ROOT"
)
```

The generator performs six canonical stages:

1. Build one canonical floor fixture for each B8/B32/B64/B255 Block class.
2. Freeze the four Block classes.
3. Build, prove, verify, and export the four Block matrices.
4. Freeze the four-slot m22 Link ladder and the genesis T relation.
5. Create the class registry, or verify an existing registry against the
   independently rebuilt digest.
6. Export the genesis T matrix and the four Link matrices.

The result is `selected-recursive.classes` plus nine final
`*.field-r1cs.zst` leaves under `$PACK_ROOT/v1/`. The generator is invoked once
and writes level-19 artifacts directly. Its default level 3 remains useful for
local experiments, but it is not part of this release procedure. Do not rerun
the generator and do not externally recompress these files.

The relations and registry identities are deterministic. Compressed bytes can
still vary with the zstd implementation or thread configuration, so release
pins bind the exact final byte streams.

### 3. Validate the compact pack

Remove generator receipts and require the exact release layout:

```bash
(
  set -euo pipefail
  PACK_ROOT="$PWD/target/release-pack"
  PACK_V1="$PACK_ROOT/v1"
  expected=(
    selected-recursive.classes
    genesis-link.field-r1cs.zst
    link-b8.field-r1cs.zst
    link-b32.field-r1cs.zst
    link-b64.field-r1cs.zst
    link-b255.field-r1cs.zst
    block-b8.field-r1cs.zst
    block-b32.field-r1cs.zst
    block-b64.field-r1cs.zst
    block-b255.field-r1cs.zst
  )

  for name in "${expected[@]}"; do
    test -s "$PACK_V1/$name"
    test ! -L "$PACK_V1/$name"
  done

  find "$PACK_V1" -mindepth 1 -maxdepth 1 -name '*.trust' -delete

  shopt -s nullglob dotglob
  entries=("$PACK_V1"/*)
  leaves=("$PACK_V1"/*.field-r1cs.zst)
  test "${#entries[@]}" -eq 10
  test "${#leaves[@]}" -eq 9
  for path in "${entries[@]}"; do
    test -f "$path"
    test ! -L "$path"
  done

  du -sh "$PACK_ROOT"
)
```

The current m22 pack contains exactly nine compressed matrix leaves. The
approved set is approximately 23 MiB, although filesystem reporting and
compression versions can change the displayed size slightly.

### 4. Compute release pins

The registry digest is the 32-byte trailer of
`selected-recursive.classes`. Matrix leaf digests are computed over the exact
compressed bytes in consensus order: genesis T, four Link leaves, then four
Block leaves.

```bash
(
  set -euo pipefail
  PACK_ROOT="$PWD/target/release-pack"
  APPROVED_REGISTRY_DIGEST="fdebbe54ad2f473458e7dcdf4cc5905e224fd6f816c0c62acd8b18e398de756a"

  REGISTRY_DIGEST="$(
    tail -c 32 "$PACK_ROOT/v1/selected-recursive.classes" |
      od -An -tx1 |
      tr -d ' \n'
  )"

  LEAF_DIGESTS="$(
    ./target/release/noid_pack_pins "$PACK_ROOT" |
      sed -n 's/^NOID_SELECTED_RECURSIVE_PACK_LEAF_DIGESTS=//p'
  )"

  [[ $REGISTRY_DIGEST =~ ^[0-9a-f]{64}$ ]]
  [[ $LEAF_DIGESTS =~ ^[0-9a-f]{576}$ ]]
  test "$REGISTRY_DIGEST" = "$APPROVED_REGISTRY_DIGEST"

  printf 'export NOID_SELECTED_RECURSIVE_REGISTRY_RELEASE_DIGEST=%s\nexport NOID_SELECTED_RECURSIVE_PACK_LEAF_DIGESTS=%s\n' \
    "$REGISTRY_DIGEST" \
    "$LEAF_DIGESTS" \
    > "$PACK_ROOT/pins.env"

  cat "$PACK_ROOT/pins.env"
)
```

Compute pins only from the final level-19 artifacts. Changing the compressed
byte stream changes a leaf digest even when the decoded relation is identical.
Treat any unexpected registry or matrix drift as a release failure until it
has been independently reproduced and reviewed.

The independently reproduced registry pin for the current m22 release is:

```text
fdebbe54ad2f473458e7dcdf4cc5905e224fd6f816c0c62acd8b18e398de756a
```

Computing a pin from the same pack being assembled is not independent
authorization. Compare the result with the approved release record before
building a distributable binary.

### 5. Inspect matrix sizes

The optional sizing tool decodes the selected artifacts and compares their
current representation with a planar encoding experiment:

```bash
(
  set -euo pipefail
  PACK_ROOT="$PWD/target/release-pack"
  ./target/release/noid_matrix_stats \
    "$PACK_ROOT"/v1/*.field-r1cs.zst
)
```

This can be expensive for large classes and is not required for a normal node
build.

### 6. Build the self-contained release

```bash
(
  set -euo pipefail
  PACK_ROOT="$PWD/target/release-pack"
  source "$PACK_ROOT/pins.env"
  export NOID_SELECTED_RECURSIVE_PACK_DIR="$PACK_ROOT"
  cargo build --locked --release -p noid_node --bins
)
```

During this build, `noid_node/build.rs`:

1. Validates the registry format, internal digest, and supplied registry pin,
   which the preceding step already compared with the approved digest.
2. Validates the Poseidon2b pin of every compressed matrix leaf.
3. Copies the authenticated bytes into Cargo's build output directory.
4. Embeds those immutable bytes with `include_bytes!`.

This closes the validation-to-compilation substitution window. There is no
runtime filesystem fallback for the selected-recursive pack.

The manual build leaves its binaries in `target/release/`. Use
`build_release.sh` for a publication archive with normalized metadata, exact
member validation, checksums, and a retained build log.

## Verification gates

Run formatting and warning-free static checks first:

```bash
(
  set -euo pipefail
  cargo fmt --all -- --check
  env -u CARGO_ENCODED_RUSTFLAGS \
    RUSTFLAGS='-C target-cpu=native -D warnings' \
    cargo check --locked --workspace --all-targets
)
```

Run the main selected-history tests:

```bash
(
  set -euo pipefail
  cargo test --locked -p noid_recursive --lib
  cargo test --locked -p noid_node -p noid_chain -p noid_miner
)
```

Release-profile gates need the authenticated pack environment:

```bash
(
  set -euo pipefail
  PACK_ROOT="$PWD/target/release-pack"
  source "$PACK_ROOT/pins.env"
  export NOID_SELECTED_RECURSIVE_PACK_DIR="$PACK_ROOT"
  cargo test --locked --release \
    -p noid_recursive \
    -p noid_node \
    -p noid_chain \
    -p noid_miner
  cargo build --locked --release --workspace
)
```

The optional full-workspace release gate is:

```bash
(
  set -euo pipefail
  PACK_ROOT="$PWD/target/release-pack"
  source "$PACK_ROOT/pins.env"
  export NOID_SELECTED_RECURSIVE_PACK_DIR="$PACK_ROOT"
  cargo test --locked --release --workspace
)
```

Do not make a drift failure pass by weakening a test or replacing a pin before
the registry and matrices have been independently regenerated and checked.

## Run a node

The daemon has four operating modes:

| Mode | Behavior |
|---|---|
| `relay` | Validates blocks and remote selected-history terminals; does not mine or build local proofs |
| `prover` | Relay behavior plus the local selected-history worker; no mining |
| `miner` | Internal PoW mining, block-certificate assembly, and the selected-history worker |
| `extminer` | Serves external mining templates and runs the selected-history worker; requires `--mining-key` |

Use `--genesis` only for the first node of a new network. Do not use it when
joining or restarting an existing chain.

Example single-node mining and proving run:

The examples prefer the most recent automated release and fall back to
`target/release/` for a manual build. Set `BIN_DIR` before a block to override
that selection.

```bash
set -euo pipefail
if [[ -z ${BIN_DIR:-} ]]; then
  if [[ -f "$PWD/target/release-builds/LAST_RELEASE" ]]; then
    BIN_DIR="$(< "$PWD/target/release-builds/LAST_RELEASE")/bin"
  else
    BIN_DIR="$PWD/target/release"
  fi
fi
RUN_PARENT="$PWD/target/live-tests"
mkdir -p "$RUN_PARENT"
RUN="$(mktemp -d "$RUN_PARENT/m22-one-node.XXXXXX")"
printf '%s\n' "$RUN" > "$RUN_PARENT/LAST_M22_RUN"

"$BIN_DIR/paranoid" \
  --mode miner \
  --genesis \
  --mining-threads 1 \
  --data-dir "$RUN/data" \
  --p2p-listen 127.0.0.1:19750 \
  --rpc-listen 127.0.0.1:19751 \
  --log info 2>&1 | tee "$RUN/node.log"
```

Use a new, empty data directory for a clean measurement. From another shell:

```bash
set -euo pipefail
if [[ -z ${BIN_DIR:-} ]]; then
  if [[ -f "$PWD/target/release-builds/LAST_RELEASE" ]]; then
    BIN_DIR="$(< "$PWD/target/release-builds/LAST_RELEASE")/bin"
  else
    BIN_DIR="$PWD/target/release"
  fi
fi
export NOID_RPC=http://127.0.0.1:19751

"$BIN_DIR/noid-cli" status
"$BIN_DIR/noid-cli" mining
"$BIN_DIR/noid-cli" proof
"$BIN_DIR/noid-cli" stop
```

A release node with an embedded pack reports these startup markers:

```text
self-contained selected-recursive pack authenticated from the node image
selected-history verifier uses only executable-embedded registry and matrices
selected-history prover registry retained for all pipeline drains
```

## Selected-history pipeline

Every accepted block creates a durable proof job in MDBX and wakes a dedicated
worker. The worker uses three ordered stages:

1. **Block:** claim the next durable job, load its inputs, replay the state
   transition, construct the in-memory end-state cursor, and build the selected
   Block proof. The successor uses the preceding in-memory end state; durable
   state loading is needed only at the head of a pipeline session.
2. **Link:** build the m22 Link proof. The exact terminal bytes produced for
   height `N` become the predecessor for height `N+1` in the same ordered lane.
3. **Verify and promote:** verify the terminal proof against the pinned
   registry and matrix authority, then atomically promote it in FIFO order.
   MDBX independently enforces exact predecessor coverage.

The stage handoffs use bounded channels with capacity one. Each proof-memory
session admits at most three consecutive claims. Available memory and retained
ladder overlays determine whether the active depth is one, two, or three;
B255 work is always sequential. A failure, cancellation, or reorganization
releases unpromoted durable jobs for a later retry.

In `miner` mode, PoW runs concurrently with the selected-history worker.
`prover` runs the same proof pipeline without PoW.

### Pipeline timing

Successful promotions are logged as:

```bash
RUN="$(< "$PWD/target/live-tests/LAST_M22_RUN")"
rg 'selected-history terminal promoted' "$RUN/node.log"
```

The record includes:

- `block_ms`: durable state loading, pipeline-head predecessor decoding,
  replay, and selected Block proving
- `link_ms`: local or in-pipeline predecessor resolution, m22 Link proving,
  and terminal-package encoding
- `verify_ms`: terminal-proof verification
- `block_queue_ms`, `link_queue_ms`, and `verify_queue_ms`: time waiting before
  each stage
- `promote_ms`: the atomic store promotion
- `e2e_ms`: latency from claim to promotion for that height
- `cadence_ms`: interval between consecutive promotions

`e2e_ms` starts when the durable job is claimed, not when the block was mined.
`cadence_ms` is the throughput signal only while the pipeline has continuous
work; an idle interval is intentionally included in the next cadence sample.
A `block found` record belongs to normal mining and is not the recursive
Block-stage measurement.

The existing phase records isolate work inside a slow Block or Link stage:

```bash
RUN="$(< "$PWD/target/live-tests/LAST_M22_RUN")"
rg 'selected-history (Block build/prove phases|Link stage phases|Link sequential matrix phases|m22 Link body phases)' \
  "$RUN/node.log"
```

Detailed kernel timing is opt-in because it produces noisy logs and can affect
measurements:

```bash
set -euo pipefail
if [[ -z ${BIN_DIR:-} ]]; then
  if [[ -f "$PWD/target/release-builds/LAST_RELEASE" ]]; then
    BIN_DIR="$(< "$PWD/target/release-builds/LAST_RELEASE")/bin"
  else
    BIN_DIR="$PWD/target/release"
  fi
fi
RUN_PARENT="$PWD/target/live-tests"
mkdir -p "$RUN_PARENT"
DIAG_RUN="$(mktemp -d "$RUN_PARENT/m22-diagnostics.XXXXXX")"

NOIDH_FIELD_PROVE_TIMING=1 \
NOIDH_SIDECAR_TIMING=1 \
NOIDH_COMMIT_TIMING=1 \
NOIDH_ZC_TIMING=1 \
NOIDH_MATRIX_FOLD_TIMING=1 \
NOIDH_DEEP_CHAIN_TIMING=1 \
PCS_TRACE=1 \
"$BIN_DIR/paranoid" \
  --mode miner \
  --genesis \
  --mining-threads 1 \
  --data-dir "$DIAG_RUN/data" \
  --p2p-listen 127.0.0.1:19760 \
  --rpc-listen 127.0.0.1:19761 \
  --log info 2>&1 | tee "$DIAG_RUN/node.log"
```

## Embedded matrix lifecycle

The executable contains the compact registry bytes and all nine compressed
matrix leaves. In `miner`, `prover`, and `extminer` modes, startup authenticates
the embedded authority and materializes the B8 Link/Block pair in packed
storage before opening P2P or RPC listeners. Genesis T remains compact-planar;
it is prewarmed while local selected-history coverage is at height zero and
can be evicted after it becomes idle. Relay mode keeps the embedded
verification authority but does not perform prover prewarm. Larger tiers are
materialized lazily under a memory-governed LRU cache and process-wide
proof-memory admission. Active matrix leases are never evicted.

Each matrix is checked at two levels during its lifecycle:

1. At build time, its compressed leaf digest must match the supplied release
   pin before the bytes are embedded.
2. When materialized at runtime, its decoded relation shape and structural
   digest must match the pinned registry identity.

The prover and terminal verifier share this authenticated in-memory matrix
bank. Runtime operation does not trust or load release-pack paths.

## Optional live wallet scenarios

These scenarios start and stop their own nodes using the binaries in
`target/release/`. Stop conflicting local nodes before running them:

```bash
python3 scripts/live_cli_wallet_scenarios.py
python3 scripts/live_slot_mempool_wallet_scenarios.py
```

Each script deletes and recreates its fixed test directory:
`target/live-tests/cli-wallet/` or
`target/live-tests/slot-mempool-wallet/`. Preserve anything needed from those
directories before running a scenario.

## License

Apache-2.0.
