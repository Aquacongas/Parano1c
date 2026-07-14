# Paranoid

Paranoid is a proof-native UTXO blockchain written in Rust. Every node checks
proof of work and block certificates. Mining nodes also create block
certificates and maintain a recursive selected-history proof whose size does
not grow with chain height. Proof generation is an automatic part of mining,
whether PoW runs inside the node or in an external worker.

The current release uses the m22 Link relation and four Block classes: B8,
B32, B64, and B255. The release binary contains the registry and all nine
runtime matrix images. End users run the binary directly; they do not install
or distribute matrix files.

## Quick start

Node operators normally need only this section. The remaining sections are
for release builders, matrix regeneration, and pipeline diagnostics.

### Hardware and software

| Role | Requirement |
|---|---|
| Node and wallet | The default `./paranoid` process. It validates and relays the chain, serves P2P/RPC, and owns the wallet. It does not mine or create local selected-history proofs. |
| Mining node | At least 16 GiB RAM and a multi-core CPU. The node creates block certificates and selected-history proofs with either built-in or external PoW. Built-in PoW requires at least two logical CPUs and uses one worker by default. |
| Release builder | At least 16 GiB RAM, Linux, Rust with `rustfmt`, a C/C++ toolchain, `pkg-config`, libclang, OpenSSL development headers, Bash, GNU userland, and enough disk for a fresh matrix pack. |

The tracked `.cargo/config.toml` applies `-C target-cpu=native` to every Cargo
build and test started from the repository. `Cargo.lock` fixes dependency
versions; compiler flags do not belong in it. Release compilation stops if the
effective target loses the proof CPU contract: SSE4.1, PCLMULQDQ, AVX2, and
VPCLMULQDQ on x86-64, or AES/PMULL on aarch64. This catches `RUSTFLAGS`
overrides that remove those features and Cargo invoked from outside the
repository. Build an official binary on the least capable supported CPU that
still satisfies this contract.
Python 3 and `rg` are optional conveniences used by later diagnostic examples.

### Release contents

`paranoid-release.tar.gz` contains exactly two executables:

```text
paranoid
noid-cli
```

`paranoid` is the node and owns the wallet key. `noid-cli` is its wallet-control
and JSON-RPC client. No registry or matrix files are required beside them.

In a complete release directory, verify the distributable binaries and archive
with:

```bash
sha256sum -c SHA256SUMS
```

If only the archive is distributed, compare its digest with the published
`paranoid-release.tar.gz` entry instead:

```bash
sha256sum paranoid-release.tar.gz
```

Then unpack the archive and start the node and wallet:

```bash
tar -xzf paranoid-release.tar.gz
./paranoid
```

On first start the node creates:

```text
~/.paranoid/paranoid.toml   node configuration
~/.paranoid/data/           chain database and wallet
```

Default listeners are:

```text
P2P  0.0.0.0:9400
RPC  127.0.0.1:9401
```

The node tries its built-in DNS seeds automatically. To add a known peer
explicitly:

```bash
./paranoid --seed SEED_IP:9400
```

The `--seed` option expects `IP:PORT`, not a DNS name or libp2p multiaddress.
For example, use `127.0.0.1:9400`, not `/ip4/127.0.0.1/tcp/9400`.

### Ways to run the node

| Invocation | What it does |
|---|---|
| `./paranoid` | Ordinary node and wallet. Validates and relays the chain, serves P2P/RPC, and verifies remote proofs. It does not mine. |
| `./paranoid --miner` | Mining node with built-in PoW. The node assembles block certificates and runs the selected-history proof pipeline automatically. |
| `./paranoid --extminer` | Mining node with an external PoW worker. The node still assembles and proves the block and runs the selected-history pipeline; the external worker only searches for the nonce. Requires `--mining-key`. |

There is no separate proving-node role. Producing the Block and Link proofs is
part of both mining configurations.

The release archive does not include the separate external-miner client.

Bootstrap the first node of a new network:

```bash
./paranoid --miner --genesis --mining-threads 1
```

`--genesis` is only for the first node of a fresh network. A miner joining an
existing network uses seeds instead:

```bash
./paranoid \
  --miner \
  --seed SEED_IP:9400 \
  --mining-threads 1
```

See every option with:

```bash
./paranoid --help
```

### Wallet and node control

With the default RPC listener, the client needs no extra flags:

```bash
./noid-cli status
./noid-cli peers
./noid-cli address
./noid-cli balance
./noid-cli history
./noid-cli mining
./noid-cli proof
```

For a non-default endpoint, use `--rpc` or `NOID_RPC`:

```bash
NOID_RPC=http://127.0.0.1:9501 ./noid-cli status
```

Stop the node cleanly:

```bash
./noid-cli stop
```

### Isolated configuration

Use explicit paths for tests or for multiple nodes on one machine. A missing
config file is created automatically with defaults:

```bash
RUN="$PWD/target/my-node"
mkdir -p "$RUN"

./paranoid \
  --config "$RUN/paranoid.toml" \
  --data-dir "$RUN/data" \
  --p2p-listen 127.0.0.1:9500 \
  --rpc-listen 127.0.0.1:9501
```

Command-line overrides apply to that process only; they are not written back
to the generated TOML. Pass `--miner` or `--extminer` on every start that
should mine.

## Build an official release

The supported release path is one command from the repository root:

```bash
./scripts/build_release.sh
```

The script intentionally requires a new output directory. With no argument it
creates a unique directory under `target/release-builds/`. An explicit output
may be supplied, but it must not already exist:

```bash
./scripts/build_release.sh target/release-builds/my-release
```

The script performs these steps in order:

1. Checks formatting and checks all workspace targets in Cargo's normal
   non-release profile.
2. Builds the matrix generator and pin tool with `--locked --release`.
3. Generates the registry and nine canonical matrices exactly once, directly
   at zstd level 19.
4. Requires the exact ten-file pack layout and rejects symlinks or empty files.
5. Checks the approved m22 registry digest and computes pins over the final
   compressed matrix bytes.
6. Lets `noid_node/build.rs` strictly validate the registry and all nine
   matrix relations, then embeds build-produced runtime images.
7. Builds `paranoid` and `noid-cli` in release mode; the shared core rejects a
   target that does not satisfy the proof CPU contract.
8. Runs release tests for `noid_recursive`, `noid_node`, `noid_chain`, and
   `noid_miner`.
9. Creates the binary archive and SHA-256 checksums.

The result is:

```text
<release-directory>/
├── pack/                         build evidence; not needed by deployed nodes
│   ├── pins.env
│   └── v1/
│       ├── selected-recursive.classes
│       └── nine *.field-r1cs.zst files
├── bin/
│   ├── paranoid
│   └── noid-cli
├── paranoid-release.tar.gz      contains only paranoid and noid-cli
├── SHA256SUMS
└── build.log
```

The last successful directory is written to:

```text
target/release-builds/LAST_RELEASE
```

`NOID_RELEASE_SKIP_TESTS=1` exists for local development only. Do not publish
an archive built with that setting.

`Cargo.lock` is part of the release source, and the script uses `--locked` so
dependency resolution cannot drift during the build.

## Build from an existing matrix pack

The normal release script generates a fresh pack. For development, an existing
pack has this layout:

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

Build the self-contained node from it:

```bash
set -euo pipefail
PACK_ROOT="$PWD/target/release-pack"
source "$PACK_ROOT/pins.env"
export NOID_SELECTED_RECURSIVE_PACK_DIR="$PACK_ROOT"

cargo build --locked --release -p noid_node --bins
```

The output is:

```text
target/release/paranoid
target/release/noid-cli
```

A release build requires all three values below:

```text
NOID_SELECTED_RECURSIVE_PACK_DIR
NOID_SELECTED_RECURSIVE_REGISTRY_RELEASE_DIGEST
NOID_SELECTED_RECURSIVE_PACK_LEAF_DIGESTS
```

`pins.env` supplies the two digest variables. The command supplies the pack
directory. A debug build may omit the pack, but its mining modes then refuse
to start because they cannot create selected-history proofs.

## Generate matrices manually

This section explains what the release script automates. Do not perform both
the automated and manual procedures for the same release.

Build the tools:

```bash
cargo build --locked --release -p bench_prover \
  --bin noid_matrix_gen \
  --bin noid_matrix_stats \
  --bin noid_pack_pins
```

Generate directly at the final compression level. The destination must not
exist, which prevents an independent rebuild from overwriting an approved
pack:

```bash
set -euo pipefail
PACK_ROOT="$PWD/target/selected-recursive-release"
test ! -e "$PACK_ROOT"

NOID_ARTIFACT_ZSTD_LEVEL=19 \
  ./target/release/noid_matrix_gen "$PACK_ROOT"
```

This single invocation:

1. Builds and freezes B8, B32, B64, and B255 Block classes.
2. Proves, verifies, and exports their four matrices.
3. Freezes the four-slot m22 Link ladder and Genesis Link relation.
4. Creates the selected-recursive class registry.
5. Exports Genesis Link and the four Link matrices.

The generator also writes nine local `*.trust` receipts. They are generation
evidence, not release-pack inputs. Remove them before using the directory as
the exact ten-file pack:

```bash
find "$PACK_ROOT/v1" -mindepth 1 -maxdepth 1 -name '*.trust' -delete
```

The pack now contains one registry plus nine `*.field-r1cs.zst` files under
`v1/`. Do not rerun the generator at level 3 and then recompress the output.
The one level-19 invocation above already creates the final release bytes.

The current approved registry digest is:

```text
fdebbe54ad2f473458e7dcdf4cc5905e224fd6f816c0c62acd8b18e398de756a
```

Compute leaf pins from the final compressed files:

```bash
PACK_ROOT="${PACK_ROOT:-$PWD/target/selected-recursive-release}"
./target/release/noid_pack_pins "$PACK_ROOT"
```

The tool prints `NOID_SELECTED_RECURSIVE_PACK_LEAF_DIGESTS=...`. To complete a
manual development pack, compare the registry trailer with the independently
approved value and write `pins.env`:

```bash
set -euo pipefail
PACK_ROOT="${PACK_ROOT:-$PWD/target/selected-recursive-release}"
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

test "$REGISTRY_DIGEST" = "$APPROVED_REGISTRY_DIGEST"
[[ $LEAF_DIGESTS =~ ^[0-9a-f]{576}$ ]]
printf 'export NOID_SELECTED_RECURSIVE_REGISTRY_RELEASE_DIGEST=%s\nexport NOID_SELECTED_RECURSIVE_PACK_LEAF_DIGESTS=%s\n' \
  "$REGISTRY_DIGEST" "$LEAF_DIGESTS" > "$PACK_ROOT/pins.env"
```

The pack can now be used by the earlier **Build from an existing matrix pack**
procedure. `build_release.sh` performs all pin checks and writes `pins.env`
automatically; this manual block is not an additional release step.

`noid_matrix_stats` is an optional, expensive sizing tool. It is not part of a
normal node build:

```bash
PACK_ROOT="${PACK_ROOT:-$PWD/target/selected-recursive-release}"
./target/release/noid_matrix_stats "$PACK_ROOT"/v1/*.field-r1cs.zst
```

## How embedded artifacts work

Canonical registry and matrix files are release-build inputs, not deployed
node dependencies.

At build time:

1. The official release script compares the registry with the approved m22
   digest and derives pins from the final compressed leaves.
2. `noid_node/build.rs` checks the supplied registry and compressed-leaf pins.
3. Full and terminal registry forms are strictly decoded.
4. Every matrix is decompressed and checked against its registry shape and
   structural statement digest.
5. Every checked matrix is converted to a fixed-width packed runtime image.
6. The runtime images are compressed at zstd level 9 and embedded into the
   executable with the registry. The canonical build-input pack remains at
   zstd level 19.

At runtime, the official binary trusts those immutable build-produced bytes.
It decompresses them and checks cheap image framing, lengths, ordering, and
the requested identity against the build seal. It does not repeat the
canonical row parse, compressed-leaf hash, structural Poseidon hash, layout
derivation, or repack. The embedded registry is bounded-decoded once to build
runtime tables without repeating its semantic proof validation. There is no
filesystem fallback.

Both mining configurations prewarm the B8 Block/Link matrices. Genesis Link is
also prewarmed while selected-history coverage is zero. A mining node retains
every matrix after its first use. An ordinary node releases a matrix when its
active verification leases disappear. There is no matrix LRU, host
`MemAvailable` polling, hard byte budget, or memory-dependent eviction policy.

This trust applies only to immutable artifacts built into the executable.
Blocks, transactions, peer messages, and remote proofs remain untrusted and
are verified at runtime.

## Selected-history pipeline

Every accepted block creates a durable proof job in MDBX. A mining node's
proof pipeline moves consecutive jobs through three ordered stages:

1. **Block:** load the claimed block and parent state, replay the transition,
   produce its ladder update and accumulator, and build the selected Block
   proof.
2. **Link:** consume the previous terminal package and current Block proof,
   then build the m22 Link proof. Locally produced predecessor packages are
   passed as typed in-process replay capabilities instead of being loaded and
   reverified from disk.
3. **Verify and promote:** verify the terminal package and atomically promote
   it. MDBX independently enforces exact predecessor coverage and FIFO height
   order.

For B8, B32, and B64, up to three heights may occupy Block, Link, and Verify
simultaneously. The worker continues draining consecutive jobs; there is no
three-claims-per-session limit. B255 currently uses depth one. Capacity-one
stage channels are handoff/backpressure slots, not memory quotas.

The successor parent view is reconstructed from the durable forward cursor
plus ordered updates from still-in-flight predecessors. On failure, the valid
lower prefix may still finish and promote; the failing height and dependent
in-flight claims are released for retry. Shutdown releases unpromoted claims,
while canonical queue maintenance handles stale jobs after a reorganization.

## Live one-node test

Use a clean data directory and an explicit config so the test cannot touch the
normal node installation:

```bash
set -euo pipefail

BIN_DIR="$PWD/target/release"
RUN_PARENT="$PWD/target/live-tests"
mkdir -p "$RUN_PARENT"
RUN="$(mktemp -d "$RUN_PARENT/m22-one-node.XXXXXX")"
printf '%s\n' "$RUN" > "$RUN_PARENT/LAST_M22_RUN"

"$BIN_DIR/paranoid" \
  --miner \
  --genesis \
  --mining-threads 1 \
  --config "$RUN/paranoid.toml" \
  --data-dir "$RUN/data" \
  --p2p-listen 127.0.0.1:19750 \
  --rpc-listen 127.0.0.1:19751 \
  --log info 2>&1 | tee "$RUN/node.log"
```

From another shell:

```bash
export NOID_RPC=http://127.0.0.1:19751
./target/release/noid-cli status
./target/release/noid-cli mining
./target/release/noid-cli proof
./target/release/noid-cli stop
```

Inspect successful promotions:

```bash
RUN="$(<"$PWD/target/live-tests/LAST_M22_RUN")"
rg 'selected-history terminal promoted' "$RUN/node.log"
```

Each promotion reports:

- `block_ms`, `link_ms`, and `verify_ms`: wall time inside each stage;
- `block_queue_ms`: time after the durable claim and before Block starts; it
  can include topology admission and prover-registry preparation;
- `link_queue_ms` and `verify_queue_ms`: waits at the stage handoffs;
- `promote_ms`: the atomic MDBX promotion;
- `e2e_ms`: latency from return of the durable claim to promotion;
- `cadence_ms`: time between consecutive promotions.

`cadence_ms` is the interval between successful promotions and includes idle
time. Treat it as throughput only after startup while the job queue remains
continuous. `e2e_ms` is per-height latency and can be larger when several
heights occupy the pipeline. The current performance target is a steady
`cadence_ms <= 15000`; it is not a consensus rule and the latest local run did
not pass that threshold on every height.

The expected embedded-artifact startup markers are:

```text
build-authenticated selected-recursive runtime images loaded from the executable
selected-history verifier uses only executable-embedded registry and matrices
selected-history prover registry retained for all pipeline drains
```

`No known peers` is expected in an isolated genesis test.

## Verification commands

The release script is the primary gate. Useful focused commands are:

```bash
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo test --locked -p noid_recursive --lib
cargo test --locked -p noid_node -p noid_chain -p noid_miner
```

Release-profile tests need an authenticated pack environment:

```bash
set -euo pipefail
PACK_ROOT="$PWD/target/release-pack"
source "$PACK_ROOT/pins.env"
export NOID_SELECTED_RECURSIVE_PACK_DIR="$PACK_ROOT"

cargo test --locked --release \
  -p noid_recursive \
  -p noid_node \
  -p noid_chain \
  -p noid_miner
```

Do not make a digest failure pass by weakening a check or replacing a pin.
Regenerate the artifacts independently and review the drift.

## Optional wallet scenarios

These scripts use `target/release/paranoid` and `target/release/noid-cli` and
manage their own test directories:

```bash
python3 scripts/live_cli_wallet_scenarios.py
python3 scripts/live_slot_mempool_wallet_scenarios.py
```

## License

Apache-2.0.
