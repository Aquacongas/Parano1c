# Paranoid

Paranoid is a proof-native UTXO blockchain written in Rust. Every accepted
non-genesis block is one atomic unit: native proof of work plus a recursive
HistoryStep binding that exact header, nonce, transaction set and state
transition. The HistoryStep terminal stays constant-size as the chain grows.
Proof generation is part of mining whether nonce search runs inside the node
or in an external worker.

HistoryStep has four current-block tiers (B8, B32, B64 and B255) and four
possible parent tiers, forming one release-pinned 4×4 class bank. Block 1 is
the exact genesis-anchored base case of the same relation; there is no separate
genesis proof or bootstrap class. The release binary contains the authenticated
runtime metadata and matrix images; end users do not install or distribute
matrix files.

## Quick start

Node operators normally need only this section. The remaining sections are
for release builders, matrix regeneration, and pipeline diagnostics.

### Hardware and software

| Role | Requirement |
|---|---|
| Node and wallet | The default `./paranoid` process. It validates and relays complete block bundles, serves P2P/RPC, and owns the wallet. It does not mine. |
| Mining node | At least 16 GiB RAM and a multi-core CPU. The node creates a complete PoW + HistoryStep block with either built-in or external nonce search. Built-in mining reuses all host-visible CPUs for each ordered phase. |
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
and JSON-RPC client. No metadata or matrix files are required beside them.

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
| `./paranoid --miner` | Mining node with built-in PoW. It uses all visible CPUs for PoW, then all CPUs for the block's required HistoryStep before accepting and announcing it. |
| `./paranoid --extminer` | Mining node with an external PoW worker. The external worker only returns a nonce; the node builds, proves and atomically accepts the complete block. Requires `--mining-key`. |

There is no separate proving-node role and no background proof backlog. A block
is not accepted and creates no reward until its exact HistoryStep is complete.

The release archive does not include the separate external-miner client.

Bootstrap the first node of a new network:

```bash
./paranoid --miner --genesis
```

`--genesis` is only for the first node of a fresh network. A miner joining an
existing network uses seeds instead:

```bash
./paranoid \
  --miner \
  --seed SEED_IP:9400
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

The script checks the workspace, generates and authenticates the sixteen
HistoryStep class matrices, embeds their runtime images, builds both binaries,
runs the release test suite, and creates the archive and checksums. Matrix
generation happens once at the final compression level; the release build
does not regenerate or recompress an approved pack.

The result is:

```text
<release-directory>/
├── pack/                         build evidence; not needed by deployed nodes
│   ├── pins.env
│   └── v1/
│       ├── history-step.runtime
│       └── sixteen history-step-*.field-r1cs.zst files
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

The normal release script generates a fresh pack. A development build may use
an existing pack containing `pins.env`, `v1/history-step.runtime`, and the
sixteen class matrices.

```text
target/release-pack/
├── pins.env
└── v1/
    ├── history-step.runtime
    └── history-step-*.field-r1cs.zst
```

Build the self-contained node from it:

```bash
set -euo pipefail
PACK_ROOT="$PWD/target/release-pack"
source "$PACK_ROOT/pins.env"
export NOID_HISTORY_STEP_PACK_DIR="$PACK_ROOT"

cargo build --locked --release -p noid_node --bins
```

The output is:

```text
target/release/paranoid
target/release/noid-cli
```

A release build requires the authenticated pack directory plus the runtime
metadata and leaf pins emitted by `noid_pack_pins`:

```text
NOID_HISTORY_STEP_PACK_DIR
NOID_HISTORY_STEP_RUNTIME_METADATA_RELEASE_DIGEST
NOID_HISTORY_STEP_PACK_LEAF_DIGESTS
```

`pins.env` supplies the two digest variables. The command supplies the pack
directory. A pack-free debug node can exercise non-proof code, but it cannot
mine or verify HistoryStep terminals.

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
PACK_ROOT="$PWD/target/history-step-release"
test ! -e "$PACK_ROOT"

NOID_ARTIFACT_ZSTD_LEVEL=19 \
  ./target/release/noid_matrix_gen "$PACK_ROOT"
```

The invocation freezes the four current tiers against the four possible parent
tiers from mined, native-valid fixtures, exports the sixteen matrices, and
writes `history-step.runtime`. `noid_pack_pins` below emits the exact pins for
those final compressed bytes. Do not generate at one level and recompress
later.

Inspect or recompute the leaf pins with:

```bash
PACK_ROOT="${PACK_ROOT:-$PWD/target/history-step-release}"
./target/release/noid_pack_pins "$PACK_ROOT"
```

For a reusable development pack, save the two emitted assignments as exported
variables in `$PACK_ROOT/pins.env`; the release script does this automatically.

`noid_matrix_stats` is an optional, expensive sizing tool. It is not part of a
normal node build:

```bash
PACK_ROOT="${PACK_ROOT:-$PWD/target/history-step-release}"
./target/release/noid_matrix_stats "$PACK_ROOT"/v1/*.field-r1cs.zst
```

## Benchmark production HistoryStep proofs

Run the isolated prover benchmark against a completed, pinned pack:

```bash
set -euo pipefail
PACK_ROOT="$PWD/target/release-pack"
source "$PACK_ROOT/pins.env"
export NOID_HISTORY_STEP_PACK_DIR="$PACK_ROOT"

cargo bench --locked -p bench_prover --bench history_step_proof
```

The benchmark authenticates all sixteen matrices, builds and verifies an
honest B8 parent, then reports one uniform line for B8, B32, B64 and B255.
Fixture construction and matrix assembly are outside `prove_ms`; `verify_ms`
includes bounded terminal decoding and complete production verification.

## How embedded artifacts work

Canonical runtime metadata and matrix files are release-build inputs, not
deployed node dependencies.

At build time:

1. The generator derives the fixed runtime metadata and final compressed leaves.
2. `noid_node/build.rs` checks the supplied metadata and every leaf pin.
3. The sixteen identities are decoded into the canonical HistoryStep bank.
4. Every matrix is decompressed and checked against its pinned shape and
   structural statement digest.
5. Every checked matrix is converted to a fixed-width packed runtime image.
6. The runtime images are compressed at zstd level 9 and embedded into the
   executable with the metadata. The canonical build-input pack remains at
   zstd level 19.

At runtime, the official binary trusts those immutable build-produced bytes.
It decompresses them and checks cheap image framing, lengths, ordering, and
the requested identity against the build seal. It does not repeat the
canonical row parse, compressed-leaf hash, structural Poseidon hash, or
repack. The fixed-size metadata rebuilds the canonical runtime once.

Both mining configurations use the release-pinned 4×4 HistoryStep class bank.
Before PoW, the node loads the authenticated current matrix and assembles the
complete HistoryStep witness except for the fixed 4,402-row direct-accumulator
and `BLOCKHDR` suffix. Matrix loading is strictly one-at-a-time: the miner uses
the current class and the terminal decider walks live bank lanes sequentially.

This trust applies only to immutable artifacts built into the executable.
Blocks, transactions, peer messages, and remote proofs remain untrusted and
are verified at runtime.

## Atomic HistoryStep production

PoW and accepted history are one consensus unit. A non-genesis block cannot
mutate state, create a reward or be announced as complete until a HistoryStep
for that exact height, header and nonce is ready. There is no independent
history-height cursor that can lag behind the chain tip.

The mining loop is phase ordered:

1. build the template, current-block relation and parent-recursion witness;
2. search PoW with the complete shared CPU pool;
3. seal the builder-branded nonce/block-id boundary cells and append the fixed
   direct suffix;
4. move that one complete witness directly into the all-core HistoryStep
   prover;
5. atomically commit block, terminal, state and receipt indexes;
6. announce the complete bundle, then start the next height.

There is no durable proof job, no asynchronous history worker and no partially
accepted non-genesis block. A competing complete block drops the local
in-memory carrier. Restarts either recover a fully committed bundle or no block
at that height. The detailed consensus and sync design is in
[`noid_chain/HISTORY_STEP.md`](noid_chain/HISTORY_STEP.md).

## Live one-node test

Use a clean data directory and an explicit config so the test cannot touch the
normal node installation:

```bash
set -euo pipefail

BIN_DIR="$PWD/target/release"
RUN_PARENT="$PWD/target/live-tests"
mkdir -p "$RUN_PARENT"
RUN="$(mktemp -d "$RUN_PARENT/history-step-one-node.XXXXXX")"
printf '%s\n' "$RUN" > "$RUN_PARENT/LAST_HISTORY_STEP_RUN"

"$BIN_DIR/paranoid" \
  --miner \
  --genesis \
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

At the default `info` level, the lifecycle is intentionally concise:

```bash
RUN="$(<"$PWD/target/live-tests/LAST_HISTORY_STEP_RUN")"
rg 'mining complete block|block accepted' "$RUN/node.log"
```

`block accepted` includes `nonce_to_commit_ms`, the critical latency
from the winning nonce through HistoryStep and the atomic MDBX commit. Detailed
matrix, transcript, prefetch and proving timings stay at `debug`. The release
gate requires p95 nonce-to-commit at or below 15 seconds and rejects any run
that exposes a proof backlog or a lagging canonical history height.

The embedded-artifact startup details are also available at `debug`:

```text
build-authenticated HistoryStep runtime images loaded from the executable
HistoryStep verifier uses only executable-embedded metadata and matrices
HistoryStep class bank ready
```

The expected libp2p `No known peers` bootstrap warning is suppressed for an
isolated `--genesis` node.

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
export NOID_HISTORY_STEP_PACK_DIR="$PACK_ROOT"

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
