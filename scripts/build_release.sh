#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
umask 022

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
BUILD_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
DEFAULT_RELEASE_DIR="$ROOT_DIR/target/release-builds/$BUILD_ID"
LAST_RELEASE_FILE="$ROOT_DIR/target/release-builds/LAST_RELEASE"
APPROVED_REGISTRY_DIGEST="fdebbe54ad2f473458e7dcdf4cc5905e224fd6f816c0c62acd8b18e398de756a"

usage() {
  cat <<'EOF'
Usage: ./scripts/build_release.sh [RELEASE_DIR]

Build the canonical matrices once at zstd level 19, authenticate the pack,
run release gates, build the self-contained node, and create a binary archive.

RELEASE_DIR must not already exist. If omitted, a unique directory is created
under target/release-builds/.

Environment:
  NOID_RELEASE_SKIP_TESTS=1  Skip the release test suite (not for publication).
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

if (( $# > 1 )); then
  usage >&2
  exit 2
fi
if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  usage
  exit 0
fi

if (( $# == 1 )); then
  if [[ $1 = /* ]]; then
    RELEASE_DIR="$1"
  else
    RELEASE_DIR="$ROOT_DIR/$1"
  fi
else
  RELEASE_DIR="$DEFAULT_RELEASE_DIR"
fi

RELEASE_PARENT="$(dirname -- "$RELEASE_DIR")"
mkdir -p "$RELEASE_PARENT"
[[ ! -e "$RELEASE_DIR" && ! -L "$RELEASE_DIR" ]] || \
  die "release directory already exists: $RELEASE_DIR"
mkdir "$RELEASE_DIR" || die "cannot create release directory: $RELEASE_DIR"
RELEASE_DIR="$(CDPATH= cd -- "$RELEASE_DIR" && pwd -P)"

PACK_ROOT="$RELEASE_DIR/pack"
PACK_STAGING="$RELEASE_DIR/.pack-staging"
PACK_V1="$PACK_STAGING/v1"
BIN_DIR="$RELEASE_DIR/bin"
ARCHIVE="$RELEASE_DIR/paranoid-release.tar.gz"
LOG_FILE="$RELEASE_DIR/build.log"
CURRENT_STAGE="initialization"

on_error() {
  local status=$?
  printf '\nFAILED during: %s\n' "$CURRENT_STAGE" >&2
  printf 'Partial output was kept at: %s\n' "$RELEASE_DIR" >&2
  exit "$status"
}
trap on_error ERR

require_command cargo
require_command rustc
require_command date
require_command du
require_command find
require_command flock
require_command gzip
require_command install
require_command mv
require_command od
require_command rm
require_command sed
require_command tail
require_command tar
require_command tee
require_command tr
require_command sha256sum

# The shared Cargo target and final binary paths must belong to one release
# build from start to finish. Keep the descriptor open for the whole script.
mkdir -p "$ROOT_DIR/target"
exec 9>"$ROOT_DIR/target/.build_release.lock"
flock -n 9 || die "another build_release.sh process is already running"

exec > >(tee "$LOG_FILE") 2>&1

cd "$ROOT_DIR"

# Make the one-command build independent of stale caller build/pack settings.
unset CARGO_BUILD_TARGET
unset CARGO_ENCODED_RUSTFLAGS
unset RUSTFLAGS
unset NOID_SELECTED_RECURSIVE_PACK_DIR
unset NOID_SELECTED_RECURSIVE_REGISTRY_RELEASE_DIGEST
unset NOID_SELECTED_RECURSIVE_PACK_LEAF_DIGESTS
# These variables are interpreted implicitly by GNU tar/gzip. A caller must
# not be able to exclude a binary or silently change the archive byte stream.
unset TAR_OPTIONS
unset GZIP
unset GZIP_OPT
export CARGO_TARGET_DIR="$ROOT_DIR/target"
export RUSTFLAGS='-C target-cpu=native'

printf 'Paranoid self-contained release build\n'
printf '  source:       %s\n' "$ROOT_DIR"
printf '  release dir:  %s\n' "$RELEASE_DIR"
printf '  rustc:        %s\n' "$(rustc --version)"
printf '  cargo:        %s\n' "$(cargo --version)"

CURRENT_STAGE="format check"
printf '\n==> Checking formatting\n'
cargo fmt --all -- --check

CURRENT_STAGE="workspace check"
printf '\n==> Checking the workspace\n'
cargo check --locked --workspace --all-targets

CURRENT_STAGE="release tool build"
printf '\n==> Building matrix and pin tools\n'
cargo build --locked --release -p bench_prover \
  --bin noid_matrix_gen \
  --bin noid_pack_pins

CURRENT_STAGE="canonical matrix generation"
printf '\n==> Generating the registry and nine canonical matrices (zstd level 19)\n'
NOID_ARTIFACT_ZSTD_LEVEL=19 \
  "$ROOT_DIR/target/release/noid_matrix_gen" "$PACK_STAGING"

CURRENT_STAGE="pack layout validation"
printf '\n==> Validating the generated pack layout\n'
expected_files=(
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
for file_name in "${expected_files[@]}"; do
  artifact="$PACK_V1/$file_name"
  [[ -s "$artifact" ]] || die "generated artifact is missing or empty: $artifact"
  [[ ! -L "$artifact" ]] || die "generated artifact must not be a symlink: $artifact"
done

shopt -s nullglob
matrix_leaves=("$PACK_V1"/*.field-r1cs.zst)
shopt -u nullglob
(( ${#matrix_leaves[@]} == 9 )) || \
  die "expected exactly 9 matrix leaves, found ${#matrix_leaves[@]}"

# Trust sidecars are local generation receipts, not release-pack inputs.
find "$PACK_V1" -mindepth 1 -maxdepth 1 -name '*.trust' -delete

shopt -s nullglob dotglob
pack_entries=("$PACK_V1"/*)
shopt -u nullglob dotglob
(( ${#pack_entries[@]} == 10 )) || \
  die "expected exactly 10 entries in v1, found ${#pack_entries[@]}"
for artifact in "${pack_entries[@]}"; do
  [[ -f "$artifact" && ! -L "$artifact" ]] || \
    die "unexpected non-regular pack entry: $artifact"
done

CURRENT_STAGE="release pin generation"
printf '\n==> Computing and checking release pins\n'
REGISTRY_DIGEST="$(
  tail -c 32 "$PACK_V1/selected-recursive.classes" |
    od -An -tx1 |
    tr -d ' \n'
)"
[[ $REGISTRY_DIGEST =~ ^[0-9a-f]{64}$ ]] || die "registry digest is not 64 lowercase hex characters"
[[ $REGISTRY_DIGEST == "$APPROVED_REGISTRY_DIGEST" ]] || \
  die "registry digest drift: expected $APPROVED_REGISTRY_DIGEST, got $REGISTRY_DIGEST"

PIN_OUTPUT="$("$ROOT_DIR/target/release/noid_pack_pins" "$PACK_STAGING")"
printf '%s\n' "$PIN_OUTPUT"
LEAF_DIGESTS="$(
  printf '%s\n' "$PIN_OUTPUT" |
    sed -n 's/^NOID_SELECTED_RECURSIVE_PACK_LEAF_DIGESTS=//p'
)"
[[ $LEAF_DIGESTS =~ ^[0-9a-f]{576}$ ]] || \
  die "matrix leaf pin string is not 576 lowercase hex characters"

PINS_TMP="$PACK_STAGING/.pins.env.tmp.$$"
printf 'export NOID_SELECTED_RECURSIVE_REGISTRY_RELEASE_DIGEST=%s\nexport NOID_SELECTED_RECURSIVE_PACK_LEAF_DIGESTS=%s\n' \
  "$REGISTRY_DIGEST" \
  "$LEAF_DIGESTS" \
  > "$PINS_TMP"
mv "$PINS_TMP" "$PACK_STAGING/pins.env"

# The staging tree and final pack share one filesystem, so publication is an
# atomic rename after every generated byte and pin has been validated.
mv "$PACK_STAGING" "$PACK_ROOT"
PACK_V1="$PACK_ROOT/v1"

export NOID_SELECTED_RECURSIVE_PACK_DIR="$PACK_ROOT"
export NOID_SELECTED_RECURSIVE_REGISTRY_RELEASE_DIGEST="$REGISTRY_DIGEST"
export NOID_SELECTED_RECURSIVE_PACK_LEAF_DIGESTS="$LEAF_DIGESTS"

CURRENT_STAGE="self-contained node build"
printf '\n==> Building the self-contained node and RPC client\n'
cargo build --locked --release -p noid_node --bins

if [[ ${NOID_RELEASE_SKIP_TESTS:-0} == 1 ]]; then
  printf '\n==> Skipping release tests because NOID_RELEASE_SKIP_TESTS=1\n'
else
  CURRENT_STAGE="release test suite"
  printf '\n==> Running release tests\n'
  cargo test --locked --release \
    -p noid_recursive \
    -p noid_node \
    -p noid_chain \
    -p noid_miner
fi

CURRENT_STAGE="binary packaging"
printf '\n==> Packaging binaries\n'
mkdir -p "$BIN_DIR"
install -m 0755 "$ROOT_DIR/target/release/paranoid" "$BIN_DIR/paranoid"
install -m 0755 "$ROOT_DIR/target/release/noid-cli" "$BIN_DIR/noid-cli"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"
[[ $SOURCE_DATE_EPOCH =~ ^[0-9]+$ ]] || \
  die "SOURCE_DATE_EPOCH must be a non-negative integer"
tar -C "$BIN_DIR" \
  --sort=name \
  --owner=0 \
  --group=0 \
  --numeric-owner \
  --mtime="@$SOURCE_DATE_EPOCH" \
  -cf - \
  paranoid noid-cli |
  gzip -n -9 > "$ARCHIVE"

ARCHIVE_LIST="$RELEASE_DIR/.archive-members.tmp"
tar -tzf "$ARCHIVE" > "$ARCHIVE_LIST"
mapfile -t archive_members < "$ARCHIVE_LIST"
rm "$ARCHIVE_LIST"
(( ${#archive_members[@]} == 2 )) || \
  die "binary archive must contain exactly two entries"
[[ ${archive_members[0]} == paranoid && ${archive_members[1]} == noid-cli ]] || \
  die "binary archive has an unexpected member list"

(
  cd "$RELEASE_DIR"
  sha256sum bin/paranoid bin/noid-cli paranoid-release.tar.gz > SHA256SUMS
)

CURRENT_STAGE="publishing release location"
mkdir -p "$(dirname -- "$LAST_RELEASE_FILE")"
LAST_RELEASE_TMP="$LAST_RELEASE_FILE.tmp.$$"
printf '%s\n' "$RELEASE_DIR" > "$LAST_RELEASE_TMP"
mv "$LAST_RELEASE_TMP" "$LAST_RELEASE_FILE"

CURRENT_STAGE="complete"
printf '\nSUCCESS\n'
printf '  matrix pack:  %s\n' "$PACK_ROOT"
printf '  binaries:     %s\n' "$BIN_DIR"
printf '  archive:      %s\n' "$ARCHIVE"
printf '  checksums:    %s\n' "$RELEASE_DIR/SHA256SUMS"
printf '  build log:    %s\n' "$LOG_FILE"
printf '  last release: %s\n' "$LAST_RELEASE_FILE"
du -sh "$PACK_ROOT" "$ARCHIVE"
