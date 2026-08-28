#!/usr/bin/env bash
set -euo pipefail

PINNED_REVISION="8e514ff4eb59e7925992e8274c4f10214d7c6b9f"
SHORT_REVISION="8e514ff4"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPOSITORY="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
TEMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/paranoid-frost-gkr.XXXXXX")"
WORKTREE="$TEMP_ROOT/source"

cleanup() {
    if git -C "$REPOSITORY" worktree list --porcelain | grep -Fqx "worktree $WORKTREE"; then
        git -C "$REPOSITORY" worktree remove --force "$WORKTREE"
    fi
    rmdir "$TEMP_ROOT" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

git -C "$REPOSITORY" worktree add --detach "$WORKTREE" "$PINNED_REVISION"
mkdir -p "$WORKTREE/research"
cp -R "$SCRIPT_DIR" "$WORKTREE/research/frost_gkr"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$REPOSITORY/target/frost-gkr-$SHORT_REVISION}"
cd "$WORKTREE/research/frost_gkr"
cargo run --release --locked -- "$@"
