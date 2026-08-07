#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
umask 022

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=release_common.sh
source "$SCRIPT_DIR/release_common.sh"

usage() {
  cat <<'EOF'
Usage: ./scripts/publish_release.sh VERSION PACK_DIR --channel CHANNEL

From a clean main branch synchronized with origin/main, require a public
repository, authenticate the canonical HistoryStep pack, run and await the
manual five-platform Platform CI, create and push vVERSION, open a draft
GitHub release, attach the normalized pack, and dispatch the native Core plus
GUI release workflow. The workflow publishes the draft only after every
native deliverable has built and uploaded successfully.

CHANNEL must be one of:
  prerelease   Publish a GitHub pre-release and do not mark it as latest.
  stable       Publish a normal GitHub release and mark it as latest.

Examples:
  ./scripts/publish_release.sh 0.0.4 \
    /home/neo/rust/parano1d-artifacts/history-step-pack-v1 \
    --channel prerelease

  ./scripts/publish_release.sh 1.0.0 \
    /home/neo/rust/parano1d-artifacts/history-step-pack-v1 \
    --channel stable
EOF
}

if (( $# == 1 )) && [[ $1 == -h || $1 == --help ]]; then
  usage
  exit 0
fi
if (( $# != 4 )) || [[ $3 != --channel ]]; then
  usage >&2
  exit 2
fi

VERSION=$1
PACK_DIR=$(release_absolute_from_root "$2")
CHANNEL=$4
[[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]] || \
  release_die "VERSION must be a semantic version without a leading v"
case "$CHANNEL" in
  prerelease|stable) ;;
  *) release_die "CHANNEL must be prerelease or stable" ;;
esac
VERSION_WITHOUT_BUILD=${VERSION%%+*}
if [[ $CHANNEL == stable && $VERSION_WITHOUT_BUILD == *-* ]]; then
  release_die "stable releases cannot use a semantic prerelease version"
fi
TAG="v$VERSION"
NOTES_FILE="$RELEASE_ROOT_DIR/.github/release-notes/$TAG.md"
PACK_ASSET=history-step-pack-v1.tar.gz
WORKFLOW=release.yml
PLATFORM_CI_WORKFLOW=platform-ci.yml

release_require_command cargo
release_require_command find
release_require_command gh
release_require_command git
release_require_command gzip
release_require_command jq
release_require_command mktemp
release_require_command sed
release_require_command sha256sum
release_require_command sleep
release_require_command tail
release_require_command tar

dispatch_workflow() {
  local workflow=$1
  local ref=$2
  local expected_sha=$3
  shift 3

  local existing_ids dispatch_output candidates candidate_count
  local run_id run_url

  existing_ids=$(
    gh run list \
      --workflow "$workflow" \
      --event workflow_dispatch \
      --limit 100 \
      --json databaseId |
      jq '[.[].databaseId]'
  )

  dispatch_output=$(gh workflow run "$workflow" --ref "$ref" "$@")
  run_url=$(
    printf '%s\n' "$dispatch_output" |
      sed -nE 's#.*(https://github\.com/[^[:space:]]+/actions/runs/[0-9]+).*#\1#p' |
      tail -n 1
  )
  run_id=${run_url##*/}
  if [[ $run_id =~ ^[0-9]+$ ]]; then
    DISPATCHED_WORKFLOW_URL=$run_url
    DISPATCHED_WORKFLOW_RUN_ID=$run_id
    return
  fi

  printf 'Workflow dispatch accepted; waiting for GitHub to expose its run ID.\n'
  for _ in {1..30}; do
    candidates=$(
      gh run list \
        --workflow "$workflow" \
        --event workflow_dispatch \
        --limit 20 \
        --json databaseId,headSha,url |
        jq \
          --arg expected_sha "$expected_sha" \
          --argjson existing_ids "$existing_ids" \
          '[
            .[]
            | select(.headSha == $expected_sha)
            | select(.databaseId as $id | ($existing_ids | index($id)) == null)
          ]'
    )
    candidate_count=$(jq 'length' <<<"$candidates")
    if (( candidate_count == 1 )); then
      DISPATCHED_WORKFLOW_RUN_ID=$(jq -r '.[0].databaseId' <<<"$candidates")
      DISPATCHED_WORKFLOW_URL=$(jq -r '.[0].url' <<<"$candidates")
      return
    fi
    if (( candidate_count > 1 )); then
      release_die "multiple new $workflow runs match commit $expected_sha"
    fi
    sleep 2
  done

  release_die "could not determine the dispatched $workflow run ID"
}

[[ -f $NOTES_FILE && -s $NOTES_FILE && ! -L $NOTES_FILE ]] || \
  release_die "release notes are missing, empty, or a symlink: $NOTES_FILE"
TITLE=$(sed -n '1s/^# //p' "$NOTES_FILE")
[[ -n $TITLE && $TITLE != \#* ]] || \
  release_die "release notes must begin with one Markdown H1 title"
PACK_DIR=$(release_canonical_directory "$PACK_DIR")

cd "$RELEASE_ROOT_DIR"
[[ $(git rev-parse --show-toplevel) == "$RELEASE_ROOT_DIR" ]] || \
  release_die "run this command from the ParanO(1)d repository"
[[ $(git branch --show-current) == main ]] || \
  release_die "releases may be published only from main"
[[ -z $(git status --porcelain=v1 --untracked-files=all) ]] || \
  release_die "main must be completely clean before publication"

printf '==> Synchronizing release authority with origin/main\n'
git fetch --prune origin main
LOCAL_HEAD=$(git rev-parse HEAD)
REMOTE_HEAD=$(git rev-parse origin/main)
[[ $LOCAL_HEAD == "$REMOTE_HEAD" ]] || \
  release_die "local main is not identical to origin/main"

release_workspace_version
[[ $RELEASE_VERSION == "$VERSION" ]] || \
  release_die "requested version $VERSION differs from workspace version $RELEASE_VERSION"

if git show-ref --verify --quiet "refs/tags/$TAG"; then
  release_die "local tag already exists: $TAG"
fi
set +e
git ls-remote --exit-code --tags origin "refs/tags/$TAG" >/dev/null 2>&1
REMOTE_TAG_STATUS=$?
set -e
case "$REMOTE_TAG_STATUS" in
  0) release_die "remote tag already exists: $TAG" ;;
  2) ;;
  *) release_die "could not determine whether remote tag $TAG exists" ;;
esac
if gh release view "$TAG" >/dev/null 2>&1; then
  release_die "GitHub release already exists: $TAG"
fi
gh auth status >/dev/null
[[ $(gh repo view --json visibility --jq .visibility) == PUBLIC ]] || \
  release_die "make the GitHub repository public before opening the release window"

release_build_pack_tools 0
printf '\n==> Authenticating publishable HistoryStep pack\n'
release_authenticate_pack "$PACK_DIR" 1

if ! tar --version 2>/dev/null | grep -q 'GNU tar'; then
  release_die "release publication requires GNU tar for a normalized pack archive"
fi

TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/parano1d-release.XXXXXX")
cleanup() {
  local status=$?
  if [[ -d $TEMP_DIR && $TEMP_DIR == "${TMPDIR:-/tmp}"/parano1d-release.* ]]; then
    rm -r -- "$TEMP_DIR" || true
  fi
  exit "$status"
}
trap cleanup EXIT

NORMALIZED_ROOT="$TEMP_DIR/history-step-pack-v1"
mkdir -- "$NORMALIZED_ROOT"
cp -R -- "$PACK_DIR/v1" "$NORMALIZED_ROOT/v1"
cp -- "$PACK_DIR/pins.env" "$NORMALIZED_ROOT/pins.env"
cp -- "$PACK_DIR/SHA256SUMS" "$NORMALIZED_ROOT/SHA256SUMS"
PACK_ARCHIVE="$TEMP_DIR/$PACK_ASSET"
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}
[[ $SOURCE_DATE_EPOCH =~ ^[0-9]+$ ]] || \
  release_die "SOURCE_DATE_EPOCH must be a non-negative integer"
tar -C "$TEMP_DIR" \
  --sort=name \
  --owner=0 \
  --group=0 \
  --numeric-owner \
  --mtime="@$SOURCE_DATE_EPOCH" \
  -cf - history-step-pack-v1 |
  gzip -n -9 > "$PACK_ARCHIVE"
PACK_SHA256=$(release_sha256_file "$PACK_ARCHIVE")

printf '\n==> Running mandatory five-platform source validation\n'
dispatch_workflow "$PLATFORM_CI_WORKFLOW" main "$LOCAL_HEAD"
PLATFORM_CI_URL=$DISPATCHED_WORKFLOW_URL
PLATFORM_CI_RUN_ID=$DISPATCHED_WORKFLOW_RUN_ID
printf 'Platform CI: %s\n' "$PLATFORM_CI_URL"
gh run watch "$PLATFORM_CI_RUN_ID" --exit-status
PLATFORM_CI_RESULT=$(gh run view "$PLATFORM_CI_RUN_ID" \
  --json conclusion,headSha,status,workflowName)
[[ $(jq -r .status <<<"$PLATFORM_CI_RESULT") == completed ]] || \
  release_die "Platform CI did not complete"
[[ $(jq -r .conclusion <<<"$PLATFORM_CI_RESULT") == success ]] || \
  release_die "Platform CI did not succeed"
[[ $(jq -r .workflowName <<<"$PLATFORM_CI_RESULT") == "Platform CI" ]] || \
  release_die "unexpected validation workflow"
[[ $(jq -r .headSha <<<"$PLATFORM_CI_RESULT") == "$LOCAL_HEAD" ]] || \
  release_die "Platform CI validated a different commit"

printf '\n==> Reconfirming immutable release authority\n'
git fetch --prune origin main
[[ $(git rev-parse HEAD) == "$LOCAL_HEAD" ]] || \
  release_die "local main changed during Platform CI"
[[ $(git rev-parse origin/main) == "$LOCAL_HEAD" ]] || \
  release_die "origin/main changed during Platform CI"

printf '\nRelease candidate\n'
printf '  commit:       %s\n' "$LOCAL_HEAD"
printf '  tag:          %s\n' "$TAG"
printf '  title:        %s\n' "$TITLE"
printf '  channel:      %s\n' "$CHANNEL"
printf '  matrix pack:  %s\n' "$PACK_ARCHIVE"
printf '  pack SHA-256: %s\n' "$PACK_SHA256"
printf '  platform CI:  %s\n' "$PLATFORM_CI_RUN_ID"

printf '\n==> Creating and pushing annotated release identity\n'
git tag -a "$TAG" -m "$TITLE"
git push origin "refs/tags/$TAG"

printf '\n==> Creating draft release and uploading the canonical pack\n'
gh release create "$TAG" "$PACK_ARCHIVE" \
  --verify-tag \
  --draft \
  --title "$TITLE" \
  --notes-file "$NOTES_FILE"

printf '\n==> Dispatching five-platform native release workflow\n'
dispatch_workflow "$WORKFLOW" main "$LOCAL_HEAD" \
  -f "tag=$TAG" \
  -f "pack_sha256=$PACK_SHA256" \
  -f "release_channel=$CHANNEL" \
  -f "platform_ci_run_id=$PLATFORM_CI_RUN_ID"
WORKFLOW_URL=$DISPATCHED_WORKFLOW_URL
WORKFLOW_RUN_ID=$DISPATCHED_WORKFLOW_RUN_ID

printf '\n==> Waiting for every Core and GUI deliverable\n'
printf 'Workflow: %s\n' "$WORKFLOW_URL"
gh run watch "$WORKFLOW_RUN_ID" --exit-status

RELEASE_STATE=$(gh release view "$TAG" \
  --json assets,isDraft,isPrerelease,name,tagName,url)
[[ $(jq -r .isDraft <<<"$RELEASE_STATE") == false ]] || \
  release_die "Native Release completed but the GitHub release is still a draft"
[[ $(jq -r .tagName <<<"$RELEASE_STATE") == "$TAG" ]] || \
  release_die "published release tag differs from $TAG"
[[ $(jq -r .name <<<"$RELEASE_STATE") == "$TITLE" ]] || \
  release_die "published release title differs from the release notes title"
EXPECTED_PRERELEASE=false
if [[ $CHANNEL == prerelease ]]; then
  EXPECTED_PRERELEASE=true
fi
[[ $(jq -r .isPrerelease <<<"$RELEASE_STATE") == "$EXPECTED_PRERELEASE" ]] || \
  release_die "published GitHub release channel does not match $CHANNEL"

EXPECTED_ASSETS=(
  "parano1d-core-$TAG-linux-x86_64.tar.gz"
  "parano1d-core-$TAG-linux-aarch64.tar.gz"
  "parano1d-core-$TAG-windows-x86_64.zip"
  "parano1d-core-$TAG-macos-aarch64.tar.gz"
  "parano1d-core-$TAG-macos-x86_64.tar.gz"
  "parano1d-gui-$TAG-linux-x86_64.deb"
  "parano1d-gui-$TAG-linux-aarch64.deb"
  "parano1d-gui-$TAG-windows-x86_64-setup.exe"
  "parano1d-gui-$TAG-macos-aarch64.dmg"
  "parano1d-gui-$TAG-macos-x86_64.dmg"
  history-step-pack-v1.tar.gz
  SHA256SUMS
)
[[ $(jq '.assets | length' <<<"$RELEASE_STATE") == "${#EXPECTED_ASSETS[@]}" ]] || \
  release_die "published GitHub release does not contain exactly ${#EXPECTED_ASSETS[@]} assets"
for asset in "${EXPECTED_ASSETS[@]}"; do
  jq -e --arg asset "$asset" \
    '.assets | any(.name == $asset)' <<<"$RELEASE_STATE" >/dev/null || \
    release_die "published GitHub release is missing $asset"
done

printf '\n==> Downloading and verifying the published release\n'
VERIFY_DIR="$TEMP_DIR/published"
mkdir -- "$VERIFY_DIR"
gh release download "$TAG" --dir "$VERIFY_DIR"
mapfile -t DOWNLOADED_ASSETS < <(
  find "$VERIFY_DIR" -maxdepth 1 -type f -printf '%f\n'
)
[[ ${#DOWNLOADED_ASSETS[@]} == "${#EXPECTED_ASSETS[@]}" ]] || \
  release_die "downloaded release does not contain exactly ${#EXPECTED_ASSETS[@]} files"
(
  cd "$VERIFY_DIR"
  sha256sum -c SHA256SUMS
)
[[ $(release_sha256_file "$VERIFY_DIR/$PACK_ASSET") == "$PACK_SHA256" ]] || \
  release_die "published matrix pack differs from the authenticated candidate"

REMOTE_TAG_COMMIT=$(
  git ls-remote origin "refs/tags/$TAG^{}" |
    sed -n '1s/[[:space:]].*$//p'
)
[[ $REMOTE_TAG_COMMIT == "$LOCAL_HEAD" ]] || \
  release_die "published annotated tag does not resolve to the release commit"

printf '\nPUBLISHED\n'
printf 'All five Core and GUI builds succeeded; every published digest verifies.\n'
printf 'Requested channel: %s\n' "$CHANNEL"
printf 'Platform CI: %s\n' "$PLATFORM_CI_URL"
printf 'Native Release: %s\n' "$WORKFLOW_URL"
printf 'Release: %s\n' "$(jq -r .url <<<"$RELEASE_STATE")"
