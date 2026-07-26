#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
umask 022

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
RELEASE_ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/../.." && pwd -P)"

usage() {
  cat <<'EOF'
Usage: package_macos_gui.sh BIN_DIR OUTPUT_DIR VERSION PLATFORM

Build a native ParanO(1)d .app and compressed DMG.
PLATFORM must be macos-aarch64 or macos-x86_64.
EOF
}

if (( $# != 4 )); then
  usage >&2
  exit 2
fi

BIN_DIR=$1
OUTPUT_DIR=$2
VERSION=$3
PLATFORM=$4
[[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]] || {
  echo "invalid semantic version: $VERSION" >&2
  exit 1
}
case "$PLATFORM" in
  macos-aarch64|macos-x86_64) ;;
  *)
    echo "unsupported macOS GUI platform: $PLATFORM" >&2
    exit 1
    ;;
esac

for command in codesign hdiutil iconutil install mktemp plutil sed; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required command is missing: $command" >&2
    exit 1
  }
done

BIN_DIR="$(CDPATH='' cd -- "$BIN_DIR" && pwd -P)"
mkdir -p -- "$OUTPUT_DIR"
OUTPUT_DIR="$(CDPATH='' cd -- "$OUTPUT_DIR" && pwd -P)"
for binary in paranoid-gui paranoid; do
  [[ -f $BIN_DIR/$binary && -x $BIN_DIR/$binary ]] || {
    echo "release binary is missing or not executable: $BIN_DIR/$binary" >&2
    exit 1
  }
done

TEMPORARY=$(mktemp -d "${TMPDIR:-/tmp}/paranoid-macos-gui.XXXXXX")
MOUNTED=0
cleanup() {
  local status=$?
  if [[ $MOUNTED == 1 ]]; then
    hdiutil detach "$TEMPORARY/mount" -quiet || true
  fi
  if [[ -d $TEMPORARY && $TEMPORARY == "${TMPDIR:-/tmp}"/paranoid-macos-gui.* ]]; then
    rm -r -- "$TEMPORARY" || true
  fi
  exit "$status"
}
trap cleanup EXIT

APP="$TEMPORARY/ParanO1d.app"
CONTENTS="$APP/Contents"
MACOS="$CONTENTS/MacOS"
RESOURCES="$CONTENTS/Resources"
ICONSET="$TEMPORARY/ParanO1d.iconset"
DMG_ROOT="$TEMPORARY/dmg"
mkdir -p -- "$MACOS" "$RESOURCES" "$ICONSET" "$DMG_ROOT"

install -m 0755 "$BIN_DIR/paranoid-gui" "$MACOS/ParanO1d"
install -m 0755 "$BIN_DIR/paranoid" "$MACOS/paranoid"
install -m 0644 "$RELEASE_ROOT_DIR/LICENSE" "$RESOURCES/LICENSE.txt"
install -m 0644 "$RELEASE_ROOT_DIR/NOTICE" "$RESOURCES/NOTICE.txt"

BUNDLE_VERSION=${VERSION%%[-+]*}
sed \
  -e "s/@VERSION@/$VERSION/g" \
  -e "s/@BUNDLE_VERSION@/$BUNDLE_VERSION/g" \
  "$SCRIPT_DIR/gui/macos/Info.plist.in" \
  > "$CONTENTS/Info.plist"
plutil -lint "$CONTENTS/Info.plist" >/dev/null

for specification in \
  "16 icon_16x16.png" \
  "32 icon_16x16@2x.png" \
  "32 icon_32x32.png" \
  "64 icon_32x32@2x.png" \
  "128 icon_128x128.png" \
  "256 icon_128x128@2x.png" \
  "256 icon_256x256.png" \
  "512 icon_256x256@2x.png" \
  "512 icon_512x512.png" \
  "1024 icon_512x512@2x.png"
do
  size=${specification%% *}
  name=${specification#* }
  icon="$RELEASE_ROOT_DIR/noid_gui/assets/app-icons/ParanO1d-${size}.png"
  [[ -f $icon ]] || {
    echo "macOS icon source is missing: $icon" >&2
    exit 1
  }
  install -m 0644 "$icon" "$ICONSET/$name"
done
iconutil -c icns "$ICONSET" -o "$RESOURCES/ParanO1d.icns"

xattr -cr "$APP"
SIGN_IDENTITY=${NOID_MACOS_SIGN_IDENTITY:--}
if [[ $SIGN_IDENTITY == - ]]; then
  codesign --force --sign - --timestamp=none "$MACOS/paranoid"
  codesign --force --sign - --timestamp=none "$MACOS/ParanO1d"
  codesign --force --deep --sign - --timestamp=none "$APP"
else
  codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" "$MACOS/paranoid"
  codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" "$MACOS/ParanO1d"
  codesign --force --deep --options runtime --timestamp --sign "$SIGN_IDENTITY" "$APP"
fi
codesign --verify --deep --strict "$APP"
"$MACOS/ParanO1d" --release-self-check >/dev/null

cp -R "$APP" "$DMG_ROOT/ParanO1d.app"
ln -s /Applications "$DMG_ROOT/Applications"
ARTIFACT="$OUTPUT_DIR/paranoid-gui-v${VERSION}-${PLATFORM}.dmg"
hdiutil create \
  -volname "ParanO(1)d" \
  -srcfolder "$DMG_ROOT" \
  -format UDZO \
  -ov \
  "$ARTIFACT" >/dev/null
hdiutil verify "$ARTIFACT" >/dev/null
mkdir "$TEMPORARY/mount"
hdiutil attach -readonly -nobrowse -mountpoint "$TEMPORARY/mount" "$ARTIFACT" >/dev/null
MOUNTED=1
"$TEMPORARY/mount/ParanO1d.app/Contents/MacOS/ParanO1d" \
  --release-self-check >/dev/null
[[ -s $TEMPORARY/mount/ParanO1d.app/Contents/Resources/LICENSE.txt ]]
[[ -s $TEMPORARY/mount/ParanO1d.app/Contents/Resources/NOTICE.txt ]]
[[ ! -e $TEMPORARY/mount/ParanO1d.app/Contents/MacOS/noid-cli ]]
[[ ! -e $TEMPORARY/mount/ParanO1d.app/Contents/MacOS/noid-extminer ]]
hdiutil detach "$TEMPORARY/mount" -quiet
MOUNTED=0
printf '%s\n' "$ARTIFACT"
