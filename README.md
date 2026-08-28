# Parano1c

Parano1c is an Android wallet and mobile node implementation based on the Parano1d codebase.

## Android Wallet

The Android application provides:

- Wallet balance
- Active address
- Send and receive functionality
- Network status
- Block height
- Synchronization status
- Peer count
- Recent transactions
- Local mobile node integration

## Requirements

Rust:
- Rust toolchain from rust-toolchain.toml
- cargo-ndk
- Android ARM64 target

Android:
- Android SDK
- Android NDK
- Java 17
- Gradle wrapper included in android/

## Building

From the project root:

    cd ~/parano1d-mobile-full

    HISTORY_PACK_DIR="$PWD/release-assets/history-step/pack/history-step-pack-v1"

    set -a
    source "$HISTORY_PACK_DIR/pins.env"
    set +a

    export NOID_HISTORY_STEP_PACK_DIR="$HISTORY_PACK_DIR"

Check Rust components:

    cargo fmt

    cargo check \
      -p noid_wallet \
      -p noid_mobile_node \
      -p noid_mobile_ffi \
      -j16

Build Android ARM64 native library:

    NOID_HISTORY_STEP_PACK_DIR="$HISTORY_PACK_DIR" \
    cargo ndk -t arm64-v8a \
      -o android/app/src/main/jniLibs \
      build --release -p noid_mobile_ffi -j16

Build debug APK:

    cd android
    ./gradlew assembleDebug

Build release APK:

    ./gradlew assembleRelease

## Android Configuration

Application ID:

    org.parano1d.mobile

Current configuration:

- Minimum SDK: 26
- Target SDK: 35
- Architecture: ARM64-v8a

## Releases

Official signed Android APK files are published in the GitHub Releases section.

Signing keys and keystore files are not included in this repository.

## License

See the LICENSE file included in this repository.

## Project Status

Parano1c is under active development.
