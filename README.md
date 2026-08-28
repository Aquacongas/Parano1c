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

## Android Build Integration

The Android source is not intended to be built as a completely standalone repository.

To build Parano1c Android from source, the following directories must be placed inside the main Parano1d repository:

- android/
- noid_mobile_node/

The build also depends on the Parano1d workspace and its Rust crates.

Expected layout:

Parano1d/
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── release-assets/
├── noid_wallet/
├── noid_mobile_ffi/
├── noid_mobile_node/
├── noid_networking/
├── noid_p2p/
├── noid_chain/
├── noid_core/
├── noid_recursive/
├── android/
└── ...

## Building the Android Wallet

From the root of the Parano1d repository:

    HISTORY_PACK_DIR="$PWD/release-assets/history-step/pack/history-step-pack-v1"

    set -a
    source "$HISTORY_PACK_DIR/pins.env"
    set +a

    export NOID_HISTORY_STEP_PACK_DIR="$HISTORY_PACK_DIR"

Format and check the Rust components:

    cargo fmt

    cargo check \
      -p noid_wallet \
      -p noid_mobile_node \
      -p noid_mobile_ffi \
      -j16

Build the Android ARM64 native library:

    NOID_HISTORY_STEP_PACK_DIR="$HISTORY_PACK_DIR" \
    cargo ndk -t arm64-v8a \
      -o android/app/src/main/jniLibs \
      build --release -p noid_mobile_ffi -j16

Build the Android APK:

    cd android

Debug build:

    ./gradlew assembleDebug

Signed release build:

    ./gradlew assembleRelease

The generated release APK will be available under:

    android/app/build/outputs/apk/release/

The current release artifact is named:

    parano1c-release.apk

## Android Configuration

Application ID:

    org.parano1d.mobile

Current configuration:

- Minimum SDK: 26
- Target SDK: 35
- Architecture: ARM64-v8a

## Android Storage Limitation

The current Android wallet uses MDBX for persistent local storage.

For the mobile build, the maximum MDBX database size has been reduced from approximately 1 TB to 64 GB.

This does not mean that the application immediately reserves or consumes 64 GB of storage. The database grows gradually as data is stored. The 64 GB value is the maximum configured size of the local MDBX database.

For normal wallet usage, this limit is expected to provide substantial headroom and the wallet can operate normally as long as the local database remains below this limit.

If the local MDBX database were ever to reach the configured 64 GB maximum, additional database writes could fail until the storage architecture is changed or the limit is increased.

This limitation does not directly limit:

- wallet balance
- number of addresses
- blockchain height
- number of transactions that can exist on the network
- cryptographic security

It only limits the maximum size of the local MDBX database used by the Android application.

The Android storage architecture is still being developed. A future version is planned to reduce the amount of persistent blockchain data required by the mobile wallet, remove unnecessary full-node storage dependencies, or otherwise provide a more suitable storage model for mobile devices.

If future Android devices routinely support significantly larger practical storage and memory-mapping requirements, the database limit may also be increased where appropriate.

## Releases

Official signed Android APK files are published in the GitHub Releases section.

Signing keys and keystore files are not included in this repository.

## License

See the LICENSE file included in this repository.

## Project Status

Parano1c is under active development.
