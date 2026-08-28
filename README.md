# Parano1c Android

Parano1c is an Android wallet and mobile node implementation built on top of the Parano1d source code.

The current Parano1c Android release is built against:

Parano1d v1.0.3

Upstream project:

https://github.com/ignotusnemo/parano1d

Parano1c Android:

https://github.com/Aquacongas/Parano1c


## Current Status

Parano1c Android is under active development.

The current Android version is based on the Parano1d v1.0.4 source tree and adds the Android application, mobile node integration, mobile wallet functionality and native Rust/Android interface.

This is still an experimental mobile implementation.

Things may break and future versions may require changes to synchronization, storage or mobile-specific components.

Always keep your wallet keys backed up.


## Android Features

The current Android wallet provides:

- Wallet balance
- Active wallet address
- Send
- Send All
- Receive
- Network status
- Current block height
- Synchronization status
- Peer count
- Recent transactions
- Local mobile node integration
- Native Rust backend through noid_mobile_ffi


## Source Layout

Parano1c uses the complete Parano1d Rust workspace.

The main Android-specific components are:

    android/
    noid_mobile_node/
    noid_mobile_ffi/

These components depend on the rest of the Parano1d workspace and are not intended to be compiled completely independently.

Important dependencies include:

    noid_wallet/
    noid_networking/
    noid_p2p/
    noid_chain/
    noid_core/
    noid_recursive/
    noid_sync_apply/
    noid_history_runtime/

and other Parano1d crates.


## Requirements

The following tools are required to build the Android version:

- Rust
- Cargo
- Android SDK
- Android NDK
- Java 17
- cargo-ndk
- Android ARM64 Rust target

Install cargo-ndk:

    cargo install cargo-ndk

Install the Android ARM64 Rust target:

    rustup target add aarch64-linux-android

The Rust version used by the project is defined in:

    rust-toolchain.toml


## HistoryStep Pack

The Android/mobile build requires the Parano1d HistoryStep pack corresponding to the Parano1d version being built.

For Parano1d v1.0.4 download:

https://github.com/ignotusnemo/parano1d/releases/download/v1.0.4/history-step-pack-v1.tar.gz

From the root of the repository:

    mkdir -p release-assets/history-step/pack

    curl -L \
      https://github.com/ignotusnemo/parano1d/releases/download/v1.0.4/history-step-pack-v1.tar.gz \
      -o /tmp/history-step-pack-v1.tar.gz

    tar -xzf /tmp/history-step-pack-v1.tar.gz \
      -C release-assets/history-step/pack

Locate pins.env:

    find release-assets/history-step/pack -name pins.env -print

Set the pack directory automatically:

    HISTORY_PACK_DIR="$(dirname "$(find "$PWD/release-assets/history-step/pack" -name pins.env -print -quit)")"

Load the pinned configuration:

    set -a
    source "$HISTORY_PACK_DIR/pins.env"
    set +a

    export NOID_HISTORY_STEP_PACK_DIR="$HISTORY_PACK_DIR"


## Build the Rust Components

From the repository root:

    cargo fmt

    cargo check \
      -p noid_wallet \
      -p noid_mobile_node \
      -p noid_mobile_ffi \
      -j16

The build should complete successfully before building the Android native library.


## Build the Android ARM64 Native Library

From the repository root:

    NOID_HISTORY_STEP_PACK_DIR="$HISTORY_PACK_DIR" \
    cargo ndk -t arm64-v8a \
      -o android/app/src/main/jniLibs \
      build --release -p noid_mobile_ffi -j16

This generates the native Rust library used by the Android application.


## Build the Debug APK

    cd android

    ./gradlew assembleDebug

The debug APK will be created under:

    android/app/build/outputs/apk/debug/


## Build a Signed Release APK

The Android project supports a release signing configuration.

A private signing keystore is intentionally NOT included in this repository.

Never commit your signing keystore or passwords.

The expected keystore location for the current configuration is:

    android/parano1c-release.jks

The following environment variables are used for signing:

    PARANO1C_KEYSTORE_PASSWORD
    PARANO1C_KEY_PASSWORD

Example:

    export PARANO1C_KEYSTORE_PASSWORD='YOUR_PASSWORD'
    export PARANO1C_KEY_PASSWORD='YOUR_PASSWORD'

Then:

    cd android

    ./gradlew assembleRelease

The signed APK is generated under:

    android/app/build/outputs/apk/release/

The current release artifact name is:

    parano1c-release.apk


## Verify the APK

Generate the APK SHA256 checksum:

    sha256sum parano1c-release.apk

Create a checksum file:

    sha256sum parano1c-release.apk > SHA256SUMS.txt

Verify the signing certificate embedded in the APK:

    apksigner verify --print-certs parano1c-release.apk

Official releases should publish both:

- APK SHA256 checksum
- Signing certificate SHA256 fingerprint


## Official Signing Certificate

The current Parano1c Android signing certificate SHA256 fingerprint is:

    D0:1A:B5:DB:87:F8:1E:95:55:A2:11:DB:86:A5:03:61:35:3D:82:27:F2:48:2B:C6:92:58:56:83:27:B4:F0:18

Users should verify that downloaded Android releases are signed with the expected certificate.


## MDBX Android Storage Limitation

Parano1c Android currently uses MDBX for persistent local storage.

The original database geometry allowed approximately 1 TB.

For the Android implementation the maximum MDBX database size has been reduced to:

    64 GB

This does not mean that the application immediately allocates or consumes 64 GB.

The MDBX database grows gradually as data is stored.

The 64 GB limit applies only to the maximum size of the local MDBX database.

It does not directly limit:

- wallet balance
- number of addresses
- blockchain height
- number of transactions on the network
- cryptographic security

The wallet can operate normally while its local MDBX database remains below the configured maximum.

If the database eventually reaches the 64 GB limit, additional database writes may fail.


## Future Android Storage Work

The current MDBX configuration is not intended to be the final mobile storage architecture.

Future development may reduce the amount of persistent full-node data required by the mobile wallet, separate unnecessary full-node storage dependencies from Android, or introduce a storage architecture better suited to mobile devices.

The configured MDBX limit may also be increased in the future if Android hardware and platform constraints make significantly larger local databases practical.


## Releases

Signed Android releases are published here:

https://github.com/Aquacongas/Parano1c/releases


## Security

Never commit or publish:

- Android signing keystores
- private keys
- wallet master keys
- seed phrases
- passwords
- API tokens
- environment files containing secrets

Before using experimental releases with funds, make sure your wallet keys are safely backed up.


## Upstream

Parano1c Android uses the Parano1d source code.

Upstream repository:

https://github.com/ignotusnemo/parano1d

The current Android version is built against Parano1d v1.0.4.


## License

Parano1c retains the licensing and notices applicable to the upstream Parano1d source code.

See:

    LICENSE
    NOTICE

for details.
