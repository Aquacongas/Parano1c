# Parano1c Android

Parano1c is an Android wallet and mobile node implementation built on top of the Parano1d source code.

The current Parano1c Android release is built against:

Parano1d v2.0.3

## Android-specific source adaptations

Parano1c is based on the Parano1d source code, but some upstream files have been adapted specifically for Android/mobile operation.

These changes are limited to platform-specific compatibility and runtime handling required by Android. They do not represent an attempt to change the underlying Parano1d consensus rules or network protocol.

Where applicable, the modified files can be compared directly with the original Parano1d sources to review the Android-specific differences.

Upstream project:
https://github.com/ignotusnemo/parano1d

This repository:
https://github.com/Aquacongas/Parano1c

## Current Status

Parano1c Android is under active development.

The current Android version is based on the Parano1d v2.0.3 source tree and adds the Android application, mobile node integration, mobile wallet functionality and native Rust/Android interface.

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


## HistoryStep v1 and v2 packs

The Android release embeds authenticated proof material for both the legacy
HistoryStep ancestry and the frozen v2 bank. The pack directories are external
build inputs; do not commit generated matrices, retirement keys or local paths.

Obtain the release-matched legacy pack, the frozen v2 pack, its reviewed bank
pin and both independently verified retirement-key pins from the official
Parano1d release/build documentation. Do not substitute an H10 test pack for
the mainnet v2 bank. The legacy pack must contain the `v1/` runtime metadata
and matrices; the v2 pack must contain the authenticated v2 runtime metadata,
Small/Large matrices and `retirement-keys/class-0.key` and `class-1.key`.

Set the following environment variables to paths and verified **64-character
lowercase hexadecimal SHA-256 digests** appropriate to the release being built:

```sh
export NOID_HISTORY_STEP_PACK_DIR="PATH_TO_LEGACY_HISTORY_STEP_PACK"
export NOID_HISTORY_STEP_RUNTIME_METADATA_RELEASE_DIGEST="REVIEWED_LEGACY_METADATA_SHA256"
export NOID_V2_PACK_DIR="PATH_TO_FROZEN_V2_PACK"
export NOID_V2_RELEASE_BANK="REVIEWED_V2_BANK_SHA256"
export NOID_RETIREMENT_KEYS_DIR="${NOID_V2_PACK_DIR}/retirement-keys"
export NOID_RETIREMENT_KEY_0_PIN="REVIEWED_CLASS_0_KEY_SHA256"
export NOID_RETIREMENT_KEY_1_PIN="REVIEWED_CLASS_1_KEY_SHA256"
```

The placeholders above are **not usable digests**. Verify the actual pins and
pack layout against the upstream release manifest before building. A release
build must fail if an artifact or digest does not match; do not bypass these
checks. For provenance and reproduction see the upstream
[build guide](https://github.com/ignotusnemo/parano1d/blob/v2/docs/developers/build.md).

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

    cargo ndk --target arm64-v8a --platform 26 \
      --output-dir android/app/src/main/jniLibs \
      build --release -p noid_mobile_ffi

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

Configure the release signing key, alias and passwords locally in the
Android Gradle signing configuration. Never hard-code them in the repository.
The chosen keystore **must** match the certificate of the APK being updated.
The signed release build can be produced with:

    cd android

    ./gradlew :app:assembleRelease

If Gradle requires a keystore, provide it through the local signing
configuration, not through files committed to Git.

The signed APK is generated under:

    android/app/build/outputs/apk/release/

The release artifact may be renamed to `Parano1c.apk` for publication.


## Verify the APK

Generate the APK SHA256 checksum:

    sha256sum Parano1c.apk

Create a checksum file:

    sha256sum Parano1c.apk > SHA256SUMS.txt

Verify the signing certificate embedded in the APK:

    apksigner verify --verbose --print-certs Parano1c.apk

Official releases should publish both:

- APK SHA-256 and SHA-512 checksums
- Signing certificate SHA-256 fingerprint


## Official Signing Certificate

The current Parano1c Android signing certificate SHA256 fingerprint is:

    AD:B0:D8:65:E5:4E:CB:46:8F:10:A6:CC:91:D4:60:E7:C0:E9:D3:A6:AA:83:2D:0F:4B:4B:0E:EC:6C:1E:2F:53

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

The current Android version is built against Parano1d v2.0.3.


## License

Parano1c retains the licensing and notices applicable to the upstream Parano1d source code.

See:

    LICENSE
    NOTICE

for details.
