// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero. All rights reserved.

// Release proving must never fall back to scalar GF(2^128) arithmetic or lose
// the two-lane Link kernel because Cargo was invoked outside the workspace or
// a caller replaced `.cargo/config.toml` through RUSTFLAGS.  `build.rs` marks
// the release profile; these built-in cfg values describe the final codegen
// target even when `cargo rustc` appends another CPU flag.
#[cfg(all(
    noid_release_profile,
    target_arch = "x86_64",
    not(all(
        target_feature = "sse4.1",
        target_feature = "pclmulqdq",
        target_feature = "avx2",
        target_feature = "vpclmulqdq"
    ))
))]
compile_error!(
    "Paranoid release builds require SSE4.1, PCLMULQDQ, AVX2, and VPCLMULQDQ; \
     do not override the workspace `-C target-cpu=native` rustflags"
);

#[cfg(all(
    noid_release_profile,
    target_arch = "aarch64",
    not(target_feature = "aes")
))]
compile_error!(
    "Paranoid release builds on aarch64 require AES/PMULL; \
     do not override the workspace `-C target-cpu=native` rustflags"
);

#[cfg(all(
    noid_release_profile,
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
compile_error!("Paranoid release builds support only x86_64 and aarch64 proof targets");

pub mod field;
pub mod hardware;
pub mod mem_profile;
pub mod mle;
pub mod ntt;
pub mod packable;
pub mod packed;
pub mod sumcheck;
pub mod tower;
pub mod transcript;

pub use field::*;
pub use ntt::AdditiveNTT;
pub use tower::*;
