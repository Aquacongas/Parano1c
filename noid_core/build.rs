// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero. All rights reserved.

fn main() {
    println!("cargo:rustc-check-cfg=cfg(noid_release_profile)");

    if std::env::var("PROFILE").as_deref() == Ok("release") {
        println!("cargo:rustc-cfg=noid_release_profile");
    }
}
