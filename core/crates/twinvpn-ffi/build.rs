//! Decides, at build time, whether this staticlib must carry the iOS adapter.
//!
//! # Why this is a build script and not a `#[cfg(target_os = "ios")]`
//!
//! ADR-0018 **CB-3** forbids `#[cfg(target_os = …)]` outside a
//! `twinvpn-platform-*` crate, and `core/xtask`'s CD-CB3 check enforces it as a
//! merge gate. `docs/networking.md` §5.1 says why: nothing above the adapter may
//! branch on OS, because a behavioural difference that only appears on one
//! target is a defect nobody's CI sees.
//!
//! The linkage question is not that kind of branch. Nothing about how this crate
//! *behaves* varies here — the three `tw_host_vtable` slots
//! (`os_csprng`, `elapsed_millis`, `boot_id`) have existed since minor 0 and are
//! served identically on every target. What varies is only **which object files
//! the archiver puts in the `.a`**, and a build script is where build-target
//! decisions belong. So the crate source names a linkage capability
//! (`link_ios_adapter`) and this file is the single place that knows an OS name.
//!
//! # What goes wrong without it
//!
//! `shells/ios` links exactly one archive — this crate's `staticlib` — and
//! nothing in this crate *references* `twinvpn-platform-ios`, so the linker has
//! no reason to pull its objects in. Every `twinvpn_ios_*` symbol the Swift side
//! calls is then undefined at the shell's link step: a link failure, not a
//! runtime one, and invisible on any host without a Darwin SDK. `extern crate`
//! under this cfg is what forces the archive membership.

fn main() {
    // Declared so `--cfg link_ios_adapter` is a known cfg and an unexpected-cfgs
    // warning fires if this name and the one in `lib.rs` ever drift apart.
    println!("cargo:rustc-check-cfg=cfg(link_ios_adapter)");
    println!("cargo:rerun-if-changed=build.rs");

    // CARGO_CFG_TARGET_OS is an environment variable Cargo sets for the build
    // script. It is a string lookup, not a `cfg` predicate, which is both why
    // CD-CB3 does not fire on it and why this is the honest place for the
    // decision rather than a way around the rule.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("ios") {
        println!("cargo:rustc-cfg=link_ios_adapter");
    }
}
