//! The userspace packet path: TUN in, tunnel out, and back.
//!
//! **Owner:** `core-composition`. Scaffolded by the integration lead; the
//! implementation is this module's own.
//!
//! **Authority:** ADR-0018 §11.2 row 2.3 ("on Linux/OpenWrt the core *programs*
//! the kernel WireGuard module; elsewhere the core *is* the datapath"), CB-1
//! (the packet path reaches the OS only through the adapter), CB-2 (the core
//! decides), CD-1/CD-2 (clocks and `Env` are injected);
//! `twinvpn_platform::config::{Datapath, TunnelDevice}`.
