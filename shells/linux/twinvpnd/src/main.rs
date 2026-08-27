//! `twinvpnd` — the privileged Linux agent: hosts the core, owns the tun device, the routing table, nftables and resolv.conf (ADR-0016).
//!
//! **Owner:** `desktop-linux`.
//!
//! **CB-2 (ADR-0018 §11.1): this binary holds no decision.** Nothing is
//! implemented yet.
#![forbid(unsafe_code)]

fn main() {
    eprintln!("twinvpnd: not implemented (owner: desktop-linux)");
    std::process::exit(1);
}
