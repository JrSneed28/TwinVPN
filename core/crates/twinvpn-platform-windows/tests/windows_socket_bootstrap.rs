//! **The first Winsock call this process makes must succeed.**
//!
//! **Authority:** [`twinvpn_platform::SocketProvider::bind_udp`]'s contract — a
//! refusal is "a **fact about the host**", so a refusal caused by this process
//! never having initialised Winsock is a lie about the host.
//!
//! # Why this is its own test target and not one more case in `windows_host.rs`
//!
//! Every Winsock entry point except `WSAGetLastError` refuses with
//! `WSANOTINITIALISED` (10093) until the **process** has called `WSAStartup`.
//! `std` does it lazily from inside `std::net`, so any test that had already
//! touched a `std::net` type would leave the stack initialised and this
//! assertion would pass over a crate that never calls `WSAStartup` at all — a
//! vacuous test of exactly the property that matters.
//!
//! One test in its own binary is the only shape that is decisive: the process
//! contains this test and nothing else, `#[tokio::test]` builds a runtime
//! (which creates an IOCP and is **not** a Winsock call), and then the first
//! Winsock call in the process is the one under test.
//!
//! # The defect this pins
//!
//! Observed on a live Windows host on 2026-09-03: `bind_udp` refused with
//! `PLATFORM.ADAPTER_UNAVAILABLE`, `OsDetail { code: 10093, call: "WSASocketW" }`,
//! in a process whose only prior work was building a tokio runtime and opening
//! a Wintun adapter. `twinvpnsvc` has that exact shape — it talks to its shell
//! over a **named pipe**, which is not Winsock — so the first socket the L-DATA
//! handshake needs was the first Winsock call in the service too.
//!
//! # Gated the same way as `windows_host.rs`
//!
//! `#![cfg(windows)]`, so it compiles to nothing on the Linux host this crate
//! was written on and is type-checked for `x86_64-pc-windows-msvc` by
//! `make cross-check`. It needs **no** `TWINVPN_WINDOWS_TEST` opt-in: binding a
//! UDP socket on the loopback at an ephemeral port installs no filter, programs
//! no route and writes no registry key.

#![cfg(windows)]

use twinvpn_platform::{SocketFamily, SocketOptions, SocketProvider as _, UdpBindSpec};
use twinvpn_platform_windows::sock::WindowsSocketProvider;
use twinvpn_platform_windows::ShutdownLatch;

#[tokio::test]
async fn the_first_winsock_call_in_a_process_opens_a_socket() {
    let provider = WindowsSocketProvider::new(ShutdownLatch::new());
    let socket = provider
        .bind_udp(&UdpBindSpec {
            family: SocketFamily::V4,
            // The wildcard at an ephemeral port: nothing on this host can be
            // holding it, so a failure here is the stack and not the address.
            local: None,
            options: SocketOptions::default(),
        })
        .await;

    let socket = match socket {
        Ok(socket) => socket,
        Err(error) => panic!(
            "the first Winsock call in this process was refused: {error:?}. \
             `code: 10093` is WSANOTINITIALISED and means `WSAStartup` was never \
             called -- see `sock::imp::ensure_winsock`."
        ),
    };
    let bound = socket
        .local_endpoint()
        .expect("a bound socket reports its endpoint");
    assert_ne!(bound.port.get(), 0, "an ephemeral port was resolved");
    socket.close().await.expect("close is idempotent");
}
