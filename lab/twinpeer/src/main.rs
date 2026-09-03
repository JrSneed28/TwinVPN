//! `twinpeer` — the TwinLab L-DATA peer.
//!
//! **Authority:** ADR-0018 §11.12 ("`/lab/` TwinLab; never shipped");
//! `docs/testing-strategy.md` §3.1's REALIZATION PRINCIPLE.
//!
//! The Windows kill-switch lane's oracle has to observe egress that came out of
//! a real tunnel. That needs a real peer at the other end, and a peer that
//! reimplemented `Noise_IKpsk2` would be a second implementation whose agreement
//! with the product is the thing under test. So this binary calls the product's
//! own handshake and the product's own pump through
//! [`twinvpn_core::lab`], over the product's own Windows adapter.
//!
//! ```text
//! twinpeer seed  --guest-out guest.json --peer-out peer.json \
//!                --peer-endpoint 10.77.0.1:51820
//! twinpeer serve --seed peer.json --adapter-name twinpeer --wintun-dll C:\lab
//! ```
//!
//! `seed` writes two halves of one document; `serve` reads the peer half, holds
//! a Wintun adapter for the whole run and prints `TWINPEER_ADAPTER_READY <luid>`
//! once the adapter exists, which is the line the lane blocks on before it
//! assigns the overlay addresses.
//!
//! **Never shipped, and never a release artifact.** The seed carries a static
//! private key in a JSON file, and the crate that lets it reach the handshake is
//! behind `twinvpn-core/lab-peer`, which is in neither `default` nor `full`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]

mod seed;
mod seedfile;
mod serve;
mod sockets;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "twinpeer", about = "the TwinLab L-DATA peer")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generates the two halves of a lab seed.
    Seed {
        /// Where the guest half is written. Copied into the disposable guest.
        #[arg(long)]
        guest_out: PathBuf,
        /// Where the peer half is written. Stays on the lab host.
        #[arg(long)]
        peer_out: PathBuf,
        /// The peer's UDP endpoint, which the guest sends its initiation to.
        #[arg(long)]
        peer_endpoint: String,
        /// The `TwinNet` both halves name.
        #[arg(long, default_value = "tn-lab")]
        twinnet_id: String,
        /// The guest's overlay IPv4 address.
        #[arg(long, default_value = seed::GUEST_OVERLAY_V4)]
        guest_overlay_v4: String,
        /// The guest's overlay IPv6 address.
        #[arg(long, default_value = seed::GUEST_OVERLAY_V6)]
        guest_overlay_v6: String,
        /// The peer's overlay IPv4 address, which is the oracle's beacon target.
        #[arg(long, default_value = seed::PEER_OVERLAY_V4)]
        peer_overlay_v4: String,
        /// The peer's overlay IPv6 address.
        #[arg(long, default_value = seed::PEER_OVERLAY_V6)]
        peer_overlay_v6: String,
    },
    /// Holds a Wintun adapter and answers the guest's handshakes.
    Serve {
        /// The peer half, as `seed --peer-out` wrote it.
        #[arg(long)]
        seed: PathBuf,
        /// The Wintun adapter's name.
        #[arg(long, default_value = "twinpeer")]
        adapter_name: String,
        /// A directory holding `wintun.dll`.
        ///
        /// The DLL is copied beside this binary if it is not already there,
        /// because `WintunDriver::load` searches the application directory and
        /// nowhere else — a property this lab tool does not weaken.
        #[arg(long)]
        wintun_dll: Option<PathBuf>,
        /// A scratch directory the adapter is told about and never writes to.
        #[arg(long, default_value = ".")]
        state_dir: PathBuf,
    },
}

fn main() -> Result<()> {
    // The subscriber is installed by the binary and never by a library: it is a
    // process-global side effect, which is why `twinvpn-core` declines to own
    // one. Logs go to stdout beside `TWINPEER_ADAPTER_READY`, which is what the
    // lane scrapes.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match Cli::parse().command {
        Command::Seed {
            guest_out,
            peer_out,
            peer_endpoint,
            twinnet_id,
            guest_overlay_v4,
            guest_overlay_v6,
            peer_overlay_v4,
            peer_overlay_v6,
        } => seed::run(&seed::SeedArgs {
            guest_out,
            peer_out,
            peer_endpoint,
            twinnet_id,
            guest_overlay_v4,
            guest_overlay_v6,
            peer_overlay_v4,
            peer_overlay_v6,
        }),
        Command::Serve {
            seed: peer_file,
            adapter_name,
            wintun_dll,
            state_dir,
        } => serve::run(&serve::ServeArgs {
            peer_file,
            adapter_name,
            wintun_dll,
            state_dir,
        }),
    }
}
