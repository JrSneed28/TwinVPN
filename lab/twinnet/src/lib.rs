//! `twinnet` — the real network fabric TwinLab scenarios run on.
//!
//! **Owner:** `test-engineering`. **Never shipped** (ADR-0018 §11.12).
//!
//! # What this crate adds to TwinLab
//!
//! `twinlab` describes conditions and decides verdicts. Until now nothing
//! *produced* those conditions on this class of host: `twinlab-scenarios` has a
//! `plan` subcommand and deliberately no `run`, because `ip netns add` needs
//! `CAP_NET_ADMIN` and every §3.3 NAT personality was realized by `nftables`,
//! and this host has neither. The honest state was `Verdict::Unavailable` for
//! the entire NAT matrix.
//!
//! This crate changes what the host can do, not what a missing facility is
//! allowed to report:
//!
//! | Obstacle | What this crate does about it |
//! |---|---|
//! | `ip netns add` needs `CAP_NET_ADMIN` | [`agent`] unshares a user namespace, where it holds the full capability set, and mounts a private `tmpfs` over `/run` so `ip netns`'s bind directory exists |
//! | no `nftables`, no `conntrack` | [`nat`] is a real middlebox process with a real RFC 4787 mapping table, real filtering behaviour and real timers |
//! | no `tcpdump` | [`observer`] reads `AF_PACKET` directly and owns its own parser, which is what rule **PT-2** wants anyway: an oracle the system under test shares no code with |
//! | nothing to prove the middlebox is what it claims | [`prober`] is an RFC 5780-style behaviour prober that is **not TwinVPN code**, which is what §3.4.2 requires before rule **L-1** lets a traversal test run at all |
//!
//! # What it does not change
//!
//! `Verdict::Unavailable` still means what it meant. A facility this host cannot
//! provide — `nftables` for a scenario that specifically asserts an `nft`
//! ruleset, a container runtime, an eBPF classifier for a `BIT`-deterministic
//! loss schedule — is still reported as absent, with the evidence of its
//! absence, and is never collapsed into a pass. The set of things this host can
//! do got larger; the rule about the things it cannot did not move.
//!
//! # The unsafe surface, enumerated
//!
//! Two files: [`afpacket`] (raw sockets) and the [`agent::enter`] function
//! (`unshare` and `mount`). Everything else is safe Rust, and `twinlab` itself
//! remains `#![forbid(unsafe_code)]`.

#![warn(missing_docs)]
#![warn(clippy::pedantic)]
// Product and protocol nouns — TwinVPN, TwinLab, TwinNet, NAT, IPv4, IPv6, DNS —
// and the specification quotations that carry them read worse back-ticked.
#![allow(clippy::doc_markdown)]
#![allow(clippy::module_name_repetitions)]
// Every fallible function here returns `NetError` with the condition in its
// message; the ones whose failure is interesting carry an `# Errors` section and
// the rest would be restating "an I/O failure" once per constructor.
#![allow(clippy::missing_errors_doc)]
// A laboratory converts between packet lengths, port numbers and byte offsets on
// nearly every line. Each conversion is bounded by a length check immediately
// above it, and `#[allow]` here is preferable to two hundred `try_from`s that
// would each need an `expect` a reviewer must also check.
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_wrap)]
// Every fallible path in this crate returns `NetError`; the `expect`s that
// remain are on values this code just constructed — a `serde_json::to_string` of
// a type that derives `Serialize`, a `CString` from a literal, a lock this
// process owns. A `# Panics` section on each would say "this cannot happen"
// fourteen times, which is noise a reviewer learns to skip past — and skipping
// past a panic note is the habit worth not forming.
#![allow(clippy::missing_panics_doc)]
// A 64 KiB receive buffer is one IP datagram. Putting it on the heap would move
// an allocation into the per-packet path of a middlebox whose latency the
// laboratory measures.
#![allow(clippy::large_stack_arrays)]
// `a`/`b` for the two ends of a link and the two sites of a pair is the
// vocabulary `docs/networking.md` §3.2 uses for the same things.
#![allow(clippy::similar_names)]
#![allow(clippy::many_single_char_names)]
// The topology builders are long because a topology is long: every address,
// route and neighbour is one line, and splitting `build_two_site` into three
// functions would put the parts of one picture in three places.
#![allow(clippy::too_many_lines)]
// A helper `fn` declared next to the loop that uses it, rather than at the top
// of a 200-line function far from its only caller.
#![allow(clippy::items_after_statements)]

pub mod afpacket;
pub mod agent;
pub mod dns64;
pub mod error;
pub mod fabric;
pub mod ip;
pub mod nat;
pub mod observer;
pub mod probe;
pub mod prober;
pub mod proto;
pub mod ra;
pub mod relay;
pub mod rewrite;
pub mod rigs;
pub mod sandbox;
pub mod traffic;
pub mod tun;

pub use error::{NetError, Result};
pub use observer::{Capture, Escape, LeakPolicy, Prefix, Reason, Strictness};
pub use sandbox::{ProcHandle, Ran, Sandbox};
