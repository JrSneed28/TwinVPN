//! `twinnet` — one binary that is every role in the fabric.
//!
//! **Owner:** `test-engineering`. Never shipped.
//!
//! One binary rather than seven because every role has to be spawnable *inside*
//! a namespace by the agent, and the agent knows exactly one path: its own. A
//! fabric that had to locate seven binaries would have seven ways to be
//! half-installed, and the failure mode of each is a scenario that quietly does
//! not run.
//!
//! | Subcommand | Role |
//! |---|---|
//! | `agent` | the privileged half: unshare, then take orders on stdin |
//! | `capabilities` | the same probe the agent runs, printed for a human |
//! | `natbox` | a §3.3 middlebox |
//! | `observe` | the rule PT-2 wire oracle |
//! | `reflect` | the two-address, two-port responder the prober measures against |
//! | `probe` | the §3.4.2 RFC 5780-style behaviour prober |
//! | `udp-send` / `udp-echo` | the traffic that makes a middlebox do work |
//! | `relay` / `relayed` | a forwarder, and a peer that fails over between forwarders |
//! | `tunnel` / `p2p` / `measure` | a real TUN tunnel, a simultaneous open, an impairment measurement |
//! | `dns64` / `nat64-probe` | §3.3's `N-NAT64`: a synthesizing resolver, and a v6-only client that uses it |
//! | `dns-query` | the DNS-leak positive control |

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use twinnet::nat::config::NatConfig;
use twinnet::nat::xlat::Pref64;
use twinnet::{agent, dns64, nat, observer, probe, prober, ra, relay, traffic, tun};

/// The three prefix-discovery paths, as a flag.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum DiscoveryArg {
    /// A AAAA the DNS64 synthesized for the destination.
    Aaaa,
    /// RFC 7050 `ipv4only.arpa`.
    Rfc7050,
    /// RFC 8781 PREF64 in a Router Advertisement.
    Ra,
}

impl DiscoveryArg {
    /// `iface` is leaked because [`dns64::Discovery`] holds a `'static` name and
    /// this is a one-shot process that exits immediately afterwards. A lifetime
    /// parameter threaded through the report type would buy nothing here.
    fn resolve(self, iface: String) -> dns64::Discovery {
        match self {
            DiscoveryArg::Aaaa => dns64::Discovery::SynthesizedAaaa,
            DiscoveryArg::Rfc7050 => dns64::Discovery::Rfc7050,
            DiscoveryArg::Ra => dns64::Discovery::RouterAdvertisement {
                iface: Box::leak(iface.into_boxed_str()),
            },
        }
    }
}

#[derive(Parser)]
#[command(name = "twinnet", about = "the TwinLab network fabric", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Unshare into a laboratory sandbox and serve requests on stdin.
    Agent,
    /// Probe what this host can realize, and print it.
    Capabilities,
    /// Run a §3.3 middlebox from a JSON configuration.
    Natbox {
        /// The configuration file.
        #[arg(long)]
        config: PathBuf,
    },
    /// Capture an interface and write one JSON record per frame.
    Observe {
        /// The interface.
        #[arg(long)]
        iface: String,
        /// Where to write the records.
        #[arg(long)]
        out: PathBuf,
        /// How long to capture.
        #[arg(long)]
        ms: u64,
    },
    /// Run the two-address, two-port reflector.
    Reflect {
        /// The primary address.
        #[arg(long)]
        primary: IpAddr,
        /// The alternate address.
        #[arg(long)]
        alternate: IpAddr,
        /// The primary port.
        #[arg(long, default_value_t = 3478)]
        port_a: u16,
        /// The alternate port.
        #[arg(long, default_value_t = 3479)]
        port_b: u16,
        /// How long to run.
        #[arg(long, default_value_t = 30_000)]
        ms: u64,
    },
    /// Measure a middlebox's behaviour, and print the report as JSON.
    Probe {
        /// The reflector's primary address.
        #[arg(long)]
        primary: IpAddr,
        /// Its alternate address.
        #[arg(long)]
        alternate: IpAddr,
        /// Its primary port.
        #[arg(long, default_value_t = 3478)]
        port_a: u16,
        /// Its alternate port.
        #[arg(long, default_value_t = 3479)]
        port_b: u16,
        /// How long to wait for each answer.
        #[arg(long, default_value_t = 500)]
        wait_ms: u64,
        /// Idle this long to measure the mapping lifetime. Expensive; omitted
        /// means "not measured", never "within tolerance".
        #[arg(long)]
        lifetime_ms: Option<u64>,
        /// The public endpoint of another host behind the same middlebox.
        #[arg(long)]
        hairpin_target: Option<SocketAddr>,
    },
    /// Send UDP and report what came back, as JSON.
    UdpSend {
        /// Where to send.
        #[arg(long)]
        to: SocketAddr,
        /// What to bind locally.
        #[arg(long, default_value = "0.0.0.0:0")]
        bind: SocketAddr,
        /// How many datagrams.
        #[arg(long, default_value_t = 3)]
        count: u32,
        /// The gap between them.
        #[arg(long, default_value_t = 50)]
        interval_ms: u64,
        /// How long to wait for each reply.
        #[arg(long, default_value_t = 500)]
        wait_ms: u64,
        /// The payload.
        #[arg(long, default_value = "TWINNET")]
        payload: String,
    },
    /// Send sequenced datagrams to an echo and report loss, duplication,
    /// reordering and latency.
    Measure {
        /// Where to send.
        #[arg(long)]
        to: SocketAddr,
        /// What to bind locally.
        #[arg(long, default_value = "0.0.0.0:0")]
        bind: SocketAddr,
        /// How many datagrams.
        #[arg(long, default_value_t = 200)]
        count: u32,
        /// The gap between them.
        #[arg(long, default_value_t = 2)]
        interval_ms: u64,
        /// How long to drain replies after the last send.
        #[arg(long, default_value_t = 1500)]
        wait_ms: u64,
    },
    /// Echo every datagram back to its sender.
    UdpEcho {
        /// What to bind.
        #[arg(long)]
        bind: SocketAddr,
        /// How long to run.
        #[arg(long, default_value_t = 30_000)]
        ms: u64,
    },
    /// Run a forwarder two peers behind symmetric NATs can both reach.
    Relay {
        /// What to bind.
        #[arg(long)]
        bind: SocketAddr,
        /// How long to run.
        #[arg(long, default_value_t = 120_000)]
        ms: u64,
    },
    /// Bind to the first relay that answers and exchange traffic through it.
    Relayed {
        /// The relays to try, in order.
        #[arg(long, value_delimiter = ',', num_args = 1..)]
        relays: Vec<SocketAddr>,
        /// The tag the two legs meet under.
        #[arg(long)]
        tag: String,
        /// How many exchange rounds.
        #[arg(long, default_value_t = 10)]
        rounds: u32,
        /// The gap between rounds.
        #[arg(long, default_value_t = 60)]
        interval_ms: u64,
        /// How long to wait for each relay's acknowledgement before trying the
        /// next.
        #[arg(long, default_value_t = 400)]
        bind_wait_ms: u64,
    },
    /// Run a datagram tunnel between a TUN device and a UDP endpoint.
    Tunnel {
        /// The TUN device to create.
        #[arg(long, default_value = "tun0")]
        dev: String,
        /// The underlay address to bind.
        #[arg(long)]
        bind: SocketAddr,
        /// The underlay address of the far end. Omit on the far end of a
        /// tunnel whose near end is behind a NAT: its mapped endpoint is
        /// allocated by the middlebox and cannot be known in advance, so this
        /// end learns it from the first datagram.
        #[arg(long)]
        peer: Option<SocketAddr>,
        /// How long to run.
        #[arg(long, default_value_t = 60_000)]
        ms: u64,
    },
    /// One side of a simultaneous open across two middleboxes.
    P2p {
        /// The reflector that tells this peer its external endpoint.
        #[arg(long)]
        reflector: SocketAddr,
        /// Where to publish this peer's external endpoint.
        #[arg(long)]
        mine: PathBuf,
        /// Where to read the other peer's from.
        #[arg(long)]
        theirs: PathBuf,
        /// How many punch rounds.
        #[arg(long, default_value_t = 10)]
        rounds: u32,
        /// The gap between rounds.
        #[arg(long, default_value_t = 60)]
        interval_ms: u64,
        /// How long to wait for the peer to publish.
        #[arg(long, default_value_t = 4000)]
        wait_ms: u64,
        /// Keep the established path alive for this long after the punch,
        /// touching no third party. The window a chaos scenario acts in.
        #[arg(long, default_value_t = 0)]
        hold_ms: u64,
    },
    /// Advertise RFC 8781's PREF64 option in Router Advertisements.
    ///
    /// The path `docs/networking.md` §3.8 prefers, and the third of §3.3's
    /// independently switchable prefix advertisements.
    RaAdvertise {
        /// The interface to advertise on.
        #[arg(long)]
        iface: String,
        /// The prefix to advertise.
        #[arg(long, default_value = "64:ff9b::")]
        pref64: Ipv6Addr,
        /// RFC 8781's scaled lifetime, in seconds.
        #[arg(long, default_value_t = 600)]
        lifetime_s: u16,
        /// The gap between advertisements.
        #[arg(long, default_value_t = 200)]
        interval_ms: u64,
        /// How long to run.
        #[arg(long, default_value_t = 120_000)]
        ms: u64,
    },
    /// Serve a laboratory DNS64 resolver.
    ///
    /// The two discovery paths §3.3 wants switchable are `--synthesize` and
    /// `--rfc7050`, and they are independent flags for exactly that reason.
    Dns64 {
        /// What to bind.
        #[arg(long)]
        bind: SocketAddr,
        /// `NAME=A.B.C.D`, repeatable.
        #[arg(long = "map", value_name = "NAME=IPV4")]
        maps: Vec<String>,
        /// The RFC 6052 translation prefix.
        #[arg(long, default_value = "64:ff9b::")]
        pref64: Ipv6Addr,
        /// Synthesize AAAA for an ordinary name. Off is §3.3's "PREF64 absent".
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        synthesize: bool,
        /// Answer `ipv4only.arpa`, which is RFC 7050's discovery path.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        rfc7050: bool,
        /// How long to run.
        #[arg(long, default_value_t = 120_000)]
        ms: u64,
    },
    /// A v6-only client reaching a v4-only destination through a NAT64.
    Nat64Probe {
        /// The resolver.
        #[arg(long)]
        resolver: SocketAddr,
        /// The name to reach.
        #[arg(long)]
        name: String,
        /// The destination port.
        #[arg(long, default_value_t = 9)]
        port: u16,
        /// How to learn the translation prefix. The three are independently
        /// switchable, which is what §3.3 asks for.
        #[arg(long, value_enum, default_value_t = DiscoveryArg::Aaaa)]
        discover: DiscoveryArg,
        /// The interface to listen on, for `--discover ra`.
        #[arg(long, default_value = "lan")]
        iface: String,
        /// How long to wait for each answer.
        #[arg(long, default_value_t = 700)]
        wait_ms: u64,
    },
    /// Send one real plaintext DNS query. The leak oracle's positive control.
    DnsQuery {
        /// The resolver.
        #[arg(long)]
        server: SocketAddr,
        /// The name to ask for.
        #[arg(long)]
        name: String,
        /// How long to wait for an answer.
        #[arg(long, default_value_t = 500)]
        wait_ms: u64,
    },
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        // MUST be first: `unshare(CLONE_NEWUSER)` is refused from a
        // multi-threaded process, and clap has not started one.
        Command::Agent => agent::enter().and_then(|()| {
            let stdin = std::io::stdin();
            let stdout = std::io::stdout();
            agent::serve(stdin.lock(), stdout.lock())
        }),
        Command::Capabilities => agent::enter().map(|()| {
            for fact in probe::probe_all() {
                let mark = if fact.available {
                    "AVAILABLE  "
                } else {
                    "unavailable"
                };
                println!("  {:<20} {mark} {}", fact.facility, fact.evidence);
            }
        }),
        Command::Natbox { config } => std::fs::read_to_string(&config)
            .map_err(|e| twinnet::NetError::os("reading the middlebox configuration", e))
            .and_then(|text| {
                serde_json::from_str::<NatConfig>(&text)
                    .map_err(|e| twinnet::NetError::Malformed(e.to_string()))
            })
            .and_then(nat::run),
        Command::Observe { iface, out, ms } => {
            observer::run(&iface, &out, Duration::from_millis(ms))
        }
        Command::Reflect {
            primary,
            alternate,
            port_a,
            port_b,
            ms,
        } => traffic::reflect(
            primary,
            alternate,
            port_a,
            port_b,
            Duration::from_millis(ms),
        ),
        Command::Probe {
            primary,
            alternate,
            port_a,
            port_b,
            wait_ms,
            lifetime_ms,
            hairpin_target,
        } => prober::Probe {
            primary,
            alternate,
            port_a,
            port_b,
            wait: Duration::from_millis(wait_ms),
            lifetime_ms,
            hairpin_target,
        }
        .run()
        .map(|report| print_json(&report)),
        Command::UdpSend {
            to,
            bind,
            count,
            interval_ms,
            wait_ms,
            payload,
        } => traffic::udp_send(
            bind,
            to,
            &payload,
            count,
            Duration::from_millis(interval_ms),
            Duration::from_millis(wait_ms),
        )
        .map(|report| print_json(&report)),
        Command::Measure {
            to,
            bind,
            count,
            interval_ms,
            wait_ms,
        } => traffic::measure(
            bind,
            to,
            count,
            Duration::from_millis(interval_ms),
            Duration::from_millis(wait_ms),
        )
        .map(|report| print_json(&report)),
        Command::UdpEcho { bind, ms } => {
            traffic::udp_echo(bind, Duration::from_millis(ms)).map(|seen| {
                println!("{{\"seen\":{seen}}}");
            })
        }
        Command::Relay { bind, ms } => relay::serve(bind, Duration::from_millis(ms)),
        Command::Relayed {
            relays,
            tag,
            rounds,
            interval_ms,
            bind_wait_ms,
        } => relay::relayed(
            &relays,
            &tag,
            rounds,
            Duration::from_millis(interval_ms),
            Duration::from_millis(bind_wait_ms),
        )
        .map(|report| print_json(&report)),
        Command::Tunnel {
            dev,
            bind,
            peer,
            ms,
        } => tun::run(&dev, bind, peer, Duration::from_millis(ms)),
        Command::P2p {
            reflector,
            mine,
            theirs,
            rounds,
            interval_ms,
            wait_ms,
            hold_ms,
        } => traffic::p2p(
            reflector,
            &mine,
            &theirs,
            rounds,
            Duration::from_millis(interval_ms),
            Duration::from_millis(wait_ms),
            Duration::from_millis(hold_ms),
        )
        .map(|report| print_json(&report)),
        Command::RaAdvertise {
            iface,
            pref64,
            lifetime_s,
            interval_ms,
            ms,
        } => ra::advertise(
            &iface,
            Pref64 {
                prefix: pref64,
                len: 96,
            },
            lifetime_s,
            Duration::from_millis(interval_ms),
            Duration::from_millis(ms),
        ),
        Command::Dns64 {
            bind,
            maps,
            pref64,
            synthesize,
            rfc7050,
            ms,
        } => {
            let mut a = std::collections::BTreeMap::new();
            for entry in &maps {
                let Some((name, addr)) = entry.split_once('=') else {
                    eprintln!("twinnet: `{entry}` is not NAME=IPV4");
                    return std::process::ExitCode::FAILURE;
                };
                match addr.parse() {
                    Ok(v4) => {
                        a.insert(name.to_ascii_lowercase(), v4);
                    }
                    Err(_) => {
                        eprintln!("twinnet: `{addr}` is not an IPv4 address");
                        return std::process::ExitCode::FAILURE;
                    }
                }
            }
            let zone = dns64::Zone {
                a,
                pref64: Pref64 {
                    prefix: pref64,
                    len: 96,
                },
                synthesize,
                rfc7050,
            };
            dns64::serve(bind, &zone, Duration::from_millis(ms))
        }
        Command::Nat64Probe {
            resolver,
            name,
            port,
            discover,
            iface,
            wait_ms,
        } => dns64::probe(
            resolver,
            &name,
            port,
            discover.resolve(iface),
            Duration::from_millis(wait_ms),
        )
        .map(|report| print_json(&report)),
        Command::DnsQuery {
            server,
            name,
            wait_ms,
        } => traffic::dns_query(server, &name, Duration::from_millis(wait_ms)).map(|answered| {
            println!("{{\"answered\":{answered}}}");
        }),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("twinnet: {e}");
            // A facility this host cannot provide exits 3 rather than 1, so a
            // caller can tell "could not produce the condition" from "the
            // condition did not hold" without parsing a message. §3.1's rule,
            // carried all the way to the process boundary.
            if e.is_unavailable() {
                std::process::ExitCode::from(3)
            } else {
                std::process::ExitCode::FAILURE
            }
        }
    }
}

fn print_json<T: serde::Serialize>(value: &T) {
    match serde_json::to_string(value) {
        Ok(text) => println!("{text}"),
        Err(e) => eprintln!("twinnet: could not encode the report: {e}"),
    }
}
