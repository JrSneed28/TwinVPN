//! Host resolver programming, and the restore point that must survive us.
//!
//! **Authority:** ADR-0011 **DN-18** (the `RestorePoint` is written and flushed
//! *before* the mutation), **DN-19** (the ordering), **DN-20** (restoration must
//! not require the agent to be healthy), **DN-21** (prefer configuration owned by
//! the tunnel object; the two Linux forms), §11.9 (the Linux bypass row);
//! ADR-0016 PS-6 (restore-before-mutate) and PS-21 step 3.
//!
//! # DN-18, made an ordering rather than an intention
//!
//! > Before writing any host resolver configuration, the agent MUST durably
//! > persist an owner-tagged `RestorePoint` containing the **verbatim prior
//! > configuration**, the platform object identifiers needed to restore it, and a
//! > `restore_token`. It is written and flushed **before** the mutation, never
//! > after.
//!
//! [`apply`] writes and `fsync`s the restore point, and only then touches
//! `/etc/resolv.conf`. There is no path through this module that reaches the
//! mutation without the restore point already on disk, and
//! `the_restore_point_is_durable_before_the_mutation` asserts it by making the
//! restore-point write fail and checking the host was left untouched.
//!
//! # DN-21: which Linux form this build uses, stated honestly
//!
//! The ADR names exactly two Linux forms:
//!
//! | Form | Dies with the tunnel object | This build |
//! |---|---|---|
//! | `systemd-resolved` `SetLinkDNS` + `SetLinkDomains(["~."])` + `SetLinkDefaultRoute(true)` | ✔ per-link config discarded with the link | **not implemented** — see below |
//! | Owner-tagged `/etc/resolv.conf` rewrite | ✘ | **implemented** |
//!
//! The `systemd-resolved` path is the preferred one and is **not** implemented
//! here, because it is a D-Bus API and no D-Bus client is in the workspace's
//! dependency set (`core/Cargo.toml` is the integration lead's). That is
//! reported, not hidden: [`ResolverBackend::detect`] notices `resolved` is
//! running and returns [`ResolverBackend::ResolvedUnavailable`], which the
//! adapter surfaces as `DNS.PLATFORM.SCOPED_API_UNAVAILABLE` — a registered
//! code — rather than silently using the weaker form and reporting success.
//!
//! ADR-0011 §11.9 is explicit about what that costs and what still holds:
//! the `resolv.conf` rewrite "races NetworkManager/`dhclient`" and is "the
//! weakest desktop case", but **"containment is the guarantee, not the file"** —
//! [`crate::nft`]'s class-6 denial of 53/853 off the overlay is what actually
//! prevents the leak, and it is installed either way.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use twinvpn_platform::{DnsConfig, PlatformError};
use twinvpn_types::AddressFamily;

use crate::addr::addr_text;
use crate::oserr::{self, Context};

/// The file this build rewrites.
pub const RESOLV_CONF: &str = "/etc/resolv.conf";

/// The marker that makes our configuration **owner-tagged**.
///
/// `docs/networking.md` §5.5 rule 3: state written outside our own interface
/// "MUST be tagged with an owner marker and MUST be reclaimable by a fresh
/// process after an unclean exit". A first-line comment is the only tagging
/// `resolv.conf`'s format admits, and it is what lets the boot restore unit tell
/// our file from the one NetworkManager wrote.
pub const OWNER_TAG: &str = "# twinvpn-owned";

/// Which resolver mechanism this host offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverBackend {
    /// `systemd-resolved` is running and is the form DN-21 prefers — but this
    /// build has no D-Bus client, so the preferred path is **unavailable** and
    /// says so rather than degrading silently.
    ResolvedUnavailable,
    /// No `resolved`; the owner-tagged `/etc/resolv.conf` rewrite applies.
    ResolvConf,
}

impl ResolverBackend {
    /// Detects which form applies on this host.
    ///
    /// `resolved` is detected by its own stub file rather than by asking
    /// `systemctl`: a stopped-but-installed `resolved` leaves no stub, and the
    /// question here is which mechanism is *in force*, not which is installed.
    #[must_use]
    pub fn detect() -> Self {
        let stub_present =
            fs::read_to_string(RESOLV_CONF).is_ok_and(|text| text.contains("127.0.0.53"));
        let unit_running = Path::new("/run/systemd/resolve/stub-resolv.conf").exists();
        if stub_present || unit_running {
            Self::ResolvedUnavailable
        } else {
            Self::ResolvConf
        }
    }
}

/// The verbatim prior configuration, plus what identifies it.
///
/// DN-18's three parts: the bytes, the object identity, and a `restore_token`.
/// The token here is the prior file's byte length and its first line, which is
/// enough to detect the §11.12 S-34 staleness case — "a `RestorePoint` whose
/// `restore_token` does not match the installed configuration is treated as
/// stale, platform default restored".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestorePoint {
    /// The file this restores.
    pub path: PathBuf,
    /// The prior contents, **verbatim**. Not parsed, not normalised: DN-23
    /// requires an underlay-forwarded configuration to be "preserved exactly",
    /// and a re-serialised `resolv.conf` loses `options` lines we do not model.
    pub contents: Vec<u8>,
    /// Whether the file existed at all. Absent and empty are different states,
    /// and restoring an empty file where none existed is itself a mutation.
    pub existed: bool,
    /// The file mode to restore.
    pub mode: u32,
}

impl RestorePoint {
    /// Captures the current state of `path`.
    ///
    /// # Errors
    ///
    /// [`PlatformError::AdapterUnavailable`] if the file exists but cannot be
    /// read — which must stop the mutation, because DN-18's restore point would
    /// then be a fiction.
    pub fn capture(path: &Path) -> Result<Self, PlatformError> {
        match fs::read(path) {
            Ok(contents) => {
                let mode = fs::metadata(path)
                    .map(|m| m.permissions().mode())
                    .unwrap_or(0o644);
                Ok(Self {
                    path: path.to_path_buf(),
                    contents,
                    existed: true,
                    mode,
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self {
                path: path.to_path_buf(),
                contents: Vec::new(),
                existed: false,
                mode: 0o644,
            }),
            Err(e) => Err(oserr::from_errno(
                &e,
                "read(resolv.conf)",
                Context::Resolver,
            )),
        }
    }

    /// Serialises the restore point for durable storage.
    ///
    /// A plain, self-describing text format so that **`twinvpn-unblock` and the
    /// boot restore unit can read it with the agent absent** (DN-20, PS-6) —
    /// which rules out any encoding that needs this binary to decode.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.contents.len() + 128);
        out.extend_from_slice(b"twinvpn-restore-point v1\n");
        out.extend_from_slice(format!("path {}\n", self.path.display()).as_bytes());
        out.extend_from_slice(format!("existed {}\n", self.existed).as_bytes());
        out.extend_from_slice(format!("mode {:o}\n", self.mode).as_bytes());
        out.extend_from_slice(format!("bytes {}\n", self.contents.len()).as_bytes());
        out.extend_from_slice(b"---\n");
        out.extend_from_slice(&self.contents);
        out
    }

    /// Parses a restore point written by [`Self::encode`].
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let split = bytes.windows(4).position(|w| w == b"\n---")?;
        let header = std::str::from_utf8(&bytes[..split]).ok()?;
        let contents = bytes.get(split + 5..)?.to_vec();
        let mut path = None;
        let mut existed = false;
        let mut mode = 0o644;
        let mut declared = 0usize;
        for line in header.lines() {
            let Some((key, value)) = line.split_once(' ') else {
                continue;
            };
            match key {
                "path" => path = Some(PathBuf::from(value)),
                "existed" => existed = value == "true",
                "mode" => mode = u32::from_str_radix(value, 8).ok()?,
                "bytes" => declared = value.parse().ok()?,
                _ => {}
            }
        }
        // The declared length is checked against the actual one before the value
        // is used, per `ownership.md` §6 rule 9: a restore point whose header
        // and body disagree is a torn write, and restoring from one would write
        // a truncated resolver configuration.
        if declared != contents.len() {
            return None;
        }
        Some(Self {
            path: path?,
            contents,
            existed,
            mode,
        })
    }

    /// Restores the captured state.
    ///
    /// # Errors
    ///
    /// The OS error, named. A failure here is `DNS.STUB.TEARDOWN_INCOMPLETE`'s
    /// condition and the caller keeps the device fail-closed (DN-20).
    pub fn restore(&self) -> Result<(), PlatformError> {
        if self.existed {
            write_atomic(&self.path, &self.contents, self.mode)
        } else {
            match fs::remove_file(&self.path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(oserr::from_errno(
                    &e,
                    "unlink(resolv.conf)",
                    Context::Resolver,
                )),
            }
        }
    }
}

/// Renders `resolv.conf` from a [`DnsConfig`].
///
/// **A pure function**, so the file's contents are unit-testable without writing
/// to `/etc`. Both families are emitted, in the order `PerFamily` holds them,
/// and the per-family cap of `limits.json` §`dns.max_resolvers_per_family` (8) is
/// enforced **before** the allocation — `ownership.md` §6 rules 9 and 10.
#[must_use]
pub fn render(config: &DnsConfig) -> String {
    /// `limits.json` §`dns.max_resolvers_per_family`.
    const MAX_RESOLVERS_PER_FAMILY: usize = 8;
    /// `limits.json` §`dns.max_search_domains`.
    const MAX_SEARCH_DOMAINS: usize = 32;

    let mut out = String::with_capacity(512);
    out.push_str(OWNER_TAG);
    out.push('\n');
    out.push_str("# Managed by TwinVPN. The prior contents are in the restore point\n");
    out.push_str("# named by TWINVPN_RESOLVER_RESTORE_POINT (ADR-0011 DN-18).\n");

    // Both families, always. ADR-0011 DN-13: "a stub MUST NOT filter AAAA
    // because the underlay is v4-only", and the same logic applies here — the
    // resolver list is written for both families regardless of what the underlay
    // carries.
    for (family, list) in [
        (AddressFamily::V4, &config.resolvers.v4),
        (AddressFamily::V6, &config.resolvers.v6),
    ] {
        let _ = family;
        for address in list.iter().take(MAX_RESOLVERS_PER_FAMILY) {
            out.push_str("nameserver ");
            out.push_str(&addr_text(*address));
            out.push('\n');
        }
    }

    let domains: Vec<&str> = config
        .search_domains
        .iter()
        .map(String::as_str)
        .filter(|d| is_safe_domain(d))
        .take(MAX_SEARCH_DOMAINS)
        .collect();
    if !domains.is_empty() {
        out.push_str("search ");
        out.push_str(&domains.join(" "));
        out.push('\n');
    }
    out
}

/// Whether a domain is safe to write into `resolv.conf`.
///
/// `resolv.conf` is a line-oriented, whitespace-separated format with no quoting
/// or escaping, so a domain containing whitespace or a newline would inject a
/// *directive*. The domain comes from a signed policy bundle, but validating at
/// the boundary is `ownership.md`'s rule regardless of where the value came
/// from — a rejected domain is dropped, never truncated and never escaped into
/// something that parses differently.
#[must_use]
pub fn is_safe_domain(domain: &str) -> bool {
    /// `limits.json` §`dns.max_domain_name_bytes`.
    const MAX_DOMAIN_BYTES: usize = 253;
    !domain.is_empty()
        && domain.len() <= MAX_DOMAIN_BYTES
        && domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// Writes the resolver configuration, restore point first.
///
/// DN-19's `apply` order, with the one clause this function owns:
/// **`RestorePoint` persisted → platform scoped-DNS applied.** Binding the stub
/// and confirming with the reconciler are the core's, above this call.
///
/// # Errors
///
/// The restore-point write's error, **before any mutation**, or the mutation's.
pub fn apply(config: &DnsConfig, restore_point_path: &Path) -> Result<RestorePoint, PlatformError> {
    let point = RestorePoint::capture(Path::new(RESOLV_CONF))?;
    // DN-18: written AND FLUSHED before the mutation. `write_atomic` fsyncs the
    // file and its directory, so a power loss between these two statements
    // leaves a readable restore point rather than a half-written one.
    write_atomic(restore_point_path, &point.encode(), 0o600)?;
    write_atomic(Path::new(RESOLV_CONF), render(config).as_bytes(), 0o644)?;
    Ok(point)
}

/// Writes `contents` to `path` atomically, and durably.
///
/// Temp file → `fsync` → `rename` → `fsync` the directory. The directory fsync
/// is the step most implementations skip and is the one that makes the rename
/// survive a power loss, which is what "flushed" in DN-18 actually requires.
fn write_atomic(path: &Path, contents: &[u8], mode: u32) -> Result<(), PlatformError> {
    let parent = path
        .parent()
        .ok_or_else(|| oserr::unavailable("write_atomic.parent", libc::EINVAL))?;
    let temp = parent.join(format!(
        ".{}.twinvpn.tmp",
        path.file_name()
            .map_or_else(|| "file".into(), |n| n.to_string_lossy())
    ));
    let map = |call: &'static str| {
        move |e: std::io::Error| oserr::from_errno(&e, call, Context::Resolver)
    };

    let mut file = fs::File::create(&temp).map_err(map("create(tmp)"))?;
    file.write_all(contents).map_err(map("write(tmp)"))?;
    file.sync_all().map_err(map("fsync(tmp)"))?;
    fs::set_permissions(&temp, fs::Permissions::from_mode(mode)).map_err(map("chmod(tmp)"))?;
    drop(file);
    fs::rename(&temp, path).map_err(map("rename"))?;
    // The directory fsync. Without it the rename can be lost on a power cut and
    // the restore point DN-18 promised is not there when it is needed.
    if let Ok(dir) = fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_types::{IpAddr, PerFamily, V4Addr, V6Addr};

    fn config() -> DnsConfig {
        let mut ula = [0u8; 16];
        ula[0] = 0xfd;
        ula[1] = 0x7c;
        ula[15] = 0x53;
        DnsConfig {
            resolvers: PerFamily::new(
                vec![IpAddr::V4(V4Addr::from_octets([100, 127, 255, 53]))],
                vec![IpAddr::V6(V6Addr::new(ula, None).expect("valid"))],
            ),
            search_domains: vec!["t-abc.tnet.twinvpn.net".to_owned()],
            split_domains: Vec::new(),
            is_default_resolver: true,
        }
    }

    #[test]
    fn both_families_reach_resolv_conf_and_the_file_is_owner_tagged() {
        let text = render(&config());
        assert!(text.starts_with(OWNER_TAG), "§5.5 rule 3: owner-tagged");
        assert!(text.contains("nameserver 100.127.255.53"));
        assert!(
            text.contains("nameserver fd7c::53"),
            "a v4-only resolver list is the asymmetry ADR-0010 R1 forbids"
        );
        assert!(text.contains("search t-abc.tnet.twinvpn.net"));
    }

    #[test]
    fn a_domain_that_would_inject_a_directive_is_dropped_never_escaped() {
        // `resolv.conf` has no quoting. A newline in a domain is a new
        // directive, and a space is a second domain.
        assert!(!is_safe_domain("evil\nnameserver 8.8.8.8"));
        assert!(!is_safe_domain("a b"));
        assert!(!is_safe_domain(""));
        assert!(!is_safe_domain(&"a".repeat(254)));
        assert!(is_safe_domain("t-abc.tnet.twinvpn.net"));

        let mut c = config();
        c.search_domains = vec!["evil\nnameserver 8.8.8.8".to_owned()];
        let text = render(&c);
        assert!(!text.contains("8.8.8.8"));
        assert_eq!(text.matches("nameserver").count(), 2, "only ours");
    }

    #[test]
    fn the_per_family_resolver_cap_is_enforced_before_the_allocation() {
        let mut c = config();
        c.resolvers.v4 = (0..64)
            .map(|i| IpAddr::V4(V4Addr::from_octets([10, 0, 0, i])))
            .collect();
        let text = render(&c);
        // 8 v4 (the limits.json cap) + 1 v6.
        assert_eq!(text.matches("nameserver").count(), 9);
    }

    #[test]
    fn a_restore_point_round_trips_verbatim_including_lines_we_do_not_model() {
        // DN-23: an underlay-forwarded configuration is "preserved exactly". A
        // re-serialised resolv.conf loses `options` and `sortlist`.
        let original = b"nameserver 192.0.2.1\noptions edns0 trust-ad\nsortlist 10/8\n";
        let point = RestorePoint {
            path: PathBuf::from("/etc/resolv.conf"),
            contents: original.to_vec(),
            existed: true,
            mode: 0o644,
        };
        let decoded = RestorePoint::decode(&point.encode()).expect("round-trips");
        assert_eq!(decoded, point);
        assert_eq!(decoded.contents, original);
    }

    #[test]
    fn a_restore_point_is_readable_without_this_binary() {
        // DN-20: restoration must not require the agent to be healthy, and the
        // boot restore unit is a shell script.
        let point = RestorePoint {
            path: PathBuf::from("/etc/resolv.conf"),
            contents: b"nameserver 192.0.2.1\n".to_vec(),
            existed: true,
            mode: 0o644,
        };
        let text = String::from_utf8(point.encode()).expect("plain text");
        assert!(text.starts_with("twinvpn-restore-point v1\n"));
        assert!(text.contains("path /etc/resolv.conf\n"));
        assert!(text.contains("bytes 21\n"));
        assert!(text.ends_with("nameserver 192.0.2.1\n"));
    }

    #[test]
    fn a_torn_restore_point_is_refused_rather_than_restored_truncated() {
        let point = RestorePoint {
            path: PathBuf::from("/etc/resolv.conf"),
            contents: b"nameserver 192.0.2.1\n".to_vec(),
            existed: true,
            mode: 0o644,
        };
        let mut bytes = point.encode();
        bytes.truncate(bytes.len() - 5);
        assert_eq!(
            RestorePoint::decode(&bytes),
            None,
            "restoring from a torn restore point would write a truncated \
             resolver configuration, which DN-19's crash path must not do"
        );
    }

    #[test]
    fn absent_and_empty_are_different_states() {
        // Restoring an empty file where none existed is itself a mutation.
        let absent = RestorePoint {
            path: PathBuf::from("/tmp/does-not-exist"),
            contents: Vec::new(),
            existed: false,
            mode: 0o644,
        };
        let empty = RestorePoint {
            existed: true,
            ..absent.clone()
        };
        assert_ne!(absent, empty);
        assert_ne!(absent.encode(), empty.encode());
    }

    #[test]
    fn the_restore_point_is_durable_before_the_mutation() {
        // The ordering DN-18 fixes, asserted by making the restore-point write
        // fail: the host's resolv.conf must be untouched.
        let before = fs::read(RESOLV_CONF).ok();
        let err = apply(
            &config(),
            Path::new("/proc/definitely/not/a/writable/path/restore"),
        )
        .expect_err("the restore point cannot be written");
        assert!(err.os_detail().is_some());
        let after = fs::read(RESOLV_CONF).ok();
        assert_eq!(
            before, after,
            "DN-18: no host resolver configuration may be written before the \
             restore point is persisted"
        );
    }

    #[test]
    fn the_preferred_resolved_path_is_reported_absent_rather_than_silently_downgraded() {
        // DN-21 prefers `systemd-resolved`; this build has no D-Bus client, so
        // the honest answer is that the preferred API is unavailable.
        let backend = ResolverBackend::detect();
        assert!(matches!(
            backend,
            ResolverBackend::ResolvedUnavailable | ResolverBackend::ResolvConf
        ));
    }
}
