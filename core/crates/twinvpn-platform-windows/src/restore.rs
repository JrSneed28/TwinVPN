//! The DN-18 resolver restore point, on disk.
//!
//! **Authority:** ADR-0011 DN-18 (written and flushed **before** the mutation),
//! DN-19 (the ordering), DN-20 ("restoration MUST NOT require the agent to be
//! healthy"), §11.7 (Windows is "the highest-risk platform for D7");
//! ADR-0016 PS-6 ("restore before mutate") and PS-21 step 3; ADR-0020 ST-4 (a
//! fact readable when the vault cannot be opened lives outside the vault, as a
//! named sidecar, and is not `SECRET`-classified).
//!
//! # Why this is a file and not a field
//!
//! DN-20 is the whole reason:
//!
//! > restoration MUST NOT require agent to be healthy — the restore entry point
//! > is the same OS-applied artifact family as KS-19's boot ruleset (**a Windows
//! > service**), and runs **after** enforcement is live.
//!
//! The process that repairs a host whose agent will not start is a **different
//! process**, package-owned, and it must be able to read this without linking the
//! core. So the format is a small line-oriented text one that a hundred lines of
//! anything can parse, and both halves of it live here as pure functions with
//! tests that run on this host.
//!
//! # Why the addresses are hex and not presentation form
//!
//! An IPv6 presentation parser is a second implementation of a subtle format,
//! and this file is read by a service rather than by a person. Sixteen hex bytes
//! round-trip exactly, cannot be ambiguous about zero-compression, and carry the
//! zone index explicitly instead of behind a `%`. The cost is that the file is
//! not pleasant to read by eye; the benefit is that "the restore point did not
//! parse" cannot be caused by an address spelling.
//!
//! # Not `SECRET`
//!
//! A restore point holds the resolver addresses the host used before TwinVPN
//! configured it. ADR-0015 §11.4 classes an address `SENSITIVE`, not `SECRET`,
//! and ST-4 requires a fact readable with the vault closed to be exactly that.
//! It is written with the store's own ACL (SYSTEM + Administrators) and is never
//! included verbatim in a Tier-1 bundle.

use core::fmt::Write as _;
use std::io::Write as _;
use std::path::Path;

use twinvpn_platform::PlatformError;
use twinvpn_types::{AddressFamily, IpAddr, PerFamily, V4Addr, V6Addr, ZoneIndex};

use crate::dns::{InterfaceDns, NrptRule, RestorePoint};
use crate::route::InterfaceLuid;

/// The format's first line. A version, because DN-20's reader is a separate
/// binary with its own release cadence and it must refuse a file it does not
/// understand rather than half-parse one.
pub const MAGIC: &str = "twinvpn-resolver-restore 1";

/// Renders a restore point.
#[must_use]
pub fn encode(point: &RestorePoint) -> String {
    let mut out = String::new();
    out.push_str(MAGIC);
    out.push('\n');
    let _ = writeln!(out, "token {}", point.restore_token);
    let _ = writeln!(out, "iface-luid {}", point.prior_interface.luid.0);
    for family in [AddressFamily::V4, AddressFamily::V6] {
        let tag = match family {
            AddressFamily::V4 => "iface-v4",
            AddressFamily::V6 => "iface-v6",
        };
        out.push_str(tag);
        for address in point.prior_interface.resolvers.get(family) {
            out.push(' ');
            out.push_str(&encode_address(*address));
        }
        out.push('\n');
    }
    out.push_str("iface-search");
    for domain in &point.prior_interface.search_list {
        out.push(' ');
        out.push_str(domain);
    }
    out.push('\n');
    let _ = writeln!(
        out,
        "iface-register {}",
        u8::from(point.prior_interface.register_adapter_name)
    );
    for rule in &point.prior_rules {
        let _ = write!(
            out,
            "rule {} {} {}",
            rule.id,
            rule.namespace,
            u8::from(rule.dnssec_validation)
        );
        for address in &rule.resolvers {
            out.push(' ');
            out.push_str(&encode_address(*address));
        }
        out.push('\n');
    }
    out
}

/// Parses a restore point.
///
/// Returns `None` for anything that is not exactly this format at this version.
/// **Never a partial parse**: a restore point that half-decoded would put back
/// half a resolver configuration, which is a worse state than the one D7
/// describes.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn decode(text: &str) -> Option<RestorePoint> {
    let mut lines = text.lines();
    if lines.next()? != MAGIC {
        return None;
    }
    let mut token = None;
    let mut luid = None;
    let mut resolvers = PerFamily::new(Vec::new(), Vec::new());
    let mut search = Vec::new();
    let mut register = None;
    let mut rules = Vec::new();

    for line in lines {
        let mut fields = line.split(' ');
        match fields.next()? {
            "token" => token = Some(fields.next()?.parse::<u64>().ok()?),
            "iface-luid" => luid = Some(InterfaceLuid(fields.next()?.parse::<u64>().ok()?)),
            tag @ ("iface-v4" | "iface-v6") => {
                let family = if tag == "iface-v4" {
                    AddressFamily::V4
                } else {
                    AddressFamily::V6
                };
                let list = resolvers.get_mut(family);
                for field in fields {
                    let address = decode_address(field)?;
                    // A v6 address on the v4 line is a corrupted file, not a
                    // value to accept: the whole point of the per-family shape
                    // is that "we programmed one family" is visible.
                    if address.family() != family {
                        return None;
                    }
                    list.push(address);
                }
            }
            "iface-search" => search = fields.map(str::to_owned).collect(),
            "iface-register" => register = Some(fields.next()? == "1"),
            "rule" => {
                let id = fields.next()?.to_owned();
                let namespace = fields.next()?.to_owned();
                let dnssec = fields.next()? == "1";
                let mut rule_resolvers = Vec::new();
                for field in fields {
                    rule_resolvers.push(decode_address(field)?);
                }
                rules.push(NrptRule {
                    id,
                    namespace,
                    resolvers: rule_resolvers,
                    dnssec_validation: dnssec,
                });
            }
            // An unknown key is a file a newer writer produced. Refusing is the
            // safe direction: a restore that silently dropped a field it did not
            // recognise would restore something that was never the prior state.
            _ => return None,
        }
    }

    Some(RestorePoint {
        prior_rules: rules,
        prior_interface: InterfaceDns {
            luid: luid?,
            resolvers,
            search_list: search,
            register_adapter_name: register?,
        },
        restore_token: token?,
    })
}

/// Writes a restore point **atomically**, then flushes.
///
/// DN-18's "written and flushed before the mutation" is not satisfied by a
/// `write` that is still in the page cache when the host loses power. The
/// sequence is write-temp → `sync_all` → rename, and the rename is what makes a
/// reader see either the whole old file or the whole new one.
///
/// # Errors
///
/// [`PlatformError::SecureStoreUnavailable`] — the condition is "a durable local
/// fact could not be written", which is the store's, not the resolver's, and
/// mapping it to a DNS code would send a support case to the wrong subsystem.
pub fn write(path: &Path, point: &RestorePoint) -> Result<(), PlatformError> {
    let body = encode(point);
    let temp = path.with_extension("tmp");
    let map = |call: &'static str| {
        move |err: std::io::Error| {
            PlatformError::SecureStoreUnavailable(Some(twinvpn_platform::OsDetail {
                code: i64::from(err.raw_os_error().unwrap_or(0)),
                call,
            }))
        }
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(map("create_dir_all"))?;
    }
    {
        let mut file = std::fs::File::create(&temp).map_err(map("CreateFileW"))?;
        file.write_all(body.as_bytes()).map_err(map("WriteFile"))?;
        // `FlushFileBuffers` on Windows — ADR-0020's explicit durability barrier.
        file.sync_all().map_err(map("FlushFileBuffers"))?;
    }
    std::fs::rename(&temp, path).map_err(map("MoveFileExW"))
}

/// Reads a restore point back.
///
/// # Errors
///
/// [`PlatformError::SecureStoreUnavailable`] if the file cannot be read or does
/// not parse. A malformed restore point is **not** treated as an absent one:
/// absent means "we never configured the resolver", and acting on that belief
/// when a file exists is how D7's dead pointer survives.
pub fn read(path: &Path) -> Result<Option<RestorePoint>, PlatformError> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(PlatformError::SecureStoreUnavailable(Some(
                twinvpn_platform::OsDetail {
                    code: i64::from(err.raw_os_error().unwrap_or(0)),
                    call: "ReadFile",
                },
            )))
        }
    };
    decode(&text)
        .map(Some)
        .ok_or(PlatformError::SecureStoreUnavailable(Some(
            twinvpn_platform::OsDetail {
                code: 0,
                call: "restore point did not parse",
            },
        )))
}

/// `v4:AABBCCDD` or `v6:<32 hex>%<zone>`.
fn encode_address(address: IpAddr) -> String {
    match address {
        IpAddr::V4(a) => {
            let mut out = String::from("v4:");
            push_hex(&mut out, &a.octets());
            out
        }
        IpAddr::V6(a) => {
            let mut out = String::from("v6:");
            push_hex(&mut out, &a.octets());
            // The zone travels explicitly. `V6Addr` requires one on `fe80::/10`
            // and forbids one elsewhere, so dropping it would make a link-local
            // resolver unrestorable.
            out.push('%');
            let _ = write!(out, "{}", a.zone().map_or(0, ZoneIndex::get));
            out
        }
    }
}

fn decode_address(field: &str) -> Option<IpAddr> {
    if let Some(hex) = field.strip_prefix("v4:") {
        let octets: [u8; 4] = decode_hex(hex)?.try_into().ok()?;
        return Some(IpAddr::V4(V4Addr::from_octets(octets)));
    }
    let rest = field.strip_prefix("v6:")?;
    let (hex, zone) = rest.split_once('%')?;
    let octets: [u8; 16] = decode_hex(hex)?.try_into().ok()?;
    let zone: u32 = zone.parse().ok()?;
    V6Addr::from_slice(&octets, zone).ok().map(IpAddr::V6)
}

/// Appends `bytes` as lower-case hex.
fn push_hex(out: &mut String, bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
}

fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    // `limits.json` bounds the resolver lists that reach this file, and the
    // length is checked by the `try_into` at the call site before anything is
    // used; the cap here bounds the allocation itself, which is §6 rule 10.
    if hex.len() > 32 {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    for pair in bytes.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(u8::try_from(hi * 16 + lo).ok()?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(octets: [u8; 4]) -> IpAddr {
        IpAddr::V4(V4Addr::from_octets(octets))
    }

    fn v6(tail: u8) -> IpAddr {
        let mut octets = [0u8; 16];
        octets[0] = 0x20;
        octets[1] = 0x01;
        octets[15] = tail;
        IpAddr::V6(V6Addr::new(octets, None).expect("address"))
    }

    fn link_local() -> IpAddr {
        let mut octets = [0u8; 16];
        octets[0] = 0xfe;
        octets[1] = 0x80;
        octets[15] = 1;
        IpAddr::V6(V6Addr::new(octets, ZoneIndex::new(7)).expect("link-local"))
    }

    fn point() -> RestorePoint {
        RestorePoint {
            prior_rules: vec![NrptRule {
                id: "TwinVPN-.corp.example".to_owned(),
                namespace: ".corp.example".to_owned(),
                resolvers: vec![v4([10, 0, 0, 1]), v6(0x53)],
                dnssec_validation: true,
            }],
            prior_interface: InterfaceDns {
                luid: InterfaceLuid(0x0001_0000_0000_0006),
                resolvers: PerFamily::new(vec![v4([192, 168, 1, 1])], vec![link_local()]),
                search_list: vec!["lan".to_owned(), "corp.example".to_owned()],
                register_adapter_name: true,
            },
            restore_token: 42,
        }
    }

    #[test]
    fn a_restore_point_round_trips_exactly() {
        let original = point();
        let decoded = decode(&encode(&original)).expect("decodes");
        assert_eq!(decoded, original);
    }

    #[test]
    fn a_link_local_resolver_keeps_its_zone() {
        // `V6Addr` requires a zone on `fe80::/10`; dropping it would make the
        // address unrestorable, and inventing one would restore a resolver on
        // the wrong segment.
        let decoded = decode(&encode(&point())).expect("decodes");
        let v6 = decoded.prior_interface.resolvers.get(AddressFamily::V6);
        match v6.first().expect("one") {
            IpAddr::V6(a) => assert_eq!(a.zone().map(ZoneIndex::get), Some(7)),
            IpAddr::V4(_) => panic!("a v6 resolver decoded as v4"),
        }
    }

    #[test]
    fn an_empty_configuration_round_trips_too() {
        // The common first-run case: no rules, no resolvers, no search list. A
        // format that could not express "there was nothing here" would make the
        // first apply unrollbackable.
        let empty = RestorePoint {
            prior_rules: Vec::new(),
            prior_interface: InterfaceDns {
                luid: InterfaceLuid(6),
                resolvers: PerFamily::new(Vec::new(), Vec::new()),
                search_list: Vec::new(),
                register_adapter_name: false,
            },
            restore_token: 0,
        };
        assert_eq!(decode(&encode(&empty)).expect("decodes"), empty);
    }

    #[test]
    fn a_file_from_a_newer_writer_is_refused_rather_than_half_read() {
        // "twinvpn-resolver-restore 2", or a key this version does not know.
        assert_eq!(decode("twinvpn-resolver-restore 2\ntoken 1\n"), None);
        let mut text = encode(&point());
        text.push_str("something-new 1\n");
        assert_eq!(decode(&text), None);
    }

    #[test]
    fn a_truncated_file_is_refused_rather_than_half_read() {
        // A restore point that half-decoded would put back half a resolver
        // configuration, which is worse than the state D7 describes.
        let full = encode(&point());
        for cut in [1, 10, 30, full.len() / 2] {
            let truncated = &full[..cut.min(full.len())];
            // Either it fails the magic line or it is missing a required key.
            assert!(
                decode(truncated).is_none(),
                "accepted a prefix of {cut} bytes"
            );
        }
    }

    #[test]
    fn a_family_mismatch_on_a_line_is_a_corrupt_file_and_not_a_value() {
        let text = format!(
            "{MAGIC}\ntoken 1\niface-luid 6\niface-v4 v6:{}%0\niface-v6\niface-search\niface-register 0\n",
            "00".repeat(16)
        );
        assert_eq!(decode(&text), None);
    }

    #[test]
    fn a_malformed_address_is_refused() {
        for bad in ["v4:zz", "v4:0102", "v6:0102", "v6:abc%0", "v9:01020304", ""] {
            assert_eq!(decode_address(bad), None, "{bad}");
        }
        assert_eq!(decode_address("v4:0a000001"), Some(v4([10, 0, 0, 1])));
    }

    #[test]
    fn an_over_long_hex_field_is_bounded_before_it_is_allocated() {
        // §6 rule 10: every allocation an untrusted input can drive is bounded.
        assert_eq!(decode_hex(&"ab".repeat(64)), None);
        assert_eq!(decode_hex("abcd"), Some(vec![0xab, 0xcd]));
    }

    #[test]
    fn the_file_is_written_atomically_and_reads_back() {
        let dir = std::env::temp_dir().join("twinvpn-restore-test");
        let path = dir.join("resolver.restore");
        let _ = std::fs::remove_file(&path);
        write(&path, &point()).expect("writes");
        assert_eq!(read(&path).expect("reads"), Some(point()));
        // The temporary is gone: a reader must never find two files and have to
        // decide which is current.
        assert!(!path.with_extension("tmp").exists());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_absent_file_and_a_corrupt_one_are_different_answers() {
        // Absent means "we never configured the resolver". Acting on that belief
        // when a file exists is how D7's dead pointer survives.
        let dir = std::env::temp_dir().join("twinvpn-restore-test");
        std::fs::create_dir_all(&dir).expect("dir");
        let missing = dir.join("absent.restore");
        let _ = std::fs::remove_file(&missing);
        assert_eq!(read(&missing).expect("absent is not an error"), None);

        let corrupt = dir.join("corrupt.restore");
        std::fs::write(&corrupt, b"not a restore point").expect("writes");
        let err = read(&corrupt).expect_err("corrupt is an error");
        assert_eq!(err.reason_code().as_str(), "AUTH.KEY_STORE_UNAVAILABLE");
        let _ = std::fs::remove_file(&corrupt);
    }

    #[test]
    fn the_written_form_is_readable_by_a_reader_that_knows_only_the_format() {
        // DN-20's reader is a separate binary. Asserting the shape here is what
        // keeps this file parseable by a hundred lines of anything.
        let text = encode(&point());
        assert!(text.starts_with(MAGIC));
        assert!(text.contains("\ntoken 42\n"));
        assert!(text.lines().all(|l| !l.contains('\t')));
        assert!(text.ends_with('\n'));
    }
}
