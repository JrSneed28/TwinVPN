//! ADR-0011 §11.4's classification: exact name > `TwinNet` zones >
//! protocol-reserved > longest suffix > default.
//!
//! **Authority:** ADR-0011 §11.4 (normative), DN-6, DN-9, §11.5's mode table.
//!
//! # DN-9: matching is on whole labels, in wire form
//!
//! > `example.com` matches `a.example.com` and `example.com`, never
//! > `notexample.com`. Comparison is case-insensitive per RFC 4343 and performed
//! > on the **wire-format labels**, not on a presentation string — which is why
//! > an implementation must convert before comparing rather than doing a suffix
//! > test on this field's text.
//!
//! [`wire_labels`] is that conversion, and every comparison here goes through
//! it. A `str::ends_with` on the presentation form is the bug this rule names.

use crate::policy::{Disposition, Dnspolicy, Mode};

/// Splits a presentation name into lowercase wire labels, dropping the root.
///
/// RFC 4343 case-insensitivity is applied here, once, so no comparison later has
/// to remember to.
#[must_use]
pub fn wire_labels(name: &str) -> Vec<Vec<u8>> {
    name.trim_end_matches('.')
        .split('.')
        .filter(|l| !l.is_empty())
        .map(|l| l.to_ascii_lowercase().into_bytes())
        .collect()
}

/// Whether `name` is `suffix` or is under it, by whole labels.
#[must_use]
pub fn is_suffix_of(suffix: &[Vec<u8>], name: &[Vec<u8>]) -> bool {
    if suffix.is_empty() || suffix.len() > name.len() {
        return false;
    }
    name[name.len() - suffix.len()..] == *suffix
}

/// The classes of §11.4, in precedence order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Class {
    /// 1 — an exact-name rule matched.
    ExactRule,
    /// 2 — the query is in a `TwinNet` forward or reverse zone.
    TwinnetZone,
    /// 3 — protocol-reserved or locally-served. **Never forwarded.**
    ProtocolReserved,
    /// 4 — the longest matching `split_domains[]` suffix.
    SuffixRule,
    /// 5 — everything else, per `DNSPolicy.mode`.
    Default,
}

/// What to do with a classified query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Classification {
    /// Which class matched.
    pub class: Class,
    /// The disposition that follows.
    pub disposition: Disposition,
    /// Which scope answers it.
    pub scope: crate::scope::Scope,
}

/// RFC 6761/6762/8375/6303 names that are **never forwarded** (§11.4 class 3).
///
/// `local.` is additionally excluded from the scoped-DNS match set on every
/// platform "so the host's own mDNS handles it; if one still reaches the stub it
/// is REFUSED + EDE 20".
pub const LOCALLY_SERVED: &[&str] = &[
    "local",
    "localhost",
    "invalid",
    "test",
    "example",
    "onion",
    "home.arpa",
    "internal",
];

/// The `TwinNet` reverse zones: the sixty-four `/16`s covering `100.64.0.0/10`,
/// plus the product ULA's `ip6.arpa` zone (§11.3).
#[must_use]
pub fn is_twinnet_reverse(labels: &[Vec<u8>]) -> bool {
    // The product ULA /48 reversed: 0.1.a.2.d.5.e.9.c.7.d.f.ip6.arpa
    const ULA_NIBBLES: [&[u8]; 12] = [
        b"0", b"1", b"a", b"2", b"d", b"5", b"e", b"9", b"c", b"7", b"d", b"f",
    ];
    // <n>.100.in-addr.arpa with 64 <= n <= 127.
    if labels.len() >= 4 {
        let tail = &labels[labels.len() - 3..];
        if tail[0] == b"100" && tail[1] == b"in-addr" && tail[2] == b"arpa" {
            let n = &labels[labels.len() - 4];
            if let Ok(s) = core::str::from_utf8(n) {
                if let Ok(v) = s.parse::<u16>() {
                    return (64..=127).contains(&v);
                }
            }
        }
    }
    if labels.len() >= 14 {
        let tail = &labels[labels.len() - 14..];
        if tail[12] == b"ip6" && tail[13] == b"arpa" {
            return tail[..12]
                .iter()
                .zip(ULA_NIBBLES.iter())
                .all(|(a, b)| a.as_slice() == *b);
        }
    }
    false
}

/// Classifies one query name.
///
/// `twinnet_forward_zone` is `<twinnet-label>.tnet.twinvpn.net` in wire-label
/// form, derived from the signed contract.
#[must_use]
pub fn classify(
    qname: &str,
    policy: &Dnspolicy,
    twinnet_forward_zone: &[Vec<u8>],
    full_tunnel_or_exit_engaged: bool,
) -> Classification {
    let labels = wire_labels(qname);

    // 1 — exact-name rules first, above every suffix rule of any length.
    for r in policy.split_rules.iter().filter(|r| r.exact) {
        if r.labels == labels {
            return Classification {
                class: Class::ExactRule,
                disposition: r.disposition,
                scope: scope_for(r.disposition, full_tunnel_or_exit_engaged),
            };
        }
    }

    // 2 — TwinNet zones. DN-6: never forwarded, in any scope, mode or failure
    // path.
    if is_suffix_of(twinnet_forward_zone, &labels) || is_twinnet_reverse(&labels) {
        return Classification {
            class: Class::TwinnetZone,
            disposition: Disposition::Twinnet,
            scope: crate::scope::Scope::Twinnet,
        };
    }

    // 3 — protocol-reserved and locally-served. Never forwarded.
    for reserved in LOCALLY_SERVED {
        if is_suffix_of(&wire_labels(reserved), &labels) {
            return Classification {
                class: Class::ProtocolReserved,
                disposition: Disposition::Refuse,
                scope: crate::scope::Scope::Twinnet,
            };
        }
    }

    // 4 — longest matching suffix.
    let mut best: Option<&crate::policy::SplitRule> = None;
    for r in policy.split_rules.iter().filter(|r| !r.exact) {
        if is_suffix_of(&r.labels, &labels) && best.is_none_or(|b| r.labels.len() > b.labels.len())
        {
            best = Some(r);
        }
    }
    if let Some(r) = best {
        return Classification {
            class: Class::SuffixRule,
            disposition: r.disposition,
            scope: scope_for(r.disposition, full_tunnel_or_exit_engaged),
        };
    }

    // 5 — default, per mode.
    let disposition = match policy.mode {
        // §11.5 SPLIT: forwarded to the host's pre-existing upstream, over the
        // underlay — but DN-10 clause 3: "when the routing mode is full-tunnel,
        // or an ExitNode is engaged, *every* default-class query is
        // PROTECTED_UPSTREAM by construction".
        Mode::Split if !full_tunnel_or_exit_engaged => Disposition::ProtectedUpstream,
        Mode::Split | Mode::Full => Disposition::ProtectedUpstream,
        // OFF serves nothing; the stub writes no resolver configuration at all,
        // so a query reaching it in this mode is refused rather than guessed at.
        Mode::Off => Disposition::Refuse,
    };
    let scope = match (policy.mode, full_tunnel_or_exit_engaged) {
        // SPLIT out-of-scope names go to the host's upstream on a RESOLVER
        // socket — ADR-0012 class 6b, "deliberate policy-directed forwarding,
        // not a fallback".
        (Mode::Split, false) => crate::scope::Scope::Bootstrap,
        _ => crate::scope::Scope::Protected,
    };
    Classification {
        class: Class::Default,
        disposition,
        scope,
    }
}

const fn scope_for(d: Disposition, _full_tunnel: bool) -> crate::scope::Scope {
    match d {
        Disposition::Twinnet | Disposition::Refuse => crate::scope::Scope::Twinnet,
        Disposition::ProtectedUpstream => crate::scope::Scope::Protected,
    }
}
