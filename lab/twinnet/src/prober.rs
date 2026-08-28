//! The independent behaviour prober §3.4.2 requires before rule **L-1** lets any
//! traversal test run.
//!
//! **Authority:** `docs/testing-strategy.md` §3.4.2:
//!
//! > **Rule L-1.** No traversal, leak, or relay test may run against a
//! > personality or impairment that has not passed its conformance suite in the
//! > same lab instantiation, on the same day.
//!
//! > | NAT personality | An independent RFC 5780-style behaviour prober **(not
//! > TwinVPN code)** reports exactly the configured mapping and filtering
//! > behaviour, the configured mapping lifetime within ±10 %, and the configured
//! > hairpin result — for both families |
//!
//! # What "independent" means here, precisely
//!
//! This module imports nothing from `core/` or `services/`. It does not know
//! what a `Candidate`, a `Path` or a `reason_code` is. It measures a middlebox
//! by talking to a reflector, exactly as an off-the-shelf STUN client would, and
//! its answer is a description of the middlebox rather than a claim about
//! TwinVPN. If it disagreed with [`crate::nat::config::NatConfig`], the
//! middlebox would be the thing at fault — which is the entire point of running
//! it, and the reason the conformance suite is not "assert the config equals
//! itself".
//!
//! # The one measurement that is honestly expensive
//!
//! Mapping lifetime is measured by opening a mapping, waiting, and asking the
//! reflector to send to it unsolicited. §3.3's shortest configured lifetime is
//! 30 s, so a ±10 % measurement costs tens of seconds of wall clock. It is
//! therefore **opt-in**: [`Probe::lifetime_ms`] is `None` unless a caller asks,
//! and `None` is reported as "not measured", never as "within tolerance".

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{NetError, Result};
use crate::traffic::verbs;

/// What the prober concluded about a middlebox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    /// The observed mapping behaviour, in RFC 4787 vocabulary.
    pub mapping: Behaviour,
    /// The observed filtering behaviour.
    pub filtering: Behaviour,
    /// The measured mapping lifetime, when it was measured at all.
    pub lifetime_ms: Option<u64>,
    /// Whether hairpinning was observed, when it was tested at all.
    pub hairpin: Option<bool>,
    /// The external address the middlebox presented, if any traffic got out.
    pub mapped: Option<String>,
    /// Every observation, in order, so a disagreement can be read rather than
    /// re-run.
    pub evidence: Vec<String>,
}

/// RFC 4787's vocabulary, plus the two answers a prober can honestly give that
/// are not behaviours at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Behaviour {
    /// No translation was observed: the mapped address equalled the local one.
    None,
    /// Endpoint-independent.
    EndpointIndependent,
    /// Address-dependent.
    AddressDependent,
    /// Address-and-port-dependent.
    AddressPortDependent,
    /// Nothing came back at all, so no behaviour could be established.
    ///
    /// **Not a behaviour.** A conformance run treats this as a failure to
    /// measure, never as "symmetric" — which is the mistake that would let a
    /// blackholed path masquerade as the hardest NAT class and quietly satisfy
    /// every `RELAY_EXPECTED` scenario.
    Unreachable,
}

/// How to reach the reflector.
#[derive(Debug, Clone)]
pub struct Probe {
    /// The reflector's primary address.
    pub primary: IpAddr,
    /// Its alternate address.
    pub alternate: IpAddr,
    /// Its primary port.
    pub port_a: u16,
    /// Its alternate port.
    pub port_b: u16,
    /// How long to wait for each answer.
    pub wait: Duration,
    /// When set, measure the mapping lifetime by idling for this long and then
    /// testing whether the mapping survived.
    pub lifetime_ms: Option<u64>,
    /// When set, probe hairpinning by addressing this endpoint — the *public*
    /// endpoint of another host behind the same middlebox.
    pub hairpin_target: Option<SocketAddr>,
}

impl Probe {
    /// Runs the behaviour tests.
    ///
    /// # Errors
    ///
    /// [`NetError::Os`] if a socket cannot be bound. A reflector that does not
    /// answer is **not** an error: it is [`Behaviour::Unreachable`], because a
    /// blocked path is a thing a scenario deliberately produces.
    pub fn run(&self) -> Result<Report> {
        let mut evidence = Vec::new();
        let sock = self.socket()?;
        let local = SocketAddr::new(
            self.source_address()?,
            sock.local_addr()
                .map_err(|e| NetError::os("reading the prober's local address", e))?
                .port(),
        );

        let m1 = self.ask(
            &sock,
            self.primary,
            self.port_a,
            verbs::PROBE,
            &mut evidence,
        );
        let Some(m1) = m1 else {
            evidence.push("no answer from the reflector's primary endpoint".to_owned());
            return Ok(Report {
                mapping: Behaviour::Unreachable,
                filtering: Behaviour::Unreachable,
                lifetime_ms: None,
                hairpin: None,
                mapped: None,
                evidence,
            });
        };
        evidence.push(format!(
            "local {local} mapped to {m1} via the primary endpoint"
        ));

        let mapping = self.mapping_behaviour(&sock, local, m1, &mut evidence);
        let filtering = self.filtering_behaviour(&mut evidence);
        let lifetime_ms = self.measure_lifetime(m1, &mut evidence);
        let hairpin = self.measure_hairpin(&mut evidence);

        Ok(Report {
            mapping,
            filtering,
            lifetime_ms,
            hairpin,
            mapped: Some(m1.to_string()),
            evidence,
        })
    }

    /// The address the kernel will actually source packets to the reflector
    /// from.
    ///
    /// A prober that compared the mapped address against its socket's own
    /// `local_addr` would compare it against `0.0.0.0`, conclude that the two
    /// differ, and report a translation on a router that performs none. That is
    /// not a cosmetic error: `N-ROUTED` is the personality every `DIRECT_EXPECTED`
    /// v6 cell in §3.2's matrix is evaluated as, so a prober that cannot
    /// recognise "no NAT" cannot certify the case the matrix leans on hardest.
    ///
    /// `connect` on a UDP socket performs a route lookup and binds the chosen
    /// source without sending anything.
    fn source_address(&self) -> Result<IpAddr> {
        let probe = self.socket()?;
        probe
            .connect(SocketAddr::new(self.primary, self.port_a))
            .map_err(|e| NetError::os("resolving the prober's source address", e))?;
        Ok(probe
            .local_addr()
            .map_err(|e| NetError::os("reading the prober's source address", e))?
            .ip())
    }

    fn socket(&self) -> Result<UdpSocket> {
        let bind: SocketAddr = if self.primary.is_ipv4() {
            "0.0.0.0:0".parse().expect("a literal")
        } else {
            "[::]:0".parse().expect("a literal")
        };
        let sock =
            UdpSocket::bind(bind).map_err(|e| NetError::os("binding the prober socket", e))?;
        sock.set_read_timeout(Some(self.wait))
            .map_err(|e| NetError::os("setting the prober read timeout", e))?;
        Ok(sock)
    }

    /// Sends one verb and parses the `MAPPED` answer.
    fn ask(
        &self,
        sock: &UdpSocket,
        addr: IpAddr,
        port: u16,
        verb: &str,
        evidence: &mut Vec<String>,
    ) -> Option<SocketAddr> {
        let dest = SocketAddr::new(addr, port);
        let mut buf = [0u8; 512];
        // A plain PROBE is retransmitted; the two filtering verbs are not.
        // For those, the absence of an answer IS the measurement, and
        // retransmitting would only make an address-and-port-dependent filter
        // take twice as long to report the same thing.
        let attempts = if verb == verbs::PROBE { 3 } else { 1 };
        let mut received = None;
        for attempt in 0..attempts {
            if attempt > 0 {
                std::thread::sleep(std::time::Duration::from_millis(80));
            }
            if sock.send_to(verb.as_bytes(), dest).is_err() {
                evidence.push(format!("{verb} to {dest} could not be sent"));
                return None;
            }
            if let Ok(got) = sock.recv_from(&mut buf) {
                received = Some(got);
                break;
            }
        }
        let Some((n, from)) = received else {
            evidence.push(format!(
                "{verb} to {dest}: no answer within {:?}",
                self.wait
            ));
            return None;
        };
        let text = String::from_utf8_lossy(&buf[..n]).into_owned();
        let mut parts = text.split_whitespace();
        if parts.next() != Some(verbs::MAPPED) {
            evidence.push(format!("{verb} to {dest}: unrecognised answer `{text}`"));
            return None;
        }
        let (Some(ip), Some(port)) = (parts.next(), parts.next()) else {
            evidence.push(format!("{verb} to {dest}: malformed answer `{text}`"));
            return None;
        };
        let (Ok(ip), Ok(port)) = (ip.parse::<IpAddr>(), port.parse::<u16>()) else {
            evidence.push(format!("{verb} to {dest}: unparseable answer `{text}`"));
            return None;
        };
        evidence.push(format!(
            "{verb} to {dest}: answered by {from}, mapped {ip}:{port}"
        ));
        Some(SocketAddr::new(ip, port))
    }

    /// RFC 5780 §4.3, reduced to what a laboratory needs.
    fn mapping_behaviour(
        &self,
        sock: &UdpSocket,
        local: SocketAddr,
        m1: SocketAddr,
        evidence: &mut Vec<String>,
    ) -> Behaviour {
        if m1.port() == local.port() && m1.ip() == local.ip() {
            evidence.push("the mapped endpoint equals the local one: no translation".to_owned());
            return Behaviour::None;
        }
        let Some(m2) = self.ask(sock, self.alternate, self.port_a, verbs::PROBE, evidence) else {
            evidence.push(
                "the alternate address did not answer, so mapping behaviour is unmeasured"
                    .to_owned(),
            );
            return Behaviour::Unreachable;
        };
        if m1 == m2 {
            evidence.push("a different destination address reused the mapping: EIM".to_owned());
            return Behaviour::EndpointIndependent;
        }
        let Some(m3) = self.ask(sock, self.alternate, self.port_b, verbs::PROBE, evidence) else {
            evidence.push(
                "the alternate port did not answer, so the mapping axis cannot be narrowed"
                    .to_owned(),
            );
            return Behaviour::Unreachable;
        };
        if m2 == m3 {
            evidence.push(
                "a different address allocated a new mapping but a different port did not: ADM"
                    .to_owned(),
            );
            Behaviour::AddressDependent
        } else {
            evidence.push("every destination tuple allocated a distinct mapping: APDM".to_owned());
            Behaviour::AddressPortDependent
        }
    }

    /// RFC 5780 §4.4: ask the reflector to answer from somewhere else and see
    /// whether the middlebox lets it through.
    fn filtering_behaviour(&self, evidence: &mut Vec<String>) -> Behaviour {
        // A fresh socket, so the mapping under test has been written to exactly
        // one endpoint and nothing else has widened its filter.
        let Ok(fresh) = self.socket() else {
            return Behaviour::Unreachable;
        };
        if self
            .ask(&fresh, self.primary, self.port_a, verbs::PROBE, evidence)
            .is_none()
        {
            return Behaviour::Unreachable;
        }
        if self
            .ask(
                &fresh,
                self.primary,
                self.port_a,
                verbs::PROBE_CHANGE_ADDR,
                evidence,
            )
            .is_some()
        {
            evidence.push("an answer from a never-contacted address arrived: EIF".to_owned());
            return Behaviour::EndpointIndependent;
        }
        if self
            .ask(
                &fresh,
                self.primary,
                self.port_a,
                verbs::PROBE_CHANGE_PORT,
                evidence,
            )
            .is_some()
        {
            evidence.push(
                "a different address was filtered but a different port was not: ADF".to_owned(),
            );
            return Behaviour::AddressDependent;
        }
        evidence.push("both a changed address and a changed port were filtered: APDF".to_owned());
        Behaviour::AddressPortDependent
    }

    fn measure_lifetime(&self, mapped: SocketAddr, evidence: &mut Vec<String>) -> Option<u64> {
        let idle = self.lifetime_ms?;
        let Ok(holder) = self.socket() else {
            return None;
        };
        let mut ignored = Vec::new();
        let held = self.ask(
            &holder,
            self.primary,
            self.port_a,
            verbs::PROBE,
            &mut ignored,
        )?;
        evidence.push(format!(
            "holding a mapping at {held} (the first probe mapped to {mapped}) and idling {idle} ms"
        ));
        std::thread::sleep(Duration::from_millis(idle));
        // A second socket asks the reflector to send unsolicited to the held
        // mapping: the holder itself must stay silent, or the request would
        // refresh the very mapping being measured.
        let Ok(asker) = self.socket() else {
            return None;
        };
        let request = format!("{} {} {}", verbs::SENDTO, held.ip(), held.port());
        let _ = asker.send_to(
            request.as_bytes(),
            SocketAddr::new(self.primary, self.port_a),
        );
        let mut buf = [0u8; 512];
        let survived = holder.recv_from(&mut buf).is_ok();
        evidence.push(format!(
            "after {idle} ms the mapping {} still deliver traffic",
            if survived { "did" } else { "did not" }
        ));
        survived.then_some(idle)
    }

    fn measure_hairpin(&self, evidence: &mut Vec<String>) -> Option<bool> {
        let target = self.hairpin_target?;
        let Ok(sock) = self.socket() else {
            return None;
        };
        if sock.send_to(b"HAIRPIN", target).is_err() {
            evidence.push(format!("the hairpin probe to {target} could not be sent"));
            return Some(false);
        }
        let mut buf = [0u8; 512];
        let got = sock.recv_from(&mut buf).is_ok();
        evidence.push(format!(
            "the hairpin probe to {target} {} answered",
            if got { "was" } else { "was not" }
        ));
        Some(got)
    }
}

/// Whether an observed report matches what a middlebox was configured to be.
///
/// This is the assertion **L-1** turns on. It is written as a list of
/// disagreements rather than a boolean so a failing conformance run says which
/// axis drifted — and a personality that drifted on one axis is a personality
/// whose whole column of the matrix is void, not merely red.
#[must_use]
pub fn disagreements(
    configured_mapping: Behaviour,
    configured_filtering: Behaviour,
    report: &Report,
) -> Vec<String> {
    let mut out = Vec::new();
    if report.mapping != configured_mapping {
        out.push(format!(
            "mapping: configured {configured_mapping:?}, the prober measured {:?}",
            report.mapping
        ));
    }
    if report.filtering != configured_filtering {
        out.push(format!(
            "filtering: configured {configured_filtering:?}, the prober measured {:?}",
            report.filtering
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreachable_is_never_silently_accepted_as_the_configured_behaviour() {
        let report = Report {
            mapping: Behaviour::Unreachable,
            filtering: Behaviour::Unreachable,
            lifetime_ms: None,
            hairpin: None,
            mapped: None,
            evidence: Vec::new(),
        };
        let d = disagreements(
            Behaviour::AddressPortDependent,
            Behaviour::AddressPortDependent,
            &report,
        );
        assert_eq!(
            d.len(),
            2,
            "a blackholed path must not be reported as a symmetric NAT"
        );
    }

    #[test]
    fn an_agreeing_report_produces_no_disagreements() {
        let report = Report {
            mapping: Behaviour::EndpointIndependent,
            filtering: Behaviour::AddressPortDependent,
            lifetime_ms: Some(30_000),
            hairpin: Some(false),
            mapped: Some("203.0.113.1:40000".to_owned()),
            evidence: Vec::new(),
        };
        assert!(disagreements(
            Behaviour::EndpointIndependent,
            Behaviour::AddressPortDependent,
            &report
        )
        .is_empty());
    }
}
