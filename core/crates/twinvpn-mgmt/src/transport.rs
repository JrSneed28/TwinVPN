//! MI-21's **closed** set of four transport-layer operations.
//!
//! **Authority:** [ADR-0017](../../../../docs/adr/ADR-0017-local-management-interface.md)
//! MI-21 and §11.1.1; [ADR-0018](../../../../docs/adr/ADR-0018-shared-core-and-build-architecture.md)
//! §11.16 (o) and F-1.
//!
//! > **MI-21.** Exactly **four** MI operations have no core counterpart, and this
//! > set is **closed**: the `Hello`/`HelloAck` version and scope negotiation,
//! > `mi.catalogue.get`, `event.resync`, and the MI half of `version.get`. Every
//! > one of them is about **the connection**, a thing that does not exist
//! > in-process. Each **MUST NOT** acquire an ABI counterpart. Adding a fifth
//! > requires amending this ADR.
//!
//! # Why they live in a separate type
//!
//! Because MI-21 protects ADR-0018 F-1 rather than threatening it. These four are
//! "precisely the ones that would otherwise have to become exported functions",
//! each carrying a permanent compatibility obligation for a concern the
//! in-process caller does not have. A separate enum means the ABI's command
//! encoding cannot name one by construction, and [`assert_closed`] means the set
//! cannot quietly become five.
//!
//! **`version.get` deliberately appears in both.** It is the one operation that
//! is genuinely split: the *core's* half — agent version, `ProtocolEpoch` range,
//! build profile — is [`crate::CoreCommand::VersionGet`]; the *MI* half —
//! `mi_version` range, channel identity, catalogue digest — is
//! [`TransportOp::VersionGetMiHalf`]. That is MI-21's wording exactly ("the MI
//! half of `version.get` … which it returns **alongside** the core's own
//! version"), and splitting it anywhere else would either put `mi_version` on the
//! ABI or leave a client unable to learn it.

use crate::command::CoreCommand;

/// One of MI-21's four.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TransportOp {
    /// `Hello`/`HelloAck` — `mi_version` and scope negotiation (§11.7).
    Hello,
    /// `mi.catalogue.get` — the full operation table.
    CatalogueGet,
    /// `event.resync` — `SnapshotBegin` / rows / `SnapshotEnd{cursor}` (§11.10,
    /// MI-9).
    EventResync,
    /// The MI half of `version.get`: `mi_version` range, channel identity, and
    /// the catalogue digest.
    VersionGetMiHalf,
}

impl TransportOp {
    /// The closed set. **Exactly four.**
    pub const ALL: [TransportOp; 4] = [
        TransportOp::Hello,
        TransportOp::CatalogueGet,
        TransportOp::EventResync,
        TransportOp::VersionGetMiHalf,
    ];

    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            TransportOp::Hello => "hello",
            TransportOp::CatalogueGet => "mi.catalogue.get",
            TransportOp::EventResync => "event.resync",
            // The name is shared with the core command by design; the two halves
            // are answered together and the client sees one operation.
            TransportOp::VersionGetMiHalf => "version.get",
        }
    }
}

/// Asserts MI-21's closure at runtime as well as in the type.
///
/// Called by this crate's tests and re-exported so a shell's own conformance
/// suite can assert the same thing without duplicating the number four.
///
/// # Errors
///
/// The count and the one legitimate name overlap are the two things that can
/// drift; both are named in the message rather than left to a bare `assert_eq!`.
pub fn assert_closed() -> Result<(), &'static str> {
    if TransportOp::ALL.len() != 4 {
        return Err(
            "ADR-0017 MI-21 closes the transport-layer set at FOUR operations. Adding a fifth \
             requires amending that ADR, not editing this array.",
        );
    }
    for t in TransportOp::ALL {
        // The only permitted overlap is `version.get`, and only because MI-21
        // splits that one operation across the two layers by name.
        if t != TransportOp::VersionGetMiHalf && CoreCommand::from_name(t.name()).is_some() {
            return Err(
                "an MI transport operation acquired a core counterpart; MI-21 forbids it and \
                 ADR-0018 §11.16 (o) blocks it from reaching the ABI",
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_transport_set_is_closed_at_four() {
        assert_closed().expect("MI-21 holds");
        assert_eq!(TransportOp::ALL.len(), 4);
    }

    #[test]
    fn only_version_get_overlaps_the_core_command_set() {
        let overlaps: Vec<&str> = TransportOp::ALL
            .iter()
            .map(|t| t.name())
            .filter(|n| CoreCommand::from_name(n).is_some())
            .collect();
        assert_eq!(overlaps, vec!["version.get"]);
    }

    #[test]
    fn none_of_the_four_is_reachable_through_the_catalogue() {
        // §11.16 (o): each "MUST NOT acquire an ABI counterpart", and the
        // catalogue is what the ABI's command set is derived from.
        for t in TransportOp::ALL {
            if t == TransportOp::VersionGetMiHalf {
                continue;
            }
            assert!(crate::catalogue::lookup(t.name()).is_none(), "{}", t.name());
        }
    }
}
