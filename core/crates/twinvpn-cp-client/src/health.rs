//! The control channel's own health, at **device scope and never session scope**.
//!
//! **Authority:** ADR-0002 R-a, `docs/reliability.md` §9.4, §4.3.
//!
//! ADR-0002 R-a is explicit: the control-channel liveness signal MUST NOT emit
//! `EV_PATH_SUSPECT`, `EV_PATH_DEAD`, `EV_LINK_DOWN` or any `reliability.md`
//! §4.3 event, and MUST NOT consume a token from the `peer:<DeviceId>` retry
//! budget. Its only outputs are a `HealthState` contribution at **device** scope
//! and a `CONTROL.*` reason code.
//!
//! That is why [`ChannelHealth`] has no relationship to `ConnectionState` and
//! this crate never constructs one: a control-plane outage cannot even *express*
//! itself as a data-plane event.

use crate::error::CpError;
use crate::transport::Rung;

/// The client's own view of the control channel. **Device scope, never session
/// scope.**
///
/// ADR-0002 R-a is explicit: the control-channel liveness signal MUST NOT emit
/// `EV_PATH_SUSPECT`, `EV_PATH_DEAD`, `EV_LINK_DOWN` or any `reliability.md`
/// §4.3 event, and MUST NOT consume a token from the `peer:<DeviceId>` retry
/// budget. Its only outputs are a `HealthState` contribution at **device** scope
/// and a `CONTROL.*` reason code — which is why this enum has no relationship to
/// `ConnectionState` and this crate never constructs one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelHealth {
    /// Never attached in this process.
    Detached,
    /// Attached on a rung.
    Attached {
        /// Which rung.
        rung: Rung,
    },
    /// Every rung exhausted. **Established sessions are unaffected.**
    Unreachable,
    /// Draining after a `GOAWAY`; reattach is scheduled inside the window.
    Draining,
}

impl ChannelHealth {
    /// Whether the data plane may still re-establish a session with a known
    /// `TrustedPeer`.
    ///
    /// **`true` in every state**, including `Unreachable`. That is I5, and it is
    /// a method rather than a comment so a change that broke it would have to
    /// delete a test.
    #[must_use]
    pub const fn permits_data_plane_reconnect(self) -> bool {
        true
    }

    /// The reason code to surface, if any.
    #[must_use]
    pub const fn diagnostic(self) -> Option<CpError> {
        match self {
            ChannelHealth::Detached | ChannelHealth::Draining => None,
            ChannelHealth::Attached { rung } => match rung {
                Rung::Quic => None,
                degraded => Some(CpError::TransportDegraded { rung: degraded }),
            },
            ChannelHealth::Unreachable => Some(CpError::Unreachable),
        }
    }
}
