//! IP Helper, as [`RouteTable`].
//!
//! **Authority:** ADR-0010 §11.3's Windows row (`CreateIpForwardEntry2` plus an
//! explicit interface metric; the host's own default route is never deleted or
//! modified), R1, R5, R7; `docs/networking.md` §7.2; ADR-0018 DP-4.
//!
//! # This file has never been executed
//!
//! Nothing in `sys/win/` has been linked, loaded or run. `make cross-check`
//! type-checks it against the real `windows-sys` for `x86_64-pc-windows-msvc`
//! with `-D warnings`; that is a compile proof and it is not a behaviour proof.
//!
//! # All-or-nothing, on an API that has no transaction
//!
//! WFP has a real transaction. **IP Helper does not.** `CreateIpForwardEntry2`
//! and its siblings each take effect on their own, so "atomic per contract
//! generation" (R5) has to be built out of compensation: perform the plan step
//! by step, record what was done, and on a failure undo the record before
//! returning.
//!
//! What that costs, stated rather than glossed:
//!
//! - **There is a window.** Between the first delete and the last add the host's
//!   routing table holds neither generation. It is short and it is entirely
//!   inside the overlay interface's own rows, and the enforcement layer — which
//!   `netcfg` installs *before* this runs — is what keeps the window from being a
//!   leak rather than merely a gap.
//! - **A compensating call can itself fail.** If it does, the host is in a state
//!   no generation describes. [`apply`] returns the **original** error in that
//!   case, because the original is what a support case has to diagnose, and it
//!   logs the compensation failure at `ERROR` so the two are both visible. The
//!   caller's recovery is `netcfg`'s: re-assert `BLOCKED` and read back, never
//!   retry the apply.
//!
//! # Nothing outside the overlay is named
//!
//! [`crate::route::RoutePlan::validate`] refuses a plan holding a row on another
//! interface, and `netcfg` calls it before this module sees one. This module
//! therefore never has to decide whether a row is ours: by the time a plan
//! arrives, every row in it carries the overlay LUID and every delete carries
//! `MIB_IPPROTO_NETMGMT`.

// Every method below is a method of the shim rather than a free function: they
// are the shim's operations, and reading them as one impl is what makes the API
// surface reviewable against the trait. Several do not touch `self`, because the
// type is stateless by design — R5's recovery entry point depends on this module
// holding nothing between calls — and that is the shape the lint objects to.
#![allow(clippy::unused_self)]

use twinvpn_platform::{LinkFacts, PlatformError};
use twinvpn_types::{AddressFamily, PerFamily, UnderlayFamilies};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DeleteIpForwardEntry2,
    DeleteUnicastIpAddressEntry, FreeMibTable, GetIpForwardTable2, GetIpInterfaceEntry,
    GetUnicastIpAddressTable, InitializeUnicastIpAddressEntry, SetIpInterfaceEntry,
    IP_ADDRESS_PREFIX, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
    MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{AF_UNSPEC, MIB_IPPROTO_NETMGMT};

use crate::oserr::{self, Context, Win32Error};
use crate::route::{
    AddressRow, InstalledRoutes, InterfaceLuid, RoutePlan, RouteProtocol, RouteRow,
};
use crate::sys::RouteTable;

use super::addr;


/// IP Helper. Stateless — every call is a query or a mutation, and nothing is
/// remembered between them (R5's recovery entry point depends on that).
pub struct IpHelper;

impl IpHelper {
    /// Binds it.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for IpHelper {
    fn default() -> Self {
        Self::new()
    }
}

const fn luid(value: InterfaceLuid) -> NET_LUID_LH {
    NET_LUID_LH { Value: value.0 }
}

/// The `MIB_IPFORWARD_ROW2` one of ours becomes.
fn forward_row(row: &RouteRow) -> MIB_IPFORWARD_ROW2 {
    let (prefix, length) = addr::to_prefix(row.destination);
    let mut out = MIB_IPFORWARD_ROW2 {
        InterfaceLuid: luid(row.luid),
        InterfaceIndex: 0,
        DestinationPrefix: IP_ADDRESS_PREFIX {
            Prefix: prefix,
            PrefixLength: length,
        },
        // An on-link route is the unspecified address in `NextHop`, in the same
        // family as the destination — not a zeroed struct, which would carry
        // `AF_UNSPEC` and be rejected.
        NextHop: row.next_hop.map_or_else(
            || unspecified_of(row.destination.family()),
            addr::to_sockaddr,
        ),
        SitePrefixLength: 0,
        ValidLifetime: u32::MAX,
        PreferredLifetime: u32::MAX,
        Metric: row.metric,
        Protocol: MIB_IPPROTO_NETMGMT,
        Loopback: false,
        AutoconfigureAddress: false,
        Publish: false,
        Immortal: false,
        Age: 0,
        Origin: 0,
    };
    // `SitePrefixLength` must be 0 for a route; the field is an address
    // property. Written explicitly rather than left to the zeroed value so a
    // reader does not have to know that.
    out.SitePrefixLength = 0;
    out
}

/// The unspecified address of a family, as a `SOCKADDR_INET`.
fn unspecified_of(family: AddressFamily) -> windows_sys::Win32::Networking::WinSock::SOCKADDR_INET {
    match family {
        AddressFamily::V4 => addr::to_sockaddr(twinvpn_types::IpAddr::V4(
            twinvpn_types::V4Addr::from_octets([0; 4]),
        )),
        AddressFamily::V6 => {
            // `V6Addr::prefix_base` accepts the all-zero value; `V6Addr::new`
            // would too, but `prefix_base` is the constructor whose contract is
            // "a value with no zone", which is what an unspecified next hop is.
            twinvpn_types::V6Addr::prefix_base([0; 16]).map_or_else(
                |_| windows_sys::Win32::Networking::WinSock::SOCKADDR_INET::default(),
                |a| addr::to_sockaddr(twinvpn_types::IpAddr::V6(a)),
            )
        }
    }
}

/// The `MIB_UNICASTIPADDRESS_ROW` one of ours becomes.
///
/// `InitializeUnicastIpAddressEntry` first, because the struct has fields whose
/// correct default is not zero — `PreferredLifetime` and `ValidLifetime` in
/// particular, where zero means "already expired".
fn address_row(row: &AddressRow) -> MIB_UNICASTIPADDRESS_ROW {
    let mut out = MIB_UNICASTIPADDRESS_ROW::default();
    // SAFETY: `out` is a live, correctly aligned row the API fills with its own
    // defaults.
    unsafe { InitializeUnicastIpAddressEntry(&raw mut out) };
    out.InterfaceLuid = luid(row.luid);
    out.InterfaceIndex = 0;
    out.Address = addr::to_sockaddr(row.address.address());
    #[allow(clippy::cast_possible_truncation)]
    {
        out.OnLinkPrefixLength = row.address.prefix_len() as u8;
    }
    out.SkipAsSource = row.skip_as_source;
    out
}

impl IpHelper {
    fn read_forward(&self, overlay: InterfaceLuid) -> Result<Vec<RouteRow>, PlatformError> {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = core::ptr::null_mut();
        // SAFETY: `table` is a live out-parameter the API fills with memory it
        // owns and `FreeMibTable` releases.
        let status = unsafe { GetIpForwardTable2(AF_UNSPEC, &raw mut table) };
        if status != 0 {
            return Err(oserr::from_status(
                Win32Error(status),
                "GetIpForwardTable2",
                Context::RouteProgram,
            ));
        }
        let guard = MibGuard(table.cast());
        // SAFETY: the call succeeded, so `table` points at a header whose
        // `Table` field is the first of `NumEntries` rows.
        let entries = unsafe { (*table).NumEntries } as usize;
        // SAFETY: as above — `NumEntries` rows follow the header.
        let rows = unsafe { core::slice::from_raw_parts((*table).Table.as_ptr(), entries) };

        let mut out = Vec::new();
        for row in rows {
            // SAFETY: the union's `Value` member is always readable; a LUID is
            // a plain `u64` under it.
            if unsafe { row.InterfaceLuid.Value } != overlay.0 {
                continue;
            }
            // SAFETY: the OS filled the prefix in.
            let Some(address) = (unsafe { addr::from_sockaddr(&row.DestinationPrefix.Prefix) })
            else {
                continue;
            };
            let Ok(destination) = twinvpn_types::IpPrefix::new(
                address,
                u32::from(row.DestinationPrefix.PrefixLength),
            ) else {
                // A prefix with host bits set is not something `IpPrefix` can
                // hold. Skipping rather than masking: a masked value would be a
                // different route, and reporting it as ours would make rollback
                // delete something nobody installed.
                continue;
            };
            // SAFETY: the OS filled the next hop in.
            let next_hop = unsafe { addr::from_sockaddr(&row.NextHop) };
            let next_hop = next_hop.filter(|a| !is_unspecified(*a));
            out.push(RouteRow {
                luid: overlay,
                destination,
                next_hop,
                metric: row.Metric,
                protocol: if row.Protocol == MIB_IPPROTO_NETMGMT {
                    RouteProtocol::NetMgmt
                } else {
                    #[allow(clippy::cast_sign_loss)]
                    RouteProtocol::Other(row.Protocol as u32)
                },
            });
        }
        drop(guard);
        Ok(out)
    }

    fn read_addresses(&self, overlay: InterfaceLuid) -> Result<Vec<AddressRow>, PlatformError> {
        let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = core::ptr::null_mut();
        // SAFETY: live out-parameter; the API owns the memory until `FreeMibTable`.
        let status = unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &raw mut table) };
        if status != 0 {
            return Err(oserr::from_status(
                Win32Error(status),
                "GetUnicastIpAddressTable",
                Context::RouteProgram,
            ));
        }
        let guard = MibGuard(table.cast());
        // SAFETY: the call succeeded.
        let entries = unsafe { (*table).NumEntries } as usize;
        // SAFETY: as above.
        let rows = unsafe { core::slice::from_raw_parts((*table).Table.as_ptr(), entries) };

        let mut out = Vec::new();
        for row in rows {
            // SAFETY: the union's `Value` member is always readable.
            if unsafe { row.InterfaceLuid.Value } != overlay.0 {
                continue;
            }
            // SAFETY: the OS filled the address in.
            let Some(address) = (unsafe { addr::from_sockaddr(&row.Address) }) else {
                continue;
            };
            // ADR-0010 §11.1 allocates a `/32` and a `/128`, so the address is
            // reported as a host prefix rather than at its on-link length: an
            // `IpPrefix` at the on-link length would have host bits set and
            // would not construct at all.
            let Ok(prefix) =
                twinvpn_types::IpPrefix::new(address, address.family().max_prefix_len())
            else {
                continue;
            };
            out.push(AddressRow {
                luid: overlay,
                address: prefix,
                skip_as_source: row.SkipAsSource,
            });
        }
        drop(guard);
        Ok(out)
    }

    fn read_metric(
        &self,
        overlay: InterfaceLuid,
        family: AddressFamily,
    ) -> Result<Option<u32>, PlatformError> {
        let mut row = MIB_IPINTERFACE_ROW {
            Family: addr::address_family(family),
            InterfaceLuid: luid(overlay),
            ..MIB_IPINTERFACE_ROW::default()
        };
        // SAFETY: `row` is live and carries the two keys the API reads.
        let status = unsafe { GetIpInterfaceEntry(&raw mut row) };
        match status {
            0 => Ok(if row.UseAutomaticMetric {
                // An automatic metric is not a value to restore: putting a
                // number back where the stack was choosing one would pin it.
                None
            } else {
                Some(row.Metric)
            }),
            // The interface has no stack for that family yet. Not an error: R1
            // requires both families to be programmed, and "v6 is not up yet" is
            // a state the caller converges out of.
            s if Win32Error(s).get() == oserr::ERROR_NOT_FOUND
                || Win32Error(s).get() == oserr::ERROR_FILE_NOT_FOUND =>
            {
                Ok(None)
            }
            s => Err(oserr::from_status(
                Win32Error(s),
                "GetIpInterfaceEntry",
                Context::RouteProgram,
            )),
        }
    }

    fn set_metric(
        &self,
        overlay: InterfaceLuid,
        family: AddressFamily,
        metric: Option<u32>,
    ) -> Result<(), PlatformError> {
        let mut row = MIB_IPINTERFACE_ROW {
            Family: addr::address_family(family),
            InterfaceLuid: luid(overlay),
            ..MIB_IPINTERFACE_ROW::default()
        };
        // `SetIpInterfaceEntry` requires the row to have been read first: it
        // rejects a partially-filled one, and the fields it will not accept
        // defaults for are not documented as a closed list.
        // SAFETY: `row` is live and carries the two keys.
        let status = unsafe { GetIpInterfaceEntry(&raw mut row) };
        if status != 0 {
            return Err(oserr::from_status(
                Win32Error(status),
                "GetIpInterfaceEntry",
                Context::RouteProgram,
            ));
        }
        match metric {
            Some(value) => {
                row.UseAutomaticMetric = false;
                row.Metric = value;
            }
            None => row.UseAutomaticMetric = true,
        }
        // `SitePrefixLength` on a v6 row must be reset before a set, or the API
        // rejects the row. A documented quirk this build has not observed.
        if family == AddressFamily::V6 {
            row.SitePrefixLength = 0;
        }
        // SAFETY: `row` was filled by `GetIpInterfaceEntry` and is live.
        let status = unsafe { SetIpInterfaceEntry(&raw mut row) };
        if status == 0 {
            Ok(())
        } else {
            Err(oserr::from_status(
                Win32Error(status),
                "SetIpInterfaceEntry",
                Context::RouteProgram,
            ))
        }
    }
}

const fn is_unspecified(address: twinvpn_types::IpAddr) -> bool {
    match address {
        twinvpn_types::IpAddr::V4(a) => u32::from_be_bytes(a.octets()) == 0,
        twinvpn_types::IpAddr::V6(a) => {
            let o = a.octets();
            let mut i = 0;
            while i < 16 {
                if o[i] != 0 {
                    return false;
                }
                i += 1;
            }
            true
        }
    }
}

/// Frees a MIB table however the block exits.
struct MibGuard(*mut core::ffi::c_void);

impl Drop for MibGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from a `Get*Table` call that succeeded
            // and has not been freed.
            unsafe { FreeMibTable(self.0) };
        }
    }
}

/// One completed step of a plan, and how to undo it.
enum Done {
    RouteAdded(MIB_IPFORWARD_ROW2),
    RouteDeleted(MIB_IPFORWARD_ROW2),
    AddressAdded(MIB_UNICASTIPADDRESS_ROW),
    AddressDeleted(MIB_UNICASTIPADDRESS_ROW),
}

impl RouteTable for IpHelper {
    fn read(&self, overlay: InterfaceLuid) -> Result<InstalledRoutes, PlatformError> {
        Ok(InstalledRoutes {
            rows: self.read_forward(overlay)?,
            addresses: self.read_addresses(overlay)?,
            interface_metric: PerFamily::new(
                self.read_metric(overlay, AddressFamily::V4)?,
                self.read_metric(overlay, AddressFamily::V6)?,
            ),
        })
    }

    #[allow(clippy::too_many_lines)]
    fn apply(&self, plan: &RoutePlan) -> Result<(), PlatformError> {
        let mut done: Vec<Done> = Vec::new();

        // The order is the same one the fake models and the same one rollback
        // inverts: deletes first, then addresses, then routes. Adding a route
        // before its source address exists is what produces a route the stack
        // cannot resolve a source for.
        let result = (|| -> Result<(), PlatformError> {
            for row in &plan.deletes {
                let native = forward_row(row);
                // SAFETY: `native` is live for the call.
                let status = unsafe { DeleteIpForwardEntry2(&raw const native) };
                if status != 0 && Win32Error(status).get() != oserr::ERROR_NOT_FOUND {
                    return Err(oserr::from_status(
                        Win32Error(status),
                        "DeleteIpForwardEntry2",
                        Context::RouteProgram,
                    ));
                }
                done.push(Done::RouteDeleted(native));
            }
            for row in &plan.addresses.deletes {
                let native = address_row(row);
                // SAFETY: `native` is live for the call.
                let status = unsafe { DeleteUnicastIpAddressEntry(&raw const native) };
                if status != 0 && Win32Error(status).get() != oserr::ERROR_NOT_FOUND {
                    return Err(oserr::from_status(
                        Win32Error(status),
                        "DeleteUnicastIpAddressEntry",
                        Context::RouteProgram,
                    ));
                }
                done.push(Done::AddressDeleted(native));
            }
            for row in &plan.addresses.adds {
                let native = address_row(row);
                // SAFETY: `native` is live for the call.
                let status = unsafe { CreateUnicastIpAddressEntry(&raw const native) };
                if status != 0 && Win32Error(status).get() != oserr::ERROR_OBJECT_ALREADY_EXISTS {
                    return Err(oserr::from_status(
                        Win32Error(status),
                        "CreateUnicastIpAddressEntry",
                        Context::RouteProgram,
                    ));
                }
                done.push(Done::AddressAdded(native));
            }
            for row in &plan.adds {
                let native = forward_row(row);
                // SAFETY: `native` is live for the call.
                let status = unsafe { CreateIpForwardEntry2(&raw const native) };
                if status != 0 && Win32Error(status).get() != oserr::ERROR_OBJECT_ALREADY_EXISTS {
                    return Err(oserr::from_status(
                        Win32Error(status),
                        "CreateIpForwardEntry2",
                        Context::RouteProgram,
                    ));
                }
                done.push(Done::RouteAdded(native));
            }
            Ok(())
        })();

        if let Err(cause) = result {
            // Undo in reverse, and keep going past a failure: a compensation
            // that stopped at the first error would leave more behind than one
            // that tried every step.
            let mut compensation_failed = false;
            for step in done.into_iter().rev() {
                // SAFETY: every row was built by this function and is live for
                // its own call.
                let status = unsafe {
                    match &step {
                        Done::RouteAdded(row) => DeleteIpForwardEntry2(&raw const *row),
                        Done::RouteDeleted(row) => CreateIpForwardEntry2(&raw const *row),
                        Done::AddressAdded(row) => DeleteUnicastIpAddressEntry(&raw const *row),
                        Done::AddressDeleted(row) => CreateUnicastIpAddressEntry(&raw const *row),
                    }
                };
                if status != 0 {
                    compensation_failed = true;
                }
            }
            if compensation_failed {
                // The host is in a state no generation describes. The ORIGINAL
                // error is returned, because that is what a support case has to
                // diagnose; this line is what makes the second failure visible
                // rather than swallowed.
                tracing::error!(
                    "a compensating IP Helper call failed; the routing table matches no generation"
                );
            }
            return Err(cause);
        }

        // The metric last, and only where the plan states one: it is the field
        // §11.3's Windows row names as the mechanism, and setting it before the
        // routes exist would have nothing to apply to.
        for family in [AddressFamily::V4, AddressFamily::V6] {
            if let Some(metric) = *plan.addresses.interface_metric.get(family) {
                let overlay = plan
                    .adds
                    .first()
                    .or_else(|| plan.deletes.first())
                    .map(|r| r.luid)
                    .or_else(|| plan.addresses.adds.first().map(|a| a.luid))
                    .or_else(|| plan.addresses.deletes.first().map(|a| a.luid));
                if let Some(overlay) = overlay {
                    self.set_metric(overlay, family, Some(metric))?;
                }
            }
        }
        Ok(())
    }

    fn link_facts(&self, overlay: InterfaceLuid) -> Result<LinkFacts, PlatformError> {
        let mut mtu = 1500u32;
        for family in [AddressFamily::V4, AddressFamily::V6] {
            let mut row = MIB_IPINTERFACE_ROW {
                Family: addr::address_family(family),
                InterfaceLuid: luid(overlay),
                ..MIB_IPINTERFACE_ROW::default()
            };
            // SAFETY: `row` is live and carries the two keys.
            if unsafe { GetIpInterfaceEntry(&raw mut row) } == 0 && row.NlMtu != 0 {
                mtu = mtu.min(row.NlMtu);
            }
        }

        // A default route in either family, on ANY interface — the underlay's
        // facts are about the host, not about the overlay.
        let mut table: *mut MIB_IPFORWARD_TABLE2 = core::ptr::null_mut();
        // SAFETY: live out-parameter.
        let status = unsafe { GetIpForwardTable2(AF_UNSPEC, &raw mut table) };
        if status != 0 {
            return Err(oserr::from_status(
                Win32Error(status),
                "GetIpForwardTable2",
                Context::RouteProgram,
            ));
        }
        let guard = MibGuard(table.cast());
        // SAFETY: the call succeeded.
        let entries = unsafe { (*table).NumEntries } as usize;
        // SAFETY: as above.
        let rows = unsafe { core::slice::from_raw_parts((*table).Table.as_ptr(), entries) };
        let mut v4 = false;
        let mut v6 = false;
        for row in rows {
            if row.DestinationPrefix.PrefixLength != 0 {
                continue;
            }
            // SAFETY: the OS filled the prefix in.
            match unsafe { addr::family_of(&row.DestinationPrefix.Prefix) } {
                Some(AddressFamily::V4) => v4 = true,
                Some(AddressFamily::V6) => v6 = true,
                None => {}
            }
        }
        drop(guard);

        Ok(LinkFacts {
            mtu,
            // `(true, false)` and `(false, false)` share a body and are written
            // out separately on purpose: the first is a real v4-only host, and
            // the second is a host with no default route at all, which
            // `UnderlayFamilies` has no value for. Merging them would hide that
            // the second is an approximation — the `default_routes` pair below
            // carries the honest answer and the core reads that.
            #[allow(clippy::match_same_arms)]
            families: match (v4, v6) {
                (true, true) => UnderlayFamilies::DualStack,
                (true, false) => UnderlayFamilies::V4Only,
                (false, true) => UnderlayFamilies::V6Only { nat64: None },
                (false, false) => UnderlayFamilies::V4Only,
            },
            default_routes: PerFamily::new(v4, v6),
            // The host's resolvers are the resolver module's to report, and
            // reporting an empty list here rather than a guess is what keeps
            // `query_link_facts` from becoming a second source for a fact
            // ADR-0011 already owns. **A stated gap.**
            resolvers: PerFamily::new(Vec::new(), Vec::new()),
            // `metered` and `low_power` come from the Windows connection-cost
            // and power APIs, which are the shell's (ADR-0022 LC-31, LC-23a).
            // Reported false rather than guessed. **A stated gap.**
            metered: false,
            low_power: false,
        })
    }
}
