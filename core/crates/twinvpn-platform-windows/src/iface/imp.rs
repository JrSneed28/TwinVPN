//! The IP Helper shim: the only part of [`crate::iface`] that needs Windows.
//!
//! **Authority:** ADR-0018 DP-4, CB-3; `docs/networking.md` §5.1
//! ("event-driven, never polled"); ADR-0022 LC-23b.
//!
//! # What is here, and what has never run
//!
//! Everything above this module — the `IF_TYPE` classification, the notification
//! decode, the facts assembly, the drop accounting — is target-free and tested
//! on the Linux host this crate was written on. What is here is
//! `GetAdaptersAddresses`, `GetIpForwardTable2` and the three `Notify*`
//! registrations, and **none of it has ever executed**.
//!
//! # The callbacks run on a thread-pool thread, and that constrains them
//!
//! IP Helper invokes a change callback on a thread it owns. Two rules follow,
//! and both are structural here rather than advisory:
//!
//! - **A callback must not block.** [`Sink::emit`] uses `try_send`, which never
//!   waits: a full channel is a *counted drop* ([`DropLedger`]), which is
//!   ADR-0018 §11.6's "a dropped event is itself recorded". A callback that
//!   awaited a slot would hold an IP Helper worker for as long as the core was
//!   not draining.
//! - **A callback must not call back into IP Helper.** Nothing here does; the
//!   callback decodes the row it was handed and enqueues, and the
//!   re-enumeration that a `EventsLost` marker prompts happens on the core's own
//!   task through [`InterfaceProvider::enumerate`].
//!
//! `CancelMibChangeNotify2` is documented to wait for any in-flight callback to
//! return before it does, which is what makes freeing the context in
//! [`Subscription`]'s `Drop` — *after* all three cancels — sound.

use std::ffi::c_void;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use futures_core::Stream;
use twinvpn_platform::{InterfaceFacts, InterfaceIndex, NetworkChange, PlatformError};
use twinvpn_types::{AddressFamily, IpAddr};
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, HANDLE, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper as ip;
use windows_sys::Win32::Networking::WinSock as ws;

use super::{
    decode_change, facts_from, AdapterRow, ChangeStream, DropLedger, Notification,
    NotificationType, CHANGE_QUEUE,
};
use crate::oserr::{self, Context, Win32Error};
use crate::route::InterfaceLuid;
use crate::shutdown::ShutdownLatch;

/// The flags `GetAdaptersAddresses` is called with.
///
/// Anycast, multicast and DNS-server lists are skipped because the seam carries
/// none of them, and each one Windows fills in is a linked list this walk would
/// have to traverse for nothing. `GAA_FLAG_INCLUDE_PREFIX` is not requested:
/// `IP_ADAPTER_UNICAST_ADDRESS_LH.OnLinkPrefixLength` already carries the
/// length, and the `FirstPrefix` list it enables is the older, ambiguous form.
/// `GAA_FLAG_SKIP_FRIENDLY_NAME` is deliberately **not** among them: the
/// friendly name is how [`crate::iface::is_overlay`] answers "is this ours".
const ADAPTER_FLAGS: ip::GET_ADAPTERS_ADDRESSES_FLAGS =
    ip::GAA_FLAG_SKIP_ANYCAST | ip::GAA_FLAG_SKIP_MULTICAST | ip::GAA_FLAG_SKIP_DNS_SERVER;

/// How far [`wide_to_string`] will scan for a terminator.
///
/// A provider that hands back an unterminated string is malfunctioning, and
/// walking off the end of its buffer to find that out is worse than stopping.
/// The bound is generous against `InterfaceName::MAX_BYTES` so that a name the
/// seam would refuse is refused **by the seam**, with its own reason code,
/// rather than silently truncated here into one it accepts.
const NAME_SCAN_LIMIT: usize = 4096;

/// How much room the first `GetAdaptersAddresses` attempt gets.
///
/// **A decision recorded as one.** Microsoft's own guidance is 15 KB; a host
/// with many adapters needs more, and the call reports the size it wants, so
/// this is a first guess and never a cap. Starting smaller costs an extra call
/// on an ordinary host; starting larger wastes nothing that matters.
const FIRST_ATTEMPT_BYTES: usize = 16 * 1024;

/// How many times the size-then-fill loop will retry.
///
/// Bounded because the table can grow between the two calls: an unbounded loop
/// on a host whose adapters are churning is a hang, and `ownership.md` §6 rule
/// 10 bounds every allocation an external input can drive.
const SIZE_ATTEMPTS: usize = 4;

/// Decodes a NUL-terminated UTF-16 string.
///
/// Lossy, and deliberately: an adapter name is a value a user chose in Network
/// Connections and it can hold anything the shell allows. A name that will not
/// decode is still a name, and [`crate::iface::facts_from`] is what refuses one
/// the seam cannot carry.
///
/// # Safety
///
/// `ptr` must be null or point at a NUL-terminated UTF-16 sequence that stays
/// valid for the duration of the call.
unsafe fn wide_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    // SAFETY: the caller guarantees a NUL terminator, so the read is in bounds
    // for every offset up to and including it.
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
        // A name without a terminator inside a sane bound is a malfunctioning
        // provider; stopping is better than walking off the end.
        if len > NAME_SCAN_LIMIT {
            break;
        }
    }
    // SAFETY: `len` bytes before the terminator were just proved readable.
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf16_lossy(slice)
}

/// Reads a `SOCKET_ADDRESS` into a canonical address.
///
/// # Safety
///
/// `address` must hold a valid pointer and length, as IP Helper fills it in.
unsafe fn socket_address(address: &ws::SOCKET_ADDRESS) -> Option<IpAddr> {
    if address.lpSockaddr.is_null() {
        return None;
    }
    let len = usize::try_from(address.iSockaddrLength).ok()?;
    // SAFETY: IP Helper documents `lpSockaddr` as pointing at `iSockaddrLength`
    // readable bytes for the lifetime of the buffer this row lives in, which
    // the caller holds.
    let bytes = unsafe { std::slice::from_raw_parts(address.lpSockaddr.cast::<u8>(), len) };
    let raw = crate::sock::parse_sockaddr(bytes, "GetAdaptersAddresses").ok()?;
    crate::sock::address_from_raw(raw, "GetAdaptersAddresses").ok()
}

/// Which interfaces carry a default route, per family.
///
/// Read from `GetIpForwardTable2` rather than inferred: ADR-0010 R6's question
/// is whether the **host** has a way out, and our own two `/1` routes are not
/// that — a `/1` is not a `/0`, so this filter answers the right question by
/// construction.
fn default_routes() -> Result<Vec<(u32, AddressFamily)>, PlatformError> {
    let mut table: *mut ip::MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: `table` is a live out-parameter; on success IP Helper allocates
    // the table and this function frees it with `FreeMibTable` on every path.
    let status = unsafe { ip::GetIpForwardTable2(ws::AF_UNSPEC, &raw mut table) };
    if status != NO_ERROR {
        return Err(oserr::from_status(
            Win32Error(status),
            "GetIpForwardTable2",
            Context::InterfaceQuery,
        ));
    }
    let mut out = Vec::new();
    if !table.is_null() {
        // SAFETY: the call succeeded, so `table` points at an initialised
        // `MIB_IPFORWARD_TABLE2` whose `Table` field is a `NumEntries`-long
        // array. The pointer is not used after `FreeMibTable` below.
        let count = unsafe { (*table).NumEntries } as usize;
        for index in 0..count {
            // SAFETY: `index` is below `NumEntries`, which is the array's own
            // declared length.
            let row = unsafe {
                &*(&raw const (*table).Table)
                    .cast::<ip::MIB_IPFORWARD_ROW2>()
                    .add(index)
            };
            if row.DestinationPrefix.PrefixLength != 0 {
                continue;
            }
            // SAFETY: `SOCKADDR_INET` is a union whose `si_family` overlaps
            // every member's first field, which is what it exists for.
            let family = unsafe { row.DestinationPrefix.Prefix.si_family };
            let family = match family {
                ws::AF_INET => AddressFamily::V4,
                ws::AF_INET6 => AddressFamily::V6,
                _ => continue,
            };
            out.push((row.InterfaceIndex, family));
        }
        // SAFETY: `table` was allocated by `GetIpForwardTable2` and has not been
        // freed; nothing refers to it after this point.
        unsafe { ip::FreeMibTable(table.cast::<c_void>()) };
    }
    Ok(out)
}

/// Every interface the OS currently reports.
pub(super) fn enumerate() -> Result<Vec<InterfaceFacts>, PlatformError> {
    let defaults = default_routes()?;
    let buffer = adapters()?;
    let mut out = Vec::new();
    // SAFETY: `buffer` holds the bytes `GetAdaptersAddresses` filled in, and the
    // first entry begins at its start. The list is walked only through `Next`,
    // which the provider terminates with null, and the buffer outlives the walk.
    let mut node = buffer.as_ptr().cast::<ip::IP_ADAPTER_ADDRESSES_LH>();
    while !node.is_null() {
        // SAFETY: `node` is non-null and points into the live buffer.
        let adapter = unsafe { &*node };
        let mut addresses = Vec::new();
        let mut unicast = adapter.FirstUnicastAddress;
        while !unicast.is_null() {
            // SAFETY: as above — a non-null node inside the same buffer.
            let entry = unsafe { &*unicast };
            // SAFETY: `entry.Address` is the row IP Helper filled in.
            if let Some(address) = unsafe { socket_address(&entry.Address) } {
                addresses.push((address, u32::from(entry.OnLinkPrefixLength)));
            }
            unicast = entry.Next;
        }
        // SAFETY: `NET_LUID_LH` is a union whose `Value` member is the whole
        // 64-bit identifier; reading it is the documented way to obtain it.
        let luid = unsafe { adapter.Luid.Value };
        // SAFETY: `FriendlyName` is a NUL-terminated wide string owned by the
        // buffer.
        let name = unsafe { wide_to_string(adapter.FriendlyName) };
        let index = index_of(adapter);
        let row = AdapterRow {
            index,
            luid: InterfaceLuid(luid),
            name,
            if_type: adapter.IfType,
            // `IF_OPER_STATUS` is a signed enumeration on the wire and an
            // unsigned one in the seam's vocabulary; a negative value is not
            // one Windows produces, and mapping it to zero makes it "not up",
            // which is the safe direction.
            oper_status: u32::try_from(adapter.OperStatus).unwrap_or(0),
            mtu: adapter.Mtu,
            addresses,
            has_default_route_v4: defaults
                .iter()
                .any(|(i, f)| *i == index && *f == AddressFamily::V4),
            has_default_route_v6: defaults
                .iter()
                .any(|(i, f)| *i == index && *f == AddressFamily::V6),
        };
        // A row the seam refuses is skipped rather than failing the whole
        // enumeration: one malformed adapter name must not make the host look
        // like it has no network at all.
        if let Ok(facts) = facts_from(&row) {
            out.push(facts);
        }
        node = adapter.Next;
    }
    Ok(out)
}

/// The adapter's IPv4 interface index, from the anonymous union.
fn index_of(adapter: &ip::IP_ADAPTER_ADDRESSES_LH) -> u32 {
    // SAFETY: `Anonymous1` is a union of a `u64` and a struct whose second
    // field is `IfIndex`; reading the named member is the documented access.
    unsafe { adapter.Anonymous1.Anonymous.IfIndex }
}

/// Calls `GetAdaptersAddresses`, growing the buffer until it fits.
fn adapters() -> Result<Vec<u64>, PlatformError> {
    let mut words = FIRST_ATTEMPT_BYTES / 8;
    for _ in 0..SIZE_ATTEMPTS {
        let mut buffer = vec![0u64; words];
        let mut size = u32::try_from(words * 8).unwrap_or(u32::MAX);
        // SAFETY: `buffer` is a live allocation of `size` bytes at 8-byte
        // alignment, which is `IP_ADAPTER_ADDRESSES_LH`'s. `size` is a live
        // out-parameter the call updates when the buffer is too small.
        let status = unsafe {
            ip::GetAdaptersAddresses(
                u32::from(ws::AF_UNSPEC),
                ADAPTER_FLAGS,
                std::ptr::null(),
                buffer.as_mut_ptr().cast::<ip::IP_ADAPTER_ADDRESSES_LH>(),
                &raw mut size,
            )
        };
        match status {
            NO_ERROR => return Ok(buffer),
            ERROR_BUFFER_OVERFLOW => {
                // The call reported how much it wants. Round up to whole words
                // and add a margin, because the table can grow between calls.
                words = (usize::try_from(size).unwrap_or(0) / 8) + 512;
            }
            other => {
                return Err(oserr::from_status(
                    Win32Error(other),
                    "GetAdaptersAddresses",
                    Context::InterfaceQuery,
                ))
            }
        }
    }
    Err(oserr::from_status(
        Win32Error(ERROR_BUFFER_OVERFLOW),
        "GetAdaptersAddresses",
        Context::InterfaceQuery,
    ))
}

/// Where a callback puts what it decoded.
struct Sink {
    tx: tokio::sync::mpsc::Sender<NetworkChange>,
    lost: Mutex<DropLedger>,
}

impl Sink {
    /// Enqueues one change, counting it as lost if there is no room.
    ///
    /// Never blocks: this runs on an IP Helper worker thread.
    fn emit(&self, change: NetworkChange) {
        let mut ledger = self
            .lost
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // The marker goes first, so it is ordered *before* the change that
        // follows the gap it announces rather than after it.
        if let Some(marker) = ledger.marker() {
            if self.tx.try_send(marker).is_ok() {
                ledger.clear();
            }
        }
        // Only a FULL channel is a dropped event the core needs to hear about.
        // A CLOSED one means the core dropped the stream, so there is nothing to
        // record and nowhere to record it; the subscription is cancelled when
        // `Subscription` drops. The two are written as one arm because the
        // *action* is the same — do nothing — and the distinction that matters
        // is the one the `if let` makes.
        if let Err(tokio::sync::mpsc::error::TrySendError::Full(_)) = self.tx.try_send(change) {
            ledger.record();
        }
    }
}

/// Turns a context pointer back into the sink, without taking ownership.
///
/// # Safety
///
/// `context` must be a pointer produced by `Arc::into_raw` on a `Sink` that is
/// still alive — which every registration's context is until
/// [`Subscription::drop`] has cancelled it.
unsafe fn sink_of(context: *const c_void) -> Option<&'static Sink> {
    if context.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees the pointee outlives this borrow.
    Some(unsafe { &*context.cast::<Sink>() })
}

unsafe extern "system" fn on_interface(
    context: *const c_void,
    row: *const ip::MIB_IPINTERFACE_ROW,
    kind: ip::MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: `context` is the pointer handed to `NotifyIpInterfaceChange`,
    // which stays alive until the matching `CancelMibChangeNotify2` returns.
    let Some(sink) = (unsafe { sink_of(context) }) else {
        return;
    };
    let Some(kind) = NotificationType::from_raw(kind) else {
        return;
    };
    // A `MibDeleteInstance` may carry a null row; the index then comes from
    // nowhere and there is nothing to report.
    if row.is_null() {
        return;
    }
    // SAFETY: non-null, and IP Helper owns the row for the callback's duration.
    let row = unsafe { &*row };
    if let Some(change) = decode_change(&Notification::Interface {
        index: InterfaceIndex(row.InterfaceIndex),
        connected: row.Connected,
        kind,
    }) {
        sink.emit(change);
    }
}

unsafe extern "system" fn on_address(
    context: *const c_void,
    row: *const ip::MIB_UNICASTIPADDRESS_ROW,
    kind: ip::MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: as in `on_interface`.
    let Some(sink) = (unsafe { sink_of(context) }) else {
        return;
    };
    let Some(kind) = NotificationType::from_raw(kind) else {
        return;
    };
    if row.is_null() {
        return;
    }
    // SAFETY: non-null, and owned by IP Helper for the callback's duration.
    let row = unsafe { &*row };
    // SAFETY: `SOCKADDR_INET` is a union; reading it as bytes of its own size is
    // what `parse_sockaddr` expects, and every member is plain data.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            (&raw const row.Address).cast::<u8>(),
            size_of::<ws::SOCKADDR_INET>(),
        )
    };
    let Ok(sockaddr) = crate::sock::parse_sockaddr(bytes, "NotifyUnicastIpAddressChange") else {
        return;
    };
    let Ok(address) = crate::sock::address_from_raw(sockaddr, "NotifyUnicastIpAddressChange")
    else {
        return;
    };
    if let Some(change) = decode_change(&Notification::Address {
        index: InterfaceIndex(row.InterfaceIndex),
        address,
        kind,
    }) {
        sink.emit(change);
    }
}

unsafe extern "system" fn on_route(
    context: *const c_void,
    row: *const ip::MIB_IPFORWARD_ROW2,
    kind: ip::MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: as in `on_interface`.
    let Some(sink) = (unsafe { sink_of(context) }) else {
        return;
    };
    let Some(kind) = NotificationType::from_raw(kind) else {
        return;
    };
    if row.is_null() {
        return;
    }
    // SAFETY: non-null, and owned by IP Helper for the callback's duration.
    let row = unsafe { &*row };
    // SAFETY: the union's `si_family` overlaps every member's first field.
    let family = match unsafe { row.DestinationPrefix.Prefix.si_family } {
        ws::AF_INET => AddressFamily::V4,
        ws::AF_INET6 => AddressFamily::V6,
        _ => return,
    };
    if let Some(change) = decode_change(&Notification::Route {
        family,
        prefix_len: row.DestinationPrefix.PrefixLength,
        kind,
    }) {
        sink.emit(change);
    }
}

/// A registration handle plus the context it borrows.
///
/// `HANDLE` is a raw pointer and therefore not `Send` by default, but the value
/// is an opaque token IP Helper owns; nothing dereferences it here, and it is
/// only ever passed back to `CancelMibChangeNotify2`. The same is true of the
/// context pointer, which is an `Arc` this type owns one strong reference to.
struct Registration {
    handle: HANDLE,
    context: *const Sink,
}

// SAFETY: neither field is dereferenced on this thread except in `Drop`, and
// the values themselves are thread-agnostic — `HANDLE` is an opaque kernel
// token and `context` is an `Arc` pointer whose pointee is `Sync`.
unsafe impl Send for Registration {}

/// The three registrations, cancelled together.
struct Subscription {
    registrations: Vec<Registration>,
}

impl Drop for Subscription {
    fn drop(&mut self) {
        for registration in self.registrations.drain(..) {
            // SAFETY: `handle` came from a successful `Notify*` call and has not
            // been cancelled. `CancelMibChangeNotify2` waits for any in-flight
            // callback to return, so no callback can be holding `context` once
            // it has.
            unsafe {
                ip::CancelMibChangeNotify2(registration.handle);
            }
            // SAFETY: one strong reference was leaked per registration by
            // `Arc::into_raw`; this reclaims exactly that one, after the cancel
            // above has guaranteed no callback still borrows it.
            unsafe {
                drop(Arc::from_raw(registration.context));
            }
        }
    }
}

/// The stream, which owns the registrations so dropping it cancels them.
struct WindowsChangeStream {
    inner: ChangeStream,
    _subscription: Subscription,
}

impl Stream for WindowsChangeStream {
    type Item = NetworkChange;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(cx)
    }
}

/// Registers for the three change notifications.
pub(super) fn subscribe(
    _shutdown: ShutdownLatch,
) -> Result<Pin<Box<dyn Stream<Item = NetworkChange> + Send>>, PlatformError> {
    let (tx, rx) = tokio::sync::mpsc::channel(CHANGE_QUEUE);
    let sink = Arc::new(Sink {
        tx,
        lost: Mutex::new(DropLedger::new()),
    });
    let mut subscription = Subscription {
        registrations: Vec::with_capacity(3),
    };

    // `initialnotification: false` on every one: the stream carries changes and
    // not the initial state, and `decode_change` drops an initial notification
    // anyway. Asking for one we would then discard is a burst of work at the
    // moment the agent is busiest.
    let mut handle: HANDLE = std::ptr::null_mut();
    let context = Arc::into_raw(Arc::clone(&sink));
    // SAFETY: `handle` is a live out-parameter and `context` is a leaked strong
    // reference that `Subscription::drop` reclaims after cancelling. The
    // callback is a plain `extern "system"` function with no captured state.
    let status = unsafe {
        ip::NotifyIpInterfaceChange(
            ws::AF_UNSPEC,
            Some(on_interface),
            context.cast::<c_void>(),
            false,
            &raw mut handle,
        )
    };
    if status != NO_ERROR {
        // SAFETY: the registration failed, so no callback can hold the
        // reference; reclaiming it here is the only way it is freed.
        unsafe { drop(Arc::from_raw(context)) };
        return Err(oserr::from_status(
            Win32Error(status),
            "NotifyIpInterfaceChange",
            Context::InterfaceQuery,
        ));
    }
    subscription
        .registrations
        .push(Registration { handle, context });

    let mut handle: HANDLE = std::ptr::null_mut();
    let context = Arc::into_raw(Arc::clone(&sink));
    // SAFETY: as above.
    let status = unsafe {
        ip::NotifyUnicastIpAddressChange(
            ws::AF_UNSPEC,
            Some(on_address),
            context.cast::<c_void>(),
            false,
            &raw mut handle,
        )
    };
    if status != NO_ERROR {
        // SAFETY: as above.
        unsafe { drop(Arc::from_raw(context)) };
        return Err(oserr::from_status(
            Win32Error(status),
            "NotifyUnicastIpAddressChange",
            Context::InterfaceQuery,
        ));
    }
    subscription
        .registrations
        .push(Registration { handle, context });

    let mut handle: HANDLE = std::ptr::null_mut();
    let context = Arc::into_raw(Arc::clone(&sink));
    // SAFETY: as above.
    let status = unsafe {
        ip::NotifyRouteChange2(
            ws::AF_UNSPEC,
            Some(on_route),
            context.cast::<c_void>(),
            false,
            &raw mut handle,
        )
    };
    if status != NO_ERROR {
        // SAFETY: as above.
        unsafe { drop(Arc::from_raw(context)) };
        return Err(oserr::from_status(
            Win32Error(status),
            "NotifyRouteChange2",
            Context::InterfaceQuery,
        ));
    }
    subscription
        .registrations
        .push(Registration { handle, context });

    Ok(Box::pin(WindowsChangeStream {
        inner: ChangeStream::new(rx),
        _subscription: subscription,
    }))
}
