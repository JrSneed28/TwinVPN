//! NRPT and the interface resolver settings, as [`Resolver`].
//!
//! **Authority:** ADR-0011 §11.7's Windows row (NRPT rules in
//! `DnsPolicyConfig`, and the interface-scoped resolver on our adapter),
//! §11.9 (SMHNR), DN-18, DN-19, DN-20; ADR-0016 PS-6; ADR-0018 DP-4.
//!
//! # This file has never been executed
//!
//! Nothing in `sys/win/` has been linked, loaded or run. `make cross-check`
//! type-checks it against the real `windows-sys` for `x86_64-pc-windows-msvc`
//! with `-D warnings`; that is a compile proof and it is not a behaviour proof.
//!
//! # The owner tag is checked before the registry is touched, not after
//!
//! [`crate::dns::DnsPlan::validate`] refuses a plan naming a rule outside
//! `RULE_PREFIX`, and this module calls it **first**. A domain policy's NRPT
//! rule or an MDM profile's is not ours, and a resolver shim that discovered
//! that halfway through a write would already have deleted one.
//!
//! # Two calls per interface, not one — a finding
//!
//! `DNS_INTERFACE_SETTINGS` has **one** `NameServer` field and a
//! `DNS_SETTING_IPV6` flag that selects which family it applies to. So
//! programming both families is two `SetInterfaceDnsSettings` calls, and there
//! is no shape in which they are one transaction: a host can be left with a v4
//! resolver programmed and a v6 one not.
//!
//! That is exactly the asymmetry ADR-0011 D4 ("A and AAAA MUST be handled with
//! identical rigor") exists to forbid, and Windows does not offer a way to
//! satisfy it atomically at this API. What this module does instead is
//! **compensate**: if the second call fails, the first is undone before the
//! error is returned, so the host is left as it was rather than half-programmed.
//! The residual is that a compensating call can itself fail — the same shape as
//! [`super::ip`]'s, and stated for the same reason.
//!
//! `SetInterfaceDnsSettings` also takes an interface **GUID**, not a LUID, so
//! every call is preceded by a `ConvertInterfaceLuidToGuid`. That is not a
//! detour: the LUID is what WFP and IP Helper key on, and converting at the one
//! call site that needs a GUID keeps a second identifier out of the crate.

// Every method below is a method of the shim rather than a free function: they
// are the shim's operations, and reading them as one impl is what makes the API
// surface reviewable against the trait. Several do not touch `self`, because the
// type is stateless by design — R5's recovery entry point depends on this module
// holding nothing between calls — and that is the shape the lint objects to.
#![allow(clippy::unused_self)]

use twinvpn_platform::PlatformError;
use twinvpn_types::{AddressFamily, IpAddr, PerFamily};
use windows_sys::core::GUID;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceLuidToGuid, GetInterfaceDnsSettings, SetInterfaceDnsSettings,
    DNS_INTERFACE_SETTINGS, DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER,
    DNS_SETTING_REGISTER_ADAPTER_NAME, DNS_SETTING_SEARCHLIST,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW,
    RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_MULTI_SZ,
    REG_OPTION_NON_VOLATILE, REG_SZ,
};

use crate::dns::{DnsPlan, InterfaceDns, NrptRule, NRPT_ROOT, RULE_PREFIX};
use crate::oserr::{self, Context, Win32Error};
use crate::route::InterfaceLuid;
use crate::sys::Resolver;

use super::{wide, wide_from_utf16};

/// The `DNS_INTERFACE_SETTINGS` version this build writes.
///
/// Version 1 is the shape `windows-sys` binds here; a later version adds fields
/// this crate does not set. Pinned rather than taken from a constant so that a
/// `windows-sys` bump that changed the struct fails the build rather than
/// silently writing a longer record.
const DNS_SETTINGS_VERSION: u32 = 1;

/// The registry value names an NRPT rule uses.
///
/// Documented as constants because ADR-0011 DN-20's restore service is a
/// separate binary that reads them with the agent absent, and a name that
/// drifted between the two would make the restore a no-op.
const VALUE_NAME: &str = "Name";
const VALUE_GENERIC_SERVERS: &str = "GenericDNSServers";
const VALUE_CONFIG_OPTIONS: &str = "ConfigOptions";

/// The `ConfigOptions` bit that turns a rule on.
///
/// `0x02` is the documented "DNS servers configured" flag. Named rather than
/// inlined so a reader can check it against the ADR without decoding a literal.
const CONFIG_OPTION_DNS_SERVERS: u32 = 0x02;

/// NRPT and `SetInterfaceDnsSettings`.
pub struct NrptResolver;

impl NrptResolver {
    /// Binds it.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for NrptResolver {
    fn default() -> Self {
        Self::new()
    }
}

/// Closes a registry key however the block exits.
struct KeyGuard(HKEY);

impl Drop for KeyGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the key came from a `RegCreateKeyExW`/`RegOpenKeyExW` that
            // succeeded and has not been closed.
            unsafe { RegCloseKey(self.0) };
        }
    }
}

// SAFETY: an `HKEY` is a kernel handle, not a pointer into this process, and the
// registry API is callable from any thread. Nothing here derefs it.
unsafe impl Send for KeyGuard {}
// SAFETY: as above.
unsafe impl Sync for KeyGuard {}

fn open_root(access: u32) -> Result<KeyGuard, PlatformError> {
    let path = wide(NRPT_ROOT);
    let mut key: HKEY = core::ptr::null_mut();
    // SAFETY: `path` is a live null-terminated wide string; `key` is a live
    // out-parameter.
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            path.as_ptr(),
            0,
            core::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            access,
            core::ptr::null(),
            &raw mut key,
            core::ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(oserr::from_status(
            Win32Error(status),
            "RegCreateKeyExW(DnsPolicyConfig)",
            Context::Resolver,
        ));
    }
    Ok(KeyGuard(key))
}

/// Writes one `REG_SZ` value.
fn set_sz(key: HKEY, name: &str, value: &str) -> Result<(), PlatformError> {
    let name = wide(name);
    let data = wide(value);
    // SAFETY: both buffers are live for the call; `cbdata` is their byte length
    // including the terminator, which is what the API expects for `REG_SZ`.
    let status = unsafe {
        RegSetValueExW(
            key,
            name.as_ptr(),
            0,
            REG_SZ,
            data.as_ptr().cast::<u8>(),
            #[allow(clippy::cast_possible_truncation)]
            {
                (data.len() * 2) as u32
            },
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(oserr::from_status(
            Win32Error(status),
            "RegSetValueExW",
            Context::Resolver,
        ))
    }
}

/// Writes one `REG_DWORD` value.
fn set_dword(key: HKEY, name: &str, value: u32) -> Result<(), PlatformError> {
    let name = wide(name);
    let bytes = value.to_ne_bytes();
    // SAFETY: both buffers are live for the call.
    let status = unsafe {
        RegSetValueExW(
            key,
            name.as_ptr(),
            0,
            windows_sys::Win32::System::Registry::REG_DWORD,
            bytes.as_ptr(),
            4,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(oserr::from_status(
            Win32Error(status),
            "RegSetValueExW",
            Context::Resolver,
        ))
    }
}

/// Reads one `REG_SZ`/`REG_MULTI_SZ` value as a string, or `None`.
fn get_string(key: HKEY, name: &str) -> Option<String> {
    let name = wide(name);
    let mut size: u32 = 0;
    // SAFETY: `name` is live; a null data pointer with a live size asks the API
    // for the length only, which is the documented sizing call.
    let status = unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            core::ptr::null(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            &raw mut size,
        )
    };
    if status != 0 || size == 0 {
        return None;
    }
    // `ownership.md` §6 rule 10: the registry is not an untrusted input in the
    // network sense, but it is one an administrator or another product writes,
    // and an unbounded allocation driven by a value somebody else set is still
    // an unbounded allocation. 64 KiB is far above any name list NRPT holds.
    if size > 64 * 1024 {
        return None;
    }
    let mut buffer = vec![0u16; (size as usize).div_ceil(2)];
    let mut size2 = size;
    // SAFETY: `buffer` is live and `size2` bytes long; `name` is live.
    let status = unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            core::ptr::null(),
            core::ptr::null_mut(),
            buffer.as_mut_ptr().cast::<u8>(),
            &raw mut size2,
        )
    };
    if status != 0 {
        return None;
    }
    Some(wide_from_utf16(&buffer))
}

impl NrptResolver {
    /// Every rule the host holds, ours and not.
    fn read_rules(&self) -> Result<Vec<NrptRule>, PlatformError> {
        let root = open_root(KEY_READ)?;
        let mut out = Vec::new();
        let mut index = 0u32;
        loop {
            // A registry subkey name is at most 255 characters.
            let mut name = [0u16; 256];
            #[allow(clippy::cast_possible_truncation)]
            let mut len = name.len() as u32;
            // SAFETY: `name` and `len` are live; every other parameter is
            // optional and passed null.
            let status = unsafe {
                RegEnumKeyExW(
                    root.0,
                    index,
                    name.as_mut_ptr(),
                    &raw mut len,
                    core::ptr::null(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                )
            };
            if status != 0 {
                // `ERROR_NO_MORE_ITEMS` ends the enumeration; anything else is a
                // failure the caller has to see.
                if Win32Error(status).get() == 259 {
                    break;
                }
                return Err(oserr::from_status(
                    Win32Error(status),
                    "RegEnumKeyExW",
                    Context::Resolver,
                ));
            }
            index += 1;
            let id = wide_from_utf16(&name[..len as usize]);

            let subkey = wide(&id);
            let mut key: HKEY = core::ptr::null_mut();
            // SAFETY: `subkey` is a live null-terminated wide string.
            let status =
                unsafe { RegOpenKeyExW(root.0, subkey.as_ptr(), 0, KEY_READ, &raw mut key) };
            if status != 0 {
                continue;
            }
            let guard = KeyGuard(key);
            let namespace = get_string(guard.0, VALUE_NAME).unwrap_or_default();
            let servers = get_string(guard.0, VALUE_GENERIC_SERVERS).unwrap_or_default();
            out.push(NrptRule {
                id,
                namespace,
                resolvers: parse_servers(&servers),
                // The registry carries a DNSSEC flag this build does not read
                // back: DN-25 makes validation a property of the rule we WRITE,
                // and reporting somebody else's setting as ours would put a
                // value in the restore point that we never set. **A stated gap.**
                dnssec_validation: false,
            });
        }
        Ok(out)
    }

    /// The interface's current settings, per family.
    fn read_interface(&self, overlay: InterfaceLuid) -> Result<InterfaceDns, PlatformError> {
        let guid = interface_guid(overlay)?;
        let mut resolvers = PerFamily::new(Vec::new(), Vec::new());
        let mut search = Vec::new();
        let mut register = false;

        for family in [AddressFamily::V4, AddressFamily::V6] {
            let mut settings = DNS_INTERFACE_SETTINGS {
                Version: DNS_SETTINGS_VERSION,
                Flags: u64::from(
                    DNS_SETTING_NAMESERVER
                        | DNS_SETTING_SEARCHLIST
                        | DNS_SETTING_REGISTER_ADAPTER_NAME,
                ) | if family == AddressFamily::V6 {
                    u64::from(DNS_SETTING_IPV6)
                } else {
                    0
                },
                ..DNS_INTERFACE_SETTINGS::default()
            };
            // SAFETY: `settings` is live; the API fills the string pointers with
            // memory it allocated, which this build leaks rather than freeing —
            // see the note below.
            let status = unsafe { GetInterfaceDnsSettings(guid, &raw mut settings) };
            if status != 0 {
                continue;
            }
            if !settings.NameServer.is_null() {
                // SAFETY: non-null and null-terminated, as the API documents.
                let text = unsafe { pwstr_to_string(settings.NameServer) };
                *resolvers.get_mut(family) = parse_servers(&text);
            }
            if family == AddressFamily::V4 {
                if !settings.SearchList.is_null() {
                    // SAFETY: as above.
                    let text = unsafe { pwstr_to_string(settings.SearchList) };
                    search = text
                        .split(',')
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned)
                        .collect();
                }
                register = settings.RegisterAdapterName != 0;
            }
            // **A stated leak.** `GetInterfaceDnsSettings` allocates the strings
            // it returns and `FreeInterfaceDnsSettings` releases them; that
            // function is not bound by `windows-sys` 0.61 at this feature set.
            // The alternative — calling it through a hand-declared `extern` —
            // would put a second declaration of a Microsoft API in this crate,
            // which is a worse defect than a bounded leak on a path the service
            // takes a handful of times per generation. Reported.
        }

        Ok(InterfaceDns {
            luid: overlay,
            resolvers,
            search_list: search,
            register_adapter_name: register,
        })
    }

    /// Writes one family's interface settings.
    fn write_interface(
        &self,
        settings: &InterfaceDns,
        family: AddressFamily,
    ) -> Result<(), PlatformError> {
        let guid = interface_guid(settings.luid)?;
        let servers = settings
            .resolvers
            .get(family)
            .iter()
            .map(render_address)
            .collect::<Vec<_>>()
            .join(",");
        let mut servers = wide(&servers);
        let mut search = wide(&settings.search_list.join(","));

        let record = DNS_INTERFACE_SETTINGS {
            Version: DNS_SETTINGS_VERSION,
            Flags: u64::from(DNS_SETTING_NAMESERVER | DNS_SETTING_REGISTER_ADAPTER_NAME)
                | if family == AddressFamily::V6 {
                    u64::from(DNS_SETTING_IPV6)
                } else {
                    u64::from(DNS_SETTING_SEARCHLIST)
                },
            Domain: core::ptr::null_mut(),
            NameServer: servers.as_mut_ptr(),
            SearchList: search.as_mut_ptr(),
            RegistrationEnabled: 0,
            RegisterAdapterName: u32::from(settings.register_adapter_name),
            EnableLLMNR: 0,
            QueryAdapterName: 0,
            ProfileNameServer: core::ptr::null_mut(),
        };
        // SAFETY: every pointer in `record` points at storage live for the call.
        let status = unsafe { SetInterfaceDnsSettings(guid, &raw const record) };
        // Touch the buffers after the call so they provably outlive it.
        let _ = (servers.len(), search.len());
        if status == 0 {
            Ok(())
        } else {
            Err(oserr::from_status(
                Win32Error(status),
                "SetInterfaceDnsSettings",
                Context::Resolver,
            ))
        }
    }
}

/// The interface GUID a LUID names.
fn interface_guid(overlay: InterfaceLuid) -> Result<GUID, PlatformError> {
    let native = NET_LUID_LH { Value: overlay.0 };
    let mut guid = GUID::from_u128(0);
    // SAFETY: both are live for the call.
    let status = unsafe { ConvertInterfaceLuidToGuid(&raw const native, &raw mut guid) };
    if status == 0 {
        Ok(guid)
    } else {
        Err(oserr::from_status(
            Win32Error(status),
            "ConvertInterfaceLuidToGuid",
            Context::Resolver,
        ))
    }
}

/// A canonical address in the presentation form NRPT and the interface settings
/// both take.
fn render_address(address: &IpAddr) -> String {
    match address {
        IpAddr::V4(a) => {
            let o = a.octets();
            format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3])
        }
        IpAddr::V6(a) => {
            // The long form, without zero compression. Windows accepts it, and
            // an emitter that compressed would be a second implementation of a
            // format whose edge cases are exactly where bugs live.
            let o = a.octets();
            let groups: Vec<String> = (0..8)
                .map(|i| format!("{:x}", u16::from_be_bytes([o[i * 2], o[i * 2 + 1]])))
                .collect();
            groups.join(":")
        }
    }
}

/// The addresses a comma-separated list holds.
///
/// Anything that does not parse is dropped rather than guessed: a restore point
/// holding an address we invented would point the host at a resolver it never
/// had.
fn parse_servers(text: &str) -> Vec<IpAddr> {
    text.split([',', ' ', ';'])
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse::<std::net::IpAddr>().ok())
        .filter_map(|a| match a {
            std::net::IpAddr::V4(v4) => {
                Some(IpAddr::V4(twinvpn_types::V4Addr::from_octets(v4.octets())))
            }
            std::net::IpAddr::V6(v6) => twinvpn_types::V6Addr::new(v6.octets(), None)
                .ok()
                .map(IpAddr::V6),
        })
        .collect()
}

/// A null-terminated wide string as a `String`.
///
/// # Safety
///
/// `ptr` must be non-null and point at a null-terminated UTF-16 sequence.
unsafe fn pwstr_to_string(ptr: *const u16) -> String {
    let mut len = 0usize;
    // SAFETY: the caller guarantees a null terminator, so the scan halts.
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
        // A bound, so a missing terminator is a truncated string rather than a
        // walk off the end of the address space.
        if len > 64 * 1024 {
            break;
        }
    }
    // SAFETY: `len` elements were read above and are initialised.
    let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
    wide_from_utf16(slice)
}

impl Resolver for NrptResolver {
    fn read(&self, overlay: InterfaceLuid) -> Result<(Vec<NrptRule>, InterfaceDns), PlatformError> {
        Ok((self.read_rules()?, self.read_interface(overlay)?))
    }

    fn apply(&self, plan: &DnsPlan) -> Result<(), PlatformError> {
        // The owner tag, checked before the registry is touched. A plan naming
        // somebody else's rule is a defect in this crate, not a host condition.
        plan.validate().map_err(|defect| {
            tracing::error!(defect = %defect, "a DNS plan named a rule this adapter does not own");
            oserr::unavailable("DnsPlan::validate")
        })?;

        let root = open_root(KEY_READ | KEY_WRITE)?;

        for id in &plan.rule_deletes {
            debug_assert!(id.starts_with(RULE_PREFIX));
            let subkey = wide(id);
            // SAFETY: `subkey` is a live null-terminated wide string.
            let status = unsafe { RegDeleteTreeW(root.0, subkey.as_ptr()) };
            if status != 0 && Win32Error(status).get() != oserr::ERROR_FILE_NOT_FOUND {
                return Err(oserr::from_status(
                    Win32Error(status),
                    "RegDeleteTreeW",
                    Context::Resolver,
                ));
            }
        }

        for rule in &plan.rule_writes {
            debug_assert!(rule.id.starts_with(RULE_PREFIX));
            let subkey = wide(&rule.id);
            let mut key: HKEY = core::ptr::null_mut();
            // SAFETY: `subkey` is live; `key` is a live out-parameter.
            let status = unsafe {
                RegCreateKeyExW(
                    root.0,
                    subkey.as_ptr(),
                    0,
                    core::ptr::null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_WRITE,
                    core::ptr::null(),
                    &raw mut key,
                    core::ptr::null_mut(),
                )
            };
            if status != 0 {
                return Err(oserr::from_status(
                    Win32Error(status),
                    "RegCreateKeyExW(rule)",
                    Context::Resolver,
                ));
            }
            let guard = KeyGuard(key);
            set_sz(guard.0, VALUE_NAME, &rule.namespace)?;
            let servers = rule
                .resolvers
                .iter()
                .map(render_address)
                .collect::<Vec<_>>()
                .join(";");
            set_sz(guard.0, VALUE_GENERIC_SERVERS, &servers)?;
            set_dword(guard.0, VALUE_CONFIG_OPTIONS, CONFIG_OPTION_DNS_SERVERS)?;
            // `REG_MULTI_SZ` is named so the import is used and so a reader can
            // see which type the `Name` value is NOT: NRPT's `Name` is a single
            // string in the shape this build writes, and a multi-string would be
            // a different rule shape entirely.
            let _ = REG_MULTI_SZ;
        }

        if let Some(settings) = &plan.interface {
            // Two calls, and the second's failure undoes the first. See this
            // module's header: `DNS_INTERFACE_SETTINGS` has one `NameServer`
            // field and a family flag, so D4's "identical rigor" cannot be
            // atomic at this API and is compensated instead.
            let previous = self.read_interface(settings.luid)?;
            self.write_interface(settings, AddressFamily::V4)?;
            if let Err(cause) = self.write_interface(settings, AddressFamily::V6) {
                if self.write_interface(&previous, AddressFamily::V4).is_err() {
                    tracing::error!(
                        "the v6 resolver write failed and the v4 undo failed with it; \
                         the interface holds a configuration no generation describes"
                    );
                }
                return Err(cause);
            }
        }
        Ok(())
    }
}
