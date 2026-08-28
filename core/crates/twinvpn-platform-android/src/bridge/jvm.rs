//! The JNI-backed [`TunnelController`] and [`KeystoreElement`].
//!
//! **Authority:** `docs/implementation/ownership.md` §10.4 ("Swift and Kotlin
//! marshal; they do not decide"), §6 rule 11; ADR-0018 CB-2, CB-5, CB-7, PB-1;
//! ADR-0012 KS-9(1); ADR-0020 §11's Android rows.
//!
//! **`#[cfg(target_os = "android")]`. `cargo check`ed against the real `jni` and
//! bionic crates by `make cross-check`; never linked, never run.**
//!
//! # Why the `Builder` walk is in Rust
//!
//! [`crate::builder::render`] produces a [`Programme`] — an ordered list of
//! typed operations. Something has to walk it and make the corresponding
//! `VpnService.Builder` calls, and there were two places to put the loop:
//!
//! | Where the walk lives | What Kotlin has to be | `ownership.md` §9.2 row |
//! |---|---|---|
//! | Kotlin decodes an encoded programme | a decoder with a `when` over op tags | **written, not compiled** |
//! | **Rust calls each `Builder` method over JNI** | eight one-line methods, no branching | **compiled** |
//!
//! The second is chosen. Every Kotlin method this module calls is a single
//! `builder.addRoute(…)`-shaped statement with no condition in it, so there is
//! no Kotlin code path that could hold a decision, and the loop that *is* a
//! decision — which ops, in which order — is type-checked for the real target.
//!
//! # Secrets and logging
//!
//! §6 rule 11: never log private keys, session keys, tunnel payloads, pairing
//! secrets or tokens. Nothing in this module logs a value; the Java exception
//! *message* is deliberately never read (see [`crate::oserr::from_java_exception`]),
//! only its class name.

use std::sync::Arc;

use jni::objects::{GlobalRef, JByteArray, JObject, JString, JValue};
use jni::JavaVM;

use twinvpn_platform::PlatformError;
use twinvpn_types::IpAddr;

use crate::builder::{BuilderOp, Programme};
use crate::hostcall::{RawFd, TunnelController};
use crate::oserr::{self, Context};
use crate::power::KeepalivePlan;

mod keystore;

/// The Kotlin object both implementations call into.
///
/// One global reference, held for the life of the process, so no JNI local
/// reference outlives the frame that made it.
#[derive(Debug)]
pub struct JvmHost {
    vm: Arc<JavaVM>,
    host: GlobalRef,
}

impl JvmHost {
    /// Wraps the `net.twinvpn.android.NativeHost` instance the shell registered.
    #[must_use]
    pub const fn new(vm: Arc<JavaVM>, host: GlobalRef) -> Self {
        Self { vm, host }
    }

    /// Calls one method, mapping a pending exception onto the seam's vocabulary.
    ///
    /// The exception is **cleared** before the error is built: leaving one
    /// pending makes the next JNI call in this thread fail for a reason that has
    /// nothing to do with it, which is how a single Keystore refusal becomes a
    /// cascade nobody can read.
    fn call<T>(
        &self,
        method: &'static str,
        signature: &'static str,
        args: &[JValue<'_, '_>],
        context: Context,
        extract: impl for<'a> FnOnce(
            &mut jni::JNIEnv<'a>,
            jni::objects::JValueOwned<'a>,
        ) -> Result<T, PlatformError>,
    ) -> Result<T, PlatformError> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| oserr::unavailable(method, libc::ESRCH))?;

        let Ok(value) = env.call_method(&self.host, method, signature, args) else {
            let class = describe_pending_exception(&mut env);
            return Err(oserr::from_java_exception(&class, method, context));
        };
        extract(&mut env, value)
    }
}

/// The class name of the pending exception, with the exception cleared.
///
/// Returns `"java.lang.Throwable"` when the class cannot be read, so the caller
/// always has a name to map. **The message is never read** — it is localised,
/// vendor-variable, and on the Keystore path can quote a key alias.
fn describe_pending_exception(env: &mut jni::JNIEnv<'_>) -> String {
    let Ok(throwable) = env.exception_occurred() else {
        return "java.lang.Throwable".to_owned();
    };
    let _ = env.exception_clear();
    let name = (|| -> Result<String, jni::errors::Error> {
        let class = env.call_method(&throwable, "getClass", "()Ljava/lang/Class;", &[])?;
        let class = class.l()?;
        let name = env.call_method(&class, "getName", "()Ljava/lang/String;", &[])?;
        let name: JString<'_> = name.l()?.into();
        let text: String = env.get_string(&name)?.into();
        Ok(text)
    })();
    // A failure to read the class name must not itself throw on the way out.
    let _ = env.exception_clear();
    name.unwrap_or_else(|_| "java.lang.Throwable".to_owned())
}

/// Copies a Rust slice into a fresh Java `byte[]`.
fn to_java_bytes<'a>(
    env: &mut jni::JNIEnv<'a>,
    bytes: &[u8],
) -> Result<JByteArray<'a>, PlatformError> {
    let array = env
        .byte_array_from_slice(bytes)
        .map_err(|_| oserr::unavailable("byte_array_from_slice", libc::ENOMEM))?;
    Ok(array)
}

/// Copies a Java `byte[]` (or `null`) into a Rust `Vec`.
fn from_java_bytes(
    env: &mut jni::JNIEnv<'_>,
    object: JObject<'_>,
) -> Result<Option<Vec<u8>>, PlatformError> {
    if object.is_null() {
        return Ok(None);
    }
    let array: JByteArray<'_> = object.into();
    let bytes = env
        .convert_byte_array(&array)
        .map_err(|_| oserr::unavailable("convert_byte_array", libc::ENOMEM))?;
    Ok(Some(bytes))
}

// ---------------------------------------------------------------------------
// TunnelController
// ---------------------------------------------------------------------------

impl TunnelController for JvmHost {
    fn name(&self) -> &'static str {
        "vpnservice"
    }

    fn establish(&self, programme: &Programme) -> Result<RawFd, PlatformError> {
        // A fresh `VpnService.Builder`. Every previous partial configuration is
        // discarded, so a failed apply cannot leave half a programme behind --
        // `docs/networking.md` §2.3's partial-application window, closed by
        // construction.
        self.call("builderReset", "()V", &[], Context::TunnelDevice, |_, _| {
            Ok(())
        })?;

        for op in &programme.ops {
            self.apply_op(op)?;
        }

        // `establish()` returns the DETACHED descriptor. PB-1: one JNI call at
        // setup, then direct reads -- zero crossings per packet.
        let fd = self.call(
            "builderEstablish",
            "()I",
            &[],
            Context::TunnelDevice,
            |_, value| {
                value
                    .i()
                    .map_err(|_| oserr::unavailable("builderEstablish", libc::EPROTO))
            },
        )?;
        if fd < 0 {
            // `establish()` returns null when consent is absent or another app
            // holds the slot; the Kotlin side reports that as -1.
            return Err(PlatformError::VpnPermissionDenied(Some(
                oserr::detail_from_code(fd, "VpnService.Builder.establish"),
            )));
        }
        Ok(fd)
    }

    fn close_tun(&self, fd: RawFd) -> Result<(), PlatformError> {
        self.call(
            "closeTun",
            "(I)V",
            &[JValue::Int(fd)],
            Context::TunnelDevice,
            |_, _| Ok(()),
        )
    }

    fn set_underlying_networks(&self, handles: &[u64]) -> Result<(), PlatformError> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| oserr::unavailable("setUnderlyingNetworks", libc::ESRCH))?;
        let array = env
            .new_long_array(i32::try_from(handles.len()).unwrap_or(i32::MAX))
            .map_err(|_| oserr::unavailable("new_long_array", libc::ENOMEM))?;
        // A Java `long` is signed and the handle came from Java as one, so the
        // conversion is bit-preserving rather than numeric: `networkHandle` is
        // an opaque token and its VALUE has no meaning, only its identity.
        let as_i64: Vec<i64> = handles
            .iter()
            .map(|h| i64::from_ne_bytes(h.to_ne_bytes()))
            .collect();
        env.set_long_array_region(&array, 0, &as_i64)
            .map_err(|_| oserr::unavailable("set_long_array_region", libc::ENOMEM))?;
        let outcome = env.call_method(
            &self.host,
            "setUnderlyingNetworks",
            "([J)V",
            &[JValue::Object(&array)],
        );
        if outcome.is_err() {
            let class = describe_pending_exception(&mut env);
            return Err(oserr::from_java_exception(
                &class,
                "setUnderlyingNetworks",
                Context::Connectivity,
            ));
        }
        Ok(())
    }

    fn protect_socket(&self, fd: RawFd) -> Result<(), PlatformError> {
        // KS-9(1) on Android is NOT "by construction": an unprotected socket in
        // a process holding a 0.0.0.0/0 claim sends into our own tunnel. A
        // `false` return is a refusal, not a warning.
        let protected = self.call(
            "protectSocket",
            "(I)Z",
            &[JValue::Int(fd)],
            Context::Socket,
            |_, value| {
                value
                    .z()
                    .map_err(|_| oserr::unavailable("protectSocket", libc::EPROTO))
            },
        )?;
        if protected {
            Ok(())
        } else {
            Err(PlatformError::NotPermitted(Some(oserr::detail_from_code(
                fd,
                "VpnService.protect",
            ))))
        }
    }

    fn request_keepalive(&self, fd: RawFd, plan: KeepalivePlan) -> Result<(), PlatformError> {
        // An `Unavailable` plan is a no-op that succeeds: the core has already
        // been told the platform cannot serve the interval, and failing here as
        // well would report one condition twice.
        let KeepalivePlan::KernelSocketKeepalive { interval_secs } = plan else {
            return Ok(());
        };
        self.call(
            "requestKeepalive",
            "(II)V",
            &[
                JValue::Int(fd),
                JValue::Int(i32::try_from(interval_secs).unwrap_or(i32::MAX)),
            ],
            Context::Power,
            |_, _| Ok(()),
        )
    }
}

impl JvmHost {
    /// One `VpnService.Builder` call.
    ///
    /// Addresses cross as **octets**, never as text: `twinvpn-types`' address
    /// types have no `Display` because ADR-0015 §11.4 classes an address
    /// `SENSITIVE`, and the Kotlin side calls
    /// `InetAddress.getByAddress(byte[])`.
    fn apply_op(&self, op: &BuilderOp) -> Result<(), PlatformError> {
        match op {
            BuilderOp::SetMtu(mtu) => self.call(
                "builderSetMtu",
                "(I)V",
                &[JValue::Int(i32::try_from(*mtu).unwrap_or(i32::MAX))],
                Context::RouteProgram,
                |_, _| Ok(()),
            ),
            BuilderOp::AddAddress {
                address,
                prefix_len,
            } => self.address_call("builderAddAddress", *address, *prefix_len),
            BuilderOp::AddRoute { destination } => self.address_call(
                "builderAddRoute",
                destination.address(),
                destination.prefix_len(),
            ),
            BuilderOp::AddDnsServer(address) => {
                let mut env = self
                    .vm
                    .attach_current_thread()
                    .map_err(|_| oserr::unavailable("builderAddDnsServer", libc::ESRCH))?;
                let octets = to_java_bytes(&mut env, &address.octets())?;
                let outcome = env.call_method(
                    &self.host,
                    "builderAddDnsServer",
                    "([B)V",
                    &[JValue::Object(&octets)],
                );
                if outcome.is_err() {
                    let class = describe_pending_exception(&mut env);
                    return Err(oserr::from_java_exception(
                        &class,
                        "builderAddDnsServer",
                        Context::Resolver,
                    ));
                }
                Ok(())
            }
            BuilderOp::AddSearchDomain(domain) => {
                self.string_call("builderAddSearchDomain", domain, Context::Resolver)
            }
            BuilderOp::AddDisallowedApplication(package) => self.string_call(
                "builderAddDisallowedApplication",
                package,
                Context::RouteProgram,
            ),
            BuilderOp::SetBlocking(blocking) => self.call(
                "builderSetBlocking",
                "(Z)V",
                &[JValue::Bool(u8::from(*blocking))],
                Context::TunnelDevice,
                |_, _| Ok(()),
            ),
            // Walked by `establish`, which calls it after every other op.
            BuilderOp::Establish => Ok(()),
        }
    }

    /// A `(byte[], int)` builder call.
    fn address_call(
        &self,
        method: &'static str,
        address: IpAddr,
        prefix_len: u32,
    ) -> Result<(), PlatformError> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| oserr::unavailable(method, libc::ESRCH))?;
        let octets = to_java_bytes(&mut env, &address.octets())?;
        let outcome = env.call_method(
            &self.host,
            method,
            "([BI)V",
            &[
                JValue::Object(&octets),
                JValue::Int(i32::try_from(prefix_len).unwrap_or(i32::MAX)),
            ],
        );
        if outcome.is_err() {
            let class = describe_pending_exception(&mut env);
            return Err(oserr::from_java_exception(
                &class,
                method,
                Context::RouteProgram,
            ));
        }
        Ok(())
    }

    /// A `(String)` builder call.
    fn string_call(
        &self,
        method: &'static str,
        value: &str,
        context: Context,
    ) -> Result<(), PlatformError> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| oserr::unavailable(method, libc::ESRCH))?;
        let text = env
            .new_string(value)
            .map_err(|_| oserr::unavailable(method, libc::ENOMEM))?;
        let outcome = env.call_method(
            &self.host,
            method,
            "(Ljava/lang/String;)V",
            &[JValue::Object(&text)],
        );
        if outcome.is_err() {
            let class = describe_pending_exception(&mut env);
            return Err(oserr::from_java_exception(&class, method, context));
        }
        Ok(())
    }
}
