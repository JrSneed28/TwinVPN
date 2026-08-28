//! The two host-side doubles: a `TunnelController` over `socketpair`, and a
//! Keystore that performs the AEAD itself and can be locked.
//!
//! Both implement the traits in `twinvpn_platform_android::hostcall`, which is
//! the whole point of those traits existing: `ownership.md` §10.4 keeps the
//! JVM behind two interfaces, and an interface with a host-side implementation
//! is one the layers above it can be tested through.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use twinvpn_platform::{
    IdentityKeyRef, IdentityPublic, PeerPublicKey, PlatformError, SecureItemKey, SharedSecret,
    Signature,
};
use twinvpn_platform_android::builder::Programme;
use twinvpn_platform_android::hostcall::{KeystoreElement, RawFd, SecurityLevel, TunnelController};
use twinvpn_platform_android::power::KeepalivePlan;

/// A `TunnelController` backed by `socketpair`, so `establish` yields a real
/// descriptor and the claim read-back is a real `fcntl`.
#[derive(Debug)]
pub struct FakeController {
    establishes: AtomicUsize,
    pub underlying: Mutex<Vec<Vec<u64>>>,
    open: Mutex<Vec<RawFd>>,
}

impl FakeController {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            establishes: AtomicUsize::new(0),
            underlying: Mutex::new(Vec::new()),
            open: Mutex::new(Vec::new()),
        })
    }

    /// How many times `establish()` was called.
    pub fn establishes(&self) -> usize {
        self.establishes.load(Ordering::SeqCst)
    }
}

impl Drop for FakeController {
    fn drop(&mut self) {
        for fd in self.open.lock().expect("lock").drain(..) {
            // SAFETY: every descriptor here is the far end of a `socketpair`
            // this value created and nothing else owns.
            unsafe { libc::close(fd) };
        }
    }
}

impl TunnelController for FakeController {
    fn name(&self) -> &'static str {
        "fake-vpnservice"
    }
    fn establish(&self, _programme: &Programme) -> Result<RawFd, PlatformError> {
        self.establishes.fetch_add(1, Ordering::SeqCst);
        let mut fds = [0 as RawFd; 2];
        // SAFETY: `socketpair` writes exactly two ints through the pointer it is
        // given; `fds` is a live array of exactly that size.
        let rc = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM,
                0,
                fds.as_mut_ptr().cast::<libc::c_int>(),
            )
        };
        assert_eq!(rc, 0, "socketpair");
        self.open.lock().expect("lock").push(fds[0]);
        Ok(fds[1])
    }
    fn close_tun(&self, _fd: RawFd) -> Result<(), PlatformError> {
        Ok(())
    }
    fn set_underlying_networks(&self, handles: &[u64]) -> Result<(), PlatformError> {
        self.underlying.lock().expect("lock").push(handles.to_vec());
        Ok(())
    }
    fn protect_socket(&self, _fd: RawFd) -> Result<(), PlatformError> {
        Ok(())
    }
    fn request_keepalive(&self, _fd: RawFd, _plan: KeepalivePlan) -> Result<(), PlatformError> {
        Ok(())
    }
}

/// A Keystore that performs the AEAD itself (CB-6a) and can be locked (LC-15).
#[derive(Debug)]
pub struct FakeElement {
    locked: Mutex<bool>,
    items: Mutex<std::collections::BTreeMap<String, Vec<u8>>>,
}

impl FakeElement {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            locked: Mutex::new(false),
            items: Mutex::new(std::collections::BTreeMap::new()),
        })
    }

    /// Simulates a device that has rebooted and not yet been unlocked.
    pub fn lock(&self) {
        *self.locked.lock().expect("lock") = true;
    }

    /// Simulates the first unlock.
    pub fn unlock(&self) {
        *self.locked.lock().expect("lock") = false;
    }

    fn check(&self) -> Result<(), PlatformError> {
        if *self.locked.lock().expect("lock") {
            return Err(PlatformError::SecureStoreUnavailable(None));
        }
        Ok(())
    }
}

impl KeystoreElement for FakeElement {
    fn name(&self) -> &'static str {
        "fake-keystore"
    }
    fn security_level(&self) -> SecurityLevel {
        SecurityLevel::StrongBox
    }
    fn public_identity(&self) -> Result<IdentityPublic, PlatformError> {
        self.check()?;
        Ok(IdentityPublic {
            device_id: twinvpn_types::DeviceId::from_array([0xd0; 32]),
            identity_id: twinvpn_types::IdentityId::from_array([0xd1; 32]),
            generation: 0,
            public_key: vec![0x04; 65],
        })
    }
    fn sign(&self, _key: IdentityKeyRef, _message: &[u8]) -> Result<Signature, PlatformError> {
        self.check()?;
        Ok(Signature::new(vec![0u8; 64]))
    }
    fn agree(
        &self,
        _key: IdentityKeyRef,
        _peer: &PeerPublicKey,
    ) -> Result<SharedSecret, PlatformError> {
        Err(PlatformError::OsUnsupported(None))
    }
    fn attestation(&self) -> Option<Vec<u8>> {
        Some(vec![0x30, 0x82])
    }
    fn item_read(&self, key: &SecureItemKey) -> Result<Option<Vec<u8>>, PlatformError> {
        self.check()?;
        Ok(self.items.lock().expect("lock").get(key.as_str()).cloned())
    }
    fn item_write_atomic(&self, key: &SecureItemKey, value: &[u8]) -> Result<(), PlatformError> {
        self.check()?;
        self.items
            .lock()
            .expect("lock")
            .insert(key.as_str().to_owned(), value.to_vec());
        Ok(())
    }
    fn item_delete(&self, key: &SecureItemKey) -> Result<(), PlatformError> {
        self.items.lock().expect("lock").remove(key.as_str());
        Ok(())
    }
}
