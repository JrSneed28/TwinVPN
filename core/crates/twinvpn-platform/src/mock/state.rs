//! The mock's stateful capabilities: tunnel, configuration, identity, store.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use futures_core::future::BoxFuture;
use twinvpn_types::{DeviceId, IdentityId, PerFamily, UnderlayFamilies};
use zeroize::Zeroizing;

use crate::config::{
    ContractGeneration, Datapath, EnforcementCustody, LinkFacts, LinkState, NetworkConfig,
    NetworkContract, Ruleset, TunnelDevice, TunnelHandle,
};
use crate::custody::{
    IdentityAttestation, IdentityCustody, IdentityKeyRef, IdentityPublic, PeerPublicKey,
    RecordAeadCustody, SecureItem, SecureItemKey, SecureStore, SharedSecret, Signature, StoreRoot,
    StoreRootAttributes,
};
use crate::error::PlatformError;
use crate::iface::InterfaceName;

fn guard<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// Tunnel
// ---------------------------------------------------------------------------

/// An in-memory tunnel device.
pub struct MockTunnel {
    datapath: Datapath,
    state: Mutex<TunnelState>,
    next_handle: AtomicU64,
}

#[derive(Default)]
struct TunnelState {
    interfaces: HashMap<u64, (String, u32, LinkState)>,
    destroy_calls: u64,
    inbound: Vec<Vec<u8>>,
    outbound: Vec<Vec<u8>>,
}

impl MockTunnel {
    pub(super) fn new(datapath: Datapath) -> Self {
        Self {
            datapath,
            state: Mutex::new(TunnelState::default()),
            next_handle: AtomicU64::new(1),
        }
    }

    /// The link state of a created interface.
    #[must_use]
    pub fn link_state(&self, handle: TunnelHandle) -> Option<LinkState> {
        guard(&self.state)
            .interfaces
            .get(&handle.0)
            .map(|(_, _, s)| *s)
    }

    /// The MTU of a created interface.
    #[must_use]
    pub fn mtu(&self, handle: TunnelHandle) -> Option<u32> {
        guard(&self.state)
            .interfaces
            .get(&handle.0)
            .map(|(_, m, _)| *m)
    }

    /// How many times `destroy_interface` has been called, so a test can assert
    /// that repeating it is idempotent rather than merely not an error.
    #[must_use]
    pub fn destroy_calls(&self) -> u64 {
        guard(&self.state).destroy_calls
    }

    /// Queues a packet for [`TunnelDevice::read_packet`] to return.
    pub fn push_inbound(&self, packet: Vec<u8>) {
        guard(&self.state).inbound.push(packet);
    }

    /// Everything written through [`TunnelDevice::write_packet`].
    #[must_use]
    pub fn written(&self) -> Vec<Vec<u8>> {
        guard(&self.state).outbound.clone()
    }
}

impl TunnelDevice for MockTunnel {
    fn create_interface<'a>(
        &'a self,
        name: &'a InterfaceName,
        mtu: u32,
    ) -> BoxFuture<'a, Result<TunnelHandle, PlatformError>> {
        Box::pin(async move {
            let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
            // Created DOWN, per docs/networking.md §5.1: an interface that comes
            // up before its addresses, routes and rules are installed is the
            // partial-application leak window.
            guard(&self.state)
                .interfaces
                .insert(handle, (name.as_str().to_owned(), mtu, LinkState::Down));
            Ok(TunnelHandle(handle))
        })
    }

    fn set_link(
        &self,
        handle: TunnelHandle,
        state: LinkState,
    ) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            let mut s = guard(&self.state);
            match s.interfaces.get_mut(&handle.0) {
                Some(entry) => {
                    entry.2 = state;
                    Ok(())
                }
                None => Err(PlatformError::InterfaceDown(None)),
            }
        })
    }

    fn destroy_interface(&self, handle: TunnelHandle) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            let mut s = guard(&self.state);
            s.destroy_calls += 1;
            // Idempotent and safe after a crash: destroying an interface that is
            // already gone succeeds.
            s.interfaces.remove(&handle.0);
            Ok(())
        })
    }

    fn datapath(&self) -> Datapath {
        self.datapath
    }

    fn read_packet<'a>(
        &'a self,
        _handle: TunnelHandle,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, Result<usize, PlatformError>> {
        Box::pin(async move {
            if self.datapath == Datapath::KernelOffload {
                return Err(PlatformError::OsUnsupported(None));
            }
            let packet = guard(&self.state).inbound.pop();
            match packet {
                Some(p) => {
                    let n = p.len().min(buf.len());
                    buf[..n].copy_from_slice(&p[..n]);
                    Ok(n)
                }
                None => Err(PlatformError::Transient(None)),
            }
        })
    }

    fn write_packet<'a>(
        &'a self,
        _handle: TunnelHandle,
        packet: &'a [u8],
    ) -> BoxFuture<'a, Result<usize, PlatformError>> {
        Box::pin(async move {
            if self.datapath == Datapath::KernelOffload {
                return Err(PlatformError::OsUnsupported(None));
            }
            guard(&self.state).outbound.push(packet.to_vec());
            Ok(packet.len())
        })
    }

    fn set_mtu(&self, handle: TunnelHandle, mtu: u32) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            let mut s = guard(&self.state);
            match s.interfaces.get_mut(&handle.0) {
                Some(entry) => {
                    entry.1 = mtu;
                    Ok(())
                }
                None => Err(PlatformError::InterfaceDown(None)),
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Network configuration
// ---------------------------------------------------------------------------

/// An in-memory transactional configuration surface.
pub struct MockConfig {
    state: Mutex<ConfigState>,
    custody: EnforcementCustody,
    shutting_down: Arc<AtomicBool>,
}

#[derive(Default)]
struct ConfigState {
    /// Every generation ever applied, so `rollback` can restore one exactly.
    history: BTreeMap<u64, NetworkContract>,
    current: Option<ContractGeneration>,
    installed_ruleset: Option<Ruleset>,
    apply_calls: u64,
    fail_next_apply: Option<PlatformError>,
    link_facts: Option<LinkFacts>,
}

impl MockConfig {
    pub(super) fn new(survives_core_exit: bool, shutting_down: Arc<AtomicBool>) -> Self {
        Self {
            state: Mutex::new(ConfigState::default()),
            custody: EnforcementCustody {
                survives_core_exit,
                swap_is_atomic: true,
            },
            shutting_down,
        }
    }

    /// How many times `apply` was called, including the idempotent repeats — so
    /// a test can distinguish "converged" from "was never asked".
    #[must_use]
    pub fn apply_calls(&self) -> u64 {
        guard(&self.state).apply_calls
    }

    /// The contract currently in force.
    #[must_use]
    pub fn current_contract(&self) -> Option<NetworkContract> {
        let s = guard(&self.state);
        s.current.and_then(|g| s.history.get(&g.0).cloned())
    }

    /// Fails the next `apply`, leaving the previous generation intact.
    pub fn fail_next_apply(&self, error: PlatformError) {
        guard(&self.state).fail_next_apply = Some(error);
    }

    /// Sets what `query_link_facts` reports.
    pub fn set_link_facts(&self, facts: LinkFacts) {
        guard(&self.state).link_facts = Some(facts);
    }
}

impl NetworkConfig for MockConfig {
    fn apply<'a>(
        &'a self,
        contract: &'a NetworkContract,
    ) -> BoxFuture<'a, Result<(), PlatformError>> {
        Box::pin(async move {
            if self.shutting_down.load(Ordering::Acquire) {
                return Err(PlatformError::ShuttingDown);
            }
            let mut s = guard(&self.state);
            s.apply_calls += 1;
            if let Some(err) = s.fail_next_apply.take() {
                // All-or-nothing: nothing about `current` or `history` changes.
                return Err(err);
            }
            // Idempotent on the generation id: re-applying the generation in
            // force succeeds and changes nothing, so a retry after a crash
            // converges rather than duplicating routes.
            if s.current == Some(contract.generation) {
                return Ok(());
            }
            s.history.insert(contract.generation.0, contract.clone());
            s.current = Some(contract.generation);
            s.installed_ruleset = Some(contract.ruleset);
            Ok(())
        })
    }

    fn rollback(&self, generation: ContractGeneration) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            let mut s = guard(&self.state);
            let previous = s.history.range(..generation.0).next_back().map(|(k, _)| *k);
            if let Some(g) = previous {
                {
                    let contract = s.history.get(&g).cloned();
                    s.current = Some(ContractGeneration(g));
                    s.installed_ruleset = contract.map(|c| c.ruleset);
                    s.history.retain(|k, _| *k <= g);
                    Ok(())
                }
            } else {
                // Rolling back the first generation clears the configuration
                // but NOT the ruleset: CB-6 keeps protection installed.
                s.current = None;
                s.history.clear();
                Ok(())
            }
        })
    }

    fn current_generation(
        &self,
    ) -> BoxFuture<'_, Result<Option<ContractGeneration>, PlatformError>> {
        Box::pin(async move { Ok(guard(&self.state).current) })
    }

    fn set_ruleset(
        &self,
        _generation: ContractGeneration,
        ruleset: Ruleset,
    ) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            // An atomic swap between the two: the field moves from one `Some` to
            // the other and is never `None` in between (KS-17).
            guard(&self.state).installed_ruleset = Some(ruleset);
            Ok(())
        })
    }

    fn installed_ruleset(&self) -> BoxFuture<'_, Result<Option<Ruleset>, PlatformError>> {
        Box::pin(async move { Ok(guard(&self.state).installed_ruleset) })
    }

    fn enforcement_custody(&self) -> EnforcementCustody {
        self.custody
    }

    fn query_link_facts(&self) -> BoxFuture<'_, Result<LinkFacts, PlatformError>> {
        Box::pin(async move {
            Ok(guard(&self.state).link_facts.clone().unwrap_or(LinkFacts {
                mtu: 1500,
                families: UnderlayFamilies::DualStack,
                default_routes: PerFamily::new(true, true),
                resolvers: PerFamily::new(Vec::new(), Vec::new()),
                metered: false,
                low_power: false,
            }))
        })
    }
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// A **non-cryptographic** identity stub.
///
/// It refuses to sign until [`MockIdentity::allow_insecure_stub_signer`] is
/// called, so a stub tag can never be mistaken for a real signature by a test
/// that forgot which adapter it bound. It reports `hardware_backed: false`
/// truthfully, per ADR-0018 §11.16 (l) — "the core MUST NOT substitute a
/// file-backed signer silently", and neither may a mock pretend otherwise.
pub struct MockIdentity {
    allowed: AtomicBool,
    state: Mutex<IdentityState>,
}

struct IdentityState {
    device_id: DeviceId,
    identity_id: IdentityId,
    generation: u32,
    sign_calls: u64,
    unavailable: bool,
}

impl MockIdentity {
    pub(super) fn new() -> Self {
        Self {
            allowed: AtomicBool::new(false),
            state: Mutex::new(IdentityState {
                device_id: DeviceId::from_array([0xd0; 32]),
                identity_id: IdentityId::from_array([0xd0; 32]),
                generation: 0,
                sign_calls: 0,
                unavailable: false,
            }),
        }
    }

    /// Permits the stub signer. **Test code only.**
    pub fn allow_insecure_stub_signer(&self) {
        self.allowed.store(true, Ordering::Release);
    }

    /// Makes every operation report `AUTH.KEY_UNAVAILABLE`, modelling a locked
    /// device.
    pub fn set_unavailable(&self, unavailable: bool) {
        guard(&self.state).unavailable = unavailable;
    }

    /// How many times the core asked for a signature.
    #[must_use]
    pub fn sign_calls(&self) -> u64 {
        guard(&self.state).sign_calls
    }

    /// Rotates the identity: a new `identity_id` at `generation + 1`, with
    /// `device_id` **unchanged** (`identifiers.md` §2).
    pub fn rotate(&self, new_identity: IdentityId) {
        let mut s = guard(&self.state);
        s.identity_id = new_identity;
        s.generation += 1;
    }
}

impl IdentityCustody for MockIdentity {
    fn public_identity(&self) -> BoxFuture<'_, Result<IdentityPublic, PlatformError>> {
        Box::pin(async move {
            let s = guard(&self.state);
            if s.unavailable {
                return Err(PlatformError::IdentityKeyUnavailable(None));
            }
            Ok(IdentityPublic {
                device_id: s.device_id,
                identity_id: s.identity_id,
                generation: s.generation,
                public_key: vec![0xab; 32],
            })
        })
    }

    fn identity_sign<'a>(
        &'a self,
        key: IdentityKeyRef,
        message: &'a [u8],
    ) -> BoxFuture<'a, Result<Signature, PlatformError>> {
        Box::pin(async move {
            assert!(
                self.allowed.load(Ordering::Acquire),
                "MockIdentity produces a NON-CRYPTOGRAPHIC tag; call \
                 allow_insecure_stub_signer() to acknowledge that before signing"
            );
            let mut s = guard(&self.state);
            if s.unavailable {
                return Err(PlatformError::IdentityKeyUnavailable(None));
            }
            s.sign_calls += 1;
            // A deterministic tag over (key, message). Not a signature.
            let mut tag = vec![0u8; 32];
            let discriminant = match key {
                IdentityKeyRef::Identity { generation } => {
                    u8::try_from(generation & 0xff).unwrap_or(0)
                }
                IdentityKeyRef::OwnerSigning => 0xf0,
                IdentityKeyRef::OwnerRoot => 0xf1,
            };
            for (i, slot) in tag.iter_mut().enumerate() {
                *slot = discriminant
                    ^ message.get(i % message.len().max(1)).copied().unwrap_or(0)
                    ^ u8::try_from(i).unwrap_or(0);
            }
            Ok(Signature::new(tag))
        })
    }

    fn identity_agree<'a>(
        &'a self,
        _key: IdentityKeyRef,
        _peer: &'a PeerPublicKey,
    ) -> BoxFuture<'a, Result<SharedSecret, PlatformError>> {
        Box::pin(async move {
            // ADR-0018 §11.16 (c): in-element agree is NOT required, and an
            // adapter that cannot do it says so. The mock says so by default,
            // which is the honest default for the eight targets whose key APIs
            // do not offer X25519 ECDH.
            Err(PlatformError::OsUnsupported(None))
        })
    }

    fn identity_attestation(&self) -> BoxFuture<'_, Result<IdentityAttestation, PlatformError>> {
        Box::pin(async move {
            Ok(IdentityAttestation {
                // Truthful. TM-13's residual, stated rather than papered over.
                hardware_backed: false,
                attestation: None,
                format: None,
            })
        })
    }
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// An in-memory Tier-1 store and a caller-supplied store root.
pub struct MockStore {
    // `Zeroizing`, so the mock's own copy of the SEK scrubs on drop. A test
    // double that leaves plaintext behind is a test double that would pass a
    // review the real store would fail.
    items: Mutex<HashMap<String, Zeroizing<Vec<u8>>>>,
    root: Mutex<Option<StoreRoot>>,
    custody: RecordAeadCustody,
    unavailable: AtomicBool,
}

impl MockStore {
    pub(super) fn new(platform_performs_record_aead: bool) -> Self {
        Self {
            items: Mutex::new(HashMap::new()),
            root: Mutex::new(None),
            custody: if platform_performs_record_aead {
                RecordAeadCustody::PlatformPerformed
            } else {
                RecordAeadCustody::CoreHeld
            },
            unavailable: AtomicBool::new(false),
        }
    }

    /// Vends a store root. Taken from the caller so the mock touches no
    /// filesystem of its own.
    pub fn set_store_root(&self, path: std::path::PathBuf) {
        *guard(&self.root) = Some(StoreRoot {
            path,
            attributes: StoreRootAttributes {
                backup_excluded: true,
                protection_class: Some("mock"),
                owner_only: true,
            },
        });
    }

    /// Makes every operation report `AUTH.KEY_STORE_UNAVAILABLE`.
    pub fn set_unavailable(&self, unavailable: bool) {
        self.unavailable.store(unavailable, Ordering::Release);
    }

    fn check(&self) -> Result<(), PlatformError> {
        if self.unavailable.load(Ordering::Acquire) {
            Err(PlatformError::SecureStoreUnavailable(None))
        } else {
            Ok(())
        }
    }
}

impl SecureStore for MockStore {
    fn secure_item_read<'a>(
        &'a self,
        key: &'a SecureItemKey,
    ) -> BoxFuture<'a, Result<Option<SecureItem>, PlatformError>> {
        Box::pin(async move {
            self.check()?;
            // `Ok(None)` is "absent", a normal first-run state — never confused
            // with "unavailable", which must not enrol.
            Ok(guard(&self.items)
                .get(key.as_str())
                .map(|v| SecureItem::new(v.to_vec())))
        })
    }

    fn secure_item_write_atomic<'a>(
        &'a self,
        key: &'a SecureItemKey,
        value: &'a SecureItem,
    ) -> BoxFuture<'a, Result<(), PlatformError>> {
        Box::pin(async move {
            self.check()?;
            guard(&self.items).insert(
                key.as_str().to_owned(),
                Zeroizing::new(value.as_bytes().to_vec()),
            );
            Ok(())
        })
    }

    fn secure_item_delete<'a>(
        &'a self,
        key: &'a SecureItemKey,
    ) -> BoxFuture<'a, Result<(), PlatformError>> {
        Box::pin(async move {
            self.check()?;
            guard(&self.items).remove(key.as_str());
            Ok(())
        })
    }

    fn store_root(&self) -> BoxFuture<'_, Result<StoreRoot, PlatformError>> {
        Box::pin(async move {
            self.check()?;
            guard(&self.root)
                .clone()
                .ok_or(PlatformError::SecureStoreUnavailable(None))
        })
    }

    fn record_aead_custody(&self) -> RecordAeadCustody {
        self.custody
    }
}
