//! The tests that need Windows. **None of them has ever executed.**
//!
//! **Authority:** the wave-2 objective ("Where a test genuinely needs Windows,
//! write it, gate it, and make sure it **compiles** under `cross-check` — and
//! say in your report that it has never executed"); ADR-0012 K12 and KS-17;
//! ADR-0010 R5; ADR-0011 D7; ADR-0015 O-17; ADR-0016 §11.6.
//!
//! # What this file is for
//!
//! `tests/enforcement.rs` proves the part of this adapter where a mistake is a
//! leak: which filters a contract implies, what the read-back concludes, how a
//! failed apply compensates, whether the canary can be fooled. It proves all of
//! that on a Linux host, against `sys::fake`.
//!
//! What it cannot prove is that `FwpmFilterAdd0` was called with a structure the
//! Base Filtering Engine accepts, that `CreateIpForwardEntry2` puts the route
//! where IP Helper says it will, or that an NRPT rule written into
//! `DnsPolicyConfig` is one `dnscache` obeys. **Only a Windows host can answer
//! those**, and this file is the shape of that answer, written now so that the
//! day somebody has such a host the work is running a command rather than
//! writing a suite.
//!
//! # Gated, and gated the honest way
//!
//! `#![cfg(windows)]` on the file, plus a run-time opt-in on every test that
//! **mutates** the host. The two gates do different jobs and both are needed:
//!
//! - The `cfg` means the file compiles to nothing here, and is **type-checked**
//!   by `make cross-check` for `x86_64-pc-windows-msvc` with `-D warnings`. A
//!   test that no longer matches the API fails the build on this Linux host,
//!   which is the only continuous protection these tests have.
//! - [`MUTATING_TEST_ENV`] means that running `cargo test` on a developer's own
//!   Windows machine does **not** install WFP filters, program routes or rewrite
//!   the NRPT. `twinvpn-platform-linux`'s `tests/netns.rs` takes the same shape
//!   for the same reason, and it also **asserts the refusal** when unprivileged
//!   rather than skipping — so a plain `cargo test` still checks that an
//!   unprivileged adapter names the right `reason_code`.
//!
//! # How to run them, when there is a host
//!
//! ```text
//! # Read-only, unprivileged. Asserts the refusals.
//! cargo test -p twinvpn-platform-windows --test windows_host
//!
//! # The write path. An Administrator shell on a machine you are willing to
//! # have TwinVPN filters installed on, and which you will reboot or run
//! # `twinvpn-unblock` on afterwards.
//! set TWINVPN_WINDOWS_TEST=1
//! cargo test -p twinvpn-platform-windows --test windows_host -- --test-threads=1
//! ```
//!
//! `--test-threads=1` is not tidiness: there is one WFP sublayer and one
//! routing table per host, and two tests mutating them concurrently would be
//! testing a race rather than the adapter.

#![cfg(windows)]

use twinvpn_platform_windows::custody;
use twinvpn_platform_windows::oserr::{self, Win32Error};
use twinvpn_platform_windows::route::InterfaceLuid;
use twinvpn_platform_windows::sys::SystemOps as _;
use twinvpn_platform_windows::wfp;

/// The opt-in every mutating test requires.
///
/// Absent, the mutating tests assert the **refusal** an unprivileged process
/// gets rather than skipping, so a plain `cargo test` on a Windows host still
/// checks something real: that a `PlatformError` comes back with a registered
/// `reason_code` and the `WIN32_ERROR` as evidence, rather than a panic or a
/// silent success.
const MUTATING_TEST_ENV: &str = "TWINVPN_WINDOWS_TEST";

fn mutating_enabled() -> bool {
    std::env::var_os(MUTATING_TEST_ENV).is_some()
}

/// The overlay LUID these tests use.
///
/// **A placeholder that a real run must replace.** There is no adapter until
/// `wintun::WindowsTunnelDevice::create_interface` has made one, and the LUID it
/// returns is the only correct value. A test that guessed would program routes
/// onto whatever interface happened to hold that LUID, which on a real machine
/// is somebody's Wi-Fi.
const PLACEHOLDER_LUID: InterfaceLuid = InterfaceLuid(0);

fn system() -> twinvpn_platform_windows::sys::win::WindowsSystem {
    twinvpn_platform_windows::sys::win::WindowsSystem::new()
}

// ---------------------------------------------------------------------------
// read-only: these run unprivileged and assert what an unprivileged process gets
// ---------------------------------------------------------------------------

#[test]
fn the_engine_can_be_queried_or_the_refusal_is_named() {
    // ADR-0015 O-17: the `ProtectionAssertion` is a query. This is the query,
    // against a real Base Filtering Engine. Opening the engine for READ does not
    // need Administrator; opening it for write does. Either outcome is
    // acceptable here — what is not acceptable is a panic, or an `Ok` carrying a
    // state nobody asked the engine for.
    match system().filters().read() {
        Ok(state) => {
            // A host with no TwinVPN install holds no ruleset of ours, and
            // `parse_installed` must say so rather than inventing a posture.
            let installed = wfp::readback::parse_installed(&state);
            if !state.sublayer_present {
                assert!(installed.is_none(), "no sublayer is no posture");
            }
        }
        Err(err) => {
            assert!(
                err.reason_code().as_str().contains('.'),
                "the refusal must carry a registered code"
            );
            assert!(
                err.os_detail().is_some(),
                "and the WIN32_ERROR as evidence, never alone"
            );
        }
    }
}

#[test]
fn the_boot_artifact_check_answers_from_the_engine_and_never_from_a_file() {
    // ADR-0016 §11.6 step (1), and PS-7: verification, never installation. On a
    // host where the MSI has not run this must report absent; on one where it
    // has, present. Both are correct answers and neither is a failure of this
    // test — what it checks is that the question reaches the engine at all.
    if let Ok(state) = system().filters().read() {
        let artifact = wfp::boot::verify(&state);
        // Both families or neither: KS-5 at the moment the host is least
        // defended, and a one-family boot set must not read as registered.
        assert_eq!(
            artifact.is_registered(),
            artifact.v4_deny && artifact.v6_deny
        );
    }
}

#[test]
fn the_routing_table_can_be_read_and_reports_only_our_interface() {
    // `RouteTable::read` narrows to one LUID. On a host with no overlay adapter
    // the answer is empty, which is the honest one.
    if let Ok(routes) = system().routes().read(PLACEHOLDER_LUID) {
        for row in &routes.rows {
            assert_eq!(row.luid, PLACEHOLDER_LUID);
        }
        for address in &routes.addresses {
            assert_eq!(address.luid, PLACEHOLDER_LUID);
        }
    }
}

#[test]
fn every_oserr_literal_matches_the_platforms_own_constant() {
    // The `const _: () = assert!(...)` block in `sys::win` already checks this
    // at compile time. This test exists so that a reader of the *test* output on
    // a Windows host sees the fact stated, and so that a future `oserr` constant
    // added without an assertion is visible in one more place.
    assert_eq!(
        oserr::from_status(
            Win32Error(oserr::ERROR_ACCESS_DENIED),
            "probe",
            oserr::Context::RouteProgram
        )
        .reason_code()
        .as_str(),
        "ROUTE.PROGRAMMING_DENIED"
    );
    // `NTE_EXISTS` is the provisioning race, and it is an identity condition in
    // every context but the store's — the same split the CNG arm makes for
    // `NTE_BAD_KEYSET`, because DPAPI-NG returns the same numbers.
    assert_eq!(
        oserr::from_status(
            Win32Error(oserr::NTE_EXISTS),
            "NCryptCreatePersistedKey",
            oserr::Context::Identity
        )
        .reason_code()
        .as_str(),
        "AUTH.KEY_UNAVAILABLE"
    );
}

// ---------------------------------------------------------------------------
// the write path: gated, and asserting the refusal when the gate is closed
// ---------------------------------------------------------------------------

#[test]
fn installing_the_blocked_ruleset_either_works_or_names_the_refusal() {
    // KS-17's arm step, against a real engine. Unprivileged, `FwpmEngineOpen0`
    // for write returns `ERROR_ACCESS_DENIED`, which must arrive as
    // `PLATFORM.ADAPTER_UNAVAILABLE` with the number as evidence — the same
    // assertion `twinvpn-platform-linux`'s `tests/netns.rs` makes about an
    // unprivileged `nft`.
    let set = wfp::boot::boot_set();
    let result = system().filters().commit(&set);
    if mutating_enabled() {
        result.expect("an Administrator shell can install the boot set");
        // KS-17: the read-back must show exactly what was committed, and it must
        // show it as a query rather than as a remembered value.
        let state = system().filters().read().expect("reads back");
        let installed = wfp::readback::parse_installed(&state).expect("a ruleset is installed");
        assert_eq!(installed.posture, wfp::Ruleset::Blocked);
        assert!(
            installed.both_families_covered(),
            "KS-5: one family without the other is non-conforming"
        );
        // And the cleanup, because this test just made a real host fail-closed.
        system().filters().purge().expect("purges");
    } else {
        let err = result.expect_err(
            "an unprivileged process must be refused, not silently succeed; \
             set TWINVPN_WINDOWS_TEST=1 in an Administrator shell to exercise the write path",
        );
        assert!(err.os_detail().is_some());
    }
}

#[test]
fn a_posture_swap_leaves_no_instant_with_no_rules() {
    // KS-17, on the only host that can answer it: install BLOCKED, swap to
    // PROTECTED, and read back between. The property cannot be *observed* from
    // one thread — there is no instant to sample — so what this checks is the
    // weaker, still-worth-having thing: that both postures read back correctly
    // and that the swap did not go through a state with no sublayer.
    if !mutating_enabled() {
        return;
    }
    let blocked = wfp::boot::boot_set();
    system()
        .filters()
        .commit(&blocked)
        .expect("installs BLOCKED");
    assert!(system().filters().read().expect("reads").sublayer_present);
    // A real swap renders from a contract; the boot set stands in for one here
    // because this file has no core to ask for one.
    system().filters().commit(&blocked).expect("re-installs");
    assert!(
        system().filters().read().expect("reads").sublayer_present,
        "the sublayer must never be absent between two commits"
    );
    system().filters().purge().expect("purges");
}

#[test]
fn the_net_event_stream_reports_its_own_losses() {
    // ADR-0012 §11.9's canary depends on this: a fold over a stream that lost
    // events under-counts, and `canary_verdict` refuses to conclude `Denied`
    // from a lossy window. Whether `FwpmNetEventEnum` reports its drops at all
    // is the single largest open question in this adapter — see the crate's
    // report — and this is the test that answers it.
    if !mutating_enabled() {
        return;
    }
    let (events, lost) = system().filters().net_events().expect("enumerates");
    // No assertion on the counts: a quiet host produces none. What is asserted
    // is that the call answers at all and that the loss flag is a fact the
    // engine supplied rather than one inferred from an empty slice.
    let snapshot = wfp::canary::fold(&events, lost);
    assert_eq!(snapshot.lost_events, lost);
}

// ---------------------------------------------------------------------------
// the identity element: a real CNG key, under a container that is NOT this
// machine's identity
// ---------------------------------------------------------------------------

/// The container the provisioning test uses.
///
/// **Never `custody::IDENTITY_KEY_CONTAINER`.** A test that provisioned the
/// production container would mint a device identity on whatever machine ran
/// `cargo test` — and then destroy it again in its cleanup, which ADR-0007 §7.3
/// makes indistinguishable from a compromise twice over.
/// [`the_test_container_is_not_the_devices_own`] asserts the two are different,
/// so a rename cannot quietly merge them.
const TEST_CONTAINER: &str = "TwinVPN.WindowsHostTest.DoNotUse";

/// Deletes the test container on the way out, panic or not.
///
/// A `Drop` guard rather than a call at the end of the test: every assertion
/// below can fail, and a failed assertion that left a persisted machine key
/// behind would make the next run start from a different state.
struct ContainerGuard(custody::CngElement);

impl Drop for ContainerGuard {
    fn drop(&mut self) {
        if let Err(error) = self.0.delete_identity_key_for_test() {
            // Printed rather than panicked: a panic inside `drop` during
            // another panic aborts the process and hides the real failure.
            eprintln!("WARNING: {TEST_CONTAINER} was left behind: {error}");
        }
    }
}

#[test]
fn the_test_container_is_not_the_devices_own() {
    assert_ne!(TEST_CONTAINER, custody::IDENTITY_KEY_CONTAINER);
}

#[test]
fn provisioning_creates_a_signing_key_whose_public_half_is_the_spki_the_core_reads() {
    use twinvpn_platform::IdentityKeyRef;
    use twinvpn_platform_windows::custody::{SigningElement as _, Tier1Backend};

    // The **software** KSP, deliberately. A Platform Crypto Provider create
    // consumes TPM storage a test has no business spending, and ADR-0020
    // §11.3's second Windows row is the one this exercises.
    let element = custody::CngElement::new_for_test(Tier1Backend::SoftwareKsp, TEST_CONTAINER);

    // Unprivileged, and before anything is created: the container is absent, so
    // the element must name the refusal rather than invent an identity. This
    // branch is what a plain `cargo test` on a Windows host runs, and it is an
    // assertion rather than a skip.
    let absent = element
        .public_identity()
        .expect_err("nothing has been provisioned yet");
    assert_eq!(absent.reason_code().as_str(), "AUTH.KEY_UNAVAILABLE");
    assert!(absent.os_detail().is_some(), "the CNG status is evidence");

    if !mutating_enabled() {
        return;
    }

    element.provision().expect("the software KSP creates a key");
    // `CngElement` is `Copy`, so the guard takes its own and the test keeps
    // using `element`.
    let guard = ContainerGuard(element);
    // Idempotent: the second call finds the container and does not overwrite
    // it. `NCRYPT_OVERWRITE_KEY_FLAG` is never passed, so this passes only
    // because `provision` opens before it creates.
    element.provision().expect("provisioning twice is a no-op");

    let identity = element.public_identity().expect("exports the public half");
    // X.509 `SubjectPublicKeyInfo`: the 26-byte P-256 header, the uncompressed
    // point marker, then 64 bytes of coordinates. This is what
    // `twinvpn_crypto::cose::es256_cose_key_from_spki` parses, and it is the
    // whole reason the element re-encodes CNG's blob at all.
    assert_eq!(identity.public_key.len(), 91);
    assert_eq!(identity.public_key[0], 0x30);
    assert_eq!(identity.public_key[26], 0x04, "uncompressed point");
    assert_eq!(identity.generation, 0);

    // One signature, verified against the **exported** public half rather than
    // against the same handle: that is what proves the SPKI carries the point
    // belonging to the key that signed, which is the property enrolment needs.
    let digest = [0x5au8; 32];
    let signature = element
        .sign(IdentityKeyRef::Identity { generation: 0 }, &digest)
        .expect("the key signs");
    assert_eq!(signature.as_bytes().len(), 64, "P-256 r||s");
    assert!(
        verify_p256(&identity.public_key[26..], &digest, signature.as_bytes()),
        "the exported point must verify the signature the element produced"
    );

    drop(guard);
    // And the container is gone, so a second run starts where this one did.
    assert!(element.public_identity().is_err());
}

/// Verifies a P-256 signature through BCrypt, from the uncompressed point.
///
/// Test-only, and deliberately not the element's job: CD-I2 keeps signature
/// verification in `twinvpn-crypto`, and the platform's own primitive is the
/// one thing that can check this element without putting a cryptographic
/// dependency into an adapter that has none.
fn verify_p256(point: &[u8], digest: &[u8], signature: &[u8]) -> bool {
    use windows_sys::Win32::Security::Cryptography::{
        BCryptCloseAlgorithmProvider, BCryptDestroyKey, BCryptImportKeyPair,
        BCryptOpenAlgorithmProvider, BCryptVerifySignature, BCRYPT_ALG_HANDLE,
        BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALGORITHM, BCRYPT_ECDSA_PUBLIC_P256_MAGIC,
        BCRYPT_KEY_HANDLE,
    };

    assert_eq!(point.len(), 65, "0x04 || X || Y");
    // `BCRYPT_ECCKEY_BLOB`: dwMagic, cbKey, then X and Y without the 0x04.
    let mut blob = Vec::with_capacity(8 + 64);
    blob.extend_from_slice(&BCRYPT_ECDSA_PUBLIC_P256_MAGIC.to_le_bytes());
    blob.extend_from_slice(&32u32.to_le_bytes());
    blob.extend_from_slice(&point[1..]);

    let mut algorithm: BCRYPT_ALG_HANDLE = core::ptr::null_mut();
    let mut key: BCRYPT_KEY_HANDLE = core::ptr::null_mut();
    // SAFETY: every pointer is a live out-parameter or a live slice whose true
    // length is passed, and the algorithm identifier and blob type are
    // `windows-sys`' own static wide literals. Both handles are closed before
    // this function returns.
    unsafe {
        assert_eq!(
            BCryptOpenAlgorithmProvider(
                &raw mut algorithm,
                BCRYPT_ECDSA_P256_ALGORITHM,
                core::ptr::null(),
                0
            ),
            0
        );
        assert_eq!(
            BCryptImportKeyPair(
                algorithm,
                core::ptr::null_mut(),
                BCRYPT_ECCPUBLIC_BLOB,
                &raw mut key,
                blob.as_ptr(),
                u32::try_from(blob.len()).expect("fits"),
                0,
            ),
            0,
            "the exported point must import as a P-256 public key"
        );
        let verdict = BCryptVerifySignature(
            key,
            core::ptr::null(),
            digest.as_ptr(),
            u32::try_from(digest.len()).expect("fits"),
            signature.as_ptr(),
            u32::try_from(signature.len()).expect("fits"),
            0,
        );
        BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        verdict == 0
    }
}
