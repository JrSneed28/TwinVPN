# Signing the Windows artifacts

**Owner:** `desktop-windows`.
**Authority:** [ADR-0021](../../../docs/adr/ADR-0021-packaging-distribution-and-updates.md)
§11 (the Windows row, the trust-anchor table, the compromise-response table),
§11.14 clause 8;
[ADR-0016](../../../docs/adr/ADR-0016-client-process-and-privilege-separation.md)
§11.9 (the Windows hardening posture, and the external approval column).

> **Nothing here has been done.** No certificate has been obtained, no binary has
> been signed, no MSI has been produced, and no timestamp countersignature
> exists. This document is the procedure, written so it can be reviewed against
> the ADRs now; it is not a record. See `shells/windows/README.md` §7.

---

## 1. What is signed

| Artifact | Signature | Why |
|---|---|---|
| `twinvpnsvc.exe` | Authenticode | It is the authority (ADR-0016 PS-1). A tampered service is a total compromise |
| `twinvpnctl.exe` | Authenticode | It connects to the pipe and is on the machine PATH. This is the **cargo artifact** name; D-1 has the MSI install it as `twinvpn.exe` with a `twinvpnctl.exe` `DuplicateFile` alias. Sign the artifact once — Authenticode rides inside the file, so the duplicate the installer makes is signed too |
| `twinvpn-unblock.exe` | Authenticode | ADR-0016 O13's elevated recovery tool. **Not built** — see README §7 |
| `twinvpn-restore.exe` | Authenticode | ADR-0011 DN-20's restore service. **Not built** |
| `TwinVPN.msi` | Authenticode | ADR-0021 §11: "Authenticode-signed per-machine MSI (WiX)" |
| `TwinVPN.cat` | Authenticode | The catalog `ProcessSignaturePolicy` needs — §3 below |
| `wintun.dll` | **Not ours.** Ships already Microsoft-signed | §2 |

Every one is timestamped. §4 explains why that is not optional.

---

## 2. WinTun is signed by somebody else, and we do not re-sign it

ADR-0021 §11's Windows row, verbatim:

> WinTun is a kernel-mode driver: since Windows 10 1607 kernel-mode drivers must
> be Microsoft-signed, so we ship the **upstream Microsoft-signed** WinTun
> binaries app-locally and re-verify their signature at load; we do **not**
> re-sign them and we do **not** submit them.

Three consequences worth stating:

1. **We cannot fix a WinTun defect by rebuilding it.** A patched WinTun would be
   unsigned and would not load. The upgrade path is a new upstream release.
2. **The re-verification at load is ours to do.** Shipping a Microsoft-signed DLL
   and then `LoadLibrary`-ing whatever is at that path is not the same thing:
   ADR-0016 §10 requires the service to compare versions at startup and emit
   `NET.DRIVER_REPLACED`, and the signature check is the other half of that.
3. **If TwinVPN ever authors its own driver**, ADR-0021 §11 says that becomes a
   Partner Center attestation or WHQL submission with an EV certificate and "a
   **separate release cadence gated by Microsoft**", recorded there as §14
   revisit 7. It is not a thing this package can absorb.

---

## 3. The catalog, and why `MicrosoftSignedOnly=0` needs one

ADR-0016 §11.9's Windows row lists the process mitigations the service applies:

```
ProcessDynamicCodePolicy{ProhibitDynamicCode}
ProcessImageLoadPolicy{NoRemoteImages, NoLowMandatoryLabelImages, PreferSystem32}
ProcessExtensionPointDisablePolicy
ProcessSignaturePolicy{MicrosoftSignedOnly=0} with our own catalog
```

The last one is the reason this section exists. `ProcessSignaturePolicy` with
`MicrosoftSignedOnly = 1` would refuse to load **our own** DLLs, so the ADR sets
it to `0` and pairs it with a catalog: the mitigation still refuses unsigned and
remotely-sourced images, and our binaries are admitted because a catalog vouches
for them.

So `TwinVPN.cat` is not a convenience — without it the mitigation is either off
or fatal, and neither is what §11.9 specifies.

The linker flags in the same row — `/guard:cf /CETCOMPAT /DYNAMICBASE
/HIGHENTROPYVA` — are a build concern rather than a signing one, and they belong
in the Rust build configuration. **They are not currently set anywhere in this
workspace**; see README §7.

### Protected Process Light is not claimed

§11.9, verbatim: *"Protected Process Light is **not** claimed (it requires ELAM
signing); noted as future work."*

PPL would stop an administrator from injecting into or debugging the service.
Claiming it needs an Early Launch Anti-Malware signing arrangement with
Microsoft, which is a different relationship from an EV code-signing certificate
and is not on this product's path today. The residual is recorded in ADR-0016
§11.9 and in the threat model, not resolved here.

---

## 4. The certificate

ADR-0021 §11's Windows row, verbatim:

> Cost: an **OV or EV code-signing certificate whose private key is in FIPS
> 140-2 L2+ hardware** (mandatory for all code-signing keys since the 2023 CA/B
> Forum change — EV now buys SmartScreen reputation seeding and
> driver-submission eligibility, not key protection); SmartScreen reputation
> accrues per certificate and **resets on rotation**.

Read carefully, that says three things:

1. **Hardware key storage is mandatory either way.** Since the 2023 CA/B Forum
   change, OV and EV both require the private key to live in FIPS 140-2 Level 2+
   hardware. An HSM or a cloud signing service is not an EV-only cost.
2. **EV buys reputation and driver eligibility.** ADR-0021 §11's trust-anchor
   table names the holder as "Cloud signing service or on-prem HSM (hardware
   mandatory)" and the CA as issuing rather than holding.
3. **Rotation resets SmartScreen reputation.** §11 calls certificate rotation "a
   scheduled operational event", and the reputation reset is the operational cost
   — users see warnings until it re-accrues.

The product ships EV, per `docs/application-architecture.md` §7's Windows row
("MSI + Authenticode EV").

---

## 5. Timestamping

Every signature carries an RFC 3161 timestamp countersignature.

The reason is in ADR-0021 §11's compromise-response table, and it is sharper than
"so signatures do not expire":

> **Authenticode key compromised** — Revoke with the CA, **setting the revocation
> date to the compromise time** so countersigned timestamps before it stay valid;
> re-sign under a new certificate.

That recovery is only available if the earlier signatures are timestamped. Without
a countersignature there is no "before" to be on the right side of, and revoking
the certificate invalidates every artifact ever signed with it — including the
ones that were signed honestly.

---

## 6. The procedure

Written as steps because that is what it is. **None of these has been run.**

```
1. Build release binaries with the §11.9 linker flags.
2. Sign each .exe:
     signtool sign /fd SHA256 /tr <rfc3161-url> /td SHA256 /a <exe>
3. Generate the catalog over the signed binaries, and sign it the same way.
4. Build the MSI with WiX (candle, light), staging the signed binaries and the
   upstream Microsoft-signed wintun.dll.
5. Sign the MSI, timestamped as above.
6. Verify every artifact:
     signtool verify /pa /all <artifact>
   and confirm the countersignature is present, not merely that the chain builds.
7. Record the digests in the ReleaseManifest (ADR-0021 §11.14), which is what
   the updater checks BEFORE the platform signature check — clause 8 of the
   ladder is "the artifact's own platform signature verifies", failing with
   UPDATE.VERIFY.PLATFORM_SIGNATURE_INVALID.
8. Produce the .intunewin wrapper for the managed-deployment path.
```

Step 6 is worth its line. `signtool verify` succeeding tells you the chain
builds; it does not by itself tell you the signature is timestamped, and an
untimestamped signature is the one that cannot survive §5's revocation. The
`/all` flag and an explicit countersignature check are what close that.

---

## 7. What this does not cover

- **Key custody and rotation procedure.** ADR-0021 §11 makes rotation "a
  scheduled operational event"; who holds the HSM credential and on what cadence
  is an operational matter this repository does not hold.
- **Reproducible builds.** ADR-0021 §11's table marks Windows MSI reproducibility
  as best-effort at most; the packaging tools introduce timestamps we do not
  fully control.
- **SBOM generation.** Named in ADR-0021's scope, not implemented here.
