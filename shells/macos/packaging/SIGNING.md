# Signing, notarization and stapling — the macOS shell

**Owner:** `desktop-macos`.
**Authority:** [ADR-0016](../../../docs/adr/ADR-0016-client-process-and-privilege-separation.md)
§11.9 (the macOS hardening row), §12.6 / MX-1, P-06;
[ADR-0021](../../../docs/adr/ADR-0021-packaging-distribution-and-updates.md)
(packaging, distribution and updates);
[ADR-0020](../../../docs/adr/ADR-0020-local-persistence-and-secure-storage.md)
§10.5 (the keychain ACL binds to the code-signing identity).

> ## None of this has been run.
>
> This document is a **procedure**, not a record. This domain works on a Linux
> host with no Darwin SDK, no `codesign`, no `notarytool`, no `stapler` and no
> Apple Developer account. Every command below is written from Apple's
> documented interfaces; **not one has been executed, and no artifact described
> here has ever been produced.** A reader must treat every claim as untested.
>
> The dependency that gates all of it is ADR-0016 **P-06**: *"Apple grants the
> NetworkExtension entitlement for `packet-tunnel-provider-systemextension`."*
> Until that grant exists there is nothing to sign, and ADR-0016 §14(2) makes
> the grant a falsifiable schedule trigger with MX-3 as the fallback.

---

## 1. What gets signed, and as what

| Artifact | Identity | Runtime | Entitlements |
|---|---|---|---|
| `TwinVPN.app` | `Developer ID Application: … (TEAMID)` | hardened | `TwinVPNApp.entitlements` |
| `TwinVPN.app/Contents/Library/SystemExtensions/com.twinvpn.app.sysext.systemextension` | same | hardened | `TwinVPNTunnel.entitlements` |
| `twinvpnd` (the authority daemon) | same | hardened | none |
| `twinvpn-ksd` (the KS-19 boot job) | same | hardened | none |
| `twinvpn` / `twinvpnctl` (the CLI) | same | hardened | none |
| `TwinVPN.pkg` (the installer) | `Developer ID Installer: … (TEAMID)` | n/a | n/a |

Two different Developer ID certificates are involved and they are not
interchangeable: **Application** signs Mach-O and bundles, **Installer** signs
`.pkg`. Using the wrong one produces an artifact that Gatekeeper rejects at
install time rather than at build time.

`twinvpnd` and `twinvpn-ksd` carry **no entitlements**. ADR-0016 §11.9's macOS
row assigns entitlements to the app and the sysext only, and `ksd` explicitly has
"no network entitlement, no keychain access". An entitlement on a root daemon is
surface with no compensating control.

---

## 2. Order matters

Sign **inside out**. `codesign` seals a bundle's contents into its own
signature, so signing a container before its nested code invalidates the
container the moment the nested code is signed.

```
1. the CLI, twinvpnd, twinvpn-ksd          (plain Mach-O)
2. the .systemextension bundle
3. TwinVPN.app                             (--deep is NOT used; see below)
4. productbuild the .pkg
5. sign the .pkg with Developer ID Installer
6. notarize the .pkg
7. staple the .pkg
```

**`--deep` is deliberately not used.** Apple has deprecated it and it applies the
*outer* bundle's entitlements to nested code — which here would give the app's
sandbox entitlements to a root system extension, or the extension's
NetworkExtension entitlement to the app. Each nested item is signed explicitly,
with its own entitlements file.

---

## 3. The commands

```sh
TEAM_ID="XXXXXXXXXX"
APP_ID="Developer ID Application: TwinVPN Ltd ($TEAM_ID)"
PKG_ID="Developer ID Installer: TwinVPN Ltd ($TEAM_ID)"

# ---- 1. the plain executables -------------------------------------------
# --options runtime is the HARDENED RUNTIME. ADR-0016 §11.9 requires it, and it
# is the macOS analogue of the Linux unit's MemoryDenyWriteExecute=yes: without
# it, library validation is off and DYLD_INSERT_LIBRARIES works against a root
# process.
# --timestamp is required for notarization; an unsigned timestamp is rejected.
for bin in twinvpnd twinvpn-ksd twinvpnctl; do
  codesign --force --sign "$APP_ID" \
           --options runtime \
           --timestamp \
           "build/$bin"
done

# ---- 2. the system extension --------------------------------------------
codesign --force --sign "$APP_ID" \
         --options runtime \
         --timestamp \
         --entitlements packaging/TwinVPNTunnel.entitlements \
         "TwinVPN.app/Contents/Library/SystemExtensions/com.twinvpn.app.sysext.systemextension"

# ---- 3. the containing app ----------------------------------------------
codesign --force --sign "$APP_ID" \
         --options runtime \
         --timestamp \
         --entitlements packaging/TwinVPNApp.entitlements \
         "TwinVPN.app"

# ---- 4/5. the installer package ------------------------------------------
productbuild --component "TwinVPN.app" /Applications \
             --sign "$PKG_ID" \
             TwinVPN.pkg

# ---- 6. notarization ------------------------------------------------------
# `--wait` blocks until Apple returns a verdict, so a failure is a non-zero exit
# in CI rather than a silent success that Gatekeeper rejects on a user's Mac.
xcrun notarytool submit TwinVPN.pkg \
      --keychain-profile "twinvpn-notary" \
      --wait

# On rejection, the log names the offending binary and reason. It is the only
# way to see why:
xcrun notarytool log <submission-id> --keychain-profile "twinvpn-notary"

# ---- 7. stapling ----------------------------------------------------------
# Staples the notarization ticket INTO the artifact, so a Mac with no network
# can still verify it. An unstapled artifact works online and fails offline,
# which is the worst failure mode to discover in the field.
xcrun stapler staple TwinVPN.pkg
xcrun stapler validate TwinVPN.pkg
```

---

## 4. Verification — what to check before shipping

```sh
# Gatekeeper's own verdict, as a user's Mac will compute it.
spctl -a -vvv -t install TwinVPN.pkg
spctl -a -vvv -t exec    TwinVPN.app

# The entitlements ACTUALLY sealed into each artifact. This is the check that
# catches the release-blocking defect: `get-task-allow` present in a shipped
# build. ADR-0016 §11.9 requires it, and the three
# `com.apple.security.cs.*` relaxations, to be ABSENT in release.
codesign -dv --entitlements - "TwinVPN.app" 2>&1
codesign -dv --entitlements - \
  "TwinVPN.app/Contents/Library/SystemExtensions/com.twinvpn.app.sysext.systemextension" 2>&1

# Hardened runtime and library validation, as flags on the signature.
# Expect `flags=0x10000(runtime)` and NOT `library-validation` in the disabled set.
codesign -dvvv "TwinVPN.app" 2>&1 | grep -E 'flags|Runtime|TeamIdentifier'

# The seal is intact and nested code is covered.
codesign --verify --deep --strict --verbose=4 "TwinVPN.app"
```

A release gate that does not run the second block is a gate that will eventually
ship a debuggable root daemon. The four entitlements it exists to catch are named
in `TwinVPNTunnel.entitlements`'s closing comment.

---

## 5. The keychain ACL is bound to this identity

ADR-0020 §10.5, verbatim:

> "the macOS keychain item ACL binds to the code-signing identity… a change of
> Team ID, service account, or package identity is an event
> [ADR-0021](../../../docs/adr/ADR-0021-packaging-distribution-and-updates.md)
> must schedule."

This is not a note about signing hygiene. The Developer-ID daemon shape stores
the identity key in `/Library/Keychains/System.keychain` with an ACL created by
`SecAccessCreateWithOwnerAndACL` and bound to the Team-signed binary. That ACL is
what makes the key **openable by the authority with no user logged in** and
**unopenable by the unprivileged client** — ADR-0016 §11.16 (g)'s two halves.

The consequence: **changing the Team ID, the `_twinvpn` service account, or the
package identity invalidates every existing item's ACL.** Devices already in the
field cannot read their own identity key afterwards, and ADR-0007's rotation
ceremony is the only recovery. That makes any of those three changes a scheduled
migration owned by ADR-0021, never an incidental build change. It is recorded
here because the person who changes a signing identity is reading this file, not
ADR-0020.

---

## 6. What is missing from this procedure

1. **No CI wiring.** These are commands a person runs. Notarization needs an
   App Store Connect API key in a keychain profile
   (`notarytool store-credentials`), which is a secret this repository has no
   place to hold and no mechanism to rotate.
2. **No reproducibility claim.** ADR-0018 §11.3 pins one Rust toolchain version
   so "the bindings compile" is reproducible; nothing equivalent is stated here
   for the Xcode version, and two Xcode versions produce different binaries.
3. **No `twinvpn-unblock` row.** ADR-0012 KS-20a makes the offline unblock
   command mandatory, ADR-0016 §11.6 gives it its own executable, and it is not
   in this wave — so it is not in the table in §1 either.
4. **The `.pkg` scripts are not covered.** `install.sh` is written as a
   standalone script; folding it into a `preinstall`/`postinstall` pair inside
   the package is not done, and a `.pkg` script is signed as part of the package
   rather than separately.
