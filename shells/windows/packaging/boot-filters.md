# The KS-19 boot artifact on Windows

**Owner:** `desktop-windows`.
**Authority:** [ADR-0012](../../../docs/adr/ADR-0012-kill-switch-and-leak-prevention.md)
**KS-19**, §11.6 (the Windows row and the honest-limitation row), K3, K7;
[ADR-0016](../../../docs/adr/ADR-0016-client-process-and-privilege-separation.md)
**PS-7**, §11.6 step (1);
[ADR-0022](../../../docs/adr/ADR-0022-application-lifecycle-and-background-execution.md)
**LC-12**.

> **This has never been applied to a machine.** Nothing in this document has run.
> The filter set it describes is defined in Rust and its *contents* are tested on
> a Linux host; the act of installing it into the Base Filtering Engine has never
> happened. See `shells/windows/README.md` §7.

---

## 1. What KS-19 asks for, and why this file exists

> **Rule KS-19 — the boot race.** The rule set that covers the interval between
> the network stack coming up and the agent starting MUST be installed by an
> artifact the **OS itself applies**, never by the agent. **This is where real
> products leak.**

The Linux answer is `twinvpn-killswitch.service`, ordered `Before=network-pre.target`.
The Windows answer is a pair of WFP filter flags, and the artifact that applies
them is the Base Filtering Engine — a service that starts before ours and does
not depend on it.

ADR-0012 §11.6's Windows row, verbatim:

| Enforcement object | Boot-time mechanism |
|---|---|
| One owned WFP sublayer containing `FWPM_LAYER_ALE_AUTH_CONNECT_V4` **and** `_V6` filters, installed in one transaction | `FWPM_FILTER_FLAG_BOOTTIME` coarse deny **plus** `FWPM_FILTER_FLAG_PERSISTENT` full policy reinstated by BFE |

Both flags, and both are load-bearing:

- **`FWPM_FILTER_FLAG_BOOTTIME`** — applied by BFE during boot, before any
  user-mode service including ours has started. This is the flag that closes
  the race KS-19 names.
- **`FWPM_FILTER_FLAG_PERSISTENT`** — survives the transition out of the boot
  phase and every service stop. Without it there is an instant between "the boot
  filters expire" and "the service installs its own" in which the host is open,
  which is the same window one flag earlier.

---

## 2. What is installed is defined in Rust, not here

The set is
[`twinvpn_platform_windows::wfp::boot::boot_set()`](../../../core/crates/twinvpn-platform-windows/src/wfp/boot.rs).
The installer's custom action reads that value and applies it. **This document
describes a mechanism; it does not contain a ruleset.**

That split is deliberate. Two definitions of a boot ruleset — one in Rust, one in
XML or in a `netsh` script — is the second contract ADR-0017 MI-20 forbids in its
own domain, and it would drift the first time either changed. It also means the
service's ADR-0016 §11.6 step-(1) check
([`wfp::boot::verify`](../../../core/crates/twinvpn-platform-windows/src/wfp/boot.rs))
is asking about *the same objects the installer wrote*, rather than about a
separate boot-only shape that could be wrong in its own way.

What `boot_set()` contains, and why each piece:

| Class | Why it is in a boot set |
|---|---|
| Loopback permit, both families | The stub's own listeners and every local IPC must survive the boot window |
| DHCP, DHCPv6, ND and RA permits | Without these the boot window is not merely offline for TwinVPN, it is offline for the host. KS-19 asks for a coverage guarantee, not a disconnected machine |
| A coarse deny of the product's own address space, both families | ADR-0010 §11.1's RFC 6598 block and the pinned product ULA |
| One posture marker | So the read-back path is the same code the runtime uses |

It denies the **product's own address space** rather than a contract's scope,
because at boot there is no contract: the durable store has not been opened and
the last-applied generation is not yet known. A boot set that guessed at a scope
would be wrong on the first host that changed routing mode. What it guarantees is
the narrow, always-true thing — no traffic to the overlay space leaves this host
before the authority has asserted a posture.

---

## 3. The one thing a boot-time filter cannot do

ADR-0012 §11.6's honest-limitation table, Windows row, verbatim:

| Limitation | Consequence | Disposition |
|---|---|---|
| BOOTTIME filters cannot use ALE app-id conditions, so the bootstrap exception is unavailable during the boot window | The agent cannot connect until BFE and the service start — an **availability** gap, not a leak | **Deliberate: the boot window fails closed, which is the correct direction** |

So `boot_set()` carries no `ALE_APP_ID` and no `ALE_USER_ID` condition, and
`FilterSet::validate` **refuses** a boot-flagged filter that names either — the
rule is enforced by a type check on this side of the machine rather than
discovered as an `FwpmFilterAdd0` rejection on a user's.

The consequence, stated rather than glossed: between BFE applying these filters
and the service reaching step 4 of ADR-0022 LC-4, **TwinVPN itself cannot reach
the control plane**. It is offline in exactly the same way everything else is.

This is why ADR-0022 **LC-12** chooses `SERVICE_AUTO_START` over Automatic
(Delayed Start):

> delayed start defers the service by ~2 minutes after boot, which lengthens
> exactly the window in which the host is fail-closed-and-offline, and buys only
> a boot-time perception improvement the product does not need.

The residual is the interval between BFE applying the persistent filters and our
service reaching LC-4 step 4, and `T_REHYDRATE` is what bounds it.

---

## 4. Who may write it, and who may only read it

**ADR-0016 PS-7**, verbatim in effect: the artifact is installed by the **package**
and is modified only by an **atomic replace** performed under `ADMINISTER`
authority. The authority MUST NOT rewrite it as an ordinary runtime action, and
MUST NOT be a prerequisite for it to apply.

| Actor | May |
|---|---|
| The MSI's `InstallBootFilters` custom action | Write and replace the set |
| An `ADMINISTER`-authenticated operation | Atomically replace it |
| `TwinVPNService` | **Verify its presence only** — `wfp::boot::verify` |

The service's startup check is ADR-0016 §11.6 step (1), and a missing artifact is
**`CRITICAL` and not fatal**: refusing to start would leave the host with neither
the boot ruleset *nor* an agent, which is the worse of the two states. The Linux
shell records the same disposition for the same reason.

`verify` requires **both** families to be covered. A boot set covering one is
KS-5's non-conforming case arriving at the moment the host is least defended, and
reporting it as present would hide exactly what KS-19 exists to close.

The MSI has no dependency on the service component in either direction, exactly
as `twinvpn-killswitch.service` has none on `twinvpnd.service`. That is PS-7's
"MUST NOT be a prerequisite for it to apply", expressed as the absence of an
edge.

---

## 5. Ordering, install and uninstall

**Install** — `InstallBootFilters` runs `Before="StartServices"`, so the host is
never running the authority without the boot ruleset the authority verifies.

**Uninstall** — PS-21 step 7 deregisters the boot artifact, and it runs *after*
the service has performed steps 1–6 in-process. `RemoveBootFilters` returns
`ignore`: an artifact that is already gone must not fail an uninstall, because
ADR-0008 requires re-running an interrupted uninstaller to converge on the same
end state.

**Update** — ADR-0012 **KS-23**: an update replaces the rule set by an atomic
swap, never remove-then-add, and MUST NOT clear the latch. The MSI's
`MajorUpgrade` is scheduled `afterInstallExecute` so the old product's persistent
filters stay resident until the new ones are in place.

---

## 6. Durability, and where it stops

ADR-0012 §11.6's Windows durability row:

| Event | Survives |
|---|---|
| Agent crash | ✔ WFP filters are kernel objects |
| Agent killed | ✔ |
| Agent update / uninstall | ✔ persistent filters survive service stop; the installer swaps atomically |
| Reboot | ✔ BOOTTIME + PERSISTENT |
| Safe Mode **without** Networking | ◐ there is no network |
| Safe Mode **with** Networking | ◐ BFE starts, so persistent filters apply |
| Logout / fast user switching | ✔ service and system scope |

The two `◐` rows are the honest ones. Safe Mode without Networking has no network
to leak through, so the absence of enforcement there is not an exposure. Safe Mode
with Networking starts BFE, so the persistent set applies — but the **service**
does not start, so the host is fail-closed and offline, which is the availability
gap of §3 arriving by a different route.
