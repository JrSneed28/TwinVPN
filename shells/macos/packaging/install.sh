#!/bin/bash
#
# The macOS installer for the privileged half of the TwinVPN client.
#
# Authority: ADR-0016 PS-7 (the boot artifact is installed by the PACKAGE, never
# by the authority), §11.5's macOS row, §11.7's macOS principals (`_twinvpn`,
# `_twinvpn_op`), O8 (the 0700 state directory); ADR-0012 KS-19, §11.6's macOS
# row; ADR-0017 MI-A3 (the endpoint directory is created by the installer, and
# the agent refuses to bind into a directory it does not own); ADR-0020's macOS
# rows (store root, backup exclusion).
#
# =============================================================================
# THIS SCRIPT HAS NEVER BEEN EXECUTED — but there is now a lane that runs it.
#
# It was written on a Linux host with no macOS, no `pfctl`, no `launchctl`, no
# `dscl`, no `tmutil` and no way to run it. Every command is written from the
# documented interface; as of this writing none has been observed to work, so a
# green read of this file is a review and never a test.
#
# `build/ci/ci-macos-pf-anchor.sh` (`MACOS-PF-BOOT-ANCHOR`) executes it as root
# on a GitHub-hosted `macos-26` runner and then asserts, against pf itself, that
# the anchor is loaded AND evaluated. That lane is where the first real
# execution happens and where corrections to this file will come from. Nothing
# in it skips a validation step here: the `pfctl -n -f` gates and the `pfctl -E`
# arm below are the point of running it at all.
# =============================================================================
#
# Idempotent by construction: running it twice must leave the host in the same
# state as running it once, and must never widen anything on the second run.
# ADR-0016 R-27 requires install, restart, update and uninstall each to have "a
# defined terminal state that leaves the host neither silently unprotected nor
# permanently broken", and an installer that is only correct the first time
# cannot have one.

set -euo pipefail

readonly PREFIX="/Library/Application Support/TwinVPN"
readonly ANCHOR_DIR="/etc/twinvpn"
readonly ANCHOR_FILE="${ANCHOR_DIR}/pf.anchor"
readonly PF_CONF="/etc/pf.conf"
readonly LAUNCH_DAEMONS="/Library/LaunchDaemons"
readonly RUN_DIR="/var/run/twinvpn"
readonly LOG_DIR="/var/log/twinvpn"
readonly SVC_USER="_twinvpn"
readonly OP_GROUP="_twinvpn_op"

# The two lines spliced into /etc/pf.conf. Kept identical to
# `packaging/pf.conf.include`, whose header explains WHERE in the file they must
# land and why the wrong section is a total-loss failure.
readonly PF_ANCHOR_LINE='anchor "twinvpn/*"'
readonly PF_LOAD_LINE='load anchor "twinvpn" from "/etc/twinvpn/pf.anchor"'

here() { cd "$(dirname "${BASH_SOURCE[0]}")" && pwd; }
readonly SRC="$(here)"

say()  { printf '==> %s\n' "$*"; }
die()  { printf 'installer: %s\n' "$*" >&2; exit 1; }

[[ "$(id -u)" -eq 0 ]] || die "must run as root"
[[ "$(uname -s)" == "Darwin" ]] || die "this installer is for macOS only"

# ---------------------------------------------------------------------------
# 1. Principals. ADR-0016 §11.7's macOS row: group `_twinvpn` for OBSERVE,
#    group `_twinvpn_op` for the operator scopes, Authorization Services right
#    `system.privilege.admin` for ADMINISTER.
#
#    PS-12a: "'every local account can enumerate this device's peers and
#    endpoints' should be an install-time decision (TB-13), not a platform
#    default." So these are DEDICATED groups and never `staff` or `everyone`.
#
#    THE PACKAGE creates them; the authority never does.
# ---------------------------------------------------------------------------

# macOS has no `groupadd`. A system group needs a free gid below 500 and a
# `dscl` record. UNVERIFIED: this uid/gid allocation has not been run, and a
# collision with an existing record on a real host is the likely first failure.
next_free_id() {
    local kind="$1" # Users or Groups
    local key="$2"  # UniqueID or PrimaryGroupID
    local id
    id=$(dscl . -list "/${kind}" "${key}" 2>/dev/null \
         | awk '$2 > 300 && $2 < 500 { print $2 }' | sort -n | tail -1)
    echo $(( ${id:-300} + 1 ))
}

ensure_group() {
    local name="$1"
    if dscl . -read "/Groups/${name}" >/dev/null 2>&1; then
        say "group ${name} exists"
        return
    fi
    local gid; gid=$(next_free_id Groups PrimaryGroupID)
    say "creating group ${name} (gid ${gid})"
    dscl . -create "/Groups/${name}"
    dscl . -create "/Groups/${name}" PrimaryGroupID "${gid}"
    dscl . -create "/Groups/${name}" RealName "TwinVPN ${name}"
}

ensure_service_user() {
    if dscl . -read "/Users/${SVC_USER}" >/dev/null 2>&1; then
        say "service account ${SVC_USER} exists"
        return
    fi
    local uid; uid=$(next_free_id Users UniqueID)
    local gid; gid=$(dscl . -read "/Groups/${SVC_USER}" PrimaryGroupID | awk '{print $2}')
    say "creating service account ${SVC_USER} (uid ${uid})"
    dscl . -create "/Users/${SVC_USER}"
    dscl . -create "/Users/${SVC_USER}" UniqueID "${uid}"
    dscl . -create "/Users/${SVC_USER}" PrimaryGroupID "${gid}"
    dscl . -create "/Users/${SVC_USER}" UserShell /usr/bin/false
    dscl . -create "/Users/${SVC_USER}" NFSHomeDirectory /var/empty
    dscl . -create "/Users/${SVC_USER}" RealName "TwinVPN service"
    # Hide it from the login window. Without this a service account appears as a
    # user someone can try to log in as.
    dscl . -create "/Users/${SVC_USER}" IsHidden 1
}

ensure_group "${SVC_USER}"
ensure_group "${OP_GROUP}"
ensure_service_user

# ---------------------------------------------------------------------------
# 2. Directories.
#
#    ADR-0016 O8: the state directory is 0700. ADR-0020's macOS row puts the
#    store root at /Library/Application Support/TwinVPN/, root:wheel, 0700 —
#    which is what makes it "unopenable by the unprivileged client" (§11.16 (g)).
#
#    ADR-0017 MI-A3: the endpoint directory must be created with a privileged
#    owner and no non-privileged write, and the agent verifies it before
#    binding. launchd has no RuntimeDirectory= equivalent, so the INSTALLER
#    creates it — a weaker discharge than the Linux supervisor's, and recorded
#    as such in shells/macos/README.md §7.
# ---------------------------------------------------------------------------
say "directories"
install -d -o root -g wheel -m 0700 "${PREFIX}"
install -d -o root -g wheel -m 0755 "${ANCHOR_DIR}"
install -d -o root -g wheel -m 0755 "${RUN_DIR}"
install -d -o root -g wheel -m 0750 "${LOG_DIR}"

# ADR-0020's macOS row: backup exclusion is BOTH the URL resource key on the
# store root AND a Time Machine exclusion registered by the installer. The first
# is the app's to set; this is the second.
#
# The store root holds the sealed vault. A Time Machine copy of it is a copy of
# the device's cryptographic state that outlives any local wipe, and ADR-0020
# treats that as a durability liability rather than a feature.
if command -v tmutil >/dev/null 2>&1; then
    say "excluding the store root from Time Machine"
    tmutil addexclusion "${PREFIX}" || \
        say "WARNING: tmutil addexclusion failed; the store root may be backed up"
fi

# ---------------------------------------------------------------------------
# 3. Binaries.
# ---------------------------------------------------------------------------
#    X-7 / PS-22: there is NO `twinvpnd`. The authority is the NE system
#    extension, which is installed by the app through
#    `OSSystemExtensionRequest` and is not a file this script copies. What is
#    left for the installer is the boot daemon and the two unprivileged /
#    package-owned commands.
say "binaries"
[[ -f "${SRC}/../target/release/twinvpn-ksd" ]] \
    || die "missing twinvpn-ksd; build it first (cd shells/macos && cargo build --release)"
install -o root -g wheel -m 0755 \
    "${SRC}/../target/release/twinvpn-ksd" "${PREFIX}/twinvpn-ksd"

# ADR-0012 KS-20a / ADR-0017 MI-12: the unblock command is a PACKAGE-OWNED
# artifact, of the same class as the boot anchor beside it, and it must work
# when the authority will not start. It goes in /usr/local/sbin rather than
# beside the CLI because it is privileged: `sbin` is where a reader expects a
# command they must be root to run, and the split is the only signal a PATH
# gives.
[[ -f "${SRC}/../target/release/twinvpn-unblock" ]] \
    || die "missing twinvpn-unblock; build it first"
install -d -o root -g wheel -m 0755 /usr/local/sbin
install -o root -g wheel -m 0755 \
    "${SRC}/../target/release/twinvpn-unblock" "/usr/local/sbin/twinvpn-unblock"

# `ownership.md` §9.5 D-1: the cargo target stays `twinvpnctl` and the PACKAGE
# installs it as `twinvpn` — the name ADR-0016 §11.2, ADR-0017 §11.12 and
# ADR-0023 EM-11/EM-42 all use — with `twinvpnctl` kept beside it as a
# compatibility alias. `ln -sfn` rather than a second copy: one file to sign,
# one file to replace on upgrade, and no way for the two names to drift apart.
#
# CREATED ONLY IF ABSENT, unlike /usr/local/sbin above. macOS does not ship
# /usr/local at all, so on a clean host or a CI runner this directory may not
# exist and `install` would fail with ENOENT. Where it DOES exist it is left
# exactly as found: on many machines Homebrew owns it, and an `install -d`
# that chowned it to root:wheel would break every later `brew` call — an
# installer that "normalizes" somebody else's directory is the same class of
# defect as one that normalizes their /etc/pf.conf.
[[ -d /usr/local/bin ]] || install -d -o root -g wheel -m 0755 /usr/local/bin
install -o root -g wheel -m 0755 \
    "${SRC}/../target/release/twinvpnctl" "/usr/local/bin/twinvpn"
ln -sfn twinvpn "/usr/local/bin/twinvpnctl"

# ---------------------------------------------------------------------------
# 4. The KS-19 boot artifact.
#
#    PS-7: package-owned, "modified only by atomic replace under ADMINISTER; the
#    authority MUST NOT rewrite it as a runtime action". So it is written HERE,
#    by an atomic replace (write-temp-then-rename), and the authority has no
#    code path that opens it.
# ---------------------------------------------------------------------------
say "the pf anchor"
anchor_tmp="$(mktemp "${ANCHOR_DIR}/.pf.anchor.XXXXXX")"
install -o root -g wheel -m 0644 "${SRC}/pf.anchor" "${anchor_tmp}"

# Validate BEFORE committing. `pfctl -n` parses without loading.
#
# This matters more than it looks. The anchor uses pf's `user` keyword for
# KS-9(1)'s uid half, and this domain has NOT confirmed that Apple's pf fork
# retained it. If it did not, the anchor fails to parse — and an unvalidated
# install would leave /etc/pf.conf referencing a file pf cannot read, which
# makes pf load NOTHING and takes the host's entire filter set with it.
if ! pfctl -n -f "${anchor_tmp}" 2>/tmp/twinvpn-pf-check.$$; then
    printf 'installer: the pf anchor does not parse on this host:\n' >&2
    cat /tmp/twinvpn-pf-check.$$ >&2
    rm -f "${anchor_tmp}" /tmp/twinvpn-pf-check.$$
    die "refusing to install an anchor pf cannot load"
fi
rm -f /tmp/twinvpn-pf-check.$$
mv -f "${anchor_tmp}" "${ANCHOR_FILE}"

# ---------------------------------------------------------------------------
# 5. /etc/pf.conf.
#
#    Idempotent AND non-weakening: if the two lines are already present, this
#    does nothing. It never rewrites, reorders or removes anything else in the
#    file — a host may have its own anchors and an installer that "normalizes"
#    /etc/pf.conf is an installer that silently disarms somebody else's firewall.
#    ADR-0012 §11.11: we install into our OWN object so a third party's "reset
#    firewall" does not remove us and we do not remove them.
# ---------------------------------------------------------------------------
say "/etc/pf.conf"
if grep -qF "${PF_LOAD_LINE}" "${PF_CONF}"; then
    say "the anchor reference is already present; leaving ${PF_CONF} untouched"
else
    # Keep a restore point. ADR-0016 R-27 requires uninstall to "restore every
    # host mutation from a durable restore point", and this is that point for
    # this mutation. Written ONCE: a second install must not overwrite the
    # pristine copy with an already-modified one.
    [[ -f "${PF_CONF}.twinvpn-orig" ]] || cp -p "${PF_CONF}" "${PF_CONF}.twinvpn-orig"

    pf_tmp="$(mktemp /etc/.pf.conf.XXXXXX)"
    cp -p "${PF_CONF}" "${pf_tmp}"
    {
        printf '\n# --- TwinVPN (ADR-0012 KS-19). Installed by the TwinVPN package.\n'
        printf '# Removing these two lines disarms boot-window leak protection.\n'
        printf '%s\n' "${PF_ANCHOR_LINE}"
        printf '%s\n' "${PF_LOAD_LINE}"
    } >> "${pf_tmp}"

    # Validate the WHOLE file, not just our lines. An anchor statement in the
    # wrong section is a parse error that costs the host every rule it has.
    if ! pfctl -n -f "${pf_tmp}" 2>/tmp/twinvpn-pfconf-check.$$; then
        printf 'installer: %s does not parse with the TwinVPN anchor appended:\n' "${PF_CONF}" >&2
        cat /tmp/twinvpn-pfconf-check.$$ >&2
        rm -f "${pf_tmp}" /tmp/twinvpn-pfconf-check.$$
        die "refusing to commit an unparseable ${PF_CONF}"
    fi
    rm -f /tmp/twinvpn-pfconf-check.$$
    chmod 0644 "${pf_tmp}"
    chown root:wheel "${pf_tmp}"
    mv -f "${pf_tmp}" "${PF_CONF}"
fi

# ---------------------------------------------------------------------------
# 6. launchd jobs.
#
#    ONE job, and X-7 is why. ADR-0016 §11.2's macOS row lists exactly one
#    LaunchDaemon — `com.twinvpn.ksd`, "root, minimal" — and amendment PS-22
#    puts the core, the keys and the management interface inside the NE system
#    extension. `com.twinvpn.twinvpnd` was a second root component §11.2 never
#    had, and it is gone along with its plist.
#
#      com.twinvpn.ksd       the KS-19 boot artifact, package-owned (PS-7)
#
#    `bootout` before `bootstrap` is NOT the unlink-then-bind pattern MI-A3
#    prohibits — that rule is about the MI SOCKET, where a window with no
#    listener makes a client hang instead of getting MGMT.UNAVAILABLE. A launchd
#    job has no such window: an unloaded job is unambiguously absent. Reloading
#    is the only way to make launchd re-read a changed plist.
# ---------------------------------------------------------------------------
say "launchd"
label=com.twinvpn.ksd
plist="${LAUNCH_DAEMONS}/${label}.plist"
install -o root -g wheel -m 0644 "${SRC}/${label}.plist" "${plist}"
launchctl bootout "system/${label}" 2>/dev/null || true
launchctl bootstrap system "${plist}"

# The authority's plist is NOT installed, and its absence is the point: a
# LaunchDaemon that hosted the core would be the second privileged surface
# §11.2 forbids. If a `com.twinvpn.twinvpnd.plist` is found on a host, it is a
# leftover from a pre-X-7 install and this script removes it — leaving it would
# leave a root job trying to bind the MI socket the extension now owns.
if [[ -f "${LAUNCH_DAEMONS}/com.twinvpn.twinvpnd.plist" ]]; then
    say "removing the pre-X-7 authority daemon"
    launchctl bootout system/com.twinvpn.twinvpnd 2>/dev/null || true
    rm -f "${LAUNCH_DAEMONS}/com.twinvpn.twinvpnd.plist"
    rm -f "${PREFIX}/twinvpnd"
fi

# ---------------------------------------------------------------------------
# 7. Arm pf now, so the first boot after install is not the first time the
#    anchor is in force.
#
#    `pfctl -E` enables pf and takes a reference; `pfctl -e` enables it without
#    one. `-E` is used so that another product's `pfctl -d` does not disable pf
#    underneath us. UNVERIFIED on a real host.
# ---------------------------------------------------------------------------
say "arming pf"
pfctl -E 2>/dev/null || say "WARNING: could not enable pf; the host is UNPROTECTED until reboot"
pfctl -f "${PF_CONF}" || die "pf refused ${PF_CONF} at load time"

# ---------------------------------------------------------------------------
# 8. The read-back. ADR-0015 §11.6 rule 1: the ProtectionAssertion is produced
#    by QUERYING the enforcement layer, never from the fact that a load call
#    returned success. The installer asserts the same way the authority does.
# ---------------------------------------------------------------------------
say "reading back what the kernel is actually holding"
if pfctl -a twinvpn -s labels 2>/dev/null | grep -q 'twinvpn\.deny\.v4'; then
    say "anchor 'twinvpn' is loaded and denies IPv4 protected scope"
else
    die "anchor 'twinvpn' is NOT loaded; do not report this host as protected"
fi
if pfctl -a twinvpn -s labels 2>/dev/null | grep -q 'twinvpn\.deny\.v6'; then
    say "anchor 'twinvpn' denies IPv6 protected scope"
else
    # KS-5: "an implementation that can install the Tier-2 rule set for one
    # family without the other is NON-CONFORMING, not degraded."
    die "IPv4 protection is loaded without IPv6 — KS-5 non-conformance; refusing"
fi

cat <<'NOTE'

==> Installed.

    ADR-0012 §11.6's macOS limitation, unchanged by anything above:

      "Recovery and safe boot do not load the LaunchDaemon. A device booted to
       Recovery is unprotected. Disclosed; Recovery has no user session running
       ordinary applications."

    The system extension is NOT installed by this script. It is activated by
    TwinVPN.app through OSSystemExtensionRequest, which requires an
    administrator to approve it in System Settings > General > Login Items &
    Extensions. Until that approval exists the tunnel cannot start, and the
    authority reports PLATFORM.SERVICE.SYSEXT_NOT_APPROVED rather than a
    generic failure (ADR-0016's code table).

NOTE
