#!/usr/bin/env bash
#
# ci-macos-pf-anchor.sh — `MACOS-PF-BOOT-ANCHOR`.
#
# ===========================================================================
# WHAT THIS CRITERION IS
# ===========================================================================
# The KS-19 boot artifact, installed by the package onto a real Mac, and
# Apple's own pf parsing and EVALUATING the anchor this repository ships.
# `shells/macos/README.md` §7 gap 2 records that this has never happened, and
# names the two constructs most likely to differ on Apple's fork: the `user`
# rule keyword and the ICMPv6 type spellings. If `user` is absent the anchor
# does not parse and the KS-19 artifact does not load AT ALL — the largest
# unverified assumption in the macOS enforcement path, settleable here for the
# price of one hosted job.
#
# IT IS NOT `MACOS-SYSEXT-LIFECYCLE`, which is the extension reaching
# `activated enabled`, arming a contract, and an external oracle seeing
# silence — all of it needing an Apple-granted entitlement and then a human at
# a keyboard or MDM enrolment. This claims only that the BOOT ruleset is
# installed, referenced, held by an ENABLED filter, and dropping packets into
# the two prefixes it denies. Separate criterion, separate evidence file,
# separate row: folding them would be the conflation the August 2026 split of
# the macOS row exists to prevent.
#
# NO ORACLE, DELIBERATELY. The anchor denies `100.64.0.0/10` (RFC 6598) and
# `fd7c:9e5d:2a10::/48` (AP-1's pinned ULA); neither reaches a public observer,
# so there is no egress claim to adjudicate. It is NOT in `report.py`'s
# `ORACLE_REQUIRED`, and adding it would silently demand path-identity keys
# this lane cannot produce truthfully.
#
# ===========================================================================
# HOW "EVALUATED" IS TOLD FROM "LOADED"
# ===========================================================================
# Four facts, because each of the first three holds on a wholly unprotected
# host. pf is ENABLED (`pfctl -s info`), since an anchor in a disabled filter
# is dead text. It is REFERENCED (`pfctl -s rules` carries `anchor
# "twinvpn"` -- the exact form; the wildcard evaluates only children, G-35),
# since pf evaluates an anchor only where the main ruleset calls
# it and that line lives in /etc/pf.conf, which only `install.sh` writes. It
# has RULES and the read-back TABLES `ksd`'s W-24 query parses. And it DROPS
# PACKETS: a connect into each covered prefix fails AND that family's deny
# counter moved — the counter being the load-bearing half, because a failed
# connect alone is equally well explained by a host with no route.
#
# THE CONTROL IS LOOPBACK, AND IT IS ONLY A SANITY CHECK. It rules out
# "everything failed" (the stack still connects), no more: the boot anchor has
# no default deny and 127.0.0.1 is in neither protected table, so loopback
# survives whether or not the anchor is evaluated. What PROVES evaluation is
# the anchor's own counters: `pfctl -a twinvpn -s labels` field 2 (evaluations)
# and field 3 (packets) on `twinvpn.deny.v4`/`.v6` must both rise across the
# covered connect. Evaluations flat means the kernel never stepped into the
# anchor -- which is exactly how the 2026-09-02 run exposed the wildcard
# reference defect (see packaging/pf.conf.include). A control that left the
# machine would measure the runner's internet path, about which this criterion
# says nothing.
#
# First executed on hosted macos-26 on 2026-09-02 (it found G-35).

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck disable=SC1091
. "$REPO/build/ci/digest.sh"
SHELL_DIR="$REPO/shells/macos"
PACKAGING="$SHELL_DIR/packaging"
LOGDIR="$REPO/build/ci/logs/macos"
EVIDENCE="$REPO/build/ci/evidence/macos-pf-anchor.json"
CRITERION="MACOS-PF-BOOT-ANCHOR"
RESULT_BUNDLE="$LOGDIR/TwinVPNBridgeTests-root.xcresult"

# ADR-0010 §11.1's overlay space and AP-1's pinned ULA: the two prefixes
# `packaging/pf.anchor` denies, and the only two this lane probes.
COVERED_V4="100.64.0.0/10"
COVERED_V6="fd7c:9e5d:2a10::/48"
PROBE_V4="100.64.0.1"
PROBE_V6="fd7c:9e5d:2a10::1"
PROBE_PORT=443
KSD="/Library/Application Support/TwinVPN/twinvpn-ksd"
# What `pfread::parse_tables` reads and `packaging/pf.anchor` declares.
# Generation 0 and one covered prefix per family are the boot artifact's own
# truthful answer, so these four names are exact rather than a prefix match.
READ_BACK_TABLES="tv_posture_blocked tv_gen_0 tv_scope4_n1 tv_scope6_n1"

mkdir -p "$LOGDIR" "$(dirname "$EVIDENCE")"

[ "$(uname -s)" = "Darwin" ] || {
  echo "::error::ci-macos-pf-anchor.sh must run on macOS" >&2; exit 2; }

# shellcheck disable=SC1091
. "$REPO/build/ci/pf-probe.sh"   # connect_probe, label_packets, label_evals, loopback_control_probe

# --- --cleanup: `if: always()`, and it checks itself -----------------------
#
# The removal, the reason CI cannot use the sanctioned command, and the
# read-back all live in `apple_remove_twinvpn_anchor` (ci-common-apple.sh),
# because `ci-macos.sh`'s teardown needs exactly the same thing and had a
# broken copy of it. What is local to this lane is pf's own on/off state: this
# is the only lane that runs `pfctl -E`, so it is the only one that owes the
# host the state it found.
if [ "${1:-}" = "--cleanup" ]; then
  echo "=== cleanup: remove the boot anchor and return /etc/pf.conf ==="
  # shellcheck disable=SC1091
  source "$REPO/build/ci/ci-common-apple.sh"
  cleanup_rc=0
  apple_remove_twinvpn_anchor "$LOGDIR" || cleanup_rc=$?

  if [ -f "$LOGDIR/pf-status-before.txt" ] \
     && grep -q Disabled "$LOGDIR/pf-status-before.txt"; then
    sudo -n pfctl -d 2>&1 || echo "(pf would not disable; it was disabled before)"
  fi

  if [ "$cleanup_rc" -ne 0 ]; then
    exit 1
  fi
  echo "=== cleanup done; the host holds no TwinVPN enforcement ==="
  exit 0
fi

# --- 0. the attestation, before anything is installed ---
echo "::group::environment attestation"
macos_version="$(sw_vers -productVersion)"
sip_config="$(csrutil status 2>&1 | tr -d '\n' | tr -s ' ')"
echo "macOS: $macos_version"
echo "SIP:   $sip_config"

# PRIVILEGE IS MEASURED: `privileged: true` has to mean "this process reached
# uid 0". `-n` throughout, so the lane cannot block on a password prompt.
sudo -n true 2>/dev/null || {
  echo "::error::passwordless sudo is unavailable, and every step here — \
install.sh, ksd, pfctl — needs uid 0. Hosted macOS runners provide it; a host \
that does not cannot produce this evidence." >&2
  exit 2; }
sudo_uid="$(sudo -n id -u 2>/dev/null || true)"
[ "$sudo_uid" = "0" ] || {
  echo "::error::\`sudo -n id -u\` returned '${sudo_uid:-<nothing>}', not 0" >&2
  exit 2; }
privileged=true
runner_kind="${TWINVPN_RUNNER_KIND:-${RUNNER_ENVIRONMENT:-github-hosted}}"
echo "privileged: $privileged   runner kind: $runner_kind"

# THE REFUSAL THAT PROTECTS THE RUNNER. `100.64.0.0/10` is RFC 6598 CARRIER
# shared space, so a host behind CGNAT legitimately holds an address in it and
# this lane would deny the underlay it runs over. Refused by name rather than
# discovered by timeout.
{ ifconfig -a 2>/dev/null | awk '/^[[:space:]]*inet6? /{ print $2 }' | sed 's/%.*//'
  netstat -rn 2>/dev/null | awk '$1 == "default" { print $2 }'
} > "$LOGDIR/pf-anchor-host-addresses.txt"
overlapping="$(python3 - "$LOGDIR/pf-anchor-host-addresses.txt" \
  "$COVERED_V4" "$COVERED_V6" <<'PY'
import ipaddress, sys
nets = [ipaddress.ip_network(n) for n in sys.argv[2:]]
with open(sys.argv[1]) as fh:
    for line in fh:
        try:
            addr = ipaddress.ip_address(line.strip())
        except ValueError:
            continue
        if any(addr.version == n.version and addr in n for n in nets):
            print(addr)
PY
)"
if [ -n "$overlapping" ]; then
  echo "::error::this host holds an address or gateway inside a prefix the boot \
anchor denies ($COVERED_V4, $COVERED_V6): $(echo "$overlapping" | tr '\n' ' '). \
Loading the anchor here would black-hole the runner's own underlay. Refusing." >&2
  exit 2
fi

# SC2024 here and below: the redirect is this shell's, into a directory the CI
# user owns. Only the command needs root; a root-owned log is one the upload
# step cannot read.
# shellcheck disable=SC2024
sudo -n pfctl -s info > "$LOGDIR/pf-status-before.txt" 2>&1 || true
echo "pf before this run: $(head -1 "$LOGDIR/pf-status-before.txt")"
echo "::endgroup::"

# --- 1. the package-owned binaries, and WHICH BYTES they are ---
echo "::group::build the package-owned binaries"
# `-p ksd`, not `-p twinvpn-ksd`: the PACKAGE is `ksd` and its `[[bin]]` is
# `twinvpn-ksd` (shells/macos/ksd/Cargo.toml), because §11.2 names the
# component `com.twinvpn.ksd` while every installed executable carries the
# product prefix. `-p twinvpn-ksd` names no package and fails.
( cd "$SHELL_DIR" && cargo build --locked --release -p ksd -p twinvpn-unblock -p twinvpnctl )

# `install.sh` reads `packaging/../target/release/` and this repository shares ONE
# `CARGO_TARGET_DIR` across workspaces, so the output is not necessarily there.
# The directory is ASKED FOR and the binaries staged where the installer looks,
# which leaves its own paths untouched.
target_dir="$(cd "$SHELL_DIR" && cargo metadata --format-version 1 --no-deps \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
if [ "$target_dir/release" != "$SHELL_DIR/target/release" ]; then
  mkdir -p "$SHELL_DIR/target/release"
  for binary in twinvpn-ksd twinvpn-unblock twinvpnctl; do
    cp -f "$target_dir/release/$binary" "$SHELL_DIR/target/release/$binary"
  done
  echo "staged the binaries from $target_dir/release for the installer"
fi

ARTIFACT_DIGESTS="$(twinvpn_digest_json twinvpn-ksd "$SHELL_DIR/target/release/twinvpn-ksd")"
echo "artifact digests: $ARTIFACT_DIGESTS"
echo "::endgroup::"

# --- 2. the installer — the only thing that writes /etc/pf.conf and runs `pfctl -E` ---
echo "::group::install the KS-19 boot artifact"
# Whole and unmodified. Its two `pfctl -n -f` validations are the point: one
# gates the anchor, one gates the SPLICED /etc/pf.conf, where a statement in the
# wrong section is a parse error that costs the host every rule it has.
sudo -n "$PACKAGING/install.sh" 2>&1 | tee "$LOGDIR/pf-anchor-install.log"
echo "::endgroup::"

# --- 3. ksd, the boot-path job itself ---
echo "::group::ksd --apply-boot-anchor and --status"
# `sudo -n test`, not `[ -x ]`: install.sh makes the store root 0700 root:wheel
# (its own header, "the store root ... root:wheel, 0700"), so the unprivileged
# runner user cannot even stat the file it is about to have root execute.
sudo -n test -x "$KSD" || { echo "::error::install.sh did not place $KSD" >&2; exit 1; }
ksd_apply_exit=0
sudo -n "$KSD" --apply-boot-anchor 2>&1 | tee "$LOGDIR/ksd-apply.log" \
  || ksd_apply_exit=${PIPESTATUS[0]}
ksd_status_exit=0
sudo -n "$KSD" --status 2>&1 | tee "$LOGDIR/ksd-status.log" \
  || ksd_status_exit=${PIPESTATUS[0]}
echo "ksd --apply-boot-anchor exit $ksd_apply_exit, --status exit $ksd_status_exit"
echo "::endgroup::"

# --- 4. the read-back: enabled, referenced, populated ---
echo "::group::what the kernel actually holds"
# shellcheck disable=SC2024
{
  sudo -n pfctl -s info              > "$LOGDIR/pf-info.txt"           2>&1 || true
  sudo -n pfctl -s rules             > "$LOGDIR/pf-main-rules.txt"     2>&1 || true
  sudo -n pfctl -a twinvpn -s rules  > "$LOGDIR/pf-anchor-rules.txt"   2>&1 || true
  sudo -n pfctl -a twinvpn -s Tables > "$LOGDIR/pf-anchor-tables.txt"  2>&1 || true
  sudo -n pfctl -a twinvpn -s labels > "$LOGDIR/pf-labels-before.txt"  2>&1 || true
}

# Only the word after `Status:` is read, as `pfread::parse_status` does. `awk`
# and not `grep`: grep exits 1 on no match and a measurement has no `|| true`.
pf_enabled="$(awk '/^[[:space:]]*Status:[[:space:]]+Enabled/ { f = 1 } \
  END { print (f ? "true" : "false") }' "$LOGDIR/pf-info.txt")"
# The EXACT form. `anchor "twinvpn/*"` also contains the word, and it is the
# form that evaluates nothing (packaging/pf.conf.include); a check that accepted
# it is how an inert anchor read as referenced.
anchor_referenced="$(awk '$0 ~ /^[[:space:]]*anchor "twinvpn"([[:space:]]|$)/ { f = 1 } \
  END { print (f ? "true" : "false") }' "$LOGDIR/pf-main-rules.txt")"
anchor_rule_count="$(awk '/^[[:space:]]*(block|pass|match)[[:space:]]/ { n++ } \
  END { print n + 0 }' "$LOGDIR/pf-anchor-rules.txt")"

# INTERSECTED with what pf reports rather than asserted, so `read_back_tables`
# names what was FOUND. `-s Tables` prints `<name>` or `--a-r-- <name>`, so the
# name is the last field — `parse_tables` reads it the same way.
read_back_tables="$(awk '{ print $NF }' "$LOGDIR/pf-anchor-tables.txt" | sort -u \
  | python3 -c "import sys
want = '$READ_BACK_TABLES'.split()
have = set(sys.stdin.read().split())
print(','.join(t for t in want if t in have))")"
read_back_matched=false
if [ "$read_back_tables" = "$(echo "$READ_BACK_TABLES" | tr ' ' ',')" ]; then
  read_back_matched=true
fi

echo "pf enabled: $pf_enabled | anchor referenced: $anchor_referenced | \
rules: $anchor_rule_count"
echo "read-back tables: ${read_back_tables:-<none>} (matched: $read_back_matched)"
echo "::endgroup::"

# --- 5. the behavioural proof ---
echo "::group::a packet into each covered prefix, and one that is not"
# A ROUTE IS A PRECONDITION FOR THE PROOF AND NOT PART OF THE CLAIM. pf sees a
# packet only if the kernel produced one; with no route the connect fails with
# ENETUNREACH before the filter is consulted, the deny counter cannot move, and
# this lane reports that it could not demonstrate the drop. The IPv6 probe
# route installed below is a precondition for producing a packet at all, not a
# part of the claim; the claim is decided by the anchor's own counters.
deny_v4_before="$(label_packets twinvpn.deny.v4 "$LOGDIR/pf-labels-before.txt")"
deny_v6_before="$(label_packets twinvpn.deny.v6 "$LOGDIR/pf-labels-before.txt")"
eval_v4_before="$(label_evals twinvpn.deny.v4 "$LOGDIR/pf-labels-before.txt")"
eval_v6_before="$(label_evals twinvpn.deny.v6 "$LOGDIR/pf-labels-before.txt")"

# THE IPv6 PROBE NEEDS A ROUTE, AND THE ROUTE IS A PRECONDITION, NOT THE CLAIM.
# A hosted runner has no IPv6 egress and no route covering the ULA prefix, so
# without one the kernel returns ENETUNREACH before pf is consulted and emits
# nothing. The claim under test is what pf does with a packet, so a route via
# en0 is installed for the probe and removed afterwards; pf sees the SYN on
# output before neighbour discovery can fail. Recorded in the log either way.
probe_v6_iface="$(route -n get default 2>/dev/null | awk '/interface:/ { print $2; exit }')"
probe_v6_route=false
if [ -n "$probe_v6_iface" ] \
   && sudo -n route -n add -inet6 "${PROBE_V6%::1}::/48" -interface "$probe_v6_iface" \
        > "$LOGDIR/pf-probe-route.txt" 2>&1; then
  probe_v6_route=true
fi
echo "IPv6 probe route via ${probe_v6_iface:-<no default interface>}: installed=$probe_v6_route"
route -n get "$PROBE_V4" > "$LOGDIR/pf-route-v4.txt" 2>&1 || true
route -n get -inet6 "$PROBE_V6" > "$LOGDIR/pf-route-v6.txt" 2>&1 || true

probe_v4="$(connect_probe "$PROBE_V4" "$PROBE_PORT")"
probe_v6="$(connect_probe "$PROBE_V6" "$PROBE_PORT")"
echo "connect $PROBE_V4:$PROBE_PORT   -> $probe_v4"
echo "connect [$PROBE_V6]:$PROBE_PORT -> $probe_v6"

control_probe="$(loopback_control_probe "$LOGDIR")"
echo "control connect 127.0.0.1 -> $control_probe"

# shellcheck disable=SC2024
sudo -n pfctl -a twinvpn -s labels > "$LOGDIR/pf-labels-after.txt" 2>&1 || true
if [ "$probe_v6_route" = true ]; then
  sudo -n route -n delete -inet6 "${PROBE_V6%::1}::/48" >> "$LOGDIR/pf-probe-route.txt" 2>&1 || true
fi
# THE DIAGNOSTICS THAT SEPARATE "loaded" FROM "evaluated", kept every run:
# per-rule evaluation counters in the main ruleset and inside the anchor, the
# anchor tree, and the two tables' contents.
# shellcheck disable=SC2024
{ sudo -n pfctl -vvs rules; echo '--- anchor twinvpn ---'; sudo -n pfctl -a twinvpn -vvs rules
  echo '--- anchors ---'; sudo -n pfctl -s Anchors -v
  echo '--- twinvpn_protected_v4 ---'; sudo -n pfctl -a twinvpn -t twinvpn_protected_v4 -T show
  echo '--- twinvpn_protected_v6 ---'; sudo -n pfctl -a twinvpn -t twinvpn_protected_v6 -T show
} > "$LOGDIR/pf-evaluations.txt" 2>&1 || true
deny_v4_after="$(label_packets twinvpn.deny.v4 "$LOGDIR/pf-labels-after.txt")"
deny_v6_after="$(label_packets twinvpn.deny.v6 "$LOGDIR/pf-labels-after.txt")"
eval_v4_after="$(label_evals twinvpn.deny.v4 "$LOGDIR/pf-labels-after.txt")"
eval_v6_after="$(label_evals twinvpn.deny.v6 "$LOGDIR/pf-labels-after.txt")"
echo "twinvpn.deny.v4 evaluations: $eval_v4_before -> $eval_v4_after  packets: $deny_v4_before -> $deny_v4_after"
echo "twinvpn.deny.v6 evaluations: $eval_v6_before -> $eval_v6_after  packets: $deny_v6_before -> $deny_v6_after"

# BOTH HALVES, BOTH FAMILIES, BOTH COUNTERS. The connect failing says a packet
# did not get through (a pf drop is silent on macOS, so it reads as a timeout);
# evaluations rising says the kernel stepped into THIS ANCHOR; packets rising
# says this rule is why. KS-5 gives no partial credit: one family without the
# other is non-conforming, not degraded.
covered_refused=false
if [ "${probe_v4#closed}" != "$probe_v4" ] && [ "${probe_v6#closed}" != "$probe_v6" ] \
   && [ "$eval_v4_after" -gt "$eval_v4_before" ] && [ "$deny_v4_after" -gt "$deny_v4_before" ] \
   && [ "$eval_v6_after" -gt "$eval_v6_before" ] && [ "$deny_v6_after" -gt "$deny_v6_before" ]; then
  covered_refused=true
fi
control_ok=false
if [ "$control_probe" = "open" ]; then control_ok=true; fi
echo "::endgroup::"

# --- 6. the start sequence, as root, across the production bridge ---
echo "::group::TwinVPNBridgeTests as root"
# WHY HERE AND NOT `ci-macos.sh --privileged`. That mode changes three variable
# assignments and contains no `sudo`, so on a hosted runner it would write
# `privileged: true` and `runner_kind: self-hosted` while `tvb_ext_start` still
# refused at `privilege_posture`. The uid of the process is the difference, so
# the existing bundle is run under sudo, after install.sh. As root the ADR-0016
# §11.6 start sequence passes `privilege_posture` and reaches
# `enforcement_reclaim`, which reclaims the owner-tagged ruleset and reads it
# back — Apple's pf answering this adapter's own queries for the first time. It
# stops short of `net.up`, which refuses at `enforce::arm` with
# `AUTH.IDENTITY_MISSING` for want of an overlay allocation, so nothing here
# claims a tunnel. LAST, on purpose: `enforcement_reclaim` may replace the
# anchor's CONTENT and every assertion above is about the BOOT artifact.
# shellcheck disable=SC1091
source "$REPO/build/ci/ci-common-apple.sh"
# FATAL, with no `||`. ADR-0018 §11.3 pins one exact toolchain, and a lane that
# recorded the mismatch instead of refusing would report a tick for a compiler
# nobody reviewed — which is the whole reason this assertion exists.
apple_require_pinned_swift
apple_require_xcodegen
"$SHELL_DIR/Scripts/build-bridge.sh" --profile release 2>&1 \
  | tee "$LOGDIR/pf-anchor-build-core.log"
compiled=true
( cd "$SHELL_DIR" && xcodegen generate )

bridge_rc=0
# No `sudo -E` and no `VAR=value`: `xcode-select -s` is SYSTEM-WIDE, so root
# resolves the same pinned Xcode with nothing carried across the privilege
# boundary — which is also what ADR-0016 Q10 asks of a privileged process.
sudo -n xcodebuild test \
  -project "$SHELL_DIR/TwinVPN.xcodeproj" \
  -scheme TwinVPNBridge \
  -destination 'platform=macOS' \
  -derivedDataPath "$LOGDIR/DerivedData-root" \
  -resultBundlePath "$RESULT_BUNDLE" \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY="" \
  2>&1 | tee "$LOGDIR/xctest-root.log" || bridge_rc=${PIPESTATUS[0]}
# Root ran it, so root owns the output; the upload step and `--cleanup` do not.
sudo -n chown -R "$(id -u):$(id -g)" "$LOGDIR/DerivedData-root" "$RESULT_BUNDLE" \
  2>/dev/null || true

# A SUITE THAT RAN NO CASE EXITS 0. XCTest's summary first, the result bundle
# second, so a changed console format costs a fallback rather than a red row;
# both empty answers to 0, which fails the verdict below.
bridge_test_count="$(awk '/Executed [0-9]+ test/ { if ($2 + 0 > n) n = $2 + 0 } \
  END { print n + 0 }' "$LOGDIR/xctest-root.log")"
if [ "$bridge_test_count" -eq 0 ] && [ -d "$RESULT_BUNDLE" ]; then
  bridge_test_count="$(xcrun xcresulttool get test-results summary \
    --path "$RESULT_BUNDLE" --format json 2>/dev/null \
    | python3 -c 'import json,sys; print(int(json.load(sys.stdin).get("totalTestCount") or 0))' \
    2>/dev/null || echo 0)"
fi
case "$bridge_test_count" in ''|*[!0-9]*) bridge_test_count=0 ;; esac

bridge_tests_as_root=false
if [ "$bridge_rc" -eq 0 ] && [ "$bridge_test_count" -gt 0 ]; then
  bridge_tests_as_root=true
fi
echo "xcodebuild test exit $bridge_rc, $bridge_test_count tests executed"
echo "::endgroup::"

# READ OUT OF THE SUITE'S OWN OUTPUT, never written here; an empty array is the
# correct evidence for a run that reached no transition, and fails the verdict.
transitions="$(apple_transitions_from "$LOGDIR/xctest-root.log")"

# --- 7. the verdict, and the evidence ---
verdict="FAIL"
if [ "$pf_enabled" = true ] && [ "$anchor_referenced" = true ] \
   && [ "$anchor_rule_count" -gt 0 ] && [ "$read_back_matched" = true ] \
   && [ "$covered_refused" = true ] && [ "$control_ok" = true ] \
   && [ "$ksd_apply_exit" -eq 0 ] && [ "$ksd_status_exit" -eq 0 ] \
   && [ "$bridge_tests_as_root" = true ] && [ "$transitions" != "[]" ]; then
  verdict="PASS"
fi

notes="The KS-19 BOOT anchor, not an armed contract. net.up refuses at \
enforce::arm with AUTH.IDENTITY_MISSING for want of an overlay allocation, so \
nothing here claims a tunnel, an exit or an egress path -- which is also why it \
carries no leak-oracle session: the prefixes it denies are RFC 6598 and ULA \
space no public observer sees. A step that fails before this write leaves NO \
evidence file and the row reads NOT-EXECUTED; the job outcome recorded by \
build/ci/require-job-results.py separates that from a lane that never ran."

cat > "$EVIDENCE" <<JSON
{
  "schema_version": 2,
  "platform": "macos",
  "criterion": "$CRITERION",
  "job_name": "${GITHUB_JOB:-macos-pf-anchor}",
  "runner": "${RUNNER_NAME:-local}",
  "runner_kind": "$runner_kind",
  "privileged": $privileged,
  "github_run_id": $([ -n "${GITHUB_RUN_ID:-}" ] && echo "\"$GITHUB_RUN_ID\"" || echo null),
  "github_run_attempt": $(twinvpn_run_attempt_json),
  "repository": $(twinvpn_repository_json),
  "artifact_digests": $ARTIFACT_DIGESTS,
  "github_run_url": $([ -n "${GITHUB_RUN_ID:-}" ] && echo "\"${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-}/actions/runs/$GITHUB_RUN_ID\"" || echo null),
  "commit": "$(cd "$REPO" && git rev-parse HEAD)",
  "toolchain": {
    "macos": "$macos_version",
    "macos_build": "$(sw_vers -buildVersion)",
    "xcodebuild": "$(xcodebuild -version 2>/dev/null | head -1)",
    "swift": "$(swift --version 2>&1 | head -1)",
    "rustc": "$(rustc --version)"
  },
  "environment": {
    "macos_version": "$macos_version",
    "sip_config": "$sip_config",
    "pf_enabled": $pf_enabled,
    "anchor_referenced_in_main_ruleset": $anchor_referenced,
    "anchor_rule_count": $anchor_rule_count,
    "read_back_tables": "$read_back_tables",
    "covered_prefix_connect_refused": $covered_refused,
    "control_connect_succeeded": $control_ok,
    "ksd_status_exit": $ksd_status_exit,
    "bridge_tests_as_root": $bridge_tests_as_root,
    "bridge_test_count": $bridge_test_count
  },
  "leak_oracle": null,
  "compiled": $compiled,
  "linked_real_core": $bridge_tests_as_root,
  "loaded": $bridge_tests_as_root,
  "invoked_core": $bridge_tests_as_root,
  "received_result": $bridge_tests_as_root,
  "lifecycle_transitions": $transitions,
  "graceful_shutdown": $bridge_tests_as_root,
  "test_command": "build/ci/ci-macos-pf-anchor.sh",
  "test_exit_code": $([ "$verdict" = PASS ] && echo 0 || echo 1),
  "artifacts": [
    "build/ci/logs/macos/pf-anchor-install.log",
    "build/ci/logs/macos/ksd-apply.log", "build/ci/logs/macos/ksd-status.log",
    "build/ci/logs/macos/pf-info.txt", "build/ci/logs/macos/pf-main-rules.txt",
    "build/ci/logs/macos/pf-anchor-rules.txt",
    "build/ci/logs/macos/pf-anchor-tables.txt",
    "build/ci/logs/macos/pf-labels-before.txt",
    "build/ci/logs/macos/pf-evaluations.txt", "build/ci/logs/macos/pf-probe-route.txt",
    "build/ci/logs/macos/pf-route-v4.txt", "build/ci/logs/macos/pf-route-v6.txt",
    "build/ci/logs/macos/pf-labels-after.txt", "build/ci/logs/macos/xctest-root.log"
  ],
  "notes": "$notes",
  "verdict": "$verdict",
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON

echo
echo "=== macOS pf boot-anchor evidence ==="
cat "$EVIDENCE"

[ "$verdict" = "PASS" ] || {
  echo "::error::$CRITERION did not pass: pf_enabled=$pf_enabled \
anchor_referenced=$anchor_referenced anchor_rule_count=$anchor_rule_count \
read_back_matched=$read_back_matched covered_prefix_connect_refused=$covered_refused \
control_connect_succeeded=$control_ok ksd_apply=$ksd_apply_exit \
ksd_status=$ksd_status_exit bridge_tests_as_root=$bridge_tests_as_root \
bridge_test_count=$bridge_test_count transitions=$transitions" >&2
  exit 1
}
