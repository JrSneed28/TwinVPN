#!/usr/bin/env bash
#
# check-chrome-strings.sh — the chrome/reason-code boundary, as a check.
#
# ADR-0018 CB-4 splits the two: the CORE resolves a `reason_code` into a
# sentence, and the SHELL presents its own chrome. This app once got that
# backwards — eleven `ui.*` keys were handed to `tw_render_diagnostic` AS reason
# codes, on the strength of a comment claiming a "sibling entry point" to it
# that `core/ffi/include/twinvpn.h` does not have. `ObservedReasonCode::parse`
# rejects a lowercase byte, `render` degrades to `Domain::Internal`, and the
# INTERNAL fallback is "TwinVPN hit a defect in itself." — which is what the
# three tabs, the navigation titles and the buttons were labelled with.
#
# Comments did not stop that (the file carried one saying the opposite), and
# R-15 is the same defect class on another surface, so this is the mechanical
# form. Three things are asserted:
#
#   1. Every `String(localized: "k")` in Sources/ names a key the catalogue has.
#      A missing key does not fail the build: `String(localized:)` returns the
#      KEY, so a typo ships a tab labelled "nav_stauts".
#   2. Every catalogue key is used. An unused chrome string is either dead or a
#      call site that quietly went back to a literal.
#   3. The only `ui.*` keys still routed to the core as reason codes are the
#      three `ui.protection.*` ones. Those are NOT chrome — a sentence about
#      security posture is ADR-0019 §11.4's territory, not a tab label — and
#      they are deliberately left where they are until it is decided whether
#      they deserve registered reason codes. They have the same defect today.
#      Anything else appearing on that path is the original defect returning.
#
# Pure text analysis: no Xcode, no Swift toolchain, no Darwin. It runs on the
# Linux build host, which is the point — the defect it pins was invisible to
# `swiftc -parse`, and a check that needs a Mac would not have caught it either.
#
# WHO CALLS THIS TODAY: NOBODY, AND THAT IS RECORDED RATHER THAN HIDDEN.
# `build/ci/ci-ios.sh` is owned by the CI owner and adding a line to it is not
# this shell's to do. Run it by hand, or ask for it to be wired next to
# `Scripts/stage-headers.sh`. Exits non-zero on any failure so wiring it is one
# line when someone does.

set -euo pipefail

cd "$(dirname "$0")/.."

python3 - "$PWD" <<'PY'
import json
import pathlib
import re
import sys

shell = pathlib.Path(sys.argv[1])
catalogue_path = shell / "Sources/TwinVPNApp/Resources/Localizable.xcstrings"

catalogue = json.loads(catalogue_path.read_text(encoding="utf-8"))
declared = set(catalogue["strings"])

sources = sorted((shell / "Sources").rglob("*.swift"))
used = set()
routed = set()
for path in sources:
    text = path.read_text(encoding="utf-8")
    used |= set(re.findall(r'String\(localized:\s*"([^"]+)"', text))
    # A `ui.*` literal anywhere in a source line that is not a comment is a key
    # on its way to the core. The comments in `CoreLite` and `TwinVPNApp`
    # describe the old defect and must not themselves trip this.
    for line in text.splitlines():
        if line.lstrip().startswith(("//", "///", "*")):
            continue
        routed |= set(re.findall(r'"(ui\.[^"]*)"', line))

failures = []

missing = sorted(used - declared)
if missing:
    failures.append(
        "String(localized:) names %d key(s) the catalogue does not carry, which "
        "render as the raw key: %s" % (len(missing), ", ".join(missing)))

unused = sorted(declared - used)
if unused:
    failures.append(
        "the catalogue carries %d key(s) no call site uses: %s"
        % (len(unused), ", ".join(unused)))

# `ui.protection.\(assertion.state.rawValue)` is one interpolated literal
# covering the three states, so it is matched by its prefix rather than spelled
# out three times.
allowed = {"ui.protection.unknown", "ui.protection.\\(assertion.state.rawValue)"}
stray = sorted(routed - allowed)
if stray:
    failures.append(
        "%d `ui.*` key(s) are still handed to the core as reason codes and will "
        "render \"TwinVPN hit a defect in itself.\": %s"
        % (len(stray), ", ".join(stray)))

if failures:
    print("==> chrome strings                        FAIL")
    for failure in failures:
        print("    %s" % failure)
    sys.exit(1)

print("==> chrome strings                        OK "
      "(%d catalogue keys, all used; %d deliberate ui.protection.* routings)"
      % (len(declared), len(routed)))
PY
