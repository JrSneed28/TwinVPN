#!/usr/bin/env python3
"""The run bindings and the oracle adjudication `report.py` applies to evidence.

WHY THIS IS A SEPARATE FILE
===========================
`report.py` is the report: the criteria, the probes, the table. This module is
the part of it that answers a narrower and nastier question -- "is this evidence
even ABOUT the thing we are grading?" -- and it lives here because report.py is
already long enough that burying another three tables in it would hide them.
Nothing in this file prints anything or decides a row; every function returns a
list of human-readable problems, and an empty list is the only thing that means
"nothing wrong was found".

THE THREE HOLES THESE GUARDS CLOSE, each stated in full at the function that
closes it:

(1) EVIDENCE FROM SOMEWHERE ELSE -- `check_run_binding`. The commit binding was
    already checked and is not enough: a re-run of the same commit produces a
    new run id and a new run attempt, so an artifact from an earlier attempt
    carries the CORRECT SHA while describing a machine that no longer exists.

(2) THE ARTIFACT WAS NEVER NAMED -- `ARTIFACT_DIGEST_REQUIRED`. Without a
    digest, "we tested the release APK" is a sentence in a JSON file.

(3) THE ORACLE'S REPORT WAS READ FOR ITS VERDICT ALONE --
    `check_oracle_adjudication`. "Nothing arrived" means "the kill switch held"
    only if the oracle was demonstrably still listening, the device was
    demonstrably still probing, and the two paths being compared were
    demonstrably distinct. Those are independent facts, they are all in the
    oracle's own report, and every one of them defaults to FAILURE when absent:
    an absent `ipv4_sentinel_continuous` is what a broken oracle writes, and
    reading it as `true` would make a dead observer the strongest possible
    evidence of safety.
"""

from __future__ import annotations

import json
import os
import re

# A key that must be present and non-empty, without a fixed value. Shared with
# `report.py`'s PREREQUISITES table, which is why it lives here rather than
# there: the path-identity rows below extend that table and need the same
# sentinel object, and two `object()`s would silently never compare equal.
REQUIRED = object()

# 64 lowercase hex, anchored. Uppercase is refused rather than normalised: a
# digest that arrived in the wrong case came from a different tool than the one
# the pipeline is documented to use, and quietly folding the case would hide
# that the producer is not the producer we think it is.
HEX64 = re.compile(r"^[0-9a-f]{64}$")


# ---------------------------------------------------------------------------
# WHICH ARTIFACT EACH CRITERION IS ABOUT
# ===========================================================================
#
# The keys are LOGICAL artifact names, not filenames. A filename is the thing
# most likely to be changed by a build-script tweak that has nothing to do with
# the criterion, and a table keyed on filenames would then fail every row for a
# rename -- after which somebody relaxes the table and the binding is gone. The
# producing job chooses the name once, records it in `artifact_digests`, and it
# never changes because it does not describe the disk.
#
# Each entry answers "what, exactly, did this criterion grade?":
#
#   * ANDROID-16K-PAGE-SIZE is a claim about the `.so` inside the SHIPPED APK.
#     The debug APK is a different artifact -- unminified, not shrunk, packaged
#     differently -- so `apk-release` is the only one whose digest counts.
#   * The three iOS criteria run the SIGNED IPA on a Corellium instance, and the
#     entire reason that lane exists is that the IPA is not re-signed. A digest
#     is how a reader knows the archive that was uploaded is the archive whose
#     entitlements were read.
#   * MACOS-PRODUCTION-SIGNATURE inspects the NOTARIZED PRODUCT fetched from the
#     release pipeline, never a build made on the runner. Its digest is what
#     distinguishes the two, and they are otherwise indistinguishable in the
#     evidence.
#   * MACOS-SYSEXT-LIFECYCLE needs BOTH: an app can activate a system extension
#     that came from a different build than the app bundle, and the lifecycle it
#     then drives is a lifecycle of something nobody assembled on purpose.
#   * WINDOWS-WFP-KILLSWITCH runs a binary built for and copied into a
#     throwaway guest. The copy is the step where a stale binary gets in.
#
# WHAT A DIGEST DOES AND DOES NOT PROVE, because the two are easy to conflate
# and only one of them is a binding. An artifact that CROSSED A JOB BOUNDARY --
# the IPA and the notarized `TwinVPN.app.zip`, both fetched from a URL the
# release pipeline publishes -- is bound by its digest: the digest is the only
# thing tying the bytes that were graded to the bytes somebody built and
# published. An artifact BUILT AND USED IN ONE JOB, which today is every APK,
# the sysext-lifecycle app and the Windows binaries, gets INTEGRITY from its
# digest and not provenance: it says the thing installed is the thing built
# moments earlier in the same job, which is worth recording and is not a chain
# of custody. Do not read a same-job digest as proof of where the build came
# from, and do not weaken the requirement because of that -- the day one of
# those builds moves into its own job, the field is already there and already
# checked.
ARTIFACT_DIGEST_REQUIRED = {
    "ANDROID-16K-PAGE-SIZE": ("app-release.apk",),
    "IOS-NE-FAIL-CLOSED": ("TwinVPN.ipa",),
    "IOS-PROFILE-REMOVAL-HONESTY": ("TwinVPN.ipa",),
    "IOS-SUPERVISED-ALWAYS-ON": ("TwinVPN.ipa",),
    # BOTH HALVES OF THE NOTARIZED PRODUCT. `TwinVPN.app.zip` is the operator's
    # PINNED digest, recorded verbatim rather than recomputed -- it is the digest
    # the download was gated on, and it is the only real chain of custody in this
    # table, because it is the one artifact that came from the release pipeline
    # rather than from a runner. The executable digest is what the criterion
    # actually inspected. A file carrying only the executable is evidence about
    # something the workflow built or fetched unverified, which is precisely the
    # thing this criterion exists to distinguish from the shipped product.
    "MACOS-PRODUCTION-SIGNATURE": ("TwinVPN.app/Contents/MacOS/TwinVPN",
                                   "TwinVPN.app.zip"),
    # BOTH, and the second one is the one that does not exist yet. An app can
    # activate a system extension built from a different tree than the app
    # bundle, and the lifecycle it then drives belongs to a pairing nobody
    # assembled on purpose -- so a digest of the app alone cannot discharge this
    # criterion -- and the app key names the executable PATH for exactly that
    # reason: a .app is a directory with no single-file digest, so the value
    # covers `Contents/MacOS/TwinVPN` and not the Info.plist or the nested
    # extension. A key called `TwinVPN.app` would imply it covered both, which
    # is the implication that lets one digest stand in for two artifacts.
    "MACOS-SYSEXT-LIFECYCLE": ("TwinVPN.app/Contents/MacOS/TwinVPN",
                               "net.twinvpn.client.tunnel.systemextension"),
    "WINDOWS-WFP-KILLSWITCH": ("twinvpnsvc.exe",),
}


# ---------------------------------------------------------------------------
# PATH IDENTITY, ATTESTED ON THE DEVICE SIDE
# ===========================================================================
#
# The oracle proves the two paths were distinct AS OBSERVED. This proves they
# were ESTABLISHED, and the two are not the same claim.
#
# THE FAILURE. A kill-switch session where the "unprotected" control leg never
# came up produces an oracle report with zero arrivals on both legs and nothing
# to compare -- and zero arrivals is exactly what a passing session looks like.
# The session then proves that a device with no working network sent no packets,
# which is true of a device in a drawer. Worse, if both legs go out through the
# SAME interface because the "protected" path silently fell back, the identities
# overlap, every arrival is attributable to either leg, and the oracle cannot
# tell a leak from a control probe.
#
# So each egress criterion attests, from the machine: that it brought a
# protected path up, that it brought a separate unprotected control path up, and
# what source identity each one presents. `DISTINCT_PATH_KEYS` then refuses the
# case where the two identities are the same string, which is the overlap
# described above wearing two names.
#
# AND `probe_host`, WHICH IS THE SAME FAILURE ONE LAYER DOWN. A leak probe run
# on the CI controller rather than on the device under test measures the
# CONTROLLER's egress: its attempts are the controller's attempts, its silence
# is the controller's silence, and the device the criterion is about may have
# been leaking throughout. Every number in the oracle's report is then about the
# wrong machine while remaining internally consistent -- the sentinel held, the
# attempt count is high, the identities are distinct, and the row is a
# measurement of a host nobody is making a claim about. `ci-ios-corellium.sh`
# does exactly this today, which is why the key exists and why `device` is the
# only accepted value: it means the DUT, whatever shape it takes -- the
# disposable Hyper-V guest, the virtual iPhone, the EC2 Mac itself.
PATH_IDENTITY_PREREQUISITES = {
    "protected_path_established": (True,),
    "unprotected_path_established": (True,),
    "protected_path_identity": REQUIRED,
    "unprotected_path_identity": REQUIRED,
    "probe_host": ("device",),
}

DISTINCT_PATH_KEYS = ("protected_path_identity", "unprotected_path_identity")


def path_identity_problems(criterion: str, env: dict, oracle_required) -> list[str]:
    """The one prerequisite that compares two keys rather than checking one.

    `check_environment` grades keys independently, so it cannot see that the
    protected and unprotected identities are the same string -- which is the
    overlap that makes every arrival unattributable and every silence
    meaningless. This is that comparison, and it is deliberately a string
    equality: the identities are opaque to this script, and the only thing it is
    entitled to conclude is that two equal strings are not two paths.
    """
    if criterion not in oracle_required:
        return []
    a, b = DISTINCT_PATH_KEYS
    if a not in env or b not in env:
        return []          # already reported as unmeasured by check_environment
    if env[a] == env[b]:
        return [f"`{a}` and `{b}` are both {env[a]!r}, so the protected and "
                f"unprotected legs share one source identity: no arrival can be "
                f"attributed to either, and the session's silence proves nothing"]
    return []


# ---------------------------------------------------------------------------
# THE RUN BINDING
# ---------------------------------------------------------------------------

def _expected(name: str) -> str:
    """What the environment says this run is, `TWINVPN_EXPECTED_*` winning.

    The override lets the binding be exercised outside Actions, and it is
    checked FIRST so a local re-derivation from downloaded artifacts is not
    silently graded against whatever GitHub variables happen to be exported.
    """
    return (os.environ.get(f"TWINVPN_EXPECTED_{name}")
            or os.environ.get(f"GITHUB_{name}") or "")


def check_run_binding(criterion: str, ev: dict) -> list[str]:
    """Repository, run attempt and artifact digests. Commit and run id are in
    `report.py` already; this is the rest of the tuple.

    THE CASE THIS IS FOR, again because it is the one that looks harmless: a job
    is re-run. Attempt 1 failed, attempt 2 is green, and an artifact from
    attempt 1 is still in the run's artifact store under the same name. It
    downloads, it carries the right commit, it carries the right run id, and it
    describes a guest that was destroyed hours ago. Only the attempt number
    separates the two, so the attempt number is checked, and evidence that never
    recorded one cannot be bound to any run at all.
    """
    problems: list[str] = []

    repo = _expected("REPOSITORY")
    if repo:
        got = ev.get("repository")
        if got is None:
            problems.append("the evidence records no `repository`, so it cannot "
                            "be bound to this repository's run")
        elif str(got) != repo:
            problems.append(f"the evidence was produced for repository {got!r}, "
                            f"not {repo}")

    attempt = _expected("RUN_ATTEMPT")
    got_attempt = ev.get("github_run_attempt")
    if got_attempt in (None, ""):
        problems.append("the evidence records no `github_run_attempt`; a re-run "
                        "produces the same commit and the same run id, so "
                        "without the attempt this file cannot be told apart from "
                        "an artifact left behind by a previous, failed attempt")
    elif attempt and str(got_attempt) != attempt:
        problems.append(f"the evidence was produced on run attempt "
                        f"{got_attempt!r}, not attempt {attempt} -- same commit, "
                        f"different run: a rumour from another attempt")

    problems += _artifact_digest_problems(criterion, ev)
    return problems


def _artifact_digest_problems(criterion: str, ev: dict) -> list[str]:
    names = ARTIFACT_DIGEST_REQUIRED.get(criterion)
    if not names:
        return []
    digests = ev.get("artifact_digests")
    if not isinstance(digests, dict) or not digests:
        return [f"the evidence carries no `artifact_digests`, so nothing "
                f"identifies which build {criterion} was actually run against; "
                f"expected {', '.join(names)}"]

    problems = []
    # A digest the PRODUCING job wrote about itself is a self-report. This is
    # what the aggregator recomputed after downloading, and a disagreement means
    # the bytes that were graded are not the bytes that were built.
    verified = {}
    raw = os.environ.get("TWINVPN_EXPECTED_ARTIFACT_DIGESTS")
    if raw:
        try:
            verified = json.loads(raw)
        except json.JSONDecodeError as exc:
            problems.append(f"TWINVPN_EXPECTED_ARTIFACT_DIGESTS is not valid "
                            f"JSON: {exc}")
            verified = {}

    for name in names:
        got = digests.get(name)
        if got in (None, ""):
            problems.append(f"no SHA-256 for the `{name}` artifact, so the "
                            f"criterion names no specific build")
            continue
        if not isinstance(got, str) or not HEX64.match(got):
            problems.append(f"the `{name}` digest {got!r} is not 64 lowercase "
                            f"hex characters, so it is not a SHA-256 this "
                            f"report can compare against anything")
            continue
        want = verified.get(name)
        if want and want != got:
            problems.append(f"the `{name}` artifact hashes to {want} after "
                            f"download but the evidence claims {got}: the build "
                            f"that was graded is not the build that shipped here")
    return problems


# ---------------------------------------------------------------------------
# THE TWO ANDROID RULES THE FLAT TABLE CANNOT STATE
# ===========================================================================
#
# `PREREQUISITES` grades one key against one expected value, which covers every
# other prerequisite in the report. These two need more than that, and flattening
# them into booleans the job computes for itself would move the check to the
# defendant -- the job would grade its own ABI sweep and write `true`, and the
# map holding the actual per-ABI numbers would sit beside it, ungraded.

ANDROID_16K = "ANDROID-16K-PAGE-SIZE"

# The ABI a real phone loads. `page_size == 16384` proves the EMULATOR booted
# with 16 KiB pages, and the emulator is x86_64: it can never load the arm64
# libraries the criterion is actually about. A map covering only x86_64, every
# entry aligned, is a green row about the one ABI no customer runs.

# The ABIs the 16 KiB criterion grades. Must stay identical to
# `build/ci/elf-align.py`'s GATED_ABIS -- a producer and a checker that
# disagree about scope is the exact defect the `repository` key already cost us.
GATED_ABIS = ("arm64-v8a", "x86_64")
REAL_DEVICE_ABI = "arm64-v8a"


def android_environment_problems(criterion: str, env: dict) -> list[str]:
    """Per-ABI load alignment, and that the booted image is the 16 KiB one."""
    if criterion != ANDROID_16K:
        return []
    problems = []

    # A CONFIGURED IMAGE IS NOT A BOOTED IMAGE. `system_image_package` is read
    # back from the installed package, so a run that resolved a `ps16k` image
    # and then booted something else is caught here rather than believed.
    package = env.get("system_image_package")
    if not isinstance(package, str) or "ps16k" not in package:
        problems.append(f"`system_image_package` is {package!r}, which does not "
                        f"name a `ps16k` image: the device that booted is not "
                        f"the 16 KiB one this criterion is about")

    abis = env.get("abi_load_alignment")
    if not isinstance(abis, dict) or not abis:
        problems.append("`abi_load_alignment` is missing or empty, so no ABI's "
                        "load alignment was measured at all")
        return problems
    # ONLY THE 64-BIT ABIs ARE GRADED, AND A 32-BIT `false` IS NOT A DEFECT.
    #
    # Android's 16 KB page size is a 64-bit requirement, and the NDK's clang
    # driver encodes that: it passes `-z max-page-size=16384` for android
    # aarch64 and x86_64 and `-z max-page-size=4096` for android 32-bit ARM, on
    # purpose, to reduce VMA usage. Run 33321779286 measured exactly that --
    # arm64-v8a and x86_64 at 16384, armeabi-v7a and x86 at 4096 -- on a build
    # that asks for 16384 on all four. Grading all four therefore failed the
    # criterion for a property the platform does not ask for, on two ABIs that
    # cannot be installed on a 16 KiB device at all.
    #
    # The 32-bit rows stay in the map and stay visible. They are measured and
    # not graded, which is a different thing from absent, and `build/ci/elf-align.py`
    # keeps the same split so the producer and this checker cannot drift.
    graded = {abi: v for abi, v in abis.items() if abi in GATED_ABIS}
    if not graded:
        problems.append(f"`abi_load_alignment` names {', '.join(sorted(abis))} "
                        f"but none of {', '.join(GATED_ABIS)}, so the criterion "
                        f"measured no ABI it is actually about")
    unaligned = sorted(abi for abi, v in graded.items()
                       if not isinstance(v, dict) or v.get("aligned") is not True)
    if unaligned:
        problems.append(f"`abi_load_alignment` is not true for: "
                        f"{', '.join(unaligned)} -- the shipped `.so` for those "
                        f"ABIs will not map on a 16 KiB-page device")
    if REAL_DEVICE_ABI not in abis:
        problems.append(f"`abi_load_alignment` covers {', '.join(sorted(abis))} "
                        f"but not {REAL_DEVICE_ABI}, which is the ABI real "
                        f"phones load and the one the x86_64 emulator can never "
                        f"exercise: the criterion is undischarged for it")
    return problems
