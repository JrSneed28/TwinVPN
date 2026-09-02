#!/usr/bin/env python3
"""Whether the MACHINE was capable of the claim, before any test result is read.

Split out of `test_report_prerequisites.py`, which imports it back so the one
command still runs everything -- the platform prerequisite cases outgrew that
file's 500-line ceiling and were being paid for in deleted comments.

Every case here builds evidence that is otherwise perfect and breaks one
environment key. The keys are not interchangeable trivia: each one is a machine
capability that some green, well-formed evidence file once claimed without
having.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence_fixtures as fx  # noqa: E402
from gate_harness import GateCase  # noqa: E402

# The two rows that run on a SIMULATOR, and the builder for each. They share
# every simulator pin, so the cases that grade those pins are written once and
# driven off this table rather than copied per row.
SIMULATOR_ROWS = (
    ("ios-failclosed-configuration", "IOS-FAILCLOSED-CONFIGURATION",
     fx.ios_failclosed_configuration),
    ("ios-profile-removal", "IOS-PROFILE-REMOVAL-HONESTY",
     fx.ios_profile_removal),
)


class EnvironmentAttestation(GateCase):
    """Whether the MACHINE was capable of the claim, before any test result."""

    def test_evidence_with_no_environment_map_is_refused(self):
        ev = fx.android()
        del ev["environment"]
        self.assertRefused("android-16k", "ANDROID-16K-PAGE-SIZE", ev)

    def test_windows_unprivileged_is_refused(self):
        self.assertRefused("windows-killswitch", "WINDOWS-WFP-KILLSWITCH",
                           fx.windows(privileged=False), fx.oracle())

    def test_windows_without_the_base_filtering_engine_is_refused(self):
        self.assertRefused("windows-killswitch", "WINDOWS-WFP-KILLSWITCH",
                           fx.windows(bfe_running=False), fx.oracle())

    def test_windows_without_installed_filters_is_refused(self):
        self.assertRefused("windows-killswitch", "WINDOWS-WFP-KILLSWITCH",
                           fx.windows(twinvpn_filters_installed=False),
                           fx.oracle())

    def test_windows_on_a_non_disposable_guest_is_refused(self):
        # Filters outlive the process by design, so a run on anything but a
        # throwaway guest either severed the CI controller or never armed.
        self.assertRefused("windows-killswitch", "WINDOWS-WFP-KILLSWITCH",
                           fx.windows(guest_disposable=False), fx.oracle())
        self.assertRefused("windows-killswitch", "WINDOWS-WFP-KILLSWITCH",
                           fx.windows(guest_kind="ci-controller"), fx.oracle())

    def test_an_unmeasured_prerequisite_is_refused(self):
        ev = fx.windows()
        del ev["environment"]["wfp_write_probe"]
        self.assertRefused("windows-killswitch", "WINDOWS-WFP-KILLSWITCH", ev,
                           fx.oracle())

    def test_android_on_a_4096_byte_page_emulator_is_refused(self):
        # THE CASE THIS WHOLE MECHANISM EXISTS FOR: every test green, every
        # boolean true, and the one number the criterion is about is wrong.
        self.assertRefused("android-16k", "ANDROID-16K-PAGE-SIZE",
                           fx.android(page_size=4096))

    def test_android_debug_apk_is_not_the_production_apk(self):
        self.assertRefused("android-16k", "ANDROID-16K-PAGE-SIZE",
                           fx.android(apk_variant="debug"))

    def test_android_failed_zipalign_is_refused(self):
        self.assertRefused("android-16k", "ANDROID-16K-PAGE-SIZE",
                           fx.android(zipalign_p16=False))

    def test_android_pending_jni_exception_is_refused(self):
        # A native call that left an exception pending returned to Kotlin
        # anyway; the result the test read is whatever was on the stack.
        self.assertRefused("android-16k", "ANDROID-16K-PAGE-SIZE",
                           fx.android(jni_pending_exception=True))
        self.assertRefused("android-16k", "ANDROID-16K-PAGE-SIZE",
                           fx.android(jni_pending_exception=None))

    def test_android_carrying_its_own_tunnel_is_refused(self):
        # A tunnel must never carry itself. The instrumented test was proving
        # this and nothing was recording it; `null` is what a run where the test
        # did not execute writes, and it must not read as a pass.
        for bad in (False, None):
            self.assertRefused("android-16k", "ANDROID-16K-PAGE-SIZE",
                               fx.android(underlay_excludes_vpn=bad))

    def test_android_unmeasured_load_alignment_is_refused(self):
        for bad in (None, {}, "yes"):
            detail = self.assertRefused("android-16k", "ANDROID-16K-PAGE-SIZE",
                                        fx.android(abi_load_alignment=bad))
            self.assertIn("abi_load_alignment", detail)

    def test_android_one_unaligned_abi_fails_the_row(self):
        self.assertRefused("android-16k", "ANDROID-16K-PAGE-SIZE", fx.android(
            abi_load_alignment={
                "arm64-v8a": {"aligned": False, "min_p_align": 4096},
                "x86_64": {"aligned": True, "min_p_align": 16384}}))

    def test_android_alignment_that_skips_arm64_is_refused(self):
        # THE ONE THE EMULATOR CANNOT EXERCISE. `page_size == 16384` proves the
        # x86_64 emulator booted with 16 KiB pages; arm64-v8a is what a customer
        # loads, and a map covering only x86_64 is a green row about the one ABI
        # nobody ships to.
        detail = self.assertRefused("android-16k", "ANDROID-16K-PAGE-SIZE",
                                    fx.android(abi_load_alignment={
                                        "x86_64": {"aligned": True,
                                                   "min_p_align": 16384}}))
        self.assertIn("arm64-v8a", detail)

    def test_android_32_bit_abis_are_measured_but_not_graded(self):
        # THE ONE THAT COST A CI RUN. Android's 16 KB page size is a 64-bit
        # requirement, and the NDK clang driver passes `-z max-page-size=4096`
        # for android 32-bit ARM deliberately, to reduce VMA usage. Run
        # 33321779286 measured arm64-v8a and x86_64 at 16384 and armeabi-v7a
        # and x86 at 4096, on a build asking for 16384 on all four -- and the
        # row failed, for a property the platform does not ask for, on two ABIs
        # that cannot be installed on a 16 KiB device at all.
        #
        # They stay in the map. Measured-and-not-graded is a different thing
        # from absent, and a reader must still be able to see what they were.
        self.assertGreen("android-16k", "ANDROID-16K-PAGE-SIZE", fx.android(
            abi_load_alignment={
                "arm64-v8a":   {"aligned": True,  "min_p_align": 16384},
                "x86_64":      {"aligned": True,  "min_p_align": 16384},
                "armeabi-v7a": {"aligned": False, "min_p_align": 4096},
                "x86":         {"aligned": False, "min_p_align": 4096}}))

    def test_android_alignment_naming_only_32_bit_abis_is_refused(self):
        # The other side of the same rule: not grading the 32-bit ABIs must not
        # become not grading anything. A map with no 64-bit ABI in it measured
        # nothing the criterion is about.
        detail = self.assertRefused("android-16k", "ANDROID-16K-PAGE-SIZE",
                                    fx.android(abi_load_alignment={
                                        "armeabi-v7a": {"aligned": True,
                                                        "min_p_align": 16384}}))
        self.assertIn("arm64-v8a", detail)

    def test_android_on_a_non_ps16k_system_image_is_refused(self):
        # A configured image is not a booted one: the package is read back from
        # what installed, so resolving `ps16k` and then booting something else
        # is caught here rather than believed.
        for bad in ("system-images;android-36;google_apis;x86_64", None, 36):
            self.assertRefused("android-16k", "ANDROID-16K-PAGE-SIZE",
                               fx.android(system_image_package=bad))

    def test_android_without_the_booted_device_metadata_is_refused(self):
        # The 16 KiB lane exits non-zero when any of these is unreadable, so a
        # file that reaches the report without them came from somewhere else.
        for key in ("api_level", "build_fingerprint", "kernel_release",
                    "system_image_revision"):
            ev = fx.android()
            del ev["environment"][key]
            self.assertRefused("android-16k", "ANDROID-16K-PAGE-SIZE", ev)

    def test_macos_extension_not_activated_is_refused(self):
        self.assertRefused("macos-sysext", "MACOS-SYSEXT-LIFECYCLE",
                           fx.macos_sysext(
                               systemextensionsctl_state="activated waiting for user"),
                           fx.oracle("sess-mac", "MACOS-SYSEXT-LIFECYCLE"))

    def test_macos_unstapled_product_is_refused(self):
        self.assertRefused("macos-signature", "MACOS-PRODUCTION-SIGNATURE",
                           fx.macos_signature(stapled=False))

    def test_macos_product_whose_nested_extension_is_unticketed_is_refused(self):
        # A signed, notarized, stapled APP whose .systemextension is in nobody's
        # ticket. Every other key in the file is true and the top-level checks
        # cannot see it: `spctl` assesses only the outer bundle, and the ticket
        # `stapler validate` finds is the outer bundle's. The row must be red on
        # the extension alone, and it must also be red when nothing measured it
        # -- an app bundle with no extension in it writes `false`, not nothing.
        detail = self.assertRefused("macos-signature",
                                    "MACOS-PRODUCTION-SIGNATURE",
                                    fx.macos_signature(sysext_notarized=False))
        self.assertIn("sysext_notarized", detail)
        ev = fx.macos_signature()
        del ev["environment"]["sysext_notarized"]
        self.assertRefused("macos-signature", "MACOS-PRODUCTION-SIGNATURE", ev)

    def test_lifecycle_evidence_cannot_discharge_the_signature_criterion(self):
        # A green developer-mode lifecycle once read as "the signed, notarized
        # product works". These are two criteria now, and neither file can be
        # read as the other.
        self.assertRefused("macos-signature", "MACOS-PRODUCTION-SIGNATURE",
                           fx.macos_sysext())

    def test_signature_evidence_cannot_discharge_the_lifecycle_criterion(self):
        self.assertRefused("macos-sysext", "MACOS-SYSEXT-LIFECYCLE",
                           fx.macos_signature(),
                           fx.oracle("sess-mac", "MACOS-SYSEXT-LIFECYCLE"))

    def test_macos_pf_anchor_that_is_loaded_but_not_enforcing_is_refused(self):
        # THE WHOLE POINT OF THE ROW. An anchor can be written, validated and
        # loaded while pf is off or while the main ruleset no longer references
        # it, and every one of those leaves a file whose booleans are true and
        # whose packets are not filtered.
        for bad in ({"pf_enabled": False},
                    {"anchor_referenced_in_main_ruleset": False},
                    {"covered_prefix_connect_refused": False}):
            with self.subTest(**bad):
                self.assertRefused("macos-pf-anchor", "MACOS-PF-BOOT-ANCHOR",
                                   fx.macos_pf_anchor(**bad))

    def test_macos_pf_anchor_without_its_own_control_is_refused(self):
        # A host with no network refuses the covered prefix too. The control
        # connect is what separates "the anchor denied it" from "nothing works".
        self.assertRefused("macos-pf-anchor", "MACOS-PF-BOOT-ANCHOR",
                           fx.macos_pf_anchor(control_connect_succeeded=False))

    def test_macos_pf_anchor_with_no_rules_is_refused(self):
        # A loaded anchor with zero rules forbids nothing, and `ksd --status`
        # exiting non-zero means the daemon never confirmed the read-back.
        detail = self.assertRefused("macos-pf-anchor", "MACOS-PF-BOOT-ANCHOR",
                                    fx.macos_pf_anchor(anchor_rule_count=0))
        self.assertIn("anchor_rule_count", detail)
        self.assertRefused("macos-pf-anchor", "MACOS-PF-BOOT-ANCHOR",
                           fx.macos_pf_anchor(ksd_status_exit=1))
        ev = fx.macos_pf_anchor()
        del ev["environment"]["read_back_tables"]
        self.assertRefused("macos-pf-anchor", "MACOS-PF-BOOT-ANCHOR", ev)

    def test_macos_pf_anchor_bridge_tests_that_ran_nothing_are_refused(self):
        # `TwinVPNBridgeTests` as root is what makes Apple's pf parse the
        # rendered anchor rather than this lane asserting that it would. A
        # filter that matched nothing exits 0, so the count is the evidence,
        # and an unprivileged run exercised neither `tvb_ext_start` nor
        # `enforcement_reclaim`.
        detail = self.assertRefused("macos-pf-anchor", "MACOS-PF-BOOT-ANCHOR",
                                    fx.macos_pf_anchor(bridge_test_count=0))
        self.assertIn("bridge_test_count", detail)
        self.assertRefused("macos-pf-anchor", "MACOS-PF-BOOT-ANCHOR",
                           fx.macos_pf_anchor(bridge_tests_as_root=False))

    def test_a_simulator_file_cannot_discharge_the_device_criterion(self):
        # THE SUBSTITUTION THE SIMULATOR ROWS EXIST TO MAKE IMPOSSIBLE. Apple's
        # packet tunnel provider does not run in the simulator, so a simulator
        # file describes a run in which the OS enforced nothing -- and the
        # device row's claim is entirely about what the OS did.
        self.assertRefused("ios-ne-failclosed", "IOS-NE-FAIL-CLOSED",
                           fx.ios_failclosed_configuration(),
                           fx.oracle("sess-ios", "IOS-NE-FAIL-CLOSED"))
        self.assertRefused("ios-ne-failclosed", "IOS-NE-FAIL-CLOSED",
                           fx.ios_ne(real_network_extension_invoked=False,
                                     entitlement_packet_tunnel_provider=False),
                           fx.oracle("sess-ios", "IOS-NE-FAIL-CLOSED"))

    def test_a_device_file_cannot_discharge_the_simulator_criteria(self):
        # And the other direction, which is the one that would quietly turn a
        # blocked device row into a green simulator row.
        for stem, criterion, build in SIMULATOR_ROWS:
            with self.subTest(criterion=criterion):
                self.assertRefused(stem, criterion, fx.ios_ne())
                detail = self.assertRefused(
                    stem, criterion,
                    build(execution="device", device_kind="provisioned-iphone",
                          real_network_extension_invoked=True))
                self.assertIn("execution", detail)

    def test_a_simulator_row_that_ran_no_tests_is_refused(self):
        # A VACUOUS RUN IS NOT A PASS: `xcodebuild` with a filter that matches
        # nothing exits 0, so the count out of the .xcresult bundle is what
        # says any assertion was made at all. `true` and `"17"` are refused for
        # the same reason -- neither is a number of tests that ran.
        for stem, criterion, build in SIMULATOR_ROWS:
            for bad in (0, True, "17", -1):
                with self.subTest(criterion=criterion, test_count=bad):
                    detail = self.assertRefused(stem, criterion,
                                                build(test_count=bad))
                    self.assertIn("test_count", detail)

    def test_a_simulator_row_that_observed_the_os_is_refused(self):
        # `os_enforcement_exercised: true` on a simulator is a claim the
        # platform cannot support, and `assertion_source` is what stops the row
        # being read as an observation of the OS rather than of object state.
        self.assertRefused("ios-failclosed-configuration",
                           "IOS-FAILCLOSED-CONFIGURATION",
                           fx.ios_failclosed_configuration(
                               os_enforcement_exercised=True))
        detail = self.assertRefused(
            "ios-failclosed-configuration", "IOS-FAILCLOSED-CONFIGURATION",
            fx.ios_failclosed_configuration(assertion_source="os-observation"))
        self.assertIn("assertion_source", detail)

    def test_a_simulator_row_without_its_toolchain_is_refused(self):
        for key in ("simulator_runtime", "xcode_version"):
            ev = fx.ios_failclosed_configuration()
            del ev["environment"][key]
            with self.subTest(key=key):
                self.assertRefused("ios-failclosed-configuration",
                                   "IOS-FAILCLOSED-CONFIGURATION", ev)

    def test_ios_without_the_packet_tunnel_entitlement_is_refused(self):
        # Every device farm but one re-signs the IPA and strips this. An IPA
        # without it cannot start a tunnel, so nothing that follows is a test.
        self.assertRefused("ios-ne-failclosed", "IOS-NE-FAIL-CLOSED",
                           fx.ios_ne(entitlement_packet_tunnel_provider=False),
                           fx.oracle("sess-ios", "IOS-NE-FAIL-CLOSED"))

    def test_ios_without_a_real_network_extension_is_refused(self):
        self.assertRefused("ios-ne-failclosed", "IOS-NE-FAIL-CLOSED",
                           fx.ios_ne(real_network_extension_invoked=False),
                           fx.oracle("sess-ios", "IOS-NE-FAIL-CLOSED"))

    def test_profile_removal_that_still_claims_protection_is_refused(self):
        self.assertRefused("ios-profile-removal", "IOS-PROFILE-REMOVAL-HONESTY",
                           fx.ios_profile_removal(green_shield_impossible=False))

    def test_profile_removal_that_still_claims_blocking_is_refused(self):
        # `blocked` is as wrong as `protected`: both assert TwinVPN is still
        # deciding what leaves the device after its authority was revoked.
        self.assertRefused(
            "ios-profile-removal", "IOS-PROFILE-REMOVAL-HONESTY",
            fx.ios_profile_removal(no_continued_killswitch_claim=False))

    def test_profile_removal_with_unmeasured_semantics_is_refused(self):
        ev = fx.ios_profile_removal()
        del ev["environment"]["connected_state_cleared"]
        self.assertRefused("ios-profile-removal", "IOS-PROFILE-REMOVAL-HONESTY",
                           ev)

    def test_consumer_evidence_cannot_discharge_the_supervised_criterion(self):
        self.assertRefused("ios-supervised", "IOS-SUPERVISED-ALWAYS-ON",
                           fx.ios_supervised(product_mode="consumer"),
                           fx.oracle("sess-sup", "IOS-SUPERVISED-ALWAYS-ON"))

    def test_the_two_ios_product_modes_cannot_be_swapped(self):
        # `product_mode` is pinned `consumer` on one row and `supervised` on the
        # other; that is what stops a consumer pass being read as the stronger
        # managed claim.
        self.assertRefused("ios-supervised", "IOS-SUPERVISED-ALWAYS-ON",
                           fx.ios_profile_removal())
        self.assertRefused("ios-profile-removal", "IOS-PROFILE-REMOVAL-HONESTY",
                           fx.ios_supervised())
