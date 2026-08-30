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

    def test_ios_without_the_packet_tunnel_entitlement_is_refused(self):
        # Every device farm but one re-signs the IPA and strips this. An IPA
        # without it cannot start a tunnel, so nothing that follows is a test.
        self.assertRefused("ios-corellium", "IOS-NE-FAIL-CLOSED",
                           fx.ios_ne(entitlement_packet_tunnel_provider=False),
                           fx.oracle("sess-ios", "IOS-NE-FAIL-CLOSED"))

    def test_ios_without_a_real_network_extension_is_refused(self):
        self.assertRefused("ios-corellium", "IOS-NE-FAIL-CLOSED",
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
