# R8 configuration for the androidTest APK ONLY.
#
# WHY THIS FILE EXISTS. The 16 KiB lane builds the test APK against the release
# variant (`-Ptwinvpn.testBuildType=release`), which is the only minified one, so
# it is the only lane whose test APK goes through R8 at all. AGP's own default
# for a test APK is to keep everything -- it emits `-keep class * { *; }` --
# because shrinking a test artifact saves nothing and can only remove something
# the runner needs at runtime.
#
# Naming `proguard-rules.pro` in `testProguardFiles` (to get the Error Prone
# `-dontwarn` to the test task) risks displacing that default, and run
# 33322921169 is what displacing it looks like: R8 dropped `androidx.tracing`,
# a transitive dependency of `androidx.test.runner` that nothing in the test
# SOURCE references by name, and `AndroidJUnitRunner.onCreate` died with
# `NoClassDefFoundError` before one test method ran.
#
# So state the default explicitly rather than depending on it. The APP APK is
# still fully minified and still shrinks -- that is the artifact the criterion is
# about, and nothing here touches it.
-keep class * { *; }
-dontwarn **
