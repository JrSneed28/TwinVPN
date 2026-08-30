# R8 rules.
#
# Authority: ADR-0018 §11.9 row 3 (the artifact budget), `docs/implementation/
# ownership.md` §10.4 (the JNI bridge is internal linkage), §6 rule 11.

# ---------------------------------------------------------------------------
# The JNI surface. R8 cannot see that these are reached from native code.
# ---------------------------------------------------------------------------
#
# `NativeBridge`'s `external fun`s resolve by symbol name, and `NativeHost`'s
# methods are looked up by name and JNI signature from `bridge::jvm`. Renaming
# or removing either produces an `UnsatisfiedLinkError` or a `NoSuchMethodError`
# at RUN time on a user's device, which is the class of failure a release build
# must not be able to introduce.
-keep class net.twinvpn.android.NativeBridge { *; }
-keep class net.twinvpn.android.NativeHost { *; }

# The JNI entry points are `Java_net_twinvpn_android_NativeBridge_*` on the Rust
# side; the class above is what they resolve against.
-keepclasseswithmembernames class * {
    native <methods>;
}

# ---------------------------------------------------------------------------
# The committed contract bindings.
# ---------------------------------------------------------------------------
#
# Generated protobuf types use reflection for field access and for
# `Descriptors`. ADR-0018 §11.12's codegen rule makes `contracts/gen/**`
# CI-verified byte-identical, so obfuscating them here would make the shipped
# artifact disagree with the artifact CI checked.
-keep class net.twinvpn.contracts.** { *; }
-keep class com.google.protobuf.** { *; }
-dontwarn com.google.protobuf.**

# ---------------------------------------------------------------------------
# What only the instrumented tests reach.
# ---------------------------------------------------------------------------
#
# R8 shrinks the APP without considering `androidTest` usages. The test APK is
# kept whole and is given `-applymapping`, but a mapping cannot rename a member
# R8 DELETED, so a member reached only from an instrumented test is removed from
# the app and the call lands on nothing: `NoSuchMethodError` at run time.
#
# This bites only where the tests run against a release build --
# `-Ptwinvpn.testBuildType=release`, which the 16 KiB lane sets and the ordinary
# link/run lane does not. That is why the debug lane has always been green.
#
# `CoreClient.requestNetDown` has no caller in `src/main` at all: it exists for
# the MI-K1 assertion in `NativeLinkRunTest`, so it is exactly the shape R8
# removes.
-keep class net.twinvpn.android.core.CoreClient { *; }

# `TwinVpnService$Intents` is an object of two-line factory methods -- a prime
# inlining candidate under `proguard-android-optimize.txt`. It has real callers
# in `src/main`, so R8 may inline them all and drop the holder class, which the
# instrumented tests then fail to resolve: `NoClassDefFoundError`.
-keep class net.twinvpn.android.vpn.TwinVpnService$Intents { *; }

# ---------------------------------------------------------------------------
# What must NOT be kept
# ---------------------------------------------------------------------------
#
# No `-keepattributes SourceFile,LineNumberTable` and no `-renamesourcefileattribute`.
# A stack trace with file and line numbers is a debugging convenience; §6 rule 11
# is a security rule, and a Keystore exception's own message can quote a key
# alias. The core's `reason_code` is what a support case quotes, and it survives
# obfuscation because it is data rather than a symbol.
