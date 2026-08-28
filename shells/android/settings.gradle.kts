// TwinVPN — the Android shell.
//
// Owner: `mobile-android`. ADR-0018 §11.12 places this project at
// `/shells/android/  Gradle (app + VpnService)`.
//
// ============================================================================
// NOTHING IN THIS PROJECT HAS BEEN COMPILED.
// ============================================================================
// `docs/implementation/ownership.md` §10.3 is explicit: there is no JDK, no
// Gradle, no Android SDK and no NDK on the host wave 3 runs on, so every Kotlin
// file here is **written, not compiled** in §9.2's sense, and no `make` target
// claims otherwise. The completion report says so in those words.
//
// What IS proven about this shell is its other half: every decision it would
// otherwise have made lives in `core/crates/twinvpn-platform-android`, which is
// type-checked for `aarch64-linux-android` by `make cross-check` and whose tests
// run on the Linux host. See `shells/android/README.md` §2.

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    // The build must fail rather than silently reach a repository the pinned
    // toolchain did not declare. ADR-0018 §11.11's supply-chain policy has one
    // place to audit only if there is one place repositories are declared.
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "twinvpn-android"

include(":app")
