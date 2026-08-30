import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "net.twinvpn.android"

    // `docs/networking.md` §5.2's Android row: **API 26 min, API 29 target
    // behaviour**. `compileSdk` is higher because compiling against a newer SDK
    // is how a `Build.VERSION` guard is written at all; it does not change the
    // behaviour the app opts into, which `targetSdk` fixes.
    compileSdk = 35
    defaultConfig {
        applicationId = "net.twinvpn.android"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        ndk {
            // ADR-0018 §11.9 row 3 budgets the CDYLIB **per ABI**. Four ABIs are
            // shipped; `x86`/`x86_64` are emulator and Chromebook targets and
            // are what the instrumented suite runs on.
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
        }
    }

    // ADR-0020 §11: the vault must be excluded from Auto Backup **and** from
    // device-to-device transfer. Both sections, or the exclusion is half done.
    // The rules themselves are in `res/xml/`.

    // THE RELEASE SIGNING CONFIG EXISTS SO THAT `ANDROID-16K-PAGE-SIZE` CAN
    // INSTALL THE PRODUCTION APK.
    //
    // Without one, `assembleRelease` produces `app-release-unsigned.apk`, which
    // `adb install` refuses -- so the 16 KiB criterion used to be discharged by
    // installing the DEBUG build, which is a different artifact: unminified, not
    // shrunk, and packaged by a different code path. C-12's alignment claim is
    // about the shipped `.so` inside the shipped APK, and only the release build
    // is that.
    //
    // NO FALLBACK TO THE DEBUG KEYSTORE. A silent fallback would make "the
    // production APK was installed" true in the evidence and false on the disk,
    // which is the exact class of quiet substitution the acceptance gate exists
    // to refuse. Absent properties leave `signingConfigs` empty, `assembleRelease`
    // produces an unsigned APK as before, and `build/ci/ci-android.sh --pagesize16k`
    // fails loudly naming the four properties.
    val releaseStore = providers.gradleProperty("twinvpn.release.storeFile").orNull
    if (releaseStore != null) {
        signingConfigs {
            create("release") {
                storeFile = file(releaseStore)
                storePassword = providers.gradleProperty("twinvpn.release.storePassword").get()
                keyAlias = providers.gradleProperty("twinvpn.release.keyAlias").get()
                keyPassword = providers.gradleProperty("twinvpn.release.keyPassword").get()
            }
        }
    }

    // Which build type the instrumented suite is compiled and signed against.
    // `debug` by default, so nothing about a developer's day changes; the 16 KiB
    // job passes `release` so that the test APK is signed by the same key as the
    // production APK, which `adb install` requires of a test package.
    testBuildType = providers.gradleProperty("twinvpn.testBuildType").getOrElse("debug")

    buildTypes {
        release {
            if (releaseStore != null) {
                signingConfig = signingConfigs.getByName("release")
            }
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
                // What the instrumentation needs to survive the APP's R8 pass.
                // AGP subtracts the app's runtime classpath from the test APK,
                // so these classes ship only here. Derived with R8's
                // TraceReferences, not hand-written -- see the file's header.
                "proguard-androidtest-keep.pro",
            )
            // The androidTest APK gets its own R8 invocation
            // (`minifyReleaseAndroidTestWithR8`), and it does NOT inherit the
            // list above. The 16 KiB lane is the only one that builds the test
            // APK against this variant, so it was the only lane that hit R8
            // refusing `androidx.test`'s compile-only Error Prone annotations.
            // Naming the same file here is what makes that `-dontwarn` reach
            // the task that needs it.
            // The test APK's own R8 pass needs the Error Prone `-dontwarn`;
            // a missing-class error is refused regardless of keep rules. AGP
            // always emits `-keep class * {*;}` for an application module's
            // androidTest (ProguardConfigurableTask keepAllForTest), and a
            // testProguardFiles entry cannot displace it, so nothing here has
            // to restate it.
            testProguardFiles("proguard-rules.pro")
            // ADR-0018 §11.3: `panic = "unwind"` in every SHIPPED profile,
            // because F-7's containment needs `catch_unwind` at the boundary.
            // The Rust side sets it; this comment is here so a reader of the
            // Android build knows the native library is not built with `abort`.
        }
    }

    packaging {
        jniLibs {
            // C-12: 16 KiB load alignment. A device with a 16 KiB page size
            // refuses to load a 4 KiB-aligned `.so`, and the failure lands at
            // install time on a user's device rather than in CI.
            useLegacyPackaging = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    sourceSets {
        getByName("main") {
            kotlin.srcDirs("src/main/kotlin")
            // The COMMITTED, CI-verified bindings (ADR-0018 §11.12's codegen
            // rule). They are consumed, never regenerated here, and never
            // redeclared: `ownership.md` §6 rule 2.
            java.srcDirs(
                "../../../contracts/gen/kotlin/java",
                "../../../contracts/gen/kotlin/kotlin",
            )
            // The Rust CDYLIB, built by the NDK toolchain per ABI. Wiring the
            // cargo invocation into Gradle is the `infrastructure` domain's
            // (`build/`), not this one's; until it lands, the library is placed
            // here by `shells/android/README.md` §3's manual step.
            jniLibs.srcDirs("src/main/jniLibs")
        }
        getByName("androidTest") { kotlin.srcDirs("src/androidTest/kotlin") }
    }

    kotlin {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_21)
            // Warnings are errors. A Kotlin half that nobody has compiled must
            // at least be one nobody can compile sloppily.
            allWarningsAsErrors.set(true)
        }
    }
}

dependencies {
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.tooling)
    implementation(libs.compose.material3)
    implementation(libs.activity.compose)
    implementation(libs.core.ktx)
    implementation(libs.lifecycle.runtime)
    implementation(libs.lifecycle.compose)
    implementation(libs.lifecycle.process)

    // The generated bindings' runtime. Pinned to `TWINVPN_PROTOBUF_JAVA_VERSION`.
    implementation(libs.protobuf.java)
    implementation(libs.protobuf.kotlin)

    // The pairing foundation only: camera, scan, render. The ceremony,
    // SPAKE2/QR verification and idempotency are the CORE's (ADR-0018 §11.2
    // row 2.7), and nothing in this module implements any of them.
    implementation(libs.camera.core)
    implementation(libs.camera.camera2)
    implementation(libs.camera.lifecycle)
    implementation(libs.camera.view)
    implementation(libs.mlkit.barcode)
    implementation(libs.zxing.core)

    // `androidx.test:rules` is deliberately absent: nothing under
    // `src/androidTest/` takes a `@Rule` from it, and sharing `runner`'s version
    // ref with it named `androidx.test:rules:1.6.2`, which does not exist.
    // `gradle/libs.versions.toml` carries the whole account.
    androidTestImplementation(libs.test.runner)
    androidTestImplementation(libs.test.junit)
    androidTestImplementation(libs.test.uiautomator)
}

// ---------------------------------------------------------------------------
// THE TWO CLASSPATHS R8's TraceReferences NEEDS, WHICH ONLY GRADLE KNOWS
// ---------------------------------------------------------------------------
//
// `proguard-androidtest-keep.pro` is generated by running TraceReferences over
// what the androidTest code references against what the app provides. That split
// is not a directory listing and it is not on disk anywhere: AGP wraps the
// androidTest runtime classpath in a `SubtractingArtifactCollection` against the
// tested variant (VariantDependencies.kt:265), holds both sides as in-memory
// FileCollections, and writes neither. `outputs/mapping/release/configuration.txt`
// is the merged R8 config, not a classpath.
//
// So the split has to be asked for. This task writes the two file lists that
// `build/ci/ci-android.sh` feeds to TraceReferences as `--target` and `--source`.
//
// SUBTRACTED ON ARTIFACT ID, NOT FILE NAME. Two different modules can resolve to
// jars with the same basename, and a name-based subtraction would silently drop
// one of them from the test-only set -- which shows up much later as a keep rule
// that was never generated and a class that vanishes at runtime.
tasks.register("twinvpnTraceRefsClasspaths") {
    description = "Writes the app and test-only runtime classpaths for R8 TraceReferences."
    group = "verification"

    // LOOKED UP INSIDE `doLast`, NOT AT CONFIGURATION TIME.
    // `configurations.named(...)` here resolved while this file was still being
    // evaluated, which is BEFORE AGP has created the variant configurations --
    // so `gradle :app:tasks` failed outright with "Configuration with name
    // 'releaseAndroidTestRuntimeClasspath' not found", for every developer, on a
    // task none of them run. By execution time AGP has created it and the lookup
    // succeeds whatever `testBuildType` is. The `error(...)` below is a guard,
    // not the normal path.
    val outDir = layout.buildDirectory.dir("twinvpn-tracerefs")
    outputs.dir(outDir)

    doLast {
        // `lenient(true)`: a classpath that cannot fully resolve should not take
        // the whole acceptance lane down here. A missing artifact reappears as a
        // missing keep rule, which the preflight gate in ci-android.sh reports by
        // name -- a better failure than a Gradle stack trace.
        // `android-classes-jar`, NOT the default view. The default hands back
        // raw `.aar` files, and TraceReferences resolves against CLASS FILES --
        // it accepts an archive it cannot read without complaining and simply
        // contributes nothing from it, which yields a confidently empty keep
        // set. Asking for the classes view makes AGP run its own aar->jar
        // transform and give us jars.
        val classesJar = Attribute.of("artifactType", String::class.java)
        fun view(c: Configuration) =
            c.incoming.artifactView {
                isLenient = true
                attributes { attribute(classesJar, "android-classes-jar") }
            }.artifacts.artifacts

        val testCpName = "releaseAndroidTestRuntimeClasspath"
        val testConf = configurations.findByName(testCpName)
            ?: error("$testCpName does not exist. This task needs the androidTest " +
                     "variant built against release, so run it with " +
                     "-Ptwinvpn.testBuildType=release -- the same flag " +
                     "build/ci/ci-android.sh passes in the 16 KiB lane.")
        val app = view(configurations.getByName("releaseRuntimeClasspath"))
        val test = view(testConf)
        val appIds = app.map { it.id.componentIdentifier.displayName }.toSet()

        val dir = outDir.get().asFile.apply { mkdirs() }
        dir.resolve("app-runtime.txt")
            .writeText(app.joinToString("\n") { it.file.absolutePath } + "\n")
        // TEST-ONLY: exactly what AGP would have packaged into the test APK.
        // Everything else the test references lives in the app APK and must
        // therefore survive the APP's R8 pass -- which is the whole reason the
        // generated keep file exists.
        dir.resolve("test-only.txt").writeText(
            test.filterNot { it.id.componentIdentifier.displayName in appIds }
                .joinToString("\n") { it.file.absolutePath } + "\n")

        logger.lifecycle("app runtime artifacts:  ${app.size}")
        logger.lifecycle("test-only artifacts:    ${test.size - test.count { it.id.componentIdentifier.displayName in appIds }}")
        logger.lifecycle("written to: $dir")
    }
}
