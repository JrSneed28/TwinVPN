# Keep rules for classes the INSTRUMENTATION needs from the APP APK.
#
# GENERATED, NOT WRITTEN. Every rule below came out of R8's own
# `TraceReferences`, run over the androidTest code against the app's. DO NOT
# hand-edit this file to chase a `NoClassDefFoundError`: a hand-added rule is
# precisely the guess this file exists to replace, and it never leaves again.
#
# WHY THE APP APK AND NOT THE TEST APK. AGP wraps the androidTest runtime
# classpath in a `SubtractingArtifactCollection` against the tested variant
# (VariantDependencies.kt:265), so every artifact already on the app's runtime
# classpath is REMOVED from the test APK. `androidx.tracing` and `kotlin-stdlib`
# are on both -- androidx.core:core pulls tracing, androidx.test:monitor pulls
# tracing and kotlin-stdlib -- so they ship only in the app APK, where R8 shrinks
# them. The test APK is kept whole and it does not matter: the class was never
# in it.
#
# The instrumentation runs IN THE APP PROCESS, so anything AndroidJUnitRunner
# touches has to survive the APP's R8 pass. Three runs died proving it, each on a
# different class, before a single test method executed:
#
#   33322921169  NoClassDefFoundError androidx.tracing.Trace  (onCreate:307)
#   33324089343  NoClassDefFoundError kotlin.LazyKt           (onCreate:321)
#   the run after that, `kotlin.collections.SetsKt`, reached from
#   `NativeLinkRunTest.kt:109`'s own `setOf` -- OUR test code, not a library,
#   which is why a list derived from the androidTest LIBRARIES alone could not
#   have carried it.
#
# WHAT CATCHES AN INCOMPLETE LIST NOW. `build/ci/ci-android.sh` §2d runs a
# PREFLIGHT GATE on the two built release APKs, before the emulator boots: it
# enumerates every class the test APK references that neither APK defines and
# fails naming ALL of them at once. That is a STATIC answer to the same question
# a device crash answers one class per forty-minute run. It does NOT regenerate
# this file -- it tells you to.
#
# TO REGENERATE, after an androidx.test or Kotlin version bump, after any change
# under `src/androidTest/`, and whenever the preflight gate names a class:
#
#   R8_JAR=$(find ~/.gradle/caches -name 'r8-8.*.jar' | sort -V | tail -1)
#   java -cp "$R8_JAR" com.android.tools.r8.tracereferences.TraceReferences \
#     --keep-rules --map-diagnostics error warning \
#     --lib "$ANDROID_SDK_ROOT/platforms/android-35/android.jar" \
#     --source <androidTest kotlin + javac CLASS DIRS> \
#     $(printf -- '--source %s ' $TEST_ONLY_JARS) \
#     --target <release kotlin + javac CLASS DIRS> \
#     $(printf -- '--target %s ' $APP_RUNTIME_JARS) \
#     --output shells/android/app/proguard-androidtest-keep.pro
#
# `--lib` is android-35 because `app/build.gradle.kts` sets `compileSdk = 35`.
#
# CLASS FILES, NEVER DEX. TraceReferences resolves against `.class` files. A zip
# containing `classes.dex` is accepted SILENTLY and contributes NOTHING, so
# pointing `--source`/`--target` at the APKs yields a plausible, empty, wrong
# answer. Point them at `app/build/intermediates/**/classes` and at the runtime
# jars. `$TEST_ONLY_JARS` is the androidTest runtime classpath MINUS the app's
# (the subtraction AGP itself performs); `$APP_RUNTIME_JARS` is the app's.
# Resolving those two sets is a resolution of two Gradle configurations and has
# no on-disk artifact, which is why CI does not yet re-derive and diff this file.
#
# THE STANDING COST, because this is a ONE-WAY RATCHET and nothing here is free:
#
#   * These keeps are driven by TEST-CODE IDIOMS, not by the product. A test
#     author who writes `buildList` next month changes WHAT SHIPS: the release
#     APK has to start carrying `kotlin.collections.CollectionsKt` for a reason
#     no user of the app will ever exercise.
#   * Every rule here permanently inhibits R8's inlining and horizontal class
#     merging on the class it names, in the artifact users install.
#   * NOTHING EVER PROVES A KEEP IS NO LONGER NEEDED. Deleting a test's last
#     `setOf` produces no signal that `kotlin.collections.SetsKt` may go, so the
#     list only ever grows -- unless it is regenerated from scratch, which is why
#     regeneration and not appending is the only supported edit.
#
# They are member-level rather than `-keep class X { *; }`, so the ratchet is at
# least a cheap one: `-keep class kotlin.** { *; }` measures 993 classes and
# 2,013,852 bytes of uncompressed dex.

-keep class androidx.concurrent.futures.AbstractResolvableFuture {
  public void addListener(java.lang.Runnable,java.util.concurrent.Executor);
  public boolean cancel(boolean);
  public java.lang.Object get();
  public java.lang.Object get(long,java.util.concurrent.TimeUnit);
  public boolean isCancelled();
  public boolean isDone();
}
-keep class androidx.concurrent.futures.CallbackToFutureAdapter {
  public static com.google.common.util.concurrent.ListenableFuture getFuture(androidx.concurrent.futures.CallbackToFutureAdapter$Resolver);
}
-keep class androidx.concurrent.futures.CallbackToFutureAdapter$Completer {
  public boolean set(java.lang.Object);
  public boolean setException(java.lang.Throwable);
}
-keep interface androidx.concurrent.futures.CallbackToFutureAdapter$Resolver {
  public java.lang.Object attachCompleter(androidx.concurrent.futures.CallbackToFutureAdapter$Completer);
}
-keep class androidx.concurrent.futures.ResolvableFuture {
  public static androidx.concurrent.futures.ResolvableFuture create();
  public boolean set(java.lang.Object);
  public boolean setException(java.lang.Throwable);
}
-keep enum androidx.lifecycle.Lifecycle$State {
  public static androidx.lifecycle.Lifecycle$State[] values();
  androidx.lifecycle.Lifecycle$State CREATED;
  androidx.lifecycle.Lifecycle$State DESTROYED;
  androidx.lifecycle.Lifecycle$State RESUMED;
  androidx.lifecycle.Lifecycle$State STARTED;
}
-keep class androidx.tracing.Trace {
  public static void beginSection(java.lang.String);
  public static void endSection();
  public static void forceEnableAppTracing();
}
-keep interface com.google.common.util.concurrent.ListenableFuture {
  public void addListener(java.lang.Runnable,java.util.concurrent.Executor);
}
-keep interface kotlin.Lazy {
  public java.lang.Object getValue();
}
-keep class kotlin.LazyKt {
}
-keep class kotlin.LazyKt__LazyJVMKt {
  public static kotlin.Lazy lazy(kotlin.jvm.functions.Function0);
}
-keep class kotlin.Result {
  public static java.lang.Object constructor-impl(java.lang.Object);
  public static java.lang.Throwable exceptionOrNull-impl(java.lang.Object);
  kotlin.Result$Companion Companion;
}
-keep class kotlin.Result$Companion {
}
-keep class kotlin.ResultKt {
  public static java.lang.Object createFailure(java.lang.Throwable);
  public static void throwOnFailure(java.lang.Object);
}
-keep class kotlin.Unit {
  kotlin.Unit INSTANCE;
}
-keep interface kotlin.coroutines.Continuation {
  public kotlin.coroutines.CoroutineContext getContext();
  public void resumeWith(java.lang.Object);
}
-keep class kotlin.coroutines.ContinuationKt {
  public static kotlin.coroutines.Continuation createCoroutine(kotlin.jvm.functions.Function1,kotlin.coroutines.Continuation);
}
-keep interface kotlin.coroutines.CoroutineContext {
}
-keep class kotlin.coroutines.EmptyCoroutineContext {
  kotlin.coroutines.EmptyCoroutineContext INSTANCE;
}
-keep class kotlin.coroutines.intrinsics.IntrinsicsKt {
}
-keep class kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsJvmKt {
  public static kotlin.coroutines.Continuation intercepted(kotlin.coroutines.Continuation);
}
-keep class kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt {
  public static java.lang.Object getCOROUTINE_SUSPENDED();
}
-keep class kotlin.coroutines.jvm.internal.ContinuationImpl {
  public <init>(kotlin.coroutines.Continuation);
}
-keep class kotlin.coroutines.jvm.internal.DebugProbesKt {
  public static void probeCoroutineSuspended(kotlin.coroutines.Continuation);
}
-keep interface kotlin.coroutines.jvm.internal.SuspendFunction {
}
-keep class kotlin.coroutines.jvm.internal.SuspendLambda {
  public <init>(int,kotlin.coroutines.Continuation);
}
-keep class kotlin.io.CloseableKt {
  public static void closeFinally(java.io.Closeable,java.lang.Throwable);
}
-keep interface kotlin.jvm.functions.Function0 {
  public java.lang.Object invoke();
}
-keep interface kotlin.jvm.functions.Function1 {
  public java.lang.Object invoke(java.lang.Object);
}
-keep interface kotlin.jvm.functions.Function2 {
  public java.lang.Object invoke(java.lang.Object,java.lang.Object);
}
-keep class kotlin.jvm.internal.CallableReference {
  java.lang.Object receiver;
}
-keep class kotlin.jvm.internal.FunctionReferenceImpl {
  public <init>(int,java.lang.Object,java.lang.Class,java.lang.String,java.lang.String,int);
}
-keep class kotlin.jvm.internal.Intrinsics {
  public static boolean areEqual(java.lang.Object,java.lang.Object);
  public static void checkNotNull(java.lang.Object);
  public static void checkNotNullExpressionValue(java.lang.Object,java.lang.String);
  public static void checkNotNullParameter(java.lang.Object,java.lang.String);
}
-keep class kotlin.jvm.internal.Lambda {
  public <init>(int);
}
-keep class kotlin.jvm.internal.Ref$ObjectRef {
  public <init>();
  java.lang.Object element;
}
-keep class kotlin.jvm.internal.StringCompanionObject {
  kotlin.jvm.internal.StringCompanionObject INSTANCE;
}
-keep class kotlin.time.Duration {
  kotlin.time.Duration$Companion Companion;
}
-keep class kotlin.time.Duration$Companion {
}
-keep class kotlin.time.DurationKt {
  public static long toDuration(int,kotlin.time.DurationUnit);
}
-keep enum kotlin.time.DurationUnit {
  kotlin.time.DurationUnit SECONDS;
}
-keep class kotlinx.coroutines.BuildersKt {
  public static kotlinx.coroutines.Deferred async(kotlinx.coroutines.CoroutineScope,kotlin.coroutines.CoroutineContext,kotlinx.coroutines.CoroutineStart,kotlin.jvm.functions.Function2);
  public static java.lang.Object runBlocking(kotlin.coroutines.CoroutineContext,kotlin.jvm.functions.Function2);
}
-keep interface kotlinx.coroutines.CancellableContinuation {
  public void resume(java.lang.Object,kotlin.jvm.functions.Function1);
}
-keep class kotlinx.coroutines.CancellableContinuationImpl {
  public <init>(kotlin.coroutines.Continuation,int);
  public java.lang.Object getResult();
  public void initCancellability();
}
-keep class kotlinx.coroutines.CoroutineDispatcher {
}
-keep interface kotlinx.coroutines.CoroutineScope {
  public kotlin.coroutines.CoroutineContext getCoroutineContext();
}
-keep enum kotlinx.coroutines.CoroutineStart {
  kotlinx.coroutines.CoroutineStart DEFAULT;
  kotlinx.coroutines.CoroutineStart UNDISPATCHED;
}
-keep interface kotlinx.coroutines.Deferred {
  public java.lang.Object await(kotlin.coroutines.Continuation);
}
-keep class kotlinx.coroutines.Dispatchers {
  public static kotlinx.coroutines.MainCoroutineDispatcher getMain();
  public static kotlinx.coroutines.CoroutineDispatcher getUnconfined();
}
-keep class kotlinx.coroutines.ExecutorsKt {
  public static kotlinx.coroutines.CoroutineDispatcher from(java.util.concurrent.Executor);
}
-keep interface kotlinx.coroutines.Job {
}
-keep class kotlinx.coroutines.Job$DefaultImpls {
  public static void cancel$default(kotlinx.coroutines.Job,java.util.concurrent.CancellationException,int,java.lang.Object);
}
-keep class kotlinx.coroutines.MainCoroutineDispatcher {
}
-keep class kotlinx.coroutines.TimeoutKt {
  public static java.lang.Object withTimeout-KLykuaI(long,kotlin.jvm.functions.Function2,kotlin.coroutines.Continuation);
}
