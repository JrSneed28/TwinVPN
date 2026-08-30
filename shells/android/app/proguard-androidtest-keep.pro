# Keep rules for classes the INSTRUMENTATION needs from the APP APK.
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
# touches has to survive the APP's R8 pass. Two runs died proving it, each on a
# different class, before a single test method executed:
#
#   33322921169  NoClassDefFoundError androidx.tracing.Trace  (onCreate:307)
#   33324089343  NoClassDefFoundError kotlin.LazyKt           (onCreate:321)
#
# HOW THIS LIST WAS PRODUCED, and why it is not a third guess. R8's own
# `TraceReferences` tool was run over the androidTest libraries against the app's
# libraries, which is exactly the question "what does the test code reference
# that lives on the app side". It emitted these 53 rules. They are member-level,
# not `-keep class X { *; }`, so they cost far less than the alternative:
# `-keep class kotlin.** { *; }` measures 993 classes and 2,013,852 bytes of
# uncompressed dex.
#
# TO REGENERATE after an androidx.test or Kotlin version bump:
#   java -cp r8.jar com.android.tools.r8.tracereferences.TraceReferences \
#     --keep-rules --output <this file> \
#     --source <androidTest runtime jars> --target <app runtime jars> \
#     --lib $ANDROID_HOME/platforms/android-<compileSdk>/android.jar
#
# DO NOT hand-edit this file to chase a NoClassDefFoundError. Regenerate it --
# a hand-added rule is the guess this file exists to replace.

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
