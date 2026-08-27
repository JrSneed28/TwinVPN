# Source this to put every pinned TwinVPN toolchain on PATH.
#
# All four install USER-LOCAL (no sudo). Versions are pinned here and asserted by
# `make bootstrap`: ADR-0018 §11.3 requires the Rust toolchain to be "one exact
# version ... advanced only by a reviewed commit that re-runs the full §11.9
# matrix", and the same discipline is applied to the other three so that
# "the bindings compile" is a reproducible claim rather than a local accident.
export TWINVPN_RUST_VERSION=1.90.0
export TWINVPN_SWIFT_VERSION=6.1.2
export TWINVPN_JDK_VERSION=21.0.5
export TWINVPN_KOTLIN_VERSION=2.0.21
export TWINVPN_DOTNET_VERSION=8.0

export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export JAVA_HOME="$HOME/.local/jdk"
export DOTNET_ROOT="$HOME/.dotnet"
export SWIFT_HOME="$HOME/.local/swift"

# This host has no system libicu and no sudo. Generated protobuf code contains
# no culture-sensitive formatting, so invariant globalization is sufficient for
# a compile check. Stated, not silently assumed.
export DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_NOLOGO=1

# Ubuntu 26.04 renamed libxml2 -> libxml2-16 and dropped libncurses.so.6; the
# Swift ubuntu24.04 build links the older sonames. They are unpacked into a
# user sysroot rather than installed system-wide.
export LD_LIBRARY_PATH="$HOME/.local/sysroot/usr/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH:-}"

export PATH="$CARGO_HOME/bin:$JAVA_HOME/bin:$HOME/.local/kotlinc/bin:$DOTNET_ROOT:$SWIFT_HOME/usr/bin:$PATH"

# ---------------------------------------------------------------------------
# Protobuf RUNTIME versions, pinned to match the GENERATOR versions in
# contracts/buf.gen.yaml.
#
# These are not independent choices. Generated code calls into its runtime and
# may use symbols the runtime introduced: protoc 33.x emits
# `@com.google.protobuf.Generated`, which protobuf-java 4.28 does not have, so a
# mismatched pair fails to compile. `make verify-bindings` asserts the pairing
# rather than leaving it to whoever last edited a version string.
#
#   generator (buf.gen.yaml)                 runtime
#   protocolbuffers/java:v33.1        <->    com.google.protobuf:protobuf-java:4.33.1
#   protocolbuffers/kotlin:v33.1      <->    com.google.protobuf:protobuf-kotlin:4.33.1
#   protocolbuffers/csharp:v33.1      <->    Google.Protobuf 3.33.x
#   apple/swift:v1.28.2               <->    swift-protobuf 1.28.2
#   community/neoeinstein-prost:v0.4  <->    prost 0.13
export TWINVPN_PROTOC_GEN_VERSION=33.1
export TWINVPN_PROTOBUF_JAVA_VERSION=4.33.1
export TWINVPN_PROTOBUF_CSHARP_VERSION=3.33.6
export TWINVPN_PROTOBUF_SWIFT_VERSION=1.28.2
export TWINVPN_PROST_VERSION=0.13
