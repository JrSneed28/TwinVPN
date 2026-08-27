#!/usr/bin/env bash
# Compile-verify every generated binding.
#
# ADR-0018 §11.12 requires /contracts/gen to be committed and CI-verified so that
# "a schema change that a language binding CANNOT EXPRESS fails at MERGE rather
# than at integration". A byte-diff proves the bindings are CURRENT; it does not
# prove they COMPILE. This script closes that gap: it is the difference between
# "the generator ran" and "the output is usable".
#
# Each language builds against its real protobuf runtime, because a schema
# feature a runtime cannot express (proto3 explicit presence, a deeply nested
# oneof, a reserved range) fails at compile, not at generation.
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT="$PWD"
GEN="$ROOT/contracts/gen"
WORK="${TWINVPN_VERIFY_DIR:-$ROOT/build/verify/.work}"
source "$ROOT/build/toolchain/env.sh"

only="${1:-all}"
fail=0
skipped=""
verified=""

# A missing toolchain is a SKIP locally and a FAILURE in CI. A contributor
# without all four should still be able to run the rest of the gate; CI must not
# be allowed to silently verify nothing.
have() { command -v "$1" >/dev/null 2>&1; }

run() { # run <lang> <required-binary> <cmd...>
  local lang="$1" bin="$2"; shift 2
  if [ "$only" != "all" ] && [ "$only" != "$lang" ]; then return 0; fi
  if ! have "$bin"; then
    if [ "${CI:-}" = "true" ]; then
      printf '==> %s\n    FAIL: %s not found, and CI must verify every binding\n' "$lang" "$bin"
      fail=1
    else
      printf '==> %s\n    SKIPPED: %s not found (run: make toolchains)\n' "$lang" "$bin"
      skipped="$skipped $lang"
    fi
    return 0
  fi
  printf '==> %s\n' "$lang"
  if "$@" > "$WORK/$lang.log" 2>&1; then
    printf '    %s bindings COMPILE\n' "$lang"
    verified="$verified $lang"
  else
    printf '    %s bindings FAILED to compile:\n' "$lang"
    tail -30 "$WORK/$lang.log" | sed 's/^/      /'
    fail=1
  fi
}
mkdir -p "$WORK"

# The generator versions in buf.gen.yaml and the runtime versions in env.sh are
# one decision recorded twice. Assert they agree, so a bump to either side that
# forgets the other fails HERE with a clear message rather than as a wall of
# "cannot find symbol".
gen_ver="$(grep -oE 'protocolbuffers/java:v[0-9.]+' "$ROOT/contracts/buf.gen.yaml" | head -1 | sed 's/.*:v//')"
if [ "$gen_ver" != "$TWINVPN_PROTOC_GEN_VERSION" ]; then
  echo "FAIL: buf.gen.yaml generates with protoc-gen-java v$gen_ver but"
  echo "      build/toolchain/env.sh pins runtime for v$TWINVPN_PROTOC_GEN_VERSION."
  echo "      Generated code may call runtime symbols that do not exist."
  exit 1
fi
case "$TWINVPN_PROTOBUF_JAVA_VERSION" in
  4."${TWINVPN_PROTOC_GEN_VERSION%%.*}".*) ;;
  *) echo "FAIL: protobuf-java $TWINVPN_PROTOBUF_JAVA_VERSION does not match generator major ${TWINVPN_PROTOC_GEN_VERSION%%.*}"; exit 1 ;;
esac
case "$TWINVPN_PROTOBUF_CSHARP_VERSION" in
  3."${TWINVPN_PROTOC_GEN_VERSION%%.*}".*) ;;
  *) echo "FAIL: Google.Protobuf $TWINVPN_PROTOBUF_CSHARP_VERSION does not match generator major ${TWINVPN_PROTOC_GEN_VERSION%%.*}"; exit 1 ;;
esac

# ---------------------------------------------------------------- Rust -------
verify_rust() {
  local d="$WORK/rust"
  rm -rf "$d" && mkdir -p "$d/src"
  cat > "$d/Cargo.toml" <<EOF
[package]
name = "twinvpn-contracts-verify"
version = "0.0.0"
edition = "2021"
[dependencies]
prost = "$TWINVPN_PROST_VERSION"
EOF
  cp "$GEN/rust/src/twinvpn.v1.rs" "$d/src/twinvpn_v1.rs"
  # ADR-0018 §11.3 requires #![forbid(unsafe_code)] in every crate outside the
  # DP-4 allowlist. Generated contract types are not in that allowlist, so the
  # verification asserts they compile under it.
  cat > "$d/src/lib.rs" <<EOF
#![forbid(unsafe_code)]
pub mod twinvpn {
    pub mod v1 {
        include!("twinvpn_v1.rs");
    }
}
EOF
  ( cd "$d" && cargo build --offline --quiet 2>/dev/null || cargo build --quiet )
}

# --------------------------------------------------------------- Swift -------
verify_swift() {
  local d="$WORK/swift"
  rm -rf "$d" && mkdir -p "$d/Sources/Contracts"
  cp "$GEN"/swift/*.swift "$d/Sources/Contracts/"
  cat > "$d/Package.swift" <<EOF
// swift-tools-version:5.9
import PackageDescription
let package = Package(
    name: "Contracts",
    products: [.library(name: "Contracts", targets: ["Contracts"])],
    dependencies: [
        .package(url: "https://github.com/apple/swift-protobuf.git", exact: "$TWINVPN_PROTOBUF_SWIFT_VERSION"),
    ],
    targets: [
        .target(name: "Contracts", dependencies: [
            .product(name: "SwiftProtobuf", package: "swift-protobuf"),
        ]),
    ]
)
EOF
  ( cd "$d" && swift build )
}

# ---------------------------------------------------- Java + Kotlin ----------
verify_jvm() {
  local d="$WORK/jvm"
  rm -rf "$d" && mkdir -p "$d/classes" "$d/lib"
  local ver="$TWINVPN_PROTOBUF_JAVA_VERSION"
  local base="https://repo1.maven.org/maven2/com/google/protobuf"
  for a in "protobuf-java/$ver/protobuf-java-$ver.jar" \
           "protobuf-kotlin/$ver/protobuf-kotlin-$ver.jar"; do
    local j="$d/lib/$(basename "$a")"
    [ -f "$j" ] || curl -sSL "$base/$a" -o "$j"
  done
  local cp; cp="$(printf '%s:' "$d"/lib/*.jar)"
  # Java first: the generated Kotlin DSL EXTENDS these classes, so Kotlin cannot
  # be verified without them.
  find "$GEN/kotlin/java" -name '*.java' > "$d/java.list"
  javac -nowarn -Xlint:none -cp "$cp" -d "$d/classes" @"$d/java.list"
  kotlinc -nowarn -cp "$cp$d/classes" -d "$d/kt" "$GEN/kotlin/kotlin"
}

# ------------------------------------------------------------------ C# -------
verify_csharp() {
  local d="$WORK/csharp"
  local pkgs="$WORK/nupkg"
  rm -rf "$d" && mkdir -p "$d" "$pkgs"
  # Fetch the package directly from the flat container and use a LOCAL source.
  # This is not just a workaround for a blocked service index: pinning the exact
  # .nupkg makes the C# verification hermetic and reproducible, which is the same
  # property the pinned buf plugins give the generation step.
  local v="$TWINVPN_PROTOBUF_CSHARP_VERSION"
  local nupkg="$pkgs/google.protobuf.$v.nupkg"
  [ -f "$nupkg" ] || curl -sSL \
    "https://api.nuget.org/v3-flatcontainer/google.protobuf/$v/google.protobuf.$v.nupkg" \
    -o "$nupkg"
  cat > "$d/nuget.config" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="local" value="$pkgs" />
  </packageSources>
</configuration>
EOF
  cat > "$d/Contracts.csproj" <<EOF
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <Nullable>disable</Nullable>
    <EnableDefaultCompileItems>false</EnableDefaultCompileItems>
    <InvariantGlobalization>true</InvariantGlobalization>
    <NoWarn>CS0612;CS0618</NoWarn>
  </PropertyGroup>
  <ItemGroup>
    <Compile Include="$GEN/csharp/*.cs" />
    <PackageReference Include="Google.Protobuf" Version="$v" />
  </ItemGroup>
</Project>
EOF
  ( cd "$d" && dotnet build -v quiet --nologo )
}

run rust   cargo   verify_rust
run swift  swift   verify_swift
run jvm    kotlinc verify_jvm
run csharp dotnet  verify_csharp

echo
# A machine-readable receipt, so the freeze gate reports what was actually
# verified rather than asserting that the script ran.
printf '{"verified":[%s],"skipped":[%s],"failed":%s}\n' \
  "$(echo $verified | sed 's/ /","/g; s/^/"/; s/$/"/; s/^""$//')" \
  "$(echo $skipped  | sed 's/ /","/g; s/^/"/; s/$/"/; s/^""$//')" \
  "$([ "$fail" -eq 0 ] && echo false || echo true)" > "$WORK/result.json"

if [ "$fail" -eq 0 ]; then
  if [ -n "$skipped" ]; then
    echo "bindings compile:$verified   (SKIPPED:$skipped)"
  else
    echo "all generated bindings compile:$verified"
  fi
else
  echo "FAIL: at least one binding does not compile"
fi
exit "$fail"
