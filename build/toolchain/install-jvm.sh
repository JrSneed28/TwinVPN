#!/usr/bin/env bash
# JDK + Kotlin for the Android shell (ADR-0018 §11.9).
# The generated Kotlin DSL EXTENDS the generated Java classes, so both are
# needed to compile-verify either.
set -euo pipefail
JDK_VERSION=21.0.5+11
KOTLIN_VERSION=2.0.21
PREFIX="$HOME/.local"
mkdir -p "$PREFIX"

if [ ! -x "$PREFIX/jdk/bin/javac" ]; then
  TAG="${JDK_VERSION/+/_}"
  URL="https://github.com/adoptium/temurin21-binaries/releases/download/jdk-${JDK_VERSION//+/%2B}/OpenJDK21U-jdk_x64_linux_hotspot_${TAG}.tar.gz"
  curl -sSL "$URL" -o /tmp/jdk.tar.gz
  rm -rf "$PREFIX/jdk" && mkdir -p "$PREFIX/jdk"
  tar -xzf /tmp/jdk.tar.gz -C "$PREFIX/jdk" --strip-components=1
fi
"$PREFIX/jdk/bin/java" -version 2>&1 | head -1

if [ ! -x "$PREFIX/kotlinc/bin/kotlinc" ]; then
  URL="https://github.com/JetBrains/kotlin/releases/download/v${KOTLIN_VERSION}/kotlin-compiler-${KOTLIN_VERSION}.zip"
  curl -sSL "$URL" -o /tmp/kotlin.zip
  rm -rf "$PREFIX/kotlinc"
  (cd "$PREFIX" && unzip -q /tmp/kotlin.zip)
fi
JAVA_HOME="$PREFIX/jdk" "$PREFIX/kotlinc/bin/kotlinc" -version 2>&1 | head -1
