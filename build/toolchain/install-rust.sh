#!/usr/bin/env bash
# Rust toolchain for the shared core (ADR-0018 §11.3, alternative A).
# Version is PINNED: ADR-0018 §11.3 requires "one exact toolchain version pinned
# in rust-toolchain.toml, advanced only by a reviewed commit".
set -euo pipefail
RUST_VERSION=1.90.0
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
if [ ! -x "$CARGO_HOME/bin/rustc" ]; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --no-modify-path --profile minimal --default-toolchain "$RUST_VERSION"
fi
"$CARGO_HOME/bin/rustup" toolchain install "$RUST_VERSION" --profile minimal --no-self-update 2>/dev/null || true
"$CARGO_HOME/bin/rustup" default "$RUST_VERSION"
"$CARGO_HOME/bin/rustc" --version
"$CARGO_HOME/bin/cargo" --version
