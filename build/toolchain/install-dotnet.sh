#!/usr/bin/env bash
# .NET SDK for the Windows WinUI application shell (ADR-0018 §11.9).
set -euo pipefail
DOTNET_CHANNEL=8.0
export DOTNET_ROOT="${DOTNET_ROOT:-$HOME/.dotnet}"
if [ ! -x "$DOTNET_ROOT/dotnet" ]; then
  curl -sSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh
  bash /tmp/dotnet-install.sh --channel "$DOTNET_CHANNEL" --install-dir "$DOTNET_ROOT" --no-path
fi
# This host has no system libicu and no sudo to install it. Invariant
# globalization is sufficient for compile-verifying generated protobuf code,
# which contains no culture-sensitive formatting. Recorded rather than silently
# assumed: a build that needs real globalization must install libicu.
export DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
export DOTNET_CLI_TELEMETRY_OPTOUT=1
"$DOTNET_ROOT/dotnet" --version
