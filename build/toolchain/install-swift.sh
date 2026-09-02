#!/usr/bin/env bash
# Swift toolchain for the iOS / iPadOS / macOS shells (ADR-0018 §11.9).
#
# On Linux this verifies that the generated Swift COMPILES. It cannot build the
# Apple-platform shells themselves, which require Xcode - a limitation of this
# host, not of the contract.
#
# Two host constraints are worked around explicitly rather than silently:
#   1. swiftly has no Ubuntu 26.04 platform entry, so the Ubuntu 24.04 release
#      build is used directly. Swift's Linux builds are forward-compatible
#      across glibc minor versions.
#   2. On a host where libxml2, libicu74 or libncurses are absent and there is
#      no sudo -- Ubuntu 26.04, not the ubuntu-24.04 CI runners -- the Debian
#      packages are unpacked into a user sysroot and reached via
#      LD_LIBRARY_PATH.
set -euo pipefail
SWIFT_VERSION=6.1.2
PREFIX="$HOME/.local/swift"
SYSROOT="$HOME/.local/sysroot"

mkdir -p "$SYSROOT"

# The sysroot is for hosts whose system libraries are NEWER than the ones the
# Swift ubuntu24.04 build links. A host that already provides every one of
# those sonames -- every ubuntu-24.04 GitHub runner does, being noble itself --
# needs none of this, and unpacking the archive copies anyway would have
# LD_LIBRARY_PATH below shadow the host's own libraries with them.
host_has_all_sonames=true
for soname in libicuuc.so.74 libxml2.so.2 libncurses.so.6 libtinfo.so.6; do
  [ -e "/usr/lib/x86_64-linux-gnu/$soname" ] || host_has_all_sonames=false
done

if [ "$host_has_all_sonames" = false ] \
   && [ ! -f "$SYSROOT/usr/lib/x86_64-linux-gnu/libicuuc.so.74" ]; then
  tmp="$(mktemp -d)"
  # From this release's archive: ncurses is still ABI-compatible.
  #
  # `apt-get download` and not `--print-uris` piped into curl: the URIs apt
  # prints are apt's to fetch, not curl's. A hosted GitHub runner configures
  # its sources as `URIs: mirror+file:/etc/apt/apt-mirrors.txt`, so the printed
  # URI names a protocol libcurl does not implement and curl exits 1. apt
  # speaks every transport apt is configured with, by construction.
  ( cd "$tmp" && apt-get download libncurses6 libtinfo6 )
  # Ubuntu 26.04 ships libxml2-16 (soname libxml2.so.2 -> .so.16 rename), but
  # Swift's ubuntu24.04 build links libxml2.so.2. Fetch the noble package for
  # the old soname rather than pretend the newer one satisfies it.
  NOBLE="http://archive.ubuntu.com/ubuntu/pool/main/libx/libxml2"
  XML_DEB="$(curl -sSL "$NOBLE/" | grep -oE 'libxml2_2\.9\.14[^"]*_amd64\.deb' | head -1)"
  if [ -n "$XML_DEB" ]; then
    curl -sSL "$NOBLE/$XML_DEB" -o "$tmp/libxml2.deb" || true
  fi
  # SwiftPM (swift-build) links libicuuc.so.74, which is noble's libicu74.
  # Ubuntu 26.04 ships a newer soname, so the old one is fetched alongside.
  ICU="http://archive.ubuntu.com/ubuntu/pool/main/i/icu"
  ICU_DEB="$(curl -sSL "$ICU/" | grep -oE 'libicu74_74[^"]*_amd64\.deb' | head -1)"
  if [ -n "$ICU_DEB" ]; then
    curl -sSL "$ICU/$ICU_DEB" -o "$tmp/libicu74.deb" || true
  fi
  for deb in "$tmp"/*.deb; do [ -f "$deb" ] && dpkg -x "$deb" "$SYSROOT"; done
  rm -rf "$tmp"
fi

if [ ! -x "$PREFIX/usr/bin/swiftc" ]; then
  URL="https://download.swift.org/swift-${SWIFT_VERSION}-release/ubuntu2404/swift-${SWIFT_VERSION}-RELEASE/swift-${SWIFT_VERSION}-RELEASE-ubuntu24.04.tar.gz"
  curl -sSL "$URL" -o /tmp/swift.tar.gz
  rm -rf "$PREFIX" && mkdir -p "$PREFIX"
  tar -xzf /tmp/swift.tar.gz -C "$PREFIX" --strip-components=1
  rm -f /tmp/swift.tar.gz
fi

export LD_LIBRARY_PATH="$SYSROOT/usr/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH:-}"
"$PREFIX/usr/bin/swift" --version
