# TwinVPN repository entry points.
#
# Phase 3 status: the contract freeze is DECLARED (contracts/FROZEN) and
# production implementation has begun under ADR-0018 §11.12's layout. The
# targets below cover every workspace that exists; each says plainly what it
# does not yet cover rather than pretending.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

# The four cargo workspaces. ADR-0018 §11.12 makes /core one workspace; the
# server artifacts, the Linux shell and TwinLab are SEPARATE artifacts and
# therefore separate workspaces, so that no domain silently acquires another's
# dependency graph and each domain owns its own manifests.
# `shells/android/jni` is NOT here: it is a `cdylib` for bionic with no
# host tests, and `cross-check` is where it is proven. Adding it would run
# `cargo test` on a crate whose only entry points need a JVM.
WORKSPACES := core services shells/linux lab tests
CARGO      := cargo

BUF        := ./node_modules/.bin/buf
BUF_VERSION := 1.72.0
CONTRACTS  := contracts
PROTO_DIR  := $(CONTRACTS)/proto
GEN_DIR    := $(CONTRACTS)/gen
BASELINE   := $(CONTRACTS)/.baseline.binpb

.PHONY: help bootstrap toolchains contracts contracts-lint contracts-gen \
        contracts-breaking contracts-freshness verify-bindings test-contracts \
        build lint test clean gate freeze freeze-scope build-rust lint-rust \
        test-rust fmt arch-lint doc-check cross-check swift-parse infra-bootstrap infra-check infra-up \
        infra-up-v6 infra-down budgets budgets-images redaction-check \
        dev-issuer plane-up plane-up-v6 plane-probe plane-ceremony plane-status plane-down \
        pg-up pg-down pg-reset \
        lab-capabilities lab-conformance lab-fabric netlab-up netlab-down

help:
	@echo "TwinVPN"
	@echo ""
	@echo "  make bootstrap        install/verify pinned development dependencies"
	@echo "  make toolchains       install the pinned Rust/Swift/JVM/.NET toolchains"
	@echo "  make verify-bindings  compile every generated binding against its runtime"
	@echo "  make contracts        validate, lint, generate bindings, fail if stale"
	@echo "  make test-contracts   run the contract compatibility and behaviour tests"
	@echo "  make build            build everything currently buildable"
	@echo "  make lint             lint handwritten code, schemas, and configuration"
	@echo "  make test             run every test currently available"
	@echo "  make gate             the contract freeze gate (all of the above)"
	@echo "  make freeze-scope     assert the contract freeze is declared and unbroken"
	@echo "  make arch-lint        the ADR-0018 T1 architectural lints (CD-3, CD-I2, CD-I5, CB-3)"
	@echo "  make cross-check      COMPILE-ONLY proof for the non-host targets (win/mac/ios/android)"
	@echo "  make proof            the T3/T4 proof register, its oracles, and the PT-1 mutant run"
	@echo ""
	@echo "  make infra-check      compose topology + collector redaction invariants (no Docker needed)"
	@echo "  make infra-up         bring the local plane up (dual stack); infra-up-v6 for IPv6-only"
	@echo "  make infra-down       tear it down"
	@echo "  make budgets          the ADR-0018 §11.9 artifact budgets"
	@echo ""
	@echo "  The host-native plane -- NO container runtime required:"
	@echo "  make dev-issuer       (re)generate the development relay credentials"
	@echo "  make plane-up         two real relays + two simulated peers as host processes"
	@echo "  make plane-up-v6      the same, with every leg on IPv6"
	@echo "  make plane-probe      one-shot: exit 0 iff a real leg binds a real relay"
	@echo "  make plane-ceremony   one-shot: exit 0 iff a device ATTACHES to the control plane"
	@echo "  make plane-status     what is running, and its metrics"
	@echo "  make plane-down       stop everything plane-up started"
	@echo "  make pg-up            a local PostgreSQL from pinned official binaries"
	@echo "  make pg-down          stop it; pg-reset also DESTROYS the data directory"
	@echo ""
	@echo "  make lab-capabilities what TwinLab can realize on THIS host, probed"
	@echo "  make lab-conformance  the §3.4.2 NAT-personality suite (rule L-1)"
	@echo "  make lab-fabric       the twinnet fabric tests -- real namespaces, real middleboxes"
	@echo "  make netlab-up        the simulated peers and the test network; netlab-down to stop"
	@echo ""
	@echo "  workspaces: $(WORKSPACES)"

# ---------------------------------------------------------------------------
# bootstrap
# ---------------------------------------------------------------------------
# Installs or verifies the pinned tooling. Versions are PINNED because
# ADR-0018 §11.12 requires the committed bindings to be CI-verified
# byte-identical: an unpinned generator makes that check meaningless.
bootstrap:
	@echo "==> verifying pinned toolchain"
	@command -v node >/dev/null || { echo "node is required"; exit 1; }
	@command -v python3 >/dev/null || { echo "python3 is required"; exit 1; }
	@if [ ! -x "$(BUF)" ]; then \
	  echo "==> installing buf@$(BUF_VERSION)"; \
	  npm install --no-save --no-audit --no-fund @bufbuild/buf@$(BUF_VERSION); \
	fi
	@echo -n "    buf      "; $(BUF) --version
	@echo -n "    node     "; node --version
	@echo -n "    python3  "; python3 --version
	@test "$$($(BUF) --version)" = "$(BUF_VERSION)" \
	  || { echo "buf version drift: want $(BUF_VERSION)"; exit 1; }
	@if [ -f build/toolchain/env.sh ]; then \
	  . build/toolchain/env.sh; \
	  command -v rustc  >/dev/null && echo -n "    rustc    " && rustc --version || true; \
	  command -v swift  >/dev/null && echo -n "    swift    " && (swift --version 2>&1 | head -1) || true; \
	  command -v javac  >/dev/null && echo -n "    javac    " && javac -version 2>&1 || true; \
	  command -v kotlinc >/dev/null && echo -n "    kotlinc  " && (kotlinc -version 2>&1 | head -1) || true; \
	  command -v dotnet >/dev/null && echo -n "    dotnet   " && dotnet --version || true; \
	fi
	@echo "==> toolchain OK"

# The four language toolchains needed to COMPILE the generated bindings.
# All install user-local; none needs sudo. Versions are pinned in
# build/toolchain/env.sh alongside the protobuf runtime versions they must match.
toolchains:
	@echo "==> installing pinned language toolchains"
	@bash build/toolchain/install-rust.sh
	@bash build/toolchain/install-jvm.sh
	@bash build/toolchain/install-dotnet.sh
	@bash build/toolchain/install-swift.sh
	@echo "==> toolchains OK"

# ---------------------------------------------------------------------------
# contracts
# ---------------------------------------------------------------------------
# 1. validate schemas   2. lint schemas   3. generate deterministic bindings
# 4. FAIL WHEN GENERATED CODE IS STALE
contracts: contracts-lint contracts-gen contracts-freshness
	@echo "==> contracts OK"

contracts-lint:
	@echo "==> validating schemas"
	@$(BUF) build $(CONTRACTS) -o /dev/null
	@echo "==> linting schemas"
	@$(BUF) lint $(CONTRACTS)
	@echo "==> validating registries"
	@for f in $(CONTRACTS)/registry/*.json; do python3 -c "import json,sys;json.load(open('$$f'))" || exit 1; done

contracts-gen:
	@echo "==> generating deterministic bindings"
	@rm -rf $(GEN_DIR)
	@$(BUF) generate $(CONTRACTS) --template $(CONTRACTS)/buf.gen.yaml -o $(CONTRACTS)

# A separate target so CI can assert freshness without regenerating: if
# `git status` is dirty under contracts/gen after `make contracts`, the
# committed bindings were stale and the change must be committed.
# Two distinct conditions, deliberately not conflated:
#   STALE          - a tracked generated file changed when regenerated. The
#                    committed bindings did not match the schema. Always fatal.
#   NOT COMMITTED  - gen/ is entirely untracked. Expected before the first
#                    commit; fatal in CI, where gen/ must already be committed.
contracts-freshness:
	@echo "==> checking generated bindings are current"
	@if command -v git >/dev/null && git rev-parse --git-dir >/dev/null 2>&1; then \
	  changed="$$(git status --porcelain -- $(GEN_DIR) 2>/dev/null | grep -v '^??' || true)"; \
	  if [ -n "$$changed" ]; then \
	    echo "FAIL: generated bindings are STALE - regenerating changed committed files."; \
	    echo "      Run 'make contracts' and commit $(GEN_DIR)."; \
	    echo "$$changed"; \
	    exit 1; \
	  fi; \
	  if ! git ls-files --error-unmatch $(GEN_DIR) >/dev/null 2>&1; then \
	    if [ "$${CI:-}" = "true" ]; then \
	      echo "FAIL: $(GEN_DIR) is not committed. ADR-0018 §11.12 requires the"; \
	      echo "      generated bindings to be committed and CI-verified."; \
	      exit 1; \
	    fi; \
	    echo "    note: $(GEN_DIR) is not yet committed (regeneration succeeded)"; \
	  else \
	    echo "    generated bindings match the schema"; \
	  fi; \
	fi
	@for lang in rust swift kotlin csharp; do \
	  test -d "$(GEN_DIR)/$$lang" || { echo "FAIL: missing $(GEN_DIR)/$$lang"; exit 1; }; \
	done

# Breaking-change detection against the frozen baseline. The baseline is
# refreshed only by a deliberate `make freeze` at a release boundary; a
# developer never refreshes it to make a red build go green.
contracts-breaking:
	@echo "==> breaking-change check"
	@if [ -f "$(BASELINE)" ]; then \
	  $(BUF) breaking $(CONTRACTS) --against $(BASELINE); \
	else \
	  echo "    no frozen baseline yet ($(BASELINE)); run 'make freeze' at the"; \
	  echo "    contract freeze to create one"; \
	fi

.PHONY: freeze
freeze:
	@echo "==> freezing the current schema as the compatibility baseline"
	@$(BUF) build $(CONTRACTS) -o $(BASELINE)
	@echo "    wrote $(BASELINE)"
	@echo "    commit this file; from now on every change is checked against it"

# ---------------------------------------------------------------------------
# verify-bindings
# ---------------------------------------------------------------------------
# A byte-diff proves the committed bindings are CURRENT. It does not prove they
# COMPILE. ADR-0018 §11.12 wants a schema change that a language binding "cannot
# express" to fail at MERGE - and "cannot express" is a compile error, not a
# diff. This target is that check.
#
# Skipped with a clear message when a toolchain is absent, so a contributor
# without all four can still run the rest of the gate; CI has all four and does
# not skip.
verify-bindings:
	@bash build/verify/verify-bindings.sh $(LANG_FILTER)

# ---------------------------------------------------------------------------
# test-contracts
# ---------------------------------------------------------------------------
test-contracts: contracts-breaking
	@echo "==> contract tests"
	@python3 $(CONTRACTS)/tests/run_tests.py

# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------
# Builds everything currently buildable: the contract package, then every
# cargo workspace. A workspace that is skeleton-only still MUST compile - that
# is what keeps `main` green while domains land one at a time.
build: contracts verify-bindings build-rust
	@echo "==> build complete"

build-rust:
	@for w in $(WORKSPACES); do \
	  echo "==> build $$w"; \
	  ( cd $$w && $(CARGO) build --workspace --all-targets ) || exit 1; \
	done

# ---------------------------------------------------------------------------
# lint
# ---------------------------------------------------------------------------
lint: contracts-lint lint-rust arch-lint doc-check redaction-check
	@echo "==> linting python"
	@python3 -m compileall -q $(CONTRACTS)/tests >/dev/null
	@echo "==> linting javascript"
	@node --check $(CONTRACTS)/tests/pbjs_helper.js
	@echo "==> linting documentation links"
	@python3 scripts/check_doc_links.py
	@echo "==> lint OK"

# rustfmt --check and clippy -D warnings across every workspace. The ADR-0018 T1
# architectural lints are the sibling `arch-lint` target, and as of this gate
# pass they are a prerequisite of `lint` rather than a target someone remembers
# to run: CD-3 says the deny-list "is the actual mechanism", and CD-I5 is the
# artifact ADR-0002 §11.8 step 3 requires and B-19 blocks a release without.
lint-rust:
	@for w in $(WORKSPACES); do \
	  echo "==> fmt+clippy $$w"; \
	  ( cd $$w && $(CARGO) fmt --all -- --check && \
	              $(CARGO) clippy --workspace --all-targets -- -D warnings ) || exit 1; \
	done

# Broken intra-doc links, as a gate.
#
# Added on relay-plane's recommendation after it found FOUR stale links in its
# own crates -- a type deleted in a refactor, a module that moved, and two that
# never resolved. Its diagnosis is the reason this is a target rather than a
# habit: "it is also why this drifted: nothing was watching."
#
# This matters more here than in most repositories. Several crates' stated value
# is that a claim can be checked against its source in one hop -- twinvpn-crypto
# says so explicitly -- and a broken link in those defeats the crate's own
# premise while looking cosmetic.
# `invalid_html_tags` is allowed, and ONLY that one. contracts/gen/** is frozen
# generated output that twinvpn-schema include!s, and a proto comment there
# legitimately reads "<twinnet-label>.tnet.twinvpn.net" -- which rustdoc parses
# as an unclosed HTML tag. The contract is frozen and the comment is correct
# prose, so the lint is wrong here rather than the source. core-foundation hit
# the same class from the doctest side and set `doctest = false` for the same
# reason. Every other rustdoc warning, including the broken-intra-doc-link class
# this target exists for, still fails the build.
# `private_intra_doc_links` is allowed for the reason (1) below gives for
# `--all-features`, and it is the same reason. A module header that explains an
# unsafe mechanism by naming the private function that implements it --
# `sock.rs` pointing at `read_pktinfo` and its two `copy_nonoverlapping`s,
# `route.rs` pointing at `unwind` -- is CORRECT PROSE about code that exists.
# These crates are internal artifacts nobody publishes to docs.rs, so the link's
# public reachability is worth less than the navigation it gives the reader of
# the unsafe code below it. The only way to green the lint is to demote each
# link to a plain code span, which deletes that navigation from exactly the
# documentation that most needs it.
#
# `--document-private-items` was tried first and is NOT the answer: it does not
# suppress this lint, and it exposes private items whose own docs then fail it.
# It took the count from 39 to 42.
#
# Every OTHER rustdoc warning, including the broken-intra-doc-link class this
# target exists for, still fails the build.
DOCFLAGS := -D warnings -A rustdoc::invalid_html_tags -A rustdoc::private_intra_doc_links

# A PREREQUISITE OF `lint` as of the wave-3 integration. On first run this target
# found 14 broken intra-doc links across six crates owned by three domains --
# precisely the drift it exists to catch -- and it was left as a NAMED target
# rather than a silent skip, on the same principle infrastructure applied to the
# arch-lint CI job while it was red: a gate you intend to enforce should be
# visible and failing, not absent. The instruction it carried was "wire it into
# `lint` once the six crates are clean".
#
# They are clean. The count peaked at 43 across nine crates once the earlier
# failures stopped aborting each crate's doc build and revealed the ones behind
# them; every one is now fixed at the link rather than suppressed, except the
# single lint DOCFLAGS allows and argues for below.
# --all-features, and the loop does not stop at the first failure. Both are
# test-engineering's findings against the first version of this target:
#
#   1. Without --all-features, `cargo doc` runs the default feature set, so every
#      link to a feature-gated module is unresolvable -- twinvpn-env's four links
#      to `virtual_time` (behind test-support) and twinvpn-platform's to `mock`.
#      Those links are CORRECT PROSE about modules that exist. Without this flag
#      they would have been "fixed" by deleting accurate documentation, which is
#      the opposite of what the target is for.
#   2. Failing fast on `core` meant `lab` and `tests` were never reached, so
#      their owners could not see their own state without running it by hand.
doc-check:
	@rc=0; for w in $(WORKSPACES); do \
	  echo "==> doc $$w"; \
	  ( cd $$w && RUSTDOCFLAGS="$(DOCFLAGS)" $(CARGO) doc --workspace --no-deps --all-features -q ) || rc=1; \
	done; exit $$rc

fmt:
	@for w in $(WORKSPACES); do ( cd $$w && $(CARGO) fmt --all ); done

# ---------------------------------------------------------------------------
# cross-check: the wave-2 desktop targets
# ---------------------------------------------------------------------------
# `ownership.md` §5 deferred the Windows and macOS shells because their platform
# surfaces "cannot be compiled, let alone exercised, on the Linux host this wave
# runs on". Half of that is now false and half is still true, and the split is
# exactly where this target draws it.
#
# STILL TRUE: nothing here LINKS or RUNS. There is no MSVC linker, no Darwin
# SDK, no WFP engine, no NetworkExtension host. A green `cross-check` is a
# compile proof, NOT a behaviour proof, and it must never be reported as one.
#
# NOW FALSE: the rust-std for both targets installs on this host, and `cargo
# check`/`clippy` need no linker. So every line of Rust in the two wave-2
# adapters and the two wave-2 shells is type-checked against the REAL Win32 and
# Darwin sys crates, with `-D warnings`, on this runner. That is the difference
# between "shell code that has never been built" -- the failure mode wave 1
# named -- and shell code whose behaviour has not yet been observed.
#
# READ THAT LAST PARAGRAPH WITH THE `ring` BLOCK BELOW. Since L-CONTROL it is
# true of the two ADAPTERS and of the shell code outside the core-hosting
# profile, and NOT of the core-hosting profile itself. The block below says
# exactly which half is which, and so does this target's closing banner.
#
# The behaviour half is discharged by the adapters' own host-runnable tests:
# both wave-2 adapters keep their translation layers (filter and anchor
# construction, route and DNS programme rendering, error mapping) target-free,
# so `make test` exercises them on Linux exactly as the nftables ruleset text
# and the `nft --json` parser are exercised today.
# The core workspace is checked BY PACKAGE, not `--workspace`: it holds all
# three adapters, and `twinvpn-platform-linux` does not compile for Darwin (nor
# should it). Each shell workspace holds only its own platform's crates, so
# `--workspace` is right there.
#
# WAVE 3 (mobile) joins this target on exactly the same terms. `aarch64-apple-ios`
# and `aarch64-linux-android` rust-std install here too, so both mobile adapters
# are type-checked against the real Darwin and bionic sys crates with
# `-D warnings`. NOTHING Swift and NOTHING Kotlin is reached: this target
# invokes no Swift and no Kotlin compiler over `shells/ios` or `shells/android`,
# so both are WRITTEN, NOT COMPILED in ownership.md 9.2's sense, and no `make`
# target may claim otherwise.
#
# Said as a fact about THIS TARGET, deliberately, rather than about the machine.
# A JDK and `kotlinc` ARE on this host -- `make bootstrap` prints their versions
# and `verify-bindings` compiles the JVM bindings with them -- so "there is no
# JDK here", which this comment used to say, was false and would have made a
# reader distrust the rest. What is absent for the SHELLS is an Android SDK, an
# NDK and a Darwin SDK, and what matters for a coverage claim is which compiler
# this recipe actually runs.
WIN_TARGET := x86_64-pc-windows-msvc
MAC_TARGET := aarch64-apple-darwin
IOS_TARGET := aarch64-apple-ios
AND_TARGET := aarch64-linux-android

cross-check:
	@echo "==> cross-check twinvpn-platform-windows ($(WIN_TARGET))"
	@cd core && $(CARGO) clippy -p twinvpn-platform-windows --all-targets \
	    --target $(WIN_TARGET) -- -D warnings
	@echo "==> cross-check twinvpn-platform-macos ($(MAC_TARGET))"
	@cd core && $(CARGO) clippy -p twinvpn-platform-macos --all-targets \
	    --target $(MAC_TARGET) -- -D warnings
# `ring` is back in the graph, and it took the core-hosting crates with it.
#
# History, because it decides what this target may honestly claim: both shell
# workspaces were once checked WHOLE, and that became possible only when `ring`
# left the dependency graph -- its build script refuses a GNU compiler for an
# MSVC target, needs `lib.exe`, and needs a Darwin or NDK C toolchain for the
# other two. Selecting snow's default resolver removed that edge, and the first
# full run found a real error in lines nothing had ever compiled.
#
# L-CONTROL brought it back by a different road: `twinvpn-cp-client` -> `quinn`
# -> `quinn-proto`/`rustls` -> `ring`. So every crate that hosts a core is again
# uncompilable for a foreign target on this host, and the target says which
# crates those are instead of dying at the first one and leaving the iOS and
# Android checks unrun.
#
# WHAT WILL NOT LIFT IT, and this is the correction G-6 records: swapping the
# rustls `CryptoProvider`. `ring` is NOT reached only through rustls. In
# quinn-proto 0.11.17 the feature graph is `rustls = ["rustls-ring"]` and
# `rustls-ring = ["dep:rustls", "rustls?/ring", "ring"]`, so the ONLY two ways
# to compile quinn's rustls integration at all are `ring` or `aws-lc-rs` -- and
# `aws-lc-rs` builds C, cmake and bindgen, which is strictly worse here. Beyond
# the provider seam quinn-proto uses ring DIRECTLY: `crypto/ring_like.rs`
# implements `HmacKey`, `HandshakeTokenKey` and `AeadKey` on ring's own types,
# `config/mod.rs` builds the default reset and token keys with `ring::hmac` and
# `ring::hkdf`, and `crypto/rustls.rs` selects the provider under `#[cfg]` with
# no override. A pure-Rust provider would therefore leave this edge exactly
# where it is. Removing it means forking quinn-proto or leaving quinn, which is
# an architecture decision; `ownership.md` §11 carries G-4 and G-6 with owners.
#
# WHAT THIS TARGET DOES ABOUT IT, short of that decision: it compiles the four
# core-hosting crates under the REDUCED PROFILE the repository already declares,
# rather than not compiling them at all. `core-lite` is ADR-0018 §11.12's
# parse-and-verify-only profile (S-46) and it carries no data-plane crate and no
# `twinvpn-cp-client` -- so no `quinn`, no `rustls`, no `ring`, and no C. Every
# shell below keeps `default = ["full"]`, so nothing that ships changes; what is
# new is a second profile a Linux host can reach.
#
# BE PRECISE ABOUT WHAT THAT PROVES. It is a PARTIAL proof. The shipping profile
# is `full`, and the lines that name the `full`-only core API are still compiled
# by nothing here. What it converts is the far larger remainder -- every line of
# the Win32 service surface, the Darwin bridge and the JNI carriage that does not
# name a `full`-only symbol -- from "never compiled for its target" to
# "compiled". The residue is exactly what a real Windows, macOS or Android
# builder is for, and the banner at the end of this target names it.
	@if [ -f shells/windows/Cargo.toml ]; then \
	  echo "==> cross-check shells/windows ($(WIN_TARGET)), --features service"; \
	  ( cd shells/windows && $(CARGO) clippy -p twinvpnsvc \
	      --no-default-features --features service --all-targets \
	      --target $(WIN_TARGET) -- -D warnings ) || exit 1; \
	  ( cd shells/windows && $(CARGO) clippy -p twinvpnctl --all-targets \
	      --target $(WIN_TARGET) -- -D warnings ) || exit 1; \
	  ( cd shells/windows && $(CARGO) tree -i ring --target $(WIN_TARGET) >/dev/null 2>&1 ) \
	    || { echo "    ring has LEFT the windows graph UNDER core-host: the"; \
	         echo "    --no-default-features service check below is now redundant"; \
	         echo "    with the core-host one and should be deleted"; exit 1; }; \
	fi
# The core-host half, which used to be NOT CHECKED, and the reason it no longer
# has to be. `ring` needs an MSVC-target C compiler; it does NOT need `cl.exe`.
# ring 0.17.14's build.rs branches on `is_like_clang_cl()`, and `clang-cl` is a
# NATIVE LINUX BINARY that the pinned Swift 6.1.2 toolchain already ships (it
# carries a whole LLVM 17: clang-cl, lld-link, llvm-ar). It takes Linux paths and
# reads the MSVC and Windows SDK headers as ordinary files, so nothing crosses a
# WSL interop boundary and `lib.exe` is not wanted either -- `llvm-ar` serves.
# NASM is not wanted: ring ships 17 pre-assembled COFF objects and uses them for
# any non-git checkout.
#
# `CC_SHELL_ESCAPED_FLAGS=1` is load-bearing. The SDK paths contain spaces and
# cc-rs word-splits CFLAGS without it; the failure looks like a path problem and
# is not one.
#
# GUARDED, because the headers come from a Windows installation this recipe
# cannot require: no MSVC tree, no lane, and the banner says which it got. That
# is the same rule the rest of this target follows -- report the coverage you
# actually have.
#
# The `|| true` on each probe is load-bearing. .SHELLFLAGS runs every recipe
# under `-eu -o pipefail`; on a host with no /mnt/c the glob does not expand,
# `ls` exits 2, `2>/dev/null` hides the message but not the status, pipefail
# carries it through `sort | tail`, and `-e` aborts the recipe BEFORE the `else`
# branch below can print NOT CHECKED. That killed the whole cross-check job on
# its first CI run with `Error 2` and no output, taking the macOS, iOS, Android
# and Swift lanes after it down with it.
	@win_vc=$$(ls -d "/mnt/c/Program Files/Microsoft Visual Studio/"*/*/VC/Tools/MSVC/*/ 2>/dev/null | sort -V | tail -1 || true); \
	win_sdk="/mnt/c/Program Files (x86)/Windows Kits/10"; \
	win_sdkv=$$(ls "$$win_sdk/Include" 2>/dev/null | sort -V | tail -1 || true); \
	if [ -f build/toolchain/env.sh ]; then . build/toolchain/env.sh; fi; \
	if [ -n "$$win_vc" ] && [ -n "$$win_sdkv" ] && command -v clang-cl >/dev/null; then \
	  echo "==> cross-check shells/windows twinvpnsvc ($(WIN_TARGET)), core-host"; \
	  CC_x86_64_pc_windows_msvc=clang-cl \
	  AR_x86_64_pc_windows_msvc=llvm-ar \
	  CC_SHELL_ESCAPED_FLAGS=1 \
	  CFLAGS_x86_64_pc_windows_msvc="-imsvc'$$win_vc/include' -imsvc'$$win_sdk/Include/$$win_sdkv/ucrt' -imsvc'$$win_sdk/Include/$$win_sdkv/um' -imsvc'$$win_sdk/Include/$$win_sdkv/shared'" \
	  sh -c 'cd shells/windows && exec $(CARGO) clippy -p twinvpnsvc --all-targets --target $(WIN_TARGET) -- -D warnings' \
	    || exit 1; \
	else \
	  echo "==> cross-check twinvpnsvc core-host      NOT CHECKED (no MSVC headers)"; \
	fi
	@if [ -f shells/macos/Cargo.toml ]; then \
	  echo "==> cross-check shells/macos ($(MAC_TARGET))"; \
	  ( cd shells/macos && $(CARGO) clippy -p twinvpn-mi -p twinvpnctl -p ksd \
	      -p twinvpn-unblock --all-targets --all-features \
	      --target $(MAC_TARGET) -- -D warnings ) || exit 1; \
	  echo "==> cross-check shells/macos twinvpn-bridge ($(MAC_TARGET)), core-lite"; \
	  ( cd shells/macos && $(CARGO) clippy -p twinvpn-bridge \
	      --no-default-features --features core-lite --all-targets \
	      --target $(MAC_TARGET) -- -D warnings ) || exit 1; \
	  ( cd shells/macos && $(CARGO) tree -i ring --target $(MAC_TARGET) >/dev/null 2>&1 ) \
	    || { echo "    ring has LEFT the macos graph UNDER full: drop the core-lite"; \
	         echo "    split and check twinvpn-bridge in its shipping profile"; exit 1; }; \
	fi
	@echo "==> cross-check twinvpn-platform-ios ($(IOS_TARGET))"
	@cd core && $(CARGO) clippy -p twinvpn-platform-ios --all-targets \
	    --target $(IOS_TARGET) -- -D warnings
	@echo "==> cross-check twinvpn-platform-android ($(AND_TARGET))"
	@cd core && $(CARGO) clippy -p twinvpn-platform-android --all-targets \
	    --target $(AND_TARGET) -- -D warnings
# The Android shell's Rust half. Two libraries, not one: CD-I5 forbids
# `twinvpn-platform-android` to name `twinvpn-core`, so the core's JNI entries
# live in their own crate and their own `.so`. It hosts a core, so it is in the
# blocked set above for the same reason and by the same edge, and it is reached
# the same way: `core-lite` forwarded through `twinvpn-ffi`.
	@if [ -f shells/android/jni/Cargo.toml ]; then \
	  echo "==> cross-check shells/android/jni ($(AND_TARGET)), core-lite"; \
	  ( cd shells/android/jni && $(CARGO) clippy --workspace \
	      --no-default-features --features core-lite --all-targets \
	      --target $(AND_TARGET) -- -D warnings ) || exit 1; \
	  ( cd shells/android/jni && $(CARGO) tree -i ring --target $(AND_TARGET) >/dev/null 2>&1 ) \
	    || { echo "    ring has LEFT the android graph UNDER full: the core-lite"; \
	         echo "    check is now redundant with the full one and should be"; \
	         echo "    deleted"; exit 1; }; \
	fi
# The full profile, by the same route and with a caveat the core-host lane does
# not need. `clang` targeting `aarch64-linux-android21` compiles ring here, with
# NO NDK -- but only because `-nostdlibinc -DRING_CORE_NOSTDLIBINC=1` substitutes
# ring's own headers for bionic's. ring applies that combination itself only for
# wasm32 and non-x86_64 musl, so this is a WEAKER check than an NDK build: it
# proves the Rust half type-checks for bionic, and it does NOT produce a
# shippable object. Stated here and in the banner rather than left for someone to
# infer from a green line.
#
# GUARDED on `llvm-ar` and `clang`, for the same reason the MSVC lane above is
# guarded and by the same rule -- report the coverage you actually have.
# `AR_aarch64_linux_android=llvm-ar` and `CC_..=clang` are LITERAL PROGRAM NAMES
# handed to cc-rs, and on this host they resolve only because
# `build/toolchain/env.sh` puts the pinned Swift toolchain's LLVM 17 on PATH
# (the same LLVM the Windows lane takes `clang-cl` from). A host without that
# toolchain -- a bare CI runner is the case that matters -- fails inside ring's
# build script with an exec error that READS AS A CODE FAILURE AND IS NOT ONE.
# So: no llvm-ar, no lane, and the banner says which it got.
# `.github/workflows/rust-t1.yml` installs `llvm` and `clang` on the runner so
# that the lane genuinely runs there rather than quietly reporting NOT CHECKED.
	@if [ -f shells/android/jni/Cargo.toml ]; then \
	  if [ -f build/toolchain/env.sh ]; then . build/toolchain/env.sh; fi; \
	  if ! command -v llvm-ar >/dev/null; then \
	    echo "==> cross-check android/jni full          NOT CHECKED (no llvm-ar)"; \
	  elif ! command -v clang >/dev/null; then \
	    echo "==> cross-check android/jni full          NOT CHECKED (no clang)"; \
	  else \
	    echo "==> cross-check shells/android/jni ($(AND_TARGET)), full"; \
	    CC_aarch64_linux_android=clang \
	    AR_aarch64_linux_android=llvm-ar \
	    CFLAGS_aarch64_linux_android="--target=aarch64-linux-android21 -nostdlibinc -DRING_CORE_NOSTDLIBINC=1" \
	    sh -c 'cd shells/android/jni && exec $(CARGO) clippy --locked --workspace --all-targets --target $(AND_TARGET) -- -D warnings' \
	      || exit 1; \
	  fi; \
	fi
# The Swift half, and it is a PARSE and not a compile. Said in those words
# because the difference is the whole of what this target is for.
#
# `shells/ios` and `shells/macos` import NetworkExtension, SystemExtensions,
# SwiftUI, Security and Network. A Linux Swift 6.1.2 has Foundation and has none
# of those, so `-typecheck` cannot run here and will not until a Darwin SDK does
# -- which for `shells/macos` means Apple hardware, because the SDK licence
# confines it there. What `-parse` DOES establish is that every one of these
# files is syntactically valid Swift under the pinned compiler, which is
# strictly more than the nothing that checked them before: an unbalanced brace,
# a malformed expression or a stray token in a file no CI compiles used to reach
# `main` unnoticed.
#
# So this moves ownership.md 9.2's "WRITTEN, NOT COMPILED" to "PARSED, NOT
# TYPE-CHECKED" for Swift, and moves Kotlin not at all -- see the banner.
	@$(MAKE) --no-print-directory swift-parse
	@echo "==> cross-check OK (compile only -- nothing was linked or run)"
	@echo "    PARTIAL, and the partiality is the point. The core-hosting crates"
	@echo "    were compiled in core-lite; the full profile's QUIC lines are"
	@echo "    compiled by NOTHING THIS TARGET RUNS. Per crate, exactly:"
	@echo "      shells/windows     twinvpnsvc  --features service"
	@echo "                                         core-host  see above"
	@echo "      shells/windows     twinvpnctl  whole"
	@echo "      shells/macos       twinvpn-bridge      core-lite"
	@echo "                                         full       NOT CHECKED"
	@echo "      shells/android/jni twinvpn-android-jni core-lite"
	@echo "                                         full       see above"
	@echo "    What changed, and what did not. G-18: ring needs an MSVC-target C"
	@echo "    compiler, NOT cl.exe -- its build.rs has an is_like_clang_cl()"
	@echo "    branch, and the pinned Swift toolchain ships clang-cl, lld-link"
	@echo "    and llvm-ar as native Linux binaries. So Windows core-host is"
	@echo "    checked WHEN an MSVC header tree is visible, and android full"
	@echo "    WHEN llvm-ar and clang are on PATH -- build/toolchain/env.sh"
	@echo "    supplies both from that same LLVM. The two lines above say which"
	@echo "    of them this run actually got; neither is unconditional."
	@echo "    The android full lane is WEAKER than an NDK build: -nostdlibinc"
	@echo "    substitutes ring's headers for bionic's, so it proves the Rust"
	@echo "    half type-checks and yields NO shippable object."
	@echo "    macOS/iOS stay blocked and the cause is specific: ring's"
	@echo "    include/ring-core/base.h includes <TargetConditionals.h>, which"
	@echo "    -nostdlibinc cannot supply, and cc-rs needs xcrun for iOS"
	@echo "    regardless of CC. Apple SDK, Apple hardware. ownership.md 11,"
	@echo "    findings G-4, G-6, G-7 and G-18."
	@echo "    Swift (shells/ios, shells/macos): PARSED, NOT TYPE-CHECKED."
	@echo "    swiftc -parse proves the syntax under the pinned compiler and"
	@echo "    proves NOTHING about types: NetworkExtension, SystemExtensions,"
	@echo "    SwiftUI, Security and Network are absent from a Linux Swift, so"
	@echo "    -typecheck needs a Darwin SDK -- Apple hardware for shells/macos."
	@echo "    Kotlin (shells/android): NOT COMPILED HERE AT ALL. 22 of its 24"
	@echo "    .kt files import android.* / androidx.*, and the two that do not"
	@echo "    (NativeBridge.kt, Rendered.kt) reference NativeHost, which does."
	@echo "    kotlinc IS on this host; an android.jar is not. ownership.md 9.2."
	@echo "    Every NOT CHECKED above is a statement about THIS TARGET's"
	@echo "    coverage, not about the machine. A native Windows or Darwin build"
	@echo "    lane would change which of these lines is still true; until one"
	@echo "    exists and is wired in here, read them as written."

# The Swift syntax lane, as its OWN target so that `cross-check` and CI call one
# definition rather than two that can drift -- the defect class W-20, X-4 and
# R-14 all belong to. `cross-check` depends on it; `.github/workflows/rust-t1.yml`
# runs it inside a pinned Swift container, which is the only place a Swift
# compiler is guaranteed.
#
# Each shell is parsed SEPARATELY. `swiftc` refuses two files with the same
# basename in one invocation, and `shells/ios` and `shells/macos` both carry a
# `PacketTunnelProvider.swift` -- correctly, since they are two modules.
swift-parse:
	@if [ -f build/toolchain/env.sh ]; then . build/toolchain/env.sh; fi; \
	if ! command -v swiftc >/dev/null; then \
	  echo "==> parse-check Swift                     NOT CHECKED (no swiftc)"; \
	  exit 0; \
	fi; \
	for sh in ios macos; do \
	  echo "==> parse-check shells/$$sh (Swift, syntax only)"; \
	  swiftc -parse $$(find shells/$$sh -name '*.swift') \
	    || { echo "    shells/$$sh Swift does not PARSE"; exit 1; }; \
	done

# ADR-0018 CD-3 / CD-I2 / CD-I5 / CB-3. Owned by core-foundation.
arch-lint:
	@echo "==> ADR-0018 T1 architectural lints"
	@cd core && $(CARGO) run -q -p xtask -- lint

# ---------------------------------------------------------------------------
# infrastructure
# ---------------------------------------------------------------------------
# The one infrastructure check that runs in `lint`: it asserts that telemetry
# CANNOT capture a tunnel payload, a key or a correlation-breaking service
# graph. That is a security invariant, so it must hold on every developer
# machine and not only on one with a container runtime -- and unlike the
# topology check it has no runtime precondition.
redaction-check:
	@echo "==> collector redaction is structural"
	@python3 build/verify/check-otel-redaction.py

# Local secret directories and development key material. Idempotent.
infra-bootstrap:
	@bash infra/scripts/bootstrap-local.sh

# Structural invariants over the compose topology and the collector's privacy
# controls. Needs only PyYAML, so it runs WITHOUT Docker -- which is why it is a
# prerequisite of `lint` rather than of `infra-up`: the invariant that telemetry
# cannot capture a tunnel payload must be checked on every developer machine,
# not only on one that happens to have a container runtime.
infra-check: infra-bootstrap redaction-check
	@echo "==> compose topology"
	@python3 build/verify/check-compose.py --strict
	@if command -v docker >/dev/null 2>&1; then \
	  docker compose config --quiet && echo "    compose schema OK"; \
	else \
	  echo "    note: docker not installed; compose SCHEMA not validated"; \
	fi

infra-up: infra-check
	@docker compose up -d --wait postgres otel-collector prometheus tempo loki grafana

infra-up-v6: infra-check
	@docker compose -f docker-compose.yml -f infra/compose/ipv6-only.yml \
	  up -d --wait postgres otel-collector prometheus tempo loki grafana

infra-down:
	@docker compose down -v --remove-orphans

# ---------------------------------------------------------------------------
# The host-native plane, and the lab.
#
# RECONSTRUCTED. These fifteen targets were lost to a `git checkout -- Makefile`
# that reverted the whole file rather than one edit, and are rebuilt here from
# the artifacts that survived: `infra/scripts/local-plane.sh`'s and
# `infra/scripts/local-postgres.sh`'s own usage blocks, `infra/README.md` §0 and
# §9a, `lab/README.md` §4's tier table, and `.github/workflows/lab-t1.yml`,
# which invokes six of them by name. Behaviour is the documented behaviour;
# the wording of the comments is not the original wording.
#
# `docker compose` remains the supported topology. Everything in this section
# exists because the part most worth reproducing -- a real Noise_IK leg
# carrying a real COSE_Sign1 token, and a real device attaching to a real
# control plane over QUIC -- needs no container at all, and this host cannot
# run one (rootless podman needs `newuidmap`, which only root can install).
# ---------------------------------------------------------------------------

# The development relay credentials. Idempotent, and it never rotates an
# existing seed: rotating would invalidate every token a running relay holds,
# and the symptom -- binds refused for no visible reason -- is the hardest
# failure here to diagnose.
dev-issuer:
	@bash infra/scripts/bootstrap-local.sh

plane-up: infra-check
	@bash infra/scripts/local-plane.sh up

plane-up-v6: infra-check
	@bash infra/scripts/local-plane.sh up --v6

# One-shot, and the reason this target exists rather than a test.
# `cargo test -p twinvpn-relay` was green while the shipped binary refused
# EVERY legitimate token: `main.rs` handed the packet path a monotonic offset
# from process start where a token's nbf/exp needs a wall clock, and the
# in-crate harness injects a wall-clock constant so it never exercised the
# clock the binary runs with. Only starting the real binary finds that.
plane-probe:
	@bash infra/scripts/local-plane.sh probe

# The control-plane half: a simulated device completing a real rung-1 L-CONTROL
# attach -- QUIC + TLS 1.3, mutual RFC 7250 raw public keys, the RFC 9266
# tls-exporter channel binding read off the live connection, one real C1 round
# trip. Needs `pg-up`.
plane-ceremony:
	@bash infra/scripts/local-plane.sh ceremony

plane-status:
	@bash infra/scripts/local-plane.sh status

plane-down:
	@bash infra/scripts/local-plane.sh down

# A real PostgreSQL from the official binaries, pinned by version AND SHA-256,
# run as an unprivileged user out of a cache directory. Loopback-bound on a
# non-default port, which is the only reason `--auth=trust` is safe.
pg-up:
	@bash infra/scripts/local-postgres.sh up

pg-down:
	@bash infra/scripts/local-postgres.sh down

# Stops it and DESTROYS the data directory.
pg-reset:
	@bash infra/scripts/local-postgres.sh reset

# ---------------------------------------------------------------------------
# TwinLab. NEVER SHIPPED (ADR-0018 §11.12).
# ---------------------------------------------------------------------------

# What this host can actually realize, PROBED rather than assumed. Run it
# first: every other lab target's answer is conditional on this one.
lab-capabilities:
	@cd lab && $(CARGO) run -q -p twinlab-scenarios -- capabilities

# testing-strategy.md §3.4.2's NAT-personality conformance suite, run against a
# real middlebox by a prober that is not TwinVPN code.
#
# Rule L-1: no traversal, leak or relay test may run against a personality that
# has not passed this, in the same lab instantiation, on the same day.
lab-conformance:
	@cd lab && $(CARGO) run -q -p twinlab-scenarios -- conformance

# The fabric: real namespaces, real veth pairs, real userspace middleboxes,
# real captures. T2 -- needs NET_ADMIN, `nft` and `conntrack`, and costs
# minutes rather than seconds.
lab-fabric:
	@cd lab && $(CARGO) test -p twinnet

# The lab overlay: `sim` (twinsim-alice/bob/gateway) and `netlab`
# (netlab-nat, netlab-ns-carol, twinsim-carol). Two profiles, because they
# answer different questions and cost different things -- `netlab` needs
# NET_ADMIN, `nft` and `conntrack`; `sim` needs nothing beyond the base stack.
netlab-up: infra-check
	@docker compose -f docker-compose.yml -f infra/compose/netlab.yml \
	  --profile sim --profile netlab up -d

netlab-down:
	@docker compose -f docker-compose.yml -f infra/compose/netlab.yml \
	  --profile sim --profile netlab down -v --remove-orphans

# ADR-0018 §11.9 artifact budgets. BM-4: a breach is a failure, not a re-run.
budgets:
	@python3 build/verify/check-budgets.py --list

budgets-images:
	@python3 build/verify/check-budgets.py --check-image-pins

# ---------------------------------------------------------------------------
# test
# ---------------------------------------------------------------------------
test: test-contracts test-rust
	@echo "==> all available tests passed"

test-rust:
	@for w in $(WORKSPACES); do \
	  echo "==> test $$w"; \
	  ( cd $$w && $(CARGO) test --workspace ) || exit 1; \
	done

# ---------------------------------------------------------------------------
# gate: the Phase 2 contract freeze gate
# ---------------------------------------------------------------------------
gate: bootstrap lint contracts verify-bindings test-contracts
	@python3 scripts/freeze_gate.py
	@python3 scripts/check_freeze_scope.py

# The freeze is a property of the build, not of anyone's memory: it fails if the
# schema moved after contracts/FROZEN was written.
freeze-scope:
	@python3 scripts/check_freeze_scope.py

clean:
	@rm -rf $(GEN_DIR)
	@for w in $(WORKSPACES); do ( cd $$w && $(CARGO) clean ); done

# ---------------------------------------------------------------------------
# T3/T4 proof tests — docs/testing-strategy.md §4, §4.3 and §6.2.
# ---------------------------------------------------------------------------
# §4's twenty-two proof tests P01-P22 "are the acceptance criteria for the whole
# architecture", and §4 adds that "the count is load-bearing". These four
# targets are the local half of the T3/T4 workflows in
# .github/workflows/t3-proof.yml and t4-release.yml.
#
# They are deliberately NOT wired into `test` or `gate`. Rule C-3 places the
# mutant sets at T3 and T4 and nowhere else, and `gate` is a T1/T2 shape: adding
# a several-minute mutant run to it would either blow the T1 budget (rule C-1
# forbids raising it silently) or invite someone to shrink the mutant set to fit.
.PHONY: proof proof-register proof-oracles proof-mutants

# The register's shape: the count is 22, the ids are P01..P22, and every row's
# mutant arithmetic matches the patches actually in build/mutants/. Then every
# scenario id the register cites is resolved against lab/'s catalogue, so a
# register cannot claim coverage from a scenario nobody has defined. The first
# check is seconds; the second builds the lab workspace, which is why
# `status.sh` keeps it behind a flag rather than doing it always.
proof-register:
	@build/proof/status.sh
	@build/proof/status.sh --with-catalogue

# Runs each row's evidence command and reports what happened. This is the
# runnable SUBSET of each proof test's oracle, never the proof test: every row
# carries a NEEDS column saying what the difference is.
proof-oracles:
	@build/proof/status.sh --run

# Rule PT-1, executed: for every patch in build/mutants/, the clean build must
# pass and the mutant must be buildable and caught by its named oracle. Builds
# its rig with `git worktree add` at an explicit commit, so a dirty working tree
# is reported rather than silently included (rule C-5).
proof-mutants:
	@build/proof/run-mutants.sh

proof: proof-register proof-oracles proof-mutants
	@echo "==> none of the above is a PT-1 PASS; see build/proof/register.tsv"

# ---------------------------------------------------------------------------
# First Implementation Wave — the acceptance gate.
#
# These are the stable repository-level commands the wave's blockers are proved
# with. They are thin: every one of them delegates to a script or a cargo test
# that is the actual evidence, so that the same proof runs identically here and
# in .github/workflows/first-implementation-wave-gate.yml. A make target that
# reimplemented the check would be a second thing to keep in step, and the two
# would silently diverge.
#
# NOTHING HERE PRINTS "PASS" ON ITS OWN AUTHORITY. Each target exits non-zero
# when its evidence is absent or red, and `test-first-wave-gate` computes
# Phase 5 eligibility from the rows rather than asserting it.
# ---------------------------------------------------------------------------
.PHONY: test-crypto-integration test-pairing-integration test-mutation \
        ci-linux ci-windows ci-macos ci-ios ci-android test-first-wave-gate \
        ci-windows-killswitch ci-android-16k ci-macos-sysext \
        ci-macos-signature test-acceptance-gate-logic \
        first-wave-report

# F-1. The crypto core must be exercised by the real producer/consumer paths,
# and these tests are written to FAIL IF THE WIRING IS REMOVED.
test-crypto-integration:
	@echo "==> F-1: crypto integration across the production data path"
	@source build/toolchain/env.sh && cd core && \
	  $(CARGO) test --locked -p twinvpn-crypto && \
	  $(CARGO) test --locked -p twinvpn-core --test resume && \
	  $(CARGO) test --locked -p twinvpn-core --test resume_lifecycle && \
	  $(CARGO) test --locked -p twinvpn-core --test crypto_carriage

# F-2. Pairing must work in the SAME COMPOSITION the shipped application uses.
# A test that calls `install_pairing_enrolment` directly is not evidence here.
test-pairing-integration:
	@echo "==> F-2: pairing through the production MI/application composition"
	@source build/toolchain/env.sh && cd core && \
	  $(CARGO) test --locked -p twinvpn-core --test pairing && \
	  $(CARGO) test --locked -p twinvpn-core --test pairing_refusals
	@source build/toolchain/env.sh && cd shells/linux && \
	  $(CARGO) test --locked -p twinvpnd --test pairing && \
	  $(CARGO) test --locked --workspace

# F-5. The mutation gate. It fails if any required obligation is missing, any
# required mutation is not executed, any prohibited mutant survives, B-1 is
# below 22/22, or the catalogue and the executable set disagree. It prints the
# exact totals; "mutation tests pass" is not an output it can produce.
test-mutation:
	@build/proof/mutation-gate.sh

# Platform link/run. Each writes build/ci/evidence/<platform>.json in the
# format build/acceptance/platform-evidence.schema.json fixes, and each fails
# rather than degrading to a compile-only run.
ci-linux:
	@build/ci/ci-linux.sh

ci-windows:
	@build/ci/ci-windows.sh

ci-macos:
	@build/ci/ci-macos.sh

ci-ios:
	@build/ci/ci-ios.sh

ci-android:
	@build/ci/ci-android.sh

# ---------------------------------------------------------------------------
# The environment-attested platform criteria.
#
# These replaced four jobs that needed physical machines. Each one refuses to
# run on a host that cannot support its claim, and each writes evidence
# carrying an `environment` map that `build/acceptance/report.py` checks before
# it reads a single test result. Three of them are adjudicated by the EXTERNAL
# leak oracle (`lab/twinoracle`) rather than by the platform under test, and
# they need TWINVPN_ORACLE_URL and TWINVPN_ORACLE_TOKEN.
#
# `ci-windows-killswitch` is deliberately NOT here as a plain target: it must
# run inside a disposable guest, and a make target inviting someone to run it
# on their workstation would install persistent WFP filters on it. The
# controller is the entry point.
# ---------------------------------------------------------------------------
ci-windows-killswitch:
	@echo "==> WINDOWS-WFP-KILLSWITCH runs INSIDE a disposable nested guest."
	@echo "    It installs persistent WFP filters that survive the process by"
	@echo "    design (CB-6), so running it on this machine would cut it off the"
	@echo "    network. Drive it through the controller:"
	@echo "      pwsh scripts/twinvpn-azure-l1.ps1 -Action run ..."
	@exit 2

ci-android-16k:
	@build/ci/ci-android.sh --pagesize16k

ci-macos-sysext:
	@build/ci/ci-macos-sysext.sh

ci-macos-signature:
	@build/ci/ci-macos-signature.sh


# The gate's own gate. `report.py`'s prerequisite table is the only thing
# between the acceptance report and a green row produced on a 4 KiB emulator or
# an unprivileged Windows host, so it has a test of its own that builds
# evidence which is perfect except for one thing and asserts the row is refused.
#
# THE OTHER THREE WERE WRITTEN AND THEN NEVER RUN BY ANYTHING.
#
# `test_producer_key_coverage.py` is the file that catches a lane forgetting an
# environment key the checker demands -- the exact drift that would have failed
# every platform row on fully provisioned infrastructure -- and nothing invoked
# it: `test_report_prerequisites.py` star-imports two sibling modules and not
# this one, and no workflow named it. It passed today and nothing would have
# noticed if it stopped.
#
# The two `--self-check` entry points are the runnable halves of rules with a
# security consequence: whether a beacon target is off the device, and whether
# the lab DNS relay ever sends a datagram nobody asked for (a retry inside a
# SILENCE phase manufactures a leak and fails the row against the product).
# Neither needs an oracle, a network or a device.
test-acceptance-gate-logic:
	@build/acceptance/test_report_prerequisites.py
	@build/acceptance/test_producer_key_coverage.py
	@build/ci/leak-probe.sh --self-check
	@build/ci/dns-forward.py --self-check

# The whole gate: every host-independent blocker, executed, plus verification
# of the machine-readable platform CI evidence. Non-zero unless every required
# criterion is genuinely green -- NOT-EXECUTED counts against eligibility
# exactly as a failure does, because an absence of evidence is not evidence.
test-first-wave-gate:
	@$(MAKE) --no-print-directory test-crypto-integration
	@$(MAKE) --no-print-directory test-pairing-integration
# `-` ON test-mutation, AND ONLY ON IT.
#
# B-1 is DEFERRED past Wave 1 by the integration lead, and `report.py` already
# grades the F-5 row as deferred and excludes it from the conjunction. But
# `test-mutation` still exits non-zero -- correctly, it IS undischarged -- and
# without the `-` that status aborted the whole target before `report.py` ever
# ran. Run 33352434440 is what that costs: `android-16k` went green for the
# first time and NO acceptance report was produced to record it, while the
# upload glob shipped the stale committed report from an old dirty worktree in
# its place. A deferred row must not be able to destroy the gate's only
# machine-readable answer to "what is left".
#
# Nothing is weakened. The mutation row still runs, still prints, and still
# appears in the report with its real verdict; `report.py --run` below is what
# decides this target's exit status, and it counts NOT-EXECUTED against
# eligibility exactly as it always did.
	-@$(MAKE) --no-print-directory test-mutation
	@$(MAKE) --no-print-directory test-acceptance-gate-logic
	@build/acceptance/report.py --run

# The report without re-running the host-independent blockers: reads whatever
# evidence is on disk and prints the acceptance table. Useful locally; it is
# NOT the gate, because it proves nothing it did not find already written.
first-wave-report:
	@build/acceptance/report.py
