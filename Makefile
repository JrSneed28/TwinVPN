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
        test-rust fmt arch-lint doc-check cross-check infra-bootstrap infra-check infra-up \
        infra-up-v6 infra-down budgets budgets-images redaction-check

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
	@echo ""
	@echo "  make infra-check      compose topology + collector redaction invariants (no Docker needed)"
	@echo "  make infra-up         bring the local plane up (dual stack); infra-up-v6 for IPv6-only"
	@echo "  make infra-down       tear it down"
	@echo "  make budgets          the ADR-0018 §11.9 artifact budgets"
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
lint: contracts-lint lint-rust redaction-check
	@echo "==> linting python"
	@python3 -m compileall -q $(CONTRACTS)/tests >/dev/null
	@echo "==> linting javascript"
	@node --check $(CONTRACTS)/tests/pbjs_helper.js
	@echo "==> linting documentation links"
	@python3 scripts/check_doc_links.py
	@echo "==> lint OK"

# rustfmt --check and clippy -D warnings across every workspace, then the
# ADR-0018 T1 architectural lints. The architectural lints are NOT optional
# extras: CD-3 says the deny-list "is the actual mechanism", and CD-I5 is the
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
DOCFLAGS := -D warnings -A rustdoc::invalid_html_tags

# NOT yet a prerequisite of `lint`. On first run this target found 14 broken
# intra-doc links across six crates owned by three domains -- precisely the drift
# it exists to catch. It is a NAMED target rather than a silent skip, on the same
# principle infrastructure applied to the arch-lint CI job while it was red: a
# gate you intend to enforce should be visible and failing, not absent.
# Wire it into `lint` once the six crates are clean.
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
# `-D warnings`. NOTHING Swift and NOTHING Kotlin is reached: there is no Xcode,
# no Darwin SDK, no JDK, no Android SDK and no NDK on this host, so
# `shells/ios` and `shells/android` are WRITTEN, NOT COMPILED in ownership.md
# 9.2's sense, and no `make` target may claim otherwise.
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
# The shells/windows arm is NARROWED, and the narrowing is the honest part.
#
# `twinvpnsvc`'s default features pull `twinvpn-core` -> `snow` -> `ring`, whose
# build script refuses a GNU compiler for an MSVC target and needs `lib.exe`.
# This host has no clang-cl and no llvm-lib, so `cargo-xwin` is not an option
# either: nothing here can drive that build script, and it fails before reaching
# a single line of our code.
#
# So this arm checks what it can actually check -- and that is nearly all of it:
# `twinvpnctl` whole, and `twinvpnsvc`'s ENTIRE Win32 surface (`scm`, `power`,
# `privilege`, `peer`, `start`, `mi`, `win32`) through the `service` feature that
# `desktop-windows` split from `core-host` for exactly this reason. That split
# paid for itself on its first run, finding two type errors and eight lints in
# code nothing had ever compiled.
#
# NOT covered, and it must not be reported as covered: `twinvpnsvc`'s
# `runtime`, `server` and `main`, which are the three files that name the core.
# They are compiled the day this repository has a Windows builder or an
# MSVC-targeting C toolchain. `shells/windows/README.md` §7.19 carries the
# detail and the two ways out.
	@if [ -f shells/windows/Cargo.toml ]; then \
	  echo "==> cross-check shells/windows ($(WIN_TARGET))"; \
	  ( cd shells/windows && \
	    $(CARGO) clippy -p twinvpnctl --all-targets \
	        --target $(WIN_TARGET) -- -D warnings && \
	    $(CARGO) clippy -p twinvpnsvc --no-default-features --features service \
	        --all-targets --target $(WIN_TARGET) -- -D warnings ) || exit 1; \
	  echo "    NOT covered: twinvpnsvc's runtime/server/main -- ring's build"; \
	  echo "    script needs an MSVC-targeting C compiler. README 7.19."; \
	fi
	@if [ -f shells/macos/Cargo.toml ]; then \
	  echo "==> cross-check shells/macos ($(MAC_TARGET))"; \
	  ( cd shells/macos && $(CARGO) clippy --workspace --all-targets \
	      --target $(MAC_TARGET) -- -D warnings ) || exit 1; \
	fi
	@echo "==> cross-check twinvpn-platform-ios ($(IOS_TARGET))"
	@cd core && $(CARGO) clippy -p twinvpn-platform-ios --all-targets \
	    --target $(IOS_TARGET) -- -D warnings
	@echo "==> cross-check twinvpn-platform-android ($(AND_TARGET))"
	@cd core && $(CARGO) clippy -p twinvpn-platform-android --all-targets \
	    --target $(AND_TARGET) -- -D warnings
	@echo "==> cross-check OK (compile only -- nothing was linked or run)"
	@echo "    NOT covered: Swift (shells/ios), Kotlin (shells/android) -- no"
	@echo "    Darwin SDK, no JDK/Android SDK/NDK on this host. ownership.md 9.2."

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
