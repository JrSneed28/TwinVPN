# TwinVPN repository entry points.
#
# Phase 2 status: only the shared contract package exists. Targets that will
# later cover production components are present and correct for what exists
# today, and say plainly what they do not yet cover, rather than pretending.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

BUF        := ./node_modules/.bin/buf
BUF_VERSION := 1.72.0
CONTRACTS  := contracts
PROTO_DIR  := $(CONTRACTS)/proto
GEN_DIR    := $(CONTRACTS)/gen
BASELINE   := $(CONTRACTS)/.baseline.binpb

.PHONY: help bootstrap toolchains contracts contracts-lint contracts-gen \
        contracts-breaking contracts-freshness verify-bindings test-contracts \
        build lint test clean gate freeze

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
	@echo "  make gate             the Phase 2 contract freeze gate (all of the above)"

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
# Builds everything currently buildable. In Phase 2 that is the contract
# package and nothing else: no production service, engine, daemon, relay,
# application or UI exists yet, and the freeze gate exists precisely to keep it
# that way until the contracts are frozen.
build: contracts verify-bindings
	@echo "==> build complete (contracts only; no production component exists yet)"

# ---------------------------------------------------------------------------
# lint
# ---------------------------------------------------------------------------
lint: contracts-lint
	@echo "==> linting python"
	@python3 -m compileall -q $(CONTRACTS)/tests >/dev/null
	@echo "==> linting javascript"
	@node --check $(CONTRACTS)/tests/pbjs_helper.js
	@echo "==> linting documentation links"
	@python3 scripts/check_doc_links.py
	@echo "==> lint OK"

# ---------------------------------------------------------------------------
# test
# ---------------------------------------------------------------------------
test: test-contracts
	@echo "==> all available tests passed"

# ---------------------------------------------------------------------------
# gate: the Phase 2 contract freeze gate
# ---------------------------------------------------------------------------
gate: bootstrap lint contracts verify-bindings test-contracts
	@python3 scripts/freeze_gate.py

clean:
	@rm -rf $(GEN_DIR)
