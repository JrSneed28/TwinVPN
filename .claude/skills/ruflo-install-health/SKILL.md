---
name: ruflo-install-health
description: Set up, repair, or diagnose the Ruflo installation and its two surfaces (the global `ruflo` CLI and the npx-launched MCP servers). Use when installing Ruflo in a fresh clone, after any `npm i -g ruflo@...` version bump, when `ruflo <command>` exits 134 on success, when `aidefence_*` tools return "AIDefence package not available", when `memory_bridge_status` reports a mock or hash-fallback embedding backend, when semantic memory search returns meaningless results, or when a `ruflo` CLI command and its `mcp__claude-flow__*` equivalent behave differently.
---

# Ruflo install health

Setup, the two independently-pinned surfaces, and the two silent failure modes
`ruflo doctor` cannot detect.

## Setup

`.mcp.json` is checked in, so a fresh clone only needs:

```bash
npm install                # project deps: aidefence, agentic-flow, ruv-swarm
./scripts/npx-mcp-deps     # let the npx MCP tree resolve ruflo's extra packages
ruflo doctor    # verify; --fix prints suggestions, applies nothing
```

To re-scaffold `.claude/`, `.claude-flow/`, `CLAUDE.md`, the helpers, and the
hooks from scratch, the documented flow is `ruflo init --wizard`
(`init --yes` for the non-interactive form). It overwrites the checked-in
scaffold, so commit before running it.

MCP registration follows the documented recipe:

```bash
claude mcp add claude-flow -- npx -y ruflo@latest mcp start
```

`.mcp.json` already carries that command plus this project's env, so a fresh
clone needs no `claude mcp add`.

### The two faces are pinned differently, and can drift apart

**They are not the same install and not necessarily the same version.**

- **CLI** — a **global** npm install, currently `ruflo@3.38.20`, resolved from
  `PATH`. Pinned in the sense that it moves only when someone runs
  `npm i -g ruflo@…`. The user installed it globally on purpose; there is no
  local install and no wrapper script, and neither should be reintroduced.
- **MCP servers** — `npx -y ruflo@latest mcp start` and `npx ruv-swarm`, which
  **float**: a new upstream release is picked up on the next launch.

So the CLI can sit on an older release than the MCP surface indefinitely, and
nothing warns. If a behaviour differs between a `ruflo …` command and the
equivalent `mcp__claude-flow__*` tool, **check the versions before debugging the
behaviour**. To pin both, pin `.mcp.json` and re-run the global install together.

### The global CLI's `better-sqlite3` — fixed, and it comes back on reinstall

**Symptom, if it returns.** `ruflo <anything>` prints correct output and then dies
with SIGABRT, so every invocation exits **134** even on success:

```
node[…]: void node::RemoveEnvironmentCleanupHook(…) at ../src/api/hooks.cc:142
Assertion failed: (env) != nullptr
… Statement::~Statement() [.../ruflo/node_modules/agentdb/node_modules/better-sqlite3/…]
```

**Cause.** The global install ships `agentdb` → `better-sqlite3@11.10.0`, which
aborts at teardown on Node 24 (ABI 137). This project already fixes exactly that
defect with `"overrides": {"better-sqlite3": "12.11.1"}` in `package.json` — but
an override applies to the **project** tree only and cannot reach a global
install. Same defect, second location, and the existing pin is powerless there.

**Fix, applied 2026-08-29:**

```bash
cd "$(dirname "$(readlink -f "$(command -v ruflo)")")/../node_modules/agentdb"
npm install better-sqlite3@12.11.1 --no-save --no-audit --no-fund
```

After it, `ruflo memory stats` and `ruflo status` exit **0**, and embeddings stay
real (`Xenova/all-MiniLM-L6-v2`, 384 dims). Note the command pulls agentdb's full
dependency tree (~438 packages) into the global install, and npm blocks two
`esbuild` postinstalls — neither affects ruflo.

**It is not durable.** Any `npm i -g ruflo@…` reinstalls 11.10.0 and the abort
returns. Re-run the fix after every global version bump, and check with
`ruflo status >/dev/null 2>&1; echo $?` — **0** is healthy, **134** means redo it.
Until then, do not branch on a `ruflo` CLI exit code in a hook or `set -e`
script. The MCP surface was never affected: the npx tree resolves the project's
pinned copy.

### Optional packages, per surface — `npx-mcp-deps` serves the MCP tree only

**This section is about the MCP surface. The global CLI resolves differently and
`npx-mcp-deps` does nothing for it** — the script links into
`~/.npm/_npx/node_modules`, which is not on the global install's resolution path.
Measured on the global `ruflo@3.38.20`:

| Package | Global CLI | Effect |
|---------|-----------|--------|
| `@huggingface/transformers` | **resolves** — bundled at `…/ruflo/node_modules/@huggingface/transformers` | embeddings are real: `ruflo memory stats` reports `Xenova/all-MiniLM-L6-v2`, 384 dims, semantic search yes |
| `@claude-flow/aidefence` | **`MODULE_NOT_FOUND`** | `aidefence` CLI paths degrade; the MCP surface is unaffected because it is linked there |

So a CLI `memory search` gives real semantic recall, and `aidefence` does not.
Do not "fix" the CLI by linking into the global tree without asking — the global
install is the user's deliberate choice.

The rest of this section is the **npx/MCP** tree. npx runs ruflo out of
`~/.npm/_npx/<hash>/`. Three packages ruflo imports by bare specifier do not work
from there, and every failure is **silent**:

| Package | Why it fails | Symptom |
|---------|--------------|---------|
| `@claude-flow/aidefence` | optional, declared nowhere in ruflo's dependency graph, so npx never installs it | every `aidefence_*` tool returns `AIDefence package not available` |
| `@huggingface/transformers` | same | `generateEmbedding()` falls back to a hash stub; `memory_bridge_status` reports `sql.js + MOCK (hash fallback)` and semantic recall is meaningless |
| `@xenova/transformers` | npx *does* install it, but with install scripts skipped, so its nested `sharp` has no native binary | importing it throws `Cannot find module '../build/Release/sharp-linux-x64.node'`; ruflo's BGE embedder and cross-encoder rerank degrade (they catch it) |

`ruflo doctor` cannot detect any of them — it reports them healthy while the MCP
surface is broken.

**`./scripts/npx-mcp-deps` fixes the first two**, and is idempotent. The project
declares all three in `package.json` (`@huggingface/transformers` arrives via
`agentic-flow`) and builds their native bindings; the script links those copies
into `~/.npm/_npx/node_modules`, the parent of every hashed npx tree. Node's
bare-specifier resolution walks up from the importing module, so every tree
picks them up, and npx never manages that directory. The script also clears
partial installs: a `@huggingface/transformers` with `src/` and `dist/` but no
`package.json` will shadow the link and make resolution fail outright.

`@xenova/transformers` stays broken on the MCP surface: npx's own per-tree copy
sits nearer than the link and shadows it. The link is kept for any tree that
lacks its own copy, and the script's resolution check deliberately skips it.

Re-run the script after `npm install`, after any ruflo version bump, and any
time `aidefence_*` starts erroring or `memory_bridge_status` reports a `mock`
backend.

Verify the MCP side with a direct JSON-RPC `tools/call` against the entry point,
never with `doctor`:

```bash
{ echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"a","version":"1"}}}'
  sleep 4
  echo '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"memory_bridge_status","arguments":{}}}'
  sleep 80
} | npx -y ruflo@latest mcp start 2>/dev/null | grep -o '"embeddingBackend[^,]*'
# want: onnx   —   mock means npx-mcp-deps needs re-running
```

> The background `daemon` is ON for sessions: `RUFLO_DAEMON_AUTOSTART=1` is set
> in both `.mcp.json` and `.claude/settings.json`. It runs interval workers that
> each spawn a headless `claude` session, so it bills tokens continuously — this
> is intended, do not "fix" it. Ruflo also auto-starts it on every CLI command
> except `daemon` itself, so a read-only `ruflo status` leaves workers
> running too; prefix `RUFLO_DAEMON_AUTOSTART=0` to opt out of a single call.
> Daemons self-stop after 12h (`--ttl 0` to disable). Audit with `ps`, not
> `daemon status --all`, which reports false negatives.
