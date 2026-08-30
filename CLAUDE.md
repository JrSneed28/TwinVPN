# Ruflo — Claude Code Configuration

## Rules

- Do what has been asked; nothing more, nothing less
- NEVER create files unless absolutely necessary — prefer editing existing files
- NEVER create documentation files unless explicitly requested
- NEVER save working files or tests to root — use `/src`, `/tests`, `/docs`, `/config`, `/scripts`
- ALWAYS read a file before editing it
- NEVER commit secrets, credentials, or .env files
- NEVER add a `Co-Authored-By` trailer to user commits unless this project's `.claude/settings.json` has `attribution.commit` set (#2078). The Claude Code Bash tool may suggest one in its default commit-message template — ignore it. `Co-Authored-By` is semantic authorship attribution under git/GitHub convention; the tool is the facilitator, not a co-author.
- Keep files under 500 lines
- Validate input at system boundaries

## Agent stack

Three plugins, three non-overlapping jobs. Do not blur them.

- **Ruflo** — canonical orchestration, routing, swarms, agents, learning, and
  persistent engineering memory. The only project knowledge store; the only MCP
  orchestration layer. Everything below this line is advisory, not authoritative.
- **Ponytail** (`lite` by default, `~/.config/ponytail/config.json`) —
  implementation minimalism only: reuse first, stdlib and native platform first,
  YAGNI, the minimum correct implementation. It understands the code path before
  minimizing it. It must never remove an explicit requirement, a security or
  authorization control, trust-boundary validation, required tests, or the
  observability, failure handling, and architectural contracts this project has
  already accepted.
- **Caveman** (`lite` by default, `.caveman/config.json`) — conversational
  terseness only. Project artifacts stay in normal professional prose: source
  comments, docs, ADRs, commit messages, PR and issue text, tests, logs, Ruflo
  memory entries, security findings, and user-facing copy. Caveman is not a
  memory store; Cavecrew is not the agent pipeline; the proxy stays off and
  Claude Code is never launched through `caveman claude`.

Priority when these conflict:

```text
user requirements > security/correctness/data integrity >
accepted architecture and Ruflo decisions >
Ponytail minimalism > Caveman terseness
```

Ruflo coordination records never substitute for real execution — Claude Code,
its subagents, and worktrees still do the actual work.

### Automatic activation — none of these waits to be asked

**All of them are ON in every session, by default, without the user invoking
them.** Treat "use ruflo", "be lazy", "be brief" as redundant confirmations, not
as the trigger. There is no opt-in step and no announcement: do the thing.

**`ruflo` is the CLI**, not a tool prefix. It is the npm package and the command
— `ruflo <command>` — and it has two faces, which are easy to blur
and must not be:

| Face | How it is reached | Registered as |
|---|---|---|
| **CLI** | `ruflo memory search …`, via Bash | a **global** npm install, `ruflo@3.38.20`, on `PATH`. Not npx, not a wrapper, and **not** in the project's `node_modules` |
| **MCP server** | `mcp__claude-flow__*` tools | `.mcp.json` registers it under the name **`claude-flow`**, running `npx -y ruflo@latest mcp start`. **That legacy name is the ONLY reason the tool prefix is not `ruflo`** — upstream renamed `claude-flow` to `ruflo` and the server key did not follow. |

So: the product is Ruflo, the CLI is `ruflo`, and `mcp__claude-flow__*` is Ruflo's
own MCP surface under an old registration name. `ruv-swarm` is a **separate**
package and server (`npx ruv-swarm mcp start`), not part of Ruflo.

| Layer | State | What that means in practice |
|---|---|---|
| **Ruflo, via `mcp__claude-flow__*`** | Automatic | Recall memory and route **before** non-trivial work; store what worked **after**. `guidance_brain` / `guidance_recommend` before complex Ruflo work. `aidefence_*` on untrusted input. Never wait to be told. |
| **Ruflo, via the CLI** | Automatic | The same jobs where the MCP surface has no equivalent, or where a shell one-liner is smaller — `ruflo memory search`, `hooks route`, `doctor`, `security scan`. Same coordination ledger underneath; pick whichever is fewer steps. |
| **ruv-swarm, via `mcp__ruv-swarm__*`** | Automatic | The neural/DAA and benchmarking half: `swarm_init`, `agent_spawn`, `task_orchestrate`, `daa_*`, `neural_*`, `benchmark_run`, `memory_usage`. Reach for it on the same trigger, for the capabilities Ruflo's server does not carry. |
| **Ponytail** (`lite`) | Always on | Climb the ladder on every coding task and name the lazier alternative in one line. Never announce the mode. |
| **Caveman** (`lite`) | Always on | Terse conversational prose only. Project artifacts stay normal — see the bullet above. |

**MCP tools usually arrive DEFERRED, so this rule is not self-executing.**
Deferral is the **Claude Code harness's** doing, not the servers' and not this
repo's — nothing in `.mcp.json` or `.claude/settings.json` sets it. The harness
holds back large MCP tool sets and lists their names in a `system-reminder`
without their schemas, so a deferred tool cannot be called until it is loaded and
a direct call fails with `InputValidationError`.

Do not assume either state. **Check, then act:** if the name appears in the
session's deferred list, load it first —
`ToolSearch("select:memory_search,hooks_route")` for exact names, a keyword query
to discover. If the schema is already present, just call it. That lookup is part
of "automatic", not an excuse to skip it.

Two consequences worth stating: a different MCP client may not defer at all, so
never write a rule that depends on deferral; and **the CLI face has no such step
in either case** — `ruflo …` is just Bash, which is one reason to
reach for it when a single command would do.

**Automatic ≠ unbounded.** Using the coordination tools by default does not
authorize spawning subagents, worktrees, swarms or workflows by default: those
cost real tokens and real concurrency, and §"When to Swarm" plus the session's
own agent rules still gate them. Ruflo's own priority table is unchanged — a
Ruflo recommendation loses to user requirements and to security/correctness
every time.

## Ruflo Capability Brain & Implementation Loop

Ruflo is the coordination ledger and policy decision point. Claude Code is the
executor: after a Ruflo coordination call, continue implementing the task.

When it is registered, call
`guidance_brain({ mode: "recommend", task: "..." })` before complex Ruflo
work. Use its live registry instead of guessing tool names. Treat
`registered`, `configured`, `reachable`, `healthy`, and `authorized`
as separate facts. If the brain is unavailable, continue with the compatible
`guidance_recommend` tool, CLI discovery, and repository instructions.

Follow the returned loop:

1. Recall memory and ADR constraints.
2. Inspect source, runtime, dependencies, policy, and health.
3. Route to the smallest capable topology, agents, skills, and tools.
4. Plan acceptance criteria, safety envelope, ownership, and validation.
5. Execute in isolated scopes; the coding agent performs the work.
6. Test focused, regression, and failure paths.
7. Validate types, security, policy, compatibility, and artifacts.
8. Benchmark a source-bound candidate against a source-bound baseline.
9. Optimize measured bottlenecks without weakening safety.
10. Bind claims and evidence to exact source/build receipts.
11. Reconcile concurrent handoffs and disclose limitations.
12. Publish only through a separately authorized release gate.

### Concurrency and authority

- Never allow two writers in one worktree; give each writing agent an isolated
  worktree and explicit file ownership.
- Read-only research may run concurrently and report findings to the owner.
- Only the integration owner edits shared manifests and lockfiles or reconciles
  overlapping changes.
- A child may drop capabilities but cannot add tools, network, secrets, spend,
  concurrency, namespaces, or delegation depth.
- A lease or claim coordinates ownership; it does not authorize a side effect.
- Darwin, Flywheel, MetaHarness, memory, and neural systems may propose or
  evaluate candidates but cannot self-promote or expand their SafetyEnvelope.
- Bind tests, benchmarks, policy decisions, and release evidence to an exact
  commit or immutable dirty-worktree snapshot.

## Agent Comms (SendMessage-First Coordination)

Named agents coordinate via `SendMessage`, not polling or shared state.

```
Lead (you) ←→ architect ←→ developer ←→ tester ←→ reviewer
              (named agents message each other directly)
```

### Spawning a Coordinated Team

```javascript
// ALL agents in ONE message, each knows WHO to message next
Agent({ prompt: "Research the codebase. SendMessage findings to 'architect'.",
  subagent_type: "researcher", name: "researcher", run_in_background: true })
Agent({ prompt: "Wait for 'researcher'. Design solution. SendMessage to 'coder'.",
  subagent_type: "system-architect", name: "architect", run_in_background: true })
Agent({ prompt: "Wait for 'architect'. Implement it. SendMessage to 'tester'.",
  subagent_type: "coder", name: "coder", run_in_background: true })
Agent({ prompt: "Wait for 'coder'. Write tests. SendMessage results to 'reviewer'.",
  subagent_type: "tester", name: "tester", run_in_background: true })
Agent({ prompt: "Wait for 'tester'. Review code quality and security.",
  subagent_type: "reviewer", name: "reviewer", run_in_background: true })

// Kick off the pipeline
SendMessage({ to: "researcher", summary: "Start", message: "[task context]" })
```

### Patterns

| Pattern | Flow | Use When |
|---------|------|----------|
| **Pipeline** | A → B → C → D | Sequential dependencies (feature dev) |
| **Fan-out** | Lead → A, B, C → Lead | Independent parallel work (research) |
| **Supervisor** | Lead ↔ workers | Ongoing coordination (complex refactor) |

### Rules

- ALWAYS name agents — `name: "role"` makes them addressable
- ALWAYS include comms instructions in prompts — who to message, what to send
- Spawn ALL agents in ONE message with `run_in_background: true`
- After spawning, continue independent local work; wait only when a dependency
  genuinely blocks progress
- Do not poll repeatedly — agents message back or complete automatically
- Give every writing agent an isolated worktree and a non-overlapping file scope

## Swarm & Routing

### Agent Routing

| Task | Agents | Topology |
|------|--------|----------|
| Bug Fix | researcher, coder, tester | hierarchical |
| Feature | architect, coder, tester, reviewer | hierarchical |
| Refactor | architect, coder, reviewer | hierarchical |
| Performance | perf-engineer, coder | hierarchical |
| Security | security-architect, auditor | hierarchical |

### When to Swarm
- **YES**: 3+ files, new features, cross-module refactoring, API changes, security, performance
- **NO**: single file edits, 1-2 line fixes, docs updates, config changes, questions

### 3-Tier Model Routing

| Tier | Handler | Use Cases |
|------|---------|-----------|
| 1 | Agent Booster (WASM) | Simple transforms — skip LLM, use Edit directly |
| 2 | Haiku | Simple tasks, low complexity |
| 3 | Sonnet/Opus | Architecture, security, complex reasoning |

## Memory & Learning

### Before Any Task
```bash
ruflo memory search --query "[task keywords]" --namespace patterns
ruflo hooks route --task "[task description]"
```

### After Success
```bash
ruflo memory store --namespace patterns --key "[name]" --value "[what worked]"
ruflo hooks post-task --task-id "[id]" --success true --store-results true
```

### Background Workers

| Worker | When |
|--------|------|
| `audit` | After security changes |
| `optimize` | After performance work |
| `testgaps` | After adding features |
| `map` | Every 5+ file changes |
| `document` | After API changes |

```bash
ruflo hooks worker dispatch --trigger audit
```

## Build & Test

- ALWAYS run tests after code changes
- ALWAYS verify build succeeds before committing

## Ruflo install health

The `ruflo` CLI can exit **134** on success (global `agentdb` ships a
`better-sqlite3` that aborts at teardown on Node 24) — never branch on a `ruflo`
exit code in a hook or a `set -e` script until `ruflo status >/dev/null 2>&1;
echo $?` prints 0. Setup, the CLI-vs-MCP version drift, that fix, and the two
silent MCP failures (`aidefence_*` unavailable, mock embeddings) live in the
`ruflo-install-health` skill.

> Upstream: <https://github.com/ruvnet/ruflo> (formerly `ruvnet/claude-flow`).
> `ruflo <command>` is the documented entry point on every surface —
> there is no wrapper script and no local CLI install in this repo.

**Agent tool** handles execution (agents, files, code, git). **MCP tools** handle coordination (swarm, memory, hooks). **CLI** is the same via Bash.

## Research → implementation pipeline

Two agents, defined in `.claude/agents/research/technical-researcher.md` and
`.claude/agents/implementation/research-coder.md`. This is not a second
orchestration layer — Ruflo still owns routing, memory, and coordination; these
are two ordinary Claude Code subagents that use it.

There are two ways in. The second one matters more.

**1. The user asks.** These shapes route straight into the pipeline, as does
any request needing understanding of a library, framework, API, protocol,
OS/network behaviour, dependency, configuration, migration, or an unfamiliar
TwinVPN subsystem:

```
Research and fix this bug: <problem>
Research how this works and implement it correctly: <technology/feature>
Understand this subsystem before modifying it: <subsystem>
Research the correct way to integrate: <library/API/protocol/platform>
```

**2. You notice you need it, mid-task.** The pipeline is not only a command —
it is what you reach for the moment ordinary work runs into something you do
not actually know. **Every agent and every session applies this, at all times,
without being asked**, including work that started as something else entirely.

Escalate to `technical-researcher` as soon as any of these is true:

- You are about to write code against an API, config key, protocol field, or
  CLI flag whose exact semantics you have not confirmed **in this session** —
  argument order, ownership, error contract, lifecycle, thread-safety,
  defaults, teardown.
- A fix did not work, and the second attempt would be a guess. One failed
  hypothesis is debugging; a second one without new evidence is thrashing.
- An error, panic, log line, or failure mode is one you cannot explain.
- Observed behaviour contradicts the documentation, the code comments, a test's
  premise, or your own expectation — something is wrong about the model in your
  head, and it is cheaper to find out now.
- A test fails and you do not know why, or passes and you are not sure it
  should have.
- Two sources disagree, or the code disagrees with the docs.
- An upgrade, migration, or dependency change is on the table for any reason.
- A dependency's behaviour is load-bearing for the change and unverified here.
- You are about to write "probably", "should", "I think", or "presumably"
  about something external. That phrasing **is** the trigger — do not ship the
  sentence, research the claim.
- A subagent returns low confidence, thin evidence, or a claim the tree
  contradicts.

Do not announce the decision or ask permission for read-only research — just
run it, then continue the task with the handoff in hand.

**Do not escalate** when it is already established this session; when the
change is mechanical (typo, rename, formatting, a one-line fix in code already
traced); or when one cheap, safe, non-mutating experiment answers the question
faster than research would — run the experiment.

**Budget.** One research escalation per distinct unknown. If a second pass on
the same question still comes back `low` confidence, stop and surface it to the
user with what is unresolved — do not loop, and do not implement on it anyway.

**Escalating from inside an agent.** A subagent cannot spawn the researcher.
It stops and returns a `RESEARCH REQUEST` block naming the unresolved question,
what it already checked, and what evidence would settle it. The parent session
runs `technical-researcher` on that, then resumes the agent with the handoff.

Flow:

```
question / bug / unknown system — asked, or noticed mid-task
  → local understanding (code, versions, config, docs, repro)
  → Ruflo memory
  → Context7
  → official docs / specifications
  → broad web research
  → upstream GitHub / source
  → evidence reconciliation
  → TECHNICAL HANDOFF
  → research-coder
  → tests + gates
  → validated Ruflo memory
```

Rules:

- The researcher is **read-only for production source**. It has `Bash`, so this
  is enforced by its instructions, not a sandbox — do not ask it to "just fix
  it while you're in there".
- The coder consumes a completed `TECHNICAL HANDOFF`. Never hand it raw or
  contradictory research.
- **Complex research mode** — for a hard question, launch parallel read-only
  researchers in one message: A = Context7 + official docs, B = standards/specs
  + broad web, C = upstream source/issues/PRs/commits/releases, D = TwinVPN
  local architecture/code/version/runtime. **This session reconciles them into
  one authoritative handoff** before invoking the coder. The coder must never
  be made to choose between conflicting reports.
- Skip the pipeline for anything already understood — a typo, a rename, a
  one-line fix in code already traced this session. Research is for unknowns.
- `/research <task>` is the explicit entry point (`.claude/commands/research.md`),
  with `--research-only` to stop at the handoff and `--deep` for the parallel
  A/B/C/D mode. Neither the phrasings nor the command are required — the
  mid-task escalation above is the primary path, and it fires on its own.
- **A bare `/research` is not missing an argument.** It means "research whatever
  is blocking", and you derive that from session state — the most recent
  failure, a fix or refactor that keeps breaking the same thing, an unanswered
  RESEARCH REQUEST, the in-flight task's biggest unconfirmed assumption, then
  recorded blockers. Name the derived question in one line and run it. Ask only
  when all of those are genuinely empty.
