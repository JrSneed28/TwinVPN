---
name: claude-flow-swarm
description: Coordinate multi-agent swarms for complex tasks
---

# 🐝 Ruflo Swarm Coordination

Multi-agent coordination with distributed memory sharing and adaptive
scheduling. Every command runs through `npx ruflo@latest`.

Swarm coordination is a ledger and policy layer: it routes and records. Claude
Code and its subagents still perform the actual work.

## Basic Usage
```bash
# Initialize the swarm, then start it against an objective
npx ruflo@latest swarm init --topology hierarchical-mesh --max-agents 15 --strategy specialized
npx ruflo@latest swarm start -o "your complex task" -s development
```

`swarm start` takes the objective as `-o`, not as a positional argument.

## Subcommands
| Subcommand | Purpose |
|------------|---------|
| `init` | Initialize a new swarm |
| `start` | Start swarm execution |
| `status` | Show swarm status |
| `stop` | Stop swarm execution |
| `scale` | Scale agent count |
| `coordinate` | Run V3 15-agent hierarchical mesh coordination |
| `pheromone` | Inspect or update pheromone-adaptive scheduling state (ADR-330) |

## ⚙️ Options

### `swarm init`
- `-t, --topology <type>` — topology (default `hierarchical`)
- `-m, --max-agents <n>` — maximum agents (default 15)
- `-s, --strategy <type>` — coordination strategy
- `--auto-scale` — automatic scaling (default on)
- `--v3-mode` — V3 15-agent hierarchical mesh mode
- `--with-permissions <preset>` — workspace-scoped permission manifest
  (`strict`, `standard`, `permissive`)
- `--apsc-*` — adaptive agent suspension tuning; calibration-only dry run
  unless `--apsc-live` is passed

### `swarm start`
- `-o, --objective <text>` — objective (required)
- `-s, --strategy <type>` — execution strategy
- `-p, --parallel` — parallel execution (default on)
- `--monitor` — real-time monitoring (default on)

### `swarm scale`
- `-a, --agents <n>` — target agent count (required)
- `-t, --type <type>` — agent type to scale

## 🎯 Strategies
- **auto** — automatic selection based on task analysis
- **development** — implementation with review and testing
- **research** — information gathering and synthesis
- **analysis** — data processing and pattern identification
- **testing** — quality assurance
- **optimization** — performance tuning and refactoring
- **maintenance** — updates and bug fixes
- **specialized** — the strategy this project's config uses

## 🤖 Agent Types
- **coordinator** — plans and delegates to other agents
- **developer** / **coder** — writes code
- **researcher** — gathers and analyzes information
- **analyzer** — identifies patterns and generates insights
- **tester** — creates and runs tests
- **reviewer** — code and design review
- **documenter** — documentation and guides
- **specialist** — domain-specific expert agents

## 🔄 Topologies
- **hierarchical** — tree structure with nested coordination (default)
- **hierarchical-mesh** — this project's configured anti-drift topology
- **mesh** — peer-to-peer agent collaboration
- **centralized** — one coordinator manages all agents
- **distributed** — multiple coordinators share management

## 🌟 Examples

### Development swarm
```bash
npx ruflo@latest swarm init --topology hierarchical-mesh --max-agents 8 --strategy specialized
npx ruflo@latest swarm start -o "Build e-commerce REST API" -s development
```

### Research swarm
```bash
npx ruflo@latest swarm init --max-agents 8
npx ruflo@latest swarm start -o "Analyze AI market trends" -s research --parallel
```

### V3 hierarchical mesh coordination
```bash
npx ruflo@latest swarm coordinate --agents 15
npx ruflo@latest swarm coordinate --agents 15 --domains security,core,integration
```

### Optimization swarm
```bash
npx ruflo@latest swarm start -o "Optimize database queries and API performance" -s optimization
```

## 📊 Monitoring and Control

```bash
# Swarm status
npx ruflo@latest swarm status

# Overall system status
npx ruflo@latest status

# Agents
npx ruflo@latest agent list
npx ruflo@latest agent status <agent-id>
npx ruflo@latest agent health
npx ruflo@latest agent logs <agent-id>

# Scheduling state
npx ruflo@latest swarm pheromone
```

There is no top-level `monitor` command in v3 — use `swarm status`, `status`,
and `agent health`.

## 💾 Memory Integration

Swarms share state through the memory system:

```bash
npx ruflo@latest memory store -k "swarm_objective" --value "Build scalable API" --namespace swarm
npx ruflo@latest memory search -q "swarm progress" --namespace swarm --threshold 0.3
npx ruflo@latest memory export -o swarm-results.json --namespace swarm
```

## 🔧 Concurrency Rules

- Never put two writing agents in one worktree. Each writing agent gets an
  isolated worktree and explicit file ownership.
- Read-only research agents may run concurrently and report to the owner.
- Only the integration owner edits shared manifests and lockfiles.
- A child agent may drop capabilities but cannot add tools, network, secrets,
  spend, concurrency, namespaces, or delegation depth.
- A lease or claim coordinates ownership; it does not authorize a side effect.

## When to Swarm
- **Yes** — 3+ files, new features, cross-module refactoring, API changes,
  security work, performance work
- **No** — single-file edits, one- or two-line fixes, docs, config, questions

For the full command surface, run `npx ruflo@latest swarm --help`.
