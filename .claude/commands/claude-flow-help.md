---
name: claude-flow-help
description: Show Ruflo commands and usage
---

# Ruflo Commands

Ruflo (the `ruflo` CLI, formerly claude-flow) is the agent orchestration
platform this project coordinates through.

## Entry point

Always `npx ruflo@latest`, the entry point the upstream docs use
(<https://github.com/ruvnet/ruflo>). Ruflo is not installed into this project
and there is no `./claude-flow` binary or wrapper script here.

Under npx the CLI runs out of `~/.npm/_npx/<hash>/`, whose tree lacks two
packages ruflo imports by bare specifier — `./scripts/npx-mcp-deps` links them
in, and must be re-run after `npm install` or a version bump.

```bash
npx ruflo@latest --help              # top-level commands
npx ruflo@latest <command> --help    # subcommands and flags
```

## Primary commands

| Command | Purpose |
|---------|---------|
| `init` | Initialize Ruflo in the current directory |
| `start` | Start the orchestration system |
| `status` | Show system status |
| `agent` | Agent management |
| `swarm` | Swarm coordination |
| `memory` | Memory management |
| `task` | Task management |
| `session` | Session management |
| `mcp` | MCP server management |
| `hooks` | Self-learning hooks and workflow automation |

## Agent management

```bash
npx ruflo@latest agent spawn -t coder     # spawn an agent by type
npx ruflo@latest agent list               # list active agents
npx ruflo@latest agent status <id>        # agent details
npx ruflo@latest agent stop <id>          # terminate an agent
npx ruflo@latest agent health             # health and metrics
npx ruflo@latest agent logs <id>          # activity logs
```

## Task management

```bash
npx ruflo@latest task create -t implementation -d "Add user auth"
npx ruflo@latest task list                # pending/running; --all for every task
npx ruflo@latest task status <id>
npx ruflo@latest task assign <id> --agent coder-1
npx ruflo@latest task retry <id>
npx ruflo@latest task cancel <id>
```

## Memory operations

Memory takes flags, not positional arguments.

```bash
npx ruflo@latest memory store -k "key" --value "value" --namespace patterns
npx ruflo@latest memory search -q "auth patterns" --threshold 0.3 --build-hnsw
npx ruflo@latest memory retrieve -k "key"
npx ruflo@latest memory stats
npx ruflo@latest memory export -o <file>
npx ruflo@latest memory import -i <file>
```

`memory search` defaults to a 0.7 similarity threshold, which hides most real
hits — pass `--threshold 0.3 --build-hnsw`. Writes fail while the background
daemon holds the WAL sidecars; reads still work.

## Swarm coordination

```bash
npx ruflo@latest swarm init --topology hierarchical-mesh --max-agents 15 --strategy specialized
npx ruflo@latest swarm start -o "Build REST API" -s development
npx ruflo@latest swarm coordinate --agents 15   # V3 hierarchical mesh
npx ruflo@latest swarm status
npx ruflo@latest swarm scale --agents <n>
npx ruflo@latest swarm stop
```

## MCP integration

```bash
npx ruflo@latest mcp status
npx ruflo@latest mcp tools
npx ruflo@latest mcp health
npx ruflo@latest mcp logs
```

The MCP servers are launched by `.mcp.json` with the same
`npx -y ruflo@latest mcp start` the docs prescribe. Run `./scripts/npx-mcp-deps`
after any install or version bump — see `CLAUDE.md` for why.

## Advanced and utility commands

`neural`, `security`, `policy`, `performance`, `embeddings`, `hive-mind`,
`guidance`, `autopilot`, `workflow`, `analyze`, `route`, `progress`, `claims`,
`config`, `doctor`, `daemon`, `cleanup`.

```bash
npx ruflo@latest doctor              # diagnostics; --fix only prints suggestions
npx ruflo@latest security scan
npx ruflo@latest performance benchmark
npx ruflo@latest hooks route --task "describe the task"
```

`doctor` reports the MCP-side dependency gaps as healthy even when they are
broken. Verify the MCP surface with a direct JSON-RPC `tools/call`, not with
`doctor`.

## Not available in v3

`sparc`, `monitor`, a top-level `stop`, and `claude spawn`/`claude batch` were
v2 commands and no longer exist. Use `swarm`/`agent` for orchestration,
`process` or `daemon` for lifecycle, and the Claude Code Agent tool for
spawning agents.

## Best practices

- Store durable context in memory so it survives across sessions.
- Use swarm mode for work spanning 3+ files; skip it for single-file edits.
- The Agent tool executes (files, code, git); MCP tools coordinate (swarm,
  memory, hooks); the CLI is the same surface via Bash.

## Resources

- Documentation: https://github.com/ruvnet/ruflo#readme
- Issues: https://github.com/ruvnet/ruflo/issues
