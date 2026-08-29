---
name: claude-flow-memory
description: Interact with the Ruflo memory system
---

# 🧠 Ruflo Memory System

Persistent storage for cross-session and cross-agent collaboration, backed by
`.swarm/memory.db` with vector embeddings, pattern learning, and temporal decay.

Every command runs through `npx ruflo@latest`. Memory subcommands take flags,
not positional arguments.

## Store Information
```bash
# Store in the default namespace
npx ruflo@latest memory store -k "key" --value "value"

# Store in a specific namespace
npx ruflo@latest memory store \
  -k "architecture_decisions" \
  --value "microservices with API gateway" \
  --namespace arch

# Strict insert (fail if the key already exists; stores upsert by default)
npx ruflo@latest memory store -k "pattern" --value "new" --no-upsert

# Tag the source of the value (ADR-323)
npx ruflo@latest memory store -k "user/goal" --value "ship by Friday" --provenance user_claim
```

Writes fail while the background daemon holds the database's WAL sidecars.
Reads keep working; stop the daemon if a store has to land.

## Search Memory
```bash
# Semantic search across all namespaces
npx ruflo@latest memory search -q "authentication" --threshold 0.3 --build-hnsw

# Search with filters
npx ruflo@latest memory search -q "API design" --namespace arch --limit 10

# Keyword or hybrid instead of semantic
npx ruflo@latest memory search -q "JWT" -t keyword

# SmartRetrieval pipeline (query expansion, RRF, MMR, recency)
npx ruflo@latest memory search -q "auth patterns" --smart
```

The default `--threshold` is 0.7, which hides most genuine hits. Use
`--threshold 0.3 --build-hnsw` unless you have a reason not to.

## Retrieve by Key
```bash
npx ruflo@latest memory retrieve -k "architecture_decisions"
npx ruflo@latest memory list --namespace arch
```

## Memory Statistics
```bash
npx ruflo@latest memory stats
npx ruflo@latest memory stats --namespace project
```

## Export/Import
```bash
# Export all memory
npx ruflo@latest memory export -o full-backup.json

# Export a specific namespace
npx ruflo@latest memory export -o project-backup.json --namespace project

# Import memory
npx ruflo@latest memory import -i backup.json
```

## Cleanup Operations
```bash
# Preview first — cleanup deletes
npx ruflo@latest memory cleanup --dry-run

# Delete entries older than 30 days
npx ruflo@latest memory cleanup --older-than 30d

# Clean a single namespace
npx ruflo@latest memory cleanup --namespace temp --older-than 7d

# Expired TTL entries only
npx ruflo@latest memory cleanup --expired-only
```

`memory delete` soft-deletes with a tombstone; `memory purge` hard-deletes an
entire namespace and cannot be undone.

## 🗂️ Namespaces
- **default** — General storage
- **patterns** — Learned patterns, the namespace project workflow searches first
- **agents** — Agent-specific data and state
- **tasks** — Task information and results
- **sessions** — Session history and context
- **swarm** — Swarm coordination and objectives
- **project** — Project-specific context
- **spec** — Requirements and specifications
- **arch** — Architecture decisions
- **impl** — Implementation notes
- **test** — Test results and coverage
- **debug** — Debug logs and fixes

## 🎯 Best Practices

### Naming Conventions
- Use descriptive, searchable keys
- Include a timestamp for time-sensitive data
- Prefix with the component name for clarity

### Organization
- Use namespaces to categorize data
- Store related data together
- Keep values concise but complete

### Maintenance
- Back up regularly with export
- Clean old data periodically, always after a `--dry-run`
- Monitor storage with stats
- Compress large values with `memory compress`

## Examples

### Store project context
```bash
npx ruflo@latest memory store -k "spec_auth_requirements" --value "OAuth2 + JWT with refresh tokens" --namespace spec
npx ruflo@latest memory store -k "arch_api_design" --value "RESTful microservices with GraphQL gateway" --namespace arch
npx ruflo@latest memory store -k "test_coverage_auth" --value "95% coverage, all tests passing" --namespace test
```

### Query project decisions
```bash
npx ruflo@latest memory search -q "authentication" --namespace arch --limit 5 --threshold 0.3
npx ruflo@latest memory search -q "test results" --namespace test --threshold 0.3
```

### Back up project memory
```bash
npx ruflo@latest memory export -o project-$(date +%Y%m%d).json --namespace project
```

### Distill raw entries into patterns
```bash
npx ruflo@latest memory distill
```

Storing alone does not produce reasoning patterns — the store → distill → train
sequence has to be run for learned patterns to appear.
