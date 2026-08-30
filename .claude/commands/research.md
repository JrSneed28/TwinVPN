---
name: research
description: Run the research → implementation pipeline on $ARGUMENTS — technical-researcher gathers evidence into one TECHNICAL HANDOFF, then research-coder implements and verifies it.
argument-hint: "[--research-only] [--deep] <question, bug, subsystem, or integration>"
---

# Research → implementation pipeline

Task: **$ARGUMENTS**

Run the pipeline defined in `CLAUDE.md` § "Research → implementation pipeline".
Do not re-derive it; do not build a parallel orchestration layer.

## Flags

Strip these from the task text before using it.

- `--research-only` — stop after the handoff. Present it and wait; do not
  invoke `research-coder`.
- `--deep` — complex research mode. Launch four read-only `technical-researcher`
  agents **in one message**, then reconcile:
  - **A** — Context7 and official documentation
  - **B** — standards, specifications, RFCs, broad web research
  - **C** — upstream source, issues, PRs, commits, releases
  - **D** — TwinVPN local architecture, code, versions, runtime

  You reconcile their reports into **one** authoritative TECHNICAL HANDOFF,
  naming any conflict and which source won. Never hand the coder contradictory
  reports.

Without `--deep`, a single `technical-researcher` covers all five research
steps itself.

## Steps

1. **Research.** Invoke `technical-researcher` (or the four above under
   `--deep`) with the task text. It is read-only for production source — it
   must not edit the tree, and neither should you while it runs.
2. **Reconcile.** Confirm you hold one coherent TECHNICAL HANDOFF. If its
   confidence is `low`, or its evidence is thin or self-contradictory, say so
   and ask before spending an implementation on it.
3. **Implement.** Pass the full handoff to `research-coder`. It re-verifies
   against the live tree, implements the minimum correct change, adds
   regression tests, and runs the gates that the change actually touches.
4. **Report.** Surface the coder's `RESEARCH VERIFIED / IMPLEMENTATION / FILES
   CHANGED / TESTS ADDED / COMMANDS RUN / RESULTS / REMAINING RISKS` block.
   Report failures as failures, with their output.

Do not commit unless asked.

## Examples

```
/research how does the pairing handshake derive its transport keys
/research --research-only correct way to integrate a QUIC datagram path
/research --deep why does the Android device-farm stub flake under load
```
