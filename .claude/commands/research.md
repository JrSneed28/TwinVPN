---
name: research
description: Run the research → implementation pipeline on $ARGUMENTS — technical-researcher gathers evidence into one TECHNICAL HANDOFF, then research-coder implements and verifies it.
argument-hint: "[--research-only] [--deep] [question, bug, subsystem, or integration — omit to research whatever is currently blocking]"
---

# Research → implementation pipeline

Task: **$ARGUMENTS**

Run the pipeline defined in `CLAUDE.md` § "Research → implementation pipeline".
Do not re-derive it; do not build a parallel orchestration layer.

This command is the *explicit* entry point, not the only one. The pipeline also
fires on its own whenever you or a subagent hits an unknown mid-task — see the
escalation triggers in that CLAUDE.md section. If `$ARGUMENTS` is a
`RESEARCH REQUEST` block returned by a stopped agent, research its `QUESTION`,
then resume that agent with the resulting handoff.

## No task given — derive it, do not ask

`$ARGUMENTS` empty, or only flags, is **normal usage**. It means "research
whatever is currently in the way." You are expected to already know what that
is. Work down this list and take the **first** hit:

1. **The most recent failure in this session.** A failing test, gate, build,
   lint, proof, or acceptance run; a panic, stack trace, or error output. The
   question is that failure's actual mechanism — not "why did it fail" but
   "what does this component really do such that this happens".
2. **A loop.** The same file, function, or area edited two or more times
   without the failure clearing; a fix applied that did not work; the same
   error surviving a change meant to remove it; a refactor that keeps breaking
   the same contract, test, or gate. Repetition means the mental model is
   wrong — research the mechanism it keeps violating, not the next edit.
3. **An unresolved escalation.** A `RESEARCH REQUEST` returned earlier and not
   yet answered, or a handoff that came back `low` confidence.
4. **The biggest unconfirmed assumption in the in-flight task.** The API
   semantic, config key, protocol field, or dependency behaviour the current
   change depends on and that has not been verified in this session.
5. **Recorded blockers** for the current branch — Ruflo memory (`decisions`,
   `project`, `--threshold 0.3`), and recent uncommitted work or commits.

Then say the derived question in one line — `Researching: <question>` — and
run. Do not ask which one; a wrong-but-close derived question is recoverable in
a way that stalling is not. If you are torn between two candidates, take the
one blocking the current work and note the other in the handoff.

Ask **only** when all five come up genuinely empty: nothing failing, nothing
in flight, no history to read. That is a fresh session with a clean tree, and
then one short question is right.

`--deep` with no task derives the same way first, then fans out on the derived
question. It is never a reason to stop and ask.

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
/research                          # whatever is currently blocking — derive it
/research --deep                   # same, then fan out four researchers
/research how does the pairing handshake derive its transport keys
/research --research-only correct way to integrate a QUIC datagram path
/research --deep why does the Android device-farm stub flake under load
```
