# First Implementation Wave — acceptance report

Commit `0a908c4595e7ed304d1e68a21422d24ea8a2bf18` (DIRTY WORKTREE — not release evidence)
Probes executed: **False**


## F-1

| criterion | verdict | evidence |
|---|---|---|
| crypto producer wired | **NOT-EXECUTED** | not run (pass --run) |
| crypto consumer wired | **NOT-EXECUTED** | not run (pass --run) |
| real datagram roundtrip | **NOT-EXECUTED** | not run (pass --run) |
| handshake secret type safety | **NOT-EXECUTED** | not run (pass --run) |
| local role type/state safety | **NOT-EXECUTED** | not run (pass --run) |
| replay commit-last regression | **NOT-EXECUTED** | not run (pass --run) |
| reflection rejection | **NOT-EXECUTED** | not run (pass --run) |
| RS-6 regression | **NOT-EXECUTED** | not run (pass --run) |

## F-2

| criterion | verdict | evidence |
|---|---|---|
| production enrolment installation | **NOT-EXECUTED** | not run (pass --run) |
| pair.begin production path | **NOT-EXECUTED** | not run (pass --run) |
| complete MI-P1 PairingOffer returned | **NOT-EXECUTED** | not run (pass --run) |
| QR/text carriage available | **NOT-EXECUTED** | not run (pass --run) |
| C-B integration flow | **NOT-EXECUTED** | not run (pass --run) |
| missing identity reason (AUTH.IDENTITY_MISSING) | **NOT-EXECUTED** | not run (pass --run) |

## F-5

| criterion | verdict | evidence |
|---|---|---|
| mutation obligations discharged | **NOT-EXECUTED** | no machine-readable mutation report |

## Platforms

| criterion | verdict | evidence |
|---|---|---|
| Linux | **NOT-EXECUTED** | no evidence at build/ci/evidence/linux.json |
| Windows link/run | **NOT-EXECUTED** | no evidence at build/ci/evidence/windows.json |
| macOS link/run | **NOT-EXECUTED** | no evidence at build/ci/evidence/macos.json |
| iOS link/run | **NOT-EXECUTED** | no evidence at build/ci/evidence/ios.json |
| Android link/run | **NOT-EXECUTED** | no evidence at build/ci/evidence/android.json |

## Privileged / physical

| criterion | verdict | evidence |
|---|---|---|
| Windows privileged lifecycle | **NOT-EXECUTED** | no evidence at build/ci/evidence/windows-privileged.json |
| macOS NetworkExtension lifecycle | **NOT-EXECUTED** | no evidence at build/ci/evidence/macos-privileged.json |
| iOS physical-device lifecycle | **NOT-EXECUTED** | no evidence at build/ci/evidence/ios-device.json |

## Phase 5 eligibility

`0` of `23` required criteria are PASS.

**Phase 5 eligibility: FAIL**

Not eligible. The rows above that are not PASS are the reason; `NOT-EXECUTED` counts against eligibility exactly as `FAIL` does, because an absence of evidence is not evidence of absence of defects.
