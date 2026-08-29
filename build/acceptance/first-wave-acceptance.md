# First Implementation Wave — acceptance report

Commit `aaabcce82b985cd05d2f37ebc26954988212ccad` (DIRTY WORKTREE — not release evidence)
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
| handshake/role API shape asserted | **NOT-EXECUTED** | not run (pass --run) |
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
| mutation obligations discharged | **FAIL** | specified=144 executable=17 executed=17 discharged/killed=17 survived=0 missing=127 B-1 0/22 |

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
| Android physical-device lifecycle | **NOT-EXECUTED** | no evidence at build/ci/evidence/android-device.json |

## Phase 5 eligibility

`0` of `25` required criteria are PASS.

**Phase 5 eligibility: FAIL**

Not eligible. The rows above that are not PASS are the reason; `NOT-EXECUTED` counts against eligibility exactly as `FAIL` does, because an absence of evidence is not evidence of absence of defects.
