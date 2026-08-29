# First Implementation Wave — acceptance report

Commit `61540ec3fb1f5ff7c443a12c4895203b23d49c93` (DIRTY WORKTREE — not release evidence)
Probes executed: **True**


## F-1

| criterion | verdict | evidence |
|---|---|---|
| crypto producer wired | **FAIL** | no non-test caller for: arm_resumption |
| crypto consumer wired | **FAIL** | no non-test caller for: resume_on_wire |
| real datagram roundtrip | **FAIL** | cargo test -q -p twinvpn-core --test crypto_carriage |
| handshake secret type safety | **FAIL** | core/crates/twinvpn-core/src/resume/driver.rs still contains `handshake_secret: &[u8]` |
| local role type/state safety | **FAIL** | core/crates/twinvpn-core/src/resume/driver.rs still contains `local_role: Role` |
| replay commit-last regression | **PASS** | cargo test -p twinvpn-crypto --lib replay::tests |
| reflection rejection | **PASS** | cargo test -q -p twinvpn-core --test resume reflected |
| RS-6 regression | **PASS** | cargo test -q -p twinvpn-core --test resume_lifecycle |

## F-2

| criterion | verdict | evidence |
|---|---|---|
| production enrolment installation | **FAIL** | no non-test caller for: install_pairing_enrolment |
| pair.begin production path | **PASS** | cargo test -q -p twinvpn-core --test pairing |
| complete MI-P1 PairingOffer returned | **FAIL** | cargo test -q -p twinvpn-core --test pairing_production |
| QR/text carriage available | **PASS** | cargo test -q -p twinvpn-crypto --test pairing_offer |
| C-B integration flow | **PASS** | cargo test -q --workspace |
| missing identity reason (AUTH.IDENTITY_MISSING) | **PASS** | cargo test -q -p twinvpn-core --test pairing_refusals |

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

`7` of `23` required criteria are PASS.

**Phase 5 eligibility: FAIL**

Not eligible. The rows above that are not PASS are the reason; `NOT-EXECUTED` counts against eligibility exactly as `FAIL` does, because an absence of evidence is not evidence of absence of defects.
