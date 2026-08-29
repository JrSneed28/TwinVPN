# First Implementation Wave — acceptance report

Commit `6f1eb01bf68e2b04b46f1bb0a148428dcbd3a312` (DIRTY WORKTREE — not release evidence)
Probes executed: **True**


## F-1

| criterion | verdict | evidence |
|---|---|---|
| crypto producer wired | **PASS** | every entry point has a non-test caller: arm_resumption |
| crypto consumer wired | **FAIL** | no non-test caller for: resume_on_wire |
| real datagram roundtrip | **PASS** | cargo test -q -p twinvpn-core --test crypto_carriage |
| handshake secret type safety | **PASS** | core/crates/twinvpn-core/src/resume/driver.rs no longer contains `handshake_secret: &[u8]` |
| local role type/state safety | **PASS** | core/crates/twinvpn-core/src/resume/driver.rs no longer contains `local_role: Role` |
| replay commit-last regression | **PASS** | cargo test -p twinvpn-crypto --lib replay::tests |
| reflection rejection | **PASS** | cargo test -q -p twinvpn-core --test resume reflected |
| handshake/role API shape asserted | **PASS** | cargo test -q -p twinvpn-core --test resume_api_shape |
| RS-6 regression | **PASS** | cargo test -q -p twinvpn-core --test resume_lifecycle |

## F-2

| criterion | verdict | evidence |
|---|---|---|
| production enrolment installation | **PASS** | every entry point has a non-test caller: install_pairing_enrolment |
| pair.begin production path | **PASS** | cargo test -q -p twinvpn-core --test pairing |
| complete MI-P1 PairingOffer returned | **PASS** | cargo test -q -p twinvpnd --test pairing a_provisioned_host_begins_a_ceremony_and_answers_with_the_offer |
| QR/text carriage available | **PASS** | cargo test -q -p twinvpnd --test pairing a_shell_renders_the_qr_payload_and_the_e2_text_from_the_response |
| C-B integration flow | **PASS** | cargo test -q -p twinvpnd --test pairing |
| MI-P1 rule 1: offer never on the event stream | **PASS** | cargo test -q -p twinvpnd --test pairing the_offer_reaches_the_caller_and_never_the_event_stream |
| missing identity reason (AUTH.IDENTITY_MISSING) | **PASS** | cargo test -q -p twinvpnd --test pairing a_host_with_no_element_refuses_to_begin_a_pairing |

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

`15` of `26` required criteria are PASS.

**Phase 5 eligibility: FAIL**

Not eligible. The rows above that are not PASS are the reason; `NOT-EXECUTED` counts against eligibility exactly as `FAIL` does, because an absence of evidence is not evidence of absence of defects.
