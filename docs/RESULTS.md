# Recorded results

Environment: Windows, Python 3.12, Fluxnova 2.0.0, local HTTP, synthetic data. Live acceptance output was reported by the participant on 18 November 2026. The Command Center JSON is the original supplied export; the other results below summarize actual reported terminal output. They are not independently attested engine records.

| Check | Observed output |
| --- | --- |
| Targeted BPMN acceptance | `PASS_TARGETED_FLUXNOVA_DEMO` |
| Selective containment | `PASS_LIVE_SELECTIVE_CONTAINMENT`: one denial, one unaffected allow, one native review, one automated completion |
| Regression tests (final candidate) | 68 passed; one Starlette deprecation warning |
| Dependency consistency | `pip check`: no broken requirements found |
| Policy engine outage and recovery | `PASS_LIVE_POLICY_OUTAGE`: HTTP 200 / 503 / 200; four audit events |
| Recorded assurance UI | `VERIFIED_RECORDED_SCENARIOS`; all three scenario rows PASS; production BLOCKED |
| CALM strict | 0 errors, 0 warnings, exit 0 |
| Command Center with DMN | `PASS_LIVE_COMMAND_CENTER` |
| Live DMN matrix | `PASS_LIVE_DMN_MATRIX`, 16/16 |
| Cached decision counterfactual | `PASS_CACHED_BASELINE_COMPARISON`, 1 modeled unsafe allow, 0 observed gateway unsafe allows |
| Original evidence assurance | `PASS_SCOPED_DEMO_ASSURANCE` |
| Modified event | `FAIL_SCOPED_DEMO_ASSURANCE`, exit 1 |
| Production requirement | `production_readiness: BLOCKED`, exit 1 |

## Saved DMN run

- [Original JSON export](../evidence/gate5-live-dmn.json)
- [Comparison](../evidence/gate5-comparison.json)
- [Screenshot](../evidence/screenshots/gate5-live-dmn.png)
- DMN definition ID: `618d4f37-e347-11f1-9fac-76863b3dbd01` (version 3 as reported at deployment)
- Case: `KYC-LIVE-3b8df312ba`
- Process instance: `93406872-e34b-11f1-9fac-76863b3dbd01`
- Human task ID: `983b47ca-e34b-11f1-9fac-76863b3dbd01`
- Audit decisions: ALLOW then DENY; each names the same pinned DMN definition.
- Chain length: four events; tip `7c1da9456b25f6d6fead2fa0fc441eec7b030c5d05365d6a7316cec11215ea6e`.

Regression tests cover local behavior and mocked engine contracts; the live engine checks are separate. The saved evidence verifier recomputes hashes and checks correlations, not the authenticity of an unsigned export. The counterfactual is a model of cached authorization, not a measured external attack. The CCC rows are known local control gaps, not production certification.

## Selective containment run

The participant reported a successful two-provider run after the v0.2.7 regression and CALM checks.

- [Recorded selective containment export](../evidence/selective-containment.json)
- Affected instance: `1f6e92b1-e368-11f1-9fac-76863b3dbd01`
- Unaffected instance: `1f90729f-e368-11f1-9fac-76863b3dbd01`
- Pinned DMN definition: `618d4f37-e347-11f1-9fac-76863b3dbd01`
- Seven audit events; the script checks the chain and correlations before reporting success.
- The unaffected workflow reached `COMPLETED` and `end_auto` according to the script acceptance criteria.

This run exercises two synthetic providers and two cases. It is not a load test, a production availability measurement or evidence of external credential revocation. The original four-event assurance reports retain their original scope.

## Policy engine outage and recovery

- [Recorded outage export](../evidence/policy-outage.json)
- The dedicated Fluxnova container was stopped and restarted while the gateway stayed running.
- The operator reported HTTP 200 ALLOW, HTTP 503 DENY, then HTTP 200 ALLOW for the same grant, with four audit events.
- Early recovery attempts encountered transport errors while the engine was starting. The readiness loop retried until the pinned policy evaluated successfully.
- This exercise interrupts both BPMN and DMN; it does not demonstrate independent DMN failure, workflow availability during the outage, or external provider calls.

## Recorded assurance view

[Recorded assurance screenshot](../evidence/screenshots/recorded-assurance.png)

The local view reported PASS for incident response and the DMN matrix, selective containment, and policy engine outage. Production readiness remained BLOCKED. Checks are recomputed over saved records; this is not a live health check, independent attestation or official CCC conformance assessment. The original scoped assurance exports retain their original scope.
