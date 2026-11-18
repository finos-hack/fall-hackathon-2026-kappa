# Recorded results

Environment: Windows, Python 3.12, Fluxnova 2.0.0, local HTTP, synthetic data. Live acceptance output was reported by the participant on 18 November 2026. The Command Center JSON is the original supplied export; the other results below summarize actual reported terminal output. They are not independently attested engine records.

| Check | Observed output |
| --- | --- |
| Targeted BPMN acceptance | `PASS_TARGETED_FLUXNOVA_DEMO` |
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
