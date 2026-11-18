# Selective containment

The original demonstration uses one synthetic KYC provider. This extension adds a second provider to the gateway registry and CALM topology. Both cases use the same executable BPMN and pinned DMN definition. No external provider or credential system is involved.

## Run locally

Use a dedicated gateway instance. Save existing evidence first: the script resets the in-memory gateway, but does not delete previous Fluxnova instances. Do not run another demonstration or polling worker concurrently.

With the BPMN and DMN already deployed, start the gateway with `REVOKELINE_POLICY_MODE=DMN`, `FLUXNOVA_DECISION_ID` set to the deployed decision ID, and the appropriate local Fluxnova credentials. The script uses the same `FLUXNOVA_URL` and `REVOKELINE_URL` configuration as the existing adapter. Fluxnova must record process and activity history.

```sh
python -m pytest tests -q
calm validate -a architectures/revokeline.calm.json --strict
python -m scripts.selective_containment --output evidence/selective-containment.json
```

The script starts two distinct BPMN instances, verifies both grants, revokes only the first provider, then completes each instance's targeted external task. It checks the affected case has a native `human_review` task and the unaffected case has reached `end_auto` in process history with state `COMPLETED`. It also verifies the pinned DMN decisions and seven audit events, including their digests and linkage.

Expected result: `PASS_LIVE_SELECTIVE_CONTAINMENT`. The output file is written only after all checks succeed. Use a fresh output filename for each attempt so a previous success is not mistaken for a new run.

## Recorded run

The 18 November 2026 run returned `PASS_LIVE_SELECTIVE_CONTAINMENT` on Fluxnova 2.0.0. One affected request was denied and redirected to a native human review task; one unaffected request was allowed and completed through the automated BPMN end event. The regression suite passed 56 tests and CALM strict validation returned no errors or warnings. See the [recorded export](../evidence/selective-containment.json).

## Limits

This is a local two-case test, not proof of general availability or isolation across real institutions. The dependency graph is shared; impact identifies common components potentially affected, whereas the gateway's case-to-provider binding determines which case is rerouted. The original single-provider assurance checker remains scoped to its original four-event export. The new script verifies the separate seven-event scenario. The new test cases exercise the actual FastAPI code with mocked Fluxnova/DMN responses; the two-provider live test and strict CALM validation are separate checks, both completed for the recorded run.

Fluxnova REST reference: [historic activities](https://fluxnova.finos.org/docs/fluxnova/get-historic-activity-instances).
