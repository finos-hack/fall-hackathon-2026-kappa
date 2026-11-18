# Policy engine failure and recorded assurance

The outage exercise checks one synthetic case and the same grant across three calls. The gateway must stay running in DMN mode; the operator stops and restarts the existing dedicated Fluxnova container. This interrupts both DMN and BPMN, not only DMN. No workflow completion is asserted during the outage.

Save prior evidence before running. The script resets synthetic gateway state and writes a new report only on success. Keep the existing engine deployment and use its pinned decision ID. Do not run another demo concurrently.

```sh
python -m scripts.policy_outage --output evidence/policy-outage.json
```

When prompted, stop the demo container from another terminal (`docker stop revokeline-fluxnova`), then return to the script. When prompted again, restart it (`docker start revokeline-fluxnova`). Return to the script after starting the container. It retries transient transport errors and HTTP 502/503/504 until the pinned DMN evaluates successfully or the readiness deadline is reached. You can also check the authenticated API using `python -m scripts.fluxnova probe`. The readiness loop has a 120-second total retry budget, with an individual HTTP request potentially extending the wall-clock duration slightly. Do not remove the container. Ensure the engine is restarted even if the script is interrupted or fails.

The recorded successful run followed the expected sequence: HTTP 200 ALLOW, HTTP 503 DENY with `policy_unavailable_or_invalid`, then HTTP 200 ALLOW. The test checks a real transport error against the engine, unchanged provider status and case/grant, the same pinned DMN definition before and after, and four chained audit events. It does not test independent DMN failure, high availability or real provider traffic. Local tests use a mocked transport; live execution is a separate acceptance step.

## Recorded assurance page

Start the Command Center as described in the runbook. Open `http://127.0.0.1:8001/assurance`.

The page reads the original incident export and matrix, selective containment export, and outage export from `evidence/`. Each request recalculates the corresponding checks rather than trusting a saved PASS label. Missing or invalid files cannot produce an overall verified result. The view is read-only; it does not reset the gateway, contact Fluxnova, or approve deployment. Production remains blocked by known control gaps. The reports are unsigned records, not independent attestations.
