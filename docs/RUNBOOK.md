# Local setup and demo

All commands assume the repository root. Use the environment and credentials of an isolated demo only; do not expose these services publicly.

## Setup (PowerShell)

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip check
python -m pytest tests -q
```

On Linux/macOS, activate the environment with `source .venv/bin/activate` after creating it with `python3 -m venv .venv`.

Start Fluxnova 2.0.0 (reuse the existing demo container if present):

```powershell
docker run -d --name revokeline-fluxnova -p 127.0.0.1:8080:8080 finos/fluxnova-bpm-platform:2.0.0
```

Wait for initialization. Use the credentials configured in the engine; `demo/demo` was used in the recorded local run. A GET on `/engine` alone does not establish authorization for other REST endpoints.

```powershell
$env:FLUXNOVA_USERNAME = 'demo'
$env:FLUXNOVA_PASSWORD = 'demo'
python -m scripts.fluxnova probe
python -m scripts.fluxnova deploy
python -m scripts.policy_dmn deploy
```

Deploy only on a fresh engine or when changing the relevant model. Copy the actual decision ID from the DMN deployment result into the environment variable below. IDs are assigned by Fluxnova; do not use the ID of the recorded run on a fresh engine.

```powershell
$env:FLUXNOVA_DECISION_ID = 'REPLACE_WITH_DEPLOYED_DECISION_ID'
python -m scripts.policy_dmn matrix
```

Expect 16/16 matches, one ALLOW and 15 DENY. Save the matrix output before continuing. In a terminal with the same virtual environment, engine credentials and decision ID, run:

```powershell
$env:REVOKELINE_POLICY_MODE = 'DMN'
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Keep the gateway running without auto-reload. Its state is held in memory. The default policy mode, if unset, is LOCAL; it does not call DMN.

## Demonstration

In a separate terminal with the environment activated and engine credentials configured:

```powershell
python -m uvicorn app.command_center:app --host 127.0.0.1 --port 8001
```

Open http://127.0.0.1:8001/. Start an authorized case, trigger a provider breach, then enforce and verify. Expect ALLOW, REVOKED, DENY and an active native human review task. Export the JSON evidence before starting another run.

Alternatively run `python -m scripts.fluxnova_targeted_demo` from a terminal with the engine credentials. Do not run both demonstrations concurrently. Starting a new demo resets the synthetic gateway state but does not delete earlier Fluxnova instances. The targeted worker locks the matching task directly by ID; the older fetchAndLock path is not required for this run.

## Offline checks

The following uses the recorded deployment ID and matching saved evidence, not a newly deployed policy. The matrix file must be the actual saved output from the live matrix command.

```powershell
$assuranceArgs = @('--evidence','evidence/gate5-live-dmn.json','--matrix','evidence/gate5-dmn-matrix.json','--decision-id','618d4f37-e347-11f1-9fac-76863b3dbd01')
python -m scripts.control_assurance @assuranceArgs
python -m scripts.control_assurance @assuranceArgs --negative-demo
python -m scripts.control_assurance @assuranceArgs --require-production
```

Expected exit codes respectively: 0, 1 and 1. The negative test alters an in-memory copy only. Production approval is deliberately blocked for the known local prototype. See [control assurance](CONTROL_ASSURANCE.md) for the assessed requirements and limitations.

Validate architecture separately:

```powershell
npm install -g @finos/calm-cli
calm validate -a architectures/revokeline.calm.json --strict
```
