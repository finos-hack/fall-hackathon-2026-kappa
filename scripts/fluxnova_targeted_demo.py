"""Run one isolated local REVOKELINE demo via Fluxnova's task-by-ID API.
Run from the project root as python -m scripts.fluxnova_targeted_demo.
Resets ONLY the synthetic FastAPI state; does not delete Fluxnova instances.
"""
import json
import os
import sys
import uuid
import httpx
from scripts import fluxnova as f


def read(client, path, **kwargs):
    r = client.get(path, **kwargs)
    r.raise_for_status()
    return r.json()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def show(label, value):
    print(label, json.dumps(value, ensure_ascii=False), flush=True)


def run(engine, app):
    require(f.probe(engine)['deployments']['status'] == 200, 'Fluxnova credentials rejected')
    read(engine, f'/process-definition/key/{f.PROCESS_KEY}')
    read(app, '/health')
    show('reset', f.post_json(app, '/demo/reset', {}))
    case_id = 'KYC-FLUX-' + uuid.uuid4().hex[:10]
    started = f.start(engine, app, case_id)
    show('start', started)
    instance_id = started['process_instance']['id']
    case = started['case']
    tasks = read(engine, '/external-task', params={'processInstanceId': instance_id, 'topicName': f.TOPIC})
    require(len(tasks) == 1 and tasks[0]['processInstanceId'] == instance_id and tasks[0]['topicName'] == f.TOPIC, 'Expected exactly one matching external task')
    task = tasks[0]
    # Variables were created in the root process-instance scope, not local execution scope.
    variables = read(engine, f"/process-instance/{instance_id}/variables", params={'deserializeValues': 'false'})
    show('variables', {k: variables[k]['value'] for k in ('case_id', 'provider_id', 'grant_version')})
    payload = {k: variables[k]['value'] for k in ('case_id', 'provider_id', 'grant_version')}
    require(all(payload[k] == case[k] for k in payload), 'Fluxnova variables do not match newly created case')
    before = app.post('/tools/kyc-verify', json=payload)
    show('before', {'status': before.status_code, 'response': before.json()})
    require(before.status_code == 200 and before.json().get('decision') == 'ALLOW', 'Baseline ALLOW missing')
    incident = f.post_json(app, '/incidents', {'provider_id': case['provider_id']})
    show('incident', incident)
    require(incident['status'] == 'REVOKED' and case_id in incident['cases_rerouted'], 'Fresh case was not revoked')
    tid = task['id']
    locked = engine.post(f'/external-task/{tid}/lock', json={'workerId': f.WORKER_ID, 'lockDuration': 60000})
    locked.raise_for_status()
    show('lock', {'status': locked.status_code, 'task_id': tid})
    task['variables'] = variables
    allowed, decision = f.authorize_task(app, task)
    show('worker', {'authorized': allowed, 'decision': decision, 'process_instance_id': instance_id})
    # Do not present a missing case, outage or generic failure as incident enforcement.
    require(not allowed and decision == 'DENY', 'Expected explicit HTTP 403 DENY, not an error fallback')
    completed = engine.post(f'/external-task/{tid}/complete', json={'workerId': f.WORKER_ID, 'variables': {'authorized': {'value': allowed, 'type': 'Boolean'}, 'revokeline_decision': {'value': decision, 'type': 'String'}}})
    completed.raise_for_status()
    show('complete', {'status': completed.status_code})
    inspected = f.inspect(engine, instance_id)
    show('inspect', inspected)
    evidence = read(app, '/evidence')
    decisions = [e['data']['decision'] for e in evidence['events'] if e['kind'] == 'TOOL_CALL_DECISION' and e['data']['case_id'] == case_id]
    show('evidence', {'valid': evidence['valid'], 'decisions': decisions, 'events': len(evidence['events']), 'tip_hash': evidence['tip_hash']})
    require(inspected['status'] == 'ACTIVE' and inspected['human_review_pending'], 'Actual human review task missing')
    require(evidence['valid'] and decisions == ['ALLOW', 'DENY'], 'Evidence chain or decision sequence incorrect')
    show('result', {'status': 'PASS_TARGETED_FLUXNOVA_DEMO', 'case_id': case_id, 'instance_id': instance_id})


def main():
    auth = f.engine_auth_from_environment()
    with httpx.Client(base_url=os.environ.get('FLUXNOVA_URL', f.DEFAULT_ENGINE_URL).rstrip('/'), timeout=20, trust_env=False, auth=auth) as engine, httpx.Client(base_url=os.environ.get('REVOKELINE_URL', f.DEFAULT_APP_URL).rstrip('/'), timeout=20, trust_env=False) as app:
        run(engine, app)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(f'FAIL: {type(exc).__name__}: {exc}', file=sys.stderr)
        if isinstance(exc, httpx.HTTPStatusError):
            print(exc.response.text[:1500], file=sys.stderr)
        sys.exit(2)
