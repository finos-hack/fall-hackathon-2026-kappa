"""Local-only visual driver for the validated targeted Fluxnova scenario.
Run on 127.0.0.1:8001, with the original gateway on :8000.
No production authentication, persistence or multi-user isolation is provided.
"""
from pathlib import Path
from threading import Lock
import copy
import os
import uuid
from contextlib import contextmanager

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from scripts import fluxnova as f
from scripts.fluxnova_targeted_demo import read, require

app = FastAPI(title="REVOKELINE | Live Incident Command Center", version="0.2.4")
mutex = Lock()
HERE = Path(__file__).parent

@contextmanager
def clients():
    with httpx.Client(base_url=os.environ.get('FLUXNOVA_URL', f.DEFAULT_ENGINE_URL).rstrip('/'), timeout=20, trust_env=False, auth=f.engine_auth_from_environment()) as engine, httpx.Client(base_url=os.environ.get('REVOKELINE_URL', f.DEFAULT_APP_URL).rstrip('/'), timeout=20, trust_env=False) as gateway:
        yield engine, gateway

class Demo:
    def __init__(self):
        self.state = {'phase': 'READY', 'run_id': None, 'steps': {}, 'error': None}

    def start(self, engine, gateway):
        # Check dependencies before wiping demo state. This does not delete old BPMN instances.
        require(f.probe(engine)['deployments']['status'] == 200, 'Fluxnova deployment access denied')
        read(engine, f'/process-definition/key/{f.PROCESS_KEY}')
        read(gateway, '/health')
        self.state = {'phase': 'STARTING', 'run_id': uuid.uuid4().hex, 'steps': {}, 'error': None}
        s = self.state['steps']
        s['reset'] = f.post_json(gateway, '/demo/reset', {})
        case_id = 'KYC-LIVE-' + self.state['run_id'][:10]
        s['start'] = f.start(engine, gateway, case_id)
        iid = s['start']['process_instance']['id']
        tasks = read(engine, '/external-task', params={'processInstanceId': iid, 'topicName': f.TOPIC})
        require(len(tasks) == 1 and tasks[0]['processInstanceId'] == iid and tasks[0]['topicName'] == f.TOPIC, 'Expected exactly one matching external task')
        s['external_task'] = tasks[0]
        variables = read(engine, f'/process-instance/{iid}/variables', params={'deserializeValues': 'false'})
        payload = {k: variables[k]['value'] for k in ('case_id','provider_id','grant_version')}
        require(all(payload[k] == s['start']['case'][k] for k in payload), 'BPMN variable mismatch')
        s['variables'] = payload
        before = gateway.post('/tools/kyc-verify', json=payload)
        s['before'] = {'status': before.status_code, 'response': before.json()}
        require(before.status_code == 200 and s['before']['response'].get('decision') == 'ALLOW', 'Baseline ALLOW missing')
        self.state['phase'] = 'AUTHORIZED'

    def incident(self, engine, gateway):
        require(self.state['phase'] == 'AUTHORIZED', 'Start an authorized run first')
        s = self.state['steps']
        s['incident'] = f.post_json(gateway, '/incidents', {'provider_id': s['variables']['provider_id']})
        require(s['incident']['status'] == 'REVOKED' and s['variables']['case_id'] in s['incident']['cases_rerouted'], 'Fresh case not revoked')
        self.state['phase'] = 'REVOKED'

    def enforce(self, engine, gateway):
        require(self.state['phase'] == 'REVOKED', 'Trigger the incident first')
        s = self.state['steps']; tid = s['external_task']['id']; iid = s['start']['process_instance']['id']
        # Re-read live process data: never substitute cached variables for engine state.
        variables = read(engine, f'/process-instance/{iid}/variables', params={'deserializeValues': 'false'})
        payload = {k: variables[k]['value'] for k in s['variables']}
        require(payload == s['variables'], 'BPMN state changed')
        worker_id = 'revokeline-ui-' + self.state['run_id'][:10]
        response = engine.post(f'/external-task/{tid}/lock', json={'workerId': worker_id, 'lockDuration': 60000})
        s['lock'] = {'status': response.status_code, 'task_id': tid}
        require(response.status_code == 204, f'Expected task lock HTTP 204, got {response.status_code}')
        after = gateway.post('/tools/kyc-verify', json=payload)
        s['after'] = {'status': after.status_code, 'response': after.json()}
        detail = s['after']['response'].get('detail')
        require(after.status_code == 403 and isinstance(detail, dict) and detail.get('decision') == 'DENY' and detail.get('reason') == 'revoked_or_stale_grant_or_route_blocked', 'Expected explicit revoked-grant DENY, not outage or generic failure')
        response = engine.post(f'/external-task/{tid}/complete', json={'workerId': worker_id, 'variables': {'authorized': {'value': False, 'type': 'Boolean'}, 'revokeline_decision': {'value': 'DENY', 'type': 'String'}}})
        s['complete'] = {'status': response.status_code}
        require(response.status_code == 204, f'Expected completion HTTP 204, got {response.status_code}')
        s['inspect'] = f.inspect(engine, iid)
        s['gateway_state'] = read(gateway, '/demo/state')
        s['evidence'] = read(gateway, '/evidence')
        evidence = s['evidence']
        decisions = [e['data']['decision'] for e in evidence['events'] if e['kind'] == 'TOOL_CALL_DECISION' and e['data']['case_id'] == payload['case_id']]
        require(s['inspect']['status'] == 'ACTIVE' and s['inspect']['human_review_pending'], 'Native Fluxnova human review missing')
        require(evidence['valid'] and decisions == ['ALLOW', 'DENY'], 'Decision chain invalid')
        require(s['gateway_state']['providers'][payload['provider_id']]['status'] == 'REVOKED' and s['gateway_state']['cases'][payload['case_id']]['route'] == 'HUMAN_REVIEW', 'Gateway state mismatch')
        s['result'] = {'status': 'PASS_LIVE_COMMAND_CENTER', 'case_id': payload['case_id'], 'instance_id': iid, 'decisions': decisions}
        self.state['phase'] = 'VERIFIED'

session = Demo()

@app.get('/')
def index():
    return FileResponse(HERE / 'command_center.html', media_type='text/html', headers={'Cache-Control':'no-store'})

@app.get('/ui/state')
def state():
    with mutex:
        return copy.deepcopy(session.state)

@app.post('/ui/{action}')
def mutate(action: str, request: Request):
    # Browser-only local demo protection against ordinary cross-origin form posts.
    # Not authentication. Bind strictly to loopback and never expose to a network.
    if request.headers.get('x-revokeline-demo') != '1':
        raise HTTPException(403, 'Missing local demo request header')
    expected = {'start': ('READY','VERIFIED','ERROR'), 'incident': ('AUTHORIZED',), 'enforce': ('REVOKED',)}
    if action not in expected:
        raise HTTPException(404, 'Unknown action')
    with mutex:
        if session.state['phase'] not in expected[action]:
            raise HTTPException(409, 'Action not valid in current phase')
        try:
            with clients() as (engine, gateway):
                getattr(session, action)(engine, gateway)
        except (httpx.HTTPError, RuntimeError, ValueError, KeyError, TypeError) as exc:
            session.state['phase'] = 'ERROR'
            session.state['error'] = f'{type(exc).__name__}: {exc}'
            return copy.deepcopy(session.state)
        return copy.deepcopy(session.state)
