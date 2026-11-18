"""UI orchestration tests with real FastAPI gateway, simulated Fluxnova REST."""
from contextlib import contextmanager
import json
import httpx
import pytest
from fastapi.testclient import TestClient
from app import command_center as ui
from app.main import app as gateway_app
from scripts.fluxnova import TOPIC, PROCESS_KEY

@pytest.fixture
def setup(monkeypatch):
    gateway = TestClient(gateway_app)
    seen = {'completed': False, 'missing_review': False, 'lock_status': 204}
    def engine_handler(req):
        path = req.url.path
        if path in ('/engine', '/deployment'):
            return httpx.Response(200, json=[])
        if path == f'/process-definition/key/{PROCESS_KEY}':
            return httpx.Response(200, json={'key': PROCESS_KEY})
        if path.endswith('/start'):
            seen['variables'] = json.loads(req.content)['variables']
            return httpx.Response(200, json={'id':'instance-1','definitionKey':PROCESS_KEY})
        if path == '/external-task':
            assert req.url.params['processInstanceId'] == 'instance-1'
            return httpx.Response(200, json=[{'id':'task-1','processInstanceId':'instance-1','topicName':TOPIC}])
        if path == '/process-instance/instance-1/variables':
            return httpx.Response(200, json=seen['variables'])
        if path == '/external-task/task-1/lock':
            seen['worker'] = json.loads(req.content)['workerId']
            return httpx.Response(seen['lock_status'])
        if path == '/external-task/task-1/complete':
            body = json.loads(req.content)
            assert body['workerId'] == seen['worker']
            assert body['variables']['authorized'] == {'value':False,'type':'Boolean'}
            assert body['variables']['revokeline_decision']['value'] == 'DENY'
            seen['completed'] = True
            return httpx.Response(204)
        if path == '/task':
            assert req.url.params['processInstanceId'] == 'instance-1'
            return httpx.Response(200,json=[{'id':'review-1','taskDefinitionKey':'human_review','name':'Manual KYC analyst review'}] if seen['completed'] and not seen['missing_review'] else [])
        if path == '/process-instance/instance-1':
            return httpx.Response(200,json={'id':'instance-1'})
        raise AssertionError(f'Unexpected request {req.method} {path}')
    @contextmanager
    def fake_clients():
        with httpx.Client(transport=httpx.MockTransport(engine_handler),base_url='http://engine') as engine:
            yield engine, gateway
    monkeypatch.setattr(ui,'clients',fake_clients)
    monkeypatch.setattr(ui,'session',ui.Demo())
    client = TestClient(ui.app)
    client.headers.update({'x-revokeline-demo':'1'})
    return client, gateway, seen

def test_live_ui_contract(setup):
    c,g,seen=setup
    assert c.get('/').status_code==200
    assert 'Live Incident Command Center' in c.get('/').text
    assert c.post('/ui/start').json()['phase']=='AUTHORIZED'
    state=c.post('/ui/incident').json()
    assert state['phase']=='REVOKED' and state['steps']['incident']['impact']==['fluxnova-kyc-process','revokeline-gateway']
    state=c.post('/ui/enforce').json()
    assert state['phase']=='VERIFIED'
    s=state['steps']
    assert s['after']['status']==403 and s['inspect']['human_review_pending']
    assert s['evidence']['valid'] and len(s['evidence']['events'])==4
    assert s['result']['decisions']==['ALLOW','DENY']
    assert c.get('/ui/state').json()==state
    assert c.post('/ui/enforce').status_code==409

def test_out_of_order_and_header(setup):
    c,_,_=setup
    assert c.post('/ui/start',headers={'x-revokeline-demo':'0'}).status_code==403
    assert c.post('/ui/incident').status_code==409
    assert c.get('/ui/state').json()['phase']=='READY'

def test_missing_case_not_counted_as_success(setup):
    c,g,seen=setup
    c.post('/ui/start');c.post('/ui/incident');g.post('/demo/reset')
    state=c.post('/ui/enforce').json()
    assert state['phase']=='ERROR' and not seen['completed']
    assert 'result' not in state['steps']
    assert state['steps']['after']['status']==404

def test_missing_native_review_not_counted_as_success(setup):
    c,g,seen=setup
    seen['missing_review']=True
    c.post('/ui/start');c.post('/ui/incident')
    state=c.post('/ui/enforce').json()
    assert state['phase']=='ERROR' and 'result' not in state['steps']

def test_failed_lock_does_not_complete(setup):
    c,g,seen=setup
    seen['lock_status']=409
    c.post('/ui/start');c.post('/ui/incident')
    state=c.post('/ui/enforce').json()
    assert state['phase']=='ERROR' and not seen['completed']
    assert 'after' not in state['steps']
