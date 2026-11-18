import json

import httpx
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app import policy_dmn
from scripts import selective_containment as sc
from scripts import fluxnova as f

DECISION = 'test-pinned-definition'


@pytest.fixture
def gateway(monkeypatch):
    monkeypatch.setenv('REVOKELINE_POLICY_MODE', 'DMN')
    monkeypatch.setattr(policy_dmn, 'runtime_decision', lambda facts: {
        'engine':'FLUXNOVA_DMN', 'definition_id':DECISION,
        'decision':'ALLOW' if all(facts.values()) else 'DENY', 'facts':facts})
    with TestClient(app) as client:
        client.post('/demo/reset')
        yield client


def engine_stub(*, valid_history=True, false_review=False):
    instances = {}
    def handler(req):
        path = req.url.path
        if path in ('/engine', '/deployment'):
            return httpx.Response(200, json=[])
        if path == '/process-definition/key/' + f.PROCESS_KEY:
            return httpx.Response(200, json={'key':f.PROCESS_KEY})
        if path.endswith('/start'):
            body = json.loads(req.content)
            instance = 'instance-' + str(len(instances)+1)
            instances[instance] = {'variables':body['variables'], 'decision':None, 'worker':None}
            return httpx.Response(200, json={'id':instance, 'businessKey':body['businessKey']})
        if path == '/external-task':
            instance = req.url.params['processInstanceId']
            return httpx.Response(200, json=[{'id':'task-'+instance,'processInstanceId':instance,'topicName':f.TOPIC}])
        if path.startswith('/process-instance/'):
            instance = path.split('/')[2]; record = instances[instance]
            if path.endswith('/variables'):
                return httpx.Response(200, json=record['variables'])
            return httpx.Response(404 if record['decision']=='ALLOW' else 200, json={})
        if path.startswith('/external-task/task-'):
            instance = path.split('/')[2].removeprefix('task-')
            body = json.loads(req.content); record=instances[instance]
            if path.endswith('/lock'):
                record['worker']=body['workerId']; return httpx.Response(204)
            assert record['worker'] == body['workerId']
            record['decision']=body['variables']['revokeline_decision']['value']
            assert body['variables']['authorized']['value'] == (record['decision']=='ALLOW')
            return httpx.Response(204)
        if path == '/task':
            instance=req.url.params['processInstanceId']
            tasks = [{'id':'review-'+instance,'taskDefinitionKey':'human_review','name':'Manual review'}] if instances[instance]['decision']=='DENY' and not false_review else []
            return httpx.Response(200, json=tasks)
        if path.startswith('/history/process-instance/'):
            instance=path.split('/')[-1]
            return httpx.Response(200, json={'id':instance,'endTime':'2026-11-18T12:00:00','state':'COMPLETED' if valid_history else 'EXTERNALLY_TERMINATED'})
        if path == '/history/activity-instance':
            return httpx.Response(200, json=[{'processInstanceId':req.url.params['processInstanceId'],'activityId':'end_auto','endTime':'2026-11-18T12:00:00','canceled':False}])
        raise AssertionError(path)
    return httpx.Client(base_url='http://engine.test',transport=httpx.MockTransport(handler))


def test_two_provider_isolation(gateway):
    for provider, case in zip(sc.PROVIDERS, ('A','B')):
        assert gateway.post('/cases', json={'case_id':case,'provider_id':provider}).status_code == 201
    assert gateway.post('/incidents', json={'provider_id':sc.PROVIDERS[0]}).json()['cases_rerouted']==['A']
    for provider, case, status in zip(sc.PROVIDERS, ('A','B'), (403,200)):
        assert gateway.post('/tools/kyc-verify',json={'case_id':case,'provider_id':provider,'grant_version':1}).status_code==status
    assert gateway.post('/tools/kyc-verify',json={'case_id':'A','provider_id':sc.PROVIDERS[1],'grant_version':1}).status_code==403
    assert gateway.get('/cases/B').json()['route']=='AUTOMATED_VERIFICATION'


def test_second_provider_calm(gateway):
    assert gateway.get('/impact/'+sc.PROVIDERS[1]).json()['upstream_nodes']==['fluxnova-kyc-process','revokeline-gateway']


def test_live_script_with_mock_engine(gateway):
    with engine_stub() as engine:
        result=sc.run(engine,gateway,DECISION)
    assert result['status']=='PASS_LIVE_SELECTIVE_CONTAINMENT'
    assert len(result['evidence']['events'])==7
    assert result['unaffected']['history']['process']['state']=='COMPLETED'


def test_missing_native_review_rejected(gateway):
    with engine_stub(false_review=True) as engine, pytest.raises(RuntimeError,match='Missing native review'):
        sc.run(engine,gateway,DECISION)


def test_terminated_is_not_successfully_completed(gateway):
    with engine_stub(valid_history=False) as engine, pytest.raises(RuntimeError,match='did not complete normally'):
        sc.run(engine,gateway,DECISION)


def test_wrong_pinned_policy_rejected(gateway):
    with engine_stub() as engine, pytest.raises(RuntimeError,match='Expected pinned live DMN'):
        sc.run(engine,gateway,'wrong-definition')
