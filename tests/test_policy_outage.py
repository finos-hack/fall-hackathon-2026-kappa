import copy

import httpx
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app import policy_dmn
from scripts import policy_outage as outage

ID='test-policy-id'

@pytest.fixture
def harness(monkeypatch):
    state={'down':False,'restore_count':0}
    def handle(req):
        if state['down']:
            raise httpx.ConnectError('test transport unavailable',request=req)
        if req.method=='GET':
            return httpx.Response(200,json={'id':ID,'key':policy_dmn.KEY,'version':1})
        return httpx.Response(200,json=[{'decision':{'type':'String','value':'ALLOW'}}])
    with httpx.Client(base_url='http://engine.test',transport=httpx.MockTransport(handle)) as engine, TestClient(app) as gateway:
        monkeypatch.setenv('REVOKELINE_POLICY_MODE','DMN')
        monkeypatch.setattr(policy_dmn,'runtime_decision',lambda facts:{'engine':'FLUXNOVA_DMN','definition_id':ID,'decision':policy_dmn.evaluate(engine,ID,facts),'facts':facts})
        def interrupt(): state['down']=True
        def restore():
            state['down']=False
            state['restore_count']+=1
        yield engine,gateway,interrupt,restore,state

def test_outage_and_recovery(harness):
    engine,gateway,interrupt,restore,state=harness
    result=outage.run(engine,gateway,ID,interrupt,restore)
    assert [c['status'] for c in result['calls']]==[200,503,200]
    assert state['restore_count']==1
    assert len(result['evidence']['events'])==4
    assert outage.verify(result,ID)

def test_reachable_engine_not_outage(harness):
    engine,gateway,_,restore,state=harness
    with pytest.raises(RuntimeError,match='still reachable'):
        outage.run(engine,gateway,ID,lambda:None,restore)
    assert state['restore_count']==1

def test_tampered_outage_not_verified(harness):
    engine,gateway,interrupt,restore,_=harness
    result=outage.run(engine,gateway,ID,interrupt,restore)
    modified=copy.deepcopy(result)
    modified['evidence']['events'][2]['data']['decision']='ALLOW'
    with pytest.raises(RuntimeError,match='hash'):
        outage.verify(modified,ID)

def test_changed_provider_not_recovery(harness):
    engine,gateway,interrupt,restore,_=harness
    result=outage.run(engine,gateway,ID,interrupt,restore)
    result['states'][1]['providers'][result['payload']['provider_id']]['version']=2
    with pytest.raises(RuntimeError,match='changed during outage'):
        outage.verify(result,ID)



def test_recovery_waits_for_transient_disconnect(harness, monkeypatch):
    engine, gateway, interrupt, restore, state = harness
    original = outage.evaluate
    attempts = []
    def evaluate_with_warmup(client, decision_id, facts):
        if state['restore_count'] and len(attempts) < 2:
            attempts.append(True)
            raise httpx.RemoteProtocolError('engine warming up')
        return original(client, decision_id, facts)
    monkeypatch.setattr(outage, 'evaluate', evaluate_with_warmup)
    monkeypatch.setattr(outage.time, 'sleep', lambda _: None)
    result = outage.run(engine, gateway, ID, interrupt, restore)
    assert len(attempts) == 2
    assert [c['status'] for c in result['calls']] == [200, 503, 200]
    assert len(result['evidence']['events']) == 4


def test_readiness_times_out_on_transport_error(harness, monkeypatch):
    engine, _, _, _, _ = harness
    def unavailable(*args):
        raise httpx.ConnectError('not ready')
    monkeypatch.setattr(outage, 'evaluate', unavailable)
    with pytest.raises(RuntimeError, match='not ready after 0s'):
        outage.wait_for_policy(engine, ID, dict.fromkeys(policy_dmn.INPUTS, True), timeout=0)


def test_readiness_does_not_hide_authentication_error(harness, monkeypatch):
    engine, _, _, _, _ = harness
    calls = []
    def unauthorized(*args):
        calls.append(True)
        request = httpx.Request('GET', 'http://engine.test/decision-definition/id')
        response = httpx.Response(401, request=request)
        response.raise_for_status()
    monkeypatch.setattr(outage, 'evaluate', unauthorized)
    with pytest.raises(httpx.HTTPStatusError):
        outage.wait_for_policy(engine, ID, dict.fromkeys(policy_dmn.INPUTS, True))
    assert len(calls) == 1
