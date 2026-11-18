import itertools
import xml.etree.ElementTree as ET
import httpx
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app import policy_dmn as d
from scripts import policy_dmn as cli
from scripts.compare_policy import compare

ID = '618d4f37-e347-11f1-9fac-76863b3dbd01'

def definition(decision_id=ID, key=d.KEY):
    return {'id': decision_id, 'key': key, 'version': 3}

def fake_engine(handler):
    return httpx.Client(base_url='http://engine/engine-rest', transport=httpx.MockTransport(handler))

def test_model_rules_and_full_mock_matrix():
    ns = {'m': 'https://www.omg.org/spec/DMN/20191111/MODEL/'}
    t = ET.parse(cli.MODEL).find('.//m:decisionTable', ns)
    assert t.attrib['hitPolicy'] == 'FIRST'
    assert [x.text for x in t.findall('m:input/m:inputExpression/m:text', ns)] == list(d.INPUTS)
    assert [x.text for x in t.findall('m:rule/m:outputEntry/m:text', ns)] == ['"ALLOW"','"DENY"']
    import json
    def handler(req):
        if req.method == 'GET':
            assert req.url.path.endswith('/decision-definition/' + ID)
            return httpx.Response(200, json=definition())
        assert req.url.path.endswith('/evaluate') and ID in req.url.path
        facts = json.loads(req.content)['variables']
        assert all(x['type']=='Boolean' for x in facts.values())
        decision = 'ALLOW' if all(x['value'] for x in facts.values()) else 'DENY'
        return httpx.Response(200, json=[{'decision': {'value': decision, 'type': 'String'}}])
    with fake_engine(handler) as engine:
        r = cli.matrix(engine, ID)
    assert r['passed'] == r['total'] == 16

@pytest.mark.parametrize('payload', [[], [{'decision': {'value':'UNKNOWN','type':'String'}}], [{'decision': {'value':'ALLOW','type':'Boolean'}}], [{},{}]])
def test_invalid_result(payload):
    with fake_engine(lambda r: httpx.Response(200,json=definition() if r.method == 'GET' else payload)) as e:
        with pytest.raises(d.PolicyError): d.evaluate(e,ID,dict.fromkeys(d.INPUTS,True))

@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv('REVOKELINE_POLICY_MODE','DMN')
    c = TestClient(app); c.post('/demo/reset'); c.post('/cases',json={'case_id':'test-dmn'}); return c

def tool(c): return c.post('/tools/kyc-verify',json={'case_id':'test-dmn','grant_version':1})

def test_dmn_runtime_and_comparison(client,monkeypatch):
    def decide(f): return {'engine':'FLUXNOVA_DMN','definition_id':ID,'facts':f,'decision':'ALLOW' if all(f.values()) else 'DENY'}
    monkeypatch.setattr(d,'runtime_decision',decide)
    assert tool(client).status_code == 200
    client.post('/incidents',json={})
    assert tool(client).status_code == 403
    p = client.get('/evidence').json(); assert p['valid'] and len(p['events']) == 4
    assert p['events'][-1]['data']['policy']['decision']=='DENY'
    assert compare(p, ID)['observed_gateway_unsafe_allows']==0
    with pytest.raises(ValueError): compare(p, d.KEY + ':2:other')
    p['events'][1]['data']['decision']='DENY'
    with pytest.raises(ValueError): compare(p)

def test_dmn_never_widens_local_access(client,monkeypatch):
    monkeypatch.setattr(d,'runtime_decision',lambda f:{'decision':'ALLOW'})
    client.post('/incidents',json={}); assert tool(client).status_code==403

def test_dmn_can_veto_local_allow(client,monkeypatch):
    monkeypatch.setattr(d,'runtime_decision',lambda f:{'decision':'DENY'})
    assert tool(client).status_code==403

def test_dmn_outage_fails_closed(client,monkeypatch):
    def down(f): raise httpx.ConnectError('offline')
    monkeypatch.setattr(d,'runtime_decision',down)
    assert tool(client).status_code==503
    assert client.get('/evidence').json()['events'][-1]['data']['decision']=='DENY'

@pytest.mark.parametrize('bad_definition', [definition(key='other_policy'), definition(decision_id='other-id'), {'id': ID, 'key': d.KEY, 'version': 0}])
def test_reject_wrong_definition_without_evaluating(bad_definition):
    def handler(req):
        assert req.method == 'GET'
        return httpx.Response(200, json=bad_definition)
    with fake_engine(handler) as engine:
        with pytest.raises(d.PolicyError):
            d.evaluate(engine, ID, dict.fromkeys(d.INPUTS, True))

def test_legacy_prefixed_id_is_still_supported():
    legacy = d.KEY + ':1:example'
    def handler(req):
        if req.method == 'GET':
            return httpx.Response(200, json=definition(legacy))
        assert req.url.path.endswith('/evaluate')
        return httpx.Response(200, json=[{'decision': {'value': 'ALLOW', 'type': 'String'}}])
    with fake_engine(handler) as engine:
        assert d.evaluate(engine, legacy, dict.fromkeys(d.INPUTS, True)) == 'ALLOW'

def test_missing_definition_fails_closed_before_evaluation():
    def handler(req):
        assert req.method == 'GET'
        return httpx.Response(404)
    with fake_engine(handler) as engine:
        with pytest.raises(httpx.HTTPStatusError):
            d.evaluate(engine, ID, dict.fromkeys(d.INPUTS, True))
