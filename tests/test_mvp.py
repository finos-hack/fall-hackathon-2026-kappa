import json
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from app.main import ARCH, app, state

client = TestClient(app)

@pytest.fixture(autouse=True)
def clean():
    client.post('/demo/reset')

def start(case='KYC-041'):
    r = client.post('/cases', json={'case_id': case})
    assert r.status_code == 201
    return r.json()

def call(case='KYC-041', version=1):
    return client.post('/tools/kyc-verify', json={'case_id': case, 'grant_version': version})

def breach():
    return client.post('/incidents', json={'reason': 'synthetic_vendor_breach'})

def test_allowed_before_breach():
    start()
    assert call().json()['decision'] == 'ALLOW'

def test_revoked_grant_denied_and_case_rerouted():
    start()
    assert call().status_code == 200
    r = breach().json()
    assert r['status'] == 'REVOKED'
    assert 'KYC-041' in r['cases_rerouted']
    assert call().status_code == 403
    assert client.get('/cases/KYC-041').json()['route'] == 'HUMAN_REVIEW'

def test_new_grant_does_not_bypass_revocation():
    start()
    breach()
    assert call(version=1).status_code == 403
    assert call(version=2).status_code == 403

def test_new_case_after_breach_uses_human_route():
    breach()
    assert start('KYC-042')['route'] == 'HUMAN_REVIEW'
    assert call('KYC-042', version=2).status_code == 403

def test_incident_idempotency():
    assert breach().json()['version'] == 2
    again = breach().json()
    assert again['status'] == 'ALREADY_REVOKED'
    assert again['version'] == 2

def test_actual_calm_impact_traversal():
    r = client.get('/impact/external-kyc-provider').json()
    assert r['upstream_nodes'] == ['fluxnova-kyc-process', 'revokeline-gateway']

def test_no_case_no_access():
    assert call().status_code == 404

def test_wrong_provider_no_access():
    start()
    assert client.post('/tools/kyc-verify', json={
        'case_id':'KYC-041','provider_id':'other','grant_version':1
    }).status_code == 403

def test_hash_chain_and_tampering():
    start()
    call()
    breach()
    call()
    proof = client.get('/evidence').json()
    assert proof['valid'] and len(proof['events']) == 4
    assert proof['tip_hash'] == proof['events'][-1]['hash']
    state.events[0]['kind'] = 'FORGED'
    assert client.get('/evidence').json()['valid'] is False

def test_calm_local_structural_consistency():
    arch = json.loads(ARCH.read_text())
    nodes = {x['unique-id'] for x in arch['nodes']}
    assert len(nodes) == len(arch['nodes'])
    for relationship in arch['relationships']:
        r = relationship['relationship-type']
        if 'connects' in r:
            assert r['connects']['source']['node'] in nodes
            assert r['connects']['destination']['node'] in nodes
    # This is NOT official CALM CLI schema validation.

def test_bpmn_xml_syntax():
    ET.parse(Path(__file__).parents[1] / 'process' / 'kyc-incident.bpmn')

def test_concurrent_denial_after_breach():
    start()
    breach()
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: call().status_code, range(16)))
    assert results == [403] * 16

def test_baseline_not_a_bypass():
    r = client.get('/demo/baseline').json()
    assert r['hypothetical_stale_grant_behavior'] == 'WOULD_ALLOW'
