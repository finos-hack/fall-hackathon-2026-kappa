"""Runs the end-to-end synthetic demo against FastAPI TestClient."""
from fastapi.testclient import TestClient
from app.main import app
api = TestClient(app)

def show(name, response):
    print(name, f'HTTP {response.status_code}', response.json())

show('Reset', api.post('/demo/reset'))
case = api.post('/cases', json={'case_id':'KYC-2026-041'})
show('New KYC case', case)
request = {'case_id':'KYC-2026-041','grant_version':1}
show('Before incident: tool call', api.post('/tools/kyc-verify',json=request))
show('Impact from CALM', api.get('/impact/external-kyc-provider'))
show('Synthetic provider breach', api.post('/incidents',json={'reason':'synthetic_vendor_breach'}))
show('After incident: same grant', api.post('/tools/kyc-verify',json=request))
show('Rerouted workflow',api.get('/cases/KYC-2026-041'))
proof = api.get('/evidence').json()
print('Evidence chain', proof['valid'], 'events:', len(proof['events']), 'tip:', proof['tip_hash'])
