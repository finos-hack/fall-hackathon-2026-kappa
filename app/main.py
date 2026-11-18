"""REVOKELINE synthetic incident enforcement prototype (not production security)."""
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
import hashlib, json, os
import httpx
from app import policy_dmn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[1]
ARCH = ROOT / 'architectures' / 'revokeline.calm.json'
POLICY = json.loads((ROOT / 'policies' / 'incident-policy.json').read_text())
app = FastAPI(title='REVOKELINE — FINOS Kappa', version='0.1.0')
lock = RLock()

class StartCase(BaseModel):
    case_id: str = Field(min_length=1, max_length=80, pattern=r'^[A-Za-z0-9_-]+$')
    provider_id: str = 'external-kyc-provider'

class ToolCall(BaseModel):
    case_id: str
    provider_id: str = 'external-kyc-provider'
    grant_version: int = Field(ge=0)

class Incident(BaseModel):
    provider_id: str = 'external-kyc-provider'
    reason: str = Field(default='provider_security_alert', max_length=120)

class Store:
    @staticmethod
    def digest(data):
        b = json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
        return hashlib.sha256(b).hexdigest()

    def reset(self):
        with lock:
            self.providers = {'external-kyc-provider': {'status': 'ACTIVE', 'version': 1}}
            self.cases = {}
            self.events = []

    def emit(self, kind, data):
        e = {'sequence': len(self.events) + 1, 'timestamp': datetime.now(timezone.utc).isoformat(),
             'kind': kind, 'data': data, 'previous_hash': self.events[-1]['hash'] if self.events else '0'*64}
        e['hash'] = self.digest(e)
        self.events.append(e)

    def verify(self):
        prev = '0'*64
        for event in self.events:
            payload = {k: v for k, v in event.items() if k != 'hash'}
            if payload['previous_hash'] != prev or self.digest(payload) != event['hash']:
                return False
            prev = event['hash']
        return True

state = Store()
state.reset()

def impacted(node_id):
    """Actual reverse-graph impact analysis over CALM connects relationships."""
    arch = json.loads(ARCH.read_text(encoding='utf-8'))
    if node_id not in {n['unique-id'] for n in arch['nodes']}:
        raise HTTPException(404, 'Node absent from CALM')
    reverse = defaultdict(set)
    for rel in arch['relationships']:
        c = rel.get('relationship-type', {}).get('connects')
        if c:
            reverse[c['destination']['node']].add(c['source']['node'])
    found, queue = set(), deque([node_id])
    while queue:
        for caller in reverse[queue.popleft()]:
            if caller not in found:
                found.add(caller)
                queue.append(caller)
    return sorted(found - {node_id})

@app.get('/health')
def health():
    return {'status': 'ok', 'mode': 'SYNTHETIC_DEMO'}

@app.post('/demo/reset')
def reset():
    state.reset()
    return {'reset': True}

@app.get('/demo/state')
def snapshot():
    with lock:
        return {'providers': state.providers, 'cases': state.cases}

@app.post('/cases', status_code=201)
def start_case(req: StartCase):
    with lock:
        provider = state.providers.get(req.provider_id)
        if not provider:
            raise HTTPException(404, 'Unknown provider')
        if req.case_id in state.cases:
            raise HTTPException(409, 'Duplicate case')
        route = 'AUTOMATED_VERIFICATION' if provider['status'] == 'ACTIVE' else 'HUMAN_REVIEW'
        case = {'case_id': req.case_id, 'provider_id': req.provider_id,
                'grant_version': provider['version'], 'route': route}
        state.cases[req.case_id] = case
        state.emit('CASE_STARTED', {'case_id': req.case_id, 'route': route})
        return case

@app.get('/cases/{case_id}')
def get_case(case_id: str):
    with lock:
        if case_id not in state.cases:
            raise HTTPException(404, 'Unknown case')
        return state.cases[case_id]

@app.get('/impact/{provider_id}')
def impact(provider_id: str):
    return {'target': provider_id, 'upstream_nodes': impacted(provider_id),
            'source': 'architectures/revokeline.calm.json'}

@app.post('/incidents')
def incident(req: Incident):
    with lock:
        p = state.providers.get(req.provider_id)
        if not p:
            raise HTTPException(404, 'Unknown provider')
        nodes = impacted(req.provider_id)
        if p['status'] == 'REVOKED':
            return {'status': 'ALREADY_REVOKED', 'version': p['version'], 'cases_rerouted': [], 'impact': nodes}
        p['status'] = 'REVOKED'
        p['version'] += 1
        rerouted = []
        for case in state.cases.values():
            if case['provider_id'] == req.provider_id and case['route'] != 'HUMAN_REVIEW':
                case['route'] = 'HUMAN_REVIEW'
                rerouted.append(case['case_id'])
        state.emit('PROVIDER_REVOKED', {'provider_id': req.provider_id, 'reason': req.reason,
                                        'version': p['version'], 'cases_rerouted': rerouted, 'impact': nodes})
        return {'status': 'REVOKED', 'version': p['version'], 'cases_rerouted': rerouted, 'impact': nodes}

@app.post('/tools/kyc-verify')
def tool_call(req: ToolCall):
    with lock:
        case, p = state.cases.get(req.case_id), state.providers.get(req.provider_id)
        if case is None:
            raise HTTPException(404, 'Unknown case')
        if p is None or case['provider_id'] != req.provider_id:
            raise HTTPException(403, 'Provider not approved for this case')
        facts = {
            'policy_enabled': POLICY['enforce_at_each_call'] is True,
            'provider_active': p['status'] == 'ACTIVE',
            'route_automated': case['route'] == 'AUTOMATED_VERIFICATION',
            'grant_matches': req.grant_version == p['version'] == case['grant_version'],
        }
        allowed = all(facts.values())
        decision_event = {'case_id': req.case_id, 'provider_id': req.provider_id,
                          'grant_version': req.grant_version, 'provider_version': p['version']}
        mode = os.environ.get('REVOKELINE_POLICY_MODE', 'LOCAL')
        if mode == 'DMN':
            try:
                policy = policy_dmn.runtime_decision(facts)
                decision_event['policy'] = policy
                # A misconfigured external ruleset must never widen access.
                allowed = allowed and policy['decision'] == 'ALLOW'
            except (httpx.HTTPError, ValueError, RuntimeError, KeyError, TypeError):
                decision_event.update(decision='DENY', policy={'engine': 'FLUXNOVA_DMN', 'status': 'UNAVAILABLE_OR_INVALID'})
                state.emit('TOOL_CALL_DECISION', decision_event)
                raise HTTPException(503, {'decision': 'DENY', 'reason': 'policy_unavailable_or_invalid'})
        elif mode != 'LOCAL':
            raise HTTPException(503, {'decision': 'DENY', 'reason': 'unknown_policy_mode'})
        decision_event['decision'] = 'ALLOW' if allowed else 'DENY'
        state.emit('TOOL_CALL_DECISION', decision_event)
        if not allowed:
            raise HTTPException(403, {'decision': 'DENY', 'route': 'HUMAN_REVIEW',
                  'reason': 'revoked_or_stale_grant_or_route_blocked'})
        return {'decision': 'ALLOW', 'synthetic_result': 'DOCUMENT_CHECK_COMPLETED'}

@app.get('/evidence')
def evidence():
    with lock:
        return {'mode': 'IN_MEMORY_HASH_CHAIN', 'valid': state.verify(), 'events': list(state.events),
                'tip_hash': state.events[-1]['hash'] if state.events else None}

@app.get('/demo/baseline')
def baseline():
    return {'counterfactual': 'without_request_time_enforcement',
            'hypothetical_stale_grant_behavior': 'WOULD_ALLOW',
            'warning': 'Illustrative only; does not access third party'}
