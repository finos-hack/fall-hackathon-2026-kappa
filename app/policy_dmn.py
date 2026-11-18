"""Optional runtime DMN policy. A deployed policy can restrict but never widen local access."""
import os
import re
from urllib.parse import quote
import httpx
from scripts.fluxnova import DEFAULT_ENGINE_URL, engine_auth_from_environment

KEY = 'revokeline_runtime_authority_v1'
INPUTS = ('policy_enabled', 'provider_active', 'route_automated', 'grant_matches')

class PolicyError(RuntimeError):
    pass

def evaluate(engine, decision_id, facts):
    # Engine-assigned IDs are opaque (including bare UUIDs). Verify the
    # referenced definition by ID rather than guessing its format or using latest.
    if not isinstance(decision_id, str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,255}', decision_id) or decision_id in ('.', '..', 'key', 'count'):
        raise PolicyError('Expected pinned REVOKELINE decision definition ID')
    if set(facts) != set(INPUTS) or any(type(v) is not bool for v in facts.values()):
        raise PolicyError('Invalid policy facts')
    path = '/decision-definition/' + quote(decision_id, safe='')
    metadata = engine.get(path)
    metadata.raise_for_status()
    definition = metadata.json()
    if (not isinstance(definition, dict) or definition.get('id') != decision_id
            or definition.get('key') != KEY
            or type(definition.get('version')) is not int or definition['version'] < 1):
        raise PolicyError('Pinned decision is not a valid REVOKELINE definition')
    r = engine.post(path + '/evaluate',
                    json={'variables': {k: {'value': v, 'type': 'Boolean'} for k,v in facts.items()}})
    r.raise_for_status()
    rows = r.json()
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise PolicyError('Expected exactly one DMN result')
    output = rows[0].get('decision')
    if not isinstance(output, dict) or output.get('type') != 'String' or output.get('value') not in ('ALLOW','DENY'):
        raise PolicyError('Invalid DMN decision output')
    return output['value']

def runtime_decision(facts):
    decision_id = os.environ.get('FLUXNOVA_DECISION_ID', '')
    with httpx.Client(base_url=os.environ.get('FLUXNOVA_URL', DEFAULT_ENGINE_URL).rstrip('/'),
                      auth=engine_auth_from_environment(), trust_env=False, timeout=5) as engine:
        result = evaluate(engine, decision_id, facts)
    return {'engine': 'FLUXNOVA_DMN', 'definition_id': decision_id, 'decision': result, 'facts': facts}
