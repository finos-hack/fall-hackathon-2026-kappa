"""Deploy a DMN-only resource and verify all 16 Boolean policy combinations on Fluxnova."""
import argparse
import hashlib
import itertools
import json
import os
from pathlib import Path
import sys
import httpx
from app.policy_dmn import KEY, INPUTS, evaluate
from scripts.fluxnova import DEFAULT_ENGINE_URL, engine_auth_from_environment

MODEL = Path(__file__).resolve().parents[1] / 'policies' / 'runtime-authority.dmn'

def deploy(engine):
    raw = MODEL.read_bytes()
    r = engine.post('/deployment/create', data={'deployment-name': 'revokeline-dmn-v1'},
                    files={'data': (MODEL.name, raw, 'application/xml')})
    r.raise_for_status()
    deployment = r.json()['id']
    r = engine.get('/decision-definition', params={'deploymentId': deployment, 'key': KEY})
    r.raise_for_status()
    definitions = r.json()
    if len(definitions) != 1 or definitions[0]['key'] != KEY or definitions[0]['deploymentId'] != deployment:
        raise RuntimeError('DMN definition not found in new deployment')
    return {'deployment_id': deployment, 'decision_id': definitions[0]['id'], 'version': definitions[0]['version'],
            'local_model_sha256': hashlib.sha256(raw).hexdigest()}

def matrix(engine, decision_id):
    rows = []
    for values in itertools.product((False, True), repeat=len(INPUTS)):
        facts = dict(zip(INPUTS, values))
        expected = 'ALLOW' if all(values) else 'DENY'
        result = evaluate(engine, decision_id, facts)
        rows.append({'facts': facts, 'expected': expected, 'observed': result, 'pass': result == expected})
    return {'decision_id': decision_id, 'rows': rows, 'passed': sum(r['pass'] for r in rows), 'total': len(rows),
            'status': 'PASS_LIVE_DMN_MATRIX' if all(r['pass'] for r in rows) else 'FAIL_DMN_MATRIX'}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('deploy','matrix'))
    parser.add_argument('--decision-id', default=os.environ.get('FLUXNOVA_DECISION_ID', ''))
    args = parser.parse_args()
    with httpx.Client(base_url=os.environ.get('FLUXNOVA_URL', DEFAULT_ENGINE_URL).rstrip('/'), auth=engine_auth_from_environment(), timeout=15, trust_env=False) as engine:
        result = deploy(engine) if args.action == 'deploy' else matrix(engine, args.decision_id)
    print(json.dumps(result, indent=2))
    return int(result.get('status') == 'FAIL_DMN_MATRIX')

if __name__ == '__main__':
    try:
        sys.exit(main())
    except (httpx.HTTPError, ValueError, RuntimeError, KeyError, TypeError) as exc:
        print(f'FAIL: {type(exc).__name__}: {exc}', file=sys.stderr)
        if isinstance(exc, httpx.HTTPStatusError):
            print(exc.response.text, file=sys.stderr)
        sys.exit(1)
