"""Compare a deliberately cached-authorization baseline with observed gateway decisions.
Reads current evidence only. Does not invoke a provider or create an unprotected route.
"""
import argparse
import json
import os
import sys
import httpx
from pathlib import Path
from app.main import Store
from scripts.fluxnova import DEFAULT_APP_URL

def compare(proof, decision_id=None):
    events = proof['events']
    prev = '0'*64
    for i, e in enumerate(events, 1):
        if e['sequence'] != i or e['previous_hash'] != prev or e['hash'] != Store.digest({k:v for k,v in e.items() if k!='hash'}):
            raise ValueError('Evidence hash chain invalid')
        prev = e['hash']
    if not proof['valid'] or not events or proof['tip_hash'] != prev:
        raise ValueError('Evidence incomplete')
    # Compare only identical case/provider/grant tuples with an intervening revocation.
    cached = {}; revoked = set(); rows = []
    for e in events:
        d = e['data']
        if e['kind'] == 'PROVIDER_REVOKED':
            revoked.add(d['provider_id'])
        if e['kind'] != 'TOOL_CALL_DECISION':
            continue
        key = (d['case_id'], d['provider_id'], d['grant_version'])
        if d['provider_id'] not in revoked and d['decision'] == 'ALLOW':
            cached[key] = d.get('policy')
        elif d['provider_id'] in revoked and key in cached:
            if decision_id:
                for policy, expected in ((cached[key], 'ALLOW'), (d.get('policy'), 'DENY')):
                    if not isinstance(policy, dict) or policy.get('engine') != 'FLUXNOVA_DMN' or policy.get('definition_id') != decision_id or policy.get('decision') != expected:
                        raise ValueError('Missing or mismatched live DMN policy decision')
            rows.append({'case_id': key[0], 'grant_version': key[2], 'cached_baseline': 'ALLOW', 'observed_gateway': d['decision'], 'policy': d.get('policy'), 'event_hash': e['hash']})
    if not rows:
        raise ValueError('No matched pre/post-incident calls in evidence')
    n = len(rows)
    denied = sum(r['observed_gateway'] == 'DENY' for r in rows)
    return {'status': 'PASS_CACHED_BASELINE_COMPARISON' if denied == n else 'FAIL_COMPARISON', 'matched_post_incident_calls': n,
            'cached_baseline_unsafe_allows': n, 'observed_gateway_unsafe_allows': n-denied, 'rows': rows,
            'scope': 'Synthetic cached-decision counterfactual computed from actual gateway audit events; no unprotected provider call or external credential test.'}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-dmn', metavar='DECISION_ID')
    parser.add_argument('--evidence-file', type=Path, help='Read a saved Command Center export or raw gateway evidence instead of calling the API')
    args = parser.parse_args()
    try:
        if args.evidence_file:
            raw = json.loads(args.evidence_file.read_text(encoding='utf-8-sig'))
            proof = raw['steps']['evidence'] if 'steps' in raw else raw
            result = compare(proof, args.require_dmn)
        else:
            with httpx.Client(base_url=os.environ.get('REVOKELINE_URL', DEFAULT_APP_URL), timeout=10, trust_env=False) as client:
                r = client.get('/evidence'); r.raise_for_status(); result = compare(r.json(), args.require_dmn)
        print(json.dumps(result, indent=2)); sys.exit(int(result['status'] != 'PASS_CACHED_BASELINE_COMPARISON'))
    except (httpx.HTTPError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f'FAIL: {exc}', file=sys.stderr); sys.exit(1)
