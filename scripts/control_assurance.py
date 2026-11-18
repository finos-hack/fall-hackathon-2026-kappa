"""Scoped, offline governance-assurance checks; not a CCC compliance validator."""
import argparse
import copy
import hashlib
import itertools
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FACTS = ('policy_enabled', 'provider_active', 'route_automated', 'grant_matches')
CATALOG = 'https://ccc.finos.org/catalogs/core/core/controls/v2026.11/'


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def chain(export):
    proof = export['steps']['evidence']
    events = proof['events']
    require(isinstance(events, list) and len(events) == 4, 'Expected four scenario events')
    prev = '0' * 64
    for index, event in enumerate(events, 1):
        require(event['sequence'] == index and event['previous_hash'] == prev, 'Sequence or previous hash mismatch')
        require(event['hash'] == digest({k: v for k, v in event.items() if k != 'hash'}), 'Event digest mismatch')
        prev = event['hash']
    require(proof['tip_hash'] == prev, 'Tip mismatch')
    return events


def scenario(export, decision_id):
    events = chain(export)
    s = export['steps']
    require(export['phase'] == 'VERIFIED' and export['error'] is None, 'Run not verified')
    require([e['kind'] for e in events] == ['CASE_STARTED', 'TOOL_CALL_DECISION', 'PROVIDER_REVOKED', 'TOOL_CALL_DECISION'], 'Unexpected event order')
    a, b, c, d = (e['data'] for e in events)
    case = s['start']['case']['case_id']; provider = s['start']['case']['provider_id']; instance = s['start']['process_instance']['id']
    require(a['case_id'] == b['case_id'] == d['case_id'] == case and b['provider_id'] == c['provider_id'] == d['provider_id'] == provider, 'Case/provider mismatch')
    require(case in c['cases_rerouted'] and case in s['incident']['cases_rerouted'], 'Missing rerouted case')
    require(b['grant_version'] == b['provider_version'] == d['grant_version'] == s['variables']['grant_version'] and d['provider_version'] == c['version'] == s['incident']['version'] and d['provider_version'] > d['grant_version'], 'Version mismatch')
    require(s['variables']['case_id'] == case and s['variables']['provider_id'] == provider, 'Variable mismatch')
    for data, expected, expected_facts in [(b,'ALLOW',(True,True,True,True)), (d,'DENY',(True,False,False,False))]:
        p = data['policy']
        require(p['engine'] == 'FLUXNOVA_DMN' and p['definition_id'] == decision_id and p['decision'] == data['decision'] == expected, 'DMN decision mismatch')
        require(set(p['facts']) == set(FACTS) and all(p['facts'][k] is v for k,v in zip(FACTS,expected_facts)), 'Unexpected DMN facts')
    require(s['before']['status'] == 200 and s['before']['response']['decision'] == 'ALLOW' and s['after']['status'] == 403 and s['after']['response']['detail']['decision'] == 'DENY', 'HTTP decision mismatch')
    require(s['after']['response']['detail']['route'] == 'HUMAN_REVIEW' and s['incident']['status'] == 'REVOKED', 'No confirmed revocation')
    require(s['external_task']['processInstanceId'] == instance and s['lock']['task_id'] == s['external_task']['id'] and s['lock']['status'] == s['complete']['status'] == 204, 'External task mismatch')
    i = s['inspect']
    require(i['process_instance_id'] == instance and i['status'] == 'ACTIVE' and i['human_review_pending'] is True and any(t['taskDefinitionKey'] == 'human_review' and t['id'] for t in i['tasks']), 'No native human task in export')
    require(s['gateway_state']['cases'][case]['route'] == 'HUMAN_REVIEW', 'Gateway route mismatch')
    require(s['result']['instance_id'] == instance and s['result']['case_id'] == case, 'Result correlation mismatch')
    return 'Correlated synthetic ALLOW -> REVOKE -> DENY -> native human_review, pinned DMN.'


def matrix_check(matrix, decision_id):
    require(matrix['decision_id'] == decision_id, 'Matrix definition mismatch')
    rows = matrix['rows']; seen = set()
    for r in rows:
        f = r['facts']; require(set(f) == set(FACTS) and all(type(f[k]) is bool for k in FACTS), 'Invalid matrix facts')
        key = tuple(f[k] for k in FACTS); require(key not in seen, 'Duplicate matrix row'); seen.add(key)
        expected = 'ALLOW' if all(key) else 'DENY'
        require(r['expected'] == r['observed'] == expected and r['pass'] is True, 'Matrix decision mismatch')
    require(seen == set(itertools.product((False, True), repeat=4)) and matrix['passed'] == matrix['total'] == 16, 'Incomplete matrix')
    return '16 distinct boolean combinations: 1 ALLOW, 15 DENY.'


def assess(export, matrix, decision_id, arch):
    checks = []
    def check(identifier, fn):
        try:
            msg = fn(); checks.append({'id':identifier,'status':'PASS','detail':msg})
        except (ValueError, KeyError, TypeError, IndexError, AttributeError) as exc:
            checks.append({'id':identifier,'status':'FAIL','detail':str(exc)})
    check('RVL.EVIDENCE.CHAIN', lambda: (chain(export), 'All four event digests, sequence and tip verified.')[1])
    check('RVL.RUNTIME.CORRELATION', lambda: scenario(export, decision_id))
    check('RVL.DMN.MATRIX', lambda: matrix_check(matrix, decision_id))
    links = [f"{n['unique-id']}:{i.get('port')}" for n in arch['nodes'] for i in n.get('interfaces',[]) if str(i.get('protocol','')).upper() == 'HTTP']
    # These are evidence-scoped assessments, not a FINOS certification.
    controls = [
      {'id':'CCC.Core.CN01.AR01','status':'FAIL' if links else 'NOT_VERIFIED','detail':'Declared plaintext HTTP: '+', '.join(links) if links else 'No independent TLS handshake test; configuration alone is insufficient.'},
      {'id':'CCC.Core.CN01.AR03','status':'FAIL','detail':'Recorded local HTTP API requests were accepted; no HTTPS redirect or block in demo.'},
      {'id':'CCC.Core.CN04.AR03','status':'PARTIAL','detail':'Two access decisions contain timestamps, results and case/provider IDs; authenticated client identity and complete read-attempt coverage are not established.'},
      {'id':'CCC.Core.CN09.AR01','status':'FAIL','detail':'In-memory log is exposed by the same gateway; no separate protected log sink.'},
    ]
    # A chained digest only detects tampering relative to the supplied chain, not a complete rewrite.
    demo_ok = all(c['status']=='PASS' for c in checks)
    return {'status':'PASS_SCOPED_DEMO_ASSURANCE' if demo_ok else 'FAIL_SCOPED_DEMO_ASSURANCE',
            'production_readiness':'BLOCKED', 'decision_id':decision_id, 'checks':checks, 'ccc_assessments':controls,
            'aigf_traceability': {'MI-18':['RVL.RUNTIME.CORRELATION','RVL.DMN.MATRIX'], 'MI-21':['RVL.EVIDENCE.CHAIN','RVL.RUNTIME.CORRELATION'], 'MI-12':[]},
            'scope':'Custom offline checks on a local synthetic scenario; no official CCC validator, no authenticated actor proof, no external attestation. Not a production approval.'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evidence', type=Path, required=True)
    p.add_argument('--matrix', type=Path, required=True)
    p.add_argument('--decision-id', required=True)
    p.add_argument('--negative-demo', action='store_true', help='Modify a copy of one decision; never overwrite evidence')
    p.add_argument('--require-production', action='store_true', help='Return nonzero if production is blocked')
    a = p.parse_args()
    try:
        export = read(a.evidence); matrix = read(a.matrix); arch = read(ROOT/'architectures/revokeline.calm.json')
        if a.negative_demo:
            export = copy.deepcopy(export); export['steps']['evidence']['events'][-1]['data']['decision'] = 'ALLOW'
        result = assess(export, matrix, a.decision_id, arch)
    except (OSError, ValueError, KeyError, TypeError, IndexError) as exc:
        result = {'status':'FAIL_INPUT','detail':str(exc),'production_readiness':'BLOCKED'}
    print(json.dumps(result, indent=2))
    return int(result['status'] != 'PASS_SCOPED_DEMO_ASSURANCE' or a.require_production)

if __name__ == '__main__':
    raise SystemExit(main())
