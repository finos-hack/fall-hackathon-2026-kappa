"""Run two independent synthetic KYC cases on the existing Fluxnova BPMN/DMN.

Resets the local gateway, not Fluxnova. Run only in a dedicated demo instance.
Requires history recording to prove the unaffected process completed normally.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import uuid

import httpx
from scripts import fluxnova as f
from scripts.control_assurance import digest
from scripts.fluxnova_targeted_demo import read, require

PROVIDERS = ('external-kyc-provider', 'secondary-kyc-provider')


def start_case(engine, gateway, provider, suffix):
    started = f.start(engine, gateway, 'KYC-SELECT-' + suffix, provider)
    case = started['case']
    instance = started['process_instance']['id']
    tasks = read(engine, '/external-task', params={
        'processInstanceId': instance, 'topicName': f.TOPIC})
    require(len(tasks) == 1, 'Expected one external task')
    task = tasks[0]
    require(task['processInstanceId'] == instance and task['topicName'] == f.TOPIC,
            'External task does not belong to this process')
    raw = read(engine, f'/process-instance/{instance}/variables',
               params={'deserializeValues': 'false'})
    payload = {k: raw[k]['value'] for k in ('case_id', 'provider_id', 'grant_version')}
    require(all(payload[k] == case[k] for k in payload) and provider == payload['provider_id'],
            'Process authorization variables mismatch')
    return {'started': started, 'task': task, 'payload': payload}


def call(gateway, payload, expected):
    r = gateway.post('/tools/kyc-verify', json=payload)
    body = r.json()
    decision = body.get('decision') if expected == 200 else body.get('detail', {}).get('decision')
    require(r.status_code == expected and decision == ('ALLOW' if expected == 200 else 'DENY'),
            f'Unexpected gateway response: {r.status_code} {body}')
    if expected == 403:
        require(body['detail']['reason'] == 'revoked_or_stale_grant_or_route_blocked',
                'Expected explicit incident denial')
    return {'status': r.status_code, 'response': body}


def finish_task(engine, gateway, entry, expected):
    task_id = entry['task']['id']
    # Use the same proven task-by-ID route as the single-provider demo.
    worker_id = 'revokeline-select-' + uuid.uuid4().hex[:12]
    lock = engine.post(f'/external-task/{task_id}/lock', json={
        'workerId': worker_id, 'lockDuration': 60000})
    require(lock.status_code == 204, f'Task lock failed: {lock.status_code}')
    decision = call(gateway, entry['payload'], expected)
    allowed = expected == 200
    complete = engine.post(f'/external-task/{task_id}/complete', json={
        'workerId': worker_id, 'variables': {
            'authorized': {'value': allowed, 'type': 'Boolean'},
            'revokeline_decision': {'value': 'ALLOW' if allowed else 'DENY', 'type': 'String'}}})
    require(complete.status_code == 204, f'Task completion failed: {complete.status_code}')
    return {'lock_status': lock.status_code, 'gateway': decision, 'complete_status': complete.status_code}


def verify_audit(proof, entries, decision_id):
    a, b = (entry['payload']['case_id'] for entry in entries)
    events = proof['events']
    require(proof['valid'] is True and len(events) == 7, 'Expected seven valid events')
    prev = '0' * 64
    for i, event in enumerate(events, 1):
        require(event['sequence'] == i and event['previous_hash'] == prev and
                event['hash'] == digest({k: v for k, v in event.items() if k != 'hash'}),
                'Invalid evidence hash chain')
        prev = event['hash']
    require(prev == proof['tip_hash'], 'Evidence tip mismatch')
    expected_kinds = ['CASE_STARTED', 'CASE_STARTED', 'TOOL_CALL_DECISION', 'TOOL_CALL_DECISION',
                      'PROVIDER_REVOKED', 'TOOL_CALL_DECISION', 'TOOL_CALL_DECISION']
    require([e['kind'] for e in events] == expected_kinds, 'Unexpected event sequence')
    require([e['data']['case_id'] for e in events[:2]] == [a, b], 'Case creation mismatch')
    incident = events[4]['data']
    require(incident['provider_id'] == PROVIDERS[0] and incident['cases_rerouted'] == [a]
            and incident['version'] == 2, 'Incident appears to affect wrong cases')
    rows = [e['data'] for e in events if e['kind'] == 'TOOL_CALL_DECISION']
    for row, entry, decision, version in zip(rows, [entries[0], entries[1], entries[0], entries[1]],
                                            ['ALLOW','ALLOW','DENY','ALLOW'], [1,1,2,1]):
        payload = entry['payload']
        require(all(row[k] == v for k,v in payload.items()) and row['provider_version'] == version,
                'Audit decision belongs to wrong grant or provider')
        policy = row.get('policy', {})
        require(row['decision'] == policy.get('decision') == decision and
                policy.get('engine') == 'FLUXNOVA_DMN' and policy.get('definition_id') == decision_id,
                'Expected pinned live DMN decision')
        expected_facts = {'policy_enabled': True, 'provider_active': decision == 'ALLOW',
                          'route_automated': decision == 'ALLOW', 'grant_matches': decision == 'ALLOW'}
        require(policy.get('facts') == expected_facts, 'Unexpected DMN facts')


def verify_completion(engine, instance):
    # Runtime 404 alone cannot prove successful completion. Check actual history.
    history = read(engine, f'/history/process-instance/{instance}')
    require(history.get('id') == instance and history.get('endTime') and
            history.get('state') == 'COMPLETED', 'Unaffected process did not complete normally')
    activities = read(engine, '/history/activity-instance', params={
        'processInstanceId': instance, 'activityId': 'end_auto'})
    require(any(x.get('processInstanceId') == instance and x.get('activityId') == 'end_auto'
                and x.get('endTime') and not x.get('canceled', False) for x in activities),
            'No completed automated end event in history')
    return {'process': history, 'automated_end_activities': activities}


def run(engine, gateway, decision_id):
    require(bool(decision_id), 'Set FLUXNOVA_DECISION_ID to the deployed DMN ID')
    require(f.probe(engine)['deployments']['status'] == 200, 'Fluxnova access failed')
    read(engine, f'/process-definition/key/{f.PROCESS_KEY}')
    read(gateway, '/health')
    # Check that the gateway really has both modeled providers before resetting.
    for provider in PROVIDERS:
        require(provider in read(gateway, '/demo/state')['providers'], 'Gateway missing second provider; restart updated app')
        impact = read(gateway, f'/impact/{provider}')
        require(impact['target'] == provider and 'revokeline-gateway' in impact['upstream_nodes'],
                'Provider absent from CALM dependency graph')
    f.post_json(gateway, '/demo/reset', {})
    suffix = uuid.uuid4().hex[:10]
    a, b = [start_case(engine, gateway, provider, suffix + tag) for provider,tag in zip(PROVIDERS, ('-A','-B'))]
    for entry in (a,b):
        entry['before'] = call(gateway, entry['payload'], 200)
    a_id, b_id = (e['payload']['case_id'] for e in (a,b))
    incident = f.post_json(gateway, '/incidents', {'provider_id': PROVIDERS[0], 'reason': 'provider_security_alert'})
    require(incident['status'] == 'REVOKED' and incident['version'] == 2 and incident['cases_rerouted'] == [a_id],
            'Incident must affect only provider A')
    a['after'] = finish_task(engine, gateway, a, 403)
    b['after'] = finish_task(engine, gateway, b, 200)
    a_instance, b_instance = (e['started']['process_instance']['id'] for e in (a,b))
    a['inspect'] = f.inspect(engine, a_instance)
    require(a['inspect']['status'] == 'ACTIVE' and a['inspect']['human_review_pending'] and
            any(t['id'] and t['taskDefinitionKey'] == 'human_review' for t in a['inspect']['tasks']),
            'Missing native review task for affected process')
    b['inspect'] = f.inspect(engine, b_instance)
    require(not b['inspect']['tasks'] and b['inspect']['status'] == 'NO_ACTIVE_INSTANCE_CHECK_HISTORY_FOR_COMPLETION',
            'Unaffected process unexpectedly active or awaiting review')
    b['history'] = verify_completion(engine, b_instance)
    state = read(gateway, '/demo/state')
    require(state['providers'][PROVIDERS[0]] == {'status':'REVOKED','version':2} and
            state['providers'][PROVIDERS[1]] == {'status':'ACTIVE','version':1} and
            state['cases'][a_id]['route'] == 'HUMAN_REVIEW' and
            state['cases'][b_id]['route'] == 'AUTOMATED_VERIFICATION', 'Provider isolation failed')
    proof = read(gateway, '/evidence')
    verify_audit(proof, [a,b], decision_id)
    return {'status':'PASS_LIVE_SELECTIVE_CONTAINMENT', 'decision_id': decision_id,
            'affected':a, 'unaffected':b, 'incident':incident, 'gateway_state':state, 'evidence':proof,
            'metrics': {'affected_post_incident_calls_denied':1, 'unaffected_post_incident_calls_allowed':1,
                        'affected_native_reviews':1, 'unaffected_automated_completions':1},
            'scope':'Two synthetic providers and cases; no external provider call or production availability claim.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='Write successful JSON evidence as UTF-8')
    args = parser.parse_args()
    with httpx.Client(base_url=os.environ.get('FLUXNOVA_URL', f.DEFAULT_ENGINE_URL),
                      auth=f.engine_auth_from_environment(), timeout=30, trust_env=False) as engine, \
         httpx.Client(base_url=os.environ.get('REVOKELINE_URL', f.DEFAULT_APP_URL),
                      timeout=30, trust_env=False) as gateway:
        result = run(engine, gateway, os.environ.get('FLUXNOVA_DECISION_ID', ''))
    output = json.dumps(result, indent=2, ensure_ascii=False) + '\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding='utf-8')
    print(json.dumps({'status': result['status'], 'decision_id': result['decision_id'],
                      'affected_instance':result['affected']['started']['process_instance']['id'],
                      'unaffected_instance':result['unaffected']['started']['process_instance']['id'],
                      'metrics':result['metrics'], 'event_count':len(result['evidence']['events']),
                      'evidence_file':str(args.output) if args.output else None}, indent=2))
    if not args.output:
        print(output)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(f'FAIL: {type(exc).__name__}: {exc}', file=sys.stderr)
        if isinstance(exc, httpx.HTTPStatusError):
            print(exc.response.text[:1500], file=sys.stderr)
        sys.exit(1)
