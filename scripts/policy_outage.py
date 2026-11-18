"""Check the gateway through a real stop/start of a dedicated local policy engine.
The operator stops and starts Fluxnova in a second terminal; this script does not
manage containers. Keep the gateway running and do not run other demos.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import time
import uuid

import httpx
from app.policy_dmn import evaluate, INPUTS
from scripts import fluxnova as f
from scripts.control_assurance import digest
from scripts.fluxnova_targeted_demo import read, require


def verify(report, decision_id):
    require(report['decision_id'] == decision_id and report['status'] == 'PASS_LIVE_POLICY_OUTAGE', 'Unexpected report or definition')
    payload = report['payload']
    case, provider, grant = (payload[k] for k in ('case_id', 'provider_id', 'grant_version'))
    require(report['engine_before'] == report['engine_after'] == 'ALLOW' and report['engine_outage']['transport_error'] in ('ConnectError', 'ConnectTimeout', 'ReadTimeout', 'ReadError', 'RemoteProtocolError', 'PoolTimeout', 'WriteError', 'WriteTimeout'), 'Missing engine availability evidence')
    for state in report['states']:
        require(state['providers'][provider] == {'status':'ACTIVE','version':grant} and state['cases'][case] == {**payload,'route':'AUTOMATED_VERIFICATION'}, 'Case or provider changed during outage')
    require(len(report['states']) == 3, 'Expected three state snapshots')
    calls = report['calls']
    require([c['status'] for c in calls] == [200,503,200], 'Expected HTTP 200/503/200')
    for c in (calls[0],calls[2]):
        require(c['response'].get('decision') == 'ALLOW' and c['response'].get('synthetic_result') == 'DOCUMENT_CHECK_COMPLETED', 'Missing successful synthetic call')
    require(calls[1]['response'].get('detail') == {'decision':'DENY','reason':'policy_unavailable_or_invalid'}, 'Missing explicit fail-closed response')
    proof = report['evidence']; events = proof['events']; prev = '0'*64
    require(proof['valid'] is True and len(events) == 4, 'Expected four audit events')
    for i,event in enumerate(events,1):
        require(event['sequence'] == i and event['previous_hash'] == prev and event['hash'] == digest({k:v for k,v in event.items() if k!='hash'}), 'Invalid outage evidence hash')
        prev = event['hash']
    require(prev == proof['tip_hash'], 'Outage evidence tip mismatch')
    require([e['kind'] for e in events] == ['CASE_STARTED'] + ['TOOL_CALL_DECISION']*3 and events[0]['data']['case_id'] == case, 'Unexpected outage event sequence')
    for index,event in enumerate(events[1:]):
        row=event['data']; policy=row['policy']
        require(all(row[k]==v for k,v in payload.items()) and row['provider_version']==grant, 'Outage event identity mismatch')
        require(row['decision'] == ('DENY' if index==1 else 'ALLOW') and policy['engine']=='FLUXNOVA_DMN', 'Unexpected gateway decision')
        if index==1:
            require(policy.get('status')=='UNAVAILABLE_OR_INVALID', 'Missing policy failure audit')
        else:
            require(policy['definition_id']==decision_id and policy['decision']=='ALLOW' and policy['facts']==dict.fromkeys(INPUTS,True), 'Unexpected healthy DMN evaluation')
    return 'Same grant: ALLOW / DENY (503) / ALLOW; provider remained active; four audit events verified.'


def wait_for_policy(engine, decision_id, facts, timeout=120, interval=2):
    """Wait for the pinned policy itself, not just the container or /engine."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            decision = evaluate(engine, decision_id, facts)
        except httpx.TransportError as exc:
            last_error = exc
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code not in (502, 503, 504):
                raise
            last_error = exc
        else:
            require(decision == 'ALLOW', 'Healthy pinned policy did not allow')
            return decision
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError(f'Pinned DMN not ready after {timeout}s: {last_error}') from last_error
        print(f'Waiting for pinned DMN: {type(last_error).__name__}; retrying...', flush=True)
        time.sleep(min(interval, remaining))


def run(engine, gateway, decision_id, interrupt, restore):
    require(bool(decision_id),'Set FLUXNOVA_DECISION_ID')
    facts=dict.fromkeys(INPUTS,True)
    before=wait_for_policy(engine,decision_id,facts)
    read(gateway,'/health'); f.post_json(gateway,'/demo/reset',{})
    case=f.post_json(gateway,'/cases',{'case_id':'KYC-OUTAGE-'+uuid.uuid4().hex[:10]})
    payload={k:case[k] for k in ('case_id','provider_id','grant_version')}
    def call():
        r=gateway.post('/tools/kyc-verify',json=payload)
        return {'status':r.status_code,'response':r.json()}
    calls=[call()]; states=[read(gateway,'/demo/state')]
    require(calls[0]['status']==200 and calls[0]['response'].get('decision')=='ALLOW','Baseline ALLOW missing; check gateway DMN mode')
    # Check baseline is actually DMN before asking operator to stop anything.
    baseline=read(gateway,'/evidence')['events'][-1]['data']['policy']
    require(baseline['engine']=='FLUXNOVA_DMN' and baseline['definition_id']==decision_id,'Gateway policy mismatch')
    print('Baseline: HTTP 200 ALLOW',flush=True)
    try:
        interrupt()
        try:
            evaluate(engine,decision_id,facts)
        except httpx.TransportError as exc:
            unavailable={'transport_error':type(exc).__name__}
        else:
            raise RuntimeError('Engine still reachable; no transport outage observed')
        calls.append(call()); states.append(read(gateway,'/demo/state'))
        require(calls[-1]['status']==503 and calls[-1]['response'].get('detail')=={'decision':'DENY','reason':'policy_unavailable_or_invalid'},'Expected fail-closed HTTP 503, not incident denial')
        print('During outage: HTTP 503 DENY',flush=True)
    finally:
        restore()
    after=wait_for_policy(engine,decision_id,facts)
    calls.append(call()); states.append(read(gateway,'/demo/state'))
    result={'status':'PASS_LIVE_POLICY_OUTAGE','decision_id':decision_id,'payload':payload,
            'engine_before':before,'engine_outage':unavailable,'engine_after':after,
            'calls':calls,'states':states,'evidence':read(gateway,'/evidence'),
            'scope':'Dedicated local Fluxnova REST outage (BPMN also unavailable). Gateway stays up. No real provider calls or workflow availability guarantee.'}
    verify(result,decision_id)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    print('Dedicated demo only. Resets synthetic gateway data. Existing Fluxnova instances are not deleted.')
    print('Use a second terminal to stop/start the existing container; never remove it.')
    def interrupt():
        input('Stop Fluxnova (docker stop revokeline-fluxnova), then press Enter here: ')
    def restore():
        input('Start Fluxnova (docker start revokeline-fluxnova), then press Enter here (the script will wait for DMN readiness): ')
    with httpx.Client(base_url=os.environ.get('FLUXNOVA_URL',f.DEFAULT_ENGINE_URL),auth=f.engine_auth_from_environment(),timeout=6,trust_env=False,limits=httpx.Limits(max_keepalive_connections=0)) as engine, httpx.Client(base_url=os.environ.get('REVOKELINE_URL',f.DEFAULT_APP_URL),timeout=20,trust_env=False) as gateway:
        result=run(engine,gateway,os.environ.get('FLUXNOVA_DECISION_ID',''),interrupt,restore)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    print(json.dumps({'status':result['status'],'http_statuses':[x['status'] for x in result['calls']], 'event_count':len(result['evidence']['events']), 'evidence_file':str(a.output)},indent=2))

if __name__=='__main__':
    try:
        main()
    except (Exception,KeyboardInterrupt) as exc:
        print(f'FAIL: {type(exc).__name__}: {exc}. Ensure Fluxnova is restarted.',file=sys.stderr)
        sys.exit(1)
