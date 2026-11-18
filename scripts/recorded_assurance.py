"""Read-only inspection of recorded evidence; never drives live services."""
from scripts.control_assurance import assess, read, ROOT
from scripts.selective_containment import verify_audit, PROVIDERS
from scripts.policy_outage import verify as verify_outage
from scripts.fluxnova_targeted_demo import require


def selective(report, decision_id):
    require(report['status']=='PASS_LIVE_SELECTIVE_CONTAINMENT' and report['decision_id']==decision_id,'Unexpected selective report or policy')
    a,b=report['affected'],report['unaffected']
    require(a['payload']['provider_id']==PROVIDERS[0] and b['payload']['provider_id']==PROVIDERS[1], 'Provider mismatch')
    verify_audit(report['evidence'],[a,b],decision_id)
    ai,bi=(e['started']['process_instance']['id'] for e in (a,b))
    require(ai!=bi,'Expected separate instances')
    for entry,status in ((a,403),(b,200)):
        require(entry['before']['status']==200 and entry['before']['response']['decision']=='ALLOW' and entry['after']['gateway']['status']==status and entry['after']['lock_status']==entry['after']['complete_status']==204,'HTTP or task correlation mismatch')
    require(a['after']['gateway']['response']['detail']['decision']=='DENY' and b['after']['gateway']['response']['decision']=='ALLOW','Decision mismatch')
    inspection=a['inspect']; history=b['history']['process']
    require(inspection['process_instance_id']==ai and inspection['status']=='ACTIVE' and inspection['human_review_pending'] is True and any(t['id'] and t['taskDefinitionKey']=='human_review' for t in inspection['tasks']),'Missing recorded native review')
    require(history['id']==bi and history['state']=='COMPLETED' and history['endTime'] and any(t['processInstanceId']==bi and t['activityId']=='end_auto' and t['endTime'] and not t.get('canceled',False) for t in b['history']['automated_end_activities']),'Missing recorded automated completion')
    return 'Affected: DENY and native review. Unaffected: ALLOW and recorded automated completion. Seven event hashes verified.'


def report(root=ROOT):
    directory=root/'evidence'; checks=[]; controls=[]; decision_id=None
    def check(name,filename,fn):
        try:
            result=fn(read(directory/filename))
            checks.append({'name':name,'status':'PASS','detail':result})
        except FileNotFoundError:
            checks.append({'name':name,'status':'NOT_AVAILABLE','detail':f'{filename} or a required input is missing.'})
        except (OSError,ValueError,RuntimeError,KeyError,TypeError,IndexError,AttributeError) as exc:
            checks.append({'name':name,'status':'FAIL','detail':str(exc)})
    def original(export):
        nonlocal decision_id,controls
        matrix=read(directory/'gate5-dmn-matrix.json')
        decision_id=matrix['decision_id']
        result=assess(export,matrix,decision_id,read(root/'architectures/revokeline.calm.json'))
        controls=result['ccc_assessments']
        require(result['status']=='PASS_SCOPED_DEMO_ASSURANCE', 'One or more original assurance checks failed')
        return 'Four hashes, native human review and all 16 policy combinations verified.'
    check('Incident response & DMN matrix','gate5-live-dmn.json',original)
    check('Selective containment','selective-containment.json',lambda e: selective(e,decision_id))
    check('Policy engine outage','policy-outage.json',lambda e: verify_outage(e,decision_id))
    return {'checks':checks,'ccc_assessments':controls,'production_readiness':'BLOCKED',
            'status':'VERIFIED_RECORDED_SCENARIOS' if all(c['status']=='PASS' for c in checks) else 'INCOMPLETE_OR_INVALID',
            'scope':'Recorded local evidence, checked offline. No live service status, independent attestation or CCC certification.'}
