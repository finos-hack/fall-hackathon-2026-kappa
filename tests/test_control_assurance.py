import copy
import itertools
from scripts.control_assurance import assess, read, ROOT, FACTS

ID = '618d4f37-e347-11f1-9fac-76863b3dbd01'

def fixtures():
    e = read(ROOT/'evidence/gate5-live-dmn.json')
    a = read(ROOT/'architectures/revokeline.calm.json')
    # Synthetic matrix fixture for local tests, not a saved live artifact.
    rows = []
    for values in itertools.product((False, True), repeat=4):
        d = 'ALLOW' if all(values) else 'DENY'
        rows.append(dict(facts=dict(zip(FACTS,values)),expected=d,observed=d,**{'pass':True}))
    return e,dict(decision_id=ID,rows=rows,passed=16,total=16),a

def run(e,m,a):
    return assess(e,m,ID,a)

def test_valid_scope_not_production():
    e,m,a=fixtures(); r=run(e,m,a)
    assert r['status']=='PASS_SCOPED_DEMO_ASSURANCE' and r['production_readiness']=='BLOCKED'
    assert r['ccc_assessments'][0]['status']=='FAIL'

def test_tamper_rejected():
    e,m,a=fixtures(); e['steps']['evidence']['events'][-1]['data']['decision']='ALLOW'
    assert run(e,m,a)['status']=='FAIL_SCOPED_DEMO_ASSURANCE'

def test_missing_human_review_rejected():
    e,m,a=fixtures(); e['steps']['inspect']['tasks']=[]
    assert run(e,m,a)['status']=='FAIL_SCOPED_DEMO_ASSURANCE'

def test_duplicate_matrix_rejected():
    e,m,a=fixtures(); m['rows'][0]=copy.deepcopy(m['rows'][1])
    assert run(e,m,a)['status']=='FAIL_SCOPED_DEMO_ASSURANCE'

def test_wrong_policy_rejected():
    e,m,a=fixtures(); m['decision_id']='foreign'
    assert run(e,m,a)['status']=='FAIL_SCOPED_DEMO_ASSURANCE'

def test_http_status_mismatch_rejected():
    e,m,a=fixtures(); e['steps']['after']['status']=200
    assert run(e,m,a)['status']=='FAIL_SCOPED_DEMO_ASSURANCE'
