import json
from fastapi.testclient import TestClient
from app.command_center import app
from scripts import recorded_assurance as ra
from test_control_assurance import fixtures
from test_selective_containment import engine_stub, gateway, DECISION
from scripts import selective_containment as sc
import pytest


def test_missing_evidence_not_pass(tmp_path):
    result=ra.report(tmp_path)
    assert result['status']=='INCOMPLETE_OR_INVALID'
    assert all(c['status']=='NOT_AVAILABLE' for c in result['checks'])
    assert result['production_readiness']=='BLOCKED'


def test_corrupt_export_not_pass(tmp_path):
    directory=tmp_path/'evidence'; directory.mkdir()
    (directory/'gate5-live-dmn.json').write_text('{bad')
    assert ra.report(tmp_path)['checks'][0]['status']=='FAIL'


def test_original_report_recalculated(tmp_path):
    e,m,a=fixtures(); directory=tmp_path/'evidence'; directory.mkdir()
    arch=tmp_path/'architectures';arch.mkdir()
    for path,data in [(directory/'gate5-live-dmn.json',e),(directory/'gate5-dmn-matrix.json',m),(arch/'revokeline.calm.json',a)]:
        path.write_text(json.dumps(data))
    r=ra.report(tmp_path)
    assert r['checks'][0]['status']=='PASS'
    assert r['status']=='INCOMPLETE_OR_INVALID'
    assert r['production_readiness']=='BLOCKED'
    assert len(r['ccc_assessments'])==4


def test_selective_history_rechecked(gateway):
    with engine_stub() as engine:
        result=sc.run(engine,gateway,DECISION)
    assert ra.selective(result,DECISION)
    result['unaffected']['history']['process']['state']='EXTERNALLY_TERMINATED'
    with pytest.raises(RuntimeError,match='automated completion'):
        ra.selective(result,DECISION)


def test_read_only_page_and_report(monkeypatch,tmp_path):
    original=ra.report
    monkeypatch.setattr(ra,'report',lambda:original(tmp_path))
    with TestClient(app) as c:
        assert c.get('/assurance').status_code==200
        assert 'Recorded control assurance' in c.get('/assurance').text
        assert c.get('/ui/assurance-report').json()['production_readiness']=='BLOCKED'
        assert c.get('/ui/assurance-report').json()['status']=='INCOMPLETE_OR_INVALID'
        assert c.post('/ui/assurance-report',headers={'x-revokeline-demo':'1'}).status_code==404
