import json
from pathlib import Path
import pytest
from scripts.compare_policy import compare

EXPORT = Path(__file__).resolve().parents[1] / 'evidence' / 'gate5-live-dmn.json'
DECISION = '618d4f37-e347-11f1-9fac-76863b3dbd01'

def test_saved_live_export_comparison():
    raw = json.loads(EXPORT.read_text(encoding='utf-8'))
    result = compare(raw['steps']['evidence'], DECISION)
    assert result['status'] == 'PASS_CACHED_BASELINE_COMPARISON'
    assert result['matched_post_incident_calls'] == 1
    assert result['observed_gateway_unsafe_allows'] == 0

def test_saved_live_export_modified_event_rejected():
    raw = json.loads(EXPORT.read_text(encoding='utf-8'))
    proof = raw['steps']['evidence']
    proof['events'][-1]['data']['decision'] = 'ALLOW'
    with pytest.raises(ValueError, match='hash chain invalid'):
        compare(proof, DECISION)
