"""Offline contract tests; not proof of a deployed Fluxnova runtime."""
import xml.etree.ElementTree as ET
import httpx
from pathlib import Path
from scripts.fluxnova import BPMN, TOPIC, authorize_task, work_once, start


def task_fixture():
    return {"id": "task-1", "processInstanceId": "instance-1", "variables": {
        "case_id": {"value": "KYC-FLUX-041"},
        "provider_id": {"value": "external-kyc-provider"},
        "grant_version": {"value": 1},
    }}


def test_bpmn_executable_with_external_task_and_default_denial():
    root = ET.parse(BPMN).getroot()
    ns = {"b": "http://www.omg.org/spec/BPMN/20100524/MODEL"}
    proc = root.find("b:process", ns)
    assert proc.attrib["isExecutable"] == "true"
    service = root.find(".//b:serviceTask", ns)
    assert service.attrib["{http://camunda.org/schema/1.0/bpmn}type"] == "external"
    assert service.attrib["{http://camunda.org/schema/1.0/bpmn}topic"] == TOPIC
    gateway = root.find(".//b:exclusiveGateway", ns)
    assert gateway.attrib["default"] == "flow_deny"
    assert root.find(".//b:userTask", ns).attrib["id"] == "human_review"


def test_worker_denies_revoked_grant_and_completes_fluxnova_task():
    completed = []
    def app_handler(request):
        assert request.url.path == "/tools/kyc-verify"
        return httpx.Response(403, json={"detail": {"decision": "DENY"}})
    def engine_handler(request):
        if request.url.path.endswith("/fetchAndLock"):
            return httpx.Response(200, json=[task_fixture()])
        completed.append(request)
        return httpx.Response(204)
    with httpx.Client(transport=httpx.MockTransport(app_handler), base_url="http://app") as app, \
         httpx.Client(transport=httpx.MockTransport(engine_handler), base_url="http://engine") as engine:
        result = work_once(engine, app)
    assert result[0]["decision"] == "DENY"
    assert result[0]["authorized"] is False
    assert len(completed) == 1
    import json
    payload = json.loads(completed[0].content)
    assert payload["variables"]["authorized"] == {"value": False, "type": "Boolean"}


def test_worker_allows_valid_grant():
    def app_handler(request):
        return httpx.Response(200, json={"decision": "ALLOW"})
    def engine_handler(request):
        if request.url.path.endswith("/fetchAndLock"):
            return httpx.Response(200, json=[task_fixture()])
        return httpx.Response(204)
    with httpx.Client(transport=httpx.MockTransport(app_handler), base_url="http://app") as app, \
         httpx.Client(transport=httpx.MockTransport(engine_handler), base_url="http://engine") as engine:
        assert work_once(engine, app)[0]["authorized"] is True


def test_worker_fails_closed_if_authority_unavailable():
    def app_handler(request):
        raise httpx.ConnectError("simulated outage")
    with httpx.Client(transport=httpx.MockTransport(app_handler), base_url="http://app") as app:
        assert authorize_task(app, task_fixture()) == (False, "DENY_AUTHORITY_UNAVAILABLE")


def test_missing_task_variables_fails_closed():
    with httpx.Client(base_url="http://app") as app:
        assert authorize_task(app, {"variables": {}}) == (False, "DENY_MISSING_TASK_VARIABLES")


def test_start_process_passes_case_and_grant():
    seen = []
    def app_handler(request):
        seen.append(("app", request.url.path, request.content))
        return httpx.Response(201, json={"case_id": "KYC-FLUX-041", "provider_id": "external-kyc-provider", "grant_version": 1})
    def engine_handler(request):
        seen.append(("engine", request.url.path, request.content))
        return httpx.Response(200, json={"id": "inst-001"})
    with httpx.Client(transport=httpx.MockTransport(app_handler), base_url="http://app") as app, \
         httpx.Client(transport=httpx.MockTransport(engine_handler), base_url="http://engine") as engine:
        result = start(engine, app, "KYC-FLUX-041")
    assert result["process_instance"]["id"] == "inst-001"
    assert seen[0][0] == "app" and seen[1][0] == "engine"
    import json
    assert json.loads(seen[1][2])["variables"]["grant_version"]["value"] == 1
