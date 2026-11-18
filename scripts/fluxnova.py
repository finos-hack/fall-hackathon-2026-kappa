"""Fluxnova REST adapter for REVOKELINE's synthetic demonstration.

Requires an actual Fluxnova engine at FLUXNOVA_URL, and a running REVOKELINE
FastAPI application at REVOKELINE_URL. Not an enterprise integration or IdP
revocation adapter. No remote calls occur at import time.
"""
import argparse
import json
import os
from pathlib import Path
import sys

import httpx

ROOT = Path(__file__).resolve().parents[1]
BPMN = ROOT / "process" / "kyc-incident-executable.bpmn"
PROCESS_KEY = "revokeline_kyc_v02"
TOPIC = "revokeline-kyc-authority"
DEFAULT_ENGINE_URL = "http://127.0.0.1:8080/engine-rest"
DEFAULT_APP_URL = "http://127.0.0.1:8000"
WORKER_ID = "revokeline-kappa-demo-worker"


def engine_auth_from_environment(environ=None):
    """Optional Basic auth for local Fluxnova; do not hardcode credentials."""
    env = os.environ if environ is None else environ
    username = env.get("FLUXNOVA_USERNAME")
    password = env.get("FLUXNOVA_PASSWORD")
    if bool(username) != bool(password):
        raise ValueError("Set both FLUXNOVA_USERNAME and FLUXNOVA_PASSWORD, or neither")
    return httpx.BasicAuth(username, password) if username else None


def probe(engine):
    """Read-only check; /engine alone does not prove write access."""
    details = {}
    for name, path in (("engine", "/engine"), ("deployments", "/deployment")):
        response = engine.get(path)
        details[name] = {
            "status": response.status_code,
            "www_authenticate": response.headers.get("www-authenticate"),
        }
    return details


def post_json(client, path, body):
    response = client.post(path, json=body)
    response.raise_for_status()
    return response.json() if response.content else {}


def deploy(engine):
    """Deploy an actual executable BPMN model; requires an accessible engine."""
    with BPMN.open("rb") as fh:
        response = engine.post(
            "/deployment/create",
            data={"deployment-name": "revokeline-kappa-v02", "enable-duplicate-filtering": "true"},
            files={"data": (BPMN.name, fh, "application/xml")},
        )
    response.raise_for_status()
    return response.json()


def start(engine, app, case_id, provider_id="external-kyc-provider"):
    """Create the local case first, then start a real Fluxnova process instance."""
    case = post_json(app, "/cases", {"case_id": case_id, "provider_id": provider_id})
    body = {"businessKey": case_id, "variables": {
        "case_id": {"value": case_id, "type": "String"},
        "provider_id": {"value": provider_id, "type": "String"},
        "grant_version": {"value": case["grant_version"], "type": "Integer"},
    }}
    # A failed process start leaves a local case: reset or use a new case ID.
    instance = post_json(engine, f"/process-definition/key/{PROCESS_KEY}/start", body)
    return {"case": case, "process_instance": instance}


def authorize_task(app, task):
    """Return a fail-closed decision; the guarded API is the only authority."""
    variables = task.get("variables") or {}
    required = ("case_id", "provider_id", "grant_version")
    if not all(name in variables and "value" in variables[name] for name in required):
        return False, "DENY_MISSING_TASK_VARIABLES"
    payload = {name: variables[name]["value"] for name in required}
    try:
        response = app.post("/tools/kyc-verify", json=payload)
        if response.status_code == 200 and response.json().get("decision") == "ALLOW":
            return True, "ALLOW"
        if response.status_code == 403:
            return False, "DENY"
        return False, f"DENY_AUTHORITY_ERROR_{response.status_code}"
    except (httpx.HTTPError, ValueError):
        return False, "DENY_AUTHORITY_UNAVAILABLE"


def work_once(engine, app):
    """Poll and complete up to five external tasks; returns the processed decisions."""
    request = {"workerId": WORKER_ID, "maxTasks": 5, "topics": [{
        "topicName": TOPIC,
        "lockDuration": 60000,
        "variables": ["case_id", "provider_id", "grant_version"],
    }]}
    tasks = post_json(engine, "/external-task/fetchAndLock", request)
    if not isinstance(tasks, list):
        raise TypeError("Fluxnova fetchAndLock did not return a list")
    results = []
    for task in tasks:
        allowed, decision = authorize_task(app, task)
        complete = {"workerId": WORKER_ID, "variables": {
            "authorized": {"value": allowed, "type": "Boolean"},
            "revokeline_decision": {"value": decision, "type": "String"},
        }}
        response = engine.post(f"/external-task/{task['id']}/complete", json=complete)
        response.raise_for_status()
        results.append({"task_id": task["id"], "process_instance_id": task.get("processInstanceId"),
                        "authorized": allowed, "decision": decision})
    return results


def inspect(engine, instance_id):
    tasks_response = engine.get("/task", params={"processInstanceId": instance_id})
    tasks_response.raise_for_status()
    tasks = tasks_response.json()
    process_response = engine.get(f"/process-instance/{instance_id}")
    if process_response.status_code == 404:
        # A completed process normally disappears from the runtime API.
        status = "NO_ACTIVE_INSTANCE_CHECK_HISTORY_FOR_COMPLETION"
    else:
        process_response.raise_for_status()
        status = "ACTIVE"
    return {"process_instance_id": instance_id, "status": status,
            "tasks": [{"id": t.get("id"), "taskDefinitionKey": t.get("taskDefinitionKey"),
                       "name": t.get("name")} for t in tasks],
            "human_review_pending": any(t.get("taskDefinitionKey") == "human_review" for t in tasks)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["probe", "deploy", "start", "work-once", "inspect", "incident", "reset"])
    parser.add_argument("--case-id", default="KYC-FLUX-041")
    parser.add_argument("--provider-id", default="external-kyc-provider")
    parser.add_argument("--instance-id", help="Required for inspect")
    parser.add_argument("--engine-url", default=os.environ.get("FLUXNOVA_URL", DEFAULT_ENGINE_URL))
    parser.add_argument("--app-url", default=os.environ.get("REVOKELINE_URL", DEFAULT_APP_URL))
    args = parser.parse_args(argv)
    # Local-first: proxy environment disabled. Basic auth is opt-in via environment.
    auth = engine_auth_from_environment()
    with httpx.Client(base_url=args.engine_url.rstrip("/"), timeout=20, trust_env=False, auth=auth) as engine, \
         httpx.Client(base_url=args.app_url.rstrip("/"), timeout=20, trust_env=False) as app:
        if args.command == "probe":
            result = probe(engine)
        elif args.command == "deploy":
            result = deploy(engine)
        elif args.command == "start":
            result = start(engine, app, args.case_id, args.provider_id)
        elif args.command == "work-once":
            result = work_once(engine, app)
        elif args.command == "inspect":
            if not args.instance_id:
                parser.error("--instance-id is required for inspect")
            result = inspect(engine, args.instance_id)
        elif args.command == "incident":
            result = post_json(app, "/incidents", {"provider_id": args.provider_id})
        else:
            result = post_json(app, "/demo/reset", {})
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except httpx.HTTPStatusError as exc:
        response = exc.response
        print(f"Fluxnova/REVOKELINE HTTP error: {response.status_code} {response.request.method} {response.request.url}", file=sys.stderr)
        print(f"Response body: {response.text[:1500]}", file=sys.stderr)
        sys.exit(2)
    except httpx.RequestError as exc:
        print(f"HTTP connection error ({type(exc).__name__}): {exc} for {exc.request.url}", file=sys.stderr)
        sys.exit(2)
