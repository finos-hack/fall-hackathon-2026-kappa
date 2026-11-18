"""Auth configuration and read-only probe tests (no external runtime required)."""
import httpx
import pytest

from scripts.fluxnova import engine_auth_from_environment, probe


def test_default_has_no_auth():
    assert engine_auth_from_environment({}) is None


def test_partial_credentials_are_rejected():
    with pytest.raises(ValueError, match="both"):
        engine_auth_from_environment({"FLUXNOVA_USERNAME": "demo"})


def test_basic_auth_is_sent_only_when_configured():
    captured = []
    def handler(request):
        captured.append(request.headers.get("authorization"))
        return httpx.Response(200, json=[])
    auth = engine_auth_from_environment({"FLUXNOVA_USERNAME": "demo", "FLUXNOVA_PASSWORD": "demo"})
    with httpx.Client(transport=httpx.MockTransport(handler), base_url="http://engine", auth=auth) as client:
        response = client.get("/deployment")
        assert response.status_code == 200
    assert captured == ["Basic ZGVtbzpkZW1v"]


def test_probe_reports_401_and_challenge():
    def handler(request):
        if request.url.path == "/engine":
            return httpx.Response(200, json=[{"name": "default"}])
        return httpx.Response(401, headers={"WWW-Authenticate": 'Basic realm="Fluxnova"'})
    with httpx.Client(transport=httpx.MockTransport(handler), base_url="http://engine") as client:
        result = probe(client)
    assert result["engine"]["status"] == 200
    assert result["deployments"]["status"] == 401
    assert result["deployments"]["www_authenticate"] == 'Basic realm="Fluxnova"'
