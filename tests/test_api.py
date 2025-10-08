from fastapi.testclient import TestClient

import conmap.api as api
from conmap.api import app
from conmap.models import (
    McpEndpoint,
    McpEvidence,
    ScanMetadata,
    ScanResult,
    Severity,
    Vulnerability,
)


def build_result() -> ScanResult:
    endpoint = McpEndpoint(
        address="10.0.0.10",
        scheme="http",
        port=80,
        base_url="http://10.0.0.10",
        probes=[],
        evidence=McpEvidence(),
    )
    metadata = ScanMetadata(
        scanned_hosts=1, reachable_hosts=1, mcp_endpoints=1, duration_seconds=0.5
    )
    vuln = Vulnerability(
        endpoint=endpoint.base_url,
        component="tool",
        category="schema.issue",
        severity=Severity.medium,
        message="Something",
        evidence={},
    )
    return ScanResult(metadata=metadata, endpoints=[endpoint], vulnerabilities=[vuln])


def test_health_endpoint():
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_scan_endpoint(monkeypatch):
    async def fake_scan(config):
        return build_result()

    monkeypatch.setattr(api, "scan_async", fake_scan)
    client = TestClient(app)
    response = client.post("/scan", json={"subnet": "10.0.0.0/30"})
    assert response.status_code == 200
    data = response.json()
    assert data["metadata"]["mcp_endpoints"] == 1
    assert data["vulnerabilities"][0]["category"] == "schema.issue"


def test_scan_endpoint_invalid_config(monkeypatch):
    class DummyConfig(api.ScanConfig):  # type: ignore[misc]
        @classmethod
        def from_env(cls):
            raise ValueError("bad config")

    monkeypatch.setattr(api, "ScanConfig", DummyConfig)
    client = TestClient(app)
    response = client.post("/scan", json={})
    assert response.status_code == 400
