from fastapi.testclient import TestClient

import conmap.api as api
from conmap.api import app
from conmap.logging import publish_progress_message
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
    seen = {}

    async def fake_scan(config):
        seen["analysis_depth"] = config.analysis_depth
        seen["enable_llm_analysis"] = config.enable_llm_analysis
        seen["target_urls"] = config.target_urls
        seen["llm_batch_size"] = config.llm_batch_size
        return build_result()

    monkeypatch.setattr(api, "scan_async", fake_scan)
    client = TestClient(app)
    response = client.post(
        "/scan",
        json={
            "subnet": "10.0.0.0/30",
            "analysis_depth": "deep",
            "enable_ai": True,
            "url": "https://mcp.example.com",
            "llm_batch_size": 7,
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["metadata"]["mcp_endpoints"] == 1
    assert data["vulnerabilities"][0]["category"] == "schema.issue"
    assert seen["analysis_depth"] == "deep"
    assert seen["enable_llm_analysis"] is True
    assert seen["target_urls"] == ["https://mcp.example.com"]
    assert seen["llm_batch_size"] == 7


def test_scan_endpoint_invalid_config(monkeypatch):
    class DummyConfig(api.ScanConfig):  # type: ignore[misc]
        @classmethod
        def from_env(cls):
            raise ValueError("bad config")

    monkeypatch.setattr(api, "ScanConfig", DummyConfig)
    client = TestClient(app)
    response = client.post("/scan", json={})
    assert response.status_code == 400


def test_scan_progress_peek_returns_backlog():
    client = TestClient(app)
    backlog_marker = "test-backlog-progress"
    live_marker = "test-live-progress"

    publish_progress_message(backlog_marker)

    response = client.get("/scan-progress?peek=1")
    assert response.status_code == 200
    messages = response.json()["messages"]
    assert backlog_marker in messages

    publish_progress_message(live_marker)

    response = client.get("/scan-progress?peek=1")
    assert response.status_code == 200
    messages = response.json()["messages"]
    assert backlog_marker in messages
    assert live_marker in messages
