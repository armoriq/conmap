import asyncio
import queue

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request
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


@pytest.mark.asyncio
async def test_scan_progress_streaming(monkeypatch):
    class DummyQueue:
        def __init__(self):
            self.items = ["live-1"]

        def get(self, block=True, timeout=None):
            if self.items:
                return self.items.pop(0)
            raise queue.Empty

    history = ["hist-1"]
    unregister_calls = {"count": 0}

    def fake_register(include_history=True):
        return DummyQueue(), history

    def fake_unregister(progress_queue):
        unregister_calls["count"] += 1

    call_state = {"count": 0}

    async def fake_to_thread(func, *args, **kwargs):
        call_state["count"] += 1
        if call_state["count"] == 1:
            return func(*args, **kwargs)
        raise asyncio.CancelledError

    monkeypatch.setattr(api, "register_progress_listener", fake_register)
    monkeypatch.setattr(api, "unregister_progress_listener", fake_unregister)
    monkeypatch.setattr(api.asyncio, "to_thread", fake_to_thread)

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/scan-progress",
        "query_string": b"",
        "headers": [],
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    request = Request(scope, receive)
    response = await api.scan_progress(request)
    iterator = response.body_iterator
    first_chunk = await iterator.__anext__()
    assert "hist-1" in first_chunk
    second_chunk = await iterator.__anext__()
    assert "live-1" in second_chunk
    await iterator.aclose()

    assert unregister_calls["count"] == 1
