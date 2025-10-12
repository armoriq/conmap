import asyncio

import httpx
import pytest

from conmap import discovery
from conmap.config import ScanConfig
from conmap.models import McpEndpoint, McpEvidence


@pytest.mark.asyncio
async def test_probe_single_path_success():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"tools": []}, headers={"Content-Type": "application/json"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        semaphore = asyncio.Semaphore(1)
        probe = await discovery._probe_single_path(
            semaphore,
            client,
            url="http://example.com/api/mcp",
            path="/api/mcp",
            timeout=1.0,
        )
    assert probe.status_code == 200
    assert probe.json_payload == {"tools": []}


@pytest.mark.asyncio
async def test_probe_single_path_error():
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        semaphore = asyncio.Semaphore(1)
        probe = await discovery._probe_single_path(
            semaphore,
            client,
            url="http://example.com/api/mcp",
            path="/api/mcp",
            timeout=1.0,
        )
    assert probe.error is not None


@pytest.mark.asyncio
async def test_scan_base_url_detects_mcp():
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, json={"model": {}}, headers={"X-MCP-Support": "1"})
        return httpx.Response(200, json={"tools": []})

    config = ScanConfig(paths=["/api/mcp"])
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        endpoint = await discovery._scan_base_url(
            semaphore=asyncio.Semaphore(5),
            client=client,
            base_url="http://example.com",
            config=config,
        )
    assert endpoint is not None
    assert endpoint.evidence.capability_paths == ["/api/mcp"]
    assert endpoint.evidence.headers["X-MCP-Support"] == "1"


@pytest.mark.asyncio
async def test_discover_mcp_endpoints(monkeypatch):
    dummy_endpoint = McpEndpoint(
        address="10.0.0.11",
        scheme="http",
        port=80,
        base_url="http://10.0.0.11",
        probes=[],
        evidence=McpEvidence(),
    )

    async def fake_scan(*args, **kwargs):
        return dummy_endpoint

    monkeypatch.setattr(
        discovery,
        "discover_networks",
        lambda config: [__import__("ipaddress").ip_network("10.0.0.0/30")],
    )
    monkeypatch.setattr(
        discovery, "iter_target_hosts", lambda network, include_self=False: ["10.0.0.11"]
    )
    monkeypatch.setattr(discovery, "build_candidate_urls", lambda host, ports: ["http://10.0.0.11"])
    monkeypatch.setattr(discovery, "_scan_base_url", lambda **kwargs: fake_scan())

    endpoints, metadata = await discovery.discover_mcp_endpoints(ScanConfig())
    assert metadata.mcp_endpoints == 1
    assert endpoints[0].base_url == "http://10.0.0.11"


@pytest.mark.asyncio
async def test_discover_mcp_endpoints_handles_none(monkeypatch):
    monkeypatch.setattr(
        discovery,
        "discover_networks",
        lambda config: [__import__("ipaddress").ip_network("10.0.0.0/30")],
    )
    monkeypatch.setattr(
        discovery, "iter_target_hosts", lambda network, include_self=False: ["10.0.0.12"]
    )
    monkeypatch.setattr(discovery, "build_candidate_urls", lambda host, ports: ["http://10.0.0.12"])

    async def fake_scan(*args, **kwargs):
        return None

    monkeypatch.setattr(discovery, "_scan_base_url", lambda **kwargs: fake_scan())
    endpoints, metadata = await discovery.discover_mcp_endpoints(ScanConfig())
    assert metadata.mcp_endpoints == 0
    assert endpoints == []


@pytest.mark.asyncio
async def test_scan_base_url_without_evidence():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="not found")

    config = ScanConfig(paths=["/api/mcp"])
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        endpoint = await discovery._scan_base_url(
            semaphore=asyncio.Semaphore(1),
            client=client,
            base_url="http://example.com",
            config=config,
        )
    assert endpoint is None
