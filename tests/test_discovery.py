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
            paths=config.paths,
            is_target=False,
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
            paths=config.paths,
            is_target=False,
        )
    assert endpoint is None


@pytest.mark.asyncio
async def test_discover_mcp_endpoints_with_target_urls(monkeypatch):
    captured = []
    dummy_endpoint = McpEndpoint(
        address="direct.example.com",
        scheme="https",
        port=443,
        base_url="https://direct.example.com",
        probes=[],
        evidence=McpEvidence(),
    )

    async def fake_scan_base_url(**kwargs):
        base_url = kwargs["base_url"]
        captured.append(base_url)
        if base_url == "https://direct.example.com/":
            return dummy_endpoint
        return None

    called_networks = {"value": False}

    def fake_discover_networks(config):
        called_networks["value"] = True
        return []

    monkeypatch.setattr(discovery, "_scan_base_url", fake_scan_base_url)
    monkeypatch.setattr(discovery, "discover_networks", fake_discover_networks)

    config = ScanConfig(target_urls=["https://direct.example.com/", "direct.example.com"])
    endpoints, metadata = await discovery.discover_mcp_endpoints(config)

    assert called_networks["value"] is False
    assert captured == ["https://direct.example.com/"]
    assert metadata.mcp_endpoints == 1
    assert metadata.scanned_hosts == 1
    assert endpoints[0].base_url == "https://direct.example.com"


def test_normalize_target_url_variants():
    normalized = discovery._normalize_target_url("Example.COM:8080/api/mcp/")
    assert normalized is not None
    origin, is_https, dedupe_key = normalized
    assert origin == "http://example.com:8080/api/mcp/"
    assert is_https is False
    assert dedupe_key == "example.com:8080/api/mcp/"


def test_normalize_target_url_blank_returns_none():
    assert discovery._normalize_target_url("   ") is None
    assert discovery._normalize_target_url("") is None


def test_prepare_target_urls_prefers_https_and_deduplicates():
    urls = [
        "http://mixed.example.com",
        " https://mixed.example.com/ ",
        "https://mixed.example.com",  # duplicate
        "",
        "http://other.example.com",
        "http://other.example.com:8080",
        "HTTPS://Other.example.com:8080/",
    ]
    targets = discovery._prepare_target_urls(urls)
    assert targets == [
        "https://mixed.example.com/",
        "http://other.example.com/",
        "https://other.example.com:8080/",
    ]
