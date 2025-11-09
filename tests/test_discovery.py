import asyncio

import httpx
import pytest

from conmap import discovery
from conmap.config import ScanConfig
from conmap.models import McpEvidence


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
    from conmap.models import McpEndpoint

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
    from conmap.models import McpEndpoint

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
        "https://mixed.example.com",
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


@pytest.mark.asyncio
async def test_probe_jsonrpc_with_session():
    call_count = {"get": 0, "post": 0}
    session_id = "test-session-abc123"

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            call_count["get"] += 1
            return httpx.Response(
                200, headers={"mcp-session-id": session_id}, json={"status": "ok"}
            )
        elif request.method == "POST":
            call_count["post"] += 1
            assert request.headers.get("mcp-session-id") == session_id
            body = request.read()
            import json

            data = json.loads(body)
            method = data.get("method")

            if method == "initialize":
                return httpx.Response(
                    200,
                    headers={"content-type": "text/event-stream"},
                    text='data: {"jsonrpc":"2.0","id":"conmap-initialize","result":{"protocolVersion":"2024-11-05"}}\n\n',
                )
            elif method == "tools/list":
                return httpx.Response(
                    200,
                    headers={"content-type": "text/event-stream"},
                    text='data: {"jsonrpc":"2.0","id":"conmap-tools/list","result":{"tools":[]}}\n\n',
                )
            else:
                return httpx.Response(
                    200,
                    headers={"content-type": "application/json"},
                    json={"jsonrpc": "2.0", "id": data.get("id"), "result": {}},
                )
        return httpx.Response(404)

    config = ScanConfig(rpc_methods=["initialize", "tools/list"])
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        probes = []
        evidence = McpEvidence()
        result = await discovery._probe_jsonrpc(
            semaphore=asyncio.Semaphore(5),
            client=client,
            base_url="http://example.com",
            config=config,
            probes=probes,
            evidence=evidence,
            methods=config.rpc_methods,
        )

    assert call_count["get"] == 1
    assert call_count["post"] == 2
    assert result is True
    assert len(probes) == 2


@pytest.mark.asyncio
async def test_probe_jsonrpc_without_session():
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"status": "ok"})
        elif request.method == "POST":
            body = request.read()
            import json

            data = json.loads(body)
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                json={"jsonrpc": "2.0", "id": data.get("id"), "result": {}},
            )
        return httpx.Response(404)

    config = ScanConfig(rpc_methods=["initialize"])
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        probes = []
        evidence = McpEvidence()
        result = await discovery._probe_jsonrpc(
            semaphore=asyncio.Semaphore(5),
            client=client,
            base_url="http://example.com",
            config=config,
            probes=probes,
            evidence=evidence,
            methods=config.rpc_methods,
        )

    assert len(probes) == 1
    assert result is True


@pytest.mark.asyncio
async def test_probe_jsonrpc_single_with_session():
    session_id = "test-session-xyz"

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("mcp-session-id") == session_id
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"jsonrpc": "2.0", "id": "test-1", "result": {"tools": []}},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        probe = await discovery._probe_jsonrpc_single(
            semaphore=asyncio.Semaphore(1),
            client=client,
            url="http://example.com/api/mcp",
            method="tools/list",
            payload={"jsonrpc": "2.0", "method": "tools/list", "id": "test-1", "params": {}},
            timeout=5.0,
            session_id=session_id,
        )

    assert probe.status_code == 200
    assert probe.json_payload is not None
    assert "result" in probe.json_payload


@pytest.mark.asyncio
async def test_probe_jsonrpc_single_sse_response():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            text='data: {"jsonrpc":"2.0","id":"test-1","result":{"tools":[{"name":"test"}]}}\n\n',
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        probe = await discovery._probe_jsonrpc_single(
            semaphore=asyncio.Semaphore(1),
            client=client,
            url="http://example.com/api/mcp",
            method="tools/list",
            payload={"jsonrpc": "2.0", "method": "tools/list", "id": "test-1"},
            timeout=5.0,
            session_id="test-session",
        )

    assert probe.status_code == 200
    assert probe.json_payload is not None
    assert probe.json_payload.get("result", {}).get("tools") == [{"name": "test"}]


@pytest.mark.asyncio
async def test_probe_jsonrpc_detects_errors():
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, headers={"mcp-session-id": "session-123"})
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={
                "jsonrpc": "2.0",
                "id": "conmap-tools/list",
                "error": {"code": -32602, "message": "Invalid params"},
            },
        )

    config = ScanConfig(rpc_methods=["tools/list"])
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        probes = []
        evidence = McpEvidence()
        result = await discovery._probe_jsonrpc(
            semaphore=asyncio.Semaphore(5),
            client=client,
            base_url="http://example.com",
            config=config,
            probes=probes,
            evidence=evidence,
            methods=config.rpc_methods,
        )

    assert result is False


def test_parse_sse_response():
    sse_text = 'data: {"jsonrpc":"2.0","id":"1","result":{"tools":[]}}\n\n'
    result = discovery._parse_sse_response(sse_text)
    assert result == {"jsonrpc": "2.0", "id": "1", "result": {"tools": []}}

    assert discovery._parse_sse_response("") is None

    json_text = '{"test": "value"}'
    result = discovery._parse_sse_response(json_text)
    assert result == {"test": "value"}


@pytest.mark.asyncio
async def test_establish_sse_session():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"mcp-session-id": "session-abc-123"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        session_id = await discovery._establish_sse_session(
            client=client, url="http://example.com/api/mcp", timeout=5.0
        )

    assert session_id == "session-abc-123"


@pytest.mark.asyncio
async def test_establish_sse_session_timeout():
    async def handler(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(10)
        return httpx.Response(200)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        session_id = await discovery._establish_sse_session(
            client=client, url="http://example.com/api/mcp", timeout=0.1
        )

    assert session_id is None
