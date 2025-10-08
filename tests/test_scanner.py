import pytest

from conmap.config import ScanConfig
from conmap.models import (
    McpEndpoint,
    McpEvidence,
    ScanMetadata,
    ScanResult,
    Severity,
    Vulnerability,
)
from conmap.scanner import scan, scan_async


@pytest.mark.asyncio
async def test_scan_async_aggregates(monkeypatch):
    endpoint = McpEndpoint(
        address="10.0.0.8",
        scheme="http",
        port=80,
        base_url="http://10.0.0.8",
        probes=[],
        evidence=McpEvidence(),
    )
    metadata = ScanMetadata(
        scanned_hosts=1, reachable_hosts=1, mcp_endpoints=1, duration_seconds=0.2
    )

    async def fake_discover(config):
        return [endpoint], metadata

    def fake_schema(endpoints):
        return [
            Vulnerability(
                endpoint=endpoints[0].base_url,
                component="tool:demo",
                category="schema.test",
                severity=Severity.low,
                message="schema",
                evidence={},
            )
        ]

    def fake_chain(endpoints):
        return []

    def fake_llm(endpoints, cache, enabled=True):
        return []

    monkeypatch.setattr("conmap.scanner.discover_mcp_endpoints", fake_discover)
    monkeypatch.setattr("conmap.scanner.run_schema_inspector", fake_schema)
    monkeypatch.setattr("conmap.scanner.run_chain_detector", fake_chain)
    monkeypatch.setattr("conmap.scanner.run_llm_analyzer", fake_llm)

    config = ScanConfig()
    result = await scan_async(config)
    assert isinstance(result, ScanResult)
    assert result.metadata.mcp_endpoints == 1
    assert result.vulnerabilities[0].category == "schema.test"


def test_scan_sync(monkeypatch):
    expected = ScanResult(
        metadata=ScanMetadata(
            scanned_hosts=0, reachable_hosts=0, mcp_endpoints=0, duration_seconds=0
        ),
        endpoints=[],
        vulnerabilities=[],
    )

    async def fake_scan_async(config):
        return expected

    monkeypatch.setattr("conmap.scanner.scan_async", fake_scan_async)
    result = scan(ScanConfig())
    assert result == expected


@pytest.mark.asyncio
async def test_scan_async_uses_cache_path(monkeypatch):
    config = ScanConfig(cache_path="/tmp/cache.json")

    async def fake_discover(config):
        return [], ScanMetadata()

    monkeypatch.setattr("conmap.scanner.discover_mcp_endpoints", fake_discover)
    monkeypatch.setattr("conmap.scanner.run_schema_inspector", lambda endpoints: [])
    monkeypatch.setattr("conmap.scanner.run_chain_detector", lambda endpoints: [])
    monkeypatch.setattr("conmap.scanner.run_llm_analyzer", lambda endpoints, cache, enabled: [])

    calls = {}

    class DummyCache:
        def __init__(self, path=None, maxsize=256):
            calls["path"] = path

    monkeypatch.setattr("conmap.scanner.Cache", DummyCache)
    result = await scan_async(config)
    assert result.endpoints == []
    assert calls["path"] == "/tmp/cache.json"
