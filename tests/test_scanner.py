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
                detection_source="static",
            )
        ]

    def fake_chain(endpoints):
        return []

    def fake_llm(endpoints, cache, enabled=True, batch_size=5):
        return []

    monkeypatch.setattr("conmap.scanner.discover_mcp_endpoints", fake_discover)
    monkeypatch.setattr("conmap.scanner.run_schema_inspector", fake_schema)
    monkeypatch.setattr("conmap.scanner.run_chain_detector", fake_chain)
    monkeypatch.setattr("conmap.scanner.run_safe_mcp_detector", lambda endpoints: [])
    monkeypatch.setattr("conmap.scanner.run_llm_analyzer", fake_llm)

    config = ScanConfig()
    result = await scan_async(config)
    assert isinstance(result, ScanResult)
    assert result.metadata.mcp_endpoints == 1
    assert result.vulnerabilities[0].category == "schema.test"
    assert result.enhanced_vulnerabilities == result.vulnerabilities
    assert result.chain_attacks_detected == 0
    assert result.analysis_depth == "standard"
    assert result.safe_mcp_techniques_total >= 20
    assert result.safe_mcp_techniques_detected == 0
    assert result.safe_mcp_technique_details == []
    assert result.vulnerability_score == 5.0
    assert result.severity_level == "safe"


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
    assert expected.vulnerability_score is None
    assert expected.severity_level is None


@pytest.mark.asyncio
async def test_scan_async_uses_cache_path(monkeypatch):
    config = ScanConfig(cache_path="/tmp/cache.json")

    async def fake_discover(config):
        return [], ScanMetadata()

    monkeypatch.setattr("conmap.scanner.discover_mcp_endpoints", fake_discover)
    monkeypatch.setattr("conmap.scanner.run_schema_inspector", lambda endpoints: [])
    monkeypatch.setattr("conmap.scanner.run_chain_detector", lambda endpoints: [])
    monkeypatch.setattr("conmap.scanner.run_safe_mcp_detector", lambda endpoints: [])
    monkeypatch.setattr(
        "conmap.scanner.run_llm_analyzer",
        lambda endpoints, cache, enabled, batch_size=5: [],
    )

    calls = {}

    class DummyCache:
        def __init__(self, path=None, maxsize=256):
            calls["path"] = path

    monkeypatch.setattr("conmap.scanner.Cache", DummyCache)
    result = await scan_async(config)
    assert result.endpoints == []
    assert calls["path"] == "/tmp/cache.json"
    assert result.analysis_depth == "standard"
    assert result.safe_mcp_techniques_detected == 0
    assert result.safe_mcp_technique_details == []
    assert result.vulnerability_score == 0.0
    assert result.severity_level == "safe"


@pytest.mark.asyncio
async def test_scan_async_basic_depth(monkeypatch):
    config = ScanConfig(analysis_depth="basic", enable_llm_analysis=False)

    markers = {"schema": 0, "chain": 0, "llm": 0}

    async def fake_discover(conf):
        return [], ScanMetadata()

    def fake_schema(endpoints):
        markers["schema"] += 1
        return []

    def fake_chain(endpoints):
        markers["chain"] += 1
        return []

    def fake_llm(endpoints, cache, enabled, batch_size=5):
        markers["llm"] += 1
        assert enabled is False
        return []

    monkeypatch.setattr("conmap.scanner.discover_mcp_endpoints", fake_discover)
    monkeypatch.setattr("conmap.scanner.run_schema_inspector", fake_schema)
    monkeypatch.setattr("conmap.scanner.run_chain_detector", fake_chain)
    monkeypatch.setattr("conmap.scanner.run_safe_mcp_detector", lambda endpoints: [])
    monkeypatch.setattr("conmap.scanner.run_llm_analyzer", fake_llm)

    result = await scan_async(config)
    assert result.analysis_depth == "basic"
    assert markers["schema"] == 0
    assert markers["chain"] == 0
    assert markers["llm"] == 1


@pytest.mark.asyncio
async def test_scan_async_safe_mcp_summary(monkeypatch):
    endpoint = McpEndpoint(
        address="10.0.0.88",
        scheme="https",
        port=443,
        base_url="https://10.0.0.88",
        probes=[],
        evidence=McpEvidence(),
    )
    metadata = ScanMetadata(
        scanned_hosts=1, reachable_hosts=1, mcp_endpoints=1, duration_seconds=0.1
    )

    async def fake_discover(config):
        return [endpoint], metadata

    monkeypatch.setattr("conmap.scanner.discover_mcp_endpoints", fake_discover)
    monkeypatch.setattr("conmap.scanner.run_schema_inspector", lambda endpoints: [])
    monkeypatch.setattr("conmap.scanner.run_chain_detector", lambda endpoints: [])
    monkeypatch.setattr(
        "conmap.scanner.run_llm_analyzer",
        lambda endpoints, cache, enabled, batch_size=5: [],
    )

    safe_mcp_finding = Vulnerability(
        endpoint=endpoint.base_url,
        component="tool:exec",
        category="safe_mcp.safe-t1101",
        severity=Severity.critical,
        message="test",
        evidence={"technique": "SAFE-T1101"},
        mitigation="",
        detection_source="static",
    )

    monkeypatch.setattr(
        "conmap.scanner.run_safe_mcp_detector",
        lambda endpoints: [safe_mcp_finding],
    )

    result = await scan_async(ScanConfig())
    assert result.safe_mcp_techniques_detected == 1
    assert result.safe_mcp_techniques_total >= 21
    assert len(result.safe_mcp_technique_details) == 1
    detail = result.safe_mcp_technique_details[0]
    assert detail["id"] == "SAFE-T1101"
    assert detail["detected_severity"] == "critical"
    assert "tool:exec" in detail["affected_components"]
    assert result.vulnerability_score == 25.0
    assert result.severity_level == "safe"


@pytest.mark.asyncio
async def test_safe_mcp_summary_handles_unknown_technique(monkeypatch):
    endpoint = McpEndpoint(
        address="10.0.0.77",
        scheme="https",
        port=443,
        base_url="https://10.0.0.77",
        probes=[],
        evidence=McpEvidence(),
    )
    metadata = ScanMetadata(
        scanned_hosts=1, reachable_hosts=1, mcp_endpoints=1, duration_seconds=0.1
    )

    async def fake_discover(config):
        return [endpoint], metadata

    monkeypatch.setattr("conmap.scanner.discover_mcp_endpoints", fake_discover)
    monkeypatch.setattr("conmap.scanner.run_schema_inspector", lambda endpoints: [])
    monkeypatch.setattr("conmap.scanner.run_chain_detector", lambda endpoints: [])
    monkeypatch.setattr(
        "conmap.scanner.run_llm_analyzer",
        lambda endpoints, cache, enabled, batch_size=5: [],
    )

    findings = [
        Vulnerability(
            endpoint=endpoint.base_url,
            component="tool:one",
            category="safe_mcp.safe-unknown",
            severity=Severity.low,
            message="first",
            evidence={"technique": "SAFE-UNKNOWN"},
            detection_source="static",
        ),
        Vulnerability(
            endpoint=endpoint.base_url,
            component="tool:two",
            category="safe_mcp.safe-unknown",
            severity=Severity.critical,
            message="second",
            evidence={"technique": "SAFE-UNKNOWN"},
            detection_source="static",
        ),
    ]

    monkeypatch.setattr("conmap.scanner.run_safe_mcp_detector", lambda endpoints: findings)
    monkeypatch.setattr("conmap.scanner.safe_mcp_lookup", lambda technique: None)

    result = await scan_async(ScanConfig())
    assert result.safe_mcp_techniques_detected == 1
    assert len(result.safe_mcp_technique_details) == 1
    detail = result.safe_mcp_technique_details[0]
    assert detail["id"] == "SAFE-UNKNOWN"
    assert detail["name"] is None
    assert detail["detected_severity"] == "critical"
    assert detail["occurrences"] == 2
    assert detail["affected_components"] == ["tool:one", "tool:two"]
    assert result.vulnerability_score == 30.0
    assert result.severity_level == "safe"


def test_compute_vulnerability_score_progression():
    from conmap.scanner import _compute_vulnerability_score

    base_vulnerability = Vulnerability(
        endpoint="http://example",
        component="tool",
        category="schema.issue",
        severity=Severity.high,
        message="",
        evidence={},
        detection_source="static",
    )
    score, level = _compute_vulnerability_score([base_vulnerability])
    assert pytest.approx(score, rel=1e-3) == 18.0
    assert level == "safe"

    graph_vulnerability = base_vulnerability.model_copy(
        update={"severity": Severity.critical, "detection_source": "graph"}
    )
    score, level = _compute_vulnerability_score([base_vulnerability, graph_vulnerability])
    assert pytest.approx(score, rel=1e-3) == 18.0 + 25.0 * 1.3
    assert level == "warning"

    unknown_vulnerability = base_vulnerability.model_copy()
    object.__setattr__(unknown_vulnerability, "severity", "mystery")
    score, level = _compute_vulnerability_score(
        [base_vulnerability, graph_vulnerability, unknown_vulnerability]
    )
    assert pytest.approx(score, rel=1e-3) == 18.0 + 25.0 * 1.3 + 5.0
    assert level == "warning"
