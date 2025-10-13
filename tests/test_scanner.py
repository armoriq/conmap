import pytest

from conmap.config import ScanConfig
from conmap.models import (
    McpEndpoint,
    McpEvidence,
    EndpointProbe,
    ScanMetadata,
    ScanResult,
    Severity,
    Vulnerability,
)
from conmap.scanner import (
    _build_policy_hints,
    _evaluate_endpoint_posture,
    _evaluate_runtime_anomalies,
    _evaluate_tool_vetting,
    _scan_output_leaks,
    _RUNTIME_HISTORY,
    scan,
    scan_async,
)


@pytest.mark.asyncio
async def test_scan_async_aggregates(monkeypatch):
    endpoint = McpEndpoint(
        address="10.0.0.8",
        scheme="https",
        port=443,
        base_url="https://10.0.0.8",
        probes=[
            EndpointProbe(
                url="https://10.0.0.8/",
                path="/",
                status_code=200,
                headers={
                    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
                    "Content-Security-Policy": "default-src 'none'",
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                },
            )
        ],
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
        probes=[
            EndpointProbe(
                url="https://10.0.0.88/",
                path="/",
                status_code=200,
                headers={
                    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
                    "Content-Security-Policy": "default-src 'none'",
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                },
            )
        ],
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
        probes=[
            EndpointProbe(
                url="https://10.0.0.77/",
                path="/",
                status_code=200,
                headers={
                    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
                    "Content-Security-Policy": "default-src 'none'",
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                },
            )
        ],
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


def test_evaluate_endpoint_posture_detects_insecure_config():
    endpoint = McpEndpoint(
        address="10.0.0.1",
        scheme="http",
        port=80,
        base_url="http://10.0.0.1",
        probes=[
            EndpointProbe(
                url="http://10.0.0.1/",
                path="/",
                status_code=200,
                headers={
                    "Content-Type": "application/json",
                },
            )
        ],
        evidence=McpEvidence(),
    )

    findings = _evaluate_endpoint_posture(endpoint)
    categories = {finding.category for finding in findings}
    assert "posture.insecure_transport" in categories
    assert "posture.missing_security_headers" in categories


def test_build_policy_hints_groups_findings():
    vulnerabilities = [
        Vulnerability(
            endpoint="http://target",
            component="tool:demo",
            category="schema.weak_validation",
            severity=Severity.high,
            message="Permissive schema",
            evidence={},
        ),
        Vulnerability(
            endpoint="http://target",
            component="gateway",
            category="posture.insecure_transport",
            severity=Severity.critical,
            message="HTTP endpoint",
            evidence={},
        ),
        Vulnerability(
            endpoint="http://target",
            component="chain",
            category="chain.data_exfiltration",
            severity=Severity.medium,
            message="Chain risk",
            evidence={},
        ),
    ]

    recommendations = _build_policy_hints(vulnerabilities)
    assert recommendations
    risks = {item["risk"] for item in recommendations}
    assert "Tool Poisoning & Malicious Tooling" in risks
    assert "Transport & Gateway Hardening" in risks
    assert "Data Exfiltration & Lateral Movement" in risks


def test_scan_output_leaks_detects_sensitive_data():
    endpoint = McpEndpoint(
        address="10.0.0.5",
        scheme="https",
        port=443,
        base_url="https://10.0.0.5",
        probes=[
            EndpointProbe(
                url="https://10.0.0.5/resource",
                path="/resource",
                status_code=200,
                headers={"Content-Type": "application/json"},
                json_payload={"ssn": "111-22-3333"},
            )
        ],
        evidence=McpEvidence(),
    )

    findings = _scan_output_leaks(endpoint)
    categories = {finding.category for finding in findings}
    assert "dlp.ssn" in categories


def test_evaluate_runtime_anomalies_detects_ratio_shift():
    _RUNTIME_HISTORY.clear()
    endpoint = McpEndpoint(
        address="10.0.0.6",
        scheme="https",
        port=443,
        base_url="https://10.0.0.6",
        probes=[
            EndpointProbe(
                url="https://10.0.0.6/ok",
                path="/ok",
                status_code=200,
                headers={"Content-Length": "100"},
            )
            for _ in range(5)
        ],
        evidence=McpEvidence(),
    )

    # Establish baseline
    assert _evaluate_runtime_anomalies(endpoint) == []

    failing_endpoint = endpoint.model_copy()
    failing_endpoint.probes = [
        EndpointProbe(
            url="https://10.0.0.6/fail",
            path="/fail",
            status_code=500,
            headers={"Content-Length": "400"},
        )
        for _ in range(4)
    ] + [
        EndpointProbe(
            url="https://10.0.0.6/fail",
            path="/fail",
            status_code=200,
            headers={"Content-Length": "400"},
        )
    ]

    findings = _evaluate_runtime_anomalies(failing_endpoint)
    categories = {finding.category for finding in findings}
    assert "runtime.success_ratio_shift" in categories


def test_evaluate_tool_vetting_flags_missing_signature(monkeypatch):
    endpoint = McpEndpoint(
        address="10.0.0.9",
        scheme="https",
        port=443,
        base_url="https://10.0.0.9",
        probes=[],
        evidence=McpEvidence(
            json_structures=[
                {
                    "tools": [
                        {
                            "name": "admin_tool",
                            "description": "reset passwords",
                            "metadata": {
                                "approved_at": "2024-01-01T00:00:00",
                            },
                        }
                    ]
                }
            ]
        ),
    )

    findings = _evaluate_tool_vetting(endpoint)
    categories = {finding.category for finding in findings}
    assert "governance.tool_unverified" in categories


@pytest.mark.asyncio
async def test_sandbox_execution_integrates_with_scan(monkeypatch):
    config = ScanConfig(enable_sandbox=True)

    endpoint = McpEndpoint(
        address="10.0.0.55",
        scheme="https",
        port=443,
        base_url="https://10.0.0.55",
        probes=[
            EndpointProbe(
                url="https://10.0.0.55/",
                path="/",
                status_code=200,
                headers={
                    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
                    "Content-Security-Policy": "default-src 'none'",
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                },
            )
        ],
        evidence=McpEvidence(
            json_structures=[
                {
                    "tools": [
                        {
                            "name": "suspect",
                            "metadata": {
                                "sandbox_simulation": {
                                    "network": ["198.51.100.10"],
                                }
                            },
                        }
                    ]
                }
            ]
        ),
    )

    metadata = ScanMetadata(
        scanned_hosts=1,
        reachable_hosts=1,
        mcp_endpoints=1,
        duration_seconds=0.1,
    )

    async def fake_discover(_config):
        return [endpoint], metadata

    monkeypatch.setattr("conmap.scanner.discover_mcp_endpoints", fake_discover)
    monkeypatch.setattr("conmap.scanner.run_schema_inspector", lambda endpoints: [])
    monkeypatch.setattr("conmap.scanner.run_chain_detector", lambda endpoints: [])
    monkeypatch.setattr("conmap.scanner.run_safe_mcp_detector", lambda endpoints: [])
    monkeypatch.setattr(
        "conmap.scanner.run_llm_analyzer",
        lambda endpoints, cache, enabled, batch_size=5: [],
    )

    result = await scan_async(config)
    categories = {finding.category for finding in result.vulnerabilities}
    assert "sandbox.network_exfiltration" in categories
    risks = {item["risk"] for item in result.security_recommendations}
    assert "Sandbox Behavior Anomalies" in risks


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
