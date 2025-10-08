from conmap.models import McpEndpoint, ScanMetadata, ScanResult, Vulnerability, Severity
from conmap.reporting import build_report, render_report


def sample_result() -> ScanResult:
    endpoint = McpEndpoint(
        address="10.0.0.5",
        scheme="http",
        port=80,
        base_url="http://10.0.0.5",
        probes=[],
    )
    vulnerability = Vulnerability(
        endpoint=endpoint.base_url,
        component="tool:demo",
        category="schema.unbounded_string",
        severity=Severity.medium,
        message="Example",
        evidence={},
    )
    metadata = ScanMetadata(scanned_hosts=1, reachable_hosts=1, mcp_endpoints=1, duration_seconds=0.1)
    return ScanResult(metadata=metadata, endpoints=[endpoint], vulnerabilities=[vulnerability])


def test_build_and_render_report():
    result = sample_result()
    payload = build_report(result)
    assert payload["metadata"]["scanned_hosts"] == 1
    json_text = render_report(result, pretty=False)
    assert '"schema.unbounded_string"' in json_text
    pretty = render_report(result, pretty=True)
    assert "\n" in pretty
