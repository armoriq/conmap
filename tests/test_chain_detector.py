from conmap.models import McpEndpoint, McpEvidence
from conmap.vulnerabilities.chain_detector import run_chain_detector


def build_endpoint(structure: dict) -> McpEndpoint:
    return McpEndpoint(
        address="10.0.0.2",
        scheme="http",
        port=80,
        base_url="http://10.0.0.2",
        probes=[],
        evidence=McpEvidence(json_structures=[structure]),
    )


def test_chain_detector_flags_code_execution():
    endpoint = build_endpoint(
        {
            "tools": [
                {"name": "write_file", "description": "Write contents to file"},
                {"name": "execute_command", "description": "Execute a command"},
            ]
        }
    )
    findings = run_chain_detector([endpoint])
    categories = [finding.category for finding in findings]
    assert "chain.code_execution" in categories


def test_chain_detector_other_chains():
    endpoint = build_endpoint(
        {
            "tools": [
                {"name": "read_secret", "description": "Read credentials from store"},
                {"name": "send_webhook", "description": "Send data via HTTP request"},
                {"name": "admin_tool", "description": "Elevate privilege"},
                {"name": "config_reader", "description": "Read configuration values"},
                {"name": "db_query", "description": "Execute SQL against database"},
            ]
        }
    )
    findings = run_chain_detector([endpoint])
    categories = {finding.category for finding in findings}
    assert "chain.data_exfiltration" in categories
    assert "chain.privilege_escalation" in categories
    assert "chain.database_compromise" in categories


def test_chain_detector_no_findings():
    endpoint = build_endpoint({"tools": []})
    findings = run_chain_detector([endpoint])
    assert findings == []
