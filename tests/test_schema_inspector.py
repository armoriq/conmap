from conmap.models import McpEndpoint, McpEvidence, Severity
from conmap.vulnerabilities.schema_inspector import run_schema_inspector


def build_endpoint(structure: dict) -> McpEndpoint:
    return McpEndpoint(
        address="10.0.0.1",
        scheme="http",
        port=80,
        base_url="http://10.0.0.1",
        probes=[],
        evidence=McpEvidence(json_structures=[structure]),
    )


def test_schema_inspector_detects_unbounded_string():
    endpoint = build_endpoint(
        {
            "tools": [
                {
                    "name": "dangerous_tool",
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "Command to run",
                            }
                        },
                    },
                }
            ]
        }
    )
    findings = run_schema_inspector([endpoint])
    categories = {finding.category for finding in findings}
    assert "schema.sensitive_parameter_unvalidated" in categories
    severities = {finding.severity for finding in findings}
    assert Severity.high in severities


def test_schema_inspector_additional_properties_and_required():
    endpoint = build_endpoint(
        {
            "tools": [
                {
                    "name": "config_tool",
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "config": {
                                "type": "object",
                                "additionalProperties": True,
                            }
                        },
                    },
                }
            ]
        }
    )
    findings = run_schema_inspector([endpoint])
    categories = {finding.category for finding in findings}
    assert "schema.additional_properties" in categories
    assert "schema.missing_required_fields" in categories


def test_schema_inspector_detects_enum_size_and_defaults():
    endpoint = build_endpoint(
        {
            "tools": [
                {
                    "name": "enum_tool",
                    "input_schema": {
                        "type": "string",
                        "default": "../etc/passwd",
                        "enum": list(range(12)),
                    },
                }
            ]
        }
    )
    findings = run_schema_inspector([endpoint])
    categories = {finding.category for finding in findings}
    assert "schema.dangerous_default" in categories
    assert "schema.overly_permissive_enum" in categories


def test_schema_inspector_array_items():
    endpoint = build_endpoint(
        {
            "tools": [
                {
                    "name": "array_tool",
                    "input_schema": {
                        "type": "array",
                        "items": {
                            "type": "string",
                        },
                    },
                }
            ]
        }
    )
    findings = run_schema_inspector([endpoint])
    categories = {finding.category for finding in findings}
    assert "schema.unbounded_string" in categories
