from __future__ import annotations

from typing import Any, Dict, List

from ..models import McpEndpoint, Severity, Vulnerability

SENSITIVE_KEYS = {"command", "path", "file", "filepath", "directory", "target", "url"}
DANGEROUS_DEFAULTS = {"admin", "root", "../", "..\\", "/etc/passwd", "~/.ssh", "C:\\Windows"}


def run_schema_inspector(endpoints: List[McpEndpoint]) -> List[Vulnerability]:
    findings: List[Vulnerability] = []
    for endpoint in endpoints:
        for structure in endpoint.evidence.json_structures:
            tools = structure.get("tools") or []
            if isinstance(tools, dict):
                tools = tools.values()
            for tool in tools:
                name = str(tool.get("name", "unknown"))
                schema = _extract_schema(tool)
                if schema:
                    findings.extend(_inspect_schema(endpoint.base_url, f"tool:{name}", schema))
            resources = structure.get("resources") or []
            for resource in resources:
                name = str(resource.get("name", "unknown"))
                schema = _extract_schema(resource)
                if schema:
                    findings.extend(_inspect_schema(endpoint.base_url, f"resource:{name}", schema))
    return findings


def _extract_schema(item: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(item, dict):
        return {}
    return item.get("input_schema") or item.get("schema") or item.get("request_schema") or {}


def _inspect_schema(endpoint: str, component: str, schema: Dict[str, Any]) -> List[Vulnerability]:
    findings: List[Vulnerability] = []
    findings.extend(_check_schema_recursively(endpoint, component, schema, path="$"))
    if schema.get("type") == "object" and schema.get("properties"):
        if not schema.get("required"):
            findings.append(
                Vulnerability(
                    endpoint=endpoint,
                    component=component,
                    category="schema.missing_required_fields",
                    severity=Severity.medium,
                    message="Object schema defines properties but no required fields.",
                    evidence={"schema": schema},
                )
            )
    enum_values = schema.get("enum")
    if isinstance(enum_values, list) and enum_values:
        if len(enum_values) > 10 or any(str(v) in {"*", "any", "all"} for v in enum_values):
            findings.append(
                Vulnerability(
                    endpoint=endpoint,
                    component=component,
                    category="schema.overly_permissive_enum",
                    severity=Severity.medium,
                    message=(
                        "Enum allows "
                        f"{len(enum_values)} values, including potentially permissive entries."
                    ),
                    evidence={"enum": enum_values},
                )
            )
    return findings


def _check_schema_recursively(
    endpoint: str,
    component: str,
    schema: Dict[str, Any],
    path: str,
) -> List[Vulnerability]:
    findings: List[Vulnerability] = []
    schema_type = schema.get("type")
    default = schema.get("default")
    if isinstance(default, str):
        if any(token in default.lower() for token in ("admin", "root", "../", "..\\")):
            findings.append(
                Vulnerability(
                    endpoint=endpoint,
                    component=component,
                    category="schema.dangerous_default",
                    severity=Severity.high,
                    message=f"Default value '{default}' at {path} is potentially dangerous.",
                    evidence={"default": default, "path": path},
                )
            )
    if isinstance(default, str) and default in DANGEROUS_DEFAULTS:
        findings.append(
            Vulnerability(
                endpoint=endpoint,
                component=component,
                category="schema.dangerous_default",
                severity=Severity.high,
                message=f"Default value '{default}' at {path} references sensitive location.",
                evidence={"default": default, "path": path},
            )
        )
    if schema_type == "string":
        if not schema.get("maxLength") and not schema.get("pattern"):
            severity = Severity.medium
            findings.append(
                Vulnerability(
                    endpoint=endpoint,
                    component=component,
                    category="schema.unbounded_string",
                    severity=severity,
                    message=f"String field {path} lacks maxLength or pattern validation.",
                    evidence={"schema": schema, "path": path},
                )
            )
        if _is_sensitive_path(path) and not schema.get("enum") and not schema.get("pattern"):
            findings.append(
                Vulnerability(
                    endpoint=endpoint,
                    component=component,
                    category="schema.sensitive_parameter_unvalidated",
                    severity=Severity.high,
                    message=f"Sensitive parameter {path} lacks strict validation.",
                    evidence={"schema": schema, "path": path},
                )
            )
    if schema_type == "object":
        properties = schema.get("properties") or {}
        for key, subschema in properties.items():
            if isinstance(subschema, dict):
                findings.extend(
                    _check_schema_recursively(
                        endpoint,
                        component,
                        subschema,
                        path=f"{path}.{key}",
                    )
                )
        additional_properties = schema.get("additionalProperties")
        if additional_properties is True:
            findings.append(
                Vulnerability(
                    endpoint=endpoint,
                    component=component,
                    category="schema.additional_properties",
                    severity=Severity.medium,
                    message=f"Schema {path} permits arbitrary additional properties.",
                    evidence={"schema": schema, "path": path},
                )
            )
        elif isinstance(additional_properties, dict):
            findings.extend(
                _check_schema_recursively(
                    endpoint,
                    component,
                    additional_properties,
                    path=f"{path}.*",
                )
            )
    if schema_type == "array":
        items = schema.get("items")
        if isinstance(items, dict):
            findings.extend(
                _check_schema_recursively(
                    endpoint,
                    component,
                    items,
                    path=f"{path}[]",
                )
            )
    return findings


def _is_sensitive_path(path: str) -> bool:
    lowered = path.lower()
    return any(key in lowered for key in SENSITIVE_KEYS)
