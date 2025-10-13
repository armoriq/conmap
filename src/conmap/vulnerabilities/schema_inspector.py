from __future__ import annotations

import re
from typing import Any, Dict, List

from ..models import McpEndpoint, Severity, Vulnerability
from ..logging import get_logger

SENSITIVE_KEYS = {"command", "path", "file", "filepath", "directory", "target", "url"}
DANGEROUS_DEFAULTS = {"admin", "root", "../", "..\\", "/etc/passwd", "~/.ssh", "C:\\Windows"}

logger = get_logger(__name__)


def _preview_text(value: Any, limit: int = 120) -> str:
    if not value:
        return ""
    text = str(value)
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[:limit].rstrip() + "..."


def run_schema_inspector(endpoints: List[McpEndpoint]) -> List[Vulnerability]:
    findings: List[Vulnerability] = []
    for endpoint in endpoints:
        structures = len(endpoint.evidence.json_structures)
        tool_names: List[str] = []
        resource_names: List[str] = []
        for structure in endpoint.evidence.json_structures:
            raw_tools = structure.get("tools") or []
            if isinstance(raw_tools, dict):
                raw_tools = raw_tools.values()
            tool_names.extend(str(tool.get("name", "unknown")) for tool in raw_tools)
            raw_resources = structure.get("resources") or []
            if isinstance(raw_resources, dict):
                raw_resources = raw_resources.values()
            resource_names.extend(str(res.get("name", "resource")) for res in raw_resources)
        logger.info(
            "Schema inspector endpoint=%s structures=%s tools=%s resources=%s",
            endpoint.base_url,
            structures,
            len(tool_names),
            len(resource_names),
        )
        start_count = len(findings)
        for structure in endpoint.evidence.json_structures:
            tools = structure.get("tools") or []
            if isinstance(tools, dict):
                tools = tools.values()
            for tool in tools:
                name = str(tool.get("name", "unknown"))
                schema = _extract_schema(tool)
                if schema:
                    logger.info(
                        "Inspecting tool schema endpoint=%s name=%s keys=%s desc=%s",
                        endpoint.base_url,
                        name,
                        f"tool:{name}",
                        sorted(schema.keys())[:8],
                        _preview_text(tool.get("description")),
                    )
                    findings.extend(
                        _inspect_schema(
                            endpoint.base_url,
                            f"tool:{name}",
                            schema,
                            tool_name=name,
                        )
                    )
            resources = structure.get("resources") or []
            for resource in resources:
                name = str(resource.get("name", "unknown"))
                schema = _extract_schema(resource)
                if schema:
                    logger.info(
                        "Inspecting resource schema endpoint=%s name=%s keys=%s desc=%s",
                        endpoint.base_url,
                        name,
                        f"resource:{name}",
                        sorted(schema.keys())[:8],
                        _preview_text(resource.get("description")),
                    )
                    findings.extend(
                        _inspect_schema(
                            endpoint.base_url,
                            f"resource:{name}",
                            schema,
                            tool_name=name,
                        )
                    )
        logger.info(
            "Schema inspector endpoint=%s findings=%s",
            endpoint.base_url,
            len(findings) - start_count,
        )
    return findings


def _extract_schema(item: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(item, dict):
        return {}
    return item.get("input_schema") or item.get("schema") or item.get("request_schema") or {}


def _inspect_schema(
    endpoint: str,
    component: str,
    schema: Dict[str, Any],
    tool_name: str,
) -> List[Vulnerability]:
    findings: List[Vulnerability] = []
    if not schema.get("type"):
        logger.info("Schema %s missing root type", component)
        findings.append(
            Vulnerability(
                endpoint=endpoint,
                component=component,
                category="schema.missing_type",
                severity=Severity.high,
                message="Schema missing root type definition.",
                mitigation="Add an explicit `type` field to the schema root.",
                detection_source="static",
                evidence={"schema": schema},
            )
        )
    findings.extend(_check_schema_recursively(endpoint, component, schema, path="$"))
    if schema.get("type") == "object" and schema.get("properties"):
        if not schema.get("required"):
            logger.info("Schema %s missing required fields", component)
            findings.append(
                Vulnerability(
                    endpoint=endpoint,
                    component=component,
                    category="schema.missing_required_fields",
                    severity=Severity.medium,
                    message="Object schema defines properties but no required fields.",
                    mitigation="Define required parameters to prevent permissive execution.",
                    detection_source="static",
                    evidence={"schema": schema},
                )
            )
    enum_values = schema.get("enum")
    if isinstance(enum_values, list) and enum_values:
        if len(enum_values) > 10 or any(str(v) in {"*", "any", "all"} for v in enum_values):
            logger.info("Schema %s has permissive enum (%s values)", component, len(enum_values))
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
                    mitigation="Reduce enum options or enforce stricter validation.",
                    detection_source="static",
                    evidence={"enum": enum_values},
                )
            )

    sensitive_pattern = re.compile(
        r"(delete|remove|drop|destroy|execute|exec|admin)", re.IGNORECASE
    )
    if sensitive_pattern.search(tool_name) and (not schema.get("required")):
        findings.append(
            Vulnerability(
                endpoint=endpoint,
                component=component,
                category="schema.sensitive_operation_permissive",
                severity=Severity.high,
                message="Sensitive operation lacks required parameters.",
                mitigation="Mark critical parameters as required and validate inputs strictly.",
                detection_source="static",
                evidence={"tool": tool_name, "schema": schema},
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
            logger.info("Schema %s detected dangerous default '%s'", path, default)
            findings.append(
                Vulnerability(
                    endpoint=endpoint,
                    component=component,
                    category="schema.dangerous_default",
                    severity=Severity.high,
                    message=f"Default value '{default}' at {path} is potentially dangerous.",
                    mitigation="Remove or harden default value; require explicit safe input.",
                    detection_source="static",
                    evidence={"default": default, "path": path},
                )
            )
    if isinstance(default, str) and default in DANGEROUS_DEFAULTS:
        logger.info("Schema %s detected sensitive default '%s'", path, default)
        findings.append(
            Vulnerability(
                endpoint=endpoint,
                component=component,
                category="schema.dangerous_default",
                severity=Severity.high,
                message=f"Default value '{default}' at {path} references sensitive location.",
                mitigation="Do not point defaults to sensitive paths or credentials.",
                detection_source="static",
                evidence={"default": default, "path": path},
            )
        )
    if schema_type == "string":
        if not schema.get("maxLength") and not schema.get("pattern"):
            severity = Severity.medium
            logger.info("Schema %s string field lacks bounds", path)
            findings.append(
                Vulnerability(
                    endpoint=endpoint,
                    component=component,
                    category="schema.unbounded_string",
                    severity=severity,
                    message=f"String field {path} lacks maxLength or pattern validation.",
                    mitigation="Add maxLength and/or regex pattern constraints.",
                    detection_source="static",
                    evidence={"schema": schema, "path": path},
                )
            )
        if _is_sensitive_path(path) and not schema.get("enum") and not schema.get("pattern"):
            logger.info(
                "Schema %s has sensitive parameter %s lacking strict validation", component, path
            )
            findings.append(
                Vulnerability(
                    endpoint=endpoint,
                    component=component,
                    category="schema.sensitive_parameter_unvalidated",
                    severity=Severity.high,
                    message=f"Sensitive parameter {path} lacks strict validation.",
                    mitigation="Whitelist allowable values or enforce strict regex validation.",
                    detection_source="static",
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
            logger.info("Schema %s allows additionalProperties", path)
            findings.append(
                Vulnerability(
                    endpoint=endpoint,
                    component=component,
                    category="schema.additional_properties",
                    severity=Severity.medium,
                    message=f"Schema {path} permits arbitrary additional properties.",
                    mitigation="Set additionalProperties to false or define explicit schema.",
                    detection_source="static",
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
