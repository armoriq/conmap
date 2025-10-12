from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

from ..models import EndpointProbe, McpEndpoint, Severity, Vulnerability
from .chain_detector import _build_capability_nodes  # type: ignore


@dataclass
class TechniqueMatch:
    component: str
    detail: str
    evidence: Dict[str, Any]
    severity: Optional[Severity] = None
    mitigation: Optional[str] = None


@dataclass
class TechniqueMeta:
    identifier: str
    name: str
    tactic: str
    default_severity: Severity
    default_message: str
    default_mitigation: str


ZERO_WIDTH_CHARS = {
    "\u200b",
    "\u200c",
    "\u200d",
    "\u200e",
    "\u200f",
    "\u2060",
    "\u2061",
    "\u2062",
    "\u2063",
    "\u2064",
    "\ufeff",
}

SAFE_MCP_TECHNIQUES: Dict[str, TechniqueMeta] = {
    "SAFE-T1001": TechniqueMeta(
        identifier="SAFE-T1001",
        name="Tool Poisoning Attack",
        tactic="Initial Access",
        default_severity=Severity.critical,
        default_message="Tool description contains hidden instructions consistent with tool poisoning (SAFE-T1001).",
        default_mitigation="Strip hidden content, normalize Unicode, and enforce linting on tool descriptors before publishing.",
    ),
    "SAFE-T1002": TechniqueMeta(
        identifier="SAFE-T1002",
        name="Supply Chain Compromise",
        tactic="Initial Access",
        default_severity=Severity.critical,
        default_message="MCP endpoint is served over an untrusted channel, increasing supply-chain compromise risk (SAFE-T1002).",
        default_mitigation="Distribute MCP servers over authenticated HTTPS endpoints and verify signatures before install.",
    ),
    "SAFE-T1003": TechniqueMeta(
        identifier="SAFE-T1003",
        name="Malicious MCP-Server Distribution",
        tactic="Initial Access",
        default_severity=Severity.critical,
        default_message="Tool catalog exposes language indicative of trojanized distribution (SAFE-T1003).",
        default_mitigation="Audit server provenance, require signed manifests, and block unknown tool registries.",
    ),
    "SAFE-T1007": TechniqueMeta(
        identifier="SAFE-T1007",
        name="OAuth Authorization Phishing",
        tactic="Initial Access",
        default_severity=Severity.critical,
        default_message="Tool attempts to drive OAuth authorization without sufficient validation (SAFE-T1007).",
        default_mitigation="Require explicit allow-lists for OAuth scopes and validate redirect URIs against trusted domains.",
    ),
    "SAFE-T1101": TechniqueMeta(
        identifier="SAFE-T1101",
        name="Command Injection",
        tactic="Execution",
        default_severity=Severity.critical,
        default_message="Tool exposes raw command execution surfaces susceptible to command injection (SAFE-T1101).",
        default_mitigation="Disable shell execution or strictly validate command arguments before invocation.",
    ),
    "SAFE-T1102": TechniqueMeta(
        identifier="SAFE-T1102",
        name="Prompt Injection (Multiple Vectors)",
        tactic="Execution",
        default_severity=Severity.high,
        default_message="Unbounded prompt input detected that could facilitate prompt injection (SAFE-T1102).",
        default_mitigation="Constrain prompt inputs, filter directives, and sanitize resource responses before use.",
    ),
    "SAFE-T1104": TechniqueMeta(
        identifier="SAFE-T1104",
        name="Over-Privileged Tool Abuse",
        tactic="Privilege Escalation",
        default_severity=Severity.high,
        default_message="Tool advertises elevated privileges without guardrails (SAFE-T1104).",
        default_mitigation="Split high-risk capabilities and require secondary approvals before privileged usage.",
    ),
    "SAFE-T1105": TechniqueMeta(
        identifier="SAFE-T1105",
        name="Path Traversal via File Tool",
        tactic="Execution",
        default_severity=Severity.high,
        default_message="File/path parameter lacks validation allowing traversal (SAFE-T1105).",
        default_mitigation="Whitelist allowable paths, normalize traversal, and reject relative segments.",
    ),
    "SAFE-T1106": TechniqueMeta(
        identifier="SAFE-T1106",
        name="Autonomous Loop Exploit",
        tactic="Execution",
        default_severity=Severity.high,
        default_message="Autonomous or looping execution detected without safeguards (SAFE-T1106).",
        default_mitigation="Require human checkpoints for autonomous loops and enforce runtime limits.",
    ),
    "SAFE-T1109": TechniqueMeta(
        identifier="SAFE-T1109",
        name="Debugging Tool Exploitation",
        tactic="Credential Access",
        default_severity=Severity.critical,
        default_message="Debug-oriented tool with expansive introspection detected (SAFE-T1109).",
        default_mitigation="Restrict debugging endpoints in production and gate behind authenticated sessions.",
    ),
    "SAFE-T1110": TechniqueMeta(
        identifier="SAFE-T1110",
        name="Multimodal Prompt Injection",
        tactic="Execution",
        default_severity=Severity.high,
        default_message="Multimodal ingestion tool lacks sanitization for embedded payloads (SAFE-T1110).",
        default_mitigation="Sanitize and scan multimodal inputs before forwarding to LLMs.",
    ),
    "SAFE-T1111": TechniqueMeta(
        identifier="SAFE-T1111",
        name="AI Agent CLI Weaponization",
        tactic="Execution",
        default_severity=Severity.critical,
        default_message="Command-line automation tool can be weaponized via MCP (SAFE-T1111).",
        default_mitigation="Require explicit approval for CLI tool invocation and lock down shell contexts.",
    ),
    "SAFE-T1201": TechniqueMeta(
        identifier="SAFE-T1201",
        name="MCP Rug Pull Attack",
        tactic="Persistence",
        default_severity=Severity.high,
        default_message="Tool advertises self-updating behavior susceptible to rug pulls (SAFE-T1201).",
        default_mitigation="Pin tool versions, vet update channels, and require signing for auto-updates.",
    ),
    "SAFE-T1202": TechniqueMeta(
        identifier="SAFE-T1202",
        name="OAuth Token Persistence",
        tactic="Persistence",
        default_severity=Severity.high,
        default_message="Tool persists OAuth tokens without scoped storage (SAFE-T1202).",
        default_mitigation="Store OAuth tokens in dedicated secrets managers with rotation and scoping.",
    ),
    "SAFE-T1303": TechniqueMeta(
        identifier="SAFE-T1303",
        name="Container Sandbox Escape via Runtime Exec",
        tactic="Persistence",
        default_severity=Severity.critical,
        default_message="Container runtime controls exposed that enable sandbox escape (SAFE-T1303).",
        default_mitigation="Revoke runtime exec permissions and isolate MCP servers from container daemons.",
    ),
    "SAFE-T1304": TechniqueMeta(
        identifier="SAFE-T1304",
        name="Credential Relay Chain",
        tactic="Credential Access",
        default_severity=Severity.high,
        default_message="Tool can relay captured credentials to external services (SAFE-T1304).",
        default_mitigation="Partition credentials from network tools and audit relay destinations.",
    ),
    "SAFE-T1501": TechniqueMeta(
        identifier="SAFE-T1501",
        name="Full-Schema Poisoning",
        tactic="Defense Evasion",
        default_severity=Severity.critical,
        default_message="Schema defaults or enums permit hidden poisoning vectors (SAFE-T1501).",
        default_mitigation="Lint schemas for malicious defaults and require deterministic validation.",
    ),
    "SAFE-T1601": TechniqueMeta(
        identifier="SAFE-T1601",
        name="MCP Server Enumeration",
        tactic="Discovery",
        default_severity=Severity.high,
        default_message="Server discloses extensive capability catalogue without authentication (SAFE-T1601).",
        default_mitigation="Require authentication before exposing capability listings and throttle enumeration.",
    ),
    "SAFE-T1703": TechniqueMeta(
        identifier="SAFE-T1703",
        name="Tool-Chaining Pivot",
        tactic="Lateral Movement",
        default_severity=Severity.high,
        default_message="Discovered tool chain enables privilege pivoting (SAFE-T1703).",
        default_mitigation="Segment tool privileges and require approvals for cross-tool invocations.",
    ),
    "SAFE-T1705": TechniqueMeta(
        identifier="SAFE-T1705",
        name="Cross-Agent Instruction Injection",
        tactic="Lateral Movement",
        default_severity=Severity.critical,
        default_message="Multi-agent orchestration susceptible to instruction injection (SAFE-T1705).",
        default_mitigation="Validate inter-agent messages and remove implicit trust between agents.",
    ),
    "SAFE-T2107": TechniqueMeta(
        identifier="SAFE-T2107",
        name="AI Model Poisoning via MCP Tool Training Data Contamination",
        tactic="Resource Development",
        default_severity=Severity.critical,
        default_message="Tool feeds training pipelines without sanitizing outputs (SAFE-T2107).",
        default_mitigation="Validate and sanitize data before using MCP outputs for model training.",
    ),
}


def run_safe_mcp_detector(endpoints: List[McpEndpoint]) -> List[Vulnerability]:
    findings: List[Vulnerability] = []
    for endpoint in endpoints:
        context = _build_endpoint_context(endpoint)
        findings.extend(_detect_safe_t1001(endpoint, context))
        findings.extend(_detect_safe_t1002(endpoint, context))
        findings.extend(_detect_safe_t1003(endpoint, context))
        findings.extend(_detect_safe_t1007(endpoint, context))
        findings.extend(_detect_safe_t1101(endpoint, context))
        findings.extend(_detect_safe_t1102(endpoint, context))
        findings.extend(_detect_safe_t1104(endpoint, context))
        findings.extend(_detect_safe_t1105(endpoint, context))
        findings.extend(_detect_safe_t1106(endpoint, context))
        findings.extend(_detect_safe_t1109(endpoint, context))
        findings.extend(_detect_safe_t1110(endpoint, context))
        findings.extend(_detect_safe_t1111(endpoint, context))
        findings.extend(_detect_safe_t1201(endpoint, context))
        findings.extend(_detect_safe_t1202(endpoint, context))
        findings.extend(_detect_safe_t1303(endpoint, context))
        findings.extend(_detect_safe_t1304(endpoint, context))
        findings.extend(_detect_safe_t1501(endpoint, context))
        findings.extend(_detect_safe_t1601(endpoint, context))
        findings.extend(_detect_safe_t1703(endpoint, context))
        findings.extend(_detect_safe_t1705(endpoint, context))
        findings.extend(_detect_safe_t2107(endpoint, context))
    return findings


@dataclass
class ToolContext:
    component: str
    name: str
    description: str
    schema: Dict[str, Any]
    raw: Dict[str, Any]


@dataclass
class EndpointContext:
    tools: List[ToolContext]
    resources: List[ToolContext]
    headers: Dict[str, str]
    capability_paths: List[str]


def _build_endpoint_context(endpoint: McpEndpoint) -> EndpointContext:
    tools: List[ToolContext] = []
    resources: List[ToolContext] = []
    for structure in endpoint.evidence.json_structures:
        raw_tools = structure.get("tools") or []
        if isinstance(raw_tools, dict):
            raw_tools = list(raw_tools.values())
        for tool in raw_tools:
            name = str(tool.get("name") or "tool")
            tools.append(
                ToolContext(
                    component=f"tool:{name}",
                    name=name,
                    description=_normalize_text(tool.get("description")),
                    schema=_extract_schema(tool),
                    raw=tool,
                )
            )
        raw_resources = structure.get("resources") or []
        if isinstance(raw_resources, dict):
            raw_resources = list(raw_resources.values())
        for resource in raw_resources:
            name = str(resource.get("name") or resource.get("uri") or "resource")
            resources.append(
                ToolContext(
                    component=f"resource:{name}",
                    name=name,
                    description=_normalize_text(resource.get("description")),
                    schema=_extract_schema(resource),
                    raw=resource,
                )
            )
    headers = {}
    for probe in endpoint.probes:
        if probe.path == "/":
            headers = _merge_headers(headers, probe)
    return EndpointContext(
        tools=tools,
        resources=resources,
        headers=headers,
        capability_paths=list(endpoint.evidence.capability_paths),
    )


def _merge_headers(headers: Dict[str, str], probe: EndpointProbe) -> Dict[str, str]:
    merged = dict(headers)
    for key, value in probe.headers.items():
        merged.setdefault(key, value)
    return merged


def _extract_schema(item: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(item, dict):
        return {}
    for key in ("input_schema", "schema", "request_schema"):
        schema = item.get(key)
        if isinstance(schema, dict):
            return schema
    return {}


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _collect_schema_strings(schema: Dict[str, Any]) -> List[str]:
    strings: List[str] = []
    if not isinstance(schema, dict):
        return strings
    for key, value in schema.items():
        if isinstance(value, str):
            strings.append(value)
        elif isinstance(value, dict):
            strings.extend(_collect_schema_strings(value))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    strings.append(item)
                elif isinstance(item, dict):
                    strings.extend(_collect_schema_strings(item))
    return strings


def _contains_keywords(text: str, keywords: Iterable[str]) -> bool:
    lower = text.lower()
    return any(keyword in lower for keyword in keywords)


def _technique_metadata(meta: TechniqueMeta) -> Dict[str, Any]:
    return {
        "id": meta.identifier,
        "name": meta.name,
        "tactic": meta.tactic,
        "default_severity": meta.default_severity.value,
        "default_message": meta.default_message,
        "default_mitigation": meta.default_mitigation,
    }


def _build_vulnerabilities(
    endpoint: McpEndpoint,
    technique: TechniqueMeta,
    matches: List[TechniqueMatch],
) -> List[Vulnerability]:
    vulns: List[Vulnerability] = []
    for match in matches:
        evidence = {
            "technique": technique.identifier,
            "technique_name": technique.name,
            "tactic": technique.tactic,
            **match.evidence,
        }
        vulns.append(
            Vulnerability(
                endpoint=endpoint.base_url,
                component=match.component,
                category=f"safe_mcp.{technique.identifier.lower()}",
                severity=match.severity or technique.default_severity,
                message=match.detail or technique.default_message,
                mitigation=match.mitigation or technique.default_mitigation,
                detection_source="safe_mcp",
                evidence=evidence,
            )
        )
    return vulns


def _detect_safe_t1001(endpoint: McpEndpoint, context: EndpointContext) -> List[Vulnerability]:
    technique = SAFE_MCP_TECHNIQUES["SAFE-T1001"]
    matches: List[TechniqueMatch] = []
    suspicious_pattern = re.compile(
        r"(<!--.*?-->|system:|assistant:|ignore previous|base64:)", re.IGNORECASE | re.DOTALL
    )
    for entry in context.tools + context.resources:
        combined = f"{entry.description} {' '.join(_collect_schema_strings(entry.schema))}"
        snippets: List[str] = []
        if suspicious_pattern.search(combined):
            snippets.append(suspicious_pattern.search(combined).group(0) or "")
        hidden = [ch for ch in combined if ch in ZERO_WIDTH_CHARS]
        if hidden:
            snippets.append("zero-width characters")
        if snippets:
            matches.append(
                TechniqueMatch(
                    component=entry.component,
                    detail=technique.default_message,
                    evidence={"snippets": snippets, "tool": entry.name},
                )
            )
    return _build_vulnerabilities(endpoint, technique, matches)


def _detect_safe_t1002(endpoint: McpEndpoint, context: EndpointContext) -> List[Vulnerability]:
    technique = SAFE_MCP_TECHNIQUES["SAFE-T1002"]
    matches: List[TechniqueMatch] = []
    if endpoint.scheme != "https":
        matches.append(
            TechniqueMatch(
                component="server",
                detail=technique.default_message,
                evidence={"scheme": endpoint.scheme},
            )
        )
    ip_like = re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", endpoint.address)
    if ip_like:
        matches.append(
            TechniqueMatch(
                component="server",
                detail="Endpoint served from raw IP address without domain verification (SAFE-T1002).",
                evidence={"address": endpoint.address},
                mitigation=technique.default_mitigation,
            )
        )
    return _build_vulnerabilities(endpoint, technique, matches)


def _detect_safe_t1003(endpoint: McpEndpoint, context: EndpointContext) -> List[Vulnerability]:
    technique = SAFE_MCP_TECHNIQUES["SAFE-T1003"]
    matches: List[TechniqueMatch] = []
    suspect_keywords = ["backdoor", "payload", "trojan", "stealth", "masquerade", "unauthorized"]
    for entry in context.tools:
        if _contains_keywords(entry.description, suspect_keywords):
            matches.append(
                TechniqueMatch(
                    component=entry.component,
                    detail=technique.default_message,
                    evidence={"tool": entry.name, "description": entry.description},
                )
            )
    return _build_vulnerabilities(endpoint, technique, matches)


def _detect_safe_t1007(endpoint: McpEndpoint, context: EndpointContext) -> List[Vulnerability]:
    technique = SAFE_MCP_TECHNIQUES["SAFE-T1007"]
    matches: List[TechniqueMatch] = []
    oauth_keywords = ["oauth", "authorization", "consent", "redirect_uri", "client_id", "scope"]
    for entry in context.tools:
        schema_strings = _collect_schema_strings(entry.schema)
        combined = f"{entry.description} {' '.join(schema_strings)}"
        if _contains_keywords(combined, oauth_keywords):
            matches.append(
                TechniqueMatch(
                    component=entry.component,
                    detail=technique.default_message,
                    evidence={"tool": entry.name, "keywords": oauth_keywords},
                )
            )
    return _build_vulnerabilities(endpoint, technique, matches)


def _detect_safe_t1101(endpoint: McpEndpoint, context: EndpointContext) -> List[Vulnerability]:
    technique = SAFE_MCP_TECHNIQUES["SAFE-T1101"]
    matches: List[TechniqueMatch] = []
    command_keywords = ["shell", "execute", "command", "cli", "terminal", "powershell", "bash"]
    for entry in context.tools:
        schema_properties = entry.schema.get("properties") if isinstance(entry.schema, dict) else {}
        if isinstance(schema_properties, dict):
            for key in schema_properties.keys():
                if any(token in key.lower() for token in ("command", "cmd", "shell", "script")):
                    matches.append(
                        TechniqueMatch(
                            component=entry.component,
                            detail="Tool accepts raw command strings enabling command injection (SAFE-T1101).",
                            evidence={"tool": entry.name, "parameter": key},
                        )
                    )
        if _contains_keywords(entry.description, command_keywords):
            matches.append(
                TechniqueMatch(
                    component=entry.component,
                    detail="Tool description advertises command execution capability (SAFE-T1101).",
                    evidence={"tool": entry.name},
                )
            )
    return _build_vulnerabilities(endpoint, technique, matches)


def _detect_safe_t1102(endpoint: McpEndpoint, context: EndpointContext) -> List[Vulnerability]:
    technique = SAFE_MCP_TECHNIQUES["SAFE-T1102"]
    matches: List[TechniqueMatch] = []
    prompt_keywords = ["prompt", "instruction", "system", "act as", "override", "ignore previous"]
    for entry in context.tools + context.resources:
        text = f"{entry.description} {' '.join(_collect_schema_strings(entry.schema))}"
        if _contains_keywords(text, prompt_keywords):
            matches.append(
                TechniqueMatch(
                    component=entry.component,
                    detail="Unbounded prompt input present that may enable prompt injection (SAFE-T1102).",
                    evidence={"component": entry.component, "keywords": prompt_keywords},
                )
            )
    return _build_vulnerabilities(endpoint, technique, matches)


def _detect_safe_t1104(endpoint: McpEndpoint, context: EndpointContext) -> List[Vulnerability]:
    technique = SAFE_MCP_TECHNIQUES["SAFE-T1104"]
    matches: List[TechniqueMatch] = []
    privilege_keywords = ["admin", "root", "sudo", "privileged", "full access", "elevated"]
    for entry in context.tools:
        if _contains_keywords(entry.description, privilege_keywords):
            matches.append(
                TechniqueMatch(
                    component=entry.component,
                    detail="Tool advertises administrator-level privileges without controls (SAFE-T1104).",
                    evidence={"tool": entry.name},
                )
            )
    return _build_vulnerabilities(endpoint, technique, matches)


def _detect_safe_t1105(endpoint: McpEndpoint, context: EndpointContext) -> List[Vulnerability]:
    technique = SAFE_MCP_TECHNIQUES["SAFE-T1105"]
    matches: List[TechniqueMatch] = []
    for entry in context.tools:
        schema = entry.schema
        if schema.get("type") != "object":
            continue
        properties = schema.get("properties")
        if not isinstance(properties, dict):
            continue
        for key, subschema in properties.items():
            if not isinstance(subschema, dict):
                continue
            if any(token in key.lower() for token in ("path", "file", "directory", "target")):
                has_constraints = any(
                    constraint in subschema for constraint in ("enum", "pattern", "maxLength")
                )
                if not has_constraints:
                    matches.append(
                        TechniqueMatch(
                            component=entry.component,
                            detail="Path parameter is unbounded and susceptible to traversal (SAFE-T1105).",
                            evidence={"tool": entry.name, "parameter": key},
                        )
                    )
    return _build_vulnerabilities(endpoint, technique, matches)


def _detect_safe_t1106(endpoint: McpEndpoint, context: EndpointContext) -> List[Vulnerability]:
    technique = SAFE_MCP_TECHNIQUES["SAFE-T1106"]
    matches: List[TechniqueMatch] = []
    loop_keywords = ["auto", "loop", "repeat", "continuous", "cron", "schedule", "autonomous"]
    for entry in context.tools:
        if _contains_keywords(entry.description, loop_keywords):
            matches.append(
                TechniqueMatch(
                    component=entry.component,
                    detail="Autonomous looping behavior detected without human-in-the-loop (SAFE-T1106).",
                    evidence={"tool": entry.name},
                )
            )
    return _build_vulnerabilities(endpoint, technique, matches)


def _detect_safe_t1109(endpoint: McpEndpoint, context: EndpointContext) -> List[Vulnerability]:
    technique = SAFE_MCP_TECHNIQUES["SAFE-T1109"]
    matches: List[TechniqueMatch] = []
    debug_keywords = ["debug", "trace", "dump", "introspect", "memory", "stack", "profile"]
    for entry in context.tools:
        if _contains_keywords(entry.description, debug_keywords):
            matches.append(
                TechniqueMatch(
                    component=entry.component,
                    detail="Debug capability exposes sensitive runtime state (SAFE-T1109).",
                    evidence={"tool": entry.name},
                )
            )
    return _build_vulnerabilities(endpoint, technique, matches)


def _detect_safe_t1110(endpoint: McpEndpoint, context: EndpointContext) -> List[Vulnerability]:
    technique = SAFE_MCP_TECHNIQUES["SAFE-T1110"]
    matches: List[TechniqueMatch] = []
    multimodal_keywords = ["image", "audio", "vision", "speech", "render", "multimodal", "media"]
    for entry in context.tools + context.resources:
        if _contains_keywords(entry.description, multimodal_keywords):
            matches.append(
                TechniqueMatch(
                    component=entry.component,
                    detail="Multimodal ingestion lacks sanitization (SAFE-T1110).",
                    evidence={"component": entry.component},
                )
            )
    return _build_vulnerabilities(endpoint, technique, matches)


def _detect_safe_t1111(endpoint: McpEndpoint, context: EndpointContext) -> List[Vulnerability]:
    technique = SAFE_MCP_TECHNIQUES["SAFE-T1111"]
    matches: List[TechniqueMatch] = []
    cli_keywords = ["cli", "terminal", "shell", "command-line", "powershell", "bash"]
    for entry in context.tools:
        if _contains_keywords(entry.description, cli_keywords):
            matches.append(
                TechniqueMatch(
                    component=entry.component,
                    detail="CLI automation capability can weaponize the MCP agent (SAFE-T1111).",
                    evidence={"tool": entry.name},
                )
            )
    return _build_vulnerabilities(endpoint, technique, matches)


def _detect_safe_t1201(endpoint: McpEndpoint, context: EndpointContext) -> List[Vulnerability]:
    technique = SAFE_MCP_TECHNIQUES["SAFE-T1201"]
    matches: List[TechniqueMatch] = []
    update_keywords = [
        "auto-update",
        "auto update",
        "self-update",
        "hot swap",
        "latest version",
        "dynamic update",
    ]
    for entry in context.tools:
        if _contains_keywords(entry.description, update_keywords):
            matches.append(
                TechniqueMatch(
                    component=entry.component,
                    detail="Tool performs self-updates from remote sources (SAFE-T1201).",
                    evidence={"tool": entry.name},
                )
            )
    return _build_vulnerabilities(endpoint, technique, matches)


def _detect_safe_t1202(endpoint: McpEndpoint, context: EndpointContext) -> List[Vulnerability]:
    technique = SAFE_MCP_TECHNIQUES["SAFE-T1202"]
    matches: List[TechniqueMatch] = []
    persistence_keywords = [
        "refresh_token",
        "token store",
        "persist",
        "cache token",
        "long-lived token",
    ]
    for entry in context.tools:
        combined = f"{entry.description} {' '.join(_collect_schema_strings(entry.schema))}".lower()
        if any(keyword in combined for keyword in persistence_keywords):
            matches.append(
                TechniqueMatch(
                    component=entry.component,
                    detail="Tool persists OAuth tokens without scoped storage (SAFE-T1202).",
                    evidence={"tool": entry.name},
                )
            )
    return _build_vulnerabilities(endpoint, technique, matches)


def _detect_safe_t1303(endpoint: McpEndpoint, context: EndpointContext) -> List[Vulnerability]:
    technique = SAFE_MCP_TECHNIQUES["SAFE-T1303"]
    matches: List[TechniqueMatch] = []
    container_keywords = [
        "docker",
        "container",
        "podman",
        "kubectl",
        "k8s",
        "containerd",
        "runtime exec",
    ]
    for entry in context.tools:
        if _contains_keywords(entry.description, container_keywords):
            matches.append(
                TechniqueMatch(
                    component=entry.component,
                    detail="Container runtime controls exposed to MCP client (SAFE-T1303).",
                    evidence={"tool": entry.name},
                )
            )
    return _build_vulnerabilities(endpoint, technique, matches)


def _detect_safe_t1304(endpoint: McpEndpoint, context: EndpointContext) -> List[Vulnerability]:
    technique = SAFE_MCP_TECHNIQUES["SAFE-T1304"]
    matches: List[TechniqueMatch] = []
    credential_keywords = ["credential", "token", "secret", "password", "api key"]
    relay_keywords = ["send", "forward", "webhook", "post", "callback", "relay", "proxy"]
    for entry in context.tools:
        lower_desc = entry.description.lower()
        if any(word in lower_desc for word in credential_keywords) and any(
            word in lower_desc for word in relay_keywords
        ):
            matches.append(
                TechniqueMatch(
                    component=entry.component,
                    detail="Tool can relay captured credentials to external destinations (SAFE-T1304).",
                    evidence={"tool": entry.name},
                )
            )
    return _build_vulnerabilities(endpoint, technique, matches)


def _detect_safe_t1501(endpoint: McpEndpoint, context: EndpointContext) -> List[Vulnerability]:
    technique = SAFE_MCP_TECHNIQUES["SAFE-T1501"]
    matches: List[TechniqueMatch] = []
    for entry in context.tools:
        schema_strings = _collect_schema_strings(entry.schema)
        suspicious_defaults = [
            value
            for value in schema_strings
            if isinstance(value, str)
            and any(
                token in value.lower() for token in ("system:", "inject", "exec", "ignore previous")
            )
        ]
        if suspicious_defaults:
            matches.append(
                TechniqueMatch(
                    component=entry.component,
                    detail="Schema contains suspicious defaults or enum values (SAFE-T1501).",
                    evidence={"tool": entry.name, "defaults": suspicious_defaults[:5]},
                )
            )
    return _build_vulnerabilities(endpoint, technique, matches)


def _detect_safe_t1601(endpoint: McpEndpoint, context: EndpointContext) -> List[Vulnerability]:
    technique = SAFE_MCP_TECHNIQUES["SAFE-T1601"]
    matches: List[TechniqueMatch] = []
    exposed_paths = [path for path in context.capability_paths if path]
    if len(exposed_paths) >= 3:
        matches.append(
            TechniqueMatch(
                component="server",
                detail=technique.default_message,
                evidence={"paths": exposed_paths[:10]},
            )
        )
    return _build_vulnerabilities(endpoint, technique, matches)


def _detect_safe_t1703(endpoint: McpEndpoint, context: EndpointContext) -> List[Vulnerability]:
    technique = SAFE_MCP_TECHNIQUES["SAFE-T1703"]
    matches: List[TechniqueMatch] = []
    nodes = _build_capability_nodes(endpoint)
    low_priv = [node for node in nodes if "admin" not in node["privileges"] and node["privileges"]]
    admin_like = [node for node in nodes if {"admin", "execute"} & node["privileges"]]
    for helper in low_priv:
        for elevated in admin_like:
            if helper["id"] == elevated["id"]:
                continue
            matches.append(
                TechniqueMatch(
                    component="chain",
                    detail="Tool chaining path permits privilege pivoting (SAFE-T1703).",
                    evidence={"helper": helper, "elevated": elevated},
                    mitigation=technique.default_mitigation,
                )
            )
    return _build_vulnerabilities(endpoint, technique, matches)


def _detect_safe_t1705(endpoint: McpEndpoint, context: EndpointContext) -> List[Vulnerability]:
    technique = SAFE_MCP_TECHNIQUES["SAFE-T1705"]
    matches: List[TechniqueMatch] = []
    agent_keywords = ["agent", "multi-agent", "orchestrator", "workflow", "planner", "delegate"]
    for entry in context.tools + context.resources:
        if _contains_keywords(entry.description, agent_keywords):
            matches.append(
                TechniqueMatch(
                    component=entry.component,
                    detail="Inter-agent instruction surface exposed without validation (SAFE-T1705).",
                    evidence={"component": entry.component},
                )
            )
    return _build_vulnerabilities(endpoint, technique, matches)


def _detect_safe_t2107(endpoint: McpEndpoint, context: EndpointContext) -> List[Vulnerability]:
    technique = SAFE_MCP_TECHNIQUES["SAFE-T2107"]
    matches: List[TechniqueMatch] = []
    training_keywords = [
        "training data",
        "dataset",
        "label",
        "annotate",
        "collect data",
        "feedback",
    ]
    for entry in context.tools:
        if _contains_keywords(entry.description, training_keywords):
            matches.append(
                TechniqueMatch(
                    component=entry.component,
                    detail="Tool outputs feed training data pipelines without sanitization (SAFE-T2107).",
                    evidence={"tool": entry.name},
                )
            )
    return _build_vulnerabilities(endpoint, technique, matches)


def safe_mcp_technique_count() -> int:
    """Return the total count of SAFE-MCP techniques tracked by Conmap."""
    return len(SAFE_MCP_TECHNIQUES)


def safe_mcp_catalog() -> List[Dict[str, Any]]:
    """Return the full SAFE-MCP technique catalog metadata."""
    return [_technique_metadata(meta) for meta in SAFE_MCP_TECHNIQUES.values()]


def safe_mcp_lookup(technique_id: str) -> Optional[Dict[str, Any]]:
    """Lookup metadata for a specific SAFE-MCP technique ID."""
    meta = SAFE_MCP_TECHNIQUES.get(technique_id)
    if not meta:
        return None
    return _technique_metadata(meta)
