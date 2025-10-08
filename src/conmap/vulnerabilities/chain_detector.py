from __future__ import annotations

from typing import Dict, List, Set

from ..models import McpEndpoint, Severity, Vulnerability


def run_chain_detector(endpoints: List[McpEndpoint]) -> List[Vulnerability]:
    findings: List[Vulnerability] = []
    for endpoint in endpoints:
        graph = _build_capability_graph(endpoint)
        findings.extend(_detect_data_exfiltration(endpoint.base_url, graph))
        findings.extend(_detect_privilege_escalation(endpoint.base_url, graph))
        findings.extend(_detect_code_execution(endpoint.base_url, graph))
        findings.extend(_detect_database_compromise(endpoint.base_url, graph))
    return findings


def _build_capability_graph(endpoint: McpEndpoint) -> Dict[str, Set[str]]:
    graph: Dict[str, Set[str]] = {"read_sensitive": set(), "network_tx": set(), "admin": set(),
                                  "write_file": set(), "execute": set(), "config_read": set(),
                                  "database": set()}
    for structure in endpoint.evidence.json_structures:
        tools = structure.get("tools") or []
        if isinstance(tools, dict):
            tools = tools.values()
        for tool in tools:
            name = str(tool.get("name", "unknown"))
            description = str(tool.get("description", "")).lower()
            tags = _classify_tool(name.lower(), description)
            for tag in tags:
                graph.setdefault(tag, set()).add(name)
    return graph


def _classify_tool(name: str, description: str) -> Set[str]:
    tags: Set[str] = set()
    text = f"{name} {description}"
    if any(keyword in text for keyword in ["secret", "credential", "token", "password", "sensitive"]):
        tags.add("read_sensitive")
    if any(keyword in text for keyword in ["download", "export", "exfiltrate", "send", "http", "upload", "webhook"]):
        tags.add("network_tx")
    if any(keyword in text for keyword in ["admin", "elevate", "privilege", "sudo"]):
        tags.add("admin")
    if any(keyword in text for keyword in ["write", "save", "store", "create file", "append"]):
        tags.add("write_file")
    if any(keyword in text for keyword in ["execute", "run", "shell", "command", "launch"]):
        tags.add("execute")
    if any(keyword in text for keyword in ["config", "configuration", "settings"]):
        tags.add("config_read")
    if any(keyword in text for keyword in ["database", "sql", "query", "postgres", "mysql"]):
        tags.add("database")
    return tags


def _detect_data_exfiltration(endpoint: str, graph: Dict[str, Set[str]]) -> List[Vulnerability]:
    if graph.get("read_sensitive") and graph.get("network_tx"):
        return [
            Vulnerability(
                endpoint=endpoint,
                component="chain",
                category="chain.data_exfiltration",
                severity=Severity.high,
                message="Sensitive data read capabilities combine with network transmission tools.",
                evidence={
                    "read_tools": sorted(graph.get("read_sensitive", [])),
                    "network_tools": sorted(graph.get("network_tx", [])),
                },
            )
        ]
    return []


def _detect_privilege_escalation(endpoint: str, graph: Dict[str, Set[str]]) -> List[Vulnerability]:
    if graph.get("admin") and (graph.get("read_sensitive") or graph.get("config_read")):
        return [
            Vulnerability(
                endpoint=endpoint,
                component="chain",
                category="chain.privilege_escalation",
                severity=Severity.high,
                message="Normal tools interact with admin-level functions without barriers.",
                evidence={
                    "admin_tools": sorted(graph.get("admin", [])),
                    "supporting_tools": sorted(
                        graph.get("read_sensitive", set()) | graph.get("config_read", set())
                    ),
                },
            )
        ]
    return []


def _detect_code_execution(endpoint: str, graph: Dict[str, Set[str]]) -> List[Vulnerability]:
    if graph.get("write_file") and graph.get("execute"):
        return [
            Vulnerability(
                endpoint=endpoint,
                component="chain",
                category="chain.code_execution",
                severity=Severity.critical,
                message="Tools allow writing files and executing arbitrary commands.",
                evidence={
                    "write_tools": sorted(graph.get("write_file", [])),
                    "execute_tools": sorted(graph.get("execute", [])),
                },
            )
        ]
    return []


def _detect_database_compromise(endpoint: str, graph: Dict[str, Set[str]]) -> List[Vulnerability]:
    if graph.get("config_read") and graph.get("database"):
        return [
            Vulnerability(
                endpoint=endpoint,
                component="chain",
                category="chain.database_compromise",
                severity=Severity.high,
                message="Configuration inspection tools combine with database access operations.",
                evidence={
                    "config_tools": sorted(graph.get("config_read", [])),
                    "database_tools": sorted(graph.get("database", [])),
                },
            )
        ]
    return []
