from __future__ import annotations

from typing import Dict, List, Set

from ..models import McpEndpoint, Severity, Vulnerability


def run_chain_detector(endpoints: List[McpEndpoint]) -> List[Vulnerability]:
    findings: List[Vulnerability] = []
    for endpoint in endpoints:
        nodes = _build_capability_nodes(endpoint)
        findings.extend(_detect_data_exfiltration(endpoint.base_url, nodes))
        findings.extend(_detect_privilege_escalation(endpoint.base_url, nodes))
        findings.extend(_detect_code_execution(endpoint.base_url, nodes))
        findings.extend(_detect_database_compromise(endpoint.base_url, nodes))
    return findings


def _build_capability_nodes(endpoint: McpEndpoint) -> List[Dict[str, Set[str]]]:
    nodes: List[Dict[str, Set[str]]] = []
    for structure in endpoint.evidence.json_structures:
        tools = structure.get("tools") or []
        if isinstance(tools, dict):
            tools = tools.values()
        for tool in tools:
            name = str(tool.get("name", "unknown"))
            description = str(tool.get("description", ""))
            nodes.append(
                {
                    "id": f"tool:{name}",
                    "name": name,
                    "privileges": _infer_privileges(name, description),
                    "data_access": _infer_data_access(name, description),
                }
            )
        resources = structure.get("resources") or []
        for resource in resources:
            resource_name = str(resource.get("name") or resource.get("uri") or "resource")
            description = str(resource.get("description", ""))
            nodes.append(
                {
                    "id": f"resource:{resource_name}",
                    "name": resource_name,
                    "privileges": _infer_privileges(resource_name, description),
                    "data_access": _infer_data_access(resource_name, description),
                }
            )
    return nodes


def _infer_privileges(name: str, description: str) -> Set[str]:
    text = f"{name} {description}".lower()
    privileges: Set[str] = set()
    if any(keyword in text for keyword in ["read", "get", "fetch", "list", "view", "dump"]):
        privileges.add("read")
    if any(
        keyword in text
        for keyword in ["write", "create", "post", "add", "insert", "save", "upload"]
    ):
        privileges.add("create")
    if any(keyword in text for keyword in ["update", "modify", "edit", "patch", "put"]):
        privileges.add("update")
    if any(keyword in text for keyword in ["delete", "remove", "drop", "destroy"]):
        privileges.add("delete")
    if any(keyword in text for keyword in ["admin", "root", "sudo", "elevate", "privilege"]):
        privileges.add("admin")
    if any(
        keyword in text for keyword in ["network", "http", "fetch", "request", "url", "webhook"]
    ):
        privileges.add("network")
    if any(keyword in text for keyword in ["file", "path", "directory", "disk"]):
        privileges.add("filesystem")
    if any(keyword in text for keyword in ["execute", "run", "shell", "command", "launch", "exec"]):
        privileges.add("execute")
    return privileges


def _infer_data_access(name: str, description: str) -> Set[str]:
    text = f"{name} {description}".lower()
    data_types: Set[str] = set()
    if any(keyword in text for keyword in ["user", "account", "profile", "identity"]):
        data_types.add("user_data")
    if any(
        keyword in text for keyword in ["password", "secret", "key", "token", "credential", "auth"]
    ):
        data_types.add("credentials")
    if any(keyword in text for keyword in ["file", "document", "path"]):
        data_types.add("files")
    if any(keyword in text for keyword in ["database", "db", "sql", "query", "postgres", "mysql"]):
        data_types.add("database")
    if any(keyword in text for keyword in ["config", "configuration", "setting", "environment"]):
        data_types.add("configuration")
    if any(keyword in text for keyword in ["log", "audit", "history", "telemetry"]):
        data_types.add("logs")
    return data_types


def _detect_data_exfiltration(
    endpoint: str,
    nodes: List[Dict[str, Set[str]]],
) -> List[Vulnerability]:
    findings: List[Vulnerability] = []
    readers = [
        node
        for node in nodes
        if "read" in node["privileges"] and ({"credentials", "user_data"} & node["data_access"])
    ]
    networkers = [node for node in nodes if "network" in node["privileges"]]

    for reader in readers:
        for networker in networkers:
            reader_priv = reader["privileges"]
            network_priv = networker["privileges"]
            combined_privileges = reader_priv | network_priv
            privilege_union = sorted(combined_privileges)
            findings.append(
                Vulnerability(
                    endpoint=endpoint,
                    component="chain",
                    category="chain.data_exfiltration",
                    severity=Severity.high,
                    message=(
                        f"{reader['name']} can access sensitive data "
                        f"which may be exfiltrated via {networker['name']}."
                    ),
                    mitigation=(
                        "Segment sensitive data access and gate outbound network operations."
                    ),
                    detection_source="graph",
                    chain_path=[reader["name"], networker["name"]],
                    steps=[reader["id"], networker["id"]],
                    required_privileges=privilege_union,
                    evidence={"reader": reader, "network": networker},
                )
            )
    return findings


def _detect_privilege_escalation(
    endpoint: str,
    nodes: List[Dict[str, Set[str]]],
) -> List[Vulnerability]:
    findings: List[Vulnerability] = []
    admin_nodes = [node for node in nodes if "admin" in node["privileges"]]
    helpers = [
        node
        for node in nodes
        if "admin" not in node["privileges"]
        and ("read" in node["privileges"] or "configuration" in node["data_access"])
    ]

    for helper in helpers:
        for admin in admin_nodes:
            helper_priv = helper["privileges"]
            admin_priv = admin["privileges"]
            combined_privileges = helper_priv | admin_priv
            privilege_union = sorted(combined_privileges)
            findings.append(
                Vulnerability(
                    endpoint=endpoint,
                    component="chain",
                    category="chain.privilege_escalation",
                    severity=Severity.high,
                    message=(
                        f"{helper['name']} can provide inputs that enable "
                        f"elevated tool {admin['name']}."
                    ),
                    mitigation=(
                        "Require step-up authentication and audit access to admin-capable tools."
                    ),
                    detection_source="graph",
                    chain_path=[helper["name"], admin["name"]],
                    steps=[helper["id"], admin["id"]],
                    required_privileges=privilege_union,
                    evidence={"support": helper, "admin": admin},
                )
            )
    return findings


def _detect_code_execution(
    endpoint: str,
    nodes: List[Dict[str, Set[str]]],
) -> List[Vulnerability]:
    findings: List[Vulnerability] = []
    file_nodes = [
        node
        for node in nodes
        if "filesystem" in node["privileges"] and ({"create", "update"} & node["privileges"])
    ]
    exec_nodes = [node for node in nodes if "execute" in node["privileges"]]

    for file_node in file_nodes:
        for exec_node in exec_nodes:
            file_priv = file_node["privileges"]
            exec_priv = exec_node["privileges"]
            combined_privileges = file_priv | exec_priv
            privilege_union = sorted(combined_privileges)
            findings.append(
                Vulnerability(
                    endpoint=endpoint,
                    component="chain",
                    category="chain.code_execution",
                    severity=Severity.critical,
                    message=(
                        f"{file_node['name']} can create or alter files "
                        f"that {exec_node['name']} may execute."
                    ),
                    mitigation=(
                        "Restrict execution contexts and enforce signed or allow-listed binaries."
                    ),
                    detection_source="graph",
                    chain_path=[file_node["name"], exec_node["name"]],
                    steps=[file_node["id"], exec_node["id"]],
                    required_privileges=privilege_union,
                    evidence={"file": file_node, "executor": exec_node},
                )
            )
    return findings


def _detect_database_compromise(
    endpoint: str,
    nodes: List[Dict[str, Set[str]]],
) -> List[Vulnerability]:
    findings: List[Vulnerability] = []
    config_nodes = [node for node in nodes if "configuration" in node["data_access"]]
    database_nodes = [node for node in nodes if "database" in node["data_access"]]

    for config in config_nodes:
        for db in database_nodes:
            config_priv = config["privileges"]
            db_priv = db["privileges"]
            combined_privileges = config_priv | db_priv
            privilege_union = sorted(combined_privileges)
            findings.append(
                Vulnerability(
                    endpoint=endpoint,
                    component="chain",
                    category="chain.database_compromise",
                    severity=Severity.high,
                    message=(
                        f"Configuration insights from {config['name']} could expose secrets "
                        f"for database tool {db['name']}."
                    ),
                    mitigation=(
                        "Rotate credentials and constrain tools that expose configuration secrets."
                    ),
                    detection_source="graph",
                    chain_path=[config["name"], db["name"]],
                    steps=[config["id"], db["id"]],
                    required_privileges=privilege_union,
                    evidence={"config": config, "database": db},
                )
            )
    return findings
