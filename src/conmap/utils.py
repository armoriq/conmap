from __future__ import annotations

import ipaddress
import json
from typing import Any, Dict, Iterable, Optional


MCP_KEYWORDS = {"capabilities", "tools", "resources", "prompts", "model"}


def is_likely_mcp_payload(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    lowered = {str(key).lower(): value for key, value in payload.items()}
    if "model" in lowered and isinstance(lowered["model"], dict):
        return True
    intersection = MCP_KEYWORDS.intersection(lowered.keys())
    if intersection:
        return True
    if "type" in lowered and lowered["type"].lower() == "mcp":
        return True
    if "schema" in lowered and isinstance(lowered["schema"], dict):
        return True
    return False


def safe_json_parse(text: str) -> Optional[Any]:
    try:
        return json.loads(text)
    except (TypeError, json.JSONDecodeError):
        return None


def iter_hosts(network: ipaddress.IPv4Network, include_self: bool = False) -> Iterable[str]:
    if include_self:
        yield str(network.network_address)
    for host in network.hosts():
        yield str(host)
