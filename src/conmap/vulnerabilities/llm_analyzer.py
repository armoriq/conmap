from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, Iterable, List, Optional

from openai import APIError, OpenAI

from ..cache import Cache
from ..models import AIInsight, McpEndpoint, Severity, Vulnerability

# Model configuration
DEFAULT_MODEL = os.getenv("CONMAP_MODEL") or os.getenv("MCP_SCANNER_MODEL") or "gpt-4o-mini"


def _format_tool_list(names: List[str], max_items: int = 5) -> str:
    filtered = [name or "unknown" for name in names if name]
    if not filtered:
        return "none"
    if len(filtered) <= max_items:
        return ", ".join(filtered)
    remaining = len(filtered) - max_items
    return ", ".join(filtered[:max_items]) + f", ... (+{remaining} more)"


def _preview_text(text: str, limit: int = 160) -> str:
    if not text:
        return ""
    compact = " ".join(str(text).split())
    if len(compact) <= limit:
        return compact
    return compact[:limit].rstrip() + "..."


def run_llm_analyzer(
    endpoints: List[McpEndpoint],
    cache: Cache,
    enabled: bool = True,
    batch_size: int = 5,
) -> List[Vulnerability]:
    """
    Analyze MCP endpoints using OpenAI LLM to detect semantic vulnerabilities.

    Args:
        endpoints: List of discovered MCP endpoints
        cache: Cache for storing API responses
        enabled: Whether LLM analysis is enabled
        batch_size: Number of tools to analyze per API call (default: 5)

    Returns:
        List of vulnerabilities found by the LLM
    """
    if not enabled:
        logger.info("LLM analyzer disabled; skipping")
        return []

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        logger.info("OPENAI_API_KEY missing; skipping LLM analysis")
        return []

    client = OpenAI(api_key=api_key)
    findings: List[Vulnerability] = []

    for endpoint in endpoints:
        batches = _extract_tools_in_batches(endpoint, batch_size=batch_size)

        for batch in batches:
            empty = False
            tool_names = [str(tool.get("name", "unknown") or "unknown") for tool in batch]
            tools_summary = _format_tool_list(tool_names)
            description_preview = next(
                (
                    _preview_text(tool.get("description"), 120)
                    for tool in batch
                    if tool.get("description")
                ),
                "",
            )
            schema_preview = ""
            for tool in batch:
                schema = tool.get("schema") or {}
                if schema:
                    keys = sorted(schema.keys())
                    if keys:
                        max_keys = 5
                        preview = ", ".join(keys[:max_keys])
                        if len(keys) > max_keys:
                            preview += f", ... (+{len(keys) - max_keys} more)"
                        schema_preview = f"schema_keys=[{preview}]"
                        break
            context_bits = []
            if description_preview:
                context_bits.append(f'desc="{description_preview}"')
            if schema_preview:
                context_bits.append(schema_preview)
            context_summary = "; ".join(context_bits)
            payload = {
                "endpoint": endpoint.base_url,
                "tools": [_normalize_tool(tool) for tool in batch],
            }
            logger.info(
                "Prepared LLM batch endpoint=%s tools=%s context=%s",
                endpoint.base_url,
                tools_summary,
                context_summary or "no descriptive metadata",
            )
            cached = cache.get(payload)
            if cached:
                logger.info(
                    "Using cached LLM analysis endpoint=%s tools=%s",
                    endpoint.base_url,
                    tools_summary,
                )
                findings.extend(_vulns_from_response(endpoint.base_url, cached, tools_summary))
                continue
            logger.info(
                "Invoking OpenAI model=%s endpoint=%s tools=%s context=%s",
                DEFAULT_MODEL,
                endpoint.base_url,
                tools_summary,
                context_summary or "no descriptive metadata",
            )
            response = _call_openai(
                client,
                payload,
                endpoint.base_url,
                tools_summary,
                context_summary,
            )
            if response:
                cache.set(payload, response)
                response_preview = _preview_text(response, 200)
                logger.info(
                    "LLM response captured endpoint=%s tools=%s preview=%s",
                    endpoint.base_url,
                    tools_summary,
                    response_preview or "<empty>",
                )
                findings.extend(_vulns_from_response(endpoint.base_url, response, tools_summary))
            else:
                logger.warning(
                    "LLM analysis returned no response endpoint=%s tools=%s",
                    endpoint.base_url,
                    tools_summary,
                )
        if empty:
            logger.info("No tools found for %s; skipping LLM analysis", endpoint.base_url)
    return findings


def _extract_tools_in_batches(
    endpoint: McpEndpoint, batch_size: int = 5
) -> Iterable[List[Dict[str, Any]]]:
    """
    Extract and batch tools from endpoint evidence.

    Args:
        endpoint: MCP endpoint to extract tools from
        batch_size: Number of tools per batch

    Yields:
        Batches of tool definitions
    """
    tools: List[Dict[str, Any]] = []

    for structure in endpoint.evidence.json_structures:
        raw_tools = structure.get("tools", [])

        # Handle both list and dict formats
        if isinstance(raw_tools, dict):
            raw_tools = list(raw_tools.values())

        for tool in raw_tools:
            if not isinstance(tool, dict):
                continue

            tools.append(_normalize_tool(tool))

    # Yield tools in batches
    for i in range(0, len(tools), batch_size):
        yield tools[i : i + batch_size]


SYSTEM_PROMPT = """You are an expert security researcher specializing in Model Context Protocol (MCP) vulnerabilities.

Your task is to analyze MCP tool definitions and identify security risks including:
- Unrestricted file system access
- Command injection vulnerabilities
- SQL injection possibilities
- Privilege escalation paths
- Data exfiltration risks
- Missing input validation
- Unsafe default values
- Insufficient access controls

CRITICAL: You must respond with ONLY valid JSON, no markdown formatting, no code blocks.

Response format:
{
  "threats": [
    {
      "tool": "tool_name",
      "threat": "Brief threat description",
      "confidence": 95,
      "rationale": "Detailed explanation of the vulnerability",
      "suggestedMitigation": "How to fix this issue"
    }
  ]
}

If no threats are found, return: {"threats": []}

DO NOT wrap your response in ```json``` or any markdown formatting.
DO NOT include any text before or after the JSON.
ONLY return valid JSON."""


def _normalize_tool(tool: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize tool definitions to a consistent, JSON-safe structure."""

    def _sanitize(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: _sanitize(val) for key, val in value.items()}
        if isinstance(value, list):
            return [_sanitize(item) for item in value]
        if isinstance(value, set):
            sanitized = [_sanitize(item) for item in value]
            try:
                return sorted(sanitized, key=lambda item: json.dumps(item, sort_keys=True))
            except TypeError:
                return sorted(sanitized, key=lambda item: str(item))
        return value

    sanitized_tool = _sanitize(tool)
    schema = (
        sanitized_tool.get("inputSchema")
        or sanitized_tool.get("input_schema")
        or sanitized_tool.get("schema")
        or {}
    )
    sanitized_tool["inputSchema"] = schema
    sanitized_tool["schema"] = schema
    sanitized_tool["name"] = sanitized_tool.get("name", "unknown")
    sanitized_tool["description"] = sanitized_tool.get("description", "")
    return sanitized_tool


def _call_openai(
    client: OpenAI,
    payload: Dict[str, Any],
    endpoint: str = "unknown",
    tools_summary: str = "unknown",
    context_summary: str = "",
) -> Optional[str]:
    logger.info(
        "Submitting LLM request endpoint=%s tools=%s context=%s",
        endpoint,
        tools_summary,
        context_summary or "no descriptive metadata",
    )
    try:
        response = client.responses.create(
            model=DEFAULT_MODEL,
            input=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(payload, indent=2)},
            ],
            temperature=0.1,
        )
    except APIError as exc:
        logger.warning(
            "OpenAI API error endpoint=%s tools=%s error=%s",
            endpoint,
            tools_summary,
            exc,
        )
        return None
    text_chunks = []
    output_text = getattr(response, "output_text", None)
    if output_text:
        logger.info(
            "LLM direct output endpoint=%s tools=%s body=%s",
            endpoint,
            tools_summary,
            output_text,
        )
        text_chunks.append(output_text)
    for item in getattr(response, "output", []):
        if getattr(item, "type", None) == "message":
            message = getattr(item, "message", None)
            if message:
                for content in getattr(message, "content", []) or []:
                    if getattr(content, "type", None) == "text":
                        text = getattr(content, "text", None)
                        if text:
                            text_chunks.append(text)
    if not text_chunks:
        choices = getattr(response, "choices", None)
        if choices:
            for choice in choices:
                message = getattr(choice, "message", None)
                if message and isinstance(message, dict):
                    content = message.get("content")
                    if isinstance(content, str):
                        text_chunks.append(content)
        if not text_chunks and hasattr(response, "output"):
            logger.info(
                "LLM response endpoint=%s tools=%s lacked text output message_types=%s",
                endpoint,
                tools_summary,
                [getattr(item, "type", None) for item in response.output],
            )
    if not text_chunks:
        logger.info(
            "LLM response contained no text output endpoint=%s tools=%s",
            endpoint,
            tools_summary,
        )
        return None
    combined = "\n".join(text_chunks)
    logger.info(
        "LLM aggregated response endpoint=%s tools=%s body=%s",
        endpoint,
        tools_summary,
        combined,
    )
    return combined

    Args:
        endpoint: Endpoint URL
        response_text: JSON response from OpenAI

def _vulns_from_response(
    endpoint: str, response_text: str, tools_summary: str
) -> List[Vulnerability]:
    try:
        data = json.loads(cleaned_text)
    except json.JSONDecodeError as e:
        print(f"Failed to parse OpenAI response as JSON: {e}")
        print(f"Response text: {cleaned_text[:500]}")
        return []

    # Extract threats
    if isinstance(data, dict):
        threats = data.get("threats", [])
    elif isinstance(data, list):
        threats = data
    else:
        print(f"Unexpected response format: {type(data)}")
        return []

    if not isinstance(threats, list):
        print(f"Threats is not a list: {type(threats)}")
        return []

    # Convert threats to vulnerabilities
    findings: List[Vulnerability] = []

    for threat in threats:
        if not isinstance(threat, dict):
            continue

        # Extract and validate confidence
        try:
            confidence = float(threat.get("confidence", 0))
            confidence = max(0, min(100, confidence))  # Clamp to 0-100
        except (TypeError, ValueError):
            confidence = 50  # Default to medium confidence

        # Map confidence to severity
        if confidence >= 85:
            severity = Severity.critical
        elif confidence >= 70:
            severity = Severity.high
        elif confidence >= 50:
            severity = Severity.medium
        elif confidence >= 30:
            severity = Severity.low
        else:
            severity = Severity.info

        # Create AI insight
        ai_insight = AIInsight(
            threat=str(threat.get("threat", "Unknown threat")),
            confidence=int(confidence),
            rationale=str(threat.get("rationale", "")),
            suggested_mitigation=threat.get("suggestedMitigation"),
        )
        logger.info(
            "LLM insight endpoint=%s tool=%s severity=%s confidence=%s message=%s",
            endpoint,
            entry.get("tool", "llm"),
            severity.value,
            insight.confidence,
            insight.threat,
        )
        logger.info(
            "LLM insight rationale endpoint=%s tool=%s rationale=%s mitigation=%s",
            endpoint,
            entry.get("tool", "llm"),
            insight.rationale,
            insight.suggested_mitigation,
        )
    logger.info(
        "LLM analysis produced %s threats endpoint=%s tools=%s",
        len(findings),
        endpoint,
        tools_summary,
    )
    return findings
