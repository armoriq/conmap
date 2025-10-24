from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, Iterable, List, Optional

from openai import APIError, OpenAI

from ..cache import Cache
from ..logging import get_logger
from ..models import AIInsight, McpEndpoint, Severity, Vulnerability

# Model configuration
DEFAULT_MODEL = os.getenv("CONMAP_MODEL") or os.getenv("MCP_SCANNER_MODEL") or "gpt-4o-mini"

_CODE_FENCE_PATTERN = re.compile(r"^```[a-zA-Z0-9_-]*\s*|\s*```$", re.IGNORECASE | re.MULTILINE)

logger = get_logger(__name__)


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


def run_llm_analyzer(
    endpoints: List[McpEndpoint],
    cache: Cache,
    enabled: bool = True,
    batch_size: int = 5,
) -> List[Vulnerability]:
    """
    Analyze MCP endpoints using OpenAI LLM to detect semantic vulnerabilities.
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
        batches = list(_extract_tools_in_batches(endpoint, batch_size=batch_size))
        if not batches:
            logger.info("No tools found for %s; skipping LLM analysis", endpoint.base_url)
            continue

        for batch in batches:
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
                        preview = ", ".join(keys[:5])
                        if len(keys) > 5:
                            preview += f", ... (+{len(keys) - 5} more)"
                        schema_preview = f"schema_keys=[{preview}]"
                        break
            context_bits = []
            if description_preview:
                context_bits.append(f'desc="{description_preview}"')
            if schema_preview:
                context_bits.append(schema_preview)
            context_summary = "; ".join(context_bits)

            normalized_batch = [_normalize_tool(tool) for tool in batch]
            payload = {"endpoint": endpoint.base_url, "tools": normalized_batch}

            cached_response = cache.get(payload)
            if cached_response:
                logger.info(
                    "Using cached LLM analysis endpoint=%s tools=%s",
                    endpoint.base_url,
                    tools_summary,
                )
                findings.extend(
                    _vulns_from_response(endpoint.base_url, cached_response, tools_summary)
                )
                continue

            response_text = _call_openai(
                client,
                payload,
                endpoint=endpoint.base_url,
                tools_summary=tools_summary,
                context_summary=context_summary,
            )
            if not response_text:
                logger.warning(
                    "LLM analysis returned no response endpoint=%s tools=%s",
                    endpoint.base_url,
                    tools_summary,
                )
                continue

            cache.set(payload, response_text)
            findings.extend(_vulns_from_response(endpoint.base_url, response_text, tools_summary))

    return findings


def _extract_tools_in_batches(
    endpoint: McpEndpoint, batch_size: int = 5
) -> Iterable[List[Dict[str, Any]]]:
    """
    Extract and batch tools from endpoint evidence.
    """
    tools: List[Dict[str, Any]] = []

    for structure in endpoint.evidence.json_structures:
        raw_tools = structure.get("tools", [])

        if isinstance(raw_tools, dict):
            raw_tools = list(raw_tools.values())

        for tool in raw_tools:
            if not isinstance(tool, dict):
                continue
            tools.append(_normalize_tool(tool))

    for i in range(0, len(tools), batch_size):
        yield tools[i : i + batch_size]


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

    text_chunks: List[str] = []

    output_text = getattr(response, "output_text", None)
    if isinstance(output_text, str) and output_text.strip():
        logger.info(
            "LLM direct output endpoint=%s tools=%s body=%s",
            endpoint,
            tools_summary,
            output_text,
        )
        text_chunks.append(output_text)

    for item in getattr(response, "output", []) or []:
        if getattr(item, "type", None) == "message":
            message = getattr(item, "message", None)
            if message:
                contents = getattr(message, "content", [])
                for content in contents or []:
                    if getattr(content, "type", None) == "text":
                        text = getattr(content, "text", None)
                        if isinstance(text, str) and text:
                            text_chunks.append(text)
        else:
            text = getattr(item, "text", None)
            if isinstance(text, str) and text:
                text_chunks.append(text)

    if not text_chunks:
        choices = getattr(response, "choices", None)
        if choices:
            for choice in choices:
                message = getattr(choice, "message", None)
                if isinstance(message, dict):
                    content = message.get("content")
                    if isinstance(content, str) and content:
                        text_chunks.append(content)
                elif hasattr(message, "content"):
                    contents = getattr(message, "content", [])
                    if isinstance(contents, list):
                        for part in contents:
                            if isinstance(part, dict):
                                text = part.get("text")
                                if isinstance(text, str) and text:
                                    text_chunks.append(text)
                            elif hasattr(part, "text"):
                                text = getattr(part, "text", None)
                                if isinstance(text, str) and text:
                                    text_chunks.append(text)

    if not text_chunks:
        logger.info(
            "LLM response endpoint=%s tools=%s lacked text output",
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


def _clean_response_text(response_text: str) -> str:
    if not response_text:
        return ""
    cleaned = response_text.strip()
    if cleaned.startswith("```"):
        cleaned = _CODE_FENCE_PATTERN.sub("", cleaned).strip()
    return cleaned


def _parse_vulnerabilities(endpoint: str, response_text: str) -> List[Vulnerability]:
    cleaned_text = _clean_response_text(response_text)
    if not cleaned_text:
        return []

    try:
        data = json.loads(cleaned_text)
    except json.JSONDecodeError as exc:
        logger.warning(
            "Failed to parse OpenAI response endpoint=%s error=%s preview=%s",
            endpoint,
            exc,
            _preview_text(cleaned_text, 120),
        )
        return []

    if isinstance(data, dict):
        threats = data.get("threats", [])
    elif isinstance(data, list):
        threats = data
    else:
        logger.warning(
            "Unexpected response format endpoint=%s type=%s",
            endpoint,
            type(data).__name__,
        )
        return []

    if not isinstance(threats, list):
        logger.warning(
            "Threats payload not a list endpoint=%s type=%s",
            endpoint,
            type(threats).__name__,
        )
        return []

    findings: List[Vulnerability] = []

    for entry in threats:
        if not isinstance(entry, dict):
            continue

        tool_name = str(entry.get("tool") or "unknown")
        threat_message = str(entry.get("threat") or "Unknown threat")

        try:
            confidence_value = float(entry.get("confidence", 0))
        except (TypeError, ValueError):
            confidence_value = 50.0

        confidence_value = max(0.0, min(100.0, confidence_value))

        if confidence_value >= 85:
            severity = Severity.critical
        elif confidence_value >= 70:
            severity = Severity.high
        elif confidence_value >= 50:
            severity = Severity.medium
        elif confidence_value >= 30:
            severity = Severity.low
        else:
            severity = Severity.info

        ai_insight = AIInsight(
            threat=threat_message,
            confidence=int(confidence_value),
            rationale=str(entry.get("rationale") or ""),
            suggested_mitigation=entry.get("suggestedMitigation"),
        )

        finding = Vulnerability(
            endpoint=endpoint,
            component=tool_name,
            category="llm.analysis",
            severity=severity,
            message=threat_message,
            evidence={"tool": tool_name},
            mitigation=entry.get("suggestedMitigation"),
            detection_source="llm",
            confidence=float(ai_insight.confidence),
            ai_insight=ai_insight,
        )
        findings.append(finding)

    return findings


def _vulns_from_response(
    endpoint: str, response_text: str, tools_summary: str
) -> List[Vulnerability]:
    findings = _parse_vulnerabilities(endpoint, response_text)

    if not findings:
        logger.info(
            "LLM analysis produced 0 threats endpoint=%s tools=%s",
            endpoint,
            tools_summary,
        )
        return []

    for finding in findings:
        confidence = finding.ai_insight.confidence if finding.ai_insight else finding.confidence
        logger.info(
            "LLM insight endpoint=%s tool=%s severity=%s confidence=%s message=%s",
            endpoint,
            finding.component,
            finding.severity.value,
            confidence,
            finding.message,
        )
        if finding.ai_insight:
            logger.info(
                "LLM insight rationale endpoint=%s tool=%s rationale=%s mitigation=%s",
                endpoint,
                finding.component,
                finding.ai_insight.rationale,
                finding.ai_insight.suggested_mitigation,
            )

    logger.info(
        "LLM analysis produced %s threats endpoint=%s tools=%s",
        len(findings),
        endpoint,
        tools_summary,
    )
    return findings
