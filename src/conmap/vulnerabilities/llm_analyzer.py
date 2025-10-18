from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, Iterable, List, Optional

from openai import APIError, OpenAI

from ..cache import Cache
from ..models import AIInsight, McpEndpoint, Severity, Vulnerability

# Model configuration
DEFAULT_MODEL = "gpt-4o-mini"


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
        return []

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return []

    client = OpenAI(api_key=api_key)
    findings: List[Vulnerability] = []

    for endpoint in endpoints:
        batches = _extract_tools_in_batches(endpoint, batch_size=batch_size)

        for batch in batches:
            if not batch:
                continue

            # Check cache first
            payload = {"endpoint": endpoint.base_url, "tools": batch}
            cached_response = cache.get(payload)

            if cached_response:
                findings.extend(_parse_vulnerabilities(endpoint.base_url, cached_response))
                continue

            # Call OpenAI API
            response = _analyze_with_openai(client, endpoint.base_url, batch)

            if response:
                cache.set(payload, response)
                findings.extend(_parse_vulnerabilities(endpoint.base_url, response))

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

            tools.append(
                {
                    "name": tool.get("name", "unknown"),
                    "description": tool.get("description", ""),
                    "inputSchema": tool.get("inputSchema")
                    or tool.get("input_schema")
                    or tool.get("schema")
                    or {},
                }
            )

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


def _analyze_with_openai(
    client: OpenAI, endpoint_url: str, tools: List[Dict[str, Any]]
) -> Optional[str]:
    """
    Send tools to OpenAI for security analysis.

    Args:
        client: OpenAI client instance
        endpoint_url: URL of the endpoint being analyzed
        tools: List of tool definitions to analyze

    Returns:
        OpenAI response text or None if failed
    """
    user_message = json.dumps({"endpoint": endpoint_url, "tools": tools}, indent=2)

    try:
        response = client.chat.completions.create(
            model=DEFAULT_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
            temperature=0.1,
            response_format={"type": "json_object"},
        )

        if response.choices and len(response.choices) > 0:
            return response.choices[0].message.content

        return None

    except APIError as e:
        print(f"OpenAI API Error: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error calling OpenAI: {e}")
        return None


def _clean_response_text(text: str) -> str:
    """
    Clean OpenAI response by removing markdown code blocks and extra whitespace.

    Args:
        text: Raw response text from OpenAI

    Returns:
        Cleaned JSON string
    """
    text = text.strip()

    # Remove markdown code blocks (```json ... ``` or ``` ... ```)
    code_block_pattern = r"^```(?:json)?\s*\n(.*?)\n```$"
    match = re.match(code_block_pattern, text, re.DOTALL)
    if match:
        text = match.group(1).strip()

    # Remove leading/trailing backticks if present
    text = text.strip("`").strip()

    return text


def _parse_vulnerabilities(endpoint: str, response_text: str) -> List[Vulnerability]:
    """
    Parse OpenAI response and convert to Vulnerability objects.

    Args:
        endpoint: Endpoint URL
        response_text: JSON response from OpenAI

    Returns:
        List of Vulnerability objects
    """
    # Clean the response
    cleaned_text = _clean_response_text(response_text)

    # Parse JSON
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

        # Create vulnerability
        vulnerability = Vulnerability(
            endpoint=endpoint,
            component=str(threat.get("tool", "unknown")),
            category="llm.semantic_analysis",
            severity=severity,
            message=ai_insight.threat,
            mitigation=ai_insight.suggested_mitigation,
            detection_source="openai_llm",
            confidence=ai_insight.confidence,
            ai_insight=ai_insight,
            evidence={
                "source": "openai",
                "model": DEFAULT_MODEL,
                "rationale": ai_insight.rationale,
            },
        )

        findings.append(vulnerability)

    return findings
