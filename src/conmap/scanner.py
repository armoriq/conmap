from __future__ import annotations

import asyncio
import datetime as _dt
import json
import re

from typing import Any, Dict, List

from .cache import Cache
from .config import ScanConfig
from .discovery import discover_mcp_endpoints
from .conbox import ConboxConfig, run_sandbox, should_profile_tool
from .logging import get_logger
from .models import McpEndpoint, ScanResult, Severity, Vulnerability
from .vulnerabilities.chain_detector import run_chain_detector
from .vulnerabilities.llm_analyzer import run_llm_analyzer
from .vulnerabilities.schema_inspector import run_schema_inspector
from .vulnerabilities.safe_mcp_detector import (
    run_safe_mcp_detector,
    safe_mcp_technique_count,
    safe_mcp_lookup,
)


logger = get_logger(__name__)

_RUNTIME_HISTORY: Dict[str, Dict[str, float]] = {}


_POLICY_MAPPINGS = [
    {
        "risk": "Tool Poisoning & Malicious Tooling",
        "prefixes": ("schema.", "safe_mcp.safe-t1", "llm.semantic_analysis", "governance."),
        "categories": {"posture.tool_poisoning", "governance.tool_unverified"},
        "controls": [
            "Perform rigorous tool vetting and recertification",
            "Sanitize and sign tool descriptions before publication",
            "Execute high-risk tools in monitored sandboxes",
        ],
    },
    {
        "risk": "Data Exfiltration & Lateral Movement",
        "prefixes": ("chain.", "safe_mcp.safe-t170", "safe_mcp.safe-t130"),
        "categories": set(),
        "controls": [
            "Enforce network segmentation and egress filtering",
            "Apply just-in-time access with scoped tokens",
            "Continuously monitor tool chaining patterns",
        ],
    },
    {
        "risk": "Command & Control / Arbitrary Execution",
        "prefixes": ("safe_mcp.safe-t110", "schema.sensitive_operation_permissive"),
        "categories": set(),
        "controls": [
            "Restrict high-risk capabilities behind approvals",
            "Apply runtime policy enforcement and command validation",
            "Deploy behavioral monitoring for tool execution",
        ],
    },
    {
        "risk": "Transport & Gateway Hardening",
        "prefixes": ("posture.",),
        "categories": {"runtime.unhealthy_success_ratio"},
        "controls": [
            "Enforce TLS with HSTS, mTLS, and certificate pinning",
            "Harden API gateways with protocol validation and rate limiting",
            "Continuously audit security headers and endpoint posture",
        ],
    },
    {
        "risk": "Data Loss Prevention",
        "prefixes": ("dlp.",),
        "categories": set(),
        "controls": [
            "Integrate DLP scanning on MCP responses",
            "Redact sensitive identifiers before returning to models",
            "Apply contextual allow-lists for permitted data disclosures",
        ],
    },
    {
        "risk": "Runtime Anomalies & Observability",
        "prefixes": ("runtime.",),
        "categories": set(),
        "controls": [
            "Baseline MCP response sizes and success ratios",
            "Alert on sudden deviation in tool behavior or output volume",
            "Correlate runtime anomalies with authentication and network telemetry",
        ],
    },
    {
        "risk": "Sandbox Behavior Anomalies",
        "prefixes": ("sandbox.",),
        "categories": set(),
        "controls": [
            "Contain tools that exhibit malicious behavior during sandbox execution",
            "Review tool source code and dependencies before re-enabling",
            "Integrate sandbox telemetry with incident response workflows",
        ],
    },
]


async def scan_async(config: ScanConfig) -> ScanResult:
    summary = "auto" if not config.target_urls else len(config.target_urls)
    logger.info(
        "Starting scan depth=%s llm_enabled=%s targets=%s",
        config.analysis_depth,
        config.enable_llm_analysis,
        summary,
    )
    await asyncio.sleep(0)
    endpoints, metadata = await discover_mcp_endpoints(config)
    logger.info(
        "Discovery summary endpoints=%s reachable_hosts=%s",
        len(endpoints),
        metadata.reachable_hosts,
    )
    await asyncio.sleep(0)
    cache = Cache(path=config.cache_path)
    findings: List[Vulnerability] = []

    posture_findings: List[Vulnerability] = []
    for endpoint in endpoints:
        posture = _evaluate_endpoint_posture(endpoint)
        if posture:
            posture_findings.extend(posture)
        leaks = _scan_output_leaks(endpoint)
        if leaks:
            logger.info(
                "Output safety scan flagged %s potential leaks for %s",
                len(leaks),
                endpoint.base_url,
            )
            findings.extend(leaks)
        runtime = _evaluate_runtime_anomalies(endpoint)
        if runtime:
            logger.info(
                "Runtime anomaly checks surfaced %s observations for %s",
                len(runtime),
                endpoint.base_url,
            )
            findings.extend(runtime)
        vetting = _evaluate_tool_vetting(endpoint)
        if vetting:
            logger.info(
                "Tool vetting checks produced %s findings for %s",
                len(vetting),
                endpoint.base_url,
            )
            findings.extend(vetting)
        sandbox_findings = _run_sandbox_checks(endpoint, config) if config.enable_sandbox else []
        if sandbox_findings:
            logger.info(
                "Sandbox execution surfaced %s alerts for %s",
                len(sandbox_findings),
                endpoint.base_url,
            )
            findings.extend(sandbox_findings)
    if posture_findings:
        logger.info(
            "Endpoint posture assessment identified %s issues",
            len(posture_findings),
        )
        findings.extend(posture_findings)

    depth = (config.analysis_depth or "standard").lower()
    run_structural = depth in {"standard", "deep"}
    enable_llm = config.enable_llm_analysis or depth == "deep"

    if run_structural:
        logger.info("Running schema inspector on %s endpoints", len(endpoints))
        await asyncio.sleep(0)
        schema_findings = await asyncio.to_thread(run_schema_inspector, endpoints)
        _log_vulnerabilities(schema_findings)
        findings.extend(schema_findings)

        logger.info("Running chain detector")
        await asyncio.sleep(0)
        chain_findings = await asyncio.to_thread(run_chain_detector, endpoints)
        _log_vulnerabilities(chain_findings)
        findings.extend(chain_findings)

        logger.info("Running SAFE-MCP detector")
        await asyncio.sleep(0)
        safe_mcp_findings = await asyncio.to_thread(run_safe_mcp_detector, endpoints)
        _log_vulnerabilities(safe_mcp_findings)
        findings.extend(safe_mcp_findings)

    logger.info("Running LLM analyzer enabled=%s", enable_llm)
    await asyncio.sleep(0)
    llm_findings = await asyncio.to_thread(
        run_llm_analyzer,
        endpoints,
        cache,
        enable_llm,
        config.llm_batch_size or 5,
    )
    _log_vulnerabilities(llm_findings)
    findings.extend(llm_findings)

    chain_count = sum(1 for finding in findings if finding.category.startswith("chain."))
    safe_mcp_findings = [
        finding for finding in findings if finding.category.startswith("safe_mcp.")
    ]
    safe_mcp_total = safe_mcp_technique_count()
    safe_mcp_detected = len(
        {finding.evidence.get("technique") for finding in safe_mcp_findings} - {None}
    )

    safe_mcp_details = _aggregate_safe_mcp_details(safe_mcp_findings)

    score, severity_level = _compute_vulnerability_score(findings)

    logger.info(
        "Scan complete: findings=%s critical=%s high=%s medium=%s low=%s chain=%s safe_mcp=%s/%s score=%.1f",
        len(findings),
        sum(1 for f in findings if f.severity == Severity.critical),
        sum(1 for f in findings if f.severity == Severity.high),
        sum(1 for f in findings if f.severity == Severity.medium),
        sum(1 for f in findings if f.severity == Severity.low),
        chain_count,
        safe_mcp_detected,
        safe_mcp_total,
        score,
    )
    await asyncio.sleep(0)

    policy_hints = _build_policy_hints(findings)
    if policy_hints:
        logger.info(
            "Generated %s security policy hints from findings",
            len(policy_hints),
        )

    return ScanResult(
        metadata=metadata,
        endpoints=endpoints,
        vulnerabilities=findings,
        enhanced_vulnerabilities=findings,
        ai_analysis_enabled=enable_llm,
        chain_attacks_detected=chain_count,
        analysis_depth=depth,
        safe_mcp_techniques_total=safe_mcp_total,
        safe_mcp_techniques_detected=safe_mcp_detected,
        safe_mcp_technique_details=safe_mcp_details,
        vulnerability_score=score,
        severity_level=severity_level,
        security_recommendations=policy_hints,
    )


def scan(config: ScanConfig) -> ScanResult:
    return asyncio.run(scan_async(config))


def _evaluate_endpoint_posture(endpoint: McpEndpoint) -> List[Vulnerability]:
    findings: List[Vulnerability] = []
    root_probe = next(
        (probe for probe in endpoint.probes if probe.path in {"/", ""}),
        None,
    )
    if not root_probe and endpoint.probes:
        root_probe = endpoint.probes[0]

    headers: Dict[str, str] = {}
    if root_probe:
        headers = {k.lower(): v for k, v in (root_probe.headers or {}).items()}

    detection_source = "posture"

    if endpoint.scheme.lower() != "https":
        logger.info("Endpoint %s uses insecure transport", endpoint.base_url)
        findings.append(
            Vulnerability(
                endpoint=endpoint.base_url,
                component="gateway",
                category="posture.insecure_transport",
                severity=Severity.high,
                message="Endpoint is served over HTTP without TLS protection.",
                mitigation="Enforce HTTPS with HSTS, mutual TLS, and certificate pinning.",
                detection_source=detection_source,
                evidence={"base_url": endpoint.base_url},
            )
        )

    if endpoint.scheme.lower() == "https":
        hsts_present = "strict-transport-security" in headers
        if not hsts_present:
            logger.info("Endpoint %s missing Strict-Transport-Security header", endpoint.base_url)
            findings.append(
                Vulnerability(
                    endpoint=endpoint.base_url,
                    component="gateway",
                    category="posture.missing_hsts",
                    severity=Severity.medium,
                    message="Strict-Transport-Security header not observed on HTTPS endpoint.",
                    mitigation="Configure HSTS to enforce secure transport for all clients.",
                    detection_source=detection_source,
                    evidence={"base_url": endpoint.base_url},
                )
            )

    critical_headers = [
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
    ]
    missing_headers = [header for header in critical_headers if header not in headers]
    if missing_headers:
        logger.info(
            "Endpoint %s missing security headers: %s",
            endpoint.base_url,
            ", ".join(missing_headers),
        )
        findings.append(
            Vulnerability(
                endpoint=endpoint.base_url,
                component="gateway",
                category="posture.missing_security_headers",
                severity=Severity.low,
                message="Recommended security headers are absent: " + ", ".join(missing_headers),
                mitigation="Add CSP, X-Content-Type-Options, and X-Frame-Options headers at the gateway layer.",
                detection_source=detection_source,
                evidence={"missing_headers": missing_headers},
            )
        )

    return findings


def _scan_output_leaks(endpoint: McpEndpoint) -> List[Vulnerability]:
    patterns = {
        "ssn": (Severity.high, r"\b\d{3}-\d{2}-\d{4}\b", "US Social Security Number"),
        "credit_card": (
            Severity.high,
            r"\b(?:\d[ -]*?){13,16}\b",
            "Payment card number",
        ),
        "aws_key": (Severity.high, r"AKIA[0-9A-Z]{16}", "AWS access key"),
        "password_hint": (
            Severity.medium,
            r"(?i)password\s*[:=]\s*[^\s]+",
            "Password-like assignment",
        ),
    }

    findings: List[Vulnerability] = []
    for probe in endpoint.probes:
        payload_text = ""
        if probe.json_payload is not None:
            try:
                payload_text = json.dumps(probe.json_payload)
            except Exception:  # pragma: no cover - defensive for non-serializable payloads
                payload_text = str(probe.json_payload)
        elif probe.headers:
            payload_text = " ".join(f"{k}:{v}" for k, v in probe.headers.items())

        if not payload_text:
            continue

        for category_suffix, (severity, pattern, description) in patterns.items():
            matches = re.findall(pattern, payload_text)
            if not matches:
                continue
            logger.info(
                "DLP pattern %s detected in response from %s",
                category_suffix,
                probe.url,
            )
            findings.append(
                Vulnerability(
                    endpoint=endpoint.base_url,
                    component="gateway",
                    category=f"dlp.{category_suffix}",
                    severity=severity,
                    message=f"Detected potential {description} in MCP response for {probe.path}.",
                    mitigation="Integrate DLP redaction and limit sensitive data exposure via MCP.",
                    detection_source="dlp",
                    evidence={
                        "path": probe.path,
                        "matches": matches[:3],
                    },
                )
            )
    return findings


def _evaluate_runtime_anomalies(endpoint: McpEndpoint) -> List[Vulnerability]:
    probes = endpoint.probes
    if not probes:
        return []

    total = len(probes)
    successes = sum(1 for probe in probes if probe.status_code and 200 <= probe.status_code < 400)
    success_ratio = successes / total if total else 0.0

    content_lengths: List[int] = []
    for probe in probes:
        if probe.headers:
            header_val = probe.headers.get("Content-Length") or probe.headers.get("content-length")
            if header_val and header_val.isdigit():
                content_lengths.append(int(header_val))

    avg_length = sum(content_lengths) / len(content_lengths) if content_lengths else 0.0

    baseline = _RUNTIME_HISTORY.get(endpoint.base_url, {})
    findings: List[Vulnerability] = []

    if total >= 3 and success_ratio < 0.3:
        findings.append(
            Vulnerability(
                endpoint=endpoint.base_url,
                component="runtime",
                category="runtime.unhealthy_success_ratio",
                severity=Severity.medium,
                message=f"Only {successes}/{total} MCP probes succeeded (ratio={success_ratio:.2f}).",
                mitigation="Investigate tool availability, authentication posture, and gateway throttling.",
                detection_source="runtime",
                evidence={"success_ratio": success_ratio, "total_probes": total},
            )
        )

    if baseline:
        previous_ratio = baseline.get("success_ratio")
        if previous_ratio is not None and abs(success_ratio - previous_ratio) >= 0.5:
            severity = Severity.medium if success_ratio < previous_ratio else Severity.low
            findings.append(
                Vulnerability(
                    endpoint=endpoint.base_url,
                    component="runtime",
                    category="runtime.success_ratio_shift",
                    severity=severity,
                    message=f"Success ratio changed from {previous_ratio:.2f} to {success_ratio:.2f}.",
                    mitigation="Correlate with recent deployments or access-control changes.",
                    detection_source="runtime",
                    evidence={
                        "previous_ratio": previous_ratio,
                        "current_ratio": success_ratio,
                    },
                )
            )

        previous_length = baseline.get("avg_length")
        if content_lengths and previous_length and avg_length > previous_length * 2:
            findings.append(
                Vulnerability(
                    endpoint=endpoint.base_url,
                    component="runtime",
                    category="runtime.response_size_spike",
                    severity=Severity.medium,
                    message=f"Average response size grew from {int(previous_length)} to {int(avg_length)} bytes.",
                    mitigation="Inspect tool outputs for accidental data dumps or exfiltration attempts.",
                    detection_source="runtime",
                    evidence={
                        "previous_avg_bytes": previous_length,
                        "current_avg_bytes": avg_length,
                    },
                )
            )

    if content_lengths and avg_length > 200_000:
        findings.append(
            Vulnerability(
                endpoint=endpoint.base_url,
                component="runtime",
                category="runtime.large_response_payload",
                severity=Severity.medium,
                message=f"Observed large MCP response (~{int(avg_length)} bytes).",
                mitigation="Introduce pagination or redact sensitive data before returning to MCP clients.",
                detection_source="runtime",
                evidence={"average_bytes": avg_length},
            )
        )

    _RUNTIME_HISTORY[endpoint.base_url] = {
        "success_ratio": success_ratio,
        "avg_length": avg_length or baseline.get("avg_length", 0.0),
    }

    return findings


def _evaluate_tool_vetting(endpoint: McpEndpoint) -> List[Vulnerability]:
    findings: List[Vulnerability] = []

    def _parse_date(value: str) -> _dt.datetime | None:
        try:
            return _dt.datetime.fromisoformat(value.replace("Z", ""))
        except Exception:
            return None

    vetting_window_days = 180

    for structure in endpoint.evidence.json_structures:
        raw_tools = structure.get("tools") or []
        if isinstance(raw_tools, dict):
            raw_tools = raw_tools.values()
        for tool in raw_tools:
            name = str(tool.get("name", "unknown"))
            metadata = tool.get("metadata") or {}
            if not isinstance(metadata, dict):
                metadata = {}

            signature = metadata.get("signature")
            if not signature:
                logger.info("Tool %s lacks signature metadata", name)
                findings.append(
                    Vulnerability(
                        endpoint=endpoint.base_url,
                        component=f"tool:{name}",
                        category="governance.tool_unverified",
                        severity=Severity.high,
                        message=f"Tool '{name}' missing signature metadata for vetting.",
                        mitigation="Require signed manifests or registry approval before enabling tool.",
                        detection_source="governance",
                        evidence={"tool": name},
                    )
                )

            approved_at = metadata.get("approved_at")
            if approved_at:
                approved_date = _parse_date(str(approved_at))
                if approved_date:
                    age_days = (_dt.datetime.utcnow() - approved_date).days
                    if age_days > vetting_window_days:
                        findings.append(
                            Vulnerability(
                                endpoint=endpoint.base_url,
                                component=f"tool:{name}",
                                category="governance.tool_recirtification_overdue",
                                severity=Severity.medium,
                                message=f"Tool '{name}' approval older than {vetting_window_days} days ({age_days} days).",
                                mitigation="Trigger recertification workflow to review tool security posture.",
                                detection_source="governance",
                                evidence={"approved_at": approved_at, "age_days": age_days},
                            )
                        )
                else:
                    findings.append(
                        Vulnerability(
                            endpoint=endpoint.base_url,
                            component=f"tool:{name}",
                            category="governance.tool_metadata_invalid",
                            severity=Severity.low,
                            message=f"Tool '{name}' has unparseable approval timestamp: {approved_at}.",
                            mitigation="Normalize ISO-8601 timestamps in tool metadata.",
                            detection_source="governance",
                            evidence={"approved_at": approved_at},
                        )
                    )

            expires_at = metadata.get("expires_at")
            if expires_at:
                expires_date = _parse_date(str(expires_at))
                if expires_date and expires_date < _dt.datetime.utcnow():
                    findings.append(
                        Vulnerability(
                            endpoint=endpoint.base_url,
                            component=f"tool:{name}",
                            category="governance.tool_certificate_expired",
                            severity=Severity.high,
                            message=f"Tool '{name}' approval expired on {expires_at}.",
                            mitigation="Disable tool until new approval and signature are issued.",
                            detection_source="governance",
                            evidence={"expires_at": expires_at},
                        )
                    )

    return findings


def _run_sandbox_checks(endpoint: McpEndpoint, config: ScanConfig) -> List[Vulnerability]:
    conbox_config = ConboxConfig(
        enabled=config.enable_sandbox,
        max_runtime=config.sandbox_max_runtime,
        max_tools=config.sandbox_max_tools,
    )

    tools: List[Dict[str, Any]] = []
    for structure in endpoint.evidence.json_structures:
        raw_tools = structure.get("tools") or []
        if isinstance(raw_tools, dict):
            raw_tools = raw_tools.values()
        for tool in raw_tools:
            if isinstance(tool, dict):
                tools.append(tool)

    candidates: List[Dict[str, Any]] = []
    for tool in tools:
        if len(candidates) >= conbox_config.max_tools:
            break
        if should_profile_tool(tool):
            candidates.append(tool)

    findings: List[Vulnerability] = []
    for tool in candidates:
        report = run_sandbox(tool, conbox_config)
        for alert in report.alerts:
            findings.append(
                Vulnerability(
                    endpoint=endpoint.base_url,
                    component=f"tool:{report.tool_name}",
                    category=f"sandbox.{alert.category}",
                    severity=alert.severity,
                    message=alert.message,
                    mitigation="Isolate tool, review sandbox telemetry, and remediate per enterprise policies.",
                    detection_source="sandbox",
                    evidence={**alert.evidence, "duration_seconds": report.duration_seconds},
                )
            )
    return findings


def _build_policy_hints(vulnerabilities: List[Vulnerability]) -> List[Dict[str, Any]]:
    if not vulnerabilities:
        return []

    severity_rank = {
        Severity.critical: 4,
        Severity.high: 3,
        Severity.medium: 2,
        Severity.low: 1,
        Severity.info: 0,
    }
    inverse_severity = {value: key.value for key, value in severity_rank.items()}

    summary: Dict[str, Dict[str, Any]] = {}

    for vuln in vulnerabilities:
        for mapping in _POLICY_MAPPINGS:
            matches_prefix = any(vuln.category.startswith(prefix) for prefix in mapping["prefixes"])
            matches_category = vuln.category in mapping["categories"]
            if not (matches_prefix or matches_category):
                continue
            entry = summary.setdefault(
                mapping["risk"],
                {
                    "count": 0,
                    "categories": set(),
                    "max_rank": -1,
                    "examples": [],
                    "controls": mapping["controls"],
                },
            )
            entry["count"] += 1
            entry["categories"].add(vuln.category)
            rank = severity_rank.get(vuln.severity, 0)
            if rank > entry["max_rank"]:
                entry["max_rank"] = rank
            if len(entry["examples"]) < 3:
                entry["examples"].append(vuln.message)

    recommendations: List[Dict[str, Any]] = []
    for risk, data in summary.items():
        if data["count"] == 0:
            continue
        recommendations.append(
            {
                "risk": risk,
                "matched_findings": data["count"],
                "max_severity": inverse_severity.get(data["max_rank"], Severity.info.value),
                "categories": sorted(data["categories"]),
                "recommended_controls": data["controls"],
                "sample_messages": data["examples"],
            }
        )

    recommendations.sort(key=lambda item: item["risk"].lower())
    return recommendations


def _aggregate_safe_mcp_details(findings: List[Vulnerability]) -> List[Dict[str, Any]]:
    severity_rank = {
        Severity.critical: 4,
        Severity.high: 3,
        Severity.medium: 2,
        Severity.low: 1,
        Severity.info: 0,
    }
    stats = {}
    for finding in findings:
        technique_id = finding.evidence.get("technique")
        if not technique_id:
            continue
        entry = stats.setdefault(
            technique_id,
            {
                "count": 0,
                "components": set(),
                "max_severity": Severity.info,
            },
        )
        entry["count"] += 1
        entry["components"].add(finding.component)
        if severity_rank[finding.severity] > severity_rank[entry["max_severity"]]:
            entry["max_severity"] = finding.severity

    aggregated = []
    for technique_id in sorted(stats.keys()):
        meta = safe_mcp_lookup(technique_id) or {"id": technique_id}
        entry = stats[technique_id]
        aggregated.append(
            {
                "id": meta.get("id", technique_id),
                "name": meta.get("name"),
                "tactic": meta.get("tactic"),
                "default_severity": meta.get("default_severity"),
                "detected_severity": entry["max_severity"].value,
                "occurrences": entry["count"],
                "affected_components": sorted(entry["components"]),
            }
        )
    return aggregated


def _log_vulnerabilities(vulnerabilities: List[Vulnerability]) -> None:
    for vuln in vulnerabilities:
        logger.info(
            "Vulnerability detected endpoint=%s component=%s category=%s severity=%s source=%s message=%s",
            vuln.endpoint,
            vuln.component,
            vuln.category,
            vuln.severity,
            vuln.detection_source,
            vuln.message,
        )


def _compute_vulnerability_score(findings: List[Vulnerability]) -> tuple[float, str]:
    base_score = 0.0
    severity_reward = {
        Severity.critical: 25.0,
        Severity.high: 18.0,
        Severity.medium: 10.0,
        Severity.low: 5.0,
        Severity.info: 0.0,
    }
    source_weight = {
        "static": 1.0,
        "graph": 1.3,
        "llm": 1.2,
        "hybrid": 1.1,
    }

    score = base_score
    bonus_unknown = 5.0
    logger.info("Calculating vulnerability score for %s findings", len(findings))
    for finding in findings:
        severity_reward_value = severity_reward.get(finding.severity)
        weight = source_weight.get((finding.detection_source or "").lower(), 1.0)
        if severity_reward_value is None:
            logger.info(
                "Unknown severity %s for category=%s; awarding bonus %.1f",
                finding.severity,
                finding.category,
                bonus_unknown,
            )
            score += bonus_unknown
            continue
        reward = severity_reward_value * weight
        score += reward
        logger.info(
            "Score update category=%s severity=%s source=%s delta=%.2f base_reward=%.2f weight=%.2f total=%.2f",
            finding.category,
            finding.severity.value,
            finding.detection_source,
            reward,
            severity_reward_value,
            weight,
            score,
        )

    score = max(0.0, min(100.0, score))
    if score >= 70:
        level = "critical"
    elif score >= 40:
        level = "warning"
    else:
        level = "safe"
    return score, level
