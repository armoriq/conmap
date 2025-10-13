from __future__ import annotations

import asyncio

from typing import Any, Dict, List

from .cache import Cache
from .config import ScanConfig
from .discovery import discover_mcp_endpoints
from .logging import get_logger
from .models import ScanResult, Severity, Vulnerability
from .vulnerabilities.chain_detector import run_chain_detector
from .vulnerabilities.llm_analyzer import run_llm_analyzer
from .vulnerabilities.schema_inspector import run_schema_inspector
from .vulnerabilities.safe_mcp_detector import (
    run_safe_mcp_detector,
    safe_mcp_technique_count,
    safe_mcp_lookup,
)


logger = get_logger(__name__)


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
    findings = []

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
    )


def scan(config: ScanConfig) -> ScanResult:
    return asyncio.run(scan_async(config))


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
