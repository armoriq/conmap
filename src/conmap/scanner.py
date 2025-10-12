from __future__ import annotations

import asyncio

from typing import Any, Dict, List

from .cache import Cache
from .config import ScanConfig
from .discovery import discover_mcp_endpoints
from .models import ScanResult, Severity, Vulnerability
from .vulnerabilities.chain_detector import run_chain_detector
from .vulnerabilities.llm_analyzer import run_llm_analyzer
from .vulnerabilities.schema_inspector import run_schema_inspector
from .vulnerabilities.safe_mcp_detector import (
    run_safe_mcp_detector,
    safe_mcp_technique_count,
    safe_mcp_lookup,
)


async def scan_async(config: ScanConfig) -> ScanResult:
    endpoints, metadata = await discover_mcp_endpoints(config)
    cache = Cache(path=config.cache_path)
    findings = []

    depth = (config.analysis_depth or "standard").lower()
    run_structural = depth in {"standard", "deep"}
    enable_llm = config.enable_llm_analysis or depth == "deep"

    if run_structural:
        findings.extend(run_schema_inspector(endpoints))
        findings.extend(run_chain_detector(endpoints))
        findings.extend(run_safe_mcp_detector(endpoints))

    findings.extend(run_llm_analyzer(endpoints, cache, enabled=enable_llm))

    chain_count = sum(1 for finding in findings if finding.category.startswith("chain."))
    safe_mcp_findings = [
        finding for finding in findings if finding.category.startswith("safe_mcp.")
    ]
    safe_mcp_total = safe_mcp_technique_count()
    safe_mcp_detected = len(
        {finding.evidence.get("technique") for finding in safe_mcp_findings} - {None}
    )

    safe_mcp_details = _aggregate_safe_mcp_details(safe_mcp_findings)

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
