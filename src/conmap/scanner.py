from __future__ import annotations

import asyncio

from .cache import Cache
from .config import ScanConfig
from .discovery import discover_mcp_endpoints
from .models import ScanResult
from .vulnerabilities.chain_detector import run_chain_detector
from .vulnerabilities.llm_analyzer import run_llm_analyzer
from .vulnerabilities.schema_inspector import run_schema_inspector


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

    findings.extend(run_llm_analyzer(endpoints, cache, enabled=enable_llm))

    chain_count = sum(1 for finding in findings if finding.category.startswith("chain."))

    return ScanResult(
        metadata=metadata,
        endpoints=endpoints,
        vulnerabilities=findings,
        enhanced_vulnerabilities=findings,
        ai_analysis_enabled=enable_llm,
        chain_attacks_detected=chain_count,
        analysis_depth=depth,
    )


def scan(config: ScanConfig) -> ScanResult:
    return asyncio.run(scan_async(config))
