from __future__ import annotations

import asyncio
import time
from typing import Dict, Iterable, List, Optional, Tuple

import async_timeout
import httpx

from .config import ScanConfig
from .models import EndpointProbe, McpEndpoint, McpEvidence, ScanMetadata
from .network import build_candidate_urls, discover_networks, iter_target_hosts
from .utils import is_likely_mcp_payload, safe_json_parse


class DiscoveryStats:
    def __init__(self) -> None:
        self.scanned_hosts = 0
        self.reachable_hosts = 0


async def discover_mcp_endpoints(config: ScanConfig) -> Tuple[List[McpEndpoint], ScanMetadata]:
    networks = discover_networks(config)
    stats = DiscoveryStats()
    start_time = time.monotonic()
    endpoints: List[McpEndpoint] = []

    async with httpx.AsyncClient(
        verify=config.verify_tls, timeout=config.request_timeout, follow_redirects=True
    ) as client:
        semaphore = asyncio.Semaphore(config.concurrency)
        tasks: List[asyncio.Task[Optional[McpEndpoint]]] = []

        for network in networks:
            hosts = list(iter_target_hosts(network, include_self=config.include_self))
            stats.scanned_hosts += len(hosts)
            for host in hosts:
                urls = build_candidate_urls(host, config.ports)
                for base_url in urls:
                    task = asyncio.create_task(
                        _scan_base_url(
                            semaphore=semaphore,
                            client=client,
                            base_url=base_url,
                            config=config,
                        )
                    )
                    tasks.append(task)

        for task in asyncio.as_completed(tasks):
            endpoint = await task
            if endpoint:
                endpoints.append(endpoint)
                stats.reachable_hosts += 1

    metadata = ScanMetadata(
        scanned_hosts=stats.scanned_hosts,
        reachable_hosts=stats.reachable_hosts,
        mcp_endpoints=len(endpoints),
        duration_seconds=time.monotonic() - start_time,
    )
    return endpoints, metadata


async def _scan_base_url(
    semaphore: asyncio.Semaphore,
    client: httpx.AsyncClient,
    base_url: str,
    config: ScanConfig,
) -> Optional[McpEndpoint]:
    probes: List[EndpointProbe] = []
    evidence = McpEvidence()
    has_positive_signal = False

    async with semaphore:
        try:
            async with async_timeout.timeout(config.request_timeout):
                root_response = await client.get(f"{base_url}/")
        except (httpx.HTTPError, asyncio.TimeoutError):
            return None

    headers = {k: v for k, v in root_response.headers.items()}
    probes.append(
        EndpointProbe(
            url=f"{base_url}/",
            path="/",
            status_code=root_response.status_code,
            headers=headers,
        )
    )

    mcp_header = root_response.headers.get("X-MCP-Support")
    if mcp_header is not None:
        evidence.headers["X-MCP-Support"] = mcp_header
        has_positive_signal = True

    root_json = safe_json_parse(root_response.text[:100_000])
    if root_json and is_likely_mcp_payload(root_json):
        evidence.json_structures.append(root_json)
        has_positive_signal = True

    discovered_paths = await _probe_paths(semaphore, client, base_url, config, probes, evidence)
    has_positive_signal = has_positive_signal or discovered_paths

    if not has_positive_signal:
        return None

    scheme, _, host_port = base_url.partition("://")
    host, _, port_str = host_port.partition(":")
    port = int(port_str) if port_str else (443 if scheme == "https" else 80)

    return McpEndpoint(
        address=host,
        scheme=scheme,
        port=port,
        base_url=base_url.rstrip("/"),
        probes=probes,
        evidence=evidence,
    )


async def _probe_paths(
    semaphore: asyncio.Semaphore,
    client: httpx.AsyncClient,
    base_url: str,
    config: ScanConfig,
    probes: List[EndpointProbe],
    evidence: McpEvidence,
) -> bool:
    positive = False
    tasks: List[asyncio.Task[EndpointProbe]] = []
    for path in config.paths:
        normalized_path = path if path.startswith("/") else f"/{path}"
        tasks.append(
            asyncio.create_task(
                _probe_single_path(
                    semaphore=semaphore,
                    client=client,
                    url=f"{base_url}{normalized_path}",
                    path=normalized_path,
                    timeout=config.request_timeout,
                )
            )
        )

    for task in asyncio.as_completed(tasks):
        probe = await task
        probes.append(probe)
        if probe.status_code and 200 <= probe.status_code < 400:
            evidence.capability_paths.append(probe.path)
            positive = True
            if probe.json and is_likely_mcp_payload(probe.json):
                evidence.json_structures.append(probe.json)
    return positive


async def _probe_single_path(
    semaphore: asyncio.Semaphore,
    client: httpx.AsyncClient,
    url: str,
    path: str,
    timeout: float,
) -> EndpointProbe:
    async with semaphore:
        try:
            async with async_timeout.timeout(timeout):
                response = await client.get(url)
        except (httpx.HTTPError, asyncio.TimeoutError) as exc:
            return EndpointProbe(url=url, path=path, error=str(exc))
    content_type = response.headers.get("Content-Type", "")
    payload = None
    if "json" in content_type.lower():
        payload = safe_json_parse(response.text[:100_000])
    return EndpointProbe(
        url=url,
        path=path,
        status_code=response.status_code,
        headers={k: v for k, v in response.headers.items()},
        json=payload,
    )
