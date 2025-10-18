from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

import async_timeout
import httpx

from .config import ScanConfig
from .logging import get_logger
from .models import EndpointProbe, McpEndpoint, McpEvidence, ScanMetadata
from .network import build_candidate_urls, discover_networks, iter_target_hosts
from .utils import safe_json_parse


logger = get_logger(__name__)


class DiscoveryStats:
    def __init__(self) -> None:
        self.scanned_hosts = 0
        self.reachable_hosts = 0


async def discover_mcp_endpoints(config: ScanConfig) -> Tuple[List[McpEndpoint], ScanMetadata]:
    stats = DiscoveryStats()
    start_time = time.monotonic()
    endpoints: List[McpEndpoint] = []

    mode = "target" if config.target_urls else "network"
    logger.info("Starting MCP discovery (%s mode)", mode)

    async with httpx.AsyncClient(
        verify=config.verify_tls,
        timeout=config.request_timeout,
        follow_redirects=True,
        headers=config.default_headers or None,
    ) as client:
        semaphore = asyncio.Semaphore(config.concurrency)
        tasks: List[asyncio.Task[Optional[McpEndpoint]]] = []

        if config.target_urls:
            targets = _prepare_target_urls(config.target_urls)
            stats.scanned_hosts += len(targets)
            for base_url in targets:
                logger.debug("Queueing explicit target %s", base_url)
                task = asyncio.create_task(
                    _scan_base_url(
                        semaphore=semaphore,
                        client=client,
                        base_url=base_url,
                        config=config,
                        paths=[],
                        is_target=True,
                    )
                )
                tasks.append(task)
        else:
            networks = discover_networks(config)
            for network in networks:
                logger.debug("Discovered network %s", network)
                hosts = list(iter_target_hosts(network, include_self=config.include_self))
                stats.scanned_hosts += len(hosts)
                for host in hosts:
                    urls = build_candidate_urls(host, config.ports)
                    for base_url in urls:
                        logger.debug("Queueing candidate %s", base_url)
                        task = asyncio.create_task(
                            _scan_base_url(
                                semaphore=semaphore,
                                client=client,
                                base_url=base_url,
                                config=config,
                                paths=config.paths,
                                is_target=False,
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
    logger.info(
        "Discovery complete: scanned=%s reachable=%s endpoints=%s duration=%.2fs",
        metadata.scanned_hosts,
        metadata.reachable_hosts,
        metadata.mcp_endpoints,
        metadata.duration_seconds,
    )
    return endpoints, metadata


async def _scan_base_url(
    semaphore: asyncio.Semaphore,
    client: httpx.AsyncClient,
    base_url: str,
    config: ScanConfig,
    paths: List[str],
    is_target: bool,
) -> Optional[McpEndpoint]:
    probes: List[EndpointProbe] = []
    evidence = McpEvidence()
    has_positive_signal = False

    if is_target:
        root_url = base_url
    else:
        root_url = base_url.rstrip("/") or base_url
        if not root_url.endswith("/"):
            root_url = f"{root_url}/"
    async with semaphore:
        try:
            async with async_timeout.timeout(config.request_timeout):
                root_response = await client.get(root_url)
        except (httpx.HTTPError, asyncio.TimeoutError):
            logger.debug("No response from %s", root_url)
            return None

    parsed_root = urlparse(root_url)
    probe_path = parsed_root.path or "/"

    headers = {k: v for k, v in root_response.headers.items()}
    probes.append(
        EndpointProbe(
            url=root_url,
            path=probe_path,
            status_code=root_response.status_code,
            headers=headers,
        )
    )

    if (
        probe_path
        and probe_path != "/"
        and root_response.status_code
        and 200 <= root_response.status_code < 400
    ):
        evidence.capability_paths.append(probe_path)

    mcp_header = root_response.headers.get("X-MCP-Support")
    if mcp_header is not None:
        evidence.headers["X-MCP-Support"] = mcp_header
        has_positive_signal = True

    root_json = safe_json_parse(root_response.text[:100_000])
    if root_json:
        _record_structure(evidence, root_json)
        has_positive_signal = True

    discovered_paths = await _probe_paths(
        semaphore, client, base_url, config, probes, evidence, paths
    )
    has_positive_signal = has_positive_signal or discovered_paths

    jsonrpc_results = await _probe_jsonrpc(
        semaphore,
        client,
        base_url,
        config,
        probes,
        evidence,
        config.rpc_methods,
    )
    has_positive_signal = has_positive_signal or jsonrpc_results

    if not has_positive_signal:
        logger.debug("No MCP signals detected for %s", base_url)
        return None

    parsed_endpoint = urlparse(base_url)
    scheme = parsed_endpoint.scheme or "http"
    host = parsed_endpoint.hostname or parsed_endpoint.netloc
    if parsed_endpoint.port:
        port = parsed_endpoint.port
    else:
        port = 443 if scheme == "https" else 80

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
    paths: List[str],
) -> bool:
    positive = False
    tasks: List[asyncio.Task[EndpointProbe]] = []
    for path in paths:
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
            if probe.json_payload:
                _record_structure(evidence, probe.json_payload)
    return positive


async def _probe_jsonrpc(
    semaphore: asyncio.Semaphore,
    client: httpx.AsyncClient,
    base_url: str,
    config: ScanConfig,
    probes: List[EndpointProbe],
    evidence: McpEvidence,
    methods: List[str],
) -> bool:
    if not methods:
        return False

    positive = False
    tasks: List[asyncio.Task[EndpointProbe]] = []
    rpc_url = base_url.rstrip("/") if base_url.endswith("/") else base_url

    for method in methods:
        body = {
            "jsonrpc": "2.0",
            "id": f"conmap-{method}",
            "method": method,
            "params": {},
        }
        logger.debug("Queueing JSON-RPC call %s -> %s", method, rpc_url)
        tasks.append(
            asyncio.create_task(
                _probe_jsonrpc_single(
                    semaphore=semaphore,
                    client=client,
                    url=rpc_url,
                    method=method,
                    payload=body,
                    timeout=config.request_timeout,
                )
            )
        )

    for task in asyncio.as_completed(tasks):
        probe = await task
        probes.append(probe)
        if probe.status_code and 200 <= probe.status_code < 400:
            positive = True
            if probe.json_payload:
                _record_structure(evidence, probe.json_payload)
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
            logger.debug("Error fetching %s: %s", url, exc)
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
        json_payload=payload,
    )


async def _probe_jsonrpc_single(
    semaphore: asyncio.Semaphore,
    client: httpx.AsyncClient,
    url: str,
    method: str,
    payload: Dict[str, Any],
    timeout: float,
) -> EndpointProbe:
    async with semaphore:
        try:
            async with async_timeout.timeout(timeout):
                response = await client.post(
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
        except (httpx.HTTPError, asyncio.TimeoutError) as exc:
            logger.debug("JSON-RPC error for %s: %s", url, exc)
            return EndpointProbe(url=url, path=f"RPC:{method}", error=str(exc))
    response_snippet = response.text[:2_048]
    logger.debug(
        "JSON-RPC response %s status=%s body=%s",
        method,
        response.status_code,
        response_snippet,
    )
    data = safe_json_parse(response.text[:100_000])
    return EndpointProbe(
        url=url,
        path=f"RPC:{method}",
        status_code=response.status_code,
        headers={k: v for k, v in response.headers.items()},
        json_payload=data,
    )


def _record_structure(evidence: McpEvidence, payload: Any) -> None:
    evidence.json_structures.append(payload)
    unwrapped = _unwrap_mcp_payload(payload)
    if unwrapped is not payload:
        evidence.json_structures.append(unwrapped)


def _unwrap_mcp_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    for key in ("result", "data"):
        inner = payload.get(key)
        if isinstance(inner, dict):
            return inner
    return payload


def _prepare_target_urls(urls: List[str]) -> List[str]:
    targets: List[str] = []
    seen: Dict[str, Tuple[int, bool]] = {}
    for raw in urls:
        result = _normalize_target_url(raw)
        if not result:
            logger.warning("Ignoring invalid target URL '%s'", raw)
            continue
        origin, is_https, dedupe_key = result
        logger.debug("Normalized target '%s' -> origin=%s", raw, origin)
        entry = seen.get(dedupe_key)
        if entry is not None:
            idx, existing_https = entry
            if is_https and not existing_https:
                targets[idx] = origin
                seen[dedupe_key] = (idx, True)
            continue
        idx = len(targets)
        seen[dedupe_key] = (idx, is_https)
        targets.append(origin)
    return targets


def _normalize_target_url(url: str) -> Optional[tuple[str, bool, str]]:
    if not url:
        return None
    candidate = url.strip()
    if not candidate:
        return None
    if "://" not in candidate:
        candidate = f"http://{candidate}"
    parsed = urlparse(candidate)
    if not parsed.netloc and parsed.path:
        candidate = f"http://{candidate}"
        parsed = urlparse(candidate)
    if not parsed.netloc:
        return None
    scheme = (parsed.scheme or "http").lower()
    hostname = (parsed.hostname or parsed.netloc).strip("[]")
    if not hostname:
        return None
    port = parsed.port
    default_port = 443 if scheme == "https" else 80
    if port:
        netloc = f"{hostname.lower()}:{port}"
    else:
        netloc = hostname.lower()
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = f"/{path}"
    query = parsed.query or ""
    normalized = parsed._replace(
        scheme=scheme,
        netloc=netloc,
        path=path,
    )
    normalized_url = urlunparse(normalized)
    if port is None or port == default_port:
        port_component = ""
    else:
        port_component = f":{port}"
    key = f"{hostname.lower()}{port_component}{path}"
    if query:
        key = f"{key}?{query}"
    dedupe_key = key.rstrip("/") if path == "/" and not query else key
    logger.debug("Computed normalized=%s dedupe_key=%s", normalized_url, dedupe_key)
    return normalized_url, scheme == "https", dedupe_key
