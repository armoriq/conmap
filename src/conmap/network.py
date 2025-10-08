from __future__ import annotations

import ipaddress
from typing import Iterable, List, Optional

import netifaces

from .config import ScanConfig


def discover_networks(config: ScanConfig) -> List[ipaddress.IPv4Network]:
    if config.subnet:
        return [ipaddress.ip_network(config.subnet, strict=False)]

    networks: List[ipaddress.IPv4Network] = []
    for interface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET not in addrs:
            continue
        for addr_info in addrs[netifaces.AF_INET]:
            ip = addr_info.get("addr")
            netmask = addr_info.get("netmask")
            if not ip or not netmask:
                continue
            if ip.startswith("127."):
                continue
            try:
                iface = ipaddress.IPv4Interface(f"{ip}/{netmask}")
            except ValueError:
                continue
            networks.append(iface.network)
    # Deduplicate by collapsing identical networks.
    unique = {str(network): network for network in networks}
    return list(unique.values())


def iter_target_hosts(
    network: ipaddress.IPv4Network, include_self: bool = False
) -> Iterable[str]:
    for host in network.hosts():
        if not include_self and str(host) == str(network.network_address):
            continue
        yield str(host)


def build_candidate_urls(host: str, ports: Iterable[int]) -> List[str]:
    urls: List[str] = []
    for port in ports:
        scheme = "https" if port == 443 else "http"
        default_port = 443 if scheme == "https" else 80
        if port == default_port:
            urls.append(f"{scheme}://{host}")
        else:
            urls.append(f"{scheme}://{host}:{port}")
    return urls
