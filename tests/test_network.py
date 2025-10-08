import ipaddress

import netifaces

from conmap.config import ScanConfig
from conmap.network import build_candidate_urls, discover_networks, iter_target_hosts


def test_discover_networks(monkeypatch):
    monkeypatch.setattr(netifaces, "interfaces", lambda: ["eth0"])

    def fake_ifaddresses(interface):
        return {
            netifaces.AF_INET: [
                {"addr": "192.168.1.5", "netmask": "255.255.255.0"},
            ]
        }

    monkeypatch.setattr(netifaces, "ifaddresses", fake_ifaddresses)
    networks = discover_networks(ScanConfig())
    assert str(networks[0]) == "192.168.1.0/24"


def test_discover_networks_with_subnet_override():
    config = ScanConfig(subnet="10.10.0.0/16")
    networks = discover_networks(config)
    assert str(networks[0]) == "10.10.0.0/16"


def test_iter_target_hosts():
    network = ipaddress.ip_network("10.0.0.0/30")
    hosts = list(iter_target_hosts(network, include_self=False))
    assert hosts == ["10.0.0.1", "10.0.0.2"]


def test_build_candidate_urls():
    urls = build_candidate_urls("10.0.0.1", [80, 8080, 443])
    assert "http://10.0.0.1" in urls
    assert "https://10.0.0.1" in urls
    assert "http://10.0.0.1:8080" in urls
