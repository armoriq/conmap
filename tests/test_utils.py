import ipaddress

from conmap import utils


def test_is_likely_mcp_payload_detects_keywords():
    payload = {"tools": [], "model": {"name": "demo"}}
    assert utils.is_likely_mcp_payload(payload) is True
    assert utils.is_likely_mcp_payload({"other": "value"}) is False
    assert utils.is_likely_mcp_payload({"type": "MCP"}) is True


def test_safe_json_parse():
    assert utils.safe_json_parse('{"key": 1}') == {"key": 1}
    assert utils.safe_json_parse("not json") is None
    assert utils.safe_json_parse(None) is None


def test_iter_hosts_respects_include_self():
    network = ipaddress.ip_network("192.168.1.0/30")
    hosts = list(utils.iter_hosts(network, include_self=False))
    assert "192.168.1.0" not in hosts
    assert "192.168.1.1" in hosts
    assert "192.168.1.2" in hosts
    with_self = list(utils.iter_hosts(network, include_self=True))
    assert "192.168.1.0" in with_self
