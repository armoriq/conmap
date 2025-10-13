import os

import pytest

from conmap.config import DEFAULT_MCP_PATHS, ScanConfig


def test_scan_config_defaults(monkeypatch):
    for var in list(os.environ):
        if var.startswith("CONMAP_") or var.startswith("MCP_SCANNER_"):
            monkeypatch.delenv(var, raising=False)
    config = ScanConfig.from_env()
    assert config.ports == [80, 443]
    assert config.paths == DEFAULT_MCP_PATHS
    assert config.verify_tls is False
    assert config.target_urls == []


def test_scan_config_env_overrides(monkeypatch):
    monkeypatch.setenv("CONMAP_SUBNET", "10.0.0.0/30")
    monkeypatch.setenv("MCP_SCANNER_PORTS", "8080,8443")
    monkeypatch.setenv("CONMAP_MAX_CONCURRENCY", "10")
    monkeypatch.setenv("CONMAP_TIMEOUT", "9.5")
    monkeypatch.setenv("CONMAP_VERIFY_TLS", "true")
    monkeypatch.setenv("CONMAP_INCLUDE_SELF", "1")
    monkeypatch.setenv("CONMAP_CACHE_PATH", "/tmp/conmap-cache.json")
    monkeypatch.setenv("CONMAP_ANALYSIS_DEPTH", "deep")
    monkeypatch.setenv("CONMAP_ENABLE_LLM_ANALYSIS", "0")
    monkeypatch.setenv("CONMAP_TARGET_URLS", "https://one.example.com, http://two.example.com/")
    config = ScanConfig.from_env()
    assert config.subnet == "10.0.0.0/30"
    assert config.ports == [8080, 8443]
    assert config.concurrency == 10
    assert config.request_timeout == pytest.approx(9.5)
    assert config.verify_tls is True
    assert config.include_self is True
    assert config.cache_path == "/tmp/conmap-cache.json"
    assert config.analysis_depth == "deep"
    assert config.enable_llm_analysis is False
    assert config.target_urls == ["https://one.example.com", "http://two.example.com/"]


def test_scan_config_legacy_env(monkeypatch):
    monkeypatch.delenv("CONMAP_SUBNET", raising=False)
    monkeypatch.setenv("MCP_SCANNER_SUBNET", "192.168.1.0/24")
    config = ScanConfig.from_env()
    assert config.subnet == "192.168.1.0/24"
