from __future__ import annotations

import os
from typing import List, Literal, Optional

from pydantic import BaseModel, Field, ValidationError


DEFAULT_MCP_PATHS = [
    "/api/mcp",
    "/mcp/capabilities",
    "/.well-known/mcp.json",
    "/api/mcp/tools",
    "/api/mcp/resources",
    "/api/mcp/prompts",
    "/mcp.json",
    "/mcp.yaml",
    "/llms.txt",
    "/mcp-config.json",
    "/model-context-protocol.json",
]


class ScanConfig(BaseModel):
    subnet: Optional[str] = None
    ports: List[int] = Field(default_factory=lambda: [80, 443])
    concurrency: int = Field(default=64, ge=1, le=1024)
    request_timeout: float = Field(default=5.0, gt=0)
    verify_tls: bool = False
    paths: List[str] = Field(default_factory=lambda: list(DEFAULT_MCP_PATHS))
    rpc_methods: List[str] = Field(
        default_factory=lambda: [
            "initialize",
            "tools/list",
            "resources/list",
            "prompts/list",
        ]
    )
    llm_batch_size: int = Field(default=5, ge=1, le=50)
    include_self: bool = False
    enable_llm_analysis: bool = True
    cache_path: Optional[str] = None
    analysis_depth: Literal["basic", "standard", "deep"] = "standard"
    target_urls: List[str] = Field(default_factory=list)
    enable_sandbox: bool = False
    sandbox_max_runtime: float = Field(default=15.0, gt=0)
    sandbox_max_tools: int = Field(default=5, ge=1, le=50)

    @classmethod
    def from_env(cls) -> "ScanConfig":
        def _env(*names: str) -> Optional[str]:
            for name in names:
                value = os.getenv(name)
                if value:
                    return value
            return None

        data = {}
        subnet = _env("CONMAP_SUBNET", "MCP_SCANNER_SUBNET")
        if subnet:
            data["subnet"] = subnet
        ports = _env("CONMAP_PORTS", "MCP_SCANNER_PORTS")
        if ports:
            data["ports"] = [int(p.strip()) for p in ports.split(",") if p.strip()]
        concurrency = _env("CONMAP_MAX_CONCURRENCY", "MCP_SCANNER_MAX_CONCURRENCY")
        if concurrency:
            data["concurrency"] = int(concurrency)
        timeout = _env("CONMAP_TIMEOUT", "MCP_SCANNER_TIMEOUT")
        if timeout:
            data["request_timeout"] = float(timeout)
        verify_tls = _env("CONMAP_VERIFY_TLS", "MCP_SCANNER_VERIFY_TLS")
        if verify_tls:
            data["verify_tls"] = verify_tls.lower() in {"1", "true", "yes"}
        include_self = _env("CONMAP_INCLUDE_SELF", "MCP_SCANNER_INCLUDE_SELF")
        if include_self:
            data["include_self"] = include_self.lower() in {"1", "true", "yes"}
        enable_llm = _env("CONMAP_ENABLE_LLM_ANALYSIS", "MCP_SCANNER_ENABLE_LLM_ANALYSIS")
        if enable_llm:
            data["enable_llm_analysis"] = enable_llm.lower() in {"1", "true", "yes"}
        cache_path = _env("CONMAP_CACHE_PATH", "MCP_SCANNER_CACHE_PATH")
        if cache_path:
            data["cache_path"] = cache_path
        depth = _env("CONMAP_ANALYSIS_DEPTH", "MCP_SCANNER_ANALYSIS_DEPTH")
        if depth:
            depth_normalized = depth.strip().lower()
            if depth_normalized in {"basic", "standard", "deep"}:
                data["analysis_depth"] = depth_normalized
        target_urls = _env("CONMAP_TARGET_URLS", "MCP_SCANNER_TARGET_URLS")
        if target_urls:
            urls = [url.strip() for url in target_urls.split(",") if url.strip()]
            if urls:
                data["target_urls"] = urls
        llm_batch_size = _env("CONMAP_LLM_BATCH_SIZE", "MCP_SCANNER_LLM_BATCH_SIZE")
        if llm_batch_size:
            data["llm_batch_size"] = int(llm_batch_size)
        enable_sandbox = _env("CONMAP_ENABLE_SANDBOX", "MCP_SCANNER_ENABLE_SANDBOX")
        if enable_sandbox:
            data["enable_sandbox"] = enable_sandbox.lower() in {"1", "true", "yes"}
        sandbox_runtime = _env("CONMAP_SANDBOX_MAX_RUNTIME", "MCP_SCANNER_SANDBOX_MAX_RUNTIME")
        if sandbox_runtime:
            data["sandbox_max_runtime"] = float(sandbox_runtime)
        sandbox_max_tools = _env("CONMAP_SANDBOX_MAX_TOOLS", "MCP_SCANNER_SANDBOX_MAX_TOOLS")
        if sandbox_max_tools:
            data["sandbox_max_tools"] = int(sandbox_max_tools)
        try:
            return cls(**data)
        except ValidationError as exc:  # pragma: no cover - defensive
            raise ValueError(f"Invalid environment configuration: {exc}") from exc
