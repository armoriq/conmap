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
    include_self: bool = False
    enable_llm_analysis: bool = True
    cache_path: Optional[str] = None
    analysis_depth: Literal["basic", "standard", "deep"] = "standard"

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
        try:
            return cls(**data)
        except ValidationError as exc:  # pragma: no cover - defensive
            raise ValueError(f"Invalid environment configuration: {exc}") from exc
