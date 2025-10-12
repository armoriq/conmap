from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class EndpointProbe(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    url: str
    path: str
    status_code: Optional[int] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    json_payload: Optional[Any] = Field(
        default=None,
        serialization_alias="json",
        validation_alias="json",
    )
    error: Optional[str] = None


class McpEvidence(BaseModel):
    capability_paths: List[str] = Field(default_factory=list)
    headers: Dict[str, str] = Field(default_factory=dict)
    json_structures: List[Dict[str, Any]] = Field(default_factory=list)


class McpEndpoint(BaseModel):
    address: str
    scheme: str
    port: int
    base_url: str
    probes: List[EndpointProbe] = Field(default_factory=list)
    evidence: McpEvidence = Field(default_factory=McpEvidence)


class AIInsight(BaseModel):
    threat: str
    confidence: int = Field(ge=0, le=100)
    rationale: str
    suggested_mitigation: Optional[str] = None


class Vulnerability(BaseModel):
    endpoint: str
    component: str
    category: str
    severity: Severity
    message: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    mitigation: Optional[str] = None
    detection_source: Optional[str] = None
    confidence: Optional[float] = None
    ai_insight: Optional[AIInsight] = None
    chain_path: List[str] = Field(default_factory=list)
    steps: List[str] = Field(default_factory=list)
    required_privileges: List[str] = Field(default_factory=list)
    count: Optional[int] = None


class ScanMetadata(BaseModel):
    scanned_hosts: int = 0
    reachable_hosts: int = 0
    mcp_endpoints: int = 0
    duration_seconds: float = 0.0


class ScanResult(BaseModel):
    metadata: ScanMetadata
    endpoints: List[McpEndpoint]
    vulnerabilities: List[Vulnerability]
    enhanced_vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    ai_analysis_enabled: bool = False
    chain_attacks_detected: int = 0
    analysis_depth: str = "standard"
    safe_mcp_techniques_total: int = 0
    safe_mcp_techniques_detected: int = 0
    safe_mcp_technique_details: List[Dict[str, Any]] = Field(default_factory=list)


class ToolDescriptor(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    name: str
    description: Optional[str] = None
    schema_data: Dict[str, Any] = Field(
        default_factory=dict,
        serialization_alias="schema",
        validation_alias="schema",
    )
    metadata: Dict[str, Any] = Field(default_factory=dict)
