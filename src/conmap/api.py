from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .config import ScanConfig
from .reporting import build_report
from .scanner import scan_async

app = FastAPI(title="Conmap API", version="0.1.0")


class ScanRequest(BaseModel):
    subnet: str | None = Field(default=None, description="CIDR subnet to scan")
    ports: list[int] | None = Field(default=None, description="Ports to probe")
    concurrency: int | None = Field(default=None, ge=1, le=1024)
    enable_llm_analysis: bool | None = Field(default=None)
    verify_tls: bool | None = Field(default=None)
    enable_ai: bool | None = Field(default=None, description="Alias for enable_llm_analysis")
    analysis_depth: str | None = Field(default=None, description="basic | standard | deep")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan")
async def scan_endpoint(request: ScanRequest) -> dict:
    try:
        config = ScanConfig.from_env()
        update = request.model_dump(exclude_unset=True)
        if "enable_ai" in update and "enable_llm_analysis" not in update:
            update["enable_llm_analysis"] = update.pop("enable_ai")
        depth = update.get("analysis_depth")
        if depth:
            update["analysis_depth"] = depth.lower()
        config = config.model_copy(update=update)  # type: ignore[attr-defined]
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result = await scan_async(config)
    return build_report(result)
