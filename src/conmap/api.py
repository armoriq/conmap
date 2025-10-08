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


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan")
async def scan_endpoint(request: ScanRequest) -> dict:
    try:
        config = ScanConfig.from_env()
        update = request.model_dump(exclude_unset=True)
        config = config.model_copy(update=update)  # type: ignore[attr-defined]
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result = await scan_async(config)
    return build_report(result)
