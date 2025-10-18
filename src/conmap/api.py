from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .config import ScanConfig
from .logging import get_logger
from .reporting import build_report
from .scanner import scan_async

# Load environment variables after imports
load_dotenv()

app = FastAPI(title="Conmap API", version="0.1.0")
logger = get_logger(__name__)


class ScanRequest(BaseModel):
    subnet: str | None = Field(default=None, description="CIDR subnet to scan")
    ports: list[int] | None = Field(default=None, description="Ports to probe")
    concurrency: int | None = Field(default=None, ge=1, le=1024)
    enable_llm_analysis: bool | None = Field(default=None)
    verify_tls: bool | None = Field(default=None)
    enable_ai: bool | None = Field(default=None, description="Alias for enable_llm_analysis")
    analysis_depth: str | None = Field(default=None, description="basic | standard | deep")
    url: str | None = Field(default=None, description="Single MCP base URL to scan")
    llm_batch_size: int | None = Field(default=None, ge=1, le=50)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "okay"}


@app.post("/scan")
async def scan_endpoint(request: ScanRequest) -> dict:
    try:
        config = ScanConfig.from_env()
        update = request.model_dump(exclude_unset=True)
        logger.info(
            "API scan request received depth=%s url=%s",
            update.get("analysis_depth"),
            update.get("url"),
        )
        if "enable_ai" in update and "enable_llm_analysis" not in update:
            update["enable_llm_analysis"] = update.pop("enable_ai")
        depth = update.get("analysis_depth")
        if depth:
            update["analysis_depth"] = depth.lower()
        target_url = update.pop("url", None)
        batch_size = update.get("llm_batch_size")
        config = config.model_copy(update=update)  # type: ignore[attr-defined]
        if target_url:
            config = config.model_copy(update={"target_urls": [target_url]})  # type: ignore[attr-defined]
        if batch_size is not None:
            config = config.model_copy(update={"llm_batch_size": batch_size})  # type: ignore[attr-defined]
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result = await scan_async(config)
    logger.info(
        "API scan completed endpoints=%s findings=%s score=%s",
        len(result.endpoints),
        len(result.vulnerabilities),
        result.vulnerability_score,
    )
    return build_report(result)
