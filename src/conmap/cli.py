from __future__ import annotations

import asyncio
import importlib
import logging
from pathlib import Path
from typing import Optional

import typer
from rich import print_json

from .config import ScanConfig
from .logging import get_logger, set_log_level
from .reporting import render_report
from .scanner import scan_async

app = typer.Typer(help="Discover MCP endpoints on your network and audit them for vulnerabilities.")

logger = get_logger(__name__)


@app.command()
def scan(
    subnet: Optional[str] = typer.Option(
        None, help="CIDR subnet to scan instead of auto-discovery."
    ),
    output: Optional[Path] = typer.Option(None, help="Write JSON report to this file."),
    concurrency: Optional[int] = typer.Option(
        None, min=1, max=1024, help="Concurrent probe limit."
    ),
    disable_llm: bool = typer.Option(False, help="Disable GPT-4o semantic analysis."),
    verify_tls: bool = typer.Option(False, help="Verify TLS certificates for HTTPS probes."),
    depth: str = typer.Option(
        "standard",
        "--depth",
        "-d",
        help="Analysis depth: basic, standard, or deep.",
        show_choices=True,
    ),
    url: Optional[str] = typer.Option(
        None,
        "--url",
        "-u",
        help="Scan a single MCP base URL instead of network discovery.",
    ),
    log_level: str = typer.Option(
        "info",
        "--log-level",
        help="Logging level (critical,error,warning,info,debug).",
    ),
    llm_batch_size: int = typer.Option(
        5,
        "--llm-batch-size",
        min=1,
        max=50,
        help="Number of tools to send per LLM batch (1-50).",
    ),
) -> None:
    """Run a one-shot scan and output the JSON report."""
    try:
        level = getattr(logging, log_level.upper())
    except AttributeError as exc:  # pragma: no cover - user input validation
        raise typer.BadParameter("Invalid log level") from exc
    set_log_level(level)
    config = ScanConfig.from_env()
    updates = {}
    if subnet:
        updates["subnet"] = subnet
    if concurrency:
        updates["concurrency"] = concurrency
    updates["enable_llm_analysis"] = not disable_llm
    updates["verify_tls"] = verify_tls
    updates["llm_batch_size"] = llm_batch_size
    if depth:
        normalized_depth = depth.strip().lower()
        if normalized_depth not in {"basic", "standard", "deep"}:
            raise typer.BadParameter("Depth must be one of: basic, standard, deep.")
        updates["analysis_depth"] = normalized_depth
    config = config.model_copy(update=updates)  # type: ignore[attr-defined]
    if url:
        config = config.model_copy(update={"target_urls": [url]})  # type: ignore[attr-defined]

    logger.info("CLI scan invoked depth=%s url=%s", config.analysis_depth, url)
    result = asyncio.run(scan_async(config))
    report_json = render_report(result)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(report_json, encoding="utf-8")
        typer.echo(f"Wrote report to {output}")
    else:
        print_json(report_json)


@app.command()
def api(
    host: str = typer.Option("127.0.0.1", help="Host interface to bind."),
    port: int = typer.Option(8000, help="Port to bind."),
    log_level: str = typer.Option("info", help="Uvicorn log level."),
) -> None:
    """Run the Conmap HTTP API (FastAPI)."""
    try:
        level = getattr(logging, log_level.upper())
    except AttributeError as exc:  # pragma: no cover - user input validation
        raise typer.BadParameter("Invalid log level") from exc
    set_log_level(level)
    try:
        uvicorn = importlib.import_module("uvicorn")
    except ImportError as exc:  # pragma: no cover - runtime check
        raise typer.BadParameter(
            "uvicorn is required to run the API. Install with `pip install uvicorn`."
        ) from exc
    logger.info("Starting API server on %s:%s", host, port)
    uvicorn.run("conmap.api:app", host=host, port=port, log_level=log_level)


def main() -> None:
    app()
