from __future__ import annotations

import asyncio
import importlib
from pathlib import Path
from typing import Optional

import typer
from rich import print_json

from .config import ScanConfig
from .reporting import render_report
from .scanner import scan_async

app = typer.Typer(help="Discover MCP endpoints on your network and audit them for vulnerabilities.")


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
) -> None:
    """Run a one-shot scan and output the JSON report."""
    config = ScanConfig.from_env()
    updates = {}
    if subnet:
        updates["subnet"] = subnet
    if concurrency:
        updates["concurrency"] = concurrency
    updates["enable_llm_analysis"] = not disable_llm
    updates["verify_tls"] = verify_tls
    config = config.model_copy(update=updates)  # type: ignore[attr-defined]

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
        uvicorn = importlib.import_module("uvicorn")
    except ImportError as exc:  # pragma: no cover - runtime check
        raise typer.BadParameter(
            "uvicorn is required to run the API. Install with `pip install uvicorn`."
        ) from exc
    uvicorn.run("conmap.api:app", host=host, port=port, log_level=log_level)


def main() -> None:
    app()
