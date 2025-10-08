from pathlib import Path

from typer.testing import CliRunner

from conmap import cli
from conmap.models import McpEndpoint, ScanMetadata, ScanResult, Vulnerability, Severity


def fake_result() -> ScanResult:
    endpoint = McpEndpoint(
        address="10.0.0.9",
        scheme="http",
        port=80,
        base_url="http://10.0.0.9",
        probes=[],
    )
    metadata = ScanMetadata(scanned_hosts=1, reachable_hosts=1, mcp_endpoints=1, duration_seconds=0.1)
    vuln = Vulnerability(
        endpoint=endpoint.base_url,
        component="tool",
        category="schema.test",
        severity=Severity.low,
        message="ok",
        evidence={},
    )
    return ScanResult(metadata=metadata, endpoints=[endpoint], vulnerabilities=[vuln])


def test_cli_scan_writes_file(tmp_path, monkeypatch):
    runner = CliRunner()
    monkeypatch.setattr("conmap.cli.asyncio.run", lambda coro: fake_result())
    result = runner.invoke(cli.app, ["scan", "--output", str(tmp_path / "report.json")])
    assert result.exit_code == 0, result.stdout
    assert (tmp_path / "report.json").exists()


def test_cli_scan_prints_stdout(monkeypatch):
    runner = CliRunner()
    monkeypatch.setattr("conmap.cli.asyncio.run", lambda coro: fake_result())
    result = runner.invoke(cli.app, ["scan"])
    assert result.exit_code == 0
    assert "schema.test" in result.stdout


def test_cli_api_invokes_uvicorn(monkeypatch):
    calls = {}

    def fake_run(app_path, host, port, log_level):
        calls["args"] = (app_path, host, port, log_level)

    from types import SimpleNamespace

    dummy_module = SimpleNamespace(run=fake_run)

    monkeypatch.setattr("conmap.cli.importlib.import_module", lambda name: dummy_module)
    runner = CliRunner()
    result = runner.invoke(cli.app, ["api", "--host", "0.0.0.0", "--port", "9000"])
    assert result.exit_code == 0, result.stdout
    assert calls["args"] == ("conmap.api:app", "0.0.0.0", 9000, "info")
