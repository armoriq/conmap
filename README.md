# Conmap

Conmap discovers Model Context Protocol (MCP) endpoints on the local network and evaluates them against the [safe-mcp](https://github.com/fkautz/safe-mcp) guidance. It ships with a feature-rich command line interface and an HTTP API suitable for enterprise automation pipelines.

## Features

- **Subnet discovery** – Detects local subnets automatically and probes HTTP/HTTPS endpoints for MCP support.
- **MCP fingerprinting** – Validates headers, capability manifests, and well-known paths to confirm MCP compatibility.
- **Vulnerability analysis** – Applies Schema Inspector, Chain Attack Detector, and LLM Analyzer heuristics inspired by the safe-mcp framework.
- **OpenAI integration** – Uses GPT-4o for semantic reviews of tool descriptions with transparent caching.
- **Layered depth** – Choose basic, standard, or deep analysis (deep enables AI semantics and richer chain detection with privilege paths).
- **Automation-ready output** – Produces structured JSON reports grouped by endpoint, tool, resource, and prompt.
- **Interfaces** – Provides both a Typer-based CLI and FastAPI server for flexible deployments.

## Quick Start

```bash
pip install conmap
conmap scan --output report.json
# Run a deeper AI-assisted assessment
conmap scan --depth deep --output deep-report.json
```

To run the web service:

```bash
conmap api --host 0.0.0.0 --port 8080
```

## Development

### Using uv (recommended)

```bash
uv sync --extra dev
uv run pre-commit install
uv run pre-commit run --all-files --show-diff-on-failure
uv run pytest --cov=conmap
uv run conmap scan --output report.json
```

This will create an isolated `.venv` managed by [uv](https://github.com/astral-sh/uv) and install both runtime and development dependencies.

### Using pip

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
pre-commit install
pre-commit run --all-files --show-diff-on-failure
pytest --cov=conmap
```

### Versioning

Conmap derives its version automatically from Git tags via `setuptools_scm`. Tag commits in the format `vX.Y.Z` (for example `v0.2.0`) before publishing to ensure the package metadata reflects the expected release number.

## Configuration

- Set `OPENAI_API_KEY` for GPT-4o analysis.
- Use `CONMAP_MAX_CONCURRENCY` and `CONMAP_TIMEOUT` (legacy `MCP_SCANNER_*`) to tune scanning behavior.
- Control automation flags with `CONMAP_ENABLE_LLM_ANALYSIS` and analysis depth with `CONMAP_ANALYSIS_DEPTH` (`basic`, `standard`, `deep`).
- The HTTP API accepts `analysis_depth` (`basic|standard|deep`) and `enable_ai` fields in the body of `POST /scan`.

## Publishing

Releases are automated with [python-semantic-release](https://python-semantic-release.readthedocs.io/). Use
conventional commit messages (Angular style) and merge to `main`; the `Release` workflow bumps the
semantic version, updates `CHANGELOG.md`, publishes to PyPI, and creates the GitHub release. Manual
tags are no longer required.

Ensure the repository secret `PYPI_API_TOKEN` is set to a valid PyPI API token so the workflow can
upload new versions.

When running `semantic-release` locally, export both tokens first:

```bash
export GH_TOKEN=<github-personal-access-token>
export PYPI_TOKEN=<pypi-api-token>
uv run semantic-release publish
```
