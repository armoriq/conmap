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

Conmap still derives the packaged version from Git tags via `setuptools_scm`, but tags are now
generated automatically by [autogitsemver](https://github.com/semver/auto-semver). The tool inspects
commit history, decides the next semantic version, and emits a tag in `vX.Y.Z` form.

## Configuration

- Set `OPENAI_API_KEY` for GPT-4o analysis.
- Use `CONMAP_MAX_CONCURRENCY` and `CONMAP_TIMEOUT` (legacy `MCP_SCANNER_*`) to tune scanning behavior.
- Control automation flags with `CONMAP_ENABLE_LLM_ANALYSIS` and analysis depth with `CONMAP_ANALYSIS_DEPTH` (`basic`, `standard`, `deep`).
- The HTTP API accepts `analysis_depth` (`basic|standard|deep`) and `enable_ai` fields in the body of `POST /scan`.

## Publishing

The `Release` GitHub Action runs on pushes to `main` (or via manual dispatch). It:

1. Runs formatting/tests.
2. Invokes `autogitsemver` to compute the next version and create/push the `vX.Y.Z` tag.
3. Builds the distribution, uploads it to PyPI, and creates the GitHub release.

Ensure the repository secret `PYPI_API_TOKEN` is populated so uploads succeed.

To reproduce the process locally:

```bash
export PYPI_TOKEN=<pypi-api-token>
export GH_TOKEN=<github-personal-access-token>
uv run autogitsemver
git tag -a "v$(uv run autogitsemver | tail -n1)" -m "release"
uv run python -m build
python -m pip install --upgrade twine
python -m twine upload dist/*
```
