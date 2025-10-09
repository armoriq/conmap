# Conmap

[![CI](https://github.com/armoriq/conmap/actions/workflows/ci.yml/badge.svg)](https://github.com/armoriq/conmap/actions/workflows/ci.yml)
[![Security Scan](https://github.com/armoriq/conmap/actions/workflows/security.yml/badge.svg)](https://github.com/armoriq/conmap/actions/workflows/security.yml)
[![SBOM](https://github.com/armoriq/conmap/actions/workflows/sbom.yml/badge.svg)](https://github.com/armoriq/conmap/actions/workflows/sbom.yml)
[![Coverage](https://img.shields.io/badge/coverage-%3E%3D90%25-brightgreen.svg)](#)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](#)

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

Conmap derives its version from annotated Git tags via `setuptools_scm`. When you are ready to cut a
release, create a tag such as `v0.2.0`; the version embedded in the build will match the tag.

## Configuration

- Set `OPENAI_API_KEY` for GPT-4o analysis.
- Use `CONMAP_MAX_CONCURRENCY` and `CONMAP_TIMEOUT` (legacy `MCP_SCANNER_*`) to tune scanning behavior.
- Control automation flags with `CONMAP_ENABLE_LLM_ANALYSIS` and analysis depth with `CONMAP_ANALYSIS_DEPTH` (`basic`, `standard`, `deep`).
- The HTTP API accepts `analysis_depth` (`basic|standard|deep`) and `enable_ai` fields in the body of `POST /scan`.

## Publishing

Releases are driven by annotated tags. Create and push a tag in the form `vX.Y.Z` to trigger the
`Release` workflow:

```bash
git tag -a v0.1.0 -m "release v0.1.0"
git push origin v0.1.0
```

The workflow will:

1. Install dependencies, lint, and run tests.
2. Build the project with `setuptools_scm` pinned to the tag version.
3. Upload artifacts to PyPI via `pypa/gh-action-pypi-publish` and create a GitHub release.

Ensure the repository secret `PYPI_API_TOKEN` contains a valid PyPI API token before pushing tags.

For a manual (local) release:

```bash
export VERSION=0.1.0
git tag -a "v$VERSION" -m "release v$VERSION"
git push origin "v$VERSION"
export SETUPTOOLS_SCM_PRETEND_VERSION="$VERSION"
uv run python -m build
python -m pip install --upgrade twine
python -m twine upload dist/*
```

## Trust Center

- **Signed releases & provenance** – GitHub Actions builds run from annotated `v*` tags with immutable execution logs.
- **Continuous assurance** – CI enforces linting, tests, and 90% line coverage before a build is published.
- **Security automation** – Bandit and pip-audit workflows scan every push & pull request for code and dependency vulnerabilities.
- **Supply chain transparency** – CycloneDX SBOMs are generated for each release and uploaded as artifacts.
- **Responsible disclosure** – See [SECURITY.md](SECURITY.md) for vulnerability reporting guidelines and response timelines.
- **Dependency hygiene** – Dependabot monitors both Python packages and GitHub Actions for outdated or vulnerable components.
- **Operational support** – [SUPPORT.md](SUPPORT.md) documents response targets and contact processes for assistance.
- **Community standards** – Participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).
