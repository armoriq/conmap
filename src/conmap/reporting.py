from __future__ import annotations

import json
from typing import Any, Dict

from .models import ScanResult


def _normalize(value):
    if isinstance(value, dict):
        return {key: _normalize(val) for key, val in value.items()}
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    if isinstance(value, (set, tuple)):
        return [_normalize(item) for item in value]
    return value


def build_report(result: ScanResult) -> Dict[str, Any]:
    return _normalize(result.model_dump(by_alias=True))


def render_report(result: ScanResult, pretty: bool = True) -> str:
    data = build_report(result)
    if pretty:
        return json.dumps(data, indent=2)
    return json.dumps(data, separators=(",", ":"))
