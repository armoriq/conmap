from __future__ import annotations

import json
from typing import Any, Dict

from .models import ScanResult


def build_report(result: ScanResult) -> Dict[str, Any]:
    return result.model_dump(by_alias=True)


def render_report(result: ScanResult, pretty: bool = True) -> str:
    data = build_report(result)
    if pretty:
        return json.dumps(data, indent=2)
    return json.dumps(data, separators=(",", ":"))
