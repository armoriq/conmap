from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

from cachetools import LRUCache


class Cache:
    """Simple file-backed cache for expensive operations such as LLM calls."""

    def __init__(self, path: Optional[str] = None, maxsize: int = 256) -> None:
        self._path = Path(path) if path else None
        self._memory = LRUCache(maxsize=maxsize)
        if self._path:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            if self._path.exists():
                self._load()

    @staticmethod
    def _digest(payload: Dict[str, Any]) -> str:
        serialized = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()

    def get(self, payload: Dict[str, Any]) -> Optional[Any]:
        key = self._digest(payload)
        if key in self._memory:
            return self._memory[key]
        if self._path:
            data = self._read()
            if key in data:
                value = data[key]
                self._memory[key] = value
                return value
        return None

    def set(self, payload: Dict[str, Any], value: Any) -> None:
        key = self._digest(payload)
        self._memory[key] = value
        if self._path:
            data = self._read()
            data[key] = value
            tmp_path = self._path.with_suffix(".tmp")
            tmp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            os.replace(tmp_path, self._path)

    def _read(self) -> Dict[str, Any]:
        if not self._path or not self._path.exists():
            return {}
        try:
            return json.loads(self._path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}

    def _load(self) -> None:
        if not self._path:
            return
        data = self._read()
        for key, value in data.items():
            self._memory[key] = value
