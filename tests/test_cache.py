import json
from pathlib import Path

from conmap.cache import Cache


def test_cache_memory_only():
    cache = Cache()
    payload = {"foo": "bar"}
    assert cache.get(payload) is None
    cache.set(payload, {"result": 1})
    assert cache.get(payload) == {"result": 1}


def test_cache_file_roundtrip(tmp_path: Path):
    cache_path = tmp_path / "cache.json"
    cache = Cache(path=str(cache_path))
    payload = {"alpha": 1}
    cache.set(payload, {"ok": True})
    assert json.loads(cache_path.read_text())  # ensure file written

    rehydrated = Cache(path=str(cache_path))
    assert rehydrated.get(payload) == {"ok": True}


def test_cache_handles_corrupt_file(tmp_path: Path):
    cache_path = tmp_path / "cache.json"
    cache_path.write_text("not-json", encoding="utf-8")
    cache = Cache(path=str(cache_path))
    assert cache.get({"missing": True}) is None
