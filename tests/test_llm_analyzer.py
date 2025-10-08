from conmap.cache import Cache
from conmap.models import McpEndpoint, McpEvidence
import conmap.vulnerabilities.llm_analyzer as llm_analyzer


def test_llm_analyzer_skips_without_api_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    endpoint = McpEndpoint(
        address="10.0.0.3",
        scheme="http",
        port=80,
        base_url="http://10.0.0.3",
        probes=[],
        evidence=McpEvidence(json_structures=[{"tools": []}]),
    )
    findings = llm_analyzer.run_llm_analyzer([endpoint], Cache(), enabled=True)
    assert findings == []


def test_llm_analyzer_disabled(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "testkey")
    endpoint = McpEndpoint(
        address="10.0.0.6",
        scheme="http",
        port=80,
        base_url="http://10.0.0.6",
        probes=[],
        evidence=McpEvidence(json_structures=[{"tools": []}]),
    )
    findings = llm_analyzer.run_llm_analyzer([endpoint], Cache(), enabled=False)
    assert findings == []


def test_llm_analyzer_invalid_response(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "testkey")
    endpoint = McpEndpoint(
        address="10.0.0.7",
        scheme="http",
        port=80,
        base_url="http://10.0.0.7",
        probes=[],
        evidence=McpEvidence(json_structures=[{"tools": [{"name": "demo"}]}]),
    )

    class DummyResponses:
        def create(self, **kwargs):
            return type("Resp", (), {"output": []})

    class DummyClient:
        def __init__(self, api_key):
            self.responses = DummyResponses()

    monkeypatch.setattr(
        "conmap.vulnerabilities.llm_analyzer.OpenAI", lambda api_key: DummyClient(api_key)
    )
    findings = llm_analyzer.run_llm_analyzer([endpoint], Cache(), enabled=True)
    assert findings == []


def test_llm_analyzer_model_override(monkeypatch):
    monkeypatch.setenv("CONMAP_MODEL", "special-model")
    from importlib import reload
    import conmap.vulnerabilities.llm_analyzer as module

    reload(module)
    assert module.DEFAULT_MODEL == "special-model"
    global llm_analyzer
    llm_analyzer = module
    monkeypatch.delenv("CONMAP_MODEL", raising=False)
    reload(module)
    llm_analyzer = module


def test_llm_analyzer_uses_cache(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    endpoint = McpEndpoint(
        address="10.0.0.4",
        scheme="http",
        port=80,
        base_url="http://10.0.0.4",
        probes=[],
        evidence=McpEvidence(
            json_structures=[
                {
                    "tools": [
                        {"name": "demo", "description": "Perform admin task", "input_schema": {}},
                    ]
                }
            ]
        ),
    )

    class DummyContent:
        type = "text"
        text = '[{"component": "demo", "severity": "high", "message": "Issue"}]'

    class DummyMessage:
        content = [DummyContent()]

    class DummyItem:
        type = "message"
        message = DummyMessage()

    class DummyResponse:
        output = [DummyItem()]

    calls = {"count": 0}

    class DummyResponses:
        def create(self, **kwargs):
            calls["count"] += 1
            return DummyResponse()

    class DummyClient:
        def __init__(self, api_key):
            self.responses = DummyResponses()

    def fake_openai(api_key):
        return DummyClient(api_key)

    monkeypatch.setattr("conmap.vulnerabilities.llm_analyzer.OpenAI", fake_openai)

    cache = Cache()
    findings_first = llm_analyzer.run_llm_analyzer([endpoint], cache, enabled=True)
    # Subsequent call should hit cache and reuse findings
    findings_second = llm_analyzer.run_llm_analyzer([endpoint], cache, enabled=True)
    assert findings_first[0].component == "demo"
    assert findings_second[0].message == "Issue"
    assert calls["count"] == 1
