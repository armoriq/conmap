import importlib
from types import SimpleNamespace

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
    findings = llm_analyzer.run_llm_analyzer([endpoint], Cache(), enabled=True, batch_size=5)
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
    findings = llm_analyzer.run_llm_analyzer([endpoint], Cache(), enabled=False, batch_size=5)
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
    findings = llm_analyzer.run_llm_analyzer([endpoint], Cache(), enabled=True, batch_size=5)
    assert findings == []


def test_llm_analyzer_parses_dict_response(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "testkey")
    endpoint = McpEndpoint(
        address="10.0.0.8",
        scheme="http",
        port=80,
        base_url="http://10.0.0.8",
        probes=[],
        evidence=McpEvidence(json_structures=[{"tools": [{"name": "demo"}]}]),
    )

    class DummyResponses:
        def create(self, **kwargs):
            return type(
                "Resp",
                (),
                {
                    "output": [
                        type(
                            "Msg",
                            (),
                            {
                                "type": "message",
                                "message": type(
                                    "Inner",
                                    (),
                                    {
                                        "content": [
                                            type(
                                                "Part",
                                                (),
                                                {
                                                    "type": "text",
                                                    "text": (
                                                        '{"threats": ['
                                                        '{"tool": "demo", "threat": "issue", '
                                                        '"confidence": 92, "rationale": "bad"}]}'
                                                    ),
                                                },
                                            )
                                        ]
                                    },
                                ),
                            },
                        )
                    ]
                },
            )

    class DummyClient:
        def __init__(self, api_key):
            self.responses = DummyResponses()

    monkeypatch.setattr(
        "conmap.vulnerabilities.llm_analyzer.OpenAI", lambda api_key: DummyClient(api_key)
    )
    findings = llm_analyzer.run_llm_analyzer([endpoint], Cache(), enabled=True, batch_size=5)
    assert findings[0].ai_insight is not None
    assert findings[0].ai_insight.confidence == 92


def test_llm_analyzer_model_override(monkeypatch):
    monkeypatch.setenv("CONMAP_MODEL", "special-model")
    module = importlib.import_module("conmap.vulnerabilities.llm_analyzer")
    importlib.reload(module)
    assert module.DEFAULT_MODEL == "special-model"
    global llm_analyzer
    llm_analyzer = module
    monkeypatch.delenv("CONMAP_MODEL", raising=False)
    importlib.reload(module)
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
        text = (
            '{"threats": ['
            '{"tool": "demo", "threat": "Issue", "confidence": 88, '
            '"rationale": "Because", "suggestedMitigation": "Fix"}]}'
        )

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
    findings_first = llm_analyzer.run_llm_analyzer([endpoint], cache, enabled=True, batch_size=5)
    # Subsequent call should hit cache and reuse findings
    findings_second = llm_analyzer.run_llm_analyzer([endpoint], cache, enabled=True, batch_size=5)
    assert findings_first[0].component == "demo"
    assert findings_first[0].detection_source == "llm"
    assert findings_first[0].ai_insight is not None
    assert findings_first[0].ai_insight.confidence == 88
    assert findings_second[0].message == "Issue"
    assert calls["count"] == 1


def test_normalize_tool_handles_sets():
    tool = {
        "name": "multi",
        "description": "example",
        "schema": {"privileges": {"read", "write"}, "nested": [{"values": {"a", "b"}}]},
    }
    normalized = llm_analyzer._normalize_tool(tool)
    privileges = normalized["schema"]["privileges"]
    assert isinstance(privileges, list)
    assert sorted(privileges) == ["read", "write"]
    nested = normalized["schema"]["nested"][0]["values"]
    assert isinstance(nested, list)
    assert sorted(nested) == ["a", "b"]


def test_call_openai_handles_output_text(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    payload = {"endpoint": "https://example.com", "tools": []}

    class DummyResponses:
        def create(self, **kwargs):
            return SimpleNamespace(output_text='{"threats": []}', output=[])

    dummy_client = SimpleNamespace(responses=DummyResponses())

    result = llm_analyzer._call_openai(dummy_client, payload)
    assert result == '{"threats": []}'


def test_call_openai_handles_choices(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    payload = {"endpoint": "https://example.com", "tools": []}

    class DummyResponses:
        def create(self, **kwargs):
            choice = SimpleNamespace(message={"content": '{"threats": [{"tool": "demo"}]}'})
            return SimpleNamespace(output=[], choices=[choice])

    dummy_client = SimpleNamespace(responses=DummyResponses())
    result = llm_analyzer._call_openai(dummy_client, payload)
    assert result == '{"threats": [{"tool": "demo"}]}'


def test_call_openai_handles_api_error(monkeypatch):
    class DummyAPIError(Exception):
        pass

    monkeypatch.setattr(llm_analyzer, "APIError", DummyAPIError)

    class DummyResponses:
        def create(self, **kwargs):
            raise DummyAPIError("boom")

    dummy_client = SimpleNamespace(responses=DummyResponses())
    result = llm_analyzer._call_openai(
        dummy_client, {"endpoint": "https://example.com", "tools": []}
    )
    assert result is None


def test_call_openai_handles_output_text_attr(monkeypatch):
    payload = {"endpoint": "https://example.com", "tools": []}

    class DummyItem:
        text = '{"threats": []}'

    class DummyResponses:
        def create(self, **kwargs):
            return SimpleNamespace(output=[DummyItem()], output_text=None)

    dummy_client = SimpleNamespace(responses=DummyResponses())
    result = llm_analyzer._call_openai(dummy_client, payload)
    assert result == '{"threats": []}'


def test_call_openai_handles_choice_content_list(monkeypatch):
    payload = {"endpoint": "https://example.com", "tools": []}

    class DummyResponses:
        def create(self, **kwargs):
            choice = SimpleNamespace(
                message=SimpleNamespace(
                    content=[{"type": "text", "text": '{"threats": [{"tool": "x"}]}'}]
                )
            )
            return SimpleNamespace(output=[], choices=[choice])

    dummy_client = SimpleNamespace(responses=DummyResponses())
    result = llm_analyzer._call_openai(dummy_client, payload)
    assert result == '{"threats": [{"tool": "x"}]}'


def test_clean_response_text_strips_code_block():
    raw = "```json\n{\"threats\": []}\n```"
    assert llm_analyzer._clean_response_text(raw) == '{"threats": []}'


def test_parse_vulnerabilities_handles_list():
    data = '[{"tool": "demo", "threat": "issue", "confidence": 70}]'
    findings = llm_analyzer._parse_vulnerabilities("https://demo", data)
    assert findings[0].component == "demo"
    assert findings[0].severity.name == "high"


def test_extract_tools_handles_mapping(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    class DummyResponses:
        def create(self, **kwargs):
            return SimpleNamespace(output_text='{"threats": []}', output=[])

    class DummyClient:
        def __init__(self, api_key):
            self.responses = DummyResponses()

    monkeypatch.setattr("conmap.vulnerabilities.llm_analyzer.OpenAI", DummyClient)
    endpoint = McpEndpoint(
        address="host",
        scheme="https",
        port=443,
        base_url="https://host",
        probes=[],
        evidence=McpEvidence(json_structures=[{"tools": {"a": {"name": "alpha"}}}]),
    )
    findings = llm_analyzer.run_llm_analyzer([endpoint], Cache(), enabled=True, batch_size=5)
    assert findings == []
